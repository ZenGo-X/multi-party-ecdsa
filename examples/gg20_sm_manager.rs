use std::collections::hash_map::{Entry, HashMap};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};

use futures::Stream;
use rocket::data::ToByteUnit;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::stream::{stream, Event, EventStream};
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, RwLock};

#[rocket::get("/rooms/<room_id>/subscribe")]
async fn subscribe(
    db: &State<Db>,
    mut shutdown: rocket::Shutdown,
    last_seen_msg: LastEventId,
    room_id: &str,
) -> EventStream<impl Stream<Item = Event>> {
    let room = db.get_room_or_create_empty(room_id).await;
    let mut subscription = room.subscribe(last_seen_msg.0);
    EventStream::from(stream! {
        loop {
            let (id, msg) = tokio::select! {
                message = subscription.next() => message,
                _ = &mut shutdown => return,
            };
            yield Event::data(msg)
                .event("new-message")
                .id(id.to_string())
        }
    })
}

#[rocket::post("/rooms/<room_id>/issue_unique_idx")]
async fn issue_idx(db: &State<Db>, room_id: &str) -> Json<IssuedUniqueIdx> {
    let room = db.get_room_or_create_empty(room_id).await;
    let idx = room.issue_unique_idx();
    Json::from(IssuedUniqueIdx { unique_idx: idx })
}

#[rocket::post("/rooms/<room_id>/broadcast", data = "<message>")]
async fn broadcast(db: &State<Db>, room_id: &str, message: String) -> Status {
    let room = db.get_room_or_create_empty(room_id).await;
    room.publish(message).await;
    Status::Ok
}

struct Db {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

struct Room {
    messages: RwLock<Vec<String>>,
    message_appeared: Notify,
    subscribers: AtomicU16,
    next_idx: AtomicU16,
}

impl Db {
    pub fn empty() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_room_or_create_empty(&self, room_id: &str) -> Arc<Room> {
        let rooms = self.rooms.read().await;
        if let Some(room) = rooms.get(room_id) {
            // If no one is watching this room - we need to clean it up first
            if !room.is_abandoned() {
                return room.clone();
            }
        }
        drop(rooms);

        let mut rooms = self.rooms.write().await;
        match rooms.entry(room_id.to_owned()) {
            Entry::Occupied(entry) if !entry.get().is_abandoned() => entry.get().clone(),
            Entry::Occupied(entry) => {
                let room = Arc::new(Room::empty());
                *entry.into_mut() = room.clone();
                room
            }
            Entry::Vacant(entry) => entry.insert(Arc::new(Room::empty())).clone(),
        }
    }
}

impl Room {
    pub fn empty() -> Self {
        Self {
            messages: RwLock::new(vec![]),
            message_appeared: Notify::new(),
            subscribers: AtomicU16::new(0),
            next_idx: AtomicU16::new(1),
        }
    }

    pub async fn publish(self: &Arc<Self>, message: String) {
        let mut messages = self.messages.write().await;
        messages.push(message);
        self.message_appeared.notify_waiters();
    }

    pub fn subscribe(self: Arc<Self>, last_seen_msg: Option<u16>) -> Subscription {
        self.subscribers.fetch_add(1, Ordering::SeqCst);
        Subscription {
            room: self,
            next_event: last_seen_msg.map(|i| i + 1).unwrap_or(0),
        }
    }

    pub fn is_abandoned(&self) -> bool {
        self.subscribers.load(Ordering::SeqCst) == 0
    }

    pub fn issue_unique_idx(&self) -> u16 {
        self.next_idx.fetch_add(1, Ordering::Relaxed)
    }
}

struct Subscription {
    room: Arc<Room>,
    next_event: u16,
}

impl Subscription {
    pub async fn next(&mut self) -> (u16, String) {
        loop {
            let history = self.room.messages.read().await;
            if let Some(msg) = history.get(usize::from(self.next_event)) {
                let event_id = self.next_event;
                self.next_event = event_id + 1;
                return (event_id, msg.clone());
            }
            let notification = self.room.message_appeared.notified();
            drop(history);
            notification.await;
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.room.subscribers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Represents a header Last-Event-ID
struct LastEventId(Option<u16>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LastEventId {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header = request
            .headers()
            .get_one("Last-Event-ID")
            .map(|id| id.parse::<u16>());
        match header {
            Some(Ok(last_seen_msg)) => Outcome::Success(LastEventId(Some(last_seen_msg))),
            Some(Err(_parse_err)) => {
                Outcome::Failure((Status::BadRequest, "last seen msg id is not valid"))
            }
            None => Outcome::Success(LastEventId(None)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct IssuedUniqueIdx {
    unique_idx: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let figment = rocket::Config::figment().merge((
        "limits",
        rocket::data::Limits::new().limit("string", 100.megabytes()),
    ));
    rocket::custom(figment)
        .mount("/", rocket::routes![subscribe, issue_idx, broadcast])
        .manage(Db::empty())
        .launch()
        .await?;
    Ok(())
}
