#[macro_use]
extern crate rocket;

use reqwest::header::CONTENT_TYPE;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
async fn send_tx(serialized_tx: &str) -> &'static str {
    println!("req from client: {}", serialized_tx);
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8001/sign")
        .header(CONTENT_TYPE, "text/plain")
        .body(serialized_tx.to_owned())
        .send()
        .await
        .expect("REASON")
        .text()
        .await;

    println!("res from server: {:?}", res.unwrap());
    "Good"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .mount("/send-tx", routes![send_tx])
}
