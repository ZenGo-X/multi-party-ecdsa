#[macro_use]
extern crate rocket;
mod gg20_signing;
use std::path::PathBuf;
use std::{thread, time::Duration};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
async fn sign(serialized_tx: &str) -> &'static str {
    println!("{}", serialized_tx);
    thread::sleep(Duration::from_millis(2000));

    let a = gg20_signing::sign(
        serialized_tx.to_owned(),
        PathBuf::from(r"./examples/local-share2.json"),
        vec![1, 2],
        surf::Url::parse("http://localhost:8000").unwrap(),
        "default-signing".to_string(),
    )
    .await;

    println!("a: {:?}", a);

    "Server Good"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let figment = rocket::Config::figment().merge(("port", 8002));
    rocket::custom(figment)
        .mount("/", routes![index])
        .mount("/sign", routes![sign])
        .launch()
        .await?;
    Ok(())
}
