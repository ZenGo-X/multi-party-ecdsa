#[macro_use]
extern crate rocket;
use reqwest::header::CONTENT_TYPE;
mod gg20_signing;
use std::path::PathBuf;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
async fn send_tx(serialized_tx: &str) -> &'static str {
    println!("req from client: {}", &serialized_tx);
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8002/sign")
        .header(CONTENT_TYPE, "text/plain")
        .body(serialized_tx.to_owned())
        .send()
        .expect("REASON")
        .text();

    println!("res from server: {:?}", res.unwrap());

    let a = gg20_signing::sign(
        serialized_tx.to_owned(),
        PathBuf::from(r"./examples/local-share1.json"),
        vec![1, 2],
        surf::Url::parse("http://localhost:8000").unwrap(),
        "default-signing".to_string()
    ).await;

    println!("a: {:?}", a);

    "Good"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let figment = rocket::Config::figment().merge(("port", 8001));
    rocket::custom(figment)
        .mount("/", routes![index])
        .mount("/send-tx", routes![send_tx])
        .launch()
        .await?;
    Ok(())
}
