#[macro_use]
extern crate rocket;
mod gg20_signing;
use std::path::PathBuf;
use futures::executor::block_on;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
async fn sign(serialized_tx: String) -> &'static str {
    println!("{}", serialized_tx);
    // thread::spawn( move || {
        // println!("thread spawned");
        let a = gg20_signing::sign(
            serialized_tx.to_owned(),
            PathBuf::from(r"./examples/local-share2.json"),
            vec![1, 2],
            surf::Url::parse("http://localhost:8000").unwrap(),
            "default-signing".to_string(),
        );
        block_on(a);

    println!("signed 27!!!!!");

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
