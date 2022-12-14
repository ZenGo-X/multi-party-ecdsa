#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
fn sign(serialized_tx: &str) -> &'static str {
    println!("{}", serialized_tx);
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
