#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[post("/", format = "plain", data = "<serialized_tx>")]
fn sign(serialized_tx: &str) -> &'static str  {
    println!("{}", serialized_tx);
    "Server Good"
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .mount("/sign", routes![sign])
}
