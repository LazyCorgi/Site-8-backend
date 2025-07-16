#[macro_use]
extern crate rocket;

mod notices;
mod users;

use rocket::Route;

#[launch]
async fn rocket() -> _ {
    let db = sqlx::SqlitePool::connect("sqlite:./data.db").await.unwrap();
    rocket::build().manage(db).mount("/", get_route())
}

fn get_route() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.extend(notices::get_route());

    routes
}
