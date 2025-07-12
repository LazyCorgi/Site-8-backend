use rocket::Route;

mod api;
pub mod model;

pub fn get_route() -> Vec<Route> {
    routes![api::create_notice, api::get_notices]
}
