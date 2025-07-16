use rocket::Route;

mod api;
pub mod method;
pub mod model;

pub fn get_route() -> Vec<Route> {
    routes![api::login_user]
}
