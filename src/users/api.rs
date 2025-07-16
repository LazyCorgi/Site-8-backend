use rocket::State;
use rocket::http::Status;
use rocket::serde::json::Json;
use sqlx::SqlitePool;

use super::method::{generate_jwt, json_error, json_jwt_error, json_msg, verify_password};
use super::model::{LoginRequest, LoginResponse};

#[post("/login", format = "json", data = "<login>")]
pub async fn login_user(
    pool: &State<SqlitePool>,
    login: Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (Status, Json<serde_json::Value>)> {
    let row = sqlx::query!(
        "SELECT username, password_hash FROM users WHERE username = ?",
        login.username
    )
    .fetch_optional(pool.inner())
    .await
    .map_err(|e| (Status::InternalServerError, json_error(e)))?;

    if let Some(user) = row {
        let password_match = verify_password(&user.password_hash, &login.password).await;
        if password_match {
            match generate_jwt(&user.username) {
                Ok(token) => Ok(Json(LoginResponse {
                    token,
                    username: user.username,
                })),
                Err(e) => Err((Status::InternalServerError, json_jwt_error(e))),
            }
        } else {
            Err((Status::Unauthorized, json_msg("密码错误")))
        }
    } else {
        Err((Status::Unauthorized, json_msg("用户不存在")))
    }
}
