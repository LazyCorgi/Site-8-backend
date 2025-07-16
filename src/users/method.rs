use argon2::{Argon2, PasswordHash, PasswordVerifier};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{FromRequest, Request};
use rocket::serde::json::Json;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::model::Claims;

const SECRET: &[u8] = b"my_secret_key_please_change_me"; // 改成你自己的密钥，存到环境变量中更安全
pub fn generate_jwt(username: &str) -> String {
    let expiration = OffsetDateTime::now_utc() + Duration::hours(2); // 有效期 2 小时
    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration.unix_timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

pub fn verify_jwt(token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET),
        &Validation::default(),
    )
}

pub async fn verify_password(stored_hash: &str, input_password: &str) -> bool {
    let parsed_hash = PasswordHash::new(stored_hash).unwrap();
    Argon2::default()
        .verify_password(input_password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[derive(Debug)]
pub enum AuthError {
    Missing,
    Invalid,
}

pub struct AuthenticatedUser(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error, ()> {
        let auth_header = req.headers().get_one("Authorization");

        if let Some(auth_header) = auth_header {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(SECRET),
                    &Validation::default(),
                ) {
                    Ok(token_data) => {
                        return Outcome::Success(AuthenticatedUser(token_data.claims.sub));
                    }
                    Err(_) => {
                        return Outcome::Failure((Status::Unauthorized, ()));
                    }
                }
            }
        }

        Outcome::Failure((Status::Unauthorized, ()))
    }
}

/// 用于自定义错误响应：`json_msg("密码错误")`
pub fn json_msg(msg: &str) -> Json<serde_json::Value> {
    Json(json!({ "message": msg }))
}

/// 用于调试错误：`json_error(err)`
pub fn json_error<E: std::fmt::Debug>(err: E) -> Json<serde_json::Value> {
    Json(json!({ "message": format!("服务器错误: {:?}", err) }))
}
