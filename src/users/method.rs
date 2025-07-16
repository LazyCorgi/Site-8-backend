use argon2::{Argon2, PasswordHash, PasswordVerifier};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};

use rocket::serde::json::Json;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::model::Claims;

const SECRET: &[u8] = b"my_secret_key_please_change_me"; // 改成你自己的密钥，存到环境变量中更安全

pub fn generate_jwt(username: &str) -> Result<String, jsonwebtoken::errors::Error> {
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
}

pub fn verify_jwt(token: &str) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET),
        &Validation::default(),
    )
}

pub async fn verify_password(stored_hash: &str, input_password: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(input_password.as_bytes(), &parsed_hash)
            .is_ok(),
        Err(_) => false,
    }
}

/// usused now, but useful in your own route.
pub struct AuthenticatedUser(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = Status;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let auth_header = req.headers().get_one("Authorization");

        if let Some(auth_header) = auth_header {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                match verify_jwt(token) {
                    Ok(token_data) => {
                        return request::Outcome::Success(AuthenticatedUser(token_data.claims.sub));
                    }
                    Err(_) => {
                        return request::Outcome::Error((
                            Status::Unauthorized,
                            Status::Unauthorized,
                        ));
                    }
                }
            }
        }

        request::Outcome::Error((Status::Unauthorized, Status::Unauthorized))
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

/// 用于JWT错误处理
pub fn json_jwt_error(err: jsonwebtoken::errors::Error) -> Json<serde_json::Value> {
    let message = match err.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token已过期",
        jsonwebtoken::errors::ErrorKind::InvalidToken => "无效的Token",
        jsonwebtoken::errors::ErrorKind::InvalidSignature => "Token签名无效",
        _ => "Token验证失败",
    };
    Json(json!({ "message": message }))
}
