use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{State, get, post};
use sqlx::SqlitePool;
use std::result::Result;

use super::model::{Notice, NoticeBase};
// use super::model::NoticeResponse;

#[post("/notices", format = "json", data = "<notice>")]
pub async fn create_notice(
    pool: &State<SqlitePool>,
    notice: Json<NoticeBase>,
) -> Result<Status, Status> {
    let now: String = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query!(
        r#"
        INSERT INTO notices (title, content, author, created_at) VALUES (?, ?, ?, ?)"#,
        notice.title,
        notice.content,
        "admin",
        now
    )
    .execute(pool.inner())
    .await
    .map_err(|_| Status::InternalServerError)?;
    // .map_err(|_| rocket::http::Status::InternalServerError)?;
    Ok(Status::Created)
}

#[get("/notices")]
pub async fn get_notices(pool: &State<SqlitePool>) -> Json<Vec<Notice>> {
    let notices = sqlx::query_as!(
        Notice,
        r#"
        SELECT id, title, content, author, created_at
        FROM notices
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool.inner())
    .await
    .unwrap_or_else(|err| {
        println!("查询失败: {:?}", err);
        vec![]
    });

    Json(notices)
}
