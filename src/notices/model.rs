use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct NoticeBase {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct Notice {
    pub id: i64,
    pub title: String,
    pub content: String,
    pub author: String,
    pub created_at: String,
}
