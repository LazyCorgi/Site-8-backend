use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use rand::rngs::OsRng;
use sqlx::SqlitePool;

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect("sqlite://data.db")
        .await
        .expect("连接数据库失败");

    let username = "admin";
    let raw_password = "123456";

    // 加密密码
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(raw_password.as_bytes(), &salt)
        .expect("密码加密失败")
        .to_string();

    let existing: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) as count FROM users WHERE username = ?",
        username
    )
    .fetch_one(&pool)
    .await
    .expect("检查用户存在失败");

    if existing == 0 {
        sqlx::query!(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            username,
            password_hash
        )
        .execute(&pool)
        .await
        .expect("插入失败");

        println!(
            "✅ 用户 `{}` 添加成功，初始密码：{}",
            username, raw_password
        );
    } else {
        println!("⚠️ 用户 `{}` 已存在，跳过添加", username);
    }
}
