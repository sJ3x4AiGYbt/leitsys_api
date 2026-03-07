use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::env;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub jwt_secret: String,
}

pub async fn create_pool() -> anyhow::Result<SqlitePool> {
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:./leitsys.db".into());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;
    run_migrations(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    let migrations = include_str!("../data/001_init.sql");

    for stmt in migrations.split(';') {
        let stmt = stmt.trim();
        if !stmt.is_empty() && !stmt.starts_with("--") {
            sqlx::query(stmt).execute(pool).await?;
        }
    }

    Ok(())
}
