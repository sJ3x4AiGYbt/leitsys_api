use bcrypt::{hash, DEFAULT_COST};
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

/// Creates the first admin account when the `users` table is empty.
///
/// Reads `ADMIN_USERNAME`, `ADMIN_EMAIL` and `ADMIN_PASSWORD` from the
/// environment. If any of them is missing, seeding is skipped (a fresh
/// database just stays empty, no error). This avoids the chicken-and-egg
/// problem where `PATCH /users/{id}/admin` requires an existing admin.
pub async fn seed_admin(pool: &SqlitePool) -> anyhow::Result<()> {
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if user_count > 0 {
        return Ok(());
    }

    let (username, email, password) = match (
        env::var("ADMIN_USERNAME"),
        env::var("ADMIN_EMAIL"),
        env::var("ADMIN_PASSWORD"),
    ) {
        (Ok(u), Ok(e), Ok(p)) => (u, e, p),
        _ => {
            tracing::warn!(
                "No users in database and ADMIN_USERNAME/ADMIN_EMAIL/ADMIN_PASSWORD \
                 are not all set — skipping admin seed."
            );
            return Ok(());
        }
    };

    let hashed = hash(&password, DEFAULT_COST)?;

    let mut tx = pool.begin().await?;

    let result = sqlx::query(
        "INSERT INTO users (username, email, pswd, is_admin) VALUES (?, ?, ?, TRUE)",
    )
    .bind(&username)
    .bind(&email)
    .bind(&hashed)
    .execute(&mut *tx)
    .await?;

    let user_id = result.last_insert_rowid();

    let default_steps = [
        (1, 1, "#e74c3c", "Step 1"),
        (2, 3, "#e67e22", "Step 2"),
        (3, 7, "#f1c40f", "Step 3"),
        (4, 14, "#2ecc71", "Step 4"),
        (5, 30, "#1abc9c", "Step 5"),
        (6, 60, "#3498db", "Step 6"),
        (7, 90, "#9b59b6", "Step 7"),
    ];

    for (order, spacing, color, title) in default_steps {
        sqlx::query(
            "INSERT INTO steps (title, step_order, spacing_days, color_code, user_id) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(title)
        .bind(order)
        .bind(spacing)
        .bind(color)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("INSERT INTO categories (title, color_code, user_id) VALUES (?, ?, ?)")
        .bind("Default")
        .bind("#3498db")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::info!("Seeded initial admin user '{username}'.");

    Ok(())
}
