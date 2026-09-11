use bcrypt::{hash, DEFAULT_COST};
use sqlx::{SqlitePool, sqlite::{SqlitePoolOptions, SqliteConnectOptions}};
use std::env;
use std::str::FromStr;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub jwt_secret: String,
}

pub async fn create_pool() -> anyhow::Result<SqlitePool> {
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:./leitsys.db".into());
    let connect_options = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;
    run_migrations(&pool).await?;

    Ok(pool)
}

/// Migrations are embedded at compile time and applied in order. Each one is
/// recorded by filename in `_migrations` so re-running on an existing database
/// (e.g. `ALTER TABLE` in a later migration) only ever executes once.
const MIGRATIONS: &[(&str, &str)] = &[
    ("001_init.sql", include_str!("../data/001_init.sql")),
    ("002_login_security.sql", include_str!("../data/002_login_security.sql")),
    ("003_refresh_sessions.sql", include_str!("../data/003_refresh_sessions.sql")),
];

async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            filename TEXT PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;

    for (filename, sql) in MIGRATIONS {
        let already_applied: Option<String> =
            sqlx::query_scalar("SELECT filename FROM _migrations WHERE filename = ?")
                .bind(filename)
                .fetch_optional(pool)
                .await?;

        if already_applied.is_some() {
            continue;
        }

        // Strip full-line comments before splitting on ';' — otherwise a
        // comment glued to the following statement (no blank line/semicolon
        // between them) makes the whole chunk start with "--" and silently
        // drops the statement instead of just the comment.
        let sql_without_comments: String = sql
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");

        for stmt in sql_without_comments.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                sqlx::query(stmt).execute(pool).await?;
            }
        }

        sqlx::query("INSERT INTO _migrations (filename) VALUES (?)")
            .bind(filename)
            .execute(pool)
            .await?;
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
