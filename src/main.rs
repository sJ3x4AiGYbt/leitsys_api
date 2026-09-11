mod db;
mod models;
mod middleware;
mod rate_limit;
mod csrf;
mod mailer;
mod routes;
mod cors;
mod swagger;

use std::env;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = db::create_pool().await?;
    db::seed_admin(&pool).await?;

    // No fallback: a missing/weak secret would mean every token in prod is
    // signed with a value visible in the source code. Fail fast instead.
    let jwt_secret = env::var("JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("JWT_SECRET environment variable must be set"))?;
    if jwt_secret.len() < 32 {
        anyhow::bail!("JWT_SECRET must be at least 32 characters long");
    }

    let mailer = mailer::build_mailer()?;
    let mail_from = mailer::required_env("SMTP_FROM")?;

    let state = db::AppState {
        db: pool,
        jwt_secret,
        mailer,
        mail_from,
    };

    let app = routes::build_router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}