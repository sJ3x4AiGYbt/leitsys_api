mod db;
mod models;
mod middleware;
mod rate_limit;
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
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret_change_me".into());

    let state = db::AppState {
        db: pool,
        jwt_secret,
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