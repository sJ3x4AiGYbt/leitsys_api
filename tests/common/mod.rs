// Each tests/*.rs file only uses a subset of these helpers; the rest would
// otherwise warn as dead code in that particular test binary.
#![allow(dead_code)]

use std::net::SocketAddr;

use axum::{body::Body, extract::ConnectInfo, http::Request, http::StatusCode, Router};
use http_body_util::BodyExt;
use lettre::{transport::smtp::authentication::Credentials, AsyncSmtpTransport, Tokio1Executor};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;

use leitsys_api::db::{self, AppState};
use leitsys_api::middleware;
use leitsys_api::routes;

pub const TEST_JWT_SECRET: &str = "test-secret-at-least-32-characters-long!!";

/// Boots a full router against a fresh in-memory database (migrated, no
/// seeded data beyond what registration itself creates).
pub async fn spawn_app() -> (Router, SqlitePool) {
    // `cors::cors_layer()` reads this directly at router-build time and
    // panics if it's unset. Every test sets the same value, so the lack of
    // synchronization across threads is harmless.
    unsafe {
        std::env::set_var("FRONTEND_ORIGIN", "http://localhost:8080");
    }

    // A pool of more than one connection to `sqlite::memory:` would silently
    // scatter data across separate, mostly-empty databases — one per
    // connection — since each connection gets its own in-memory database.
    let pool = db::connect_with("sqlite::memory:", 1)
        .await
        .expect("failed to set up the in-memory test database");

    // Never actually sent to; routes exercised by these tests don't trigger
    // real email delivery, and `relay()` only sets up TLS config, no I/O.
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay("localhost")
        .expect("failed to build the test mailer")
        .credentials(Credentials::new("test".into(), "test".into()))
        .build();

    let state = AppState {
        db: pool.clone(),
        jwt_secret: TEST_JWT_SECRET.to_string(),
        mailer,
        mail_from: "test@example.com".to_string(),
    };

    (routes::build_router(state), pool)
}

/// Registers a fresh user through the real `/auth/register` handler (which
/// seeds their 7 default steps + default category, exactly like production),
/// then mints a valid Bearer token directly — sidestepping the
/// email-verification gate, since these tests target business logic, not
/// the auth flow itself.
pub async fn register_and_login(router: &Router, pool: &SqlitePool, username: &str) -> (i64, String) {
    let body = json!({
        "username": username,
        "email": format!("{username}@example.com"),
        "pswd": "TestPass123!",
    });

    let (status, response) = post(router, "/auth/register", None, body).await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {response:?}");

    let user_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
        .expect("just-registered user should exist");

    let token = middleware::generate_access_token(user_id, username, false, TEST_JWT_SECRET)
        .expect("failed to mint a test access token");

    (user_id, token)
}

/// `register_and_login` returns an owned `String`; every helper below wants
/// `Option<&str>`, and `Some(&token)` alone doesn't coerce `&String` to
/// `&str` through the `Option` wrapper — call sites use `tok(&token)` instead.
pub fn tok(token: &str) -> Option<&str> {
    Some(token)
}

async fn request(router: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    let mut request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    // The rate limiter on /auth/* extracts the client IP via `ConnectInfo`,
    // normally injected by `into_make_service_with_connect_info` over a real
    // socket. `oneshot` bypasses that, so it's inserted by hand here.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };

    if status.is_server_error() {
        eprintln!("{method} {uri} -> {status}: {parsed}");
    }

    (status, parsed)
}

pub async fn post(router: &Router, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    request(router, "POST", uri, token, Some(body)).await
}

pub async fn get(router: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    request(router, "GET", uri, token, None).await
}

pub async fn put(router: &Router, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    request(router, "PUT", uri, token, Some(body)).await
}

pub async fn patch(router: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    request(router, "PATCH", uri, token, None).await
}

pub async fn delete(router: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    request(router, "DELETE", uri, token, None).await
}

/// Finds the single item in a `{"data": [...]}` list response whose `field`
/// equals `value` (compared as a JSON string).
pub fn find_by<'a>(list_response: &'a Value, field: &str, value: &str) -> &'a Value {
    list_response["data"]
        .as_array()
        .expect("expected a data array")
        .iter()
        .find(|item| item[field] == value)
        .unwrap_or_else(|| panic!("no item with {field} == {value} in {list_response}"))
}

/// Returns the `data` array of a list response sorted by `step_order`.
pub fn sorted_by_step_order(list_response: &Value) -> Vec<Value> {
    let mut items: Vec<Value> = list_response["data"].as_array().expect("expected a data array").clone();
    items.sort_by_key(|item| item["step_order"].as_i64().unwrap());
    items
}
