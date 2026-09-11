use crate::models::{Claims, RefreshClaims};
use axum::{
    Json,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::AppState;

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t.to_string(),
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "message": "Missing Authorization header"})),
            ));
        }
    };

    let claims = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "message": "Invalid or expired token"})),
        )
    })?
    .claims;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

pub fn generate_access_token(
    user_id: i64,
    username: &str,
    is_admin: bool,
    secret: &str,
) -> anyhow::Result<String> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(15))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        user_id,
        username: username.to_string(),
        is_admin,
        exp: expiration,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

/// Issues a refresh token and records its `jti` as an active session row, so
/// it can later be individually revoked (logout, rotation, password change)
/// instead of staying valid for anyone who steals it until it expires.
pub async fn generate_refresh_token(
    pool: &SqlitePool,
    user_id: i64,
    secret: &str,
) -> anyhow::Result<String> {
    let jti = Uuid::new_v4().to_string();
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(7))
        .expect("valid timestamp");

    sqlx::query("INSERT INTO refresh_sessions (jti, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&jti)
        .bind(user_id)
        .bind(expiration)
        .execute(pool)
        .await?;

    let claims = RefreshClaims {
        user_id,
        jti,
        exp: expiration.timestamp() as usize,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

/// Decodes and validates the JWT signature/expiry, then checks that its
/// session hasn't been revoked. Both checks must pass for the token to be
/// usable.
pub async fn extract_refresh_claims(
    pool: &SqlitePool,
    token: &str,
    secret: &str,
) -> Option<RefreshClaims> {
    let claims = decode::<RefreshClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?
    .claims;

    let active: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM refresh_sessions WHERE jti = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind(&claims.jti)
    .bind(claims.user_id)
    .fetch_optional(pool)
    .await
    .ok()?;

    active.map(|_| claims)
}

pub async fn revoke_refresh_session(pool: &SqlitePool, jti: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE refresh_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE jti = ? AND revoked_at IS NULL")
        .bind(jti)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revokes every active session for a user — used on password change so a
/// refresh token issued before the change stops working immediately.
pub async fn revoke_all_refresh_sessions(pool: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE refresh_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}