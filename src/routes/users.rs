use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use bcrypt::{hash, DEFAULT_COST};
use chrono::Utc;
use tower_cookies::{Cookie, Cookies};

use validator::Validate;

use crate::{
    db::AppState,
    mailer::{send_verification_email, send_password_reset_email},
    middleware::{
        generate_access_token, generate_refresh_token, extract_refresh_claims,
        revoke_refresh_session, revoke_all_refresh_sessions,
    },
    models::{
        ApiResponse, Claims, User, CreateUser, UpdateUser, LoginRequest, LoginResponse,
        VerifyEmailRequest, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest,
        validation_error_response,
    },
};

/// Number of consecutive failed login attempts before an account is locked.
const MAX_FAILED_LOGIN_ATTEMPTS: i64 = 5;
/// How long an account stays locked once `MAX_FAILED_LOGIN_ATTEMPTS` is reached.
const LOCKOUT_MINUTES: i64 = 15;
/// How long an email verification link stays valid.
const EMAIL_VERIFICATION_HOURS: i64 = 24;
/// How long a password reset link stays valid. Kept short since, unlike email
/// verification, a leaked link directly grants account takeover.
const PASSWORD_RESET_MINUTES: i64 = 60;

/// Generates a verification token, stores it, and emails the link to the
/// user. Errors are the caller's to decide whether to surface or just log —
/// a failed send shouldn't necessarily fail the request that triggered it.
async fn issue_and_send_verification_email(
    state: &AppState,
    user_id: i64,
    username: &str,
    email: &str,
) -> anyhow::Result<()> {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::hours(EMAIL_VERIFICATION_HOURS);

    sqlx::query("INSERT INTO email_verification_tokens (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&token)
        .bind(user_id)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

    let frontend_origin = std::env::var("FRONTEND_ORIGIN")
        .map_err(|_| anyhow::anyhow!("FRONTEND_ORIGIN environment variable must be set"))?;
    let verification_link = format!("{frontend_origin}/verify-email?token={token}");

    // The token already exists in the DB at this point, which is what
    // actually matters for verification to work. Don't let a slow or
    // unreachable SMTP server hang the HTTP response — send in the
    // background with a timeout instead of awaiting it inline.
    let mailer = state.mailer.clone();
    let mail_from = state.mail_from.clone();
    let email = email.to_string();
    let username = username.to_string();

    tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_verification_email(&mailer, &mail_from, &email, &username, &verification_link),
        )
        .await;

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, %email, "failed to send verification email"),
            Err(_) => tracing::error!(%email, "sending verification email timed out"),
        }
    });

    Ok(())
}

/// Generates a password reset token, stores it, and emails the link to the
/// user. Same fire-and-forget rationale as `issue_and_send_verification_email`.
async fn issue_and_send_password_reset_email(
    state: &AppState,
    user_id: i64,
    username: &str,
    email: &str,
) -> anyhow::Result<()> {
    let token = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(PASSWORD_RESET_MINUTES);

    sqlx::query("INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&token)
        .bind(user_id)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

    let frontend_origin = std::env::var("FRONTEND_ORIGIN")
        .map_err(|_| anyhow::anyhow!("FRONTEND_ORIGIN environment variable must be set"))?;
    let reset_link = format!("{frontend_origin}/reset-password?token={token}");

    let mailer = state.mailer.clone();
    let mail_from = state.mail_from.clone();
    let email = email.to_string();
    let username = username.to_string();

    tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_password_reset_email(&mailer, &mail_from, &email, &username, &reset_link),
        )
        .await;

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, %email, "failed to send password reset email"),
            Err(_) => tracing::error!(%email, "sending password reset email timed out"),
        }
    });

    Ok(())
}

/// Bcrypt hash of an arbitrary, never-used password, computed once per process.
/// Verifying against it when a username doesn't exist keeps the response time
/// close to the "wrong password" path, so timing can't be used to enumerate
/// valid usernames.
static DUMMY_PASSWORD_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dummy_password_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.get_or_init(|| {
        bcrypt::hash("not-a-real-password-timing-decoy", DEFAULT_COST)
            .expect("dummy hash generation should not fail")
    })
}


/// Creates a new user account.
///
/// Password is hashed using bcrypt, then transactionally creates:
/// - the user
/// - 7 default review steps (1, 3, 7, 14, 30, 60, 90 days)
/// - a "Default" category
///
/// # Errors
/// - `422 Unprocessable Entity` — invalid username/email/password (see field rules on `CreateUser`)
/// - `409 Conflict` — username or email already in use
/// - `429 Too Many Requests` — too many registration attempts from this IP
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = CreateUser,
    responses(
        (status = 201, description = "User created"),
        (status = 422, description = "Validation failed"),
        (status = 409, description = "Username or email already taken"),
        (status = 429, description = "Too many requests from this IP"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    Json(mut payload): Json<CreateUser>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), (StatusCode, Json<ApiResponse<()>>)> {
    payload.username = payload.username.trim().to_string();
    payload.email = payload.email.trim().to_lowercase();

    payload.validate().map_err(validation_error_response)?;

    let hashed = hash(&payload.pswd, DEFAULT_COST)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Hashing failed"))))?;

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let user = sqlx::query(
        "INSERT INTO users (username, email, pswd) VALUES (?, ?, ?)",
    )
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&hashed)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, Json(ApiResponse::<()>::error("Username or email already taken")))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string())))
        }
    })?;

    let user_id = user.last_insert_rowid();
    
    let default_steps = [
        (1, 1,  "#e74c3c", "Step 1"),
        (2, 3,  "#e67e22", "Step 2"),
        (3, 7,  "#f1c40f", "Step 3"),
        (4, 14, "#2ecc71", "Step 4"),
        (5, 30, "#1abc9c", "Step 5"),
        (6, 60, "#3498db", "Step 6"),
        (7, 90, "#9b59b6", "Step 7"),
    ];

    for (order, spacing, color, title) in default_steps {
        sqlx::query(
            "INSERT INTO steps (title, step_order, spacing_days, color_code, user_id)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(title)
        .bind(order)
        .bind(spacing)
        .bind(color)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;
    }

    sqlx::query(
        "INSERT INTO categories (title, color_code, user_id) VALUES (?, ?, ?)",
    )
    .bind("Default")
    .bind("#3498db")
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    // The account exists regardless of whether the email actually goes out —
    // a delivery failure shouldn't strand the user with a 500 and no account.
    // /auth/resend-verification covers the case where it didn't arrive.
    if let Err(e) = issue_and_send_verification_email(&state, user_id, &payload.username, &payload.email).await {
        tracing::error!(error = %e, username = %payload.username, "failed to send verification email");
    }

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::<()>::message(
            "User created successfully. Please check your email to verify your account.",
        )),
    ))
}

/// Confirms a user's email address using the token sent by `/auth/register`
/// or `/auth/resend-verification`.
///
/// # Errors
/// - `422 Unprocessable Entity` — malformed token
/// - `400 Bad Request` — token unknown, already used, or expired
/// - `429 Too Many Requests` — too many attempts from this IP
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/auth/verify-email",
    tag = "auth",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified"),
        (status = 422, description = "Validation failed"),
        (status = 400, description = "Invalid, already-used or expired token"),
        (status = 429, description = "Too many requests from this IP"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn verify_email(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    payload.validate().map_err(validation_error_response)?;

    let row = sqlx::query_as::<_, (i64, i64, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)>(
        "SELECT id, user_id, expires_at, used_at FROM email_verification_tokens WHERE token = ?",
    )
    .bind(&payload.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let (token_id, user_id, expires_at, used_at) = row.ok_or((
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::<()>::error("Invalid verification token")),
    ))?;

    if used_at.is_some() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("This verification link has already been used"))));
    }
    if expires_at < Utc::now() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("This verification link has expired"))));
    }

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    sqlx::query("UPDATE users SET email_verified_at = ? WHERE id = ?")
        .bind(Utc::now())
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    sqlx::query("UPDATE email_verification_tokens SET used_at = ? WHERE id = ?")
        .bind(Utc::now())
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Email verified successfully.")))
}

/// Resends the verification email for an unverified account.
///
/// Always returns the same generic message regardless of whether the email
/// is registered or already verified, to avoid leaking account existence —
/// a new email is only actually sent when there's something to verify.
#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    tag = "auth",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Generic acknowledgement (see description)"),
        (status = 422, description = "Validation failed"),
        (status = 429, description = "Too many requests from this IP"),
    )
)]
pub async fn resend_verification(
    State(state): State<AppState>,
    Json(mut payload): Json<ResendVerificationRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    payload.email = payload.email.trim().to_lowercase();
    payload.validate().map_err(validation_error_response)?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, failed_attempts, locked_until, email_verified_at, created_at, modified_at \
         FROM users WHERE email = ?",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if let Some(user) = user {
        if user.email_verified_at.is_none() {
            if let Err(e) = issue_and_send_verification_email(&state, user.id, &user.username, &user.email).await {
                tracing::error!(error = %e, email = %user.email, "failed to resend verification email");
            }
        }
    }

    Ok(Json(ApiResponse::<()>::message(
        "If this email is registered and not yet verified, a new verification link has been sent.",
    )))
}

/// Requests a password reset link for an account.
///
/// Always returns the same generic message regardless of whether the email
/// is registered, to avoid leaking account existence — a reset email is only
/// actually sent when there's an active account behind it.
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    tag = "auth",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Generic acknowledgement (see description)"),
        (status = 422, description = "Validation failed"),
        (status = 429, description = "Too many requests from this IP"),
    )
)]
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(mut payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    payload.email = payload.email.trim().to_lowercase();
    payload.validate().map_err(validation_error_response)?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, failed_attempts, locked_until, email_verified_at, created_at, modified_at \
         FROM users WHERE email = ?",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if let Some(user) = user {
        // A blocked account can't log in even after a reset, so don't hand
        // whoever controls this mailbox a working password for it.
        if !user.is_blocked {
            if let Err(e) = issue_and_send_password_reset_email(&state, user.id, &user.username, &user.email).await {
                tracing::error!(error = %e, email = %user.email, "failed to send password reset email");
            }
        }
    }

    Ok(Json(ApiResponse::<()>::message(
        "If this email is registered, a password reset link has been sent.",
    )))
}

/// Resets a user's password using the token sent by `/auth/forgot-password`.
///
/// Revokes every existing refresh session for the account, so any
/// stolen-but-unused refresh token stops working immediately.
///
/// # Errors
/// - `422 Unprocessable Entity` — malformed token or password not meeting policy
/// - `400 Bad Request` — token unknown, already used, or expired
/// - `429 Too Many Requests` — too many attempts from this IP
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/auth/reset-password",
    tag = "auth",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset"),
        (status = 422, description = "Validation failed"),
        (status = 400, description = "Invalid, already-used or expired token"),
        (status = 429, description = "Too many requests from this IP"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    payload.validate().map_err(validation_error_response)?;

    let row = sqlx::query_as::<_, (i64, i64, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>)>(
        "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token = ?",
    )
    .bind(&payload.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let (token_id, user_id, expires_at, used_at) = row.ok_or((
        StatusCode::BAD_REQUEST,
        Json(ApiResponse::<()>::error("Invalid password reset token")),
    ))?;

    if used_at.is_some() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("This password reset link has already been used"))));
    }
    if expires_at < Utc::now() {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("This password reset link has expired"))));
    }

    let hashed = hash(&payload.pswd, DEFAULT_COST)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Hashing failed"))))?;

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    sqlx::query("UPDATE users SET pswd = ?, failed_attempts = 0, locked_until = NULL, modified_at = ? WHERE id = ?")
        .bind(&hashed)
        .bind(Utc::now())
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    sqlx::query("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?")
        .bind(Utc::now())
        .bind(token_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    revoke_all_refresh_sessions(&state.db, user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Password reset successfully.")))
}

/// Authenticates a user.
///
/// Returns an access token (15 min) in the response body
/// and sets a HttpOnly refresh token cookie (7 days, Path=/auth).
///
/// After `MAX_FAILED_LOGIN_ATTEMPTS` consecutive wrong passwords, the account
/// is locked for `LOCKOUT_MINUTES` minutes. Every failed attempt (unknown
/// username, wrong password, blocked or locked account) is logged via
/// `tracing::warn!`.
///
/// An unknown username still runs a bcrypt verification (against a decoy
/// hash) before responding, so response time doesn't reveal whether the
/// username exists.
///
/// # Errors
/// - `422 Unprocessable Entity` — empty/oversized username or password
/// - `401 Unauthorized` — invalid credentials
/// - `403 Forbidden`    — account is blocked, temporarily locked, or email not yet verified
/// - `500 Internal Server Error` — database or token error
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Access token + HttpOnly refresh cookie", body = LoginResponse),
        (status = 422, description = "Validation failed"),
        (status = 401, description = "Invalid credentials"),
        (status = 403, description = "Account is blocked, temporarily locked, or email not verified"),
        (status = 429, description = "Too many requests from this IP"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(mut payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    payload.username = payload.username.trim().to_string();

    payload.validate().map_err(validation_error_response)?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, failed_attempts, locked_until, email_verified_at, created_at, modified_at \
         FROM users WHERE username = ?",
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let user = match user {
        Some(user) => user,
        None => {
            // Same cost as a real password check, so a missing username
            // doesn't respond measurably faster than a wrong password.
            let _ = bcrypt::verify(&payload.pswd, dummy_password_hash());
            tracing::warn!(username = %payload.username, "login failed: unknown username");
            return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("Invalid credentials"))));
        }
    };

    if user.is_blocked {
        tracing::warn!(username = %user.username, "login failed: account is blocked");
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Account is blocked"))));
    }

    if let Some(locked_until) = user.locked_until {
        if locked_until > Utc::now() {
            tracing::warn!(username = %user.username, %locked_until, "login failed: account temporarily locked");
            return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Account temporarily locked due to too many failed attempts. Try again later."))));
        }
    }

    let valid = bcrypt::verify(&payload.pswd, &user.pswd)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Verification failed"))))?;

    if !valid {
        let attempts = user.failed_attempts + 1;
        let locked_until = if attempts >= MAX_FAILED_LOGIN_ATTEMPTS {
            Some(Utc::now() + chrono::Duration::minutes(LOCKOUT_MINUTES))
        } else {
            None
        };
        let attempts_after_lock = if locked_until.is_some() { 0 } else { attempts };

        sqlx::query("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?")
            .bind(attempts_after_lock)
            .bind(locked_until)
            .bind(user.id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

        if locked_until.is_some() {
            tracing::warn!(username = %user.username, attempts, "login failed: too many attempts, account locked for {LOCKOUT_MINUTES} minutes");
        } else {
            tracing::warn!(username = %user.username, attempts, "login failed: invalid password");
        }

        return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("Invalid credentials"))));
    }

    if user.failed_attempts != 0 || user.locked_until.is_some() {
        sqlx::query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
            .bind(user.id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;
    }

    // Checked after the password to avoid leaking verification status to
    // anyone who doesn't already know the password.
    if user.email_verified_at.is_none() {
        tracing::warn!(username = %user.username, "login failed: email not verified");
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error("Please verify your email address before logging in")),
        ));
    }

    let access_token = generate_access_token(user.id, &user.username, user.is_admin, &state.jwt_secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;
 
    let refresh_token = generate_refresh_token(&state.db, user.id, &state.jwt_secret)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;
 
    let mut cookie = Cookie::new("refresh_token", refresh_token);
    cookie.set_http_only(true);
    cookie.set_secure(true);
    // Frontend and API run on different origins (different ports/hosts), so the
    // cookie must be sent on cross-site fetch requests — `Strict` or `Lax` would
    // silently prevent the browser from ever sending it back to the API.
    cookie.set_same_site(tower_cookies::cookie::SameSite::None);
    cookie.set_path("/auth");
    cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
    cookies.add(cookie);
 
    Ok(Json(ApiResponse::ok(LoginResponse { access_token })))
}
 
/// Renews the access token using the HttpOnly refresh cookie.
///
/// The browser sends the cookie automatically — no JS access needed.
/// Also verifies that the account is not blocked before issuing a new token.
///
/// The refresh token is single-use: this endpoint revokes the one it was
/// called with and issues a new one (rotation), so a stolen-but-unused
/// refresh token stops working the moment the legitimate client refreshes.
///
/// # Errors
/// - `401 Unauthorized` — cookie absent, invalid, expired or already used/revoked
/// - `403 Forbidden`    — account is blocked, or the request's Origin/Referer
///   doesn't match `FRONTEND_ORIGIN` (CSRF check)
/// - `500 Internal Server Error` — database or token error
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "New access token + rotated HttpOnly refresh cookie", body = LoginResponse),
        (status = 401, description = "Missing, invalid or already-used refresh token"),
        (status = 403, description = "Account is blocked, or Origin/Referer check failed"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<ApiResponse<LoginResponse>>, (StatusCode, Json<ApiResponse<()>>)> {
    let refresh_token = cookies
        .get("refresh_token")
        .map(|c| c.value().to_string())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("No refresh token")),
        ))?;

    let claims = extract_refresh_claims(&state.db, &refresh_token, &state.jwt_secret)
        .await
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid or expired refresh token")),
        ))?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, failed_attempts, locked_until, email_verified_at, created_at, modified_at \
         FROM users WHERE id = ?",
    )
    .bind(claims.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("User not found"))))?;

    if user.is_blocked {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Account is blocked"))));
    }

    revoke_refresh_session(&state.db, &claims.jti)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let access_token = generate_access_token(user.id, &user.username, user.is_admin, &state.jwt_secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;

    let new_refresh_token = generate_refresh_token(&state.db, user.id, &state.jwt_secret)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;

    let mut cookie = Cookie::new("refresh_token", new_refresh_token);
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(tower_cookies::cookie::SameSite::None);
    cookie.set_path("/auth");
    cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
    cookies.add(cookie);

    Ok(Json(ApiResponse::ok(LoginResponse { access_token })))
}

/// Logs out the current user: revokes the refresh session tied to the
/// cookie (if any) and expires the cookie itself.
///
/// The backend sets `Max-Age=0` on the cookie — the browser suppresses it immediately.
/// The access token in memory on the frontend must be cleared client-side.
///
/// # Errors
/// - `403 Forbidden` — the request's Origin/Referer doesn't match `FRONTEND_ORIGIN` (CSRF check)
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logged out, session revoked and cookie cleared"),
        (status = 403, description = "Origin/Referer check failed"),
    )
)]
pub async fn logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    if let Some(token) = cookies.get("refresh_token").map(|c| c.value().to_string()) {
        if let Some(claims) = extract_refresh_claims(&state.db, &token, &state.jwt_secret).await {
            let _ = revoke_refresh_session(&state.db, &claims.jti).await;
        }
    }

    let cookie = Cookie::build(("refresh_token", ""))
        .path("/auth")
        .max_age(tower_cookies::cookie::time::Duration::seconds(0))
        .build();
    cookies.remove(cookie);
 
    Json(ApiResponse::<()>::message("Logged out"))
}

/// Returns a user profile by its ID.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — user not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "User found", body = User),
        (status = 403, description = "Access denied"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<User>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))))?;

    Ok(Json(ApiResponse::ok(user)))
}

/// Returns the list of all users, sorted by `id`. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/users",
    tag = "users",
    responses(
        (status = 200, description = "All users (admin only)", body = Vec<User>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_all_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<User>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let users = sqlx::query_as::<_, User>("SELECT id, username, email, pswd, is_admin, is_blocked, failed_attempts, locked_until, email_verified_at, created_at, modified_at FROM users ORDER BY id")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(users)))
}

/// Updates a user profile (username, email and/or password).
///
/// Fields missing from the payload keep their current value.
///
/// # Errors
/// - `422 Unprocessable Entity` — invalid username/email/password (see field rules on `UpdateUser`)
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — user not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    put,
    path = "/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    request_body = UpdateUser,
    responses(
        (status = 200, description = "User updated"),
        (status = 422, description = "Validation failed"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(mut payload): Json<UpdateUser>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    payload.username = payload.username.map(|u| u.trim().to_string());
    payload.email = payload.email.map(|e| e.trim().to_lowercase());

    payload.validate().map_err(validation_error_response)?;

    let existing = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))))?;

    let password_changed = payload.pswd.is_some();
    let new_pswd = if let Some(p) = payload.pswd {
        hash(p, DEFAULT_COST)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Hashing failed"))))?
    } else {
        existing.pswd.clone()
    };

    let new_username = payload.username.unwrap_or(existing.username);
    let new_email = payload.email.unwrap_or(existing.email);
    let now = Utc::now();

    sqlx::query("UPDATE users SET username = ?, email = ?, pswd = ?, modified_at = ? WHERE id = ?")
    .bind(&new_username)
    .bind(&new_email)
    .bind(&new_pswd)
    .bind(now)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    // A stolen refresh token issued before a password change must stop
    // working immediately, not stay valid until it naturally expires.
    if password_changed {
        revoke_all_refresh_sessions(&state.db, id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;
    }

    Ok(Json(ApiResponse::<()>::message("User updated successfully.")))
}

/// Toggles the `is_admin` flag of a user. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — user not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    patch,
    path = "/users/{id}/admin",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "Admin flag toggled"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mark_admin(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let result = sqlx::query("UPDATE users SET is_admin = NOT is_admin, modified_at = ? WHERE id = ?")
    .bind(Utc::now())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))));
    }

    Ok(Json(ApiResponse::<()>::message("User status changed to admin.")))
}

/// Toggles the `is_blocked` flag of a user. Admin only.
///
/// A blocked user can no longer log in.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — user not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    patch,
    path = "/users/{id}/block",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "Blocked flag toggled"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mark_blocked(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let result = sqlx::query("UPDATE users SET is_blocked = NOT is_blocked, modified_at = ? WHERE id = ?")
    .bind(Utc::now())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))));
    }

    Ok(Json(ApiResponse::<()>::message("User blocked successfully.")))
}

/// Permanently deletes a user account.
///
/// This triggers a cascade deletion of all related data
/// (categories, steps, questions, answers).
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — user not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/users/{id}",
    tag = "users",
    params(("id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "User deleted"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))));
    }

    Ok(Json(ApiResponse::<()>::message("User deleted successfully.")))
}