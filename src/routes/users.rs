use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use bcrypt::{hash, DEFAULT_COST};
use chrono::Utc;
use tower_cookies::{Cookie, Cookies};

use crate::{
    db::AppState,
    middleware::{generate_access_token, generate_refresh_token, extract_refresh_claims},
    models::{ApiResponse, Claims, User, CreateUser, UpdateUser, LoginRequest, LoginResponse},
};


/// Creates a new user account.
///
/// Password is hashed using bcrypt, then transactionally creates:
/// - the user
/// - 7 default review steps (1, 3, 7, 14, 30, 60, 90 days)
/// - a "Default" category
///
/// # Errors
/// - `409 Conflict` — username or email already in use
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = CreateUser,
    responses(
        (status = 201, description = "User created"),
        (status = 409, description = "Username or email already taken"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUser>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), (StatusCode, Json<ApiResponse<()>>)> {
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

    Ok((StatusCode::CREATED, Json(ApiResponse::<()>::message("User created successfully."))))
}

/// Authenticates a user.
///
/// Returns an access token (15 min) in the response body
/// and sets a HttpOnly refresh token cookie (7 days, Path=/auth).
///
/// # Errors
/// - `401 Unauthorized` — invalid credentials
/// - `403 Forbidden`    — account is blocked
/// - `500 Internal Server Error` — database or token error
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Access token + HttpOnly refresh cookie", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 403, description = "Account is blocked"),
        (status = 500, description = "Internal error"),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiResponse<()>>)> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, created_at, modified_at \
         FROM users WHERE username = ?",
    )
    .bind(&payload.username)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("Invalid credentials"))))?;
 
    if user.is_blocked {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Account is blocked"))));
    }
 
    let valid = bcrypt::verify(&payload.pswd, &user.pswd)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Verification failed"))))?;
 
    if !valid {
        return Err((StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("Invalid credentials"))));
    }
 
    let access_token = generate_access_token(user.id, &user.username, user.is_admin, &state.jwt_secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;
 
    let refresh_token = generate_refresh_token(user.id, &state.jwt_secret)
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
/// # Errors
/// - `401 Unauthorized` — cookie absent, invalid or expired
/// - `403 Forbidden`    — account is blocked
/// - `500 Internal Server Error` — database or token error
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "New access token", body = LoginResponse),
        (status = 401, description = "Missing or invalid refresh token"),
        (status = 403, description = "Account is blocked"),
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
 
    let claims = extract_refresh_claims(&refresh_token, &state.jwt_secret)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("Invalid or expired refresh token")),
        ))?;
 
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, pswd, is_admin, is_blocked, created_at, modified_at \
         FROM users WHERE id = ?",
    )
    .bind(claims.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ApiResponse::<()>::error("User not found"))))?;
 
    if user.is_blocked {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Account is blocked"))));
    }
 
    let access_token = generate_access_token(user.id, &user.username, user.is_admin, &state.jwt_secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error("Token generation failed"))))?;
 
    Ok(Json(ApiResponse::ok(LoginResponse { access_token })))
}

/// Logs out the current user by expiring the refresh token cookie.
///
/// The backend sets `Max-Age=0` on the cookie — the browser suppresses it immediately.
/// The access token in memory on the frontend must be cleared client-side.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logged out, cookie revoked"),
    )
)]
pub async fn logout(cookies: Cookies) -> impl IntoResponse {
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

    let users = sqlx::query_as::<_, User>("SELECT id, username, email, pswd, is_admin, is_blocked, created_at, modified_at FROM users ORDER BY id")
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
    Json(payload): Json<UpdateUser>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let existing = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("User not found"))))?;

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