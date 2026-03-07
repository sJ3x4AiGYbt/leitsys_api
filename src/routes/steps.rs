use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    db::AppState,
    models::{ApiResponse, Claims, Step, CreateStep, UpdateStep},
};


/// Creates a new review step for the authenticated user.
///
/// `step_order` is calculated automatically (existing MAX + 1).
/// If `color_code` is missing, the default color `#95a5a6` is applied.
///
/// # Errors
/// - `409 Conflict` — step already exists (UNIQUE constraint)
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/steps",
    tag = "steps",
    request_body = CreateStep,
    responses(
        (status = 200, description = "Step created"),
        (status = 409, description = "Step already exists"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_step(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateStep>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let color = payload.color_code.unwrap_or_else(|| "#95a5a6".to_string());

    let max_order: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(step_order), 0) FROM steps WHERE user_id = ?"
    )
    .bind(claims.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let new_order = max_order + 1;

    sqlx::query("INSERT INTO steps (title, step_order, spacing_days, user_id, color_code) VALUES (?, ?, ?, ?, ?)")
    .bind(&payload.title)
    .bind(new_order)
    .bind(payload.spacing_days)
    .bind(claims.user_id)
    .bind(&color)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, Json(ApiResponse::<()>::error("Step already exists")))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string())))
        }
    })?;

    Ok(Json(ApiResponse::<()>::message("Step recorded successfully.")))
}

/// Returns a step by its ID.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/steps/{id}",
    tag = "steps",
    params(("id" = i64, Path, description = "Step ID")),
    responses(
        (status = 200, description = "Step found", body = Step),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_step(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Step>>, (StatusCode, Json<ApiResponse<()>>)> {
    let step = sqlx::query_as::<_, Step>("SELECT title, step_order, spacing_days, user_id, color_code, created_at, modified_at FROM steps WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Step not found"))))?;
    
    if !claims.is_admin && claims.user_id != step.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    Ok(Json(ApiResponse::ok(step)))
}

/// Returns all steps for a user, sorted by `step_order`.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/steps/user/{id}",
    tag = "steps",
    params(("user_id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "User's steps", body = Vec<Step>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_steps(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Step>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    let steps = sqlx::query_as::<_, Step>("SELECT title, step_order, spacing_days, color_code, created_at, modified_at FROM steps WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Steps not found"))))?;

    Ok(Json(ApiResponse::ok(steps)))
}

/// Returns all steps from all users, sorted by `user_id` and `step_order`. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/steps",
    tag = "steps",
    responses(
        (status = 200, description = "All steps (admin only)", body = Vec<Step>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_all_steps(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Step>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    let steps = sqlx::query_as::<_, Step>("SELECT id, title, step_order, spacing_days, user_id, color_code, created_at, modified_at FROM steps ORDER BY user_id, step_order")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(steps)))
}

/// Updates a step (title, order, spacing, color).
///
/// If `step_order` changes, the orders of the other user's steps
/// are automatically reordered within a transaction.
/// The value of `step_order` must be between 1 and the number of existing steps.
///
/// # Errors
/// - `400 Bad Request` — `step_order` out of bounds
/// - `403 Forbidden`   — access denied
/// - `404 Not Found`   — step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    put,
    path = "/steps/{id}",
    tag = "steps",
    params(("id" = i64, Path, description = "Step ID")),
    request_body = UpdateStep,
    responses(
        (status = 200, description = "Step updated"),
        (status = 400, description = "Invalid step_order"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_step(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateStep>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Step>("SELECT * FROM steps WHERE id = ?") // need only title, step_order, spacing_days, user_id, color_code
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Step not found"))))?;

    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if let Some(new_order) = payload.step_order {
        let old_order = existing.step_order;

        if new_order != old_order {
            let max_order: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(step_order), 0) FROM steps WHERE user_id = ?"
            )
            .bind(existing.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

            if new_order < 1 || new_order > max_order {
                return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error(
                    format!("step_order must be between 1 and {}", max_order)
                ))));
            }

            if new_order < old_order {
                sqlx::query(
                    "UPDATE steps SET step_order = step_order + 1 
                     WHERE user_id = ? AND step_order >= ? AND step_order < ? AND id != ?"
                )
                .bind(existing.user_id)
                .bind(new_order)
                .bind(old_order)
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;
            } else {
                sqlx::query(
                    "UPDATE steps SET step_order = step_order - 1 
                     WHERE user_id = ? AND step_order > ? AND step_order <= ? AND id != ?"
                )
                .bind(existing.user_id)
                .bind(old_order)
                .bind(new_order)
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;
            }
        }
    }

    let new_title = payload.title.unwrap_or(existing.title);
    let new_order = payload.step_order.unwrap_or(existing.step_order);
    let new_spacing = payload.spacing_days.unwrap_or(existing.spacing_days);
    let new_color = payload.color_code.unwrap_or(existing.color_code);

    sqlx::query("UPDATE steps SET title = ?, step_order = ?, spacing_days = ?, color_code = ?, modified_at = ? WHERE id = ?")
    .bind(&new_title)
    .bind(new_order)
    .bind(new_spacing)
    .bind(&new_color)
    .bind(Utc::now())
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Step updated successfully.")))
}

/// Deletes a step and reorders the following steps.
///
/// Deletion is refused if:
/// - it is the user's first step
/// - questions are still assigned to this step
///
/// Deletion and reordering are performed within a transaction.
///
/// # Errors
/// - `400 Bad Request` — first step or linked questions
/// - `403 Forbidden`   — access denied
/// - `404 Not Found`   — step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/steps/{id}",
    tag = "steps",
    params(("id" = i64, Path, description = "Step ID")),
    responses(
        (status = 200, description = "Step deleted"),
        (status = 400, description = "Cannot delete (first step or has questions)"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_step(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Step>(
        "SELECT step_order, user_id FROM steps WHERE id = ?"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Step not found"))))?;

    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let min_order: i64 = sqlx::query_scalar("SELECT COALESCE(MIN(step_order), 1) FROM steps WHERE user_id = ?")
        .bind(existing.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if existing.step_order == min_order {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("Cannot delete the first step"))));
    }

    let mut tx = state.db.begin().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    let question_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM questions WHERE current_step_id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if question_count > 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                format!(
                    "Cannot delete this step because some questions are linked to it ({}). Please move them to another step first.",
                    question_count
                )
            ))
        ));
    }

    sqlx::query("DELETE FROM steps WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    sqlx::query(
        "UPDATE steps SET step_order = step_order - 1 WHERE user_id = ? AND step_order > ?"
    )
    .bind(existing.user_id)
    .bind(existing.step_order)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    tx.commit().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Step deleted successfully.")))
}