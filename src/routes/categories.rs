use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    db::AppState,
    models::{ApiResponse, Claims, Category, CreateCategory, UpdateCategory},
};


/// Creates a new category for the authenticated user.
///
/// If `color_code` is missing, the default color `#3498db` is applied.
///
/// # Errors
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/categories",
    tag = "categories",
    request_body = CreateCategory,
    responses(
        (status = 200, description = "Category created"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_category(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateCategory>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let color = payload.color_code.unwrap_or_else(|| "#3498db".to_string());

    sqlx::query("INSERT INTO categories (title, user_id, color_code) VALUES (?, ?, ?)")
    .bind(&payload.title)
    .bind(claims.user_id)
    .bind(&color)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Category recorded successfully.")))
}

/// Returns a category by its ID.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — category not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/categories/{id}",
    tag = "categories",
    params(("id" = i64, Path, description = "Category ID")),
    responses(
        (status = 200, description = "Category found", body = Category),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Category not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_category(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Category>>, (StatusCode, Json<ApiResponse<()>>)> {    
    let category = sqlx::query_as::<_, Category>("SELECT * FROM categories WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Category not found"))))?;

    if !claims.is_admin && claims.user_id != category.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    Ok(Json(ApiResponse::ok(category)))
}

/// Returns all categories for a given user, sorted by `created_at`.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/categories/user/{id}",
    tag = "categories",
    params(("user_id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "User's categories", body = Vec<Category>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_categories(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Category>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let categories = sqlx::query_as::<_, Category>("SELECT * FROM categories WHERE user_id = ? ORDER BY created_at")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Categories not found"))))?;

    Ok(Json(ApiResponse::ok(categories)))
}

/// Returns all categories from all users, sorted by `user_id` and `created_at`. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/categories",
    tag = "categories",
    responses(
        (status = 200, description = "All categories (admin only)", body = Vec<Category>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_all_categories(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Category>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    let categories = sqlx::query_as::<_, Category>("SELECT id, title, user_id, color_code, created_at, modified_at FROM categories ORDER BY user_id, created_at")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(categories)))
}

/// Updates the title and/or color of a category.
///
/// Fields missing from the payload keep their current value.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — category not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    put,
    path = "/categories/{id}",
    tag = "categories",
    params(("id" = i64, Path, description = "Category ID")),
    request_body = UpdateCategory,
    responses(
        (status = 200, description = "Category updated"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Category not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_category(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateCategory>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Category>("SELECT * FROM categories WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Category not found"))))?;


    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let new_title = payload.title.unwrap_or(existing.title);
    let new_color = payload.color_code.unwrap_or(existing.color_code);

    sqlx::query("UPDATE categories SET title = ?, color_code = ?, modified_at = ? WHERE id = ?")
    .bind(&new_title)
    .bind(&new_color)
    .bind(Utc::now())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Category updated successfully.")))
}

/// Deletes a category.
///
/// Deletion is refused if:
/// - it is the first category created by the user (default category)
/// - questions are still attached to it
///
/// # Errors
/// - `400 Bad Request` — default category or linked questions
/// - `403 Forbidden`   — access denied
/// - `404 Not Found`   — category not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/categories/{id}",
    tag = "categories",
    params(("id" = i64, Path, description = "Category ID")),
    responses(
        (status = 200, description = "Category deleted"),
        (status = 400, description = "Cannot delete (default or has questions)"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Category not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_category(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Category>("SELECT * FROM categories WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Category not found"))))?;

    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let default_category = sqlx::query_scalar::<_, i64>("SELECT id FROM categories WHERE user_id = ? ORDER BY created_at ASC LIMIT 1")
        .bind(existing.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if existing.id == default_category {
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error("Cannot delete the first category"))));
    }

    let question_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM questions WHERE category_id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if question_count > 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                format!(
                    "Cannot delete this category because {} question(s) are linked to it. Please move them to another category first.",
                    question_count
                )
            ))
        ));
    }

    sqlx::query("DELETE FROM categories WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Category deleted successfully.")))
}