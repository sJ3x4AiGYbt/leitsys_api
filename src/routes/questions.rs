use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    db::AppState,
    models::{ApiResponse, Claims, Question, CreateQuestion, GetQuestionsParams, UpdateQuestion},
};


/// Creates a new question for the authenticated user.
///
/// If `category_id` or `current_step_id` are missing, the user's default values
/// are used (category default and first step).
/// `next_review_date` is calculated from the `spacing_days` of the chosen step.
///
/// # Errors
/// - `403 Forbidden` — the category or step does not belong to the user
/// - `404 Not Found` — category or step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/questions",
    tag = "questions",
    request_body = CreateQuestion,
    responses(
        (status = 200, description = "Question created"),
        (status = 403, description = "Category or step does not belong to you"),
        (status = 404, description = "Category or step not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_question(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateQuestion>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let category_id = match payload.category_id {
        Some(id) => {
            let owner = sqlx::query_scalar::<_, i64>(
                "SELECT user_id FROM categories WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Category not found"))))?;

            if owner != claims.user_id {
                return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Category does not belong to you"))));
            }
            id
        }
        None => sqlx::query_scalar::<_, i64>(
            "SELECT id FROM categories WHERE user_id = ? ORDER BY created_at ASC LIMIT 1",
        )
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("No category found for this user"))))?,
    };

    let (current_step_id, spacing_days) = match payload.current_step_id {
        Some(id) => {
            let step = sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT id, spacing_days, user_id FROM steps WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Step not found"))))?;

            if step.2 != claims.user_id {
                return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Step does not belong to you"))));
            }
            (step.0, step.1)
        }
        None => sqlx::query_as::<_, (i64, i64)>(
            "SELECT id, spacing_days FROM steps WHERE user_id = ? ORDER BY step_order ASC LIMIT 1",
        )
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("No step found for this user"))))?,
    };

    let next_review_date = Utc::now() + chrono::Duration::days(spacing_days);

    sqlx::query("INSERT INTO questions (title, answer, category_id, current_step_id, user_id, next_review_date) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(&payload.title)
    .bind(&payload.answer)
    .bind(category_id)
    .bind(current_step_id)
    .bind(claims.user_id)
    .bind(next_review_date)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Question recorded successfully.")))
}

/// Returns a question by its ID.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — question not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/questions/{id}",
    tag = "questions",
    params(("id" = i64, Path, description = "Question ID")),
    responses(
        (status = 200, description = "Question found", body = Question),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Question>>, (StatusCode, Json<ApiResponse<()>>)> {
    let question = sqlx::query_as::<_, Question>("SELECT title, answer, category_id, current_step_id, user_id, next_review_date, is_archived, created_at, modified_at FROM questions WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && claims.user_id != question.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    Ok(Json(ApiResponse::ok(question)))
}

/// Returns a user's questions with optional filters, sorted by `created_at` (ascending).
///
/// # Query parameters
/// - `status`      : `"todo"` (due today) or `"late"` (overdue)
/// - `date`        : exact `next_review_date` (ISO 8601)
/// - `from` / `to` : date range on `next_review_date`
/// - `category_id` : filter by category
/// - `step_id`     : filter by current step
/// - `is_archived` : filter by archived status
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/questions/user/{id}",
    tag = "questions",
    params(
        ("id_user" = i64, Path, description = "User ID"),
        ("status"      = Option<String>, Query, description = "Filter: `todo` (due today) or `late` (overdue)"),
        ("date"        = Option<String>, Query, description = "Exact next_review_date (ISO 8601)"),
        ("from"        = Option<String>, Query, description = "next_review_date >= from"),
        ("to"          = Option<String>, Query, description = "next_review_date <= to"),
        ("category_id" = Option<i64>,    Query, description = "Filter by category"),
        ("step_id"     = Option<i64>,    Query, description = "Filter by current step"),
        ("is_archived" = Option<bool>,   Query, description = "Filter by archived flag"),
    ),
    responses(
        (status = 200, description = "User's questions", body = Vec<Question>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_questions(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<GetQuestionsParams>,
) -> Result<Json<ApiResponse<Vec<Question>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let today = Utc::now();

    let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT title, answer, category_id, current_step_id, user_id, next_review_date, is_archived, created_at, modified_at FROM questions WHERE user_id = "
    );
    qb.push_bind(claims.user_id);
    qb.push(" AND is_completed = FALSE");

    match params.status.as_deref() {
        Some("todo") => {
            qb.push(" AND is_archived = FALSE AND next_review_date <= ");
            qb.push_bind(today);
        }
        Some("late") => {
            qb.push(" AND is_archived = FALSE AND next_review_date < ");
            qb.push_bind(today);
        }
        _ => {}
    }

    if let Some(date) = params.date {
        qb.push(" AND next_review_date = ");
        qb.push_bind(date);
    }

    if let Some(from) = params.from {
        qb.push(" AND next_review_date >= ");
        qb.push_bind(from);
    }

    if let Some(to) = params.to {
        qb.push(" AND next_review_date <= ");
        qb.push_bind(to);
    }

    if let Some(category_id) = params.category_id {
        qb.push(" AND category_id = ");
        qb.push_bind(category_id);
    }

    if let Some(step_id) = params.step_id {
        qb.push(" AND current_step_id = ");
        qb.push_bind(step_id);
    }

    if let Some(is_archived) = params.is_archived {
        qb.push(" AND is_archived = ");
        qb.push_bind(is_archived);
    }

    qb.push(" ORDER BY created_at ASC");

    let questions = qb
        .build_query_as::<Question>()
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(questions)))
}

/// Returns all questions from all users, sorted by `created_at` (descending). Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/questions",
    tag = "questions",
    responses(
        (status = 200, description = "All questions (admin only)", body = Vec<Question>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_all_questions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Question>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let questions = sqlx::query_as::<_, Question>("SELECT id, title, answer, category_id, current_step_id, user_id, next_review_date, is_archived, is_completed, created_at, modified_at FROM questions ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(questions)))
}

/// Updates the title, answer, category, and/or step of a question.
///
/// If `current_step_id` changes, `next_review_date` is recalculated immediately.
/// Fields missing from the payload keep their current value.
///
/// # Errors
/// - `403 Forbidden` — access denied or foreign resource
/// - `404 Not Found` — question, category, or step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    put,
    path = "/questions/{id}",
    tag = "questions",
    params(("id" = i64, Path, description = "Question ID")),
    request_body = UpdateQuestion,
    responses(
        (status = 200, description = "Question updated"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateQuestion>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Question>("SELECT title, answer, category_id, current_step_id, user_id, next_review_date, is_archived FROM questions WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let new_title = payload.title.unwrap_or(existing.title);
    let new_answer = payload.answer.unwrap_or(existing.answer);

    let category_id = match payload.category_id {
        Some(id) => {
            let owner = sqlx::query_scalar::<_, i64>(
                "SELECT user_id FROM categories WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Category not found"))))?;

            if owner != claims.user_id {
                return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Category does not belong to you"))));
            }
            id
        }
        None => existing.category_id,
    };

    let (current_step_id, new_date) = match payload.current_step_id {
        Some(id) => {
            let step = sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT id, spacing_days, user_id FROM steps WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Step not found"))))?;

            if step.2 != claims.user_id {
                return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Step does not belong to you"))));
            }
            let new_date = Utc::now() + chrono::Duration::days(step.1);
            (step.0, new_date)
        }
        None => (existing.current_step_id, existing.next_review_date),
    };

    sqlx::query("UPDATE questions SET title = ?, answer = ?, category_id = ?, current_step_id = ?, next_review_date = ?, modified_at = ? WHERE id = ?")
    .bind(&new_title)
    .bind(&new_answer)
    .bind(category_id)
    .bind(current_step_id)
    .bind(new_date)
    .bind(Utc::now())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Question updated successfully.")))
}

/// Permanently deletes a question and all associated answers.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — question not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/questions/{id}",
    tag = "questions",
    params(("id" = i64, Path, description = "Question ID")),
    responses(
        (status = 200, description = "Question deleted"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let existing = sqlx::query_as::<_, Question>("SELECT user_id FROM questions WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && existing.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    sqlx::query("DELETE FROM questions WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Question deleted successfully.")))
}