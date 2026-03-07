use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;

use crate::{
    db::AppState,
    models::{Answer, ApiResponse, Claims, CreateAnswer, UpdateAnswer, Question},
};


/// Records an answer to a question.
///
/// Automatically computes:
/// - `days_since_last_answer` : days since the last answer to this question
/// - `days_since_creation`    : days since the question was created
/// - `late_spacing_days`      : number of days late compared to `next_review_date`
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — question or previous answer not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/answers",
    tag = "answers",
    request_body = CreateAnswer,
    responses(
        (status = 200, description = "Answer recorded"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question or previous answer not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_answer(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateAnswer>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let question = sqlx::query_as::<_, Question>("SELECT id, user_id, next_review_date, created_at FROM questions WHERE id = ?")
        .bind(payload.question_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && question.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let last = sqlx::query_as::<_, Answer>("SELECT user_id, created_at FROM answers WHERE id_question = ? ORDER BY created_at DESC LIMIT 1")
        .bind(question.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))))?;
    
    if !claims.is_admin && last.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let now = Utc::now();
    let days_since_last_answer = last.created_at.map(|d| (now - d).num_days()).unwrap_or(0);
    let days_since_creation = question.created_at.map(|d| (now - d).num_days()).unwrap_or(0);
    let late_spacing_days = if question.next_review_date < now {
        (now - question.next_review_date).num_days()
    } else {
        0
    };

    sqlx::query("INSERT INTO answers (question_id, user_id, user_response, step, days_since_last_answer, days_since_creation, late_spacing_days) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(&payload.question_id)
    .bind(claims.user_id)
    .bind(&payload.user_response)
    .bind(&payload.step)
    .bind(days_since_last_answer)
    .bind(days_since_creation)
    .bind(late_spacing_days)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Answer recorded successfully.")))
}

/// Returns an answer by its ID.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — answer not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/answers/{id}",
    tag = "answers",
    params(("id" = i64, Path, description = "Answer ID")),
    responses(
        (status = 200, description = "Answer found", body = Answer),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Answer not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_answer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Answer>>, (StatusCode, Json<ApiResponse<()>>)> {    
    let answer = sqlx::query_as::<_, Answer>("SELECT question_id, user_id, user_response, step, days_since_last_answer, days_since_creation, is_correct, created_at FROM answers WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))))?;

    if !claims.is_admin && claims.user_id != answer.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    Ok(Json(ApiResponse::ok(answer)))
}

/// Returns all answers for a given user, sorted by `created_at`.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/answers/user/{id}",
    tag = "answers",
    params(("user_id" = i64, Path, description = "User ID")),
    responses(
        (status = 200, description = "User's answers", body = Vec<Answer>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_answers(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Answer>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin && claims.user_id != user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let answers = sqlx::query_as::<_, Answer>("SELECT question_id, user_id, user_response, step, days_since_last_answer, days_since_creation, is_correct, created_at FROM answers WHERE user_id = ? ORDER BY created_at")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("answers not found"))))?;

    Ok(Json(ApiResponse::ok(answers)))
}

/// Returns all answers from all users, sorted by `user_id` and `created_at`. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/answers",
    tag = "answers",
    responses(
        (status = 200, description = "All answers (admin only)", body = Vec<Answer>),
        (status = 403, description = "Access denied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_all_answers(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<Answer>>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }
    
    let answers = sqlx::query_as::<_, Answer>("SELECT question_id, user_id, user_response, step, days_since_last_answer, days_since_creation, is_correct, created_at FROM answers ORDER BY user_id, created_at")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::ok(answers)))
}

/// Updates the text content of an answer. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — answer not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    put,
    path = "/answers/{id}",
    tag = "answers",
    params(("id" = i64, Path, description = "Answer ID")),
    request_body = UpdateAnswer,
    responses(
        (status = 200, description = "Answer updated"),
        (status = 403, description = "Admin only"),
        (status = 404, description = "Answer not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_answer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateAnswer>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let existing = sqlx::query_as::<_, Answer>("SELECT id, user_response FROM answers WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))))?;

    let new_response = payload.user_response.or(existing.user_response).unwrap_or_default();
    let now = Utc::now();

    sqlx::query("UPDATE answers SET user_response = ?, modified_at = ? WHERE id = ?")
    .bind(&new_response)
    .bind(now)
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Answer updated successfully.")))
}

/// Marks an answer as correct and advances the question through the steps.
///
/// - If a next step exists: `current_step_id` is advanced and `next_review_date`
///   is recalculated based on the `spacing_days` of the new step.
/// - If it was the last step: the question is archived (`is_archived = TRUE`)
///   and `next_review_date` is set to `NULL`.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — ranswer or question not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    patch,
    path = "/answers/{id}/correct",
    tag = "answers",
    params(("id" = i64, Path, description = "Answer ID")),
    responses(
        (status = 200, description = "Correct — question moved to next step (or archived if last step)"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Answer or question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn good_answer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let answer = sqlx::query_as::<_, Answer>("SELECT question_id, user_id FROM answers WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))))?;

    if !claims.is_admin && answer.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let question = sqlx::query_as::<_, Question>("SELECT user_id, current_step_id FROM questions WHERE id = ?")
        .bind(answer.question_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && question.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let next_step = sqlx::query_as::<_, (i64, i64)>(
        "SELECT id, spacing_days FROM steps
         WHERE user_id = ? AND step_order > (
             SELECT step_order FROM steps WHERE id = ?
         )
         ORDER BY step_order ASC LIMIT 1",
    )
    .bind(claims.user_id)
    .bind(question.current_step_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    match next_step {
        Some((next_step_id, spacing_days)) => {
            let next_date = Utc::now() + chrono::Duration::days(spacing_days);
            sqlx::query(
                "UPDATE questions SET current_step_id = ?, next_review_date = ?, modified_at = ?
                 WHERE id = ?",
            )
            .bind(next_step_id)
            .bind(next_date)
            .bind(Utc::now())
            .bind(answer.question_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?
        }
        None => {
            sqlx::query(
                "UPDATE questions SET is_archived = TRUE, next_review_date = NULL, modified_at = ?
                 WHERE id = ?",
            )
            .bind(Utc::now())
            .bind(answer.question_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?
        }
    };

    Ok(Json(ApiResponse::<()>::message("Correct answer! Question moved to the next step.")))
}

/// Marks an answer as incorrect and resets the question to the first step.
///
/// `current_step_id` is reset to the user's first step
/// and `next_review_date` is recalculated accordingly.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — answer, question, or step not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    patch,
    path = "/answers/{id}/error",
    tag = "answers",
    params(("id" = i64, Path, description = "Answer ID")),
    responses(
        (status = 200, description = "Incorrect — question reset to first step"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Answer or question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn bad_answer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let answer = sqlx::query_as::<_, Answer>("SELECT * FROM answers WHERE id = ?") // besoin que de : question_id, user_id
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))))?;

    if !claims.is_admin && answer.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let question = sqlx::query_as::<_, Question>("SELECT user_id FROM questions WHERE id = ?")
        .bind(answer.question_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Question not found"))))?;

    if !claims.is_admin && question.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let (first_step_id, spacing_days) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT id, spacing_days FROM steps WHERE user_id = ? ORDER BY step_order ASC LIMIT 1",
    )
    .bind(claims.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("No step found for this user"))))?;

    let next_date = Utc::now() + chrono::Duration::days(spacing_days);

    sqlx::query("UPDATE questions SET current_step_id = ?, next_review_date = ?, modified_at = ? WHERE id = ?")
    .bind(first_step_id)
    .bind(next_date)
    .bind(Utc::now())
    .bind(answer.question_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    Ok(Json(ApiResponse::<()>::message("Incorrect answer. Question reset to the first step.")))
}

/// Permanently deletes an answer. Admin only.
///
/// # Errors
/// - `403 Forbidden` — access denied
/// - `404 Not Found` — answer not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/answers/{id}",
    tag = "answers",
    params(("id" = i64, Path, description = "Answer ID")),
    responses(
        (status = 200, description = "Answer deleted"),
        (status = 403, description = "Admin only"),
        (status = 404, description = "Answer not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_answer(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    if !claims.is_admin {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    let result = sqlx::query("DELETE FROM answers WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string()))))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Answer not found"))));
    }

    Ok(Json(ApiResponse::<()>::message("Answer deleted successfully.")))
}