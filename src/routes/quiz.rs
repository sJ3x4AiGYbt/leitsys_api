use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::Utc;
use validator::Validate;

use crate::{
    db::AppState,
    models::{
        validation_error_response, ApiResponse, AttemptResult, Claims, ImportMode, ImportQuiz,
        ImportReport, QuizAttempt, QuizQuestion, QuizQuestionRow,
    },
    quiz_parser::{self, ParsedQuestion},
};

type ApiError = (StatusCode, Json<ApiResponse<()>>);

fn internal(e: impl ToString) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(e.to_string())))
}

/// Loads a quiz question and checks it belongs to the caller. Banks are
/// private, so there is no admin override here.
async fn owned_question(state: &AppState, id: i64, claims: &Claims) -> Result<QuizQuestionRow, ApiError> {
    let row = sqlx::query_as::<_, QuizQuestionRow>("SELECT * FROM quiz_questions WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ApiResponse::<()>::error("Quiz question not found"))))?;

    if row.user_id != claims.user_id {
        return Err((StatusCode::FORBIDDEN, Json(ApiResponse::<()>::error("Access denied"))));
    }

    Ok(row)
}

/// Returns the caller's quiz bank with their progress on each question,
/// sorted by quiz number.
///
/// # Errors
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    get,
    path = "/quiz/questions",
    tag = "quiz",
    responses(
        (status = 200, description = "Caller's quiz bank", body = Vec<QuizQuestion>),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_quiz_questions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<Vec<QuizQuestion>>>, ApiError> {
    let rows = sqlx::query_as::<_, QuizQuestionRow>(
        "SELECT * FROM quiz_questions WHERE user_id = ? ORDER BY num, id",
    )
    .bind(claims.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(internal)?;

    Ok(Json(ApiResponse::ok(rows.into_iter().map(QuizQuestion::from).collect())))
}

/// Parses quizzes in the text format and adds them to the caller's bank.
///
/// - `add` (default) inserts only the questions not already in the bank
///   (same prompt and option texts).
/// - `replace` makes the bank exactly the imported questions; those already
///   present are updated in place and keep their progress.
/// - `dry_run` only returns the report, so the client can show
///   "N new, M already in the bank" before choosing.
///
/// # Errors
/// - `400 Bad Request` — no valid question in the text
/// - `422 Unprocessable Entity` — empty or oversized text
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/quiz/import",
    tag = "quiz",
    request_body = ImportQuiz,
    responses(
        (status = 200, description = "Import report", body = ImportReport),
        (status = 400, description = "No valid question found"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn import_quiz(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ImportQuiz>,
) -> Result<Json<ApiResponse<ImportReport>>, ApiError> {
    payload.validate().map_err(validation_error_response)?;

    let parsed = quiz_parser::parse(&payload.text);
    if parsed.questions.is_empty() {
        let message = if parsed.invalid > 0 {
            format!("No usable question found: {} block(s) are missing a prompt, two answers or the correct answer.", parsed.invalid)
        } else {
            "No question found. Expected lines like \"* Question : …\", \"* Answer A : …\", \"* Correct answer : A\".".to_string()
        };
        return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<()>::error(message))));
    }

    // Keep the first occurrence of a question repeated within the text.
    let mut seen = HashSet::new();
    let unique: Vec<&ParsedQuestion> = parsed.questions.iter().filter(|q| seen.insert(q.qkey.as_str())).collect();

    let mut tx = state.db.begin().await.map_err(internal)?;

    let existing: Vec<(i64, String)> = sqlx::query_as("SELECT id, qkey FROM quiz_questions WHERE user_id = ?")
        .bind(claims.user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(internal)?;
    let existing_keys: HashSet<&str> = existing.iter().map(|(_, k)| k.as_str()).collect();
    let fresh = unique.iter().filter(|q| !existing_keys.contains(q.qkey.as_str())).count();

    let mut report = ImportReport {
        read: parsed.questions.len(),
        invalid: parsed.invalid,
        unique: unique.len(),
        fresh,
        added: 0,
        total: existing.len(),
    };

    if payload.dry_run {
        return Ok(Json(ApiResponse::ok(report)));
    }

    if payload.mode == ImportMode::Replace {
        let imported_keys: HashSet<&str> = unique.iter().map(|q| q.qkey.as_str()).collect();
        for (id, key) in &existing {
            if !imported_keys.contains(key.as_str()) {
                sqlx::query("DELETE FROM quiz_questions WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
            }
        }
    }

    // `add` leaves questions already in the bank untouched; `replace` refreshes
    // their category, details and answer key from the imported text.
    let on_conflict = match payload.mode {
        ImportMode::Add => "DO NOTHING",
        ImportMode::Replace => {
            "DO UPDATE SET num = excluded.num, category = excluded.category, prompt = excluded.prompt, \
             options = excluded.options, correct = excluded.correct, modified_at = excluded.modified_at"
        }
    };
    let insert_sql = format!(
        "INSERT INTO quiz_questions (user_id, num, category, prompt, options, correct, qkey, modified_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id, qkey) {on_conflict}"
    );
    let now = Utc::now();

    for q in &unique {
        let options = serde_json::to_string(&q.options).map_err(internal)?;
        sqlx::query(&insert_sql)
            .bind(claims.user_id)
            .bind(q.num)
            .bind(&q.category)
            .bind(&q.prompt)
            .bind(options)
            .bind(q.correct.join(","))
            .bind(&q.qkey)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    }

    report.added = fresh;
    report.total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM quiz_questions WHERE user_id = ?")
        .bind(claims.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)? as usize;

    tx.commit().await.map_err(internal)?;

    Ok(Json(ApiResponse::ok(report)))
}

/// Deletes one question from the caller's bank.
///
/// # Errors
/// - `403 Forbidden` — not the caller's question
/// - `404 Not Found` — question not found
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/quiz/questions/{id}",
    tag = "quiz",
    params(("id" = i64, Path, description = "Quiz question ID")),
    responses(
        (status = 200, description = "Question deleted"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question not found"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_quiz_question(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    owned_question(&state, id, &claims).await?;

    sqlx::query("DELETE FROM quiz_questions WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(internal)?;

    Ok(Json(ApiResponse::<()>::message("Quiz question deleted successfully.")))
}

/// Deletes every question of the caller's bank.
///
/// # Errors
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/quiz/questions",
    tag = "quiz",
    responses(
        (status = 200, description = "Bank emptied"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn clear_quiz_bank(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query("DELETE FROM quiz_questions WHERE user_id = ?")
        .bind(claims.user_id)
        .execute(&state.db)
        .await
        .map_err(internal)?;

    Ok(Json(ApiResponse::<()>::message("Quiz bank emptied.")))
}

/// Records an answer to a question and returns whether it was right.
///
/// `selected` uses the original letters of the options, whatever order the
/// client displayed them in. The answer is right only if exactly the correct
/// letters were picked.
///
/// # Errors
/// - `403 Forbidden` — not the caller's question
/// - `404 Not Found` — question not found
/// - `422 Unprocessable Entity` — no letter selected
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    post,
    path = "/quiz/questions/{id}/attempt",
    tag = "quiz",
    params(("id" = i64, Path, description = "Quiz question ID")),
    request_body = QuizAttempt,
    responses(
        (status = 200, description = "Attempt recorded", body = AttemptResult),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Question not found"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn submit_quiz_attempt(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<QuizAttempt>,
) -> Result<Json<ApiResponse<AttemptResult>>, ApiError> {
    payload.validate().map_err(validation_error_response)?;

    let question = QuizQuestion::from(owned_question(&state, id, &claims).await?);

    let mut selected: Vec<String> = payload.selected.iter().map(|l| l.trim().to_uppercase()).collect();
    selected.sort();
    selected.dedup();
    let correct = selected == question.correct;

    sqlx::query(
        "UPDATE quiz_questions SET attempts = attempts + 1, successes = successes + ?, \
         last_correct = ?, last_answered_at = ? WHERE id = ?",
    )
    .bind(correct as i64)
    .bind(correct)
    .bind(Utc::now())
    .bind(id)
    .execute(&state.db)
    .await
    .map_err(internal)?;

    Ok(Json(ApiResponse::ok(AttemptResult { correct, correct_letters: question.correct })))
}

/// Resets the caller's progress on every question of their bank.
///
/// # Errors
/// - `500 Internal Server Error` — database error
#[utoipa::path(
    delete,
    path = "/quiz/progress",
    tag = "quiz",
    responses(
        (status = 200, description = "Progress reset"),
        (status = 500, description = "Internal error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_quiz_progress(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    sqlx::query(
        "UPDATE quiz_questions SET attempts = 0, successes = 0, last_correct = NULL, last_answered_at = NULL \
         WHERE user_id = ?",
    )
    .bind(claims.user_id)
    .execute(&state.db)
    .await
    .map_err(internal)?;

    Ok(Json(ApiResponse::<()>::message("Quiz progress reset.")))
}
