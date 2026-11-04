use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        Ok(())
    } else {
        Err(ValidationError::new(
            "username may only contain letters, digits, '_', '-' and '.'",
        ))
    }
}

const PASSWORD_SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`\"'\\";

/// bcrypt silently truncates anything past 72 bytes, so that limit is enforced
/// explicitly here rather than letting extra characters be accepted then ignored.
/// The rest follows an OWASP-style complexity baseline: length plus all four
/// character classes, rather than just length + one letter/digit.
fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() > 72 {
        return Err(ValidationError::new(
            "password must not exceed 72 bytes",
        ));
    }
    if password.chars().count() < 10 {
        return Err(ValidationError::new(
            "password must be at least 10 characters long",
        ));
    }
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| PASSWORD_SPECIAL_CHARS.contains(c));
    if !has_lower || !has_upper || !has_digit || !has_special {
        return Err(ValidationError::new(
            "password must contain at least one lowercase letter, one uppercase letter, one digit and one special character",
        ));
    }
    Ok(())
}

// ─── User

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub pswd: String,
    pub is_admin: bool,
    pub is_blocked: bool,
    #[serde(skip_serializing)]
    pub failed_attempts: i64,
    #[serde(skip_serializing)]
    pub locked_until: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct CreateUser {
    /// 3-32 characters. Letters, digits, `_`, `-` and `.` only.
    #[validate(length(min = 3, max = 32), custom(function = "validate_username"))]
    pub username: String,
    #[validate(email, length(max = 254))]
    pub email: String,
    /// 10-72 bytes. Must contain at least one lowercase letter, one uppercase
    /// letter, one digit and one special character.
    #[validate(custom(function = "validate_password"))]
    pub pswd: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct UpdateUser {
    /// 3-32 characters. Letters, digits, `_`, `-` and `.` only.
    #[validate(length(min = 3, max = 32), custom(function = "validate_username"))]
    pub username: Option<String>,
    #[validate(email, length(max = 254))]
    pub email: Option<String>,
    /// 10-72 bytes. Must contain at least one lowercase letter, one uppercase
    /// letter, one digit and one special character.
    #[validate(custom(function = "validate_password"))]
    pub pswd: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, max = 64))]
    pub username: String,
    #[validate(length(min = 1, max = 128))]
    pub pswd: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1, max = 128))]
    pub token: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ResendVerificationRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1, max = 128))]
    pub token: String,
    /// 10-72 bytes. Must contain at least one lowercase letter, one uppercase
    /// letter, one digit and one special character.
    #[validate(custom(function = "validate_password"))]
    pub pswd: String,
}

// ─── Category 

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Category {
    pub id: i64,
    pub title: String,
    pub user_id: i64,
    pub color_code: String,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCategory {
    pub title: String,
    pub color_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCategory {
    pub title: Option<String>,
    pub color_code: Option<String>,
}

// ─── Step

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Step {
    pub id: i64,
    pub title: String,
    pub step_order: i64,
    pub spacing_days: i64,
    pub user_id: i64,
    pub color_code: String,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateStep {
    pub title: String,
    pub spacing_days: i64,
    pub color_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateStep {
    pub title: Option<String>,
    pub step_order: Option<i64>,
    pub spacing_days: Option<i64>,
    pub color_code: Option<String>,
}

// ─── Question 

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Question {
    pub id: i64,
    pub title: String,
    pub answer: String,
    pub category_id: i64,
    pub current_step_id: i64,
    pub user_id: i64,
    pub next_review_date: DateTime<Utc>,
    pub is_archived: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateQuestion {
    pub title: String,
    pub answer: String,
    pub current_step_id: Option<i64>,
    pub category_id: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct GetQuestionsParams {
    pub status: Option<String>, // "todo", "late"
    pub date: Option<DateTime<Utc>>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub category_id: Option<i64>,
    pub step_id: Option<i64>,
    pub is_archived: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateQuestion {
    pub title: Option<String>,
    pub answer: Option<String>,
    pub category_id: Option<i64>,
    pub current_step_id: Option<i64>,
}

// ─── Answer ──

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Answer {
    pub id: i64,
    pub question_id: i64,
    pub user_id: i64,
    pub user_response: Option<String>,
    pub step: i64,
    pub is_correct: bool,
    pub days_since_last_answer: i64,
    pub days_since_creation: i64,
    pub late_spacing_days: i64,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAnswer {
    pub question_id: i64,
    pub user_response: String,
    pub step: i64,
    pub is_correct: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAnswer {
    pub user_response: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedAnswer {
    pub id: i64,
}

// ─── Quiz

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct QuizOption {
    /// Original letter, `A` to `H`.
    pub letter: String,
    pub text: String,
    /// Explanation shown once the question is answered. Empty if none.
    #[serde(default)]
    pub detail: String,
}

/// Raw `quiz_questions` row: `options` is JSON and `correct` a
/// comma-separated letter list, both decoded into `QuizQuestion`.
#[derive(Debug, sqlx::FromRow)]
pub struct QuizQuestionRow {
    pub id: i64,
    pub user_id: i64,
    pub num: i64,
    pub category: String,
    pub prompt: String,
    pub options: String,
    pub correct: String,
    pub attempts: i64,
    pub successes: i64,
    pub last_correct: Option<bool>,
    pub last_answered_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuizQuestion {
    pub id: i64,
    /// The `N` of the `Quiz N` header it was imported from.
    pub num: i64,
    /// e.g. `Rootkits / Detection`.
    pub category: String,
    pub prompt: String,
    pub options: Vec<QuizOption>,
    /// Letters of the correct options, sorted.
    pub correct: Vec<String>,
    pub attempts: i64,
    pub successes: i64,
    /// `null` if never answered.
    pub last_correct: Option<bool>,
    pub last_answered_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

impl From<QuizQuestionRow> for QuizQuestion {
    fn from(row: QuizQuestionRow) -> Self {
        Self {
            id: row.id,
            num: row.num,
            category: row.category,
            prompt: row.prompt,
            options: serde_json::from_str(&row.options).unwrap_or_default(),
            correct: row.correct.split(',').filter(|l| !l.is_empty()).map(String::from).collect(),
            attempts: row.attempts,
            successes: row.successes,
            last_correct: row.last_correct,
            last_answered_at: row.last_answered_at,
            created_at: row.created_at,
            modified_at: row.modified_at,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Keep the bank, insert only the questions not already in it.
    #[default]
    Add,
    /// Make the bank exactly the imported questions. Questions present in
    /// both keep their progress.
    Replace,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ImportQuiz {
    /// Quizzes in the text format (`Quiz N`, `* Category :`, `* Question :`,
    /// `* Answer A :`, `* Detail answer A :`, `* Correct answer :`, `---`).
    #[validate(length(min = 1, max = 1_000_000))]
    pub text: String,
    #[serde(default)]
    pub mode: ImportMode,
    /// Only report what the import would do, without writing anything.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportReport {
    /// Valid questions found in the text.
    pub read: usize,
    /// Blocks skipped for lack of a prompt, two options or a correct answer.
    pub invalid: usize,
    /// Distinct questions among `read` (what `replace` would keep).
    pub unique: usize,
    /// Distinct questions not already in the bank (what `add` would insert).
    pub fresh: usize,
    /// Questions actually inserted. Always 0 on a dry run.
    pub added: usize,
    /// Bank size after the import (current size on a dry run).
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct QuizAttempt {
    /// Letters picked, using the original letters (`QuizOption::letter`).
    #[validate(length(min = 1, max = 8))]
    pub selected: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttemptResult {
    pub correct: bool,
    pub correct_letters: Vec<String>,
}

// ─── JWT Claims 

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub user_id: i64,
    pub username: String,
    pub is_admin: bool,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshClaims {
    pub user_id: i64,
    /// Unique ID of the `refresh_sessions` row backing this token — lets a
    /// single refresh token be revoked (logout, password change, rotation)
    /// without invalidating every token signed with this secret.
    pub jti: String,
    pub exp: usize,
}

// ─── Generic responses 

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }
    pub fn message(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            message: Some(msg.into()),
        }
    }
    pub fn error(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(msg.into()),
        }
    }
}

pub fn validation_error_response(
    errors: validator::ValidationErrors,
) -> (axum::http::StatusCode, axum::Json<ApiResponse<()>>) {
    let message = errors
        .field_errors()
        .into_iter()
        .map(|(field, errs)| {
            let reasons: Vec<String> = errs
                .iter()
                .map(|e| {
                    e.message
                        .clone()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| e.code.to_string())
                })
                .collect();
            format!("{field}: {}", reasons.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");

    (
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        axum::Json(ApiResponse::<()>::error(message)),
    )
}
