use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ─── User ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub pswd: String,
    pub is_admin: bool,
    pub is_blocked: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub pswd: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    pub pswd: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub pswd: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
}

// ─── Category ─────────────────────────────────────────────────────────────────

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

// ─── Step ─────────────────────────────────────────────────────────────────────

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

// ─── Question ─────────────────────────────────────────────────────────────────

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

// ─── Answer ───────────────────────────────────────────────────────────────────

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

// ─── JWT Claims ───────────────────────────────────────────────────────────────

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
    pub exp: usize,
}

// ─── Generic responses ────────────────────────────────────────────────────────

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
