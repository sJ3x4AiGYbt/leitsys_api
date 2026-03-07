use utoipa::OpenApi;

use crate::models::{
    User, CreateUser, UpdateUser, LoginRequest, LoginResponse,
    Category, CreateCategory, UpdateCategory,
    Step, CreateStep, UpdateStep,
    Question, CreateQuestion, UpdateQuestion, GetQuestionsParams,
    Answer, CreateAnswer, UpdateAnswer,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Leitsys",
        version = "0.1.0",
        description = "Learning with Leitner System. API Rust Axum. Authentication via Bearer JWT token. Good reading."
    ),
    paths(
        // Auth
        crate::routes::users::create_user,
        crate::routes::users::login,
        // Users
        crate::routes::users::get_user,
        crate::routes::users::get_all_users,
        crate::routes::users::update_user,
        crate::routes::users::delete_user,
        crate::routes::users::mark_admin,
        crate::routes::users::mark_blocked,
        // Categories
        crate::routes::categories::create_category,
        crate::routes::categories::get_category,
        crate::routes::categories::get_my_categories,
        crate::routes::categories::get_all_categories,
        crate::routes::categories::update_category,
        crate::routes::categories::delete_category,
        // Steps
        crate::routes::steps::create_step,
        crate::routes::steps::get_step,
        crate::routes::steps::get_my_steps,
        crate::routes::steps::get_all_steps,
        crate::routes::steps::update_step,
        crate::routes::steps::delete_step,
        // Questions
        crate::routes::questions::create_question,
        crate::routes::questions::get_question,
        crate::routes::questions::get_my_questions,
        crate::routes::questions::get_all_questions,
        crate::routes::questions::update_question,
        crate::routes::questions::delete_question,
        // Answers
        crate::routes::answers::create_answer,
        crate::routes::answers::get_answer,
        crate::routes::answers::get_my_answers,
        crate::routes::answers::get_all_answers,
        crate::routes::answers::update_answer,
        crate::routes::answers::delete_answer,
        crate::routes::answers::good_answer,
        crate::routes::answers::bad_answer,
    ),
    components(
        schemas(
            User, CreateUser, UpdateUser, LoginRequest, LoginResponse,
            Category, CreateCategory, UpdateCategory,
            Step, CreateStep, UpdateStep,
            Question, CreateQuestion, UpdateQuestion, GetQuestionsParams,
            Answer, CreateAnswer, UpdateAnswer,
        )
    ),
    tags(
        (name = "auth",       description = "Registration and login"),
        (name = "users",      description = "User management"),
        (name = "categories", description = "Questions categories"),
        (name = "steps",      description = "Questions spaced-repetition steps"),
        (name = "questions",  description = "Questions"),
        (name = "answers",    description = "Answers and review workflow"),
    ),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer,
                ),
            ),
        );
    }
}