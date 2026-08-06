pub mod answers;
pub mod categories;
pub mod questions;
pub mod steps;
pub mod users;

use axum::{
    Router, 
    middleware as axum_middleware,
    routing::{get, patch, post},
};
use tower_http::trace::TraceLayer;
use tower_cookies::CookieManagerLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::{SwaggerUi, Config};

use crate::db::AppState;
use crate::middleware;
use crate::cors;
use crate::swagger::ApiDoc;
use crate::routes::{
    answers::{
        bad_answer, create_answer, delete_answer, get_all_answers, get_answer, get_my_answers,
        good_answer, update_answer,
    },
    categories::{
        create_category, delete_category, get_all_categories, get_category, get_my_categories,
        update_category,
    },
    questions::{
        create_question, delete_question, get_all_questions, get_my_questions, get_question,
        update_question,
    },
    steps::{
        create_step, delete_step, get_all_steps, get_my_steps, get_step, update_step,
    },
    users::{
        create_user, delete_user, get_all_users, get_user, login, logout, mark_admin, mark_blocked, 
        refresh, update_user,
    },    
};


pub fn build_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(create_user));

    let auth_cookie_routes = Router::new()
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout));

    let user_routes = Router::new()
        .route("/users", get(get_all_users))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/{id}/admin", patch(mark_admin))
        .route("/users/{id}/block", patch(mark_blocked))
        .route("/questions", post(create_question).get(get_all_questions))
        .route(
            "/questions/{id}",
            get(get_question)
                .put(update_question)
                .delete(delete_question),
        )
        .route("/questions/user/{id}", get(get_my_questions))
        .route("/answers", post(create_answer).get(get_all_answers))
        .route(
            "/answers/{id}",
            get(get_answer).put(update_answer).delete(delete_answer),
        )
        .route("/answers/user/{id}", get(get_my_answers))
        .route("/answers/{id}/correct", patch(good_answer))
        .route("/answers/{id}/error", patch(bad_answer))
        .route("/categories", post(create_category).get(get_all_categories))
        .route(
            "/categories/{id}",
            get(get_category)
                .put(update_category)
                .delete(delete_category),
        )
        .route("/categories/user/{id}", get(get_my_categories))
        .route("/steps", post(create_step).get(get_all_steps))
        .route(
            "/steps/{id}",
            get(get_step).put(update_step).delete(delete_step),
        )
        .route("/steps/user/{id}", get(get_my_steps))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::require_auth,
        ));

    Router::new()
        .merge(SwaggerUi::new("/swagger")
            .url("/api-doc/openapi.json", ApiDoc::openapi())
            .config(
                Config::default().default_models_expand_depth(-1)
            )
        )
        .merge(public)
        .merge(auth_cookie_routes)
        .merge(user_routes)
        .layer(CookieManagerLayer::new())
        .layer(cors::cors_layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
