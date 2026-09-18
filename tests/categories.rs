mod common;

use axum::http::StatusCode;
use common::{delete, find_by, get, post, put, register_and_login, spawn_app, tok};
use serde_json::json;

#[tokio::test]
async fn create_without_color_defaults_to_blue() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "cat_default_color").await;

    let (status, _) = post(&router, "/categories", tok(&token), json!({"title": "No color"})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let created = find_by(&list, "title", "No color");
    assert_eq!(created["color_code"], "#3498db");
}

#[tokio::test]
async fn get_my_categories_is_scoped_to_the_caller() {
    let (router, pool) = spawn_app().await;
    let (user_a, token_a) = register_and_login(&router, &pool, "cat_scope_a").await;
    let (_user_b, token_b) = register_and_login(&router, &pool, "cat_scope_b").await;

    post(&router, "/categories", tok(&token_a), json!({"title": "A1"})).await;
    post(&router, "/categories", tok(&token_a), json!({"title": "A2"})).await;
    post(&router, "/categories", tok(&token_b), json!({"title": "B1"})).await;

    let (status, list) = get(&router, &format!("/categories/user/{user_a}"), tok(&token_a)).await;
    assert_eq!(status, StatusCode::OK);
    let titles: Vec<&str> = list["data"].as_array().unwrap().iter().map(|c| c["title"].as_str().unwrap()).collect();
    assert_eq!(titles.len(), 3, "expected Default + A1 + A2, got {titles:?}");
    assert!(titles.contains(&"A1"));
    assert!(titles.contains(&"A2"));
    assert!(!titles.contains(&"B1"));
}

#[tokio::test]
async fn get_my_categories_for_another_user_is_forbidden() {
    let (router, pool) = spawn_app().await;
    let (user_a, _token_a) = register_and_login(&router, &pool, "cat_forbid_a").await;
    let (_user_b, token_b) = register_and_login(&router, &pool, "cat_forbid_b").await;

    let (status, _) = get(&router, &format!("/categories/user/{user_a}"), tok(&token_b)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_only_touches_the_provided_fields() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "cat_partial_update").await;

    post(&router, "/categories", tok(&token), json!({"title": "Original", "color_code": "#111111"})).await;
    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let id = find_by(&list, "title", "Original")["id"].as_i64().unwrap();

    let (status, _) = put(&router, &format!("/categories/{id}"), tok(&token), json!({"title": "Renamed"})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let updated = find_by(&list, "title", "Renamed");
    assert_eq!(updated["color_code"], "#111111", "color should be untouched by a title-only update");

    let id = updated["id"].as_i64().unwrap();
    let (status, _) = put(&router, &format!("/categories/{id}"), tok(&token), json!({"color_code": "#222222"})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let updated = find_by(&list, "title", "Renamed");
    assert_eq!(updated["color_code"], "#222222");
}

#[tokio::test]
async fn cannot_delete_the_default_category() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "cat_delete_default").await;

    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let default_id = find_by(&list, "title", "Default")["id"].as_i64().unwrap();

    let (status, _) = delete(&router, &format!("/categories/{default_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cannot_delete_a_category_with_questions() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "cat_delete_linked").await;

    post(&router, "/categories", tok(&token), json!({"title": "Linked"})).await;
    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let category_id = find_by(&list, "title", "Linked")["id"].as_i64().unwrap();

    let (status, _) = post(
        &router,
        "/questions",
        tok(&token),
        json!({"title": "Q", "answer": "A", "category_id": category_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = delete(&router, &format!("/categories/{category_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deletes_an_unlinked_non_default_category() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "cat_delete_ok").await;

    post(&router, "/categories", tok(&token), json!({"title": "Disposable"})).await;
    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let category_id = find_by(&list, "title", "Disposable")["id"].as_i64().unwrap();

    let (status, _) = delete(&router, &format!("/categories/{category_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    assert!(list["data"].as_array().unwrap().iter().all(|c| c["title"] != "Disposable"));
}
