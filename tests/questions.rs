mod common;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use common::{find_by, get, post, put, register_and_login, sorted_by_step_order, spawn_app, tok};
use serde_json::json;

fn parse_date(value: &serde_json::Value) -> DateTime<Utc> {
    value.as_str().unwrap().parse().expect("expected an RFC3339 timestamp")
}

#[tokio::test]
async fn create_without_category_or_step_uses_the_users_defaults() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "q_defaults").await;

    let (_, categories) = get(&router, &format!("/categories/user/{user_id}"), tok(&token)).await;
    let default_category_id = find_by(&categories, "title", "Default")["id"].as_i64().unwrap();
    let (_, steps) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step1_id = sorted_by_step_order(&steps).into_iter().find(|s| s["title"] == "Step 1").unwrap()["id"].as_i64().unwrap();

    let (status, _) = post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1"})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let created = find_by(&list, "title", "Q1");
    assert_eq!(created["category_id"], default_category_id);
    assert_eq!(created["current_step_id"], step1_id);
}

#[tokio::test]
async fn create_with_another_users_category_is_forbidden() {
    let (router, pool) = spawn_app().await;
    let (user_a, token_a) = register_and_login(&router, &pool, "q_forbid_a").await;
    let (_user_b, token_b) = register_and_login(&router, &pool, "q_forbid_b").await;

    let (_, categories_a) = get(&router, &format!("/categories/user/{user_a}"), tok(&token_a)).await;
    let category_a_id = find_by(&categories_a, "title", "Default")["id"].as_i64().unwrap();

    let (status, _) = post(
        &router,
        "/questions",
        tok(&token_b),
        json!({"title": "Q", "answer": "A", "category_id": category_a_id}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_todo_includes_due_and_excludes_future() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "q_status_todo").await;

    let (status, _) = post(&router, "/steps", tok(&token), json!({"title": "Instant", "spacing_days": 0})).await;
    assert_eq!(status, StatusCode::OK);
    let (_, steps) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let instant_step_id = sorted_by_step_order(&steps).into_iter().find(|s| s["title"] == "Instant").unwrap()["id"].as_i64().unwrap();

    post(&router, "/questions", tok(&token), json!({"title": "Due now", "answer": "A", "current_step_id": instant_step_id})).await;
    post(&router, "/questions", tok(&token), json!({"title": "Future", "answer": "A"})).await;

    let (status, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false&status=todo"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let titles: Vec<&str> = list["data"].as_array().unwrap().iter().map(|q| q["title"].as_str().unwrap()).collect();
    assert!(titles.contains(&"Due now"), "expected 'Due now' in {titles:?}");
    assert!(!titles.contains(&"Future"), "'Future' should not be due yet, got {titles:?}");
}

#[tokio::test]
async fn updating_the_step_recalculates_next_review_date() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "q_update_step").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1"})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question = find_by(&list, "title", "Q1");
    let question_id = question["id"].as_i64().unwrap();
    let original_date = parse_date(&question["next_review_date"]);

    post(&router, "/steps", tok(&token), json!({"title": "Far out", "spacing_days": 50})).await;
    let (_, steps) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let far_step_id = sorted_by_step_order(&steps).into_iter().find(|s| s["title"] == "Far out").unwrap()["id"].as_i64().unwrap();

    let (status, _) = put(&router, &format!("/questions/{question_id}"), tok(&token), json!({"current_step_id": far_step_id})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let updated = find_by(&list, "title", "Q1");
    let new_date = parse_date(&updated["next_review_date"]);

    assert!(new_date > original_date);
    assert!((new_date - Utc::now()).num_days() >= 45, "expected ~50 days out, got {new_date}");
}
