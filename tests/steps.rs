mod common;

use axum::http::StatusCode;
use common::{delete, get, post, put, register_and_login, sorted_by_step_order, spawn_app, tok};
use serde_json::json;

#[tokio::test]
async fn create_without_color_defaults_and_appends_order() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_default_color").await;

    // 7 default steps already exist from registration; this one should land at order 8.
    let (status, _) = post(&router, "/steps", tok(&token), json!({"title": "Step 8", "spacing_days": 120})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let steps = sorted_by_step_order(&list);
    let created = steps.iter().find(|s| s["title"] == "Step 8").unwrap();
    assert_eq!(created["step_order"], 8);
    assert_eq!(created["color_code"], "#95a5a6");
}

#[tokio::test]
async fn reorder_earlier_shifts_the_steps_in_between() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_reorder_earlier").await;

    post(&router, "/steps", tok(&token), json!({"title": "Step 8", "spacing_days": 120})).await;
    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step8_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 8").unwrap()["id"].as_i64().unwrap();

    let (status, _) = put(&router, &format!("/steps/{step8_id}"), tok(&token), json!({"step_order": 3})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let titles: Vec<String> = sorted_by_step_order(&list).iter().map(|s| s["title"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        titles,
        vec!["Step 1", "Step 2", "Step 8", "Step 3", "Step 4", "Step 5", "Step 6", "Step 7"]
    );
}

#[tokio::test]
async fn reorder_later_shifts_the_steps_in_between() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_reorder_later").await;

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step1_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 1").unwrap()["id"].as_i64().unwrap();

    let (status, _) = put(&router, &format!("/steps/{step1_id}"), tok(&token), json!({"step_order": 4})).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let titles: Vec<String> = sorted_by_step_order(&list).iter().map(|s| s["title"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        titles,
        vec!["Step 2", "Step 3", "Step 4", "Step 1", "Step 5", "Step 6", "Step 7"]
    );
}

#[tokio::test]
async fn step_order_out_of_bounds_is_rejected() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_order_bounds").await;

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step1_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 1").unwrap()["id"].as_i64().unwrap();

    let (status, _) = put(&router, &format!("/steps/{step1_id}"), tok(&token), json!({"step_order": 0})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cannot_delete_the_first_step() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_delete_first").await;

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step1_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 1").unwrap()["id"].as_i64().unwrap();

    let (status, _) = delete(&router, &format!("/steps/{step1_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cannot_delete_a_step_with_questions() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_delete_linked").await;

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step2_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 2").unwrap()["id"].as_i64().unwrap();

    let (status, _) = post(
        &router,
        "/questions",
        tok(&token),
        json!({"title": "Q", "answer": "A", "current_step_id": step2_id}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = delete(&router, &format!("/steps/{step2_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_a_step_closes_the_gap() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "step_delete_ok").await;

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let step2_id = sorted_by_step_order(&list).into_iter().find(|s| s["title"] == "Step 2").unwrap()["id"].as_i64().unwrap();

    let (status, _) = delete(&router, &format!("/steps/{step2_id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/steps/user/{user_id}"), tok(&token)).await;
    let titles: Vec<String> = sorted_by_step_order(&list).iter().map(|s| s["title"].as_str().unwrap().to_string()).collect();
    assert_eq!(titles, vec!["Step 1", "Step 3", "Step 4", "Step 5", "Step 6", "Step 7"]);
}
