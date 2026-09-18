mod common;

use axum::http::StatusCode;
use common::{find_by, get, patch, post, register_and_login, sorted_by_step_order, spawn_app, tok};
use serde_json::json;

async fn step_id(router: &axum::Router, token: &str, user_id: i64, title: &str) -> i64 {
    let (_, steps) = get(router, &format!("/steps/user/{user_id}"), tok(token)).await;
    sorted_by_step_order(&steps).into_iter().find(|s| s["title"] == title).unwrap()["id"].as_i64().unwrap()
}

#[tokio::test]
async fn create_answer_returns_the_new_answer_id() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_returns_id").await;
    let step1 = step_id(&router, &token, user_id, "Step 1").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": step1})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question_id = find_by(&list, "title", "Q1")["id"].as_i64().unwrap();

    let (status, body) = post(
        &router,
        "/answers",
        tok(&token),
        json!({"question_id": question_id, "user_response": "my answer", "step": step1, "is_correct": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["id"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn late_spacing_days_is_positive_when_overdue() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_late_spacing").await;

    // Negative spacing puts next_review_date two days in the past.
    post(&router, "/steps", tok(&token), json!({"title": "Overdue", "spacing_days": -2})).await;
    let overdue_step = step_id(&router, &token, user_id, "Overdue").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": overdue_step})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question_id = find_by(&list, "title", "Q1")["id"].as_i64().unwrap();

    let (status, body) = post(
        &router,
        "/answers",
        tok(&token),
        json!({"question_id": question_id, "user_response": "x", "step": overdue_step, "is_correct": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let answer_id = body["data"]["id"].as_i64().unwrap();

    let (_, answer) = get(&router, &format!("/answers/{answer_id}"), tok(&token)).await;
    assert!(answer["data"]["late_spacing_days"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn good_answer_advances_to_the_next_step() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_good_advances").await;
    let step1 = step_id(&router, &token, user_id, "Step 1").await;
    let step2 = step_id(&router, &token, user_id, "Step 2").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": step1})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question_id = find_by(&list, "title", "Q1")["id"].as_i64().unwrap();

    let (_, body) = post(
        &router,
        "/answers",
        tok(&token),
        json!({"question_id": question_id, "user_response": "x", "step": step1, "is_correct": true}),
    )
    .await;
    let answer_id = body["data"]["id"].as_i64().unwrap();

    let (status, _) = patch(&router, &format!("/answers/{answer_id}/correct"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let updated = find_by(&list, "title", "Q1");
    assert_eq!(updated["current_step_id"], step2);
    assert_eq!(updated["is_archived"], false);
}

#[tokio::test]
async fn good_answer_on_the_last_step_archives_the_question() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_good_archives").await;
    let step7 = step_id(&router, &token, user_id, "Step 7").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": step7})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question_id = find_by(&list, "title", "Q1")["id"].as_i64().unwrap();

    let (_, body) = post(
        &router,
        "/answers",
        tok(&token),
        json!({"question_id": question_id, "user_response": "x", "step": step7, "is_correct": true}),
    )
    .await;
    let answer_id = body["data"]["id"].as_i64().unwrap();

    let (status, _) = patch(&router, &format!("/answers/{answer_id}/correct"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (_, question) = get(&router, &format!("/questions/{question_id}"), tok(&token)).await;
    assert_eq!(question["data"]["is_archived"], true);
}

#[tokio::test]
async fn bad_answer_resets_to_the_first_step() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_bad_resets").await;
    let step1 = step_id(&router, &token, user_id, "Step 1").await;
    let step5 = step_id(&router, &token, user_id, "Step 5").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": step5})).await;
    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let question_id = find_by(&list, "title", "Q1")["id"].as_i64().unwrap();

    let (_, body) = post(
        &router,
        "/answers",
        tok(&token),
        json!({"question_id": question_id, "user_response": "x", "step": step5, "is_correct": false}),
    )
    .await;
    let answer_id = body["data"]["id"].as_i64().unwrap();

    let (status, _) = patch(&router, &format!("/answers/{answer_id}/error"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let updated = find_by(&list, "title", "Q1");
    assert_eq!(updated["current_step_id"], step1);
}

#[tokio::test]
async fn three_correct_answers_in_a_row_walk_through_three_steps() {
    let (router, pool) = spawn_app().await;
    let (user_id, token) = register_and_login(&router, &pool, "ans_walk_three").await;
    let step1 = step_id(&router, &token, user_id, "Step 1").await;
    let step4 = step_id(&router, &token, user_id, "Step 4").await;

    post(&router, "/questions", tok(&token), json!({"title": "Q1", "answer": "A1", "current_step_id": step1})).await;

    for _ in 0..3 {
        let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
        let question = find_by(&list, "title", "Q1");
        let question_id = question["id"].as_i64().unwrap();
        let current_step_id = question["current_step_id"].as_i64().unwrap();

        let (_, body) = post(
            &router,
            "/answers",
            tok(&token),
            json!({"question_id": question_id, "user_response": "x", "step": current_step_id, "is_correct": true}),
        )
        .await;
        let answer_id = body["data"]["id"].as_i64().unwrap();
        let (status, _) = patch(&router, &format!("/answers/{answer_id}/correct"), tok(&token)).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (_, list) = get(&router, &format!("/questions/user/{user_id}?is_archived=false"), tok(&token)).await;
    let updated = find_by(&list, "title", "Q1");
    assert_eq!(updated["current_step_id"], step4);
    assert_eq!(updated["is_archived"], false);
}
