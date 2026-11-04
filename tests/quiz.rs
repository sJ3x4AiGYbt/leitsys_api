mod common;

use axum::http::StatusCode;
use common::{delete, get, post, register_and_login, spawn_app, tok};
use serde_json::{json, Value};

const TWO_QUESTIONS: &str = "Quiz 1
* Category : Network / Ports
* Question : SSH port?
* Answer A : 22
* Detail answer A : The standard port.
* Answer B : 80
* Correct answer : A
---
Quiz 2
* Category : Network / Protocols
* Question : Encrypted protocols?
* Answer A : HTTPS
* Answer B : Telnet
* Answer C : SSH
* Details answers A and C : Encrypted.
* Correct answer : A and C
";

const THIRD_QUESTION: &str = "Quiz 3
* Category : System
* Question : Which file holds the password hashes?
* Answer A : /etc/passwd
* Answer B : /etc/shadow
* Correct answer : B
";

async fn import(router: &axum::Router, token: &str, text: &str, mode: &str, dry_run: bool) -> (StatusCode, Value) {
    post(router, "/quiz/import", tok(token), json!({"text": text, "mode": mode, "dry_run": dry_run})).await
}

async fn bank(router: &axum::Router, token: &str) -> Vec<Value> {
    let (status, body) = get(router, "/quiz/questions", tok(token)).await;
    assert_eq!(status, StatusCode::OK);
    body["data"].as_array().expect("expected a data array").clone()
}

fn by_num(bank: &[Value], num: i64) -> &Value {
    bank.iter().find(|q| q["num"] == num).unwrap_or_else(|| panic!("no quiz {num} in {bank:?}"))
}

#[tokio::test]
async fn dry_run_reports_without_writing() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_dry_run").await;

    let (status, body) = import(&router, &token, TWO_QUESTIONS, "add", true).await;
    assert_eq!(status, StatusCode::OK);
    let report = &body["data"];
    assert_eq!(report["read"], 2);
    assert_eq!(report["fresh"], 2);
    assert_eq!(report["added"], 0);
    assert_eq!(report["total"], 0);

    assert!(bank(&router, &token).await.is_empty());
}

#[tokio::test]
async fn add_stores_questions_and_skips_duplicates() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_add").await;

    let (status, body) = import(&router, &token, TWO_QUESTIONS, "add", false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["added"], 2);
    assert_eq!(body["data"]["total"], 2);

    let questions = bank(&router, &token).await;
    let multi = by_num(&questions, 2);
    assert_eq!(multi["category"], "Network / Protocols");
    assert_eq!(multi["correct"], json!(["A", "C"]));
    assert_eq!(multi["options"].as_array().unwrap().len(), 3);
    assert_eq!(multi["options"][2]["detail"], "Encrypted.");
    assert_eq!(multi["options"][1]["detail"], "");
    assert_eq!(multi["last_correct"], Value::Null);

    // Same text again plus a new question: only the new one is added.
    let text = format!("{TWO_QUESTIONS}---\n{THIRD_QUESTION}");
    let (_, body) = import(&router, &token, &text, "add", true).await;
    assert_eq!(body["data"]["read"], 3);
    assert_eq!(body["data"]["fresh"], 1);

    let (_, body) = import(&router, &token, &text, "add", false).await;
    assert_eq!(body["data"]["added"], 1);
    assert_eq!(body["data"]["total"], 3);
}

#[tokio::test]
async fn replace_keeps_progress_of_questions_still_present() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_replace").await;

    import(&router, &token, TWO_QUESTIONS, "add", false).await;
    let ssh = by_num(&bank(&router, &token).await, 1)["id"].as_i64().unwrap();
    post(&router, &format!("/quiz/questions/{ssh}/attempt"), tok(&token), json!({"selected": ["A"]})).await;

    // Quiz 1 survives (with a new category), quiz 2 goes, quiz 3 arrives.
    let kept = TWO_QUESTIONS.split("---").next().unwrap().replace("Network / Ports", "Network");
    let text = format!("{kept}---\n{THIRD_QUESTION}");
    let (status, body) = import(&router, &token, &text, "replace", false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["added"], 1);
    assert_eq!(body["data"]["total"], 2);

    let questions = bank(&router, &token).await;
    assert_eq!(questions.len(), 2);
    let ssh_after = by_num(&questions, 1);
    assert_eq!(ssh_after["id"], ssh);
    assert_eq!(ssh_after["category"], "Network");
    assert_eq!(ssh_after["attempts"], 1);
    assert_eq!(ssh_after["last_correct"], true);
    by_num(&questions, 3);
}

#[tokio::test]
async fn invalid_blocks_are_counted_and_an_unusable_text_is_rejected() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_invalid").await;

    let text = format!("{THIRD_QUESTION}---\n* Question : Only one answer\n* Answer A : alone\n* Correct answer : A\n");
    let (status, body) = import(&router, &token, &text, "add", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["read"], 1);
    assert_eq!(body["data"]["invalid"], 1);

    let (status, _) = import(&router, &token, "just some text", "add", false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = import(&router, &token, "", "add", false).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn attempts_update_progress_for_single_and_multiple_answers() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_attempt").await;
    import(&router, &token, TWO_QUESTIONS, "add", false).await;
    let questions = bank(&router, &token).await;
    let single = by_num(&questions, 1)["id"].as_i64().unwrap();
    let multi = by_num(&questions, 2)["id"].as_i64().unwrap();

    let (status, body) = post(&router, &format!("/quiz/questions/{single}/attempt"), tok(&token), json!({"selected": ["B"]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["correct"], false);
    assert_eq!(body["data"]["correct_letters"], json!(["A"]));

    // Only part of the right answers is still wrong.
    let (_, body) = post(&router, &format!("/quiz/questions/{multi}/attempt"), tok(&token), json!({"selected": ["A"]})).await;
    assert_eq!(body["data"]["correct"], false);

    // Order and case don't matter.
    let (_, body) = post(&router, &format!("/quiz/questions/{multi}/attempt"), tok(&token), json!({"selected": ["c", "A"]})).await;
    assert_eq!(body["data"]["correct"], true);

    let questions = bank(&router, &token).await;
    let single_after = by_num(&questions, 1);
    assert_eq!(single_after["attempts"], 1);
    assert_eq!(single_after["successes"], 0);
    assert_eq!(single_after["last_correct"], false);
    let multi_after = by_num(&questions, 2);
    assert_eq!(multi_after["attempts"], 2);
    assert_eq!(multi_after["successes"], 1);
    assert_eq!(multi_after["last_correct"], true);
    assert!(multi_after["last_answered_at"].is_string());

    let (status, _) = post(&router, &format!("/quiz/questions/{single}/attempt"), tok(&token), json!({"selected": []})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn reset_progress_and_clear_bank() {
    let (router, pool) = spawn_app().await;
    let (_, token) = register_and_login(&router, &pool, "quiz_reset").await;
    import(&router, &token, TWO_QUESTIONS, "add", false).await;
    let id = by_num(&bank(&router, &token).await, 1)["id"].as_i64().unwrap();
    post(&router, &format!("/quiz/questions/{id}/attempt"), tok(&token), json!({"selected": ["A"]})).await;

    let (status, _) = delete(&router, "/quiz/progress", tok(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let questions = bank(&router, &token).await;
    assert_eq!(questions.len(), 2);
    assert!(questions.iter().all(|q| q["attempts"] == 0 && q["last_correct"].is_null()));

    let (status, _) = delete(&router, &format!("/quiz/questions/{id}"), tok(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bank(&router, &token).await.len(), 1);

    let (status, _) = delete(&router, "/quiz/questions", tok(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(bank(&router, &token).await.is_empty());
}

#[tokio::test]
async fn banks_are_private() {
    let (router, pool) = spawn_app().await;
    let (_, token_a) = register_and_login(&router, &pool, "quiz_private_a").await;
    let (_, token_b) = register_and_login(&router, &pool, "quiz_private_b").await;
    import(&router, &token_a, TWO_QUESTIONS, "add", false).await;
    let id = by_num(&bank(&router, &token_a).await, 1)["id"].as_i64().unwrap();

    // The same text is new for B: banks don't dedupe across users.
    let (_, body) = import(&router, &token_b, TWO_QUESTIONS, "add", true).await;
    assert_eq!(body["data"]["fresh"], 2);
    assert!(bank(&router, &token_b).await.is_empty());

    let (status, _) = post(&router, &format!("/quiz/questions/{id}/attempt"), tok(&token_b), json!({"selected": ["A"]})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = delete(&router, &format!("/quiz/questions/{id}"), tok(&token_b)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = delete(&router, "/quiz/questions/999999", tok(&token_b)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // B clearing or resetting their own bank leaves A's untouched.
    delete(&router, "/quiz/questions", tok(&token_b)).await;
    assert_eq!(bank(&router, &token_a).await.len(), 2);

    let (status, _) = get(&router, "/quiz/questions", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
