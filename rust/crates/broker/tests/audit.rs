//! The audit feed's paging: more items at one time than a page holds.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::http::router;
use agent_auth_broker::state::AppState;
use agent_auth_core::policy::Policy;
use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use time::macros::datetime;
use tower::ServiceExt;

const ADMIN: &str = "Bearer admin-token";
const POLICY: &str = "audit: {readers: [auditor]}\n";

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    auth: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", auth)
        .header("content-type", "application/json");
    let req = req
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn agent(app: &Router, name: &str) -> String {
    let (status, body) = call(
        app,
        "POST",
        "/admin/agents",
        ADMIN,
        Some(json!({"name": name})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    format!("Bearer {}", body["api_key"].as_str().unwrap())
}

fn key(e: &Value) -> String {
    format!("{} {} {}", e["kind"], e["id"], e["status"])
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_cursor_pages_through_many_items_at_one_time(pool: sqlx::PgPool) {
    let st = AppState::new(
        Store::from_pool(pool.clone()),
        Policy::from_yaml(POLICY).unwrap(),
        AuthConfig {
            admin_token: Some(Secret::new("admin-token".to_owned())),
            oauth_enabled: false,
            trust_x_real_ip: false,
        },
    );
    let log = st.security_log.clone();
    let app = router(st);
    let reader = agent(&app, "auditor").await;
    for i in 0..7 {
        agent(&app, &format!("w{i}")).await;
    }
    // Every item at one instant: 8 agents created, 3 refusals.
    let t = datetime!(2026-01-01 00:00:00 UTC);
    sqlx::query("UPDATE agents SET created_at = $1")
        .bind(t)
        .execute(&pool)
        .await
        .unwrap();
    for i in 0..3 {
        let a = format!("w{i}");
        log.record(
            "credential_refused",
            t,
            &[("agent", Some(&a)), ("grant", Some("g"))],
        );
    }

    // The inclusive time cannot get past them: the next page is this one.
    let since = "/v1/audit/events?since=2026-01-01T00:00:00Z&limit=2";
    let (_, first) = call(&app, "GET", since, &reader, None).await;
    assert_eq!(first["truncated"], true);
    assert_eq!(first["next"], "2026-01-01T00:00:00.000000Z");

    // The cursor does, exactly once each.
    let mut seen = Vec::new();
    let mut page = first;
    for _ in 0..20 {
        for e in page["events"].as_array().unwrap() {
            seen.push(key(e));
        }
        if page["truncated"] == false {
            break;
        }
        let cursor = page["cursor"].as_str().unwrap();
        let q: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("after", cursor)
            .append_pair("limit", "2")
            .finish();
        let (status, next) =
            call(&app, "GET", &format!("/v1/audit/events?{q}"), &reader, None).await;
        assert_eq!(status, StatusCode::OK, "{next:?}");
        page = next;
    }
    assert_eq!(page["truncated"], false, "paging ended");
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "no item twice: {seen:?}");
    assert_eq!(
        seen.iter()
            .filter(|k| k.starts_with("\"agent.created\""))
            .count(),
        8
    );
    assert_eq!(
        seen.iter()
            .filter(|k| k.starts_with("\"security.credential_refused\""))
            .count(),
        3
    );

    // A cursor past the end is a fixed point: nothing, and the same cursor.
    let q: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("after", page["cursor"].as_str().unwrap())
        .finish();
    let (_, end) = call(&app, "GET", &format!("/v1/audit/events?{q}"), &reader, None).await;
    assert_eq!(end["events"], json!([]));
    assert_eq!(end["cursor"], page["cursor"]);

    // Not a cursor: 422.
    let (status, body) = call(&app, "GET", "/v1/audit/events?after=x", &reader, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["detail"], "after: a cursor from a previous page");
}
