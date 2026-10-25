//! The spine's routes through the whole router (http-api §7: test_api,
//! test_containment, test_zones' audit part, and the §8 fixes).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::http::router;
use agent_auth_broker::provisioners::{AnyProvisioner, FakeProvisioner, Registry};
use agent_auth_broker::state::AppState;
use agent_auth_core::Platform;
use agent_auth_core::policy::Policy;
use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ADMIN: &str = "Bearer admin-token";

const POLICY: &str = r#"
defaults: {action: surface, max_duration: 24h}
containment: {agents: [{name: "guard-*"}]}
audit: {readers: [auditor]}
rules:
  - {match: {platform: a2a, agent: "auto-*"}, action: approve, constraints: {max_duration: 2h}}
"#;

fn state(pool: sqlx::PgPool, policy: &str) -> AppState {
    let mut st = AppState::new(
        Store::from_pool(pool),
        Policy::from_yaml(policy).unwrap(),
        AuthConfig {
            admin_token: Some(Secret::new("admin-token".to_owned())),
            oauth_enabled: false,
            trust_x_real_ip: false,
        },
    );
    let mut reg = Registry::default();
    for p in Platform::ALL {
        reg.register(AnyProvisioner::Fake(FakeProvisioner::new(p)));
    }
    st.registry = Arc::new(reg);
    st
}

struct Res {
    status: StatusCode,
    body: Value,
    headers: axum::http::HeaderMap,
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&str>,
) -> Res {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_owned())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    Res {
        status,
        body,
        headers,
    }
}

/// Create an agent through the admin API; returns its bearer header.
async fn agent(app: &Router, name: &str, extra: Value) -> String {
    let mut body = json!({"name": name});
    if let (Value::Object(b), Value::Object(e)) = (&mut body, extra) {
        b.extend(e);
    }
    let r = call(
        app,
        "POST",
        "/admin/agents",
        Some(ADMIN),
        Some(&body.to_string()),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    format!("Bearer {}", r.body["api_key"].as_str().unwrap())
}

fn request(platform: &str, cap: &str, resource: &str, duration: Value) -> String {
    json!({"platform": platform, "capability": cap, "resource": resource,
           "justification": "a reason", "requested_duration": duration})
    .to_string()
}

#[sqlx::test(migrations = "../store/migrations")]
async fn transport(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let r = call(&app, "GET", "/healthz", None, None).await;
    assert_eq!(r.body, json!({"ok": true}));
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["x-frame-options"], "DENY");
    assert_eq!(r.headers["cache-control"], "no-store");
    for path in ["/docs", "/redoc", "/openapi.json", "/v1/a2a/send", "/nope"] {
        let r = call(&app, "GET", path, None, None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(r.body, json!({"detail": "Not Found"}));
    }
    let r = call(&app, "DELETE", "/v1/me", None, None).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    // A body over the limit.
    let big = "x".repeat(3 * 1024 * 1024);
    let key = agent(&app, "worker", json!({})).await;
    let r = call(&app, "POST", "/v1/requests", Some(&key), Some(&big)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn auth_and_admin_agents(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    for bad in [None, Some("Bearer aa_bogus_key"), Some("garbage")] {
        assert_eq!(
            call(&app, "GET", "/v1/me", bad, None).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        call(&app, "GET", "/v1/catalog", None, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/admin/agents", None, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/admin/agents", Some("Bearer nope"), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let key = agent(&app, "worker", json!({"runtime": "claude"})).await;
    assert!(key.starts_with("Bearer aa_"));
    let r = call(
        &app,
        "POST",
        "/admin/agents",
        Some(ADMIN),
        Some(r#"{"name": "worker"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.body["detail"], "agent 'worker' already exists");
    let r = call(
        &app,
        "POST",
        "/admin/agents",
        Some(ADMIN),
        Some(r#"{"name": "operator"}"#),
    )
    .await;
    assert_eq!(
        r.body["detail"],
        "'operator' is the admin panel's name for the operator"
    );
    let r = call(
        &app,
        "POST",
        "/admin/agents",
        Some(ADMIN),
        Some(r#"{"name": "w2", "webhook_url": "ftp://x"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let list = call(&app, "GET", "/admin/agents", Some(ADMIN), None).await;
    let worker = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "worker")
        .unwrap();
    assert_eq!(worker["api_key"], Value::Null);
    assert_eq!(worker["webhook_secret"], Value::Null);
    let me = call(&app, "GET", "/v1/me", Some(&key), None).await;
    assert_eq!(me.body["name"], "worker");
    assert_eq!(me.body["runtime"], "claude");
    assert!(me.body.get("webhook_secret").is_none());
    assert!(me.body.get("session").is_none());
    // Rotate: the old key stops at once.
    let id = me.body["id"].as_str().unwrap().to_owned();
    let r = call(
        &app,
        "POST",
        &format!("/admin/agents/{id}/rotate-key"),
        Some(ADMIN),
        None,
    )
    .await;
    let new_key = format!("Bearer {}", r.body["api_key"].as_str().unwrap());
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&key), None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&new_key), None)
            .await
            .status,
        StatusCode::OK
    );
    // Rename by name; then disable.
    let r = call(
        &app,
        "POST",
        "/admin/agents/worker/rename",
        Some(ADMIN),
        Some(r#"{"name": "w9"}"#),
    )
    .await;
    assert_eq!(r.body["previous_name"], "worker");
    let r = call(
        &app,
        "POST",
        &format!("/admin/agents/{id}/disable"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(r.body, json!({"disabled": ["w9"]}));
    assert_eq!(
        call(&app, "GET", "/v1/me", Some(&new_key), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn request_flow_via_api(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let key = agent(&app, "worker", json!({})).await;
    let other = agent(&app, "other", json!({})).await;
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&key),
        Some(&request("a2a", "talk", "peer", json!("1h"))),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["status"], "awaiting_human");
    assert!(r.body["guidance"].as_str().unwrap().contains("Discord"));
    let id = r.body["id"].as_str().unwrap().to_owned();
    // Isolation (INV-22).
    let r = call(
        &app,
        "GET",
        &format!("/v1/requests/{id}"),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.body["detail"], "unknown request");
    let r = call(
        &app,
        "POST",
        &format!("/v1/requests/{id}/escalate"),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // The long-poll wakes on a concurrent decision.
    let waiter = {
        let (app, key, id) = (app.clone(), key.clone(), id.clone());
        tokio::spawn(async move {
            call(
                &app,
                "GET",
                &format!("/v1/requests/{id}/wait?timeout=30"),
                Some(&key),
                None,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bad = call(
        &app,
        "POST",
        &format!("/admin/requests/{id}/decide"),
        Some(ADMIN),
        Some(r#"{"approve": true, "duration": "x"}"#),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        bad.body["detail"]
            .as_str()
            .unwrap()
            .contains("invalid duration 'x'")
    );
    let started = Instant::now();
    let d = call(
        &app,
        "POST",
        &format!("/admin/requests/{id}/decide"),
        Some(ADMIN),
        Some(r#"{"approve": true, "duration": "10m"}"#),
    )
    .await;
    assert_eq!(d.status, StatusCode::OK, "{:?}", d.body);
    let w = waiter.await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(w.body["status"], "granted");
    assert_eq!(w.body["approved_duration_secs"], 600);
    let grant = w.body["grant_id"].as_str().unwrap().to_owned();
    assert!(w.body["guidance"].as_str().unwrap().contains(&grant));
    let again = call(
        &app,
        "POST",
        &format!("/admin/requests/{id}/decide"),
        Some(ADMIN),
        Some(r#"{"approve": false}"#),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(
        again.body["detail"],
        "request already resolved (status granted)"
    );
    let grants = call(&app, "GET", "/v1/grants", Some(&key), None).await;
    assert_eq!(grants.body.as_array().unwrap().len(), 1);
    assert_eq!(grants.body[0]["capability"], "talk");
    let bad = call(&app, "GET", "/v1/grants?status=bogus", Some(&key), None).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["detail"], "invalid status 'bogus'");
    let cred = call(
        &app,
        "GET",
        &format!("/v1/grants/{grant}/credential"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(cred.status, StatusCode::OK, "{:?}", cred.body);
    assert_eq!(cred.body["kind"], "a2a_grant");
    for k in ["value", "username", "url", "expires_at", "note"] {
        assert!(cred.body.get(k).is_some(), "{k}");
    }
    let cred = call(
        &app,
        "GET",
        &format!("/v1/grants/{grant}/credential"),
        Some(&other),
        None,
    )
    .await;
    assert_eq!(cred.status, StatusCode::NOT_FOUND);
    // Revoke: the credential is refused, a second revoke is 409.
    let r = call(
        &app,
        "POST",
        &format!("/admin/grants/{grant}/revoke"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(
        r.body,
        json!({"ok": true, "grant_id": grant, "status": "revoked"})
    );
    let r = call(
        &app,
        "POST",
        &format!("/admin/grants/{grant}/revoke"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let cred = call(
        &app,
        "GET",
        &format!("/v1/grants/{grant}/credential"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(cred.status, StatusCode::FORBIDDEN);
    assert_eq!(cred.body["detail"], "grant is not active");
    let listed = call(&app, "GET", "/admin/requests?limit=-1", Some(ADMIN), None).await;
    assert_eq!(listed.body.as_array().unwrap().len(), 1);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn bodies_are_checked(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let key = agent(&app, "worker", json!({})).await;
    for (body, why) in [
        (
            request("a2a", "talk", "p", json!("sometime")),
            "bad duration",
        ),
        (request("a2a", "talk", "p", json!("400d")), "over 365 days"),
        (request("a2a", "talk", "p", json!(true)), "a boolean"),
        (
            json!({"platform": "a2a", "capability": "talk", "resource": "p",
                "justification": "x".repeat(5000), "requested_duration": 60})
            .to_string(),
            "long",
        ),
        (
            json!({"platform": "a2a", "capability": "talk", "resource": "p", "justification": "j",
                "requested_duration": 60, "nope": 1})
            .to_string(),
            "unknown field",
        ),
        ("{not json".to_owned(), "not JSON"),
    ] {
        let r = call(&app, "POST", "/v1/requests", Some(&key), Some(&body)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{why}");
        assert!(r.body.get("detail").is_some());
    }
    // Authentication comes before the body.
    let r = call(&app, "POST", "/v1/requests", None, Some("{not json")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A NaN wait answers at once.
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&key),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    let id = r.body["id"].as_str().unwrap();
    let t = Instant::now();
    let w = call(
        &app,
        "GET",
        &format!("/v1/requests/{id}/wait?timeout=nan"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(w.status, StatusCode::OK);
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_platform_not_enabled_is_400(pool: sqlx::PgPool) {
    let mut st = state(pool, POLICY);
    st.registry = Arc::new(Registry::default());
    let app = router(st);
    let key = agent(&app, "worker", json!({})).await;
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&key),
        Some(&request("github", "repo", "jrt/x", json!(60))),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        r.body["detail"],
        "platform 'github' is not enabled on this broker"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn web_connectors_get_no_credential(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let key = agent(&app, "web-x", json!({"runtime": "web"})).await;
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&key),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    call(
        &app,
        "POST",
        &format!("/admin/requests/{id}/decide"),
        Some(ADMIN),
        Some(r#"{"approve": true}"#),
    )
    .await;
    let grant = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&key), None)
        .await
        .body["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cred = call(
        &app,
        "GET",
        &format!("/v1/grants/{grant}/credential"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(cred.status, StatusCode::FORBIDDEN);
    assert_eq!(
        cred.body["detail"],
        "credentials are not issued to a web UI connector"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn containment_routes(pool: sqlx::PgPool) {
    let app = router(state(pool.clone(), POLICY));
    let guard = agent(&app, "guard-1", json!({})).await;
    let worker = agent(&app, "auto-w", json!({"project": "soc"})).await;
    // Not allowed: the route does not exist, whatever the body.
    for body in ["{garbage", r#"{"match": {}, "reason": "x"}"#] {
        let r = call(&app, "POST", "/v1/containment", Some(&worker), Some(body)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        assert_eq!(r.body["detail"], "Not Found");
    }
    assert_eq!(
        call(&app, "GET", "/v1/containment", Some(&worker), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // Everyone, however written, is the operator's (B-2).
    for m in [
        json!({}),
        json!({"name": "*"}),
        json!({"placement": ["host", "sandbox"]}),
        json!({"name": "*", "kind": ["service", "ephemeral"]}),
    ] {
        let body = json!({"match": m, "reason": "all"}).to_string();
        let r = call(&app, "POST", "/v1/containment", Some(&guard), Some(&body)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{m}");
        assert_eq!(
            r.body["detail"],
            "containing every agent at once is the operator's"
        );
    }
    let r = call(
        &app,
        "POST",
        "/v1/containment",
        Some(&guard),
        Some(r#"{"match": {"bogus": 1}, "reason": "x"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(r.body["detail"].is_string());
    let grant_req = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&worker),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    assert_eq!(grant_req.body["status"], "granted");
    let grant = grant_req.body["grant_id"].as_str().unwrap().to_owned();
    let r = call(
        &app,
        "POST",
        "/v1/containment",
        Some(&guard),
        Some(r#"{"match": {"project": ["soc"]}, "reason": "odd"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["by"], "guard-1");
    assert_eq!(r.body["source"], "agent");
    assert_eq!(r.body["agents"], json!(["auto-w"]));
    assert_eq!(r.body["grants_revoked"], 1);
    let entry = r.body["id"].as_str().unwrap().to_owned();
    // INV-3 with the security log.
    let cred = call(
        &app,
        "GET",
        &format!("/v1/grants/{grant}/credential"),
        Some(&worker),
        None,
    )
    .await;
    assert_eq!(cred.status, StatusCode::FORBIDDEN);
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&worker),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    assert_eq!(
        r.body["decision_reason"],
        format!("contained ({entry}): odd")
    );
    // Agents never lift; the operator does, explicitly.
    let r = call(
        &app,
        "POST",
        "/admin/containment/lift",
        Some(&guard),
        Some(r#"{"all": true}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = call(
        &app,
        "POST",
        "/admin/containment/lift",
        Some(ADMIN),
        Some("{}"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = call(
        &app,
        "POST",
        "/admin/containment/lift",
        Some(ADMIN),
        Some(r#"{"id": "ffffffff"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.body["detail"], "no containment 'ffffffff'");
    let r = call(&app, "GET", "/admin/containment", Some(ADMIN), None).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    let r = call(
        &app,
        "POST",
        "/admin/containment/lift",
        Some(ADMIN),
        Some(&json!({"id": entry}).to_string()),
    )
    .await;
    assert_eq!(r.body["lifted"].as_array().unwrap().len(), 1);
    let r = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&worker),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    assert_eq!(r.body["status"], "granted");

    // With allow_all, an allowed agent may hold everyone.
    let app2 = router(state(
        pool,
        &format!("{POLICY}\n").replace(
            "containment: {agents: [{name: \"guard-*\"}]}",
            "containment: {agents: [{name: \"guard-*\"}], allow_all: true}",
        ),
    ));
    let r = call(
        &app2,
        "POST",
        "/v1/containment",
        Some(&guard),
        Some(r#"{"match": {}, "reason": "all"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_audit_feed_is_its_readers_alone(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let reader = agent(&app, "auditor", json!({})).await;
    let worker = agent(&app, "auto-w", json!({})).await;
    // A non-reader: 404 before any parameter is read (§8.3).
    for q in ["", "?limit=x", "?since=garbage"] {
        let r = call(
            &app,
            "GET",
            &format!("/v1/audit/events{q}"),
            Some(&worker),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{q}");
    }
    call(
        &app,
        "POST",
        "/v1/requests",
        Some(&worker),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    call(
        &app,
        "GET",
        "/v1/me",
        Some("Bearer aa_000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        None,
    )
    .await;
    let r = call(&app, "GET", "/v1/audit/events?limit=x", Some(&reader), None).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = call(
        &app,
        "GET",
        "/v1/audit/events?since=nope",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(r.body["detail"], "since: an ISO 8601 time");
    let r = call(&app, "GET", "/v1/audit/events", Some(&reader), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let kinds: Vec<&str> = r.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for k in [
        "request",
        "grant.issued",
        "agent.created",
        "security.bad_key",
    ] {
        assert!(kinds.contains(&k), "{k} in {kinds:?}");
    }
    assert_eq!(r.body["truncated"], false);
    let r = call(&app, "GET", "/v1/audit/events?limit=1", Some(&reader), None).await;
    assert_eq!(r.body["events"].as_array().unwrap().len(), 1);
    assert_eq!(r.body["truncated"], true);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn admin_rules_projects_and_logs(pool: sqlx::PgPool) {
    let policy = format!("{POLICY}projects: {{soc: {{description: SOC, repos: [jrt/soc]}}}}\n");
    let app = router(state(pool, &policy));
    let key = agent(&app, "worker", json!({"project": "soc"})).await;
    agent(&app, "x2", json!({"project": "misc"})).await;
    let r = call(&app, "GET", "/admin/projects", Some(ADMIN), None).await;
    assert_eq!(r.body["projects"]["soc"]["agents"], json!(["worker"]));
    assert_eq!(r.body["projects"]["soc"]["in_policy"], true);
    assert_eq!(r.body["projects"]["misc"]["in_policy"], false);
    assert_eq!(r.body["wiki"], Value::Null);
    assert_eq!(
        call(&app, "GET", "/admin/rules", Some(ADMIN), None)
            .await
            .body,
        json!([])
    );
    let r = call(
        &app,
        "DELETE",
        "/admin/rules/00000000-0000-4000-8000-000000000000",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.body["detail"], "unknown rule");
    call(
        &app,
        "POST",
        "/v1/requests",
        Some(&key),
        Some(&request("a2a", "talk", "p", json!(60))),
    )
    .await;
    let r = call(
        &app,
        "GET",
        "/admin/log/decisions?source=bogus",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = call(
        &app,
        "GET",
        "/admin/log/decisions?agent=worker",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    assert_eq!(r.body[0]["what"], "talk");
    let r = call(&app, "GET", "/admin/log/commands", Some(ADMIN), None).await;
    assert_eq!(r.body, json!([]));
    let r = call(&app, "GET", "/admin/a2a/graph?hours=0", Some(ADMIN), None).await;
    assert_eq!(r.body["hours"], 1);
    let r = call(&app, "GET", "/admin/models/usage", Some(ADMIN), None).await;
    assert_eq!(r.body, json!({"enabled": false, "agents": []}));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn per_agent_limits(pool: sqlx::PgPool) {
    let mut st = state(pool, POLICY);
    let mut spine = agent_auth_broker::service::Spine::default();
    spine.limits = agent_auth_broker::limits::Limits::new(1, 2);
    st.spine = Arc::new(spine);
    let app = router(st);
    let key = agent(&app, "worker", json!({})).await;
    let other = agent(&app, "other", json!({})).await;
    let body = request("a2a", "talk", "p", json!(60));
    let first = call(&app, "POST", "/v1/requests", Some(&key), Some(&body)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(
        call(&app, "POST", "/v1/requests", Some(&key), Some(&body))
            .await
            .status,
        StatusCode::OK
    );
    let r = call(&app, "POST", "/v1/requests", Some(&key), Some(&body)).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        r.body["detail"],
        "at most 2 access requests an hour; wait before asking again"
    );
    assert_eq!(
        call(&app, "POST", "/v1/requests", Some(&other), Some(&body))
            .await
            .status,
        StatusCode::OK
    );
    // One long-poll at a time for this agent.
    let id = first.body["id"].as_str().unwrap().to_owned();
    let parked = {
        let (app, key, id) = (app.clone(), key.clone(), id.clone());
        tokio::spawn(async move {
            call(
                &app,
                "GET",
                &format!("/v1/requests/{id}/wait?timeout=3"),
                Some(&key),
                None,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = call(
        &app,
        "GET",
        &format!("/v1/requests/{id}/wait?timeout=1"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        r.body["detail"]
            .as_str()
            .unwrap()
            .starts_with("at most 1 decision waits")
    );
    assert_eq!(parked.await.unwrap().status, StatusCode::OK);
    // The slot is free again.
    let r = call(
        &app,
        "GET",
        &format!("/v1/requests/{id}/wait?timeout=1"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// `POST /v1/grants/{id}/release`: an agent ends its own grant early; any
/// other agent's is unknown; one already ended says so; a contained agent
/// may still give access back.
#[sqlx::test(migrations = "../store/migrations")]
async fn release_grant(pool: sqlx::PgPool) {
    let app = router(state(pool, POLICY));
    let worker = agent(&app, "auto-w", json!({})).await;
    let other = agent(&app, "auto-o", json!({})).await;
    let guard = agent(&app, "guard-1", json!({})).await;
    let body = request("a2a", "talk", "p", json!(600));
    let make = || call(&app, "POST", "/v1/requests", Some(&worker), Some(&body));
    let grant_of = |r: Res| r.body["grant_id"].as_str().unwrap().to_owned();
    let g = grant_of(make().await);
    let path = format!("/v1/grants/{g}/release");
    for (who, id) in [
        (&other, g.as_str()),
        (&worker, "not-an-id"),
        (&worker, "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9"),
    ] {
        let r = call(
            &app,
            "POST",
            &format!("/v1/grants/{id}/release"),
            Some(who),
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{id}");
        assert_eq!(r.body["detail"], "unknown grant");
    }
    let r = call(&app, "POST", &path, Some(&worker), None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body, json!({"released": true}));
    let r = call(&app, "POST", &path, Some(&worker), None).await;
    assert_eq!(r.body, json!({"released": false, "status": "revoked"}));
    let r = call(&app, "GET", "/v1/grants?status=all", Some(&worker), None).await;
    let listed = r.body.as_array().unwrap();
    assert!(
        listed
            .iter()
            .any(|x| x["id"] == g && x["status"] == "revoked")
    );
    // Contained: giving access back is still allowed.
    let g2 = grant_of(make().await);
    let r = call(
        &app,
        "POST",
        "/v1/containment",
        Some(&guard),
        Some(r#"{"match": {"name": "auto-w"}, "reason": "odd"}"#),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = call(
        &app,
        "POST",
        &format!("/v1/grants/{g2}/release"),
        Some(&worker),
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(
        r.body == json!({"released": true}) || r.body["status"] == "revoked",
        "{:?}",
        r.body
    );
}
