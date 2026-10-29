//! Evals end to end: a guarded shell's decisions are recorded, labelled
//! over the admin API, and replayed with another system prompt and
//! context; the replay changes nothing but its own results.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::daemons::testkit::{Broker, FakeModel, HOST, Host, POLICY, caller, jrt};
use crate::hostexec::watcher::GUARD_PROMPT;
use crate::service::HumanDecision;

const STRICT: &str = "REFUSE EVERYTHING.";

fn model() -> impl Fn(&str, &str) -> Option<Value> + Send + Sync + 'static {
    |system: &str, user: &str| {
        let command = user.rsplit("\"command\":").next().unwrap_or("");
        Some(
            if system.starts_with(STRICT) || command.contains("\"curl\"") {
                json!({"level": "odd", "summary": "not for this purpose"})
            } else {
                json!({"level": "fine", "summary": "part of the work"})
            },
        )
    }
}

async fn admin(b: &Broker, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let app = crate::http::router(b.st.clone());
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer admin-token");
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let res = app.oneshot(req.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[sqlx::test(migrations = "../store/migrations")]
async fn decisions_are_recorded_labelled_and_replayed(pool: sqlx::PgPool) {
    let m = FakeModel::start(model()).await;
    let b = Broker::start_with_model(pool.clone(), POLICY, &m).await;
    let host = Host::start(&b).await;
    let a = b.agent("claude-1").await;
    let r = crate::service::create(
        &b.st,
        &caller(&a),
        serde_json::from_value(json!({
            "platform": "hostexec", "capability": "shell", "resource": HOST,
            "scope": {"tier": "user", "mode": "guarded"},
            "justification": "rebuild the larder service", "requested_duration": "1h",
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    crate::service::decide(
        &b.st,
        r.id,
        &jrt(),
        HumanDecision {
            approve: true,
            totp: Some(host.code("user-shell", 0)),
            duration_secs: Some(600),
            ..HumanDecision::default()
        },
    )
    .await
    .unwrap();
    let tx = b.st.store.begin().await.unwrap();
    let g = agent_auth_store::grants::by_request(&tx, r.id)
        .await
        .unwrap()
        .unwrap()
        .id;
    drop(tx);
    let hx = b.hostexec();
    let exec = |argv: &[&str]| -> agent_auth_wire::hostexec::ShellExecBody {
        serde_json::from_value(json!({"argv": argv, "wait": 2})).unwrap()
    };
    hx.shell_exec(a.id, g, &exec(&["echo", "build"]))
        .await
        .unwrap();
    hx.shell_exec(a.id, g, &exec(&["curl", "https://x.example"]))
        .await
        .unwrap_err();

    // Recorded: both, with their facts, exact prompts and classes.
    let (st, page) = admin(&b, Method::GET, "/admin/evals/calls?kind=shell_guard", None).await;
    assert_eq!(st, StatusCode::OK, "{page}");
    let calls = page["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 2, "{page}");
    let (curl, echo) = (&calls[0], &calls[1]);
    assert_eq!(
        (echo["class"].as_str(), curl["class"].as_str()),
        (Some("fine"), Some("odd"))
    );
    assert_eq!(curl["subject"]["grant_id"], g.to_string());
    let (_, detail) = admin(
        &b,
        Method::GET,
        &format!("/admin/evals/calls/{}", echo["id"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(detail["system"], GUARD_PROMPT);
    assert_eq!(
        detail["facts"]["approved_purpose"],
        "rebuild the larder service"
    );
    let sent = m.calls_to(GUARD_PROMPT);
    assert_eq!(
        detail["user_message"].as_str(),
        Some(sent[0].as_str()),
        "what the model got, exactly"
    );

    // Labels: a class of the kind, or refused.
    async fn label_call(b: &Broker, id: &Value, expected: &str) -> (StatusCode, Value) {
        let path = format!("/admin/evals/calls/{}/label", id.as_str().unwrap());
        admin(
            b,
            Method::PUT,
            &path,
            Some(json!({"expected": expected, "note": "checked by hand"})),
        )
        .await
    }
    assert_eq!(
        label_call(&b, &echo["id"], "maybe").await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (st, labelled) = label_call(&b, &echo["id"], "fine").await;
    assert_eq!(st, StatusCode::OK, "{labelled}");
    assert_eq!(labelled["label"]["source"], "operator");
    label_call(&b, &curl["id"], "odd").await;

    // A replay with a stricter prompt and no history: compared.
    let recorded_before: i64 = sqlx::query_scalar("SELECT count(*) FROM model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let jobs_before: i64 = sqlx::query_scalar("SELECT count(*) FROM host_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    let bad_knob = json!({"kind": "shell_guard", "context": {"histroy_items": 0}});
    assert_eq!(
        admin(&b, Method::POST, "/admin/evals/runs", Some(bad_knob))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (st, run) = admin(
        &b,
        Method::POST,
        "/admin/evals/runs",
        Some(json!({
            "kind": "shell_guard", "labeled": true,
            "system": format!("{STRICT} {GUARD_PROMPT}"),
            "context": {"history_items": 0}, "note": "stricter",
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{run}");
    assert_eq!(run["total"], 2);
    let id = run["id"].as_str().unwrap().to_owned();
    let mut done = Value::Null;
    for _ in 0..200 {
        let (_, r) = admin(&b, Method::GET, &format!("/admin/evals/runs/{id}"), None).await;
        if r["status"] != "running" {
            done = r;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(done["status"], "done", "{done}");
    let s = &done["summary"];
    assert_eq!(
        (s["done"].as_u64(), s["labeled"].as_u64()),
        (Some(2), Some(2)),
        "{s}"
    );
    assert_eq!(
        s["labeled_right"], 1,
        "the strict prompt gets the echo wrong"
    );
    assert_eq!(s["original_right"], 2);
    assert_eq!(s["changed"], 1);
    assert_eq!(s["confusion"]["fine"]["odd"], 1);
    assert_eq!(done["cases"].as_array().unwrap().len(), 2);
    // The replay's prompt had no history, and used the given system prompt.
    let strict: Vec<String> = m
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(sys, _)| sys.starts_with(STRICT))
        .map(|(_, u)| u.clone())
        .collect();
    assert_eq!(strict.len(), 2);
    assert!(
        strict
            .iter()
            .all(|u| u.contains("\"earlier_commands\": []")),
        "{strict:?}"
    );

    // Nothing but its results: no command ran, no decision was recorded.
    let recorded_after: i64 = sqlx::query_scalar("SELECT count(*) FROM model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    let jobs_after: i64 = sqlx::query_scalar("SELECT count(*) FROM host_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((recorded_before, jobs_before), (recorded_after, jobs_after));
    // A recorded call is evidence: it never changes.
    assert!(
        sqlx::query("UPDATE model_calls SET class = 'fine'")
            .execute(&pool)
            .await
            .is_err()
    );
    // Admin only.
    let app = crate::http::router(b.st.clone());
    let res = app
        .oneshot(
            Request::builder()
                .uri("/admin/evals/calls")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn outcome_labels_never_override_the_operator(pool: sqlx::PgPool) {
    use agent_auth_store::evals;
    let store = agent_auth_store::Store::from_pool(pool);
    let now = time::OffsetDateTime::now_utc();
    let tx = store.begin().await.unwrap();
    let sha = agent_auth_crypto::digest::sha256_hex(b"sys");
    evals::put_prompt(&tx, &sha, "sys").await.unwrap();
    // A wrong digest stores nothing.
    assert!(
        evals::put_prompt(&tx, &"0".repeat(64), "sys")
            .await
            .is_err()
    );
    let mut ids = Vec::new();
    for (i, age_days) in [(0, 0i64), (1, 200), (2, 200)] {
        let id = uuid::Uuid::new_v4();
        evals::record_call(
            &tx,
            &evals::NewCall {
                id,
                kind: "request_review",
                model: "m",
                facts: &json!({}),
                context: &json!({}),
                system_sha256: &sha,
                user_message: "u",
                answer: None,
                class: Some("deny"),
                error: None,
                latency_ms: 1,
                subject: &json!({"request_id": format!("r{i}")}),
                now: now - time::Duration::days(age_days),
            },
        )
        .await
        .unwrap();
        ids.push(id);
    }
    tx.commit().await.unwrap();
    // Outcome, then operator: the operator's stands; outcome cannot undo it.
    crate::models::label_outcome(
        &store,
        crate::models::Kind::RequestReview,
        json!({"request_id": "r0"}),
        "approve",
        "jrt",
    )
    .await;
    let tx = store.begin().await.unwrap();
    assert_eq!(
        evals::get_call(&tx, ids[0])
            .await
            .unwrap()
            .unwrap()
            .label
            .unwrap()
            .source,
        "outcome"
    );
    evals::set_label(&tx, ids[0], "deny", "", "operator", "jrt", now)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    crate::models::label_outcome(
        &store,
        crate::models::Kind::RequestReview,
        json!({"request_id": "r0"}),
        "approve",
        "jrt",
    )
    .await;
    let tx = store.begin().await.unwrap();
    let l = evals::get_call(&tx, ids[0])
        .await
        .unwrap()
        .unwrap()
        .label
        .unwrap();
    assert_eq!(
        (l.expected.as_str(), l.source.as_str()),
        ("deny", "operator")
    );
    // Retention: old calls go unless an operator labelled them (a label
    // from what happened next keeps nothing).
    evals::set_label(&tx, ids[1], "deny", "", "operator", "jrt", now)
        .await
        .unwrap();
    evals::set_label(&tx, ids[2], "deny", "", "outcome", "jrt", now)
        .await
        .unwrap();
    let forgotten = evals::purge(&tx, now - time::Duration::days(90), 1000)
        .await
        .unwrap();
    assert_eq!(forgotten, 1);
    assert!(evals::get_call(&tx, ids[1]).await.unwrap().is_some());
    assert!(evals::get_call(&tx, ids[2]).await.unwrap().is_none());
}

/// A call that cannot be recorded (here: its record would break a
/// column's limit, and the store refuses it) still decides.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_record_that_fails_leaves_the_decision_alone(pool: sqlx::PgPool) {
    let m = FakeModel::start(|_s: &str, _u: &str| Some(json!({"level": "fine", "summary": "ok"})))
        .await;
    let store = agent_auth_store::Store::from_pool(pool.clone());
    let client = crate::models::ModelClient::new(
        agent_auth_crypto::Secret::new("k".to_owned()),
        &m.url,
        Some(store),
        None,
    )
    .unwrap();
    let facts = json!({
        "agent": "a", "host": "h", "tier": "user", "approved_purpose": "p",
        "earlier": [], "total": 0, "spec": {"argv": ["true"]},
    });
    // A subject past its 4000-byte limit: the insert fails.
    let d = client
        .decide(
            crate::models::Kind::ShellGuard,
            "m",
            facts,
            json!({"pad": "x".repeat(5000)}),
            Duration::from_secs(5),
        )
        .await;
    assert_eq!(d.class.as_deref(), Some("fine"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    // Mail is never recorded in the clear: no sealer, no record.
    let d = client
        .decide(
            crate::models::Kind::MailOutbound,
            "m",
            json!({"constraints": [], "purpose": "p", "draft": {"body": "secret code 123456"}, "context": []}),
            json!({}),
            Duration::from_secs(5),
        )
        .await;
    assert!(d.answer.is_some());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM model_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "mail is not recorded without ENCRYPTION_KEY");
}
