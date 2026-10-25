//! The client against a fake broker answering the shapes the spec records.

// Test code: helpers outside #[test] functions may unwrap and index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use agent_auth_client::testing::{FakeBroker, Reply, shapes};
use agent_auth_client::{BrokerClient, ClientError, Config};
use serde_json::{Value, json};

fn config(url: &str) -> Config {
    Config {
        base_url: Some(url.to_owned()),
        api_key: Some("aa_abcdef_secret".into()),
        admin_token: Some("admin-token".into()),
        session_id: None,
    }
}

async fn setup() -> (FakeBroker, BrokerClient) {
    let fake = FakeBroker::start().await.unwrap();
    let client = BrokerClient::new(config(&fake.url)).unwrap();
    (fake, client)
}

#[tokio::test]
async fn agent_calls_carry_the_key_and_the_session_admin_calls_neither_session() {
    let (fake, client) = setup().await;
    fake.json("GET", "/v1/me", 200, shapes::me("ephemeral"));
    fake.json(
        "GET",
        "/admin/agents",
        200,
        json!([shapes::agent("hermes")]),
    );

    let me = client.me().await.unwrap();
    assert_eq!(me.name, "claude-x-host");
    client.set_session_id(Some("sess-1"));
    client.me().await.unwrap();
    let agents = client.admin_list_agents().await.unwrap();
    assert_eq!(agents.len(), 1);

    let seen = fake.seen();
    assert_eq!(
        seen[0].header("authorization"),
        Some("Bearer aa_abcdef_secret")
    );
    assert_eq!(seen[0].header("x-agent-session"), None);
    assert_eq!(seen[1].header("x-agent-session"), Some("sess-1"));
    assert_eq!(seen[2].header("authorization"), Some("Bearer admin-token"));
    assert_eq!(seen[2].header("x-agent-session"), None);
}

#[tokio::test]
async fn sessions_are_shared_by_clones_and_not_by_with_session() {
    let (fake, client) = setup().await;
    fake.json(
        "POST",
        "/v1/sessions",
        200,
        shapes::session(shapes::SESSION_ID),
    );
    let clone = client.clone();
    let other = client.with_session(Some("sess-other"));
    let out = client.create_session("task").await.unwrap();
    assert_eq!(out.session_id.to_string(), shapes::SESSION_ID);
    assert_eq!(clone.session_id().as_deref(), Some(shapes::SESSION_ID));
    assert_eq!(other.session_id().as_deref(), Some("sess-other"));
    assert_eq!(
        fake.calls("POST", "/v1/sessions")[0].json(),
        json!({"label": "task"})
    );
    assert!(!client.clear_session_if("sess-other"));
    assert!(client.clear_session_if(shapes::SESSION_ID));
    assert_eq!(clone.session_id(), None);
}

#[tokio::test]
async fn missing_keys_and_bad_urls_fail_before_any_request() {
    let fake = FakeBroker::start().await.unwrap();
    let client = BrokerClient::new(Config {
        base_url: Some(fake.url.clone()),
        ..Config::default()
    })
    .unwrap();
    let err = client.me().await.unwrap_err();
    assert_eq!(err.to_string(), "[0] AGENT_AUTH_API_KEY not set");
    let err = client.admin_list_agents().await.unwrap_err();
    assert_eq!(err.to_string(), "[0] AGENT_AUTH_ADMIN_TOKEN not set");
    // Before the body is even looked at, as the Python.
    let err = client
        .request_access("nope", "", "", "", "x", None, None)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "[0] AGENT_AUTH_API_KEY not set");

    let plain = BrokerClient::new(config("http://agent-auth.lan")).unwrap();
    let err = plain.me().await.unwrap_err();
    assert_eq!(err.status(), Some(0));
    assert!(err.to_string().contains("https://"), "{err}");
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn refusals_carry_the_brokers_status_and_detail() {
    let (fake, client) = setup().await;
    fake.on("GET", "/v1/requests/*", |_| {
        Reply::detail(404, "unknown request")
    });
    fake.on("GET", "/v1/grants", |_| {
        Reply::text(502, "text/plain", "Bad Gateway")
    });
    fake.on("GET", "/v1/me", |_| {
        Reply::detail(401, "unknown or closed session")
    });

    let err = client.get_request(shapes::REQUEST_ID).await.unwrap_err();
    assert_eq!(err.to_string(), "[404] unknown request");
    let err = client.grants("active").await.unwrap_err();
    assert_eq!(err.to_string(), "[502] Bad Gateway");
    let err = client.me().await.unwrap_err();
    assert!(err.is_stale_session());
}

#[tokio::test]
async fn a_body_the_broker_would_refuse_is_refused_here_with_its_message() {
    let (fake, client) = setup().await;
    let err = client
        .request_access("github", "repo", "o/r", "why", "0m", None, None)
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(422));
    assert!(err.to_string().contains("duration"), "{err}");
    let err = client.create_session("has space").await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "[422] String should match pattern '^[a-zA-Z0-9._-]+$'"
    );
    assert!(fake.seen().is_empty());
}

#[tokio::test]
async fn request_access_sends_the_python_body() {
    let (fake, client) = setup().await;
    fake.json("POST", "/v1/requests", 200, shapes::request("pending"));
    let req = client
        .request_access(
            "homelab",
            "group",
            "svc-gitea",
            "claude asked in-thread",
            "1h",
            None,
            Some(shapes::THREAD_ID),
        )
        .await
        .unwrap();
    assert_eq!(req.id.to_string(), shapes::REQUEST_ID);
    let body = fake.calls("POST", "/v1/requests")[0].json();
    assert_eq!(
        body,
        json!({
            "platform": "homelab", "capability": "group", "resource": "svc-gitea",
            "scope": {}, "justification": "claude asked in-thread",
            "requested_duration": 3600, "on_behalf_of_thread": shapes::THREAD_ID
        })
    );
}

#[tokio::test]
async fn ids_are_one_path_segment() {
    let (fake, client) = setup().await;
    fake.json(
        "GET",
        "/v1/grants/*/credential",
        200,
        shapes::credential("a2a_grant", None, None),
    );
    client.credential("a/b?c").await.unwrap();
    let seen = fake.seen();
    assert_eq!(seen.len(), 1);
    // axum hands the path over still encoded.
    assert_eq!(seen[0].path, "/v1/grants/a%2Fb%3Fc/credential");
    for bad in ["..", ".", ""] {
        let err = client.credential(bad).await.unwrap_err();
        assert_eq!(err.status(), Some(0), "{bad}");
    }
    assert_eq!(fake.seen().len(), 1);
}

#[tokio::test]
async fn waits_send_their_slice_and_stop_when_settled() {
    let (fake, client) = setup().await;
    fake.json(
        "GET",
        "/v1/requests/*/wait",
        200,
        shapes::request("granted"),
    );
    let req = client.wait(shapes::REQUEST_ID, 150.0).await.unwrap();
    assert_eq!(
        req.grant_id.map(|g| g.to_string()).as_deref(),
        Some(shapes::GRANT_ID)
    );
    let calls = fake.calls("GET", "/v1/requests/*/wait");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].param("timeout"), Some("60.0"));

    // Zero: exactly one call, with zero.
    fake.json(
        "GET",
        "/v1/requests/*/wait",
        200,
        shapes::request("awaiting_human"),
    );
    client.wait(shapes::REQUEST_ID, 0.0).await.unwrap();
    let calls = fake.calls("GET", "/v1/requests/*/wait");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].param("timeout"), Some("0.0"));
}

#[tokio::test]
async fn a2a_reads_and_events() {
    let (fake, client) = setup().await;
    fake.json(
        "GET",
        "/v1/a2a/threads/*/messages",
        200,
        shapes::messages(
            shapes::THREAD_ID,
            "open",
            &[json!({"type": "result", "status": "done"})],
        ),
    );
    fake.json(
        "GET",
        "/v1/a2a/events",
        200,
        shapes::events(
            vec![shapes::thread(shapes::THREAD_ID, "pending_open")],
            vec![],
            Some(shapes::T),
        ),
    );
    let read = client.a2a_poll(shapes::THREAD_ID, 3, 30.0).await.unwrap();
    assert_eq!(read.messages.len(), 1);
    let call = &fake.calls("GET", "/v1/a2a/threads/*/messages")[0];
    assert_eq!(call.param("after_seq"), Some("3"));
    assert_eq!(call.param("wait"), Some("30.0"));

    let snap = client.a2a_events(5.0, Some(shapes::T)).await.unwrap();
    assert_eq!(snap.pending_opens.len(), 1);
    let call = &fake.calls("GET", "/v1/a2a/events")[0];
    assert_eq!(call.param("after"), Some(shapes::T));
    assert_eq!(call.param("wait"), Some("5.0"));
}

#[tokio::test]
async fn a_shell_command_is_posted_once_and_then_waited_on_by_its_job_id() {
    let (fake, client) = setup().await;
    let job_id = "61e4d294-bf60-41e4-b0b7-cf9283746077";
    fake.json(
        "POST",
        "/v1/hostexec/shells/*/exec",
        200,
        shapes::job(job_id, "running"),
    );
    fake.json(
        "GET",
        "/v1/hostexec/jobs/*",
        200,
        shapes::job(job_id, "done"),
    );
    let argv = vec!["uptime".to_owned()];
    let job = client
        .host_shell_exec(shapes::GRANT_ID, &argv, Some("/tmp"), None, Some(30), 60.5)
        .await
        .unwrap();
    assert_eq!(job.output.as_deref(), Some("ok\n"));
    let exec = fake.calls("POST", "/v1/hostexec/shells/*/exec");
    assert_eq!(exec.len(), 1);
    assert_eq!(
        exec[0].json(),
        json!({"argv": ["uptime"], "cwd": "/tmp", "env": {}, "stdin": null, "timeout": 30, "wait": 60.0})
    );
    let jobs = fake.calls("GET", "/v1/hostexec/jobs/*");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].path, format!("/v1/hostexec/jobs/{job_id}"));

    // A short wait: the exec alone.
    client
        .host_shell_exec(shapes::GRANT_ID, &argv, None, None, None, 10.0)
        .await
        .unwrap();
    assert_eq!(
        fake.calls("POST", "/v1/hostexec/shells/*/exec")[1].json()["wait"],
        json!(10.0)
    );
    assert_eq!(fake.calls("GET", "/v1/hostexec/jobs/*").len(), 1);
}

#[tokio::test]
async fn admin_bodies_and_queries() {
    let (fake, client) = setup().await;
    fake.json(
        "PATCH",
        "/admin/agents/*/attributes",
        200,
        shapes::agent("hermes"),
    );
    fake.json(
        "POST",
        "/admin/grants/*/revoke",
        200,
        json!({"ok": true, "grant_id": shapes::GRANT_ID, "status": "revoked"}),
    );
    fake.json(
        "POST",
        "/admin/containment/lift",
        200,
        json!({"lifted": []}),
    );
    fake.json(
        "POST",
        "/admin/hosts/*/disarm",
        200,
        json!({"disarmed": true}),
    );

    client
        .admin_set_attributes("hermes", Some(""), None, Some("excelsior"))
        .await
        .unwrap();
    assert_eq!(
        fake.seen()[0].json(),
        json!({"runtime": "", "host": "excelsior"})
    );

    client
        .admin_revoke_grant(shapes::GRANT_ID, "revoked by admin")
        .await
        .unwrap();
    assert_eq!(fake.seen()[1].param("reason"), Some("revoked by admin"));

    client.admin_contain_lift(None).await.unwrap();
    client.admin_contain_lift(Some("0a1b2c3d")).await.unwrap();
    assert_eq!(fake.seen()[2].json(), json!({"all": true}));
    assert_eq!(fake.seen()[3].json(), json!({"id": "0a1b2c3d"}));

    let out: Value = client
        .admin_disarm("excelsior", Some("root"))
        .await
        .unwrap();
    assert_eq!(out, json!({"disarmed": true}));
    assert_eq!(fake.seen()[4].param("tier"), Some("root"));
}

#[tokio::test]
async fn unreachable_brokers_are_transport_errors() {
    let fake = FakeBroker::start().await.unwrap();
    let url = fake.url.clone();
    drop(fake);
    tokio::task::yield_now().await;
    let client = BrokerClient::new(config(&url)).unwrap();
    match client.me().await {
        Err(ClientError::Transport(_)) => {}
        other => panic!("{other:?}"),
    }
}
