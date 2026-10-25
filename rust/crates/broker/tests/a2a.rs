//! a2a threads, sessions, sweeps, webhooks and the operator's chat over
//! HTTP, against a real database (rust/spec/a2a-wiki-desktop.md §3-§6 and
//! §11; every a2a INV-n has a test here or in the store's tests).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_auth_broker::a2a::{self, A2a, A2aConfig};
use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::provisioners::{Provisioner, RequestSpec};
use agent_auth_broker::state::AppState;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::lifecycle::state;
use agent_auth_core::policy::Policy;
use agent_auth_core::{AgentId, Authority, Glob, GrantId, HumanApproval, RequestId, SessionId};
use agent_auth_crypto::{Secret, api_key};
use agent_auth_store::Store;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{self, GrantEnd};
use agent_auth_store::lockdown::{self, ContainmentSource, NewEntry};
use agent_auth_store::requests::{self, AnyRequest, Approval, Escalation, NewRequest, Request};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Request as HttpRequest, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";

struct T {
    app: Router,
    state: AppState,
    pool: PgPool,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn config() -> A2aConfig {
    A2aConfig {
        webhook_http_hosts: vec!["127.0.0.1".to_owned()],
        ..A2aConfig::default()
    }
}

fn setup_with(pool: PgPool, policy: Policy, config: A2aConfig) -> T {
    let mut state = AppState::new(
        Store::from_pool(pool.clone()),
        policy,
        AuthConfig {
            admin_token: Some(Secret::new(ADMIN.to_owned())),
            oauth_enabled: false,
            trust_x_real_ip: false,
        },
    );
    state.a2a = Arc::new(A2a::new(config));
    T {
        app: a2a::routes().with_state(state.clone()),
        state,
        pool,
    }
}

fn setup(pool: PgPool) -> T {
    setup_with(pool, Policy::default(), config())
}

enum Who<'a> {
    Agent(&'a str, Option<&'a str>),
    Admin,
}

fn ag(key: &str) -> Who<'_> {
    Who::Agent(key, None)
}

fn ses<'a>(key: &'a str, session: &'a str) -> Who<'a> {
    Who::Agent(key, Some(session))
}

impl T {
    async fn req(
        &self,
        method: Method,
        path: &str,
        who: Who<'_>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = HttpRequest::builder().method(method).uri(path);
        match who {
            Who::Agent(key, session) => {
                req = req.header("authorization", format!("Bearer {key}"));
                if let Some(s) = session {
                    req = req.header("x-agent-session", s);
                }
            }
            Who::Admin => req = req.header("authorization", format!("Bearer {ADMIN}")),
        }
        let body = match body {
            Some(b) => Body::from(b.to_string()),
            None => Body::empty(),
        };
        let res = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(&self, path: &str, who: Who<'_>) -> (StatusCode, Value) {
        self.req(Method::GET, path, who, None).await
    }

    async fn post(&self, path: &str, who: Who<'_>, body: Value) -> (StatusCode, Value) {
        self.req(Method::POST, path, who, Some(body)).await
    }

    async fn agent(&self, name: &str, kind: AgentKind) -> (AgentRow, String) {
        let key = api_key::generate().unwrap();
        let tx = self.state.store.begin().await.unwrap();
        let row = agents::insert(
            &tx,
            &agents::NewAgent {
                id: AgentId::new(),
                name,
                description: "",
                key_id: key.key_id.as_str(),
                api_key_hash: key.hash.as_str(),
                kind,
                webhook_url: None,
                webhook_secret: None,
                lldap_username: None,
                parent_agent_id: None,
                sandbox_id: None,
                runtime: None,
                project: None,
                host: None,
                placement: Placement::Host,
                lease_expires_at: None,
                last_seen_at: None,
                now: now(),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        (row, key.full_key.expose().clone())
    }

    /// A service agent that has polled for inbound threads.
    async fn service(&self, name: &str) -> (AgentRow, String) {
        let (row, key) = self.agent(name, AgentKind::Service).await;
        self.listen(&key).await;
        (row, key)
    }

    async fn listen(&self, key: &str) -> Value {
        let (s, v) = self.get("/v1/a2a/events?wait=0", ag(key)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v
    }

    async fn session(&self, key: &str, label: &str) -> String {
        let (s, v) = self
            .post("/v1/sessions", ag(key), json!({"label": label}))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(
            v["name"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{label}-"))
        );
        assert_eq!(v["name"].as_str().unwrap().len(), label.len() + 5);
        v["session_id"].as_str().unwrap().to_owned()
    }

    /// An ACTIVE a2a grant of `agent` to talk to `to`, through the kernel.
    async fn grant(&self, agent: &AgentRow, to: &str, topic: Option<&str>) -> GrantId {
        let authority = Authority::A2a {
            topic: topic.map(Glob::new),
        };
        let store = &self.state.store;
        let tx = store.begin().await.unwrap();
        let r = requests::insert(
            &tx,
            &NewRequest {
                id: RequestId::new(),
                agent_id: agent.id,
                session_id: None,
                delegation: None,
                platform: authority.platform(),
                resource: to,
                requested_capability: "talk",
                requested_scope: &json!({}),
                authority: Some(&authority),
                justification: "coordinate work",
                requested_duration_secs: 3600,
                risk_notes: &[],
                now: now(),
            },
        )
        .await
        .unwrap();
        let r =
            requests::transition::<_, state::AwaitingHuman>(&tx, r, Escalation::default(), now())
                .await
                .unwrap()
                .unwrap();
        let id = r.id();
        let r = requests::transition::<_, state::Approved>(
            &tx,
            r,
            Approval::human(HumanApproval::attest(id, "jrt"), "ok", 3600),
            now(),
        )
        .await
        .unwrap()
        .unwrap();
        let r: Request<state::Provisioning> = requests::transition(&tx, r, (), now())
            .await
            .unwrap()
            .unwrap();
        let nh = lockdown::check(&tx, agent.id, now())
            .await
            .unwrap()
            .unwrap();
        let g = grants::begin(&tx, &r, &nh, GrantId::new(), now())
            .await
            .unwrap()
            .unwrap();
        let g = grants::activate(&tx, g, &nh, &json!({"mode": "check_based"}))
            .await
            .unwrap()
            .unwrap();
        drop(nh);
        let Some(AnyRequest::Provisioning(r)) = requests::get(&tx, g.request_id).await.unwrap()
        else {
            panic!("not provisioning");
        };
        requests::transition::<_, state::Granted>(&tx, r, (), now())
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        g.id
    }

    async fn revoke(&self, grant: GrantId) {
        let tx = self.state.store.begin().await.unwrap();
        grants::end(
            &tx,
            grant,
            GrantEnd::Revoked {
                reason: "test".to_owned(),
            },
            now(),
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn open(
        &self,
        key: &str,
        session: Option<&str>,
        to: &str,
        topic: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut body = json!({"to": to, "payload": {"q": 1}});
        if let Some(t) = topic {
            body["topic"] = json!(t);
        }
        self.post("/v1/a2a/threads", Who::Agent(key, session), body)
            .await
    }

    async fn open_ok(&self, key: &str, to: &str) -> String {
        let (s, v) = self.open(key, None, to, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["thread_id"].as_str().unwrap().to_owned()
    }

    async fn sql(&self, q: &'static str, id: &str, secs_ago: i64) {
        sqlx::query(q)
            .bind(uuid::Uuid::parse_str(id).unwrap())
            .bind(now() - time::Duration::seconds(secs_ago))
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn thread_row(&self, id: &str) -> agent_auth_store::a2a::ThreadRow {
        let tx = self.state.store.begin().await.unwrap();
        agent_auth_store::a2a::get(&tx, id.parse().unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    async fn sweep(&self) -> a2a::SweepCounts {
        a2a::sweep(&self.state, now()).await.unwrap()
    }
}

/// Wait until `n` a2a long-polls are parked (each holds a slot): what a
/// test that wakes a long-poll waits for, instead of a sleep that guesses
/// how long the poll takes to get there (30 s at most).
async fn until_parked(state: &AppState, n: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while state.a2a.long_polls_in_progress() < n {
        assert!(
            std::time::Instant::now() < deadline,
            "no long-poll parked in 30 s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn detail(v: &Value) -> &str {
    v["detail"].as_str().unwrap_or_default()
}

// ------------------------------------------------------------ sessions

#[sqlx::test(migrations = "../store/migrations")]
async fn session_lifecycle(pool: PgPool) {
    let t = setup(pool);
    let (_, key) = t.agent("claude-host2", AgentKind::Ephemeral).await;
    let sid = t.session(&key, "agent-auth").await;
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&key, &sid)).await.0,
        StatusCode::OK
    );
    // A bogus session is a stale auth context: 401 with the exact text the
    // MCP client re-mints on.
    let (s, v) = t.get("/v1/a2a/threads", ses(&key, "bogus")).await;
    assert_eq!(
        (s, detail(&v)),
        (StatusCode::UNAUTHORIZED, "unknown or closed session")
    );
    // Closing: no header is 400; with it, the session never works again.
    let (s, v) = t.post("/v1/sessions/close", ag(&key), json!({})).await;
    assert_eq!(
        (s, detail(&v)),
        (StatusCode::BAD_REQUEST, "no X-Agent-Session header")
    );
    let (s, v) = t
        .post("/v1/sessions/close", ses(&key, &sid), json!({}))
        .await;
    assert_eq!(
        (s, v),
        (StatusCode::OK, json!({"ok": true, "threads_closed": 0}))
    );
    let (s, v) = t.get("/v1/a2a/threads", ses(&key, &sid)).await;
    assert_eq!(
        (s, detail(&v)),
        (StatusCode::UNAUTHORIZED, "unknown or closed session")
    );
    // Another agent's session is not yours.
    let (_, other) = t.agent("claude-host3", AgentKind::Ephemeral).await;
    let theirs = t.session(&other, "x").await;
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&key, &theirs)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Labels are checked.
    assert_eq!(
        t.post("/v1/sessions", ag(&key), json!({"label": "has space"}))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

// ----------------------------------------------------------- handshake

/// INV-7, INV-8, INV-9: only the responder moves a pending thread; seqs
/// are contiguous; nothing lands on a closed thread.
#[sqlx::test(migrations = "../store/migrations")]
async fn explicit_accept_and_close(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-open1").await;
    let (_, r) = t.service("svc-resp1").await;
    t.grant(&s_row, "svc-resp1", None).await;
    let (st, thread) = t.open(&s, None, "svc-resp1", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(thread["state"], "pending_open");
    assert_eq!(thread["role"], "initiator");
    assert_eq!(thread["last_seq"], 1);
    let tid = thread["thread_id"].as_str().unwrap();

    let (st, v) = t
        .post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&s), json!({}))
        .await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::FORBIDDEN,
            "only the thread responder may do this"
        )
    );
    let (st, v) = t
        .post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        (v["state"].as_str(), v["role"].as_str()),
        (Some("open"), Some("responder"))
    );
    let (st, v) = t
        .post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::CONFLICT,
            "thread is not pending_open (state open)"
        )
    );

    for (n, key) in [(2, &s), (3, &r), (4, &s)] {
        let (st, v) = t
            .post(
                &format!("/v1/a2a/threads/{tid}/messages"),
                ag(key),
                json!({"payload": {"n": n}}),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(v["seq"], n);
        assert_eq!(v["thread_state"], "open");
    }
    let (_, read) = t
        .get(&format!("/v1/a2a/threads/{tid}/messages"), ag(&r))
        .await;
    let seqs: Vec<i64> = read["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 2, 3, 4]);
    assert_eq!(read["thread"]["last_seq"], 4);

    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/close"),
            ag(&s),
            json!({"reason": "done"}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        (
            v["state"].as_str(),
            v["close_reason"].as_str(),
            v["close_note"].as_str()
        ),
        (Some("closed"), Some("closed"), Some("done"))
    );
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&r),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::CONFLICT, "thread is closed (closed)")
    );
    let (st, _) = t
        .post(&format!("/v1/a2a/threads/{tid}/close"), ag(&r), json!({}))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    // The body is required (send {} at least).
    let (st, _) = t
        .req(
            Method::POST,
            &format!("/v1/a2a/threads/{tid}/close"),
            ag(&r),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(t.thread_row(tid).await.last_seq, 4);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn reject(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-open2").await;
    let (_, r) = t.service("svc-resp2").await;
    t.grant(&s_row, "svc-resp2", None).await;
    let tid = t.open_ok(&s, "svc-resp2").await;
    let (st, _) = t
        .post(&format!("/v1/a2a/threads/{tid}/reject"), ag(&s), json!({}))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/reject"),
            ag(&r),
            json!({"reason": "busy, try later"}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        (
            v["state"].as_str(),
            v["close_reason"].as_str(),
            v["close_note"].as_str()
        ),
        (Some("closed"), Some("rejected"), Some("busy, try later"))
    );
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await;
    assert_eq!(seen["close_reason"], "rejected");
    let row = t.thread_row(&tid).await;
    assert!(row.closed_by.is_some());
}

/// INV-8.
#[sqlx::test(migrations = "../store/migrations")]
async fn initiator_cannot_send_on_pending_open(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-open3").await;
    t.service("svc-resp3").await;
    t.grant(&s_row, "svc-resp3", None).await;
    let tid = t.open_ok(&s, "svc-resp3").await;
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&s),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(
        detail(&v)
            .starts_with("thread is pending_open: your opening message already rides the open")
    );
    assert_eq!(t.thread_row(&tid).await.last_seq, 1);
}

/// INV-1: to anyone else a thread does not exist.
#[sqlx::test(migrations = "../store/migrations")]
async fn non_participant_gets_404(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-open4").await;
    t.service("svc-resp4").await;
    let (_, c) = t.service("svc-nosy").await;
    t.grant(&s_row, "svc-resp4", None).await;
    let tid = t.open_ok(&s, "svc-resp4").await;
    let missing = SessionId::new().to_string();
    for id in [tid.as_str(), missing.as_str(), "not-a-uuid"] {
        for (m, path, body) in [
            (Method::GET, format!("/v1/a2a/threads/{id}"), None),
            (Method::GET, format!("/v1/a2a/threads/{id}/messages"), None),
            (
                Method::POST,
                format!("/v1/a2a/threads/{id}/messages"),
                Some(json!({"payload": {}})),
            ),
            (
                Method::POST,
                format!("/v1/a2a/threads/{id}/accept"),
                Some(json!({})),
            ),
            (
                Method::POST,
                format!("/v1/a2a/threads/{id}/reject"),
                Some(json!({})),
            ),
            (
                Method::POST,
                format!("/v1/a2a/threads/{id}/close"),
                Some(json!({})),
            ),
        ] {
            let (st, v) = t.req(m, &path, ag(&c), body).await;
            assert_eq!(
                (st, detail(&v)),
                (StatusCode::NOT_FOUND, "unknown thread"),
                "{path}"
            );
        }
    }
    let (_, listed) = t.get("/v1/a2a/threads", ag(&c)).await;
    assert_eq!(listed, json!([]));
}

// --------------------------------------------- responder-side sessions

/// INV-2 on the responder side, and wake routing to the bound worker.
#[sqlx::test(migrations = "../store/migrations")]
async fn responder_session_binding(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-disp").await;
    let (_, r) = t.service("svc-worker-pool").await;
    t.grant(&s_row, "svc-worker-pool", None).await;
    let tid = t.open_ok(&s, "svc-worker-pool").await;

    let (_, disp) = t.get("/v1/a2a/events", ag(&r)).await;
    assert_eq!(disp["pending_opens"][0]["thread_id"], tid.as_str());
    let worker = t.session(&r, "task-cactus").await;
    let (_, wev) = t.get("/v1/a2a/events", ses(&r, &worker)).await;
    assert_eq!(wev["pending_opens"], json!([]));

    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/accept"),
            ses(&r, &worker),
            json!({}),
        )
        .await;
    assert_eq!((st, v["state"].as_str()), (StatusCode::OK, Some("open")));

    let (st, v) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&r)).await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::FORBIDDEN,
            "thread is bound to a different session of this agent"
        )
    );
    let other = t.session(&r, "task-other").await;
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}"), ses(&r, &other))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ses(&r, &other),
            json!({"payload": {}})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ses(&r, &worker),
            json!({"payload": {"done": 1}})
        )
        .await
        .0,
        StatusCode::OK
    );

    let (_, mine) = t.get("/v1/a2a/threads", ses(&r, &worker)).await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
    // a2a B8: the dispatcher's events leave out a thread a worker claimed
    // (every read of it would 403); the initiator, sessionless on its own
    // side, still sees it.
    let (_, disp) = t.get("/v1/a2a/events", ag(&r)).await;
    assert_eq!(disp["activity"], json!([]));
    let (_, init) = t.get("/v1/a2a/events", ag(&s)).await;
    assert_eq!(init["activity"][0]["thread_id"], tid.as_str());
    assert_eq!(t.get("/v1/a2a/threads", ses(&r, &other)).await.1, json!([]));

    // The worker's parked events poll wakes on the initiator's message.
    let cursor = wev["cursor"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| agent_auth_wire::timestamp::format(now()).unwrap());
    let sender = {
        let (app, state) = (t.app.clone(), t.state.clone());
        let (s, tid) = (s.clone(), tid.clone());
        tokio::spawn(async move {
            until_parked(&state, 1).await;
            let req = HttpRequest::builder()
                .method(Method::POST)
                .uri(format!("/v1/a2a/threads/{tid}/messages"))
                .header("authorization", format!("Bearer {s}"))
                .body(Body::from(json!({"payload": {"more": true}}).to_string()))
                .unwrap();
            app.oneshot(req).await.unwrap().status()
        })
    };
    let started = std::time::Instant::now();
    let (_, ev) = t
        .get(
            &format!("/v1/a2a/events?wait=60&after={cursor}"),
            ses(&r, &worker),
        )
        .await;
    assert_eq!(sender.await.unwrap(), StatusCode::OK);
    assert!(
        started.elapsed() < Duration::from_secs(45),
        "woke on the message, not the deadline"
    );
    let ids: Vec<&str> = ev["activity"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["thread_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [tid.as_str()]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn implicit_accept_binds_replying_session(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-disp2").await;
    let (_, r) = t.service("svc-worker2").await;
    t.grant(&s_row, "svc-worker2", None).await;
    let tid = t.open_ok(&s, "svc-worker2").await;
    let worker = t.session(&r, "task-x").await;
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ses(&r, &worker),
            json!({"payload": {"claimed": true}}),
        )
        .await;
    assert_eq!(
        (st, v["thread_state"].as_str(), v["seq"].as_i64()),
        (StatusCode::OK, Some("open"), Some(2))
    );
    let row = t.thread_row(&tid).await;
    assert_eq!(
        row.responder_session_id.map(|s| s.to_string()),
        Some(worker.clone())
    );
    assert!(row.accepted_at.is_some());

    let tid2 = t.open_ok(&s, "svc-worker2").await;
    assert_eq!(
        t.post(&format!("/v1/a2a/threads/{tid2}/accept"), ag(&r), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(t.thread_row(&tid2).await.responder_session_id.is_none());
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid2}"), ag(&r)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid2}"), ses(&r, &worker))
            .await
            .0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn responder_session_death_closes_thread(pool: PgPool) {
    let t = setup(pool);
    let cfg = A2aConfig::default();
    let (s_row, s) = t.service("auto-disp3").await;
    let (_, r) = t.service("svc-worker3").await;
    t.grant(&s_row, "svc-worker3", None).await;
    let tid = t.open_ok(&s, "svc-worker3").await;
    let worker = t.session(&r, "task-y").await;
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/accept"),
            ses(&r, &worker),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );

    // The initiator's liveness view is the worker session's, not the agent's.
    t.sql(
        "UPDATE agent_sessions SET last_seen_at = $2 WHERE id = $1",
        &worker,
        cfg.liveness_threshold.whole_seconds() + 60,
    )
    .await;
    t.get("/v1/a2a/threads", ag(&r)).await; // the agent itself is alive
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await;
    assert_eq!(seen["peer_alive"], false);

    t.sql(
        "UPDATE agent_sessions SET last_seen_at = $2 WHERE id = $1",
        &worker,
        cfg.session_idle_timeout.whole_seconds() + 60,
    )
    .await;
    let counts = t.sweep().await;
    assert_eq!(counts.sessions_idled, 1);
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await;
    assert_eq!(
        (seen["state"].as_str(), seen["close_reason"].as_str()),
        (Some("closed"), Some("peer_gone"))
    );
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&r, &worker)).await.0,
        StatusCode::UNAUTHORIZED
    );

    let tid2 = t.open_ok(&s, "svc-worker3").await;
    let worker2 = t.session(&r, "task-z").await;
    t.post(
        &format!("/v1/a2a/threads/{tid2}/accept"),
        ses(&r, &worker2),
        json!({}),
    )
    .await;
    let (_, v) = t
        .post("/v1/sessions/close", ses(&r, &worker2), json!({}))
        .await;
    assert_eq!(v["threads_closed"], 1);
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid2}"), ag(&s)).await;
    assert_eq!(seen["close_reason"], "peer_gone");
}

// -------------------------------------------------- per-session grants

/// INV-3: an ephemeral agent never uses a2a without a session.
#[sqlx::test(migrations = "../store/migrations")]
async fn grants_shared_across_sessions_threads_are_not(pool: PgPool) {
    let t = setup(pool);
    t.service("svc-homelab").await;
    let (desk, key) = t.agent("claude-desk", AgentKind::Ephemeral).await;
    let a = t.session(&key, "proj-a").await;
    t.grant(&desk, "svc-homelab", None).await;
    assert_eq!(
        t.open(&key, Some(&a), "svc-homelab", None).await.0,
        StatusCode::OK
    );
    let b = t.session(&key, "proj-b").await;
    let (_, check) = t.get("/v1/a2a/check?peer=svc-homelab", ses(&key, &b)).await;
    assert_eq!(check["allowed"], true);
    assert_eq!(
        t.open(&key, Some(&b), "svc-homelab", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&key, &a))
            .await
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (st, v) = t.open(&key, None, "svc-homelab", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(detail(&v).starts_with("ephemeral agents must open a session before using a2a"));
}

/// INV-2 on the initiator side, INV-3.
#[sqlx::test(migrations = "../store/migrations")]
async fn thread_access_bound_to_session(pool: PgPool) {
    let t = setup(pool);
    t.service("svc-bound").await;
    let (row, key) = t.agent("claude-bound", AgentKind::Ephemeral).await;
    let a = t.session(&key, "proj-a").await;
    t.grant(&row, "svc-bound", None).await;
    let (_, th) = t.open(&key, Some(&a), "svc-bound", None).await;
    let tid = th["thread_id"].as_str().unwrap();
    let b = t.session(&key, "proj-b").await;
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}"), ses(&key, &b))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}/messages"), ses(&key, &b))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/close"),
            ses(&key, &b),
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ses(&key, &b),
            json!({"payload": {}})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(t.get("/v1/a2a/threads", ses(&key, &b)).await.1, json!([]));
    let (_, ev) = t.get("/v1/a2a/events", ses(&key, &b)).await;
    assert_eq!(
        (ev["pending_opens"].clone(), ev["activity"].clone()),
        (json!([]), json!([]))
    );
    for path in [
        format!("/v1/a2a/threads/{tid}"),
        format!("/v1/a2a/threads/{tid}/messages"),
        "/v1/a2a/threads".to_owned(),
        "/v1/a2a/events".to_owned(),
    ] {
        assert_eq!(
            t.get(&path, ag(&key)).await.0,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}"), ses(&key, &a))
            .await
            .0,
        StatusCode::OK
    );
}

/// INV-4: threads only to enabled service agents; the a2a validator
/// refuses grants to anything else.
#[sqlx::test(migrations = "../store/migrations")]
async fn ephemeral_cannot_receive(pool: PgPool) {
    let t = setup(pool);
    let (caller, s) = t.service("auto-caller").await;
    let (_, _) = t.agent("claude-target", AgentKind::Ephemeral).await;
    let (dis, _) = t.service("svc-disabled").await;

    let p = a2a::provisioner::A2aProvisioner;
    let tx = t.state.store.begin().await.unwrap();
    for (resource, want) in [
        (
            "claude-target",
            "a2a targets must be service agents; 'claude-target' is ephemeral and can only initiate threads itself",
        ),
        ("auto-caller", "agent cannot request a2a access to itself"),
        ("nobody", "unknown target agent 'nobody'"),
    ] {
        let spec = RequestSpec {
            agent: &caller,
            resource: resource.to_owned(),
            authority: Authority::A2a { topic: None },
        };
        assert_eq!(
            p.validate(&tx, spec, now()).await.unwrap().unwrap_err().0,
            want
        );
    }
    let spec = RequestSpec {
        agent: &caller,
        resource: "svc-disabled".to_owned(),
        authority: Authority::A2a { topic: None },
    };
    assert!(p.validate(&tx, spec, now()).await.unwrap().is_ok());
    agents::set_disabled(&tx, dis.id, true).await.unwrap();
    let spec = RequestSpec {
        agent: &caller,
        resource: "svc-disabled".to_owned(),
        authority: Authority::A2a { topic: None },
    };
    assert!(p.validate(&tx, spec, now()).await.unwrap().is_err());
    tx.commit().await.unwrap();

    // A manufactured grant still opens nothing.
    t.grant(&caller, "claude-target", None).await;
    let (st, v) = t.open(&s, None, "claude-target", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(detail(&v).contains("ephemeral"));
    t.grant(&caller, "svc-disabled", None).await;
    let (st, v) = t.open(&s, None, "svc-disabled", None).await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::NOT_FOUND, "unknown agent 'svc-disabled'")
    );
    let (st, v) = t.open(&s, None, "nobody", None).await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::NOT_FOUND, "unknown agent 'nobody'")
    );
}

/// INV-5: topic globs at open; a topic-less open matches only unscoped
/// grants; the check without a topic reports any grant.
#[sqlx::test(migrations = "../store/migrations")]
async fn topic_glob_enforced_at_open(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-topic").await;
    t.service("svc-topic").await;
    t.grant(&s_row, "svc-topic", Some("deploy/*")).await;
    assert_eq!(
        t.open(&s, None, "svc-topic", Some("deploy/cactus")).await.0,
        StatusCode::OK
    );
    let (st, v) = t.open(&s, None, "svc-topic", Some("gossip")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        detail(&v),
        "no active a2a grant to talk to 'svc-topic'; request one via POST /v1/requests {\"platform\": \"a2a\", \"capability\": \"talk\", \"resource\": \"svc-topic\"} — topic-scoped grants also require an explicit matching topic on the open"
    );
    assert_eq!(
        t.open(&s, None, "svc-topic", None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/v1/a2a/check?peer=svc-topic", ag(&s)).await.1["allowed"],
        true
    );
    let (_, c) = t
        .get("/v1/a2a/check?peer=svc-topic&topic=gossip", ag(&s))
        .await;
    assert_eq!(
        (c["allowed"].clone(), c["reason"].clone()),
        (json!(false), json!("no active a2a grant"))
    );
    let (s2_row, s2) = t.service("auto-topic2").await;
    t.grant(&s2_row, "svc-topic", None).await;
    assert_eq!(t.open(&s2, None, "svc-topic", None).await.0, StatusCode::OK);
    // A topic with a newline is refused at the body.
    assert_eq!(
        t.open(&s2, None, "svc-topic", Some("a\nb")).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // direction=in: may the peer open to me?
    let (_, c) = t
        .get("/v1/a2a/check?peer=auto-topic2&direction=in", ag(&s))
        .await;
    assert_eq!(c["allowed"], false);
    let (st, v) = t
        .get("/v1/a2a/check?peer=svc-topic&direction=sideways", ag(&s))
        .await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::BAD_REQUEST, "direction must be 'out' or 'in'")
    );
}

// ---------------------------------------------------------- long-polls

#[sqlx::test(migrations = "../store/migrations")]
async fn message_longpoll_wakes_on_reply_and_does_not_mark_listening(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.agent("auto-poll", AgentKind::Service).await;
    let (_, r) = t.service("svc-poll").await;
    t.grant(&s_row, "svc-poll", None).await;
    let tid = t.open_ok(&s, "svc-poll").await;
    let replier = {
        let (app, state) = (t.app.clone(), t.state.clone());
        let (r, tid) = (r.clone(), tid.clone());
        tokio::spawn(async move {
            until_parked(&state, 1).await;
            let req = HttpRequest::builder()
                .method(Method::POST)
                .uri(format!("/v1/a2a/threads/{tid}/messages"))
                .header("authorization", format!("Bearer {r}"))
                .body(Body::from(json!({"payload": {"answer": 42}}).to_string()))
                .unwrap();
            app.oneshot(req).await.unwrap().status()
        })
    };
    let started = std::time::Instant::now();
    let (_, body) = t
        .get(
            &format!("/v1/a2a/threads/{tid}/messages?after_seq=1&wait=60"),
            ag(&s),
        )
        .await;
    assert_eq!(replier.await.unwrap(), StatusCode::OK);
    assert!(started.elapsed() < Duration::from_secs(45));
    assert_eq!(body["messages"][0]["payload"], json!({"answer": 42}));
    assert_eq!(body["messages"][0]["from"], "svc-poll");
    let (_, body) = t
        .get(
            &format!("/v1/a2a/threads/{tid}/messages?after_seq=2&wait=0.5"),
            ag(&s),
        )
        .await;
    assert_eq!(body["messages"], json!([]));
    // a2a B2: long-polling replies is not listening for threads.
    let tx = t.state.store.begin().await.unwrap();
    assert!(
        agents::get(&tx, s_row.id)
            .await
            .unwrap()
            .unwrap()
            .last_listen_at
            .is_none()
    );
    // INV-20: NaN and negative waits do not wait; garbage is 422.
    for w in ["nan", "-5", "NaN"] {
        let started = std::time::Instant::now();
        let (st, _) = t
            .get(
                &format!("/v1/a2a/threads/{tid}/messages?after_seq=9&wait={w}"),
                ag(&s),
            )
            .await;
        assert_eq!(st, StatusCode::OK);
        // No wait at all; the cap (what a NaN taken as "forever" would
        // wait) is 300 s.
        assert!(started.elapsed() < Duration::from_secs(30));
    }
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}/messages?wait=soon"), ag(&s))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn events_longpoll_and_cursor(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-ev").await;
    let (_, r) = t.service("svc-ev").await;
    t.grant(&s_row, "svc-ev", None).await;
    // The open waits for the events poll to park: polling it is also
    // what makes svc-ev reachable.
    let opener = {
        let (app, state) = (t.app.clone(), t.state.clone());
        let s = s.clone();
        tokio::spawn(async move {
            until_parked(&state, 1).await;
            let req = HttpRequest::builder()
                .method(Method::POST)
                .uri("/v1/a2a/threads")
                .header("authorization", format!("Bearer {s}"))
                .body(Body::from(
                    json!({"to": "svc-ev", "payload": {}}).to_string(),
                ))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        })
    };
    let (_, body) = t.get("/v1/a2a/events?wait=60", ag(&r)).await;
    let thread = opener.await.unwrap();
    assert_eq!(body["pending_opens"][0]["thread_id"], thread["thread_id"]);
    let cursor = body["cursor"].as_str().expect("cursor").to_owned();
    assert!(!cursor.contains('+'), "the cursor needs no URL-encoding");
    let (_, again) = t
        .get(&format!("/v1/a2a/events?wait=0&after={cursor}"), ag(&r))
        .await;
    assert_eq!(again["activity"], json!([]));
    assert_eq!(again["pending_opens"][0]["thread_id"], thread["thread_id"]);
    assert_eq!(again["cursor"], cursor.as_str());
    // A bad cursor is 422.
    assert_eq!(
        t.get("/v1/a2a/events?after=yesterday", ag(&r)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Activity after the cursor shows up once, then the cursor moves past it.
    let tid = thread["thread_id"].as_str().unwrap();
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;
    let (_, ev) = t
        .get(&format!("/v1/a2a/events?after={cursor}"), ag(&s))
        .await;
    assert_eq!(ev["activity"][0]["state"], "open");
    let c2 = ev["cursor"].as_str().unwrap();
    assert_eq!(ev["activity"][0]["last_activity_at"], c2);
    let (_, ev) = t.get(&format!("/v1/a2a/events?after={c2}"), ag(&s)).await;
    assert_eq!(ev["activity"], json!([]));
}

// --------------------------------------------------------------- sweeps

#[sqlx::test(migrations = "../store/migrations")]
async fn sweeps(pool: PgPool) {
    let t = setup(pool);
    let cfg = A2aConfig::default();
    let (s_row, s) = t.service("auto-sweep").await;
    let (_, r) = t.service("svc-sweep").await;
    t.grant(&s_row, "svc-sweep", None).await;

    let pending = t.open_ok(&s, "svc-sweep").await;
    t.sql(
        "UPDATE a2a_threads SET created_at = $2 WHERE id = $1",
        &pending,
        cfg.open_timeout.whole_seconds() + 60,
    )
    .await;
    let idle = t.open_ok(&s, "svc-sweep").await;
    t.post(&format!("/v1/a2a/threads/{idle}/accept"), ag(&r), json!({}))
        .await;
    t.sql(
        "UPDATE a2a_threads SET last_activity_at = $2 WHERE id = $1",
        &idle,
        cfg.thread_idle_timeout.whole_seconds() + 60,
    )
    .await;
    // A pending thread is never idle-swept, only open-timed-out.
    let young = t.open_ok(&s, "svc-sweep").await;
    t.sql(
        "UPDATE a2a_threads SET last_activity_at = $2 WHERE id = $1",
        &young,
        cfg.thread_idle_timeout.whole_seconds() + 60,
    )
    .await;

    let counts = t.sweep().await;
    assert_eq!(
        (
            counts.open_timeout,
            counts.idle_timeout,
            counts.grant_revoked
        ),
        (1, 1, 0)
    );
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{pending}"), ag(&s)).await.1["close_reason"],
        "open_timeout"
    );
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{idle}"), ag(&s)).await.1["close_reason"],
        "idle_timeout"
    );
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{young}"), ag(&s)).await.1["state"],
        "pending_open"
    );
    assert_eq!(t.sweep().await, a2a::SweepCounts::default());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn idle_session_sweep_closes_threads_peer_gone(pool: PgPool) {
    let t = setup(pool);
    let cfg = A2aConfig::default();
    t.service("svc-sweep3").await;
    let (row, key) = t.agent("claude-sweep", AgentKind::Ephemeral).await;
    let stale = t.session(&key, "worktree").await;
    let fresh = t.session(&key, "fresh").await;
    t.grant(&row, "svc-sweep3", None).await;
    let (_, th) = t.open(&key, Some(&stale), "svc-sweep3", None).await;
    let tid = th["thread_id"].as_str().unwrap();
    t.sql(
        "UPDATE agent_sessions SET last_seen_at = $2 WHERE id = $1",
        &stale,
        cfg.session_idle_timeout.whole_seconds() + 60,
    )
    .await;
    assert_eq!(t.sweep().await.sessions_idled, 1);
    let row = t.thread_row(tid).await;
    assert_eq!(
        row.close_reason,
        Some(agent_auth_store::a2a::CloseReason::PeerGone)
    );
    assert!(row.closed_by.is_none());
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&key, &stale)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        t.get("/v1/a2a/threads", ses(&key, &fresh)).await.0,
        StatusCode::OK
    );
}

/// INV-6: a dead backing grant closes the thread and stores nothing,
/// lazily on send or from the sweep.
#[sqlx::test(migrations = "../store/migrations")]
async fn grant_revocation_closes_thread(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-rev1").await;
    let (_, r) = t.service("svc-rev1").await;
    let g = t.grant(&s_row, "svc-rev1", None).await;
    let tid = t.open_ok(&s, "svc-rev1").await;
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;
    t.revoke(g).await;
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&s),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::FORBIDDEN,
            "backing grant is no longer active; thread closed"
        )
    );
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&r)).await;
    assert_eq!(
        (seen["state"].as_str(), seen["close_reason"].as_str()),
        (Some("closed"), Some("grant_revoked"))
    );
    assert_eq!(seen["last_seq"], 1, "nothing was stored");
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&r),
            json!({"payload": {}})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // The responder's first reply on a pending thread with a dead grant.
    let g2 = t.grant(&s_row, "svc-rev1", None).await;
    let tid2 = t.open_ok(&s, "svc-rev1").await;
    t.revoke(g2).await;
    let (st, _) = t
        .post(
            &format!("/v1/a2a/threads/{tid2}/messages"),
            ag(&r),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(t.thread_row(&tid2).await.last_seq, 1);

    // Sweep path: nobody sends.
    let (s2_row, s2) = t.service("auto-rev2").await;
    t.service("svc-rev2").await;
    let g3 = t.grant(&s2_row, "svc-rev2", None).await;
    let tid3 = t.open_ok(&s2, "svc-rev2").await;
    t.revoke(g3).await;
    assert_eq!(t.sweep().await.grant_revoked, 1);
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid3}"), ag(&s2)).await.1["close_reason"],
        "grant_revoked"
    );
}

// ------------------------------------------------------------- liveness

#[sqlx::test(migrations = "../store/migrations")]
async fn peer_liveness_fields(pool: PgPool) {
    let t = setup(pool);
    let cfg = A2aConfig::default();
    let (s_row, s) = t.service("auto-live").await;
    let (r_row, _) = t.service("svc-live").await;
    t.grant(&s_row, "svc-live", None).await;
    let tid = t.open_ok(&s, "svc-live").await;
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await;
    assert_eq!(
        (seen["peer"].as_str(), seen["peer_alive"].as_bool()),
        (Some("svc-live"), Some(true))
    );
    t.sql(
        "UPDATE agents SET last_seen_at = $2 WHERE id = $1",
        &r_row.id.to_string(),
        cfg.liveness_threshold.whole_seconds() + 60,
    )
    .await;
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await.1["peer_alive"],
        false
    );
}

/// INV-21: reachable means listening, not merely calling the broker.
#[sqlx::test(migrations = "../store/migrations")]
async fn requesting_access_does_not_make_a_peer_reachable(pool: PgPool) {
    let t = setup(pool);
    let cfg = A2aConfig::default();
    let (s_row, s) = t.service("auto-reach").await;
    let (busy_row, busy) = t.agent("svc-busy", AgentKind::Service).await;
    t.grant(&s_row, "svc-busy", None).await;
    for _ in 0..3 {
        assert_eq!(t.get("/v1/a2a/threads", ag(&busy)).await.0, StatusCode::OK);
    }
    let (_, check) = t.get("/v1/a2a/check?peer=svc-busy", ag(&s)).await;
    assert_eq!(check["allowed"], true);
    assert_eq!(
        (
            check["peer"]["reachable"].clone(),
            check["peer"]["why"].clone()
        ),
        (json!(false), json!("idle"))
    );
    assert!(check["reason"].as_str().unwrap().contains("not listening"));
    let before = t.thread_count().await;
    let (st, v) = t.open(&s, None, "svc-busy", None).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(detail(&v).starts_with(
        "'svc-busy' is registered but not listening for threads (no webhook, last polled never)"
    ));
    assert_eq!(
        t.thread_count().await,
        before,
        "a refused open creates nothing"
    );
    t.listen(&busy).await;
    assert_eq!(t.open(&s, None, "svc-busy", None).await.0, StatusCode::OK);
    // Listening ages out.
    t.sql(
        "UPDATE agents SET last_listen_at = $2 WHERE id = $1",
        &busy_row.id.to_string(),
        cfg.listen_threshold.whole_seconds() + 60,
    )
    .await;
    assert_eq!(
        t.open(&s, None, "svc-busy", None).await.0,
        StatusCode::CONFLICT
    );
}

impl T {
    async fn thread_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM a2a_threads")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn ephemeral_peer_is_403_not_409(pool: PgPool) {
    let t = setup(pool);
    let (_, s) = t.service("auto-kinds").await;
    t.agent("claude-cli", AgentKind::Ephemeral).await;
    let (st, v) = t.open(&s, None, "claude-cli", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(detail(&v).contains("initiate-only"));
    let (_, c) = t.get("/v1/a2a/check?peer=claude-cli", ag(&s)).await;
    assert_eq!(
        (c["peer"]["addressable"].clone(), c["peer"]["why"].clone()),
        (json!(false), json!("ephemeral"))
    );
}

/// INV-4 (demotion half): an agent that can no longer receive threads has
/// its inbound ones closed `peer_gone`; its outbound ones stay.
#[sqlx::test(migrations = "../store/migrations")]
async fn demotion_orphans_inbound_threads(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-demote").await;
    let (mis_row, mis) = t.service("claude-mis").await;
    t.grant(&s_row, "claude-mis", None).await;
    t.grant(&mis_row, "auto-demote", None).await;
    let inbound = t.open_ok(&s, "claude-mis").await;
    let outbound = t.open_ok(&mis, "auto-demote").await;
    let tx = t.state.store.begin().await.unwrap();
    agents::set_kind(&tx, mis_row.id, AgentKind::Ephemeral)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a2a::orphan_inbound(&t.state, mis_row.id).await.unwrap(), 1);
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{inbound}"), ag(&s)).await;
    assert_eq!(
        (seen["state"].as_str(), seen["close_reason"].as_str()),
        (Some("closed"), Some("peer_gone"))
    );
    assert_eq!(
        t.thread_row(&outbound).await.state,
        agent_auth_store::a2a::ThreadState::PendingOpen
    );
    let (st, v) = t.open(&s, None, "claude-mis", None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(detail(&v).contains("initiate-only"));
}

/// a2a B7 and B6: a disabled agent's threads close, and the check calls it
/// unknown as the open does.
#[sqlx::test(migrations = "../store/migrations")]
async fn disabling_an_agent_closes_its_threads(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-dis").await;
    let (r_row, _) = t.service("svc-dis").await;
    t.grant(&s_row, "svc-dis", None).await;
    let tid = t.open_ok(&s, "svc-dis").await;
    let tx = t.state.store.begin().await.unwrap();
    agents::set_disabled(&tx, r_row.id, true).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a2a::on_agent_disabled(&t.state, r_row.id).await.unwrap(), 1);
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{tid}"), ag(&s)).await;
    assert_eq!(seen["close_reason"], "peer_gone");
    let (_, c) = t.get("/v1/a2a/check?peer=svc-dis", ag(&s)).await;
    assert_eq!(
        c,
        json!({"allowed": false, "grant_id": null, "expires_at": null, "reason": "unknown agent 'svc-dis'", "peer": null})
    );
}

/// INV-11: nothing opens, accepts or sends while either side is held;
/// containment closes the held agent's threads; the operator is exempt.
#[sqlx::test(migrations = "../store/migrations")]
async fn containment_stops_a2a(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-held").await;
    let (r_row, r) = t.service("svc-held").await;
    t.grant(&s_row, "svc-held", None).await;
    let pending = t.open_ok(&s, "svc-held").await;
    let open = t.open_ok(&s, "svc-held").await;
    t.post(&format!("/v1/a2a/threads/{open}/accept"), ag(&r), json!({}))
        .await;
    let tx = t.state.store.begin().await.unwrap();
    lockdown::record(
        &tx,
        &NewEntry {
            id: "0badc0de",
            r#match: &json!({"name": "svc-held"}),
            reason: "test",
            evidence: "",
            by: "jrt",
            source: ContainmentSource::Operator,
            at: now(),
        },
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    let held = "svc-held is contained (0badc0de): no a2a while it is held";
    let (st, v) = t.open(&s, None, "svc-held", None).await;
    assert_eq!((st, detail(&v)), (StatusCode::FORBIDDEN, held));
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{pending}/accept"),
            ag(&r),
            json!({}),
        )
        .await;
    assert_eq!((st, detail(&v)), (StatusCode::FORBIDDEN, held));
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{open}/messages"),
            ag(&s),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!((st, detail(&v)), (StatusCode::FORBIDDEN, held));
    assert_eq!(t.thread_row(&open).await.last_seq, 1);
    // Ending a thread is always allowed.
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{pending}/reject"),
            ag(&r),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    // The operator may still talk to a held agent.
    let (st, v) = t
        .post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "svc-held", "text": "what were you doing?"}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        a2a::close_all_for(&t.state, r_row.id, "contained")
            .await
            .unwrap(),
        2
    );
    let (_, seen) = t.get(&format!("/v1/a2a/threads/{open}"), ag(&s)).await;
    assert_eq!(
        (seen["close_reason"].as_str(), seen["close_note"].as_str()),
        (Some("closed"), Some("contained"))
    );
}

/// a2a B5: zones hold on open and send, not only on the grant request.
#[sqlx::test(migrations = "../store/migrations")]
async fn zones_hold_on_open_and_send(pool: PgPool) {
    let policy =
        Policy::from_yaml("projects: {soc: {}}\nrestricted:\n  soc: {members: [{project: soc}]}\n")
            .unwrap();
    let t = setup_with(pool, policy, config());
    let (s_row, s) = t.service("auto-out").await;
    let (inside, inside_key) = t.service("svc-soc").await;
    t.grant(&s_row, "svc-soc", None).await;
    let tid = t.open_ok(&s, "svc-soc").await;
    t.post(
        &format!("/v1/a2a/threads/{tid}/accept"),
        ag(&inside_key),
        json!({}),
    )
    .await;
    // Now svc-soc joins the zone.
    let tx = t.state.store.begin().await.unwrap();
    agents::set_attributes(&tx, inside.id, None, Some("soc"), None, Placement::Host)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (st, v) = t.open(&s, None, "svc-soc", None).await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::NOT_FOUND, "unknown agent 'svc-soc'")
    );
    let (st, _) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&s),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        t.get("/v1/a2a/check?peer=svc-soc", ag(&s)).await.1["reason"],
        "unknown agent 'svc-soc'"
    );
    // The catalog leaves it out too.
    let tx = t.state.store.begin().await.unwrap();
    let entry = a2a::catalog_entry(&t.state, &tx, &s_row, now())
        .await
        .unwrap();
    let names: Vec<String> = entry.peers.unwrap().into_iter().map(|p| p.name).collect();
    assert!(!names.contains(&"svc-soc".to_owned()));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn catalog_peers_reachable_first(pool: PgPool) {
    let t = setup(pool);
    let (me, _) = t.service("auto-me").await;
    t.agent("svc-b-asleep", AgentKind::Service).await;
    t.service("svc-z-awake").await;
    t.service("svc-a-awake").await;
    t.agent("claude-eph", AgentKind::Ephemeral).await;
    let tx = t.state.store.begin().await.unwrap();
    let entry = a2a::catalog_entry(&t.state, &tx, &me, now()).await.unwrap();
    let v = serde_json::to_value(&entry).unwrap();
    assert_eq!(
        (
            v["platform"].clone(),
            v["capability_hint"].clone(),
            v["resource_hint"].clone()
        ),
        (json!("a2a"), json!("talk"), json!("<agent name>"))
    );
    let names: Vec<&str> = v["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["svc-a-awake", "svc-z-awake", "svc-b-asleep"]);
}

// ------------------------------------------------------------- webhooks

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<(HeaderMap, Bytes)>>>);

async fn hook_server() -> (String, Captured) {
    let captured = Captured::default();
    let c = captured.clone();
    let app = Router::new().route(
        "/cb",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let c = c.clone();
            async move {
                c.0.lock().unwrap().push((headers, body));
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{}/cb", addr.port()), captured)
}

impl Captured {
    /// The pings once `n` arrived (webhooks are sent after the commit, on
    /// their own task), or what arrived in 30 s.
    async fn wait_for(&self, n: usize) -> Vec<(HeaderMap, Bytes)> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while self.0.lock().unwrap().len() < n && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.0.lock().unwrap().clone()
    }
}

impl T {
    async fn set_webhook(&self, agent: AgentId, url: &str, secret: Option<&str>) {
        let tx = self.state.store.begin().await.unwrap();
        agents::set_webhook(&tx, agent, Some(url), secret)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
}

/// INV-12: signed, notify-only, never a payload; failures never fail the
/// call.
#[sqlx::test(migrations = "../store/migrations")]
async fn webhook_ping_shape_and_signature(pool: PgPool) {
    let t = setup(pool);
    let (url, captured) = hook_server().await;
    let (s_row, s) = t.service("auto-hook").await;
    let (r_row, r) = t.agent("svc-hook", AgentKind::Service).await;
    let secret = "per-agent-secret";
    t.set_webhook(r_row.id, &url, Some(secret)).await;
    t.grant(&s_row, "svc-hook", None).await;
    let (st, thread) = t
        .post(
            "/v1/a2a/threads",
            ag(&s),
            json!({"to": "svc-hook", "topic": "t", "payload": {"secret": "no"}}),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let tid = thread["thread_id"].as_str().unwrap();
    let got = captured.wait_for(1).await;
    assert_eq!(got.len(), 1);
    let (headers, body) = &got[0];
    let v: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(
        v,
        json!({"type": "a2a_thread_open", "thread_id": tid, "from": "auto-hook", "topic": "t", "seq": 1})
    );
    assert_eq!(headers["content-type"], "application/json");
    let sig = headers["x-agent-auth-signature"].to_str().unwrap();
    let ts = headers["x-agent-auth-timestamp"].to_str().unwrap();
    let sent_at: i64 = ts.parse().unwrap();
    assert!((now().unix_timestamp() - sent_at).abs() < 60);
    assert!(agent_auth_crypto::webhook::verify_timestamped(
        secret.as_bytes(),
        ts,
        body,
        sig,
        now().unix_timestamp(),
        agent_auth_crypto::webhook::DEFAULT_TOLERANCE_SECS,
    ));
    assert_eq!(
        sig,
        agent_auth_crypto::webhook::sign_timestamped(secret.as_bytes(), sent_at, body)
    );
    // The body alone is not what is signed: a replay with another
    // timestamp, or the old untimestamped check, fails.
    assert!(!agent_auth_crypto::webhook::verify_body(
        secret.as_bytes(),
        body,
        sig
    ));

    // A message ping to the initiator? It has no webhook: only the
    // responder's side is pinged when the initiator writes.
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await; // no ping on accept
    t.post(
        &format!("/v1/a2a/threads/{tid}/messages"),
        ag(&s),
        json!({"payload": {"x": 1}}),
    )
    .await;
    let got = captured.wait_for(2).await;
    assert_eq!(got.len(), 2);
    let v: Value = serde_json::from_slice(&got[1].1).unwrap();
    assert_eq!(v["type"], "a2a_message");
    assert_eq!(v["seq"], 2);
    assert!(v.get("payload").is_none());
    t.post(&format!("/v1/a2a/threads/{tid}/close"), ag(&s), json!({}))
        .await;
    let got = captured.wait_for(3).await;
    let v: Value = serde_json::from_slice(&got[2].1).unwrap();
    assert_eq!(
        v,
        json!({"type": "a2a_thread_closed", "thread_id": tid, "topic": "t", "close_reason": "closed"})
    );

    // A dead webhook does not fail the call.
    t.set_webhook(r_row.id, "http://127.0.0.1:9/cb", Some(secret))
        .await;
    let tid2 = t.open_ok(&s, "svc-hook").await;
    assert_eq!(
        t.post(&format!("/v1/a2a/threads/{tid2}/reject"), ag(&r), json!({}))
            .await
            .0,
        StatusCode::OK
    );
}

/// No broker-wide fallback key (upstream review 2026-10): an agent without
/// its own secret gets no ping, never an unsigned one or one signed with a
/// key other receivers hold.
#[sqlx::test(migrations = "../store/migrations")]
async fn webhook_pings_need_the_agents_own_secret(pool: PgPool) {
    let (url, captured) = hook_server().await;
    let cfg = A2aConfig::from_lookup(|k| match k {
        "WEBHOOK_SIGNING_SECRET" => Some("global-fallback".to_owned()),
        "A2A_WEBHOOK_HTTP_HOSTS" => Some("127.0.0.1".to_owned()),
        _ => None,
    })
    .unwrap();
    let t = setup_with(pool.clone(), Policy::default(), cfg);
    let (s_row, s) = t.service("auto-hook2").await;
    let (r_row, _) = t.agent("svc-hook2", AgentKind::Service).await;
    t.set_webhook(r_row.id, &url, None).await;
    t.grant(&s_row, "svc-hook2", None).await;
    t.open_ok(&s, "svc-hook2").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(captured.0.lock().unwrap().len(), 0);

    // With its own secret, it is pinged.
    t.set_webhook(r_row.id, &url, Some("own")).await;
    t.open_ok(&s, "svc-hook2").await;
    assert_eq!(captured.wait_for(1).await.len(), 1);

    // Plain http to a host not listed: not sent.
    let t = setup_with(t.pool.clone(), Policy::default(), A2aConfig::default());
    t.open_ok(&s, "svc-hook2").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(captured.0.lock().unwrap().len(), 1);
}

// --------------------------------------------------------------- payloads

/// INV-10 too: `from` is the broker's name for the sender, whatever the
/// payload says.
#[sqlx::test(migrations = "../store/migrations")]
async fn payloads_verbatim_capped_and_never_set_from(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-sender").await;
    let (_, r) = t.service("plain-receiver").await;
    t.grant(&s_row, "plain-receiver", None).await;
    let payload = json!({"_sandbox": {"conversation": "c1"}, "_sample": 1, "task": "x", "from": "operator", "big": 18446744073709551615u64, "f": 1.5});
    let (_, th) = t
        .post(
            "/v1/a2a/threads",
            ag(&s),
            json!({"to": "plain-receiver", "payload": payload}),
        )
        .await;
    let tid = th["thread_id"].as_str().unwrap();
    let (_, got) = t
        .get(&format!("/v1/a2a/threads/{tid}/messages"), ag(&r))
        .await;
    assert_eq!(got["messages"][0]["payload"], payload);
    assert_eq!(got["messages"][0]["from"], "auto-sender");

    // 16384 in Python's measure: {"a": "x..."} has 9 characters around.
    let fits = json!({"payload": {"a": "x".repeat(16375)}});
    let over = json!({"payload": {"a": "x".repeat(16376)}});
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;
    assert_eq!(
        t.post(&format!("/v1/a2a/threads/{tid}/messages"), ag(&s), fits)
            .await
            .0,
        StatusCode::OK
    );
    let (st, v) = t
        .post(&format!("/v1/a2a/threads/{tid}/messages"), ag(&s), over)
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(detail(&v).contains("payload exceeds 16384 bytes"), "{v}");
    // An integer serde_json cannot keep exactly is refused, not rounded.
    let req = HttpRequest::builder()
        .method(Method::POST)
        .uri(format!("/v1/a2a/threads/{tid}/messages"))
        .header("authorization", format!("Bearer {s}"))
        .body(Body::from(
            r#"{"payload": {"n": 123456789012345678901234567890}}"#,
        ))
        .unwrap();
    let res = t.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(t.thread_row(tid).await.last_seq, 2);
    // A payload must be an object.
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&s),
            json!({"payload": [1]})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn relay_disabled_is_404_but_sessions_work(pool: PgPool) {
    let t = setup_with(
        pool,
        Policy::default(),
        A2aConfig {
            enabled: false,
            ..A2aConfig::default()
        },
    );
    let (_, key) = t.agent("svc-off", AgentKind::Service).await;
    for path in ["/v1/a2a/threads", "/v1/a2a/events", "/v1/a2a/check?peer=x"] {
        let (st, v) = t.get(path, ag(&key)).await;
        assert_eq!(
            (st, detail(&v)),
            (StatusCode::NOT_FOUND, "a2a is disabled on this broker"),
            "{path}"
        );
    }
    assert_eq!(
        t.get("/admin/chat/threads", Who::Admin).await.0,
        StatusCode::NOT_FOUND
    );
    // Auth comes first.
    assert_eq!(
        t.get("/v1/a2a/threads", ag("aa_000000000000_x")).await.0,
        StatusCode::UNAUTHORIZED
    );
    t.session(&key, "still-works").await;
}

// --------------------------------------------------------- concurrency

/// a2a B4: of two racing accepts exactly one wins, and the thread is bound
/// to the winner's session.
#[sqlx::test(migrations = "../store/migrations")]
async fn two_concurrent_accepts(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-race").await;
    let (_, r) = t.service("svc-race").await;
    t.grant(&s_row, "svc-race", None).await;
    for _ in 0..5 {
        let tid = t.open_ok(&s, "svc-race").await;
        let w1 = t.session(&r, "w1").await;
        let w2 = t.session(&r, "w2").await;
        let mut tasks = Vec::new();
        for w in [w1.clone(), w2.clone()] {
            let app = t.app.clone();
            let (r, tid) = (r.clone(), tid.clone());
            tasks.push(tokio::spawn(async move {
                let req = HttpRequest::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/a2a/threads/{tid}/accept"))
                    .header("authorization", format!("Bearer {r}"))
                    .header("x-agent-session", w.as_str())
                    .body(Body::from("{}"))
                    .unwrap();
                (w, app.oneshot(req).await.unwrap().status())
            }));
        }
        let mut winners = Vec::new();
        for task in tasks {
            let (w, status) = task.await.unwrap();
            match status {
                StatusCode::OK => winners.push(w),
                // The loser sees the thread either still pending-then-taken
                // (409) or already bound to the winner (403).
                StatusCode::CONFLICT | StatusCode::FORBIDDEN => {}
                other => panic!("unexpected {other}"),
            }
        }
        assert_eq!(winners.len(), 1);
        let row = t.thread_row(&tid).await;
        assert_eq!(
            row.responder_session_id.map(|s| s.to_string()),
            Some(winners[0].clone())
        );
    }
}

/// INV-7 under concurrency: a send racing a close either lands before the
/// close or is refused; nothing follows the close.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_send_racing_a_close(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-sc").await;
    let (_, r) = t.service("svc-sc").await;
    t.grant(&s_row, "svc-sc", None).await;
    for _ in 0..10 {
        let tid = t.open_ok(&s, "svc-sc").await;
        t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
            .await;
        let send = {
            let app = t.app.clone();
            let (s, tid) = (s.clone(), tid.clone());
            tokio::spawn(async move {
                let req = HttpRequest::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/a2a/threads/{tid}/messages"))
                    .header("authorization", format!("Bearer {s}"))
                    .body(Body::from(r#"{"payload": {"late": true}}"#))
                    .unwrap();
                app.oneshot(req).await.unwrap().status()
            })
        };
        let close = {
            let app = t.app.clone();
            let (r, tid) = (r.clone(), tid.clone());
            tokio::spawn(async move {
                let req = HttpRequest::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/a2a/threads/{tid}/close"))
                    .header("authorization", format!("Bearer {r}"))
                    .body(Body::from("{}"))
                    .unwrap();
                app.oneshot(req).await.unwrap().status()
            })
        };
        let (sent, closed) = (send.await.unwrap(), close.await.unwrap());
        assert_eq!(closed, StatusCode::OK);
        assert!(
            sent == StatusCode::OK || sent == StatusCode::CONFLICT,
            "{sent}"
        );
        let row = t.thread_row(&tid).await;
        let last: OffsetDateTime =
            sqlx::query_scalar("SELECT max(created_at) FROM a2a_messages WHERE thread_id = $1")
                .bind(uuid::Uuid::parse_str(&tid).unwrap())
                .fetch_one(&t.pool)
                .await
                .unwrap();
        assert!(last <= row.closed_at.unwrap(), "no message after the close");
        assert_eq!(row.last_seq, if sent == StatusCode::OK { 2 } else { 1 });
    }
}

// ------------------------------------------------------- operator chat

async fn hermes(t: &T) -> String {
    let (_, key) = t.service("hermes-homelab-recusant").await;
    key
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_operator_writes_and_an_agent_answers(pool: PgPool) {
    let t = setup(pool);
    let h = hermes(&t).await;
    let (st, opened) = t.post("/admin/chat/threads", Who::Admin, json!({"to": "hermes-homelab-recusant", "topic": "backups", "text": "Did last night's backup run?"})).await;
    assert_eq!(st, StatusCode::OK, "{opened}");
    assert_eq!(opened["state"], "pending_open");
    assert_eq!(opened["grant_id"], Value::Null);
    let tid = opened["thread_id"].as_str().unwrap();

    let (_, ev) = t.get("/v1/a2a/events", ag(&h)).await;
    assert_eq!(
        (
            ev["pending_opens"][0]["peer"].clone(),
            ev["pending_opens"][0]["topic"].clone()
        ),
        (json!("operator"), json!("backups"))
    );
    let (_, got) = t
        .get(&format!("/v1/a2a/threads/{tid}/messages"), ag(&h))
        .await;
    assert_eq!(got["messages"][0]["from"], "operator");
    assert_eq!(
        got["messages"][0]["payload"],
        json!({"type": "message", "text": "Did last night's backup run?", "operator": "admin token"})
    );
    assert_eq!(
        t.post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&h),
            json!({"payload": {"type": "message", "text": "Yes, at 03:00.", "operator": "jrt"}})
        )
        .await
        .0,
        StatusCode::OK
    );

    let (_, read) = t
        .get(&format!("/admin/chat/threads/{tid}"), Who::Admin)
        .await;
    assert_eq!(
        (
            read["thread"]["state"].clone(),
            read["thread"]["peer"].clone()
        ),
        (json!("open"), json!("hermes-homelab-recusant"))
    );
    let rows: Vec<(String, String)> = read["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["from"].as_str().unwrap().to_owned(),
                m["text"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "operator".to_owned(),
                "Did last night's backup run?".to_owned()
            ),
            (
                "hermes-homelab-recusant".to_owned(),
                "Yes, at 03:00.".to_owned()
            )
        ]
    );
    // a2a B18: the agent's own `operator` field is not shown as the operator.
    assert_eq!(read["messages"][0]["operator"], "admin token");
    assert_eq!(read["messages"][1]["operator"], Value::Null);
    assert_eq!(read["messages"][0]["payload"], Value::Null);
    assert_eq!(read["requests"], json!([]));
    assert_eq!(
        t.get(
            &format!("/admin/chat/threads/{tid}?after_seq=2"),
            Who::Admin
        )
        .await
        .1["messages"],
        json!([])
    );

    let (st, sent) = t
        .post(
            &format!("/admin/chat/threads/{tid}/messages"),
            Who::Admin,
            json!({"text": "Thanks."}),
        )
        .await;
    assert_eq!((st, sent["seq"].as_i64()), (StatusCode::OK, Some(3)));
    let (_, listed) = t.get("/admin/chat/threads", Who::Admin).await;
    assert_eq!(
        (
            listed[0]["to"].clone(),
            listed[0]["preview"].clone(),
            listed[0]["last_from_operator"].clone()
        ),
        (
            json!("hermes-homelab-recusant"),
            json!("Thanks."),
            json!(true)
        )
    );

    t.post(
        &format!("/v1/a2a/threads/{tid}/messages"),
        ag(&h),
        json!({"payload": {"type": "result", "status": "done", "summary": "Answered."}}),
    )
    .await;
    let (_, last) = t
        .get(
            &format!("/admin/chat/threads/{tid}?after_seq=3"),
            Who::Admin,
        )
        .await;
    let m = &last["messages"][0];
    assert_eq!(
        (
            m["type"].clone(),
            m["status"].clone(),
            m["summary"].clone(),
            m["text"].clone()
        ),
        (
            json!("result"),
            json!("done"),
            json!("Answered."),
            Value::Null
        )
    );
    assert_eq!(m["payload"]["summary"], "Answered.");
    assert_eq!(
        t.get("/admin/chat/threads", Who::Admin).await.1[0]["preview"],
        "Answered."
    );

    let (st, closed) = t
        .post(
            &format!("/admin/chat/threads/{tid}/close"),
            Who::Admin,
            json!({}),
        )
        .await;
    assert_eq!(
        (st, closed["state"].as_str()),
        (StatusCode::OK, Some("closed"))
    );
    assert_eq!(
        t.post(
            &format!("/admin/chat/threads/{tid}/messages"),
            Who::Admin,
            json!({"text": "?"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // Agents cannot use the chat routes; unknown conversations are 404.
    assert_eq!(
        t.get("/admin/chat/threads", ag(&h)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (st, v) = t
        .get(
            &format!("/admin/chat/threads/{}", SessionId::new()),
            Who::Admin,
        )
        .await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::NOT_FOUND, "unknown conversation")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_reply_wakes_the_waiting_panel(pool: PgPool) {
    let t = setup(pool);
    let h = hermes(&t).await;
    let (_, opened) = t
        .post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-homelab-recusant", "text": "hi"}),
        )
        .await;
    let tid = opened["thread_id"].as_str().unwrap().to_owned();
    let waiting = {
        let app = t.app.clone();
        let tid = tid.clone();
        tokio::spawn(async move {
            let req = HttpRequest::builder()
                .uri(format!("/admin/chat/threads/{tid}?after_seq=1&wait=20"))
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(Body::empty())
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished());
    t.post(
        &format!("/v1/a2a/threads/{tid}/messages"),
        ag(&h),
        json!({"payload": {"type": "message", "text": "hello"}}),
    )
    .await;
    let got = tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got["messages"][0]["text"], "hello");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn no_grant_backs_it_and_the_sweep_leaves_it_open(pool: PgPool) {
    let t = setup(pool);
    let h = hermes(&t).await;
    let (_, opened) = t
        .post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-homelab-recusant", "text": "hi"}),
        )
        .await;
    let tid = opened["thread_id"].as_str().unwrap();
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&h), json!({}))
        .await;
    assert_eq!(t.sweep().await.grant_revoked, 0);
    let row = t.thread_row(tid).await;
    assert!(row.grant_id.is_none());
    assert_eq!(row.state, agent_auth_store::a2a::ThreadState::Open);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn only_service_agents_that_listen(pool: PgPool) {
    let t = setup(pool);
    t.agent("claude-x-galaxy", AgentKind::Ephemeral).await;
    t.agent("hermes-asleep", AgentKind::Service).await;
    hermes(&t).await;
    let (_, peers) = t.get("/admin/chat/peers", Who::Admin).await;
    let got: Vec<(String, bool)> = peers
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_owned(),
                p["reachable"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("hermes-asleep".to_owned(), false),
            ("hermes-homelab-recusant".to_owned(), true)
        ]
    );
    assert_eq!(peers[0]["placement"], "host");
    assert_eq!(peers[0]["description"], "");
    assert_eq!(
        t.post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "claude-x-galaxy", "text": "hi"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-asleep", "text": "hi"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    // The operator's topic is one line too (a2a B17).
    assert_eq!(
        t.post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-homelab-recusant", "topic": "a\nb", "text": "hi"})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

/// INV-10: the operator row never authenticates with a key.
#[sqlx::test(migrations = "../store/migrations")]
async fn the_operator_row_speaks_only_through_the_panel(pool: PgPool) {
    let t = setup(pool);
    hermes(&t).await;
    t.post(
        "/admin/chat/threads",
        Who::Admin,
        json!({"to": "hermes-homelab-recusant", "text": "hi"}),
    )
    .await;
    let tx = t.state.store.begin().await.unwrap();
    let op = agents::by_name(&tx, "operator").await.unwrap().unwrap();
    assert_eq!(op.kind, AgentKind::Operator);
    assert!(op.last_seen_at.is_some());
    drop(tx);
    // Even with a real key written into it, the row does not authenticate.
    let key = api_key::generate().unwrap();
    sqlx::query("UPDATE agents SET key_id = $1, api_key_hash = $2 WHERE kind = 'operator'")
        .bind(key.key_id.as_str())
        .bind(key.hash.as_str())
        .execute(&t.pool)
        .await
        .unwrap();
    let full = key.full_key.expose().clone();
    let (st, v) = t.get("/v1/a2a/threads", ag(&full)).await;
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::UNAUTHORIZED, "invalid API key")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_named_operator_blocks_the_chat_until_renamed(pool: PgPool) {
    let t = setup(pool);
    t.agent("operator", AgentKind::Service).await;
    hermes(&t).await;
    let (st, v) = t
        .post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-homelab-recusant", "text": "hi"}),
        )
        .await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::CONFLICT,
            "an agent is already named 'operator'; rename it to chat from the panel"
        )
    );
}

/// An operator thread backs a delegated request (as the Python now does):
/// the operator is the delegator.
#[sqlx::test(migrations = "../store/migrations")]
async fn delegation_rules(pool: PgPool) {
    use agent_auth_broker::a2a::delegation;
    use agent_auth_core::Platform;
    let t = setup(pool);
    let h = hermes(&t).await;
    let (_, opened) = t
        .post(
            "/admin/chat/threads",
            Who::Admin,
            json!({"to": "hermes-homelab-recusant", "text": "hi"}),
        )
        .await;
    let op_tid = opened["thread_id"].as_str().unwrap().to_owned();
    t.post(
        &format!("/v1/a2a/threads/{op_tid}/accept"),
        ag(&h),
        json!({}),
    )
    .await;

    let (s_row, s) = t.service("auto-del").await;
    t.grant(&s_row, "hermes-homelab-recusant", None).await;
    let (_, th) = t
        .post(
            "/v1/a2a/threads",
            ag(&s),
            json!({"to": "hermes-homelab-recusant", "topic": "deploy \"x\"", "payload": {}}),
        )
        .await;
    let tid = th["thread_id"].as_str().unwrap().to_owned();

    // The resolver takes an AgentCaller: get one through a tiny route.
    async fn resolve(
        axum::extract::State(state): axum::extract::State<AppState>,
        caller: agent_auth_broker::auth::AgentCaller,
        axum::extract::Path((platform, thread)): axum::extract::Path<(String, String)>,
    ) -> axum::Json<Value> {
        let tx = state.store.begin().await.unwrap();
        let platform = Platform::parse(&platform).unwrap();
        let out = delegation::resolve(&tx, &caller, platform, &thread)
            .await
            .unwrap();
        axum::Json(match out {
            Ok(r) => json!({"ok": r.risk_note}),
            Err(e) => json!({"err": e}),
        })
    }
    let app = Router::new()
        .route("/r/{platform}/{thread}", axum::routing::get(resolve))
        .with_state(t.state.clone());
    let call = |key: String, path: String| {
        let app = app.clone();
        async move {
            let req = HttpRequest::builder()
                .uri(path)
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap();
            let bytes = app
                .oneshot(req)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        }
    };
    assert_eq!(
        call(h.clone(), format!("/r/homelab/{op_tid}")).await,
        json!({"ok": "on behalf of operator (a2a thread topic (none))"})
    );
    assert_eq!(
        call(h.clone(), format!("/r/homelab/{tid}")).await,
        json!({"err": "thread is pending_open; delegation requires an OPEN thread (the other side must have accepted)"})
    );
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&h), json!({}))
        .await;
    assert_eq!(
        call(h.clone(), format!("/r/homelab/{tid}")).await,
        json!({"ok": "on behalf of auto-del (a2a thread topic \"deploy \\\"x\\\"\")"})
    );
    assert_eq!(
        call(s.clone(), format!("/r/homelab/{tid}")).await["err"]
            .as_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap(),
        "you opened this thread"
    );
    assert_eq!(
        call(h.clone(), format!("/r/a2a/{tid}")).await,
        json!({"err": "a2a access cannot be requested on behalf of another agent"})
    );
    let (_, nosy) = t.service("svc-nosy").await;
    assert_eq!(
        call(nosy, format!("/r/homelab/{tid}")).await,
        json!({"err": "unknown thread (you must be a participant of the thread you cite)"})
    );
    assert_eq!(
        call(h.clone(), "/r/homelab/garbage".to_owned()).await["err"],
        "unknown thread (you must be a participant of the thread you cite)"
    );
}

// ------------------------------------------------------------ DoS caps

#[sqlx::test(migrations = "../store/migrations")]
async fn open_sessions_are_capped_per_agent(pool: PgPool) {
    let t = setup_with(
        pool,
        Policy::default(),
        A2aConfig {
            max_sessions_per_agent: 2,
            ..config()
        },
    );
    let (_, key) = t.agent("claude-many", AgentKind::Ephemeral).await;
    let a = t.session(&key, "a").await;
    t.session(&key, "b").await;
    let (st, v) = t
        .post("/v1/sessions", ag(&key), json!({"label": "c"}))
        .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(detail(&v).starts_with("too many open sessions for this agent (at most 2)"));
    // Another agent is not affected; closing one makes room.
    let (_, other) = t.agent("claude-other", AgentKind::Ephemeral).await;
    t.session(&other, "a").await;
    t.post("/v1/sessions/close", ses(&key, &a), json!({})).await;
    t.session(&key, "c").await;
}

#[sqlx::test(migrations = "../store/migrations")]
async fn messages_per_thread_are_capped(pool: PgPool) {
    let t = setup_with(
        pool,
        Policy::default(),
        A2aConfig {
            max_messages_per_thread: 3,
            ..config()
        },
    );
    let (s_row, s) = t.service("auto-chatty").await;
    let (_, r) = t.service("svc-chatty").await;
    t.grant(&s_row, "svc-chatty", None).await;
    let tid = t.open_ok(&s, "svc-chatty").await;
    for key in [&r, &s] {
        let (st, _) = t
            .post(
                &format!("/v1/a2a/threads/{tid}/messages"),
                ag(key),
                json!({"payload": {}}),
            )
            .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, v) = t
        .post(
            &format!("/v1/a2a/threads/{tid}/messages"),
            ag(&r),
            json!({"payload": {}}),
        )
        .await;
    assert_eq!(
        (st, detail(&v)),
        (
            StatusCode::CONFLICT,
            "thread has reached its limit of 3 messages; close it and open a new one"
        )
    );
    assert_eq!(t.thread_row(&tid).await.last_seq, 3);
    assert_eq!(
        t.post(&format!("/v1/a2a/threads/{tid}/close"), ag(&r), json!({}))
            .await
            .0,
        StatusCode::OK
    );
}

fn spawn_get(t: &T, path: String, key: &str) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let app = t.app.clone();
    let key = key.to_owned();
    tokio::spawn(async move {
        let req = HttpRequest::builder()
            .uri(path)
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    })
}

/// A read of a thread's messages is one snapshot. Found by the e2e suite
/// once a reply raced the poll: the reply (which accepts the thread)
/// committed between the read of the thread and the read of its messages,
/// and the poll answered with the message and the thread still
/// `pending_open`, `last_seq` short of it. Here the reply is made to land
/// exactly there: it holds the messages table until the read is blocked on
/// it, then writes and commits.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_message_read_is_one_snapshot(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-snap").await;
    t.service("svc-snap").await;
    t.grant(&s_row, "svc-snap", None).await;
    let tid = t.open_ok(&s, "svc-snap").await;
    let mut reply = t.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE a2a_messages IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *reply)
        .await
        .unwrap();
    let read = spawn_get(
        &t,
        format!("/v1/a2a/threads/{tid}/messages?after_seq=1"),
        &s,
    );
    // The read has the thread and waits for the messages table.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&t.pool)
        .await
        .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the read never blocked"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The reply, as `send` writes it: the thread accepted, message 2.
    sqlx::query(
        "UPDATE a2a_threads SET state = 'open', accepted_at = now(), last_seq = 2, \
         last_activity_at = now() WHERE id = $1::uuid",
    )
    .bind(&tid)
    .execute(&mut *reply)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO a2a_messages (id, thread_id, seq, sender_agent_id, recipient_agent_id, \
         grant_id, payload) \
         SELECT gen_random_uuid(), id, 2, responder_agent_id, initiator_agent_id, grant_id, \
         '{\"answer\": 42}'::json FROM a2a_threads WHERE id = $1::uuid",
    )
    .bind(&tid)
    .execute(&mut *reply)
    .await
    .unwrap();
    reply.commit().await.unwrap();
    let (st, v) = read.await.unwrap();
    assert_eq!(st, StatusCode::OK, "{v}");
    // As of the read's start: before the reply, all of it.
    assert_eq!(v["thread"]["state"], "pending_open", "{v}");
    assert_eq!(v["messages"], json!([]), "{v}");
    // The next read sees all of the reply.
    let (_, v) = t
        .get(
            &format!("/v1/a2a/threads/{tid}/messages?after_seq=1"),
            ag(&s),
        )
        .await;
    assert_eq!(v["thread"]["state"], "open", "{v}");
    assert_eq!(v["messages"][0]["payload"], json!({"answer": 42}), "{v}");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_long_polls_are_capped_per_agent(pool: PgPool) {
    let t = setup_with(
        pool,
        Policy::default(),
        A2aConfig {
            max_long_polls_per_agent: 1,
            ..config()
        },
    );
    let (s_row, s) = t.service("auto-poller").await;
    let (_, r) = t.service("svc-poller").await;
    t.grant(&s_row, "svc-poller", None).await;
    let tid = t.open_ok(&s, "svc-poller").await;
    let parked = spawn_get(
        &t,
        format!("/v1/a2a/threads/{tid}/messages?after_seq=1&wait=60"),
        &s,
    );
    until_parked(&t.state, 1).await;
    let (st, v) = t
        .get("/v1/a2a/events?wait=5&after=2100-01-01T00:00:00Z", ag(&s))
        .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        detail(&v).starts_with("too many concurrent a2a long-polls for this agent (at most 1)")
    );
    // A read that does not wait needs no slot; another agent has its own.
    assert_eq!(
        t.get(&format!("/v1/a2a/threads/{tid}/messages"), ag(&s))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        t.get("/v1/a2a/events?wait=0", ag(&s)).await.0,
        StatusCode::OK
    );
    t.post(
        &format!("/v1/a2a/threads/{tid}/messages"),
        ag(&r),
        json!({"payload": {"x": 1}}),
    )
    .await;
    assert_eq!(parked.await.unwrap().0, StatusCode::OK);
    // The slot is free again.
    let (st, _) = t
        .get(
            &format!("/v1/a2a/threads/{tid}/messages?after_seq=9&wait=0.2"),
            ag(&s),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
}

/// A parked long-poll stops when its agent is disabled, its key rotated or
/// its session closed: each re-read re-checks the caller.
#[sqlx::test(migrations = "../store/migrations")]
async fn a_long_poll_stops_for_a_caller_no_longer_valid(pool: PgPool) {
    let t = setup(pool);
    let (s_row, s) = t.service("auto-gone").await;
    let (_, r) = t.service("svc-gone").await;
    t.grant(&s_row, "svc-gone", None).await;
    let tid = t.open_ok(&s, "svc-gone").await;
    t.post(&format!("/v1/a2a/threads/{tid}/accept"), ag(&r), json!({}))
        .await;

    // Disabled while waiting: the next wake-up answers 401, not the message.
    let parked = spawn_get(
        &t,
        format!("/v1/a2a/threads/{tid}/messages?after_seq=1&wait=60"),
        &s,
    );
    until_parked(&t.state, 1).await;
    let tx = t.state.store.begin().await.unwrap();
    agents::set_disabled(&tx, s_row.id, true).await.unwrap();
    tx.commit().await.unwrap();
    // (A send to a disabled agent is refused; a close still wakes it.)
    let started = std::time::Instant::now();
    t.post(&format!("/v1/a2a/threads/{tid}/close"), ag(&r), json!({}))
        .await;
    let (st, v) = parked.await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(45),
        "on the wake-up, not the deadline"
    );
    assert_eq!(
        (st, detail(&v)),
        (StatusCode::UNAUTHORIZED, "invalid API key")
    );

    // Key rotated while waiting on events.
    let (r2_row, r2) = t.service("svc-rotated").await;
    let parked = spawn_get(&t, "/v1/a2a/events?wait=60".to_owned(), &r2);
    until_parked(&t.state, 1).await;
    let fresh = api_key::generate().unwrap();
    let tx = t.state.store.begin().await.unwrap();
    agents::set_key(&tx, r2_row.id, fresh.key_id.as_str(), fresh.hash.as_str())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Any write that concerns it wakes it: a thread opened to it.
    let (s2_row, s2) = t.service("auto-waker").await;
    t.grant(&s2_row, "svc-rotated", None).await;
    t.open_ok(&s2, "svc-rotated").await;
    let started = std::time::Instant::now();
    let (st, _) = parked.await.unwrap();
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(started.elapsed() < Duration::from_secs(45));
}
