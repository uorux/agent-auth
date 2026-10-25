//! The extractors against a real database (rust/spec/http-api.md §3).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use agent_auth_broker::auth::{AdminCaller, AgentCaller, AuthConfig};
use agent_auth_broker::state::AppState;
use agent_auth_core::AgentId;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::Policy;
use agent_auth_crypto::{Secret, api_key};
use agent_auth_store::{Store, agents, sessions};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use time::OffsetDateTime;
use tower::ServiceExt;

async fn agent_name(caller: AgentCaller) -> String {
    format!(
        "{}:{}",
        caller.agent().name,
        caller
            .session_id()
            .map(|s| s.to_string())
            .unwrap_or_default()
    )
}

async fn admin(caller: AdminCaller) -> String {
    caller.label()
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/me", get(agent_name))
        .route("/admin", get(admin))
        .with_state(state)
}

async fn make_agent(
    store: &Store,
    name: &str,
    kind: AgentKind,
    disabled: bool,
) -> (AgentId, String) {
    let key = api_key::generate().expect("random");
    let tx = store.begin().await.expect("begin");
    let now = OffsetDateTime::now_utc();
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
            now,
        },
    )
    .await
    .expect("insert");
    if disabled {
        agents::set_disabled(&tx, row.id, true)
            .await
            .expect("disable");
    }
    tx.commit().await.expect("commit");
    (row.id, key.full_key.expose().clone())
}

async fn call(
    app: &Router,
    path: &str,
    auth: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, String) {
    let mut req = Request::builder().uri(path);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    if let Some(s) = session {
        req = req.header("x-agent-session", s);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = res.status();
    let body = res.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn state(pool: sqlx::PgPool, admin_token: Option<&str>) -> AppState {
    AppState::new(
        Store::from_pool(pool),
        Policy::default(),
        AuthConfig {
            admin_token: admin_token.map(|t| Secret::new(t.to_owned())),
            oauth_enabled: false,
        },
    )
}

#[sqlx::test(migrations = "../store/migrations")]
async fn agent_keys(pool: sqlx::PgPool) {
    let st = state(pool, None);
    let (_, key) = make_agent(&st.store, "alice", AgentKind::Service, false).await;
    let (_, disabled_key) = make_agent(&st.store, "bob", AgentKind::Service, true).await;
    let app = app(st.clone());

    assert_eq!(
        call(&app, "/me", Some(&format!("Bearer {key}")), None).await,
        (StatusCode::OK, "alice:".to_owned())
    );
    assert_eq!(
        call(&app, "/me", Some(&format!("bearer {key}")), None)
            .await
            .0,
        StatusCode::OK
    );

    let (s, body) = call(&app, "/me", None, None).await;
    assert_eq!(
        (s, body.as_str()),
        (
            StatusCode::UNAUTHORIZED,
            r#"{"detail":"missing bearer token"}"#
        )
    );
    let (s, body) = call(&app, "/me", Some("Bearer nope"), None).await;
    assert_eq!(
        (s, body.as_str()),
        (
            StatusCode::UNAUTHORIZED,
            r#"{"detail":"malformed API key"}"#
        )
    );
    let wrong = format!("{}A", &key[..key.len() - 1]);
    let wrong = if wrong == key {
        format!("{}B", &key[..key.len() - 1])
    } else {
        wrong
    };
    let (s, body) = call(&app, "/me", Some(&format!("Bearer {wrong}")), None).await;
    assert_eq!(
        (s, body.as_str()),
        (StatusCode::UNAUTHORIZED, r#"{"detail":"invalid API key"}"#)
    );
    let (s, _) = call(&app, "/me", Some(&format!("Bearer {disabled_key}")), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, "/me", Some(&format!("Basic {key}")), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let kinds: Vec<String> = st
        .security_log
        .since(OffsetDateTime::UNIX_EPOCH, 100)
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds.iter().filter(|k| *k == "security.bad_key").count(), 3);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn operator_row_cannot_use_a_key(pool: sqlx::PgPool) {
    let st = state(pool, None);
    let (_, key) = make_agent(&st.store, "operator", AgentKind::Operator, false).await;
    let (s, _) = call(&app(st), "/me", Some(&format!("Bearer {key}")), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn sessions_must_be_own_and_open(pool: sqlx::PgPool) {
    let st = state(pool, None);
    let (alice, key) = make_agent(&st.store, "alice", AgentKind::Ephemeral, false).await;
    let (bob, _) = make_agent(&st.store, "bob", AgentKind::Ephemeral, false).await;
    let now = OffsetDateTime::now_utc();
    let tx = st.store.begin().await.expect("begin");
    let mine = sessions::insert(
        &tx,
        agent_auth_core::SessionId::new(),
        alice,
        "cli-a1b2",
        now,
    )
    .await
    .expect("session");
    let theirs = sessions::insert(&tx, agent_auth_core::SessionId::new(), bob, "cli-c3d4", now)
        .await
        .expect("session");
    tx.commit().await.expect("commit");
    let app = app(st);
    let auth = format!("Bearer {key}");

    let (s, body) = call(&app, "/me", Some(&auth), Some(&mine.id.to_string())).await;
    assert_eq!((s, body), (StatusCode::OK, format!("alice:{}", mine.id)));
    for bad in [
        theirs.id.to_string(),
        "not-a-session".to_owned(),
        mine.id.to_string().to_uppercase(),
    ] {
        let (s, body) = call(&app, "/me", Some(&auth), Some(&bad)).await;
        assert_eq!(
            (s, body.as_str()),
            (
                StatusCode::UNAUTHORIZED,
                r#"{"detail":"unknown or closed session"}"#
            )
        );
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn admin_token(pool: sqlx::PgPool) {
    let disabled = app(state(pool.clone(), None));
    let (s, body) = call(&disabled, "/admin", Some("Bearer x"), None).await;
    assert_eq!(
        (s, body.as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"detail":"admin API disabled: ADMIN_TOKEN not configured"}"#
        )
    );

    let st = state(pool, Some("s3cret-token"));
    let app = app(st.clone());
    assert_eq!(
        call(&app, "/admin", Some("Bearer s3cret-token"), None).await,
        (StatusCode::OK, "admin token".to_owned())
    );
    let (s, body) = call(&app, "/admin", Some("Bearer s3cret-tokeN"), None).await;
    assert_eq!(
        (s, body.as_str()),
        (
            StatusCode::UNAUTHORIZED,
            r#"{"detail":"invalid admin token"}"#
        )
    );
    // Non-ASCII is a 401 like any wrong token, never a 500.
    let req = Request::builder()
        .uri("/admin")
        .header("authorization", "Bearer s3cr\u{e9}t".as_bytes())
        .body(Body::empty())
        .expect("req");
    assert_eq!(
        app.clone().oneshot(req).await.expect("res").status(),
        StatusCode::UNAUTHORIZED
    );
    let (s, _) = call(&app, "/admin", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        st.security_log.since(OffsetDateTime::UNIX_EPOCH, 10).len(),
        2
    );
}
