//! Every route needs credentials, except the ones listed in [`PUBLIC`].
//!
//! The routes are read from the broker's sources (every `.route("…", …)`
//! outside test code), so a route added without a principal fails here
//! until it is either given one or listed below with the reason it may be
//! reached without one. Each listed route does its own, protocol-specific
//! checking (a pairing code, a signed hello, a sealed consent, a bearer
//! token checked before anything else runs).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::path::Path;

use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::state::AppState;
use agent_auth_core::AgentId;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::Policy;
use agent_auth_crypto::{Secret, api_key};
use agent_auth_store::Store;
use agent_auth_store::agents;
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use regex::Regex;
use sqlx::PgPool;
use time::OffsetDateTime;
use tower::ServiceExt;

const ADMIN: &str = "admin-token-for-the-route-auth-test-0123";

/// Routes reachable without an agent, admin or panel credential, and why.
const PUBLIC: &[(&str, &str, &str)] = &[
    ("GET", "/healthz", "liveness probe; answers {ok: true}"),
    (
        "GET",
        "/.well-known/jwks.json",
        "public keys MCP servers verify tokens with",
    ),
    (
        "GET",
        "/.well-known/openid-configuration",
        "issuer metadata for those tokens",
    ),
    (
        "GET",
        "/.well-known/oauth-protected-resource",
        "OAuth metadata (RFC 9728)",
    ),
    (
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        "OAuth metadata (RFC 9728)",
    ),
    (
        "GET",
        "/.well-known/oauth-authorization-server",
        "OAuth metadata (RFC 8414)",
    ),
    (
        "GET",
        "/v1/tokens/verify",
        "an MCP server's proxy presents the token being verified",
    ),
    (
        "POST",
        "/oauth/register",
        "dynamic client registration (RFC 7591) is open by design",
    ),
    (
        "GET",
        "/oauth/authorize",
        "starts a flow that ends at the operator's sign-in",
    ),
    (
        "GET",
        "/oauth/callback",
        "the identity provider's redirect; state-checked",
    ),
    (
        "POST",
        "/oauth/consent",
        "a sealed consent blob bound to this browser's cookie",
    ),
    (
        "POST",
        "/oauth/token",
        "the authorization code and PKCE verifier are the credential",
    ),
    (
        "POST",
        "/oauth/revoke",
        "RFC 7009: the token being revoked is the credential",
    ),
    (
        "ANY",
        "/mcp",
        "the gate checks the bearer token before the MCP service runs",
    ),
    (
        "ANY",
        "/mcp/",
        "the gate checks the bearer token before the MCP service runs",
    ),
    ("GET", "/ui", "the panel's static page"),
    ("GET", "/ui/", "the panel's static page"),
    ("GET", "/ui/{name}", "the panel's static assets"),
    ("GET", "/ui/login", "starts the operator's sign-in"),
    (
        "GET",
        "/ui/callback",
        "the identity provider's redirect; state-checked",
    ),
    (
        "GET",
        "/ui/session",
        "answers 401 without a session; checks it itself",
    ),
    ("GET", "/ui/logout", "does nothing"),
    (
        "POST",
        "/ui/logout",
        "ends the session it is sent with (CSRF-checked)",
    ),
    (
        "POST",
        "/v1/daemons/pair",
        "a one-time pairing code is the credential",
    ),
    (
        "GET",
        "/v1/daemons/connect",
        "a WebSocket whose first frame is a signed hello",
    ),
];

/// `(method, path)` for every route in the broker's non-test sources.
fn routes() -> BTreeSet<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let start = Regex::new(r#"\.route\(\s*"([^"]+)"\s*,"#).unwrap();
    let method = Regex::new(r"(?:^|[.:\s])(get|post|put|delete|patch|any)\(").unwrap();
    let mut out = BTreeSet::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !name.ends_with(".rs")
                || name == "tests.rs"
                || name.ends_with("_tests.rs")
                || name.starts_with("testkit")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Test modules sit at the end of a file.
            let text = text.split("#[cfg(test)]").next().unwrap();
            for m in start.captures_iter(text) {
                let whole = m.get(0).unwrap();
                // The handler chain: up to the parenthesis closing `.route(`.
                let rest = &text[whole.end()..];
                let mut depth = 1usize;
                let mut end = rest.len();
                for (i, c) in rest.char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let chain = &rest[..end];
                let methods: Vec<String> = method
                    .captures_iter(chain)
                    .map(|c| c[1].to_uppercase())
                    .collect();
                assert!(
                    !methods.is_empty(),
                    "no method found for route {} in {}",
                    &m[1],
                    path.display()
                );
                for meth in methods {
                    out.insert((meth, m[1].to_owned()));
                }
            }
        }
    }
    out
}

/// A concrete path for a route pattern: ids get a UUID, other parameters
/// a plain name.
fn concrete(pattern: &str) -> String {
    let param = Regex::new(r"\{([^}]+)\}").unwrap();
    param
        .replace_all(pattern, |c: &regex::Captures<'_>| {
            let name = &c[1];
            if name == "id" || name.ends_with("_id") || name == "item" || name == "tid" {
                "6f1c2a3e-0b7d-4c55-9a3e-2f8d7c1b4a90".to_owned()
            } else if name == "index" {
                "0".to_owned()
            } else {
                "probe".to_owned()
            }
        })
        .into_owned()
}

fn is_public(method: &str, path: &str) -> bool {
    PUBLIC
        .iter()
        .any(|(m, p, _)| *p == path && (*m == "ANY" || *m == method))
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> (StatusCode, String) {
    let method = Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = Request::builder().method(method.clone()).uri(path);
    if let Some(b) = bearer {
        req = req.header("authorization", format!("Bearer {b}"));
    }
    let body = if method == Method::GET || method == Method::DELETE {
        Body::empty()
    } else {
        req = req.header("content-type", "application/json");
        Body::from("{}")
    };
    let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn app(pool: PgPool) -> (Router, AppState) {
    let state = AppState::new(
        Store::from_pool(pool),
        Policy::default(),
        AuthConfig {
            admin_token: Some(Secret::new(ADMIN.to_owned())),
            oauth_enabled: true,
            trust_x_real_ip: false,
        },
    );
    (agent_auth_broker::http::router(state.clone()), state)
}

async fn agent_key(state: &AppState) -> String {
    let key = api_key::generate().unwrap();
    let tx = state.store.begin().await.unwrap();
    agents::insert(
        &tx,
        &agents::NewAgent {
            id: AgentId::new(),
            name: "route-prober",
            description: "",
            key_id: key.key_id.as_str(),
            api_key_hash: key.hash.as_str(),
            kind: AgentKind::Service,
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
            now: OffsetDateTime::now_utc(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    key.full_key.expose().clone()
}

/// What the sources say, sanity-checked, so a parser that silently finds
/// nothing cannot pass the tests below.
#[test]
fn the_route_list_is_complete_and_the_allowlist_current() {
    let all = routes();
    assert!(
        all.len() >= 100,
        "only {} routes found: is the parser broken?",
        all.len()
    );
    for probe in [
        ("GET", "/v1/me"),
        ("POST", "/admin/lockdown"),
        ("GET", "/v1/grants/{id}/credential"),
    ] {
        assert!(
            all.contains(&(probe.0.to_owned(), probe.1.to_owned())),
            "{probe:?} not found"
        );
    }
    for (m, p, _) in PUBLIC {
        assert!(
            all.iter()
                .any(|(rm, rp)| rp == p && (*m == "ANY" || rm == m)),
            "allowlisted {m} {p} is not a route any more: drop it from PUBLIC"
        );
    }
}

/// No credentials, a malformed one, an unknown API key, a wrong admin
/// token: every route outside the allowlist refuses with 401 or 403.
#[sqlx::test(migrations = "../store/migrations")]
async fn every_other_route_refuses_without_valid_credentials(pool: PgPool) {
    let (app, _) = app(pool);
    let bad = [
        None,
        Some("not-a-key"),
        Some("aa_0123456789ab_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Some("aat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Some("admin-token-for-the-route-auth-test-0124"),
    ];
    let mut failures = Vec::new();
    let mut checked = 0usize;
    for (method, pattern) in routes() {
        if is_public(&method, &pattern) {
            continue;
        }
        let path = concrete(&pattern);
        let methods: Vec<&str> = if method == "ANY" {
            vec!["GET", "POST"]
        } else {
            vec![method.as_str()]
        };
        for m in methods {
            for b in bad {
                let (status, body) = send(&app, m, &path, b).await;
                checked += 1;
                if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
                    failures.push(format!("{m} {path} with {b:?}: {status} {body}"));
                }
            }
        }
    }
    assert!(checked > 300, "only {checked} requests made");
    assert!(
        failures.is_empty(),
        "reachable without valid credentials:\n{}",
        failures.join("\n")
    );
}

/// An agent's valid API key opens no admin route.
#[sqlx::test(migrations = "../store/migrations")]
async fn an_agent_key_opens_no_admin_route(pool: PgPool) {
    let (app, state) = app(pool);
    let key = agent_key(&state).await;
    // The key works where it should.
    let (status, body) = send(&app, "GET", "/v1/me", Some(&key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut failures = Vec::new();
    for (method, pattern) in routes() {
        if !pattern.starts_with("/admin") || is_public(&method, &pattern) {
            continue;
        }
        let path = concrete(&pattern);
        let (status, body) = send(&app, &method, &path, Some(&key)).await;
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
            failures.push(format!("{method} {path}: {status} {body}"));
        }
    }
    assert!(
        failures.is_empty(),
        "admin routes open to an agent key:\n{}",
        failures.join("\n")
    );
}
