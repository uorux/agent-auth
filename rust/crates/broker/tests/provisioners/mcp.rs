//! MCP tokens and the token routes (provisioners spec §6).

use std::sync::Arc;

use agent_auth_broker::auth::AuthConfig;
use agent_auth_broker::provisioners::mcp::McpProvisioner;
use agent_auth_broker::provisioners::{PlatformServices, Provisioner, tokens};
use agent_auth_broker::state::AppState;
use agent_auth_core::authority::ToolSet;
use agent_auth_core::policy::Policy;
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::daemon::SigningKey;
use agent_auth_crypto::jwt::TokenIssuer;
use agent_auth_store::Store;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use crate::common::*;

fn policy() -> Policy {
    Policy::from_value(json!({"platforms": {"mcp": {
        "issuer": "https://broker.example/",
        "token_ttl": "1h",
        "servers": {
            "notes": {"url": "https://notes.example/mcp", "description": "Shared notes", "tools": ["read", "write"]},
            "open": {"url": "https://open.example/mcp", "audience": "open-aud"},
        },
    }}}))
    .unwrap()
}

fn issuer() -> Arc<TokenIssuer> {
    let key = SigningKey::from_seed(&[3u8; 32]).unwrap();
    Arc::new(TokenIssuer::new(&key, "https://broker.example/").unwrap())
}

struct T {
    store: Store,
    p: McpProvisioner,
    tokens: Arc<TokenIssuer>,
    state: AppState,
}

fn setup(pool: PgPool) -> T {
    let policy = policy();
    let tokens = issuer();
    let p = McpProvisioner::new(&policy.platforms().mcp, tokens.clone());
    let store = Store::from_pool(pool);
    let mut state = AppState::new(store.clone(), policy, AuthConfig::default());
    state.platform_services = Arc::new(PlatformServices {
        tokens: Some(tokens.clone()),
        ..PlatformServices::default()
    });
    T {
        store,
        p,
        tokens,
        state,
    }
}

fn tools(t: &[&str]) -> Authority {
    Authority::Mcp {
        tools: ToolSet::Some(t.iter().map(|s| (*s).to_owned()).collect()),
    }
}

async fn get(
    state: &AppState,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut req = Request::builder().uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let res = tokens::routes()
        .with_state(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[sqlx::test(migrations = "../store/migrations")]
async fn validation(pool: PgPool) {
    let t = setup(pool);
    let a = agent(&t.store, "mcp-agent").await;
    let v = |scope: Value, res: &'static str| {
        let (store, p, a) = (t.store.clone(), &t.p, a.clone());
        async move { validate(&store, p, &a, Platform::Mcp, "use", scope, res).await }
    };
    let ok = v(json!({"tools": ["write", "read", "read"]}), " Notes ")
        .await
        .unwrap();
    assert_eq!(ok.resource, "notes");
    assert_eq!(ok.authority, tools(&["read", "write"]));
    assert_eq!(
        ok.notes,
        ["tools read, write of notes (https://notes.example/mcp): Shared notes"]
    );
    let all = v(json!({}), "notes").await.unwrap();
    assert_eq!(
        all.notes,
        ["every tool of notes (https://notes.example/mcp): Shared notes"]
    );
    assert_eq!(
        v(json!({}), "nope").await.unwrap_err(),
        "no MCP server 'nope' in the catalog (there is: notes, open)"
    );
    assert_eq!(
        v(json!({"tools": ["delete"]}), "notes").await.unwrap_err(),
        "notes has no tool delete"
    );
    assert_eq!(
        v(json!({"tools": ["bad tool"]}), "open").await.unwrap_err(),
        "malformed tool name"
    );
    assert!(v(json!({"tools": []}), "notes").await.is_err());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_token_names_the_server_tools_and_grant(pool: PgPool) {
    let t = setup(pool);
    let a = agent(&t.store, "mcp-agent").await;
    let g = granted(&t.store, &t.p, a.id, &tools(&["read"]), "notes").await;
    assert_eq!(g.provisioner_state, json!({"server": "notes"}));
    let c = credential(&t.store, &t.p, &g).await.unwrap();
    assert_eq!(kind_name(&c), "mcp_token");
    let now_f = now().unix_timestamp() as f64;
    let claims = t
        .tokens
        .verify(expose(&c), "https://notes.example/mcp", now_f)
        .unwrap();
    assert_eq!(claims["sub"], "agent:mcp-agent");
    assert_eq!(claims["aud"], "https://notes.example/mcp");
    assert_eq!(claims["iss"], "https://broker.example");
    assert_eq!(claims["server"], "notes");
    assert_eq!(claims["tools"], json!(["read"]));
    assert_eq!(claims["grant"], json!(g.id.to_string()));
    let exp = claims["exp"].as_i64().unwrap();
    assert!(exp <= g.expires_at.unix_timestamp() && exp <= now().unix_timestamp() + 3600);
    assert_eq!(c.expires_at.unwrap().unix_timestamp(), exp);
    assert!(
        c.note.unwrap().starts_with(
            "Send it to https://notes.example/mcp as `Authorization: Bearer <value>`."
        )
    );

    // A short grant caps the token.
    let short = provisioning(&t.store, a.id, &tools(&["read"]), "notes", 120).await;
    let short = provision(&t.store, &t.p, &short).await.unwrap();
    let c = credential(&t.store, &t.p, &short).await.unwrap();
    assert!(c.expires_at.unwrap() <= short.expires_at);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn verify_answers_for_live_grants_only(pool: PgPool) {
    let t = setup(pool);
    let a = agent(&t.store, "mcp-agent").await;
    let g = granted(
        &t.store,
        &t.p,
        a.id,
        &Authority::Mcp {
            tools: ToolSet::All,
        },
        "open",
    )
    .await;
    let token = expose(&credential(&t.store, &t.p, &g).await.unwrap()).to_owned();
    let bearer = format!("Bearer {token}");

    let (s, h, _) = get(&t.state, "/v1/tokens/verify?server=open", Some(&bearer)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["x-agent-auth-agent"], "mcp-agent");
    assert_eq!(h["x-agent-auth-tools"], "*");

    let (s, h, _) = get(&t.state, "/v1/tokens/verify?server=notes", Some(&bearer)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h["www-authenticate"],
        "Bearer error=\"invalid_token\", error_description=\"not a valid token for this server\""
    );
    for (uri, auth) in [
        ("/v1/tokens/verify?server=nope", Some(bearer.as_str())),
        ("/v1/tokens/verify?server=open", None),
        ("/v1/tokens/verify?server=open", Some("Basic x")),
    ] {
        let (s, h, _) = get(&t.state, uri, auth).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(
            h["www-authenticate"],
            "Bearer error=\"invalid_token\", error_description=\"a bearer token for a known server is required\""
        );
    }

    // Containment ends verification at once (B20).
    contain(&t.store, "abcd1234", json!({"name": "mcp-agent"})).await;
    assert_eq!(
        get(&t.state, "/v1/tokens/verify?server=open", Some(&bearer))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    lift_all(&t.store).await;
    assert_eq!(
        get(&t.state, "/v1/tokens/verify?server=open", Some(&bearer))
            .await
            .0,
        StatusCode::OK
    );

    expire(&t.store, &t.p, g.id).await.unwrap();
    let (s, h, _) = get(&t.state, "/v1/tokens/verify?server=open", Some(&bearer)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h["www-authenticate"],
        "Bearer error=\"invalid_token\", error_description=\"the grant behind this token has ended\""
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn keys_and_discovery(pool: PgPool) {
    let t = setup(pool);
    let (s, _, body) = get(&t.state, "/.well-known/jwks.json", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, t.tokens.jwks());
    let (s, _, body) = get(&t.state, "/.well-known/openid-configuration", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        body["jwks_uri"],
        "https://broker.example/.well-known/jwks.json"
    );

    let mut off = t.state.clone();
    off.platform_services = Arc::default();
    for uri in [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/v1/tokens/verify?server=open",
    ] {
        assert_eq!(get(&off, uri, None).await.0, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_server_removed_from_the_catalog_issues_nothing(pool: PgPool) {
    let t = setup(pool);
    let a = agent(&t.store, "mcp-agent").await;
    let g = granted(&t.store, &t.p, a.id, &tools(&["read"]), "notes").await;
    let fewer = Policy::from_value(json!({"platforms": {"mcp": {"issuer": "https://broker.example", "servers": {"open": {"url": "https://o"}}}}})).unwrap();
    let p = McpProvisioner::new(&fewer.platforms().mcp, t.tokens.clone());
    assert_eq!(
        credential(&t.store, &p, &g).await.unwrap_err().text(),
        "MCP server 'notes' is no longer in the catalog"
    );
    let c = p.catalog(&a).unwrap();
    assert_eq!(
        c["servers"],
        json!([{"name": "open", "url": "https://o", "description": "", "tools": null}])
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn the_credential_route_serves_an_mcp_token(pool: PgPool) {
    let t = setup(pool);
    let a = agent(&t.store, "mcp-agent").await;
    let g = granted(&t.store, &t.p, a.id, &tools(&["read"]), "notes").await;
    let out = credentials_over_http(
        &t.store,
        agent_auth_broker::provisioners::AnyProvisioner::Mcp(t.p),
        &[&g],
    )
    .await;
    assert_eq!(out[0].0, axum::http::StatusCode::OK, "{}", out[0].1);
    assert_eq!(out[0].1["kind"], "mcp_token");
    assert!(out[0].1["value"].as_str().is_some_and(|v| !v.is_empty()));
}
