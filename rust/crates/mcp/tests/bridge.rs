//! agent-auth-mcp-bridge: stdio in, the server's HTTP endpoint out, with the
//! agent's own token, refreshed when the server says it ran out.

// Test code: helpers outside #[test] functions may unwrap and index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::{Arc, Mutex};

use agent_auth_client::testing::{FakeBroker, Reply, shapes};
use agent_auth_client::{BrokerClient, Config};
use agent_auth_mcp::bridge::{Bridge, BridgeError, upstream_client};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What the upstream saw: authorization, session id, protocol, method.
type Upstream = (String, Option<String>, Option<String>, Option<String>);

const G1: &str = "b0000000-0000-4000-8000-000000000001";
const G2: &str = "b0000000-0000-4000-8000-000000000002";
const G3: &str = "b0000000-0000-4000-8000-000000000003";

fn later(minutes: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::minutes(minutes);
    agent_auth_wire::timestamp::format(t).unwrap()
}

async fn broker(upstream_url: &str, grants: bool) -> (FakeBroker, Arc<Mutex<Vec<String>>>) {
    let fake = FakeBroker::start().await.unwrap();
    fake.json(
        "GET",
        "/v1/catalog",
        200,
        shapes::catalog_with_mcp("browser", upstream_url),
    );
    let list = if grants {
        json!([
            shapes::grant(
                G1,
                "mcp",
                "browser",
                json!({"tools": ["navigate"]}),
                "2099-01-01T00:00:00.000000Z"
            ),
            shapes::grant(
                G2,
                "mcp",
                "browser",
                json!({"tools": ["*"]}),
                "2098-01-01T00:00:00.000000Z"
            ),
            shapes::grant(
                G3,
                "github",
                "browser",
                json!({}),
                "2099-01-01T00:00:00.000000Z"
            ),
        ])
    } else {
        json!([])
    };
    fake.json("GET", "/v1/grants", 200, list);
    let issued: Arc<Mutex<Vec<String>>> = Arc::default();
    let i = issued.clone();
    fake.on("GET", "/v1/grants/*/credential", move |seen| {
        assert_eq!(
            seen.path,
            format!("/v1/grants/{G2}/credential"),
            "the widest grant"
        );
        let mut i = i.lock().unwrap();
        let token = format!("token-{}", i.len() + 1);
        i.push(token.clone());
        Reply::json(
            200,
            &shapes::credential("mcp_token", Some(&token), Some(&later(10))),
        )
    });
    (fake, issued)
}

fn client(url: &str) -> BrokerClient {
    BrokerClient::new(Config {
        base_url: Some(url.to_owned()),
        api_key: Some("aa_key".into()),
        ..Config::default()
    })
    .unwrap()
}

#[tokio::test]
async fn the_bridge_adds_a_fresh_token_and_relays_json_and_event_streams() {
    let upstream = FakeBroker::start().await.unwrap();
    let seen: Arc<Mutex<Vec<Upstream>>> = Arc::default();
    let s = seen.clone();
    upstream.on("POST", "/mcp", move |req| {
        let message = req.json();
        let method = message["method"].as_str().map(str::to_owned);
        let auth = req.header("authorization").unwrap_or_default().to_owned();
        s.lock().unwrap().push((
            auth.clone(),
            req.header("mcp-session-id").map(str::to_owned),
            req.header("mcp-protocol-version").map(str::to_owned),
            method.clone(),
        ));
        assert_eq!(req.header("accept"), Some("application/json, text/event-stream"));
        match method.as_deref() {
            Some("tools/call") if auth == "Bearer token-1" => Reply::text(401, "text/plain", ""),
            Some("initialize") => Reply::json(
                200,
                &json!({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-06-18"}}),
            )
            .header("mcp-session-id", "s-1"),
            Some("tools/call") => Reply::text(
                200,
                "text/event-stream",
                &format!(
                    "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\n\n\
                     data: {{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"ok\":true}}}}\n\n",
                    message["id"]
                ),
            ),
            Some("tools/list") => Reply::text(500, "text/plain", "boom"),
            _ => Reply::text(202, "text/plain", ""),
        }
    });
    let (fake, issued) = broker(&format!("{}/mcp", upstream.url), true).await;

    let (out_w, out_r) = tokio::io::duplex(1 << 20);
    let bridge = Arc::new(Bridge::new(
        "browser",
        client(&fake.url),
        upstream_client().unwrap(),
        Box::new(out_w),
    ));
    let (mut stdin_w, stdin_r) = tokio::io::duplex(1 << 20);
    let run = tokio::spawn(bridge.clone().run(BufReader::new(stdin_r)));
    for message in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ] {
        stdin_w
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
    }
    stdin_w.write_all(b"\nnot json\n").await.unwrap();
    let mut out = BufReader::new(out_r).lines();
    let first: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(first["result"]["protocolVersion"], "2025-06-18");
    // One at a time, so the order of the answers is known.
    stdin_w
        .write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "navigate"}})).as_bytes())
        .await
        .unwrap();
    let progress: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    let result: Value = serde_json::from_str(&out.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(progress["method"], "notifications/progress");
    assert_eq!(
        result,
        json!({"jsonrpc": "2.0", "id": 2, "result": {"ok": true}})
    );
    stdin_w
        .write_all(
            format!(
                "{}\n",
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let line = out.next_line().await.unwrap().unwrap();
    let failed: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(failed["id"], 3);
    assert_eq!(failed["error"]["code"], -32000);
    assert_eq!(
        failed["error"]["message"],
        "agent-auth-mcp-bridge: browser answered 500: boom"
    );
    // Compact, one line.
    assert!(!line.contains("\": ") && !line.contains(", \""), "{line}");
    drop(stdin_w);
    run.await.unwrap();

    // The 401 was retried once with a new token; the session id is kept.
    let seen = seen.lock().unwrap().clone();
    let calls: Vec<_> = seen
        .iter()
        .filter(|(_, _, _, m)| m.as_deref() == Some("tools/call"))
        .map(|(a, s, v, _)| (a.clone(), s.clone(), v.clone()))
        .collect();
    assert_eq!(
        calls,
        [
            (
                "Bearer token-1".into(),
                Some("s-1".into()),
                Some("2025-06-18".into())
            ),
            (
                "Bearer token-2".into(),
                Some("s-1".into()),
                Some("2025-06-18".into())
            ),
        ]
    );
    assert_eq!(seen[0].1, None, "no session id before initialize answered");
    assert_eq!(*issued.lock().unwrap(), ["token-1", "token-2"]);
    // The broker saw the agent's key on every call.
    assert!(
        fake.seen()
            .iter()
            .all(|s| s.header("authorization") == Some("Bearer aa_key"))
    );
}

#[tokio::test]
async fn without_a_grant_it_says_how_to_get_one() {
    let (fake, _) = broker("https://browser.example/mcp", false).await;
    let bridge = Bridge::new(
        "browser",
        client(&fake.url),
        upstream_client().unwrap(),
        Box::new(tokio::io::sink()),
    );
    match bridge.token(false).await {
        Err(BridgeError::NoGrant(msg)) => {
            assert_eq!(
                msg,
                "no active agent-auth grant for MCP server 'browser': ask with \
                 request_access(platform=\"mcp\", capability=\"use\", resource=\"browser\")"
            );
        }
        other => panic!("{other:?}"),
    }
    let bridge = Bridge::new(
        "nope",
        client(&fake.url),
        upstream_client().unwrap(),
        Box::new(tokio::io::sink()),
    );
    match bridge.token(false).await {
        Err(BridgeError::NoGrant(msg)) => {
            assert_eq!(msg, "agent-auth has no MCP server 'nope' in its catalog");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_token_is_reused_until_it_is_close_to_expiring() {
    let (fake, issued) = broker("https://browser.example/mcp", true).await;
    let bridge = Bridge::new(
        "browser",
        client(&fake.url),
        upstream_client().unwrap(),
        Box::new(tokio::io::sink()),
    );
    assert_eq!(bridge.token(false).await.unwrap(), "token-1");
    assert_eq!(bridge.token(false).await.unwrap(), "token-1");
    assert_eq!(bridge.token(true).await.unwrap(), "token-2");
    assert_eq!(issued.lock().unwrap().len(), 2);
    // The catalog is read once.
    assert_eq!(fake.calls("GET", "/v1/catalog").len(), 1);
}
