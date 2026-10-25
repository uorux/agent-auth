//! The stdio server over the MCP protocol: what `tools/list` advertises is
//! the Python server's (a golden copy of its `tools/list`), and a waiting
//! tool does not hold up the others.

// Test code: helpers outside #[test] functions may unwrap and index.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::Duration;

use agent_auth_client::testing::{FakeBroker, Reply, shapes};
use agent_auth_client::{BrokerClient, Config};
use agent_auth_mcp::caller::LocalCaller;
use agent_auth_mcp::server::AgentAuthServer;
use rmcp::ServiceExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

struct Peer {
    write: WriteHalf<DuplexStream>,
    read: BufReader<ReadHalf<DuplexStream>>,
    _server: tokio::task::JoinHandle<()>,
}

impl Peer {
    async fn start(broker_url: &str) -> Peer {
        let client = BrokerClient::new(Config {
            base_url: Some(broker_url.to_owned()),
            api_key: Some("aa_abcdef_secret".into()),
            ..Config::default()
        })
        .unwrap();
        let server = AgentAuthServer::new(LocalCaller::new(client));
        let (ours, theirs) = tokio::io::duplex(1 << 22);
        let (r, w) = tokio::io::split(theirs);
        let task = tokio::spawn(async move {
            if let Ok(running) = server.serve((r, w)).await {
                let _ = running.waiting().await;
            }
        });
        let (read, write) = tokio::io::split(ours);
        let mut peer = Peer {
            write,
            read: BufReader::new(read),
            _server: task,
        };
        peer.send(
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
        )
        .await;
        let init = peer.answer(0).await;
        peer.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "agent-auth");
        peer
    }

    async fn send(&mut self, message: Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.write.write_all(line.as_bytes()).await.unwrap();
        self.write.flush().await.unwrap();
    }

    async fn next(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.read.read_line(&mut line))
            .await
            .expect("an answer within 10 s")
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn answer(&mut self, id: i64) -> Value {
        loop {
            let m = self.next().await;
            if m["id"] == json!(id) {
                return m;
            }
        }
    }

    async fn call(&mut self, id: i64, name: &str, arguments: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}}))
            .await;
    }
}

fn golden() -> Value {
    serde_json::from_str(include_str!("golden/tools.json")).unwrap()
}

#[tokio::test]
async fn tools_and_instructions_are_the_python_servers() {
    let fake = FakeBroker::start().await.unwrap();
    let mut peer = Peer::start(&fake.url).await;
    let golden = golden();

    peer.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .await;
    let listed = peer.answer(1).await;
    let tools = listed["result"]["tools"].as_array().unwrap().clone();
    let expected = golden["tools"].as_array().unwrap();
    assert_eq!(tools.len(), expected.len());
    for (got, want) in tools.iter().zip(expected) {
        assert_eq!(got["name"], want["name"]);
        assert_eq!(got["description"], want["description"], "{}", want["name"]);
        assert_eq!(got["inputSchema"], want["inputSchema"], "{}", want["name"]);
        assert_eq!(
            got["outputSchema"], want["outputSchema"],
            "{}",
            want["name"]
        );
    }
    let names: Vec<&str> = agent_auth_mcp::tool_names().collect();
    let golden_names: Vec<&str> = expected
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, golden_names);
    assert_eq!(
        agent_auth_mcp::tools::INSTRUCTIONS,
        golden["instructions"].as_str().unwrap()
    );
    for tool in [
        "whoami",
        "list_capabilities",
        "request_access",
        "wait_for_decision",
        "get_credential",
        "a2a_open",
        "create_session",
    ] {
        assert!(agent_auth_mcp::tools::INSTRUCTIONS.contains(tool));
    }
}

#[tokio::test]
async fn the_instructions_reach_the_client() {
    let fake = FakeBroker::start().await.unwrap();
    let client = BrokerClient::new(Config {
        base_url: Some(fake.url.clone()),
        api_key: Some("k".into()),
        ..Config::default()
    })
    .unwrap();
    let server = AgentAuthServer::new(LocalCaller::new(client));
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    let (r, w) = tokio::io::split(theirs);
    tokio::spawn(async move {
        if let Ok(running) = server.serve((r, w)).await {
            let _ = running.waiting().await;
        }
    });
    let (read, mut write) = tokio::io::split(ours);
    let mut read = BufReader::new(read);
    let init = json!({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}});
    write
        .write_all(format!("{init}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    read.read_line(&mut line).await.unwrap();
    let answer: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(answer["result"]["instructions"], golden()["instructions"]);
    assert!(answer["result"]["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn a_tool_returns_its_text_and_the_same_as_structured_content() {
    let fake = FakeBroker::start().await.unwrap();
    fake.json("GET", "/v1/me", 200, shapes::me("ephemeral"));
    fake.on("GET", "/v1/grants", |_| Reply::detail(403, "nope"));
    let mut peer = Peer::start(&fake.url).await;

    peer.call(1, "whoami", json!({})).await;
    let r = peer.answer(1).await["result"].clone();
    let text = r["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("{\n  \"id\": "), "{text}");
    assert_eq!(r["structuredContent"]["result"], json!(text));
    assert_ne!(r["isError"], json!(true));

    peer.call(2, "list_grants", json!({})).await;
    let r = peer.answer(2).await["result"].clone();
    assert_eq!(
        r["content"][0]["text"],
        json!(r#"{"error": "nope", "status_code": 403}"#)
    );

    peer.call(3, "check_status", json!({})).await;
    let r = peer.answer(3).await["result"].clone();
    assert_eq!(r["isError"], json!(true));
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("request_id: Field required")
    );

    peer.call(4, "no_such_tool", json!({})).await;
    let r = peer.answer(4).await;
    assert_eq!(r["result"]["isError"], json!(true), "{r}");
}

#[tokio::test]
async fn a_waiting_tool_does_not_hold_up_the_others() {
    let fake = FakeBroker::start().await.unwrap();
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    fake.on_async("GET", "/v1/hostexec/jobs/*", move |_| {
        let gate = gate.clone();
        async move {
            gate.notified().await;
            Reply::json(
                200,
                &shapes::job("61e4d294-bf60-41e4-b0b7-cf9283746077", "done"),
            )
        }
    });
    fake.json("GET", "/v1/me", 200, shapes::me("ephemeral"));
    let mut peer = Peer::start(&fake.url).await;

    peer.call(
        1,
        "host_job",
        json!({"job_id": "61e4d294-bf60-41e4-b0b7-cf9283746077", "wait_secs": 5}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await; // the job's call is in flight
    peer.call(2, "whoami", json!({})).await;
    let first = peer.next().await;
    assert_eq!(first["id"], json!(2), "whoami answered first: {first}");
    release.notify_one();
    let second = peer.answer(1).await;
    let text = second["result"]["content"][0]["text"].as_str().unwrap();
    let job: Value = serde_json::from_str(text).unwrap();
    assert_eq!(job["status"], "done");
}
