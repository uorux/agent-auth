//! Scenario 6: the stdio MCP server, as an agent's runtime starts it.

use std::os::unix::fs::PermissionsExt;

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::harness::{Mcp, TempDir};
use crate::world::World;

fn golden() -> Value {
    serde_json::from_str(include_str!("../../../mcp/tests/golden/tools.json")).unwrap()
}

#[sqlx::test(migrations = false)]
async fn stdio_mcp_requests_waits_and_writes_the_credential_to_a_file(
    _: PgPoolOptions,
    opts: PgConnectOptions,
) {
    let w = World::start(&opts).await;
    let agent = w
        .broker
        .create_agent("auto-mcp", &["--kind", "ephemeral"])
        .await;
    let runtime = TempDir::new();
    let mut mcp = Mcp::start(&w.broker, &agent.key, runtime.path()).await;

    // What the server advertises is the golden copy of the Python's.
    let golden = golden();
    assert_eq!(mcp.instructions, golden["instructions"].as_str().unwrap());
    let listed = mcp.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let expected = golden["tools"].as_array().unwrap();
    let names = |ts: &[Value]| ts.iter().map(|t| t["name"].clone()).collect::<Vec<_>>();
    assert_eq!(names(tools), names(expected));
    for (got, want) in tools.iter().zip(expected) {
        for field in ["description", "inputSchema", "outputSchema"] {
            assert_eq!(got[field], want[field], "{} {field}", want["name"]);
        }
    }

    let me = mcp.call_ok("whoami", json!({})).await;
    assert_eq!(me["name"], "auto-mcp", "{me}");

    let r = mcp
        .call_ok(
            "request_access",
            json!({"platform": "github", "capability": "repo", "resource": "acme/auto-tool",
                   "justification": "release the CLI tool", "duration": "1h",
                   "scope": {"permissions": {"contents": "write"}}}),
        )
        .await;
    let id = r["id"].as_str().unwrap().to_owned();
    let r = mcp
        .call_ok(
            "wait_for_decision",
            json!({"request_id": id, "timeout": 30}),
        )
        .await;
    assert_eq!(r["status"], "granted", "{r}");
    let grant = r["grant_id"].as_str().unwrap().to_owned();

    let c = mcp
        .call_ok(
            "get_credential",
            json!({"grant_id": grant, "to_file": true}),
        )
        .await;
    assert_eq!(
        c["value"],
        Value::Null,
        "the token stays out of the conversation: {c}"
    );
    let file = c["file"].as_str().unwrap();
    assert!(
        file.starts_with(
            runtime
                .path()
                .join("agent-auth/credentials")
                .to_str()
                .unwrap()
        ),
        "{file}"
    );
    assert_eq!(std::fs::read_to_string(file).unwrap().trim(), "ghs_e2e_2");
    let mode = std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    let dir_mode = std::fs::metadata(std::path::Path::new(file).parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "{dir_mode:o}");
    assert!(
        c["git_helper"].as_str().is_some_and(|h| h.contains(file)),
        "{c}"
    );

    // A refusal comes back as the broker's words.
    let refused = mcp
        .call_ok(
            "get_credential",
            json!({"grant_id": "00000000-0000-4000-8000-000000000000"}),
        )
        .await;
    assert_eq!(
        refused,
        json!({"error": "unknown grant", "status_code": 404})
    );

    assert!(mcp.close().await.success());
}
