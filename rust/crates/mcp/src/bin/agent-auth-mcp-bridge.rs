#![forbid(unsafe_code)]
//! `agent-auth-mcp-bridge <server>`: a server from agent-auth's mcp catalog
//! as a local stdio MCP server. Needs `AGENT_AUTH_URL` and
//! `AGENT_AUTH_API_KEY` (no default URL here); `AGENT_AUTH_SESSION` is sent
//! when set.

use std::process::ExitCode;
use std::sync::Arc;

use agent_auth_client::{BrokerClient, Config};
use agent_auth_mcp::bridge::{Bridge, BridgeError, upstream_client};

const USAGE: &str =
    "usage: agent-auth-mcp-bridge <server>   (a server from agent-auth's mcp catalog)";

fn fail(text: &str) -> ExitCode {
    eprintln!("agent-auth-mcp-bridge: {text}");
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let server = match args.as_slice() {
        [server] if !server.starts_with('-') => server.clone(),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = Config::from_env();
    if config.base_url.is_none() || config.api_key.is_none() {
        return fail("AGENT_AUTH_URL and AGENT_AUTH_API_KEY must be set");
    }
    let broker = match BrokerClient::new(Config {
        admin_token: None,
        ..config
    }) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };
    let upstream = match upstream_client() {
        Ok(u) => u,
        Err(e) => return fail(&e),
    };
    let bridge = Arc::new(Bridge::new(
        server,
        broker,
        upstream,
        Box::new(tokio::io::stdout()),
    ));
    match bridge.token(false).await {
        Ok(_) => {}
        Err(BridgeError::NoGrant(msg)) => return fail(&msg),
        Err(e) => return fail(&format!("cannot reach agent-auth: {e}")),
    }
    bridge
        .run(tokio::io::BufReader::new(tokio::io::stdin()))
        .await;
    ExitCode::SUCCESS
}
