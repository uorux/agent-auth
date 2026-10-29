#![forbid(unsafe_code)]
//! `agent-auth-mcp`: the broker's agent API as MCP tools, over stdio.
//! Environment: `AGENT_AUTH_URL` (default `https://agent-auth.rooty.dev`),
//! `AGENT_AUTH_API_KEY`, `AGENT_AUTH_SESSION`.

use std::process::ExitCode;

use agent_auth_client::BrokerClient;
use agent_auth_mcp::caller::LocalCaller;
use agent_auth_mcp::server::AgentAuthServer;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> ExitCode {
    let client = match BrokerClient::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent-auth-mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    let server = AgentAuthServer::new(LocalCaller::new(client));
    let running = match server.serve(rmcp::transport::stdio()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agent-auth-mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    match running.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-auth-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}
