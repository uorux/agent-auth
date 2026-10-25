#![forbid(unsafe_code)]
//! `agent-auth-sandbox-mcp`: the sandbox MCP server over stdio, or with
//! `hook`, claude's PostToolUse / UserPromptSubmit hook. Environment:
//! `AGENT_AUTH_SANDBOX_SOCKET`, `AGENT_AUTH_SANDBOX_TOKEN`.

use std::io::Read as _;
use std::process::ExitCode;

use agent_auth_sandboxd::mcp::{AgentEnv, SandboxMcp, hook};
use rmcp::ServiceExt as _;

#[tokio::main]
async fn main() -> ExitCode {
    let env = AgentEnv::from_env();
    if std::env::args().nth(1).as_deref() == Some("hook") {
        let mut stdin = String::new();
        let _ = std::io::stdin()
            .take(1024 * 1024)
            .read_to_string(&mut stdin);
        if let Some(out) = hook(&env, &stdin).await {
            println!("{out}");
        }
        return ExitCode::SUCCESS;
    }
    let running = match SandboxMcp::new(env).serve(rmcp::transport::stdio()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agent-auth-sandbox-mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    match running.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-auth-sandbox-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}
