#![forbid(unsafe_code)]
//! The agent-side MCP programs.
//!
//! - `agent-auth-mcp`: a stdio MCP server (rmcp) whose tools are the
//!   broker's agent API. Tool names, descriptions, parameter schemas and the
//!   server instructions are the Python server's, verbatim ([`tools`]).
//! - `agent-auth-mcp-bridge <server>`: a catalogued MCP server as a local
//!   stdio server, with the agent's own short-lived token ([`bridge`]).
//!
//! The tools act for a [`caller::Caller`]: the stdio server's is the
//! environment's agent ([`caller::LocalCaller`]); the broker's remote MCP
//! endpoint provides its own per connector and calls [`dispatch::call`].

pub mod bridge;
pub mod caller;
pub mod dispatch;
pub mod server;
pub mod to_file;
pub mod tools;

/// The tool names (Python `mcp_names.TOOL_NAMES`), for policy's
/// `remote_mcp.tools`.
pub fn tool_names() -> impl Iterator<Item = &'static str> {
    tools::tool_names()
}
