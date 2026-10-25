//! The MCP server (rmcp) over a [`Caller`]: the tool table for
//! `tools/list`, [`crate::dispatch`] for `tools/call`.
//!
//! rmcp runs each request in its own task, so a tool waiting on the broker
//! (a decision, a reply, a host job) does not hold up other calls on the
//! connection.

use std::sync::Arc;

use rmcp::ErrorData as McpError;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::json;

use crate::caller::Caller;
use crate::tools::{INSTRUCTIONS, SERVER_NAME, rmcp_tools};

/// The agent-auth MCP server.
#[derive(Debug)]
pub struct AgentAuthServer<C> {
    caller: Arc<C>,
    tools: Arc<Vec<Tool>>,
}

impl<C> Clone for AgentAuthServer<C> {
    fn clone(&self) -> Self {
        AgentAuthServer {
            caller: self.caller.clone(),
            tools: self.tools.clone(),
        }
    }
}

impl<C: Caller> AgentAuthServer<C> {
    #[must_use]
    pub fn new(caller: C) -> Self {
        AgentAuthServer {
            caller: Arc::new(caller),
            tools: Arc::new(rmcp_tools()),
        }
    }

    /// The caller the tools act for.
    #[must_use]
    pub fn caller(&self) -> &C {
        &self.caller
    }
}

/// A tool's answer as MCP carries it: the text, and the same text as
/// `structuredContent {"result": ...}` (what FastMCP sent for a function
/// returning `str`).
#[must_use]
pub fn tool_result(outcome: Result<String, String>) -> CallToolResult {
    match outcome {
        Ok(text) => {
            let mut result = CallToolResult::success(vec![ContentBlock::text(text.clone())]);
            result.structured_content = Some(json!({ "result": text }));
            result
        }
        Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
    }
}

impl<C: Caller> ServerHandler for AgentAuthServer<C> {
    fn get_info(&self) -> ServerConfig {
        let mut config = ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS);
        config.server_info = Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION"));
        config
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.as_ref().clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let outcome = crate::dispatch::call(
            self.caller.as_ref(),
            &request.name,
            request.arguments.as_ref(),
        )
        .await;
        Ok(tool_result(outcome).into())
    }
}
