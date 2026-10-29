//! `agent-auth-sandbox-mcp`: the sandbox MCP server the VM's agents get
//! (sandboxd spec §4.14), over stdio, and `hook`, claude's PostToolUse /
//! UserPromptSubmit hook. Tool names, descriptions and parameters are the
//! Python's, verbatim; every tool returns one string: the answer as JSON
//! (indent 2), or `{"error": "..."}`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_auth_daemon::localsock::{self, CallError};
use agent_auth_mcp::server::tool_result;
use agent_auth_mcp::tools::Args;
use agent_auth_wire::mcp_tools::{DefaultValue, Param, ToolDef, Ty, input_schema, output_schema};
use rmcp::ErrorData as McpError;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Map, Value, json};

use crate::{AGENT_SOCKET_ENV, DEFAULT_AGENT_SOCKET, TOKEN_ENV};

pub const SERVER_NAME: &str = "sandbox";

pub const INSTRUCTIONS: &str = r#"You are running in an agent VM, as one project's agent (or as the VM's
orchestrator). These tools describe and manage the VM itself; access to
anything outside it (GitHub, homelab, Kubernetes, other agents) goes through
the agent-auth MCP server instead.

sandbox_whoami tells you your agent name, project and conversation. a2a
messages arrive as turns starting with "[a2a]"; answer them with agent-auth's
a2a_send. The orchestrator alone uses project_create, project_seal,
agent_mint and agent_spawn to set projects and their agents up."#;

const fn req(name: &'static str) -> Param {
    Param {
        name,
        ty: Ty::Str,
        nullable: false,
        default: DefaultValue::Required,
    }
}

/// The tools, in the Python's order.
pub const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "sandbox_whoami",
        description: "Your agent name, project, conversation id, and whether you are the\norchestrator.",
        params: &[],
    },
    ToolDef {
        name: "project_list",
        description: r#"Projects in this VM. Each has its own directory under
/var/lib/sandbox/projects and its own unix user; reading another project
needs a "sandbox" grant (request_access platform="sandbox",
capability="project.read", resource=<project>)."#,
        params: &[],
    },
    ToolDef {
        name: "conversations",
        description: r#"Your agent's conversations in this VM (running, parked, attached).
To continue one from another agent, the opener of an a2a thread can put
{"_sandbox": {"conversation": "<id>"}} in its first message."#,
        params: &[],
    },
    ToolDef {
        name: "inbox",
        description: "Messages queued for this conversation that haven't been delivered yet\n(normally they arrive as turns on their own).",
        params: &[],
    },
    ToolDef {
        name: "project_create",
        description: "Orchestrator: create a project (lowercase letters, digits, '-', ≤30):\nits directory, its own unix user, and write access for you until\nproject_seal. Then put the code there (git clone with a github grant).",
        params: &[req("name")],
    },
    ToolDef {
        name: "project_seal",
        description: "Orchestrator: hand the project over to its own user and drop your write\naccess. Spawning one of its agents seals it automatically.",
        params: &[req("name")],
    },
    ToolDef {
        name: "agent_mint",
        description: r#"Orchestrator: ask the broker for <runtime>-<project>-<host>-sandbox
(runtime "claude" or "codex"; the project must exist). Waits for the
decision (a human may be asked); the key goes to sandboxd, not to you.
Minting an existing agent renews its lease."#,
        params: &[
            req("runtime"),
            req("project"),
            Param {
                name: "why",
                ty: Ty::Str,
                nullable: false,
                default: DefaultValue::Str(""),
            },
        ],
    },
    ToolDef {
        name: "agent_spawn",
        description: r#"Orchestrator: start a new conversation of a minted agent with `prompt`
as its first message (e.g. "set up the dev shell and report back on
thread X"). Returns the conversation id."#,
        params: &[req("agent"), req("prompt")],
    },
];

/// How long a call to sandboxd may take (a mint waits for a human).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(600);

/// Where the agent socket is and which conversation this is.
#[derive(Clone)]
pub struct AgentEnv {
    pub socket: PathBuf,
    pub token: Option<String>,
}

impl std::fmt::Debug for AgentEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentEnv")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl AgentEnv {
    /// `AGENT_AUTH_SANDBOX_SOCKET` (default `/run/sandboxd-agent/agent.sock`)
    /// and `AGENT_AUTH_SANDBOX_TOKEN`.
    #[must_use]
    pub fn from_env() -> AgentEnv {
        AgentEnv {
            socket: std::env::var_os(AGENT_SOCKET_ENV)
                .filter(|v| !v.is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_AGENT_SOCKET), PathBuf::from),
            token: std::env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty()),
        }
    }

    pub async fn call(&self, method: &str, params: Map<String, Value>) -> Result<Value, CallError> {
        localsock::call(
            &self.socket,
            method,
            params,
            self.token.as_deref(),
            CALL_TIMEOUT,
        )
        .await
    }
}

/// The Python's `_safe`: the answer as JSON, or the error as JSON.
#[must_use]
pub fn safe_text(result: Result<Value, CallError>) -> String {
    let dumps = |v: &Value| agent_auth_client::pyjson::dumps(v).unwrap_or_default();
    match result {
        Ok(v) => agent_auth_client::pyjson::dumps_indent(&v).unwrap_or_default(),
        Err(CallError::Refused(msg)) => dumps(&json!({"error": msg})),
        Err(e) => dumps(&json!({"error": format!("sandboxd unreachable: {e}")})),
    }
}

/// A tool call's method and params on the agent API.
#[must_use]
pub fn method_of(tool: &str, args: &Args) -> Option<(&'static str, Map<String, Value>)> {
    let mut p = Map::new();
    let mut put = |k: &str| {
        p.insert(k.to_owned(), json!(args.str(k)));
    };
    let method = match tool {
        "sandbox_whoami" => "whoami",
        "project_list" => "project_list",
        "conversations" => "conversations",
        "inbox" => {
            p.insert("drain".into(), json!(false));
            "inbox"
        }
        "project_create" => {
            put("name");
            "project_create"
        }
        "project_seal" => {
            put("name");
            "project_seal"
        }
        "agent_mint" => {
            put("runtime");
            put("project");
            put("why");
            "agent_mint"
        }
        "agent_spawn" => {
            put("agent");
            put("prompt");
            "agent_spawn"
        }
        _ => return None,
    };
    Some((method, p))
}

/// The MCP server.
#[derive(Debug, Clone)]
pub struct SandboxMcp {
    env: Arc<AgentEnv>,
    tools: Arc<Vec<Tool>>,
}

impl SandboxMcp {
    #[must_use]
    pub fn new(env: AgentEnv) -> SandboxMcp {
        let tools = TOOLS
            .iter()
            .map(|t| {
                let mut tool = Tool::default();
                tool.name = t.name.into();
                tool.description = Some(t.description.into());
                tool.input_schema = Arc::new(input_schema(t));
                tool.output_schema = Some(Arc::new(output_schema(t)));
                tool
            })
            .collect();
        SandboxMcp {
            env: Arc::new(env),
            tools: Arc::new(tools),
        }
    }

    /// One tool call: its text, or the MCP error text.
    pub async fn call(
        &self,
        name: &str,
        args: Option<&Map<String, Value>>,
    ) -> Result<String, String> {
        let Some(tool) = TOOLS.iter().find(|t| t.name == name) else {
            return Err(format!("Unknown tool: {name}"));
        };
        let args = Args::parse(tool, args).map_err(|e| {
            format!("Error executing tool {name}: 1 validation error for {name}Arguments\n{e}")
        })?;
        let Some((method, params)) = method_of(name, &args) else {
            return Err(format!("Unknown tool: {name}"));
        };
        Ok(safe_text(self.env.call(method, params).await))
    }
}

impl ServerHandler for SandboxMcp {
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
        let outcome = self.call(&request.name, request.arguments.as_ref()).await;
        Ok(tool_result(outcome).into())
    }
}

/// The hook's answer: what to print (nothing when the inbox is empty).
/// `stdin` is the hook's JSON; the reply names the same event (anything
/// other than PostToolUse is UserPromptSubmit).
#[must_use]
pub fn hook_output(stdin: &str, queued: &[String]) -> Option<String> {
    let event = serde_json::from_str::<Value>(stdin).ok().and_then(|v| {
        v.get("hook_event_name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let event = match event.as_deref() {
        Some("PostToolUse") => "PostToolUse",
        _ => "UserPromptSubmit",
    };
    if queued.is_empty() {
        return None;
    }
    let context = format!(
        "Messages that arrived for this conversation while you were working:\n\n{}",
        queued.join("\n\n")
    );
    agent_auth_client::pyjson::dumps(
        &json!({"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}}),
    )
    .ok()
}

/// The hook: drain the conversation's inbox (any failure: nothing).
pub async fn hook(env: &AgentEnv, stdin: &str) -> Option<String> {
    let mut p = Map::new();
    p.insert("drain".into(), json!(true));
    let queued: Vec<String> = match env.call("inbox", p).await {
        Ok(Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    hook_output(stdin, &queued)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hook_names_its_event_and_says_nothing_when_empty() {
        let out = hook_output(
            r#"{"hook_event_name": "PostToolUse"}"#,
            &["[a2a] hello".into()],
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert!(
            v["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap()
                .ends_with("while you were working:\n\n[a2a] hello")
        );
        let out = hook_output("{}", &["x".into()]).unwrap();
        assert!(out.contains("\"UserPromptSubmit\""));
        assert!(
            hook_output("garbage", &["x".into()])
                .unwrap()
                .contains("UserPromptSubmit")
        );
        assert!(hook_output(r#"{"hook_event_name": "PostToolUse"}"#, &[]).is_none());
    }

    #[test]
    fn tools_and_errors() {
        let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            [
                "sandbox_whoami",
                "project_list",
                "conversations",
                "inbox",
                "project_create",
                "project_seal",
                "agent_mint",
                "agent_spawn"
            ]
        );
        let schema = input_schema(TOOLS.iter().find(|t| t.name == "agent_mint").unwrap());
        assert_eq!(schema["required"], json!(["runtime", "project"]));
        assert_eq!(
            safe_text(Err(CallError::Refused("no".into()))),
            r#"{"error": "no"}"#
        );
        assert!(safe_text(Err(CallError::NoReply)).contains("sandboxd unreachable"));
        assert_eq!(safe_text(Ok(json!({"a": 1}))), "{\n  \"a\": 1\n}");
    }

    #[tokio::test]
    async fn an_unreachable_daemon_is_an_error_string() {
        let mcp = SandboxMcp::new(AgentEnv {
            socket: "/nonexistent/agent.sock".into(),
            token: None,
        });
        let text = mcp.call("sandbox_whoami", None).await.unwrap();
        assert!(text.contains("sandboxd unreachable"), "{text}");
        assert!(
            mcp.call("project_create", None)
                .await
                .unwrap_err()
                .contains("Field required")
        );
        assert!(mcp.call("nope", None).await.is_err());
    }
}
