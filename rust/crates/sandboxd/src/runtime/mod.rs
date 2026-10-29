//! The model runtimes sandboxd drives (sandboxd spec §4.8): Claude Code
//! headless over stream-json, and codex's app-server over a WebSocket on a
//! unix socket. Static dispatch over the two.

pub mod claude;
pub mod codex;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::host::{Host, HostError, UnitSpec};
use crate::names::ConvId;

/// The environment variable holding the agent's model-gateway key.
pub const GATEWAY_KEY_ENV: &str = "AGENT_AUTH_MODELS_KEY";

/// What a running process reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Assistant output.
    Text(String),
    TurnDone(String),
    Error(String),
    /// The process ended.
    Exit,
}

/// One MCP server in a process's config. Its env holds names only (the
/// values are in the unit's environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServer {
    pub command: String,
    pub args: Vec<String>,
    pub env_vars: Vec<String>,
}

/// Everything a runtime needs to start one conversation's process.
#[derive(Clone)]
pub struct SpawnContext {
    pub conversation_id: ConvId,
    pub unit: String,
    pub uid: u32,
    pub workdir: PathBuf,
    pub home: PathBuf,
    /// The host path bound to `/tmp` in the unit.
    pub tmp: PathBuf,
    /// Secrets included; goes into the root-only env file only.
    pub env: BTreeMap<String, String>,
    pub system_prompt: String,
    /// The runtime's own session/thread id: None = new conversation.
    pub runtime_session_id: Option<String>,
    pub mcp_servers: BTreeMap<String, McpServer>,
    pub read_write: Vec<PathBuf>,
    pub model: Option<String>,
    /// Hook commands by event name (claude: PostToolUse, UserPromptSubmit).
    pub hooks: BTreeMap<String, String>,
    /// The model gateway's URL when calls go through it.
    pub model_gateway: Option<String>,
    /// The tmp directory, reached without following (for codex's socket).
    pub tmp_tree: crate::host::Tree,
}

impl std::fmt::Debug for SpawnContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnContext")
            .field("conversation_id", &self.conversation_id)
            .field("unit", &self.unit)
            .field("uid", &self.uid)
            .field("workdir", &self.workdir)
            .finish_non_exhaustive()
    }
}

impl SpawnContext {
    #[must_use]
    pub fn unit_spec(&self, argv: Vec<String>, description: String) -> UnitSpec {
        UnitSpec {
            name: self.unit.clone(),
            uid: self.uid,
            argv,
            workdir: self.workdir.clone(),
            home: self.home.clone(),
            tmp: self.tmp.clone(),
            env: self.env.clone(),
            read_write: self.read_write.clone(),
            description,
        }
    }
}

/// A runtime.
#[derive(Debug, Clone)]
pub enum Runtime {
    Claude(claude::ClaudeRuntime),
    Codex(codex::CodexRuntime),
}

impl Runtime {
    /// The runtime for a configured name (`claude`, `codex`).
    #[must_use]
    pub fn from_config(name: &str, command: &str, model: Option<&str>) -> Option<Runtime> {
        match name {
            "claude" => Some(Runtime::Claude(claude::ClaudeRuntime::new(command, model))),
            "codex" => Some(Runtime::Codex(codex::CodexRuntime::new(command, model))),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Runtime::Claude(_) => "claude",
            Runtime::Codex(_) => "codex",
        }
    }

    /// Whether a TUI joins the live process (codex) or takes the session
    /// over (claude: stop, then resume in the TUI).
    #[must_use]
    pub fn shares_live_process(&self) -> bool {
        matches!(self, Runtime::Codex(_))
    }

    /// Whether a message for a busy process waits in the inbox for the
    /// runtime's own hook (claude's PostToolUse) instead of being written
    /// to it (codex steers the running turn).
    #[must_use]
    pub fn doorbell(&self) -> bool {
        matches!(self, Runtime::Claude(_))
    }

    #[must_use]
    pub fn model(&self) -> Option<&str> {
        match self {
            Runtime::Claude(r) => r.model.as_deref(),
            Runtime::Codex(r) => r.model.as_deref(),
        }
    }

    /// The command (tests replace it).
    pub fn set_command(&mut self, command: &str) {
        match self {
            Runtime::Claude(r) => r.command = command.to_owned(),
            Runtime::Codex(r) => r.command = command.to_owned(),
        }
    }

    pub async fn start<H: Host>(&self, host: &H, ctx: &mut SpawnContext) -> Result<Run, HostError> {
        match self {
            Runtime::Claude(r) => r.start(host, ctx).await.map(Run::Claude),
            Runtime::Codex(r) => r.start(host, ctx).await.map(Run::Codex),
        }
    }

    #[must_use]
    pub fn tui_argv(&self, ctx: &SpawnContext) -> Vec<String> {
        match self {
            Runtime::Claude(r) => r.tui_argv(ctx),
            Runtime::Codex(r) => r.tui_argv(ctx),
        }
    }

    #[must_use]
    pub fn gateway_argv(&self, url: Option<&str>) -> Vec<String> {
        match self {
            Runtime::Claude(_) => Vec::new(),
            Runtime::Codex(_) => codex::gateway_argv(url),
        }
    }

    #[must_use]
    pub fn triage_argv(&self, model: Option<&str>) -> Vec<String> {
        match self {
            Runtime::Claude(r) => r.triage_argv(model),
            Runtime::Codex(r) => r.triage_argv(model),
        }
    }

    #[must_use]
    pub fn triage_answer(&self, stdout: &str) -> String {
        match self {
            Runtime::Claude(_) => claude::triage_answer(stdout),
            Runtime::Codex(_) => codex::triage_answer(stdout),
        }
    }
}

/// One live process of a conversation.
#[derive(Debug)]
pub enum Run {
    Claude(claude::ClaudeRun),
    Codex(codex::CodexRun),
}

impl Run {
    #[must_use]
    pub fn busy(&self) -> bool {
        match self {
            Run::Claude(r) => r.busy(),
            Run::Codex(r) => r.busy(),
        }
    }

    #[must_use]
    pub fn runtime_session_id(&self) -> Option<String> {
        match self {
            Run::Claude(r) => Some(r.session_id()),
            Run::Codex(r) => r.thread_id(),
        }
    }

    pub async fn send(&self, text: &str) -> Result<(), HostError> {
        match self {
            Run::Claude(r) => r.send(text).await,
            Run::Codex(r) => r.send(text).await,
        }
    }

    pub async fn stop<H: Host>(&self, host: &H) {
        match self {
            Run::Claude(r) => r.stop(host).await,
            Run::Codex(r) => r.stop(host).await,
        }
    }

    /// The event stream (once).
    #[must_use]
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<Event>> {
        match self {
            Run::Claude(r) => r.take_events(),
            Run::Codex(r) => r.take_events(),
        }
    }

    #[must_use]
    pub fn unit(&self) -> &str {
        match self {
            Run::Claude(r) => r.unit(),
            Run::Codex(r) => r.unit(),
        }
    }
}

/// A run shared between the conversation and its pump.
pub type RunRef = Arc<Run>;
