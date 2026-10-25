//! Claude Code headless: `claude -p` with stream-json in and out
//! (sandboxd spec §4.8). One process takes many turns: each user line
//! written after a `result` starts the next turn, and lines written
//! mid-turn queue up as turns of their own. The TUI resumes the same
//! session (`claude --resume <id>`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{Event, SpawnContext};
use crate::host::{Host, HostError, ProcExit};

/// The longest line read from the process (the Python's stream limit).
pub const MAX_LINE: usize = 16 * 1024 * 1024;
/// How long a stopping process gets before it is killed.
pub const STOP_WAIT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct ClaudeRuntime {
    pub command: String,
    pub model: Option<String>,
}

/// `--mcp-config`: the servers' commands and args, never their
/// environment (stdio servers inherit claude's; INV-11).
#[must_use]
pub fn mcp_config(ctx: &SpawnContext) -> String {
    let mut servers = serde_json::Map::new();
    for (name, s) in &ctx.mcp_servers {
        servers.insert(name.clone(), json!({"command": s.command, "args": s.args}));
    }
    json!({"mcpServers": servers}).to_string()
}

/// `--settings`: the hooks.
#[must_use]
pub fn hook_settings(ctx: &SpawnContext) -> String {
    let mut hooks = serde_json::Map::new();
    for (event, command) in &ctx.hooks {
        hooks.insert(
            event.clone(),
            json!([{"hooks": [{"type": "command", "command": command}]}]),
        );
    }
    json!({"hooks": hooks}).to_string()
}

impl ClaudeRuntime {
    #[must_use]
    pub fn new(command: &str, model: Option<&str>) -> ClaudeRuntime {
        ClaudeRuntime {
            command: command.to_owned(),
            model: model.map(str::to_owned),
        }
    }

    fn common(&self, ctx: &SpawnContext) -> Vec<String> {
        let mut argv = vec![
            "--append-system-prompt".to_owned(),
            ctx.system_prompt.clone(),
            "--mcp-config".to_owned(),
            mcp_config(ctx),
            "--permission-mode".to_owned(),
            "bypassPermissions".to_owned(),
        ];
        if let Some(model) = ctx.model.as_ref().or(self.model.as_ref()) {
            argv.push("--model".to_owned());
            argv.push(model.clone());
        }
        if !ctx.hooks.is_empty() {
            argv.push("--settings".to_owned());
            argv.push(hook_settings(ctx));
        }
        argv
    }

    /// The headless argv for `sid` (resumed or new).
    #[must_use]
    pub fn headless_argv(&self, ctx: &SpawnContext, sid: &str, resume: bool) -> Vec<String> {
        let mut argv = vec![
            self.command.clone(),
            "-p".to_owned(),
            "--input-format".to_owned(),
            "stream-json".to_owned(),
            "--output-format".to_owned(),
            "stream-json".to_owned(),
            "--verbose".to_owned(),
        ];
        argv.extend(self.common(ctx));
        argv.push(if resume { "--resume" } else { "--session-id" }.to_owned());
        argv.push(sid.to_owned());
        argv
    }

    pub async fn start<H: Host>(
        &self,
        host: &H,
        ctx: &mut SpawnContext,
    ) -> Result<ClaudeRun, HostError> {
        let (sid, resume) = match &ctx.runtime_session_id {
            Some(sid) => (sid.clone(), true),
            None => (uuid::Uuid::new_v4().to_string(), false),
        };
        let argv = self.headless_argv(ctx, &sid, resume);
        let piped = host
            .start_piped(
                &ctx.unit_spec(argv, format!("claude conversation {}", ctx.conversation_id)),
            )
            .await?;
        Ok(ClaudeRun::new(ctx.unit.clone(), piped, sid))
    }

    /// The TUI: `<cmd> <common…> [--resume <sid>]`.
    #[must_use]
    pub fn tui_argv(&self, ctx: &SpawnContext) -> Vec<String> {
        let mut argv = vec![self.command.clone()];
        argv.extend(self.common(ctx));
        if let Some(sid) = &ctx.runtime_session_id {
            argv.push("--resume".to_owned());
            argv.push(sid.clone());
        }
        argv
    }

    /// No tools, no MCP, no project or user settings, nothing saved: the
    /// prompt (on stdin) carries untrusted text and only its one-line
    /// answer is used (INV-20).
    #[must_use]
    pub fn triage_argv(&self, model: Option<&str>) -> Vec<String> {
        vec![
            self.command.clone(),
            "-p".to_owned(),
            "--model".to_owned(),
            model.unwrap_or("haiku").to_owned(),
            "--output-format".to_owned(),
            "json".to_owned(),
            "--tools".to_owned(),
            String::new(),
            "--strict-mcp-config".to_owned(),
            "--setting-sources".to_owned(),
            String::new(),
            "--no-session-persistence".to_owned(),
        ]
    }
}

/// The `.result` string of claude's JSON output (else empty).
#[must_use]
pub fn triage_answer(stdout: &str) -> String {
    serde_json::from_str::<Value>(stdout)
        .ok()
        .and_then(|v| v.get("result").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

/// One live `claude -p` process.
pub struct ClaudeRun {
    unit: String,
    stdin: tokio::sync::Mutex<std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>>,
    pending: Arc<AtomicU64>,
    session: Arc<Mutex<String>>,
    exit: ProcExit,
    events: Mutex<Option<mpsc::UnboundedReceiver<Event>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for ClaudeRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeRun")
            .field("unit", &self.unit)
            .field("pending", &self.pending.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl ClaudeRun {
    fn new(unit: String, piped: crate::host::Piped, sid: String) -> ClaudeRun {
        let (tx, rx) = mpsc::unbounded_channel();
        let pending = Arc::new(AtomicU64::new(0));
        let session = Arc::new(Mutex::new(sid));
        let reader = tokio::spawn(read(
            piped.stdout,
            piped.exit.clone(),
            tx,
            Arc::clone(&pending),
            Arc::clone(&session),
        ));
        ClaudeRun {
            unit,
            stdin: tokio::sync::Mutex::new(piped.stdin),
            pending,
            session,
            exit: piped.exit,
            events: Mutex::new(Some(rx)),
            reader: Mutex::new(Some(reader)),
        }
    }

    #[must_use]
    pub fn busy(&self) -> bool {
        self.pending.load(Ordering::SeqCst) > 0
    }

    #[must_use]
    pub fn session_id(&self) -> String {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }

    #[must_use]
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<Event>> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// One user turn.
    pub async fn send(&self, text: &str) -> Result<(), HostError> {
        let mut line = json!({"type": "user", "message": {"role": "user", "content": text}})
            .to_string()
            .into_bytes();
        line.push(b'\n');
        self.pending.fetch_add(1, Ordering::SeqCst);
        let mut stdin = self.stdin.lock().await;
        let written = async {
            stdin.write_all(&line).await?;
            stdin.flush().await
        }
        .await;
        if let Err(e) = written {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(HostError(format!("claude went away: {e}")));
        }
        Ok(())
    }

    /// Stop the unit; kill the process if it outlives [`STOP_WAIT`].
    pub async fn stop<H: Host>(&self, host: &H) {
        if !self.exit.exited() {
            host.stop_unit(&self.unit).await;
            if tokio::time::timeout(STOP_WAIT, self.exit.wait())
                .await
                .is_err()
            {
                self.exit.kill();
                let _ = tokio::time::timeout(STOP_WAIT, self.exit.wait()).await;
            }
        }
        let reader = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(r) = reader
            && tokio::time::timeout(STOP_WAIT, r).await.is_err()
        {
            tracing::warn!(unit = %self.unit, "claude's output did not end after it stopped");
        }
    }
}

async fn read(
    stdout: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    exit: ProcExit,
    tx: mpsc::UnboundedSender<Event>,
    pending: Arc<AtomicU64>,
    session: Arc<Mutex<String>>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let line = match agent_auth_daemon::localsock::read_line_capped(&mut reader, MAX_LINE).await
        {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("reading claude's output: {e}");
                break;
            }
        };
        let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        match msg.get("type").and_then(Value::as_str) {
            Some("system") => {
                if let Some(sid) = msg.get("session_id").and_then(Value::as_str)
                    && !sid.is_empty()
                {
                    *session.lock().unwrap_or_else(PoisonError::into_inner) = sid.to_owned();
                }
            }
            Some("assistant") => {
                let text: String = msg
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|c| c.get("type").and_then(Value::as_str) == Some("text"))
                            .filter_map(|c| c.get("text").and_then(Value::as_str))
                            .collect()
                    })
                    .unwrap_or_default();
                if !text.is_empty() {
                    let _ = tx.send(Event::Text(text));
                }
            }
            Some("result") => {
                let _ = pending.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.saturating_sub(1))
                });
                let result = msg
                    .get("result")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let is_error = msg
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let _ = tx.send(if is_error {
                    Event::Error(result)
                } else {
                    Event::TurnDone(result)
                });
            }
            _ => {}
        }
    }
    exit.wait().await;
    pending.store(0, Ordering::SeqCst);
    let _ = tx.send(Event::Exit);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::runtime::McpServer;
    use std::collections::BTreeMap;

    fn ctx() -> SpawnContext {
        let mut mcp = BTreeMap::new();
        mcp.insert(
            "agent-auth".to_owned(),
            McpServer {
                command: "agent-auth-mcp".into(),
                args: vec![],
                env_vars: vec!["AGENT_AUTH_API_KEY".into()],
            },
        );
        let mut env = BTreeMap::new();
        env.insert("AGENT_AUTH_API_KEY".to_owned(), "aa_secret".to_owned());
        let mut hooks = BTreeMap::new();
        hooks.insert(
            "PostToolUse".to_owned(),
            "agent-auth-sandbox-mcp hook".to_owned(),
        );
        SpawnContext {
            conversation_id: crate::names::ConvId::parse("0123456789ab").unwrap(),
            unit: "sbx-conv-0123456789ab".into(),
            uid: 40001,
            workdir: "/w".into(),
            home: "/h".into(),
            tmp: "/t".into(),
            env,
            system_prompt: "be good".into(),
            runtime_session_id: None,
            mcp_servers: mcp,
            read_write: vec![],
            model: None,
            hooks,
            model_gateway: None,
            tmp_tree: crate::host::Tree::new(std::path::Path::new("/"), &["t"]),
        }
    }

    #[test]
    fn argv_carries_no_secret_and_resumes() {
        let rt = ClaudeRuntime::new("claude", Some("opus"));
        let c = ctx();
        let argv = rt.headless_argv(&c, "sid-1", false);
        assert!(!argv.join(" ").contains("aa_secret"));
        assert_eq!(&argv[..2], ["claude", "-p"]);
        assert!(argv.windows(2).any(|w| w == ["--session-id", "sid-1"]));
        assert!(argv.windows(2).any(|w| w == ["--model", "opus"]));
        let mcp: Value = serde_json::from_str(&mcp_config(&c)).unwrap();
        assert_eq!(
            mcp,
            json!({"mcpServers": {"agent-auth": {"command": "agent-auth-mcp", "args": []}}})
        );
        let hooks: Value = serde_json::from_str(&hook_settings(&c)).unwrap();
        assert_eq!(
            hooks,
            json!({"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "agent-auth-sandbox-mcp hook"}]}]}})
        );
        let mut c2 = c.clone();
        c2.runtime_session_id = Some("sid-2".into());
        let tui = rt.tui_argv(&c2);
        assert_eq!(&tui[tui.len() - 2..], ["--resume", "sid-2"]);
        assert!(!tui.contains(&"-p".to_owned()));
    }

    #[test]
    fn triage() {
        let rt = ClaudeRuntime::new("claude", None);
        let argv = rt.triage_argv(None);
        assert!(argv.windows(2).any(|w| w == ["--tools", ""]));
        assert!(argv.windows(2).any(|w| w == ["--model", "haiku"]));
        assert!(argv.contains(&"--strict-mcp-config".to_owned()));
        assert!(argv.contains(&"--no-session-persistence".to_owned()));
        assert_eq!(triage_answer(r#"{"result": "abc"}"#), "abc");
        assert_eq!(triage_answer(r#"{"result": 3}"#), "");
        assert_eq!(triage_answer("garbage"), "");
    }
}
