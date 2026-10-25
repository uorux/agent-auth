//! Codex headless: `codex app-server` on a unix socket, driven as a
//! JSON-RPC client over WebSocket (sandboxd spec §4.8). Several clients
//! can share one server, which is how an operator's TUI (`codex --remote
//! unix://… resume <thread>`) joins a live conversation; `turn/steer`
//! adds input to a running turn.
//!
//! The socket is under the unit's `/tmp` (the project's tmp directory
//! here) and is reached without following anything the project controls
//! (B-13, [`crate::fsops::codex_socket`]).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::SinkExt as _;
use futures::stream::{SplitSink, StreamExt as _};
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::{Event, GATEWAY_KEY_ENV, SpawnContext};
use crate::host::{Host, HostError};

/// How long the app-server gets to open its socket.
pub const SOCKET_WAIT: Duration = Duration::from_secs(30);
/// Each JSON-RPC call's timeout.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct CodexRuntime {
    pub command: String,
    pub model: Option<String>,
}

/// A JSON string is a valid TOML basic string.
fn toml_str(s: &str) -> String {
    Value::String(s.to_owned()).to_string()
}

/// A model provider for the gateway (OpenAI Responses API at `/v1`,
/// authenticated with the agent's key).
#[must_use]
pub fn gateway_argv(url: Option<&str>) -> Vec<String> {
    let Some(url) = url else {
        return Vec::new();
    };
    let prefix = "model_providers.agentauth";
    let base = format!("{}/v1", url.trim_end_matches('/'));
    [
        "model_provider=\"agentauth\"".to_owned(),
        format!("{prefix}.name=\"model gateway\""),
        format!("{prefix}.base_url={}", toml_str(&base)),
        format!("{prefix}.env_key=\"{GATEWAY_KEY_ENV}\""),
        format!("{prefix}.wire_api=\"responses\""),
    ]
    .into_iter()
    .flat_map(|c| ["-c".to_owned(), c])
    .collect()
}

/// The last non-empty line.
#[must_use]
pub fn triage_answer(stdout: &str) -> String {
    stdout
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .to_owned()
}

impl CodexRuntime {
    #[must_use]
    pub fn new(command: &str, model: Option<&str>) -> CodexRuntime {
        CodexRuntime {
            command: command.to_owned(),
            model: model.map(str::to_owned),
        }
    }

    #[must_use]
    pub fn socket_name(ctx: &SpawnContext) -> String {
        format!("codex-{}.sock", ctx.conversation_id)
    }

    /// `codex [gateway] app-server --listen unix:///tmp/<sock>` plus each
    /// MCP server as `-c` settings (codex hands MCP servers a scrubbed
    /// environment: `env_vars` names what passes).
    #[must_use]
    pub fn server_argv(&self, ctx: &SpawnContext) -> Vec<String> {
        let mut argv = vec![self.command.clone()];
        argv.extend(gateway_argv(ctx.model_gateway.as_deref()));
        argv.push("app-server".to_owned());
        argv.push("--listen".to_owned());
        argv.push(format!("unix:///tmp/{}", Self::socket_name(ctx)));
        for (name, server) in &ctx.mcp_servers {
            let prefix = format!("mcp_servers.{name}");
            argv.push("-c".to_owned());
            argv.push(format!("{prefix}.command={}", toml_str(&server.command)));
            if !server.args.is_empty() {
                argv.push("-c".to_owned());
                argv.push(format!("{prefix}.args={}", json!(server.args)));
            }
            if !server.env_vars.is_empty() {
                argv.push("-c".to_owned());
                argv.push(format!("{prefix}.env_vars={}", json!(server.env_vars)));
            }
        }
        argv
    }

    pub async fn start<H: Host>(
        &self,
        host: &H,
        ctx: &mut SpawnContext,
    ) -> Result<CodexRun, HostError> {
        let sock = Self::socket_name(ctx);
        if let Ok(tmp) = ctx.tmp_tree.open() {
            let _ = tmp.remove(&sock);
        }
        let argv = self.server_argv(ctx);
        host.start_detached(
            &ctx.unit_spec(argv, format!("codex conversation {}", ctx.conversation_id)),
        )
        .await?;
        if ctx.model.is_none() {
            ctx.model.clone_from(&self.model);
        }
        match CodexRun::connect(ctx, &sock).await {
            Ok(run) => Ok(run),
            Err(e) => {
                host.stop_unit(&ctx.unit).await;
                Err(e)
            }
        }
    }

    /// The TUI: a second client of the live server.
    #[must_use]
    pub fn tui_argv(&self, ctx: &SpawnContext) -> Vec<String> {
        let mut argv = vec![self.command.clone()];
        argv.extend(gateway_argv(ctx.model_gateway.as_deref()));
        argv.push("--remote".to_owned());
        argv.push(format!("unix:///tmp/{}", Self::socket_name(ctx)));
        argv.push("resume".to_owned());
        if let Some(t) = &ctx.runtime_session_id {
            argv.push(t.clone());
        }
        argv
    }

    /// `codex exec … -` (the prompt on stdin, the answer on stdout). NOT
    /// tool-less (B-16; an open question).
    #[must_use]
    pub fn triage_argv(&self, model: Option<&str>) -> Vec<String> {
        let mut argv = vec![
            self.command.clone(),
            "exec".to_owned(),
            "--skip-git-repo-check".to_owned(),
            "--ephemeral".to_owned(),
            "-s".to_owned(),
            "read-only".to_owned(),
        ];
        if let Some(m) = model.or(self.model.as_deref()) {
            argv.push("-m".to_owned());
            argv.push(m.to_owned());
        }
        argv.push("-".to_owned());
        argv
    }
}

type Sink = SplitSink<WebSocketStream<UnixStream>, Message>;

struct Inner {
    unit: String,
    sink: tokio::sync::Mutex<Sink>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    thread: Mutex<Option<String>>,
    /// The running turn and the inputs waiting for the next one, under one
    /// lock: a steer that failed because the turn just ended must not
    /// queue behind a turn that will never come.
    turns: Mutex<Turns>,
    events: mpsc::UnboundedSender<Event>,
}

#[derive(Debug, Default)]
struct Turns {
    current: Option<String>,
    queued: VecDeque<String>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inner {
    async fn call(&self, method: &str, params: Value) -> Result<Value, HostError> {
        let id = self
            .next_id
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        let (tx, rx) = oneshot::channel();
        locked(&self.pending).insert(id, tx);
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let sent = self
            .sink
            .lock()
            .await
            .send(Message::text(msg.to_string()))
            .await;
        if let Err(e) = sent {
            locked(&self.pending).remove(&id);
            return Err(HostError(format!("codex {method}: {e}")));
        }
        let reply = match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => {
                return Err(HostError("codex app-server went away".to_owned()));
            }
            Err(_) => {
                locked(&self.pending).remove(&id);
                return Err(HostError(format!("codex {method}: no answer in time")));
            }
        };
        if let Some(err) = reply.get("error") {
            let text = err
                .get("message")
                .and_then(Value::as_str)
                .map_or_else(|| err.to_string(), str::to_owned);
            return Err(HostError(format!("codex {method}: {text}")));
        }
        Ok(reply.get("result").cloned().unwrap_or_else(|| json!({})))
    }

    fn thread_id(&self) -> Option<String> {
        locked(&self.thread).clone()
    }

    async fn start_turn(&self, text: &str) -> Result<(), HostError> {
        let result = self
            .call(
                "turn/start",
                json!({"threadId": self.thread_id(), "input": [{"type": "text", "text": text}]}),
            )
            .await?;
        if let Some(id) = result
            .get("turn")
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str)
        {
            locked(&self.turns).current = Some(id.to_owned());
        }
        Ok(())
    }
}

/// One live app-server connection.
pub struct CodexRun {
    inner: Arc<Inner>,
    events: Mutex<Option<mpsc::UnboundedReceiver<Event>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for CodexRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexRun")
            .field("unit", &self.inner.unit)
            .finish_non_exhaustive()
    }
}

impl CodexRun {
    /// Wait for the socket, connect, initialize, and start or resume the
    /// conversation's thread.
    pub async fn connect(ctx: &SpawnContext, sock: &str) -> Result<CodexRun, HostError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(SOCKET_WAIT)
            .unwrap_or_else(tokio::time::Instant::now);
        let entry = loop {
            let found = ctx
                .tmp_tree
                .open()
                .and_then(|tmp| crate::fsops::codex_socket(&tmp, sock));
            if let Ok(Some(e)) = found {
                break e;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(HostError(format!(
                    "codex app-server did not open its socket within {} s (in the VM: journalctl -u {})",
                    SOCKET_WAIT.as_secs(),
                    ctx.unit
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let stream = UnixStream::connect(entry.magic_path()).await?;
        let (ws, _) = tokio_tungstenite::client_async("ws://localhost/", stream)
            .await
            .map_err(|e| HostError(format!("codex app-server: {e}")))?;
        let run = CodexRun::over(ws, ctx.unit.clone(), ctx.runtime_session_id.clone());
        run.open_thread(ctx).await?;
        Ok(run)
    }

    /// A run over a connected WebSocket (tests use a fake app-server).
    #[must_use]
    pub fn over(ws: WebSocketStream<UnixStream>, unit: String, thread: Option<String>) -> CodexRun {
        let (sink, stream) = ws.split();
        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            unit,
            sink: tokio::sync::Mutex::new(sink),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            thread: Mutex::new(thread),
            turns: Mutex::new(Turns::default()),
            events: tx,
        });
        let reader = tokio::spawn(read(Arc::clone(&inner), stream));
        CodexRun {
            inner,
            events: Mutex::new(Some(rx)),
            reader: Mutex::new(Some(reader)),
        }
    }

    async fn open_thread(&self, ctx: &SpawnContext) -> Result<(), HostError> {
        let inner = &self.inner;
        inner
            .call(
                "initialize",
                json!({"clientInfo": {"name": "sandboxd", "version": "1"}}),
            )
            .await?;
        let mut base = json!({
            "cwd": ctx.workdir.display().to_string(),
            "approvalPolicy": "never",
            "sandbox": "danger-full-access",
            "developerInstructions": ctx.system_prompt,
        });
        if let (Some(model), Value::Object(m)) = (&ctx.model, &mut base) {
            m.insert("model".into(), json!(model));
        }
        let existing = inner.thread_id();
        let result = match &existing {
            Some(id) => {
                if let Value::Object(m) = &mut base {
                    m.insert("threadId".into(), json!(id));
                }
                inner.call("thread/resume", base).await?
            }
            None => inner.call("thread/start", base).await?,
        };
        let id = result
            .get("thread")
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| HostError("codex: no thread id in the answer".to_owned()))?
            .to_owned();
        *locked(&inner.thread) = Some(id.clone());
        if existing.is_none() {
            // A thread has no rollout until its first turn, and without one
            // no second client (the operator's TUI) can resume it. Naming it
            // writes the rollout.
            if let Err(e) = inner
                .call(
                    "thread/name/set",
                    json!({"threadId": id, "name": format!("conversation {}", ctx.conversation_id)}),
                )
                .await
            {
                tracing::warn!(
                    "codex: could not name the new thread (the TUI may not attach before a turn): {e}"
                );
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn busy(&self) -> bool {
        let t = locked(&self.inner.turns);
        t.current.is_some() || !t.queued.is_empty()
    }

    #[must_use]
    pub fn thread_id(&self) -> Option<String> {
        self.inner.thread_id()
    }

    #[must_use]
    pub fn unit(&self) -> &str {
        &self.inner.unit
    }

    #[must_use]
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<Event>> {
        locked(&self.events).take()
    }

    /// A new turn, or (mid-turn) steering the running one; a failed steer
    /// waits for the next turn.
    pub async fn send(&self, text: &str) -> Result<(), HostError> {
        let turn = locked(&self.inner.turns).current.clone();
        let Some(turn) = turn else {
            return self.inner.start_turn(text).await;
        };
        let steered = self
            .inner
            .call(
                "turn/steer",
                json!({"threadId": self.inner.thread_id(), "expectedTurnId": turn,
                       "input": [{"type": "text", "text": text}]}),
            )
            .await;
        if steered.is_ok() {
            return Ok(());
        }
        // The turn ended meanwhile: the next one. If none is running now,
        // that is this one (the end already went by).
        let start_now = {
            let mut t = locked(&self.inner.turns);
            if t.current.is_some() {
                t.queued.push_back(text.to_owned());
                false
            } else {
                true
            }
        };
        if start_now {
            self.inner.start_turn(text).await
        } else {
            Ok(())
        }
    }

    pub async fn stop<H: Host>(&self, host: &H) {
        let _ = self.inner.sink.lock().await.close().await;
        host.stop_unit(&self.inner.unit).await;
        let reader = locked(&self.reader).take();
        if let Some(r) = reader
            && tokio::time::timeout(Duration::from_secs(15), r)
                .await
                .is_err()
        {
            tracing::warn!(unit = %self.inner.unit, "codex connection did not end after it stopped");
        }
    }
}

async fn read(
    inner: Arc<Inner>,
    mut stream: futures::stream::SplitStream<WebSocketStream<UnixStream>>,
) {
    while let Some(frame) = stream.next().await {
        let text = match frame {
            Ok(Message::Text(t)) => t.as_str().to_owned(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        let Ok(msg) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if let Some(id) = msg.get("id").and_then(Value::as_u64)
            && (msg.get("result").is_some() || msg.get("error").is_some())
        {
            if let Some(tx) = locked(&inner.pending).remove(&id) {
                let _ = tx.send(msg);
            }
            continue;
        }
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
        match params.get("threadId") {
            None | Some(Value::Null) => {}
            Some(t) => {
                if t.as_str().map(str::to_owned) != inner.thread_id() {
                    continue;
                }
            }
        }
        match method {
            "turn/started" => {
                if let Some(id) = params
                    .get("turn")
                    .and_then(|t| t.get("id"))
                    .and_then(Value::as_str)
                {
                    locked(&inner.turns).current = Some(id.to_owned());
                }
            }
            "item/completed" => {
                let item = params.get("item").cloned().unwrap_or_else(|| json!({}));
                if item.get("type").and_then(Value::as_str) == Some("agentMessage")
                    && let Some(t) = item.get("text").and_then(Value::as_str)
                    && !t.is_empty()
                {
                    let _ = inner.events.send(Event::Text(t.to_owned()));
                }
            }
            "turn/completed" => {
                let next = {
                    let mut t = locked(&inner.turns);
                    t.current = None;
                    t.queued.pop_front()
                };
                let error = params
                    .get("turn")
                    .and_then(|t| t.get("error"))
                    .filter(|e| !e.is_null())
                    .cloned();
                let _ = inner.events.send(match error {
                    Some(e) => Event::Error(e.to_string()),
                    None => Event::TurnDone(String::new()),
                });
                // The next queued input starts the next turn. Not here: this
                // task reads the answers that call waits for (the Python
                // awaited it here and stalled for the call's timeout).
                if let Some(text) = next {
                    let inner = Arc::clone(&inner);
                    tokio::spawn(async move {
                        if let Err(e) = inner.start_turn(&text).await {
                            tracing::warn!("codex: the next turn did not start: {e}");
                            let _ = inner.events.send(Event::Error(e.to_string()));
                        }
                    });
                }
            }
            "error"
                if !params
                    .get("willRetry")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) =>
            {
                let e = params.get("error").cloned().unwrap_or(Value::Null);
                let _ = inner.events.send(Event::Error(e.to_string()));
            }
            _ => {}
        }
    }
    locked(&inner.pending).clear();
    let _ = inner.events.send(Event::Exit);
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::runtime::McpServer;
    use std::collections::BTreeMap;
    use tokio::net::UnixListener;

    fn ctx(dir: &std::path::Path) -> SpawnContext {
        let mut mcp = BTreeMap::new();
        mcp.insert(
            "sandbox".to_owned(),
            McpServer {
                command: "agent-auth-sandbox-mcp".into(),
                args: vec![],
                env_vars: vec!["AGENT_AUTH_SANDBOX_SOCKET".into()],
            },
        );
        mcp.insert(
            "gitea".to_owned(),
            McpServer {
                command: "agent-auth-mcp-bridge".into(),
                args: vec!["gitea".into()],
                env_vars: vec![],
            },
        );
        SpawnContext {
            conversation_id: crate::names::ConvId::parse("0123456789ab").unwrap(),
            unit: "sbx-conv-0123456789ab".into(),
            uid: 40001,
            workdir: "/w".into(),
            home: "/h".into(),
            tmp: dir.to_owned(),
            env: BTreeMap::new(),
            system_prompt: "be good".into(),
            runtime_session_id: None,
            mcp_servers: mcp,
            read_write: vec![],
            model: None,
            hooks: BTreeMap::new(),
            model_gateway: Some("https://gw.example/".into()),
            tmp_tree: crate::host::Tree::new(dir, &[]),
        }
    }

    #[test]
    fn argv() {
        let d = crate::testdir::TestDir::new("codex-argv");
        let rt = CodexRuntime::new("codex", Some("gpt"));
        let c = ctx(d.path());
        let argv = rt.server_argv(&c);
        assert_eq!(argv[0], "codex");
        assert!(
            argv.contains(
                &"model_providers.agentauth.base_url=\"https://gw.example/v1\"".to_owned()
            )
        );
        assert!(argv.windows(3).any(|w| w
            == [
                "app-server",
                "--listen",
                "unix:///tmp/codex-0123456789ab.sock"
            ]));
        assert!(argv.contains(&"mcp_servers.gitea.args=[\"gitea\"]".to_owned()));
        assert!(
            argv.contains(
                &"mcp_servers.sandbox.env_vars=[\"AGENT_AUTH_SANDBOX_SOCKET\"]".to_owned()
            )
        );
        assert!(
            !argv
                .iter()
                .any(|a| a.starts_with("mcp_servers.gitea.env_vars"))
        );
        let tui = rt.tui_argv(&c);
        assert_eq!(
            &tui[tui.len() - 3..],
            ["--remote", "unix:///tmp/codex-0123456789ab.sock", "resume"]
        );
        let t = rt.triage_argv(None);
        assert_eq!(&t[t.len() - 3..], ["-m", "gpt", "-"]);
        assert_eq!(triage_answer("progress\n\n  abc  \n\n"), "abc");
        assert!(gateway_argv(None).is_empty());
    }

    /// A fake app-server: answers the handshake, starts turns, refuses a
    /// steer, and completes turns when told.
    async fn fake_server(listener: UnixListener, done: mpsc::UnboundedSender<String>) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let mut turns = 0;
        while let Some(Ok(Message::Text(t))) = ws.next().await {
            let msg: Value = serde_json::from_str(t.as_str()).unwrap();
            let id = msg["id"].clone();
            let method = msg["method"].as_str().unwrap().to_owned();
            let _ = done.send(method.clone());
            let reply = match method.as_str() {
                "initialize" => json!({"id": id, "result": {}}),
                "thread/start" => json!({"id": id, "result": {"thread": {"id": "th-1"}}}),
                "thread/name/set" => json!({"id": id, "error": {"message": "no names here"}}),
                "turn/start" => {
                    turns += 1;
                    let turn = format!("turn-{turns}");
                    ws.send(Message::text(
                        json!({"id": id, "result": {"turn": {"id": turn}}}).to_string(),
                    ))
                    .await
                    .unwrap();
                    ws.send(Message::text(json!({"method": "item/completed", "params": {"threadId": "th-1",
                        "item": {"type": "agentMessage", "text": format!("said {}", msg["params"]["input"][0]["text"].as_str().unwrap())}}}).to_string()))
                        .await
                        .unwrap();
                    // Another thread's events are not ours.
                    ws.send(Message::text(
                        json!({"method": "item/completed", "params": {"threadId": "th-2",
                        "item": {"type": "agentMessage", "text": "not mine"}}})
                        .to_string(),
                    ))
                    .await
                    .unwrap();
                    continue;
                }
                "turn/steer" => json!({"id": id, "error": {"message": "turn ended"}}),
                "complete" => continue,
                _ => json!({"id": id, "result": {}}),
            };
            ws.send(Message::text(reply.to_string())).await.unwrap();
            if method == "turn/steer" {
                ws.send(Message::text(json!({"method": "turn/completed", "params": {"threadId": "th-1", "turn": {"id": "turn-1"}}}).to_string()))
                    .await
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn drives_turns_steers_and_queues() {
        let d = crate::testdir::TestDir::new("codex-run");
        let path = d.path().join("codex-0123456789ab.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, mut seen) = mpsc::unbounded_channel();
        tokio::spawn(fake_server(listener, tx));
        let c = ctx(d.path());
        let run = CodexRun::connect(&c, "codex-0123456789ab.sock")
            .await
            .unwrap();
        assert_eq!(run.thread_id().as_deref(), Some("th-1"));
        let mut events = run.take_events().unwrap();
        run.send("one").await.unwrap();
        assert!(run.busy());
        assert_eq!(events.recv().await.unwrap(), Event::Text("said one".into()));
        // Mid-turn: the steer is refused, so it waits for the next turn,
        // which the completion of this one starts.
        run.send("two").await.unwrap();
        assert_eq!(events.recv().await.unwrap(), Event::TurnDone(String::new()));
        assert_eq!(events.recv().await.unwrap(), Event::Text("said two".into()));
        let mut methods = Vec::new();
        while let Ok(m) = seen.try_recv() {
            methods.push(m);
        }
        assert_eq!(
            methods,
            [
                "initialize",
                "thread/start",
                "thread/name/set",
                "turn/start",
                "turn/steer",
                "turn/start"
            ]
        );
    }
}
