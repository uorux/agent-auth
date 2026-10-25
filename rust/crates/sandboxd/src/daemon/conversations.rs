//! Conversations: their processes, delivery, parking, closing, the
//! interactive TUI, and what the orchestrator asks for (sandboxd spec
//! §4.7, §4.9, §4.13).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use agent_auth_core::pyfmt::{repr, shlex_join, shlex_quote};
use serde_json::{Value, json};

use super::{Live, Sandboxd, SbxError, SbxResult, locked};
use crate::host::Host;
use crate::names::{ConvId, ORCHESTRATOR_USER, mcp_name_ok};
use crate::runtime::{Event, McpServer, RunRef, SpawnContext};
use crate::store::{AgentRecord, ConvState, Conversation};

pub const SYSTEM_PROMPT: &str = r#"You are {agent}, an agent running headless in the agent VM on {host}.
{where}
You have no human at this terminal. Requests reach you as a2a messages from
other agents (or from the operator); they appear as user turns starting with
"[a2a]". Answer an a2a request with the agent-auth MCP tool a2a_send on that
thread — your final message is {"type": "result", "status":
"done"|"failed"|"declined", "summary": "..."} — then a2a_close. Plain text
you write here is only logged. A message that arrives while you are working
may be shown to you after a tool call instead, as added context starting with
"[a2a]": treat it exactly like such a turn.
Access you don't have (GitHub, homelab services, Kubernetes, other agents)
goes through the agent-auth MCP tools: list_capabilities, request_access,
wait_for_decision, get_credential. Never ask anyone for credentials.
The sandbox MCP tools describe this VM (sandbox_whoami, project_list,
conversations).{extra}"#;

pub const ORCHESTRATOR_EXTRA: &str = r#"
You are the orchestrator: you set projects up and start their agents.
- project_create(name) makes a project (a directory and its own user) and
  gives you write access until project_seal(name). Clone or prepare it there
  (request a github "repo" grant first, or "create" a new uorux repo).
- agent_mint(runtime, project) asks the broker for <runtime>-<project>-{host}-sandbox;
  agent_spawn(agent, prompt) starts a conversation of it with a first message.
- Seal a project before its agents start (spawning one seals it for you).
- To hand a requester its new agent, reply with the agent's name: the
  requester opens its own thread to it (there is no handoff of threads)."#;

/// Printed by the TUI's wrapper when it fails or ends within seconds.
pub const TUI_FAILED: &str = "[the TUI exited with status";
/// A TUI gets this long to show it started.
pub const TUI_SETTLE: Duration = Duration::from_millis(1500);
/// How long a delivery waits for a process slot before it is queued for
/// later.
pub const SLOT_WAIT: Duration = Duration::from_secs(120);
/// How long `attach` waits for a busy claude turn (without `now`).
pub const ATTACH_WAIT: Duration = Duration::from_secs(600);
/// The longest backoff between retries of a queued delivery.
pub const MAX_RETRY: Duration = Duration::from_secs(900);

/// What a turn's end did with the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flush {
    Sent,
    Nothing,
    /// The agent is held: nothing sent, and the process is not parked
    /// (frozen processes are kept to look at).
    Held,
}

impl<H: Host> Sandboxd<H> {
    /// A conversation's process context (`tui`: also the prompt hook).
    pub(crate) fn context(
        &self,
        conv: &Conversation,
        lv: &Live,
        tui: bool,
    ) -> SbxResult<SpawnContext> {
        let rec = self.agent_record(&conv.agent)?;
        let project = self.project_of(&rec);
        let (workdir, home, tmp) = self.paths(project.as_deref());
        let (_, _, tmp_tree) = self.trees(project.as_deref());
        let uid = self.project_uid(project.as_deref())?;
        let c = &self.config;
        let user = project
            .as_deref()
            .map_or_else(|| ORCHESTRATOR_USER.to_owned(), |p| format!("p-{p}"));
        let mut env = BTreeMap::new();
        let mut set = |k: &str, v: String| {
            env.insert(k.to_owned(), v);
        };
        set("HOME", home.display().to_string());
        set("USER", user.clone());
        set("LOGNAME", user);
        set("PATH", c.agent_path.clone());
        set("LANG", "C.UTF-8".to_owned());
        set("TERM", "xterm-256color".to_owned());
        set("AGENT_AUTH_URL", c.broker_url.as_str().to_owned());
        set("AGENT_AUTH_API_KEY", rec.api_key.expose().clone());
        set(
            "AGENT_AUTH_SESSION",
            conv.broker_session_id.clone().unwrap_or_default(),
        );
        set(
            "AGENT_AUTH_SANDBOX_SOCKET",
            c.agent_socket.display().to_string(),
        );
        set("AGENT_AUTH_SANDBOX_TOKEN", lv.token.expose().clone());
        set("CODEX_HOME", home.join(".codex").display().to_string());
        if let Some(token) = self.oauth_token() {
            set("CLAUDE_CODE_OAUTH_TOKEN", token);
        }
        let place = match &project {
            Some(p) => format!(
                "Your project is {p}, at {} (your working directory).",
                workdir.display()
            ),
            None => format!(
                "Your workspace is {}; projects are under {}.",
                workdir.display(),
                c.sandbox_root.join("projects").display()
            ),
        };
        let extra = if project.is_none() {
            ORCHESTRATOR_EXTRA.replace("{host}", c.name.as_str())
        } else {
            String::new()
        };
        let system_prompt = SYSTEM_PROMPT
            .replace("{agent}", &rec.name)
            .replace("{host}", c.name.as_str())
            .replace("{where}", &place)
            .replace("{extra}", &extra);
        let agent_env = vec![
            "AGENT_AUTH_URL".to_owned(),
            "AGENT_AUTH_API_KEY".to_owned(),
            "AGENT_AUTH_SESSION".to_owned(),
        ];
        let mut mcp_servers = BTreeMap::new();
        mcp_servers.insert(
            "agent-auth".to_owned(),
            McpServer {
                command: c.agent_auth_mcp.clone(),
                args: Vec::new(),
                env_vars: agent_env,
            },
        );
        mcp_servers.insert(
            "sandbox".to_owned(),
            McpServer {
                command: c.sandbox_mcp.clone(),
                args: Vec::new(),
                env_vars: vec![
                    "AGENT_AUTH_SANDBOX_SOCKET".to_owned(),
                    "AGENT_AUTH_SANDBOX_TOKEN".to_owned(),
                ],
            },
        );
        let mut hooks = BTreeMap::new();
        hooks.insert("PostToolUse".to_owned(), format!("{} hook", c.sandbox_mcp));
        if tui {
            hooks.insert(
                "UserPromptSubmit".to_owned(),
                format!("{} hook", c.sandbox_mcp),
            );
        }
        Ok(SpawnContext {
            conversation_id: conv.id.clone(),
            unit: conv.id.unit(),
            uid,
            workdir,
            home,
            tmp,
            env,
            system_prompt,
            runtime_session_id: conv.runtime_session_id.clone(),
            mcp_servers,
            read_write: Vec::new(),
            model: c.runtimes.get(&conv.runtime).and_then(|r| r.model.clone()),
            hooks,
            model_gateway: None,
            tmp_tree,
        })
    }

    /// `secrets/claude-oauth-token`, stripped, if it is there.
    pub(crate) fn oauth_token(&self) -> Option<String> {
        let dir = crate::fsops::Dir::open_trusted(&self.config.secrets_dir()).ok()?;
        let (bytes, _) = dir.read_file("claude-oauth-token", 64 * 1024).ok()??;
        let text = String::from_utf8(bytes).ok()?;
        let t = text.trim();
        (!t.is_empty()).then(|| t.to_owned())
    }

    pub(crate) fn agent_record(&self, agent: &str) -> SbxResult<AgentRecord> {
        self.store
            .agent(agent)
            .ok_or_else(|| SbxError::Lookup(format!("no key for agent {} in this VM", repr(agent))))
    }

    /// The catalogued MCP servers this agent holds a grant for, as local
    /// stdio servers (read when a process starts).
    async fn add_mcp_servers(&self, ctx: &mut SpawnContext, rec: &AgentRecord) {
        let grants = match self.client(rec, None).grants("active").await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("mcp servers for {}: {e}", rec.name);
                return;
            }
        };
        let mut names: Vec<String> = grants
            .into_iter()
            .filter(|g| g.platform == agent_auth_core::Platform::Mcp)
            .map(|g| g.resource)
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            if !ctx.mcp_servers.contains_key(&name) && mcp_name_ok(&name) {
                ctx.mcp_servers.insert(
                    name.clone(),
                    McpServer {
                        command: self.config.mcp_bridge.clone(),
                        args: vec![name],
                        env_vars: vec![
                            "AGENT_AUTH_URL".to_owned(),
                            "AGENT_AUTH_API_KEY".to_owned(),
                            "AGENT_AUTH_SESSION".to_owned(),
                        ],
                    },
                );
            }
        }
    }

    // ------------------------------------------------------ conversations

    /// A new conversation of `agent` (parked) with its own broker session.
    pub async fn new_conversation(
        &self,
        agent: &str,
        created_by: &str,
        title: &str,
        mode: &str,
    ) -> SbxResult<Conversation> {
        let rec = self.agent_record(agent)?;
        let runtime = self.runtime_of(&rec)?;
        let conv = self
            .store
            .new_conversation(agent, &runtime, mode, title, created_by)?;
        let out = self
            .client(&rec, None)
            .create_session(&format!("conv-{}", conv.id))
            .await?;
        let sid = out.session_id.to_string();
        self.store
            .update_conversation(&conv.id, |c| c.broker_session_id = Some(sid))?;
        let conv = self
            .store
            .conversation(&conv.id)
            .ok_or_else(|| SbxError::Internal("the new conversation is gone".to_owned()))?;
        self.live(&conv.id);
        self.watch(&conv.id);
        Ok(conv)
    }

    /// The conversation's broker session; a new one if the broker ended
    /// the last (B-9: a sessionless conversation claimed threads without a
    /// session and never heard from them again).
    pub(crate) async fn ensure_session(&self, conv: &Conversation) -> SbxResult<String> {
        if let Some(sid) = &conv.broker_session_id {
            return Ok(sid.clone());
        }
        let rec = self.agent_record(&conv.agent)?;
        let out = self
            .client(&rec, None)
            .create_session(&format!("conv-{}", conv.id))
            .await?;
        let sid = out.session_id.to_string();
        let set = sid.clone();
        self.store
            .update_conversation(&conv.id, |c| c.broker_session_id = Some(set))?;
        tracing::info!("conversation {} has a new broker session", conv.id);
        self.watch(&conv.id);
        Ok(sid)
    }

    /// Start the conversation's process if it has none. The caller holds
    /// the conversation's lock.
    async fn ensure_running(&self, conv: &Conversation, lv: &Live) -> SbxResult<RunRef> {
        if let Some(run) = lv.run() {
            return Ok(run);
        }
        let rec = self.agent_record(&conv.agent)?;
        let project = self.project_of(&rec);
        if let Some(p) = &project
            && !self.store.project(p).is_some_and(|r| r.sealed)
        {
            self.seal_project(p).await?;
        }
        let sid = self.ensure_session(conv).await?;
        let mut conv = conv.clone();
        conv.broker_session_id = Some(sid);
        let slot = self
            .slots
            .acquire(project.as_deref().unwrap_or("_orchestrator"), SLOT_WAIT)
            .await
            .map_err(SbxError::Runtime)?;
        let mut ctx = self.context(&conv, lv, false)?;
        self.add_mcp_servers(&mut ctx, &rec).await;
        let gateway = self
            .use_gateway(&mut ctx, &rec)
            .await
            .map_err(|e| SbxError::Runtime(e.0))?;
        if !gateway && conv.runtime == "codex" {
            self.codex_sync_into(project.as_deref(), ctx.uid).await;
        }
        let runtime = self.runtime(&conv.runtime).ok_or_else(|| {
            SbxError::Runtime(format!("no runtime configured for {}", conv.agent))
        })?;
        let run: RunRef = Arc::new(runtime.start(&self.host, &mut ctx).await?);
        let events = run.take_events();
        *locked(&lv.run) = Some((Arc::clone(&run), slot));
        *locked(&lv.ctx) = Some(ctx);
        let sid_now = run.runtime_session_id();
        self.store.update_conversation(&conv.id, |c| {
            if sid_now.is_some() && sid_now != c.runtime_session_id {
                c.runtime_session_id = sid_now;
            }
            c.state = ConvState::Running;
        })?;
        if let (Some(events), Some(me)) = (events, self.me()) {
            let id = conv.id.clone();
            let r = Arc::clone(&run);
            self.spawn(async move { me.pump(id, r, events).await });
        }
        Ok(run)
    }

    /// Hand `text` to the conversation: a turn now, or queued while it is
    /// held, attached to a claude TUI, or busy with a doorbell.
    pub async fn deliver(&self, conv_id: &ConvId, text: &str) -> SbxResult<()> {
        let Some(conv) = self.store.conversation(conv_id) else {
            return Ok(());
        };
        if conv.state == ConvState::Closed {
            return Ok(());
        }
        let lv = self.live(conv_id);
        self.log(conv_id, "in", text);
        self.store.touch(conv_id)?;
        if self.held(&conv.agent) {
            self.store.queue(conv_id, text)?;
            return Ok(());
        }
        let Some(runtime) = self.runtime(&conv.runtime) else {
            self.store.queue(conv_id, text)?;
            return Err(SbxError::Runtime(format!(
                "no runtime configured for {} ({})",
                conv.agent, conv.runtime
            )));
        };
        if lv.tui() && !runtime.shares_live_process() {
            // Claude's TUI holds the session: its prompt hook (or the next
            // headless start) picks these up.
            self.store.queue(conv_id, text)?;
            return Ok(());
        }
        let _op = lv.op.lock().await;
        if let Some(run) = lv.run()
            && run.busy()
            && runtime.doorbell()
        {
            // Mid-turn: the hook collects it after the next tool call; what
            // is still queued at the turn's end becomes the next turn.
            self.store.queue(conv_id, text)?;
            return Ok(());
        }
        lv.cancel_park();
        let mut pending = self.store.drain(conv_id)?;
        pending.push(text.to_owned());
        let run = match self.ensure_running(&conv, &lv).await {
            Ok(r) => r,
            Err(e) => {
                // Not started (no model key, the broker away, no slot, a
                // runtime that failed): it waits, and is tried again later.
                self.store.queue_all(conv_id, &pending)?;
                self.schedule_retry(&lv);
                return Err(e);
            }
        };
        if self.held(&conv.agent) {
            // Held while it was starting: the hold saw no process to
            // freeze. Freeze it here, and send it nothing.
            self.host.freeze_unit(&conv_id.unit(), true).await;
            self.store.queue_all(conv_id, &pending)?;
            return Ok(());
        }
        for (i, item) in pending.iter().enumerate() {
            if let Err(e) = run.send(item).await {
                let rest = pending.get(i..).unwrap_or_default();
                self.store.queue_all(conv_id, rest)?;
                self.schedule_retry(&lv);
                return Err(e.into());
            }
        }
        *locked(&lv.retry) = super::Retry::default();
        Ok(())
    }

    /// What queued up, delivered as one text (after a hold is lifted, a
    /// TUI ended, or a retry is due).
    pub(crate) async fn deliver_queued(&self, conv_id: &ConvId) {
        let Some(conv) = self.store.conversation(conv_id) else {
            return;
        };
        if conv.state == ConvState::Closed || self.held(&conv.agent) {
            return;
        }
        let lv = self.live(conv_id);
        let claude_tui = lv.tui()
            && self
                .runtime(&conv.runtime)
                .is_some_and(|r| !r.shares_live_process());
        if claude_tui {
            return;
        }
        let queued = match self.store.drain(conv_id) {
            Ok(q) => q,
            Err(e) => {
                tracing::error!("conversation {conv_id}: {e}");
                return;
            }
        };
        if queued.is_empty() {
            return;
        }
        // Delivered as one text, logged once more as `in` (as the Python).
        if let Err(e) = self.deliver(conv_id, &queued.join("\n\n")).await {
            tracing::warn!("delivering to conversation {conv_id}: {e}");
        }
    }

    fn schedule_retry(&self, lv: &Live) {
        let mut r = locked(&lv.retry);
        let now = tokio::time::Instant::now();
        r.at = now.checked_add(r.backoff);
        r.backoff = r.backoff.saturating_mul(2).min(MAX_RETRY);
    }

    async fn pump(
        self: Arc<Self>,
        conv_id: ConvId,
        run: RunRef,
        mut events: tokio::sync::mpsc::UnboundedReceiver<Event>,
    ) {
        while let Some(event) = events.recv().await {
            match event {
                Event::Text(t) => self.log(&conv_id, "out", &t),
                Event::TurnDone(_) | Event::Error(_) => {
                    if let Event::Error(t) = &event {
                        self.log(&conv_id, "error", t);
                    }
                    let _ = self
                        .store
                        .update_conversation(&conv_id, |c| c.turns = c.turns.saturating_add(1));
                    if !run.busy() && self.flush_queue(&conv_id, &run).await == Flush::Nothing {
                        self.schedule_park(&conv_id, &run);
                    }
                }
                Event::Exit => break,
            }
        }
        let lv = self.live(&conv_id);
        let mine = {
            let mut slot = locked(&lv.run);
            let mine = slot.as_ref().is_some_and(|(r, _)| Arc::ptr_eq(r, &run));
            if mine {
                *slot = None;
            }
            mine
        };
        if mine {
            let _ = self.store.update_conversation(&conv_id, |c| {
                if c.state == ConvState::Running {
                    c.state = ConvState::Parked;
                }
            });
        }
    }

    /// A turn ended: what queued up during it (and no hook collected) is
    /// the next turn.
    async fn flush_queue(&self, conv_id: &ConvId, run: &RunRef) -> Flush {
        let lv = self.live(conv_id);
        if lv.tui() {
            return Flush::Nothing;
        }
        let Some(conv) = self.store.conversation(conv_id) else {
            return Flush::Nothing;
        };
        if self.held(&conv.agent) {
            return Flush::Held;
        }
        let _op = lv.op.lock().await;
        if !lv.run().is_some_and(|r| Arc::ptr_eq(&r, run)) {
            return Flush::Nothing;
        }
        let queued = match self.store.drain(conv_id) {
            Ok(q) => q,
            Err(_) => return Flush::Nothing,
        };
        if queued.is_empty() {
            return Flush::Nothing;
        }
        if run.send(&queued.join("\n\n")).await.is_err() {
            let _ = self.store.queue_all(conv_id, &queued);
        }
        Flush::Sent
    }

    fn schedule_park(&self, conv_id: &ConvId, run: &RunRef) {
        let lv = self.live(conv_id);
        if lv.tui() {
            return; // an attached operator decides
        }
        let Some(me) = self.me() else { return };
        let grace = Duration::from_secs_f64(self.config.park_grace_secs);
        let id = conv_id.clone();
        let run = Arc::clone(run);
        lv.cancel_park();
        let task = self.spawn(async move {
            tokio::time::sleep(grace).await;
            me.park(&id, Some(&run)).await;
        });
        *locked(&lv.park_timer) = Some(task);
    }

    /// Stop the process (if it is the one expected and idle); resumable.
    pub async fn park(&self, conv_id: &ConvId, expected: Option<&RunRef>) {
        let lv = self.live(conv_id);
        let _op = lv.op.lock().await;
        let Some(run) = lv.run() else { return };
        if expected.is_some_and(|e| !Arc::ptr_eq(e, &run)) || run.busy() {
            return;
        }
        let conv = self.store.conversation(conv_id);
        if conv.as_ref().is_some_and(|c| self.held(&c.agent)) {
            return; // frozen: kept as it is
        }
        let taken = locked(&lv.run).take();
        run.stop(&self.host).await;
        drop(taken);
        if let Some(conv) = &conv {
            if conv.runtime == "codex" {
                let ctx = locked(&lv.ctx).clone();
                if let Some(ctx) = ctx {
                    let rec = self.store.agent(&conv.agent);
                    let project = rec.as_ref().and_then(|r| self.project_of(r));
                    self.codex_sync_back(project.as_deref(), ctx.uid).await;
                }
            }
            if conv.state != ConvState::Closed {
                let _ = self
                    .store
                    .update_conversation(conv_id, |c| c.state = ConvState::Parked);
            }
        }
        tracing::info!("parked conversation {conv_id}");
    }

    /// End a conversation: its TUI and process stop, its broker session
    /// closes (ending its threads), its token stops working.
    pub async fn close(&self, conv_id: &ConvId) -> SbxResult<()> {
        let Some(conv) = self.store.conversation(conv_id) else {
            return Ok(());
        };
        let lv = self.live(conv_id);
        self.stop_tui(conv_id).await;
        {
            let _op = lv.op.lock().await;
            lv.cancel_park();
            let taken = locked(&lv.run).take();
            if let Some((run, _slot)) = taken {
                run.stop(&self.host).await;
            }
        }
        self.store
            .update_conversation(conv_id, |c| c.state = ConvState::Closed)?;
        if let (Some(rec), Some(sid)) = (self.store.agent(&conv.agent), &conv.broker_session_id)
            && let Err(e) = self.client(&rec, Some(sid)).close_session().await
        {
            tracing::info!("closing the session of {conv_id}: {e}");
        }
        if let Some(w) = locked(&lv.watcher).take() {
            w.abort();
        }
        self.forget_live(conv_id);
        Ok(())
    }

    /// The operator's `stop`: end the TUI, park the process.
    pub async fn stop(&self, conv_id: &ConvId) {
        self.stop_tui(conv_id).await;
        self.park(conv_id, None).await;
    }

    // ------------------------------------------------------------ reaper

    /// Every 10 s: TUIs that exited, TUIs idle past
    /// `interactive_idle_secs` (B-5), and queued deliveries due a retry.
    pub(crate) async fn reaper(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            self.reap_once().await;
        }
    }

    pub async fn reap_once(&self) {
        let now = tokio::time::Instant::now();
        for lv in self.lives() {
            let conv = lv.conv.clone();
            if lv.tui() {
                if !self.host.unit_active(&conv.tui_unit()).await {
                    self.tui_ended(&conv).await;
                } else if self.tui_idle(&conv).await {
                    tracing::info!("the TUI of {conv} was idle; back to headless");
                    self.stop_tui(&conv).await;
                }
                continue;
            }
            let due = locked(&lv.retry).at.is_some_and(|t| t <= now);
            if due && lv.run().is_none() {
                locked(&lv.retry).at = None;
                self.deliver_queued(&conv).await;
            }
        }
    }

    /// No client attached, and nothing happened in the session for
    /// `interactive_idle_secs`.
    async fn tui_idle(&self, conv_id: &ConvId) -> bool {
        let Some((uid, host_sock)) = self.tui_socket(conv_id) else {
            return false;
        };
        let argv = vec![
            self.config.tmux.clone(),
            "-S".to_owned(),
            host_sock,
            "display-message".to_owned(),
            "-p".to_owned(),
            "-t".to_owned(),
            "conv".to_owned(),
            "#{session_attached} #{session_activity}".to_owned(),
        ];
        let (code, out) = self.host.run_as(uid, &argv).await;
        if code != 0 {
            return false;
        }
        let mut parts = out.split_whitespace();
        let attached: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
        let activity: f64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(f64::MAX);
        attached == 0 && crate::store::now() - activity > self.config.interactive_idle_secs
    }

    // -------------------------------------------------------- interactive

    /// (uid, host path) of the conversation's tmux socket.
    fn tui_socket(&self, conv_id: &ConvId) -> Option<(u32, String)> {
        let conv = self.store.conversation(conv_id)?;
        let rec = self.store.agent(&conv.agent)?;
        let project = self.project_of(&rec);
        let uid = self.project_uid(project.as_deref()).ok()?;
        let (_, _, tmp) = self.paths(project.as_deref());
        Some((
            uid,
            tmp.join(format!("tmux-{}.sock", conv_id.as_str()))
                .display()
                .to_string(),
        ))
    }

    /// Put the conversation in a TUI (tmux) and say how to attach.
    pub async fn attach(&self, conv_id: &ConvId, now: bool) -> SbxResult<Value> {
        let Some(conv) = self
            .store
            .conversation(conv_id)
            .filter(|c| c.state != ConvState::Closed)
        else {
            return Err(SbxError::Lookup(format!("no open conversation {conv_id}")));
        };
        if let Some(why) = self.hold_refusal(&conv.agent) {
            return Err(SbxError::Runtime(why));
        }
        let lv = self.live(conv_id);
        let runtime = self.runtime(&conv.runtime).ok_or_else(|| {
            SbxError::Runtime(format!("no runtime configured for {}", conv.agent))
        })?;
        if lv.tui() && self.host.unit_active(&conv_id.tui_unit()).await {
            return self.attach_info(conv_id);
        }
        let _op = lv.op.lock().await;
        lv.cancel_park();
        let rec = self.agent_record(&conv.agent)?;
        if runtime.shares_live_process() {
            // codex: the TUI is a second client of the live app-server.
            self.ensure_running(&conv, &lv).await?;
        } else if let Some(run) = lv.run() {
            // claude: one writer per session — the headless process ends at
            // a turn boundary, the TUI resumes the same session.
            let deadline = tokio::time::Instant::now()
                .checked_add(if now { Duration::ZERO } else { ATTACH_WAIT })
                .unwrap_or_else(tokio::time::Instant::now);
            while run.busy() && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let taken = locked(&lv.run).take();
            run.stop(&self.host).await;
            drop(taken);
        }
        let conv = self
            .store
            .conversation(conv_id)
            .ok_or_else(|| SbxError::Lookup(format!("no open conversation {conv_id}")))?;
        let sid = self.ensure_session(&conv).await?;
        let mut conv = conv;
        conv.broker_session_id = Some(sid);
        let mut ctx = self.context(&conv, &lv, true)?;
        self.add_mcp_servers(&mut ctx, &rec).await;
        self.use_gateway(&mut ctx, &rec)
            .await
            .map_err(|e| SbxError::Runtime(e.0))?;
        let tui = if conv.runtime == "claude" && ctx.runtime_session_id.is_none() {
            let sid = uuid::Uuid::new_v4().to_string();
            ctx.runtime_session_id = Some(sid.clone());
            self.store
                .update_conversation(conv_id, |c| c.runtime_session_id = Some(sid))?;
            let mut argv = runtime.tui_argv(&ctx);
            if let Some(a) = argv.iter_mut().rev().find(|a| *a == "--resume") {
                *a = "--session-id".to_owned();
            }
            argv
        } else {
            runtime.tui_argv(&ctx)
        };
        // The wait above can be minutes: a hold that came meanwhile applies.
        if let Some(why) = self.hold_refusal(&conv.agent) {
            return Err(SbxError::Runtime(why));
        }
        let project = self.project_of(&rec);
        let slot = self
            .slots
            .acquire(project.as_deref().unwrap_or("_orchestrator"), SLOT_WAIT)
            .await
            .map_err(SbxError::Runtime)?;
        self.start_tui(conv_id, &ctx, &tui).await?;
        *locked(&lv.tui_slot) = Some(slot);
        lv.tui.store(true, Ordering::SeqCst);
        self.store
            .update_conversation(conv_id, |c| c.state = ConvState::Attached)?;
        if self.held(&conv.agent) {
            // Arrived while it started.
            self.host.freeze_unit(&conv_id.tui_unit(), true).await;
        }
        self.attach_info(conv_id)
    }

    async fn start_tui(
        &self,
        conv_id: &ConvId,
        ctx: &SpawnContext,
        tui: &[String],
    ) -> SbxResult<()> {
        let sock_name = format!("tmux-{}.sock", conv_id.as_str());
        let host_sock = ctx.tmp.join(&sock_name).display().to_string();
        let unit_sock = format!("/tmp/{sock_name}");
        if let Ok(tmp) = ctx.tmp_tree.open() {
            let _ = tmp.remove(&sock_name);
        }
        let tmux = self.config.tmux.clone();
        let mut server = ctx.unit_spec(
            vec![
                tmux.clone(),
                "-D".to_owned(),
                "-S".to_owned(),
                unit_sock.clone(),
                "-f".to_owned(),
                "/dev/null".to_owned(),
            ],
            format!("tui {conv_id}"),
        );
        server.name = conv_id.tui_unit();
        self.host.start_detached(&server).await?;
        for _ in 0..100 {
            let up = ctx
                .tmp_tree
                .open()
                .and_then(|t| t.entry(&sock_name))
                .ok()
                .flatten()
                .is_some_and(|e| e.is_socket());
            if up {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The session runs inside the server, so inside the unit's sandbox;
        // when the TUI exits the server goes too and the unit ends. A TUI
        // that fails keeps its pane (and its error) up instead of vanishing.
        let command = format!(
            "t0=$(date +%s); {}; rc=$?; if [ \"$rc\" -ne 0 ] || [ $(( $(date +%s) - t0 )) -lt 5 ]; then printf '\\n{TUI_FAILED} %s]\\n' \"$rc\"; sleep 600; fi; {} -S {} kill-server",
            shlex_join(tui),
            shlex_quote(&tmux),
            shlex_quote(&unit_sock),
        );
        let client = |rest: &[&str]| -> Vec<String> {
            let mut v = vec![tmux.clone(), "-S".to_owned(), host_sock.clone()];
            v.extend(rest.iter().map(|s| (*s).to_owned()));
            v
        };
        let workdir = ctx.workdir.display().to_string();
        let (code, out) = self
            .host
            .run_as(
                ctx.uid,
                &client(&[
                    "new-session",
                    "-d",
                    "-s",
                    "conv",
                    "-c",
                    &workdir,
                    "/bin/sh",
                    "-c",
                    &command,
                ]),
            )
            .await;
        if code != 0 {
            self.host.stop_unit(&conv_id.tui_unit()).await;
            return Err(SbxError::Runtime(format!(
                "tmux new-session failed: {}",
                out.trim().chars().take(300).collect::<String>()
            )));
        }
        // Don't hand the operator a dead session: give the TUI a moment,
        // then report what it printed if it already failed.
        tokio::time::sleep(TUI_SETTLE).await;
        let (alive, _) = self
            .host
            .run_as(ctx.uid, &client(&["has-session", "-t", "conv"]))
            .await;
        let (_, pane) = self
            .host
            .run_as(ctx.uid, &client(&["capture-pane", "-p", "-t", "conv"]))
            .await;
        if alive != 0 || pane.contains(TUI_FAILED) {
            self.host.stop_unit(&conv_id.tui_unit()).await;
            let shown: String = pane
                .lines()
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            let n = shown.chars().count();
            let shown: String = shown.chars().skip(n.saturating_sub(1500)).collect();
            let detail = if alive == 0 && !shown.is_empty() {
                format!(":\n{shown}")
            } else {
                format!(" (see journalctl -u {})", conv_id.tui_unit())
            };
            return Err(SbxError::Runtime(format!(
                "the TUI exited as soon as it started{detail}"
            )));
        }
        Ok(())
    }

    fn attach_info(&self, conv_id: &ConvId) -> SbxResult<Value> {
        let (uid, host_sock) = self
            .tui_socket(conv_id)
            .ok_or_else(|| SbxError::Lookup(format!("no open conversation {conv_id}")))?;
        Ok(json!({
            "conversation": conv_id.as_str(),
            "uid": uid,
            "argv": [self.config.tmux, "-S", host_sock, "attach", "-t", "conv"],
        }))
    }

    /// End the TUI (if one is attached); back to headless.
    pub async fn stop_tui(&self, conv_id: &ConvId) {
        let lv = self.live(conv_id);
        if lv.tui() {
            self.host.stop_unit(&conv_id.tui_unit()).await;
            self.tui_ended(conv_id).await;
        }
    }

    async fn tui_ended(&self, conv_id: &ConvId) {
        let lv = self.live(conv_id);
        lv.tui.store(false, Ordering::SeqCst);
        locked(&lv.tui_slot).take();
        // The env file of a unit that ended by itself (B-18).
        self.host.stop_unit(&conv_id.tui_unit()).await;
        let Some(conv) = self.store.conversation(conv_id) else {
            return;
        };
        if conv.state == ConvState::Closed {
            return;
        }
        let run = lv.run();
        let _ = self.store.update_conversation(conv_id, |c| {
            c.state = if run.is_some() {
                ConvState::Running
            } else {
                ConvState::Parked
            };
        });
        if let Some(run) = &run
            && !run.busy()
        {
            self.schedule_park(conv_id, run);
        }
        // What arrived while the TUI held the session, headless now.
        self.deliver_queued(conv_id).await;
    }

    // ------------------------------------------------------ orchestrator

    /// Ask the broker, as the orchestrator, for
    /// `<runtime>-<project>-<host>-sandbox` (spec §4.13).
    pub async fn mint(
        &self,
        runtime: &str,
        project: &str,
        why: &str,
        wait_secs: f64,
    ) -> SbxResult<Value> {
        let Some(orch) = self.store.agent(&self.orchestrator) else {
            return Err(SbxError::Runtime(
                "this VM has no orchestrator key yet (is it paired?)".to_owned(),
            ));
        };
        if self.locked() {
            return Err(SbxError::Runtime("locked down".to_owned()));
        }
        if self.store.project(project).is_none() {
            return Err(SbxError::Lookup(format!(
                "create project {} first",
                repr(project)
            )));
        }
        let name =
            agent_auth_core::sandbox::agent_name(runtime, project, self.config.name.as_str());
        let why = if why.is_empty() {
            format!("run {runtime} on project {project}")
        } else {
            why.to_owned()
        };
        let mut scope = serde_json::Map::new();
        scope.insert("runtime".into(), json!(runtime));
        let client = self.client(&orch, None);
        let mut req = client
            .request_access("agents", "mint", &name, &why, "1h", Some(scope), None)
            .await?;
        use agent_auth_core::RequestStatus as S;
        if !matches!(req.status, S::Granted | S::Denied | S::ProvisionFailed) {
            req = client.wait(&req.id.to_string(), wait_secs).await?;
        }
        let mut out = json!({
            "agent": name,
            "request_id": req.id.to_string(),
            "status": req.status.as_str(),
            "reason": req.decision_reason,
        });
        if req.status == S::Granted {
            let steps = (wait_secs * 10.0).clamp(0.0, 100_000.0);
            let mut n = 0.0;
            while n < steps && self.store.agent(&name).is_none() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                n += 1.0;
            }
            if let Value::Object(m) = &mut out {
                m.insert(
                    "key_received".into(),
                    json!(self.store.agent(&name).is_some()),
                );
            }
        }
        Ok(out)
    }

    /// A new conversation of `agent` with `prompt` as its first message.
    pub async fn spawn_conversation(
        &self,
        agent: &str,
        prompt: &str,
        created_by: &str,
        title: &str,
    ) -> SbxResult<Conversation> {
        let title = if title.is_empty() {
            prompt.chars().take(80).collect()
        } else {
            title.to_owned()
        };
        let conv = self
            .new_conversation(agent, created_by, &title, "headless")
            .await?;
        self.deliver(&conv.id, prompt).await?;
        Ok(self.store.conversation(&conv.id).unwrap_or(conv))
    }
}
