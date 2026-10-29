//! Desktop prompts (a2a-wiki-desktop spec §8): a request waiting for a
//! human is also asked on the desks the operator is at (hostd-user's
//! dialog), and the first answer decides — through the request service,
//! like any human decision (INV-18).
//!
//! - Only a `host` connection's answer counts, for a prompt id the broker
//!   sent to **that** host, while the offer is open.
//! - A command at its own host's desk shows what that hostd would run, and
//!   that hostd decides whether Allow there is its own approval
//!   (`desktop.approve`; root also takes the user's password).
//! - A shell is asked only at its own host's desk, where hostd takes the
//!   user's password before Allow counts; other requests without an
//!   authority never are.
//!
//! Rates (per agent, overall, bursts), pauses after denies and mutes, and
//! do-not-disturb are kept in memory (a restart resets them: B19). The
//! rate slot is reserved when the offer is accepted, not later (B16: the
//! Python counted after awaits, so simultaneous requests all passed).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use agent_auth_core::authority::HostexecAuthority;
use agent_auth_core::durations::format_duration;
use agent_auth_core::pyfmt::{escape_unprintable, shlex_join};
use agent_auth_core::{AgentId, Authority, Platform, RequestId, RequestStatus};
use agent_auth_crypto::daemon::Role;
use agent_auth_store::agents::AgentRow;
use agent_auth_store::daemons::{self, DaemonRole};
use agent_auth_store::grants::GrantRow;
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::requests::RequestRow;
use agent_auth_store::rules::RuleRow;
use agent_auth_wire::daemon::channel::{Incoming, PromptId, parse};
use agent_auth_wire::daemon::host::{Answer, HostToBroker};
use serde_json::{Map, Value, json};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::auth::{DeskAnswer, HumanDecider};
use crate::daemons::{DaemonHub, DaemonPeer};
use crate::hostexec::HostExec;
use crate::notify::{Notifier, Notify};
use crate::state::AppState;

pub const BURST: usize = 2;
pub const BURST_WINDOW: Duration = Duration::from_secs(120);
/// How long a prompt waits for its desk's dialog slot.
pub const QUEUE: Duration = Duration::from_secs(30);
pub const DENIES_TO_MUTE: usize = 3;
const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct Offer {
    /// prompt id → host.
    prompts: HashMap<String, String>,
    /// (host, answer, whether hostd says Allow was its own approval).
    answer: Option<oneshot::Sender<(Option<String>, Answer, bool)>>,
}

#[derive(Debug, Default)]
struct DeskState {
    dnd_until: Option<Instant>,
    /// What hosts said since their last heartbeat was stored:
    /// (present, received at).
    presence: HashMap<String, (bool, time::OffsetDateTime)>,
    offers: HashMap<RequestId, Offer>,
    /// prompt id → request.
    prompts: HashMap<String, RequestId>,
    asked: HashMap<AgentId, VecDeque<Instant>>,
    asked_all: VecDeque<Instant>,
    denies: HashMap<AgentId, VecDeque<Instant>>,
    paused_until: HashMap<AgentId, Instant>,
}

/// The desktop service.
pub struct Desktop {
    hub: Arc<DaemonHub>,
    hostexec: Option<Arc<HostExec>>,
    st: OnceLock<AppState>,
    state: Mutex<DeskState>,
    host_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    me: Weak<Desktop>,
}

impl std::fmt::Debug for Desktop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Desktop").finish_non_exhaustive()
    }
}

fn prune(times: &mut VecDeque<Instant>, window: Duration, now: Instant) {
    while times
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) > window)
    {
        times.pop_front();
    }
}

fn answer_word(a: Answer) -> &'static str {
    match a {
        Answer::Allow => "allow",
        Answer::Deny => "deny",
        Answer::Mute => "mute",
        Answer::Discord => "discord",
        Answer::Timeout => "timeout",
    }
}

/// `(who, what, detail)`, one line each. Who is asking comes from the
/// broker's records; only the quoted justification is the agent's own.
#[must_use]
pub fn prompt_fields(
    request: &RequestRow,
    agent: &AgentRow,
    delegator: Option<&AgentRow>,
) -> (String, String, String) {
    let who = match delegator {
        Some(d) => format!("{} (for {})", agent.name, d.name),
        None => agent.name.clone(),
    };
    let what = match request.authority.as_ref() {
        Some(Authority::Hostexec(h)) => {
            let tier = if h.tier() == agent_auth_core::Tier::Root {
                "ROOT"
            } else {
                "your user"
            };
            let command = match h {
                HostexecAuthority::Run { argv, .. } => shlex_join(argv),
                HostexecAuthority::Template {
                    template, params, ..
                } => format!(
                    "template {template} {}",
                    agent_auth_core::pyfmt::json_str_map(
                        params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
                    )
                ),
                _ => String::new(),
            };
            format!("run on {} as {tier}: {command}", request.resource)
        }
        authority => {
            let mut what = format!(
                "{} / {} on {}",
                request.platform,
                authority.map(Authority::capability).unwrap_or_default(),
                request.resource
            );
            if let Some(a) = authority
                && !a.scope().is_empty()
            {
                let scope = Value::Object(a.scope()).to_string();
                what.push(' ');
                what.push_str(&scope.chars().take(200).collect::<String>());
            }
            what.push_str(&format!(
                ", for {}",
                format_duration(u64::from(request.requested_duration_secs))
            ));
            what
        }
    };
    let mut detail: Vec<String> = request
        .risk_notes
        .iter()
        .take(2)
        .map(|n| n.chars().take(200).collect())
        .collect();
    detail.push(format!(
        "The agent says (unverified): {}",
        request.justification.chars().take(400).collect::<String>()
    ));
    (
        escape_unprintable(&who),
        escape_unprintable(&what),
        escape_unprintable(&detail.join(" · ")),
    )
}

impl Desktop {
    /// The service, with its handlers registered on the hub.
    pub fn new(
        hub: Arc<DaemonHub>,
        hostexec: Option<Arc<HostExec>>,
    ) -> Result<Arc<Desktop>, String> {
        let me = Arc::new_cyclic(|weak| Desktop {
            hub: Arc::clone(&hub),
            hostexec,
            st: OnceLock::new(),
            state: Mutex::new(DeskState::default()),
            host_locks: Mutex::new(HashMap::new()),
            me: weak.clone(),
        });
        let d = Arc::clone(&me);
        hub.handle(
            "presence",
            Arc::new(move |peer, body| {
                let d = Arc::clone(&d);
                Box::pin(async move { d.on_presence(&peer, body) })
            }),
        )?;
        let d = Arc::clone(&me);
        hub.handle(
            "prompt.answer",
            Arc::new(move |peer, body| {
                let d = Arc::clone(&d);
                Box::pin(async move { d.on_answer(&peer, body) })
            }),
        )?;
        Ok(me)
    }

    /// The broker's state (for deciding), attached once by `main`.
    pub fn bind(&self, st: AppState) {
        let _ = self.st.set(st);
    }

    fn state(&self) -> std::sync::MutexGuard<'_, DeskState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn config(&self) -> Option<&agent_auth_core::policy::schema::DesktopConfig> {
        self.st.get().map(|s| s.policy.desktop())
    }

    // ---------------------------------------------------------- presence

    fn on_presence(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if peer.role() != Role::Host {
            return;
        }
        if let Incoming::Message(HostToBroker::Presence(p)) = parse::<HostToBroker>(body) {
            self.state().presence.insert(
                peer.name().to_owned(),
                (p.present, time::OffsetDateTime::now_utc()),
            );
        }
    }

    /// Hosts whose hostd is connected and says you are at the desk.
    pub async fn present_hosts(&self) -> Vec<String> {
        let Some(st) = self.st.get() else {
            return Vec::new();
        };
        let rows = async {
            let tx = st.store.begin().await?;
            let r = daemons::list_role(&tx, DaemonRole::Host).await?;
            tx.commit().await?;
            Ok::<_, agent_auth_store::StoreError>(r)
        }
        .await
        .unwrap_or_default();
        let fresh = self.state().presence.clone();
        let mut out: Vec<String> = rows
            .into_iter()
            .filter(|row| self.hub.is_online(Role::Host, &row.name))
            .filter(|row| {
                let mut present = row
                    .last_status
                    .as_ref()
                    .and_then(|s| s.get("desktop"))
                    .and_then(|d| d.get("present"))
                    == Some(&Value::Bool(true));
                if let Some((p, at)) = fresh.get(&row.name)
                    && row.last_seen_at.is_none_or(|seen| *at >= seen)
                {
                    present = *p;
                }
                present
            })
            .map(|row| row.name)
            .collect();
        out.sort();
        out
    }

    /// Do-not-disturb for every desk (0: off).
    pub async fn set_dnd(&self, seconds: u64) {
        self.state().dnd_until = (seconds > 0)
            .then(|| Instant::now().checked_add(Duration::from_secs(seconds)))
            .flatten();
        let Some(st) = self.st.get() else {
            return;
        };
        let names: Vec<String> = async {
            let tx = st.store.begin().await?;
            let r = daemons::list_role(&tx, DaemonRole::Host).await?;
            tx.commit().await?;
            Ok::<_, agent_auth_store::StoreError>(r)
        }
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.name)
        .collect();
        for name in names {
            let mut msg = Map::new();
            msg.insert("type".into(), json!("dnd"));
            msg.insert(
                "duration".into(),
                if seconds > 0 {
                    json!(seconds)
                } else {
                    Value::Null
                },
            );
            self.hub.send_default(Role::Host, &name, &msg).await;
        }
    }

    // ----------------------------------------------------- eligibility

    fn listed(&self, agent: &AgentRow) -> bool {
        self.config().is_some_and(|c| {
            let r = crate::service::agent_ref_of(agent);
            c.agents.iter().any(|p| p.matches(&r))
        })
    }

    fn too_sensitive(&self, request: &RequestRow) -> bool {
        let (Some(st), Some(c)) = (self.st.get(), self.config()) else {
            return true;
        };
        !c.sensitive
            && request
                .authority
                .as_ref()
                .is_some_and(|a| a.is_sensitive(&st.policy.sensitivity(), &request.resource))
    }

    /// Why this request is not asked on a desktop (`None`: it may be);
    /// when it may be, the rate slot is taken now (B16).
    pub fn refusal(&self, request: &RequestRow, agent: &AgentRow) -> Option<&'static str> {
        let Some(c) = self.config() else {
            return Some("desktop prompts are off");
        };
        if !c.enabled {
            return Some("desktop prompts are off");
        }
        if !self.listed(agent) {
            return Some("agent not listed under desktop.agents");
        }
        if !c.platforms.is_empty() && !c.platforms.contains(&request.platform) {
            return Some("platform not listed under desktop.platforms");
        }
        // A shell (the human-only authority) only at its own host's desk
        // (`ask`), where that hostd takes the password.
        if request
            .authority
            .as_ref()
            .is_none_or(|a| a.human_only() && request.platform != Platform::Hostexec)
        {
            return Some("never asked on a desktop");
        }
        // A command is asked at its own host's desk, where the host itself
        // decides what an answer is worth; the rest by sensitivity.
        if request.platform != Platform::Hostexec && self.too_sensitive(request) {
            return Some("sensitive (desktop.sensitive is off)");
        }
        let now = Instant::now();
        let mut s = self.state();
        if s.dnd_until.is_some_and(|d| d > now) {
            return Some("do-not-disturb");
        }
        if s.paused_until.get(&agent.id).is_some_and(|p| *p > now) {
            return Some("this agent's desktop prompts are paused");
        }
        let per_agent = usize::try_from(c.per_agent_per_hour).unwrap_or(usize::MAX);
        let per_hour = usize::try_from(c.per_hour).unwrap_or(usize::MAX);
        let mine = s.asked.entry(agent.id).or_default();
        prune(mine, HOUR, now);
        let burst = mine
            .iter()
            .filter(|t| now.saturating_duration_since(**t) < BURST_WINDOW)
            .count();
        if mine.len() >= per_agent || burst >= BURST {
            return Some("desktop rate-limited (agent)");
        }
        prune(&mut s.asked_all, HOUR, now);
        if s.asked_all.len() >= per_hour {
            return Some("desktop rate-limited");
        }
        s.asked.entry(agent.id).or_default().push_back(now);
        s.asked_all.push_back(now);
        None
    }

    fn note_deny(&self, agent: AgentId) {
        let Some(c) = self.config() else {
            return;
        };
        let now = Instant::now();
        let mut s = self.state();
        let denies = s.denies.entry(agent).or_default();
        denies.push_back(now);
        prune(denies, HOUR, now);
        let pause = if denies.len() >= DENIES_TO_MUTE {
            c.mute
        } else {
            c.deny_cooldown
        };
        if let Some(until) = now.checked_add(Duration::from_secs(u64::from(pause.get()))) {
            s.paused_until.insert(agent, until);
        }
    }

    // ------------------------------------------------------------ asking

    /// A request was surfaced: ask the desks (returns at once).
    pub fn offer(&self, request: &RequestRow, agent: &AgentRow) {
        if self.refusal(request, agent).is_some() {
            return;
        }
        let Some(me) = self.me.upgrade() else {
            return;
        };
        let id = request.id;
        tokio::spawn(async move {
            if let Err(e) = me.ask(id).await {
                tracing::warn!(request = %id, "desktop prompt failed: {e}");
            }
        });
    }

    async fn ask(self: Arc<Self>, request_id: RequestId) -> Result<(), String> {
        let st = self.st.get().ok_or("not bound")?.clone();
        let (request, agent, delegator) = {
            let tx = st.store.begin().await.map_err(|e| e.to_string())?;
            let Some(request) = agent_auth_store::requests::get(&tx, request_id)
                .await
                .map_err(|e| e.to_string())?
                .map(agent_auth_store::requests::AnyRequest::into_row)
            else {
                return Ok(());
            };
            if request.status != RequestStatus::AwaitingHuman {
                return Ok(());
            }
            let agent = agent_auth_store::agents::get(&tx, request.agent_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("no agent")?;
            let delegator = match &request.delegation {
                Some(d) => agent_auth_store::agents::get(&tx, d.delegator_agent_id)
                    .await
                    .map_err(|e| e.to_string())?,
                None => None,
            };
            tx.commit().await.map_err(|e| e.to_string())?;
            (request, agent, delegator)
        };
        let mut hosts = self.present_hosts().await;
        let mut job = None;
        if request.platform == Platform::Hostexec {
            let authority = request.authority.clone().ok_or("no authority")?;
            match (&self.hostexec, hosts.contains(&request.resource)) {
                (Some(hostexec), true) => {
                    // At its own host's desk: that hostd says what will run,
                    // and whether Allow there is enough.
                    let duration = st
                        .policy
                        .cap_duration(
                            agent_auth_core::DurationSecs::from_secs(i64::from(
                                request.requested_duration_secs.max(1),
                            ))
                            .unwrap_or(agent_auth_core::DurationSecs::MAX),
                            None,
                        )
                        .get();
                    let spec = match hostexec
                        .final_spec(&request.resource, &authority, duration)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::info!(request = %request_id, "desktop prompt: {e}");
                            return Ok(());
                        }
                    };
                    hosts = vec![request.resource.clone()];
                    job = Some(json!({"job_id": request.id.to_string(), "spec": spec.to_json()}));
                }
                _ => {
                    // Not at its own host's desk: a click elsewhere approves
                    // no host command (no desk approves another host's tier),
                    // so it isn't asked there (security review 2026-10,
                    // finding 1f).
                    return Ok(());
                }
            }
        }
        if hosts.is_empty() {
            return Ok(());
        }
        let (who, what, detail) = prompt_fields(&request, &agent, delegator.as_ref());
        let timeout = self.config().map_or(90, |c| c.timeout.get());
        let (tx, rx) = oneshot::channel();
        self.state().offers.insert(
            request_id,
            Offer {
                prompts: HashMap::new(),
                answer: Some(tx),
            },
        );
        let mut payload = Map::new();
        payload.insert("request_id".into(), json!(request_id.to_string()));
        payload.insert("who".into(), json!(who));
        payload.insert("what".into(), json!(what));
        payload.insert("detail".into(), json!(detail));
        payload.insert("timeout".into(), json!(timeout));
        if let Some(job) = job {
            payload.insert("job".into(), job);
        }
        let shows: Vec<_> = hosts
            .into_iter()
            .map(|host| {
                let me = Arc::clone(&self);
                let payload = payload.clone();
                tokio::spawn(async move { me.show(request_id, host, payload).await })
            })
            .collect();
        let wait = Duration::from_secs(u64::from(timeout)).saturating_add(QUEUE);
        let (host, answer, authorized) = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(a)) => a,
            _ => (None, Answer::Timeout, false),
        };
        for s in shows {
            s.abort();
        }
        self.close(request_id).await;
        let answer = Self::believed(&request, host.as_deref(), answer, authorized);
        self.apply(&st, request_id, agent.id, host, answer).await;
        Ok(())
    }

    /// One dialog on one host; a host shows one at a time. Holds the host's
    /// slot until the offer ends (this task is aborted then).
    async fn show(&self, request: RequestId, host: String, payload: Map<String, Value>) {
        let lock = {
            let mut locks = self
                .host_locks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            Arc::clone(locks.entry(host.clone()).or_default())
        };
        let Ok(_slot) = tokio::time::timeout(QUEUE, lock.lock_owned()).await else {
            return; // that desk is busy with another dialog: Discord has it
        };
        let prompt_id = PromptId::new().to_string();
        {
            let mut s = self.state();
            let Some(offer) = s.offers.get_mut(&request) else {
                return;
            };
            offer.prompts.insert(prompt_id.clone(), host.clone());
            s.prompts.insert(prompt_id.clone(), request);
        }
        let mut msg = payload;
        msg.insert("type".into(), json!("prompt"));
        msg.insert("prompt_id".into(), json!(prompt_id));
        if self
            .hub
            .call(Role::Host, &host, msg, Duration::from_secs(10))
            .await
            .is_err()
        {
            // Nobody there after all, or that host won't ask this.
            let mut s = self.state();
            s.prompts.remove(&prompt_id);
            if let Some(o) = s.offers.get_mut(&request) {
                o.prompts.remove(&prompt_id);
            }
            return;
        }
        std::future::pending::<()>().await;
    }

    async fn close(&self, request: RequestId) {
        let prompts: Vec<(String, String)> = {
            let mut s = self.state();
            let offer = s.offers.remove(&request);
            let prompts: Vec<(String, String)> = offer
                .map(|o| o.prompts.into_iter().collect())
                .unwrap_or_default();
            for (p, _) in &prompts {
                s.prompts.remove(p);
            }
            prompts
        };
        for (prompt_id, host) in prompts {
            let mut msg = Map::new();
            msg.insert("type".into(), json!("prompt.cancel"));
            msg.insert("prompt_id".into(), json!(prompt_id));
            self.hub.send_default(Role::Host, &host, &msg).await;
        }
    }

    fn on_answer(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if peer.role() != Role::Host {
            return;
        }
        let Incoming::Message(HostToBroker::PromptAnswer(a)) = parse::<HostToBroker>(body) else {
            return;
        };
        let prompt_id = a.prompt_id.to_string();
        let mut s = self.state();
        let Some(request) = s.prompts.get(&prompt_id).copied() else {
            return;
        };
        // Only for a prompt sent to this very host, still open.
        let sent_here = s
            .offers
            .get(&request)
            .and_then(|o| o.prompts.get(&prompt_id))
            .is_some_and(|h| h == peer.name());
        if !sent_here {
            return;
        }
        if a.answer == Answer::Timeout {
            // That desk gave up; the others may still answer.
            s.prompts.remove(&prompt_id);
            return;
        }
        if let Some(tx) = s.offers.get_mut(&request).and_then(|o| o.answer.take()) {
            let _ = tx.send((Some(peer.name().to_owned()), a.answer, a.authorized));
        }
    }

    /// What a desk answer counts as. An Allow for a host command counts
    /// only from that host's own desk, when hostd says it was its own
    /// approval (`authorized`: the desk approves that tier, and polkit
    /// confirmed for root); otherwise it is ignored (security review
    /// 2026-10, finding 1b).
    fn believed(
        request: &RequestRow,
        host: Option<&str>,
        answer: Answer,
        authorized: bool,
    ) -> Answer {
        if answer == Answer::Allow
            && request.platform == Platform::Hostexec
            && !(authorized && host == Some(request.resource.as_str()))
        {
            tracing::warn!(
                request = %request.id,
                host = host.unwrap_or("?"),
                "a desk Allow for a host command that host did not authorize was ignored"
            );
            return Answer::Discord;
        }
        answer
    }

    async fn apply(
        &self,
        st: &AppState,
        request: RequestId,
        agent: AgentId,
        host: Option<String>,
        answer: Answer,
    ) {
        match answer {
            Answer::Mute => {
                if let Some(c) = self.config()
                    && let Some(until) =
                        Instant::now().checked_add(Duration::from_secs(u64::from(c.mute.get())))
                {
                    self.state().paused_until.insert(agent, until);
                }
                return;
            }
            Answer::Allow | Answer::Deny => {}
            Answer::Discord | Answer::Timeout => return,
        }
        let Some(host) = host else {
            return;
        };
        if answer == Answer::Deny {
            self.note_deny(agent);
        }
        let desk = DeskAnswer::new(&host);
        let decider = HumanDecider::from(&desk);
        let decision = crate::service::HumanDecision {
            approve: answer == Answer::Allow,
            reason: if answer == Answer::Allow {
                String::new()
            } else {
                "denied at the desk".to_owned()
            },
            // Only an Allow this host vouched for gets here (`believed`).
            desk_host: (answer == Answer::Allow).then(|| host.clone()),
            ..crate::service::HumanDecision::default()
        };
        if let Err(e) = crate::service::decide(st, request, &decider, decision).await {
            // Decided elsewhere meanwhile, or the platform's gate said no:
            // the request stays where it was.
            tracing::info!(request = %request, host = %host, answer = answer_word(answer), "desk answer not applied: {e}");
        }
    }

    /// The request was decided some other way: take the dialogs down.
    pub fn cancel(&self, request: RequestId) {
        let mut s = self.state();
        if let Some(tx) = s.offers.get_mut(&request).and_then(|o| o.answer.take()) {
            let _ = tx.send((None, Answer::Discord, false));
        }
    }

    // ------------------------------------------------------- attention

    /// A notification (and a sound) on every desk the operator is at, for
    /// an agent listed under `desktop.agents`, unless do-not-disturb or the
    /// agent is paused. Not counted against the prompt rates. The hosts
    /// that showed it.
    pub async fn notify(&self, agent: &AgentRow, text: &str, urgency: &str) -> Vec<String> {
        let enabled = self.config().is_some_and(|c| c.enabled);
        let now = Instant::now();
        let blocked = {
            let s = self.state();
            s.dnd_until.is_some_and(|d| d > now)
                || s.paused_until.get(&agent.id).is_some_and(|p| *p > now)
        };
        if !enabled || !self.listed(agent) || blocked {
            return Vec::new();
        }
        let mut shown = Vec::new();
        for host in self.present_hosts().await {
            let mut msg = Map::new();
            msg.insert("type".into(), json!("notify"));
            msg.insert("title".into(), json!(format!("agent-auth: {}", agent.name)));
            msg.insert("text".into(), json!(text));
            msg.insert(
                "urgency".into(),
                json!(if urgency == "high" {
                    "critical"
                } else {
                    "normal"
                }),
            );
            if self
                .hub
                .call(Role::Host, &host, msg, Duration::from_secs(10))
                .await
                .is_ok()
            {
                shown.push(host);
            }
        }
        shown
    }

    /// Something the operator should see now, from the broker itself: on
    /// every desk they are at.
    pub async fn alert(&self, title: &str, text: &str) {
        for host in self.present_hosts().await {
            let mut msg = Map::new();
            msg.insert("type".into(), json!("notify"));
            msg.insert("title".into(), json!(title));
            msg.insert("text".into(), json!(text));
            msg.insert("urgency".into(), json!("critical"));
            let _ = self
                .hub
                .call(Role::Host, &host, msg, Duration::from_secs(10))
                .await;
        }
    }
}

/// The notifier a [`Fanout`] wraps: the human surfaces other than itself
/// (so the futures' types never name each other).
#[derive(Debug)]
pub enum Primary {
    /// Headless: as `Notifier::Null`.
    Null,
    Recording(crate::notify::Recorder),
    Discord(crate::discord::DiscordNotifier),
}

impl Primary {
    /// The primary of a notifier (a Fanout's own primary if it is one).
    #[must_use]
    pub fn from_notifier(n: Notifier) -> Primary {
        match n {
            Notifier::Null => Primary::Null,
            Notifier::Recording(r) => Primary::Recording(r),
            Notifier::Discord(d) => Primary::Discord(d),
            Notifier::Fanout(f) => f.primary,
        }
    }
}

macro_rules! primary {
    ($self:ident, $n:ident => $e:expr, null => $null:expr) => {
        match &$self.primary {
            Primary::Null => $null,
            Primary::Recording($n) => $e,
            Primary::Discord($n) => $e,
        }
    };
}

/// The broker's notifier with desks alongside: everything goes to the
/// primary (Discord); surfaced requests are also offered to desks, a
/// decision takes their dialogs down, and watcher alerts are shown there.
#[derive(Debug)]
pub struct Fanout {
    pub primary: Primary,
    pub desktop: Arc<Desktop>,
}

impl Notify for Fanout {
    async fn surface(&self, request: &RequestRow, agent: &AgentRow) {
        primary!(self, n => n.surface(request, agent).await,
            null => tracing::warn!(request = %request.id, "no notifier configured; request awaits a human via the admin API only"));
        self.desktop.offer(request, agent);
    }
    async fn update_outcome(&self, request: &RequestRow, grant: Option<&GrantRow>) {
        self.desktop.cancel(request.id);
        primary!(self, n => n.update_outcome(request, grant).await, null => ());
    }
    async fn update_grant_ended(&self, request: &RequestRow, grant: &GrantRow) {
        primary!(self, n => n.update_grant_ended(request, grant).await, null => ());
    }
    async fn rule_applied(
        &self,
        request: &RequestRow,
        agent: &AgentRow,
        rule: Option<&RuleRow>,
        grant: Option<&GrantRow>,
    ) {
        primary!(self, n => n.rule_applied(request, agent, rule, grant).await, null => ());
    }
    async fn job_finished(&self, request: &RequestRow, job: &JobRow) {
        primary!(self, n => n.job_finished(request, job).await, null => ());
    }
    async fn shell_command(
        &self,
        request: &RequestRow,
        job: &JobRow,
        scope: Option<&agent_auth_store::shell_scopes::ScopeRow>,
    ) -> bool {
        primary!(self, n => n.shell_command(request, job, scope).await, null => true)
    }
    async fn shell_event(&self, request: &RequestRow, event: crate::notify::ShellEvent<'_>) {
        primary!(self, n => n.shell_event(request, event).await,
            null => tracing::info!(request = %request.id, ?event, "shell event (no notifier)"));
        // An alarming refusal reaches the desk too, as a watcher's alarm does.
        if let crate::notify::ShellEvent::GuardRefused {
            job,
            why,
            alarming: true,
            ..
        } = event
        {
            let argv: Vec<String> = job
                .spec
                .get("argv")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let command: String = escape_unprintable(&shlex_join(&argv))
                .chars()
                .take(200)
                .collect();
            let why: String = escape_unprintable(why).chars().take(300).collect();
            self.desktop
                .alert(
                    &format!("agent-auth: guard refused on {}", job.host),
                    &format!("{command} — {why}"),
                )
                .await;
        }
    }
    async fn watch_alert(
        &self,
        request: &RequestRow,
        job: &JobRow,
        text: &str,
        call: Option<uuid::Uuid>,
    ) {
        primary!(self, n => n.watch_alert(request, job, text, call).await,
            null => tracing::warn!(job = %job.id, host = %job.host, "{text}"));
        let argv: Vec<String> = job
            .spec
            .get("argv")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let command: String = escape_unprintable(&shlex_join(&argv))
            .chars()
            .take(200)
            .collect();
        self.desktop
            .alert(
                &format!("agent-auth: look at {}", job.host),
                &format!("{command} — {text}"),
            )
            .await;
    }
    async fn attention(&self, agent: &AgentRow, text: &str, urgency: &str, desks: &[String]) {
        primary!(self, n => n.attention(agent, text, urgency, desks).await,
            null => tracing::info!(agent = %agent.name, urgency, "attention: {text}"));
    }
    async fn contained(&self, event: &Value) {
        primary!(self, n => n.contained(event).await,
            null => tracing::warn!(?event, "contained (no notifier)"));
    }
    async fn mail_held(&self, item: &agent_auth_wire::mail::MailItem) {
        primary!(self, n => n.mail_held(item).await,
            null => tracing::warn!(item = %item.id, "mail held for the operator (no notifier)"));
    }
}

#[cfg(test)]
#[path = "desktop_tests.rs"]
mod tests;
