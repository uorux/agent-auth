//! `agent-auth-server import-python [--dry-run] <export.json>`: the Python
//! broker's host pairings and agents, into an empty database, so that
//! after the cutover every hostd reconnects without pairing again and
//! every carried agent keeps its API key (both brokers store the key id
//! and `sha256_hex(secret)`; a daemon's only credential is its public key).
//!
//! The export is one JSON document made with `sqlite3` on the old host
//! (rust/README.md, "Migrating from the Python deployment"):
//! `{"format": "agent-auth-python-export/1", "agents": [..], "daemons": [..]}`,
//! read from a file or stdin (`-`). The target is the broker's own
//! database (`DATABASE_URL`, migrated first); the broker may already be
//! running on it, as long as no agent is registered and no daemon paired
//! (its operator row aside). `--dry-run` checks the file and never opens
//! the database.
//!
//! Carried: host daemons, and agents registered by hand (service or
//! ephemeral). Not carried: agent VMs (sandbox daemons; they pair again)
//! and every agent of one (minted, or with a VM or a parent), web UI
//! connectors, the Python's operator stand-in (this broker makes its own),
//! and LLDAP passwords (Fernet: a broker-managed account is adopted again
//! at the agent's next homelab grant, with a new password). Rules, grants,
//! requests, a2a, sessions, OAuth, mail and pools stay behind.
//!
//! Every row is checked with this broker's own validators first; one bad
//! row aborts the whole import, naming the row (never a secret). The
//! inserts are one transaction, read back through the store's parsers.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::sandbox::ORCHESTRATOR_RUNTIME;
use agent_auth_core::{AgentId, DaemonId};
use agent_auth_crypto::api_key::{KeyId, SecretHash};
use agent_auth_crypto::daemon::PublicKey;
use agent_auth_store::agents::{self, DisableReason, ImportedAgent};
use agent_auth_store::daemons::{self, DaemonRole, ImportedDaemon};
use agent_auth_store::{Store, StoreError};
use agent_auth_wire::text::{AgentNameInput, Attribute, DaemonName, Text, WebhookUrl};
use anyhow::Context as _;
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};
use uuid::Uuid;

use crate::a2a::A2aConfig;
use crate::config::{Config, Env};
use crate::oauth::WEB_RUNTIME;

/// The `format` the export command writes.
pub const FORMAT: &str = "agent-auth-python-export/1";

const USAGE: &str = "usage: agent-auth-server import-python [--dry-run] <export.json | ->";

/// The Python's default `managed_username_prefix` (also this broker's).
const MANAGED_PREFIX: &str = "svc-";

/// A row that cannot be carried as it is.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Refused(String),
    #[error("{what}: {source}")]
    Store {
        what: String,
        #[source]
        source: StoreError,
    },
}

fn invalid(what: impl std::fmt::Display, why: impl std::fmt::Display) -> ImportError {
    ImportError::Invalid(format!("{what}: {why}"))
}

fn store_err(what: impl Into<String>) -> impl FnOnce(StoreError) -> ImportError {
    let what = what.into();
    move |source| ImportError::Store { what, source }
}

// ------------------------------------------------------------- the file

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFile {
    format: String,
    agents: Vec<Value>,
    daemons: Vec<Value>,
}

/// One `agents` row as the export writes it (SQLite types: text, 0/1).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PyAgent {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    key_id: String,
    api_key_hash: String,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    lldap_username: Option<String>,
    /// `lldap_password_encrypted IS NOT NULL`: the account is the broker's.
    lldap_managed: Value,
    disabled: Value,
    kind: Option<String>,
    last_seen_at: Option<String>,
    last_listen_at: Option<String>,
    parent_agent_id: Option<String>,
    sandbox_id: Option<String>,
    runtime: Option<String>,
    project: Option<String>,
    host: Option<String>,
    placement: Option<String>,
    lease_expires_at: Option<String>,
    created_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PyDaemon {
    id: String,
    role: String,
    name: String,
    public_key: String,
    paired_at: Option<String>,
    last_seen_at: Option<String>,
    created_at: Option<String>,
}

/// The row's name for messages: its `name` if it has one.
fn row_name(v: &Value, index: usize) -> String {
    v.get("name")
        .and_then(Value::as_str)
        .map_or_else(|| format!("#{index}"), |n| format!("{n:?}"))
}

/// A SQLite boolean: 0/1 (what SQLAlchemy writes), or true/false.
fn boolean(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => match n.as_i64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        },
        Value::String(s) => match s.as_str() {
            "0" | "false" => Some(false),
            "1" | "true" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

/// A uuid as SQLAlchemy stored it: dashed (`str(uuid4())`), or 32 hex.
fn uuid(text: &str) -> Option<Uuid> {
    Uuid::try_parse(text.trim()).ok()
}

/// `HH:MM`, `HHMM` or `HH` after a sign.
fn offset(text: &str) -> Option<UtcOffset> {
    let (negative, digits) = match text.split_at_checked(1)? {
        ("+", d) => (false, d),
        ("-", d) => (true, d),
        _ => return None,
    };
    let digits: String = digits.chars().filter(|c| *c != ':').collect();
    let (h, m) = match digits.len() {
        2 => (digits.as_str(), "0"),
        4 => digits.split_at_checked(2)?,
        _ => return None,
    };
    let (h, m): (i8, i8) = (h.parse().ok()?, m.parse().ok()?);
    let (h, m) = if negative {
        (h.checked_neg()?, m.checked_neg()?)
    } else {
        (h, m)
    };
    UtcOffset::from_hms(h, m, 0).ok()
}

/// A timestamp as the Python's SQLite holds it: SQLAlchemy writes naive
/// UTC, `YYYY-MM-DD HH:MM:SS.ffffff`; a server default has no fraction.
/// Also `T`, any fraction, and `Z` or an offset. Naive means UTC.
fn timestamp(text: &str) -> Option<OffsetDateTime> {
    const CLOCK: &[time::format_description::BorrowedFormatItem<'_>] = time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second][optional [.[subsecond]]]"
    );
    let t = text.trim();
    let (date, rest) = t.split_at_checked(10)?;
    let rest = rest.strip_prefix(['T', 't', ' '])?;
    let (clock, off) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, UtcOffset::UTC)
    } else if let Some(i) = rest.rfind(['+', '-']) {
        let (c, o) = rest.split_at_checked(i)?;
        (c, offset(o)?)
    } else {
        (rest, UtcOffset::UTC)
    };
    let local = PrimitiveDateTime::parse(&format!("{date} {clock}"), CLOCK).ok()?;
    Some(local.assume_offset(off).to_offset(UtcOffset::UTC))
}

/// Empty text is no value (the Rust side treats `""` as unset).
fn nonempty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

// ------------------------------------------------------------- the plan

/// Why a row stays behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// `agent <name>` or `daemon <role>/<name>`.
    pub what: String,
    pub reason: String,
}

struct PlannedDaemon {
    id: DaemonId,
    name: String,
    public_key: String,
    paired_at: OffsetDateTime,
    last_seen_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

/// A validated agent. Holds the key hash and the webhook secret: no
/// `Debug`.
struct PlannedAgent {
    id: AgentId,
    name: String,
    description: String,
    key_id: String,
    api_key_hash: String,
    kind: AgentKind,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    lldap_username: Option<String>,
    disabled: bool,
    runtime: Option<String>,
    project: Option<String>,
    host: Option<String>,
    lease_expires_at: Option<OffsetDateTime>,
    last_seen_at: Option<OffsetDateTime>,
    last_listen_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

/// What an import writes: validated rows, what stays behind and why, and
/// what the operator should look at.
pub struct Plan {
    daemons: Vec<PlannedDaemon>,
    agents: Vec<PlannedAgent>,
    pub skipped: Vec<Skipped>,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan")
            .field("daemons", &self.daemon_names())
            .field("agents", &self.agent_names())
            .field("skipped", &self.skipped)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl Plan {
    /// The host daemons carried, by name.
    #[must_use]
    pub fn daemon_names(&self) -> Vec<&str> {
        self.daemons.iter().map(|d| d.name.as_str()).collect()
    }

    /// The agents carried, by name.
    #[must_use]
    pub fn agent_names(&self) -> Vec<&str> {
        self.agents.iter().map(|a| a.name.as_str()).collect()
    }

    /// The summary printed after an import (or a dry run).
    #[must_use]
    pub fn summary(&self, dry_run: bool) -> String {
        let mut out = String::new();
        let verb = if dry_run { "would import" } else { "imported" };
        let list = |names: Vec<&str>| {
            if names.is_empty() {
                "(none)".to_owned()
            } else {
                names.join(", ")
            }
        };
        let _ = writeln!(
            out,
            "{verb} {} host daemon(s): {}",
            self.daemons.len(),
            list(self.daemon_names())
        );
        let _ = writeln!(
            out,
            "{verb} {} agent(s): {}",
            self.agents.len(),
            list(self.agent_names())
        );
        let _ = writeln!(out, "skipped {}:", self.skipped.len());
        for s in &self.skipped {
            let _ = writeln!(out, "  {}: {}", s.what, s.reason);
        }
        let _ = writeln!(out, "warnings {}:", self.warnings.len());
        for w in &self.warnings {
            let _ = writeln!(out, "  {w}");
        }
        if dry_run {
            let _ = writeln!(
                out,
                "dry run: nothing was written (the database was not opened)"
            );
        }
        out
    }
}

/// The skip rules for agents, in order. `None`: carry it.
fn skip_reason(
    a: &PyAgent,
    agents_by_id: &HashMap<Uuid, &PyAgent>,
    daemons_by_id: &HashMap<Uuid, String>,
) -> Option<String> {
    if a.kind.as_deref() == Some("operator") {
        return Some(
            "the Python's operator stand-in (this broker makes its own at start)".to_owned(),
        );
    }
    if let Some(s) = nonempty(a.sandbox_id.clone()) {
        let vm = uuid(&s)
            .and_then(|id| daemons_by_id.get(&id).cloned())
            .unwrap_or_else(|| "an unknown daemon".to_owned());
        return Some(format!(
            "an agent of the agent VM {vm} (minted again by its orchestrator after the VM pairs)"
        ));
    }
    if let Some(p) = nonempty(a.parent_agent_id.clone()) {
        let parent = uuid(&p).and_then(|id| agents_by_id.get(&id)).map_or_else(
            || "an agent not in the export".to_owned(),
            |p| p.name.clone(),
        );
        return Some(format!(
            "minted by {parent} (minted agents are not carried)"
        ));
    }
    if a.runtime.as_deref() == Some(WEB_RUNTIME) {
        return Some("a web UI connector's agent (authorize the connector again)".to_owned());
    }
    if a.placement.as_deref() == Some("sandbox")
        || a.runtime.as_deref() == Some(ORCHESTRATOR_RUNTIME)
    {
        return Some(
            "an agent VM's agent (its orchestrator is made again when the VM pairs)".to_owned(),
        );
    }
    None
}

fn time_of(
    what: &str,
    field: &str,
    v: Option<&String>,
) -> Result<Option<OffsetDateTime>, ImportError> {
    match v.map(String::as_str).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => timestamp(s)
            .map(Some)
            .ok_or_else(|| invalid(what, format!("{field} is not a timestamp: {s:?}"))),
    }
}

fn required_time(
    what: &str,
    field: &str,
    v: Option<&String>,
) -> Result<OffsetDateTime, ImportError> {
    time_of(what, field, v)?.ok_or_else(|| invalid(what, format!("{field} is missing")))
}

fn attribute<const MAX: usize>(
    what: &str,
    field: &str,
    v: Option<String>,
) -> Result<Option<String>, ImportError> {
    match nonempty(v) {
        None => Ok(None),
        Some(s) => Attribute::<MAX, false>::new(s.as_str())
            .map(|_| Some(s))
            .map_err(|e| invalid(what, format!("{field}: {e}"))),
    }
}

/// Validate a host daemon.
fn plan_daemon(d: &PyDaemon, id: Uuid) -> Result<PlannedDaemon, ImportError> {
    let what = format!("daemon host/{}", d.name);
    DaemonName::new(d.name.as_str()).map_err(|e| invalid(&what, e))?;
    let key = PublicKey::parse(d.public_key.trim())
        .map_err(|e| invalid(&what, format!("public_key: {e}")))?;
    let paired_at = required_time(&what, "paired_at", d.paired_at.as_ref())?;
    Ok(PlannedDaemon {
        id: DaemonId::from_uuid(id),
        name: d.name.clone(),
        // The canonical text: heartbeats compare the stored key as text.
        public_key: key.to_text(),
        paired_at,
        last_seen_at: time_of(&what, "last_seen_at", d.last_seen_at.as_ref())?,
        created_at: time_of(&what, "created_at", d.created_at.as_ref())?.unwrap_or(paired_at),
    })
}

/// Validate an agent to carry; `warnings` gets what the operator should see.
fn plan_agent(
    a: PyAgent,
    id: Uuid,
    a2a: &A2aConfig,
    warnings: &mut Vec<String>,
) -> Result<PlannedAgent, ImportError> {
    let what = format!("agent {}", a.name);
    AgentNameInput::new(a.name.as_str()).map_err(|e| invalid(&what, e))?;
    if a.name == "operator" {
        return Err(invalid(
            &what,
            "this broker keeps the name 'operator' for the admin panel's chat; \
             rename the agent in the Python broker and export again",
        ));
    }
    let kind = match a.kind.as_deref().unwrap_or("service") {
        "service" => AgentKind::Service,
        "ephemeral" => AgentKind::Ephemeral,
        other => return Err(invalid(&what, format!("unknown kind {other:?}"))),
    };
    match a.placement.as_deref().unwrap_or("host") {
        "host" => {}
        other => return Err(invalid(&what, format!("unknown placement {other:?}"))),
    }
    KeyId::parse(&a.key_id).ok_or_else(|| invalid(&what, "key_id is not 12 lowercase hex"))?;
    SecretHash::parse(&a.api_key_hash)
        .ok_or_else(|| invalid(&what, "api_key_hash is not a sha256 hex digest"))?;
    let disabled =
        boolean(&a.disabled).ok_or_else(|| invalid(&what, "disabled is not a boolean"))?;
    let managed = boolean(&a.lldap_managed)
        .ok_or_else(|| invalid(&what, "lldap_managed is not a boolean"))?;

    let mut webhook_url = nonempty(a.webhook_url);
    let mut webhook_secret = nonempty(a.webhook_secret);
    if kind != AgentKind::Service && (webhook_url.is_some() || webhook_secret.is_some()) {
        warnings.push(format!(
            "{what}: an ephemeral agent's webhook is dropped (only service agents get pings)"
        ));
        webhook_url = None;
        webhook_secret = None;
    }
    if let Some(url) = &webhook_url {
        WebhookUrl::new(url.as_str()).map_err(|e| invalid(&what, format!("webhook_url: {e}")))?;
        if crate::a2a::webhook::check_url(a2a, url).is_err() {
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_default();
            warnings.push(format!(
                "{what}: its webhook is plain http to {host:?}, not in A2A_WEBHOOK_HTTP_HOSTS: \
                 no pings until the host is listed or the URL changed (agent-auth admin set-webhook)"
            ));
        }
        if webhook_secret.is_none() {
            warnings.push(format!(
                "{what}: a webhook without a signing secret of its own gets no pings \
                 (agent-auth admin rotate-webhook-secret)"
            ));
        }
    }
    if let Some(s) = &webhook_secret
        && s.chars().count() > 64
    {
        return Err(invalid(
            &what,
            "webhook_secret is longer than 64 characters",
        ));
    }

    let lldap = nonempty(a.lldap_username);
    let lldap_username = match lldap {
        Some(u) if managed => {
            let expected = format!("{MANAGED_PREFIX}{}", a.name).to_lowercase();
            if u.to_lowercase() == expected {
                warnings.push(format!(
                    "{what}: its broker-managed LLDAP account {u} is adopted again at its next \
                     homelab grant, with a new password"
                ));
            } else {
                warnings.push(format!(
                    "{what}: its broker-managed LLDAP account {u} is not {expected}: it is not \
                     adopted; a new account {expected} is made at its next homelab grant, \
                     and {u} is left as it is in LLDAP"
                ));
            }
            None
        }
        Some(u) => {
            Text::<0, 128>::new(u.as_str())
                .map_err(|e| invalid(&what, format!("lldap_username: {e}")))?;
            Some(u)
        }
        None => None,
    };

    Ok(PlannedAgent {
        id: AgentId::from_uuid(id),
        description: a.description.unwrap_or_default(),
        key_id: a.key_id,
        api_key_hash: a.api_key_hash,
        kind,
        webhook_url,
        webhook_secret,
        lldap_username,
        disabled,
        runtime: attribute::<16>(&what, "runtime", a.runtime)?,
        project: attribute::<64>(&what, "project", a.project)?,
        host: attribute::<64>(&what, "host", a.host)?,
        lease_expires_at: time_of(&what, "lease_expires_at", a.lease_expires_at.as_ref())?,
        last_seen_at: time_of(&what, "last_seen_at", a.last_seen_at.as_ref())?,
        // Only service agents listen (set_kind clears it for the others).
        last_listen_at: if kind == AgentKind::Service {
            time_of(&what, "last_listen_at", a.last_listen_at.as_ref())?
        } else {
            None
        },
        created_at: required_time(&what, "created_at", a.created_at.as_ref())?,
        name: a.name,
    })
}

/// Parse and validate an export; nothing is written.
pub fn plan(text: &str, a2a: &A2aConfig) -> Result<Plan, ImportError> {
    let file: ExportFile =
        serde_json::from_str(text).map_err(|e| invalid("the export", e.to_string()))?;
    if file.format != FORMAT {
        return Err(invalid(
            "the export",
            format!("format {:?}, expected {FORMAT:?}", file.format),
        ));
    }
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();

    let mut py_daemons = Vec::new();
    for (i, v) in file.daemons.into_iter().enumerate() {
        let name = row_name(&v, i);
        let d: PyDaemon =
            serde_json::from_value(v).map_err(|e| invalid(format!("daemon {name}"), e))?;
        let id =
            uuid(&d.id).ok_or_else(|| invalid(format!("daemon {name}"), "id is not a uuid"))?;
        py_daemons.push((id, d));
    }
    let daemons_by_id: HashMap<Uuid, String> = py_daemons
        .iter()
        .map(|(id, d)| (*id, format!("{}/{}", d.role, d.name)))
        .collect();
    let mut daemons = Vec::new();
    let mut seen_daemons = BTreeSet::new();
    for (id, d) in &py_daemons {
        if !seen_daemons.insert((d.role.clone(), d.name.clone())) {
            return Err(invalid(
                format!("daemon {}/{}", d.role, d.name),
                "appears twice",
            ));
        }
        match DaemonRole::parse(&d.role) {
            Some(DaemonRole::Host) => daemons.push(plan_daemon(d, *id)?),
            Some(DaemonRole::Sandbox) => skipped.push(Skipped {
                what: format!("daemon sandbox/{}", d.name),
                reason: "an agent VM: pair it again (agent-auth admin daemon-pair --role sandbox)"
                    .to_owned(),
            }),
            None => {
                return Err(invalid(
                    format!("daemon {}", d.name),
                    format!("unknown role {:?}", d.role),
                ));
            }
        }
    }
    if daemons_by_id.len() != py_daemons.len() {
        return Err(invalid("the export", "two daemons share an id"));
    }

    let mut py_agents = Vec::new();
    for (i, v) in file.agents.into_iter().enumerate() {
        let name = row_name(&v, i);
        let a: PyAgent =
            serde_json::from_value(v).map_err(|e| invalid(format!("agent {name}"), e))?;
        let id = uuid(&a.id).ok_or_else(|| invalid(format!("agent {name}"), "id is not a uuid"))?;
        py_agents.push((id, a));
    }
    let mut carried = Vec::new();
    {
        let by_id: HashMap<Uuid, &PyAgent> = py_agents.iter().map(|(id, a)| (*id, a)).collect();
        if by_id.len() != py_agents.len() {
            return Err(invalid("the export", "two agents share an id"));
        }
        for (i, (_, a)) in py_agents.iter().enumerate() {
            match skip_reason(a, &by_id, &daemons_by_id) {
                Some(reason) => skipped.push(Skipped {
                    what: format!("agent {}", a.name),
                    reason,
                }),
                None => carried.push(i),
            }
        }
    }
    let mut agents = Vec::new();
    let mut slots: Vec<Option<(Uuid, PyAgent)>> = py_agents.into_iter().map(Some).collect();
    for i in carried {
        let Some((id, a)) = slots.get_mut(i).and_then(Option::take) else {
            continue;
        };
        agents.push(plan_agent(a, id, a2a, &mut warnings)?);
    }

    // What the database's unique indexes would refuse, named here.
    let mut names = BTreeMap::new();
    let mut key_ids = BTreeMap::new();
    let mut lldap = BTreeMap::new();
    for a in &agents {
        if let Some(other) = names.insert(a.name.as_str(), a.name.as_str()) {
            return Err(invalid(format!("agent {other}"), "appears twice"));
        }
        if let Some(other) = key_ids.insert(a.key_id.as_str(), a.name.as_str()) {
            return Err(invalid(
                format!("agent {}", a.name),
                format!("has the same key id as {other}"),
            ));
        }
        if let Some(u) = &a.lldap_username
            && let Some(other) = lldap.insert(u.to_lowercase(), a.name.as_str())
        {
            return Err(invalid(
                format!("agent {}", a.name),
                format!("shares its LLDAP account with {other} (one account per agent)"),
            ));
        }
    }
    Ok(Plan {
        daemons,
        agents,
        skipped,
        warnings,
    })
}

// ------------------------------------------------------------ the write

/// Write a plan into an empty database (no agent but this broker's
/// operator row, no daemon), in one transaction.
pub async fn apply(store: &Store, plan: &Plan) -> Result<(), ImportError> {
    let tx = store
        .begin()
        .await
        .map_err(store_err("opening a transaction"))?;
    agents::lock_for_import(&tx)
        .await
        .map_err(store_err("locking the agents and daemons"))?;
    let present = agents::list(&tx)
        .await
        .map_err(store_err("reading the agents"))?;
    let present: Vec<&str> = present
        .iter()
        .filter(|a| a.kind != AgentKind::Operator)
        .map(|a| a.name.as_str())
        .collect();
    let paired = daemons::list(&tx)
        .await
        .map_err(store_err("reading the daemons"))?;
    if !present.is_empty() || !paired.is_empty() {
        return Err(ImportError::Refused(format!(
            "the database is not empty ({} agent(s), {} daemon(s)): import only into a new \
             database, before any agent is registered or daemon paired",
            present.len(),
            paired.len()
        )));
    }
    let now = OffsetDateTime::now_utc();
    for d in &plan.daemons {
        let what = format!("daemon host/{}", d.name);
        daemons::import(
            &tx,
            &ImportedDaemon {
                id: d.id,
                role: DaemonRole::Host,
                name: &d.name,
                public_key: &d.public_key,
                paired_at: d.paired_at,
                last_seen_at: d.last_seen_at,
                created_at: d.created_at,
            },
            now,
        )
        .await
        .map_err(store_err(what))?;
    }
    for a in &plan.agents {
        let what = format!("agent {}", a.name);
        agents::import(
            &tx,
            &ImportedAgent {
                id: a.id,
                name: &a.name,
                description: &a.description,
                key_id: &a.key_id,
                api_key_hash: &a.api_key_hash,
                kind: a.kind,
                webhook_url: a.webhook_url.as_deref(),
                webhook_secret: a.webhook_secret.as_deref(),
                lldap_username: a.lldap_username.as_deref(),
                disabled: a.disabled,
                // Only the operator disabled a hand-registered agent (leases
                // and unpairing are for minted ones): a renewal never undoes it.
                disabled_reason: a.disabled.then_some(DisableReason::Operator),
                runtime: a.runtime.as_deref(),
                project: a.project.as_deref(),
                host: a.host.as_deref(),
                placement: Placement::Host,
                lease_expires_at: a.lease_expires_at,
                last_seen_at: a.last_seen_at,
                last_listen_at: a.last_listen_at,
                created_at: a.created_at,
            },
        )
        .await
        .map_err(store_err(what))?;
    }
    // Every row back through the typed parsers before the commit.
    let back = agents::list(&tx)
        .await
        .map_err(store_err("reading the imported agents back"))?;
    let back_daemons = daemons::list(&tx)
        .await
        .map_err(store_err("reading the imported daemons back"))?;
    let agents_back = back
        .iter()
        .filter(|a| a.kind != AgentKind::Operator)
        .count();
    if agents_back != plan.agents.len() || back_daemons.len() != plan.daemons.len() {
        return Err(ImportError::Refused(
            "the rows read back do not match what was written".to_owned(),
        ));
    }
    tx.commit().await.map_err(store_err("committing"))?;
    Ok(())
}

// -------------------------------------------------------------- the CLI

/// `import-python [--dry-run] <export.json | ->`; returns the summary.
/// The database is the broker's own (`DATABASE_URL`, migrated first). A
/// broker may be running on it (`kubectl exec`), as long as nothing has
/// registered an agent or paired a daemon yet.
pub async fn main(env: &Env, args: &[String]) -> anyhow::Result<String> {
    let mut dry_run = false;
    let mut path = None;
    for a in args {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Ok(format!("{USAGE}\n")),
            s if s.starts_with('-') && s != "-" => anyhow::bail!("unknown option {s:?}\n{USAGE}"),
            s if path.is_none() => path = Some(s),
            _ => anyhow::bail!("{USAGE}"),
        }
    }
    let path = path.ok_or_else(|| anyhow::anyhow!("{USAGE}"))?;
    let text = if path == "-" {
        std::io::read_to_string(std::io::stdin()).context("reading the export from stdin")?
    } else {
        std::fs::read_to_string(Path::new(path)).with_context(|| format!("reading {path}"))?
    };
    let lookup = |k: &str| env.get(k).map(str::to_owned);
    let a2a = A2aConfig::from_lookup(lookup).map_err(|e| anyhow::anyhow!("a2a: {e}"))?;
    let plan = plan(&text, &a2a)?;
    if dry_run {
        return Ok(plan.summary(true));
    }
    let config = Config::from_env(env)?;
    crate::config::check_database_url(
        config.database_url.expose(),
        env.flag("DATABASE_ALLOW_INSECURE", false)?,
    )?;
    let store = Store::connect(config.database_url.expose(), 2)
        .await
        .context("connecting to PostgreSQL")?;
    store.migrate().await.context("migrating the database")?;
    apply(&store, &plan).await?;
    Ok(plan.summary(false))
}

#[cfg(test)]
mod tests;
