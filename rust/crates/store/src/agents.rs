//! `agents`: identities. Agents are never deleted (only disabled, renamed).

use std::fmt;

use agent_auth_core::containment::{AgentFacts, AgentKind, Placement};
use agent_auth_core::{AgentId, DaemonId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{StoreError, Tx};

const T: &str = "agents";

/// An agent row. `Debug` leaves out the key hash, webhook secret and the
/// LLDAP password ciphertext.
#[derive(Clone)]
pub struct AgentRow {
    pub id: AgentId,
    pub name: String,
    pub description: String,
    pub key_id: String,
    /// sha256 hex of the API key's secret.
    pub api_key_hash: String,
    pub webhook_url: Option<String>,
    /// Plaintext HMAC key for webhook pings.
    pub webhook_secret: Option<String>,
    pub lldap_username: Option<String>,
    pub lldap_password_encrypted: Option<String>,
    pub disabled: bool,
    /// Why it is disabled (`None` while enabled, or unknown).
    pub disabled_reason: Option<DisableReason>,
    pub kind: AgentKind,
    pub last_seen_at: Option<OffsetDateTime>,
    pub last_listen_at: Option<OffsetDateTime>,
    pub parent_agent_id: Option<AgentId>,
    pub sandbox_id: Option<DaemonId>,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for AgentRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("disabled", &self.disabled)
            .field("disabled_reason", &self.disabled_reason)
            .field("runtime", &self.runtime)
            .field("project", &self.project)
            .field("host", &self.host)
            .field("placement", &self.placement)
            .field("sandbox_id", &self.sandbox_id)
            .finish_non_exhaustive()
    }
}

impl AgentRow {
    /// What containment entries and policy rules match on.
    #[must_use]
    pub fn facts(&self) -> AgentFacts<'_> {
        AgentFacts {
            name: &self.name,
            kind: self.kind,
            runtime: self.runtime.as_deref(),
            project: self.project.as_deref(),
            host: self.host.as_deref(),
            placement: self.placement,
            ancestors: &[],
        }
    }

    /// [`AgentRow::facts`] with the agents that minted it (see [`chain`]),
    /// as containment matches on them.
    #[must_use]
    pub fn facts_with<'a>(&'a self, ancestors: &'a [AgentFacts<'a>]) -> AgentFacts<'a> {
        AgentFacts {
            ancestors,
            ..self.facts()
        }
    }

    /// The agent as policy patterns, zones and rules see it.
    #[must_use]
    pub fn policy_ref(&self) -> agent_auth_core::policy::AgentRef<'_> {
        agent_auth_core::policy::AgentRef {
            name: &self.name,
            runtime: self.runtime.as_deref(),
            project: self.project.as_deref(),
            host: self.host.as_deref(),
            placement: self.placement,
            kind: self.kind,
        }
    }
}

/// Why an agent is disabled (sandboxd B-1, B-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisableReason {
    /// The operator (admin endpoint or panel). A renewal never undoes it.
    Operator,
    /// Its lease, or an ancestor's, ran out. Renewing re-enables it.
    Lease,
    /// Its agent VM was unpaired.
    Unpaired,
}

impl DisableReason {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DisableReason::Operator => "operator",
            DisableReason::Lease => "lease",
            DisableReason::Unpaired => "unpaired",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<DisableReason> {
        match text {
            "operator" => Some(DisableReason::Operator),
            "lease" => Some(DisableReason::Lease),
            "unpaired" => Some(DisableReason::Unpaired),
            _ => None,
        }
    }
}

pub(crate) struct RawAgent {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub key_id: String,
    pub api_key_hash: String,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub lldap_username: Option<String>,
    pub lldap_password_encrypted: Option<String>,
    pub disabled: bool,
    pub kind: String,
    pub last_seen_at: Option<OffsetDateTime>,
    pub last_listen_at: Option<OffsetDateTime>,
    pub parent_agent_id: Option<Uuid>,
    pub sandbox_id: Option<Uuid>,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: String,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub disabled_reason: Option<String>,
}

impl TryFrom<RawAgent> for AgentRow {
    type Error = StoreError;
    fn try_from(r: RawAgent) -> Result<AgentRow, StoreError> {
        Ok(AgentRow {
            id: AgentId::from_uuid(r.id),
            kind: AgentKind::parse(&r.kind)
                .ok_or_else(|| StoreError::corrupt(T, format!("kind {:?}", r.kind)))?,
            placement: Placement::parse(&r.placement)
                .ok_or_else(|| StoreError::corrupt(T, format!("placement {:?}", r.placement)))?,
            disabled_reason: match r.disabled_reason.as_deref() {
                None => None,
                Some(t) => Some(
                    DisableReason::parse(t)
                        .ok_or_else(|| StoreError::corrupt(T, format!("disabled_reason {t:?}")))?,
                ),
            },
            name: r.name,
            description: r.description,
            key_id: r.key_id,
            api_key_hash: r.api_key_hash,
            webhook_url: r.webhook_url,
            webhook_secret: r.webhook_secret,
            lldap_username: r.lldap_username,
            lldap_password_encrypted: r.lldap_password_encrypted,
            disabled: r.disabled,
            last_seen_at: r.last_seen_at,
            last_listen_at: r.last_listen_at,
            parent_agent_id: r.parent_agent_id.map(AgentId::from_uuid),
            sandbox_id: r.sandbox_id.map(DaemonId::from_uuid),
            runtime: r.runtime,
            project: r.project,
            host: r.host,
            lease_expires_at: r.lease_expires_at,
            created_at: r.created_at,
        })
    }
}

fn rows(raw: Vec<RawAgent>) -> Result<Vec<AgentRow>, StoreError> {
    raw.into_iter().map(AgentRow::try_from).collect()
}

fn opt(raw: Option<RawAgent>) -> Result<Option<AgentRow>, StoreError> {
    raw.map(AgentRow::try_from).transpose()
}

/// A new agent row.
#[derive(Debug, Clone)]
pub struct NewAgent<'a> {
    pub id: AgentId,
    pub name: &'a str,
    pub description: &'a str,
    pub key_id: &'a str,
    pub api_key_hash: &'a str,
    pub kind: AgentKind,
    pub webhook_url: Option<&'a str>,
    pub webhook_secret: Option<&'a str>,
    pub lldap_username: Option<&'a str>,
    pub parent_agent_id: Option<AgentId>,
    pub sandbox_id: Option<DaemonId>,
    pub runtime: Option<&'a str>,
    pub project: Option<&'a str>,
    pub host: Option<&'a str>,
    pub placement: Placement,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub last_seen_at: Option<OffsetDateTime>,
    pub now: OffsetDateTime,
}

pub async fn insert(tx: &Tx<'_>, a: &NewAgent<'_>) -> Result<AgentRow, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        r#"INSERT INTO agents (id, name, description, key_id, api_key_hash, kind, webhook_url,
               webhook_secret, lldap_username, parent_agent_id, sandbox_id, runtime, project, host,
               placement, lease_expires_at, last_seen_at, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
           RETURNING *"#,
        Uuid::from(a.id),
        a.name,
        a.description,
        a.key_id,
        a.api_key_hash,
        a.kind.as_str(),
        a.webhook_url,
        a.webhook_secret,
        a.lldap_username,
        a.parent_agent_id.map(Uuid::from),
        a.sandbox_id.map(Uuid::from),
        a.runtime,
        a.project,
        a.host,
        a.placement.as_str(),
        a.lease_expires_at,
        a.last_seen_at,
        a.now,
    )
    .fetch_one(&mut **c)
    .await?;
    raw.try_into()
}

pub async fn get(tx: &Tx<'_>, id: AgentId) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// The row, locked against concurrent updates (disable, rename, rotate)
/// until the transaction ends.
pub async fn get_for_share(tx: &Tx<'_>, id: AgentId) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE id = $1 FOR SHARE",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// Several rows, share-locked in ascending id order (the crate's lock
/// order for agents).
pub async fn get_many_for_share(tx: &Tx<'_>, ids: &[AgentId]) -> Result<Vec<AgentRow>, StoreError> {
    let ids: Vec<Uuid> = ids.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE id = ANY($1) ORDER BY id FOR SHARE",
        &ids
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

pub async fn get_for_update(tx: &Tx<'_>, id: AgentId) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE id = $1 FOR UPDATE",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

pub async fn by_name(tx: &Tx<'_>, name: &str) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(RawAgent, "SELECT * FROM agents WHERE name = $1", name)
        .fetch_optional(&mut **c)
        .await?;
    opt(raw)
}

/// API-key lookup (`aa_<key_id>_<secret>`). The caller verifies the hash.
pub async fn by_key_id(tx: &Tx<'_>, key_id: &str) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(RawAgent, "SELECT * FROM agents WHERE key_id = $1", key_id)
        .fetch_optional(&mut **c)
        .await?;
    opt(raw)
}

/// Every agent, by name (admin list, containment sweeps, lockdown).
pub async fn list(tx: &Tx<'_>) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(RawAgent, "SELECT * FROM agents ORDER BY name")
        .fetch_all(&mut **c)
        .await?;
    rows(raw)
}

/// Enabled agents, by name (projects listing, a2a graph).
pub async fn list_enabled(tx: &Tx<'_>) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE NOT disabled ORDER BY name"
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Enabled service agents other than `except`, by name: a2a peers for the
/// catalog (`except` = the caller) and the operator chat.
pub async fn list_peers(tx: &Tx<'_>, except: Option<AgentId>) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents
         WHERE kind = 'service' AND NOT disabled AND ($1::uuid IS NULL OR id <> $1)
         ORDER BY name",
        except.map(Uuid::from)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Agents of one agent VM.
pub async fn list_in_sandbox(tx: &Tx<'_>, sandbox: DaemonId) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE sandbox_id = $1 ORDER BY name",
        Uuid::from(sandbox)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Web-UI connector agents (`runtime = 'web'`).
pub async fn list_web(tx: &Tx<'_>) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE runtime = 'web' ORDER BY name"
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Agents created at or after `since`, oldest first (audit feed).
pub async fn created_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    limit: i64,
) -> Result<Vec<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawAgent,
        "SELECT * FROM agents WHERE created_at >= $1 ORDER BY created_at LIMIT $2",
        since,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// `(id, name)` for a set of ids (log views).
pub async fn names(tx: &Tx<'_>, ids: &[AgentId]) -> Result<Vec<(AgentId, String)>, StoreError> {
    let ids: Vec<Uuid> = ids.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    let out = sqlx::query!("SELECT id, name FROM agents WHERE id = ANY($1)", &ids)
        .fetch_all(&mut **c)
        .await?;
    Ok(out
        .into_iter()
        .map(|r| (AgentId::from_uuid(r.id), r.name))
        .collect())
}

/// Direct children of a minted-agent tree node.
pub async fn children(tx: &Tx<'_>, parent: AgentId) -> Result<Vec<AgentId>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT id FROM agents WHERE parent_agent_id = $1",
        Uuid::from(parent)
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(AgentId::from_uuid).collect())
}

/// Enabled minted agents whose lease has run out.
pub async fn lease_expired(tx: &Tx<'_>, now: OffsetDateTime) -> Result<Vec<AgentId>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT id FROM agents
         WHERE lease_expires_at IS NOT NULL AND lease_expires_at <= $1 AND NOT disabled",
        now
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(AgentId::from_uuid).collect())
}

/// The operator row (kind `operator`), created on first use. `None` when
/// another agent already holds the name `operator` (HTTP 409 upstream).
/// Race-free: two first uses insert at most one row (a2a B11).
pub async fn ensure_operator(
    tx: &Tx<'_>,
    id: AgentId,
    key_id: &str,
    now: OffsetDateTime,
) -> Result<Option<AgentRow>, StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        "INSERT INTO agents (id, name, description, key_id, api_key_hash, kind, created_at)
         VALUES ($1, 'operator', 'the operator, writing from the admin panel', $2, repeat('!', 64),
                 'operator', $3)
         ON CONFLICT DO NOTHING",
        Uuid::from(id),
        key_id,
        now
    )
    .execute(&mut **c)
    .await?;
    let raw = sqlx::query_as!(RawAgent, "SELECT * FROM agents WHERE kind = 'operator'")
        .fetch_optional(&mut **c)
        .await?;
    opt(raw)
}

/// Record activity: `last_seen_at = now` unless it was written after
/// `unless_after` (the 20 s throttle; pass `now` for an unthrottled touch).
pub async fn touch_seen(
    tx: &Tx<'_>,
    id: AgentId,
    now: OffsetDateTime,
    unless_after: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET last_seen_at = $2
         WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < $3)",
        Uuid::from(id),
        now,
        unless_after
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// `last_listen_at` (a2a inbound surfaces only), throttled like `touch_seen`.
pub async fn mark_listening(
    tx: &Tx<'_>,
    id: AgentId,
    now: OffsetDateTime,
    unless_after: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET last_listen_at = $2
         WHERE id = $1 AND (last_listen_at IS NULL OR last_listen_at < $3)",
        Uuid::from(id),
        now,
        unless_after
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Policy attributes (operator-set). Not for the operator row.
pub async fn set_attributes(
    tx: &Tx<'_>,
    id: AgentId,
    runtime: Option<&str>,
    project: Option<&str>,
    host: Option<&str>,
    placement: Placement,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET runtime = $2, project = $3, host = $4, placement = $5
         WHERE id = $1 AND kind <> 'operator'",
        Uuid::from(id),
        runtime,
        project,
        host,
        placement.as_str()
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub async fn set_description(
    tx: &Tx<'_>,
    id: AgentId,
    description: &str,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET description = $2 WHERE id = $1",
        Uuid::from(id),
        description
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Rename (the rules and a2a grants that name the agent are rewritten by
/// `rules::rename_agent` and `grants::rename_a2a_target` in the same tx).
pub async fn rename(tx: &Tx<'_>, id: AgentId, new_name: &str) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET name = $2 WHERE id = $1 AND kind <> 'operator'",
        Uuid::from(id),
        new_name
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Replace the API key (the old one stops authenticating at once).
pub async fn set_key(
    tx: &Tx<'_>,
    id: AgentId,
    key_id: &str,
    api_key_hash: &str,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET key_id = $2, api_key_hash = $3 WHERE id = $1 AND kind <> 'operator'",
        Uuid::from(id),
        key_id,
        api_key_hash
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Webhook URL and secret (service agents only; a CHECK refuses others).
pub async fn set_webhook(
    tx: &Tx<'_>,
    id: AgentId,
    url: Option<&str>,
    secret: Option<&str>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET webhook_url = $2, webhook_secret = $3 WHERE id = $1",
        Uuid::from(id),
        url,
        secret
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

pub async fn set_webhook_secret(
    tx: &Tx<'_>,
    id: AgentId,
    secret: &str,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET webhook_secret = $2 WHERE id = $1",
        Uuid::from(id),
        secret
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Change kind between service and ephemeral. Leaving `service` clears the
/// webhook and `last_listen_at`. Never makes or unmakes the operator.
pub async fn set_kind(tx: &Tx<'_>, id: AgentId, kind: AgentKind) -> Result<bool, StoreError> {
    if kind == AgentKind::Operator {
        return Ok(false);
    }
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET kind = $2,
             webhook_url = CASE WHEN $2 = 'service' THEN webhook_url END,
             webhook_secret = CASE WHEN $2 = 'service' THEN webhook_secret END,
             last_listen_at = CASE WHEN $2 = 'service' THEN last_listen_at END
         WHERE id = $1 AND kind <> 'operator'",
        Uuid::from(id),
        kind.as_str()
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Disabling takes the containment lock exclusively first (the crate's
/// lock order), so it waits for in-flight checks instead of deadlocking
/// with them.
pub async fn set_disabled(tx: &Tx<'_>, id: AgentId, disabled: bool) -> Result<bool, StoreError> {
    if disabled {
        crate::lockdown::lock_exclusive(tx).await?;
    }
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET disabled = $2,
             disabled_reason = CASE WHEN $2 THEN disabled_reason END
         WHERE id = $1",
        Uuid::from(id),
        disabled
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// A broker-managed LLDAP account (username and the wrapped password).
pub async fn set_lldap(
    tx: &Tx<'_>,
    id: AgentId,
    username: Option<&str>,
    password_encrypted: Option<&str>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET lldap_username = $2, lldap_password_encrypted = $3 WHERE id = $1",
        Uuid::from(id),
        username,
        password_encrypted
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Renew a minted agent's lease. Does not clear a disable (sandboxd B-1):
/// re-enabling is the caller's explicit decision via `set_disabled`.
pub async fn set_lease(
    tx: &Tx<'_>,
    id: AgentId,
    lease_expires_at: Option<OffsetDateTime>,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET lease_expires_at = $2 WHERE id = $1",
        Uuid::from(id),
        lease_expires_at
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Adopt the orchestrator of a (re-)paired agent VM.
pub async fn adopt_orchestrator(
    tx: &Tx<'_>,
    id: AgentId,
    sandbox: DaemonId,
    host: &str,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET sandbox_id = $2, host = $3, placement = 'sandbox', disabled = false,
             disabled_reason = NULL
         WHERE id = $1 AND runtime = 'orchestrator' AND (sandbox_id IS NULL OR sandbox_id = $2)",
        Uuid::from(id),
        Uuid::from(sandbox),
        host
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Re-enable an agent whose lease ran out, with a new key and lease (a
/// renewal: sandboxd B-1, B-8). Only an agent disabled for `lease`; false
/// otherwise.
pub async fn reenable_after_lease(
    tx: &Tx<'_>,
    id: AgentId,
    key_id: &str,
    api_key_hash: &str,
    lease_expires_at: OffsetDateTime,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE agents SET disabled = false, disabled_reason = NULL, key_id = $2,
             api_key_hash = $3, lease_expires_at = $4
         WHERE id = $1 AND disabled AND disabled_reason = 'lease'",
        Uuid::from(id),
        key_id,
        api_key_hash,
        lease_expires_at
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// The longest parent chain followed (minting nests a level or two).
pub const MAX_CHAIN: usize = 64;

/// The agents that minted `agent`, nearest first, from `by_id`; stops at a
/// cycle (impossible by the schema) or [`MAX_CHAIN`] levels.
#[must_use]
pub fn chain_in<'a>(
    agent: &AgentRow,
    by_id: &'a std::collections::HashMap<AgentId, AgentRow>,
) -> Vec<&'a AgentRow> {
    let mut out: Vec<&'a AgentRow> = Vec::new();
    let mut next = agent.parent_agent_id;
    while let Some(id) = next {
        if out.len() >= MAX_CHAIN || id == agent.id || out.iter().any(|a| a.id == id) {
            break;
        }
        let Some(p) = by_id.get(&id) else { break };
        out.push(p);
        next = p.parent_agent_id;
    }
    out
}

/// The agents that minted `agent`, nearest first, read one by one.
pub async fn chain(tx: &Tx<'_>, agent: &AgentRow) -> Result<Vec<AgentRow>, StoreError> {
    let mut out: Vec<AgentRow> = Vec::new();
    let mut next = agent.parent_agent_id;
    while let Some(id) = next {
        if out.len() >= MAX_CHAIN || id == agent.id || out.iter().any(|a| a.id == id) {
            break;
        }
        let Some(p) = get(tx, id).await? else { break };
        next = p.parent_agent_id;
        out.push(p);
    }
    Ok(out)
}
