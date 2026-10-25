//! `grants`: what was given, for how long, and the grant kernel.
//!
//! - A grant row exists only through [`begin`], which takes the request in
//!   PROVISIONING and a [`NotHeld`] proof from the same transaction, and
//!   inserts it PROVISIONING: the durable record that an external change
//!   may exist, before the provisioner runs.
//! - What `begin` returns, and what [`load_provisioning`] returns in the
//!   finishing transaction (locked `FOR UPDATE`, still PROVISIONING), is a
//!   [`ProvisioningGrant`] borrowing its transaction. [`activate`]
//!   (PROVISIONING → ACTIVE, which also needs a `NotHeld` from that
//!   transaction) and [`fail_provisioning`] consume it.
//! - Every status change is a compare-and-swap on the current status (core
//!   B-9: the Python assigned blindly), so a reaped grant is never
//!   re-activated and a revoke racing an expiry ends the grant once.
//! - [`issuable`] is the only way to an [`IssuableGrant`], which provisioners
//!   require to hand out a credential.

use std::marker::PhantomData;

use agent_auth_core::lifecycle::state;
use agent_auth_core::{
    AgentId, Authority, GrantId, GrantStatus, Platform, RequestId, SessionId, ThreadId,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::lockdown::{self, Held, NotHeld};
use crate::requests::Request;
use crate::values::{self, Delegation};
use crate::{Outcome, StoreError, Tx};

const T: &str = "grants";

/// A grant row. Made only by this crate (`#[non_exhaustive]`): a value of
/// this type was read from the database.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GrantRow {
    pub id: GrantId,
    pub request_id: RequestId,
    pub agent_id: AgentId,
    pub session_id: Option<SessionId>,
    pub delegation: Option<Delegation>,
    pub platform: Platform,
    pub resource: String,
    pub authority: Authority,
    pub granted_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub status: GrantStatus,
    /// Provisioner-owned (may hold ciphertext).
    pub provisioner_state: Value,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoke_reason: Option<String>,
    pub created_at: OffsetDateTime,
}

impl GrantRow {
    /// Active and unexpired at `now`.
    #[must_use]
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.status == GrantStatus::Active && self.expires_at > now
    }
}

pub(crate) struct RawGrant {
    id: Uuid,
    request_id: Uuid,
    agent_id: Uuid,
    session_id: Option<Uuid>,
    delegation_thread_id: Option<Uuid>,
    delegator_agent_id: Option<Uuid>,
    platform: String,
    resource: String,
    authority: Value,
    granted_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    status: String,
    provisioner_state: Value,
    revoked_at: Option<OffsetDateTime>,
    revoke_reason: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<RawGrant> for GrantRow {
    type Error = StoreError;
    fn try_from(r: RawGrant) -> Result<GrantRow, StoreError> {
        let platform = values::platform(T, &r.platform)?;
        Ok(GrantRow {
            id: GrantId::from_uuid(r.id),
            request_id: RequestId::from_uuid(r.request_id),
            agent_id: AgentId::from_uuid(r.agent_id),
            session_id: r.session_id.map(SessionId::from_uuid),
            delegation: Delegation::from_columns(T, r.delegation_thread_id, r.delegator_agent_id)?,
            authority: values::authority(T, platform, &r.authority)?,
            platform,
            resource: r.resource,
            granted_at: r.granted_at,
            expires_at: r.expires_at,
            status: values::grant_status(&r.status)?,
            provisioner_state: r.provisioner_state,
            revoked_at: r.revoked_at,
            revoke_reason: r.revoke_reason,
            created_at: r.created_at,
        })
    }
}

fn rows(raw: Vec<RawGrant>) -> Result<Vec<GrantRow>, StoreError> {
    raw.into_iter().map(GrantRow::try_from).collect()
}

fn opt(raw: Option<RawGrant>) -> Result<Option<GrantRow>, StoreError> {
    raw.map(GrantRow::try_from).transpose()
}

fn ids(raw: Vec<Uuid>) -> Vec<GrantId> {
    raw.into_iter().map(GrantId::from_uuid).collect()
}

// -------------------------------------------------------------- kernel

/// Why [`begin`] made no grant (the request then goes PROVISION_FAILED).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BeginRefused {
    /// The delegation thread is gone, not open, or its backing grant is
    /// not active and unexpired.
    #[error("delegation thread is no longer open")]
    DelegationClosed,
    /// The delegator has been disabled since (core B-15).
    #[error("delegator agent is disabled")]
    DelegatorDisabled,
}

/// Insert the PROVISIONING grant for a request being provisioned, by an
/// agent proven not held in this transaction. Resource and authority are
/// the human's edit if any, else the request's; `expires_at = now +
/// approved duration`, and a delegated grant never outlives its thread's
/// backing grant (delegator, backing grant and thread are share-locked
/// until commit, in the crate's lock order).
pub async fn begin<'t>(
    tx: &'t Tx<'_>,
    request: &Request<state::Provisioning>,
    not_held: &NotHeld<'_>,
    id: GrantId,
    now: OffsetDateTime,
) -> Outcome<ProvisioningGrant<'t>, BeginRefused> {
    let row = request.row();
    not_held.verify(tx, row.agent_id)?;
    let authority = row
        .final_authority()
        .ok_or_else(|| StoreError::corrupt("access_requests", "provisioning without authority"))?;
    let secs = row
        .approved_duration_secs
        .ok_or_else(|| StoreError::corrupt("access_requests", "provisioning without duration"))?;
    let mut expires_at = now
        .checked_add(Duration::seconds(i64::from(secs)))
        .ok_or_else(|| StoreError::OutOfRange(format!("{secs} s from now")))?;
    if let Some(d) = row.delegation {
        match delegation_backing(tx, d, now).await? {
            Ok(Some(backing_expiry)) => expires_at = expires_at.min(backing_expiry),
            // An operator thread: no backing grant to outlive.
            Ok(None) => {}
            Err(refused) => return Ok(Err(refused)),
        }
    }
    let (thread, delegator) = match row.delegation {
        Some(d) => (
            Some(Uuid::from(d.thread_id)),
            Some(Uuid::from(d.delegator_agent_id)),
        ),
        None => (None, None),
    };
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "INSERT INTO grants (id, request_id, agent_id, session_id, delegation_thread_id,
             delegator_agent_id, platform, resource, authority, granted_at, expires_at, status,
             created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'provisioning', $10)
         RETURNING *",
        Uuid::from(id),
        Uuid::from(row.id),
        Uuid::from(row.agent_id),
        row.session_id.map(Uuid::from),
        thread,
        delegator,
        row.platform.as_str(),
        row.final_resource(),
        authority.to_json(),
        now,
        expires_at,
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(Ok(ProvisioningGrant {
        tx: tx.addr(),
        grant: raw.try_into()?,
        borrow: PhantomData,
    }))
}

/// The delegation thread must be open, its backing grant active and
/// unexpired, and the delegator enabled. Returns the backing grant's expiry,
/// or `None` for an operator thread (the admin panel's chat): it has no
/// backing grant by design, so the thread being open is the whole test and
/// the delegated grant is capped only by its own duration (it still ends
/// when the thread closes). Locks in the crate's order: delegator (agents),
/// backing grant (grants), thread (threads); the thread's backing grant id
/// is immutable, so it is read once without a lock to know what to lock.
async fn delegation_backing(
    tx: &Tx<'_>,
    d: Delegation,
    now: OffsetDateTime,
) -> Outcome<Option<OffsetDateTime>, BeginRefused> {
    let mut c = tx.conn().await;
    let backing = sqlx::query_scalar!(
        "SELECT grant_id FROM a2a_threads WHERE id = $1",
        Uuid::from(d.thread_id)
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(backing) = backing else {
        return Ok(Err(BeginRefused::DelegationClosed));
    };
    let delegator = sqlx::query!(
        r#"SELECT NOT disabled AS "ok!", kind = 'operator' AS "operator!"
           FROM agents WHERE id = $1 FOR SHARE"#,
        Uuid::from(d.delegator_agent_id)
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(delegator) = delegator.filter(|r| r.ok) else {
        return Ok(Err(BeginRefused::DelegatorDisabled));
    };
    let Some(backing) = backing else {
        // No backing grant: only the operator's own threads are like that.
        if !delegator.operator {
            return Ok(Err(BeginRefused::DelegationClosed));
        }
        let open = sqlx::query_scalar!(
            r#"SELECT state = 'open' AS "open!" FROM a2a_threads
               WHERE id = $1 AND grant_id IS NULL AND initiator_agent_id = $2 FOR SHARE"#,
            Uuid::from(d.thread_id),
            Uuid::from(d.delegator_agent_id)
        )
        .fetch_optional(&mut **c)
        .await?;
        return Ok(if open == Some(true) {
            Ok(None)
        } else {
            Err(BeginRefused::DelegationClosed)
        });
    };
    let backing = sqlx::query!(
        "SELECT expires_at FROM grants
         WHERE id = $1 AND status = 'active' AND expires_at > $2 FOR SHARE",
        backing,
        now
    )
    .fetch_optional(&mut **c)
    .await?;
    let Some(backing) = backing else {
        return Ok(Err(BeginRefused::DelegationClosed));
    };
    let open = sqlx::query_scalar!(
        r#"SELECT state = 'open' AS "open!" FROM a2a_threads WHERE id = $1 FOR SHARE"#,
        Uuid::from(d.thread_id)
    )
    .fetch_optional(&mut **c)
    .await?;
    if open != Some(true) {
        return Ok(Err(BeginRefused::DelegationClosed));
    }
    Ok(Ok(Some(backing.expires_at)))
}

/// A grant being provisioned, locked in the transaction it borrows: made
/// by [`begin`] (just inserted) or [`load_provisioning`] (`FOR UPDATE`,
/// still PROVISIONING). [`activate`] and [`fail_provisioning`] consume it.
#[derive(Debug)]
pub struct ProvisioningGrant<'t> {
    tx: usize,
    grant: GrantRow,
    borrow: PhantomData<&'t ()>,
}

impl ProvisioningGrant<'_> {
    #[must_use]
    pub fn grant(&self) -> &GrantRow {
        &self.grant
    }

    /// Was it loaded in `tx`? (Writes made on its behalf, here and in other
    /// store modules such as `mail::set_created_alias`, check it.)
    pub(crate) fn verify(&self, tx: &Tx<'_>) -> Result<(), StoreError> {
        if self.tx == tx.addr() {
            Ok(())
        } else {
            Err(StoreError::WrongProof)
        }
    }
}

/// The finishing phase's (or the reaper's) grant: locked `FOR UPDATE` and
/// still PROVISIONING (`None` otherwise). Lock order: call
/// `lockdown::check` for the grant's agent first.
pub async fn load_provisioning<'t>(
    tx: &'t Tx<'_>,
    id: GrantId,
) -> Result<Option<ProvisioningGrant<'t>>, StoreError> {
    let raw = {
        let mut c = tx.conn().await;
        sqlx::query_as!(
            RawGrant,
            "SELECT * FROM grants WHERE id = $1 AND status = 'provisioning' FOR UPDATE",
            Uuid::from(id)
        )
        .fetch_optional(&mut **c)
        .await?
    };
    Ok(opt(raw)?.map(|grant| ProvisioningGrant {
        tx: tx.addr(),
        grant,
        borrow: PhantomData,
    }))
}

/// The grant was not in the expected status (someone else moved it, or it
/// is not this agent's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("grant {id} changed state concurrently")]
pub struct GrantLost {
    pub id: GrantId,
}

/// PROVISIONING → ACTIVE, recording the provisioner's state, for an agent
/// proven not held in this transaction.
pub async fn activate(
    tx: &Tx<'_>,
    grant: ProvisioningGrant<'_>,
    not_held: &NotHeld<'_>,
    provisioner_state: &Value,
) -> Outcome<GrantRow, GrantLost> {
    grant.verify(tx)?;
    let id = grant.grant.id;
    not_held.verify(tx, grant.grant.agent_id)?;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "UPDATE grants SET status = 'active', provisioner_state = $2
         WHERE id = $1 AND status = 'provisioning'
         RETURNING *",
        Uuid::from(id),
        provisioner_state
    )
    .fetch_optional(&mut **c)
    .await?;
    match raw {
        None => Ok(Err(GrantLost { id })),
        Some(r) => Ok(Ok(r.try_into()?)),
    }
}

/// PROVISIONING → PROVISION_FAILED. `reverted_at`: when the reaper undid
/// external state (sets `revoked_at`).
pub async fn fail_provisioning(
    tx: &Tx<'_>,
    grant: ProvisioningGrant<'_>,
    reason: &str,
    reverted_at: Option<OffsetDateTime>,
) -> Outcome<GrantRow, GrantLost> {
    grant.verify(tx)?;
    let id = grant.grant.id;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "UPDATE grants SET status = 'provision_failed', revoke_reason = $2,
             revoked_at = COALESCE($3, revoked_at)
         WHERE id = $1 AND status = 'provisioning'
         RETURNING *",
        Uuid::from(id),
        reason,
        reverted_at
    )
    .fetch_optional(&mut **c)
    .await?;
    match raw {
        None => Ok(Err(GrantLost { id })),
        Some(r) => Ok(Ok(r.try_into()?)),
    }
}

/// How an active grant ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantEnd {
    /// `reason` is stored as given (`"{reason} ({by})"` is the caller's).
    Revoked { reason: String },
    /// Reason `expired`.
    Expired,
}

/// ACTIVE → REVOKED / EXPIRED, once: of a revoke racing an expiry exactly
/// one wins.
pub async fn end(
    tx: &Tx<'_>,
    id: GrantId,
    how: GrantEnd,
    now: OffsetDateTime,
) -> Outcome<GrantRow, GrantLost> {
    let (status, reason) = match how {
        GrantEnd::Revoked { reason } => (GrantStatus::Revoked, reason),
        GrantEnd::Expired => (GrantStatus::Expired, "expired".to_owned()),
    };
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "UPDATE grants SET status = $2, revoked_at = $3, revoke_reason = $4
         WHERE id = $1 AND status = 'active'
         RETURNING *",
        Uuid::from(id),
        status.as_str(),
        now,
        reason
    )
    .fetch_optional(&mut **c)
    .await?;
    match raw {
        None => Ok(Err(GrantLost { id })),
        Some(r) => Ok(Ok(r.try_into()?)),
    }
}

/// "Revoke later": an active grant's expiry moves to `now` (never later),
/// so the next expiry pass revokes it through its provisioner.
pub async fn expire_now(tx: &Tx<'_>, id: GrantId, now: OffsetDateTime) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE grants SET expires_at = LEAST(expires_at, $2) WHERE id = $1 AND status = 'active'",
        Uuid::from(id),
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// `expire_now` for every active grant of an agent (disable, lease end).
pub async fn expire_now_of_agent(
    tx: &Tx<'_>,
    agent: AgentId,
    now: OffsetDateTime,
) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE grants SET expires_at = LEAST(expires_at, $2)
         WHERE id IN (SELECT id FROM grants WHERE agent_id = $1 AND status = 'active'
                      ORDER BY id FOR NO KEY UPDATE)",
        Uuid::from(agent),
        now
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

/// Replace the provisioner's state of a live grant (e.g. a rotated key).
pub async fn set_provisioner_state(
    tx: &Tx<'_>,
    id: GrantId,
    state: &Value,
) -> Result<bool, StoreError> {
    let mut c = tx.conn().await;
    let n = sqlx::query!(
        "UPDATE grants SET provisioner_state = $2 WHERE id = $1 AND status IN ('provisioning', 'active')",
        Uuid::from(id),
        state
    )
    .execute(&mut **c)
    .await?
    .rows_affected();
    Ok(n == 1)
}

// ------------------------------------------------------------ issuance

/// Why no credential is issued for a grant. `detail` is the agent-visible
/// text (http-api §GET /v1/grants/{id}/credential).
#[derive(Debug, Clone)]
pub enum NotIssuable {
    /// Missing or another agent's: 404 `unknown grant`.
    UnknownGrant,
    /// 403 `contained (<id>): credentials are not issued`.
    Held(Held),
    /// 403 `delegation thread is closed; credential no longer issuable`.
    DelegationClosed,
    /// Not active, or expired: 403 with the platform's provisioner text.
    NotActive { platform: Platform },
}

impl NotIssuable {
    /// HTTP 404 rather than 403.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, NotIssuable::UnknownGrant)
    }

    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            NotIssuable::UnknownGrant => "unknown grant".to_owned(),
            NotIssuable::Held(Held::Contained(e)) => {
                format!("contained ({}): credentials are not issued", e.id)
            }
            NotIssuable::Held(h) => format!("{}: credentials are not issued", h.text()),
            NotIssuable::DelegationClosed => {
                "delegation thread is closed; credential no longer issuable".to_owned()
            }
            NotIssuable::NotActive {
                platform: Platform::Github | Platform::Kubernetes,
            } => "grant is not active; refusing to mint a token".to_owned(),
            NotIssuable::NotActive { .. } => "grant is not active".to_owned(),
        }
    }
}

/// A grant a credential may be issued for, now, in this transaction: the
/// caller's own, ACTIVE, unexpired, its agent not held, and (if delegated)
/// its thread open with an active backing grant. The grant, thread and
/// backing grant stay share-locked until the transaction ends, and the
/// value cannot outlive the transaction:
///
/// ```compile_fail
/// use agent_auth_store::{grants, Store};
/// async fn later(store: &Store, a: agent_auth_core::AgentId, g: agent_auth_core::GrantId,
///                now: time::OffsetDateTime) {
///     let tx = store.begin().await.unwrap();
///     let ok = grants::issuable(&tx, a, g, now).await.unwrap().unwrap();
///     tx.commit().await.unwrap(); // `ok` still borrows `tx`
///     let _ = ok.grant();
/// }
/// ```
#[derive(Debug)]
pub struct IssuableGrant<'t> {
    tx: usize,
    grant: GrantRow,
    borrow: PhantomData<&'t ()>,
}

impl IssuableGrant<'_> {
    #[must_use]
    pub fn grant(&self) -> &GrantRow {
        &self.grant
    }

    /// Was this decided in `tx`? (Writes made on its behalf, such as
    /// `credentials::replace`, check it.)
    #[must_use]
    pub fn belongs_to(&self, tx: &Tx<'_>) -> bool {
        self.tx == tx.addr()
    }
}

/// Decide whether `agent` may get a credential for `grant` now. Checks in
/// the Python's order: ownership, containment, delegation, status.
pub async fn issuable<'t>(
    tx: &'t Tx<'_>,
    agent: AgentId,
    grant: GrantId,
    now: OffsetDateTime,
) -> Outcome<IssuableGrant<'t>, NotIssuable> {
    if get_owned(tx, agent, grant).await?.is_none() {
        return Ok(Err(NotIssuable::UnknownGrant));
    }
    // Lock order: containment, agent, grant, thread (as `begin`).
    let not_held = match lockdown::check(tx, agent, now).await? {
        Ok(n) => n,
        Err(h) => return Ok(Err(NotIssuable::Held(h))),
    };
    not_held.verify(tx, agent)?;
    let row = {
        let mut c = tx.conn().await;
        sqlx::query_as!(
            RawGrant,
            "SELECT * FROM grants WHERE id = $1 AND agent_id = $2 FOR SHARE",
            Uuid::from(grant),
            Uuid::from(agent)
        )
        .fetch_optional(&mut **c)
        .await?
    };
    let Some(row) = opt(row)? else {
        return Ok(Err(NotIssuable::UnknownGrant));
    };
    if let Some(d) = row.delegation {
        let mut c = tx.conn().await;
        let open = sqlx::query_scalar!(
            r#"SELECT (t.state = 'open'
                       AND ((t.grant_id IS NULL
                             AND EXISTS (SELECT 1 FROM agents o
                                         WHERE o.id = t.initiator_agent_id
                                           AND o.kind = 'operator'))
                            OR EXISTS (SELECT 1 FROM grants b
                                       WHERE b.id = t.grant_id AND b.status = 'active'
                                         AND b.expires_at > $2))) AS "open!"
               FROM a2a_threads t WHERE t.id = $1 FOR SHARE OF t"#,
            Uuid::from(d.thread_id),
            now
        )
        .fetch_optional(&mut **c)
        .await?;
        if open != Some(true) {
            return Ok(Err(NotIssuable::DelegationClosed));
        }
    }
    if !row.is_live(now) {
        return Ok(Err(NotIssuable::NotActive {
            platform: row.platform,
        }));
    }
    Ok(Ok(IssuableGrant {
        tx: tx.addr(),
        grant: row,
        borrow: PhantomData,
    }))
}

// --------------------------------------------------------------- reads

pub async fn get(tx: &Tx<'_>, id: GrantId) -> Result<Option<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE id = $1",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// Load and lock (revoke/expire paths that call a provisioner before the
/// status write).
pub async fn get_for_update(tx: &Tx<'_>, id: GrantId) -> Result<Option<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE id = $1 FOR UPDATE",
        Uuid::from(id)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// The agent's own grant (`None` for a missing one or another agent's).
pub async fn get_owned(
    tx: &Tx<'_>,
    agent: AgentId,
    id: GrantId,
) -> Result<Option<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE id = $1 AND agent_id = $2",
        Uuid::from(id),
        Uuid::from(agent)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

pub async fn by_request(tx: &Tx<'_>, request: RequestId) -> Result<Option<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE request_id = $1",
        Uuid::from(request)
    )
    .fetch_optional(&mut **c)
    .await?;
    opt(raw)
}

/// An agent's grants, newest first, optionally of one status.
pub async fn of_agent(
    tx: &Tx<'_>,
    agent: AgentId,
    status: Option<GrantStatus>,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE agent_id = $1 AND ($2::text IS NULL OR status = $2)
         ORDER BY granted_at DESC, id",
        Uuid::from(agent),
        status.map(GrantStatus::as_str)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Active grants of these agents (containment, lockdown).
pub async fn active_of_agents(tx: &Tx<'_>, agents: &[AgentId]) -> Result<Vec<GrantId>, StoreError> {
    let a: Vec<Uuid> = agents.iter().copied().map(Uuid::from).collect();
    let mut c = tx.conn().await;
    Ok(ids(sqlx::query_scalar!(
        "SELECT id FROM grants WHERE status = 'active' AND agent_id = ANY($1) ORDER BY granted_at",
        &a
    )
    .fetch_all(&mut **c)
    .await?))
}

/// Active grants of a platform whose provisioner state lacks `key` equal
/// to their resource: for google, grants approved while it was a stub
/// (`{"stub": true}`), which the real provisioner never minted for.
pub async fn active_without_state(
    tx: &Tx<'_>,
    platform: Platform,
    key: &str,
) -> Result<Vec<GrantId>, StoreError> {
    let mut c = tx.conn().await;
    Ok(ids(sqlx::query_scalar!(
        "SELECT id FROM grants WHERE status = 'active' AND platform = $1
           AND (provisioner_state ->> $2) IS DISTINCT FROM resource
         ORDER BY granted_at",
        platform.as_str(),
        key
    )
    .fetch_all(&mut **c)
    .await?))
}

/// PROVISIONING grants created at or before `cutoff` (the reaper).
pub async fn stale_provisioning(
    tx: &Tx<'_>,
    cutoff: OffsetDateTime,
) -> Result<Vec<GrantId>, StoreError> {
    let mut c = tx.conn().await;
    Ok(ids(sqlx::query_scalar!(
        "SELECT id FROM grants WHERE status = 'provisioning' AND created_at <= $1 ORDER BY created_at",
        cutoff
    )
    .fetch_all(&mut **c)
    .await?))
}

/// Platforms with ACTIVE or PROVISIONING grants (startup: a platform no
/// longer configured must still be able to end them).
pub async fn live_platforms(tx: &Tx<'_>) -> Result<Vec<Platform>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT DISTINCT platform FROM grants WHERE status IN ('active', 'provisioning')
         ORDER BY platform"
    )
    .fetch_all(&mut **c)
    .await?;
    out.iter().map(|p| values::platform(T, p)).collect()
}

/// Active grants whose expiry has come.
pub async fn due(tx: &Tx<'_>, now: OffsetDateTime) -> Result<Vec<GrantId>, StoreError> {
    let mut c = tx.conn().await;
    Ok(ids(sqlx::query_scalar!(
        "SELECT id FROM grants WHERE status = 'active' AND expires_at <= $1 ORDER BY expires_at",
        now
    )
    .fetch_all(&mut **c)
    .await?))
}

/// Active delegated grants whose thread is closed, with the close reason.
pub async fn delegated_on_closed_threads(
    tx: &Tx<'_>,
) -> Result<Vec<(GrantId, Option<String>)>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query!(
        "SELECT g.id, t.close_reason FROM grants g
         JOIN a2a_threads t ON t.id = g.delegation_thread_id
         WHERE g.status = 'active' AND t.state = 'closed'"
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out
        .into_iter()
        .map(|r| (GrantId::from_uuid(r.id), r.close_reason))
        .collect())
}

/// `sender`'s live a2a grants to talk to the agent named `recipient`
/// (topic matching is the caller's, on each grant's authority).
pub async fn live_a2a(
    tx: &Tx<'_>,
    sender: AgentId,
    recipient: &str,
    now: OffsetDateTime,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants
         WHERE platform = 'a2a' AND agent_id = $1 AND resource = $2
           AND status = 'active' AND expires_at > $3
         ORDER BY granted_at, id",
        Uuid::from(sender),
        recipient,
        now
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Active a2a grants whose target is the agent named `target`.
pub async fn active_a2a_targeting(tx: &Tx<'_>, target: &str) -> Result<Vec<GrantId>, StoreError> {
    let mut c = tx.conn().await;
    Ok(ids(sqlx::query_scalar!(
        "SELECT id FROM grants WHERE platform = 'a2a' AND resource = $1 AND status = 'active'",
        target
    )
    .fetch_all(&mut **c)
    .await?))
}

/// Rename the target of active a2a grants (agent rename); returns how many.
pub async fn rename_a2a_target(tx: &Tx<'_>, old: &str, new: &str) -> Result<u64, StoreError> {
    let mut c = tx.conn().await;
    Ok(sqlx::query!(
        "UPDATE grants SET resource = $2
         WHERE id IN (SELECT id FROM grants
                      WHERE platform = 'a2a' AND resource = $1 AND status = 'active'
                      ORDER BY id FOR NO KEY UPDATE)",
        old,
        new
    )
    .execute(&mut **c)
    .await?
    .rows_affected())
}

/// Other grants of the same agent on the same platform and resource (e.g.
/// repos the agent created; LLDAP group keepers). Any status.
pub async fn siblings(tx: &Tx<'_>, of: &GrantRow) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE platform = $1 AND resource = $2 AND agent_id = $3 AND id <> $4
         ORDER BY granted_at, id",
        of.platform.as_str(),
        of.resource,
        Uuid::from(of.agent_id),
        Uuid::from(of.id)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Grants on a platform/resource that ended (revoked or expired) after
/// `since` (hostexec: shells to close on a reconnecting host).
pub async fn ended_on(
    tx: &Tx<'_>,
    platform: Platform,
    resource: &str,
    since: OffsetDateTime,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants
         WHERE platform = $1 AND resource = $2 AND status IN ('revoked', 'expired') AND revoked_at > $3
         ORDER BY revoked_at",
        platform.as_str(),
        resource,
        since
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Granted at or after `since`, oldest first (audit feed).
/// Keyset-paginated: with `after`, rows at exactly `since` only past
/// that id; ordered by (time, id), so a page boundary is exact.
pub async fn granted_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE granted_at > $1 OR (granted_at = $1 AND ($2::uuid IS NULL OR id > $2)) ORDER BY granted_at, id LIMIT $3",
        since,
        after,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Ended at or after `since`, oldest first (audit feed).
/// Keyset-paginated: with `after`, rows at exactly `since` only past
/// that id; ordered by (time, id), so a page boundary is exact.
pub async fn ended_since(
    tx: &Tx<'_>,
    since: OffsetDateTime,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE revoked_at > $1 OR (revoked_at = $1 AND ($2::uuid IS NULL OR id > $2)) ORDER BY revoked_at, id LIMIT $3",
        since,
        after,
        limit
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}

/// Agents that ever held a grant on `platform` (model usage view).
pub async fn agents_with(tx: &Tx<'_>, platform: Platform) -> Result<Vec<AgentId>, StoreError> {
    let mut c = tx.conn().await;
    let out = sqlx::query_scalar!(
        "SELECT DISTINCT agent_id FROM grants WHERE platform = $1",
        platform.as_str()
    )
    .fetch_all(&mut **c)
    .await?;
    Ok(out.into_iter().map(AgentId::from_uuid).collect())
}

/// Delegated grants anchored to a thread.
pub async fn by_delegation_thread(
    tx: &Tx<'_>,
    thread: ThreadId,
) -> Result<Vec<GrantRow>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawGrant,
        "SELECT * FROM grants WHERE delegation_thread_id = $1 ORDER BY granted_at",
        Uuid::from(thread)
    )
    .fetch_all(&mut **c)
    .await?;
    rows(raw)
}
