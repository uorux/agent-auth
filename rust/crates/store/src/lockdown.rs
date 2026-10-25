//! Containment (core-lifecycle-policy §8.5): entries that hold agents, and
//! the check every granting operation must pass inside its own transaction.
//!
//! [`check`] returns a [`NotHeld`] proof that borrows the transaction it was
//! made in; [`crate::grants::begin`], [`crate::grants::activate`] and
//! [`crate::grants::issuable`] require one, verify it belongs to the same
//! transaction and agent, and it cannot outlive the transaction (`commit`
//! takes the transaction by value). [`check_pair`] is the a2a form (both
//! participants, the operator exempt).
//!
//! Serialization with containment itself: `check` holds a shared advisory
//! lock until its transaction ends, and [`record`] / [`lift`] take it
//! exclusively. So an entry recorded while a provisioning transaction is in
//! flight waits for that transaction to commit; the contain sweep that
//! follows sees (and revokes) what it granted, and every check that starts
//! after the entry committed sees the entry. `check` also locks the agent
//! row (`FOR SHARE`), so a concurrent disable waits the same way.
//!
//! A proof cannot outlive its transaction:
//!
//! ```compile_fail
//! use agent_auth_store::{lockdown, Store};
//! async fn outlive(store: &Store, agent: agent_auth_core::AgentId, now: time::OffsetDateTime) {
//!     let tx = store.begin().await.unwrap();
//!     let proof = lockdown::check(&tx, agent, now).await.unwrap().unwrap();
//!     tx.commit().await.unwrap(); // `proof` still borrows `tx`
//!     let _ = proof.agent();
//! }
//! ```
//!
//! Matching is the pure `agent_auth_core::containment::holds` (fail closed:
//! an entry that does not parse holds every agent but the operator).

use std::marker::PhantomData;

use agent_auth_core::containment::{self, AgentKind, AgentMatch, MatchError};
use agent_auth_core::{AgentId, DaemonId};
use serde_json::Value;
use time::OffsetDateTime;

use crate::agents::{self, AgentRow};
use crate::values::text_enum;
use crate::{Outcome, StoreError, Tx};

const T: &str = "containment_entries";

/// Advisory lock key serializing containment changes against checks.
const CONTAINMENT_LOCK: i64 = 0x0061_6163_6f6e_7461; // "aaconta"

text_enum! {
    /// Who recorded a containment entry.
    ContainmentSource {
        Operator = "operator",
        Agent = "agent",
        Lockdown = "lockdown",
        Unspecified = "",
    }
}

#[derive(Debug, Clone)]
pub struct ContainmentEntry {
    /// 8 lowercase hex characters.
    pub id: String,
    /// An `AgentMatch` object (`{}` = every agent).
    pub r#match: Value,
    pub reason: String,
    pub evidence: String,
    pub by: String,
    pub source: ContainmentSource,
    pub at: OffsetDateTime,
}

impl ContainmentEntry {
    /// `contained ({id}): {reason or 'by the operator'}`: the refusal text
    /// of requests, retries and escalations.
    #[must_use]
    pub fn held_text(&self) -> String {
        let reason = if self.reason.is_empty() {
            "by the operator"
        } else {
            &self.reason
        };
        format!("contained ({}): {reason}", self.id)
    }

    /// `{who}: {reason or 'no reason given'} (by {by}, {at})`, with `who`
    /// `every agent` for `{}` (or a match that no longer parses: it holds
    /// everyone).
    #[must_use]
    pub fn describe(&self, at: &str) -> String {
        let who = match AgentMatch::parse(&self.r#match) {
            Ok(m) if m != AgentMatch::everyone() => m.pattern_text(),
            _ => "every agent".to_owned(),
        };
        let reason = if self.reason.is_empty() {
            "no reason given"
        } else {
            &self.reason
        };
        format!("{who}: {reason} (by {}, {at})", self.by)
    }
}

struct RawEntry {
    id: String,
    r#match: Value,
    reason: String,
    evidence: String,
    created_by: String,
    source: String,
    at: OffsetDateTime,
}

impl TryFrom<RawEntry> for ContainmentEntry {
    type Error = StoreError;
    fn try_from(r: RawEntry) -> Result<ContainmentEntry, StoreError> {
        Ok(ContainmentEntry {
            source: ContainmentSource::parse(&r.source)
                .ok_or_else(|| StoreError::corrupt(T, format!("source {:?}", r.source)))?,
            id: r.id,
            r#match: r.r#match,
            reason: r.reason,
            evidence: r.evidence,
            by: r.created_by,
            at: r.at,
        })
    }
}

fn entries_of(raw: Vec<RawEntry>) -> Result<Vec<ContainmentEntry>, StoreError> {
    raw.into_iter().map(ContainmentEntry::try_from).collect()
}

/// Every entry, in order.
pub async fn entries(tx: &Tx<'_>) -> Result<Vec<ContainmentEntry>, StoreError> {
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEntry,
        r#"SELECT id, match AS "match", reason, evidence, created_by, source, at
           FROM containment_entries ORDER BY position"#
    )
    .fetch_all(&mut **c)
    .await?;
    entries_of(raw)
}

/// The entry that holds this agent, if any (for display; the acting paths
/// use [`check`]).
pub async fn holding(
    tx: &Tx<'_>,
    agent: &AgentRow,
) -> Result<Option<ContainmentEntry>, StoreError> {
    let all = entries(tx).await?;
    Ok(containment::first_holding(&all, |e| &e.r#match, &agent.facts()).cloned())
}

/// Names of one agent VM's agents that some entry holds, sorted.
pub async fn held_in(tx: &Tx<'_>, sandbox: DaemonId) -> Result<Vec<String>, StoreError> {
    let all = entries(tx).await?;
    let mut names: Vec<String> = agents::list_in_sandbox(tx, sandbox)
        .await?
        .into_iter()
        .filter(|a| containment::first_holding(&all, |e| &e.r#match, &a.facts()).is_some())
        .map(|a| a.name)
        .collect();
    names.sort();
    Ok(names)
}

async fn lock_exclusive(tx: &Tx<'_>) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        r#"SELECT 1 AS "one!" FROM pg_advisory_xact_lock($1)"#,
        CONTAINMENT_LOCK
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(())
}

async fn lock_shared(tx: &Tx<'_>) -> Result<(), StoreError> {
    let mut c = tx.conn().await;
    sqlx::query!(
        r#"SELECT 1 AS "one!" FROM pg_advisory_xact_lock_shared($1)"#,
        CONTAINMENT_LOCK
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(())
}

/// A new entry. `match` must parse as an `AgentMatch` (refused otherwise).
#[derive(Debug, Clone)]
pub struct NewEntry<'a> {
    pub id: &'a str,
    pub r#match: &'a Value,
    pub reason: &'a str,
    pub evidence: &'a str,
    pub by: &'a str,
    pub source: ContainmentSource,
    pub at: OffsetDateTime,
}

/// Record an entry (appended last). Waits for in-flight checks to commit.
pub async fn record(tx: &Tx<'_>, e: &NewEntry<'_>) -> Outcome<ContainmentEntry, MatchError> {
    if let Err(err) = AgentMatch::parse(e.r#match) {
        return Ok(Err(err));
    }
    lock_exclusive(tx).await?;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEntry,
        r#"INSERT INTO containment_entries (id, match, reason, evidence, created_by, source, at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, match AS "match", reason, evidence, created_by, source, at"#,
        e.id,
        e.r#match,
        e.reason,
        e.evidence,
        e.by,
        e.source.as_str(),
        e.at
    )
    .fetch_one(&mut **c)
    .await?;
    Ok(Ok(raw.try_into()?))
}

/// Lift one entry (`Some(id)`; empty result = no such entry) or all.
pub async fn lift(tx: &Tx<'_>, id: Option<&str>) -> Result<Vec<ContainmentEntry>, StoreError> {
    lock_exclusive(tx).await?;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEntry,
        r#"DELETE FROM containment_entries WHERE $1::text IS NULL OR id = $1
           RETURNING id, match AS "match", reason, evidence, created_by, source, at"#,
        id
    )
    .fetch_all(&mut **c)
    .await?;
    entries_of(raw)
}

/// Lift the entries a hostexec lockdown recorded: all of them (`None`, a
/// full unlock) or those for one host (`match == {"host": host}`).
pub async fn lift_lockdown(
    tx: &Tx<'_>,
    host: Option<&str>,
) -> Result<Vec<ContainmentEntry>, StoreError> {
    lock_exclusive(tx).await?;
    let mut c = tx.conn().await;
    let raw = sqlx::query_as!(
        RawEntry,
        r#"DELETE FROM containment_entries
           WHERE source = 'lockdown'
             AND ($1::text IS NULL OR match = jsonb_build_object('host', $1::text))
           RETURNING id, match AS "match", reason, evidence, created_by, source, at"#,
        host
    )
    .fetch_all(&mut **c)
    .await?;
    entries_of(raw)
}

/// Why an agent may not be given anything now.
#[derive(Debug, Clone)]
pub enum Held {
    /// A containment entry holds it.
    Contained(ContainmentEntry),
    /// Disabled, or its lease ran out (core B-15: treated like containment).
    Disabled,
    /// No such agent (fail closed).
    Unknown,
}

impl Held {
    /// The refusal text: `contained (<id>): <reason>` for an entry.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Held::Contained(e) => e.held_text(),
            Held::Disabled => "agent is disabled".to_owned(),
            Held::Unknown => "unknown agent".to_owned(),
        }
    }
}

/// Proof that `agent` was not held, checked in the transaction it borrows.
#[derive(Debug)]
pub struct NotHeld<'t> {
    tx: usize,
    agent: AgentRow,
    borrow: PhantomData<&'t ()>,
}

impl NotHeld<'_> {
    /// The agent, as read (and share-locked) by the check.
    #[must_use]
    pub fn agent(&self) -> &AgentRow {
        &self.agent
    }

    /// Refuse a proof from another transaction or for another agent.
    pub(crate) fn verify(&self, tx: &Tx<'_>, agent: AgentId) -> Result<(), StoreError> {
        if self.tx == tx.addr() && self.agent.id == agent {
            Ok(())
        } else {
            Err(StoreError::WrongProof)
        }
    }
}

fn held(agent: Option<&AgentRow>, all: &[ContainmentEntry], now: OffsetDateTime) -> Option<Held> {
    let Some(agent) = agent else {
        return Some(Held::Unknown);
    };
    if agent.disabled || agent.lease_expires_at.is_some_and(|l| l <= now) {
        return Some(Held::Disabled);
    }
    containment::first_holding(all, |e| &e.r#match, &agent.facts())
        .map(|e| Held::Contained(e.clone()))
}

/// Is the agent held? Answered inside the transaction that will act on it;
/// the proof borrows that transaction. See the module docs for how this
/// serializes with containment and disabling.
pub async fn check<'t>(
    tx: &'t Tx<'_>,
    agent: AgentId,
    now: OffsetDateTime,
) -> Outcome<NotHeld<'t>, Held> {
    lock_shared(tx).await?;
    let row = agents::get_for_share(tx, agent).await?;
    let all = entries(tx).await?;
    if let Some(h) = held(row.as_ref(), &all, now) {
        return Ok(Err(h));
    }
    let Some(agent) = row else {
        return Ok(Err(Held::Unknown));
    };
    Ok(Ok(NotHeld {
        tx: tx.addr(),
        agent,
        borrow: PhantomData,
    }))
}

/// Proof that two a2a participants may talk: neither held, unless one is
/// the operator (then containment is skipped, as in the Python; disabling
/// still counts for both).
#[derive(Debug)]
pub struct PairClear<'t> {
    tx: usize,
    a: AgentRow,
    b: AgentRow,
    borrow: PhantomData<&'t ()>,
}

impl PairClear<'_> {
    #[must_use]
    pub fn agents(&self) -> (&AgentRow, &AgentRow) {
        (&self.a, &self.b)
    }

    /// Refuse a proof from another transaction or for other agents.
    pub(crate) fn verify(&self, tx: &Tx<'_>, x: AgentId, y: AgentId) -> Result<(), StoreError> {
        let same = (self.a.id == x && self.b.id == y) || (self.a.id == y && self.b.id == x);
        if self.tx == tx.addr() && same {
            Ok(())
        } else {
            Err(StoreError::WrongProof)
        }
    }
}

/// The a2a check: `a` first, then `b`; the first held one is reported.
pub async fn check_pair<'t>(
    tx: &'t Tx<'_>,
    a: AgentId,
    b: AgentId,
    now: OffsetDateTime,
) -> Outcome<PairClear<'t>, (AgentId, Held)> {
    lock_shared(tx).await?;
    let ra = agents::get_for_share(tx, a).await?;
    let rb = agents::get_for_share(tx, b).await?;
    let (Some(ra), Some(rb)) = (ra, rb) else {
        return Ok(Err((a, Held::Unknown)));
    };
    let operator = ra.kind == AgentKind::Operator || rb.kind == AgentKind::Operator;
    let all = if operator {
        Vec::new()
    } else {
        entries(tx).await?
    };
    for r in [&ra, &rb] {
        if let Some(h) = held(Some(r), &all, now) {
            return Ok(Err((r.id, h)));
        }
    }
    Ok(Ok(PairClear {
        tx: tx.addr(),
        a: ra,
        b: rb,
        borrow: PhantomData,
    }))
}
