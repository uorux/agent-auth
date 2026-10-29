//! `GET /v1/audit/events` (http-api §2.3): the broker's record, oldest
//! first, for the agents policy names as readers.

use std::collections::BTreeMap;

use agent_auth_core::{
    AgentId, DecisionSource, GrantId, GrantStatus, JobId, Platform, RequestId, RequestStatus,
    ThreadId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::a2a::{CloseReason, ThreadState};
use crate::common::{AgentKind, Placement, TierName};
use crate::literal::literal_str;

/// `{events, next, cursor, truncated}`. `next` is inclusive: pass it back
/// as `since` and drop items whose `(kind, id, status)` you have seen; it
/// cannot get past more than `limit` items sharing one time. `cursor`
/// (new) is exclusive and exact: pass it back as `after` and every page
/// advances.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    #[serde(with = "crate::timestamp")]
    pub next: OffsetDateTime,
    /// Opaque: the last item's position (or the request's, with no items).
    pub cursor: String,
    pub truncated: bool,
}

literal_str!(
    /// `agent.created`'s status.
    Created = "created"
);
literal_str!(
    /// A containment entry's status in the feed.
    Standing = "standing"
);

/// One item, discriminated by `kind`. Long texts (`reason`,
/// `justification`, `command`, `error`) are cut to 2000 characters plus `…`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AuditEvent {
    /// An access request as it changes.
    #[serde(rename = "request")]
    Request(RequestEvent),
    #[serde(rename = "grant.issued")]
    GrantIssued(GrantIssued),
    #[serde(rename = "grant.ended")]
    GrantEnded(GrantEnded),
    #[serde(rename = "host_job")]
    HostJob(HostJobEvent),
    #[serde(rename = "a2a.opened")]
    A2aOpened(A2aOpened),
    #[serde(rename = "a2a.closed")]
    A2aClosed(A2aClosed),
    #[serde(rename = "agent.created")]
    AgentCreated(AgentCreated),
    #[serde(rename = "containment")]
    Containment(ContainmentStanding),
    #[serde(rename = "security.bad_key")]
    BadKey(SecurityEvent),
    #[serde(rename = "security.bad_admin_token")]
    BadAdminToken(SecurityEvent),
    #[serde(rename = "security.credential_refused")]
    CredentialRefused(SecurityEvent),
    #[serde(rename = "security.containment_lifted")]
    ContainmentLifted(SecurityEvent),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestEvent {
    pub id: RequestId,
    /// `updated_at`.
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    pub agent: String,
    /// The delegator, if delegated.
    #[serde(rename = "for")]
    pub for_: Option<String>,
    pub platform: Platform,
    /// The authority's label.
    pub what: String,
    pub resource: String,
    pub status: RequestStatus,
    pub source: Option<DecisionSource>,
    pub by: Option<String>,
    pub reason: Option<String>,
    pub justification: String,
    pub risk_notes: Vec<String>,
    pub duration_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantIssued {
    /// `granted_at`.
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    /// Always `active`.
    pub status: GrantStatus,
    #[serde(with = "crate::timestamp")]
    pub expires_at: OffsetDateTime,
    pub id: GrantId,
    pub agent: String,
    pub platform: Platform,
    pub what: String,
    pub resource: String,
    pub request_id: RequestId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantEnded {
    /// `revoked_at`.
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub status: GrantStatus,
    pub reason: Option<String>,
    pub id: GrantId,
    pub agent: String,
    pub platform: Platform,
    pub what: String,
    pub resource: String,
    pub request_id: RequestId,
}

/// A job's phase in the feed: `started`, then the job's final status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobPhase {
    Started,
    Starting,
    Running,
    Done,
    Refused,
    Lost,
}

/// A command a host was asked to run (`status: started`, at `created_at`),
/// and how it ended (at `finished_at`, with `exit_code` and `error`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostJobEvent {
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub status: JobPhase,
    pub id: JobId,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    pub agent: String,
    pub host: String,
    pub tier: TierName,
    pub shell: bool,
    /// The argv joined with spaces, or `[<template>] k=v k=v`.
    pub command: String,
    pub cwd: Option<String>,
    pub via: Option<String>,
    /// Null on the `started` item.
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
}

/// A conversation between agents (never its messages).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aOpened {
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    /// Always `open`.
    pub status: ThreadState,
    pub id: ThreadId,
    pub from: String,
    pub to: String,
    pub topic: Option<String>,
    /// Opened by the operator from the admin panel.
    pub operator: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aClosed {
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    /// Always `closed`.
    pub status: ThreadState,
    pub reason: Option<CloseReason>,
    pub id: ThreadId,
    pub from: String,
    pub to: String,
    pub topic: Option<String>,
    pub operator: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCreated {
    pub id: AgentId,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub status: Created,
    /// Its name.
    pub agent: String,
    pub agent_kind: AgentKind,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
    /// The minting agent's name.
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentStanding {
    /// The entry's 8-hex id.
    pub id: String,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub status: Standing,
    #[serde(rename = "match")]
    pub matches: Map<String, Value>,
    pub reason: String,
    pub by: String,
    pub source: String,
}

/// A refusal the database does not keep (failed keys and admin tokens,
/// credentials refused to a held agent, lifted containments). Every field
/// is text cut to 300 characters; `id` is `s<n>`, reset on restart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    /// `X-Real-IP`, or the peer address.
    pub client: Option<String>,
    pub path: Option<String>,
    /// The kind's own fields (`key_id`, `agent`, `reason`, `grant`, ...).
    #[serde(flatten)]
    pub fields: BTreeMap<String, Option<String>>,
}
