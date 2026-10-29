//! The admin panel's read-only logs (`/admin/log/*`, `/admin/a2a/*`,
//! `/admin/models/usage`; http-api §2.7).

use agent_auth_core::{DecisionSource, JobId, Platform, RequestId, RequestStatus, ThreadId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::a2a::{CloseReason, ThreadState};
use crate::common::{AgentKind, Placement, TierName};
use crate::hostexec::JobStatus;

/// `GET /admin/log/decisions` items (not cut, unlike the audit feed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionItem {
    pub id: RequestId,
    /// `created_at`.
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    #[serde(default, with = "crate::timestamp::option")]
    pub decided_at: Option<OffsetDateTime>,
    pub agent: String,
    #[serde(rename = "for")]
    pub for_: Option<String>,
    pub platform: Platform,
    pub what: String,
    pub resource: String,
    pub status: RequestStatus,
    pub source: Option<DecisionSource>,
    pub by: Option<String>,
    pub reason: Option<String>,
    pub justification: String,
    pub duration_secs: u32,
}

/// `GET /admin/log/commands` items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandItem {
    pub id: JobId,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub agent: String,
    pub host: String,
    pub tier: TierName,
    pub shell: bool,
    pub command: String,
    pub cwd: Option<String>,
    pub status: JobStatus,
    /// What the host admitted it on (`totp`, `desk`, `armed+human`, ...).
    pub via: Option<String>,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub output_bytes: Option<u64>,
    pub request_id: Option<RequestId>,
}

/// `GET /admin/log/commands/{id}` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandDetail {
    #[serde(flatten)]
    pub item: CommandItem,
    pub justification: Option<String>,
    pub decided_by: Option<String>,
    /// The last 20000 characters.
    pub output: String,
    pub output_cut: bool,
    pub output_sha256: Option<String>,
}

/// `GET /admin/a2a/graph?hours=` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aGraph {
    pub hours: u32,
    #[serde(with = "crate::timestamp")]
    pub now: OffsetDateTime,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub threads: Vec<GraphThread>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub name: String,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
    pub kind: AgentKind,
    pub alive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub threads: u32,
    /// Threads `open` or `pending_open`.
    pub open: u32,
    pub messages: u32,
    /// Access requested on the threads' behalf.
    pub requests: u32,
    #[serde(with = "crate::timestamp")]
    pub last: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphThread {
    pub id: ThreadId,
    pub from: String,
    pub to: String,
    pub topic: Option<String>,
    pub state: ThreadState,
    pub close_reason: Option<CloseReason>,
    pub messages: u32,
    pub requests: u32,
    #[serde(with = "crate::timestamp")]
    pub opened: OffsetDateTime,
    #[serde(with = "crate::timestamp")]
    pub last: OffsetDateTime,
}

/// `GET /admin/a2a/threads/{id}` → 200: one conversation, long payloads cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminThread {
    pub id: ThreadId,
    pub from: String,
    pub to: String,
    pub topic: Option<String>,
    pub state: ThreadState,
    pub close_reason: Option<CloseReason>,
    #[serde(with = "crate::timestamp")]
    pub opened: OffsetDateTime,
    pub messages: Vec<AdminMessage>,
    pub requests: Vec<DelegatedRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminMessage {
    pub seq: u64,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub from: String,
    /// The payload's `type`, whatever JSON it is.
    #[serde(rename = "type")]
    pub kind: Option<Value>,
    /// The payload's `text`, or the payload as indented JSON; at most 4000
    /// characters.
    pub text: String,
    pub cut: bool,
}

/// Access requested on a thread's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedRequest {
    pub platform: Platform,
    pub what: String,
    pub resource: String,
    pub status: RequestStatus,
    pub source: Option<DecisionSource>,
}

/// `GET /admin/models/usage` → 200.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelsUsage {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub agents: Vec<UsageRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageRow {
    pub agent: String,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
    /// The gateway's list-price dollars.
    pub spend: f64,
    pub max_budget: Option<f64>,
}
