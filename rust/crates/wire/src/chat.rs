//! The operator's chat from the admin panel (`/admin/chat/*`; a2a spec §5).

use agent_auth_core::{DecisionSource, Platform, RequestId, RequestStatus, ThreadId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::a2a::{CloseReason, PeerEntry, ThreadOut, ThreadState};
use crate::common::Placement;
use crate::text::{Text, Topic};

/// `POST /admin/chat/threads`. The topic follows the agents' rule (one
/// line); the Python only capped its length here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatOpen {
    pub to: Text<1, 128>,
    #[serde(default)]
    pub topic: Option<Topic>,
    pub text: Text<1, 20000>,
}

/// `POST /admin/chat/threads/{id}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatSend {
    pub text: Text<1, 20000>,
}

/// `POST /admin/chat/threads/{id}/close`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatClose {
    #[serde(default)]
    pub reason: Option<Text<0, 2000>>,
}

/// What the operator's messages carry: `{"type": "message", "text",
/// "operator": <who in the panel>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
    pub operator: String,
}

impl OperatorPayload {
    #[must_use]
    pub fn message(text: impl Into<String>, operator: impl Into<String>) -> Self {
        OperatorPayload {
            kind: "message".to_owned(),
            text: text.into(),
            operator: operator.into(),
        }
    }
}

/// `GET /admin/chat/peers` items: reachability plus the agent's fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPeer {
    #[serde(flatten)]
    pub peer: PeerEntry,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub host: Option<String>,
    pub placement: Placement,
}

/// `GET /admin/chat/threads` items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatThreadItem {
    pub id: ThreadId,
    pub to: String,
    pub topic: Option<String>,
    pub state: ThreadState,
    pub close_reason: Option<CloseReason>,
    #[serde(with = "crate::timestamp")]
    pub opened: OffsetDateTime,
    #[serde(with = "crate::timestamp")]
    pub last: OffsetDateTime,
    pub last_seq: u64,
    /// The last message's text, summary or type, at most 200 characters.
    pub preview: String,
    pub last_from_operator: bool,
}

/// `GET /admin/chat/threads/{id}` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatThreadView {
    pub thread: ThreadOut,
    pub messages: Vec<ChatMessage>,
    pub requests: Vec<ChatRequest>,
}

/// A message, with the usual payload fields lifted out when they are text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub seq: u64,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
    pub from: String,
    #[serde(rename = "type")]
    pub kind: Option<Value>,
    pub text: Option<String>,
    pub status: Option<String>,
    pub summary: Option<String>,
    /// The raw payload, when it has no `text`.
    pub payload: Option<Map<String, Value>>,
    pub operator: Option<String>,
}

/// Access requested on the thread's behalf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatRequest {
    pub id: RequestId,
    pub platform: Platform,
    pub what: String,
    pub resource: String,
    pub status: RequestStatus,
    pub source: Option<DecisionSource>,
}
