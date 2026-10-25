//! Sessions and a2a threads (`/v1/sessions*`, `/v1/a2a/*`; http-api §2.2,
//! a2a spec §3-§4), and the webhook pings.

use agent_auth_core::{GrantId, MessageId, SessionId, ThreadId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::common::AgentKind;
use crate::literal::True;
use crate::payload::Payload;
use crate::text::{SessionLabel, Text, Topic};

/// `POST /v1/sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreate {
    pub label: SessionLabel,
}

/// `POST /v1/sessions` → 200. `name` is `<label>-<4 hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOut {
    pub session_id: SessionId,
    pub name: String,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
}

/// `POST /v1/sessions/close` → 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClosed {
    pub ok: True,
    pub threads_closed: u32,
}

/// `POST /v1/a2a/threads`. The payload's size is checked with Python's
/// measure as it deserializes; parse with [`crate::payload::parse_body`]
/// so out-of-range integers are refused too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadOpenBody {
    pub to: Text<1, 128>,
    #[serde(default)]
    pub topic: Option<Topic>,
    #[serde(default)]
    pub payload: Payload,
}

/// `POST /v1/a2a/threads/{id}/messages`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadMessageBody {
    #[serde(default)]
    pub payload: Payload,
}

/// `POST /v1/a2a/threads/{id}/reject` and `/close`. The body is required
/// (send `{}` at least).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadCloseBody {
    #[serde(default)]
    pub reason: Option<Text<0, 2000>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadState {
    PendingOpen,
    Open,
    Closed,
}

impl ThreadState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ThreadState::PendingOpen => "pending_open",
            ThreadState::Open => "open",
            ThreadState::Closed => "closed",
        }
    }
}

/// Why a thread closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    Rejected,
    Closed,
    OpenTimeout,
    IdleTimeout,
    PeerGone,
    GrantRevoked,
    /// One side was held by a containment.
    Contained,
}

/// The viewer's side of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadRole {
    Initiator,
    Responder,
}

/// A thread as one participant sees it (a2a spec §3.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadOut {
    pub thread_id: ThreadId,
    /// The other side's name (null if that agent is gone).
    pub peer: Option<String>,
    pub role: ThreadRole,
    pub topic: Option<String>,
    pub state: ThreadState,
    pub close_reason: Option<CloseReason>,
    pub close_note: Option<String>,
    /// Null for the operator's threads.
    pub grant_id: Option<GrantId>,
    pub last_seq: u64,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "crate::timestamp::option")]
    pub accepted_at: Option<OffsetDateTime>,
    #[serde(default, with = "crate::timestamp::option")]
    pub closed_at: Option<OffsetDateTime>,
    #[serde(with = "crate::timestamp")]
    pub last_activity_at: OffsetDateTime,
    #[serde(default, with = "crate::timestamp::option")]
    pub peer_last_seen_at: Option<OffsetDateTime>,
    pub peer_alive: bool,
}

/// A message as read back: the stored payload verbatim (no key is ever
/// filtered, unlike FastAPI's encoder with `_sa*` keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageOut {
    pub message_id: MessageId,
    pub seq: u64,
    pub from: String,
    pub payload: Map<String, Value>,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
}

/// `GET /v1/a2a/threads/{id}/messages` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadMessages {
    pub thread: ThreadOut,
    pub messages: Vec<MessageOut>,
}

/// `POST /v1/a2a/threads/{id}/messages` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSent {
    pub message_id: MessageId,
    pub seq: u64,
    pub thread_state: ThreadState,
}

/// `GET /v1/a2a/events` → 200. `cursor` is the newest `last_activity_at`
/// returned (or the `after` echoed back); pass it back as `after`. It keeps
/// microseconds, and the comparison is strict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsSnapshot {
    pub pending_opens: Vec<ThreadOut>,
    pub activity: Vec<ThreadOut>,
    #[serde(default, with = "crate::timestamp::option")]
    pub cursor: Option<OffsetDateTime>,
}

/// How reachable a peer is right now (a2a spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// Has a webhook: can be woken on demand.
    Webhook,
    /// Listened for threads within the threshold.
    Polling,
    /// A service agent nothing is listening on.
    Idle,
    /// Initiate-only: cannot receive threads.
    Ephemeral,
}

/// An a2a peer and whether talking to it now is worth doing. Every key is
/// present (null when unset), in the catalog as in `/v1/a2a/check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub kind: AgentKind,
    pub addressable: bool,
    pub reachable: bool,
    pub why: Reach,
    #[serde(default, with = "crate::timestamp::option")]
    pub last_seen_at: Option<OffsetDateTime>,
    /// When it last read its inbound threads: what `reachable` keys on.
    #[serde(default, with = "crate::timestamp::option")]
    pub last_listen_at: Option<OffsetDateTime>,
    pub has_webhook: bool,
}

/// `GET /v1/a2a/check` → 200. All keys present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aCheckOut {
    pub allowed: bool,
    pub grant_id: Option<GrantId>,
    #[serde(default, with = "crate::timestamp::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub reason: Option<String>,
    pub peer: Option<PeerEntry>,
}

/// A webhook ping (a2a spec §4.3): notify-only, never the payload. Signed
/// with `X-Agent-Auth-Timestamp: <unix seconds>` and `X-Agent-Auth-Signature:
/// sha256=<hex HMAC of "<timestamp>." + body>` (`crypto::webhook`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebhookPing {
    #[serde(rename = "a2a_thread_open")]
    ThreadOpen {
        thread_id: ThreadId,
        from: String,
        topic: Option<String>,
        seq: u64,
    },
    #[serde(rename = "a2a_message")]
    Message {
        thread_id: ThreadId,
        message_id: MessageId,
        from: String,
        topic: Option<String>,
        seq: u64,
    },
    #[serde(rename = "a2a_thread_closed")]
    ThreadClosed {
        thread_id: ThreadId,
        topic: Option<String>,
        close_reason: Option<CloseReason>,
    },
}
