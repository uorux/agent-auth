//! Evals (`/admin/evals/*`): the broker's recorded model decisions, their
//! labels, and replays of them under another model, system prompt or
//! context setting.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::text::{BoundedVec, Text};

/// A context setting a decision kind's prompt builder reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnobOut {
    pub name: String,
    pub default: u64,
    pub max: u64,
    pub doc: String,
}

/// `GET /admin/evals/kinds`: one decision kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindOut {
    pub kind: String,
    /// The classes its decisions fall in (labels name one; `*` stands for
    /// any part between `/`).
    pub classes: Vec<String>,
    pub knobs: Vec<KnobOut>,
    /// The system prompt this broker uses now.
    pub system: String,
    pub system_sha256: String,
}

/// A label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelOut {
    pub expected: String,
    pub note: String,
    /// `operator`, or `outcome` (from what happened next).
    pub source: String,
    pub labeled_by: String,
    #[serde(with = "crate::timestamp")]
    pub labeled_at: OffsetDateTime,
}

/// A recorded call, in a list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallOut {
    pub id: String,
    pub kind: String,
    pub model: String,
    pub class: Option<String>,
    pub error: Option<String>,
    pub latency_ms: i32,
    pub subject: Value,
    pub label: Option<LabelOut>,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    /// The model's one-sentence reason, if it gave one.
    pub summary: Option<String>,
}

/// `GET /admin/evals/calls/{id}`: everything recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallDetail {
    #[serde(flatten)]
    pub call: CallOut,
    pub facts: Value,
    pub context: Value,
    pub system: String,
    pub system_sha256: String,
    pub user_message: String,
    pub answer: Option<Value>,
}

/// `GET /admin/evals/calls`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallsPage {
    pub calls: Vec<CallOut>,
    /// Pass as `before` for the next page; none at the end.
    pub next: Option<String>,
}

/// `PUT /admin/evals/calls/{id}/label`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelBody {
    /// The class the call should have decided (`*` for any part).
    pub expected: Text<1, 64>,
    #[serde(default)]
    pub note: Option<Text<0, 2000>>,
}

/// `POST /admin/evals/runs`: replay recorded calls of one kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCreate {
    pub kind: Text<1, 32>,
    /// Ask this model (default: each call's own).
    #[serde(default)]
    pub model: Option<Text<1, 128>>,
    /// This system prompt (default: the one in use now).
    #[serde(default)]
    pub system: Option<Text<1, 100_000>>,
    /// Context settings (`GET /admin/evals/kinds` lists each kind's).
    #[serde(default)]
    pub context: Map<String, Value>,
    /// Only labelled calls (the eval set), or only unlabelled ones.
    #[serde(default)]
    pub labeled: Option<bool>,
    #[serde(default, with = "crate::timestamp::option")]
    pub since: Option<OffsetDateTime>,
    #[serde(default, with = "crate::timestamp::option")]
    pub until: Option<OffsetDateTime>,
    /// Only these calls.
    #[serde(default)]
    pub call_ids: Option<BoundedVec<Text<36, 36>, 1, 2000>>,
    /// At most this many (newest first; the policy's `evals.max_replay` caps it).
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub note: Option<Text<0, 2000>>,
}

/// How a replay compares.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSummary {
    /// Calls replayed so far.
    pub done: u32,
    /// Of those, the ones that got no usable answer.
    pub errors: u32,
    /// Labelled calls replayed, and how many the replay got right.
    pub labeled: u32,
    pub labeled_right: u32,
    /// The original calls that had been labelled, and how many of those
    /// they got right (the baseline).
    pub original_right: u32,
    /// Calls whose replayed class differs from the original's.
    pub changed: u32,
    /// `expected -> class -> count`, over the labelled calls.
    pub confusion: Map<String, Value>,
    pub mean_latency_ms: u32,
}

/// One replayed call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCase {
    pub call_id: String,
    pub original: Option<String>,
    pub expected: Option<String>,
    pub class: Option<String>,
    pub error: Option<String>,
    pub latency_ms: i32,
    /// The replayed answer's one-sentence reason, if any.
    pub summary: Option<String>,
}

/// A replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunOut {
    pub id: String,
    pub kind: String,
    pub model: String,
    pub system_sha256: String,
    pub context: Value,
    pub selection: Value,
    /// `running`, `done` or `failed`.
    pub status: String,
    pub total: i32,
    pub note: String,
    pub created_by: String,
    #[serde(with = "crate::timestamp")]
    pub created_at: OffsetDateTime,
    #[serde(default, with = "crate::timestamp::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub summary: RunSummary,
    /// Every case (`GET /admin/evals/runs/{id}` only).
    #[serde(default)]
    pub cases: Vec<RunCase>,
}
