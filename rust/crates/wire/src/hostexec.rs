//! Commands on hosts, as agents see them (`/v1/hostexec/*`; hostexec spec
//! §10.5). Asking for one is an ordinary `POST /v1/requests`.

use agent_auth_core::JobId;
use serde::{Deserialize, Serialize};

use crate::common::TierName;
use crate::text::{BoundedMap, BoundedVec, Text};

/// `host_jobs.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Row committed, host not yet asked.
    Starting,
    Running,
    Done,
    /// The host (or the call) refused it.
    Refused,
    Lost,
}

impl JobStatus {
    /// No more output will come: `output` is included from here on.
    #[must_use]
    pub const fn has_ended(self) -> bool {
        matches!(self, JobStatus::Done | JobStatus::Refused | JobStatus::Lost)
    }
}

/// What a job runs: the argv, or a template's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JobCommand {
    Argv(Vec<String>),
    Template(String),
}

/// `GET /v1/hostexec/jobs/{id}` → 200 (Python `job_out`). `output` (the
/// whole kept output) appears once the job has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobOut {
    pub job_id: JobId,
    pub host: String,
    pub tier: TierName,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub output_bytes: Option<u64>,
    pub output_sha256: Option<String>,
    pub truncated: Option<bool>,
    pub command: Option<JobCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// A run grant's credential `value` (as JSON text): the job without its
/// output, plus the last lines of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummary {
    pub job_id: JobId,
    pub host: String,
    pub tier: TierName,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub output_bytes: Option<u64>,
    pub output_sha256: Option<String>,
    pub truncated: Option<bool>,
    pub command: Option<JobCommand>,
    /// The last 30 lines, at most 1500 characters.
    pub output_tail: String,
}

/// `POST /v1/hostexec/shells/{grant_id}/exec`. These are size caps only:
/// the spec rules (at most 256 arguments of 16 KiB, 64 KiB in all, 32
/// environment variables, timeout 1..86400, ...) are core's `make_spec`,
/// which answers 400 with its own messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecBody {
    pub argv: BoundedVec<Text<0, 65_536>, 1, 1024>,
    #[serde(default)]
    pub cwd: Option<Text<0, 8192>>,
    #[serde(default)]
    pub env: BoundedMap<Text<0, 256>, Text<0, 8192>, 256>,
    #[serde(default)]
    pub stdin: Option<Text<0, 262_144>>,
    #[serde(default)]
    pub timeout: Option<u32>,
    /// Seconds to wait for the command to end (clamped to 0..300).
    #[serde(default = "sixty")]
    pub wait: f64,
}

fn sixty() -> f64 {
    60.0
}

/// `POST /v1/hostexec/shells/{grant_id}/close` → 200.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellClosed {
    pub closed: bool,
}
