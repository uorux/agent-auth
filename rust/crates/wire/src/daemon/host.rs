//! The broker ↔ hostd channel (daemon spec §5): one enum per direction, the
//! data each call's reply carries, and hostd's heartbeat status.
//!
//! Job and shell specs travel as raw JSON ([`RawSpec`]): hostd digests a
//! spec exactly as received and re-validates it from scratch with core's
//! rules, so nothing here may normalize it.

use std::collections::BTreeMap;

use agent_auth_core::{DecisionSource, JobId, RequestId};
use serde::{Deserialize, Serialize};

use crate::common::TierName;
use crate::daemon::channel::{CallId, ChannelMessage, Heartbeat, PromptId, Reply};
use crate::duration::HostDuration;
use crate::json::RawSpec;
use crate::literal::ShellKind;
use crate::secret::TotpCode;
use crate::text::{LowerHex, Text};

/// What the broker sends a host. Calls carry a `call_id` and are answered
/// with a [`Reply`]; the rest are fire-and-forget.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BrokerToHost {
    /// Would the host run this (or open this shell)? Consumes nothing.
    #[serde(rename = "hostexec.precheck")]
    Precheck(Precheck),
    /// A human's TOTP code for one job's digest.
    #[serde(rename = "hostexec.authorize")]
    Authorize(Authorize),
    #[serde(rename = "job.start")]
    JobStart(JobStart),
    #[serde(rename = "job.kill")]
    JobKill(JobRef),
    /// The result arrived and verified: drop the spool.
    #[serde(rename = "job.ack")]
    JobAck(JobRef),
    #[serde(rename = "shell.open")]
    ShellOpen(ShellOpen),
    #[serde(rename = "shell.exec")]
    ShellExec(ShellExec),
    #[serde(rename = "shell.close")]
    ShellClose(ShellRef),
    #[serde(rename = "arm")]
    Arm(Arm),
    #[serde(rename = "disarm")]
    Disarm(Disarm),
    #[serde(rename = "lockdown")]
    Lockdown(Lockdown),
    /// Needs the host's root-arm code.
    #[serde(rename = "unlock")]
    Unlock(Unlock),
    #[serde(rename = "dnd")]
    Dnd(Dnd),
    /// Ask the person at this desktop.
    #[serde(rename = "prompt")]
    Prompt(Prompt),
    #[serde(rename = "prompt.cancel")]
    PromptCancel(PromptCancel),
    #[serde(rename = "notify")]
    Notify(Notify),
}

impl ChannelMessage for BrokerToHost {
    const TYPES: &'static [&'static str] = &[
        "hostexec.precheck",
        "hostexec.authorize",
        "job.start",
        "job.kill",
        "job.ack",
        "shell.open",
        "shell.exec",
        "shell.close",
        "arm",
        "disarm",
        "lockdown",
        "unlock",
        "dnd",
        "prompt",
        "prompt.cancel",
        "notify",
    ];
}

impl BrokerToHost {
    /// The call's id, when this is a call.
    #[must_use]
    pub fn call_id(&self) -> Option<&CallId> {
        match self {
            BrokerToHost::Precheck(Precheck::Job(m)) => m.call_id.as_ref(),
            BrokerToHost::Precheck(Precheck::Shell(m)) => m.call_id.as_ref(),
            BrokerToHost::Authorize(m) => m.call_id.as_ref(),
            BrokerToHost::JobStart(m) => m.call_id.as_ref(),
            BrokerToHost::JobKill(m) | BrokerToHost::JobAck(m) => m.call_id.as_ref(),
            BrokerToHost::ShellOpen(m) => m.call_id.as_ref(),
            BrokerToHost::ShellExec(m) => m.call_id.as_ref(),
            BrokerToHost::ShellClose(m) => m.call_id.as_ref(),
            BrokerToHost::Arm(m) => m.call_id.as_ref(),
            BrokerToHost::Disarm(m) => m.call_id.as_ref(),
            BrokerToHost::Lockdown(m) => m.call_id.as_ref(),
            BrokerToHost::Unlock(m) => m.call_id.as_ref(),
            BrokerToHost::Dnd(m) => m.call_id.as_ref(),
            BrokerToHost::Prompt(m) => m.call_id.as_ref(),
            BrokerToHost::PromptCancel(m) => m.call_id.as_ref(),
            BrokerToHost::Notify(m) => m.call_id.as_ref(),
        }
    }
}

/// What a host sends the broker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HostToBroker {
    #[serde(rename = "heartbeat")]
    Heartbeat(Heartbeat),
    #[serde(rename = "reply")]
    Reply(Reply),
    /// One chunk of a finished job's output.
    #[serde(rename = "job.output")]
    JobOutput(JobOutput),
    /// A job's result; resent every ~15 s until acked.
    #[serde(rename = "job.done")]
    JobDone(JobDone),
    /// The desktop's presence changed.
    #[serde(rename = "presence")]
    Presence(Presence),
    /// The person at the desk answered a prompt.
    #[serde(rename = "prompt.answer")]
    PromptAnswer(PromptAnswer),
}

impl ChannelMessage for HostToBroker {
    const TYPES: &'static [&'static str] = &[
        "heartbeat",
        "reply",
        "job.output",
        "job.done",
        "presence",
        "prompt.answer",
    ];
}

/// Who decided a request, as hostd is told (believed only while armed).
pub type Source = DecisionSource;

/// `hostexec.precheck`: a job's form, or a shell's (`"kind": "shell"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Precheck {
    Shell(PrecheckShell),
    Job(PrecheckJob),
}

/// Everything the host would refuse about a shell, before a code is spent.
/// Replied `{"needs": "totp"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecheckShell {
    pub kind: ShellKind,
    pub tier: TierName,
    pub duration: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// Would the host admit this job, and on what? Replied `{"via": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecheckJob {
    pub spec: RawSpec,
    #[serde(default)]
    pub source: Option<Source>,
    /// A TOTP code will come with the approval.
    #[serde(default)]
    pub totp: bool,
    /// It may already be approved at that host's desk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    /// An approve-all window's probe.
    #[serde(default)]
    pub window: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `hostexec.authorize`: the code is checked against the tier's direct
/// secret, and authorizes only this digest, for this tier. Replied
/// `{"authorized": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorize {
    pub job_id: JobId,
    pub tier: TierName,
    /// `sha256` of the spec's canonical JSON, lowercase hex.
    pub digest: LowerHex<64>,
    pub totp: TotpCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `job.start`. Replied `{"started": true, "via": ...}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStart {
    pub job_id: JobId,
    pub spec: RawSpec,
    pub evidence: Evidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// Why the broker says a job was approved. hostd believes it only while the
/// tier is armed; a TOTP code or the desk needs no believing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub request_id: RequestId,
    pub decided_by: Option<Text<0, 256>>,
    pub source: Option<Source>,
    /// Approved by an approve-all window rule.
    pub window: bool,
}

/// `job.kill` (replied `{"killed": bool}`) and `job.ack` (sent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRef {
    pub job_id: JobId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `shell.open`: the shell's id is its request's. Replied
/// `{"expires_at": <unix seconds>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellOpen {
    pub shell_id: RequestId,
    pub spec: RawSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `shell.exec`: one command in an open shell. Replied `{"started": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExec {
    pub shell_id: RequestId,
    pub job_id: JobId,
    pub spec: RawSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `shell.close` (a call, or sent on connect). Replied `{"closed": bool}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellRef {
    pub shell_id: RequestId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `arm`: the code is for the tier's arm secret. Replied
/// `{"armed_until": <unix seconds>}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub tier: TierName,
    pub duration: HostDuration,
    pub totp: TotpCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `disarm`: one tier, or both (null). Needs no proof. Replied
/// `{"disarmed": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disarm {
    pub tier: Option<TierName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `lockdown` (hosts and sandboxes alike; sandboxes ignore `kill_vm`).
/// Needs no proof: it only removes authority. A host replies
/// `{"locked": true, "vm": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockdown {
    pub kill_vm: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `unlock` to a host: needs its root-arm code. Replied
/// `{"locked": false, "vm": ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unlock {
    pub totp: TotpCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `dnd`: no desk prompts for this long (null ends it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dnd {
    pub duration: Option<HostDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `prompt`: hostd collapses each text to one line and cuts `who`, `what`
/// and `detail` to 120, 600 and 800 characters. With `job`, the command is
/// at this host's desk and hostd rebuilds `what` from what it would run.
/// Replied `{"shown": true, "approves": bool}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    pub prompt_id: PromptId,
    pub request_id: RequestId,
    pub who: Text<0, 4096>,
    pub what: Text<0, 16384>,
    pub detail: Text<0, 16384>,
    /// Seconds (hostd caps it at its own maximum).
    pub timeout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<DeskJob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// The command a desk prompt would approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeskJob {
    pub job_id: JobId,
    pub spec: RawSpec,
}

/// `prompt.cancel`: decided some other way; take the dialog down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptCancel {
    pub prompt_id: PromptId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// A desktop notification's urgency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Urgency {
    Low,
    Normal,
    Critical,
}

/// `notify`: hostd cuts the title to 120 and the text to 600 characters.
/// Replied `{"shown": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    pub title: Text<0, 1024>,
    pub text: Text<0, 4096>,
    pub urgency: Urgency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<CallId>,
}

/// `job.output`: one chunk (at most 96 KiB of output, standard padded
/// base64), in order. The chunk's index is `chunk`: the Python's `seq`
/// collided with the envelope's own `seq`, which replaced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOutput {
    pub job_id: JobId,
    /// 0 for the first chunk (which resets the broker's buffer).
    #[serde(default)]
    pub chunk: Option<u32>,
    /// Standard base64 with padding; the broker decodes it strictly.
    pub data: Text<0, 131_072>,
}

/// `job.done`: the result. The broker acks once `sha256` matches the
/// chunks it received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobDone {
    pub job_id: JobId,
    pub exit_code: Option<i32>,
    pub error: Option<Text<0, 16384>>,
    /// Rounded to milliseconds.
    pub duration_secs: Option<f64>,
    /// Bytes of output kept (the end of it, at most 1 MiB).
    pub bytes: u64,
    pub sha256: LowerHex<64>,
    pub truncated: bool,
    /// The job was running when hostd stopped (crash, reboot): its outcome
    /// is unknown, and the broker records it as `lost` (daemons bug 3).
    /// Absent (false) from a Python hostd.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
}

/// `presence`: the desktop part of hostd's status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presence {
    pub enabled: bool,
    pub present: bool,
    pub away_reason: Option<Text<0, 256>>,
    /// Unix seconds.
    pub dnd_until: Option<f64>,
}

/// What the person at the desk did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    Allow,
    Deny,
    /// No more prompts for this agent for a while.
    Mute,
    /// Leave it to Discord.
    Discord,
    Timeout,
}

/// `prompt.answer`. `authorized`: an `allow` that hostd turned into an
/// authorization for the job's digest (an `allow` it could not honour
/// arrives as `discord`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptAnswer {
    pub prompt_id: PromptId,
    pub answer: Answer,
    pub authorized: bool,
}

// ------------------------------------------------------------ reply data

/// `hostexec.precheck`'s reply: `{"via": ...}` for a job, `{"needs":
/// "totp"}` for a shell.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PrecheckReply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeReply {
    pub authorized: bool,
}

/// `job.start` (with `via`) and `shell.exec` (without).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartedReply {
    pub started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KilledReply {
    pub killed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ShellOpenedReply {
    /// Unix seconds.
    pub expires_at: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedReply {
    pub closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ArmedReply {
    /// Unix seconds.
    pub armed_until: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisarmedReply {
    pub disarmed: bool,
}

/// `lockdown` and `unlock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockReply {
    pub locked: bool,
    /// What happened to the VM unit (`freeze: ok`, ...), if there is one.
    pub vm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DndReply {
    pub dnd_until: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptReply {
    pub shown: bool,
    /// Allow at this desk approves the job (otherwise an Allow there is
    /// only a click, and the decision stays with Discord).
    pub approves: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShownReply {
    pub shown: bool,
}

// ---------------------------------------------------------------- status

/// hostd's heartbeat status (daemon spec §8.13). Read leniently (it is
/// informational, stored as the daemon's `last_status`): missing fields take
/// their defaults, unknown ones are ignored.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostStatus {
    pub version: Option<String>,
    pub role: Option<String>,
    pub started_at: Option<f64>,
    pub tiers: BTreeMap<TierName, TierStatus>,
    pub jobs: u32,
    pub shells: u32,
    pub lockdown: bool,
    pub vm: Option<VmStatus>,
    pub templates: Vec<String>,
    pub desktop: Option<DesktopStatus>,
    /// Set instead of the rest when status could not be taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TierStatus {
    pub enabled: bool,
    /// Unix seconds, null unless in the future.
    pub armed_until: Option<f64>,
    /// Shells enabled for the tier.
    pub shell: bool,
    /// Both of the tier's TOTP secrets are enrolled.
    pub totp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VmStatus {
    pub unit: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DesktopStatus {
    pub enabled: bool,
    pub present: bool,
    pub away_reason: Option<String>,
    pub dnd_until: Option<f64>,
}

/// A precheck that a job's approval would come with a code, as the gate
/// sends it.
impl PrecheckJob {
    #[must_use]
    pub fn human(job_id: JobId, spec: RawSpec, totp: bool) -> Self {
        PrecheckJob {
            spec,
            source: Some(DecisionSource::Human),
            totp,
            job_id: Some(job_id),
            window: false,
            call_id: None,
        }
    }
}
