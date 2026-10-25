//! What hostd decides, without I/O: whether a job runs, on what evidence,
//! and how TOTP codes are counted (daemons-hostd spec §7-§8).
//!
//! The broker proposes; hostd decides from its own state and config. The
//! decision is typed so it cannot be skipped:
//!
//! - A job runs only as an [`AdmittedJob`], which only [`admit`] (a broker's
//!   `job.start`) and [`admit_shell_command`] (a command in an open shell)
//!   build.
//! - A TOTP code becomes a [`TotpApproval`] only through a
//!   [`totp::Attempt`] that the lockout let through and whose code matched a
//!   step after the last used one; the approval names the tier of the
//!   secret that verified it and the digest it was typed for, and admission
//!   requires both to be the job's (a code approves a job of its own tier
//!   only).
//! - A shell opens only as an [`OpenShell`], from a TOTP approval for the
//!   shell's exact spec.
//! - A root job needs a human: a root-direct code, a desk Allow with the
//!   user's password (polkit), or the root tier armed by a root-arm code or
//!   by root on the host ([`ArmProof`]).
//!
//! Time is passed in ([`UnixMillis`]); nothing here reads a clock.

mod admission;
pub mod display;
pub mod output;
pub mod policy;
pub mod totp;

#[cfg(test)]
mod tests;

use std::fmt;

use serde_json::Value;

pub use admission::{
    AUTHZ_TTL_SECS, AdmissionFacts, AdmittedJob, ApprovalVia, ArmProof, ArmState, Authorizations,
    AuthzFacts, DeskApproval, DeskPrompt, Evidence, HostView, LocalCaller, Normalized, OpenShell,
    PolkitConfirmed, RefusalKind, TotpApproval, admit, admit_shell_command, check_tier, decide,
    desk_approval, desk_prompt, loggable, normalize, open_shell, parse_shell_request, precheck_job,
    precheck_shell,
};
pub use policy::{HostPolicy, TierPolicy};

use crate::authority::Tier;
use crate::hostexec::SpecError;
use crate::pyfmt::repr;

/// hostd will not do it. The text goes back to the broker and the human
/// (the Python's `Refused`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

impl Refused {
    pub fn new(msg: impl Into<String>) -> Refused {
        Refused(msg.into())
    }
}

impl From<SpecError> for Refused {
    fn from(e: SpecError) -> Refused {
        Refused(e.0)
    }
}

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixMillis(pub u64);

impl UnixMillis {
    #[must_use]
    pub fn plus_secs(self, secs: u64) -> UnixMillis {
        UnixMillis(self.0.saturating_add(secs.saturating_mul(1000)))
    }

    /// Whole seconds (rounded down).
    #[must_use]
    pub fn secs(self) -> u64 {
        self.0 / 1000
    }

    /// Seconds as a float, for the wire (`armed_until`, `expires_at`).
    #[must_use]
    pub fn as_secs_f64(self) -> f64 {
        let whole = u32::try_from(self.0 / 1000).map_or(f64::from(u32::MAX), f64::from);
        let frac = u32::try_from(self.0 % 1000).map_or(0.0, f64::from);
        whole + frac / 1000.0
    }

    /// From float seconds (a peer's or the clock's); NaN and negatives are 0.
    #[must_use]
    pub fn from_secs_f64(secs: f64) -> UnixMillis {
        if secs.is_nan() || secs <= 0.0 {
            return UnixMillis(0);
        }
        let ms = (secs * 1000.0).floor();
        // A finite non-negative float below 2^53 converts exactly through
        // its decimal text; anything larger saturates.
        if ms >= 9.0e15 {
            return UnixMillis(u64::MAX);
        }
        UnixMillis(format!("{ms:.0}").parse().unwrap_or(0))
    }
}

/// Whether the host is locked down (the lockdown file exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Unlocked,
    Locked,
}

impl LockState {
    #[must_use]
    pub fn is_locked(self) -> bool {
        self == LockState::Locked
    }
}

/// A job, shell or prompt id as hostd accepts it: `[0-9a-f-]{8,64}`. This is
/// what keeps spool paths inside the spool directory (INV-28).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalId(String);

impl LocalId {
    pub fn parse(s: &str) -> Result<LocalId, Refused> {
        let ok = (8..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f' | b'-'));
        if ok {
            Ok(LocalId(s.to_owned()))
        } else {
            Err(Refused::new("malformed job id"))
        }
    }

    /// `_job_id(v)`: a JSON value that must be such a string.
    pub fn from_value(v: Option<&Value>) -> Result<LocalId, Refused> {
        match v {
            Some(Value::String(s)) => LocalId::parse(s),
            _ => Err(Refused::new("malformed job id")),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for LocalId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A job spec's digest: 64 lowercase hex digits (SHA-256 of its canonical
/// JSON, computed by the caller: this crate does no hashing).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecDigest(String);

impl SpecDigest {
    pub fn parse(s: &str) -> Result<SpecDigest, Refused> {
        let ok = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(SpecDigest(s.to_owned()))
        } else {
            Err(Refused::new("malformed digest"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpecDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who the broker says approved a job. Believed only while the tier is
/// armed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    Human,
    Rule,
    Llm,
    Policy,
}

impl Source {
    #[must_use]
    pub fn parse(s: &str) -> Option<Source> {
        match s {
            "human" => Some(Source::Human),
            "rule" => Some(Source::Rule),
            "llm" => Some(Source::Llm),
            "policy" => Some(Source::Policy),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Human => "human",
            Source::Rule => "rule",
            Source::Llm => "llm",
            Source::Policy => "policy",
        }
    }

    /// From an `evidence.source` / precheck `source` JSON value.
    #[must_use]
    pub fn from_value(v: Option<&Value>) -> Option<Source> {
        v.and_then(Value::as_str).and_then(Source::parse)
    }
}

/// What a job was admitted on (`via`, reported to the broker and journaled).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// A direct TOTP code for this job's digest and tier.
    Totp,
    /// Allow at this host's desk (with polkit for root).
    Desk,
    /// A user-tier `run` matching an `auto_commands` pattern.
    Auto,
    /// Armed, and an approve-all window the tier accepts.
    ArmedWindow,
    /// Armed, and a human's approval.
    ArmedHuman,
    /// Armed, a machine approval, and the tier accepts those.
    ArmedRule,
    ArmedLlm,
    ArmedPolicy,
    /// A command in a shell a TOTP code opened.
    Shell,
}

impl Via {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Totp => "totp",
            Via::Desk => "desk",
            Via::Auto => "auto",
            Via::ArmedWindow => "armed+window",
            Via::ArmedHuman => "armed+human",
            Via::ArmedRule => "armed+rule",
            Via::ArmedLlm => "armed+llm",
            Via::ArmedPolicy => "armed+policy",
            Via::Shell => "shell",
        }
    }

    /// Admitted because the tier was armed.
    #[must_use]
    pub fn is_armed(self) -> bool {
        matches!(
            self,
            Via::ArmedWindow | Via::ArmedHuman | Via::ArmedRule | Via::ArmedLlm | Via::ArmedPolicy
        )
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `{tier}` an error message names.
fn tier_word(t: Tier) -> &'static str {
    t.as_str()
}

/// Python's `{value!r}` for a JSON value that is usually a string.
fn repr_value(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(s)) => repr(s),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(other) => other.to_string(),
    }
}
