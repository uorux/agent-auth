//! How hostd counts TOTP codes: single use, and wrong codes lock the secret
//! with a lockout that escalates (daemons-hostd spec §7, bug 6).
//!
//! The code itself is checked by the caller (HMAC lives in the crypto
//! crate): it computes the highest step in the window whose code matches,
//! and hands it to [`Attempt::conclude`]. What this module decides:
//!
//! 1. A hard-locked secret accepts nothing until root on the host clears it
//!    (`agent-auth-hostctl totp-unlock NAME`). A locked one accepts nothing
//!    until its lockout ends. Neither counts as a failure.
//! 2. A wrong code is a failure. Every [`MAX_FAILURES`] consecutive failures
//!    lock the secret, for 5 min, then 10, 20, ... (doubling, at most
//!    [`BASE_LOCKOUT_SECS`]` << `[`MAX_LOCKOUT_SHIFT`]), until a code is
//!    accepted. [`HARD_LOCK_FAILURES`] wrong codes within
//!    [`FAILURE_WINDOW_SECS`] hard-lock it, accepted codes in between or
//!    not.
//! 3. A right code for a step at or before the last accepted one is
//!    refused (not a failure); otherwise its step becomes the last accepted
//!    one, which the caller persists before acting on it.
//!
//! Why the escalation: the Python allowed 5 guesses per 300 s forever,
//! about 1 guess a minute; with 3 valid codes per window that is ≈79 %
//! a year for whoever relays codes to the host (a compromised broker, the
//! adversary TOTP is there for). Here at most 20 wrong codes in any 30
//! days are evaluated, then none until root on the host clears the hard
//! lock (≈6e-5 per clearing), and a hard lock shows in the host's status.

use std::fmt;

use serde_json::{Map, Value, json};

use crate::authority::Tier;

/// Consecutive wrong codes that lock a secret.
pub const MAX_FAILURES: u32 = 5;
/// The first lockout; each further one (without an accepted code in
/// between) doubles it.
pub const BASE_LOCKOUT_SECS: u64 = 300;
/// The lockout stops doubling after this many doublings (300 s × 256 ≈ 21 h).
pub const MAX_LOCKOUT_SHIFT: u32 = 8;
/// Wrong codes within [`FAILURE_WINDOW_SECS`] that hard-lock a secret.
pub const HARD_LOCK_FAILURES: usize = 20;
pub const FAILURE_WINDOW_SECS: u64 = 30 * 86400;
/// Seconds per TOTP step.
pub const STEP_SECS: u64 = 30;
/// Steps accepted on either side of the current one.
pub const WINDOW_STEPS: u64 = 1;

/// What a secret is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Opens an arming window for its tier.
    Arm,
    /// Approves one request (its digest), armed or not.
    Direct,
    /// Opens one shell (its digest). Optional for the user tier (a
    /// `user-direct` code does when it isn't enrolled); a root shell needs
    /// it (security review 2026-10, finding 4).
    Shell,
    /// Lifts a lockdown from the broker (`root-unlock` only): a code typed
    /// to unlock can't arm.
    Unlock,
}

/// One of a host's secrets: `user-arm`, `user-direct`, `root-arm`,
/// `root-direct`, and the optional `user-shell`, `root-shell` and
/// `root-unlock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretName {
    pub tier: Tier,
    pub purpose: Purpose,
}

impl SecretName {
    /// The four every host has.
    pub const ALL: [SecretName; 4] = [
        SecretName::new(Tier::User, Purpose::Arm),
        SecretName::new(Tier::User, Purpose::Direct),
        SecretName::new(Tier::Root, Purpose::Arm),
        SecretName::new(Tier::Root, Purpose::Direct),
    ];

    /// Enrolled only when wanted.
    pub const OPTIONAL: [SecretName; 3] = [
        SecretName::new(Tier::User, Purpose::Shell),
        SecretName::new(Tier::Root, Purpose::Shell),
        SecretName::new(Tier::Root, Purpose::Unlock),
    ];

    /// Every name a secret may have.
    pub fn every() -> impl Iterator<Item = SecretName> {
        SecretName::ALL.into_iter().chain(SecretName::OPTIONAL)
    }

    #[must_use]
    pub const fn new(tier: Tier, purpose: Purpose) -> SecretName {
        SecretName { tier, purpose }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<SecretName> {
        SecretName::every().find(|n| n.as_str() == s)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match (self.tier, self.purpose) {
            (Tier::User, Purpose::Arm) => "user-arm",
            (Tier::User, Purpose::Direct) => "user-direct",
            (Tier::Root, Purpose::Arm) => "root-arm",
            (Tier::Root, Purpose::Direct) => "root-direct",
            (Tier::User, Purpose::Shell) => "user-shell",
            (Tier::Root, Purpose::Shell) => "root-shell",
            // Not a secret a host has (unlocking is root's).
            (Tier::User, Purpose::Unlock) => "user-unlock",
            (Tier::Root, Purpose::Unlock) => "root-unlock",
        }
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What is persisted per secret (`{name}.state`), written before the caller
/// acts on an accepted code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TotpState {
    /// The last accepted step; codes for it or earlier steps are refused.
    pub last_step: Option<u64>,
    /// Wrong codes since the last lockout or accepted code.
    pub failures: u32,
    /// Lockouts since the last accepted code (the escalation).
    pub lockouts: u32,
    /// Unix seconds.
    pub locked_until: Option<u64>,
    /// Unix seconds of the wrong codes within the window, oldest first (at
    /// most [`HARD_LOCK_FAILURES`]).
    pub recent_failures: Vec<u64>,
    /// Only root on the host clears it.
    pub hard_locked: bool,
}

impl TotpState {
    /// Reads a state file's JSON. Missing keys take their defaults; a
    /// Python hostd's state (`last_step` −1, float `locked_until`) reads as
    /// the same state. `None`: not a state (the caller treats an unreadable
    /// state as hard-locked rather than forgetting the last used step).
    #[must_use]
    pub fn from_json(v: &Value) -> Option<TotpState> {
        let Value::Object(map) = v else {
            return None;
        };
        let uint = |k: &str| -> Option<Option<u64>> {
            match map.get(k) {
                None | Some(Value::Null) => Some(None),
                Some(Value::Number(n)) => {
                    if let Some(u) = n.as_u64() {
                        Some(Some(u))
                    } else if let Some(i) = n.as_i64() {
                        // Python's "never" is -1.
                        (i < 0).then_some(None)
                    } else {
                        let f = n.as_f64()?;
                        (f.is_finite() && f >= 0.0).then(|| Some(float_secs(f)))
                    }
                }
                Some(_) => None,
            }
        };
        let last_step = uint("last_step")?;
        let failures = uint("failures")?
            .map_or(Some(0), |f| u32::try_from(f).ok())
            .unwrap_or(u32::MAX);
        let lockouts = uint("lockouts")?
            .map_or(Some(0), |f| u32::try_from(f).ok())
            .unwrap_or(u32::MAX);
        let locked_until = uint("locked_until")?;
        let recent_failures = match map.get("recent_failures") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let mut out = Vec::new();
                for item in items.iter().take(HARD_LOCK_FAILURES) {
                    out.push(item.as_u64()?);
                }
                out
            }
            Some(_) => return None,
        };
        let hard_locked = match map.get("hard_locked") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        Some(TotpState {
            last_step,
            failures,
            lockouts,
            locked_until,
            recent_failures,
            hard_locked,
        })
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("last_step".into(), json!(self.last_step));
        map.insert("failures".into(), json!(self.failures));
        map.insert("lockouts".into(), json!(self.lockouts));
        map.insert("locked_until".into(), json!(self.locked_until));
        map.insert("recent_failures".into(), json!(self.recent_failures));
        map.insert("hard_locked".into(), json!(self.hard_locked));
        Value::Object(map)
    }

    /// Root on the host clears a lock (`totp-unlock`). The last used step
    /// is kept: clearing a lock never makes a code reusable.
    pub fn clear_lock(&mut self) {
        self.failures = 0;
        self.lockouts = 0;
        self.locked_until = None;
        self.recent_failures.clear();
        self.hard_locked = false;
    }

    /// Is the secret refusing every code at `now` (and why)?
    #[must_use]
    pub fn lock_reason(&self, name: SecretName, now_secs: u64) -> Option<TotpRefusal> {
        if self.hard_locked {
            return Some(TotpRefusal::HardLocked { name });
        }
        match self.locked_until {
            Some(until) if until > now_secs => Some(TotpRefusal::Locked {
                name,
                secs: until.saturating_sub(now_secs),
            }),
            _ => None,
        }
    }
}

fn float_secs(f: f64) -> u64 {
    if f >= 1.8e19 {
        u64::MAX
    } else {
        format!("{:.0}", f.ceil()).parse().unwrap_or(u64::MAX)
    }
}

/// Why a code was not accepted. The texts keep the Python's words
/// (`wrong code`, `already used`, `locked`), which UIs and tests match on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpRefusal {
    #[error(
        "too many wrong codes; {name} is locked until root on the host clears it \
         (agent-auth-hostctl totp-unlock {name})"
    )]
    HardLocked { name: SecretName },
    #[error("too many wrong codes; {name} is locked for {secs}s")]
    Locked { name: SecretName, secs: u64 },
    #[error("wrong code")]
    WrongCode,
    #[error("that code was already used; wait for the next one")]
    AlreadyUsed,
}

/// A code was accepted for this secret at this step (persist the state the
/// attempt left before acting on it). Only [`Attempt::conclude`] makes one.
#[derive(Debug, PartialEq, Eq)]
pub struct AcceptedCode {
    name: SecretName,
    step: u64,
}

impl AcceptedCode {
    #[must_use]
    pub fn name(&self) -> SecretName {
        self.name
    }

    #[must_use]
    pub fn step(&self) -> u64 {
        self.step
    }
}

/// One verification in progress: the lockouts let it through. Not `Clone`:
/// one attempt, one conclusion.
#[derive(Debug)]
pub struct Attempt {
    name: SecretName,
    now_secs: u64,
}

/// Start verifying a code for `name` at `now_secs`: refused while the
/// secret is (hard-)locked, before the code is even looked at.
pub fn begin(state: &TotpState, name: SecretName, now_secs: u64) -> Result<Attempt, TotpRefusal> {
    match state.lock_reason(name, now_secs) {
        Some(refusal) => Err(refusal),
        None => Ok(Attempt { name, now_secs }),
    }
}

/// The lockout after `n` lockouts in a row (n ≥ 1).
#[must_use]
pub fn lockout_secs(n: u32) -> u64 {
    let shift = n.saturating_sub(1).min(MAX_LOCKOUT_SHIFT);
    BASE_LOCKOUT_SECS << shift
}

impl Attempt {
    #[must_use]
    pub fn name(&self) -> SecretName {
        self.name
    }

    /// The steps a code may be for at this attempt's time.
    #[must_use]
    pub fn window(&self) -> (u64, u64) {
        let current = self.now_secs / STEP_SECS;
        (
            current.saturating_sub(WINDOW_STEPS),
            current.saturating_add(WINDOW_STEPS),
        )
    }

    /// Conclude with `matched`: the highest step within [`Attempt::window`]
    /// whose code equals the one given, or `None`. Updates `state`; the
    /// caller persists it whatever the outcome (an accepted code before it
    /// acts on it).
    pub fn conclude(
        self,
        state: &mut TotpState,
        matched: Option<u64>,
    ) -> Result<AcceptedCode, TotpRefusal> {
        let (first, last) = self.window();
        let matched = matched.filter(|s| (first..=last).contains(s));
        let Some(step) = matched else {
            self.fail(state);
            return Err(TotpRefusal::WrongCode);
        };
        if state.last_step.is_some_and(|l| step <= l) {
            return Err(TotpRefusal::AlreadyUsed);
        }
        state.last_step = Some(step);
        state.failures = 0;
        state.lockouts = 0;
        state.locked_until = None;
        Ok(AcceptedCode {
            name: self.name,
            step,
        })
    }

    fn fail(&self, state: &mut TotpState) {
        let now = self.now_secs;
        let horizon = now.saturating_sub(FAILURE_WINDOW_SECS);
        state.recent_failures.retain(|t| *t > horizon);
        state.recent_failures.push(now);
        let excess = state
            .recent_failures
            .len()
            .saturating_sub(HARD_LOCK_FAILURES);
        state.recent_failures.drain(..excess);
        state.failures = state.failures.saturating_add(1);
        if state.recent_failures.len() >= HARD_LOCK_FAILURES {
            state.hard_locked = true;
        }
        if state.failures >= MAX_FAILURES {
            state.failures = 0;
            state.lockouts = state.lockouts.saturating_add(1);
            state.locked_until = Some(now.saturating_add(lockout_secs(state.lockouts)));
        }
    }
}

/// Test and proof support: an accepted code without running an attempt.
#[cfg(any(test, kani))]
impl AcceptedCode {
    pub(crate) fn for_tests(name: SecretName, step: u64) -> AcceptedCode {
        AcceptedCode { name, step }
    }
}
