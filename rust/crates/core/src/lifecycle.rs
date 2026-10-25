//! The access request's state machine, as types.
//!
//! Each status is also a zero-sized marker type, and `CanMoveTo<To>` is
//! implemented exactly for the allowed transitions. The store's transition
//! function is generic over `From: CanMoveTo<To>`, so code that tries to,
//! say, move a DENIED request to APPROVED does not compile. The runtime
//! table (`RequestStatus::can_transition`) is generated from the same list,
//! for rows whose status is only known at run time; a test checks the two
//! agree, and the Kani harnesses in `proofs` check the table's properties.

use std::fmt;

use serde::{Deserialize, Serialize};

mod sealed {
    pub trait Sealed {}
}

/// A request status known at compile time.
pub trait State: sealed::Sealed + fmt::Debug + Copy + 'static {
    const STATUS: RequestStatus;
}

/// `Self -> To` is an allowed transition.
pub trait CanMoveTo<To: State>: State {}

macro_rules! statuses {
    ($($variant:ident = $text:literal),* $(,)?) => {
        /// `access_requests.status`
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum RequestStatus { $($variant),* }

        impl RequestStatus {
            pub const ALL: &'static [RequestStatus] = &[$(RequestStatus::$variant),*];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(RequestStatus::$variant => $text),* }
            }

            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($text => Some(RequestStatus::$variant),)* _ => None }
            }
        }

        /// Marker types, one per status.
        pub mod state {
            $(
                #[derive(Debug, Clone, Copy)]
                pub struct $variant;
                impl super::sealed::Sealed for $variant {}
                impl super::State for $variant {
                    const STATUS: super::RequestStatus = super::RequestStatus::$variant;
                }
            )*
        }
    };
}

statuses! {
    Pending = "pending",
    LlmEvaluating = "llm_evaluating",
    LlmDenied = "llm_denied",
    AwaitingHuman = "awaiting_human",
    Approved = "approved",
    Provisioning = "provisioning",
    Granted = "granted",
    ProvisionFailed = "provision_failed",
    Denied = "denied",
}

macro_rules! transitions {
    ($($from:ident => [$($to:ident),*]),* $(,)?) => {
        $($(impl CanMoveTo<state::$to> for state::$from {})*)*

        impl RequestStatus {
            /// The allowed transitions out of this status.
            #[must_use]
            pub const fn successors(self) -> &'static [RequestStatus] {
                match self {
                    $(RequestStatus::$from => &[$(RequestStatus::$to),*],)*
                }
            }
        }
    };
}

transitions! {
    Pending => [Denied, Approved, LlmEvaluating, AwaitingHuman],
    LlmEvaluating => [Approved, LlmDenied, AwaitingHuman],
    LlmDenied => [LlmEvaluating, AwaitingHuman],
    AwaitingHuman => [Approved, Denied],
    Approved => [Provisioning],
    Provisioning => [Granted, ProvisionFailed],
    Granted => [],
    ProvisionFailed => [],
    Denied => [],
}

impl RequestStatus {
    #[must_use]
    pub fn can_transition(self, to: RequestStatus) -> bool {
        self.successors().contains(&to)
    }

    /// No transition out of these.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        self.successors().is_empty()
    }

    /// The agent's long-poll keeps waiting while the request is in one of
    /// these (AWAITING_HUMAN included: the agent is blocked on the human).
    #[must_use]
    pub const fn is_waiting(self) -> bool {
        matches!(
            self,
            RequestStatus::Pending
                | RequestStatus::LlmEvaluating
                | RequestStatus::AwaitingHuman
                | RequestStatus::Approved
                | RequestStatus::Provisioning
        )
    }

    /// A human may still decide it (and containment denies it).
    #[must_use]
    pub const fn is_human_decidable(self) -> bool {
        matches!(
            self,
            RequestStatus::AwaitingHuman | RequestStatus::LlmDenied | RequestStatus::LlmEvaluating
        )
    }
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `grants.status`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    /// Row committed, provisioner not finished: the durable record that an
    /// external mutation MAY exist. Never issuable; reaped if left behind.
    Provisioning,
    Active,
    Expired,
    Revoked,
    ProvisionFailed,
}

impl GrantStatus {
    pub const ALL: [GrantStatus; 5] = [
        GrantStatus::Provisioning,
        GrantStatus::Active,
        GrantStatus::Expired,
        GrantStatus::Revoked,
        GrantStatus::ProvisionFailed,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            GrantStatus::Provisioning => "provisioning",
            GrantStatus::Active => "active",
            GrantStatus::Expired => "expired",
            GrantStatus::Revoked => "revoked",
            GrantStatus::ProvisionFailed => "provision_failed",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        GrantStatus::ALL.into_iter().find(|g| g.as_str() == s)
    }

    /// Grant transitions: PROVISIONING ends in ACTIVE or PROVISION_FAILED;
    /// ACTIVE ends in EXPIRED or REVOKED; the rest are final.
    #[must_use]
    pub const fn can_transition(self, to: GrantStatus) -> bool {
        matches!(
            (self, to),
            (
                GrantStatus::Provisioning,
                GrantStatus::Active | GrantStatus::ProvisionFailed
            ) | (
                GrantStatus::Active,
                GrantStatus::Expired | GrantStatus::Revoked
            )
        )
    }
}

impl fmt::Display for GrantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who made a request's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    Policy,
    Rule,
    Llm,
    Human,
}

impl DecisionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            DecisionSource::Policy => "policy",
            DecisionSource::Rule => "rule",
            DecisionSource::Llm => "llm",
            DecisionSource::Human => "human",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Policy, Self::Rule, Self::Llm, Self::Human]
            .into_iter()
            .find(|d| d.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Python table (core/states.py ALLOWED_TRANSITIONS), verbatim.
    const PYTHON: &[(&str, &[&str])] = &[
        (
            "pending",
            &["denied", "approved", "llm_evaluating", "awaiting_human"],
        ),
        (
            "llm_evaluating",
            &["approved", "llm_denied", "awaiting_human"],
        ),
        ("llm_denied", &["llm_evaluating", "awaiting_human"]),
        ("awaiting_human", &["approved", "denied"]),
        ("approved", &["provisioning"]),
        ("provisioning", &["granted", "provision_failed"]),
        ("granted", &[]),
        ("provision_failed", &[]),
        ("denied", &[]),
    ];

    #[test]
    fn table_matches_python() {
        assert_eq!(PYTHON.len(), RequestStatus::ALL.len());
        for (from, tos) in PYTHON {
            let from = RequestStatus::parse(from).expect("known status");
            let mut ours: Vec<&str> = from.successors().iter().map(|s| s.as_str()).collect();
            let mut theirs: Vec<&str> = tos.to_vec();
            ours.sort_unstable();
            theirs.sort_unstable();
            assert_eq!(ours, theirs, "{from}");
        }
    }

    #[test]
    fn terminal_and_waiting_are_disjoint() {
        for s in RequestStatus::ALL {
            assert!(!(s.is_terminal() && s.is_waiting()), "{s}");
        }
    }

    /// Compile-time: these must type-check (and the commented ones must not).
    #[allow(dead_code)]
    fn typestate_compiles() {
        fn needs<F: CanMoveTo<T>, T: State>() {}
        needs::<state::AwaitingHuman, state::Approved>();
        needs::<state::Approved, state::Provisioning>();
        // needs::<state::Denied, state::Approved>();       // does not compile
        // needs::<state::Pending, state::Provisioning>();  // does not compile
    }
}
