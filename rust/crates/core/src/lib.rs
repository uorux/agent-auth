#![forbid(unsafe_code)]
//! The broker's domain, without I/O: identifiers, the request and grant
//! state machines, authorities, glob matching, the policy file and its
//! evaluation, restricted zones, the routing gates that decide whether a
//! request may be cleared without a human, host job specs, durations and
//! validated names.
//!
//! Everything here is deterministic and pure so it can be property-tested,
//! fuzzed, run under Miri, and model-checked with Kani (`cargo kani`).

pub mod approval;
pub mod authority;
pub mod canonical_json;
pub mod containment;
pub mod durations;
pub mod glob;
pub mod hostd;
pub mod hostexec;
pub mod ids;
pub mod lifecycle;
pub mod names;
pub mod platform;
pub mod policy;
pub mod pool;
#[cfg(kani)]
mod proofs;
#[cfg(kani)]
mod proofs_hostd;
#[cfg(kani)]
mod proofs_policy;
pub mod pyfmt;
pub mod routing;
pub mod zones;

pub use approval::HumanApproval;
pub use authority::{Authority, AuthorityError, Tier, rule_covers};
pub use durations::DurationSecs;
pub use glob::{Glob, fnmatch};
pub use ids::*;
pub use lifecycle::{DecisionSource, GrantStatus, RequestStatus};
pub use names::{AgentName, AttrValue, DaemonName, HostName, NameError};
pub use platform::Platform;
pub use policy::{Policy, PolicyDecision, PolicyError, PolicyInput, SavedRule};
pub use routing::{AutoClearance, LlmClearance, PolicyAction, Route};
