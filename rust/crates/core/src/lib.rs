#![forbid(unsafe_code)]
//! The broker's domain, without I/O: identifiers, the request and grant
//! state machines, authorities, glob matching, and the routing gates that
//! decide whether a request may be cleared without a human.
//!
//! Everything here is deterministic and pure so it can be property-tested,
//! fuzzed, run under Miri, and model-checked with Kani (`cargo kani`).

pub mod authority;
pub mod containment;
pub mod glob;
pub mod ids;
pub mod lifecycle;
pub mod platform;
#[cfg(kani)]
mod proofs;
pub mod routing;

pub use authority::{Authority, AuthorityError, Tier, rule_covers};
pub use glob::{Glob, fnmatch};
pub use ids::*;
pub use lifecycle::{DecisionSource, GrantStatus, RequestStatus};
pub use platform::Platform;
pub use routing::{AutoClearance, PolicyAction, Route, route};
