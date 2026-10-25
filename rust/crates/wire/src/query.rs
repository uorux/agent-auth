//! Query-string values with rules of their own: long-poll waits, filters,
//! limits. (Query strings are not JSON, but client and server must agree
//! on these, and two of them were 500s in the Python, http-api §8.5.)

use agent_auth_core::{DecisionSource, GrantStatus};

use crate::error::ValidationError;
use crate::pyrepr::repr;

/// A client-supplied wait, clamped to `lo..=hi` seconds; NaN is `lo`, so no
/// non-finite value reaches a timer (http-api INV-8).
#[must_use]
pub fn clamp_wait(value: f64, lo: f64, hi: f64) -> f64 {
    if value.is_nan() {
        lo
    } else {
        value.clamp(lo, hi)
    }
}

/// The longest any long-poll holds a request open.
pub const MAX_WAIT_SECS: f64 = 300.0;

/// `GET /v1/grants?status=`: a grant status, or `all`. Default `active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrantFilter {
    #[default]
    Active,
    All,
    Status(GrantStatus),
}

impl GrantFilter {
    /// The value, or the Python's 400 `invalid status 'x'`.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        match value {
            "all" => Ok(GrantFilter::All),
            "active" => Ok(GrantFilter::Active),
            other => GrantStatus::parse(other)
                .map(GrantFilter::Status)
                .ok_or_else(|| ValidationError::new(format!("invalid status {}", repr(other)))),
        }
    }

    /// The statuses listed (`None`: every one).
    #[must_use]
    pub fn status(self) -> Option<GrantStatus> {
        match self {
            GrantFilter::Active => Some(GrantStatus::Active),
            GrantFilter::All => None,
            GrantFilter::Status(s) => Some(s),
        }
    }
}

/// `GET /v1/a2a/check?direction=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// May I open a thread to the peer?
    #[default]
    Out,
    /// May the peer open one to me?
    In,
}

impl Direction {
    /// The value, or the Python's 400 message.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        match value {
            "out" => Ok(Direction::Out),
            "in" => Ok(Direction::In),
            _ => Err(ValidationError::new("direction must be 'out' or 'in'")),
        }
    }
}

/// `GET /v1/a2a/threads?role=`: any other value (or none) means both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoleFilter {
    #[default]
    Both,
    Initiator,
    Responder,
}

impl RoleFilter {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("initiator") => RoleFilter::Initiator,
            Some("responder") => RoleFilter::Responder,
            _ => RoleFilter::Both,
        }
    }
}

/// `GET /admin/log/decisions?source=`: a decision source, checked (an
/// unknown one was a Postgres enum error, 500).
pub fn decision_source(value: &str) -> Result<DecisionSource, ValidationError> {
    DecisionSource::parse(value).ok_or_else(|| {
        ValidationError::new(format!(
            "source must be one of policy, rule, llm, human (not {})",
            repr(value)
        ))
    })
}

/// A list `limit`, clamped to `1..=max` (`/admin/requests` had no lower
/// bound: `LIMIT -1` was a 500).
#[must_use]
pub fn clamp_limit(limit: i64, max: u32) -> u32 {
    let max = i64::from(max.max(1));
    u32::try_from(limit.clamp(1, max)).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits() {
        assert!((clamp_wait(f64::NAN, 1.0, 300.0) - 1.0).abs() < f64::EPSILON);
        assert!((clamp_wait(f64::INFINITY, 0.0, 300.0) - 300.0).abs() < f64::EPSILON);
        assert!((clamp_wait(f64::NEG_INFINITY, 0.0, 300.0)).abs() < f64::EPSILON);
        assert!((clamp_wait(42.5, 0.0, 300.0) - 42.5).abs() < f64::EPSILON);
    }

    #[test]
    fn filters() {
        assert_eq!(
            GrantFilter::parse("active").unwrap().status(),
            Some(GrantStatus::Active)
        );
        assert_eq!(GrantFilter::parse("all").unwrap().status(), None);
        assert_eq!(
            GrantFilter::parse("revoked").unwrap().status(),
            Some(GrantStatus::Revoked)
        );
        assert_eq!(
            GrantFilter::parse("bogus").unwrap_err().message(),
            "invalid status 'bogus'"
        );
        assert_eq!(Direction::parse("in").unwrap(), Direction::In);
        assert!(Direction::parse("sideways").is_err());
        assert_eq!(RoleFilter::parse(Some("x")), RoleFilter::Both);
        assert!(decision_source("human").is_ok());
        assert!(decision_source("bogus").is_err());
        assert_eq!(clamp_limit(-1, 500), 1);
        assert_eq!(clamp_limit(10_000, 500), 500);
        assert_eq!(clamp_limit(7, 500), 7);
    }
}
