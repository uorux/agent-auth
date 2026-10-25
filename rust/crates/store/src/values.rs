//! Conversions between database values and domain types. Every parse that
//! fails is `StoreError::Corrupt`: a stored value is never defaulted.

use agent_auth_core::{
    AgentId, Authority, DecisionSource, GrantStatus, Platform, RequestStatus, ThreadId,
};
use serde_json::Value;
use uuid::Uuid;

use crate::StoreError;

/// Defines a text enumeration stored in a CHECKed text column.
macro_rules! text_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $text:literal),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),* }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),*];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),* }
            }

            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($text => Some($name::$variant),)* _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}
pub(crate) use text_enum;

/// A delegated request or grant: the thread it is anchored to and the
/// thread's initiator (the delegator). Both or neither (a CHECK says so).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delegation {
    pub thread_id: ThreadId,
    pub delegator_agent_id: AgentId,
}

impl Delegation {
    pub(crate) fn from_columns(
        table: &'static str,
        thread: Option<Uuid>,
        delegator: Option<Uuid>,
    ) -> Result<Option<Delegation>, StoreError> {
        match (thread, delegator) {
            (None, None) => Ok(None),
            (Some(t), Some(d)) => Ok(Some(Delegation {
                thread_id: ThreadId::from_uuid(t),
                delegator_agent_id: AgentId::from_uuid(d),
            })),
            _ => Err(StoreError::corrupt(table, "half a delegation")),
        }
    }
}

pub(crate) fn platform(table: &'static str, s: &str) -> Result<Platform, StoreError> {
    Platform::parse(s).ok_or_else(|| StoreError::corrupt(table, format!("platform {s:?}")))
}

pub(crate) fn request_status(s: &str) -> Result<RequestStatus, StoreError> {
    RequestStatus::parse(s)
        .ok_or_else(|| StoreError::corrupt("access_requests", format!("status {s:?}")))
}

pub(crate) fn grant_status(s: &str) -> Result<GrantStatus, StoreError> {
    GrantStatus::parse(s).ok_or_else(|| StoreError::corrupt("grants", format!("status {s:?}")))
}

pub(crate) fn decision_source(s: Option<&str>) -> Result<Option<DecisionSource>, StoreError> {
    s.map(|s| {
        DecisionSource::parse(s)
            .ok_or_else(|| StoreError::corrupt("access_requests", format!("decision_source {s:?}")))
    })
    .transpose()
}

pub(crate) fn authority(
    table: &'static str,
    platform: Platform,
    value: &Value,
) -> Result<Authority, StoreError> {
    Authority::from_json(platform, value)
        .map_err(|e| StoreError::corrupt(table, format!("authority: {e}")))
}

pub(crate) fn string_list(table: &'static str, value: Value) -> Result<Vec<String>, StoreError> {
    serde_json::from_value(value)
        .map_err(|e| StoreError::corrupt(table, format!("not a list of strings: {e}")))
}

/// A non-negative count or duration stored as integer.
pub(crate) fn unsigned(table: &'static str, n: i32) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| StoreError::corrupt(table, format!("negative value {n}")))
}

pub(crate) fn opt_unsigned(table: &'static str, n: Option<i32>) -> Result<Option<u32>, StoreError> {
    n.map(|n| unsigned(table, n)).transpose()
}

/// A duration or count for an integer column; refused (not truncated) when
/// it does not fit.
pub(crate) fn to_i32(n: u32) -> Result<i32, StoreError> {
    i32::try_from(n).map_err(|_| StoreError::OutOfRange(n.to_string()))
}

pub(crate) fn opt_to_i32(n: Option<u32>) -> Result<Option<i32>, StoreError> {
    n.map(to_i32).transpose()
}
