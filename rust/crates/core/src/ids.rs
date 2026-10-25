//! Typed identifiers. Each table's id is its own type, so a grant id can
//! never be passed where a request id is expected (the Python passed `str`
//! everywhere, and `HostJob.id == request.id` was a convention).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        // Only the canonical spelling, as `FromStr` (uuid's own Deserialize
        // also takes upper case, braces and URNs).
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                parse_canonical(&s).map(Self).map_err(serde::de::Error::custom)
            }
        }

        impl $name {
            /// A fresh random (v4) id.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_canonical(s).map(Self)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Uuid {
                id.0
            }
        }
    };
}

/// Not an id: anything but a lowercase, hyphenated UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an id")]
pub struct IdParseError;

/// Only the canonical hyphenated lowercase form parses: ids are compared as
/// strings by clients and in logs, so one id has exactly one spelling.
fn parse_canonical(s: &str) -> Result<Uuid, IdParseError> {
    let uuid = Uuid::try_parse(s).map_err(|_| IdParseError)?;
    let mut buf = [0u8; uuid::fmt::Hyphenated::LENGTH];
    if uuid.hyphenated().encode_lower(&mut buf) == s {
        Ok(uuid)
    } else {
        Err(IdParseError)
    }
}

id_type!(
    /// `agents.id`
    AgentId
);
id_type!(
    /// `agent_sessions.id`
    SessionId
);
id_type!(
    /// `access_requests.id`
    RequestId
);
id_type!(
    /// `grants.id`
    GrantId
);
id_type!(
    /// `rules.id`
    RuleId
);
id_type!(
    /// `a2a_threads.id`
    ThreadId
);
id_type!(
    /// `a2a_messages.id`
    MessageId
);
id_type!(
    /// `daemons.id`
    DaemonId
);
id_type!(
    /// `host_jobs.id`
    JobId
);
id_type!(
    /// `credentials.id`
    CredentialId
);
id_type!(
    /// `llm_evaluations.id`
    EvaluationId
);

impl JobId {
    /// A run/tpl grant's single job shares its request's id.
    #[must_use]
    pub const fn for_request(request: RequestId) -> Self {
        Self(request.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_spelling_only() {
        let id = AgentId::new();
        let text = id.to_string();
        assert_eq!(text.parse::<AgentId>().ok(), Some(id));
        assert!(text.to_uppercase().parse::<AgentId>().is_err());
        assert!(text.replace('-', "").parse::<AgentId>().is_err());
        assert!(format!("{{{text}}}").parse::<AgentId>().is_err());
        let json = format!("\"{}\"", text.to_uppercase());
        assert!(serde_json::from_str::<AgentId>(&json).is_err());
        let json = format!("\"{text}\"");
        assert_eq!(serde_json::from_str::<AgentId>(&json).ok(), Some(id));
    }
}
