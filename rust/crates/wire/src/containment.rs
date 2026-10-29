//! Containment (`/admin/containment*`, `/v1/containment`; http-api §2.4).

use std::collections::BTreeMap;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::json::MatchObject;
use crate::text::Text;

/// `POST /admin/containment` and `POST /v1/containment`. `match` is an
/// agent match (a name glob plus attribute values; `{}` is everyone) whose
/// schema is policy's: the service validates it (422 `not an agent match:
/// ...`) and refuses an agent's match that would hold everyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainBody {
    #[serde(rename = "match")]
    pub matches: MatchObject,
    pub reason: Text<1, 500>,
    #[serde(default)]
    pub evidence: Text<0, 4000>,
}

/// What `POST /admin/containment/lift` lifts.
///
/// The Python lifted **every** entry for `{}` or `{"id": null}` (http-api
/// §8.15): a one-character mistake undid all holds. Lifting all now takes
/// `{"all": true}`; a body naming neither is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftBody {
    One(Text<1, 16>),
    All,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftRaw {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<Text<1, 16>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    all: bool,
}

impl Serialize for LiftBody {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let raw = match self {
            LiftBody::One(id) => LiftRaw {
                id: Some(id.clone()),
                all: false,
            },
            LiftBody::All => LiftRaw {
                id: None,
                all: true,
            },
        };
        raw.serialize(s)
    }
}

impl<'de> Deserialize<'de> for LiftBody {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match LiftRaw::deserialize(d)? {
            LiftRaw {
                id: Some(id),
                all: false,
            } => Ok(LiftBody::One(id)),
            LiftRaw {
                id: None,
                all: true,
            } => Ok(LiftBody::All),
            LiftRaw {
                id: Some(_),
                all: true,
            } => Err(de::Error::custom(
                "give an id to lift one containment, or {\"all\": true}, not both",
            )),
            LiftRaw {
                id: None,
                all: false,
            } => Err(de::Error::custom(
                "say which containment to lift: {\"id\": \"<id>\"}, or {\"all\": true} for every one",
            )),
        }
    }
}

/// A standing containment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentEntry {
    /// 8 hex digits.
    pub id: String,
    #[serde(rename = "match")]
    pub matches: Map<String, Value>,
    pub reason: String,
    pub evidence: String,
    pub by: String,
    /// `operator`, `agent` or `lockdown`.
    pub source: String,
    #[serde(with = "crate::timestamp")]
    pub at: OffsetDateTime,
}

/// `POST .../containment` → 200: the entry, and what holding took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainResult {
    #[serde(flatten)]
    pub entry: ContainmentEntry,
    pub agents: Vec<String>,
    pub grants_revoked: u32,
    pub requests_denied: u32,
    pub threads_closed: u32,
    /// Per agent VM, whether it was told.
    pub daemons: BTreeMap<String, Value>,
}

/// `POST /admin/containment/lift` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifted {
    pub lifted: Vec<ContainmentEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lifting_all_is_explicit() {
        let one: LiftBody = serde_json::from_value(json!({"id": "0a1b2c3d"})).unwrap();
        assert_eq!(one, LiftBody::One(Text::new("0a1b2c3d").unwrap()));
        let all: LiftBody = serde_json::from_value(json!({"all": true})).unwrap();
        assert_eq!(all, LiftBody::All);
        assert!(serde_json::from_value::<LiftBody>(json!({})).is_err());
        assert!(serde_json::from_value::<LiftBody>(json!({"id": null})).is_err());
        assert!(serde_json::from_value::<LiftBody>(json!({"id": "x", "all": true})).is_err());
        assert!(serde_json::from_value::<LiftBody>(json!({"ids": "x"})).is_err());
        for body in [one, all] {
            let back: LiftBody =
                serde_json::from_value(serde_json::to_value(&body).unwrap()).unwrap();
            assert_eq!(back, body);
        }
    }
}
