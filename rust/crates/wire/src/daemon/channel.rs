//! What both directions and both daemon roles share: call ids, replies,
//! heartbeats, and parsing an envelope body into a message.

use std::fmt;
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::error::ValidationError;
use crate::json::{ReplyData, StatusObject};
use crate::text::Text;

/// The keys every envelope body carries for itself. Sealing overwrites a
/// payload key of the same name, so no message uses them (in the Python,
/// `job.output`'s chunk `seq` was silently replaced by the envelope's).
pub const ENVELOPE_KEYS: [&str; 6] = ["id", "iss", "aud", "seq", "iat", "exp"];

/// A message type of one direction.
pub trait ChannelMessage: DeserializeOwned + Serialize {
    /// Every `type` value of the direction.
    const TYPES: &'static [&'static str];
}

/// A verified envelope body, read as one direction's message.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming<T> {
    Message(T),
    /// A `type` this side does not handle: ignored (no reply), as the
    /// Python did, so either side can be upgraded first.
    UnknownType(String),
    /// A known type with missing, extra or out-of-bounds fields.
    Malformed {
        kind: String,
        error: String,
    },
}

/// Read an envelope body (as the crypto crate returns it after verifying)
/// as a message of `T`'s direction.
pub fn parse<T: ChannelMessage>(mut body: Map<String, Value>) -> Incoming<T> {
    for key in ENVELOPE_KEYS {
        body.remove(key);
    }
    let kind = match body.get("type") {
        Some(Value::String(t)) => t.chars().take(64).collect::<String>(),
        _ => {
            return Incoming::Malformed {
                kind: String::new(),
                error: "no message type".to_owned(),
            };
        }
    };
    if !T::TYPES.contains(&kind.as_str()) {
        return Incoming::UnknownType(kind);
    }
    match serde_json::from_value::<T>(Value::Object(body)) {
        Ok(m) => Incoming::Message(m),
        Err(e) => Incoming::Malformed {
            kind,
            error: e.to_string(),
        },
    }
}

/// The id pairing a call with its reply: 32 lowercase hex digits (Python
/// `uuid4().hex`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(String);

impl CallId {
    /// A fresh random id.
    #[must_use]
    pub fn new() -> Self {
        CallId(Uuid::new_v4().simple().to_string())
    }

    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        if s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            Ok(CallId(s.to_owned()))
        } else {
            Err(ValidationError::new(
                "call_id must be 32 lowercase hex digits",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CallId {
    fn default() -> Self {
        CallId::new()
    }
}

impl fmt::Debug for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CallId({})", self.0)
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CallId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CallId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        CallId::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A desk prompt's id (Python `str(uuid4())`): a lowercase hyphenated UUID,
/// the only spelling accepted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PromptId(Uuid);

impl PromptId {
    #[must_use]
    pub fn new() -> Self {
        PromptId(Uuid::new_v4())
    }
}

impl Default for PromptId {
    fn default() -> Self {
        PromptId::new()
    }
}

impl fmt::Debug for PromptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PromptId({})", self.0.hyphenated())
    }
}

impl fmt::Display for PromptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

impl FromStr for PromptId {
    type Err = ValidationError;
    fn from_str(s: &str) -> Result<Self, ValidationError> {
        let bad = || ValidationError::new("not a prompt id");
        let uuid = Uuid::try_parse(s).map_err(|_| bad())?;
        let mut buf = [0u8; uuid::fmt::Hyphenated::LENGTH];
        if uuid.hyphenated().encode_lower(&mut buf) == s {
            Ok(PromptId(uuid))
        } else {
            Err(bad())
        }
    }
}

impl Serialize for PromptId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self.0.hyphenated())
    }
}

impl<'de> Deserialize<'de> for PromptId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// `{"type": "heartbeat", "status": ...}`: sent on connect and every
/// interval. The status is informational only (never an authorization
/// input on the broker), see [`crate::daemon::host::HostStatus`] and
/// [`crate::daemon::sandbox::SandboxStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    pub status: StatusObject,
}

/// The answer to a call: `{"type": "reply", "call_id", "ok", "data" |
/// "error"}`. A sandbox's reply to a call whose id it lost carries a null
/// `call_id`, and an `ok` reply of a sandbox has no `data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub call_id: Option<CallId>,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ReplyData>,
    /// Why it was refused (the broker shows at most 500 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Text<0, 16384>>,
}

impl Reply {
    /// The reply's data read as a call's answer type (`{}` when absent).
    pub fn data_as<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        let map = self
            .data
            .as_ref()
            .map(|d| d.as_map().clone())
            .unwrap_or_default();
        serde_json::from_value(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_ids() {
        let id = CallId::new();
        assert_eq!(id.as_str().len(), 32);
        assert!(CallId::parse(id.as_str()).is_ok());
        assert!(CallId::parse("0123456789ABCDEF0123456789abcdef").is_err());
        assert!(CallId::parse("short").is_err());
    }

    #[test]
    fn prompt_ids_are_canonical() {
        let id = PromptId::new();
        let text = id.to_string();
        assert_eq!(text.parse::<PromptId>().unwrap(), id);
        assert!(text.to_uppercase().parse::<PromptId>().is_err());
        assert!(text.replace('-', "").parse::<PromptId>().is_err());
    }
}
