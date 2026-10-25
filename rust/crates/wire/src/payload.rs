//! a2a message payloads: any JSON object, at most 16384 "bytes" as the
//! Python measured them — the length of its default `json.dumps(payload)`
//! (`", "` and `": "` separators, `ensure_ascii`: a non-ASCII BMP character
//! counts 6, an astral one 12). Agents near the limit must get the same
//! accept/reject decision as before, so the measure is that encoder's.
//!
//! That encoder lives in core (`core::canonical_json`, being written
//! separately); it is not duplicated here. Until it is merged, the size check
//! takes the measuring function as an argument ([`PyDumpsLen`]): a body
//! deserializes into a [`Payload`] (structure checked), and
//! [`Payload::sized`] with core's function yields the [`SizedPayload`] the
//! a2a service accepts. Once core's function is available this can move into
//! `Payload`'s deserializer and `sized` can go.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ValidationError;

/// The cap, in Python `json.dumps` characters.
pub const MAX_PAYLOAD_BYTES: usize = 16384;

/// `len(json.dumps(value))` with Python's default arguments.
pub type PyDumpsLen = fn(&Value) -> usize;

/// A JSON object from an agent, not yet measured.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Payload(Map<String, Value>);

impl Payload {
    #[must_use]
    pub fn new(map: Map<String, Value>) -> Self {
        Payload(map)
    }

    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    /// Measure with Python's `json.dumps` length: over
    /// [`MAX_PAYLOAD_BYTES`] is refused with the Python's message.
    pub fn sized(self, py_dumps_len: PyDumpsLen) -> Result<SizedPayload, ValidationError> {
        let value = Value::Object(self.0);
        if py_dumps_len(&value) > MAX_PAYLOAD_BYTES {
            return Err(ValidationError::new(format!(
                "payload exceeds {MAX_PAYLOAD_BYTES} bytes"
            )));
        }
        match value {
            Value::Object(map) => Ok(SizedPayload(map)),
            _ => Ok(SizedPayload(Map::new())),
        }
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// A payload within the cap: what the a2a service stores and relays.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SizedPayload(Map<String, Value>);

impl SizedPayload {
    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    #[must_use]
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }
}

impl fmt::Debug for SizedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A stand-in measure for the tests of the boundary logic only (the
    /// real one is core's): compact JSON length.
    fn compact(v: &Value) -> usize {
        serde_json::to_string(v)
            .map(|s| s.len())
            .unwrap_or(usize::MAX)
    }

    #[test]
    fn cap_is_inclusive() {
        // {"a":"xxx..."} is 8 characters of overhead.
        let fits = Payload::new(json!({"a": "x".repeat(16376)}).as_object().unwrap().clone());
        assert!(fits.sized(compact).is_ok());
        let over = Payload::new(json!({"a": "x".repeat(16377)}).as_object().unwrap().clone());
        assert_eq!(
            over.sized(compact).unwrap_err().message(),
            "payload exceeds 16384 bytes"
        );
    }

    #[test]
    fn objects_only() {
        assert!(serde_json::from_value::<Payload>(json!({"type": "x"})).is_ok());
        assert!(serde_json::from_value::<Payload>(json!([1])).is_err());
        assert!(serde_json::from_value::<Payload>(json!("x")).is_err());
        assert!(serde_json::from_value::<Payload>(json!(null)).is_err());
    }
}
