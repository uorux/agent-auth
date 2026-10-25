//! a2a message payloads: any JSON object, at most 16384 "bytes" as the
//! Python measured them — the length of its default `json.dumps(payload)`
//! (`", "` and `": "` separators, `ensure_ascii`: a non-ASCII BMP character
//! counts 6, an astral one 12). Agents near the limit get the same
//! accept/reject decision as before, so the measure is that encoder's
//! (`core::canonical_json::python_dumps_len`), applied while deserializing:
//! a [`Payload`] from the wire is always within the cap.
//!
//! Integers: Python keeps any integer exactly; serde_json (without
//! `arbitrary_precision`) turns an integer literal outside
//! `-2^63 ..= 2^64-1` into a float, which would change the value and its
//! measured length. Such payloads are refused instead: parse a body that
//! carries a payload with [`parse_body`] (this module's), which scans the
//! raw text first ([`check_integers`]).

use std::fmt;

use agent_auth_core::canonical_json::python_dumps_len;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::error::{BodyError, ValidationError};

/// The cap, in Python `json.dumps` characters.
pub const MAX_PAYLOAD_BYTES: usize = 16384;

/// The refusal for an integer serde_json cannot keep exactly.
pub const BIG_INTEGER: &str = "payload integers must be between -2^63 and 2^64-1";

/// A JSON object from an agent, within [`MAX_PAYLOAD_BYTES`] when it came
/// off the wire. [`Payload::new`] (for payloads the broker writes itself,
/// such as the operator's chat messages) does not measure.
#[derive(Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct Payload(Map<String, Value>);

impl Payload {
    #[must_use]
    pub fn new(map: Map<String, Value>) -> Self {
        Payload(map)
    }

    /// Measure with Python's `json.dumps` length: over
    /// [`MAX_PAYLOAD_BYTES`] is refused with the Python's message.
    pub fn sized(map: Map<String, Value>) -> Result<Self, ValidationError> {
        let value = Value::Object(map);
        if python_dumps_len(&value) > MAX_PAYLOAD_BYTES {
            return Err(ValidationError::new(format!(
                "payload exceeds {MAX_PAYLOAD_BYTES} bytes"
            )));
        }
        match value {
            Value::Object(map) => Ok(Payload(map)),
            _ => Ok(Payload(Map::new())),
        }
    }

    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    #[must_use]
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }
}

impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let map = Map::<String, Value>::deserialize(d)?;
        Payload::sized(map).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// Refuse a JSON text holding an integer literal (no fraction, no
/// exponent) that serde_json would turn into a float: anything outside
/// `-2^63 ..= 2^64-1`. Text inside strings is skipped. Not a JSON
/// validator: run it before the real parse.
pub fn check_integers(raw: &[u8]) -> Result<(), ValidationError> {
    let mut i = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&b) = raw.get(i) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i = i.saturating_add(1);
            continue;
        }
        if b == b'"' {
            in_string = true;
            i = i.saturating_add(1);
            continue;
        }
        if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while raw
                .get(i)
                .is_some_and(|c| matches!(c, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
            {
                i = i.saturating_add(1);
            }
            let token = raw.get(start..i).unwrap_or_default();
            let integer = !token.iter().any(|c| matches!(c, b'.' | b'e' | b'E'));
            if integer {
                let text = std::str::from_utf8(token).unwrap_or_default();
                // In valid JSON an integer literal fails both only when it
                // is out of range (a malformed number is the parser's).
                if text.parse::<i64>().is_err()
                    && text.parse::<u64>().is_err()
                    && text.bytes().any(|c| c.is_ascii_digit())
                {
                    return Err(ValidationError::new(BIG_INTEGER));
                }
            }
            continue;
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// [`crate::error::parse_body`] for a body that carries a [`Payload`]:
/// integers are checked on the raw text first ([`check_integers`]).
pub fn parse_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BodyError> {
    // Malformed JSON is reported by the parser, not as an integer problem.
    if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
        check_integers(bytes).map_err(|e| BodyError::Invalid(e.message().to_owned()))?;
    }
    crate::error::parse_body(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload(v: Value) -> Result<Payload, String> {
        serde_json::from_value::<Payload>(v).map_err(|e| e.to_string())
    }

    #[test]
    fn cap_is_inclusive_in_pythons_measure() {
        // json.dumps({"a": "xxx..."}) is 9 characters of overhead.
        assert!(payload(json!({"a": "x".repeat(16375)})).is_ok());
        assert_eq!(
            payload(json!({"a": "x".repeat(16376)})).unwrap_err(),
            "payload exceeds 16384 bytes"
        );
        // A non-ASCII character counts 6 (\uXXXX), an astral one 12.
        assert!(payload(json!({"a": "é".repeat(2729)})).is_ok()); // 9 + 6*2729 = 16383
        assert!(payload(json!({"a": "é".repeat(2730)})).is_err());
        assert!(payload(json!({"a": "😀".repeat(1364)})).is_ok()); // 9 + 12*1364 = 16377
        assert!(payload(json!({"a": "😀".repeat(1365)})).is_err());
    }

    #[test]
    fn objects_only() {
        assert!(serde_json::from_value::<Payload>(json!({"type": "x"})).is_ok());
        assert!(serde_json::from_value::<Payload>(json!([1])).is_err());
        assert!(serde_json::from_value::<Payload>(json!("x")).is_err());
        assert!(serde_json::from_value::<Payload>(json!(null)).is_err());
    }

    #[test]
    fn integers_beyond_64_bits_are_refused() {
        for ok in [
            r#"{"a": 18446744073709551615}"#,
            r#"{"a": -9223372036854775808}"#,
            r#"{"a": 1e300, "b": 1.5, "c": -0.0, "d": 0}"#,
            r#"{"a": "123456789012345678901234567890"}"#,
            r#"{"a": "\"99999999999999999999999"}"#,
        ] {
            assert!(check_integers(ok.as_bytes()).is_ok(), "{ok}");
        }
        for bad in [
            r#"{"a": 18446744073709551616}"#,
            r#"{"a": -9223372036854775809}"#,
            r#"{"a": [1, {"b": 100000000000000000000000}]}"#,
        ] {
            assert_eq!(
                check_integers(bad.as_bytes()).unwrap_err().message(),
                BIG_INTEGER,
                "{bad}"
            );
        }
    }

    #[test]
    fn bodies_with_payloads() {
        #[derive(Debug, Deserialize)]
        struct B {
            #[allow(dead_code)]
            payload: Payload,
        }
        assert!(parse_body::<B>(br#"{"payload": {"n": 1}}"#).is_ok());
        assert_eq!(
            parse_body::<B>(br#"{"payload": {"n": 99999999999999999999}}"#)
                .unwrap_err()
                .message(),
            BIG_INTEGER
        );
        assert!(matches!(
            parse_body::<B>(b"{\"payload\": 99999999999999999999").unwrap_err(),
            BodyError::Json(_)
        ));
    }
}
