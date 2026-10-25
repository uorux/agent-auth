//! Free-form JSON objects with limits: a request's `scope`, a containment
//! `match`, a job spec relayed to a host, a daemon's status. The Python took
//! these as `dict[str, Any]` with no size cap (http-api §8.8); here each has a
//! byte cap (compact JSON, UTF-8) and a nesting cap.

use std::fmt;
use std::io;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::error::ValidationError;

/// Bytes of `value` as compact JSON (`serde_json::to_vec(value).len()`),
/// counted without building the text.
#[must_use]
pub fn compact_len(value: &Value) -> usize {
    struct Count(usize);
    impl io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Serializing a Value to a writer that never fails cannot fail.
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
}

/// Nesting depth: a scalar is 0, `{}` or `[]` is 1, `{"a": []}` is 2.
/// Iterative, so no input can exhaust the stack here.
#[must_use]
pub fn depth(value: &Value) -> usize {
    let mut deepest = 0usize;
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((v, d)) = stack.pop() {
        match v {
            Value::Object(map) => {
                let here = d.saturating_add(1);
                deepest = deepest.max(here);
                stack.extend(map.values().map(|c| (c, here)));
            }
            Value::Array(items) => {
                let here = d.saturating_add(1);
                deepest = deepest.max(here);
                stack.extend(items.iter().map(|c| (c, here)));
            }
            _ => deepest = deepest.max(d),
        }
    }
    deepest
}

/// Check an object against a field's caps.
pub fn check_object(
    value: &Value,
    what: &str,
    max_bytes: usize,
    max_depth: usize,
) -> Result<(), ValidationError> {
    if depth(value) > max_depth {
        return Err(ValidationError::new(format!(
            "{what} is nested too deeply (at most {max_depth} levels)"
        )));
    }
    if compact_len(value) > max_bytes {
        return Err(ValidationError::new(format!(
            "{what} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

macro_rules! bounded_object {
    ($(#[$meta:meta])* $name:ident, $what:literal, $max_bytes:expr, $max_depth:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Default)]
        pub struct $name(Map<String, Value>);

        impl $name {
            /// Compact JSON size limit, in bytes.
            pub const MAX_BYTES: usize = $max_bytes;
            /// Nesting limit (the object itself is level 1).
            pub const MAX_DEPTH: usize = $max_depth;

            pub fn new(map: Map<String, Value>) -> Result<Self, ValidationError> {
                let value = Value::Object(map);
                check_object(&value, $what, Self::MAX_BYTES, Self::MAX_DEPTH)?;
                match value {
                    Value::Object(map) => Ok($name(map)),
                    _ => Ok($name(Map::new())),
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

            #[must_use]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }

        impl std::ops::Deref for $name {
            type Target = Map<String, Value>;
            fn deref(&self) -> &Map<String, Value> {
                &self.0
            }
        }

        impl From<$name> for Map<String, Value> {
            fn from(v: $name) -> Map<String, Value> {
                v.0
            }
        }

        impl TryFrom<Map<String, Value>> for $name {
            type Error = ValidationError;
            fn try_from(map: Map<String, Value>) -> Result<Self, ValidationError> {
                $name::new(map)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let map = Map::<String, Value>::deserialize(d)?;
                $name::new(map).map_err(de::Error::custom)
            }
        }
    };
}

bounded_object!(
    /// A request's `scope` (and a decision's `scope_override`). Room for the
    /// largest hostexec scope (64 KiB of argv, 64 KiB of stdin, 32 env
    /// values of 4 KiB) with escaping to spare.
    Scope,
    "scope",
    524_288,
    16
);

bounded_object!(
    /// A containment's agent `match` (name glob plus attribute lists).
    MatchObject,
    "match",
    4096,
    8
);

bounded_object!(
    /// A job or shell spec as the broker sends it to a host. hostd digests
    /// it exactly as received and re-validates it from scratch, so it stays
    /// raw JSON here; its schema is core's.
    RawSpec,
    "spec",
    524_288,
    8
);

bounded_object!(
    /// A daemon's heartbeat `status`. The broker stores at most 16384 bytes
    /// of it (Python `json.dumps` length) and replaces a larger one with an
    /// error marker; this cap only bounds what is parsed at all.
    StatusObject,
    "status",
    65_536,
    16
);

bounded_object!(
    /// The `data` of a daemon's reply to a call.
    ReplyData,
    "data",
    65_536,
    16
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn measures() {
        assert_eq!(
            compact_len(&json!({"a": [1, "é"]})),
            r#"{"a":[1,"é"]}"#.len()
        );
        assert_eq!(depth(&json!(1)), 0);
        assert_eq!(depth(&json!({})), 1);
        assert_eq!(depth(&json!({"a": [{"b": 1}]})), 3);
    }

    #[test]
    fn caps() {
        let ok: Result<MatchObject, _> = serde_json::from_value(json!({"name": "x-*"}));
        assert!(ok.is_ok());
        let big = json!({"name": "x".repeat(5000)});
        let err = serde_json::from_value::<MatchObject>(big)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "match exceeds 4096 bytes");
        let deep = json!({"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {}}}}}}}}});
        let err = serde_json::from_value::<MatchObject>(deep)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "match is nested too deeply (at most 8 levels)");
        assert!(serde_json::from_value::<Scope>(json!([])).is_err());
        assert!(serde_json::from_value::<Scope>(json!("x")).is_err());
    }
}
