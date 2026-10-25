//! Turning bytes into a request type, with messages fit to show the caller.

use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::Value;

/// A value broke one of a body's limits. The message is the one the spec
/// gives (the Python's `ValueError` text where it had one), without the
/// position noise of a parser error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        ValidationError {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Why a body was refused (every case is a 422).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// Not JSON at all (FastAPI's `json_invalid`).
    Json(String),
    /// JSON, but not this type: a missing or unknown field, a wrong type, or
    /// a value outside its limits. The text is the field's own message.
    Invalid(String),
}

impl BodyError {
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            BodyError::Json(m) | BodyError::Invalid(m) => m,
        }
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::Json(m) => write!(f, "JSON decode error: {m}"),
            BodyError::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for BodyError {}

/// Parse a request body. JSON syntax is checked first (so a malformed body
/// is told apart from a wrong one), then the value is converted to `T`
/// without position information, so the message of a validating field
/// (`invalid duration 'x': ...`, `payload exceeds 16384 bytes`) comes out
/// verbatim. Duplicate keys keep the last value, as Python's `json` does.
pub fn parse_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BodyError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| BodyError::Json(e.to_string()))?;
    from_value(value)
}

/// [`parse_body`] for a value already parsed (a WebSocket frame, a stored row).
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, BodyError> {
    serde_json::from_value(value).map_err(|e| BodyError::Invalid(e.to_string()))
}
