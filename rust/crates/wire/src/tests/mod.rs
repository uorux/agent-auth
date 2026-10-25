//! Cross-module tests: request bodies (samples from the spec and the Python
//! tests, unknown fields, limits), channel messages, and response round trips.

mod channel;
mod requests;
mod responses;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::parse_body;

/// Parse `v` as a request body the way the broker does, and check that what
/// it serializes to parses back to the same value.
#[track_caller]
pub(crate) fn accepted<T>(v: Value) -> T
where
    T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug,
{
    let bytes = serde_json::to_vec(&v).unwrap();
    let parsed: T = match parse_body(&bytes) {
        Ok(p) => p,
        Err(e) => panic!("refused {v}: {e}"),
    };
    let again = serde_json::to_vec(&parsed).unwrap();
    let back: T = parse_body(&again).unwrap();
    assert_eq!(back, parsed);
    parsed
}

/// The message a refused body gets.
#[track_caller]
pub(crate) fn refused<T>(v: Value) -> String
where
    T: DeserializeOwned + std::fmt::Debug,
{
    let bytes = serde_json::to_vec(&v).unwrap();
    match parse_body::<T>(&bytes) {
        Ok(p) => panic!("accepted {v}: {p:?}"),
        Err(e) => e.message().to_owned(),
    }
}

/// `v` plus an unknown key, which every request body refuses.
pub(crate) fn with_extra(mut v: Value) -> Value {
    if let Value::Object(map) = &mut v {
        map.insert("bogus".to_owned(), Value::from(1));
    }
    v
}
