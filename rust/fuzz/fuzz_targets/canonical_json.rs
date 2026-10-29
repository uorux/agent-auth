//! Canonical JSON (job-spec digests) and the default-dumps length on any
//! JSON value.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_core::canonical_json::{
    python_dumps_len, to_canonical_string, to_python_default_string,
};
use agent_auth_crypto::digest::digest;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    assert_eq!(
        python_dumps_len(&value),
        to_python_default_string(&value).len()
    );
    if let Ok(text) = to_canonical_string(&value) {
        assert!(text.is_ascii());
        let back: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        assert_eq!(back, value);
        assert_eq!(to_canonical_string(&back).as_deref(), Ok(text.as_str()));
        assert!(digest(&value).is_ok());
    }
});
