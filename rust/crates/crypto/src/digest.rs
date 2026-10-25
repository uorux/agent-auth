//! SHA-256 digests: of bytes, and of canonical JSON (job specs).

use agent_auth_core::canonical_json::{CanonicalError, to_canonical_string};
use ring::digest;
use serde_json::Value;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    out
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, data))
}

/// `hex(sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)))`, the job-spec digest a Python hostd computes too.
/// Non-integer numbers are refused (specs never carry them).
pub fn digest(value: &Value) -> Result<String, CanonicalError> {
    to_canonical_string(value).map(|text| sha256_hex(text.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::vectors;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        for case in vectors()["canonical"].as_array().unwrap() {
            let value = &case["value"];
            assert_eq!(
                to_canonical_string(value).unwrap(),
                case["canonical"].as_str().unwrap()
            );
            assert_eq!(digest(value).unwrap(), case["digest"].as_str().unwrap());
            assert_eq!(
                agent_auth_core::canonical_json::python_dumps_len(value),
                usize::try_from(case["default_len"].as_u64().unwrap()).unwrap()
            );
        }
    }

    /// Canonical text only (no hashing): runs under Miri.
    #[test]
    fn canonical_matches_python() {
        for case in vectors()["canonical"].as_array().unwrap() {
            assert_eq!(
                to_canonical_string(&case["value"]).unwrap(),
                case["canonical"].as_str().unwrap()
            );
        }
        for case in vectors()["default_len"].as_array().unwrap() {
            assert_eq!(
                agent_auth_core::canonical_json::to_python_default_string(&case["value"]),
                case["text"].as_str().unwrap()
            );
        }
    }
}
