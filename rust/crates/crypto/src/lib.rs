#![forbid(unsafe_code)]
//! Every cryptographic operation of the broker and its daemons, on `ring`.
//!
//! - [`Secret`]: a value that is zeroized on drop and never printed.
//! - [`api_key`]: agent API keys (`aa_<key id>_<secret>`), their stored hash
//!   and constant-time verification.
//! - [`secretbox`]: encryption at rest (ChaCha20-Poly1305, bound to the row
//!   and column a ciphertext belongs to).
//! - [`webhook`]: the `X-Agent-Auth-Signature` HMAC on outbound webhooks.
//! - [`jwt`]: the broker's own ES256 tokens (derived from its Ed25519 key)
//!   and GitHub App RS256 JWTs.
//! - [`daemon`]: the broker/daemon channel (keys, pairing, hello, signed
//!   envelopes), wire-compatible with the Python daemons.
//! - [`totp`]: RFC 6238 codes as hostd checks them.
//! - [`digest`]: SHA-256 over canonical JSON (job-spec digests).
//!
//! Comparisons of secret values go through [`ct_eq`].

pub mod api_key;
pub mod daemon;
pub mod digest;
mod encoding;
pub mod jwt;
pub mod pem;
mod rng;
mod secret;
pub mod secretbox;
pub mod totp;
pub mod webhook;

pub use encoding::{b64url_decode, b64url_encode};
pub use rng::RandomError;
pub use secret::{Secret, ct_eq};

/// Known-answer vectors produced by the Python implementation
/// (`tests/vectors/generate.py`).
#[cfg(test)]
pub(crate) mod testvec {
    use std::sync::OnceLock;

    use serde_json::Value;

    pub(crate) fn vectors() -> &'static Value {
        static V: OnceLock<Value> = OnceLock::new();
        V.get_or_init(|| {
            serde_json::from_str(include_str!("../tests/vectors/python.json")).unwrap()
        })
    }

    pub(crate) fn s(v: &Value) -> &str {
        v.as_str().unwrap()
    }
}
