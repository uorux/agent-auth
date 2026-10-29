//! The signing contract between the broker and its paired daemons, byte for
//! byte the Python's (`daemon_common/crypto.py`), so a Python hostd can talk
//! to a Rust broker and the other way round.
//!
//! - **Pairing** ([`pairing`]) binds a daemon's public key to its identity
//!   once, with a one-time code an admin carries to the host. Both sides
//!   prove knowledge of the code over the exact keys being exchanged.
//! - **Hello** ([`hello`]) authenticates each WebSocket connection: both
//!   sides sign a transcript of both nonces. A verified hello is the only
//!   way to get the envelope sealer and verifier for a connection.
//! - **Envelopes** ([`envelope`]) carry every later message, signed over the
//!   connection's session id, naming sender and recipient, numbered per
//!   direction, and expiring.
//!
//! Every signed or MACed byte string is a [`transcript`] whose first part is
//! a context label, so no field boundary is ambiguous and no signature made
//! for one purpose verifies for another.

pub mod envelope;
pub mod hello;
mod keyfile;
mod keys;
pub mod pairing;

use std::fmt;

pub use envelope::{EnvelopeError, EnvelopeSealer, EnvelopeVerifier, SealError};
pub use hello::{Handshake, HelloError, Nonce, SessionId, Speaker, VerifiedHello};
pub use keyfile::{KeyFileError, load_or_create_key};
pub use keys::{KeyParseError, PublicKey, SigningKey};
pub use pairing::{PairingKey, generate_pairing_code, normalize_pairing_code, proofs_equal};

/// The broker's principal in envelopes.
pub const BROKER: &str = "broker";
/// Envelope lifetimes are capped so a delayed message can't be held back
/// and delivered long after it was meant to act.
pub const MAX_ENVELOPE_TTL_SECS: f64 = 3600.0;
/// The lifetime of an envelope unless the sender says otherwise.
pub const DEFAULT_ENVELOPE_TTL_SECS: f64 = 60.0;
/// How far in the future an envelope's `iat` may be.
pub const MAX_CLOCK_SKEW_SECS: f64 = 30.0;
/// The longest variable field (hello params, envelope body) accepted into a
/// transcript. Far above any message (the channel's frames are ~1 MiB) and
/// far below the 4 GiB a transcript length prefix can express.
pub const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;

pub(crate) const CTX_PAIR_KEY: &[u8] = b"agent-auth/v1/pair-key";
pub(crate) const CTX_PAIR: &[u8] = b"agent-auth/v1/pair";
pub(crate) const CTX_PAIR_SELECTOR: &[u8] = b"agent-auth/v1/pair-selector";
pub(crate) const CTX_SESSION: &[u8] = b"agent-auth/v1/session";
pub(crate) const CTX_HELLO: &[u8] = b"agent-auth/v1/hello";
pub(crate) const CTX_MSG: &[u8] = b"agent-auth/v1/msg";

/// The length-prefixed encoding of a list of byte strings: for each part,
/// its length as a big-endian `u32`, then its bytes (Python `_transcript`).
///
/// Every caller bounds its parts far below 4 GiB (typed identities, fixed
/// size keys and nonces, [`MAX_FIELD_BYTES`] for the rest); a longer part
/// would get the length `u32::MAX`, so the encoding stays a prefix code
/// over every input that can reach it.
pub fn transcript(parts: &[&[u8]]) -> Vec<u8> {
    let total = parts
        .iter()
        .fold(0usize, |n, p| n.saturating_add(4).saturating_add(p.len()));
    let mut out = Vec::with_capacity(total);
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// What kind of daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Host,
    Sandbox,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Host => "host",
            Role::Sandbox => "sandbox",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "host" => Some(Role::Host),
            "sandbox" => Some(Role::Sandbox),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A daemon's name: `[a-z0-9][a-z0-9-]{0,62}`, the whole string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DaemonName(String);

impl DaemonName {
    pub fn parse(text: &str) -> Option<Self> {
        let mut bytes = text.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        (first_ok && rest_ok && text.len() <= 63).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DaemonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which daemon: role and name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DaemonId {
    pub role: Role,
    pub name: DaemonName,
}

impl DaemonId {
    pub fn new(role: Role, name: DaemonName) -> Self {
        Self { role, name }
    }

    /// `role:name`, the daemon's principal in envelopes.
    pub fn principal(&self) -> String {
        format!("{}:{}", self.role, self.name)
    }
}

impl fmt::Display for DaemonId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.role, self.name)
    }
}

/// Seconds since the Unix epoch, as the envelope timestamps count them.
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_encoding() {
        assert_eq!(transcript(&[]), Vec::<u8>::new());
        assert_eq!(
            transcript(&[b"ab", b""]),
            vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0]
        );
    }

    /// Reads a transcript back into its parts.
    fn split(mut t: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut parts = Vec::new();
        while !t.is_empty() {
            let (len, rest) = t.split_first_chunk::<4>()?;
            let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
            let (part, rest) = rest.split_at_checked(len)?;
            parts.push(part.to_vec());
            t = rest;
        }
        Some(parts)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: if cfg!(miri) { 8 } else { 512 },
            failure_persistence: if cfg!(miri) { None } else { proptest::prelude::ProptestConfig::default().failure_persistence },
            ..proptest::prelude::ProptestConfig::default()
        })]

        /// The encoding is injective: it decodes back to exactly its parts.
        #[test]
        fn transcript_decodes(parts in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..12), 0..6)) {
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            proptest::prop_assert_eq!(split(&transcript(&refs)), Some(parts));
        }
    }

    #[test]
    fn names() {
        assert!(DaemonName::parse("excelsior").is_some());
        assert!(DaemonName::parse("0-a").is_some());
        assert!(DaemonName::parse(&"a".repeat(63)).is_some());
        for bad in ["", "-a", "A", "a_b", "a\n", &"a".repeat(64), "é"] {
            assert!(DaemonName::parse(bad).is_none(), "{bad:?}");
        }
        let id = DaemonId::new(Role::Host, DaemonName::parse("excelsior").unwrap());
        assert_eq!(id.principal(), "host:excelsior");
        assert_eq!(Role::parse("sandbox"), Some(Role::Sandbox));
        assert_eq!(Role::parse("broker"), None);
    }
}
