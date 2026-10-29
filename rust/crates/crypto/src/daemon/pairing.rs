//! Pairing: a one-time code binds a daemon's key to its identity.
//!
//! - Code: 12 symbols from `ABCDEFGHJKMNPQRSTVWXYZ23456789` (no I L O U 0
//!   1), formatted `XXXX-XXXX-XXXX` (about 59 bits).
//! - Normalization: uppercase, keep only alphanumerics (`abcd efgh-ijkl`
//!   is `ABCDEFGHIJKL`).
//! - Pairing key: `SHA-256("agent-auth/v1/pair-key" ‖ normalized code)`
//!   (plain concatenation). The broker stores this key, never the code.
//! - Selector: the first 32 hex digits of `HMAC(key, "agent-auth/v1/pair-selector")`,
//!   naming which pending code an attempt is for without revealing it.
//! - Daemon proof: `hex(HMAC(key, transcript(pair, "daemon", role, name, daemon key)))`.
//! - Broker proof: `hex(HMAC(key, transcript(pair, "broker", role, name, daemon key, broker key)))`.
//!
//! Keys enter the proofs as their canonical text (`ed25519:…`).

use std::fmt;

use ring::{digest, hmac};

use crate::rng::{RandomError, array};
use crate::secret::{Secret, ct_eq};

use super::keys::PublicKey;
use super::{BROKER, CTX_PAIR, CTX_PAIR_KEY, CTX_PAIR_SELECTOR, DaemonId, transcript};

const CODE_ALPHABET: &[u8; 30] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
const CODE_GROUPS: usize = 3;
const CODE_GROUP_LEN: usize = 4;

/// A new pairing code, `XXXX-XXXX-XXXX`.
pub fn generate_pairing_code() -> Result<Secret<String>, RandomError> {
    let mut out = String::with_capacity(14);
    for group in 0..CODE_GROUPS {
        if group > 0 {
            out.push('-');
        }
        for _ in 0..CODE_GROUP_LEN {
            out.push(char::from(random_symbol()?));
        }
    }
    Ok(Secret::new(out))
}

/// One symbol, uniformly (rejection sampling: 240 = 8 × 30).
fn random_symbol() -> Result<u8, RandomError> {
    loop {
        let [b] = array::<1>()?;
        if b < 240 {
            let idx = usize::from(b % 30);
            if let Some(c) = CODE_ALPHABET.get(idx) {
                return Ok(*c);
            }
        }
    }
}

/// Uppercase, alphanumerics only (Python `code.upper()` then `isalnum`).
pub fn normalize_pairing_code(code: &str) -> String {
    code.to_uppercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// The HMAC key both sides derive from a pairing code.
#[derive(Clone)]
pub struct PairingKey(Secret<[u8; 32]>);

impl fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingKey(..)")
    }
}

impl PairingKey {
    /// The key for a code as typed (normalized first).
    pub fn from_code(code: &str) -> Self {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(CTX_PAIR_KEY);
        ctx.update(normalize_pairing_code(code).as_bytes());
        let mut raw = [0u8; 32];
        raw.copy_from_slice(ctx.finish().as_ref());
        Self(Secret::new(raw))
    }

    /// A stored key (64 hex digits).
    pub fn from_hex(text: &str) -> Option<Self> {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(text, &mut raw).ok()?;
        Some(Self(Secret::new(raw)))
    }

    /// The form the broker stores.
    pub fn to_hex(&self) -> Secret<String> {
        Secret::new(hex::encode(self.0.expose()))
    }

    fn mac(&self, message: &[u8]) -> hmac::Tag {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, self.0.expose()), message)
    }

    /// Names the pending code an attempt is for (32 lowercase hex digits).
    pub fn selector(&self) -> String {
        hex::encode(
            self.mac(CTX_PAIR_SELECTOR)
                .as_ref()
                .get(..16)
                .unwrap_or_default(),
        )
    }

    /// Whether a presented selector is this key's (constant time).
    pub fn selector_matches(&self, presented: &str) -> bool {
        proofs_equal(&self.selector(), presented)
    }

    /// The daemon's proof of the code over its identity and key.
    pub fn daemon_proof(&self, id: &DaemonId, daemon_key: &PublicKey) -> String {
        let t = transcript(&[
            CTX_PAIR,
            b"daemon",
            id.role.as_str().as_bytes(),
            id.name.as_str().as_bytes(),
            daemon_key.to_text().as_bytes(),
        ]);
        hex::encode(self.mac(&t))
    }

    /// The broker's proof of the code over both keys.
    pub fn broker_proof(
        &self,
        id: &DaemonId,
        daemon_key: &PublicKey,
        broker_key: &PublicKey,
    ) -> String {
        let t = transcript(&[
            CTX_PAIR,
            BROKER.as_bytes(),
            id.role.as_str().as_bytes(),
            id.name.as_str().as_bytes(),
            daemon_key.to_text().as_bytes(),
            broker_key.to_text().as_bytes(),
        ]);
        hex::encode(self.mac(&t))
    }

    /// Checks a daemon's presented proof (constant time).
    pub fn verify_daemon_proof(
        &self,
        id: &DaemonId,
        daemon_key: &PublicKey,
        presented: &str,
    ) -> bool {
        proofs_equal(&self.daemon_proof(id, daemon_key), presented)
    }

    /// Checks the broker's presented proof (constant time).
    pub fn verify_broker_proof(
        &self,
        id: &DaemonId,
        daemon_key: &PublicKey,
        broker_key: &PublicKey,
        presented: &str,
    ) -> bool {
        proofs_equal(&self.broker_proof(id, daemon_key, broker_key), presented)
    }
}

/// Constant-time comparison of two proofs (or selectors) as UTF-8 bytes.
pub fn proofs_equal(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{DaemonName, Role};
    use crate::testvec::{s, vectors};

    #[test]
    fn normalization() {
        assert_eq!(normalize_pairing_code("abcd efgh-ijkl"), "ABCDEFGHIJKL");
        assert_eq!(
            normalize_pairing_code(" A2C4-\tx9z8-QQQQ\n"),
            "A2C4X9Z8QQQQ"
        );
        assert_eq!(normalize_pairing_code("-- "), "");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn code_shape() {
        for _ in 0..50 {
            let c = generate_pairing_code().unwrap();
            let c = c.expose();
            assert_eq!(c.len(), 14);
            assert_eq!(c.matches('-').count(), 2);
            assert!(c.bytes().all(|b| b == b'-' || CODE_ALPHABET.contains(&b)));
            assert_eq!(normalize_pairing_code(c).len(), 12);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        let v = &vectors()["pairing"];
        let key = PairingKey::from_code(s(&v["code"]));
        assert_eq!(key.to_hex().expose(), s(&v["key"]));
        assert_eq!(
            PairingKey::from_hex(s(&v["key"]))
                .unwrap()
                .to_hex()
                .expose(),
            s(&v["key"])
        );
        // Normalization feeds the key.
        assert_eq!(
            PairingKey::from_code(&s(&v["code"]).to_lowercase().replace('-', " "))
                .to_hex()
                .expose(),
            s(&v["key"])
        );
        assert_eq!(key.selector(), s(&v["selector"]));
        assert!(key.selector_matches(s(&v["selector"])));
        let id = DaemonId::new(
            Role::parse(s(&v["role"])).unwrap(),
            DaemonName::parse(s(&v["name"])).unwrap(),
        );
        let dk = PublicKey::parse(s(&v["daemon_public"])).unwrap();
        let bk = PublicKey::parse(s(&v["broker_public"])).unwrap();
        assert_eq!(key.daemon_proof(&id, &dk), s(&v["daemon_proof"]));
        assert_eq!(key.broker_proof(&id, &dk, &bk), s(&v["broker_proof"]));
        assert!(key.verify_daemon_proof(&id, &dk, s(&v["daemon_proof"])));
        assert!(key.verify_broker_proof(&id, &dk, &bk, s(&v["broker_proof"])));
        // Bound to the name, the role and both keys.
        let other = DaemonId::new(id.role, DaemonName::parse("other").unwrap());
        assert!(!key.verify_daemon_proof(&other, &dk, s(&v["daemon_proof"])));
        let sandbox = DaemonId::new(Role::Sandbox, id.name.clone());
        assert!(!key.verify_daemon_proof(&sandbox, &dk, s(&v["daemon_proof"])));
        assert!(!key.verify_broker_proof(&id, &bk, &dk, s(&v["broker_proof"])));
        assert!(
            !PairingKey::from_code("AAAA-AAAA-AAAA").verify_daemon_proof(
                &id,
                &dk,
                s(&v["daemon_proof"])
            )
        );
    }

    #[test]
    fn proofs_equal_tolerates_anything() {
        assert!(proofs_equal("ab", "ab"));
        assert!(!proofs_equal("ab", "\u{e9}"));
        assert!(!proofs_equal("", "a"));
    }
}
