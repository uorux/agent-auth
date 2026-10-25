//! Ed25519 identity keys and their text forms.
//!
//! - Private key text: the 32-byte seed in URL-safe base64 without padding
//!   (`BROKER_SIGNING_KEY`, and a daemon's key file followed by `\n`).
//! - Public key text: `ed25519:` + the 32-byte raw key in URL-safe base64
//!   without padding (43 characters).
//! - Fingerprint: the first 32 hex digits of SHA-256(raw public key), in 8
//!   groups of 4 joined by `:`.

use std::fmt;
use std::sync::Arc;

use ring::digest;
use ring::signature::{self, Ed25519KeyPair, KeyPair as _};
use zeroize::Zeroize;

use crate::encoding::{b64url_decode, b64url_encode};
use crate::rng::{RandomError, array};
use crate::secret::Secret;

const PUBLIC_KEY_PREFIX: &str = "ed25519:";

/// A key text did not parse. The messages are the Python's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyParseError {
    #[error("signing key is not base64")]
    SigningKeyNotBase64,
    #[error("signing key must be a 32-byte ed25519 seed")]
    SigningKeyLength,
    #[error("public key must start with 'ed25519:'")]
    PublicKeyPrefix,
    #[error("public key is not base64")]
    PublicKeyNotBase64,
    #[error("public key must be 32 bytes")]
    PublicKeyLength,
}

/// An Ed25519 private key (the broker's, or a daemon's identity). Cheap to
/// clone; the seed is zeroized when the last clone is dropped.
#[derive(Clone)]
pub struct SigningKey {
    pair: Arc<Ed25519KeyPair>,
    seed: Arc<Secret<[u8; 32]>>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A new random key.
    pub fn generate() -> Result<Self, RandomError> {
        let mut seed: [u8; 32] = array()?;
        let key = Self::from_seed(&seed);
        seed.zeroize();
        key.map_err(|_| RandomError)
    }

    /// The key with this 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, KeyParseError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| KeyParseError::SigningKeyLength)?;
        Ok(Self {
            pair: Arc::new(pair),
            seed: Arc::new(Secret::new(*seed)),
        })
    }

    /// Parses private key text (surrounding whitespace ignored; padding
    /// optional).
    pub fn from_text(text: &str) -> Result<Self, KeyParseError> {
        let mut raw = b64url_decode(text.trim()).ok_or(KeyParseError::SigningKeyNotBase64)?;
        let seed = <[u8; 32]>::try_from(raw.as_slice());
        raw.zeroize();
        let mut seed = seed.map_err(|_| KeyParseError::SigningKeyLength)?;
        let key = Self::from_seed(&seed);
        seed.zeroize();
        key
    }

    /// The private key text (no trailing newline).
    pub fn to_text(&self) -> Secret<String> {
        Secret::new(b64url_encode(self.seed.expose()))
    }

    pub fn public_key(&self) -> PublicKey {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(self.pair.public_key().as_ref());
        PublicKey(raw)
    }

    /// The raw seed, for deriving the broker's other keys.
    pub(crate) fn seed(&self) -> &[u8; 32] {
        self.seed.expose()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_text())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl PublicKey {
    /// Parses `ed25519:<base64url>` (padding optional).
    pub fn parse(text: &str) -> Result<Self, KeyParseError> {
        let body = text
            .strip_prefix(PUBLIC_KEY_PREFIX)
            .ok_or(KeyParseError::PublicKeyPrefix)?;
        let raw = b64url_decode(body).ok_or(KeyParseError::PublicKeyNotBase64)?;
        <[u8; 32]>::try_from(raw.as_slice())
            .map(Self)
            .map_err(|_| KeyParseError::PublicKeyLength)
    }

    pub fn from_bytes(raw: [u8; 32]) -> Self {
        Self(raw)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `ed25519:<base64url>`, the canonical text (what proofs cover).
    pub fn to_text(&self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", b64url_encode(&self.0))
    }

    /// The short form both sides show at pairing, e.g.
    /// `e6c4:3ab3:bdce:125a:f325:8d43:690e:4f1f`.
    pub fn fingerprint(&self) -> String {
        let hash = digest::digest(&digest::SHA256, &self.0);
        let hex = hex::encode(hash.as_ref().get(..16).unwrap_or_default());
        let groups: Vec<&str> = (0..8)
            .filter_map(|i: usize| {
                hex.get(i.saturating_mul(4)..i.saturating_mul(4).saturating_add(4))
            })
            .collect();
        groups.join(":")
    }

    /// Whether `signature` is this key's signature of `message`.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.0)
            .verify(message, signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{s, vectors};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        let v = &vectors()["keys"];
        let key = SigningKey::from_text(s(&v["private"])).unwrap();
        assert_eq!(key.to_text().expose(), s(&v["private"]));
        assert_eq!(key.public_key().to_text(), s(&v["public"]));
        assert_eq!(key.public_key().fingerprint(), s(&v["fingerprint"]));
        let parsed = PublicKey::parse(s(&v["public"])).unwrap();
        assert_eq!(parsed, key.public_key());
        // Padded and whitespace-wrapped forms parse too.
        assert!(SigningKey::from_text(&format!("  {}=\n", s(&v["private"]))).is_ok());
        assert_eq!(
            PublicKey::parse(&format!("{}=", s(&v["public"]))).unwrap(),
            parsed
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(
            SigningKey::from_text("!!").unwrap_err(),
            KeyParseError::SigningKeyNotBase64
        );
        assert_eq!(
            SigningKey::from_text("AAAA").unwrap_err(),
            KeyParseError::SigningKeyLength
        );
        assert_eq!(
            PublicKey::parse("ed448:AAAA").unwrap_err(),
            KeyParseError::PublicKeyPrefix
        );
        assert_eq!(
            PublicKey::parse("ed25519:!").unwrap_err(),
            KeyParseError::PublicKeyNotBase64
        );
        assert_eq!(
            PublicKey::parse("ed25519:AAAA").unwrap_err(),
            KeyParseError::PublicKeyLength
        );
        let k = PublicKey::from_bytes([1; 32]);
        assert_eq!(PublicKey::parse(&k.to_text()).unwrap(), k);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sign_verify() {
        let k = SigningKey::generate().unwrap();
        let sig = k.sign(b"m");
        assert!(k.public_key().verify(b"m", &sig));
        assert!(!k.public_key().verify(b"n", &sig));
        assert!(
            !SigningKey::generate()
                .unwrap()
                .public_key()
                .verify(b"m", &sig)
        );
        assert!(format!("{k:?}").starts_with("SigningKey { public: PublicKey(ed25519:"));
    }
}
