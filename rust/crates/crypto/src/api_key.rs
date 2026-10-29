//! Agent API keys.
//!
//! A key is `aa_<key id>_<secret>`: the key id is 12 lowercase hex
//! characters (6 random bytes) and names the agent; the secret is 32 random
//! bytes in URL-safe base64 without padding (43 characters, which may
//! include `-` and `_`). The broker stores the key id and
//! `sha256_hex(secret)`, never the key; the full key is shown once.

use std::fmt;

use ring::digest;

use crate::encoding::b64url_encode;
use crate::rng::{RandomError, array};
use crate::secret::{Secret, ct_eq};

/// The fixed first part of every key.
pub const API_KEY_PREFIX: &str = "aa";
const KEY_ID_LEN: usize = 12;
const SECRET_LEN: usize = 43;

/// The public half of a key: which agent it claims to be. Safe to log.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Parses a stored key id (12 lowercase hex characters).
    pub fn parse(text: &str) -> Option<Self> {
        is_key_id(text).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `sha256_hex(secret)`, what the database keeps. Not secret by itself (it
/// does not let anyone authenticate), but compared in constant time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHash(String);

impl SecretHash {
    /// Wraps a stored hash (64 lowercase hex characters).
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A freshly generated key: show `full_key` to the operator once, store
/// `key_id` and `hash`.
#[derive(Debug)]
pub struct GeneratedKey {
    pub full_key: Secret<String>,
    pub key_id: KeyId,
    pub hash: SecretHash,
}

/// Makes a new key (Python `generate_api_key`).
pub fn generate() -> Result<GeneratedKey, RandomError> {
    let id_bytes: [u8; 6] = array()?;
    let mut secret_bytes: [u8; 32] = array()?;
    let key_id = KeyId(hex::encode(id_bytes));
    let secret = Secret::new(b64url_encode(&secret_bytes));
    zeroize::Zeroize::zeroize(&mut secret_bytes);
    let hash = hash_secret(secret.expose());
    let full_key = Secret::new(format!("{API_KEY_PREFIX}_{key_id}_{}", secret.expose()));
    Ok(GeneratedKey {
        full_key,
        key_id,
        hash,
    })
}

/// A presented key, split into its parts.
#[derive(Debug)]
pub struct ParsedKey {
    pub key_id: KeyId,
    pub secret: Secret<String>,
}

/// Splits `aa_<key id>_<secret>`; `None` is "malformed API key".
///
/// Stricter than the Python (which split on the first two `_` and accepted
/// any parts): the key id must be 12 lowercase hex characters and the
/// secret 43 URL-safe base64 characters, the only shape ever issued.
pub fn parse(full_key: &str) -> Option<ParsedKey> {
    let rest = full_key.strip_prefix(API_KEY_PREFIX)?.strip_prefix('_')?;
    let (key_id, secret) = rest.split_once('_')?;
    if !is_key_id(key_id) || !is_secret(secret) {
        return None;
    }
    Some(ParsedKey {
        key_id: KeyId(key_id.to_owned()),
        secret: Secret::new(secret.to_owned()),
    })
}

/// `sha256_hex(secret)` (Python `hash_secret`).
pub fn hash_secret(secret: &str) -> SecretHash {
    SecretHash(hex::encode(digest::digest(
        &digest::SHA256,
        secret.as_bytes(),
    )))
}

/// Whether `secret` hashes to `stored`, compared in constant time.
pub fn verify(secret: &Secret<String>, stored: &SecretHash) -> bool {
    ct_eq(
        hash_secret(secret.expose()).0.as_bytes(),
        stored.0.as_bytes(),
    )
}

fn is_key_id(text: &str) -> bool {
    text.len() == KEY_ID_LEN && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_secret(text: &str) -> bool {
    text.len() == SECRET_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testvec::{s, vectors};

    const SECRET: &str = "q8Uo2l3mZ_-xXvYkN0aB1cD2eF3gH4iJ5kL6mN7oP8Q";

    #[test]
    #[cfg_attr(miri, ignore)]
    fn known_hash() {
        let v = &vectors()["api_key"];
        let parsed = parse(s(&v["full_key"])).unwrap();
        assert_eq!(parsed.key_id.as_str(), s(&v["key_id"]));
        assert_eq!(parsed.secret.expose(), s(&v["secret"]));
        let stored = SecretHash::parse(s(&v["hash"])).unwrap();
        assert_eq!(hash_secret(parsed.secret.expose()), stored);
        assert!(verify(&parsed.secret, &stored));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_parse_verify() {
        let g = generate().unwrap();
        let text = g.full_key.expose();
        assert_eq!(text.len(), 3 + 12 + 1 + 43);
        let p = parse(text).unwrap();
        assert_eq!(p.key_id, g.key_id);
        assert!(verify(&p.secret, &g.hash));
        let other = parse(&format!("aa_{}_{}", g.key_id, SECRET)).unwrap();
        assert!(!verify(&other.secret, &g.hash));
    }

    #[test]
    fn parse_shapes() {
        let ok = format!("aa_0123456789ab_{SECRET}");
        let p = parse(&ok).unwrap();
        assert_eq!(p.key_id.as_str(), "0123456789ab");
        assert_eq!(p.secret.expose(), SECRET);
        for bad in [
            String::new(),
            "aa".into(),
            "aa__x".into(),
            format!("ab_0123456789ab_{SECRET}"),
            format!("aa_0123456789AB_{SECRET}"),
            format!("aa_0123456789a_{SECRET}"),
            format!("aa_0123456789ab_{SECRET}x"),
            format!("aa_0123456789ab_{}", &SECRET[1..]),
            format!("aa_0123456789ab_{}=", &SECRET[1..]),
            format!("aa-0123456789ab_{SECRET}"),
        ] {
            assert!(parse(&bad).is_none(), "{bad}");
        }
    }
}
