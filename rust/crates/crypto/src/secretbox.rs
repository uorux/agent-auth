//! Encryption at rest for credentials the broker keeps (cached tokens,
//! LLDAP passwords, pending key deliveries, provisioner state).
//!
//! Replaces the Python's Fernet. The key is 32 bytes, given in base64
//! (`ENCRYPTION_KEY`; URL-safe or standard alphabet, padding optional — the
//! shape of a Fernet key, so an existing setting still parses, though old
//! ciphertexts do not open: the database is new).
//!
//! # Format
//!
//! ```text
//! text = base64url_nopad( 0x01 ‖ nonce[12] ‖ ChaCha20-Poly1305(plaintext) ‖ tag[16] )
//! aad  = transcript("agent-auth/v1/secretbox", [0x01], table, column, row)
//! ```
//!
//! - `0x01` is the format version; anything else is refused.
//! - The nonce is 96 random bits per message. With random nonces a key
//!   should seal fewer than 2³² messages, far beyond what the broker writes.
//! - The associated data binds the ciphertext to where it is stored
//!   ([`Binding`]): a value copied into another row or column fails to open,
//!   so read access plus write access to the database cannot move an
//!   agent's credential to another agent. `transcript` is the
//!   length-prefixed encoding of [`crate::daemon::transcript`].

use std::fmt;

use ring::aead::{self, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroize;

use crate::daemon::transcript;
use crate::encoding::{b64url_decode, b64url_encode, decode_key32};
use crate::rng::{RandomError, array};
use crate::secret::Secret;

const VERSION: u8 = 0x01;
const CONTEXT: &[u8] = b"agent-auth/v1/secretbox";
const NONCE_LEN: usize = aead::NONCE_LEN;
const TAG_LEN: usize = 16;

/// Where a ciphertext lives. Use the same values to open as to seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding<'a> {
    pub table: &'a str,
    pub column: &'a str,
    /// The row's primary key (or another stable name for the record).
    pub row: &'a str,
}

impl<'a> Binding<'a> {
    pub fn new(table: &'a str, column: &'a str, row: &'a str) -> Self {
        Self { table, column, row }
    }

    fn aad(&self) -> Vec<u8> {
        transcript(&[
            CONTEXT,
            &[VERSION],
            self.table.as_bytes(),
            self.column.as_bytes(),
            self.row.as_bytes(),
        ])
    }
}

/// The encryption key could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ENCRYPTION_KEY must be 32 bytes in base64")]
pub struct KeyError;

/// A ciphertext did not open: malformed, wrong version, wrong key, wrong
/// binding, or tampered with. Deliberately one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ciphertext could not be decrypted")]
pub struct OpenError;

/// A value could not be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error(transparent)]
    Random(#[from] RandomError),
    /// Beyond ChaCha20's per-message limit (256 GiB).
    #[error("value too large to encrypt")]
    TooLarge,
}

/// Seals and opens values at rest with one key.
pub struct SecretBox {
    key: LessSafeKey,
}

impl fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBox(..)")
    }
}

impl SecretBox {
    /// The key from its base64 text (`ENCRYPTION_KEY`).
    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        let mut raw = decode_key32(text).ok_or(KeyError)?;
        let made = Self::from_bytes(&raw);
        raw.zeroize();
        made
    }

    /// The key from its 32 raw bytes.
    pub fn from_bytes(raw: &[u8; 32]) -> Result<Self, KeyError> {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, raw).map_err(|_| KeyError)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    /// A key of its own for another purpose, derived from the base64 key
    /// text: HKDF-SHA256 (no salt, `info`, 32 bytes) over the 32 key bytes.
    /// The admin panel seals its cookies with one, so a cookie is never a
    /// stored credential's ciphertext, nor the other way round.
    pub fn derived(master: &str, info: &[u8]) -> Result<Self, KeyError> {
        struct Len32;
        impl ring::hkdf::KeyType for Len32 {
            fn len(&self) -> usize {
                32
            }
        }
        let mut raw = decode_key32(master).ok_or(KeyError)?;
        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(&raw);
        raw.zeroize();
        let mut okm = [0u8; 32];
        let infos = [info];
        prk.expand(&infos, Len32)
            .and_then(|o| o.fill(&mut okm))
            .map_err(|_| KeyError)?;
        let made = Self::from_bytes(&okm);
        okm.zeroize();
        made
    }

    /// A new key as text for `ENCRYPTION_KEY` (URL-safe base64 with
    /// padding, 44 characters: the `gen-key` command).
    pub fn generate_key() -> Result<Secret<String>, RandomError> {
        let mut raw: [u8; 32] = array()?;
        let text = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, raw);
        raw.zeroize();
        Ok(Secret::new(text))
    }

    /// Encrypts `plaintext` for the place `binding` names.
    pub fn seal(&self, plaintext: &[u8], binding: &Binding<'_>) -> Result<String, SealError> {
        let nonce: [u8; NONCE_LEN] = array()?;
        let mut out = Vec::with_capacity(
            1usize
                .saturating_add(NONCE_LEN)
                .saturating_add(plaintext.len())
                .saturating_add(TAG_LEN),
        );
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        let sealed = self.key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(binding.aad()),
            &mut body,
        );
        if sealed.is_err() {
            body.zeroize();
            return Err(SealError::TooLarge);
        }
        out.extend_from_slice(&body);
        // `body` is ciphertext now; nothing secret is left behind.
        Ok(b64url_encode(&out))
    }

    /// Encrypts a string.
    pub fn seal_str(&self, plaintext: &str, binding: &Binding<'_>) -> Result<String, SealError> {
        self.seal(plaintext.as_bytes(), binding)
    }

    /// Decrypts what [`SecretBox::seal`] made for the same `binding`.
    pub fn open(&self, text: &str, binding: &Binding<'_>) -> Result<Secret<Vec<u8>>, OpenError> {
        let mut blob = b64url_decode(text).ok_or(OpenError)?;
        let opened = self.open_blob(&mut blob, binding);
        // Holds plaintext after a successful open (and whatever ring left
        // after a failed one).
        blob.zeroize();
        opened
    }

    fn open_blob(
        &self,
        blob: &mut [u8],
        binding: &Binding<'_>,
    ) -> Result<Secret<Vec<u8>>, OpenError> {
        let (version, rest) = blob.split_first().ok_or(OpenError)?;
        if *version != VERSION || rest.len() < NONCE_LEN.saturating_add(TAG_LEN) {
            return Err(OpenError);
        }
        let nonce = rest
            .get(..NONCE_LEN)
            .and_then(|n| <[u8; NONCE_LEN]>::try_from(n).ok())
            .ok_or(OpenError)?;
        let body = blob
            .get_mut(1usize.saturating_add(NONCE_LEN)..)
            .ok_or(OpenError)?;
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(binding.aad()),
                body,
            )
            .map_err(|_| OpenError)?
            .to_vec();
        Ok(Secret::new(plain))
    }

    /// Decrypts a string sealed with [`SecretBox::seal_str`].
    pub fn open_str(&self, text: &str, binding: &Binding<'_>) -> Result<Secret<String>, OpenError> {
        let bytes = self.open(text, binding)?;
        let s = std::str::from_utf8(bytes.expose()).map_err(|_| OpenError)?;
        Ok(Secret::new(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn boxed() -> SecretBox {
        SecretBox::from_bytes(&[42u8; 32]).unwrap()
    }

    /// HKDF-SHA256 as Python's `cryptography` computes it (salt none).
    #[test]
    fn derived_key_is_hkdf() {
        let master = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
        let derived = SecretBox::derived(master, b"agent-auth admin panel session").unwrap();
        let okm: [u8; 32] =
            hex::decode("edd675abe2f7dbc33464f17ae5081b0778b04fd3325be185ab61a766d5b0c9e6")
                .unwrap()
                .try_into()
                .unwrap();
        let expected = SecretBox::from_bytes(&okm).unwrap();
        let sealed = derived.seal(b"x", &B).unwrap();
        assert_eq!(expected.open(&sealed, &B).unwrap().expose(), b"x");
        let master_box = SecretBox::from_base64(master).unwrap();
        assert!(master_box.open(&sealed, &B).is_err());
        assert!(SecretBox::derived("short", b"i").is_err());
    }

    const B: Binding<'static> = Binding {
        table: "credentials",
        column: "value_encrypted",
        row: "7f1e",
    };

    #[test]
    #[cfg_attr(miri, ignore)]
    fn roundtrip_and_binding() {
        let b = boxed();
        let ct = b.seal_str("ghs_token", &B).unwrap();
        assert_eq!(b.open_str(&ct, &B).unwrap().expose(), "ghs_token");
        for other in [
            Binding::new("credentials", "value_encrypted", "7f1f"),
            Binding::new("credentials", "other", "7f1e"),
            Binding::new("agents", "value_encrypted", "7f1e"),
            // Field boundaries are unambiguous.
            Binding::new("credentialsv", "alue_encrypted", "7f1e"),
        ] {
            assert_eq!(b.open(&ct, &other).unwrap_err(), OpenError);
        }
        let other_key = SecretBox::from_bytes(&[43u8; 32]).unwrap();
        assert!(other_key.open(&ct, &B).is_err());
        // Fresh nonce each time.
        assert_ne!(ct, b.seal_str("ghs_token", &B).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn malformed() {
        let b = boxed();
        for bad in [
            "",
            "AQ",
            "!!!!",
            &b64url_encode(&[2u8; 40]),
            &b64url_encode(&[1u8; 28]),
        ] {
            assert!(b.open(bad, &B).is_err(), "{bad}");
        }
        let mut blob = b64url_decode(&b.seal(b"x", &B).unwrap()).unwrap();
        blob[0] = 2;
        assert!(b.open(&b64url_encode(&blob), &B).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn keys() {
        let k = SecretBox::generate_key().unwrap();
        assert_eq!(k.expose().len(), 44);
        let a = SecretBox::from_base64(k.expose()).unwrap();
        let b = SecretBox::from_base64(k.expose().trim_end_matches('=')).unwrap();
        let ct = a.seal(b"v", &B).unwrap();
        assert_eq!(b.open(&ct, &B).unwrap().expose(), b"v");
        assert_eq!(SecretBox::from_base64("short").unwrap_err(), KeyError);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        #[cfg_attr(miri, ignore)]
        fn any_tamper_fails(plain in prop::collection::vec(any::<u8>(), 0..64), idx in any::<usize>(), flip in 1u8..) {
            let b = boxed();
            let ct = b.seal(&plain, &B).unwrap();
            let opened = b.open(&ct, &B).unwrap();
            prop_assert_eq!(opened.expose(), &plain);
            let mut blob = b64url_decode(&ct).unwrap();
            let i = idx.checked_rem(blob.len()).unwrap();
            blob[i] ^= flip;
            prop_assert!(b.open(&b64url_encode(&blob), &B).is_err());
            blob[i] ^= flip;
            blob.pop();
            prop_assert!(b.open(&b64url_encode(&blob), &B).is_err());
        }
    }
}
