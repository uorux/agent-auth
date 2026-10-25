//! A secret in transit: an API key, an issued token, a TOTP code, a pairing
//! code. It goes on the wire as a plain string (the receiver needs it), but
//! never prints (`Debug` shows `[redacted]`), and its text is wiped when the
//! value is dropped. Move it into `crypto::Secret` with [`WireSecret::into_inner`].

use std::fmt;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::error::ValidationError;

/// A secret string of at most `MAX` characters.
pub struct WireSecret<const MAX: usize = 16384>(String);

/// A TOTP code as typed by the operator (hostd keeps only its digits).
pub type TotpCode = WireSecret<32>;

impl<const MAX: usize> WireSecret<MAX> {
    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let mut s: String = s.into();
        if s.len() > MAX && s.chars().count() > MAX {
            s.zeroize();
            return Err(ValidationError::new(format!(
                "a secret of at most {MAX} characters"
            )));
        }
        Ok(WireSecret(s))
    }

    /// The secret's text. Don't log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Take the text out (the caller becomes responsible for wiping it).
    #[must_use]
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl<const MAX: usize> Drop for WireSecret<MAX> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const MAX: usize> Clone for WireSecret<MAX> {
    fn clone(&self) -> Self {
        WireSecret(self.0.clone())
    }
}

impl<const MAX: usize> fmt::Debug for WireSecret<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Equality for tests and bookkeeping, compared without an early exit. Not
/// an authentication check: those hash and compare in the crypto crate.
impl<const MAX: usize> PartialEq for WireSecret<MAX> {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.0.as_bytes(), other.0.as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl<const MAX: usize> Eq for WireSecret<MAX> {}

impl<const MAX: usize> Serialize for WireSecret<MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for WireSecret<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        WireSecret::new(s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints() {
        let s: WireSecret = WireSecret::new("aa_0123_secret").unwrap();
        assert_eq!(format!("{s:?}"), "[redacted]");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"aa_0123_secret\"");
        assert_eq!(s.expose(), "aa_0123_secret");
        assert!(TotpCode::new("1".repeat(33)).is_err());
        assert_eq!(s.clone(), s);
        assert_ne!(s, WireSecret::new("aa_0123_secreT").unwrap());
    }
}
