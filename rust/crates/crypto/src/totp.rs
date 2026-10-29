//! TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 s steps, T0 = 0) as hostd
//! checks it.
//!
//! [`verify`] accepts a code for the step before, at, or after the current
//! one, compares in constant time, and returns the step it matched (the
//! highest, if several do). The caller persists that step as the secret's
//! "last used step" before acting, and passes it back next time: a code
//! for that step or any earlier one is then refused, so each code is
//! single use. Failure counting and lockout are the caller's (they need
//! storage).

use std::fmt;

use ring::hmac;

use crate::rng::{RandomError, array};
use crate::secret::{Secret, ct_eq};

/// Seconds per step.
pub const STEP_SECS: u64 = 30;
/// Digits per code.
pub const DIGITS: usize = 6;
/// Steps accepted on either side of the current one.
pub const WINDOW_STEPS: u64 = 1;

/// The shortest secret accepted, in bytes (128 bits; RFC 4226 §4 asks for
/// at least that). Generated secrets are 20 bytes.
pub const MIN_SECRET_BYTES: usize = 16;

/// A TOTP secret could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpSecretError {
    #[error("TOTP secret is not base32")]
    NotBase32,
    /// An empty or short secret makes predictable codes.
    #[error("TOTP secret is {0} bytes; at least 16 are required")]
    TooShort(usize),
}

/// A TOTP shared secret (the raw key bytes, at least
/// [`MIN_SECRET_BYTES`]).
#[derive(Clone)]
pub struct TotpSecret(Secret<Vec<u8>>);

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(..)")
    }
}

impl TotpSecret {
    /// 160 random bits.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self(Secret::new(array::<20>()?.to_vec())))
    }

    /// Parses the base32 text (what authenticator apps take): case
    /// insensitive, padding optional, surrounding whitespace ignored.
    /// Refuses secrets shorter than [`MIN_SECRET_BYTES`].
    pub fn from_base32(text: &str) -> Result<Self, TotpSecretError> {
        let raw = base32_decode(text.trim()).ok_or(TotpSecretError::NotBase32)?;
        Self::from_bytes(raw)
    }

    /// The secret from its raw bytes (at least [`MIN_SECRET_BYTES`]).
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, TotpSecretError> {
        let raw = Secret::new(raw);
        if raw.expose().len() < MIN_SECRET_BYTES {
            return Err(TotpSecretError::TooShort(raw.expose().len()));
        }
        Ok(Self(raw))
    }

    /// Base32 without padding (32 characters for a generated secret).
    pub fn to_base32(&self) -> Secret<String> {
        Secret::new(base32_encode(self.0.expose()))
    }

    /// The code for one step.
    pub fn code_at(&self, step: u64) -> Secret<String> {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, self.0.expose());
        let tag = hmac::sign(&key, &step.to_be_bytes());
        Secret::new(truncate(tag.as_ref()))
    }
}

/// RFC 4226 dynamic truncation of an HMAC-SHA1 output to 6 digits.
fn truncate(mac: &[u8]) -> String {
    let offset = mac.last().map_or(0, |b| usize::from(b & 0x0f));
    let mut word = [0u8; 4];
    if let Some(w) = mac.get(offset..offset.saturating_add(4)) {
        word.copy_from_slice(w);
    }
    let number = u32::from_be_bytes(word) & 0x7fff_ffff;
    format!("{:06}", number % 1_000_000)
}

/// Why a code was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// Counts as a failure toward the lockout.
    #[error("wrong code")]
    WrongCode,
    /// Right code, already used (or older than one used). Not a failure.
    #[error("that code was already used; wait for the next one")]
    AlreadyUsed,
}

/// A step a code was accepted for: persist it as the last used step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AcceptedStep(pub u64);

/// Checks `code` (non-digits ignored, as the Python did) at `now` (Unix
/// seconds) against the window, refusing steps at or before `last_step`.
pub fn verify(
    secret: &TotpSecret,
    code: &str,
    now_unix_secs: u64,
    last_step: Option<u64>,
) -> Result<AcceptedStep, TotpError> {
    let digits: String = code.chars().filter(char::is_ascii_digit).collect();
    let current = now_unix_secs / STEP_SECS;
    let mut matched = None;
    let first = current.saturating_sub(WINDOW_STEPS);
    let last = current.saturating_add(WINDOW_STEPS);
    for step in first..=last {
        // Every candidate is computed and compared, whatever matched.
        let candidate = secret.code_at(step);
        if digits.len() == DIGITS && ct_eq(candidate.expose().as_bytes(), digits.as_bytes()) {
            matched = Some(step);
        }
    }
    let step = matched.ok_or(TotpError::WrongCode)?;
    if last_step.is_some_and(|last| step <= last) {
        return Err(TotpError::AlreadyUsed);
    }
    Ok(AcceptedStep(step))
}

/// `otpauth://` URI for enrolling an authenticator app, labelled
/// `agent-auth:{host} {name}`.
pub fn otpauth_uri(secret: &TotpSecret, host: &str, name: &str) -> Secret<String> {
    let label = percent_encode(&format!("agent-auth:{host} {name}"));
    Secret::new(format!(
        "otpauth://totp/{label}?secret={}&issuer=agent-auth&digits={DIGITS}&period={STEP_SECS}",
        secret.to_base32().expose()
    ))
}

/// Python `urllib.parse.quote(s)` (safe characters: unreserved and `/`).
fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let idx = (buffer >> bits) & 0x1f;
            out.push(sym(idx));
        }
        buffer &= (1u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        out.push(sym((buffer << (5u32.saturating_sub(bits))) & 0x1f));
    }
    out
}

fn sym(idx: u32) -> char {
    usize::try_from(idx)
        .ok()
        .and_then(|i| B32.get(i))
        .map_or('A', |b| char::from(*b))
}

/// RFC 4648 base32, case-insensitive, `=` padding optional. Lengths a
/// whole number of bytes can't have (1, 3 or 6 symbols in the last group)
/// are refused, like Python's `b32decode`.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    if !matches!(body.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    if !text.len().is_multiple_of(8) && body.len() != text.len() {
        // Padding present but not to a multiple of 8.
        return None;
    }
    let mut out = Vec::with_capacity(body.len().saturating_mul(5) / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in body.bytes() {
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c.wrapping_sub(b'A'),
            c @ b'2'..=b'7' => c.wrapping_sub(b'2').wrapping_add(26),
            _ => return None,
        };
        buffer = ((buffer << 5) | u32::from(v)) & 0xffff;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{s, vectors};
    use proptest::prelude::*;

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn truncation_rfc4226() {
        // RFC 4226 §5.4: the HMAC for count 0 of "12345678901234567890".
        let mac = hex::decode("1f8698690e02ca16618550ef7f19da8e945b555a").unwrap();
        assert_eq!(truncate(&mac), "872921");
    }

    #[test]
    fn base32() {
        assert_eq!(base32_decode(RFC_SECRET).unwrap(), b"12345678901234567890");
        assert_eq!(base32_encode(b"12345678901234567890"), RFC_SECRET);
        assert_eq!(
            base32_decode(&RFC_SECRET.to_lowercase()).unwrap(),
            b"12345678901234567890"
        );
        assert_eq!(base32_decode("MY======").unwrap(), b"f");
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ").unwrap(), b"fo");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert!(base32_decode("M").is_none());
        assert!(base32_decode("MY=").is_none());
        assert!(base32_decode("M1").is_none());
        assert_eq!(base32_decode("").unwrap(), b"");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rfc_vector() {
        let secret = TotpSecret::from_base32(RFC_SECRET).unwrap();
        assert_eq!(secret.code_at(1).expose(), "287082");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        let v = &vectors()["totp"];
        let secret = TotpSecret::from_base32(s(&v["secret"])).unwrap();
        for case in v["codes"].as_array().unwrap() {
            let step = case["step"].as_u64().unwrap();
            assert_eq!(
                secret.code_at(step).expose(),
                s(&case["code"]),
                "step {step}"
            );
        }
        assert_eq!(
            otpauth_uri(&secret, "excelsior", "root-arm").expose(),
            s(&v["uri"])
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn window_and_replay() {
        let secret = TotpSecret::from_base32(RFC_SECRET).unwrap();
        let now = 1_761_400_015;
        let current = now / 30;
        let code = |step| secret.code_at(step).expose().clone();
        assert_eq!(
            verify(&secret, &code(current), now, None),
            Ok(AcceptedStep(current))
        );
        assert_eq!(
            verify(&secret, &code(current - 1), now, None),
            Ok(AcceptedStep(current - 1))
        );
        assert_eq!(
            verify(&secret, &code(current + 1), now, None),
            Ok(AcceptedStep(current + 1))
        );
        assert_eq!(
            verify(&secret, &code(current + 2), now, None),
            Err(TotpError::WrongCode)
        );
        assert_eq!(
            verify(&secret, &code(current - 2), now, None),
            Err(TotpError::WrongCode)
        );
        // Single use, and nothing earlier after a later step.
        assert_eq!(
            verify(&secret, &code(current), now, Some(current)),
            Err(TotpError::AlreadyUsed)
        );
        assert_eq!(
            verify(&secret, &code(current - 1), now, Some(current)),
            Err(TotpError::AlreadyUsed)
        );
        assert_eq!(
            verify(&secret, &code(current + 1), now, Some(current)),
            Ok(AcceptedStep(current + 1))
        );
        // Separators are ignored; wrong lengths never match.
        let spaced = format!("{} {}", &code(current)[..3], &code(current)[3..]);
        assert!(verify(&secret, &spaced, now, None).is_ok());
        assert_eq!(
            verify(&secret, &format!("{}0", code(current)), now, None),
            Err(TotpError::WrongCode)
        );
        assert_eq!(verify(&secret, "", now, None), Err(TotpError::WrongCode));
    }

    #[test]
    fn short_secrets_refused() {
        for (text, len) in [
            ("", 0),
            ("AA", 1),
            ("MZXW6", 3),
            ("GEZDGNBVGY3TQOJQGEZDGNBV", 15),
        ] {
            assert_eq!(
                TotpSecret::from_base32(text).unwrap_err(),
                TotpSecretError::TooShort(len),
                "{text:?}"
            );
        }
        assert_eq!(
            TotpSecret::from_bytes(vec![0; 15]).unwrap_err(),
            TotpSecretError::TooShort(15)
        );
        assert!(TotpSecret::from_bytes(vec![0; 16]).is_ok());
        assert!(TotpSecret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY").is_ok());
        assert_eq!(
            TotpSecret::from_base32("not base32!").unwrap_err(),
            TotpSecretError::NotBase32
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generated_secret() {
        let s = TotpSecret::generate().unwrap();
        let text = s.to_base32();
        assert_eq!(text.expose().len(), 32);
        let back = TotpSecret::from_base32(text.expose()).unwrap();
        assert_eq!(back.code_at(5).expose(), s.code_at(5).expose());
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 8 } else { 256 },
            // Miri isolates the file system; nothing to persist there.
            failure_persistence: if cfg!(miri) { None } else { ProptestConfig::default().failure_persistence },
            ..ProptestConfig::default()
        })]

        #[test]
        fn base32_roundtrip(data in prop::collection::vec(any::<u8>(), 0..40)) {
            prop_assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }

        #[test]
        fn truncation_is_six_digits(mac in prop::array::uniform20(any::<u8>())) {
            let code = truncate(&mac);
            prop_assert_eq!(code.len(), 6);
            prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
