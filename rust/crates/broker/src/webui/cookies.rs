//! Sealed cookies (surfaces spec §B.2) and the cookie headers.
//!
//! A cookie value is `SecretBox`-sealed JSON `{"k": kind, "t": issued (Unix
//! seconds), "d": data}` under a key of its own (HKDF of `ENCRYPTION_KEY`,
//! info `agent-auth admin panel session`), with the kind also bound into
//! the associated data: a login cookie never opens as a session, and a
//! cookie is never a stored credential's ciphertext. Opening enforces the
//! kind and the age (`max_age`), as Fernet's TTL did in the Python.
//!
//! Cookies are `Secure; HttpOnly; SameSite=Lax` (Lax: the provider's
//! redirect back is a cross-site navigation). The panel's live at `Path=/`
//! and carry the `__Host-` prefix (the browser then refuses them unless
//! they are Secure, host-only and for `/`); the OAuth ones are for
//! `/oauth`, so they take `__Secure-`.

use agent_auth_crypto::secretbox::{Binding, KeyError, SecretBox};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// What HKDF derives the cookie key with.
const KEY_INFO: &[u8] = b"agent-auth admin panel session";
/// The longest cookie value looked at (browsers keep about 4 KiB).
const MAX_COOKIE_CHARS: usize = 8192;
/// Clock skew tolerated for a cookie "issued in the future".
const SKEW_SECS: i64 = 60;

/// Seals and opens the web surfaces' cookies (and the consent form's
/// sealed blob).
pub struct Sealer {
    boxed: SecretBox,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(..)")
    }
}

/// The kinds of sealed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A sign-in in progress (state, nonce, PKCE verifier), 600 s.
    Login,
    /// A signed-in panel session, its TTL.
    Session,
    /// The OAuth consent form's blob, 600 s.
    Consent,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Session => "session",
            Kind::Consent => "consent",
        }
    }
}

impl Sealer {
    /// From `ENCRYPTION_KEY`'s text.
    pub fn new(encryption_key: &str) -> Result<Sealer, KeyError> {
        Ok(Sealer {
            boxed: SecretBox::derived(encryption_key, KEY_INFO)?,
        })
    }

    fn binding(kind: Kind) -> Binding<'static> {
        Binding::new("cookie", kind.as_str(), "agent-auth web")
    }

    /// Seals `data` as a value of `kind`, issued `now`. Fails only when the
    /// system's random source does (or `data` does not serialize).
    pub fn seal<T: Serialize>(&self, kind: Kind, data: &T, now: OffsetDateTime) -> Option<String> {
        let body = json!({"k": kind.as_str(), "t": now.unix_timestamp(), "d": data});
        self.boxed
            .seal(body.to_string().as_bytes(), &Self::binding(kind))
            .ok()
    }

    /// Opens a value of `kind` sealed at most `max_age_secs` before `now`.
    /// Anything else (another key, another kind, too old, tampered with,
    /// malformed) is `None`.
    pub fn open<T: DeserializeOwned>(
        &self,
        kind: Kind,
        value: &str,
        max_age_secs: i64,
        now: OffsetDateTime,
    ) -> Option<T> {
        if value.is_empty() || value.len() > MAX_COOKIE_CHARS {
            return None;
        }
        let plain = self.boxed.open(value, &Self::binding(kind)).ok()?;
        let body: Value = serde_json::from_slice(plain.expose()).ok()?;
        if body.get("k").and_then(Value::as_str) != Some(kind.as_str()) {
            return None;
        }
        let issued = body.get("t").and_then(Value::as_i64)?;
        let age = now.unix_timestamp().checked_sub(issued)?;
        if age < -SKEW_SECS || age > max_age_secs {
            return None;
        }
        serde_json::from_value(body.get("d")?.clone()).ok()
    }
}

/// The value of cookie `name` in the request (the first one sent).
#[must_use]
pub fn get<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

/// `Set-Cookie` for `name=value` on `path`, kept `max_age` seconds.
#[must_use]
pub fn set(
    name: &str,
    value: &str,
    path: &str,
    max_age: i64,
) -> (axum::http::HeaderName, HeaderValue) {
    let text =
        format!("{name}={value}; Max-Age={max_age}; Path={path}; Secure; HttpOnly; SameSite=Lax");
    // Sealed values are URL-safe base64; names and paths are ours.
    let value = HeaderValue::from_str(&text).unwrap_or_else(|_| HeaderValue::from_static(""));
    (SET_COOKIE, value)
}

/// `Set-Cookie` that deletes cookie `name` on `path`.
#[must_use]
pub fn delete(name: &str, path: &str) -> (axum::http::HeaderName, HeaderValue) {
    let text = format!(
        "{name}=\"\"; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path={path}; Secure; HttpOnly; SameSite=Lax"
    );
    let value = HeaderValue::from_str(&text).unwrap_or_else(|_| HeaderValue::from_static(""));
    (SET_COOKIE, value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use serde::Deserialize;
    use time::Duration;

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Data {
        user: String,
    }

    fn key(byte: u8) -> String {
        agent_auth_crypto::b64url_encode(&[byte; 32])
    }

    #[test]
    fn kinds_ages_and_keys() {
        let s = Sealer::new(&key(1)).unwrap();
        let now = OffsetDateTime::now_utc();
        let d = Data { user: "jrt".into() };
        let sealed = s.seal(Kind::Session, &d, now).unwrap();
        assert_eq!(s.open::<Data>(Kind::Session, &sealed, 60, now), Some(d));
        // Another kind, too old, another key, tampered, garbage.
        assert_eq!(s.open::<Data>(Kind::Login, &sealed, 60, now), None);
        assert_eq!(
            s.open::<Data>(Kind::Session, &sealed, 60, now + Duration::seconds(61)),
            None
        );
        let other = Sealer::new(&key(2)).unwrap();
        assert_eq!(other.open::<Data>(Kind::Session, &sealed, 60, now), None);
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(s.open::<Data>(Kind::Session, &tampered, 60, now), None);
        assert_eq!(s.open::<Data>(Kind::Session, "garbage", 60, now), None);
        // Not the at-rest key: a cookie is not a credential's ciphertext.
        let at_rest = SecretBox::from_base64(&key(1)).unwrap();
        assert!(
            at_rest
                .open(&sealed, &Sealer::binding(Kind::Session))
                .is_err()
        );
    }

    #[test]
    fn cookie_headers() {
        let mut h = HeaderMap::new();
        h.append(
            COOKIE,
            HeaderValue::from_static("a=1; __Host-aa_ui=xyz ; b=2"),
        );
        h.append(COOKIE, HeaderValue::from_static("c=3"));
        assert_eq!(get(&h, "__Host-aa_ui"), Some("xyz"));
        assert_eq!(get(&h, "c"), Some("3"));
        assert_eq!(get(&h, "aa_ui"), None);
        let (_, v) = set("__Host-aa_ui", "v", "/", 600);
        assert_eq!(
            v.to_str().unwrap(),
            "__Host-aa_ui=v; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
        assert!(
            delete("x", "/oauth")
                .1
                .to_str()
                .unwrap()
                .contains("Max-Age=0; Path=/oauth")
        );
    }
}
