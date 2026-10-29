//! The signatures on outbound webhooks.
//!
//! The broker's a2a pings are signed with a timestamp ([`sign_timestamped`]):
//! `X-Agent-Auth-Timestamp: <unix seconds>` and `X-Agent-Auth-Signature:
//! sha256=<lowercase hex HMAC-SHA256(key = the agent's webhook secret,
//! message = "<timestamp>." followed by the exact body bytes)>`, so a
//! receiver can refuse a replayed ping ([`verify_timestamped`]).
//!
//! `a2a serve` signs its dispatch to a local agent runtime the way that
//! runtime expects, over the body alone ([`sign_body`]), optionally as
//! `X-Hub-Signature-256`.

use ring::hmac;

/// The header carrying the signature.
pub const SIGNATURE_HEADER: &str = "X-Agent-Auth-Signature";
/// The header carrying the signing time of a timestamped signature.
pub const TIMESTAMP_HEADER: &str = "X-Agent-Auth-Timestamp";
/// How far a receiver should let a ping's timestamp be from its own clock
/// ([`verify_timestamped`]'s usual tolerance).
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;
/// GitHub's header name, which `a2a serve` can also emit.
pub const HUB_SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
const PREFIX: &str = "sha256=";

/// The header value for `body` (Python `sign_body`).
pub fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    format!("{PREFIX}{}", hex::encode(hmac::sign(&key, body)))
}

/// Whether `header` is a valid signature of `body` (constant time). Accepts
/// upper- or lowercase hex.
pub fn verify_body(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(mac) = header
        .trim()
        .strip_prefix(PREFIX)
        .and_then(|h| hex::decode(h).ok())
    else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, body, &mac).is_ok()
}

fn timestamped_message(timestamp: i64, body: &[u8]) -> Vec<u8> {
    let mut msg = format!("{timestamp}.").into_bytes();
    msg.extend_from_slice(body);
    msg
}

/// The signature header value for `body` sent at `timestamp` (unix
/// seconds): an HMAC over `"{timestamp}." + body`.
pub fn sign_timestamped(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    sign_body(secret, &timestamped_message(timestamp, body))
}

/// A receiver's check of a timestamped signature: the timestamp header is
/// a plain integer within `tolerance_secs` of `now` (unix seconds), and the
/// signature covers it and the body (constant time).
pub fn verify_timestamped(
    secret: &[u8],
    timestamp_header: &str,
    body: &[u8],
    signature_header: &str,
    now: i64,
    tolerance_secs: u64,
) -> bool {
    let t = timestamp_header.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(timestamp) = t.parse::<i64>() else {
        return false;
    };
    if now.abs_diff(timestamp) > tolerance_secs {
        return false;
    }
    verify_body(
        secret,
        &timestamped_message(timestamp, body),
        signature_header,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testvec::{s, vectors};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn matches_python() {
        let v = &vectors()["webhook"];
        let secret = s(&v["secret"]).as_bytes();
        let body = s(&v["body"]).as_bytes();
        let sig = sign_body(secret, body);
        assert_eq!(sig, s(&v["signature"]));
        assert!(verify_body(secret, body, &sig));
        assert!(verify_body(
            secret,
            body,
            &sig.to_uppercase().replace("SHA256=", "sha256=")
        ));
        assert!(!verify_body(secret, b"other", &sig));
        assert!(!verify_body(b"other", body, &sig));
        assert!(!verify_body(
            secret,
            body,
            sig.trim_start_matches("sha256=")
        ));
        assert!(!verify_body(secret, body, "sha256=zz"));
    }

    #[test]
    fn timestamped() {
        let sig = sign_timestamped(b"k", 1_700_000_000, b"{}");
        assert_eq!(sig, sign_body(b"k", b"1700000000.{}"));
        let ok = |t: &str, body: &[u8], now| {
            verify_timestamped(b"k", t, body, &sig, now, DEFAULT_TOLERANCE_SECS)
        };
        assert!(ok("1700000000", b"{}", 1_700_000_100));
        assert!(ok("1700000000", b"{}", 1_699_999_900));
        assert!(!ok("1700000000", b"{}", 1_700_000_301), "too old: a replay");
        assert!(!ok("1700000001", b"{}", 1_700_000_000), "another time");
        assert!(!ok("1700000000", b"{ }", 1_700_000_000), "another body");
        assert!(!ok("+1700000000", b"{}", 1_700_000_000));
        assert!(!ok("", b"{}", 1_700_000_000));
        // The untimestamped form of the same body does not pass.
        assert!(!verify_timestamped(
            b"k",
            "1700000000",
            b"{}",
            &sign_body(b"k", b"{}"),
            1_700_000_000,
            300
        ));
    }
}
