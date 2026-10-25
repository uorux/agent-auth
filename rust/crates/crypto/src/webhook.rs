//! The signature on outbound webhooks (a2a pings, `a2a serve` dispatch).
//!
//! `X-Agent-Auth-Signature: sha256=<lowercase hex HMAC-SHA256(key = the
//! secret's UTF-8 bytes, message = the exact body bytes sent)>`. The same
//! value may also be sent as `X-Hub-Signature-256`.

use ring::hmac;

/// The header carrying the signature.
pub const SIGNATURE_HEADER: &str = "X-Agent-Auth-Signature";
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
}
