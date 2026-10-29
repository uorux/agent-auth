//! The small text parsers fed from the wire or from files: public keys,
//! private key text, nonces, daemon names, TOTP secrets, PEM, webhook
//! signature headers.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_crypto::daemon::{DaemonName, Nonce, PublicKey, Role, SigningKey};
use agent_auth_crypto::totp::{self, TotpSecret};
use agent_auth_crypto::{b64url_decode, pem, webhook};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(k) = PublicKey::parse(text) {
        assert_eq!(PublicKey::parse(&k.to_text()), Ok(k));
        assert_eq!(k.fingerprint().len(), 39);
    }
    if let Ok(k) = SigningKey::from_text(text) {
        let again = SigningKey::from_text(k.to_text().expose()).map(|k| k.public_key());
        assert_eq!(again, Ok(k.public_key()));
    }
    if let Some(n) = Nonce::parse(text) {
        assert_eq!(n.as_str(), text);
        assert_eq!(b64url_decode(text).map(|b| b.len()), Some(32));
    }
    if let Some(n) = DaemonName::parse(text) {
        assert_eq!(n.as_str(), text);
        assert!(text.len() <= 63);
    }
    let _ = Role::parse(text);
    if let Ok(s) = TotpSecret::from_base32(text) {
        let _ = totp::verify(&s, text, 1_761_400_000, None);
    }
    if let Ok(p) = pem::parse(text) {
        assert!(!p.label.is_empty() || text.contains("-----BEGIN -----"));
    }
    assert!(!webhook::verify_body(b"k", b"body", text));
});
