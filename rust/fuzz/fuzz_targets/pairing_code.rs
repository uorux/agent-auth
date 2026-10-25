//! Pairing-code normalization and key derivation on what an operator types.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_crypto::daemon::{PairingKey, normalize_pairing_code, proofs_equal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let normalized = normalize_pairing_code(text);
    assert!(normalized.chars().all(char::is_alphanumeric));
    // Normalizing is what the key sees: the same key either way.
    let a = PairingKey::from_code(text);
    let b = PairingKey::from_code(&normalized);
    assert_eq!(a.selector(), b.selector());
    assert!(a.selector_matches(&b.selector()));
    assert!(!proofs_equal(&a.selector(), text) || text == a.selector());
    if let Some(k) = PairingKey::from_hex(text) {
        assert_eq!(k.to_hex().expose(), &text.to_ascii_lowercase());
    }
});
