//! SecretBox on untrusted ciphertexts (a tampered database).
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_crypto::secretbox::{Binding, SecretBox};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(sb) = SecretBox::from_bytes(&[7; 32]) else {
        return;
    };
    let binding = Binding::new("credentials", "value_encrypted", "row-1");
    if let Ok(text) = std::str::from_utf8(data) {
        // Forging a ciphertext without the key is not something a fuzzer
        // finds: anything it makes must be refused.
        assert!(sb.open(text, &binding).is_err());
        let _ = SecretBox::from_base64(text);
    }
    // And whatever it seals opens, only under the same binding.
    let Ok(sealed) = sb.seal(data, &binding) else {
        return;
    };
    let opened = sb.open(&sealed, &binding).ok();
    assert_eq!(opened.as_ref().map(|s| s.expose().as_slice()), Some(data));
    assert!(
        sb.open(
            &sealed,
            &Binding::new("credentials", "value_encrypted", "row-2")
        )
        .is_err()
    );
});
