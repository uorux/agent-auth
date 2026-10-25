//! API key parsing on untrusted bearer tokens.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_crypto::api_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(parsed) = api_key::parse(text) {
        // A parsed key is exactly its parts, in the one issued shape.
        let back = format!("aa_{}_{}", parsed.key_id, parsed.secret.expose());
        assert_eq!(back, text);
        assert_eq!(text.len(), 59);
        assert!(api_key::KeyId::parse(parsed.key_id.as_str()).is_some());
        let hash = api_key::hash_secret(parsed.secret.expose());
        assert!(api_key::verify(&parsed.secret, &hash));
    }
});
