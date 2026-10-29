//! Broker token verification on untrusted bearer tokens.
#![no_main]
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use agent_auth_crypto::daemon::SigningKey;
use agent_auth_crypto::jwt::TokenIssuer;
use libfuzzer_sys::fuzz_target;

fn issuer() -> Option<&'static TokenIssuer> {
    static I: OnceLock<Option<TokenIssuer>> = OnceLock::new();
    I.get_or_init(|| {
        let key = SigningKey::from_seed(&[9; 32]).ok()?;
        TokenIssuer::new(&key, "https://broker.example").ok()
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let (Ok(text), Some(issuer)) = (std::str::from_utf8(data), issuer()) else {
        return;
    };
    // No valid signature can come out of a fuzzer.
    assert!(issuer.verify(text, "mcp:srv", 1_761_400_000.0).is_err());
});
