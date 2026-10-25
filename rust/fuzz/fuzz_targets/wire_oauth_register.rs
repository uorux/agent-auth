//! Dynamic client registration (open to anyone) from arbitrary bytes.
#![no_main]

use agent_auth_wire::oauth::{ClientRegistration, MAX_REDIRECT_URIS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = ClientRegistration::from_json(data) {
        assert!(!r.redirect_uris.is_empty() && r.redirect_uris.len() <= MAX_REDIRECT_URIS);
        assert!(r.client_name.as_ref().is_none_or(|n| n.chars().count() <= 200));
    }
});
