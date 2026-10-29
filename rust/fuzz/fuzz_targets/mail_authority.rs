//! A mail request's capability and scope (agent-chosen JSON), the address
//! checks, and rule coverage: what parses round-trips, and covers is
//! reflexive.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_core::mail::{MailAuthority, is_address, is_glob, server_term};
use agent_auth_core::{Authority, Platform};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = (is_address(text), is_glob(text), server_term(text));
    let (cap, scope) = text.split_once('\n').unwrap_or(("read", text));
    let Ok(serde_json::Value::Object(scope)) = serde_json::from_str(scope) else {
        return;
    };
    if let Ok(m) = MailAuthority::from_wire(cap, &scope) {
        assert!(m.covers(&m));
        let a = Authority::Mail(m);
        assert_eq!(Authority::from_json(Platform::Mail, &a.to_json()), Ok(a.clone()));
        assert_eq!(Authority::from_wire(Platform::Mail, &a.capability(), &a.scope()), Ok(a));
    }
});
