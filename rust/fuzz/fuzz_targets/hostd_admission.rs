//! What hostd parses from the broker and its own state files: a raw job
//! spec through `normalize` (never panics; what it admits re-normalizes to
//! the same), TOTP state files (a state that reads writes back the same),
//! and the approval display (`fit` never exceeds its limit).
#![no_main]

use agent_auth_core::hostd::display::{display_argv, fit};
use agent_auth_core::hostd::totp::TotpState;
use agent_auth_core::hostd::{HostPolicy, normalize};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(data) else {
        if let Ok(text) = std::str::from_utf8(data) {
            let shown = fit(&display_argv(&[text]), 600, &"ab".repeat(32));
            assert!(shown.chars().count() <= 600);
        }
        return;
    };
    if let Some(state) = TotpState::from_json(&raw) {
        assert_eq!(TotpState::from_json(&state.to_json()), Some(state));
    }
    let mut policy = HostPolicy::connect_only("h");
    policy.user.enable = true;
    policy.root.enable = true;
    policy.deny_commands = vec![vec!["rm".into(), "**".into()]];
    if let Ok(n) = normalize(&policy, &raw, false) {
        let again = normalize(&policy, &n.spec().to_json(), false).expect("re-normalizes");
        assert_eq!(again.argv(), n.argv());
    }
});
