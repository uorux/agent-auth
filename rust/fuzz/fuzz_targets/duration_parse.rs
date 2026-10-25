//! Durations and validated names on arbitrary text: never panics, and
//! whatever parses is in range and formats back to the same value.
#![no_main]

use agent_auth_core::durations::{
    DurationSecs, MAX_DURATION_SECS, format_duration, host_duration_secs,
};
use agent_auth_core::names::{
    AgentName, AttrValue, DaemonName, EnvKey, SandboxProject, TemplateName,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(d) = DurationSecs::parse(text) {
        assert!(d.get() >= 1 && d.get() <= MAX_DURATION_SECS);
        let again =
            DurationSecs::parse(&format_duration(u64::from(d.get()))).expect("formats back");
        assert_eq!(again, d);
    }
    let _ = host_duration_secs(text);
    let _ = serde_json::from_str::<DurationSecs>(text);
    for ok in [
        AgentName::parse(text).is_ok(),
        AttrValue::parse(text).is_ok(),
        DaemonName::parse(text).is_ok(),
        EnvKey::parse(text).is_ok(),
        SandboxProject::parse(text).is_ok(),
        TemplateName::parse(text).is_ok(),
    ] {
        if ok {
            assert!(text.is_ascii() && !text.is_empty());
        }
    }
});
