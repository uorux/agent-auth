//! The small parsers behind the bodies and query strings: timestamps,
//! durations, validated strings, JSON measures, Python repr.
#![no_main]

use agent_auth_wire::duration::DurationSecs;
use agent_auth_wire::text::{DaemonName, Topic, WebhookUrl};
use agent_auth_wire::{json, pyrepr, query, timestamp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for t in [timestamp::parse(text), timestamp::parse_query(text)].into_iter().flatten() {
        // Whatever parses formats, and the format is a fixed point.
        if let Ok(out) = timestamp::format(t) {
            assert_eq!(timestamp::parse(&out), Ok(t));
        }
    }
    if let Ok(d) = DurationSecs::parse(text) {
        assert!(d.get() >= 1 && d.get() <= agent_auth_wire::duration::MAX_DURATION_SECS);
    }
    let r = pyrepr::repr(text);
    assert!(r.len() >= 2);
    let _ = WebhookUrl::new(text);
    let _ = Topic::new(text);
    let _ = DaemonName::new(text);
    let _ = query::GrantFilter::parse(text);
    let _ = query::decision_source(text);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        let _ = json::depth(&v);
        let _ = json::compact_len(&v);
    }
});
