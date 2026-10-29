//! Host job specs from arbitrary JSON (what hostd receives), and template
//! parameter patterns and expansion: never panics; a spec that parses is a
//! fixed point of to_json/from_json.
#![no_main]

use std::collections::BTreeMap;

use agent_auth_core::authority::Tier;
use agent_auth_core::hostexec::{JobSpec, ParamPattern, Template, match_argv};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Ok(spec) = JobSpec::from_json(&raw, 600) {
            let again = JobSpec::from_json(&spec.to_json(), 600).expect("a valid spec re-parses");
            assert_eq!(again, spec);
            let _ = spec.describe();
            if let JobSpec::Command(c) = &spec {
                if let agent_auth_core::hostexec::Command::Run { argv } = c.command() {
                    let _ = match_argv(argv, argv, true);
                }
            }
        }
        return;
    }
    // Not JSON: a pattern, a value and an argv template, NUL-separated.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.split('\0');
    let pattern = parts.next().unwrap_or("");
    let value = parts.next().unwrap_or("").to_owned();
    let argv: Vec<String> = parts.map(str::to_owned).collect();
    let Ok(p) = ParamPattern::new(pattern) else {
        return;
    };
    let _ = p.full_match(&value);
    let Ok(t) = Template::new(
        Tier::User,
        if argv.is_empty() {
            vec!["x".to_owned()]
        } else {
            argv.clone()
        },
        [("p".to_owned(), p)].into(),
        String::new(),
    ) else {
        return;
    };
    let params: BTreeMap<String, String> = [("p".to_owned(), value)].into();
    if let Ok(out) = t.expand(&params) {
        assert_eq!(out.len(), t.argv().len());
    }
});
