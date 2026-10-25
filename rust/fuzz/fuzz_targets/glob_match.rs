//! Glob compile and match on arbitrary patterns and texts (split at the
//! first NUL): never panics, `*` matches everything, a literal pattern
//! matches exactly itself.
#![no_main]

use agent_auth_core::glob::{Glob, fnmatch};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (pattern, subject) = text.split_once('\0').unwrap_or((text, ""));
    let glob = Glob::new(pattern);
    let matched = glob.matches(subject);
    assert_eq!(matched, fnmatch(subject, pattern));
    assert!(fnmatch(subject, "*"));
    if glob.is_literal() {
        assert_eq!(matched, pattern == subject);
    }
    let alphabet: Vec<char> = "ab-".chars().collect();
    if glob.matches_every_nonempty_over(&alphabet) {
        for word in ["a", "b", "-", "ab", "ba-", "--"] {
            assert!(glob.matches(word), "{pattern:?} {word:?}");
        }
    }
});
