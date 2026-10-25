//! HTML bodies and their character references: hidden text kept apart,
//! linear time, never a panic.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_mail::html::{html_to_text, style_hides, unescape, unescape_attr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (visible, hidden) = html_to_text(text);
    // Text only shrinks, except for references that expand (at most a few
    // characters each) and `[image: ...]` markers.
    assert!(visible.len() <= text.len().saturating_mul(8).saturating_add(16));
    assert!(hidden.len() <= text.len().saturating_mul(8).saturating_add(16));
    let _ = style_hides(text);
    let _ = unescape(text);
    let _ = unescape_attr(text);
});
