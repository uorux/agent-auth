//! A message as an outsider writes it: MIME, headers, charsets, HTML
//! bodies, attachments. Never panics; what comes out is bounded.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_mail::message::{attachment_bytes, hint_level, injection_hints, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let m = parse(data);
    assert!(m.subject.chars().count() <= 500);
    assert!(m.from_name.chars().count() <= 200);
    assert!(m.hidden_text.chars().count() <= 4000);
    assert!(m.references.len() <= 64 && m.in_reply_to.len() <= 64);
    for id in m.references.iter().chain(&m.in_reply_to).chain(&m.message_id) {
        assert!(id.starts_with('<') && id.ends_with('>'));
        assert!(!id.contains(['\r', '\n', ' ']));
    }
    let _ = hint_level(&injection_hints(&m));
    let _ = m.thread_root();
    for a in &m.attachments {
        assert!(a.filename.chars().count() <= 200);
        let got = attachment_bytes(data, a.index);
        assert_eq!(got.map(|(meta, bytes)| (meta.size, bytes.len())), Some((a.size, a.size)));
    }
});
