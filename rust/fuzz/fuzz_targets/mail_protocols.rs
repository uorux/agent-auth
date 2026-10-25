//! What IMAP and SMTP servers answer: responses with literals, SEARCH and
//! FETCH answers, SMTP replies; and dot-stuffing of what is sent.
#![no_main]
#![forbid(unsafe_code)]

use agent_auth_mail::{imap, smtp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for r in imap::responses(data) {
        let _ = imap::fetch_body(&r);
        if let imap::Kind::Untagged(rest) = imap::classify(r.head()) {
            let _ = imap::uidvalidity(rest);
            if let Some(uids) = imap::search_uids(rest) {
                assert!(uids.len() <= imap::MAX_UIDS);
            }
        }
    }
    for r in smtp::replies(data) {
        assert!((200..600).contains(&r.code));
        assert!(r.lines.len() <= smtp::MAX_REPLY_LINES);
    }
    let block = smtp::data_block(data);
    assert!(block.ends_with(b".\r\n"));
});
