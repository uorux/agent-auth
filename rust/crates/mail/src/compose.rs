//! What the gateway sends: one plain-text message (`gateway._deliver`,
//! which used `EmailMessage` with the SMTP policy). Every header value
//! here was checked by the gateway (addresses, a one-line subject,
//! `<msg-id>` tokens); this module encodes, it does not judge.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use time::OffsetDateTime;
use time::macros::format_description;

use crate::message::msg_ids;

/// What to send.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    pub from: &'a str,
    pub to: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
    /// The message answered (`<msg-id>`), if any.
    pub in_reply_to: Option<&'a str>,
    pub references: &'a [String],
    /// A unique token for the Message-ID's left part.
    pub unique: &'a str,
    pub date: OffsetDateTime,
}

/// RFC 2047 encoded words for a non-ASCII header value (B encoding, each
/// word at most 75 characters, folded).
fn encode_header(value: &str) -> String {
    if value.is_ascii() && value.len() <= 900 && !value.contains("=?") {
        return value.to_owned();
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in value.chars() {
        // 45 bytes of UTF-8 encode to 60 characters: the word stays < 76.
        if chunk.len().saturating_add(c.len_utf8()) > 45 {
            words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

/// The RFC 5322 date (`formatdate(localtime=False)`: `-0000`).
#[must_use]
pub fn rfc2822(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let fmt = format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] -0000"
    );
    t.format(fmt).unwrap_or_default()
}

/// The message, CRLF line endings.
#[must_use]
pub fn compose(d: &Draft<'_>) -> Vec<u8> {
    let domain = d.from.rsplit('@').next().unwrap_or("localhost");
    let mut h = String::new();
    h.push_str(&format!("From: {}\r\n", d.from));
    h.push_str(&format!("To: {}\r\n", d.to.join(", ")));
    h.push_str(&format!("Subject: {}\r\n", encode_header(d.subject)));
    h.push_str(&format!("Date: {}\r\n", rfc2822(d.date)));
    h.push_str(&format!("Message-ID: <{}@{domain}>\r\n", d.unique));
    // Only `<msg-id>` tokens, whatever was stored.
    if let Some(answered) = d.in_reply_to.and_then(|r| msg_ids(r).into_iter().next()) {
        let mut refs: Vec<String> = d.references.iter().flat_map(|r| msg_ids(r)).collect();
        refs.push(answered.clone());
        let skip = refs.len().saturating_sub(20);
        let refs: Vec<String> = refs.into_iter().skip(skip).collect();
        h.push_str(&format!("In-Reply-To: {answered}\r\n"));
        h.push_str(&format!("References: {}\r\n", refs.join("\r\n ")));
    }
    h.push_str("MIME-Version: 1.0\r\n");
    let body = d.body.replace("\r\n", "\n").replace('\r', "\n");
    let plain = body.is_ascii() && body.lines().all(|l| l.len() <= 998);
    let mut out = h.into_bytes();
    if plain {
        out.extend_from_slice(
            b"Content-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n",
        );
        out.extend_from_slice(body.replace('\n', "\r\n").as_bytes());
        if !body.ends_with('\n') {
            out.extend_from_slice(b"\r\n");
        }
    } else {
        out.extend_from_slice(
            b"Content-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        );
        let encoded = STANDARD.encode(body.as_bytes());
        for line in encoded.as_bytes().chunks(76) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::message::parse;

    #[test]
    fn round_trips_through_the_parser() {
        let to = vec!["ra+11@simplelogin.example".to_owned()];
        let refs = vec!["<r1@x>".to_owned()];
        let d = Draft {
            from: "me@mail.example",
            to: &to,
            subject: "Re: Your flight to Perth — änderung",
            body: "Please move me.\nThanks ✈",
            in_reply_to: Some("<orig@qantas.example>"),
            references: &refs,
            unique: "u1",
            date: OffsetDateTime::from_unix_timestamp(1_792_836_000).unwrap(),
        };
        let raw = compose(&d);
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("In-Reply-To: <orig@qantas.example>\r\n"));
        assert!(text.contains("Date: Sat, 24 Oct 2026 10:00:00 -0000\r\n"));
        let m = parse(&raw);
        assert_eq!(m.subject, "Re: Your flight to Perth — änderung");
        assert_eq!(m.text, "Please move me.\nThanks ✈");
        assert_eq!(m.to, to);
        assert_eq!(m.references, vec!["<r1@x>", "<orig@qantas.example>"]);
        assert_eq!(m.message_id.as_deref(), Some("<u1@mail.example>"));
    }

    #[test]
    fn hostile_reply_ids_are_dropped() {
        let to = vec!["a@b.example".to_owned()];
        let refs = vec!["x\r\nBcc: v@evil".to_owned()];
        let d = Draft {
            from: "me@mail.example",
            to: &to,
            subject: "Re: x",
            body: "thanks",
            in_reply_to: Some("<a@b>\r\nBcc: v@evil"),
            references: &refs,
            unique: "u",
            date: OffsetDateTime::UNIX_EPOCH,
        };
        let raw = String::from_utf8(compose(&d)).unwrap();
        assert!(!raw.contains("Bcc") && !raw.contains("evil"));
        assert!(raw.contains("In-Reply-To: <a@b>\r\n"));
    }
}
