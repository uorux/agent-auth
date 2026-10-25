//! One email, parsed into what the gateway filters on and what an agent is
//! shown (`message.py` `parse`): addresses, subject, date, a plain-text body
//! with hidden text taken out, attachments by name, plus the cheap checks
//! for prompt injection that run before (and alongside) the judge.
//!
//! Nothing here is trusted: the headers SimpleLogin adds can be forged by
//! anyone who mails the mailbox directly, which only ever adds an
//! outsider's message to what an agent sees.

use std::sync::OnceLock;

use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders, PartType};
use regex::Regex;
use time::OffsetDateTime;

use crate::html::{html_to_text, never};
use crate::text::{chars, clean};

/// The largest message read (`MAX_RAW_BYTES`); the rest is cut off.
pub const MAX_RAW_BYTES: usize = 25 * 1024 * 1024;
/// Most message ids kept from References/In-Reply-To.
pub const MAX_REFERENCES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub index: usize,
    pub filename: String,
    pub content_type: String,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessage {
    /// The first `<msg-id>` token of Message-ID, if any.
    pub message_id: Option<String>,
    /// `<msg-id>` tokens of In-Reply-To.
    pub in_reply_to: Vec<String>,
    /// `<msg-id>` tokens of References.
    pub references: Vec<String>,
    pub date: Option<OffsetDateTime>,
    pub subject: String,
    pub from_addr: String,
    pub from_name: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub reply_to: Vec<String>,
    pub text: String,
    pub attachments: Vec<Attachment>,
    /// SimpleLogin: the alias it was sent to. Empty when not a forward.
    pub sl_envelope_to: Vec<String>,
    /// SimpleLogin: the sender before the From was rewritten.
    pub sl_original_from: Option<String>,
    /// The topmost Authentication-Results (the one the mailbox's own
    /// provider added; each hop prepends), parsed. Trusted only when its
    /// authserv-id is the provider's ([`ParsedMessage::verified`]).
    pub auth: Option<AuthResults>,
    pub hidden_text: String,
    pub hints: Vec<String>,
    pub raw_size: usize,
}

impl ParsedMessage {
    /// The thread a message belongs to: the first reference, else what it
    /// answers, else itself.
    #[must_use]
    pub fn thread_root(&self) -> Option<&str> {
        self.references
            .first()
            .or_else(|| self.in_reply_to.first())
            .or(self.message_id.as_ref())
            .map(String::as_str)
    }

    /// Whom it is really from: SimpleLogin's original sender if it was a
    /// forward, the From address otherwise. (The gateway trusts the
    /// SimpleLogin header only on an alias.)
    #[must_use]
    pub fn sender(&self) -> &str {
        self.sl_original_from.as_deref().unwrap_or(&self.from_addr)
    }
}

fn parser() -> MessageParser {
    MessageParser::new()
        .with_mime_headers()
        .with_date_headers()
        .with_address_headers()
        .header_text("Subject")
        .header_text("X-SimpleLogin-Type")
        .header_address("X-SimpleLogin-Envelope-To")
        .header_address("X-SimpleLogin-Original-From")
        .header_raw("Message-ID")
        .header_raw("In-Reply-To")
        .header_raw("References")
        .header_raw("Authentication-Results")
}

/// Drop a parsed message without recursing into the messages nested in
/// it. mail-parser parses `message/rfc822` parts iteratively, without a
/// depth limit, but its types drop recursively: a 2 MB message of nested
/// `message/rfc822` headers is 60,000 levels deep, and dropping it
/// overflowed the stack, which aborts the whole broker (not a panic: it
/// cannot be caught), on every list until the message is gone.
fn dismantle(msg: mail_parser::Message<'_>) {
    let mut todo = vec![msg];
    while let Some(mut m) = todo.pop() {
        for part in &mut m.parts {
            if matches!(part.body, PartType::Message(_))
                && let PartType::Message(inner) = std::mem::take(&mut part.body)
            {
                todo.push(inner);
            }
        }
        // `m` has no nested message left: it drops flat.
    }
}

/// `<msg-id>` tokens (`_msg_ids`): a decoded or hostile header can hold
/// anything (a newline would break a reply), so only these are kept.
#[must_use]
pub fn msg_ids(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"<[^<>\s]{1,250}>").unwrap_or_else(|_| never()));
    re.find_iter(text)
        .take(MAX_REFERENCES)
        .map(|m| m.as_str().to_owned())
        .collect()
}

fn addresses<'a>(values: impl Iterator<Item = &'a Address<'a>>) -> Vec<String> {
    let mut out = Vec::new();
    for a in values {
        for addr in a.iter() {
            if let Some(email) = addr.address()
                && email.contains('@')
                && out.len() < 1000
            {
                out.push(clean(email).to_lowercase());
            }
        }
    }
    out
}

fn header_values<'a>(
    msg: &'a mail_parser::Message<'a>,
    name: &'a str,
) -> impl Iterator<Item = &'a HeaderValue<'a>> {
    msg.header_values(name)
}

fn header_addresses<'a>(msg: &'a mail_parser::Message<'a>, name: &'a str) -> Vec<String> {
    addresses(header_values(msg, name).filter_map(HeaderValue::as_address))
}

fn first_text(msg: &mail_parser::Message<'_>, name: &str) -> String {
    match msg.header_values(name).next() {
        Some(HeaderValue::Text(t)) => clean(t),
        Some(HeaderValue::TextList(l)) => clean(&l.join(", ")),
        _ => String::new(),
    }
}

fn first_raw(msg: &mail_parser::Message<'_>, name: &str) -> String {
    msg.header_values(name)
        .next()
        .and_then(|v| match v {
            HeaderValue::Text(t) => Some(t.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

fn to_datetime(d: &mail_parser::DateTime) -> Option<OffsetDateTime> {
    let month = time::Month::try_from(d.month).ok()?;
    let date = time::Date::from_calendar_date(i32::from(d.year), month, d.day).ok()?;
    let t = time::Time::from_hms(d.hour, d.minute, d.second).ok()?;
    let secs = i32::from(d.tz_hour)
        .checked_mul(3600)?
        .checked_add(i32::from(d.tz_minute).checked_mul(60)?)?;
    let secs = if d.tz_before_gmt {
        secs.checked_neg()?
    } else {
        secs
    };
    let offset = time::UtcOffset::from_whole_seconds(secs).ok()?;
    Some(
        time::PrimitiveDateTime::new(date, t)
            .assume_offset(offset)
            .to_offset(time::UtcOffset::UTC),
    )
}

/// One result of an Authentication-Results header (RFC 8601): a method,
/// its result, and its properties (`header.from`, `header.d`...), all
/// lowercased, comments removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub method: String,
    pub result: String,
    pub props: Vec<(String, String)>,
}

impl AuthResult {
    #[must_use]
    pub fn prop(&self, name: &str) -> Option<&str> {
        self.props
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed Authentication-Results header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResults {
    /// Who wrote it (`mx.google.com`), lowercased.
    pub authserv_id: String,
    pub results: Vec<AuthResult>,
}

/// The most results read from one header.
const MAX_AUTH_RESULTS: usize = 64;

/// Comments (nested, with quoted strings and escapes respected) removed.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for c in text.chars() {
        if escaped {
            escaped = false;
            if depth == 0 {
                out.push(c);
            }
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                if depth == 0 {
                    out.push(c);
                }
            }
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => depth = depth.saturating_add(1),
            ')' if !quoted && depth > 0 => {
                depth = depth.saturating_sub(1);
                out.push(' ');
            }
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Split on `sep` outside quoted strings.
fn split_unquoted(text: &str, sep: fn(char) -> bool) -> Vec<String> {
    let mut parts = vec![String::new()];
    let (mut quoted, mut escaped) = (false, false);
    for c in text.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && sep(c) {
            parts.push(String::new());
            continue;
        }
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
}

fn unquote(v: &str) -> String {
    v.trim_matches('"').to_lowercase()
}

/// Parse an Authentication-Results value: `authserv-id [version];
/// method=result [reason=...] [ptype.prop=value ...]; ...`.
#[must_use]
pub fn parse_auth_results(value: &str) -> Option<AuthResults> {
    let text = strip_comments(value);
    let mut parts = split_unquoted(&text, |c| c == ';').into_iter();
    let authserv_id = parts.next()?.split_whitespace().next()?.to_lowercase();
    let mut results = Vec::new();
    for part in parts.take(MAX_AUTH_RESULTS) {
        let mut tokens = split_unquoted(part.trim(), char::is_whitespace)
            .into_iter()
            .filter(|t| !t.is_empty());
        let Some((method, result)) = tokens.next().and_then(|t| {
            let (m, r) = t.split_once('=')?;
            Some((m.trim().to_lowercase(), unquote(r.trim())))
        }) else {
            continue;
        };
        let method = method.split('/').next().unwrap_or("").to_owned();
        let props = tokens
            .take(32)
            .filter_map(|t| {
                let (k, v) = t.split_once('=')?;
                Some((k.trim().to_lowercase(), unquote(v.trim())))
            })
            .collect();
        results.push(AuthResult {
            method,
            result,
            props,
        });
    }
    Some(AuthResults {
        authserv_id,
        results,
    })
}

/// The domain a DKIM result is for (`header.d`, else `header.i`'s).
fn dkim_domain(r: &AuthResult) -> Option<&str> {
    r.prop("header.d").or_else(|| {
        r.prop("header.i")
            .map(|i| i.rsplit('@').next().unwrap_or(i))
    })
}

fn same_or_parent(domain: &str, signer: &str) -> bool {
    !signer.is_empty() && (domain == signer || domain.ends_with(&format!(".{signer}")))
}

impl AuthResults {
    /// Was it written by `authserv` (the mailbox provider's own id)?
    #[must_use]
    pub fn by(&self, authserv: &str) -> bool {
        !authserv.is_empty() && self.authserv_id.eq_ignore_ascii_case(authserv)
    }

    /// `_authenticated`, as results rather than text: `dmarc=pass` with
    /// `header.from` the domain, or `dkim=pass` signed by it (or a parent);
    /// false on a DMARC, DKIM or SPF failure; None otherwise.
    #[must_use]
    pub fn verdict(&self, domain: &str) -> Option<bool> {
        let domain = domain.to_lowercase();
        if self.results.iter().any(|r| {
            r.method == "dmarc"
                && r.result == "pass"
                && r.prop("header.from") == Some(domain.as_str())
        }) {
            return Some(true);
        }
        if self.results.iter().any(|r| {
            r.method == "dkim"
                && r.result == "pass"
                && dkim_domain(r).is_some_and(|d| same_or_parent(&domain, d))
        }) {
            return Some(true);
        }
        let failed = self.results.iter().any(|r| {
            matches!(
                (r.method.as_str(), r.result.as_str()),
                ("dmarc", "fail" | "none") | ("dkim", "fail") | ("spf", "fail")
            )
        });
        failed.then_some(false)
    }

    /// A DKIM pass signed by one of `domains` (or a subdomain of one).
    #[must_use]
    pub fn dkim_pass_by(&self, domains: &[String]) -> bool {
        self.results.iter().any(|r| {
            r.method == "dkim"
                && r.result == "pass"
                && dkim_domain(r).is_some_and(|d| domains.iter().any(|x| same_or_parent(d, x)))
        })
    }
}

impl ParsedMessage {
    /// Did the mailbox's own provider (authserv-id `authserv`) see DMARC or
    /// DKIM pass for `domain`? None when it said nothing (or the header is
    /// not the provider's: anyone can write one).
    #[must_use]
    pub fn verified(&self, authserv: &str, domain: &str) -> Option<bool> {
        self.auth
            .as_ref()
            .filter(|a| a.by(authserv))
            .and_then(|a| a.verdict(domain))
    }
}

/// `authenticated` for a raw header and From (tests, fuzzing): the verdict
/// whoever wrote the header.
#[must_use]
pub fn authenticated(top: Option<&str>, from_addr: &str) -> Option<bool> {
    let auth = parse_auth_results(top?)?;
    auth.verdict(from_addr.rsplit('@').next().unwrap_or(""))
}

/// A MIME type in `type/subtype` token syntax (RFC 2045), lowercased;
/// anything else is `application/octet-stream`.
#[must_use]
pub fn safe_content_type(ct: &str) -> String {
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    match ct.split_once('/') {
        Some((t, sub)) if token(t) && token(sub) => ct.to_ascii_lowercase(),
        _ => "application/octet-stream".to_owned(),
    }
}

fn part_type(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_lowercase(),
            None => ct.ctype().to_lowercase(),
        },
        None => "text/plain".to_owned(),
    }
}

fn attachment_meta(i: usize, part: &mail_parser::MessagePart<'_>) -> Attachment {
    let name = part
        .attachment_name()
        .map(clean)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("attachment-{i}"));
    Attachment {
        index: i,
        filename: chars(&name, 200),
        content_type: safe_content_type(&part_type(part)),
        size: part.len(),
    }
}

fn body_text(part: &mail_parser::MessagePart<'_>) -> Option<String> {
    match &part.body {
        PartType::Text(t) | PartType::Html(t) => Some(t.to_string()),
        PartType::Binary(b) | PartType::InlineBinary(b) => {
            Some(String::from_utf8_lossy(b).into_owned())
        }
        _ => None,
    }
}

/// Parse one RFC 5322 message. Never fails: what can't be read comes out
/// empty.
#[must_use]
pub fn parse(raw: &[u8]) -> ParsedMessage {
    let raw = raw.get(..MAX_RAW_BYTES).unwrap_or(raw);
    let mut out = ParsedMessage {
        message_id: None,
        in_reply_to: Vec::new(),
        references: Vec::new(),
        date: None,
        subject: String::new(),
        from_addr: String::new(),
        from_name: String::new(),
        to: Vec::new(),
        cc: Vec::new(),
        reply_to: Vec::new(),
        text: String::new(),
        attachments: Vec::new(),
        sl_envelope_to: Vec::new(),
        sl_original_from: None,
        auth: None,
        hidden_text: String::new(),
        hints: Vec::new(),
        raw_size: raw.len(),
    };
    let Some(msg) = parser().parse(raw) else {
        return out;
    };
    out.message_id = msg_ids(&first_raw(&msg, "Message-ID")).into_iter().next();
    out.in_reply_to = msg_ids(&first_raw(&msg, "In-Reply-To"));
    out.references = msg_ids(&first_raw(&msg, "References"));
    // The FIRST From, Subject and Date (as Python's `msg.get`); mail-parser
    // reads the last.
    out.date = msg
        .header_values("Date")
        .next()
        .and_then(HeaderValue::as_datetime)
        .and_then(to_datetime);
    out.subject = chars(&clean(&first_text(&msg, "Subject")), 500);
    if let Some(first) = msg
        .header_values("From")
        .next()
        .and_then(HeaderValue::as_address)
        .and_then(|a| a.first())
    {
        out.from_addr = first
            .address()
            .map(|a| clean(a).to_lowercase())
            .unwrap_or_default();
        out.from_name = chars(&clean(first.name().unwrap_or("")), 200);
    }
    out.to = addresses(msg.header_values("To").filter_map(HeaderValue::as_address));
    out.cc = addresses(msg.header_values("Cc").filter_map(HeaderValue::as_address));
    out.reply_to = addresses(
        msg.header_values("Reply-To")
            .filter_map(HeaderValue::as_address),
    );
    out.sl_envelope_to = header_addresses(&msg, "X-SimpleLogin-Envelope-To");
    let forwarded = first_text(&msg, "X-SimpleLogin-Type").to_lowercase() == "forward"
        || !out.sl_envelope_to.is_empty()
        || msg
            .header_values("X-SimpleLogin-Envelope-To")
            .next()
            .is_some();
    if forwarded {
        out.sl_original_from = header_addresses(&msg, "X-SimpleLogin-Original-From")
            .into_iter()
            .next();
    }
    let auth = msg
        .header_values("Authentication-Results")
        .next()
        .and_then(|v| match v {
            HeaderValue::Text(t) => Some(t.to_string()),
            _ => None,
        });
    out.auth = auth.as_deref().and_then(parse_auth_results);

    let plain = msg
        .text_bodies()
        .find(|p| matches!(p.body, PartType::Text(_)) && part_type(p) == "text/plain");
    let html = msg
        .html_bodies()
        .find(|p| matches!(p.body, PartType::Html(_)));
    let (html_text, hidden) = html
        .and_then(body_text)
        .map(|h| html_to_text(&h))
        .unwrap_or_default();
    out.text = match plain.and_then(body_text) {
        Some(p) => clean(&p),
        None => html_text,
    };
    out.attachments = msg
        .attachments()
        .enumerate()
        .map(|(i, p)| attachment_meta(i, p))
        .collect();
    out.hidden_text = chars(&hidden, 4000);
    dismantle(msg);
    out.hints = injection_hints(&out);
    out
}

/// Attachment `index`, with its bytes.
#[must_use]
pub fn attachment_bytes(raw: &[u8], index: usize) -> Option<(Attachment, Vec<u8>)> {
    let raw = raw.get(..MAX_RAW_BYTES).unwrap_or(raw);
    let msg = parser().parse(raw)?;
    let found = msg
        .attachments()
        .nth(index)
        .map(|part| (attachment_meta(index, part), part.contents().to_vec()));
    dismantle(msg);
    found
}

// ---------------------------------------------------------------- hints

/// Phrases aimed at a model rather than a person. One is a hint; the judge
/// decides. Ordinary mail almost never says these.
const INJECTION_PATTERNS: [&str; 11] = [
    r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b[^.\n]{0,20}\b(?:instructions?|prompts?|rules|directives)",
    r"\b(?:you are|you're|act as)\b[^.\n]{0,20}\b(?:an?|the)\s+(?:ai|assistant|agent|language model|llm|chatbot)\b",
    r"\b(?:as an? (?:ai|assistant|language model))\b",
    r"\bsystem\s*prompt\b",
    r"<\s*/?\s*(?:system|assistant|instructions?|tool_call|im_start|im_end)\b",
    r"\[\s*/?\s*(?:INST|SYS)\s*\]",
    r"\b(?:new|updated|important)\s+instructions?\s*(?:for|to)\s+(?:the\s+)?(?:ai|assistant|agent|model)",
    r"\b(?:do not|don't|never)\s+(?:tell|inform|mention (?:this )?to)\s+(?:the\s+)?(?:user|human|owner|operator)",
    r"\b(?:request_access|get_credential|host_run|a2a_send|mail_send|wiki_write|notify_operator)\b",
    r"\bagent-auth\b",
    r"\b(?:api[_ -]?key|access token|password|credentials?)\b[^.\n]{0,40}\b(?:send|forward|reply|email|paste)\b[^.\n]{0,20}\b(?:to|back)\b",
];

fn patterns() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        INJECTION_PATTERNS
            .iter()
            .map(|p| Regex::new(&format!("(?i){p}")).unwrap_or_else(|_| never()))
            .collect()
    })
}

fn first_hit(text: &str) -> Option<String> {
    patterns()
        .iter()
        .find_map(|p| p.find(text))
        .map(|m| agent_auth_core::pyfmt::repr(&chars(m.as_str(), 80)))
}

/// What looks aimed at a model: phrases in what an agent would read, and
/// instructions in text hidden from a person. Hints for the judge (and the
/// operator), not a verdict: hidden preheaders are ordinary in newsletters.
#[must_use]
pub fn injection_hints(m: &ParsedMessage) -> Vec<String> {
    let mut hints = Vec::new();
    for (place, text) in [("body", &m.text), ("subject", &m.subject)] {
        if let Some(hit) = first_hit(text) {
            hints.push(format!("{place} says {hit}"));
        }
    }
    if !m.hidden_text.is_empty()
        && let Some(hit) = first_hit(&m.hidden_text)
    {
        hints.push(format!("hidden text says {hit}"));
    }
    // Attachment names reach the agent too.
    if let Some(hit) = m.attachments.iter().find_map(|a| first_hit(&a.filename)) {
        hints.push(format!("an attachment name says {hit}"));
    }
    hints
}

/// The injection level the hints alone suggest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    Suspected,
    Likely,
}

impl Level {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Suspected => "suspected",
            Level::Likely => "likely",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "none" => Some(Level::None),
            "suspected" => Some(Level::Suspected),
            "likely" => Some(Level::Likely),
            _ => None,
        }
    }
}

/// `hint_level`: instructions hidden from a person, or several kinds at
/// once, are likely; one is suspected.
#[must_use]
pub fn hint_level(hints: &[String]) -> Level {
    if hints.is_empty() {
        Level::None
    } else if hints.iter().any(|h| h.starts_with("hidden text")) || hints.len() >= 2 {
        Level::Likely
    } else {
        Level::Suspected
    }
}

#[cfg(test)]
mod tests;
