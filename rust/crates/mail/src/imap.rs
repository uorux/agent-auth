//! A minimal IMAP4rev1 client for what the gateway's IMAP backend does
//! (`backends.py` ImapBackend, which used imaplib): LOGIN, EXAMINE (a
//! read-only SELECT), UID SEARCH, UID FETCH of `BODY.PEEK[]`, LOGOUT. Over
//! implicit TLS only (port 993 by default), one connection per call.
//!
//! The server's answers are untrusted: lines are bounded, a literal is
//! bounded (and a message past [`crate::message::MAX_RAW_BYTES`] is cut
//! there), and the parsing functions are pure (fuzzed).

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::{ConnError, Lines, connect_tls};
use crate::message::MAX_RAW_BYTES;

/// Longest response line (a SEARCH answer lists every UID on one line).
pub const MAX_LINE: usize = 8 * 1024 * 1024;
/// Largest literal accepted (a whole message, with slack; what is past
/// `MAX_RAW_BYTES` is read and dropped).
pub const MAX_LITERAL: usize = 64 * 1024 * 1024;
/// Most UIDs read from one SEARCH.
pub const MAX_UIDS: usize = 1_000_000;
/// Most responses read for one command (untagged noise included).
pub const MAX_RESPONSES: usize = 100_000;
/// The most bytes one command's answer may make us hold (lines and kept
/// literal bytes): a whole message and a SEARCH line fit.
pub const COMMAND_BUDGET: usize = 48 * 1024 * 1024;
/// Most literals in one response (a FETCH of BODY[] has one).
pub const MAX_LITERALS_PER_RESPONSE: usize = 8;
/// How long a whole command (or the greeting and login) may take.
pub const COMMAND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// One server response: its lines, and the literal after each line that
/// announced one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub parts: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Response {
    /// The first line.
    #[must_use]
    pub fn head(&self) -> &[u8] {
        self.parts.first().map_or(&[], |(l, _)| l.as_slice())
    }
}

/// A completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    No,
    Bad,
}

/// What a response is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind<'a> {
    /// `TAG OK|NO|BAD text`.
    Tagged {
        tag: &'a [u8],
        status: Status,
    },
    /// `* ...`, without the `* `.
    Untagged(&'a [u8]),
    /// `+ ...`.
    Continuation,
    Unknown,
}

/// What a line ends with: `{n}` or `{n+}` announces a literal of `n`
/// bytes.
#[must_use]
pub fn literal_len(line: &[u8]) -> Option<usize> {
    let body = line.strip_suffix(b"}")?;
    let open = body.iter().rposition(|b| *b == b'{')?;
    let digits = body.get(open.saturating_add(1)..)?;
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || digits.len() > 12 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

#[must_use]
pub fn classify(line: &[u8]) -> Kind<'_> {
    if let Some(rest) = line.strip_prefix(b"* ") {
        return Kind::Untagged(rest);
    }
    if line == b"+" || line.starts_with(b"+ ") {
        return Kind::Continuation;
    }
    let mut words = line.splitn(3, |b| *b == b' ');
    let (Some(tag), Some(status)) = (words.next(), words.next()) else {
        return Kind::Unknown;
    };
    let status = match status.to_ascii_uppercase().as_slice() {
        b"OK" => Status::Ok,
        b"NO" => Status::No,
        b"BAD" => Status::Bad,
        _ => return Kind::Unknown,
    };
    Kind::Tagged { tag, status }
}

/// `OK [UIDVALIDITY n]` in an untagged response.
#[must_use]
pub fn uidvalidity(untagged: &[u8]) -> Option<u32> {
    let upper = untagged.to_ascii_uppercase();
    let at = find(&upper, b"[UIDVALIDITY ")?;
    let rest = untagged.get(at.saturating_add(13)..)?;
    let end = rest.iter().position(|b| !b.is_ascii_digit())?;
    std::str::from_utf8(rest.get(..end)?).ok()?.parse().ok()
}

/// The UIDs of an untagged `SEARCH n n n` (None: not a SEARCH answer).
#[must_use]
pub fn search_uids(untagged: &[u8]) -> Option<Vec<u32>> {
    let upper = untagged.get(..6)?.to_ascii_uppercase();
    if upper != b"SEARCH" {
        return None;
    }
    let rest = untagged.get(6..)?;
    if !rest.is_empty() && rest.first() != Some(&b' ') {
        return None;
    }
    let mut out = Vec::new();
    for word in rest.split(|b| *b == b' ').filter(|w| !w.is_empty()) {
        if out.len() >= MAX_UIDS {
            break;
        }
        if let Some(n) = std::str::from_utf8(word)
            .ok()
            .and_then(|w| w.parse::<u32>().ok())
        {
            out.push(n);
        }
    }
    Some(out)
}

/// The message of an untagged `n FETCH (... BODY[] {len}` + literal `)`
/// (or `BODY[] "..."`).
#[must_use]
pub fn fetch_body(r: &Response) -> Option<Vec<u8>> {
    let head = match classify(r.head()) {
        Kind::Untagged(rest) => rest,
        _ => return None,
    };
    let upper = head.to_ascii_uppercase();
    let fetch_at = find(&upper, b" FETCH ")?;
    if !head.get(..fetch_at)?.iter().all(u8::is_ascii_digit) {
        return None;
    }
    for (line, literal) in &r.parts {
        let upper = line.to_ascii_uppercase();
        let Some(at) = find(&upper, b"BODY[]") else {
            continue;
        };
        let after = line.get(at.saturating_add(6)..)?;
        let after = after.strip_prefix(b" ").unwrap_or(after);
        if let Some(lit) = literal
            && literal_len(after).is_some()
        {
            return Some(lit.clone());
        }
        if let Some(q) = after.strip_prefix(b"\"") {
            let mut out = Vec::new();
            let mut it = q.iter();
            while let Some(b) = it.next() {
                match b {
                    b'\\' => out.push(*it.next()?),
                    b'"' => return Some(out),
                    other => out.push(*other),
                }
            }
            return None;
        }
        return None;
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Responses in a byte buffer (what the client reads, without the I/O):
/// for fuzzing and tests.
#[must_use]
pub fn responses(mut data: &[u8]) -> Vec<Response> {
    let mut out = Vec::new();
    'responses: while !data.is_empty() && out.len() < MAX_RESPONSES {
        let mut r = Response::default();
        loop {
            let Some(pos) = data.iter().position(|b| *b == b'\n') else {
                break 'responses;
            };
            let mut line = data.get(..pos).unwrap_or(&[]).to_vec();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            data = data.get(pos.saturating_add(1)..).unwrap_or(&[]);
            if line.len() > MAX_LINE {
                break 'responses;
            }
            match literal_len(&line) {
                Some(n) if n <= MAX_LITERAL => {
                    let Some(lit) = data.get(..n) else {
                        break 'responses;
                    };
                    let kept = lit.get(..MAX_RAW_BYTES).unwrap_or(lit).to_vec();
                    data = data.get(n..).unwrap_or(&[]);
                    r.parts.push((line, Some(kept)));
                }
                Some(_) => break 'responses,
                None => {
                    r.parts.push((line, None));
                    out.push(r);
                    break;
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------- commands

/// An IMAP string argument: quoted when that is safe, else a literal.
#[must_use]
pub fn quotable(s: &str) -> bool {
    s.len() <= 1024 && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// `_quote`: a quoted string.
#[must_use]
/// `None` for a string holding CR, LF or NUL: never sent, quoted or not
/// (defence in depth: callers check their values too).
pub fn quote(s: &str) -> Option<String> {
    if s.contains(['\r', '\n', '\0']) {
        return None;
    }
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

/// An argument of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Sent as is (atoms, quoted strings, parenthesized lists).
    Raw(String),
    /// A string: quoted, or a literal when it can't be.
    Str(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImapError {
    #[error(transparent)]
    Conn(#[from] ConnError),
    #[error("login refused")]
    Login,
    #[error("{0} failed")]
    Command(&'static str),
    #[error("the message is no longer in the mailbox")]
    Gone,
}

/// One logged-in session.
#[derive(Debug)]
pub struct Session<S> {
    lines: Lines<S>,
    next_tag: u32,
}

/// What `examine` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selected {
    pub uidvalidity: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    /// Read the greeting and log in.
    pub async fn login(stream: S, user: &str, password: &str) -> Result<Session<S>, ImapError> {
        let mut s = Session {
            lines: Lines::new(stream, MAX_LINE),
            next_tag: 0,
        };
        let mut budget = COMMAND_BUDGET;
        let greeting = tokio::time::timeout(COMMAND_DEADLINE, s.read_response(&mut budget))
            .await
            .map_err(|_| ConnError::Timeout)??;
        match classify(greeting.head()) {
            Kind::Untagged(rest) if rest.to_ascii_uppercase().starts_with(b"OK") => {}
            _ => return Err(ImapError::Conn(ConnError::Refused("greeting".into()))),
        }
        let (status, _) = s
            .command(
                "LOGIN",
                &[Arg::Str(user.to_owned()), Arg::Str(password.to_owned())],
            )
            .await?;
        if status != Status::Ok {
            return Err(ImapError::Login);
        }
        Ok(s)
    }

    /// One response, charging what it holds to `budget`.
    async fn read_response(&mut self, budget: &mut usize) -> Result<Response, ConnError> {
        let mut r = Response::default();
        let mut literals = 0usize;
        loop {
            let line = self.lines.line().await?;
            *budget = budget.checked_sub(line.len()).ok_or(ConnError::TooLarge)?;
            match literal_len(&line) {
                Some(n) if n <= MAX_LITERAL => {
                    literals = literals.saturating_add(1);
                    if literals > MAX_LITERALS_PER_RESPONSE {
                        return Err(ConnError::TooLarge);
                    }
                    let keep = MAX_RAW_BYTES.min(*budget);
                    let lit = self.lines.bytes(n, keep).await?;
                    if n > keep && keep < MAX_RAW_BYTES {
                        return Err(ConnError::TooLarge);
                    }
                    *budget = budget.saturating_sub(lit.len());
                    r.parts.push((line, Some(lit)));
                }
                Some(_) => return Err(ConnError::TooLarge),
                None => {
                    r.parts.push((line, None));
                    return Ok(r);
                }
            }
        }
    }

    /// Send a command; collect the untagged responses until its tagged
    /// completion.
    pub async fn command(
        &mut self,
        name: &'static str,
        args: &[Arg],
    ) -> Result<(Status, Vec<Response>), ImapError> {
        tokio::time::timeout(COMMAND_DEADLINE, self.command_inner(name, args))
            .await
            .map_err(|_| ImapError::Conn(ConnError::Timeout))?
    }

    async fn command_inner(
        &mut self,
        name: &'static str,
        args: &[Arg],
    ) -> Result<(Status, Vec<Response>), ImapError> {
        let mut budget = COMMAND_BUDGET;
        self.next_tag = self.next_tag.saturating_add(1);
        let tag = format!("A{}", self.next_tag);
        let mut pending = format!("{tag} {name}").into_bytes();
        for arg in args {
            pending.push(b' ');
            match arg {
                Arg::Raw(r) if r.contains(['\r', '\n', '\0']) => {
                    return Err(ImapError::Command(name));
                }
                Arg::Raw(r) => pending.extend_from_slice(r.as_bytes()),
                Arg::Str(s) if s.contains(['\r', '\n', '\0']) => {
                    return Err(ImapError::Command(name));
                }
                Arg::Str(s) if quotable(s) => {
                    let q = quote(s).ok_or(ImapError::Command(name))?;
                    pending.extend_from_slice(q.as_bytes());
                }
                Arg::Str(s) => {
                    // A synchronizing literal: wait for the go-ahead.
                    pending.extend_from_slice(format!("{{{}}}\r\n", s.len()).as_bytes());
                    self.lines.write(&pending).await?;
                    pending.clear();
                    loop {
                        let r = self.read_response(&mut budget).await?;
                        match classify(r.head()) {
                            Kind::Continuation => break,
                            Kind::Tagged { .. } => return Err(ImapError::Command(name)),
                            _ => {}
                        }
                    }
                    pending.extend_from_slice(s.as_bytes());
                }
            }
        }
        pending.extend_from_slice(b"\r\n");
        self.lines.write(&pending).await?;
        let mut untagged = Vec::new();
        for _ in 0..MAX_RESPONSES {
            let r = self.read_response(&mut budget).await?;
            match classify(r.head()) {
                Kind::Tagged { tag: t, status } if t == tag.as_bytes() => {
                    return Ok((status, untagged));
                }
                Kind::Untagged(rest) if rest.to_ascii_uppercase().starts_with(b"BYE") => {
                    return Err(ImapError::Conn(ConnError::Closed));
                }
                _ => untagged.push(r),
            }
        }
        Err(ImapError::Conn(ConnError::TooLarge))
    }

    /// EXAMINE (read-only SELECT) a folder; None when it does not open.
    pub async fn examine(&mut self, folder: &str) -> Result<Option<Selected>, ImapError> {
        let (status, untagged) = self
            .command("EXAMINE", &[Arg::Str(folder.to_owned())])
            .await?;
        if status != Status::Ok {
            return Ok(None);
        }
        let uidvalidity = untagged
            .iter()
            .find_map(|r| match classify(r.head()) {
                Kind::Untagged(rest) => uidvalidity(rest),
                _ => None,
            })
            .unwrap_or(0);
        Ok(Some(Selected { uidvalidity }))
    }

    /// UID SEARCH with these criteria (already-formed search keys).
    pub async fn uid_search(&mut self, criteria: &[String]) -> Result<Vec<u32>, ImapError> {
        let mut args = vec![Arg::Raw("SEARCH".to_owned())];
        args.extend(criteria.iter().map(|c| Arg::Raw(c.clone())));
        let (status, untagged) = self.command("UID", &args).await?;
        if status != Status::Ok {
            return Err(ImapError::Command("search"));
        }
        let mut uids = Vec::new();
        for r in &untagged {
            if let Kind::Untagged(rest) = classify(r.head())
                && let Some(found) = search_uids(rest)
            {
                uids.extend(found);
                uids.truncate(MAX_UIDS);
            }
        }
        Ok(uids)
    }

    /// The whole message with this UID (cut at `MAX_RAW_BYTES`).
    pub async fn uid_fetch(&mut self, uid: u32) -> Result<Vec<u8>, ImapError> {
        let (status, untagged) = self
            .command(
                "UID",
                &[
                    Arg::Raw("FETCH".to_owned()),
                    Arg::Raw(uid.to_string()),
                    Arg::Raw("(BODY.PEEK[])".to_owned()),
                ],
            )
            .await?;
        if status != Status::Ok {
            return Err(ImapError::Gone);
        }
        untagged.iter().find_map(fetch_body).ok_or(ImapError::Gone)
    }

    /// LOGOUT, best effort.
    pub async fn logout(mut self) {
        let _ = self.command("LOGOUT", &[]).await;
        self.lines.shutdown().await;
    }
}

/// Log in over implicit TLS.
pub async fn connect(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    user: &str,
    password: &str,
) -> Result<Session<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, ImapError> {
    let stream = connect_tls(tls, host, port).await?;
    Session::login(stream, user, password).await
}

// --------------------------------------------------------------- search

/// IMAP's OR takes two keys: a OR b OR c is `OR a OR b c`
/// (`_or_all`). Each alternative is parenthesized.
#[must_use]
pub fn or_all(alternatives: &[Vec<String>]) -> Vec<String> {
    let keys: Vec<String> = alternatives
        .iter()
        .map(|a| format!("({})", a.join(" ")))
        .collect();
    let mut out = Vec::new();
    if let Some((last, rest)) = keys.split_last() {
        for k in rest {
            out.push("OR".to_owned());
            out.push(k.clone());
        }
        out.push(last.clone());
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
    use proptest::prelude::*;

    #[test]
    fn parsing() {
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {12}"), Some(12));
        assert_eq!(literal_len(b"A1 LOGIN {5+}"), Some(5));
        assert_eq!(literal_len(b"{x}"), None);
        assert_eq!(literal_len(b"{99999999999999}"), None);
        assert_eq!(
            classify(b"A3 ok done"),
            Kind::Tagged {
                tag: b"A3",
                status: Status::Ok
            }
        );
        assert_eq!(classify(b"+ go"), Kind::Continuation);
        assert_eq!(
            uidvalidity(b"OK [UIDVALIDITY 3857529045] UIDs valid"),
            Some(3_857_529_045)
        );
        assert_eq!(search_uids(b"SEARCH 2 84 882"), Some(vec![2, 84, 882]));
        assert_eq!(search_uids(b"SEARCH"), Some(vec![]));
        assert_eq!(search_uids(b"SEARCHING 1"), None);
        let rs = responses(b"* 3 FETCH (UID 9 BODY[] {5}\r\nhello)\r\nA4 OK done\r\n");
        assert_eq!(rs.len(), 2);
        assert_eq!(fetch_body(&rs[0]).as_deref(), Some(&b"hello"[..]));
        let rs = responses(b"* 3 FETCH (UID 9 BODY[] \"hi \\\"x\\\"\")\r\n");
        assert_eq!(fetch_body(&rs[0]).as_deref(), Some(&b"hi \"x\""[..]));
        assert_eq!(quote("a\"b\\c").as_deref(), Some("\"a\\\"b\\\\c\""));
        assert_eq!(quote("a\r\nb"), None);
        assert_eq!(quote("a\0"), None);
        assert!(!quotable("p\u{e9}ss") && !quotable("a\r\nb") && quotable("p@ss w"));
        assert_eq!(
            or_all(&[vec!["A".into()], vec!["B".into()], vec!["C".into()]]),
            vec!["OR", "(A)", "OR", "(B)", "(C)"]
        );
        assert_eq!(or_all(&[vec!["A".into(), "x".into()]]), vec!["(A x)"]);
    }

    proptest! {
        #[test]
        fn responses_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            for r in responses(&data) {
                let _ = fetch_body(&r);
                if let Kind::Untagged(rest) = classify(r.head()) {
                    let _ = uidvalidity(rest);
                    let _ = search_uids(rest);
                }
            }
        }
    }
}
