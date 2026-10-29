//! A minimal SMTP submission client (`backends.py` used smtplib): EHLO,
//! implicit TLS on port 465 or STARTTLS (required, never optional) on any
//! other port, AUTH PLAIN (or LOGIN), MAIL/RCPT/DATA with dot-stuffing,
//! QUIT. Nothing secret is sent before TLS.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::{ConnError, Lines, connect_tls, tcp, upgrade};

/// Longest reply line accepted.
pub const MAX_LINE: usize = 8 * 1024;
/// Most lines in one reply.
pub const MAX_REPLY_LINES: usize = 256;

/// One reply: its code and its lines' texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    #[must_use]
    pub fn positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

/// One reply line: `(code, last?, text)`.
#[must_use]
pub fn parse_reply_line(line: &[u8]) -> Option<(u16, bool, String)> {
    let code = line.get(..3)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let code: u16 = std::str::from_utf8(code).ok()?.parse().ok()?;
    if !(200..600).contains(&code) {
        return None;
    }
    let (last, text) = match line.get(3) {
        None => (true, &[][..]),
        Some(b' ') => (true, line.get(4..).unwrap_or(&[])),
        Some(b'-') => (false, line.get(4..).unwrap_or(&[])),
        Some(_) => return None,
    };
    Some((code, last, String::from_utf8_lossy(text).into_owned()))
}

/// Replies in a byte buffer (the client's parsing, without I/O; fuzzed).
#[must_use]
pub fn replies(data: &[u8]) -> Vec<Reply> {
    let mut out = Vec::new();
    let mut cur: Option<Reply> = None;
    for line in data.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.len() > MAX_LINE {
            continue;
        }
        let Some((code, last, text)) = parse_reply_line(line) else {
            cur = None;
            continue;
        };
        let r = cur.get_or_insert_with(|| Reply {
            code,
            lines: Vec::new(),
        });
        if r.code != code || r.lines.len() >= MAX_REPLY_LINES {
            cur = None;
            continue;
        }
        r.lines.push(text);
        if last && let Some(done) = cur.take() {
            out.push(done);
        }
    }
    out
}

/// Dot-stuffing and CRLF line endings for DATA, with the final `.`.
#[must_use]
pub fn data_block(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        message
            .len()
            .saturating_add(message.len() / 32)
            .saturating_add(8),
    );
    let mut at_line_start = true;
    let mut prev_cr = false;
    for &b in message {
        match b {
            b'\n' => {
                if !prev_cr {
                    out.push(b'\r');
                }
                out.push(b'\n');
                at_line_start = true;
                prev_cr = false;
                continue;
            }
            b'\r' => {
                if prev_cr {
                    // A lone CR: end that line.
                    out.push(b'\n');
                    at_line_start = true;
                }
                out.push(b'\r');
                prev_cr = true;
                continue;
            }
            _ => {}
        }
        if prev_cr {
            out.push(b'\n');
            at_line_start = true;
            prev_cr = false;
        }
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        at_line_start = false;
    }
    if prev_cr {
        out.push(b'\n');
        at_line_start = true;
    }
    if !at_line_start {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SmtpError {
    #[error(transparent)]
    Conn(#[from] ConnError),
    #[error("the server does not offer STARTTLS")]
    NoStartTls,
    #[error("login refused")]
    Login,
    #[error("no login method the broker speaks (PLAIN, LOGIN)")]
    NoAuth,
    #[error("{0} refused")]
    Refused(&'static str),
    #[error("every recipient was refused")]
    AllRecipientsRefused,
}

struct Client<S> {
    lines: Lines<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    async fn reply(&mut self) -> Result<Reply, ConnError> {
        let mut r = Reply {
            code: 0,
            lines: Vec::new(),
        };
        loop {
            let line = self.lines.line().await?;
            let (code, last, text) = parse_reply_line(&line).ok_or(ConnError::Malformed)?;
            if r.lines.is_empty() {
                r.code = code;
            } else if r.code != code {
                return Err(ConnError::Malformed);
            }
            if r.lines.len() >= MAX_REPLY_LINES {
                return Err(ConnError::TooLarge);
            }
            r.lines.push(text);
            if last {
                return Ok(r);
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> Result<Reply, ConnError> {
        self.lines.write(format!("{line}\r\n").as_bytes()).await?;
        self.reply().await
    }

    async fn ehlo(&mut self, name: &str) -> Result<Vec<String>, SmtpError> {
        let r = self.cmd(&format!("EHLO {name}")).await?;
        if r.code != 250 {
            tracing::warn!(code = r.code, "smtp: EHLO refused");
            return Err(SmtpError::Refused("EHLO"));
        }
        Ok(r.lines
            .iter()
            .skip(1)
            .map(|l| l.to_ascii_uppercase())
            .collect())
    }
}

fn offers(caps: &[String], what: &str) -> bool {
    caps.iter()
        .any(|c| c == what || c.starts_with(&format!("{what} ")))
}

fn auth_methods(caps: &[String]) -> Vec<String> {
    caps.iter()
        .filter_map(|c| c.strip_prefix("AUTH").map(str::to_owned))
        .flat_map(|rest| {
            rest.trim_start_matches(['=', ' '])
                .split(' ')
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The EHLO name: our address as a literal (smtplib without an FQDN).
fn ehlo_name(local: Option<SocketAddr>) -> String {
    match local {
        Some(SocketAddr::V4(a)) => format!("[{}]", a.ip()),
        Some(SocketAddr::V6(a)) => format!("[IPv6:{}]", a.ip()),
        None => "[127.0.0.1]".to_owned(),
    }
}

/// What to send.
#[derive(Debug, Clone, Copy)]
pub struct Envelope<'a> {
    pub sender: &'a str,
    pub recipients: &'a [String],
    pub message: &'a [u8],
}

/// The recipients the server refused (the others got the message).
pub type Refusals = Vec<String>;

async fn session<S: AsyncRead + AsyncWrite + Unpin>(
    c: &mut Client<S>,
    caps: &[String],
    user: &str,
    password: &str,
    env: Envelope<'_>,
) -> Result<Refusals, SmtpError> {
    let methods = auth_methods(caps);
    if methods.iter().any(|m| m == "PLAIN") {
        let token = STANDARD.encode(format!("\0{user}\0{password}"));
        let r = c.cmd(&format!("AUTH PLAIN {token}")).await?;
        if r.code != 235 {
            return Err(SmtpError::Login);
        }
    } else if methods.iter().any(|m| m == "LOGIN") {
        let r = c.cmd("AUTH LOGIN").await?;
        if r.code != 334 {
            return Err(SmtpError::Login);
        }
        let r = c.cmd(&STANDARD.encode(user)).await?;
        if r.code != 334 {
            return Err(SmtpError::Login);
        }
        let r = c.cmd(&STANDARD.encode(password)).await?;
        if r.code != 235 {
            return Err(SmtpError::Login);
        }
    } else {
        return Err(SmtpError::NoAuth);
    }
    let r = c.cmd(&format!("MAIL FROM:<{}>", env.sender)).await?;
    if r.code != 250 {
        return Err(SmtpError::Refused("MAIL FROM"));
    }
    let mut refused = Vec::new();
    for rcpt in env.recipients {
        let r = c.cmd(&format!("RCPT TO:<{rcpt}>")).await?;
        if r.code != 250 && r.code != 251 {
            refused.push(rcpt.clone());
        }
    }
    if refused.len() == env.recipients.len() {
        let _ = c.cmd("RSET").await;
        return Err(SmtpError::AllRecipientsRefused);
    }
    let r = c.cmd("DATA").await?;
    if r.code != 354 {
        return Err(SmtpError::Refused("DATA"));
    }
    c.lines.write(&data_block(env.message)).await?;
    let r = c.reply().await?;
    if r.code != 250 {
        return Err(SmtpError::Refused("the message"));
    }
    let _ = c.cmd("QUIT").await;
    c.lines.shutdown().await;
    Ok(refused)
}

/// Send one message: over implicit TLS (`implicit_tls`, port 465), or
/// with STARTTLS, which must be offered (never plaintext). Addresses must
/// already be valid (no `<`, `>`, CR or LF): the caller checks them.
pub async fn send(
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    implicit_tls: bool,
    user: &str,
    password: &str,
    env: Envelope<'_>,
) -> Result<Refusals, SmtpError> {
    let bad = |a: &str| a.contains(['<', '>', '\r', '\n', ' ']) || a.is_empty();
    if bad(env.sender) || env.recipients.iter().any(|r| bad(r)) || env.recipients.is_empty() {
        return Err(SmtpError::Refused("an address"));
    }
    if implicit_tls {
        let stream = connect_tls(tls, host, port).await?;
        let local = stream.get_ref().0.local_addr().ok();
        let mut c = Client {
            lines: Lines::new(stream, MAX_LINE),
        };
        if c.reply().await?.code != 220 {
            return Err(SmtpError::Refused("the greeting"));
        }
        let caps = c.ehlo(&ehlo_name(local)).await?;
        return session(&mut c, &caps, user, password, env).await;
    }
    let plain = tcp(host, port).await?;
    let local = plain.local_addr().ok();
    let mut c = Client {
        lines: Lines::new(plain, MAX_LINE),
    };
    if c.reply().await?.code != 220 {
        return Err(SmtpError::Refused("the greeting"));
    }
    let name = ehlo_name(local);
    let caps = c.ehlo(&name).await?;
    if !offers(&caps, "STARTTLS") {
        return Err(SmtpError::NoStartTls);
    }
    let r = c.cmd("STARTTLS").await?;
    if r.code != 220 {
        return Err(SmtpError::NoStartTls);
    }
    // Anything the server sent ahead of the handshake is refused
    // (`into_inner`): no response injection across the upgrade.
    let stream = upgrade(tls, host, c.lines.into_inner()?).await?;
    let mut c = Client {
        lines: Lines::new(stream, MAX_LINE),
    };
    let caps = c.ehlo(&name).await?;
    session(&mut c, &caps, user, password, env).await
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
    fn reply_lines() {
        assert_eq!(
            parse_reply_line(b"250-mail.example"),
            Some((250, false, "mail.example".into()))
        );
        assert_eq!(parse_reply_line(b"250 OK"), Some((250, true, "OK".into())));
        assert_eq!(parse_reply_line(b"220"), Some((220, true, String::new())));
        assert_eq!(parse_reply_line(b"25x OK"), None);
        assert_eq!(parse_reply_line(b"999 x"), None);
        let rs = replies(b"250-a\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n354 go\r\n");
        assert_eq!(rs.len(), 2);
        let caps: Vec<String> = rs[0].lines.iter().skip(1).cloned().collect();
        assert!(offers(&caps, "STARTTLS"));
        assert_eq!(auth_methods(&caps), vec!["PLAIN", "LOGIN"]);
        assert_eq!(auth_methods(&["AUTH=LOGIN".to_owned()]), vec!["LOGIN"]);
    }

    #[test]
    fn dot_stuffing() {
        assert_eq!(
            data_block(b"a\n.b\r\n..c\rd"),
            b"a\r\n..b\r\n...c\r\nd\r\n.\r\n"
        );
        assert_eq!(data_block(b".\r\n"), b"..\r\n.\r\n");
        assert_eq!(data_block(b""), b".\r\n");
    }

    proptest! {
        #[test]
        fn data_block_is_transparent(msg in proptest::collection::vec(any::<u8>(), 0..512)) {
            let block = data_block(&msg);
            prop_assert!(block.ends_with(b".\r\n"));
            // No line of the block is a lone "." before the end, and every
            // LF is part of a CRLF.
            let body = &block[..block.len() - 3];
            for line in body.split(|b| *b == b'\n') {
                prop_assert!(line != b"." && line != b".\r");
            }
            for (i, b) in block.iter().enumerate() {
                if *b == b'\n' { prop_assert!(i > 0 && block[i - 1] == b'\r'); }
                if *b == b'\r' { prop_assert!(block.get(i + 1) == Some(&b'\n')); }
            }
        }

        #[test]
        fn replies_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            for r in replies(&data) {
                prop_assert!((200..600).contains(&r.code));
            }
        }
    }
}
