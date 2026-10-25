//! Where mail is read and sent (`mail/backends.py`): a Gmail account
//! through the Gmail API, or any mailbox over IMAP and SMTP. A backend only
//! finds, fetches and sends raw messages; what an agent may see is decided
//! by the gateway on the message itself, never on a backend's search
//! (searches only narrow what is fetched).

use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::mail::server_term;
use agent_auth_core::policy::mail::{MailBackendKind, MailboxConfig};
use agent_auth_mail::imap;
use agent_auth_mail::message::MAX_RAW_BYTES;
use agent_auth_mail::smtp;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use time::Date;

use crate::provisioners::google::GoogleTokens;

pub const GMAIL_API: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// A backend failure. The text may reach an agent: no server text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

/// A message the backend found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The backend's id for the message.
    pub key: String,
    /// The backend's thread id, if it has one.
    pub thread: Option<String>,
}

/// A fetched message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub raw: Vec<u8>,
    /// Filed as the mailbox's own sent mail.
    pub sent: bool,
}

/// What to look for. Only ever narrows: the gateway checks each message.
#[derive(Debug, Clone, Default)]
pub struct Search {
    /// An alias the message was sent to.
    pub to: Option<String>,
    /// Correspondent globs (one layer).
    pub correspondents: Vec<String>,
    pub since: Option<Date>,
    pub text: Option<String>,
}

/// `_safe_text`: search words only (no operators, quotes or groups).
#[must_use]
pub fn safe_text(text: &str) -> String {
    let kept: String = text
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || "@.+- ".contains(c) {
                c
            } else {
                ' '
            }
        })
        .collect();
    kept.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(200)
        .collect()
}

/// The server-side terms of a correspondent layer: all of them, or none
/// (one glob without a literal domain makes the server search everything).
fn terms(globs: &[String]) -> Option<Vec<String>> {
    if globs.is_empty() {
        return None;
    }
    let mut out: Vec<String> = globs
        .iter()
        .map(|g| server_term(g))
        .collect::<Option<_>>()?;
    out.sort();
    out.dedup();
    Some(out)
}

#[derive(Debug)]
pub struct GmailBackend {
    account: String,
    api: String,
    tokens: Option<Arc<GoogleTokens>>,
    client: reqwest::Client,
}

#[derive(Debug)]
pub struct ImapBackend {
    config: MailboxConfig,
    tls: Arc<rustls::ClientConfig>,
}

/// One mailbox's backend.
#[derive(Debug)]
pub enum Backend {
    Gmail(GmailBackend),
    Imap(ImapBackend),
}

impl Backend {
    pub fn new(
        config: &MailboxConfig,
        tokens: Option<&Arc<GoogleTokens>>,
        gmail_api: &str,
        tls: &Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<Backend> {
        Ok(match config.backend {
            MailBackendKind::Gmail => Backend::Gmail(GmailBackend {
                account: config.google_account.clone().unwrap_or_default(),
                api: gmail_api.trim_end_matches('/').to_owned(),
                tokens: tokens.cloned(),
                client: agent_auth_tls::reqwest_builder(
                    rustls::ClientConfig::clone(tls),
                    Duration::from_secs(30),
                )
                .build()?,
            }),
            MailBackendKind::Imap => Backend::Imap(ImapBackend {
                config: config.clone(),
                tls: Arc::clone(tls),
            }),
        })
    }

    pub async fn search(
        &self,
        query: &Search,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Found>, Option<String>), BackendError> {
        match self {
            Backend::Gmail(g) => g.search(query, limit, page).await,
            Backend::Imap(i) => i.search(query, limit, page).await,
        }
    }

    /// The raw message, and whether the mailbox filed it as its own sent
    /// mail (Gmail's `SENT` label; an IMAP `sent_folders` folder).
    pub async fn fetch(&self, key: &str) -> Result<Fetched, BackendError> {
        match self {
            Backend::Gmail(g) => g.fetch(key).await,
            Backend::Imap(i) => i.fetch(key).await,
        }
    }

    /// Send; the backend's id of what was sent (empty when it has none).
    pub async fn send(
        &self,
        raw: &[u8],
        sender: &str,
        recipients: &[String],
        thread: Option<&str>,
    ) -> Result<String, BackendError> {
        match self {
            Backend::Gmail(g) => g.send(raw, thread).await,
            Backend::Imap(i) => i.send(raw, sender, recipients).await,
        }
    }
}

const MAX_GMAIL_ANSWER: usize = 64 * 1024 * 1024;

impl GmailBackend {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        scope: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, BackendError> {
        let tokens = self
            .tokens
            .as_ref()
            .ok_or_else(|| BackendError("gmail: no google accounts are configured".to_owned()))?;
        let (token, _) = tokens
            .token(
                &self.account,
                &[scope],
                false,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .map_err(|e| BackendError(format!("gmail: {e}")))?;
        let mut url = url::Url::parse(&format!("{}{path}", self.api))
            .map_err(|_| BackendError("gmail: a malformed API URL".to_owned()))?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let mut req = self
            .client
            .request(method.clone(), url)
            .bearer_auth(token.expose());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let mut resp = req.send().await.map_err(|e| {
            tracing::warn!(error = %e, "gmail unreachable");
            BackendError("gmail unreachable (see broker logs)".to_owned())
        })?;
        let status = resp.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            tracing::warn!(error = %e, "gmail: reading the answer failed");
            BackendError("gmail unreachable (see broker logs)".to_owned())
        })? {
            if bytes.len().saturating_add(chunk.len()) > MAX_GMAIL_ANSWER {
                return Err(BackendError("gmail: the answer was too large".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            tracing::warn!(%method, path, status = status.as_u16(), body = %String::from_utf8_lossy(&bytes), "gmail refused");
            return Err(BackendError(format!(
                "gmail: {method} {} answered {}",
                path.split('?').next().unwrap_or(path),
                status.as_u16()
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| BackendError("gmail: the answer was not JSON".to_owned()))
    }

    /// The Gmail search query (`_query`).
    #[must_use]
    pub fn query(q: &Search) -> String {
        let mut parts = Vec::new();
        if let Some(to) = &q.to {
            parts.push(format!("to:{to}"));
        }
        if let Some(t) = terms(&q.correspondents) {
            let alts: Vec<String> = t
                .iter()
                .map(|t| format!("from:{t} to:{t} cc:{t}"))
                .collect();
            parts.push(format!("{{{}}}", alts.join(" ")));
        }
        if let Some(d) = q.since {
            parts.push(format!(
                "after:{:04}/{:02}/{:02}",
                d.year(),
                u8::from(d.month()),
                d.day()
            ));
        }
        if let Some(text) = q.text.as_deref().map(safe_text).filter(|t| !t.is_empty()) {
            parts.push(format!("\"{text}\""));
        }
        parts.join(" ")
    }

    async fn search(
        &self,
        q: &Search,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Found>, Option<String>), BackendError> {
        let mut params = vec![("q", Self::query(q)), ("maxResults", limit.to_string())];
        if let Some(p) = page {
            params.push(("pageToken", p.chars().take(256).collect()));
        }
        let out = self
            .call(
                reqwest::Method::GET,
                "/messages",
                "gmail.readonly",
                &params,
                None,
            )
            .await?;
        let found = out
            .get("messages")
            .and_then(Value::as_array)
            .map(|ms| {
                ms.iter()
                    .filter_map(|m| {
                        Some(Found {
                            key: m.get("id")?.as_str()?.to_owned(),
                            thread: m.get("threadId").and_then(Value::as_str).map(str::to_owned),
                        })
                    })
                    .filter(|f| gmail_id_ok(&f.key))
                    .take(limit)
                    .collect()
            })
            .unwrap_or_default();
        let next = out
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(|s| s.chars().take(256).collect());
        Ok((found, next))
    }

    async fn fetch(&self, key: &str) -> Result<Fetched, BackendError> {
        if !gmail_id_ok(key) {
            return Err(BackendError("malformed gmail message id".to_owned()));
        }
        let out = self
            .call(
                reqwest::Method::GET,
                &format!("/messages/{key}"),
                "gmail.readonly",
                &[("format", "raw".to_owned())],
                None,
            )
            .await?;
        let raw = out.get("raw").and_then(Value::as_str).unwrap_or("");
        let raw = raw.trim_end_matches('=');
        let mut bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| BackendError("gmail: a message that does not decode".to_owned()))?;
        bytes.truncate(MAX_RAW_BYTES);
        let sent = out
            .get("labelIds")
            .and_then(Value::as_array)
            .is_some_and(|l| l.iter().any(|x| x.as_str() == Some("SENT")));
        Ok(Fetched { raw: bytes, sent })
    }

    async fn send(&self, raw: &[u8], thread: Option<&str>) -> Result<String, BackendError> {
        let mut body = json!({"raw": URL_SAFE.encode(raw)});
        if let Some(t) = thread.filter(|t| gmail_id_ok(t))
            && let Value::Object(m) = &mut body
        {
            m.insert("threadId".to_owned(), json!(t));
        }
        let out = self
            .call(
                reqwest::Method::POST,
                "/messages/send",
                "gmail.send",
                &[],
                Some(body),
            )
            .await?;
        Ok(out
            .get("id")
            .and_then(Value::as_str)
            .filter(|i| gmail_id_ok(i))
            .unwrap_or("")
            .to_owned())
    }
}

/// `[A-Za-z0-9_-]{1,64}`.
fn gmail_id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// IMAP keys are `folder\x1fuidvalidity\x1fuid`.
const SEP: char = '\u{1f}';

impl ImapBackend {
    fn password(&self) -> Result<String, BackendError> {
        std::fs::read_to_string(&self.config.password_file)
            .map(|p| p.trim().to_owned())
            .map_err(|e| {
                tracing::warn!(file = %self.config.password_file, error = %e, "mail: cannot read a password file");
                BackendError(format!(
                    "mailbox {}: cannot read its password file",
                    self.config.address
                ))
            })
    }

    fn err(&self, e: &dyn std::fmt::Display) -> BackendError {
        BackendError(format!("imap {}: {e}", self.config.imap_host))
    }

    /// `_criteria`. None when a value would not quote (CR, LF, NUL).
    #[must_use]
    pub fn criteria(q: &Search) -> Option<Vec<String>> {
        let mut c = Vec::new();
        if let Some(to) = &q.to {
            let to = imap::quote(to)?;
            c.extend([
                "OR".to_owned(),
                "HEADER".to_owned(),
                "X-SimpleLogin-Envelope-To".to_owned(),
                to.clone(),
                "TO".to_owned(),
                to,
            ]);
        }
        if let Some(t) = terms(&q.correspondents) {
            let alts: Vec<Vec<String>> = t
                .iter()
                .map(|t| {
                    let t = imap::quote(t)?;
                    Some(vec![
                        "OR".into(),
                        "FROM".into(),
                        t.clone(),
                        "OR".into(),
                        "TO".into(),
                        t.clone(),
                        "CC".into(),
                        t,
                    ])
                })
                .collect::<Option<_>>()?;
            c.extend(imap::or_all(&alts));
        }
        if let Some(d) = q.since {
            const MONTHS: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            let m = MONTHS
                .get(usize::from(u8::from(d.month())).saturating_sub(1))
                .copied()
                .unwrap_or("Jan");
            c.extend([
                "SINCE".to_owned(),
                format!("{:02}-{m}-{:04}", d.day(), d.year()),
            ]);
        }
        let text: String = safe_text(q.text.as_deref().unwrap_or(""))
            .chars()
            .filter(char::is_ascii)
            .collect();
        if !text.trim().is_empty() {
            // No CHARSET: ASCII only.
            c.extend(["TEXT".to_owned(), imap::quote(&text)?]);
        }
        if c.is_empty() {
            c.push("ALL".to_owned());
        }
        Some(c)
    }

    async fn search(
        &self,
        q: &Search,
        limit: usize,
        page: Option<&str>,
    ) -> Result<(Vec<Found>, Option<String>), BackendError> {
        let offset: usize = page
            .filter(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let password = self.password()?;
        let mut session = imap::connect(
            &self.tls,
            &self.config.imap_host,
            self.config.imap_port,
            self.config.login(),
            &password,
        )
        .await
        .map_err(|e| self.err(&e))?;
        let criteria = Self::criteria(q)
            .ok_or_else(|| BackendError("imap: a search term that does not quote".to_owned()))?;
        let mut keys: Vec<String> = Vec::new();
        let mut failure = None;
        for folder in &self.config.folders {
            match session.examine(folder).await {
                Ok(Some(sel)) => match session.uid_search(&criteria).await {
                    Ok(uids) => keys.extend(
                        uids.iter()
                            .rev()
                            .map(|u| format!("{folder}{SEP}{}{SEP}{u}", sel.uidvalidity)),
                    ),
                    Err(e) => {
                        failure = Some(self.err(&format!("search in {folder} failed ({e})")));
                        break;
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    failure = Some(self.err(&e));
                    break;
                }
            }
        }
        session.logout().await;
        if let Some(f) = failure {
            return Err(f);
        }
        let end = offset.saturating_add(limit);
        let window = keys
            .get(offset.min(keys.len())..end.min(keys.len()))
            .unwrap_or(&[])
            .iter()
            .map(|k| Found {
                key: k.clone(),
                thread: None,
            })
            .collect();
        let more = (keys.len() > end).then(|| end.to_string());
        Ok((window, more))
    }

    async fn fetch(&self, key: &str) -> Result<Fetched, BackendError> {
        let mut parts = key.split(SEP);
        let (Some(folder), Some(validity), Some(uid), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(BackendError("malformed imap message key".to_owned()));
        };
        let (Ok(validity), Ok(uid)) = (validity.parse::<u32>(), uid.parse::<u32>()) else {
            return Err(BackendError("malformed imap message key".to_owned()));
        };
        if !self.config.folders.iter().any(|f| f == folder) {
            return Err(BackendError("malformed imap message key".to_owned()));
        }
        let password = self.password()?;
        let mut session = imap::connect(
            &self.tls,
            &self.config.imap_host,
            self.config.imap_port,
            self.config.login(),
            &password,
        )
        .await
        .map_err(|e| self.err(&e))?;
        let gone = || BackendError("the message is no longer in the mailbox".to_owned());
        let out = match session.examine(folder).await {
            Ok(Some(sel)) if sel.uidvalidity == validity => match session.uid_fetch(uid).await {
                Ok(raw) => Ok(Fetched {
                    raw,
                    sent: self
                        .config
                        .sent_folders
                        .iter()
                        .any(|f| f.eq_ignore_ascii_case(folder)),
                }),
                Err(imap::ImapError::Gone) => Err(gone()),
                Err(e) => Err(self.err(&e)),
            },
            Ok(_) => Err(gone()),
            Err(e) => Err(self.err(&e)),
        };
        session.logout().await;
        out
    }

    async fn send(
        &self,
        raw: &[u8],
        sender: &str,
        recipients: &[String],
    ) -> Result<String, BackendError> {
        let password = self.password()?;
        let refused = smtp::send(
            &self.tls,
            &self.config.smtp_host,
            self.config.smtp_port,
            self.config.smtp_port == 465,
            self.config.login(),
            &password,
            smtp::Envelope {
                sender,
                recipients,
                message: raw,
            },
        )
        .await
        .map_err(|e| BackendError(format!("smtp {}: {e}", self.config.smtp_host)))?;
        if !refused.is_empty() {
            return Err(BackendError(format!("smtp refused {}", refused.join(", "))));
        }
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        let q = Search {
            to: Some("airline@me.example".into()),
            correspondents: vec!["*@qantas.example".into(), "b@x.example".into()],
            since: agent_auth_core::mail::parse_date("2026-05-01"),
            text: Some("flight (\"ABC\") OR -x".into()),
        };
        assert_eq!(
            GmailBackend::query(&q),
            "to:airline@me.example {from:b@x.example to:b@x.example cc:b@x.example from:qantas.example to:qantas.example cc:qantas.example} after:2026/05/01 \"flight ABC OR -x\""
        );
        assert_eq!(
            ImapBackend::criteria(&q).unwrap().join(" "),
            "OR HEADER X-SimpleLogin-Envelope-To \"airline@me.example\" TO \"airline@me.example\" OR (OR FROM \"b@x.example\" OR TO \"b@x.example\" CC \"b@x.example\") (OR FROM \"qantas.example\" OR TO \"qantas.example\" CC \"qantas.example\") SINCE 01-May-2026 TEXT \"flight ABC OR -x\""
        );
        let loose = Search {
            correspondents: vec!["*@*".into(), "a@b.example".into()],
            ..Search::default()
        };
        assert_eq!(GmailBackend::query(&loose), "");
        assert_eq!(ImapBackend::criteria(&loose).unwrap(), vec!["ALL"]);
        assert_eq!(safe_text("a\"b(c) d:e"), "a b c d e");
    }
}
