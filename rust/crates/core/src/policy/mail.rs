//! `platforms.mail` and `platforms.google.accounts` (`policy/schema.py`
//! MailPlatformConfig, MailboxConfig, SimpleLoginConfig, MailRestriction,
//! GoogleAccount). Agents never hold a mailbox credential: the broker reads
//! and sends for them (broker `mail`). Off while there are no mailboxes.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::mail::{MailAction, MailAuthority};
use crate::pyfmt::repr;

/// `_ADDRESS_RE` of the policy: `[^@\s]+@[^@\s]+\.[^@\s]+`.
fn loose_address(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    let ok = |p: &str| !p.is_empty() && !p.contains('@') && !p.chars().any(char::is_whitespace);
    ok(local)
        && ok(domain)
        && domain
            .char_indices()
            .any(|(i, c)| c == '.' && i > 0 && i.saturating_add(1) < domain.len())
}

pub use super::schema::config_name_ok as is_config_name;

/// A host name for IMAP/SMTP: letters, digits, `.`, `-` (or an IPv4/IPv6
/// literal's characters), at most 253.
fn is_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

/// Which service reads and sends a mailbox's mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailBackendKind {
    /// The Gmail API, logged in as a `platforms.google.accounts` entry.
    Gmail,
    /// IMAP (implicit TLS) to read, SMTP (implicit TLS on 465, else
    /// mandatory STARTTLS) to send.
    Imap,
}

/// A mailbox the broker reads and sends from: where SimpleLogin forwards,
/// or one an agent may be given filtered access to itself (`direct`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxConfig {
    pub address: String,
    pub backend: MailBackendKind,
    /// gmail: which `platforms.google.accounts` entry logs in (it needs
    /// `gmail.readonly`, and `gmail.send` to send).
    #[serde(default)]
    pub google_account: Option<String>,
    #[serde(default)]
    pub imap_host: String,
    #[serde(default = "imap_port")]
    pub imap_port: u16,
    #[serde(default)]
    pub smtp_host: String,
    /// 465: SMTPS (implicit TLS); any other port: STARTTLS, required.
    #[serde(default = "smtp_port")]
    pub smtp_port: u16,
    /// Default: the address.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password_file: String,
    /// The folders read (IMAP); Gmail leaves out spam and trash.
    #[serde(default = "inbox")]
    pub folders: Vec<String>,
    /// May an agent be granted this mailbox itself, limited to the
    /// correspondents its grant names? Always a human's call when on.
    #[serde(default)]
    pub direct: bool,
    /// The authserv-id of the mailbox provider's own
    /// Authentication-Results (`mx.google.com` for Gmail, the default
    /// there). Only its results count; unset on IMAP: no sender is ever
    /// verified, so mailbox grants hold every message for the operator.
    #[serde(default)]
    pub authserv_id: Option<String>,
    /// IMAP folders holding the mailbox's own sent mail: a message there
    /// "from" the mailbox is taken as the mailbox's own.
    #[serde(default = "sent_folders")]
    pub sent_folders: Vec<String>,
}

fn imap_port() -> u16 {
    993
}
fn smtp_port() -> u16 {
    465
}
fn inbox() -> Vec<String> {
    vec!["INBOX".to_owned()]
}
fn sent_folders() -> Vec<String> {
    ["Sent", "Sent Items", "Sent Messages", "[Gmail]/Sent Mail"]
        .map(String::from)
        .to_vec()
}

impl MailboxConfig {
    fn validate(&mut self, name: &str) -> Result<(), String> {
        if !loose_address(&self.address) {
            return Err(format!(
                "mailbox address {} is not an email address",
                repr(&self.address)
            ));
        }
        self.address = self.address.to_lowercase();
        match self.backend {
            MailBackendKind::Gmail => {
                if self.google_account.as_deref().is_none_or(str::is_empty) {
                    return Err(format!(
                        "mailbox {}: backend gmail needs google_account",
                        self.address
                    ));
                }
            }
            MailBackendKind::Imap => {
                if self.imap_host.is_empty()
                    || self.smtp_host.is_empty()
                    || self.password_file.is_empty()
                {
                    return Err(format!(
                        "mailbox {}: backend imap needs imap_host, smtp_host and password_file",
                        self.address
                    ));
                }
                if !is_host(&self.imap_host) || !is_host(&self.smtp_host) {
                    return Err(format!(
                        "mailbox {name}: imap_host and smtp_host are host names"
                    ));
                }
            }
        }
        if self.folders.is_empty()
            || self
                .folders
                .iter()
                .any(|f| f.is_empty() || f.chars().count() > 255 || f.chars().any(char::is_control))
        {
            return Err(format!(
                "mailbox {name}: folders are 1 to 255 characters, without control characters"
            ));
        }
        if let Some(u) = &self.username
            && (u.is_empty() || u.len() > 320 || u.chars().any(char::is_control))
        {
            return Err(format!("mailbox {name}: username"));
        }
        Ok(())
    }

    /// The provider's authserv-id: the configured one, else Gmail's.
    #[must_use]
    pub fn authserv(&self) -> Option<String> {
        match (&self.authserv_id, self.backend) {
            (Some(a), _) if !a.trim().is_empty() => Some(a.trim().to_lowercase()),
            (_, MailBackendKind::Gmail) => Some("mx.google.com".to_owned()),
            _ => None,
        }
    }

    /// Who logs in: the username, or the address.
    #[must_use]
    pub fn login(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.address)
    }
}

/// SimpleLogin: its API for aliases and reverse aliases; the mail itself is
/// read in, and sent from, `mailbox`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SimpleLoginConfig {
    /// `https://`, or `http://` to a loopback host (tests).
    pub api_url: String,
    pub api_key_file: String,
    /// A key of `platforms.mail.mailboxes`.
    pub mailbox: String,
    /// Aliases (globs, lowercased) agents may be granted. An alias must
    /// also exist in the account and forward to `mailbox`.
    pub aliases: Vec<String>,
    /// Domains where agents may create new aliases; empty: no creating.
    pub create_domains: Vec<String>,
    /// Who signs SimpleLogin's forwards (DKIM `d=`), besides the alias's
    /// own domain: its `X-SimpleLogin-*` headers count only on a message
    /// the provider saw a DKIM pass for from one of these.
    pub dkim_domains: Vec<String>,
}

impl Default for SimpleLoginConfig {
    fn default() -> Self {
        SimpleLoginConfig {
            api_url: "https://app.simplelogin.io".to_owned(),
            api_key_file: String::new(),
            mailbox: String::new(),
            aliases: vec!["*".to_owned()],
            create_domains: Vec::new(),
            dkim_domains: vec!["simplelogin.co".to_owned()],
        }
    }
}

/// `https://`, or `http://` to a loopback host.
#[must_use]
pub fn api_url_ok(url: &str) -> bool {
    if url.starts_with("https://") && url.len() > "https://".len() {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };
    matches!(host, "127.0.0.1" | "localhost" | "[::1]")
}

/// Constraints on every grant for the addresses it matches, on top of what
/// the grant itself says (both must hold).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailRestriction {
    /// A glob (lowercased).
    pub address: String,
    /// What mail on it may be about, judged per message by a model.
    #[serde(default)]
    pub topic: Option<String>,
    /// Whom it may be with (globs, lowercased); a grant may name fewer.
    #[serde(default)]
    pub correspondents: Vec<String>,
    /// What may be granted on it at all; None: anything.
    #[serde(default)]
    pub capabilities: Option<Vec<MailAction>>,
}

impl<'de> Deserialize<'de> for MailAction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        MailAction::parse(&s).ok_or_else(|| {
            serde::de::Error::custom("one of ['create', 'read', 'read+send', 'send']")
        })
    }
}

/// A message the judge thinks is a prompt injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectionMode {
    /// Held for the operator, who may release it.
    #[default]
    Withhold,
    /// Delivered, marked.
    Flag,
}

/// A message whose topic the judge can't place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnclearMode {
    /// Held for the operator.
    #[default]
    Hold,
    /// Withheld as out of scope.
    Withhold,
}

/// What is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SendReview {
    /// The judge sends, holds for the operator, or refuses.
    #[default]
    Llm,
    /// Every message is held for the operator.
    Human,
}

/// The largest message the gateway reads (`MAX_RAW_BYTES`).
pub const MAX_RAW_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MailConfig {
    pub mailboxes: BTreeMap<String, MailboxConfig>,
    pub simplelogin: Option<SimpleLoginConfig>,
    pub restrictions: Vec<MailRestriction>,
    /// The judge's model. Default: `llm.model`.
    pub judge_model: Option<String>,
    pub injection: InjectionMode,
    pub unclear: UnclearMode,
    pub send_review: SendReview,
    /// What an agent may read of a message (and what the judge reads).
    pub max_body_chars: u32,
    pub max_attachment_bytes: u32,
}

impl Default for MailConfig {
    fn default() -> Self {
        MailConfig {
            mailboxes: BTreeMap::new(),
            simplelogin: None,
            restrictions: Vec::new(),
            judge_model: None,
            injection: InjectionMode::Withhold,
            unclear: UnclearMode::Hold,
            send_review: SendReview::Llm,
            max_body_chars: 20_000,
            max_attachment_bytes: 10 * 1024 * 1024,
        }
    }
}

/// The restriction entries matching an address, in policy order.
impl MailConfig {
    #[must_use]
    pub fn restrictions_for(&self, address: &str) -> Vec<&MailRestriction> {
        let address = address.to_lowercase();
        self.restrictions
            .iter()
            .filter(|r| crate::glob::fnmatch(&address, &r.address))
            .collect()
    }

    /// The name of the mailbox with this address.
    #[must_use]
    pub fn mailbox_for(&self, address: &str) -> Option<(&str, &MailboxConfig)> {
        let address = address.to_lowercase();
        self.mailboxes
            .iter()
            .find(|(_, b)| b.address == address)
            .map(|(n, b)| (n.as_str(), b))
    }

    /// Is mail configured at all?
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.mailboxes.is_empty()
    }

    /// `_references` plus normalization (lowercased globs and domains).
    pub(crate) fn validate(&mut self) -> Result<(), String> {
        for (name, box_) in &mut self.mailboxes {
            if !is_config_name(name) {
                return Err(format!(
                    "mailbox name {}: lowercase letters, digits, - and _",
                    repr(name)
                ));
            }
            box_.validate(name)?;
        }
        if let Some(sl) = &mut self.simplelogin {
            if !self.mailboxes.contains_key(&sl.mailbox) {
                return Err(format!(
                    "platforms.mail.simplelogin.mailbox {} is not under platforms.mail.mailboxes",
                    repr(&sl.mailbox)
                ));
            }
            if !api_url_ok(&sl.api_url) {
                return Err(
                    "platforms.mail.simplelogin.api_url: an https URL (plain http only to a loopback host)"
                        .to_owned(),
                );
            }
            sl.aliases = sl.aliases.iter().map(|g| g.to_lowercase()).collect();
            sl.create_domains = sl.create_domains.iter().map(|d| d.to_lowercase()).collect();
            sl.dkim_domains = sl.dkim_domains.iter().map(|d| d.to_lowercase()).collect();
            if let Some(bad) = sl
                .create_domains
                .iter()
                .find(|d| !crate::mail::is_address(&format!("x@{d}")))
            {
                return Err(format!(
                    "platforms.mail.simplelogin.create_domains: {} is not a domain",
                    repr(bad)
                ));
            }
        }
        for (i, r) in self.restrictions.iter_mut().enumerate() {
            r.address = r.address.to_lowercase();
            r.correspondents = r.correspondents.iter().map(|g| g.to_lowercase()).collect();
            if let Some(t) = &r.topic
                && t.chars().count() > crate::mail::MAX_TOPIC
            {
                return Err(format!(
                    "platforms.mail.restrictions[{i}].topic: at most {} characters",
                    crate::mail::MAX_TOPIC
                ));
            }
        }
        if self.max_body_chars == 0 {
            return Err("platforms.mail.max_body_chars: at least 1".to_owned());
        }
        Ok(())
    }

    /// Does a restriction on `address` refuse `action`? The first that
    /// does (`validate_request`).
    #[must_use]
    pub fn refusing_restriction(
        &self,
        address: &str,
        action: MailAction,
    ) -> Option<&MailRestriction> {
        self.restrictions_for(address).into_iter().find(|r| {
            r.capabilities
                .as_ref()
                .is_some_and(|c| !c.contains(&action))
        })
    }

    /// Sensitivity: the mailboxes' own addresses.
    #[must_use]
    pub fn mailbox_addresses(&self) -> std::collections::BTreeSet<String> {
        self.mailboxes.values().map(|b| b.address.clone()).collect()
    }
}

/// What reads and sends on an address now: the grant's actions narrowed by
/// every restriction on it (as the policy reads now, not when granted).
#[must_use]
pub fn allowed_ops(
    config: &MailConfig,
    address: &str,
    authority: &MailAuthority,
) -> crate::mail::Ops {
    let mut ops = authority.action.ops();
    for r in config.restrictions_for(address) {
        if let Some(caps) = &r.capabilities {
            let allowed = caps
                .iter()
                .fold(crate::mail::Ops::NONE, |acc, a| acc.union(a.ops()));
            ops = ops.intersect(allowed);
        }
    }
    ops
}

/// `PlatformsConfig._cross`: a gmail mailbox's account must exist.
pub(crate) fn cross_check(
    mail: &MailConfig,
    google: &super::schema::GoogleConfig,
) -> Result<(), String> {
    for (name, b) in &mail.mailboxes {
        if b.backend == MailBackendKind::Gmail
            && !b
                .google_account
                .as_ref()
                .is_some_and(|a| google.accounts.contains_key(a))
        {
            return Err(format!(
                "platforms.mail.mailboxes.{name}.google_account {} is not under platforms.google.accounts",
                repr(b.google_account.as_deref().unwrap_or(""))
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn addresses_and_names() {
        assert!(loose_address("me@gmail.com"));
        assert!(!loose_address("me@gmail"));
        assert!(!loose_address("me @gmail.com"));
        assert!(!loose_address("a@b@c.com"));
        assert!(is_config_name("main"));
        assert!(!is_config_name("Main"));
        assert!(!is_config_name("-x"));
        assert!(api_url_ok("https://app.simplelogin.io"));
        assert!(api_url_ok("http://127.0.0.1:8080"));
        assert!(!api_url_ok("http://sl.example"));
        assert!(!api_url_ok("http://127.0.0.1.evil.example"));
    }
}
