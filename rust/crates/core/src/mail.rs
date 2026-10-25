//! Platform "mail": the privilege a mail grant conveys (`authority.py` fold
//! for MAIL, `provisioners/mail.py` `_scope`), and the pure address checks
//! the gateway shares (`mail/gateway.py` ADDRESS_RE, GLOB_RE;
//! `mail/simplelogin.py` PREFIX_RE; `mail/backends.py` server_term).
//!
//! A mail grant is for one address (the resource): what may be done on it
//! (read, send, both, or create a new alias and then both), and what the
//! mail may be about (`topic`), with whom (`correspondents`, address
//! globs) and from when (`since`). Every field narrows; [`MailAuthority::covers`]
//! is the rule-pinning relation (`_mail_covers`).

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use time::Date;
use time::macros::format_description;

use crate::authority::AuthorityError;
use crate::pyfmt::repr;

/// Longest topic, in characters (`MAX_TOPIC`).
pub const MAX_TOPIC: usize = 1000;
/// Most correspondents in one grant (`MAX_CORRESPONDENTS`).
pub const MAX_CORRESPONDENTS: usize = 32;
/// Longest correspondent glob or address, in bytes (an address is at most
/// 320 characters; the Python had no bound on a glob).
pub const MAX_GLOB_LEN: usize = 320;

/// What a mail grant allows on its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailAction {
    Read,
    Send,
    ReadSend,
    /// Create a new SimpleLogin alias (the resource is its domain), then
    /// read and send on it.
    Create,
}

impl MailAction {
    pub const ALL: [MailAction; 4] = [
        MailAction::Read,
        MailAction::Send,
        MailAction::ReadSend,
        MailAction::Create,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MailAction::Read => "read",
            MailAction::Send => "send",
            MailAction::ReadSend => "read+send",
            MailAction::Create => "create",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<MailAction> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// May mail be read under it? (`create` reads and sends on its alias.)
    #[must_use]
    pub const fn reads(self) -> bool {
        !matches!(self, MailAction::Send)
    }

    /// May mail be sent under it?
    #[must_use]
    pub const fn sends(self) -> bool {
        !matches!(self, MailAction::Read)
    }

    /// The operations a request for it may need (`_MAIL_ACTIONS`, without
    /// create, which is compared by itself).
    #[must_use]
    pub const fn ops(self) -> Ops {
        Ops {
            read: self.reads(),
            send: self.sends(),
        }
    }
}

/// Reading and sending, as a set of two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ops {
    pub read: bool,
    pub send: bool,
}

impl Ops {
    pub const NONE: Ops = Ops {
        read: false,
        send: false,
    };

    #[must_use]
    pub const fn is_subset(self, of: Ops) -> bool {
        (!self.read || of.read) && (!self.send || of.send)
    }

    #[must_use]
    pub const fn intersect(self, other: Ops) -> Ops {
        Ops {
            read: self.read && other.read,
            send: self.send && other.send,
        }
    }

    #[must_use]
    pub const fn union(self, other: Ops) -> Ops {
        Ops {
            read: self.read || other.read,
            send: self.send || other.send,
        }
    }
}

/// The privilege of a mail grant (the Python's folded dict).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MailAuthority {
    pub action: MailAction,
    /// What the mail may be about (judged per message). One line, at most
    /// [`MAX_TOPIC`] characters, whitespace collapsed.
    pub topic: Option<String>,
    /// Address globs, lowercased, sorted, distinct; empty = anyone.
    pub correspondents: BTreeSet<String>,
    /// Mail dated before this day is never shown.
    pub since: Option<Date>,
    /// `create` only: the new alias's local part (None: the broker picks).
    pub prefix: Option<String>,
}

const DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]");

/// A date as `YYYY-MM-DD`.
#[must_use]
pub fn format_date(d: Date) -> String {
    d.format(DATE_FORMAT).unwrap_or_default()
}

/// `YYYY-MM-DD` exactly (the Python's `date.fromisoformat` also took
/// `20260101` and ISO week dates).
#[must_use]
pub fn parse_date(s: &str) -> Option<Date> {
    if s.len() != 10 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return None;
    }
    Date::parse(s, DATE_FORMAT).ok()
}

fn err<T>(msg: impl Into<String>) -> Result<T, AuthorityError> {
    Err(AuthorityError(msg.into()))
}

/// A Python list repr of strings: `['a', 'b']`.
#[must_use]
pub fn repr_list<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| repr(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

impl MailAuthority {
    /// The request's `(capability, scope)`, checked as the Python's
    /// `validate_request` and `_scope` did, normalized as `fold` stored it.
    pub fn from_wire(
        capability: &str,
        scope: &Map<String, Value>,
    ) -> Result<MailAuthority, AuthorityError> {
        let Some(action) = MailAction::parse(capability) else {
            return err("mail capability is one of read, send, read+send, create");
        };
        let mut allowed = vec!["correspondents", "since", "topic"];
        if action == MailAction::Create {
            allowed.push("prefix");
            allowed.sort_unstable();
        }
        let mut extra: Vec<&str> = scope
            .keys()
            .map(String::as_str)
            .filter(|k| !allowed.contains(k))
            .collect();
        if !extra.is_empty() {
            extra.sort_unstable();
            return err(format!(
                "unknown mail scope key(s) {}; a mail scope has {}",
                repr_list(&extra),
                repr_list(&allowed)
            ));
        }
        let topic = match scope.get("topic") {
            None | Some(Value::Null) => None,
            Some(Value::String(t)) if !t.trim().is_empty() && t.chars().count() <= MAX_TOPIC => {
                Some(t.split_whitespace().collect::<Vec<_>>().join(" "))
            }
            Some(_) => {
                return err(format!(
                    "topic is a sentence of at most {MAX_TOPIC} characters"
                ));
            }
        };
        let correspondents = match scope.get("correspondents") {
            None | Some(Value::Null) => BTreeSet::new(),
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_CORRESPONDENTS => {
                let mut norm = BTreeSet::new();
                let mut bad = BTreeSet::new();
                for item in items {
                    let text = match item {
                        Value::String(s) => s.trim().to_lowercase(),
                        other => other.to_string(),
                    };
                    if item.is_string() && is_glob(&text) {
                        norm.insert(text);
                    } else {
                        bad.insert(text);
                    }
                }
                if !bad.is_empty() {
                    let bad: Vec<String> = bad.into_iter().collect();
                    return err(format!(
                        "not an address or address glob (like *@example.com): {}",
                        repr_list(&bad)
                    ));
                }
                norm
            }
            Some(_) => {
                return err(format!(
                    "correspondents is a list of 1 to {MAX_CORRESPONDENTS} address globs"
                ));
            }
        };
        let since = match scope.get("since") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => match parse_date(s) {
                Some(d) => Some(d),
                None => return err("since is a date, YYYY-MM-DD"),
            },
            Some(_) => return err("since is a date, YYYY-MM-DD"),
        };
        let prefix = match scope.get("prefix") {
            None | Some(Value::Null) => None,
            Some(Value::String(p)) if is_prefix(&p.to_lowercase()) => Some(p.to_lowercase()),
            Some(_) => {
                return err(
                    "prefix: 1-40 lowercase letters, digits, . _ - (starting with a letter or digit)",
                );
            }
        };
        Ok(MailAuthority {
            action,
            topic,
            correspondents,
            since,
            prefix,
        })
    }

    /// The wire scope (`split`): only the fields that are set.
    #[must_use]
    pub fn scope(&self) -> Map<String, Value> {
        let mut out = Map::new();
        if let Some(t) = &self.topic {
            out.insert("topic".into(), json!(t));
        }
        if !self.correspondents.is_empty() {
            out.insert("correspondents".into(), json!(self.correspondents));
        }
        if let Some(d) = self.since {
            out.insert("since".into(), json!(format_date(d)));
        }
        if let Some(p) = &self.prefix {
            out.insert("prefix".into(), json!(p));
        }
        out
    }

    /// The stored form (`fold`): every key, nulls included; `prefix` only
    /// for create.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("action".into(), json!(self.action.as_str()));
        out.insert("topic".into(), json!(self.topic));
        out.insert("correspondents".into(), json!(self.correspondents));
        out.insert("since".into(), json!(self.since.map(format_date)));
        if self.action == MailAction::Create {
            out.insert("prefix".into(), json!(self.prefix));
        }
        Value::Object(out)
    }

    /// Inverse of [`MailAuthority::to_json`]; the caller checks the round
    /// trip.
    pub fn from_json(map: &Map<String, Value>) -> Result<MailAuthority, AuthorityError> {
        let action = map
            .get("action")
            .and_then(Value::as_str)
            .and_then(MailAction::parse)
            .ok_or_else(|| AuthorityError("stored mail action".into()))?;
        let text = |key: &str| -> Result<Option<String>, AuthorityError> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => err(format!("stored mail {key}")),
            }
        };
        let correspondents = match map.get("correspondents") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| AuthorityError("stored mail correspondents".into()))
                })
                .collect::<Result<BTreeSet<String>, _>>()?,
            _ => return err("stored mail correspondents"),
        };
        let since = match text("since")? {
            None => None,
            Some(s) => {
                Some(parse_date(&s).ok_or_else(|| AuthorityError("stored mail since".into()))?)
            }
        };
        Ok(MailAuthority {
            action,
            topic: text("topic")?,
            correspondents,
            since,
            prefix: text("prefix")?,
        })
    }

    /// `label` for mail: `read`, `read:with *@x.com`, `send:topic`...
    #[must_use]
    pub fn label(&self) -> String {
        let mut bits = vec![self.action.as_str().to_owned()];
        if !self.correspondents.is_empty() {
            bits.push(format!(
                "with {}",
                self.correspondents
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if self.topic.is_some() {
            bits.push("topic".to_owned());
        }
        bits.join(":")
    }

    /// Sending (create included: from a new alias on the person's own
    /// domain) with neither a topic nor correspondents to keep it in.
    #[must_use]
    pub fn sends_unconstrained(&self) -> bool {
        self.action.sends() && self.topic.is_none() && self.correspondents.is_empty()
    }

    /// `_mail_covers`: does a rule pinned to `self` cover `request`? It does
    /// when the request asks for no more: actions it includes, its topic (or
    /// a rule with none), correspondents among its own (or a rule with
    /// none), from its `since` on (or a rule with none). `create` is only
    /// ever covered by a create rule with the same prefix.
    #[must_use]
    pub fn covers(&self, request: &MailAuthority) -> bool {
        covers_by(
            &self.view(),
            &request.view(),
            !request.correspondents.is_empty()
                && request.correspondents.is_subset(&self.correspondents),
        )
    }

    fn view(&self) -> Covering<'_, String, time::Date> {
        Covering {
            action: self.action,
            prefix: self.prefix.as_ref(),
            topic: self.topic.as_ref(),
            correspondents: !self.correspondents.is_empty(),
            since: self.since,
        }
    }
}

/// What coverage compares of an authority, generic over the values (so the
/// decision itself is model-checked with small ones: `proofs_mail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Covering<'a, T, D> {
    pub action: MailAction,
    pub prefix: Option<&'a T>,
    pub topic: Option<&'a T>,
    /// Names any correspondents.
    pub correspondents: bool,
    pub since: Option<D>,
}

/// `_mail_covers` on the compared parts; `nonempty_subset`: the request
/// names correspondents, all among the rule's.
pub(crate) fn covers_by<T: PartialEq, D: PartialOrd + Copy>(
    rule: &Covering<'_, T, D>,
    request: &Covering<'_, T, D>,
    nonempty_subset: bool,
) -> bool {
    let rule_creates = rule.action == MailAction::Create;
    if rule_creates != (request.action == MailAction::Create) {
        return false;
    }
    if rule_creates {
        if rule.prefix != request.prefix {
            return false;
        }
    } else if !request.action.ops().is_subset(rule.action.ops()) {
        return false;
    }
    if let Some(topic) = rule.topic
        && request.topic != Some(topic)
    {
        return false;
    }
    if rule.correspondents && !nonempty_subset {
        return false;
    }
    if let Some(since) = rule.since
        && request.since.is_none_or(|s| s < since)
    {
        return false;
    }
    true
}

// ------------------------------------------------------------ addresses

fn local_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b)
}

/// `ADDRESS_RE`: a lowercase address with a dotted domain of
/// letter/digit labels (hyphens inside).
#[must_use]
pub fn is_address(s: &str) -> bool {
    if s.len() > MAX_GLOB_LEN {
        return false;
    }
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    if local.is_empty() || !local.bytes().all(local_char) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
            !b.is_empty()
                && b.first().is_some_and(alnum)
                && b.last().is_some_and(alnum)
                && b.iter().all(|c| alnum(c) || *c == b'-')
        })
}

/// `GLOB_RE`: an address glob (`*@example.com`, `bookings@*.airline.com`).
#[must_use]
pub fn is_glob(s: &str) -> bool {
    if s.len() > MAX_GLOB_LEN {
        return false;
    }
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local
            .bytes()
            .all(|b| local_char(b) || b == b'[' || b == b']')
        && !domain.is_empty()
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"*?.[]-".contains(&b))
}

/// `PREFIX_RE`: a new alias's local part.
#[must_use]
pub fn is_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=40).contains(&b.len())
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// `server_term`: what a server-side search can use for a correspondent
/// glob: the exact address, or its domain; None when the glob has no
/// literal domain (then the server is not asked to narrow by it).
#[must_use]
pub fn server_term(glob: &str) -> Option<String> {
    let glob = glob.trim().to_lowercase();
    let (local, domain) = glob.rsplit_once('@')?;
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    let wild = |s: &str| s.contains(['*', '?', '[', ']']);
    if wild(domain) || !domain.contains('.') {
        return None;
    }
    Some(if wild(local) {
        domain.to_owned()
    } else {
        glob.clone()
    })
}

/// `matches_any`: does `address` (lowercased) match one of the globs?
#[must_use]
pub fn matches_any<S: AsRef<str>>(address: &str, globs: &[S]) -> bool {
    let address = address.to_lowercase();
    globs
        .iter()
        .any(|g| crate::glob::fnmatch(&address, &g.as_ref().to_lowercase()))
}

/// The domain of an address (after the last `@`), lowercased.
#[must_use]
pub fn domain_of(address: &str) -> Option<String> {
    address.rsplit_once('@').map(|(_, d)| d.to_lowercase())
}

#[cfg(test)]
mod tests;
