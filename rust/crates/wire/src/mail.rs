//! The mail gateway (`/v1/mail/{grant}/*`, `/admin/mail/*`; upstream
//! `api/mail_routes.py`, `mail/gateway.py`). Field order is the Python
//! dicts'.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::text::{BoundedVec, Text};

/// The longest body an agent may send (`MAX_SEND_BODY`).
pub const MAX_SEND_BODY: usize = 50_000;

/// `POST /v1/mail/{grant}/send`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendBody {
    #[serde(default)]
    pub to: Option<BoundedVec<Text<0, 320>, 0, 10>>,
    #[serde(default)]
    pub subject: Option<Text<0, 300>>,
    pub body: Text<1, MAX_SEND_BODY>,
    /// A message id from mail_list to answer: its sender, subject and
    /// thread.
    #[serde(default)]
    pub reply_to: Option<Text<0, 36>>,
}

/// `POST /admin/mail/items/{id}/release|discard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideBody {
    #[serde(default = "admin")]
    pub by: Text<0, 128>,
}

fn admin() -> Text<0, 128> {
    Text::new("admin").unwrap_or_default()
}

impl Default for DecideBody {
    fn default() -> Self {
        DecideBody { by: admin() }
    }
}

/// A message the agent may see, in a listing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listing {
    pub id: String,
    pub status: String,
    pub thread: Option<String>,
    pub date: Option<String>,
    pub from: Option<String>,
    pub from_name: Option<String>,
    pub subject: Option<String>,
    pub snippet: Option<String>,
    pub attachments: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<String>,
}

/// A message the screen could not judge yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unscreened {
    pub id: String,
    pub status: String,
    pub why: String,
}

/// A message held for the operator: no content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldEntry {
    pub id: String,
    pub status: String,
    pub date: Option<String>,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Listed {
    Shown(Listing),
    Unscreened(Unscreened),
    Held(HeldEntry),
}

/// `GET /v1/mail/{grant}/messages`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MailList {
    pub address: String,
    pub messages: Vec<Listed>,
    /// None while searching (counts would say what hidden mail contains).
    pub withheld_out_of_scope: Option<u64>,
    pub held_for_operator: Option<u64>,
    pub next_page: Option<String>,
    pub notice: String,
}

/// An attachment, by index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub index: u64,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
}

/// `GET /v1/mail/{grant}/messages/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MailMessage {
    pub id: String,
    pub status: String,
    pub thread: Option<String>,
    pub date: Option<String>,
    pub from: Option<String>,
    pub from_name: Option<String>,
    pub subject: Option<String>,
    pub snippet: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub notice: String,
    pub text: String,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden_text_removed: Option<bool>,
    /// Is `from` verified: a SimpleLogin forward's original sender when
    /// SimpleLogin signed it, else DMARC/DKIM for the From's own domain
    /// (null: the provider said nothing). Alias and mailbox grants.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sender_verified: Option<Option<bool>>,
}

/// `GET /v1/mail/{grant}/messages/{id}/attachments/{index}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailAttachment {
    pub index: u64,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub content_base64: String,
    pub notice: String,
}

/// `POST /v1/mail/{grant}/send`: sent, held, refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendOut {
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// A mail item as the operator sees it (`describe`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MailItem {
    pub id: String,
    pub direction: String,
    pub status: String,
    pub agent: String,
    pub address: String,
    pub grant_id: String,
    pub from: Value,
    pub to: Value,
    pub subject: Value,
    pub date: Value,
    pub verdict: Option<String>,
    pub injection: Option<String>,
    pub reason: String,
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    /// The whole text of a held item: what would be sent, or what the
    /// agent would read and the text hidden from a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl MailItem {
    /// The summary fields of a stored item.
    #[must_use]
    pub fn field(summary: &Map<String, Value>, key: &str) -> Value {
        summary.get(key).cloned().unwrap_or(Value::Null)
    }
}

/// A key that is present (even as null) is `Some`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<bool>>, D::Error> {
    Option::<bool>::deserialize(d).map(Some)
}
