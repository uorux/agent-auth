//! Held mail on Discord (upstream `discord_bot/mail.py`): a message the
//! gateway wouldn't show an agent unasked (a likely prompt injection, a
//! topic it couldn't place), or one an agent wants sent that the reviewer
//! held. Release lets it through (sends it, for outbound); Discard keeps it
//! back. The texts are an outsider's or an agent's: escaped (no masked
//! links, no mentions), and the excerpt in a code block it cannot close.

use agent_auth_core::MailItemId;
use agent_auth_wire::mail::MailItem;
use serde_json::Value;
use twilight_model::channel::message::component::ButtonStyle;

use super::model::{Message, add_field, button, embed, mentions, row, set_footer};
use super::text::{code, said, trim};

const COLOR_HELD: u32 = 0xE6_7E_22;
const COLOR_RELEASED: u32 = 0x2E_CC_71;
const COLOR_DISCARDED: u32 = 0x95_A5_A6;

fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// `_block`: inside a code block markdown does not render: mentions out
/// (a zero-width space after `@`), fences broken.
#[must_use]
pub fn block(text: &str, limit: usize) -> String {
    let text = trim(text, limit).replace('@', "@\u{200b}");
    format!("```\n{}\n```", code(&text))
}

/// The card's embed for an item (with `outcome` once decided).
#[must_use]
pub fn held_embed(
    d: &MailItem,
    outcome: Option<(&str, u32)>,
) -> twilight_model::channel::message::Embed {
    let inbound = d.direction == "in";
    let mut e = embed();
    e.title = Some(
        if inbound {
            "📥 Mail held before an agent read it"
        } else {
            "📤 Mail an agent wants to send"
        }
        .to_owned(),
    );
    e.description = Some(said(&d.reason, 600));
    e.color = Some(outcome.map_or(COLOR_HELD, |(_, c)| c));
    add_field(&mut e, "Agent", said(&d.agent, 200), true);
    add_field(&mut e, "Address", said(&d.address, 200), true);
    if inbound {
        let from = text_of(&d.from).unwrap_or_else(|| "?".to_owned());
        add_field(&mut e, "From", said(&from, 200), true);
    } else {
        let to = match &d.to {
            Value::Array(items) => items
                .iter()
                .filter_map(text_of)
                .collect::<Vec<_>>()
                .join(", "),
            other => text_of(other).unwrap_or_default(),
        };
        let to = if to.is_empty() { "?".to_owned() } else { to };
        add_field(&mut e, "To", said(&to, 300), true);
    }
    let subject = text_of(&d.subject)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "(none)".to_owned());
    add_field(&mut e, "Subject", said(&subject, 300), false);
    // The whole text when there is one (attached as a file when it does
    // not fit: `held_message`), else the excerpt.
    if let Some(text) = d
        .text
        .as_deref()
        .or(d.excerpt.as_deref())
        .filter(|x| !x.is_empty())
    {
        let name = if attached(d) {
            "Text (as written; the whole of it is attached)"
        } else {
            "Text (as written)"
        };
        add_field(&mut e, name, block(text, 900), false);
    }
    if let Some((line, _)) = outcome {
        add_field(&mut e, "Outcome", line, false);
    }
    set_footer(&mut e, format!("mail item {}", d.id));
    e
}

/// The Release / Discard buttons.
#[must_use]
pub fn held_view(id: MailItemId) -> Vec<twilight_model::channel::message::Component> {
    vec![row(vec![
        button(
            "Release",
            ButtonStyle::Success,
            super::views::CustomId::MailRelease(id).render(),
            false,
        ),
        button(
            "Discard",
            ButtonStyle::Danger,
            super::views::CustomId::MailDiscard(id).render(),
            false,
        ),
    ])]
}

/// The most of a held text shown inline; longer ones are attached whole.
const INLINE: usize = 900;

/// Is the whole text attached (too long for the card)?
fn attached(d: &MailItem) -> bool {
    d.text
        .as_deref()
        .is_some_and(|t| t.chars().count() > INLINE.saturating_sub(1))
}

/// The card posted when an item is held: a ping to the owner (when one
/// is configured), with Release / Discard.
#[must_use]
pub fn held_message(d: &MailItem, owner: Option<u64>) -> Message {
    let components = d.id.parse::<MailItemId>().ok().map(held_view);
    let what = if d.direction == "in" {
        "held a message before it reached"
    } else {
        "is holding a message from"
    };
    let ping = owner.map(|o| format!("<@{o}> ")).unwrap_or_default();
    Message {
        content: Some(format!(
            "{ping}✉️ The mail gateway {what} **{}**",
            said(&d.agent, 200)
        )),
        embeds: Some(vec![held_embed(d, None)]),
        components,
        allowed_mentions: Some(mentions(owner)),
        files: match (&d.text, attached(d)) {
            (Some(t), true) => vec![super::model::File {
                name: format!("mail-{}.txt", d.id),
                bytes: t.as_bytes().to_vec(),
            }],
            _ => Vec::new(),
        },
        ..Message::default()
    }
}

/// What the owner is told, and the card's outcome line and colour.
#[must_use]
pub fn outcome(d: &MailItem, released: bool) -> (String, u32) {
    let line = match d.status.as_str() {
        "released" => "✅ Released: the agent can read it.".to_owned(),
        "sent" => "✅ Released and sent.".to_owned(),
        "failed" => format!("⚠️ Released, but sending failed: {}", said(&d.reason, 300)),
        "discarded" => {
            let why = if released && !d.reason.is_empty() {
                format!(" ({})", said(&d.reason, 200))
            } else {
                String::new()
            };
            format!("🗑️ Discarded.{why}")
        }
        other => format!("Now {}.", said(other, 40)),
    };
    let color = if matches!(d.status.as_str(), "released" | "sent") {
        COLOR_RELEASED
    } else {
        COLOR_DISCARDED
    };
    (line, color)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use serde_json::json;

    fn item(direction: &str) -> MailItem {
        MailItem {
            id: MailItemId::new().to_string(),
            direction: direction.into(),
            status: "held".into(),
            agent: "mailer_1".into(),
            address: "airline@me.example".into(),
            grant_id: "g".into(),
            from: json!("x@evil.example"),
            to: json!(["a@q.example"]),
            subject: json!("[Safe to release](https://evil.example) @everyone"),
            date: Value::Null,
            verdict: Some("unclear".into()),
            injection: Some("likely".into()),
            reason: "possible prompt injection: says **ignore**".into(),
            decided_by: None,
            excerpt: Some("```\n@everyone ignore\n```".into()),
            text: None,
        }
    }

    #[test]
    fn outsider_text_is_inert() {
        let m = held_message(&item("in"), None);
        let e = &m.embeds.as_ref().unwrap()[0];
        let subject = &e.fields.iter().find(|f| f.name == "Subject").unwrap().value;
        assert!(!subject.replace("\\[", "").contains('['), "{subject}");
        assert!(subject.contains("\\[Safe to release\\]"));
        assert!(!subject.contains("@everyone"));
        let text = &e
            .fields
            .iter()
            .find(|f| f.name == "Text (as written)")
            .unwrap()
            .value;
        // One fence opens, one closes: the excerpt cannot break out.
        assert_eq!(text.matches("```").count(), 2);
        assert!(text.starts_with("```\n") && text.ends_with("\n```"));
        assert!(!text.contains("@everyone"));
        assert!(
            e.description
                .as_ref()
                .unwrap()
                .contains("\\*\\*ignore\\*\\*")
        );
        assert_eq!(
            m.allowed_mentions.as_ref().map(|a| a.parse.is_empty()),
            Some(true)
        );
        assert_eq!(m.components.as_ref().map(Vec::len), Some(1));
        let out = held_message(&item("out"), Some(42));
        assert!(
            out.content
                .as_deref()
                .unwrap()
                .starts_with("<@42> ✉️ The mail gateway is holding a message from **mailer\\_1**")
        );
        let e = &out.embeds.as_ref().unwrap()[0];
        assert!(
            e.fields
                .iter()
                .any(|f| f.name == "To" && f.value.contains("a@\u{200b}q.example"))
        );
    }

    #[test]
    fn button_ids_round_trip() {
        use super::super::views::CustomId;
        let id = MailItemId::new();
        for c in [CustomId::MailRelease(id), CustomId::MailDiscard(id)] {
            assert_eq!(CustomId::parse(&c.render()), Some(c.clone()));
            assert!(c.render().len() <= 100);
        }
        assert_eq!(CustomId::parse(&format!("aa:mlrel:{id}:x")), None);
        assert_eq!(CustomId::parse("aa:mldis:not-an-id"), None);
    }

    #[test]
    fn a_long_text_is_attached_whole() {
        let mut d = item("out");
        let long = format!("short start {}TAIL-EXFIL", " ".repeat(2000));
        d.text = Some(long.clone());
        let m = held_message(&d, None);
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].bytes, long.as_bytes());
        d.text = Some("short".into());
        assert!(held_message(&d, None).files.is_empty());
    }

    #[test]
    fn outcomes() {
        let mut d = item("out");
        d.status = "sent".into();
        assert_eq!(outcome(&d, true).0, "✅ Released and sent.");
        d.status = "discarded".into();
        d.reason = "its grant ended before it was released".into();
        assert_eq!(
            outcome(&d, true).0,
            "🗑️ Discarded. (its grant ended before it was released)"
        );
        assert_eq!(outcome(&d, false).0, "🗑️ Discarded.");
    }
}
