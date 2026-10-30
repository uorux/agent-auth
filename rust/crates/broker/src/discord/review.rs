//! Saying a model's decision was wrong, from Discord: the Wrong call
//! button on a message that reports one (a guard's refusal, a watcher's
//! alert, a scope check, the LLM reviewer's approval), and `/review`, the
//! latest decisions that went against an agent or called the owner (an
//! LLM denial never reaches Discord on its own).
//!
//! Either way the owner says what it should have been, and the decision
//! is labelled in the eval set (`crate::models`, an operator's label), to
//! replay prompts and models against. A label changes nothing that was
//! decided. Sealed decisions (mail) show no reason here.

use agent_auth_store::evals::{self, CallRow, Selection};
use serde_json::Value;
use time::OffsetDateTime;
use twilight_model::channel::message::Component;
use twilight_model::channel::message::component::ButtonStyle;
use uuid::Uuid;

use super::Bot;
use super::interactions::{Failure, Reply};
use super::model::{EPHEMERAL, Message, button, discord_time, row};
use super::text::{code, cut, said};
use super::views::{self, CustomId, Refusal, Submitted};
use crate::auth::HumanDecider;
use crate::models::{self, Kind};

/// Recorded decisions are kept for `evals.retention` (unless labelled).
pub const GONE: &str =
    "That decision is no longer kept (recorded decisions go after evals.retention).";
/// How many decisions `/review` shows (one button each, in one row).
pub const SHOWN: usize = 5;
/// How many recent decisions `/review` looks through.
const LOOK_BACK: i64 = 200;

async fn load(bot: &Bot, call: Uuid) -> Result<Option<(CallRow, Kind)>, Failure> {
    let tx = bot.store.begin().await?;
    let row = evals::get_call(&tx, call).await?;
    tx.commit().await?;
    Ok(row.and_then(|r| Kind::parse(&r.kind).map(|k| (r, k))))
}

/// The Wrong call button: the modal, prefilled with the likely answer.
pub(super) async fn wrong_call(bot: &Bot, reply: &Reply<'_>, call: Uuid) -> Result<(), Failure> {
    match load(bot, call).await? {
        None => reply.ephemeral(GONE).await?,
        Some((row, kind)) => {
            reply
                .modal(&views::wrong_call_modal(call, kind, row.class.as_deref()))
                .await?;
        }
    }
    Ok(())
}

/// The Wrong call modal, submitted: label the decision.
pub(super) async fn wrong_call_submit(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    call: Uuid,
    form: &Submitted,
) -> Result<(), Failure> {
    reply.defer().await?;
    let Some((row, kind)) = load(bot, call).await? else {
        reply.followup(GONE).await?;
        return Ok(());
    };
    let (expected, note) = match views::read_wrong_call(kind, form) {
        Ok(read) => read,
        Err(Refusal(text)) => {
            reply.followup(&text).await?;
            return Ok(());
        }
    };
    let tx = bot.store.begin().await?;
    let labelled = evals::set_label(
        &tx,
        call,
        &expected,
        &note,
        "operator",
        who.label(),
        OffsetDateTime::now_utc(),
    )
    .await?;
    tx.commit().await?;
    if !labelled {
        reply.followup(GONE).await?;
        return Ok(());
    }
    tracing::info!(call = %call, kind = kind.as_str(), expected, by = who.label(), "decision labelled from Discord");
    let msg = Message {
        components: Some(views::unlabel_view(call)),
        ..Message::ephemeral(labelled_text(kind, row.class.as_deref(), &expected))
    };
    reply.followup_message(&msg).await?;
    Ok(())
}

/// What the owner is told once a decision is labelled.
#[must_use]
pub fn labelled_text(kind: Kind, class: Option<&str>, expected: &str) -> String {
    let said_class = class.map_or_else(|| "nothing usable".to_owned(), |c| format!("**{c}**"));
    format!(
        "Noted: the {} said {said_class}; it should have been **{}**. It is in the eval set: \
         `agent-auth admin evals calls --kind {} --labeled`, then `replay` to try a prompt or \
         model against it.",
        models::kind_title(kind),
        code(expected),
        kind.as_str()
    )
}

/// Undo: the label goes (the decision itself never changed).
pub(super) async fn unlabel(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    call: Uuid,
) -> Result<(), Failure> {
    let tx = bot.store.begin().await?;
    let removed = evals::delete_label(&tx, call).await?;
    tx.commit().await?;
    if removed {
        tracing::info!(call = %call, by = who.label(), "label removed from Discord");
    }
    let msg = Message {
        components: Some(Vec::new()),
        ..Message::ephemeral(if removed {
            "Label removed."
        } else {
            "It had no label."
        })
    };
    reply.update(&msg).await?;
    Ok(())
}

/// `/review [kind] [everything]`: the latest decisions not yet labelled by
/// the owner, each with its Wrong call button.
pub(super) async fn command(
    bot: &Bot,
    reply: &Reply<'_>,
    kind: Option<&str>,
    everything: bool,
) -> Result<(), Failure> {
    let kind = match kind.map(|k| (k, Kind::parse(k))) {
        None => None,
        Some((_, Some(k))) => Some(k),
        Some((k, None)) => {
            reply
                .ephemeral(&format!("No decision kind `{}`.", cut(&code(k), 40)))
                .await?;
            return Ok(());
        }
    };
    let tx = bot.store.begin().await?;
    let recent = evals::list_calls(
        &tx,
        &Selection {
            kind: kind.map(|k| k.as_str().to_owned()),
            limit: LOOK_BACK,
            ..Selection::default()
        },
    )
    .await?;
    tx.commit().await?;
    let shown = to_review(recent, everything);
    let mut msg = review_message(&shown, kind, everything);
    msg.flags = Some(EPHEMERAL);
    reply.message(&msg).await?;
    Ok(())
}

/// Of `recent` (newest first): those the owner has not labelled, that
/// went against an agent or called the owner (or all, `everything`), at
/// most [`SHOWN`].
#[must_use]
pub fn to_review(recent: Vec<CallRow>, everything: bool) -> Vec<(CallRow, Kind)> {
    recent
        .into_iter()
        .filter(|c| c.label.as_ref().is_none_or(|l| l.source != "operator"))
        .filter_map(|c| Kind::parse(&c.kind).map(|k| (c, k)))
        .filter(|(c, k)| {
            c.class
                .as_deref()
                .is_some_and(|class| everything || models::adverse(*k, class))
        })
        .take(SHOWN)
        .collect()
}

/// What a call was about, shortly: its request, mail item, job or grant.
fn about(subject: &Value) -> String {
    for (key, name) in [
        ("request_id", "request"),
        ("item_id", "mail"),
        ("job_id", "job"),
        ("grant_id", "grant"),
    ] {
        if let Some(id) = subject.get(key).and_then(Value::as_str) {
            return format!(" · {name} `{}`", cut(&code(id), 8));
        }
    }
    String::new()
}

/// `/review`'s answer.
#[must_use]
pub fn review_message(shown: &[(CallRow, Kind)], kind: Option<Kind>, everything: bool) -> Message {
    if shown.is_empty() {
        let what = kind.map_or("model", models::kind_title);
        let text = if everything {
            format!("Nothing to review: no recent {what} decision is unlabelled.")
        } else {
            format!(
                "Nothing to review: no recent {what} decision went against anyone \
                 (`everything:True` shows the rest)."
            )
        };
        return Message::text(text);
    }
    let mut lines = vec![
        "Recent decisions; **Wrong #n** says what one should have been (an eval label: \
         nothing decided changes)."
            .to_owned(),
    ];
    let mut buttons: Vec<Component> = Vec::new();
    for (n, (c, k)) in (1..).zip(shown) {
        let class = c.class.as_deref().unwrap_or("?");
        let mut line = format!(
            "**#{n}** {} · the {} said **{}**{}",
            discord_time(c.created_at, 'R'),
            models::kind_title(*k),
            code(class),
            about(&c.subject)
        );
        if let Some(l) = c.label.as_ref() {
            line.push_str(&format!(" (what happened next: {})", code(&l.expected)));
        }
        // A sealed kind's answer stays sealed: no reason shown.
        let reason = (!models::recipe(*k).sealed)
            .then(|| c.answer.as_ref().and_then(models::reason_of))
            .flatten();
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            line.push_str(&format!("\n> {}", said(&r, 250)));
        }
        lines.push(line);
        buttons.push(button(
            &format!("Wrong #{n}"),
            ButtonStyle::Secondary,
            CustomId::WrongCall(c.id).render(),
            false,
        ));
    }
    Message {
        components: Some(vec![row(buttons)]),
        ..Message::text(cut(&lines.join("\n"), 2000))
    }
}
