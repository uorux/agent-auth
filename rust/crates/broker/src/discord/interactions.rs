//! Interactions: buttons, modals, slash commands and autocomplete (spec
//! A.6, A.7).
//!
//! Every interaction first goes through the owner check, which is the only
//! way to a [`DiscordOwner`] (INV-A1, INV-A2: modal submissions included).
//! Anyone else gets the ephemeral refusal and nothing happens (an
//! autocomplete from anyone else gets no choices). What a button acts on
//! comes only from its custom id (INV-A3), and decisions go through the
//! request service ([`RequestOps::decide`]).

use agent_auth_core::{GrantStatus, HumanApproval, RequestId, RuleId};
use agent_auth_store::{StoreError, grants, lockdown, requests, rules as rule_store};
use serde_json::{Map, Value, json};
use twilight_model::application::interaction::application_command::{
    CommandData, CommandOptionValue,
};
use twilight_model::application::interaction::modal::{
    ModalInteractionComponent, ModalInteractionData,
};
use twilight_model::application::interaction::{Interaction, InteractionData, InteractionType};
use twilight_model::user::User;

use super::Bot;
use super::model::{EPHEMERAL, Message, Modal};
use super::ops::{HumanDecision, OpError};
use super::rest::RestError;
use super::rules::{paginate, render};
use super::text::{cut, escape};
use super::views::{self, CustomId, Refusal, Submitted};
use crate::auth::{DiscordOwner, HumanDecider};

/// The refusal for anyone but the owner (verbatim, spec A.3).
pub const NOT_OWNER: &str = "Only the configured owner can decide access requests.";
pub const GONE: &str = "Request no longer exists.";
pub const NO_CONTAINMENT: &str = "Containment is not set up on this broker.";
pub const NOT_READY: &str = "The broker is still starting; try again in a moment.";

/// Answers one interaction.
pub(super) struct Reply<'a> {
    bot: &'a Bot,
    id: u64,
    token: String,
    app: u64,
}

impl Reply<'_> {
    async fn callback(&self, body: Value) -> Result<(), RestError> {
        self.bot.rest.respond(self.id, &self.token, &body).await
    }

    pub(super) async fn ephemeral(&self, text: &str) -> Result<(), RestError> {
        let msg = Message::ephemeral(text);
        self.callback(json!({"type": 4, "data": msg_value(&msg)}))
            .await
    }

    pub(super) async fn message(&self, msg: &Message) -> Result<(), RestError> {
        self.callback(json!({"type": 4, "data": msg_value(msg)}))
            .await
    }

    /// Replace the message the component is on (the rules browser).
    pub(super) async fn update(&self, msg: &Message) -> Result<(), RestError> {
        self.callback(json!({"type": 7, "data": msg_value(msg)}))
            .await
    }

    /// "Thinking…", ephemeral; the answer follows.
    pub(super) async fn defer(&self) -> Result<(), RestError> {
        self.callback(json!({"type": 5, "data": {"flags": EPHEMERAL}}))
            .await
    }

    pub(super) async fn followup(&self, text: &str) -> Result<(), RestError> {
        self.bot
            .rest
            .followup(self.app, &self.token, &Message::ephemeral(text))
            .await
    }

    pub(super) async fn modal(&self, modal: &Modal) -> Result<(), RestError> {
        let components: Vec<_> = modal
            .inputs
            .iter()
            .map(super::model::Input::component)
            .collect();
        self.callback(json!({
            "type": 9,
            "data": {"custom_id": modal.custom_id, "title": modal.title, "components": components},
        }))
        .await
    }

    /// "Thinking…" in the channel (the answer is public).
    pub(super) async fn defer_public(&self) -> Result<(), RestError> {
        self.callback(json!({"type": 5})).await
    }

    /// Acknowledge a click; the message is edited later.
    pub(super) async fn defer_update(&self) -> Result<(), RestError> {
        self.callback(json!({"type": 6})).await
    }

    pub(super) async fn followup_message(&self, msg: &Message) -> Result<(), RestError> {
        self.bot.rest.followup(self.app, &self.token, msg).await
    }

    /// Edit the message the interaction came from (or answered with).
    pub(super) async fn edit_original(&self, msg: &Message) -> Result<(), RestError> {
        self.bot
            .rest
            .edit_original(self.app, &self.token, msg)
            .await
    }

    async fn choices(&self, choices: Vec<(String, String)>) -> Result<(), RestError> {
        let choices: Vec<Value> = choices
            .into_iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect();
        self.callback(json!({"type": 8, "data": {"choices": choices}}))
            .await
    }
}

fn msg_value(msg: &Message) -> Value {
    serde_json::to_value(msg).unwrap_or(Value::Null)
}

/// `str(user)` as discord.py prints it.
#[must_use]
pub fn user_label(u: &User) -> String {
    if u.discriminator == 0 {
        u.name.clone()
    } else {
        format!("{}#{:04}", u.name, u.discriminator)
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Failure {
    #[error(transparent)]
    Rest(#[from] RestError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Handle one interaction. Errors are logged; nothing propagates.
pub(crate) async fn handle(bot: &Bot, interaction: Interaction) {
    let reply = Reply {
        bot,
        id: interaction.id.get(),
        token: interaction.token.clone(),
        app: interaction.application_id.get(),
    };
    let owner = interaction
        .author()
        .and_then(|u| DiscordOwner::check(bot.cfg.owner_id, u.id.get(), user_label(u)));
    if let Err(e) = dispatch(bot, &reply, owner, interaction).await {
        tracing::warn!("discord interaction failed: {e}");
    }
}

async fn dispatch(
    bot: &Bot,
    reply: &Reply<'_>,
    owner: Option<DiscordOwner>,
    interaction: Interaction,
) -> Result<(), Failure> {
    let Some(owner) = owner else {
        return match interaction.kind {
            InteractionType::Ping => Ok(()),
            // Autocomplete has no ephemeral reply: no choices.
            InteractionType::ApplicationCommandAutocomplete => {
                Ok(reply.choices(Vec::new()).await?)
            }
            _ => Ok(reply.ephemeral(NOT_OWNER).await?),
        };
    };
    let who = HumanDecider::from(&owner);
    match (interaction.kind, interaction.data) {
        (InteractionType::ApplicationCommand, Some(InteractionData::ApplicationCommand(c))) => {
            command(bot, reply, &who, &c).await
        }
        (
            InteractionType::ApplicationCommandAutocomplete,
            Some(InteractionData::ApplicationCommand(c)),
        ) => autocomplete(bot, reply, &c).await,
        (InteractionType::MessageComponent, Some(InteractionData::MessageComponent(c))) => {
            let card = interaction
                .message
                .as_ref()
                .map(|m| (m.channel_id.get(), m.id.get()));
            match CustomId::parse(&c.custom_id) {
                Some(CustomId::MailRelease(m)) => {
                    mail_decide(bot, reply, &who, m, true, card).await
                }
                Some(CustomId::MailDiscard(m)) => {
                    mail_decide(bot, reply, &who, m, false, card).await
                }
                Some(id) => component(bot, reply, &who, id, &c.values).await,
                None => {
                    tracing::debug!("discord: a component that is not ours");
                    Ok(())
                }
            }
        }
        (InteractionType::ModalSubmit, Some(InteractionData::ModalSubmit(m))) => {
            match CustomId::parse(&m.custom_id) {
                Some(id) => modal_submit(bot, reply, &who, id, &submitted(&m)).await,
                None => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

pub(super) async fn load_request(
    bot: &Bot,
    id: RequestId,
) -> Result<Option<requests::RequestRow>, StoreError> {
    let tx = bot.store.begin().await?;
    let row = requests::get(&tx, id)
        .await?
        .map(requests::AnyRequest::into_row);
    tx.commit().await?;
    Ok(row)
}

async fn component(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    id: CustomId,
    values: &[String],
) -> Result<(), Failure> {
    match id {
        CustomId::Approve(rid) => reply.modal(&views::decision_modal(rid, true)).await?,
        CustomId::Deny(rid) => reply.modal(&views::decision_modal(rid, false)).await?,
        CustomId::Edit(rid) => match load_request(bot, rid).await? {
            None => reply.ephemeral(GONE).await?,
            Some(r) => match views::edit_modal(&r) {
                Some(m) => reply.modal(&m).await?,
                None => reply.ephemeral(views::EDIT_TOO_LONG).await?,
            },
        },
        CustomId::Totp(rid) => match load_request(bot, rid).await? {
            None => reply.ephemeral(GONE).await?,
            Some(r) => reply.modal(&views::totp_modal(&r)).await?,
        },
        CustomId::EndShell(rid) => end_shell(bot, reply, who, rid).await?,
        CustomId::ApproveAll(rid) => super::hostexec::approve_all(bot, reply, rid).await?,
        CustomId::KillVms { scope, host } => {
            super::hostexec::kill_vms(bot, reply, who, scope, host).await?;
        }
        CustomId::RulesSelect { page } => {
            let selected = values.first().and_then(|v| v.parse::<RuleId>().ok());
            reply
                .update(&rules_page(bot, page, selected).await?)
                .await?;
        }
        CustomId::RulesPage { target } => {
            reply.update(&rules_page(bot, target, None).await?).await?
        }
        CustomId::RulesToggle { page, rule } => {
            let tx = bot.store.begin().await?;
            if let Some(r) = rule_store::get(&tx, rule).await? {
                rule_store::set_enabled(&tx, rule, !r.enabled).await?;
                tracing::info!(rule = %rule, enabled = !r.enabled, by = who.label(), "rule toggled from Discord");
            }
            tx.commit().await?;
            reply
                .update(&rules_page(bot, page, Some(rule)).await?)
                .await?;
        }
        CustomId::WrongCall(call) => super::review::wrong_call(bot, reply, call).await?,
        CustomId::Unlabel(call) => super::review::unlabel(bot, reply, who, call).await?,
        CustomId::RulesDelete { page, rule } => {
            let tx = bot.store.begin().await?;
            if rule_store::delete(&tx, rule).await? {
                tracing::info!(rule = %rule, by = who.label(), "rule deleted from Discord");
            }
            tx.commit().await?;
            reply.update(&rules_page(bot, page, None).await?).await?;
        }
        // Modal ids never arrive as components; mail is handled above.
        CustomId::DecisionModal { .. }
        | CustomId::EditModal(_)
        | CustomId::TotpModal(_)
        | CustomId::WindowModal(_)
        | CustomId::WrongCallModal(_)
        | CustomId::MailRelease(_)
        | CustomId::MailDiscard(_) => {}
    }
    Ok(())
}

/// Release or Discard on a held-mail card (`discord_bot/mail.py` `_decide`):
/// the gateway decides (once: a second click is told "Nothing done"), the
/// card shows the outcome and loses its buttons.
async fn mail_decide(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    item: agent_auth_core::MailItemId,
    release: bool,
    card: Option<(u64, u64)>,
) -> Result<(), Failure> {
    let Some(mail) = bot.services().mail else {
        reply
            .ephemeral("Mail is not enabled on this broker.")
            .await?;
        return Ok(());
    };
    reply.defer().await?;
    let out = if release {
        mail.release(item, who.label()).await
    } else {
        mail.discard(item, who.label()).await
    };
    let d = match out {
        Ok(d) => d,
        Err(e) => {
            reply
                .followup(&format!("Nothing done: {}", escape(&e.detail)))
                .await?;
            return Ok(());
        }
    };
    let (line, color) = super::mail::outcome(&d, release);
    if let Some((channel, message)) = card {
        let edited = Message {
            embeds: Some(vec![super::mail::held_embed(
                &d,
                Some((
                    &format!("{line} — {}", super::text::said(who.label(), 100)),
                    color,
                )),
            )]),
            components: Some(Vec::new()),
            allowed_mentions: Some(super::model::mentions(None)),
            ..Message::default()
        };
        if let Err(e) = bot.rest.edit_message(channel, message, &edited).await {
            tracing::warn!("discord: could not update the held-mail card: {e}");
        }
    }
    reply.followup(&line).await?;
    Ok(())
}

async fn rules_page(bot: &Bot, page: i64, selected: Option<RuleId>) -> Result<Message, StoreError> {
    let tx = bot.store.begin().await?;
    let all = rule_store::list(&tx).await?;
    tx.commit().await?;
    Ok(render(&paginate(all, page), selected))
}

async fn end_shell(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    rid: RequestId,
) -> Result<(), Failure> {
    reply.defer().await?;
    let tx = bot.store.begin().await?;
    let grant = grants::by_request(&tx, rid).await?;
    tx.commit().await?;
    let Some(grant) = grant.filter(|g| g.status == GrantStatus::Active) else {
        reply.followup("That shell has already ended.").await?;
        return Ok(());
    };
    let Some(ops) = bot.services().requests else {
        reply.followup(NOT_READY).await?;
        return Ok(());
    };
    match ops.revoke_grant(who, grant.id, "shell ended").await {
        Ok(()) => {
            reply
                .followup("Shell ended; anything it was running is killed.")
                .await?
        }
        Err(OpError(e)) => reply.followup(&format!("Could not end it: {e}")).await?,
    }
    Ok(())
}

/// The text inputs of a submitted modal, by custom id (inside labels or
/// action rows).
#[must_use]
pub fn submitted(m: &ModalInteractionData) -> Submitted {
    fn walk(c: &ModalInteractionComponent, out: &mut Vec<(String, String)>) {
        match c {
            ModalInteractionComponent::TextInput(t) => {
                out.push((t.custom_id.clone(), t.value.clone()))
            }
            ModalInteractionComponent::Label(l) => walk(&l.component, out),
            ModalInteractionComponent::ActionRow(r) => {
                r.components.iter().for_each(|c| walk(c, out))
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    m.components.iter().for_each(|c| walk(c, &mut out));
    Submitted(out)
}

async fn modal_submit(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    id: CustomId,
    form: &Submitted,
) -> Result<(), Failure> {
    let (rid, read): (RequestId, Result<HumanDecision, Refusal>) = match id {
        CustomId::DecisionModal { approve, request } => {
            (request, views::read_decision(approve, form))
        }
        CustomId::EditModal(request) => (request, views::read_edit(form)),
        CustomId::TotpModal(request) => (request, views::read_totp(form)),
        CustomId::WindowModal(request) => {
            return super::hostexec::window_submit(bot, reply, who, request, form).await;
        }
        CustomId::WrongCallModal(call) => {
            return super::review::wrong_call_submit(bot, reply, who, call, form).await;
        }
        _ => return Ok(()),
    };
    reply.defer().await?;
    let decision = match read {
        Ok(d) => d,
        Err(Refusal(text)) => {
            reply.followup(&text).await?;
            return Ok(());
        }
    };
    let Some(ops) = bot.services().requests else {
        reply.followup(NOT_READY).await?;
        return Ok(());
    };
    // The owner's attestation, for this request only (core::approval).
    let approval = decision
        .approve
        .then(|| HumanApproval::attest(rid, who.label()));
    match ops.decide(who, rid, decision.clone(), approval).await {
        Ok(row) => {
            reply
                .followup(&views::decided_text(rid, &decision, &row))
                .await?
        }
        Err(OpError(e)) => {
            reply
                .followup(&format!("Could not apply decision: {e}"))
                .await?
        }
    }
    Ok(())
}

pub(super) fn option<'a>(c: &'a CommandData, name: &str) -> Option<&'a CommandOptionValue> {
    c.options.iter().find(|o| o.name == name).map(|o| &o.value)
}

pub(super) fn string_option(c: &CommandData, name: &str) -> Option<String> {
    match option(c, name) {
        Some(CommandOptionValue::String(s) | CommandOptionValue::Focused(s, _)) => Some(s.clone()),
        _ => None,
    }
}

async fn command(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    c: &CommandData,
) -> Result<(), Failure> {
    match c.name.as_str() {
        "rules" => {
            let mut msg = rules_page(bot, 0, None).await?;
            msg.flags = Some(EPHEMERAL);
            reply.message(&msg).await?;
        }
        "contain" => contain(bot, reply, who, c).await?,
        "contained" => {
            let entries = containment_entries(bot).await?;
            let text: Vec<String> = entries
                .iter()
                .map(|e| format!("• `{}` {}", e.id, escape(&describe(e))))
                .collect();
            let text = cut(&text.join("\n"), 2000);
            reply
                .ephemeral(if text.is_empty() {
                    "Nothing is contained."
                } else {
                    &text
                })
                .await?;
        }
        "release" => release(bot, reply, who, c).await?,
        "review" => {
            let everything = matches!(
                option(c, "everything"),
                Some(CommandOptionValue::Boolean(true))
            );
            super::review::command(bot, reply, string_option(c, "kind").as_deref(), everything)
                .await?;
        }
        _ => {
            Box::pin(super::hostexec::command(bot, reply, who, c)).await?;
        }
    }
    Ok(())
}

async fn containment_entries(bot: &Bot) -> Result<Vec<lockdown::ContainmentEntry>, StoreError> {
    let tx = bot.store.begin().await?;
    let entries = lockdown::entries(&tx).await?;
    tx.commit().await?;
    Ok(entries)
}

fn describe(e: &lockdown::ContainmentEntry) -> String {
    e.describe(&agent_auth_wire::timestamp::format(e.at).unwrap_or_default())
}

async fn contain(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    c: &CommandData,
) -> Result<(), Failure> {
    let Some(ops) = bot.services().containment else {
        reply.ephemeral(NO_CONTAINMENT).await?;
        return Ok(());
    };
    let mut m = Map::new();
    for key in ["name", "project", "host", "runtime"] {
        if let Some(v) = string_option(c, key).filter(|v| !v.is_empty()) {
            m.insert(key.to_owned(), Value::String(v));
        }
    }
    let everyone = matches!(
        option(c, "everyone"),
        Some(CommandOptionValue::Boolean(true))
    );
    if m.is_empty() && !everyone {
        reply
            .ephemeral("Say which agents (name, project, host, runtime), or everyone:True.")
            .await?;
        return Ok(());
    }
    let reason = string_option(c, "reason").unwrap_or_default();
    reply.defer().await?;
    match ops.contain(who, Value::Object(m), &reason, everyone).await {
        Ok(out) => {
            reply
                .followup(&format!(
                    "Contained `{}`: {} agent(s), {} grant(s) revoked.",
                    out.id, out.agents, out.grants_revoked
                ))
                .await?;
        }
        Err(OpError(e)) => reply.followup(&e).await?,
    }
    Ok(())
}

async fn release(
    bot: &Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    c: &CommandData,
) -> Result<(), Failure> {
    let Some(ops) = bot.services().containment else {
        reply.ephemeral(NO_CONTAINMENT).await?;
        return Ok(());
    };
    let entry = string_option(c, "entry").filter(|e| !e.is_empty());
    let all = matches!(option(c, "all"), Some(CommandOptionValue::Boolean(true)));
    if entry.is_none() && !all {
        // Lifting everything is explicit, as on the admin API.
        let entries = containment_entries(bot).await?;
        reply.ephemeral(&release_help(&entries)).await?;
        return Ok(());
    }
    reply.defer().await?;
    match ops.lift(who, entry.as_deref()).await {
        Ok(lifted) => reply.followup(&released_text(&lifted)).await?,
        Err(OpError(e)) => reply.followup(&e).await?,
    }
    Ok(())
}

/// `/release` with neither an entry nor `all`: what stands, and how to
/// lift one or every one.
#[must_use]
pub fn release_help(entries: &[lockdown::ContainmentEntry]) -> String {
    let how =
        "Say which: `/release entry:<id>` lifts one, `/release all:True` lifts every containment.";
    if entries.is_empty() {
        return format!("Nothing is contained. {how}");
    }
    let lines: Vec<String> = entries
        .iter()
        .map(|e| format!("• `{}` {}", e.id, escape(&describe(e))))
        .collect();
    cut(&format!("{how}\n{}", lines.join("\n")), 2000)
}

/// `/release`'s answer.
#[must_use]
pub fn released_text(lifted: &[lockdown::ContainmentEntry]) -> String {
    let ids: Vec<String> = lifted.iter().map(|e| format!("`{}`", e.id)).collect();
    let list = if ids.is_empty() {
        "nothing was contained".to_owned()
    } else {
        ids.join(", ")
    };
    let tail = if lifted
        .iter()
        .any(|e| e.source == lockdown::ContainmentSource::Lockdown)
    {
        ". A lockdown's hosts stay locked until /unlock with their codes."
    } else {
        "."
    };
    format!("Lifted: {list}{tail}")
}

/// The option being typed in an autocomplete, and its text so far.
fn focused(c: &CommandData) -> Option<(&str, &str)> {
    c.options.iter().find_map(|o| match &o.value {
        CommandOptionValue::Focused(text, _) => Some((o.name.as_str(), text.as_str())),
        _ => None,
    })
}

async fn autocomplete(bot: &Bot, reply: &Reply<'_>, c: &CommandData) -> Result<(), Failure> {
    if let Some(("host", current)) = focused(c) {
        let choices = super::hostexec::host_choices(bot, current).await;
        return Ok(reply.choices(choices).await?);
    }
    if c.name != "release" {
        return Ok(reply.choices(Vec::new()).await?);
    }
    let current = string_option(c, "entry").unwrap_or_default().to_lowercase();
    let entries = containment_entries(bot).await?;
    let choices = entries
        .iter()
        .filter(|e| e.id.contains(&current))
        .take(25)
        .map(|e| {
            (
                cut(&format!("{} · {}", e.id, describe(e)), 100),
                e.id.clone(),
            )
        })
        .collect();
    reply.choices(choices).await?;
    Ok(())
}
