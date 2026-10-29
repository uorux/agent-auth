//! The hostexec side of the bot (Python `discord_bot/hostexec.py`,
//! `hosts.py`; spec daemons-hostd §10 and surfaces A.7): "Approve all…"
//! windows, `/arm`, `/disarm`, `/lockdown` (with its "Kill VMs" button),
//! `/unlock`, `/dnd`, `/hosts`. Each acts through the public
//! `crate::hostexec` functions, after the owner check every interaction
//! goes through; the host has the last word on every one.
//!
//! Rendering is pure (the functions taking rows and results); the
//! handlers below it do the calls.

use std::sync::Arc;

use agent_auth_core::durations::{DurationSecs, format_duration};
use agent_auth_core::{AgentId, RequestId, Tier};
use agent_auth_crypto::daemon::PublicKey;
use agent_auth_store::agents;
use agent_auth_store::daemons::{DaemonRole, DaemonRow};
use agent_auth_wire::admin::{LockdownResult, LockdownScope, UnlockResult};
use agent_auth_wire::daemon::host::HostStatus;
use agent_auth_wire::duration::HostDuration;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use twilight_model::application::interaction::application_command::{
    CommandData, CommandOptionValue,
};
use twilight_model::channel::message::Embed;

use super::embeds::scope;
use super::interactions::{Failure, Reply, load_request, option, string_option};
use super::model::{COLOR_DENIED, COLOR_LIST, Message, embed, set_footer};
use super::text::{code, cut, escape, said};
use super::views::{self, Refusal, Submitted, kill_vm_view, scope_of, scope_word};
use crate::auth::HumanDecider;
use crate::hostexec::{HostExec, sanitize_status};
use crate::state::AppState;

pub const NO_DAEMONS: &str = "The daemon channel is disabled on this broker.";
pub const NO_DESKTOP: &str = "Desktop prompts are not enabled.";
/// Discord caps an embed description at 4096 characters.
const MAX_DESCRIPTION: usize = 4000;

// ------------------------------------------------------------- rendering

/// One paired daemon, as `/hosts` shows it.
#[derive(Debug, Clone)]
pub struct DaemonLine {
    pub name: String,
    pub role: DaemonRole,
    pub online: bool,
    pub version: Option<String>,
    pub last_seen_at: Option<OffsetDateTime>,
    pub fingerprint: String,
    /// Re-validated (`sanitize_status`): only fixed words, numbers and
    /// timestamps are taken from it.
    pub status: HostStatus,
}

impl DaemonLine {
    #[must_use]
    pub fn from_row(row: &DaemonRow, online: bool) -> DaemonLine {
        let status = sanitize_status(row.last_status.as_ref());
        DaemonLine {
            name: row.name.clone(),
            role: row.role,
            online,
            // A daemon-supplied value: only a well-formed version is kept.
            version: row
                .version
                .clone()
                .filter(|v| agent_auth_wire::daemon::handshake::version_ok(v)),
            last_seen_at: row.last_seen_at,
            fingerprint: PublicKey::parse(&row.public_key)
                .map(|k| k.fingerprint())
                .unwrap_or_default(),
            status,
        }
    }
}

fn host_state(status: &HostStatus) -> String {
    if status.role.as_deref() != Some("host") {
        return String::new();
    }
    let mut parts = Vec::new();
    if status.lockdown {
        parts.push("⛔ locked down".to_owned());
    }
    for (name, tier) in &status.tiers {
        if !tier.enabled {
            continue;
        }
        let name = tier_word(*name);
        parts.push(match tier.armed_until {
            Some(until) => format!("{name} 🔓 until <t:{}:t>", until.trunc()),
            None => format!("{name} 🔒"),
        });
    }
    if status.jobs > 0 {
        parts.push(format!("{} job(s)", status.jobs));
    }
    if status.shells > 0 {
        parts.push(format!("{} shell(s)", status.shells));
    }
    if status.desktop.as_ref().is_some_and(|d| d.present) {
        parts.push("🧑‍💻 at the desk".to_owned());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("\n\u{3000}{}", parts.join(" · "))
    }
}

fn tier_word(t: agent_auth_wire::common::TierName) -> &'static str {
    match t {
        agent_auth_wire::common::TierName::User => "user",
        agent_auth_wire::common::TierName::Root => "root",
    }
}

fn role_word(r: DaemonRole) -> &'static str {
    match r {
        DaemonRole::Host => "host",
        DaemonRole::Sandbox => "sandbox",
    }
}

fn daemon_line(d: &DaemonLine) -> String {
    let state = if d.online {
        "🟢 online"
    } else {
        "⚫ offline"
    };
    let seen = d.last_seen_at.map_or_else(
        || "never connected".to_owned(),
        |t| format!("last seen <t:{}:R>", t.unix_timestamp()),
    );
    let version = d
        .version
        .as_deref()
        .map(|v| format!(" · v{}", escape(v)))
        .unwrap_or_default();
    format!(
        "{state} **{}** ({}){version} · {seen} · `{}`{}",
        escape(&d.name),
        role_word(d.role),
        code(&cut(&d.fingerprint, 19)),
        host_state(&d.status)
    )
}

/// `/hosts`.
#[must_use]
pub fn hosts_embed(daemons: &[DaemonLine]) -> Embed {
    let body = if daemons.is_empty() {
        "No paired daemons. Pair one with `agent-auth admin daemon-pair`.".to_owned()
    } else {
        super::text::trim(
            &daemons
                .iter()
                .map(daemon_line)
                .collect::<Vec<_>>()
                .join("\n"),
            MAX_DESCRIPTION,
        )
    };
    let online = daemons.iter().filter(|d| d.online).count();
    let mut e = embed();
    e.title = Some("Hosts".to_owned());
    e.description = Some(body);
    e.color = Some(COLOR_LIST);
    set_footer(&mut e, format!("{online}/{} online", daemons.len()));
    e
}

fn report_lines(daemons: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    daemons
        .iter()
        .map(|(name, report)| format!("• `{}`: {}", code(name), said(report, 300)))
        .collect()
}

/// The lockdown message.
#[must_use]
pub fn lockdown_embed(scope: LockdownScope, host: Option<&str>, out: &LockdownResult) -> Embed {
    let mut lines = report_lines(&out.daemons);
    if lines.is_empty() {
        lines.push("• no daemons paired".to_owned());
    }
    let mut e = embed();
    e.title = Some(format!(
        "⛔ LOCKDOWN ({}{})",
        scope_word(scope),
        host.map(|h| format!(" {}", escape(h))).unwrap_or_default()
    ));
    e.description = Some(cut(
        &format!(
            "{} grant(s) revoked, {} thread(s) closed.\n{}\n\n`/unlock` lifts the broker's side. \
             Each host stays locked until `/unlock host:<h> code:<root-unlock code>` or \
             `sudo agent-auth-hostctl unlock` on it.",
            out.grants_revoked,
            out.threads_closed,
            lines.join("\n")
        ),
        MAX_DESCRIPTION,
    ));
    e.color = Some(COLOR_DENIED);
    e
}

/// `/unlock`'s answer.
#[must_use]
pub fn unlocked_text(host: Option<&str>, code_given: bool, out: &UnlockResult) -> String {
    let done: Vec<String> = out
        .daemons
        .keys()
        .map(|k| format!("`{}`", code(k)))
        .collect();
    let done = if done.is_empty() {
        "the broker only".to_owned()
    } else {
        done.join(", ")
    };
    let mut note = if host.is_some() && code_given {
        String::new()
    } else {
        " Hosts stay locked until they get their own code.".to_owned()
    };
    if !out.broker_locked.is_empty() {
        note.push_str(" The broker is still locked (`/unlock` without a host lifts that).");
    }
    format!("Unlocked: {done}.{note}")
}

/// `/arm`'s answer, from the host's reply.
#[must_use]
pub fn armed_text(host: &str, tier: Tier, out: &Map<String, Value>) -> String {
    let until = out
        .get("armed_until")
        .and_then(Value::as_f64)
        .filter(|t| t.is_finite() && *t > 0.0)
        .map_or_else(|| "?".to_owned(), |t| format!("<t:{}:t>", t.trunc()));
    format!("🔓 **{}** {tier} tier armed until {until}.", escape(host))
}

/// The window's answer.
#[must_use]
pub fn window_text(
    duration: DurationSecs,
    agent: &str,
    tier: &str,
    host: &str,
    rule: agent_auth_core::RuleId,
    approved: usize,
) -> String {
    format!(
        "Window open for {}: **{}** may run {} commands on **{}** without asking \
         (rule `{}`, /rules to end it early). Approved now: {approved}.",
        format_duration(u64::from(duration.get())),
        escape(agent),
        escape(tier),
        escape(host),
        cut(&rule.to_string(), 8)
    )
}

// -------------------------------------------------------------- handlers

/// The broker state and its hostexec part, when the daemon channel is on.
fn hostexec(bot: &super::Bot) -> Option<(AppState, Arc<HostExec>)> {
    let app = bot.services().app?;
    let hx = app.hostd.as_ref()?.hostexec.clone()?;
    Some((app, hx))
}

fn tier_option(c: &CommandData) -> Result<Option<Tier>, String> {
    match string_option(c, "tier").filter(|t| !t.is_empty()) {
        None => Ok(None),
        Some(t) => Tier::parse(&t)
            .map(Some)
            .ok_or_else(|| "tier must be \"user\" or \"root\"".to_owned()),
    }
}

/// "Approve all…": the window modal.
pub(super) async fn approve_all(
    bot: &super::Bot,
    reply: &Reply<'_>,
    rid: RequestId,
) -> Result<(), Failure> {
    let Some((app, _)) = hostexec(bot) else {
        return Ok(reply.ephemeral(NO_DAEMONS).await?);
    };
    let Some(request) = load_request(bot, rid).await? else {
        return Ok(reply.ephemeral(super::interactions::GONE).await?);
    };
    let default = app.policy.platforms().hostexec.window_default;
    let default = format_duration(u64::from(default.get()));
    Ok(reply
        .modal(&views::window_modal(&request, &default))
        .await?)
}

async fn agent_names(
    bot: &super::Bot,
    agent: AgentId,
    delegator: Option<AgentId>,
) -> Result<Option<(String, Option<String>)>, agent_auth_store::StoreError> {
    let tx = bot.store.begin().await?;
    let a = agents::get(&tx, agent).await?;
    let d = match delegator {
        Some(id) => agents::get(&tx, id).await?.map(|d| d.name),
        None => None,
    };
    tx.commit().await?;
    Ok(a.map(|a| (a.name, d)))
}

/// The window modal's submission.
pub(super) async fn window_submit(
    bot: &super::Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    rid: RequestId,
    form: &Submitted,
) -> Result<(), Failure> {
    reply.defer().await?;
    let Some((app, hx)) = hostexec(bot) else {
        return Ok(reply.followup(NO_DAEMONS).await?);
    };
    let max = app.policy.platforms().hostexec.window_max;
    let duration = match views::read_window(form, max) {
        Ok(d) => d,
        Err(Refusal(text)) => return Ok(reply.followup(&text).await?),
    };
    let Some(request) = load_request(bot, rid).await? else {
        return Ok(reply.followup(super::interactions::GONE).await?);
    };
    let Some((agent, delegator)) = agent_names(
        bot,
        request.agent_id,
        request.delegation.map(|d| d.delegator_agent_id),
    )
    .await?
    else {
        return Ok(reply.followup(super::interactions::GONE).await?);
    };
    let tier = scope(&request)
        .get("tier")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    match hx
        .open_window(
            &request,
            &agent,
            delegator.as_deref(),
            duration.get(),
            who.label(),
        )
        .await
    {
        Ok((rule, approved)) => {
            reply
                .followup(&window_text(
                    duration,
                    &agent,
                    &tier,
                    &request.resource,
                    rule.id,
                    approved.len(),
                ))
                .await?;
        }
        Err(e) => {
            reply
                .followup(&format!(
                    "No window opened — {}: {}",
                    escape(&request.resource),
                    said(&e.0, 500)
                ))
                .await?;
        }
    }
    Ok(())
}

/// `/arm`, `/disarm`, `/lockdown`, `/unlock`, `/dnd`, `/hosts`. `false`:
/// not one of these.
pub(super) async fn command(
    bot: &super::Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    c: &CommandData,
) -> Result<bool, Failure> {
    match c.name.as_str() {
        "arm" | "disarm" | "lockdown" | "unlock" => {}
        "dnd" => {
            dnd(bot, reply, c).await?;
            return Ok(true);
        }
        "hosts" => {
            hosts(bot, reply).await?;
            return Ok(true);
        }
        _ => return Ok(false),
    }
    let Some((app, hx)) = hostexec(bot) else {
        reply.ephemeral(NO_DAEMONS).await?;
        return Ok(true);
    };
    let host = string_option(c, "host").filter(|h| !h.is_empty());
    match c.name.as_str() {
        "arm" => {
            let host = host.unwrap_or_default();
            let tier = match tier_option(c) {
                Ok(Some(t)) => t,
                Ok(None) => {
                    return Ok(reply
                        .ephemeral("Say which tier: user or root.")
                        .await
                        .map(|()| true)?);
                }
                Err(e) => return Ok(reply.ephemeral(&e).await.map(|()| true)?),
            };
            let text = string_option(c, "duration").unwrap_or_else(|| "1h".to_owned());
            let duration = match HostDuration::parse(&text) {
                Ok(d) => d,
                Err(e) => {
                    reply.ephemeral(&format!("Invalid duration: {e}")).await?;
                    return Ok(true);
                }
            };
            let code = string_option(c, "code").unwrap_or_default();
            reply.defer().await?;
            match hx.arm(&host, tier, &duration, code.trim()).await {
                Ok(out) => reply.followup(&armed_text(&host, tier, &out)).await?,
                Err(e) => {
                    reply
                        .followup(&format!(
                            "Not armed — {}: {}",
                            escape(&host),
                            said(&e.0, 500)
                        ))
                        .await?
                }
            }
        }
        "disarm" => {
            let host = host.unwrap_or_default();
            let tier = match tier_option(c) {
                Ok(t) => t,
                Err(e) => return Ok(reply.ephemeral(&e).await.map(|()| true)?),
            };
            reply.defer().await?;
            match hx.disarm(&host, tier).await {
                Ok(_) => {
                    let which = tier.map_or("both tiers".to_owned(), |t| t.as_str().to_owned());
                    reply
                        .followup(&format!("🔒 **{}** {which} disarmed.", escape(&host)))
                        .await?
                }
                Err(e) => {
                    reply
                        .followup(&format!("{}: {}", escape(&host), said(&e.0, 500)))
                        .await?
                }
            }
        }
        "lockdown" => {
            let scope = match string_option(c, "scope").filter(|s| !s.is_empty()) {
                None => LockdownScope::Sandboxes,
                Some(s) => match scope_of(&s) {
                    Some(s) => s,
                    None => {
                        reply
                            .ephemeral("scope: all | sandboxes | host (with a host name)")
                            .await?;
                        return Ok(true);
                    }
                },
            };
            let kill_vm = matches!(
                option(c, "kill_vm"),
                Some(CommandOptionValue::Boolean(true))
            );
            run_lockdown(&app, &hx, reply, who, scope, host.as_deref(), kill_vm).await?;
        }
        "unlock" => {
            let code = string_option(c, "code").filter(|s| !s.trim().is_empty());
            reply.defer().await?;
            match crate::hostexec::lockdown::unlock(
                &app,
                &hx,
                host.as_deref(),
                code.as_deref().map(str::trim),
                who.label(),
            )
            .await
            {
                Ok(out) => {
                    reply
                        .followup(&unlocked_text(host.as_deref(), code.is_some(), &out))
                        .await?
                }
                Err(e) => {
                    reply
                        .followup(&format!(
                            "Not unlocked — {}: {}",
                            escape(host.as_deref().unwrap_or("None")),
                            said(&e.0, 500)
                        ))
                        .await?
                }
            }
        }
        _ => {}
    }
    Ok(true)
}

/// A lockdown, answered in the channel (not ephemeral: everyone watching
/// sees the kill switch was pulled), with "Kill VMs" unless they were.
async fn run_lockdown(
    app: &AppState,
    hx: &Arc<HostExec>,
    reply: &Reply<'_>,
    who: &HumanDecider,
    scope: LockdownScope,
    host: Option<&str>,
    kill_vm: bool,
) -> Result<(), Failure> {
    reply.defer_public().await?;
    match crate::hostexec::lockdown::lockdown(app, hx, scope, host, kill_vm, who.label()).await {
        Ok(out) => {
            let mut msg = Message {
                embeds: Some(vec![lockdown_embed(scope, host, &out)]),
                allowed_mentions: Some(super::model::mentions(None)),
                ..Message::default()
            };
            if !kill_vm {
                msg.components = Some(kill_vm_view(scope, host, false));
            }
            reply.followup_message(&msg).await?;
        }
        Err(e) => {
            reply
                .followup_message(&Message::text(said(&e.0, 1900)))
                .await?
        }
    }
    Ok(())
}

/// "Kill VMs" on a lockdown message: the same lockdown, stopping the VMs.
pub(super) async fn kill_vms(
    bot: &super::Bot,
    reply: &Reply<'_>,
    who: &HumanDecider,
    scope: LockdownScope,
    host: Option<String>,
) -> Result<(), Failure> {
    let Some((app, hx)) = hostexec(bot) else {
        return Ok(reply.ephemeral(NO_DAEMONS).await?);
    };
    reply.defer_update().await?;
    match crate::hostexec::lockdown::lockdown(&app, &hx, scope, host.as_deref(), true, who.label())
        .await
    {
        Ok(out) => {
            let text = format!(
                "Agent VMs stopped.\n{}",
                report_lines(&out.daemons).join("\n")
            );
            reply
                .followup_message(&Message::text(cut(&text, 2000)))
                .await?;
            let done = Message {
                components: Some(kill_vm_view(scope, host.as_deref(), true)),
                ..Message::default()
            };
            reply.edit_original(&done).await?;
        }
        Err(e) => {
            reply
                .followup_message(&Message::text(said(&e.0, 1900)))
                .await?
        }
    }
    Ok(())
}

async fn dnd(bot: &super::Bot, reply: &Reply<'_>, c: &CommandData) -> Result<(), Failure> {
    let desktop = bot
        .services()
        .app
        .and_then(|a| a.hostd.as_ref().and_then(|h| h.desktop.clone()));
    let Some(desktop) = desktop else {
        return Ok(reply.ephemeral(NO_DESKTOP).await?);
    };
    let seconds = match string_option(c, "duration").filter(|d| !d.trim().is_empty()) {
        None => 0,
        Some(text) => match DurationSecs::parse(&text) {
            Ok(d) => u64::from(d.get()),
            Err(e) => return Ok(reply.ephemeral(&format!("Invalid duration: {e}")).await?),
        },
    };
    desktop.set_dnd(seconds).await;
    let text = if seconds > 0 {
        format!("Desktop prompts off for {}.", format_duration(seconds))
    } else {
        "Desktop prompts back on.".to_owned()
    };
    Ok(reply.ephemeral(&text).await?)
}

async fn hosts(bot: &super::Bot, reply: &Reply<'_>) -> Result<(), Failure> {
    let hub = bot
        .services()
        .app
        .and_then(|a| a.hostd.as_ref().map(|h| Arc::clone(&h.hub)));
    let lines = match hub {
        Some(hub) => match hub.list().await {
            Ok(rows) => rows
                .iter()
                .map(|r| DaemonLine::from_row(r, hub.row_online(r)))
                .collect(),
            Err(e) => {
                tracing::warn!("discord /hosts: {e}");
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let msg = Message {
        embeds: Some(vec![hosts_embed(&lines)]),
        flags: Some(super::model::EPHEMERAL),
        allowed_mentions: Some(super::model::mentions(None)),
        ..Message::default()
    };
    Ok(reply.message(&msg).await?)
}

/// Host-name autocomplete for the hostexec commands.
pub(super) async fn host_choices(bot: &super::Bot, current: &str) -> Vec<(String, String)> {
    let Some((_, hx)) = hostexec(bot) else {
        return Vec::new();
    };
    let current = current.to_lowercase();
    hx.hosts()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|h| h.name.contains(&current))
        .take(25)
        .map(|h| (h.name.clone(), h.name))
        .collect()
}
