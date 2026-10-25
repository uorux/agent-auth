//! `Notify` over Discord (spec A.4). Every method swallows its own errors
//! (logged, never the token): a Discord outage never fails a decision.
//! `shell_command` answers false on any failure, and the command then does
//! not run (INV-A4).
//!
//! Every message names who it may ping: the owner, or nobody (Bug-A3:
//! the approval card's mention is restricted too).

use std::sync::Arc;

use agent_auth_core::pyfmt::{escape_unprintable, shlex_join, shlex_quote};
use agent_auth_core::{GrantStatus, Platform, RequestStatus};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::requests::{self, DiscordRefs, RequestRow};
use agent_auth_store::rules::RuleRow;
use agent_auth_store::{StoreError, a2a};
use serde_json::Value;

use super::Bot;
use super::embeds::{
    self, GrantView, apply_grant_ended, apply_outcome, capability, hostexec_embed, output_file,
    request_embed, result_field, rule_applied_embed,
};
use super::model::{File, Message, MessageReference, add_field, embed, mentions, resendable};
use super::rest::RestError;
use super::text::{code, code_block, cut, display_lines, escape, said};
use super::views::{disabled_view, hostexec_pending_view, pending_view, shell_view};
use crate::notify::Notify;

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error(transparent)]
    Rest(#[from] RestError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("no channel configured")]
    NoChannel,
}

/// The notifier half of the bot.
#[derive(Debug, Clone)]
pub struct DiscordNotifier {
    bot: Arc<Bot>,
}

fn ids(refs: DiscordRefs) -> Option<(u64, u64)> {
    let c = u64::try_from(refs.channel_id?).ok()?;
    let m = u64::try_from(refs.message_id?).ok()?;
    Some((c, m))
}

fn to_i64(id: u64) -> Option<i64> {
    i64::try_from(id).ok()
}

fn is_shell(request: &RequestRow) -> bool {
    request.platform == Platform::Hostexec && capability(request) == "shell"
}

fn short(id: impl ToString) -> String {
    cut(&id.to_string(), 8)
}

fn job_argv(job: &JobRow) -> Vec<String> {
    job.spec
        .get("argv")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|s| s.as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Everything that runs, for the shell's thread: argv, cwd, env, stdin,
/// in full and display-safe (core's quoting: nothing hidden, reordered or
/// faked as another line). Too long for a message, it goes as a file.
#[must_use]
pub fn shell_command_text(job: &JobRow) -> String {
    let spec = &job.spec;
    let mut full = format!("$ {}", shlex_join(&job_argv(job)));
    if let Some(cwd) = spec
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
    {
        full.push_str(&format!("\n# cwd: {}", escape_unprintable(cwd)));
    }
    if let Some(env) = spec.get("env").and_then(Value::as_object) {
        let mut pairs: Vec<(&String, &Value)> = env.iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in pairs {
            full.push_str(&format!(
                "\n# env: {}={}",
                escape_unprintable(k),
                shlex_quote(v.as_str().unwrap_or(""))
            ));
        }
    }
    if let Some(stdin) = spec.get("stdin").and_then(Value::as_str) {
        full.push_str(&format!(
            "\n# stdin ({} chars):\n{}",
            stdin.chars().count(),
            display_lines(stdin)
        ));
    }
    full
}

impl DiscordNotifier {
    pub(crate) fn new(bot: Arc<Bot>) -> DiscordNotifier {
        DiscordNotifier { bot }
    }

    fn owner_ping(&self, ping: bool) -> (String, Message) {
        match self.bot.cfg.owner().filter(|_| ping) {
            Some(o) => (
                format!("<@{o}> "),
                Message {
                    allowed_mentions: Some(mentions(Some(o))),
                    ..Message::default()
                },
            ),
            None => (
                String::new(),
                Message {
                    allowed_mentions: Some(mentions(None)),
                    ..Message::default()
                },
            ),
        }
    }

    async fn send(&self, channel: u64, msg: &Message) -> Result<u64, Failure> {
        if channel == 0 {
            return Err(Failure::NoChannel);
        }
        Ok(self.bot.rest.create_message(channel, msg).await?)
    }

    /// The card's refs, read fresh (the row passed in may predate `surface`
    /// storing them, or a shell thread being made).
    async fn refs(&self, request: &RequestRow) -> Result<DiscordRefs, StoreError> {
        let tx = self.bot.store.begin().await?;
        let fresh = requests::get(&tx, request.id).await?;
        tx.commit().await?;
        Ok(fresh.map_or(request.discord, |r| r.row().discord))
    }

    async fn first_embed(
        &self,
        channel: u64,
        message: u64,
    ) -> Result<twilight_model::channel::message::Embed, RestError> {
        let m = self.bot.rest.get_message(channel, message).await?;
        Ok(m.embeds.into_iter().next().map_or_else(embed, resendable))
    }

    async fn try_surface(&self, request: &RequestRow, agent: &AgentRow) -> Result<(), Failure> {
        let (delegator, thread) = match request.delegation {
            Some(d) => {
                let tx = self.bot.store.begin().await?;
                let delegator = agents::get(&tx, d.delegator_agent_id).await?;
                let thread = a2a::get(&tx, d.thread_id).await?;
                tx.commit().await?;
                (delegator, thread)
            }
            None => (None, None),
        };
        let cfg = &self.bot.cfg;
        let mut channel = cfg.channel_id;
        let (card, components, what) = if request.platform == Platform::Hostexec {
            let host = match self.bot.services().hosts {
                Some(h) => h.host(&request.resource).await,
                None => None,
            };
            let card = hostexec_embed(
                request,
                agent,
                delegator.as_ref(),
                thread.as_ref(),
                host.as_ref(),
            );
            let what = if is_shell(request) {
                channel = cfg.loud_channel();
                let tier = embeds::scope(request)
                    .get("tier")
                    .and_then(Value::as_str)
                    .unwrap_or("None")
                    .to_owned();
                format!(
                    "🚨 **SHELL request** ({} on {})",
                    escape(&tier),
                    escape(&request.resource)
                )
            } else {
                "host command request".to_owned()
            };
            (card, hostexec_pending_view(request), what)
        } else {
            (
                request_embed(request, agent, delegator.as_ref(), thread.as_ref()),
                pending_view(request.id),
                "access request".to_owned(),
            )
        };
        let (ping, base) = self.owner_ping(true);
        let mut content = format!("{ping}{what} from **{}**", escape(&agent.name));
        if let Some(d) = &delegator {
            content.push_str(&format!(" on behalf of **{}**", escape(&d.name)));
        }
        let msg = Message {
            content: Some(content),
            embeds: Some(vec![card]),
            components: Some(components),
            ..base
        };
        let message = self.send(channel, &msg).await?;
        let tx = self.bot.store.begin().await?;
        requests::set_discord(
            &tx,
            request.id,
            DiscordRefs {
                channel_id: to_i64(channel),
                message_id: to_i64(message),
                thread_id: None,
            },
        )
        .await?;
        let fresh = requests::get(&tx, request.id)
            .await?
            .map(requests::AnyRequest::into_row);
        let grant = grants::by_request(&tx, request.id).await?;
        tx.commit().await?;
        // Bug-A4: a decision that landed before the ids were stored found
        // no card to update; bring the card up to date now.
        if let Some(fresh) = fresh.filter(|r| {
            matches!(
                r.status,
                RequestStatus::Granted | RequestStatus::ProvisionFailed | RequestStatus::Denied
            )
        }) {
            self.try_update_outcome(&fresh, grant.as_ref()).await?;
        }
        Ok(())
    }

    async fn try_update_outcome(
        &self,
        request: &RequestRow,
        grant: Option<&GrantRow>,
    ) -> Result<(), Failure> {
        let Some((channel, message)) = ids(self.refs(request).await?) else {
            return Ok(());
        };
        let view = grant.map(GrantView::from);
        let card = apply_outcome(
            self.first_embed(channel, message).await?,
            request,
            view.as_ref(),
        );
        let components = match grant {
            Some(g) if is_shell(request) && g.status == GrantStatus::Active => {
                shell_view(request.id)
            }
            _ => disabled_view(),
        };
        let msg = Message {
            embeds: Some(vec![card]),
            components: Some(components),
            ..Message::default()
        };
        self.bot.rest.edit_message(channel, message, &msg).await?;
        Ok(())
    }

    async fn try_grant_ended(&self, request: &RequestRow, grant: &GrantRow) -> Result<(), Failure> {
        let Some((channel, message)) = ids(self.refs(request).await?) else {
            return Ok(());
        };
        let card = apply_grant_ended(
            self.first_embed(channel, message).await?,
            &GrantView::from(grant),
        );
        let msg = Message {
            embeds: Some(vec![card]),
            ..Message::default()
        };
        self.bot.rest.edit_message(channel, message, &msg).await?;
        Ok(())
    }

    /// The shell's thread: the stored one, else (if `create`) a new thread
    /// on the approval message. `None` when there is no approval message.
    async fn shell_thread(
        &self,
        request: &RequestRow,
        create: bool,
    ) -> Result<Option<u64>, Failure> {
        let refs = self.refs(request).await?;
        if let Some(t) = refs.thread_id.and_then(|t| u64::try_from(t).ok()) {
            return Ok(Some(t));
        }
        let Some((channel, message)) = ids(refs).filter(|_| create) else {
            return Ok(None);
        };
        let tier = embeds::scope(request)
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("None")
            .to_owned();
        let name = cut(&format!("shell · {tier} on {}", request.resource), 100);
        let thread = self.bot.rest.start_thread(channel, message, &name).await?;
        let tx = self.bot.store.begin().await?;
        requests::set_discord(
            &tx,
            request.id,
            DiscordRefs {
                thread_id: to_i64(thread),
                ..DiscordRefs::default()
            },
        )
        .await?;
        tx.commit().await?;
        Ok(Some(thread))
    }

    async fn try_job_finished(&self, request: &RequestRow, job: &JobRow) -> Result<(), Failure> {
        let files: Vec<File> = output_file(job).into_iter().collect();
        let result = result_field(job);
        if job.shell_id.is_some() {
            if let Some(thread) = self.shell_thread(request, false).await? {
                let msg = Message {
                    files,
                    ..Message::text(cut(&result, 2000))
                };
                self.send(thread, &msg).await?;
            }
            return Ok(());
        }
        let Some((channel, message)) = ids(self.refs(request).await?) else {
            // Decided by a rule: no approval message to edit.
            let text = format!(
                "🖥️ `{}` ({}) for request `{}`: {result}",
                code(&job.host),
                job.tier,
                short(request.id)
            );
            let msg = Message {
                files,
                ..Message::text(cut(&text, 2000))
            };
            self.send(self.bot.cfg.activity_channel(), &msg).await?;
            return Ok(());
        };
        let mut card = self.first_embed(channel, message).await?;
        add_field(&mut card, "Result", result, false);
        let edit = Message {
            embeds: Some(vec![card]),
            ..Message::default()
        };
        self.bot.rest.edit_message(channel, message, &edit).await?;
        if !files.is_empty() {
            let msg = Message {
                files,
                message_reference: Some(MessageReference {
                    message_id: message.to_string(),
                }),
                ..Message::text("Full output:")
            };
            self.send(channel, &msg).await?;
        }
        Ok(())
    }

    async fn try_shell_command(&self, request: &RequestRow, job: &JobRow) -> Result<bool, Failure> {
        let Some(thread) = self.shell_thread(request, true).await? else {
            return Ok(false);
        };
        let full = shell_command_text(job);
        let msg = if full.chars().count() <= 1900 {
            Message::text(code_block(&full, 1900))
        } else {
            Message {
                files: vec![File {
                    name: format!("command-{}.txt", short(job.id)),
                    bytes: full.as_bytes().to_vec(),
                }],
                ..Message::text(format!(
                    "{}\n(the whole command is attached)",
                    code_block(&full, 1500)
                ))
            }
        };
        self.send(thread, &msg).await?;
        Ok(true)
    }

    async fn try_watch_alert(
        &self,
        request: &RequestRow,
        job: &JobRow,
        text: &str,
    ) -> Result<(), Failure> {
        let place = if job.shell_id.is_some() {
            self.shell_thread(request, false).await?
        } else {
            None
        };
        let (ping, base) = self.owner_ping(true);
        let content = format!(
            "{ping}🚨 **Look at this** — `{}` ({}), request `{}`: {}\n> {}\nNothing was stopped.",
            code(&job.host),
            job.tier,
            short(request.id),
            code_block(&shlex_join(&job_argv(job)), embeds::MAX_CODE),
            escape(text)
        );
        let msg = Message {
            content: Some(cut(&content, 2000)),
            ..base
        };
        self.send(place.unwrap_or(self.bot.cfg.channel_id), &msg)
            .await?;
        Ok(())
    }

    async fn try_attention(
        &self,
        agent: &AgentRow,
        text: &str,
        urgency: &str,
        desks: &[String],
    ) -> Result<(), Failure> {
        let (ping, base) = self.owner_ping(urgency == "high" || desks.is_empty());
        let shown = if desks.is_empty() {
            String::new()
        } else {
            let desks: Vec<String> = desks.iter().map(|d| escape(d)).collect();
            format!(" (shown on {})", desks.join(", "))
        };
        let content = format!(
            "{ping}🔔 **{}** wants your attention{shown}:\n> {}",
            escape(&agent.name),
            escape(text)
        );
        let msg = Message {
            content: Some(cut(&content, 2000)),
            ..base
        };
        self.send(self.bot.cfg.channel_id, &msg).await?;
        Ok(())
    }

    async fn try_contained(&self, event: &Value) -> Result<(), Failure> {
        let msg = contained_message(event, self.bot.cfg.owner());
        self.send(self.bot.cfg.channel_id, &msg).await?;
        Ok(())
    }
}

fn plain(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The containment ping (spec A.4 `contained`): always pings the owner.
#[must_use]
pub fn contained_message(event: &Value, owner: Option<u64>) -> Message {
    let id = code(&plain(event.get("id")));
    let agents: Vec<String> = event
        .get("agents")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|v| plain(Some(v))).collect())
        .unwrap_or_default();
    let count = |k: &str| event.get(k).and_then(Value::as_u64).unwrap_or(0);
    let ping = owner.map(|o| format!("<@{o}> ")).unwrap_or_default();
    let listed = said(&agents.join(", "), 500);
    let mut lines = vec![
        format!(
            "{ping}🛑 **Containment `{id}`** by {}",
            said(&plain(event.get("by")), 80)
        ),
        format!("> {}", said(&plain(event.get("reason")), 400)),
        format!(
            "Agents ({}): {}",
            agents.len(),
            if listed.is_empty() {
                "none right now (new ones matching are held too)".to_owned()
            } else {
                listed
            }
        ),
        format!(
            "Grants revoked: {} · conversations closed: {}",
            count("grants_revoked"),
            count("threads_closed")
        ),
    ];
    if let Some(d) = event
        .get("daemons")
        .and_then(Value::as_object)
        .filter(|d| !d.is_empty())
    {
        let parts: Vec<String> = d
            .iter()
            .map(|(k, v)| format!("{k} {}", plain(Some(v))))
            .collect();
        lines.push(format!("Hosts/VMs: {}", said(&parts.join(", "), 500)));
    }
    let evidence = plain(event.get("evidence"));
    if !evidence.is_empty() {
        lines.push(format!("Evidence:\n> {}", said(&evidence, 700)));
    }
    lines.push(format!(
        "Lift: `agent-auth admin contain-lift {id}` (or /unlock for a lockdown)"
    ));
    Message {
        content: Some(cut(&lines.join("\n"), 2000)),
        allowed_mentions: Some(mentions(owner)),
        ..Message::default()
    }
}

macro_rules! swallow {
    ($what:expr, $e:expr) => {
        if let Err(e) = $e {
            tracing::warn!("discord: failed to {}: {e}", $what);
        }
    };
}

impl Notify for DiscordNotifier {
    async fn surface(&self, request: &RequestRow, agent: &AgentRow) {
        swallow!(
            format!("surface request {}", request.id),
            self.try_surface(request, agent).await
        );
    }

    async fn update_outcome(&self, request: &RequestRow, grant: Option<&GrantRow>) {
        swallow!(
            format!("update the outcome of request {}", request.id),
            self.try_update_outcome(request, grant).await
        );
    }

    async fn update_grant_ended(&self, request: &RequestRow, grant: &GrantRow) {
        swallow!(
            format!("mark the grant of request {} ended", request.id),
            self.try_grant_ended(request, grant).await
        );
    }

    async fn rule_applied(
        &self,
        request: &RequestRow,
        agent: &AgentRow,
        rule: Option<&RuleRow>,
        grant: Option<&GrantRow>,
    ) {
        let msg = Message {
            embeds: Some(vec![rule_applied_embed(
                request,
                agent,
                rule,
                grant.map(GrantView::from).as_ref(),
            )]),
            allowed_mentions: Some(mentions(None)),
            ..Message::default()
        };
        swallow!(
            format!("log the decision of request {}", request.id),
            self.send(self.bot.cfg.activity_channel(), &msg).await
        );
    }

    async fn job_finished(&self, request: &RequestRow, job: &JobRow) {
        swallow!(
            format!("post the result of job {}", job.id),
            self.try_job_finished(request, job).await
        );
    }

    async fn shell_command(&self, request: &RequestRow, job: &JobRow) -> bool {
        match self.try_shell_command(request, job).await {
            Ok(shown) => shown,
            Err(e) => {
                tracing::warn!("discord: failed to mirror shell command {}: {e}", job.id);
                false
            }
        }
    }

    async fn watch_alert(&self, request: &RequestRow, job: &JobRow, text: &str) {
        swallow!(
            "post a watch alert",
            self.try_watch_alert(request, job, text).await
        );
    }

    async fn attention(&self, agent: &AgentRow, text: &str, urgency: &str, desks: &[String]) {
        swallow!(
            "post an attention message",
            self.try_attention(agent, text, urgency, desks).await
        );
    }

    async fn contained(&self, event: &Value) {
        swallow!(
            "post a containment message",
            self.try_contained(event).await
        );
    }

    async fn mail_held(&self, item: &agent_auth_wire::mail::MailItem) {
        let msg = super::mail::held_message(item, self.bot.cfg.owner());
        swallow!(
            "post a held-mail card",
            self.send(self.bot.cfg.channel_id, &msg).await.map(|_| ())
        );
    }
}
