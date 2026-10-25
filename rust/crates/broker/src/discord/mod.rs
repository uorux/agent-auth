//! The Discord bot (rust/spec/human-and-agent-surfaces.md part A): approval
//! cards and their buttons and modals, the rules browser, containment
//! commands, and the notifier ([`DiscordNotifier`], the `Notify` the
//! request service reports to).
//!
//! - `text`: escaping and Python-style trimming (agent text is inert).
//! - `model`: builders over twilight-model's types.
//! - `embeds`, `views`, `rules`, `commands`: what is shown, as pure
//!   functions.
//! - `ops`: what the bot needs from the rest of the broker (decide,
//!   revoke, contain, lift, host status), as interfaces `main` attaches.
//! - `rest`, `gateway`: Discord's REST API and gateway over the shared
//!   TLS stack.
//! - `interactions`: buttons, modals and commands, each from the owner
//!   only ([`crate::auth::DiscordOwner`]).
//! - `notifier`: the `Notify` implementation.

use std::sync::{Arc, OnceLock};

use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use tokio::sync::mpsc;

pub mod commands;
pub mod embeds;
pub mod gateway;
pub mod hostexec;
pub mod interactions;
pub mod mail;
pub mod model;
pub mod notifier;
pub mod ops;
pub mod rest;
pub mod rules;
pub mod text;
pub mod views;

pub use notifier::DiscordNotifier;
pub use ops::{ContainmentOps, HostsOps, HumanDecision, OpError, RequestOps};

use self::rest::{Rest, RestError};

/// The bot's settings (spec A.1), from the environment.
pub struct DiscordConfig {
    pub token: Secret<String>,
    /// The approvals channel; slash commands sync to its guild.
    pub channel_id: u64,
    /// The only user whose interactions count; 0: nobody's.
    pub owner_id: u64,
    /// Shell requests; 0: the approvals channel.
    pub loud_channel_id: u64,
    /// What needs no one (audit lines); 0: the approvals channel.
    pub activity_channel_id: u64,
    pub api_base: String,
    pub gateway_url: String,
}

impl std::fmt::Debug for DiscordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscordConfig")
            .field("channel_id", &self.channel_id)
            .field("owner_id", &self.owner_id)
            .field("loud_channel_id", &self.loud_channel_id)
            .field("activity_channel_id", &self.activity_channel_id)
            .finish_non_exhaustive()
    }
}

impl DiscordConfig {
    /// From the process environment; `Ok(None)` when `DISCORD_TOKEN` is
    /// empty (no bot: the null notifier, and main logs a warning).
    pub fn from_env() -> Result<Option<DiscordConfig>, String> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// From any variable source (tests).
    pub fn from_vars(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<DiscordConfig>, String> {
        let token = get("DISCORD_TOKEN").unwrap_or_default();
        let token = token.trim();
        if token.is_empty() {
            return Ok(None);
        }
        let id = |key: &str| -> Result<u64, String> {
            match get(key) {
                None => Ok(0),
                Some(v) if v.trim().is_empty() => Ok(0),
                Some(v) => v
                    .trim()
                    .parse()
                    .map_err(|_| format!("{key} must be a Discord id (a number)")),
            }
        };
        // Discord itself unless set (a fake Discord in the e2e tests).
        let url = |key: &str, default: &str| {
            get(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_owned())
        };
        Ok(Some(DiscordConfig {
            token: Secret::new(token.to_owned()),
            channel_id: id("DISCORD_CHANNEL_ID")?,
            owner_id: id("DISCORD_OWNER_ID")?,
            loud_channel_id: id("DISCORD_LOUD_CHANNEL_ID")?,
            activity_channel_id: id("DISCORD_ACTIVITY_CHANNEL_ID")?,
            api_base: url("DISCORD_API_URL", rest::DISCORD_API),
            gateway_url: url("DISCORD_GATEWAY_URL", gateway::DISCORD_GATEWAY),
        }))
    }

    /// Where shell requests go.
    #[must_use]
    pub fn loud_channel(&self) -> u64 {
        if self.loud_channel_id != 0 {
            self.loud_channel_id
        } else {
            self.channel_id
        }
    }

    /// Where what needs no one goes.
    #[must_use]
    pub fn activity_channel(&self) -> u64 {
        if self.activity_channel_id != 0 {
            self.activity_channel_id
        } else {
            self.channel_id
        }
    }

    /// The owner, when one is configured.
    #[must_use]
    pub fn owner(&self) -> Option<u64> {
        (self.owner_id != 0).then_some(self.owner_id)
    }
}

/// The other parts of the broker the bot calls; attached once by `main`
/// after they exist (the request service needs the notifier first).
#[derive(Default, Clone)]
pub struct Services {
    pub requests: Option<Arc<dyn RequestOps>>,
    pub containment: Option<Arc<dyn ContainmentOps>>,
    pub hosts: Option<Arc<dyn HostsOps>>,
    /// The broker's state, for the hostexec commands (`crate::hostexec`'s
    /// arm, disarm, open_window, lockdown, unlock; the desktop's DND; the
    /// daemon list).
    pub app: Option<crate::state::AppState>,
    /// The mail gateway: Release / Discard on held mail.
    pub mail: Option<Arc<dyn crate::mail::MailOps>>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("requests", &self.requests.is_some())
            .field("containment", &self.containment.is_some())
            .field("hosts", &self.hosts.is_some())
            .field("app", &self.app.is_some())
            .field("mail", &self.mail.is_some())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct Bot {
    pub(crate) cfg: DiscordConfig,
    pub(crate) rest: Rest,
    pub(crate) store: Store,
    pub(crate) services: OnceLock<Services>,
}

impl Bot {
    pub(crate) fn services(&self) -> Services {
        self.services.get().cloned().unwrap_or_default()
    }
}

/// The bot: cheap to clone.
#[derive(Debug, Clone)]
pub struct Discord(Arc<Bot>);

impl Discord {
    pub fn new(cfg: DiscordConfig, store: Store) -> Result<Discord, RestError> {
        let rest = Rest::new(&cfg.token, &cfg.api_base)?;
        Ok(Discord(Arc::new(Bot {
            cfg,
            rest,
            store,
            services: OnceLock::new(),
        })))
    }

    /// Attach the services (once; a second call is ignored and returns
    /// false).
    pub fn attach(&self, services: Services) -> bool {
        self.0.services.set(services).is_ok()
    }

    /// The notifier half, for `AppState::notifier`.
    #[must_use]
    pub fn notifier(&self) -> DiscordNotifier {
        DiscordNotifier::new(Arc::clone(&self.0))
    }

    /// Handle one interaction (the gateway calls this; tests too).
    pub async fn handle(&self, interaction: twilight_model::application::interaction::Interaction) {
        // Boxed: the handlers' futures are large (lockdowns, windows).
        Box::pin(interactions::handle(&self.0, interaction)).await;
    }

    /// Connect to the gateway and serve interactions until the gateway
    /// refuses the bot for good. Slash commands are synced once per
    /// process, on the first READY.
    pub async fn run(self) {
        let tls = match agent_auth_tls::default_client_config() {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!("discord: no TLS config: {e}");
                return;
            }
        };
        let (tx, mut rx) = mpsc::channel(64);
        let gateway = tokio::spawn(gateway::run(
            self.0.cfg.gateway_url.clone(),
            self.0.cfg.token.clone(),
            tls,
            tx,
        ));
        let mut synced = false;
        while let Some(delivered) = rx.recv().await {
            match delivered {
                gateway::Delivered::Ready { application_id } => {
                    tracing::info!("discord bot ready");
                    if let (false, Some(app)) = (synced, application_id) {
                        synced = commands::sync(&self.0, app).await;
                    }
                }
                gateway::Delivered::Interaction(i) => {
                    let bot = self.clone();
                    tokio::spawn(async move { bot.handle(*i).await });
                }
            }
        }
        gateway.abort();
    }
}

#[cfg(test)]
mod hostexec_tests;
#[cfg(test)]
mod tests;
