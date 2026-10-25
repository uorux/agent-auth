//! Building the provisioners from their configuration (environment plus
//! the policy's platform sections; provisioners spec §1.3, §12). `main`
//! calls [`build`] once at startup and registers what it returns.

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_auth_core::policy::Policy;
use agent_auth_crypto::daemon::SigningKey;
use agent_auth_crypto::jwt::TokenIssuer;
use agent_auth_crypto::secretbox::SecretBox;

use super::AnyProvisioner;
use super::github::{GithubApp, GithubProvisioner};
use super::google::{GoogleProvisioner, GoogleStubProvisioner, GoogleTokens};
use super::kubernetes::KubernetesProvisioner;
use super::lldap::LldapProvisioner;
use super::mcp::McpProvisioner;
use super::models::ModelsProvisioner;
use super::pool::PoolProvisioner;
use crate::wiki::Wiki;

/// Configuration the broker cannot start with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// The environment, as a lookup (the process's, or a map in tests).
pub struct Env<'a>(&'a (dyn Fn(&str) -> Option<String> + Sync));

impl std::fmt::Debug for Env<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Env(..)")
    }
}

fn process_var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

impl<'a> Env<'a> {
    #[must_use]
    pub fn new(lookup: &'a (dyn Fn(&str) -> Option<String> + Sync)) -> Env<'a> {
        Env(lookup)
    }

    /// The process environment.
    #[must_use]
    pub fn process() -> Env<'static> {
        Env(&process_var)
    }

    /// The value, or empty when unset.
    #[must_use]
    pub fn get(&self, key: &str) -> String {
        (self.0)(key).unwrap_or_default()
    }

    /// The value, or `default` when unset or empty.
    #[must_use]
    pub fn get_or(&self, key: &str, default: &str) -> String {
        let v = self.get(key);
        if v.is_empty() { default.to_owned() } else { v }
    }

    /// A boolean the way pydantic-settings reads one.
    pub fn flag(&self, key: &str) -> Result<bool, ConfigError> {
        match self.get(key).trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "f" | "no" | "n" | "off" => Ok(false),
            "1" | "true" | "t" | "yes" | "y" | "on" => Ok(true),
            other => Err(ConfigError(format!("{key}: {other:?} is not a boolean"))),
        }
    }
}

/// An environment from a map (tests, tools).
pub fn map_lookup(map: BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + Sync {
    move |k: &str| map.get(k).cloned()
}

/// What the provisioners' part shares with handlers (one `AppState`
/// field): the MCP token issuer (token routes), the wiki, and the GitHub
/// App (the wiki's backend; also the admin views).
#[derive(Debug, Default)]
pub struct PlatformServices {
    pub tokens: Option<Arc<TokenIssuer>>,
    pub wiki: Option<Arc<Wiki>>,
    pub github: Option<Arc<GithubApp>>,
    /// The Google logins (also the mail gateway's Gmail backend).
    pub google_tokens: Option<Arc<GoogleTokens>>,
}

/// What [`build`] made: the provisioners to register, and the services.
#[derive(Debug)]
pub struct Built {
    pub provisioners: Vec<AnyProvisioner>,
    pub services: PlatformServices,
}

/// Inputs `main` already parsed.
#[derive(Debug, Clone, Copy)]
pub struct Keys<'a> {
    /// `ENCRYPTION_KEY`, when set.
    pub secret_box: Option<&'a Arc<SecretBox>>,
    /// `BROKER_SIGNING_KEY`, when set.
    pub signing_key: Option<&'a SigningKey>,
}

/// Every platform this part owns whose configuration is present (§1.3).
/// google is always on (the stub without accounts); the others need their
/// settings. A platform whose
/// configuration is present but unusable is an error (the broker does not
/// start), except where the Python only warned (models, homelab managed
/// accounts), which log a warning.
pub fn build(env: &Env<'_>, policy: &Arc<Policy>, keys: Keys<'_>) -> Result<Built, ConfigError> {
    let platforms = policy.platforms();
    let mut provisioners = Vec::new();
    let mut services = PlatformServices::default();

    if platforms.google.accounts.is_empty() {
        provisioners.push(AnyProvisioner::GoogleStub(GoogleStubProvisioner));
    } else {
        let tokens = Arc::new(GoogleTokens::new(&platforms.google)?);
        services.google_tokens = Some(Arc::clone(&tokens));
        provisioners.push(AnyProvisioner::Google(GoogleProvisioner::new(
            &platforms.google,
            tokens,
        )));
        tracing::info!(
            accounts = platforms.google.accounts.len(),
            "google: account(s) configured"
        );
    }

    if let Some(app) = GithubApp::from_env(env)? {
        let app = Arc::new(app);
        provisioners.push(AnyProvisioner::Github(GithubProvisioner::new(
            Arc::clone(&app),
            &platforms.github,
            keys.secret_box.cloned(),
        )?));
        services.github = Some(app);
    }

    if let Some(l) = LldapProvisioner::from_env(env, &platforms.homelab, keys.secret_box.cloned())?
    {
        provisioners.push(AnyProvisioner::Homelab(l));
    }

    if let Some(k) =
        KubernetesProvisioner::from_env(env, &platforms.kubernetes, Arc::clone(policy))?
    {
        provisioners.push(AnyProvisioner::Kubernetes(k));
    }

    if let Some(m) = ModelsProvisioner::from_env(env, &platforms.models, keys.secret_box.cloned())?
    {
        provisioners.push(AnyProvisioner::Models(m));
    }

    if let Some(key) = keys.signing_key
        && !platforms.mcp.servers.is_empty()
    {
        let issuer = TokenIssuer::new(key, &platforms.mcp.issuer)
            .map_err(|e| ConfigError(format!("MCP token key: {e}")))?;
        let issuer = Arc::new(issuer);
        provisioners.push(AnyProvisioner::Mcp(McpProvisioner::new(
            &platforms.mcp,
            Arc::clone(&issuer),
        )));
        services.tokens = Some(issuer);
    }

    if !platforms.pools.is_empty() {
        tracing::info!(
            pools = %platforms.pools.keys().cloned().collect::<Vec<_>>().join(", "),
            "pools"
        );
        provisioners.push(AnyProvisioner::Pool(PoolProvisioner::new(&platforms.pools)));
    }

    let wiki_cfg = policy.wiki();
    if !wiki_cfg.repo.is_empty() {
        match &services.github {
            Some(app) => {
                services.wiki = Some(Arc::new(Wiki::new(Arc::clone(app), Arc::clone(policy))));
            }
            None => tracing::warn!(
                repo = %wiki_cfg.repo,
                "wiki.repo is set but GitHub is not configured; the wiki is off"
            ),
        }
    }

    Ok(Built {
        provisioners,
        services,
    })
}
