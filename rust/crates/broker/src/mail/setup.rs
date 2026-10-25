//! Building the gateway at startup (upstream `main.build_mail`): on when
//! `platforms.mail.mailboxes` names a mailbox and `ENCRYPTION_KEY` is set
//! (held drafts are sealed); the judge when `OPENROUTER_API_KEY` is set.
//!
//! Settings (all optional): `MAIL_CA_FILE`, an extra CA (PEM) trusted for
//! the mail servers and SimpleLogin besides the shared roots;
//! `GMAIL_API_URL`, where the Gmail API is (default Google's; the e2e
//! suite points it at a fake).

use std::collections::BTreeMap;
use std::sync::Arc;

use agent_auth_core::policy::Policy;
use agent_auth_crypto::Secret;
use agent_auth_crypto::secretbox::SecretBox;
use agent_auth_store::Store;

use super::Mail;
use super::backends::{Backend, GMAIL_API};
use super::judge::MailJudge;
use super::simplelogin::SimpleLogin;
use crate::provisioners::google::GoogleTokens;

/// What the gateway needs that is not in the policy.
#[derive(Debug, Clone, Default)]
pub struct MailSettings {
    pub secret_box: Option<Arc<SecretBox>>,
    pub openrouter_api_key: Option<String>,
    pub openrouter_base_url: String,
    /// `MAIL_CA_FILE`'s contents.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// `GMAIL_API_URL`.
    pub gmail_api: Option<String>,
    /// The broker's model client (records the judge's calls); without it
    /// the judge gets a client of its own that records nothing.
    pub models: Option<Arc<crate::models::ModelClient>>,
}

/// The TLS config for the mail servers, SimpleLogin and Gmail.
pub fn tls(extra_ca_pem: Option<&[u8]>) -> anyhow::Result<rustls::ClientConfig> {
    let roots = match extra_ca_pem {
        Some(pem) => agent_auth_tls::root_store_plus(pem)
            .map_err(|e| anyhow::anyhow!("MAIL_CA_FILE: {e}"))?,
        None => agent_auth_tls::root_store(),
    };
    Ok(agent_auth_tls::client_config(roots)?)
}

/// The gateway, or None when no mailbox is configured or it can't run.
pub fn build(
    policy: &Arc<Policy>,
    store: &Store,
    settings: &MailSettings,
    google: Option<&Arc<GoogleTokens>>,
) -> anyhow::Result<Option<Arc<Mail>>> {
    let config = &policy.platforms().mail;
    if !config.enabled() {
        return Ok(None);
    }
    let Some(secret_box) = settings.secret_box.clone() else {
        tracing::warn!(
            "platforms.mail has mailboxes but ENCRYPTION_KEY is unset: mail is disabled"
        );
        return Ok(None);
    };
    let tls = tls(settings.extra_ca_pem.as_deref())?;
    let shared = Arc::new(tls.clone());
    let gmail_api = settings.gmail_api.as_deref().unwrap_or(GMAIL_API);
    let mut backends = BTreeMap::new();
    for (name, mailbox) in &config.mailboxes {
        backends.insert(
            name.clone(),
            Backend::new(mailbox, google, gmail_api, &shared)?,
        );
    }
    let judge = match &settings.openrouter_api_key {
        Some(key) => {
            let model = config
                .judge_model
                .clone()
                .unwrap_or_else(|| policy.llm().model.clone());
            let client = match &settings.models {
                Some(c) => Arc::clone(c),
                None => Arc::new(crate::models::ModelClient::new(
                    Secret::new(key.clone()),
                    &settings.openrouter_base_url,
                    None,
                )?),
            };
            Some(MailJudge::new(client, &model))
        }
        None => {
            tracing::warn!(
                "mail: no OPENROUTER_API_KEY, so no judge: no topic constraints, heuristic injection screening, every send held"
            );
            None
        }
    };
    let simplelogin = match &config.simplelogin {
        Some(sl) => Some(SimpleLogin::new(sl, tls)?),
        None => None,
    };
    tracing::info!(
        mailboxes = backends.len(),
        simplelogin = simplelogin.is_some(),
        judge = judge.as_ref().map_or("none", |j| j.model.as_str()),
        "mail: gateway on"
    );
    Ok(Some(Arc::new(Mail::new(
        Arc::clone(policy),
        store.clone(),
        secret_box,
        backends,
        simplelogin,
        judge,
    ))))
}
