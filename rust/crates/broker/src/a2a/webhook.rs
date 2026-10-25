//! Webhook pings (a2a spec §4): notify-only, never a payload, always
//! signed, delivered after commit.
//!
//! What a webhook URL may be ([`check_url`]): an `https` URL with a host;
//! plain `http` only to a host listed in `A2A_WEBHOOK_HTTP_HOSTS` (for an
//! agent on the same machine or a trusted internal network). No other
//! scheme. Webhook URLs are set only by the operator (admin API), so this
//! is not a full SSRF filter: private addresses are allowed over https.
//! Requests never follow redirects, never use a proxy from the environment,
//! time out after 5 s, and carry nothing but the ping (thread id, names,
//! topic, sequence numbers), signed with the target's own secret or the
//! broker-wide `WEBHOOK_SIGNING_SECRET`; without either, nothing is sent.
//!
//! Delivery (a2a B9): pings go out from a background task, one batch per
//! operation, so a blackholed webhook never delays or fails an API call;
//! every failure is logged and dropped (the cursor read is authoritative).

use std::sync::OnceLock;
use std::time::Duration;

use agent_auth_core::containment::AgentKind;
use agent_auth_crypto::Secret;
use agent_auth_crypto::webhook::{SIGNATURE_HEADER, sign_body};
use agent_auth_store::agents::AgentRow;
use agent_auth_wire::a2a::WebhookPing;
use url::Url;

use super::A2aConfig;

const TIMEOUT: Duration = Duration::from_secs(5);

/// The message an admin route answers (422) for a URL [`check_url`] refuses.
pub const BAD_URL: &str = "webhook_url must be an https URL with a host \
                           (plain http only to the hosts in A2A_WEBHOOK_HTTP_HOSTS)";

/// Whether a webhook URL may be stored and pinged. The admin routes that
/// set one (create, set-webhook) call this and answer 422 [`BAD_URL`];
/// delivery checks again (the host list may have changed since).
pub fn check_url(config: &A2aConfig, url: &str) -> Result<Url, &'static str> {
    let parsed = Url::parse(url).map_err(|_| BAD_URL)?;
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(BAD_URL)?
        .to_ascii_lowercase();
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http"
            if config
                .webhook_http_hosts
                .iter()
                .any(|h| *h == host || format!("[{h}]") == host) =>
        {
            Ok(parsed)
        }
        _ => Err(BAD_URL),
    }
}

/// One ping's ingredients, captured inside the transaction.
pub(crate) struct Ping {
    agent: String,
    url: String,
    secret: Secret<String>,
    event: WebhookPing,
}

impl std::fmt::Debug for Ping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ping")
            .field("agent", &self.agent)
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
}

/// The ping for `agent`, if it receives pings: a service agent with a
/// webhook and a signing secret (its own, else the broker's). Never
/// unsigned (a2a INV-12).
pub(crate) fn target(config: &A2aConfig, agent: &AgentRow, event: WebhookPing) -> Option<Ping> {
    if agent.kind != AgentKind::Service {
        return None;
    }
    let url = agent.webhook_url.as_ref()?;
    let secret = agent
        .webhook_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| Secret::new(s.clone()))
        .or_else(|| {
            config
                .webhook_signing_secret
                .as_ref()
                .map(|s| Secret::new(s.expose().clone()))
        });
    let Some(secret) = secret else {
        tracing::warn!(agent = %agent.name, "no webhook signing secret; skipping ping");
        return None;
    };
    Some(Ping {
        agent: agent.name.clone(),
        url: url.clone(),
        secret,
        event,
    })
}

/// The HTTP client, built on first use.
#[derive(Debug, Default)]
pub(crate) struct Webhooks {
    client: OnceLock<Option<reqwest::Client>>,
}

impl Webhooks {
    fn client(&self) -> Option<reqwest::Client> {
        self.client
            .get_or_init(|| {
                let built = agent_auth_tls::default_client_config()
                    .map_err(|e| e.to_string())
                    .and_then(|tls| {
                        agent_auth_tls::reqwest_builder(tls, TIMEOUT)
                            .build()
                            .map_err(|e| e.to_string())
                    });
                match built {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::error!(error = %e, "webhook client unavailable; pings are off");
                        None
                    }
                }
            })
            .clone()
    }

    /// Send these pings, in order, from a background task.
    pub(crate) fn deliver(&self, config: &A2aConfig, pings: Vec<Ping>) {
        let pings: Vec<(Ping, Url)> = pings
            .into_iter()
            .filter_map(|p| match check_url(config, &p.url) {
                Ok(u) => Some((p, u)),
                Err(_) => {
                    tracing::warn!(agent = %p.agent, "webhook URL not allowed; skipping ping");
                    None
                }
            })
            .collect();
        if pings.is_empty() {
            return;
        }
        let Some(client) = self.client() else {
            return;
        };
        tokio::spawn(async move {
            for (ping, url) in pings {
                send(&client, ping, url).await;
            }
        });
    }
}

async fn send(client: &reqwest::Client, ping: Ping, url: Url) {
    let body = match serde_json::to_vec(&ping.event) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "could not encode a ping");
            return;
        }
    };
    let signature = sign_body(ping.secret.expose().as_bytes(), &body);
    let sent = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(SIGNATURE_HEADER, signature)
        .body(body)
        .send()
        .await;
    if let Err(e) = sent {
        tracing::warn!(
            agent = %ping.agent,
            error = %e.without_url(),
            "a2a webhook ping failed (poll remains authoritative)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_anywhere_http_only_to_listed_hosts() {
        let mut c = A2aConfig::default();
        assert!(check_url(&c, "https://hooks.example/cb").is_ok());
        assert!(check_url(&c, "https://10.0.0.5:8443/cb").is_ok());
        assert_eq!(
            check_url(&c, "http://hooks.internal/cb").unwrap_err(),
            BAD_URL
        );
        assert!(check_url(&c, "ftp://x/y").is_err());
        assert!(check_url(&c, "https:").is_err());
        assert!(check_url(&c, "not a url").is_err());
        assert!(check_url(&c, "file:///etc/passwd").is_err());
        c.webhook_http_hosts = vec!["hooks.internal".into(), "127.0.0.1".into(), "::1".into()];
        assert!(check_url(&c, "http://HOOKS.internal:8080/cb").is_ok());
        assert!(check_url(&c, "http://127.0.0.1:9/cb").is_ok());
        assert!(check_url(&c, "http://[::1]:9/cb").is_ok());
        assert!(check_url(&c, "http://other.internal/cb").is_err());
    }
}
