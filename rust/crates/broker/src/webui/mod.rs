//! The broker's web surfaces for people and web UIs (surfaces spec §B, §C):
//!
//! - [`panel`]: the admin panel at `/ui`. The operator signs in at the
//!   homelab's OpenID provider ([`oidc`]); the broker checks the ID token
//!   itself and the admin group, and keeps the session in a sealed cookie
//!   ([`cookies`]). A session reaches a closed list of admin routes
//!   (`panel::allowed`), with a CSRF token on every write; the
//!   `AdminCaller` extractor asks [`panel::admin_session`] first.
//! - [`crate::oauth`]: the OAuth server web UIs (claude.ai, ChatGPT) use to
//!   connect as an agent; consent needs a signed-in admin.
//! - [`crate::remote_mcp`]: `/mcp`, the agent tools over streamable HTTP for
//!   those connectors.
//!
//! All three are off unless the policy enables them and `ENCRYPTION_KEY`
//! is set. [`Web::from_policy`] builds them; [`install`] puts them into
//! the [`AppState`] (and turns on OAuth bearer tokens on the agent API);
//! [`routes`] serves them.

use std::sync::Arc;

use agent_auth_core::policy::Policy;
use axum::Router;

use crate::auth::AuthConfig;
use crate::oauth::OAuthServer;
use crate::remote_mcp::RemoteMcp;
use crate::state::AppState;

pub mod cookies;
pub mod oidc;
pub mod panel;

pub use panel::Panel;

/// The admin panel, the OAuth server and the remote MCP endpoint, each
/// `None` when off.
#[derive(Debug, Default)]
pub struct Web {
    pub panel: Option<Arc<Panel>>,
    pub oauth: Option<Arc<OAuthServer>>,
    pub remote_mcp: Option<Arc<RemoteMcp>>,
}

/// The configuration does not hold together.
#[derive(Debug, thiserror::Error)]
pub enum WebConfigError {
    #[error("ENCRYPTION_KEY: {0}")]
    Key(#[from] agent_auth_crypto::secretbox::KeyError),
    #[error("{0}")]
    Http(String),
    #[error("{0}")]
    Invalid(String),
}

impl Web {
    /// From the policy's `ui` and `remote_mcp` sections. Without
    /// `encryption_key` everything stays off (with a warning when the
    /// policy asked for it), as in the Python (main.py:199-215).
    pub fn from_policy(
        policy: &Policy,
        encryption_key: Option<&str>,
    ) -> Result<Web, WebConfigError> {
        let ui = policy.ui();
        let remote = policy.remote_mcp();
        let Some(key) = encryption_key.filter(|k| !k.trim().is_empty()) else {
            if ui.enabled {
                tracing::warn!(
                    "ui is enabled in the policy but ENCRYPTION_KEY is not set: the admin panel is off"
                );
            }
            if remote.enabled {
                tracing::warn!(
                    "remote_mcp is enabled in the policy but ENCRYPTION_KEY is not set: it is off"
                );
            }
            return Ok(Web::default());
        };
        if !ui.enabled && !remote.enabled {
            return Ok(Web::default());
        }
        let sealer = Arc::new(cookies::Sealer::new(key)?);
        let sign_in = Arc::new(oidc::OidcClient::new(
            &ui.issuer,
            &ui.client_id,
            &ui.admin_group,
        )?);
        let panel = ui.enabled.then(|| {
            Arc::new(Panel::new(
                &ui.base_url,
                ui.session_ttl.as_i64(),
                sealer.clone(),
                sign_in.clone(),
            ))
        });
        let (oauth, remote_mcp) = if remote.enabled {
            let oauth = Arc::new(OAuthServer::new(remote, sealer, sign_in)?);
            let mcp = Arc::new(RemoteMcp::new(remote)?);
            (Some(oauth), Some(mcp))
        } else {
            (None, None)
        };
        Ok(Web {
            panel,
            oauth,
            remote_mcp,
        })
    }
}

/// Put the web surfaces into the state. With the OAuth server on, the agent
/// API also accepts its access tokens (`aat_`, spec §C.7). Call before the
/// state is shared (at startup).
#[must_use]
pub fn install(mut state: AppState, web: Web) -> AppState {
    if web.oauth.is_some() && !state.auth.oauth_enabled {
        state.auth = Arc::new(AuthConfig {
            admin_token: state.auth.admin_token.clone(),
            oauth_enabled: true,
            trust_x_real_ip: state.auth.trust_x_real_ip,
        });
    }
    state.web = Arc::new(web);
    state
}

/// `/ui*`, the OAuth endpoints (with `/admin/connectors`), and `/mcp`.
/// Each answers 404 while its part is off.
pub fn routes() -> Router<AppState> {
    panel::routes()
        .merge(crate::oauth::routes())
        .merge(crate::remote_mcp::routes())
}

/// HTML-escapes text for a page (Python's `html.escape`, quotes included).
#[must_use]
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// The `host[:port]` of an absolute URL, lowercased, with the scheme's
/// default port left out (so `Host: panel.example:443` is the panel's own
/// name, surfaces Bug-B2).
#[must_use]
pub(crate) fn authority(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}
