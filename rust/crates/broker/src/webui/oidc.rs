//! Signing in at the homelab's OpenID provider (surfaces spec §B.5): the
//! authorization-code flow with PKCE as a **public** client (no client
//! secret), the ID token verified here against the provider's JWKS
//! (`agent_auth_crypto::oidc`), and membership in the admin group.
//!
//! Nothing a proxy adds to a request is trusted: the proof is the
//! provider's signature on the ID token. Used by the admin panel and by the
//! OAuth server's consent (whoever authorizes a connector is an admin).

use std::sync::Arc;
use std::time::Duration;

use agent_auth_crypto::oidc::{IdTokenError, verify_id_token};
use agent_auth_crypto::{b64url_encode, ct_eq, digest, token_urlsafe};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use super::WebConfigError;

/// The longest reply read from the provider.
const MAX_REPLY_BYTES: usize = 1024 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(20);
/// A user name longer than this is cut (it is shown and recorded).
const MAX_USER_CHARS: usize = 128;

/// A sign-in in progress, sealed into the login cookie (600 s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub redirect_uri: String,
    /// What another sign-in (the OAuth server's) carries to its return.
    #[serde(default)]
    pub carry: Option<Value>,
}

/// Why a sign-in did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInError {
    /// Refused; the text is shown to the person signing in.
    Refused(String),
    /// The provider could not be reached or answered nonsense.
    Unreachable,
}

impl SignInError {
    fn refused(text: impl Into<String>) -> SignInError {
        SignInError::Refused(text.into())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    #[serde(default)]
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
}

/// The provider, as configured (`ui.issuer`, `ui.client_id`,
/// `ui.admin_group`). Discovery and keys are fetched once and kept; the
/// keys are fetched again when a token names a key they lack.
pub struct OidcClient {
    issuer: String,
    client_id: String,
    admin_group: String,
    http: reqwest::Client,
    discovery: RwLock<Option<Arc<Discovery>>>,
    jwks: RwLock<Option<Arc<Value>>>,
}

impl std::fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// `b64url_nopad(sha256(verifier))`: the PKCE S256 challenge.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    b64url_encode(&digest::sha256(verifier.as_bytes()))
}

async fn read_json(resp: reqwest::Response) -> Result<Value, SignInError> {
    let mut resp = resp;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| SignInError::Unreachable)? {
        if body.len().saturating_add(chunk.len()) > MAX_REPLY_BYTES {
            return Err(SignInError::Unreachable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| SignInError::Unreachable)
}

impl OidcClient {
    pub fn new(
        issuer: &str,
        client_id: &str,
        admin_group: &str,
    ) -> Result<OidcClient, WebConfigError> {
        let tls = agent_auth_tls::default_client_config()
            .map_err(|e| WebConfigError::Http(e.to_string()))?;
        let http = agent_auth_tls::reqwest_builder(tls, TOKEN_TIMEOUT)
            .build()
            .map_err(|e| WebConfigError::Http(e.to_string()))?;
        Ok(OidcClient {
            issuer: issuer.trim_end_matches('/').to_owned(),
            client_id: client_id.to_owned(),
            admin_group: admin_group.to_owned(),
            http,
            discovery: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    async fn discover(&self) -> Result<Arc<Discovery>, SignInError> {
        if let Some(found) = self.discovery.read().await.as_ref() {
            return Ok(found.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let resp = self
            .http
            .get(&url)
            .timeout(DISCOVERY_TIMEOUT)
            .send()
            .await
            .map_err(|_| SignInError::Unreachable)?;
        if !resp.status().is_success() {
            return Err(SignInError::Unreachable);
        }
        let found: Discovery =
            serde_json::from_value(read_json(resp).await?).map_err(|_| SignInError::Unreachable)?;
        if found.issuer.trim_end_matches('/') != self.issuer {
            return Err(SignInError::refused(
                "the provider's discovery document names another issuer",
            ));
        }
        let found = Arc::new(found);
        *self.discovery.write().await = Some(found.clone());
        Ok(found)
    }

    async fn keys(&self, refresh: bool) -> Result<Arc<Value>, SignInError> {
        if !refresh && let Some(keys) = self.jwks.read().await.as_ref() {
            return Ok(keys.clone());
        }
        let found = self.discover().await?;
        let resp = self
            .http
            .get(&found.jwks_uri)
            .timeout(DISCOVERY_TIMEOUT)
            .send()
            .await
            .map_err(|_| SignInError::Unreachable)?;
        if !resp.status().is_success() {
            return Err(SignInError::Unreachable);
        }
        let keys = Arc::new(read_json(resp).await?);
        *self.jwks.write().await = Some(keys.clone());
        Ok(keys)
    }

    /// Where to send the browser, and the attempt to seal into the login
    /// cookie. `redirect_uri` is where the provider sends the browser
    /// back; `carry` rides along to the return.
    pub async fn begin(
        &self,
        redirect_uri: &str,
        carry: Option<Value>,
    ) -> Result<(String, LoginAttempt), SignInError> {
        let random = |n| token_urlsafe(n).map_err(|_| SignInError::Unreachable);
        let (state, nonce, verifier) = (random(24)?, random(24)?, random(48)?);
        let found = self.discover().await?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid profile groups")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &pkce_challenge(&verifier))
            .append_pair("code_challenge_method", "S256")
            .finish();
        let sep = if found.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!("{}{sep}{query}", found.authorization_endpoint);
        Ok((
            url,
            LoginAttempt {
                state,
                nonce,
                verifier,
                redirect_uri: redirect_uri.to_owned(),
                carry,
            },
        ))
    }

    /// The provider sent the browser back with `code` and `state`: who
    /// signed in (if they are in the admin group), and what the attempt
    /// carried. `attempt` is the opened login cookie (`None`: missing,
    /// expired or not ours).
    pub async fn identify(
        &self,
        attempt: Option<LoginAttempt>,
        code: &str,
        state: &str,
        now: OffsetDateTime,
    ) -> Result<(String, Option<Value>), SignInError> {
        let attempt = attempt
            .filter(|a| ct_eq(a.state.as_bytes(), state.as_bytes()))
            .ok_or_else(|| {
                SignInError::refused(
                    "this sign-in was not started here, or took too long; try again",
                )
            })?;
        let found = self.discover().await?;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &attempt.redirect_uri)
            .append_pair("client_id", &self.client_id)
            .append_pair("code_verifier", &attempt.verifier)
            .finish();
        let resp = self
            .http
            .post(&found.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(form)
            .send()
            .await
            .map_err(|_| SignInError::Unreachable)?;
        if resp.status() != reqwest::StatusCode::OK {
            tracing::warn!(status = %resp.status(), "admin panel: the provider refused the code");
            return Err(SignInError::refused("the provider refused the sign-in"));
        }
        let tokens = read_json(resp).await?;
        let id_token = tokens.get("id_token").and_then(Value::as_str).unwrap_or("");
        let claims = self.verify(id_token, now).await?;
        let nonce = claims.get("nonce").and_then(Value::as_str).unwrap_or("");
        if !ct_eq(nonce.as_bytes(), attempt.nonce.as_bytes()) {
            return Err(SignInError::refused(
                "the ID token answers a different sign-in",
            ));
        }
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let mut groups = claims.get("groups").filter(|v| !v.is_null()).cloned();
        let mut user = claims
            .get("preferred_username")
            .filter(|v| !v.is_null())
            .cloned();
        if groups.is_none() || user.is_none() {
            // Providers may keep these out of the ID token (Authelia does by
            // default) and serve them from userinfo.
            let info = self
                .userinfo(
                    &found,
                    tokens
                        .get("access_token")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                )
                .await?;
            if info.get("sub").and_then(Value::as_str) != Some(sub.as_str()) {
                return Err(SignInError::refused(
                    "the provider did not say who signed in",
                ));
            }
            groups = groups.or_else(|| info.get("groups").cloned());
            user = user.or_else(|| info.get("preferred_username").cloned());
        }
        let user = user
            .as_ref()
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty())
            .unwrap_or(sub.as_str());
        let user: String = user.chars().take(MAX_USER_CHARS).collect();
        let member = groups.as_ref().and_then(Value::as_array).is_some_and(|g| {
            g.iter()
                .any(|v| v.as_str() == Some(self.admin_group.as_str()))
        });
        if !member {
            tracing::warn!(
                user,
                group = self.admin_group,
                "admin panel: signed in but not in the admin group"
            );
            return Err(SignInError::Refused(format!(
                "{user} is not in the group {}",
                self.admin_group
            )));
        }
        Ok((user, attempt.carry))
    }

    async fn userinfo(
        &self,
        found: &Discovery,
        access_token: &str,
    ) -> Result<Map<String, Value>, SignInError> {
        let refused = || SignInError::refused("the provider did not say who signed in");
        let endpoint = found.userinfo_endpoint.as_deref().ok_or_else(refused)?;
        let resp = self
            .http
            .get(endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| SignInError::Unreachable)?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(refused());
        }
        match read_json(resp).await {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(refused()),
        }
    }

    async fn verify(
        &self,
        id_token: &str,
        now: OffsetDateTime,
    ) -> Result<Map<String, Value>, SignInError> {
        let issuer_slash = format!("{}/", self.issuer);
        let issuers = [self.issuer.as_str(), issuer_slash.as_str()];
        // Seconds with the fraction, as PyJWT compares.
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "a time::Duration holds any difference of two OffsetDateTimes"
        )]
        let now_unix = (now - OffsetDateTime::UNIX_EPOCH).as_seconds_f64();
        let mut outcome = Err(IdTokenError::UnknownKey);
        for refresh in [false, true] {
            let keys = self.keys(refresh).await?;
            outcome = verify_id_token(id_token, &keys, &self.client_id, &issuers, now_unix);
            if outcome != Err(IdTokenError::UnknownKey) {
                break;
            }
        }
        outcome.map_err(|e| {
            tracing::warn!(error = %e, "admin panel: ID token rejected");
            SignInError::refused("the provider's ID token did not check out")
        })
    }
}
