//! The OAuth server that lets web UIs (claude.ai, ChatGPT connectors) use
//! the broker as a remote MCP server (policy `remote_mcp`; surfaces spec
//! §C). The HTTP side is [`routes`].
//!
//! - Registration is dynamic (RFC 7591) and open; a client may only send
//!   the browser back to one of `remote_mcp.redirect_uris`, exactly.
//!   Registrations nobody authorized have their own cap
//!   ([`MAX_UNBOUND_CLIENTS`], the oldest evicted) and expire after
//!   [`UNBOUND_CLIENT_TTL`]; `max_clients` caps authorized clients; each
//!   address may register [`REGISTRATIONS_PER_HOUR`] an hour.
//! - Authorization is the code flow with PKCE (S256 only). The person
//!   authorizing signs in at the admin panel's provider and must be in its
//!   admin group; the consent form names the agent the client acts as.
//! - A client acts as one agent `web-<name>` (runtime `web`, kind
//!   ephemeral, no usable API key), bound at its first authorization.
//! - Codes (`aac_`, 5 minutes) and refresh tokens (`art_`) are single use,
//!   consumed atomically (`store::oauth::consume`); one presented twice
//!   revokes its whole family, durably. Access tokens (`aat_`) are opaque
//!   and short-lived. Only sha256 hashes are stored.

use std::time::Duration as StdDuration;

use agent_auth_core::AgentId;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::policy::RemoteMcpConfig;
use agent_auth_crypto::{api_key, ct_eq, digest, token_urlsafe};
use agent_auth_store::oauth::{self as db, Consumed, TokenKind};
use agent_auth_store::{Store, StoreError, Tx, agents};
use agent_auth_wire::oauth::{
    ClientRegistered, ClientRegistration, OAuthError, OAuthErrorCode, TokenAuthMethod,
};
use agent_auth_wire::secret::WireSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::webui::WebConfigError;
use crate::webui::cookies::Sealer;
use crate::webui::oidc::OidcClient;

mod routes;
pub use routes::routes;

pub const ACCESS_PREFIX: &str = "aat_";
pub const REFRESH_PREFIX: &str = "art_";
pub const CODE_PREFIX: &str = "aac_";
pub const CLIENT_PREFIX: &str = "mcpc_";
/// How long a code lives.
pub const CODE_TTL: Duration = Duration::minutes(5);
/// The runtime of a connector's agent.
pub const WEB_RUNTIME: &str = "web";
/// A registered client nobody authorized expires after this (Bug-C6).
pub const UNBOUND_CLIENT_TTL: Duration = Duration::hours(1);
/// Registrations nobody authorized kept at once; a new one evicts the
/// oldest (a flood of registrations evicts only itself).
pub const MAX_UNBOUND_CLIENTS: i64 = 20;
/// Registrations one client address may make in an hour.
pub const REGISTRATIONS_PER_HOUR: usize = 20;
/// Addresses whose registrations are remembered at once.
const MAX_TRACKED_ADDRESSES: usize = 4096;
/// The longest redirect URI registration accepts (Bug-C7).
pub const MAX_REDIRECT_URI_CHARS: usize = 512;
/// The longest `state` an authorization carries (it is sealed into a
/// cookie, and browsers drop cookies over about 4 KiB).
pub const MAX_STATE_CHARS: usize = 1024;

/// An OAuth refusal with its HTTP status (400, or 401 for client
/// authentication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub body: OAuthError,
}

fn refuse(code: OAuthErrorCode, text: impl Into<String>) -> Refusal {
    Refusal {
        status: 400,
        body: OAuthError::new(code, text),
    }
}

/// An error of the token endpoint or registration: a refusal, or a failure
/// of ours.
#[derive(Debug)]
pub enum OAuthFailure {
    Refused(Refusal),
    Store(StoreError),
}

impl From<StoreError> for OAuthFailure {
    fn from(e: StoreError) -> Self {
        OAuthFailure::Store(e)
    }
}

impl From<Refusal> for OAuthFailure {
    fn from(r: Refusal) -> Self {
        OAuthFailure::Refused(r)
    }
}

fn hash(token: &str) -> String {
    digest::sha256_hex(token.as_bytes())
}

/// `b64url_nopad(sha256(verifier)) == challenge`, in constant time.
#[must_use]
pub fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    ct_eq(
        crate::webui::oidc::pkce_challenge(verifier).as_bytes(),
        challenge.as_bytes(),
    )
}

/// The agent name a connector label becomes: lowercase, runs of anything
/// outside `[a-z0-9-]` become `-`, trimmed of `-`, cut to 40, `connector`
/// if empty, and `web-` in front unless it is there.
#[must_use]
pub fn agent_name(label: &str) -> String {
    let lower = label.to_lowercase();
    let mut out = String::new();
    let mut in_run = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('-');
            in_run = true;
        }
    }
    let trimmed: String = out.trim_matches('-').chars().take(40).collect();
    let label = if trimmed.is_empty() {
        "connector".to_owned()
    } else {
        trimmed
    };
    if label.starts_with("web-") {
        label
    } else {
        format!("web-{label}")
    }
}

fn name_ok(rest: &str) -> bool {
    let mut chars = rest.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && rest.len() <= 41
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A validated `/oauth/authorize` request, carried through the sign-in to
/// the consent form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
}

/// The consent form's sealed blob: the authorization, who signed in, and
/// the nonce the consent cookie must match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentBlob {
    #[serde(flatten)]
    pub auth: Authorization,
    pub user: String,
    pub nonce: String,
}

/// The token endpoint's form, as far as it is read.
#[derive(Debug, Default)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// The OAuth server.
pub struct OAuthServer {
    base: String,
    redirect_uris: Vec<String>,
    /// Recent registrations per client address (the rate limit).
    registrations: std::sync::Mutex<std::collections::HashMap<String, Vec<OffsetDateTime>>>,
    access_ttl: Duration,
    refresh_ttl: Duration,
    max_clients: i64,
    pub(crate) sealer: Arc<Sealer>,
    pub(crate) sign_in: Arc<OidcClient>,
}

impl std::fmt::Debug for OAuthServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthServer")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl OAuthServer {
    pub fn new(
        config: &RemoteMcpConfig,
        sealer: Arc<Sealer>,
        sign_in: Arc<OidcClient>,
    ) -> Result<OAuthServer, WebConfigError> {
        let base = config.base_url.trim_end_matches('/').to_owned();
        if base.is_empty() {
            return Err(WebConfigError::Invalid(
                "remote_mcp.base_url is required".into(),
            ));
        }
        Ok(OAuthServer {
            base,
            redirect_uris: config.redirect_uris.clone(),
            registrations: std::sync::Mutex::default(),
            access_ttl: config.access_ttl.as_duration(),
            refresh_ttl: config.refresh_ttl.as_duration(),
            max_clients: i64::from(config.max_clients),
            sealer,
            sign_in,
        })
    }

    /// `remote_mcp.base_url` without a trailing `/`.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    fn redirect_ok(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Counts a registration from `address` at `now`; `false` when the
    /// address has used up its hour.
    fn admit_registration(&self, address: &str, now: OffsetDateTime) -> bool {
        let hour_ago = now.saturating_sub(Duration::hours(1));
        let mut seen = self
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.len() >= MAX_TRACKED_ADDRESSES {
            seen.retain(|_, times| times.iter().any(|t| *t > hour_ago));
            if seen.len() >= MAX_TRACKED_ADDRESSES {
                seen.clear();
            }
        }
        let times = seen.entry(address.to_owned()).or_default();
        times.retain(|t| *t > hour_ago);
        if times.len() >= REGISTRATIONS_PER_HOUR {
            return false;
        }
        times.push(now);
        true
    }

    // ---------------------------------------------------------- registration

    /// `POST /oauth/register` (RFC 7591).
    /// `address`: the caller's address (`None`: unknown, one shared
    /// allowance).
    pub async fn register(
        &self,
        store: &Store,
        body: &[u8],
        address: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<ClientRegistered, OAuthFailure> {
        let reg =
            ClientRegistration::from_json(body).map_err(|body| Refusal { status: 400, body })?;
        if reg.redirect_uris.iter().any(|u| !self.redirect_ok(u)) {
            return Err(refuse(
                OAuthErrorCode::InvalidRedirectUri,
                format!(
                    "this broker sends the browser back only to {}",
                    self.redirect_uris.join(", ")
                ),
            )
            .into());
        }
        if reg
            .redirect_uris
            .iter()
            .any(|u| u.chars().count() > MAX_REDIRECT_URI_CHARS)
        {
            return Err(refuse(
                OAuthErrorCode::InvalidRedirectUri,
                format!("redirect_uris: at most {MAX_REDIRECT_URI_CHARS} characters each"),
            )
            .into());
        }
        if !self.admit_registration(address.unwrap_or("unknown"), now) {
            return Err(Refusal {
                status: 429,
                body: OAuthError::new(
                    OAuthErrorCode::InvalidClientMetadata,
                    "too many registrations from this address; try again later",
                ),
            }
            .into());
        }
        let name = reg.client_name.clone().unwrap_or_default();
        let tx = store.begin().await?;
        let expired =
            db::delete_unbound_clients(&tx, now.saturating_sub(UNBOUND_CLIENT_TTL)).await?;
        let evicted = db::evict_unbound_clients(&tx, MAX_UNBOUND_CLIENTS.saturating_sub(1)).await?;
        if expired > 0 || evicted > 0 {
            tracing::info!(
                expired,
                evicted,
                "oauth: registrations nobody authorized removed"
            );
        }
        if db::count_live_bound_clients(&tx).await? >= self.max_clients {
            tx.commit().await?;
            return Err(refuse(
                OAuthErrorCode::InvalidClientMetadata,
                "too many registered clients; the operator can revoke some",
            )
            .into());
        }
        let random = |n| {
            token_urlsafe(n).map_err(|e| OAuthFailure::Store(StoreError::OutOfRange(e.to_string())))
        };
        let id = format!("{CLIENT_PREFIX}{}", random(16)?);
        let secret = match reg.token_endpoint_auth_method {
            TokenAuthMethod::None => None,
            _ => Some(random(32)?),
        };
        let secret_hash = secret.as_deref().map(hash);
        let row = db::insert_client(
            &tx,
            &db::NewClient {
                id: &id,
                name: &name,
                redirect_uris: &reg.redirect_uris,
                secret_hash: secret_hash.as_deref(),
                now,
            },
        )
        .await?;
        tx.commit().await?;
        tracing::info!(
            client = id,
            name,
            uris = reg.redirect_uris.join(", "),
            "oauth: client registered"
        );
        let client_secret = match secret {
            Some(s) => Some(
                WireSecret::new(s)
                    .map_err(|e| OAuthFailure::Store(StoreError::OutOfRange(e.to_string())))?,
            ),
            None => None,
        };
        Ok(ClientRegistered {
            client_id: row.id,
            client_id_issued_at: row.created_at.unix_timestamp(),
            client_name: Some(name),
            redirect_uris: reg.redirect_uris,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: reg.token_endpoint_auth_method,
            client_secret_expires_at: client_secret.as_ref().map(|_| 0),
            client_secret,
        })
    }

    /// A live client: not revoked, and not an unauthorized one past
    /// [`UNBOUND_CLIENT_TTL`].
    pub async fn client(
        &self,
        tx: &Tx<'_>,
        id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<db::ClientRow>, StoreError> {
        if id.is_empty() {
            return Ok(None);
        }
        Ok(db::get_client(tx, id).await?.filter(|c| {
            c.revoked_at.is_none()
                && (c.agent_id.is_some() || c.created_at > now.saturating_sub(UNBOUND_CLIENT_TTL))
        }))
    }

    // --------------------------------------------------------- authorization

    /// Validates `/oauth/authorize`. Its errors are shown to the person,
    /// never sent to the redirect (it is not known good yet).
    pub async fn check_authorize(
        &self,
        store: &Store,
        params: &std::collections::HashMap<String, String>,
        now: OffsetDateTime,
    ) -> Result<Result<Authorization, String>, StoreError> {
        let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");
        let tx = store.begin().await?;
        let client = self.client(&tx, get("client_id"), now).await?;
        tx.commit().await?;
        let Some(client) = client else {
            return Ok(Err("unknown client".into()));
        };
        let redirect_uri = match (get("redirect_uri"), client.redirect_uris.as_slice()) {
            ("", [only]) => only.clone(),
            (given, _) => given.to_owned(),
        };
        if !client.redirect_uris.contains(&redirect_uri) {
            return Ok(Err("redirect_uri is not one this client registered".into()));
        }
        if get("response_type") != "code" {
            return Ok(Err("only response_type=code".into()));
        }
        let challenge = get("code_challenge");
        let challenge_ok = (43..=128).contains(&challenge.len())
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if get("code_challenge_method") != "S256" || !challenge_ok {
            return Ok(Err(
                "PKCE with code_challenge_method=S256 is required".into()
            ));
        }
        let state = get("state");
        if state.chars().count() > MAX_STATE_CHARS {
            return Ok(Err(format!("state: at most {MAX_STATE_CHARS} characters")));
        }
        Ok(Ok(Authorization {
            client_id: client.id,
            client_name: client.name,
            redirect_uri,
            state: state.to_owned(),
            code_challenge: challenge.to_owned(),
        }))
    }

    /// The name of the agent a client is bound to, if any.
    pub async fn bound_agent(
        &self,
        tx: &Tx<'_>,
        client: &db::ClientRow,
    ) -> Result<Option<String>, StoreError> {
        match client.agent_id {
            Some(id) => Ok(agents::get(tx, id).await?.map(|a| a.name)),
            None => Ok(None),
        }
    }

    /// The person agreed: bind the client to its agent (made if need be)
    /// and return a code for the redirect. `Ok(Err(text))`: refused, with
    /// the text to show.
    pub async fn approve(
        &self,
        store: &Store,
        auth: &Authorization,
        label: &str,
        by: &str,
        now: OffsetDateTime,
    ) -> Result<Result<String, String>, StoreError> {
        let tx = store.begin().await?;
        let Some(client) = self.client(&tx, &auth.client_id, now).await? else {
            return Ok(Err("unknown client".into()));
        };
        let mut agent = match client.agent_id {
            Some(id) => agents::get(&tx, id).await?,
            None => None,
        };
        if agent.is_none() {
            let name = agent_name(label);
            if !name_ok(name.strip_prefix("web-").unwrap_or(&name)) {
                return Ok(Err("name: lowercase letters, digits and '-'".into()));
            }
            let existing = agents::by_name(&tx, &name).await?;
            let row = match existing {
                Some(a) if a.runtime.as_deref() != Some(WEB_RUNTIME) => {
                    return Ok(Err(format!(
                        "{name} exists and is not a web connector's agent"
                    )));
                }
                Some(a) => a,
                None => {
                    // A key of its own that nobody is ever shown.
                    let key =
                        api_key::generate().map_err(|e| StoreError::OutOfRange(e.to_string()))?;
                    let shown = if client.name.is_empty() {
                        &client.id
                    } else {
                        &client.name
                    };
                    let description = format!("Web UI connector: {shown}, authorized by {by}");
                    agents::insert(
                        &tx,
                        &agents::NewAgent {
                            id: AgentId::new(),
                            name: &name,
                            description: &description,
                            key_id: key.key_id.as_str(),
                            api_key_hash: key.hash.as_str(),
                            kind: AgentKind::Ephemeral,
                            webhook_url: None,
                            webhook_secret: None,
                            lldap_username: None,
                            parent_agent_id: None,
                            sandbox_id: None,
                            runtime: Some(WEB_RUNTIME),
                            project: None,
                            host: None,
                            placement: Placement::Host,
                            lease_expires_at: None,
                            last_seen_at: None,
                            now,
                        },
                    )
                    .await?
                }
            };
            if !db::bind_client(&tx, &client.id, row.id).await? {
                return Ok(Err("unknown client".into()));
            }
            agent = Some(row);
        }
        let Some(agent) = agent else {
            return Ok(Err("unknown client".into()));
        };
        if agent.disabled {
            return Ok(Err(format!("{} is disabled", agent.name)));
        }
        let code = format!(
            "{CODE_PREFIX}{}",
            token_urlsafe(32).map_err(|e| StoreError::OutOfRange(e.to_string()))?
        );
        let by: String = by.chars().take(128).collect();
        db::insert_token(
            &tx,
            &db::NewToken {
                id: Uuid::new_v4(),
                kind: TokenKind::Code,
                token_hash: &hash(&code),
                client_id: &client.id,
                agent_id: agent.id,
                family: Uuid::new_v4(),
                expires_at: now.saturating_add(CODE_TTL),
                code_challenge: Some(&auth.code_challenge),
                redirect_uri: Some(&auth.redirect_uri),
                authorized_by: &by,
                now,
            },
        )
        .await?;
        tx.commit().await?;
        tracing::warn!(
            by,
            client = auth.client_id,
            name = auth.client_name,
            agent = agent.name,
            "oauth: client authorized"
        );
        Ok(Ok(code))
    }

    // ---------------------------------------------------------------- tokens

    async fn authenticate(
        &self,
        tx: &Tx<'_>,
        form: &TokenForm,
        basic: Option<&(String, String)>,
        now: OffsetDateTime,
    ) -> Result<Result<db::ClientRow, Refusal>, StoreError> {
        let pick = |b: Option<&str>, f: &Option<String>| {
            b.filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| f.clone())
                .unwrap_or_default()
        };
        let client_id = pick(basic.map(|b| b.0.as_str()), &form.client_id);
        let secret = pick(basic.map(|b| b.1.as_str()), &form.client_secret);
        let unauthorized = |text: &str| Refusal {
            status: 401,
            body: OAuthError::new(OAuthErrorCode::InvalidClient, text),
        };
        let Some(client) = self.client(tx, &client_id, now).await? else {
            return Ok(Err(unauthorized("unknown client")));
        };
        if let Some(stored) = &client.secret_hash
            && (secret.is_empty() || !ct_eq(hash(&secret).as_bytes(), stored.as_bytes()))
        {
            return Ok(Err(unauthorized("client authentication failed")));
        }
        Ok(Ok(client))
    }

    async fn pair(
        &self,
        tx: &Tx<'_>,
        client: &db::ClientRow,
        agent: AgentId,
        family: Uuid,
        by: &str,
        now: OffsetDateTime,
    ) -> Result<Value, StoreError> {
        let random = || token_urlsafe(32).map_err(|e| StoreError::OutOfRange(e.to_string()));
        let access = format!("{ACCESS_PREFIX}{}", random()?);
        let refresh = format!("{REFRESH_PREFIX}{}", random()?);
        for (kind, token, ttl) in [
            (TokenKind::Access, &access, self.access_ttl),
            (TokenKind::Refresh, &refresh, self.refresh_ttl),
        ] {
            db::insert_token(
                tx,
                &db::NewToken {
                    id: Uuid::new_v4(),
                    kind,
                    token_hash: &hash(token),
                    client_id: &client.id,
                    agent_id: agent,
                    family,
                    expires_at: now.saturating_add(ttl),
                    code_challenge: None,
                    redirect_uri: None,
                    authorized_by: by,
                    now,
                },
            )
            .await?;
        }
        db::touch_client(tx, &client.id, now).await?;
        Ok(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.access_ttl.whole_seconds(),
            "refresh_token": refresh,
        }))
    }

    /// `POST /oauth/token`. Whatever a refusal revoked (a code or refresh
    /// token used twice) or consumed is committed before it is returned.
    pub async fn exchange(
        &self,
        store: &Store,
        form: &TokenForm,
        basic: Option<&(String, String)>,
        now: OffsetDateTime,
    ) -> Result<Result<Value, Refusal>, StoreError> {
        let tx = store.begin().await?;
        let out = self.exchange_in(&tx, form, basic, now).await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn exchange_in(
        &self,
        tx: &Tx<'_>,
        form: &TokenForm,
        basic: Option<&(String, String)>,
        now: OffsetDateTime,
    ) -> Result<Result<Value, Refusal>, StoreError> {
        let client = match self.authenticate(tx, form, basic, now).await? {
            Ok(c) => c,
            Err(r) => return Ok(Err(r)),
        };
        let grant = |text: &str| Err(refuse(OAuthErrorCode::InvalidGrant, text));
        match form.grant_type.as_deref() {
            Some("authorization_code") => {
                let code = form.code.as_deref().unwrap_or("");
                let row = match db::consume(tx, &hash(code), TokenKind::Code, &client.id, now)
                    .await?
                {
                    Consumed::Unknown => return Ok(grant("unknown or expired code")),
                    Consumed::Replayed { family, revoked } => {
                        tracing::warn!(client = client.id, %family, revoked, "oauth: a code was used twice: its authorization is revoked");
                        return Ok(grant("this code was already used"));
                    }
                    Consumed::Fresh(row) => row,
                };
                let stored = row.redirect_uri.as_deref().unwrap_or("");
                let sent = form
                    .redirect_uri
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(stored);
                if sent != stored {
                    return Ok(grant("redirect_uri differs from the authorization's"));
                }
                let verifier = form.code_verifier.as_deref().unwrap_or("");
                if !pkce_ok(verifier, row.code_challenge.as_deref().unwrap_or("")) {
                    return Ok(grant("PKCE verification failed"));
                }
                if !agent_enabled(tx, row.agent_id).await? {
                    return Ok(grant("the connector's agent is disabled"));
                }
                Ok(Ok(self
                    .pair(
                        tx,
                        &client,
                        row.agent_id,
                        row.family,
                        &row.authorized_by,
                        now,
                    )
                    .await?))
            }
            Some("refresh_token") => {
                let token = form.refresh_token.as_deref().unwrap_or("");
                let row = match db::consume(tx, &hash(token), TokenKind::Refresh, &client.id, now)
                    .await?
                {
                    Consumed::Unknown => return Ok(grant("unknown or expired refresh token")),
                    Consumed::Replayed { family, revoked } => {
                        tracing::warn!(client = client.id, %family, revoked, "oauth: refresh token reused: its authorization is revoked");
                        return Ok(grant("refresh token reused; sign in again"));
                    }
                    Consumed::Fresh(row) => row,
                };
                if !agent_enabled(tx, row.agent_id).await? {
                    return Ok(grant("the connector's agent is disabled"));
                }
                Ok(Ok(self
                    .pair(
                        tx,
                        &client,
                        row.agent_id,
                        row.family,
                        &row.authorized_by,
                        now,
                    )
                    .await?))
            }
            _ => Ok(Err(refuse(
                OAuthErrorCode::UnsupportedGrantType,
                "authorization_code or refresh_token",
            ))),
        }
    }

    /// `POST /oauth/revoke` (RFC 7009): a live access or refresh token
    /// ends its whole authorization. Codes are not revoked here.
    pub async fn revoke(
        &self,
        store: &Store,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        if token.is_empty() {
            return Ok(());
        }
        let tx = store.begin().await?;
        for kind in [TokenKind::Access, TokenKind::Refresh] {
            if let Some(row) = db::find_live(&tx, &hash(token), kind, now).await? {
                db::revoke_family(&tx, row.family, now).await?;
            }
        }
        tx.commit().await
    }

    /// The live token behind an access token, if any (bearer use on `/mcp`).
    pub async fn access(
        &self,
        tx: &Tx<'_>,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<Option<db::TokenRow>, StoreError> {
        if !token.starts_with(ACCESS_PREFIX) {
            return Ok(None);
        }
        db::find_live(tx, &hash(token), TokenKind::Access, now).await
    }

    /// The access token TTL (how long a remote MCP session is kept alive
    /// after its last use).
    #[must_use]
    pub fn access_ttl(&self) -> StdDuration {
        self.access_ttl.unsigned_abs()
    }
}

async fn agent_enabled(tx: &Tx<'_>, id: AgentId) -> Result<bool, StoreError> {
    Ok(agents::get(tx, id).await?.is_some_and(|a| !a.disabled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_names() {
        assert_eq!(agent_name("Claude"), "web-claude");
        assert_eq!(agent_name("web-claude"), "web-claude");
        assert_eq!(agent_name("  My  Chat!! "), "web-my-chat");
        assert_eq!(agent_name("!!!"), "web-connector");
        assert_eq!(agent_name(""), "web-connector");
        assert_eq!(
            agent_name(&"x".repeat(60)),
            format!("web-{}", "x".repeat(40))
        );
        assert_eq!(agent_name("Ünïcode Chat"), "web-n-code-chat");
        assert!(name_ok("claude") && name_ok("a-b") && !name_ok("-a") && !name_ok(""));
        assert!(!name_ok(&"x".repeat(42)));
    }

    #[test]
    fn pkce() {
        // RFC 7636 appendix B.
        assert!(pkce_ok(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_ok(
            "other",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}
