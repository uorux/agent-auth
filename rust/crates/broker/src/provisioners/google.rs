//! Platform `google`: access tokens for a Google account's Calendar and
//! Drive (`provisioners/google.py`).
//!
//! The broker holds, per account, either an OAuth client and a refresh
//! token (`agent-auth admin google-consent` makes one; any Gmail or
//! Workspace account), or a Workspace service account with domain-wide
//! delegation. It mints short-lived access tokens with only the scope a
//! grant names, and checks the scopes Google says the token carries: a
//! token wider than the grant is never handed out.
//!
//! What Google's design leaves: a Calendar or Drive scope reaches the whole
//! account (every calendar, every file), so the resource of a grant is the
//! account. And an access token is not revoked when its grant ends (it runs
//! out within the hour): revoking one Google issued from a refresh token
//! revokes the refresh token with it, which would end the broker's login.
//!
//! Gmail is never a token here (a Gmail scope reaches the whole mailbox):
//! mail is platform `mail`.
//!
//! Without accounts the platform is the stub ([`GoogleStubProvisioner`]):
//! decisions are recorded, nothing is minted (501 on the credential).

use std::collections::{BTreeSet, HashMap};
use std::io::Read as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::authority::{GOOGLE_CAPABILITIES, google_scope_url};
use agent_auth_core::policy::{GoogleAccount, GoogleConfig};
use agent_auth_core::{Authority, GrantStatus, Platform};
use agent_auth_crypto::Secret;
use agent_auth_crypto::jwt::{AssertionClaims, ServiceAccountKey};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{GoogleAccountEntry, PlatformCatalog};
use reqwest::Method;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::common::{repr, repr_list};
use super::http::{Http, MAX_BODY};
use super::setup::ConfigError;
use super::{Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated};

/// What ending a grant does (catalog and README): tokens are shared per
/// (account, scope) and Google cannot revoke one minted from a refresh
/// token without revoking the broker's login (`provisioners/google.py`).
pub const GOOGLE_REVOCATION: &str =
    "revoking a google grant stops new tokens; one already fetched lives up to 1 h";

/// Google's token endpoint, unless a login file names another.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The token endpoints a login file may name (Google's current and legacy
/// ones). Anything else would receive the refresh token or the signed
/// assertion.
pub const TOKEN_URLS: [&str; 2] = [
    "https://oauth2.googleapis.com/token",
    "https://accounts.google.com/o/oauth2/token",
];
const BASE: &str = "https://www.googleapis.com/auth/";
/// What Google adds to a token that grants nothing beyond who it is.
const IDENTITY: [&str; 5] = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
];
const TIMEOUT: Duration = Duration::from_secs(20);
/// A cached token is renewed when it has less than this left.
const RENEW_SECS: i64 = 300;
/// Login files are small; anything larger is not one.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The one scope (short name) a capability's token carries.
#[must_use]
pub fn capability_scope(capability: &str) -> Option<&'static str> {
    match capability {
        "calendar.read" => Some("calendar.readonly"),
        "calendar.write" => Some("calendar.events"),
        "drive.read" => Some("drive.readonly"),
        _ => None,
    }
}

/// A short scope name's URL.
#[must_use]
pub fn scope_url(short: &str) -> Option<String> {
    google_scope_url(short)
}

fn short(scope: &str) -> &str {
    scope.strip_prefix(BASE).unwrap_or(scope)
}

/// What the agent-visible text may quote of a scope Google named: printable
/// ASCII, cut.
fn shown(scope: &str) -> String {
    short(scope)
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(100)
        .collect()
}

#[derive(Clone)]
struct Cached {
    token: Secret<String>,
    expires: OffsetDateTime,
    /// The scopes Google says the token carries; None when its answer did
    /// not say (then it is never handed to an agent).
    granted: Option<BTreeSet<String>>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Cached>>>;

/// Access tokens for the configured accounts, cached until shortly before
/// they run out. The login files are read at each mint, so a rotated one
/// is picked up without a restart. Each (account, scopes) has its own
/// lock, held across its mint: concurrent fetches of one token make one
/// call, and a slow Google for one account stalls nobody else (the Python
/// held one lock across every mint).
pub struct GoogleTokens {
    config: GoogleConfig,
    http: Http,
    token_url: String,
    /// Tests only: any https endpoint, or plain http to a loopback one
    /// (fake token endpoints), besides Google's.
    any_endpoint: bool,
    slots: Mutex<HashMap<(String, BTreeSet<String>), Slot>>,
}

impl std::fmt::Debug for GoogleTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleTokens")
            .field("accounts", &self.config.accounts.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// What a mint sends to the token endpoint.
struct MintRequest {
    url: String,
    form: Vec<(&'static str, String)>,
}

fn failed(msg: impl Into<String>) -> ProvisionError {
    ProvisionError::failed(msg)
}

/// Read a login file (bounded), or why not (no path in the text).
fn read_file(path: &str) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| io_reason(&e))?;
    let mut text = String::new();
    file.take(MAX_FILE_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|e| io_reason(&e))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_FILE_BYTES) {
        return Err("file too large".to_owned());
    }
    Ok(text)
}

fn io_reason(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "no such file".to_owned(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
        std::io::ErrorKind::InvalidData => "not text".to_owned(),
        _ => "unreadable".to_owned(),
    }
}

/// A token endpoint named by a login file: one of Google's
/// ([`TOKEN_URLS`]); with `any_endpoint` (tests), any https one or plain
/// http to a loopback address.
fn token_url_ok(url: &str, any_endpoint: bool) -> bool {
    if TOKEN_URLS.contains(&url) {
        return true;
    }
    if !any_endpoint {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        "http" => match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        },
        _ => false,
    }
}

impl GoogleTokens {
    /// Production: only Google's token endpoints.
    pub fn new(config: &GoogleConfig) -> Result<GoogleTokens, ConfigError> {
        let mut t = GoogleTokens::with_http(config, Http::new()?, TOKEN_URL);
        t.any_endpoint = false;
        Ok(t)
    }

    /// With this client and default token endpoint, and any https (or
    /// loopback http) endpoint allowed: tests' fake token endpoints.
    #[must_use]
    pub fn with_http(config: &GoogleConfig, http: Http, token_url: &str) -> GoogleTokens {
        GoogleTokens {
            config: config.clone(),
            http,
            token_url: token_url.to_owned(),
            any_endpoint: true,
            slots: Mutex::new(HashMap::new()),
        }
    }

    pub fn account(&self, name: &str) -> Result<&GoogleAccount, ProvisionError> {
        self.config
            .accounts
            .get(name)
            .ok_or_else(|| failed(format!("no google account {}", repr(name))))
    }

    fn slot(&self, key: (String, BTreeSet<String>)) -> Slot {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(slots.entry(key).or_default())
    }

    /// `(access token, expiry)` for account `name` with `scopes` (short
    /// names). `exact`: refuse a token Google issued with more than these
    /// (one handed to an agent); the broker's own use takes any superset.
    pub async fn token(
        &self,
        name: &str,
        scopes: &[&str],
        exact: bool,
        now: OffsetDateTime,
    ) -> Result<(Secret<String>, OffsetDateTime), ProvisionError> {
        let account = self.account(name)?;
        let wanted: BTreeSet<String> = scopes
            .iter()
            .map(|s| scope_url(s).ok_or_else(|| failed(format!("unknown scope {}", repr(s)))))
            .collect::<Result<_, _>>()?;
        let slot = self.slot((name.to_owned(), wanted.clone()));
        let cached = {
            let mut guard = slot.lock().await;
            let fresh = guard
                .as_ref()
                .filter(|c| {
                    c.expires
                        .unix_timestamp()
                        .saturating_sub(now.unix_timestamp())
                        >= RENEW_SECS
                })
                .cloned();
            match fresh {
                Some(c) => c,
                None => {
                    let c = self.mint(account, &wanted, now).await?;
                    *guard = Some(c.clone());
                    c
                }
            }
        };
        let granted = match &cached.granted {
            Some(g) => g.clone(),
            // Google did not say what the token carries: the broker's own
            // use takes it; an agent never gets a token of unknown reach.
            None if exact => {
                return Err(failed(format!(
                    "google account {name}: Google's answer did not say which scopes the token \
                     carries; not handed out"
                )));
            }
            None => wanted.clone(),
        };
        let missing: Vec<&str> = wanted
            .iter()
            .filter(|s| !granted.contains(*s))
            .map(|s| short(s))
            .collect();
        if !missing.is_empty() {
            return Err(failed(format!(
                "google account {name}: its login lacks {} (rerun agent-auth admin \
                 google-consent with it, and tick it on the consent screen)",
                missing.join(", ")
            )));
        }
        let extra: Vec<String> = granted
            .iter()
            .filter(|s| !wanted.contains(*s) && !IDENTITY.contains(&s.as_str()))
            .take(10)
            .map(|s| shown(s))
            .collect();
        if exact && !extra.is_empty() {
            return Err(failed(format!(
                "google account {name}: Google issued a token wider than this grant (also {}); \
                 not handed out. Give the account a login consented for only what agents may \
                 hold, or use domain-wide delegation",
                extra.join(", ")
            )));
        }
        Ok((cached.token, cached.expires))
    }

    async fn mint(
        &self,
        account: &GoogleAccount,
        scopes: &BTreeSet<String>,
        now: OffsetDateTime,
    ) -> Result<Cached, ProvisionError> {
        let scope = scopes.iter().cloned().collect::<Vec<_>>().join(" ");
        let req = if account.service_account_file.is_empty() {
            self.refresh(account, &scope)?
        } else {
            self.delegated(account, &scope, now)?
        };
        if !token_url_ok(&req.url, self.any_endpoint) {
            return Err(failed(format!(
                "google account {}: its token_uri is not Google's token endpoint",
                account.address
            )));
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(req.form.iter().map(|(k, v)| (*k, v.as_str())))
            .finish();
        let rb = self
            .http
            .request(Method::POST, &req.url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        let reply = self.http.send(rb, TIMEOUT, MAX_BODY).await.map_err(|e| {
            tracing::error!(account = %account.address, error = %e, "google token endpoint");
            failed("google token endpoint unreachable (see broker logs)")
        })?;
        let answer = reply.json();
        if reply.status != 200 {
            tracing::warn!(
                account = %account.address,
                status = reply.status,
                body = %reply.head(300),
                "google token endpoint refused"
            );
            return Err(failed(explain(account, reply.status, &answer)));
        }
        let Some(token) = answer
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        else {
            return Err(failed(format!(
                "google account {}: no access token in the answer",
                account.address
            )));
        };
        let granted: Option<BTreeSet<String>> = match answer.get("scope").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => Some(s.split_whitespace().map(str::to_owned).collect()),
            _ => None,
        };
        let lifetime = answer
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(3600)
            .clamp(1, 86_400);
        Ok(Cached {
            token: Secret::new(token.to_owned()),
            expires: now.saturating_add(time::Duration::seconds(lifetime)),
            granted,
        })
    }

    fn refresh(&self, account: &GoogleAccount, scope: &str) -> Result<MintRequest, ProvisionError> {
        let cannot = |why: &str| {
            failed(format!(
                "google account {}: cannot read its login files ({why})",
                account.address
            ))
        };
        let text = read_file(&account.client_secret_file).map_err(|w| cannot(&w))?;
        let data: Value =
            serde_json::from_str(&text).map_err(|_| cannot("the client secret is not JSON"))?;
        let client = client_of(&data);
        let client_id = client
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| cannot("the client secret has no client_id"))?;
        let refresh = read_file(&account.refresh_token_file).map_err(|w| cannot(&w))?;
        let refresh = refresh.trim();
        if refresh.is_empty() {
            return Err(cannot("the refresh token file is empty"));
        }
        Ok(MintRequest {
            url: client
                .get("token_uri")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(&self.token_url)
                .to_owned(),
            form: vec![
                ("grant_type", "refresh_token".to_owned()),
                ("client_id", client_id.to_owned()),
                (
                    "client_secret",
                    client
                        .get("client_secret")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                ),
                ("refresh_token", refresh.to_owned()),
                // Asks for only these; checked against what comes back.
                ("scope", scope.to_owned()),
            ],
        })
    }

    fn delegated(
        &self,
        account: &GoogleAccount,
        scope: &str,
        now: OffsetDateTime,
    ) -> Result<MintRequest, ProvisionError> {
        let cannot = |why: &str| {
            failed(format!(
                "google account {}: cannot read its service account ({why})",
                account.address
            ))
        };
        let text = read_file(&account.service_account_file).map_err(|w| cannot(&w))?;
        let sa: Value = serde_json::from_str(&text).map_err(|_| cannot("not JSON"))?;
        let field = |k: &str| sa.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
        let client_email = field("client_email").ok_or_else(|| cannot("no client_email"))?;
        let private_key = field("private_key").ok_or_else(|| cannot("no private_key"))?;
        let key = ServiceAccountKey::from_pem(private_key)
            .map_err(|_| cannot("private_key is not a usable RSA key"))?;
        let url = field("token_uri").unwrap_or(&self.token_url).to_owned();
        let iat = now.unix_timestamp();
        let subject = account.subject.as_deref().unwrap_or(&account.address);
        let assertion = key
            .assertion(
                field("private_key_id"),
                &AssertionClaims {
                    iss: client_email,
                    sub: subject,
                    scope,
                    aud: &url,
                    iat,
                    exp: iat.saturating_add(3600),
                },
            )
            .map_err(|_| cannot("signing failed"))?;
        Ok(MintRequest {
            url,
            form: vec![
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned(),
                ),
                ("assertion", assertion.expose().clone()),
            ],
        })
    }
}

/// The OAuth client of a client-secret JSON: `installed`, `web`, or the
/// object itself.
fn client_of(data: &Value) -> &Value {
    data.get("installed")
        .filter(|v| v.is_object())
        .or_else(|| data.get("web").filter(|v| v.is_object()))
        .unwrap_or(data)
}

/// An OAuth error code as Google sends it (`invalid_grant`), if it is one.
fn error_code(answer: &Value) -> Option<&str> {
    answer
        .get("error")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty() && c.len() <= 64)
        .filter(|c| c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

/// `_explain`: what went wrong, in words the operator can act on. Google's
/// free-text `error_description` is logged, not shown.
fn explain(account: &GoogleAccount, status: u16, answer: &Value) -> String {
    let code = error_code(answer);
    let delegation = !account.service_account_file.is_empty();
    match code {
        Some("invalid_grant") if !delegation => format!(
            "google account {}: the refresh token was refused (invalid_grant). It was revoked, \
             or expired: an OAuth app in Testing status issues refresh tokens that last 7 days. \
             Set the app to In production (or make it Internal on Workspace) and rerun \
             agent-auth admin google-consent",
            account.address
        ),
        Some(c @ ("unauthorized_client" | "access_denied")) if delegation => format!(
            "google account {}: domain-wide delegation refused ({c}); the Workspace admin \
             console must authorize the service account's client id for these scopes",
            account.address
        ),
        Some(c) => format!(
            "google account {}: token endpoint answered {status} {c}",
            account.address
        ),
        None => format!(
            "google account {}: token endpoint answered {status}",
            account.address
        ),
    }
}

fn reach(capability: &str) -> &'static str {
    match capability {
        "calendar.read" => "reads every calendar",
        "calendar.write" => "reads and changes the events of every calendar",
        _ => "reads every file in the Drive",
    }
}

fn action_of(authority: &Authority) -> &str {
    match authority {
        Authority::Google { action } => action,
        _ => "",
    }
}

fn gmail_refused() -> Refused {
    Refused(
        "Gmail is not handed out as a token (it would reach the whole mailbox): request \
         platform \"mail\" for an address, which the broker reads and sends for you"
            .to_owned(),
    )
}

fn unknown_capability(action: &str) -> Refused {
    Refused(format!(
        "unknown google capability {}; known: {}",
        repr(action),
        repr_list(&GOOGLE_CAPABILITIES)
    ))
}

/// The real provisioner: accounts are configured.
#[derive(Debug)]
pub struct GoogleProvisioner {
    config: GoogleConfig,
    tokens: Arc<GoogleTokens>,
}

impl GoogleProvisioner {
    #[must_use]
    pub fn new(config: &GoogleConfig, tokens: Arc<GoogleTokens>) -> GoogleProvisioner {
        GoogleProvisioner {
            config: config.clone(),
            tokens,
        }
    }

    fn account_name(&self, resource: &str) -> Result<String, Refused> {
        let resource = resource.trim().to_lowercase();
        if self.config.accounts.contains_key(&resource) {
            return Ok(resource);
        }
        if let Some((name, _)) = self
            .config
            .accounts
            .iter()
            .find(|(_, a)| a.address == resource)
        {
            return Ok(name.clone());
        }
        let known: Vec<String> = self
            .config
            .accounts
            .iter()
            .map(|(n, a)| format!("{n} ({})", a.address))
            .collect();
        let known = if known.is_empty() {
            "none".to_owned()
        } else {
            known.join(", ")
        };
        Err(Refused(format!(
            "no google account {} (there is: {known})",
            repr(&resource)
        )))
    }

    fn validate_spec(&self, spec: RequestSpec<'_>) -> Result<Validated, Refused> {
        let action = action_of(&spec.authority);
        if action.starts_with("gmail") {
            return Err(gmail_refused());
        }
        let Some(scope) = capability_scope(action) else {
            return Err(unknown_capability(action));
        };
        let name = self.account_name(&spec.resource)?;
        let who = self
            .config
            .accounts
            .get(&name)
            .map_or_else(String::new, acting_as);
        let note = format!(
            "an account-wide Google token: {} of {who} (scope {scope}), for up to an hour \
             past the grant's end",
            reach(action)
        );
        Ok(Validated {
            resource: name,
            authority: spec.authority,
            notes: vec![note],
        })
    }
}

impl Provisioner for GoogleProvisioner {
    fn platform(&self) -> Platform {
        Platform::Google
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        Ok(self.validate_spec(spec))
    }

    async fn provision<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        // Mint once now: a login that can't make this token fails the
        // grant, not the agent's first fetch.
        let grant = grant.grant();
        let scope = capability_scope(action_of(&grant.authority))
            .ok_or_else(|| failed("this grant's account or capability is no longer configured"))?;
        self.tokens
            .token(&grant.resource, &[scope], true, now)
            .await?;
        Ok(json!({"account": grant.resource}))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        // Not revoked at Google: see the module docs.
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        if grant.status != GrantStatus::Active || grant.expires_at <= now {
            return Err(failed("grant is not active"));
        }
        if !minted_here(grant) {
            return Err(failed(STUB_ERA));
        }
        let action = action_of(&grant.authority);
        let (Some(scope), Some(account)) = (
            capability_scope(action),
            self.config.accounts.get(&grant.resource),
        ) else {
            return Err(failed(
                "this grant's account or capability is no longer configured",
            ));
        };
        let (token, expires) = self
            .tokens
            .token(&grant.resource, &[scope], true, now)
            .await?;
        let api = action.split('.').next().map_or_else(String::new, title);
        Ok(Credential {
            kind: "google_access_token".to_owned(),
            value: Some(token),
            username: Some(account.address.clone()),
            expires_at: Some(expires.min(grant.expires_at.saturating_add(time::Duration::HOUR))),
            note: Some(format!(
                "Bearer token for the Google {api} API (scope {scope}), as {}. Re-fetch when it \
                 runs out; none is issued once the grant ends.",
                acting_as(account)
            )),
            ..Credential::default()
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(
            Platform::Google,
            format!(
                "{} (account-wide tokens; Gmail is platform mail; {GOOGLE_REVOCATION})",
                GOOGLE_CAPABILITIES.join(" | ")
            ),
            "<account name or address>",
        );
        c.capabilities = Some(GOOGLE_CAPABILITIES.map(str::to_owned).to_vec());
        c.accounts = (!self.config.accounts.is_empty()).then(|| {
            self.config
                .accounts
                .iter()
                .map(|(n, a)| GoogleAccountEntry {
                    name: n.clone(),
                    address: a.address.clone(),
                })
                .collect()
        });
        serde_json::to_value(c).ok()
    }
}

/// Who a token acts as: the address, and for domain-wide delegation the
/// subject the service account impersonates (which may be someone else).
fn acting_as(account: &GoogleAccount) -> String {
    if account.service_account_file.is_empty() {
        return account.address.clone();
    }
    let subject = account.subject.as_deref().unwrap_or(&account.address);
    format!(
        "{} (acting as {subject}, by domain-wide delegation)",
        account.address
    )
}

/// The refusal for a grant the real provisioner never minted for.
pub const STUB_ERA: &str = "this grant was approved while google had no account configured \
     (nothing was issued then); request it again";

/// Was this grant provisioned by the real provisioner (its state names
/// its account)? A grant approved under the stub (`{"stub": true}`) was
/// a recorded decision only, not an approval of a real token.
#[must_use]
pub fn minted_here(grant: &GrantRow) -> bool {
    grant
        .provisioner_state
        .get("account")
        .and_then(Value::as_str)
        == Some(grant.resource.as_str())
}

/// At startup, with accounts configured: end every active grant approved
/// while google was a stub. Approving one then issued nothing; it must not
/// turn into a real, account-wide token now.
pub async fn end_stub_era_grants(st: &crate::state::AppState) {
    if st.policy.platforms().google.accounts.is_empty() {
        return;
    }
    let ids = async {
        let tx = st.store.begin().await?;
        let ids = agent_auth_store::grants::active_without_state(&tx, Platform::Google, "account")
            .await?;
        tx.rollback().await?;
        Ok::<_, StoreError>(ids)
    }
    .await;
    let ids = match ids {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(error = %e, "listing stub-era google grants");
            return;
        }
    };
    for id in ids {
        tracing::warn!(grant = %id, "ending a google grant approved while google was a stub");
        if let Err(e) = crate::service::revoke_grant(st, id, STUB_ERA, "broker").await {
            tracing::error!(grant = %id, error = %e, "ending a stub-era google grant");
        }
    }
}

/// Python's `str.title()` for a one-word ASCII name (`calendar` →
/// `Calendar`).
fn title(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect()
    })
}

/// Google with no account configured: decisions are recorded, nothing is
/// minted (the credential route answers 501). Gmail is platform `mail`.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoogleStubProvisioner;

impl Provisioner for GoogleStubProvisioner {
    fn platform(&self) -> Platform {
        Platform::Google
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let action = action_of(&spec.authority);
        if action.starts_with("gmail") {
            return Ok(Err(Refused(
                "Gmail is not handed out as a token: request platform \"mail\" for an address"
                    .to_owned(),
            )));
        }
        if !GOOGLE_CAPABILITIES.contains(&action) {
            return Ok(Err(unknown_capability(action)));
        }
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: spec.authority,
            notes: vec![
                "google is a stub here (no account configured): decision recorded, no \
                 credential minted"
                    .to_owned(),
            ],
        }))
    }

    async fn provision<'t>(
        &self,
        _tx: &'t Tx<'_>,
        _grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        Ok(json!({"stub": true}))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        Ok(())
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        _grant: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        Err(ProvisionError::NotImplemented)
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(
            Platform::Google,
            format!(
                "{} (account-wide tokens; Gmail is platform mail)",
                GOOGLE_CAPABILITIES.join(" | ")
            ),
            "<account name or address>",
        );
        c.capabilities = Some(GOOGLE_CAPABILITIES.map(str::to_owned).to_vec());
        serde_json::to_value(c).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_urls() {
        // Production: Google's endpoints only.
        assert!(token_url_ok("https://oauth2.googleapis.com/token", false));
        assert!(token_url_ok(
            "https://accounts.google.com/o/oauth2/token",
            false
        ));
        assert!(!token_url_ok("https://evil.example/token", false));
        assert!(!token_url_ok("http://127.0.0.1:5555/token", false));
        // Tests' fake endpoints.
        assert!(token_url_ok("http://127.0.0.1:5555/token", true));
        assert!(token_url_ok("http://[::1]:5555/token", true));
        assert!(token_url_ok("http://localhost/token", true));
        assert!(!token_url_ok("http://oauth2.googleapis.com/token", true));
        assert!(!token_url_ok("ftp://x/", true));
        assert!(!token_url_ok("not a url", true));
    }

    #[test]
    fn names() {
        assert_eq!(title("calendar"), "Calendar");
        assert_eq!(title("drive"), "Drive");
        assert_eq!(capability_scope("drive.read"), Some("drive.readonly"));
        assert_eq!(capability_scope("gmail.read"), None);
        for cap in GOOGLE_CAPABILITIES {
            assert!(scope_url(capability_scope(cap).unwrap()).is_some());
        }
        assert_eq!(
            shown("https://www.googleapis.com/auth/gmail.readonly"),
            "gmail.readonly"
        );
        assert_eq!(
            error_code(&json!({"error": "invalid_grant"})),
            Some("invalid_grant")
        );
        assert_eq!(error_code(&json!({"error": "<b>x</b>"})), None);
    }
}
