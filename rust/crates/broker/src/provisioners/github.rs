//! GitHub (provisioners spec §2): installation tokens for one repo with a
//! set of permissions (`repo`), and repositories the broker creates itself
//! (`create`).
//!
//! The broker authenticates as its GitHub App (an RS256 JWT over the
//! private key file, re-read on every JWT). Installation tokens live at
//! most an hour; the broker re-mints on demand for the life of a grant and
//! refuses once the grant has ended (the store's issuance check). A `create`
//! uses an Administration token minted for that one call and revoked right
//! after, also when the provisioning is cancelled.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::authority::{GithubAccess, GithubAuthority, GithubPermissions, Visibility};
use agent_auth_core::policy::schema::GithubConfig;
use agent_auth_core::{Authority, CredentialId, Glob, Platform};
use agent_auth_crypto::Secret;
use agent_auth_crypto::jwt::GitHubAppKey;
use agent_auth_crypto::secretbox::{Binding, SecretBox};
use agent_auth_store::agents::AgentRow;
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx, credentials, grants};
use agent_auth_wire::catalog::PlatformCatalog;
use reqwest::Method;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::common::{at, parse_time, repr, store_failed};
use super::http::{self, Http, MAX_BODY, Reply};
use super::setup::{ConfigError, Env};
use super::{
    Credential, CredentialKind, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

/// Re-mint a cached token when less than this much validity remains.
const MIN_TOKEN_VALIDITY: time::Duration = time::Duration::minutes(5);
const TOKEN_KIND: &str = "github_installation_token";
const API_VERSION: &str = "2022-11-28";
const ACCEPT: &str = "application/vnd.github+json";
/// LLDAP-style built-ins aside, GitHub's own special repos (§2.2b).
const MAX_NAME: usize = 100;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------ validation

/// Lowercased `owner/repo`, surrounding whitespace and slashes removed.
/// Control and non-ASCII characters are refused before stripping.
fn normalize_repo(resource: &str) -> Result<String, Refused> {
    if !resource.is_ascii() || resource.chars().any(|c| c < ' ' || c == '\x7f') {
        return Err(Refused(
            "github resource contains control or non-ASCII characters".to_owned(),
        ));
    }
    Ok(resource
        .trim()
        .trim_matches('/')
        .trim()
        .to_ascii_lowercase())
}

fn path_part(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

fn lower_glob(g: &Glob) -> Glob {
    Glob::new(&g.as_str().to_lowercase())
}

fn matches_any(globs: &[Glob], text: &str) -> bool {
    globs.iter().any(|g| g.matches(text))
}

/// The policy's GitHub section, with the permission ceiling parsed.
#[derive(Debug, Clone)]
struct Policy {
    allowlist: Vec<Glob>,
    denylist: Vec<Glob>,
    ceiling: std::collections::BTreeMap<String, GithubAccess>,
    ceiling_text: std::collections::BTreeMap<String, String>,
    create_owners: Vec<String>,
}

impl Policy {
    fn new(cfg: &GithubConfig) -> Result<Policy, ConfigError> {
        let mut ceiling = std::collections::BTreeMap::new();
        for (perm, level) in &cfg.permission_ceiling {
            let parsed = GithubAccess::parse(&level.to_ascii_lowercase()).ok_or_else(|| {
                ConfigError(format!(
                    "platforms.github.permission_ceiling.{perm}: {} is not read, write or admin",
                    repr(level)
                ))
            })?;
            ceiling.insert(perm.clone(), parsed);
        }
        Ok(Policy {
            // Repos are matched lowercased: so are the globs (a capital
            // would never match, and a denylist would fail open).
            allowlist: cfg.repo_allowlist.iter().map(lower_glob).collect(),
            denylist: cfg.repo_denylist.iter().map(lower_glob).collect(),
            ceiling,
            ceiling_text: cfg.permission_ceiling.clone(),
            create_owners: cfg.create_owners.clone(),
        })
    }

    /// Steps shared by both capabilities: the deny- and allowlists.
    fn lists(&self, repo: &str) -> Result<(), Refused> {
        if matches_any(&self.denylist, repo) {
            return Err(Refused(format!(
                "repo {} is never brokered (denylist)",
                repr(repo)
            )));
        }
        if !self.allowlist.is_empty() && !matches_any(&self.allowlist, repo) {
            return Err(Refused(format!(
                "repo {} is not in the allowlist",
                repr(repo)
            )));
        }
        Ok(())
    }

    /// §2.2a. The owner half may not be `.`/`..` either (B6).
    fn repo(
        &self,
        resource: &str,
        permissions: &GithubPermissions,
    ) -> Result<(String, Vec<String>), Refused> {
        let repo = normalize_repo(resource)?;
        let Some((owner, name)) = repo
            .split_once('/')
            .filter(|_| repo.matches('/').count() == 1)
        else {
            return Err(Refused("github resource must be 'owner/repo'".to_owned()));
        };
        if !path_part(owner)
            || !path_part(name)
            || matches!(owner, "." | "..")
            || matches!(name, "." | "..")
        {
            return Err(Refused(format!(
                "invalid github repository {}",
                repr(&repo)
            )));
        }
        self.lists(&repo)?;
        if permissions.is_empty() {
            return Err(Refused(
                "scope.permissions is required, e.g. {\"contents\": \"write\"}".to_owned(),
            ));
        }
        let mut notes = Vec::new();
        for (perm, level) in permissions {
            let Some(ceiling) = self.ceiling.get(perm) else {
                return Err(Refused(format!(
                    "permission {} is not grantable by policy",
                    repr(perm)
                )));
            };
            if level > ceiling {
                return Err(Refused(format!(
                    "permission {perm}:{} exceeds policy ceiling {perm}:{}",
                    level.as_str(),
                    ceiling.as_str()
                )));
            }
            if *level >= GithubAccess::Write {
                notes.push(format!("grants {perm}:{} on {repo}", level.as_str()));
            }
        }
        Ok((repo, notes))
    }

    /// §2.2b.
    fn create(
        &self,
        resource: &str,
        visibility: Visibility,
    ) -> Result<(String, Vec<String>), Refused> {
        let repo = normalize_repo(resource)?;
        let Some((owner, name)) = repo
            .split_once('/')
            .filter(|_| repo.matches('/').count() == 1)
        else {
            return Err(Refused(
                "github create resource must be 'org/name'".to_owned(),
            ));
        };
        if !self
            .create_owners
            .iter()
            .any(|o| o.to_ascii_lowercase() == owner)
        {
            return Err(Refused(format!(
                "repos can't be created under {} (platforms.github.create_owners)",
                repr(owner)
            )));
        }
        let valid = !name.is_empty()
            && name.len() <= MAX_NAME
            && path_part(name)
            && !name.ends_with(".git")
            && !name.starts_with('.')
            && !name.ends_with(".github.io")
            && name.chars().any(|c| c.is_ascii_alphanumeric());
        if !valid {
            return Err(Refused(format!("invalid repository name {}", repr(name))));
        }
        self.lists(&repo)?;
        let v = visibility.as_str();
        let mut notes = vec![format!("creates a new {v} repo {repo}")];
        if visibility == Visibility::Public {
            notes.push("PUBLIC: everything pushed to it is visible to anyone".to_owned());
        }
        Ok((repo, notes))
    }
}

// ------------------------------------------------------------ the app

/// How a GitHub call authenticates.
#[derive(Clone, Copy)]
enum Auth<'a> {
    /// The App JWT at this time.
    App(OffsetDateTime),
    /// An installation token.
    Token(&'a str),
}

/// (repo, sorted permissions) of a token the broker holds for itself.
type OwnKey = (String, Vec<(String, String)>);

/// The broker's GitHub App: JWTs, installation lookups, token mints. Shared
/// by the provisioner and the wiki.
#[derive(Debug)]
pub struct GithubApp {
    app_id: String,
    key_file: PathBuf,
    api_url: String,
    /// `GITHUB_INSTALLATION_ID`: one installation for every repo.
    pinned: Option<String>,
    http: Http,
    /// repo → installation id (unpinned mode).
    installations: Mutex<HashMap<String, String>>,
    /// The pinned installation's account, lowercased, once looked up.
    pinned_account: Mutex<Option<String>>,
    /// The broker's own tokens (the wiki): (repo, permissions) → token.
    own: Mutex<HashMap<OwnKey, (Secret<String>, OffsetDateTime)>>,
}

impl GithubApp {
    /// `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_FILE`, `GITHUB_API_URL`,
    /// `GITHUB_INSTALLATION_ID`. `None` when the app id or key file is unset.
    pub fn from_env(env: &Env<'_>) -> Result<Option<GithubApp>, ConfigError> {
        let app_id = env.get("GITHUB_APP_ID");
        let key_file = env.get("GITHUB_APP_PRIVATE_KEY_FILE");
        if app_id.is_empty() || key_file.is_empty() {
            return Ok(None);
        }
        let api_url = env.get_or("GITHUB_API_URL", "https://api.github.com");
        let pinned = env.get("GITHUB_INSTALLATION_ID");
        Ok(Some(GithubApp::new(
            &app_id,
            PathBuf::from(key_file),
            &api_url,
            (!pinned.is_empty()).then_some(pinned),
            Http::new()?,
        )))
    }

    #[must_use]
    pub fn new(
        app_id: &str,
        key_file: PathBuf,
        api_url: &str,
        pinned: Option<String>,
        http: Http,
    ) -> GithubApp {
        GithubApp {
            app_id: app_id.to_owned(),
            key_file,
            api_url: api_url.trim_end_matches('/').to_owned(),
            pinned,
            http,
            installations: Mutex::new(HashMap::new()),
            pinned_account: Mutex::new(None),
            own: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    fn app_jwt(&self, now: OffsetDateTime) -> Result<Secret<String>, ProvisionError> {
        let failed = |what: &dyn std::fmt::Display| {
            tracing::error!(error = %what, file = %self.key_file.display(), "GitHub App key");
            ProvisionError::failed("the broker's GitHub App key is unusable (see broker logs)")
        };
        // Re-read on every JWT (the file may be rotated in place).
        let pem = Secret::new(std::fs::read_to_string(&self.key_file).map_err(|e| failed(&e))?);
        let key = GitHubAppKey::from_pem(pem.expose()).map_err(|e| failed(&e))?;
        key.app_jwt(&self.app_id, now.unix_timestamp())
            .map_err(|e| failed(&e))
    }

    /// One call to the API. Transport failures become a refusal without
    /// details beyond the error kind.
    async fn call(
        &self,
        method: Method,
        path: &str,
        auth: Auth<'_>,
        body: Option<&Value>,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Reply, ProvisionError> {
        let url = http::with_query(&format!("{}{path}", self.api_url), query);
        let mut rb = self
            .http
            .request(method, &url)
            .header("Accept", ACCEPT)
            .header("X-GitHub-Api-Version", API_VERSION);
        rb = match auth {
            Auth::App(now) => {
                let jwt = self.app_jwt(now)?;
                rb.header("Authorization", format!("Bearer {}", jwt.expose()))
            }
            Auth::Token(token) => rb.header("Authorization", format!("token {token}")),
        };
        if let Some(body) = body {
            rb = rb.json(body);
        }
        self.http.send(rb, timeout, MAX_BODY).await.map_err(|e| {
            tracing::warn!(error = %e, path, "GitHub API call failed");
            ProvisionError::failed("GitHub API unreachable (see broker logs)")
        })
    }

    /// The installation token's own API calls (the wiki): `token` auth.
    pub(crate) async fn call_with_token(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
        query: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Reply, ProvisionError> {
        self.call(method, path, Auth::Token(token), body, query, timeout)
            .await
    }

    async fn pinned_account(
        &self,
        pinned: &str,
        now: OffsetDateTime,
    ) -> Result<String, ProvisionError> {
        if let Some(a) = lock(&self.pinned_account).clone() {
            return Ok(a);
        }
        let r = self
            .call(
                Method::GET,
                &format!("/app/installations/{pinned}"),
                Auth::App(now),
                None,
                &[],
                secs(30),
            )
            .await?;
        if r.status != 200 {
            return Err(ProvisionError::failed(format!(
                "lookup of pinned installation {} failed ({})",
                repr(pinned),
                r.status
            )));
        }
        let login = at(&r.json(), &["account", "login"])
            .as_str()
            .filter(|l| !l.is_empty())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| {
                ProvisionError::failed(format!(
                    "pinned installation {} has no account login",
                    repr(pinned)
                ))
            })?;
        *lock(&self.pinned_account) = Some(login.clone());
        Ok(login)
    }

    /// The installation that covers `repo` (`owner/name`).
    async fn installation_for(
        &self,
        repo: &str,
        now: OffsetDateTime,
    ) -> Result<String, ProvisionError> {
        if let Some(pinned) = &self.pinned {
            // The token endpoint takes bare repo names resolved against the
            // installation's account: refuse an owner that is not it, or
            // the owner the lists were checked against would be dropped.
            let owner = repo.split_once('/').map_or(repo, |(o, _)| o);
            let account = self.pinned_account(pinned, now).await?;
            if owner.to_ascii_lowercase() != account {
                return Err(ProvisionError::failed(format!(
                    "repo {} is not covered by the pinned installation (GITHUB_INSTALLATION_ID belongs to {}); unset it to resolve installations per repo",
                    repr(repo),
                    repr(&account)
                )));
            }
            return Ok(pinned.clone());
        }
        if let Some(id) = lock(&self.installations).get(repo).cloned() {
            return Ok(id);
        }
        let r = self
            .call(
                Method::GET,
                &format!("/repos/{repo}/installation"),
                Auth::App(now),
                None,
                &[],
                secs(30),
            )
            .await?;
        if r.status == 404 {
            return Err(ProvisionError::failed(format!(
                "the GitHub App is not installed on {} (install it on that account/repo, then retry)",
                repr(repo)
            )));
        }
        if r.status != 200 {
            return Err(ProvisionError::failed(format!(
                "installation lookup for {} failed ({})",
                repr(repo),
                r.status
            )));
        }
        let id = json_id(at(&r.json(), &["id"])).ok_or_else(|| {
            ProvisionError::failed(format!(
                "installation lookup for {} failed (no id)",
                repr(repo)
            ))
        })?;
        lock(&self.installations).insert(repo.to_owned(), id.clone());
        Ok(id)
    }

    fn forget_installation(&self, repo: &str) {
        lock(&self.installations).remove(repo);
    }

    /// A token for one repo with `permissions` (INV-G1: `repositories` is
    /// exactly the repo's name half).
    async fn mint(
        &self,
        repo: &str,
        permissions: &Value,
        now: OffsetDateTime,
    ) -> Result<(Secret<String>, OffsetDateTime), Result<ProvisionError, u16>> {
        let name = repo.split_once('/').map_or(repo, |(_, n)| n);
        let iid = self.installation_for(repo, now).await.map_err(Ok)?;
        let r = self
            .call(
                Method::POST,
                &format!("/app/installations/{iid}/access_tokens"),
                Auth::App(now),
                Some(&json!({"repositories": [name], "permissions": permissions})),
                &[],
                secs(30),
            )
            .await
            .map_err(Ok)?;
        if r.status != 201 {
            tracing::error!(repo, status = r.status, body = %r.head(300), "GitHub token mint failed");
            // The installation may have changed (B9): look it up again next time.
            self.forget_installation(repo);
            return Err(Err(r.status));
        }
        token_of(&r).map_err(Ok)
    }

    /// A token for the broker's own use of one repo (the wiki): never
    /// handed to an agent; kept until 5 minutes before it expires.
    pub async fn own_token(
        &self,
        repo: &str,
        permissions: &[(&str, &str)],
        now: OffsetDateTime,
    ) -> Result<Secret<String>, ProvisionError> {
        let mut perms: Vec<(String, String)> = permissions
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        perms.sort();
        let key = (repo.to_owned(), perms.clone());
        if let Some((token, expires)) = lock(&self.own).get(&key)
            && expires.saturating_sub(MIN_TOKEN_VALIDITY) > now
        {
            return Ok(token.clone());
        }
        let body: serde_json::Map<String, Value> = perms
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        match self.mint(repo, &Value::Object(body), now).await {
            Ok((token, expires)) => {
                lock(&self.own).insert(key, (token.clone(), expires));
                Ok(token)
            }
            Err(Ok(e)) => Err(e),
            Err(Err(status)) => Err(ProvisionError::failed(format!(
                "GitHub token mint for {} failed ({status})",
                repr(repo)
            ))),
        }
    }

    /// Revoke an installation token (best effort; it expires within the
    /// hour regardless). Returns the status, if any answer came.
    async fn revoke_token(&self, token: &str) -> Option<u16> {
        match self
            .call(
                Method::DELETE,
                "/installation/token",
                Auth::Token(token),
                None,
                &[],
                secs(15),
            )
            .await
        {
            Ok(r) => Some(r.status),
            Err(_) => None,
        }
    }
}

fn json_id(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn token_of(r: &Reply) -> Result<(Secret<String>, OffsetDateTime), ProvisionError> {
    let body = r.json();
    let token = at(&body, &["token"]).as_str().filter(|t| !t.is_empty());
    let expires = at(&body, &["expires_at"]).as_str().and_then(parse_time);
    match (token, expires) {
        (Some(t), Some(e)) => Ok((Secret::new(t.to_owned()), e)),
        _ => Err(ProvisionError::failed(
            "GitHub token mint failed (malformed answer)",
        )),
    }
}

/// The Administration token of a `create`: revoked exactly once, by
/// [`AdminToken::revoke`] or, when the provisioning future is dropped
/// first, by a task spawned from `Drop` (INV-G5).
struct AdminToken {
    app: Arc<GithubApp>,
    token: Option<Secret<String>>,
}

impl AdminToken {
    fn expose(&self) -> &str {
        self.token.as_ref().map_or("", |t| t.expose())
    }

    async fn revoke(mut self) {
        if let Some(token) = self.token.take() {
            revoke_admin(&self.app, token).await;
        }
    }
}

impl Drop for AdminToken {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let app = Arc::clone(&self.app);
                handle.spawn(async move { revoke_admin(&app, token).await });
            }
            Err(_) => tracing::warn!(
                "the Administration token of a cancelled repo create could not be revoked (no runtime); it expires within the hour"
            ),
        }
    }
}

async fn revoke_admin(app: &GithubApp, token: Secret<String>) {
    match app.revoke_token(token.expose()).await {
        None => tracing::warn!("failed to revoke the Administration token after a repo create"),
        Some(204) => {}
        Some(status) => tracing::warn!(
            "revoking the Administration token after a repo create returned {status}; it stays valid until it expires (within the hour)"
        ),
    }
}

// ------------------------------------------------------------ provisioner

#[derive(Debug)]
pub struct GithubProvisioner {
    app: Arc<GithubApp>,
    policy: Policy,
    secret_box: Arc<SecretBox>,
}

impl GithubProvisioner {
    /// Enabled when the app is configured; then `ENCRYPTION_KEY` is required.
    pub fn new(
        app: Arc<GithubApp>,
        cfg: &GithubConfig,
        secret_box: Option<Arc<SecretBox>>,
    ) -> Result<GithubProvisioner, ConfigError> {
        let secret_box = secret_box.ok_or_else(|| {
            ConfigError("ENCRYPTION_KEY is required when GitHub is enabled".to_owned())
        })?;
        Ok(GithubProvisioner {
            app,
            policy: Policy::new(cfg)?,
            secret_box,
        })
    }

    #[must_use]
    pub fn app(&self) -> &Arc<GithubApp> {
        &self.app
    }

    fn permissions_of(grant: &GrantRow) -> Option<&GithubPermissions> {
        match &grant.authority {
            Authority::Github(GithubAuthority::Repo { permissions }) => Some(permissions),
            _ => None,
        }
    }

    fn seal(&self, id: CredentialId, token: &Secret<String>) -> Result<String, ProvisionError> {
        let row = id.to_string();
        self.secret_box
            .seal_str(
                token.expose(),
                &Binding::new("credentials", "value_encrypted", &row),
            )
            .map_err(|e| {
                tracing::error!(error = %e, "sealing a GitHub token");
                ProvisionError::failed("could not store the token (see broker logs)")
            })
    }

    /// A token for a repo grant (INV-G1).
    async fn mint_for(
        &self,
        grant: &GrantRow,
        permissions: &GithubPermissions,
        now: OffsetDateTime,
    ) -> Result<(Secret<String>, OffsetDateTime), ProvisionError> {
        let perms = Value::Object(
            permissions
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.as_str().to_owned())))
                .collect(),
        );
        match self.app.mint(&grant.resource, &perms, now).await {
            Ok(t) => Ok(t),
            Err(Ok(e)) => Err(e),
            Err(Err(status)) => Err(ProvisionError::failed(format!(
                "GitHub token mint failed ({status})"
            ))),
        }
    }

    /// Mint under the grant's mint lock and record the token (earlier ones
    /// stay recorded until they run out, so a revoke reaches each).
    async fn mint_and_record(
        &self,
        tx: &Tx<'_>,
        lock: &credentials::MintLock<'_>,
        grant: &GrantRow,
        permissions: &GithubPermissions,
        now: OffsetDateTime,
    ) -> Result<(Secret<String>, OffsetDateTime), ProvisionError> {
        let (token, expires) = self.mint_for(grant, permissions, now).await?;
        let id = CredentialId::new();
        let sealed = self.seal(id, &token)?;
        credentials::record(tx, lock, id, TOKEN_KIND, &sealed, expires, now)
            .await
            .map_err(|e| store_failed(&e))?;
        Ok((token, expires))
    }

    async fn create(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        visibility: Visibility,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let (org, name) = grant
            .resource
            .split_once('/')
            .ok_or_else(|| ProvisionError::failed("github create resource must be 'org/name'"))?;
        let iid = self.org_installation(org, now).await?;
        let token = self.admin_token(&iid, org, now).await?;
        let outcome = self
            .create_with(tx, grant, &token, name, org, visibility)
            .await;
        token.revoke().await;
        let (repo, created) = outcome?;
        let covered = self.installation_covers(&grant.resource, now).await;
        if created {
            tracing::info!(repo = %grant.resource, visibility = visibility.as_str(), "created GitHub repo");
        }
        Ok(json!({
            "action": "create",
            "repo": grant.resource,
            "html_url": repo.get("html_url").cloned().unwrap_or(Value::Null),
            "repo_id": repo.get("id").cloned().unwrap_or(Value::Null),
            "visibility": repo.get("visibility").cloned().unwrap_or_else(|| json!(visibility.as_str())),
            "created": created,
            "installation_covers": covered,
        }))
    }

    async fn create_with(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        token: &AdminToken,
        name: &str,
        org: &str,
        visibility: Visibility,
    ) -> Result<(serde_json::Map<String, Value>, bool), ProvisionError> {
        let r = self
            .app
            .call(
                Method::POST,
                &format!("/orgs/{org}/repos"),
                Auth::Token(token.expose()),
                Some(&json!({
                    "name": name,
                    "visibility": visibility.as_str(),
                    "private": visibility == Visibility::Private,
                })),
                &[],
                secs(30),
            )
            .await?;
        match r.status {
            201 => match r.json() {
                Value::Object(repo) => Ok((repo, true)),
                _ => Err(ProvisionError::failed(
                    "GitHub repo create failed (malformed answer)",
                )),
            },
            422 => {
                // Most likely the name is taken. GitHub's text stays in the
                // log: the agent reads this error.
                tracing::warn!(repo = %grant.resource, body = %r.head(300), "GitHub repo create refused (422)");
                let repo = self.adopt_own(tx, grant, token, visibility).await?;
                Ok((repo, false))
            }
            status => {
                tracing::error!(repo = %grant.resource, status, body = %r.head(300), "GitHub repo create failed");
                Err(ProvisionError::failed(format!(
                    "GitHub repo create failed ({status})"
                )))
            }
        }
    }

    /// The name is taken: report the repo only if this broker created that
    /// very repo for this agent before (INV-G7).
    async fn adopt_own(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        token: &AdminToken,
        wanted: Visibility,
    ) -> Result<serde_json::Map<String, Value>, ProvisionError> {
        let not_ours =
            || ProvisionError::failed("repository already exists (not created by the broker)");
        let siblings = grants::siblings(tx, grant)
            .await
            .map_err(|e| store_failed(&e))?;
        let own: Vec<Value> = siblings
            .iter()
            .filter(|g| {
                matches!(
                    g.authority,
                    Authority::Github(GithubAuthority::Create { .. })
                )
            })
            .filter(|g| g.provisioner_state.get("created") == Some(&Value::Bool(true)))
            .filter_map(|g| g.provisioner_state.get("repo_id"))
            .filter(|id| !id.is_null())
            .cloned()
            .collect();
        if own.is_empty() {
            return Err(not_ours());
        }
        let r = self
            .app
            .call(
                Method::GET,
                &format!("/repos/{}", grant.resource),
                Auth::Token(token.expose()),
                None,
                &[],
                secs(30),
            )
            .await?;
        if r.status != 200 {
            return Err(ProvisionError::failed("GitHub repo create failed (422)"));
        }
        let Value::Object(repo) = r.json() else {
            return Err(ProvisionError::failed("GitHub repo create failed (422)"));
        };
        if !repo.get("id").is_some_and(|id| own.contains(id)) {
            return Err(not_ours());
        }
        let actual = match repo.get("visibility").and_then(Value::as_str) {
            Some(v) if !v.is_empty() => v.to_owned(),
            _ if repo.get("private").and_then(Value::as_bool) == Some(true) => "private".to_owned(),
            _ => "public".to_owned(),
        };
        if actual != wanted.as_str() {
            return Err(ProvisionError::failed(format!(
                "repository already exists as {actual}, not the requested {}",
                wanted.as_str()
            )));
        }
        Ok(repo)
    }

    async fn org_installation(
        &self,
        org: &str,
        now: OffsetDateTime,
    ) -> Result<String, ProvisionError> {
        if let Some(pinned) = &self.app.pinned {
            let account = self.app.pinned_account(pinned, now).await?;
            if account != org {
                return Err(ProvisionError::failed(format!(
                    "org {} is not the pinned installation's account ({})",
                    repr(org),
                    repr(&account)
                )));
            }
            return Ok(pinned.clone());
        }
        let r = self
            .app
            .call(
                Method::GET,
                &format!("/orgs/{org}/installation"),
                Auth::App(now),
                None,
                &[],
                secs(15),
            )
            .await?;
        let id = (r.status == 200)
            .then(|| json_id(at(&r.json(), &["id"])))
            .flatten();
        id.ok_or_else(|| {
            ProvisionError::failed(format!(
                "the GitHub App is not installed on org {} ({})",
                repr(org),
                r.status
            ))
        })
    }

    async fn admin_token(
        &self,
        iid: &str,
        org: &str,
        now: OffsetDateTime,
    ) -> Result<AdminToken, ProvisionError> {
        let refused = |status: u16| {
            ProvisionError::failed(format!(
                "could not mint an Administration token for {} ({status}); does the GitHub App have Administration: write there?",
                repr(org)
            ))
        };
        let r = self
            .app
            .call(
                Method::POST,
                &format!("/app/installations/{iid}/access_tokens"),
                Auth::App(now),
                Some(&json!({"permissions": {"administration": "write", "metadata": "read"}})),
                &[],
                secs(30),
            )
            .await?;
        if r.status != 201 {
            tracing::error!(org, status = r.status, body = %r.head(300), "GitHub admin token mint failed");
            return Err(refused(r.status));
        }
        // Guarded from here on: once minted, it is revoked whatever happens.
        let token = at(&r.json(), &["token"])
            .as_str()
            .filter(|t| !t.is_empty())
            .map(|t| Secret::new(t.to_owned()));
        match token {
            Some(token) => Ok(AdminToken {
                app: Arc::clone(&self.app),
                token: Some(token),
            }),
            None => Err(refused(r.status)),
        }
    }

    /// Does the installation cover the new repo? Never fails the grant.
    async fn installation_covers(&self, repo: &str, now: OffsetDateTime) -> bool {
        match self
            .app
            .call(
                Method::GET,
                &format!("/repos/{repo}/installation"),
                Auth::App(now),
                None,
                &[],
                secs(15),
            )
            .await
        {
            Ok(r) if r.status == 200 => {
                if let Some(id) = json_id(at(&r.json(), &["id"])) {
                    lock(&self.app.installations).insert(repo.to_owned(), id);
                }
                true
            }
            Ok(_) => false,
            Err(_) => {
                tracing::warn!(repo, "installation lookup for a new repo failed");
                false
            }
        }
    }
}

impl Provisioner for GithubProvisioner {
    fn platform(&self) -> Platform {
        Platform::Github
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        let out = match &spec.authority {
            Authority::Github(GithubAuthority::Repo { permissions }) => self
                .policy
                .repo(&spec.resource, permissions)
                .map(|(resource, notes)| Validated {
                    resource,
                    authority: spec.authority.clone(),
                    notes,
                }),
            Authority::Github(GithubAuthority::Create { visibility }) => self
                .policy
                .create(&spec.resource, *visibility)
                .map(|(resource, notes)| Validated {
                    resource,
                    authority: spec.authority.clone(),
                    notes,
                }),
            _ => Err(Refused(
                "github capability must be 'repo' or 'create'".to_owned(),
            )),
        };
        Ok(out)
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let grant = grant.grant();
        match &grant.authority {
            Authority::Github(GithubAuthority::Create { visibility }) => {
                self.create(tx, grant, *visibility, now).await
            }
            Authority::Github(GithubAuthority::Repo { permissions }) => {
                // Minting a token scoped to the repo proves the installation
                // covers it. Nothing is issued yet, so the proof is revoked
                // at once rather than cached (no unused token lives on).
                let (token, _) = self.mint_for(grant, permissions, now).await?;
                if self.app.revoke_token(token.expose()).await != Some(204) {
                    tracing::warn!(grant = %grant.id, "revoking the provisioning proof token failed; it expires within the hour");
                }
                Ok(
                    json!({"repo": grant.resource, "permissions": grant.authority.scope().get("permissions")}),
                )
            }
            _ => Err(ProvisionError::failed("not a github grant")),
        }
    }

    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        if Self::permissions_of(grant).is_none() {
            return Ok(()); // a create: the broker never deletes repos
        }
        // Every token recorded for the grant that has not run out: two
        // fetches racing before the mint lock existed, or a refresh, can
        // leave more than one alive (B8).
        let live = credentials::live(tx, grant.id, now)
            .await
            .map_err(|e| store_failed(&e))?;
        let mut failed = None;
        for cred in live {
            let row = cred.id.to_string();
            let token = self.secret_box.open_str(
                &cred.value_encrypted,
                &Binding::new("credentials", "value_encrypted", &row),
            );
            match token {
                // Revoked (204), or already dead (401): done. Anything
                // else is retried: the grant stays ACTIVE and the tokens
                // recorded until GitHub confirms each.
                Ok(token) => match self.app.revoke_token(token.expose()).await {
                    Some(204 | 401) => {}
                    Some(status) => {
                        tracing::warn!(grant = %grant.id, credential = %cred.id, status, "revoking a cached token failed");
                        failed.get_or_insert_with(|| {
                            ProvisionError::failed(format!("GitHub token revoke failed ({status})"))
                        });
                    }
                    None => {
                        tracing::warn!(grant = %grant.id, credential = %cred.id, "revoking a cached token failed");
                        failed.get_or_insert_with(|| {
                            ProvisionError::failed("GitHub API unreachable (see broker logs)")
                        });
                    }
                },
                // Unreadable (the key changed): nothing to send; retrying
                // would never succeed.
                Err(_) => {
                    tracing::warn!(grant = %grant.id, credential = %cred.id, "cached token does not open; not revoked");
                }
            }
        }
        if let Some(e) = failed {
            return Err(e);
        }
        credentials::delete_for(tx, grant.id)
            .await
            .map_err(|e| store_failed(&e))?;
        Ok(())
    }

    async fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        let Some(permissions) = Self::permissions_of(grant) else {
            let state = &grant.provisioner_state;
            let created = state.get("created") == Some(&Value::Bool(true));
            let text = |k: &str| match state.get(k) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => "None".to_owned(),
                Some(v) => v.to_string(),
            };
            let mut note = format!(
                "{}: {} ({}). Request a 'repo' grant on it for access.",
                if created {
                    "created"
                } else {
                    "already existed"
                },
                text("repo"),
                text("visibility"),
            );
            if state.get("installation_covers") == Some(&Value::Bool(false)) {
                note.push_str(" The broker's GitHub App installation does not cover it yet, so repo grants on it will fail until it is added to the installation.");
            }
            return Ok(Credential {
                value: state
                    .get("html_url")
                    .and_then(Value::as_str)
                    .map(|u| Secret::new(u.to_owned())),
                note: Some(note),
                ..Credential::of(CredentialKind::GithubRepo)
            });
        };
        // A policy tightened since the grant (and a restart) stops the
        // minting at once (B7).
        if let Err(Refused(why)) = self.policy.repo(&grant.resource, permissions) {
            return Err(ProvisionError::failed(format!(
                "policy no longer allows this grant ({why}); refusing to mint a token"
            )));
        }
        // One fetch at a time mints for a grant: a concurrent one waits
        // here, then finds this one's token in the cache (B8).
        let lock = credentials::lock_minting(tx, issuable)
            .await
            .map_err(|e| store_failed(&e))?;
        let cached = credentials::latest(tx, grant.id)
            .await
            .map_err(|e| store_failed(&e))?;
        if let Some(cred) = cached
            && cred.expires_at.saturating_sub(MIN_TOKEN_VALIDITY) > now
        {
            let row = cred.id.to_string();
            if let Ok(token) = self.secret_box.open_str(
                &cred.value_encrypted,
                &Binding::new("credentials", "value_encrypted", &row),
            ) {
                return Ok(Credential {
                    value: Some(token),
                    expires_at: Some(cred.expires_at),
                    ..Credential::of(CredentialKind::GithubInstallationToken)
                });
            }
            tracing::warn!(grant = %grant.id, "cached token does not open; minting a new one");
        }
        let (token, expires) = self
            .mint_and_record(tx, &lock, grant, permissions, now)
            .await?;
        Ok(Credential {
            value: Some(token),
            expires_at: Some(expires),
            ..Credential::of(CredentialKind::GithubInstallationToken)
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(Platform::Github, "repo", "owner/repo");
        c.repo_allowlist = Some(if self.policy.allowlist.is_empty() {
            vec!["<any>".to_owned()]
        } else {
            self.policy
                .allowlist
                .iter()
                .map(|g| g.as_str().to_owned())
                .collect()
        });
        c.permission_ceiling = Some(self.policy.ceiling_text.clone());
        if !self.policy.create_owners.is_empty() {
            c.create_owners = Some(self.policy.create_owners.clone());
            // `create_disposition` is the catalog route's (it needs the
            // policy engine and the saved rules).
        }
        serde_json::to_value(c).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn policy() -> Policy {
        Policy {
            allowlist: vec![Glob::new("jrt/*"), Glob::new("acme/*")],
            denylist: vec![Glob::new("jrt/nixos-dots")],
            ceiling: [
                ("contents".to_owned(), GithubAccess::Write),
                ("pull_requests".to_owned(), GithubAccess::Write),
                ("metadata".to_owned(), GithubAccess::Read),
            ]
            .into(),
            ceiling_text: BTreeMap::new(),
            create_owners: vec!["Acme".to_owned()],
        }
    }

    fn perms(list: &[(&str, GithubAccess)]) -> GithubPermissions {
        list.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    fn refused<T: std::fmt::Debug>(r: Result<T, Refused>) -> String {
        r.unwrap_err().0
    }

    #[test]
    fn repo_ceilings() {
        let p = policy();
        let w = perms(&[("contents", GithubAccess::Write)]);
        let (repo, notes) = p.repo(" JRT/Cactus/ ", &w).unwrap();
        assert_eq!(repo, "jrt/cactus");
        assert_eq!(notes, ["grants contents:write on jrt/cactus"]);
        assert_eq!(
            refused(p.repo("other/x", &w)),
            "repo 'other/x' is not in the allowlist"
        );
        assert_eq!(
            refused(p.repo("jrt/nixos-dots", &w)),
            "repo 'jrt/nixos-dots' is never brokered (denylist)"
        );
        assert_eq!(
            refused(p.repo("jrt/nixos-dots /", &w)),
            "repo 'jrt/nixos-dots' is never brokered (denylist)"
        );
        assert_eq!(
            refused(p.repo("jrt/x", &perms(&[("contents", GithubAccess::Admin)]))),
            "permission contents:admin exceeds policy ceiling contents:write"
        );
        assert_eq!(
            refused(p.repo("jrt/x", &perms(&[("secrets", GithubAccess::Read)]))),
            "permission 'secrets' is not grantable by policy"
        );
        assert_eq!(
            refused(p.repo("jrt/x", &perms(&[]))),
            "scope.permissions is required, e.g. {\"contents\": \"write\"}"
        );
        let (_, notes) = p
            .repo("jrt/x", &perms(&[("metadata", GithubAccess::Read)]))
            .unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn repo_shapes() {
        let p = policy();
        let w = perms(&[("contents", GithubAccess::Read)]);
        for bad in ["jrt/x\n/", "jrt/x\t", "jrt/x\x7f", "jrt/\u{0435}"] {
            assert_eq!(
                refused(p.repo(bad, &w)),
                "github resource contains control or non-ASCII characters",
                "{bad:?}"
            );
        }
        assert_eq!(
            refused(p.repo("jrt", &w)),
            "github resource must be 'owner/repo'"
        );
        assert_eq!(
            refused(p.repo("jrt/a/b", &w)),
            "github resource must be 'owner/repo'"
        );
        for bad in [
            "jrt/a b", "jrt/..", "jrt/.", "../x", "./x", "jrt/%0a", "jrt/?",
        ] {
            assert!(
                refused(p.repo(bad, &w)).starts_with("invalid github repository"),
                "{bad}"
            );
        }
    }

    #[test]
    fn create_names() {
        let p = policy();
        let v = Visibility::Private;
        let (repo, notes) = p.create(" Acme/New-Thing ", v).unwrap();
        assert_eq!(repo, "acme/new-thing");
        assert_eq!(notes, ["creates a new private repo acme/new-thing"]);
        let (_, notes) = p.create("acme/x", Visibility::Public).unwrap();
        assert_eq!(
            notes,
            [
                "creates a new public repo acme/x",
                "PUBLIC: everything pushed to it is visible to anyone"
            ]
        );
        assert_eq!(
            refused(p.create("jrt/x", v)),
            "repos can't be created under 'jrt' (platforms.github.create_owners)"
        );
        assert_eq!(
            refused(p.create("acme", v)),
            "github create resource must be 'org/name'"
        );
        let long = format!("acme/{}", "a".repeat(101));
        for bad in [
            "acme/..",
            "acme/x.git",
            "acme/has space",
            long.as_str(),
            "acme/.github",
            "acme/.github-private",
            "acme/.hidden",
            "acme/jrt.github.io",
            "acme/...",
            "acme/-",
            "acme/_",
            "acme/-._",
        ] {
            assert!(
                refused(p.create(bad, v)).starts_with("invalid repository name"),
                "{bad}"
            );
        }
        for good in ["acme/a.b", "acme/x-1", "acme/_x", "acme/github.io-notes"] {
            assert!(p.create(good, v).is_ok(), "{good}");
        }
        let mut deny = policy();
        deny.denylist = vec![Glob::new("acme/secret*")];
        assert_eq!(
            refused(deny.create("acme/secrets", v)),
            "repo 'acme/secrets' is never brokered (denylist)"
        );
    }

    #[test]
    fn ceiling_values_are_checked_at_load() {
        let mut cfg = GithubConfig::default();
        cfg.permission_ceiling
            .insert("contents".to_owned(), "writ".to_owned());
        assert!(Policy::new(&cfg).is_err());
        cfg.permission_ceiling
            .insert("contents".to_owned(), "WRITE".to_owned());
        assert!(Policy::new(&cfg).is_ok());
    }
}
