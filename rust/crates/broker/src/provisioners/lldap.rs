//! Homelab access through LLDAP group membership (provisioners spec §3).
//!
//! Each agent has an LLDAP service account (`agents.lldap_username`):
//! registered by hand, or a managed account the broker creates at the
//! agent's first homelab grant and whose password it keeps (sealed) and
//! hands out. A grant adds the account to the group; revoke removes it once
//! no other live grant of the agent backs that membership.
//!
//! Fixes over the Python (DEVIATIONS.md):
//! - LLDAP's administration groups are never brokered (B1).
//! - A managed account is adopted only when no other agent holds that
//!   user id (case-insensitively) and the LLDAP user is the one the broker
//!   made for this agent (its display name says so) (B2).
//! - Account creation runs under the agent row's lock until the provision
//!   commits (B3).
//! - Passwords are set over LDAP (Password Modify), never with the admin
//!   JWT on a command line (B4).
//! - Group ids are looked up fresh for every add (B5).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::policy::schema::HomelabConfig;
use agent_auth_core::{AgentId, Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_crypto::secretbox::{Binding, SecretBox};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{self, GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{CatalogEntry, PlatformCatalog};
use reqwest::Method;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::common::{at, repr, store_failed};
use super::http::{Http, MAX_BODY, Reply};
use super::ldap::LdapTarget;
use super::setup::{ConfigError, Env};
use super::{
    Credential, CredentialKind, ProvisionError, Provisioner, Refused, RequestSpec, Validated,
};

/// LLDAP's built-in groups that confer administration of LLDAP itself.
pub const ADMIN_GROUPS: [&str; 3] = [
    "lldap_admin",
    "lldap_password_manager",
    "lldap_strict_readonly",
];

const ADD: &str = "mutation AddUserToGroup($user: String!, $group: Int!) { addUserToGroup(userId: $user, groupId: $group) { ok } }";
const REMOVE: &str = "mutation RemoveUserFromGroup($user: String!, $group: Int!) { removeUserFromGroup(userId: $user, groupId: $group) { ok } }";
const CREATE_USER: &str =
    "mutation CreateUser($user: CreateUserInput!) { createUser(user: $user) { id } }";
const GROUPS: &str = "query { groups { id displayName } }";
const USER: &str = "query UserExists($user: String!) { user(userId: $user) { id displayName } }";
const LIST_USERS: &str = "query ListUsers { users { id } }";
const USER_GROUPS: &str =
    "query UserGroups($user: String!) { user(userId: $user) { groups { id } } }";

const TIMEOUT: Duration = Duration::from_secs(15);

fn is_admin_group(group: &str) -> bool {
    ADMIN_GROUPS.iter().any(|g| g.eq_ignore_ascii_case(group))
}

fn admin_group_refusal(group: &str) -> String {
    format!(
        "group {} is never brokered (it administers LLDAP itself)",
        repr(group)
    )
}

/// The display name the broker gives a managed account: what adoption
/// checks (B2).
#[must_use]
pub fn managed_display_name(agent_name: &str) -> String {
    format!("{agent_name} (agent-auth managed)")
}

fn plain_user_id(u: &str) -> bool {
    !u.is_empty()
        && u.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

/// A new password: 32 random bytes, URL-safe base64 without padding (43
/// characters; Python's `token_urlsafe(32)`).
fn new_password() -> Result<Secret<String>, ProvisionError> {
    agent_auth_crypto::token_urlsafe(32)
        .map(Secret::new)
        .map_err(|_| ProvisionError::failed("the system random number generator failed"))
}

#[derive(Debug)]
pub struct LldapProvisioner {
    url: String,
    admin_user: String,
    admin_password: Secret<String>,
    config: HomelabConfig,
    secret_box: Option<Arc<SecretBox>>,
    ldap: Option<LdapTarget>,
    http: Http,
    jwt: Mutex<Option<Secret<String>>>,
}

impl LldapProvisioner {
    /// `LLDAP_URL` (none: homelab is off), `LLDAP_ADMIN_USER`,
    /// `LLDAP_ADMIN_PASSWORD`; managed accounts also need `ENCRYPTION_KEY`
    /// and LLDAP's LDAP interface (`LLDAP_LDAP_URL`, `LLDAP_BASE_DN`).
    pub fn from_env(
        env: &Env<'_>,
        config: &HomelabConfig,
        secret_box: Option<Arc<SecretBox>>,
    ) -> Result<Option<LldapProvisioner>, ConfigError> {
        let url = env.get("LLDAP_URL");
        if url.is_empty() {
            return Ok(None);
        }
        let ldap_url = env.get("LLDAP_LDAP_URL");
        let ldap = if ldap_url.is_empty() {
            None
        } else {
            Some(LdapTarget::parse(
                &ldap_url,
                &env.get("LLDAP_BASE_DN"),
                env.flag("LLDAP_LDAP_ALLOW_PLAINTEXT")?,
            )?)
        };
        if !env.get("LLDAP_SET_PASSWORD_BIN").is_empty() {
            tracing::warn!(
                "LLDAP_SET_PASSWORD_BIN is ignored: passwords are set over LDAP (LLDAP_LDAP_URL)"
            );
        }
        let p = LldapProvisioner::new(
            &url,
            &env.get("LLDAP_ADMIN_USER"),
            Secret::new(env.get("LLDAP_ADMIN_PASSWORD")),
            config.clone(),
            secret_box,
            ldap,
            Http::new()?,
        );
        if config.managed_accounts && !p.manages_accounts() {
            tracing::warn!(
                "LLDAP managed accounts are off: they need ENCRYPTION_KEY, LLDAP_LDAP_URL and LLDAP_BASE_DN"
            );
        }
        Ok(Some(p))
    }

    #[must_use]
    pub fn new(
        url: &str,
        admin_user: &str,
        admin_password: Secret<String>,
        config: HomelabConfig,
        secret_box: Option<Arc<SecretBox>>,
        ldap: Option<LdapTarget>,
        http: Http,
    ) -> LldapProvisioner {
        LldapProvisioner {
            url: url.trim_end_matches('/').to_owned(),
            admin_user: admin_user.to_owned(),
            admin_password,
            config,
            secret_box,
            ldap,
            http,
            jwt: Mutex::new(None),
        }
    }

    /// The broker can create accounts and keep their passwords.
    #[must_use]
    pub fn manages_accounts(&self) -> bool {
        self.config.managed_accounts && self.secret_box.is_some() && self.ldap.is_some()
    }

    #[must_use]
    pub fn managed_username(&self, agent_name: &str) -> String {
        format!("{}{agent_name}", self.config.managed_username_prefix).to_lowercase()
    }

    // -------------------------------------------------------- LLDAP API

    async fn post(
        &self,
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> Result<Reply, ProvisionError> {
        let mut rb = self
            .http
            .request(Method::POST, &format!("{}{path}", self.url))
            .json(body);
        if let Some(t) = token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        self.http.send(rb, TIMEOUT, MAX_BODY).await.map_err(|e| {
            tracing::warn!(error = %e, path, "LLDAP call failed");
            ProvisionError::failed("LLDAP unreachable (see broker logs)")
        })
    }

    async fn login(&self) -> Result<Secret<String>, ProvisionError> {
        let r = self
            .post(
                "/auth/simple/login",
                None,
                &json!({"username": self.admin_user, "password": self.admin_password.expose()}),
            )
            .await?;
        if r.status != 200 {
            return Err(ProvisionError::failed(format!(
                "LLDAP login failed ({})",
                r.status
            )));
        }
        let token = at(&r.json(), &["token"])
            .as_str()
            .filter(|t| !t.is_empty())
            .map(|t| Secret::new(t.to_owned()))
            .ok_or_else(|| ProvisionError::failed("LLDAP login failed (no token)"))?;
        *self.jwt.lock().unwrap_or_else(PoisonError::into_inner) = Some(token.clone());
        Ok(token)
    }

    async fn graphql(
        &self,
        query: &str,
        variables: Value,
        log_errors: bool,
    ) -> Result<Value, ProvisionError> {
        let cached = self
            .jwt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut token = match cached {
            Some(t) => t,
            None => self.login().await?,
        };
        let body = json!({"query": query, "variables": variables});
        let mut r = self
            .post("/api/graphql", Some(token.expose()), &body)
            .await?;
        if r.status == 401 {
            // The JWT expired (about a day): log in again, once.
            token = self.login().await?;
            r = self
                .post("/api/graphql", Some(token.expose()), &body)
                .await?;
        }
        if r.status != 200 {
            tracing::error!(status = r.status, body = %r.head(300), "LLDAP GraphQL error");
            return Err(ProvisionError::failed(format!(
                "LLDAP GraphQL error ({})",
                r.status
            )));
        }
        let data = r.json();
        if let Some(errors) = data
            .get("errors")
            .and_then(Value::as_array)
            .filter(|e| !e.is_empty())
        {
            if log_errors {
                let msgs: Vec<&str> = errors
                    .iter()
                    .map(|e| e.get("message").and_then(Value::as_str).unwrap_or(""))
                    .collect();
                tracing::error!(errors = %msgs.join("; "), "LLDAP GraphQL error");
            }
            return Err(ProvisionError::failed(
                "LLDAP GraphQL error (see broker logs)",
            ));
        }
        Ok(data)
    }

    /// The group's id, looked up now (never a stale cache: B5).
    async fn group_id(&self, name: &str) -> Result<i64, ProvisionError> {
        let data = self.graphql(GROUPS, json!({}), true).await?;
        at(&data, &["data", "groups"])
            .as_array()
            .into_iter()
            .flatten()
            .find(|g| at(g, &["displayName"]).as_str() == Some(name))
            .and_then(|g| at(g, &["id"]).as_i64())
            .ok_or_else(|| {
                ProvisionError::failed(format!("LLDAP group {} does not exist", repr(name)))
            })
    }

    /// The user's display name, or `None` when there is no such user.
    /// LLDAP answers an unknown user with an error, and an outage, a
    /// refused login or a database error with errors too, so a failed
    /// lookup counts as "no such user" only when the full user list, read
    /// successfully, does not hold it (B17). Any other failure is an
    /// error: the Python re-raised it, and a revoke that read it as "gone"
    /// would end the grant with the membership still in place.
    async fn user(&self, username: &str) -> Result<Option<String>, ProvisionError> {
        let lookup = self.graphql(USER, json!({"user": username}), false).await;
        if let Ok(data) = &lookup
            && let Some(user) = at(data, &["data", "user"]).as_object()
        {
            return Ok(Some(
                user.get("displayName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            ));
        }
        let listed = self.graphql(LIST_USERS, json!({}), true).await;
        let users = match &listed {
            Ok(data) => at(data, &["data", "users"]).as_array(),
            Err(_) => None,
        };
        let Some(users) = users else {
            tracing::error!(username, "cannot tell whether the LLDAP user exists");
            return Err(match (lookup, listed) {
                (Err(e), _) | (Ok(_), Err(e)) => e,
                (Ok(_), Ok(_)) => ProvisionError::failed("LLDAP GraphQL error (see broker logs)"),
            });
        };
        let present = users.iter().any(|u| {
            at(u, &["id"])
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(username))
        });
        if present {
            // Listed, yet the lookup failed: not "gone".
            tracing::error!(username, "LLDAP lists the user but its lookup failed");
            return Err(lookup.err().unwrap_or_else(|| {
                ProvisionError::failed("LLDAP GraphQL error (see broker logs)")
            }));
        }
        Ok(None)
    }

    async fn user_group_ids(&self, user: &str) -> Result<Vec<i64>, ProvisionError> {
        let data = self
            .graphql(USER_GROUPS, json!({"user": user}), true)
            .await?;
        Ok(at(&data, &["data", "user", "groups"])
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|g| at(g, &["id"]).as_i64())
            .collect())
    }

    /// Add or remove, then accept "already so": LLDAP reports duplicate
    /// adds and absent removes as opaque errors, so the end state decides.
    async fn mutate(
        &self,
        mutation: &str,
        user: &str,
        group: i64,
        want_member: bool,
    ) -> Result<(), ProvisionError> {
        let Err(original) = self
            .graphql(mutation, json!({"user": user, "group": group}), true)
            .await
        else {
            return Ok(());
        };
        match self.user_group_ids(user).await {
            Ok(groups) if groups.contains(&group) == want_member => {
                tracing::info!(user, group, member = want_member, "LLDAP no-op: already so");
                Ok(())
            }
            Ok(_) => Err(original),
            // The account itself is gone: it is in no group (B17). Only
            // a definite "no such user" counts; an outage is an error, so
            // the revoke is retried.
            Err(_) if !want_member => match self.user(user).await {
                Ok(None) => {
                    tracing::info!(user, group, "LLDAP user is gone; nothing to remove");
                    Ok(())
                }
                Ok(Some(_)) | Err(_) => Err(original),
            },
            Err(_) => Err(original),
        }
    }

    async fn set_password(
        &self,
        username: &str,
        password: &Secret<String>,
    ) -> Result<(), ProvisionError> {
        let Some(ldap) = &self.ldap else {
            return Err(ProvisionError::failed(
                "LLDAP_LDAP_URL is unset; cannot set an LLDAP password",
            ));
        };
        ldap.set_password(&self.admin_user, &self.admin_password, username, password)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, username, "setting an LLDAP password failed");
                ProvisionError::failed("setting the LLDAP password failed (see broker logs)")
            })
    }

    fn seal_password(
        &self,
        agent: AgentId,
        password: &Secret<String>,
    ) -> Result<String, ProvisionError> {
        let Some(sb) = &self.secret_box else {
            return Err(ProvisionError::failed(
                "ENCRYPTION_KEY is unset; cannot store the new password",
            ));
        };
        let row = agent.to_string();
        sb.seal_str(
            password.expose(),
            &Binding::new("agents", "lldap_password_encrypted", &row),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "sealing an LLDAP password");
            ProvisionError::failed("could not store the LLDAP password (see broker logs)")
        })
    }

    // -------------------------------------------------- managed accounts

    /// The agent's LLDAP user id, creating its managed account if it has
    /// none. The agent row stays locked until the provisioning transaction
    /// ends, so a concurrent provision for the same agent waits and then
    /// sees the committed account (B3).
    pub async fn ensure_account(
        &self,
        tx: &Tx<'_>,
        agent: AgentId,
    ) -> Result<String, ProvisionError> {
        let row = agents::get_for_update(tx, agent)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        if let Some(u) = row.lldap_username.as_deref().filter(|u| !u.is_empty()) {
            return Ok(u.to_owned());
        }
        if !self.manages_accounts() {
            return Err(ProvisionError::failed(format!(
                "agent {} has no LLDAP service account and managed accounts are unavailable (ENCRYPTION_KEY or LLDAP_LDAP_URL unset, or disabled in policy)",
                repr(&row.name)
            )));
        }
        let username = self.managed_username(&row.name);
        if !plain_user_id(&username) {
            return Err(ProvisionError::failed(format!(
                "cannot derive an LLDAP user id from {}",
                repr(&row.name)
            )));
        }
        // Another agent's account (a case variant of this name, or one
        // registered by hand) is never taken over (B2).
        let holders = agent_auth_store::lldap::holders(tx, &username, agent)
            .await
            .map_err(|e| store_failed(&e))?;
        if let Some((_, other)) = holders.first() {
            tracing::error!(username, agent = %row.name, holder = %other, "LLDAP account belongs to another agent");
            return Err(ProvisionError::failed(format!(
                "LLDAP account {} belongs to another agent; refusing to adopt it",
                repr(&username)
            )));
        }
        let display = managed_display_name(&row.name);
        match self.user(&username).await? {
            None => {
                self.graphql(
                    CREATE_USER,
                    json!({"user": {
                        "id": username,
                        "email": format!("{username}@{}", self.config.managed_email_domain),
                        "displayName": display,
                    }}),
                    true,
                )
                .await?;
                tracing::info!(username, agent = %row.name, "created LLDAP account");
            }
            // Left behind by an earlier attempt for this same agent
            // (created, but the password step failed).
            Some(existing) if existing == display => {
                tracing::info!(username, agent = %row.name, "adopting the broker's LLDAP account");
            }
            Some(existing) => {
                tracing::error!(username, agent = %row.name, display = %existing, "LLDAP user exists and is not this agent's");
                return Err(ProvisionError::failed(format!(
                    "LLDAP user {} exists and was not created by the broker for this agent; refusing to adopt it",
                    repr(&username)
                )));
            }
        }
        let password = new_password()?;
        let sealed = self.seal_password(agent, &password)?;
        // Only after the password is set do the row's fields change (INV-L3).
        self.set_password(&username, &password).await?;
        agents::set_lldap(tx, agent, Some(&username), Some(&sealed))
            .await
            .map_err(|e| store_failed(&e))?;
        Ok(username)
    }

    /// Replace a managed account's password; the next credential fetch
    /// returns the new one. Hand-registered accounts are refused (INV-L5).
    /// (`POST /admin/agents/{id}/rotate-lldap-password`; errors are 409.)
    pub async fn rotate_password(&self, tx: &Tx<'_>, agent: AgentId) -> Result<(), ProvisionError> {
        let row = agents::get_for_update(tx, agent)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        let (Some(username), Some(_)) = (
            row.lldap_username.as_deref(),
            row.lldap_password_encrypted.as_deref(),
        ) else {
            return Err(ProvisionError::failed(format!(
                "agent {} has no broker-managed LLDAP account to rotate",
                repr(&row.name)
            )));
        };
        let password = new_password()?;
        let sealed = self.seal_password(agent, &password)?;
        self.set_password(username, &password).await?;
        agents::set_lldap(tx, agent, Some(username), Some(&sealed))
            .await
            .map_err(|e| store_failed(&e))?;
        Ok(())
    }

    async fn provision_grant(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
    ) -> Result<Value, ProvisionError> {
        if is_admin_group(&grant.resource) {
            return Err(ProvisionError::failed(admin_group_refusal(&grant.resource)));
        }
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        // A managed account was made by `prepare`, before this
        // transaction locked the grant: never lock the agent row here.
        let Some(user) = agent.lldap_username.filter(|u| !u.is_empty()) else {
            return Err(ProvisionError::failed(format!(
                "agent {} has no LLDAP service account",
                repr(&agent.name)
            )));
        };
        // The add is serialized with every revoke of this membership.
        agent_auth_store::lldap::lock_membership(tx, grant.agent_id, &grant.resource)
            .await
            .map_err(|e| store_failed(&e))?;
        let group = self.group_id(&grant.resource).await?;
        self.mutate(ADD, &user, group, true).await?;
        Ok(json!({"lldap_user": user, "group": grant.resource, "group_id": group}))
    }
}

impl Provisioner for LldapProvisioner {
    fn platform(&self) -> Platform {
        Platform::Homelab
    }

    /// Make the agent's managed account, if it needs one, in a transaction
    /// of its own that locks only the agent row and commits before the
    /// finishing phase locks the grant (lock order: agent before grant).
    /// A concurrent first provision for the same agent waits on the row
    /// lock and then finds the account.
    async fn prepare(
        &self,
        store: &agent_auth_store::Store,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        if is_admin_group(&grant.resource) {
            return Ok(()); // provision refuses it
        }
        // A held agent gets no account (the finish fails the grant). Read
        // in a short transaction: taking the agent row FOR UPDATE after
        // the check's share lock in one transaction would deadlock two
        // concurrent prepares.
        let check = store.begin().await.map_err(|e| store_failed(&e))?;
        let held = agent_auth_store::lockdown::check(&check, grant.agent_id, now)
            .await
            .map_err(|e| store_failed(&e))?
            .is_err();
        check.rollback().await.map_err(|e| store_failed(&e))?;
        if held {
            return Ok(());
        }
        let tx = store.begin().await.map_err(|e| store_failed(&e))?;
        self.ensure_account(&tx, grant.agent_id).await?;
        tx.commit().await.map_err(|e| store_failed(&e))
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        if spec.authority != Authority::Homelab {
            return Ok(Err(Refused(
                "homelab capability must be 'group'".to_owned(),
            )));
        }
        let group = spec.resource.trim().to_owned();
        if is_admin_group(&group) {
            return Ok(Err(Refused(admin_group_refusal(&group))));
        }
        // An empty list means every group (the Python's meaning; an open
        // question in DEVIATIONS.md).
        if !self.config.allowed_groups.is_empty() && !self.config.allowed_groups.contains(&group) {
            return Ok(Err(Refused(format!(
                "group {} is not brokered (allowed_groups)",
                repr(&group)
            ))));
        }
        let has_account = spec
            .agent
            .lldap_username
            .as_deref()
            .is_some_and(|u| !u.is_empty());
        if !has_account && !self.manages_accounts() {
            return Ok(Err(Refused(format!(
                "agent {} has no LLDAP service account configured",
                repr(&spec.agent.name)
            ))));
        }
        Ok(Ok(Validated {
            resource: group,
            authority: Authority::Homelab,
            notes: Vec::new(),
        }))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let grant = grant.grant();
        self.provision_grant(tx, grant).await
    }

    async fn revoke(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        let state = &grant.provisioner_state;
        let recorded = (
            state
                .get("lldap_user")
                .and_then(Value::as_str)
                .filter(|u| !u.is_empty()),
            state.get("group_id").and_then(Value::as_i64),
        );
        let (user, group) = match recorded {
            (Some(u), Some(g)) => (u.to_owned(), g),
            _ => {
                // Interrupted provision (the reaper): the membership may
                // exist anyway, so derive the pair from agent and resource.
                let agent = agents::get(tx, grant.agent_id)
                    .await
                    .map_err(|e| store_failed(&e))?;
                let Some(user) = agent
                    .and_then(|a| a.lldap_username)
                    .filter(|u| !u.is_empty())
                else {
                    return Ok(()); // no account: nothing to be a member
                };
                let group = match self.group_id(&grant.resource).await {
                    Ok(g) => g,
                    // No such group: no membership in it.
                    Err(_) if is_admin_group(&grant.resource) => return Ok(()),
                    Err(e) => return Err(e),
                };
                (user, group)
            }
        };
        // One (user, group) fact shared by every grant on the group: only
        // the last live grant removes it (INV-L4). Expiry counts as well as
        // status, so of several grants lapsing in one tick one removes it.
        // Serialized per (agent, group) until commit, so a concurrent revoke
        // of the other grant sees this one's outcome.
        agent_auth_store::lldap::lock_membership(tx, grant.agent_id, &grant.resource)
            .await
            .map_err(|e| store_failed(&e))?;
        let siblings = grants::siblings(tx, grant)
            .await
            .map_err(|e| store_failed(&e))?;
        if let Some(keeper) = siblings.iter().find(|g| g.is_live(now)) {
            tracing::info!(user, group = %grant.resource, keeper = %keeper.id, "keeping LLDAP membership: still backed");
            return Ok(());
        }
        self.mutate(REMOVE, &user, group, false).await
    }

    async fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?;
        if let (Some(a), Some(sb)) = (&agent, &self.secret_box)
            && let (Some(username), Some(sealed)) = (&a.lldap_username, &a.lldap_password_encrypted)
        {
            let row = a.id.to_string();
            let password = sb
                .open_str(
                    sealed,
                    &Binding::new("agents", "lldap_password_encrypted", &row),
                )
                .map_err(|_| {
                    tracing::error!(agent = %a.name, "the stored LLDAP password does not open");
                    ProvisionError::failed(
                        "the stored LLDAP password could not be read (see broker logs)",
                    )
                })?;
            return Ok(Credential {
                value: Some(password),
                username: Some(username.clone()),
                note: Some(format!(
                    "LLDAP service account {} is in group {}; log in to Authelia-protected services with this username/password",
                    repr(username),
                    repr(&grant.resource)
                )),
                ..Credential::of(CredentialKind::LldapAccount)
            });
        }
        Ok(Credential {
            username: agent.and_then(|a| a.lldap_username),
            note: Some(format!(
                "your service account is now in group {}; authenticate to Authelia-protected services with your own credentials",
                repr(&grant.resource)
            )),
            ..Credential::of(CredentialKind::LldapGroup)
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(Platform::Homelab, "group", "<lldap group>");
        c.groups = Some(
            self.config
                .allowed_groups
                .iter()
                .filter(|g| !is_admin_group(g))
                .map(|g| CatalogEntry {
                    name: g.clone(),
                    description: self.config.group_descriptions.get(g).cloned(),
                    typical_disposition: None,
                })
                .collect(),
        );
        serde_json::to_value(c).ok()
    }
}
