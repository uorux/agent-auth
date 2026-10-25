//! Model calls through the homelab's LiteLLM gateway (provisioners spec
//! §5). A grant is one virtual key under a gateway user named after the
//! agent; the key ends with the grant at the gateway itself (`duration`),
//! and revoking deletes it. The key is kept sealed in the grant's
//! provisioner state to hand out again.
//!
//! Fixes (DEVIATIONS.md): an existing gateway user is reused only when it
//! is the broker's own for this agent (B12), and gateway answers stay in the
//! broker's log, out of agent-visible errors (B13).

use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::policy::schema::ModelsConfig;
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::Secret;
use agent_auth_crypto::secretbox::{Binding, SecretBox};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{GatewayEntry, PlatformCatalog};
use futures::StreamExt as _;
use reqwest::Method;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::common::{at, repr, secs_until, store_failed};
use super::http::{self, Http, MAX_BODY, Reply};
use super::setup::{ConfigError, Env};
use super::{Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated};

const TIMEOUT: Duration = Duration::from_secs(20);
/// The role the broker gives its gateway users.
const USER_ROLE: &str = "internal_user_viewer";

fn fields(agent: &AgentRow) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("agent".into(), json!(agent.name));
    m.insert("project".into(), json!(agent.project));
    m.insert("host".into(), json!(agent.host));
    m.insert("runtime".into(), json!(agent.runtime));
    m.insert("placement".into(), json!(agent.placement.as_str()));
    m
}

#[derive(Debug)]
pub struct ModelsProvisioner {
    config: ModelsConfig,
    admin: String,
    master_key: Secret<String>,
    secret_box: Arc<SecretBox>,
    http: Http,
}

impl ModelsProvisioner {
    /// On when `platforms.models.url`, `LITELLM_MASTER_KEY` and
    /// `ENCRYPTION_KEY` are all set; otherwise off, with a warning when only
    /// part of it is.
    pub fn from_env(
        env: &Env<'_>,
        config: &ModelsConfig,
        secret_box: Option<Arc<SecretBox>>,
    ) -> Result<Option<ModelsProvisioner>, ConfigError> {
        if config.url.is_empty() {
            return Ok(None);
        }
        let master = env.get("LITELLM_MASTER_KEY");
        match (master.is_empty(), secret_box) {
            (false, Some(sb)) => Ok(Some(ModelsProvisioner::new(
                config.clone(),
                Secret::new(master),
                sb,
                Http::new()?,
            ))),
            _ => {
                tracing::warn!(
                    "platforms.models is set but LITELLM_MASTER_KEY or ENCRYPTION_KEY is not; models is off"
                );
                Ok(None)
            }
        }
    }

    #[must_use]
    pub fn new(
        config: ModelsConfig,
        master_key: Secret<String>,
        secret_box: Arc<SecretBox>,
        http: Http,
    ) -> ModelsProvisioner {
        let admin = config
            .admin_url
            .as_deref()
            .filter(|u| !u.is_empty())
            .unwrap_or(&config.url)
            .trim_end_matches('/')
            .to_owned();
        ModelsProvisioner {
            config,
            admin,
            master_key,
            secret_box,
            http,
        }
    }

    /// What the agent's key may call (`by_runtime` first; `"*"` covers
    /// runtimes not named and agents without one).
    fn models(&self, agent: &AgentRow) -> Vec<String> {
        let by = &self.config.by_runtime;
        if by.is_empty() {
            return self.config.models.clone();
        }
        agent
            .runtime
            .as_deref()
            .and_then(|r| by.get(r))
            .or_else(|| by.get("*"))
            .cloned()
            .unwrap_or_default()
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Reply, ProvisionError> {
        let mut rb = self
            .http
            .request(
                method,
                &http::with_query(&format!("{}{path}", self.admin), query),
            )
            .header(
                "Authorization",
                format!("Bearer {}", self.master_key.expose()),
            );
        if let Some(b) = body {
            rb = rb.json(b);
        }
        http::send(rb, TIMEOUT, MAX_BODY)
            .await
            .map_err(|e| ProvisionError::failed(format!("model gateway: {e}")))
    }

    /// The gateway user `name`, if the broker made it for this agent.
    /// `Err(())`: a user of that id exists but is not the broker's.
    async fn user_info(&self, name: &str) -> Result<Result<Option<Value>, ()>, ProvisionError> {
        let r = self
            .call(Method::GET, "/user/info", &[("user_id", name)], None)
            .await?;
        if r.status != 200 {
            return Ok(Ok(None));
        }
        let info = at(&r.json(), &["user_info"]).clone();
        if at(&info, &["user_id"]).as_str() != Some(name) {
            return Ok(Ok(None));
        }
        let ours = at(&info, &["user_role"]).as_str() == Some(USER_ROLE)
            && at(&info, &["metadata", "agent"]).as_str() == Some(name);
        Ok(if ours { Ok(Some(info)) } else { Err(()) })
    }

    /// The gateway user that counts this agent's spend across its keys.
    async fn ensure_user(&self, agent: &AgentRow) -> Result<(), ProvisionError> {
        let foreign = || {
            tracing::error!(agent = %agent.name, "model gateway user exists and is not the broker's");
            ProvisionError::failed(format!(
                "the model gateway has a user {} the broker did not create; refusing to issue a key under it",
                agent.name
            ))
        };
        match self.user_info(&agent.name).await? {
            Ok(Some(_)) => return Ok(()),
            Err(()) => return Err(foreign()),
            Ok(None) => {}
        }
        let made = self
            .call(
                Method::POST,
                "/user/new",
                &[],
                Some(&json!({
                    "user_id": agent.name,
                    "user_alias": agent.name,
                    "user_role": USER_ROLE,
                    "auto_create_key": false,
                    "metadata": fields(agent),
                })),
            )
            .await?;
        if matches!(made.status, 200 | 201) {
            return Ok(());
        }
        if made.text().contains("already exists") {
            // Made concurrently: reuse it only if it is ours.
            return match self.user_info(&agent.name).await? {
                Ok(Some(_)) => Ok(()),
                _ => Err(foreign()),
            };
        }
        tracing::error!(agent = %agent.name, status = made.status, body = %made.head(200), "model gateway refused the user");
        Err(ProvisionError::failed(format!(
            "model gateway refused the user for {}: {}",
            agent.name, made.status
        )))
    }

    fn binding_row(grant: &GrantRow) -> String {
        grant.id.to_string()
    }

    fn open_key(&self, grant: &GrantRow) -> Result<Option<Secret<String>>, ProvisionError> {
        let Some(sealed) = grant
            .provisioner_state
            .get("key_encrypted")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let row = Self::binding_row(grant);
        self.secret_box
            .open_str(
                sealed,
                &Binding::new("grants", "provisioner_state.key_encrypted", &row),
            )
            .map(Some)
            .map_err(|_| {
                tracing::error!(grant = %grant.id, "the stored gateway key does not open");
                ProvisionError::failed("the stored key could not be read (see broker logs)")
            })
    }

    async fn provision_grant(
        &self,
        tx: &Tx<'_>,
        grant: &GrantRow,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        let models = self.models(&agent);
        if !self.config.by_runtime.is_empty() && models.is_empty() {
            return Err(ProvisionError::failed(format!(
                "no models for runtime {}",
                agent
                    .runtime
                    .as_deref()
                    .map_or_else(|| "None".to_owned(), repr)
            )));
        }
        self.ensure_user(&agent).await?;
        let secs = secs_until(grant.expires_at, now).max(60);
        let id = grant.id.to_string();
        let alias = format!("{}/{}", agent.name, id.get(..8).unwrap_or(&id));
        let mut metadata = fields(&agent);
        metadata.insert("grant_id".into(), json!(id));
        metadata.insert("issued_by".into(), json!("agent-auth"));
        let mut body = Map::new();
        body.insert("user_id".into(), json!(agent.name));
        body.insert("key_alias".into(), json!(alias));
        body.insert("duration".into(), json!(format!("{secs}s")));
        body.insert("metadata".into(), Value::Object(metadata));
        if !models.is_empty() {
            body.insert("models".into(), json!(models));
        }
        if let Some(budget) = self.config.max_budget {
            body.insert("max_budget".into(), json!(budget));
            body.insert("budget_duration".into(), json!(self.config.budget_duration));
        }
        let r = self
            .call(
                Method::POST,
                "/key/generate",
                &[],
                Some(&Value::Object(body)),
            )
            .await?;
        let key = (r.status == 200)
            .then(|| {
                at(&r.json(), &["key"])
                    .as_str()
                    .filter(|k| !k.is_empty())
                    .map(|k| Secret::new(k.to_owned()))
            })
            .flatten();
        let Some(key) = key else {
            tracing::error!(agent = %agent.name, status = r.status, body = %r.head(200), "model gateway refused the key");
            return Err(ProvisionError::failed(format!(
                "model gateway refused the key: {}",
                r.status
            )));
        };
        let row = Self::binding_row(grant);
        let sealed = self
            .secret_box
            .seal_str(
                key.expose(),
                &Binding::new("grants", "provisioner_state.key_encrypted", &row),
            )
            .map_err(|e| {
                tracing::error!(error = %e, "sealing a gateway key");
                ProvisionError::failed("could not store the key (see broker logs)")
            })?;
        tracing::info!(alias, agent = %agent.name, secs, "models: key issued");
        Ok(json!({"key_encrypted": sealed, "key_alias": alias, "user_id": agent.name}))
    }

    async fn revoke_grant(&self, grant: &GrantRow) -> Result<(), ProvisionError> {
        let Some(key) = self.open_key(grant)? else {
            return Ok(());
        };
        let alias = grant
            .provisioner_state
            .get("key_alias")
            .and_then(Value::as_str)
            .unwrap_or("None");
        let r = self
            .call(
                Method::POST,
                "/key/delete",
                &[],
                Some(&json!({"keys": [key.expose()]})),
            )
            .await?;
        if r.status == 404 || (r.status == 400 && r.text().to_lowercase().contains("not found")) {
            return Ok(()); // already gone at the gateway
        }
        if r.status != 200 {
            tracing::error!(alias, status = r.status, body = %r.head(200), "model gateway did not delete a key");
            return Err(ProvisionError::failed(format!(
                "model gateway did not delete {alias}: {}",
                r.status
            )));
        }
        Ok(())
    }

    /// Spend per agent, for `/admin/models/usage`: each named agent's
    /// gateway user, at most 8 lookups at a time. Never `/user/list`.
    pub async fn usage(&self, names: &[String]) -> Result<Vec<Value>, ProvisionError> {
        let found: Vec<Result<Option<Value>, ProvisionError>> = futures::stream::iter(names.iter().cloned())
            .map(|name| async move {
                let r = self.call(Method::GET, "/user/info", &[("user_id", &name)], None).await?;
                if matches!(r.status, 400 | 404) {
                    return Ok(None);
                }
                if r.status != 200 {
                    tracing::error!(status = r.status, body = %r.head(200), "model gateway usage lookup failed");
                    return Err(ProvisionError::failed(format!("model gateway: {}", r.status)));
                }
                let info = at(&r.json(), &["user_info"]).clone();
                Ok((at(&info, &["user_id"]).as_str() == Some(name.as_str())).then_some(info))
            })
            .buffered(8)
            .collect()
            .await;
        let mut out = Vec::new();
        for f in found {
            if let Some(u) = f? {
                out.push(u);
            }
        }
        Ok(out)
    }
}

impl Provisioner for ModelsProvisioner {
    fn platform(&self) -> Platform {
        Platform::Models
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        if spec.authority != Authority::Models {
            return Ok(Err(Refused("models capability must be \"use\"".to_owned())));
        }
        if spec.resource != self.config.name {
            return Ok(Err(Refused(format!(
                "unknown model gateway {} (this broker has {})",
                repr(&spec.resource),
                repr(&self.config.name)
            ))));
        }
        let models = self.models(spec.agent);
        if !self.config.by_runtime.is_empty() && models.is_empty() {
            let known: Vec<&str> = self.config.by_runtime.keys().map(String::as_str).collect();
            return Ok(Err(Refused(format!(
                "no models for runtime {} at this gateway (only {})",
                repr(spec.agent.runtime.as_deref().unwrap_or("(none)")),
                known.join(", ")
            ))));
        }
        let note = if models.is_empty() {
            "may call: every model the gateway serves".to_owned()
        } else {
            format!("may call: {}", models.join(", "))
        };
        Ok(Ok(Validated {
            resource: spec.resource,
            authority: Authority::Models,
            notes: vec![note],
        }))
    }

    async fn provision<'t>(
        &self,
        tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let grant = grant.grant();
        self.provision_grant(tx, grant, now).await
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        self.revoke_grant(grant).await
    }

    async fn credential<'t>(
        &self,
        _tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        let key = self
            .open_key(grant)?
            .ok_or_else(|| ProvisionError::failed("no key was issued for this grant"))?;
        let base = self.config.url.trim_end_matches('/').to_owned();
        Ok(Credential {
            kind: "model_gateway_key".to_owned(),
            value: Some(key),
            url: Some(base.clone()),
            expires_at: Some(grant.expires_at),
            note: Some(format!(
                "Claude Code: ANTHROPIC_BASE_URL={base} and ANTHROPIC_AUTH_TOKEN=<this key>. OpenAI-compatible clients (codex): base URL {base}/v1 with this key. The key is yours alone and ends with the grant."
            )),
            ..Credential::default()
        })
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(Platform::Models, "use", self.config.name.clone());
        c.capabilities = Some(vec!["use".to_owned()]);
        c.gateway = Some(GatewayEntry {
            name: self.config.name.clone(),
            url: self.config.url.clone(),
            models: (!self.config.models.is_empty()).then(|| self.config.models.clone()),
        });
        serde_json::to_value(c).ok()
    }
}
