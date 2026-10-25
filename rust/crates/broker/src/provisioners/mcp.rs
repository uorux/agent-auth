//! MCP servers (and other HTTP tools) that take the broker's own tokens
//! (provisioners spec §6). Nothing changes anywhere when a grant is given:
//! its credential is a short-lived ES256 token the server's proxy checks
//! against the JWKS, or per request at `/v1/tokens/verify`.

use std::collections::BTreeSet;
use std::sync::Arc;

use agent_auth_core::authority::ToolSet;
use agent_auth_core::policy::schema::{McpConfig, McpServer};
use agent_auth_core::{Authority, Platform};
use agent_auth_crypto::jwt::TokenIssuer;
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{GrantRow, IssuableGrant, ProvisioningGrant};
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::catalog::{McpServerEntry, PlatformCatalog};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::common::{repr, secs_until, store_failed};
use super::{Credential, ProvisionError, Provisioner, Refused, RequestSpec, Validated};

/// What a token's audience is for a server.
#[must_use]
pub fn audience(server: &McpServer) -> &str {
    server
        .audience
        .as_deref()
        .filter(|a| !a.is_empty())
        .unwrap_or(&server.url)
}

fn tool_name_ok(t: &str) -> bool {
    t == "*"
        || (!t.is_empty()
            && t.len() <= 128
            && t.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-')
            }))
}

fn tools_list(tools: &ToolSet) -> Vec<String> {
    match tools {
        ToolSet::All => vec!["*".to_owned()],
        ToolSet::Some(set) => set.iter().cloned().collect(),
    }
}

#[derive(Debug)]
pub struct McpProvisioner {
    config: McpConfig,
    tokens: Arc<TokenIssuer>,
}

impl McpProvisioner {
    #[must_use]
    pub fn new(config: &McpConfig, tokens: Arc<TokenIssuer>) -> McpProvisioner {
        McpProvisioner {
            config: config.clone(),
            tokens,
        }
    }

    fn gone(resource: &str) -> ProvisionError {
        ProvisionError::failed(format!(
            "MCP server {} is no longer in the catalog",
            repr(resource)
        ))
    }

    fn validate_spec(&self, spec: &RequestSpec<'_>) -> Result<Validated, Refused> {
        let name = spec.resource.trim().to_lowercase();
        let Some(server) = self.config.servers.get(name.as_str()) else {
            let known: Vec<&str> = self.config.servers.keys().map(|k| k.as_str()).collect();
            let known = if known.is_empty() {
                "none".to_owned()
            } else {
                known.join(", ")
            };
            return Err(Refused(format!(
                "no MCP server {} in the catalog (there is: {known})",
                repr(&name)
            )));
        };
        let Authority::Mcp { tools } = &spec.authority else {
            return Err(Refused("mcp capability is \"use\"".to_owned()));
        };
        if let ToolSet::Some(set) = tools {
            if !set.iter().all(|t| tool_name_ok(t)) {
                return Err(Refused("malformed tool name".to_owned()));
            }
            if !server.tools.is_empty() {
                let known: BTreeSet<&str> = server.tools.iter().map(String::as_str).collect();
                let unknown: Vec<&str> = set
                    .iter()
                    .map(String::as_str)
                    .filter(|t| !known.contains(t))
                    .collect();
                if !unknown.is_empty() {
                    return Err(Refused(format!(
                        "{name} has no tool {}",
                        unknown.join(", ")
                    )));
                }
            }
        }
        let what = match tools {
            ToolSet::All => "every tool".to_owned(),
            ToolSet::Some(set) => format!(
                "tools {}",
                set.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        };
        let mut note = format!("{what} of {name} ({})", server.url);
        if !server.description.is_empty() {
            note.push_str(&format!(": {}", server.description));
        }
        Ok(Validated {
            resource: name,
            authority: spec.authority.clone(),
            notes: vec![note],
        })
    }

    fn mint(
        &self,
        grant: &GrantRow,
        agent: &AgentRow,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let server = self
            .config
            .servers
            .get(grant.resource.as_str())
            .ok_or_else(|| Self::gone(&grant.resource))?;
        let tools = match &grant.authority {
            Authority::Mcp { tools } => tools_list(tools),
            _ => vec!["*".to_owned()],
        };
        let remaining = secs_until(grant.expires_at, now);
        let ttl = self.config.token_ttl.as_i64().min(remaining);
        let mut claims = Map::new();
        claims.insert("agent".into(), json!(agent.name));
        claims.insert("server".into(), json!(grant.resource));
        claims.insert("tools".into(), json!(tools));
        claims.insert("grant".into(), json!(grant.id.to_string()));
        let (token, exp) = self
            .tokens
            .mint(
                &format!("agent:{}", agent.name),
                audience(server),
                ttl,
                &claims,
                now.unix_timestamp(),
            )
            .map_err(|e| {
                tracing::error!(error = %e, "minting an MCP token");
                ProvisionError::failed("could not mint a token (see broker logs)")
            })?;
        Ok(Credential {
            kind: "mcp_token".to_owned(),
            value: Some(token),
            expires_at: OffsetDateTime::from_unix_timestamp(exp).ok(),
            note: Some(format!(
                "Send it to {} as `Authorization: Bearer <value>`. It is short-lived: call get_credential again for a fresh one (nothing new is issued once the grant ends).",
                server.url
            )),
            ..Credential::default()
        })
    }
}

impl Provisioner for McpProvisioner {
    fn platform(&self) -> Platform {
        Platform::Mcp
    }

    async fn validate(
        &self,
        _tx: &Tx<'_>,
        spec: RequestSpec<'_>,
        _now: OffsetDateTime,
    ) -> Result<Result<Validated, Refused>, StoreError> {
        Ok(self.validate_spec(&spec))
    }

    async fn provision<'t>(
        &self,
        _tx: &'t Tx<'_>,
        grant: &ProvisioningGrant<'t>,
        _now: OffsetDateTime,
    ) -> Result<Value, ProvisionError> {
        let grant = grant.grant();
        if !self.config.servers.contains_key(grant.resource.as_str()) {
            return Err(Self::gone(&grant.resource));
        }
        Ok(json!({"server": grant.resource}))
    }

    async fn revoke(
        &self,
        _tx: &Tx<'_>,
        _grant: &GrantRow,
        _now: OffsetDateTime,
    ) -> Result<(), ProvisionError> {
        Ok(()) // nothing changed anywhere; tokens stop being issued
    }

    async fn credential<'t>(
        &self,
        tx: &'t Tx<'_>,
        issuable: &IssuableGrant<'t>,
        now: OffsetDateTime,
    ) -> Result<Credential, ProvisionError> {
        let grant = issuable.grant();
        let agent = agents::get(tx, grant.agent_id)
            .await
            .map_err(|e| store_failed(&e))?
            .ok_or_else(|| ProvisionError::failed("agent not found"))?;
        self.mint(grant, &agent, now)
    }

    fn catalog(&self, _agent: &AgentRow) -> Option<Value> {
        let mut c = PlatformCatalog::new(
            Platform::Mcp,
            "use (scope {\"tools\": [...]}; omit for every tool)",
            "<server>",
        );
        c.capabilities = Some(vec!["use".to_owned()]);
        c.servers = Some(
            self.config
                .servers
                .iter()
                .map(|(name, s)| McpServerEntry {
                    name: name.to_string(),
                    url: s.url.clone(),
                    description: s.description.clone(),
                    tools: (!s.tools.is_empty()).then(|| s.tools.clone()),
                })
                .collect(),
        );
        serde_json::to_value(c).ok()
    }
}
