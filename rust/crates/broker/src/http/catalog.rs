//! `GET /v1/catalog` (http-api §4): each enabled provisioner's entry, in a
//! fixed order, with the policy's typical dispositions filled in and the
//! a2a peers from the a2a part's hook.

use agent_auth_core::{Authority, Platform};
use agent_auth_store::StoreError;
use agent_auth_store::agents::AgentRow;
use serde_json::{Map, Value};

use super::serialize::CATALOG_ORDER;
use agent_auth_wire::catalog::PlatformCatalog;

use crate::provisioners::{AnyProvisioner, Provisioner};
use crate::service::disposition;
use crate::state::AppState;

async fn disposition_of(
    st: &AppState,
    tx: &agent_auth_store::Tx<'_>,
    agent: &AgentRow,
    platform: Platform,
    capability: &str,
) -> Result<Option<Value>, StoreError> {
    let Ok(authority) = Authority::from_wire(platform, capability, &Map::new()) else {
        return Ok(None);
    };
    let d = disposition(&st.policy, tx, agent, &authority, st.now()).await?;
    Ok(serde_json::to_value(d).ok())
}

/// The catalog for this agent.
pub async fn catalog(st: &AppState, agent: &AgentRow) -> Result<Value, StoreError> {
    let tx = st.store.begin().await?;
    let mut platforms = Vec::new();
    for platform in CATALOG_ORDER {
        let Some(p) = st.registry.get(platform) else {
            continue;
        };
        if platform == Platform::A2a {
            let entry = crate::a2a::catalog_entry(st, &tx, agent, st.now()).await?;
            platforms.push(serde_json::to_value(entry).unwrap_or(Value::Null));
            continue;
        }
        if let AnyProvisioner::Pool(pool) = p {
            // Listed only when the agent may lease from some pool.
            let pools = pool.status(&tx, agent).await?;
            if pools.is_empty() {
                continue;
            }
            let mut c = PlatformCatalog::new(
                Platform::Pool,
                "lease (scope {} for any, {\"match\": {...}}, {\"previous\": true}, or {\"item\": name})",
                "<pool>",
            );
            let d = disposition_of(st, &tx, agent, platform, "lease")
                .await?
                .and_then(|d| d.as_str().map(str::to_owned))
                .unwrap_or_else(|| "human review".to_owned());
            c.capabilities = Some(vec![format!("lease ({d})")]);
            c.pools = Some(pools);
            platforms.push(serde_json::to_value(c).unwrap_or(Value::Null));
            continue;
        }
        let Some(Value::Object(mut entry)) = p.catalog(agent) else {
            continue;
        };
        // exclude_none on the model's own fields.
        entry.retain(|_, v| !v.is_null());
        match platform {
            Platform::Github if entry.contains_key("create_owners") => {
                if let Some(d) = disposition_of(st, &tx, agent, platform, "create").await? {
                    entry.insert("create_disposition".to_owned(), d);
                }
            }
            Platform::Kubernetes => {
                if let Some(Value::Array(roles)) = entry.get("roles").cloned() {
                    let mut out = Vec::with_capacity(roles.len());
                    for role in roles {
                        let mut role = role;
                        let name = role.get("name").and_then(Value::as_str).map(str::to_owned);
                        if let (Some(name), Value::Object(r)) = (name, &mut role)
                            && let Some(d) = disposition_of(st, &tx, agent, platform, &name).await?
                        {
                            r.insert("typical_disposition".to_owned(), d);
                        }
                        out.push(role);
                    }
                    entry.insert("roles".to_owned(), Value::Array(out));
                }
            }
            _ => {}
        }
        platforms.push(Value::Object(entry));
    }
    let mut out = Map::new();
    out.insert("platforms".to_owned(), Value::Array(platforms));
    Ok(Value::Object(out))
}
