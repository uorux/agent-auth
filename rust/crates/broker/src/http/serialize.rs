//! Rows to response bodies (http-api §5).

use agent_auth_core::Platform;
use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_store::agents::{self, AgentRow};
use agent_auth_store::grants::{self, GrantRow};
use agent_auth_store::requests::RequestRow;
use agent_auth_store::{StoreError, Tx};
use agent_auth_wire::agent::{GrantOut, RequestOut, guidance};
use agent_auth_wire::common::{AgentKind as WireKind, Placement as WirePlacement};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// A store enum to the wire's copy of it, by its text.
#[must_use]
pub fn by_name<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(Value::String(text.to_owned())).ok()
}

#[must_use]
pub fn wire_kind(k: AgentKind) -> WireKind {
    match k {
        AgentKind::Service => WireKind::Service,
        AgentKind::Ephemeral => WireKind::Ephemeral,
        AgentKind::Operator => WireKind::Operator,
    }
}

#[must_use]
pub fn wire_placement(p: Placement) -> WirePlacement {
    match p {
        Placement::Host => WirePlacement::Host,
        Placement::Sandbox => WirePlacement::Sandbox,
    }
}

/// An agent's name, `?` when it is gone.
pub async fn name_of(tx: &Tx<'_>, id: agent_auth_core::AgentId) -> Result<String, StoreError> {
    Ok(agents::get(tx, id)
        .await?
        .map_or_else(|| "?".to_owned(), |a| a.name))
}

fn object(v: &Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    }
}

/// `RequestOut`, every key present. Capability and scope come from the
/// stored authority (as submitted when it never parsed).
pub async fn request_out(tx: &Tx<'_>, r: &RequestRow) -> Result<RequestOut, StoreError> {
    let (capability, scope) = match &r.authority {
        Some(a) => (a.capability(), a.scope()),
        None => (r.requested_capability.clone(), object(&r.requested_scope)),
    };
    let grant_id = grants::by_request(tx, r.id).await?.map(|g| g.id);
    let delegator = match r.delegation {
        Some(d) => Some(name_of(tx, d.delegator_agent_id).await?),
        None => None,
    };
    Ok(RequestOut {
        id: r.id,
        agent: name_of(tx, r.agent_id).await?,
        platform: r.platform,
        capability,
        resource: r.resource.clone(),
        scope,
        justification: r.justification.clone(),
        requested_duration_secs: r.requested_duration_secs,
        status: r.status,
        attempt: r.attempt,
        decision_source: r.decision_source,
        decision_reason: r.decision_reason.clone(),
        approved_duration_secs: r.approved_duration_secs,
        approved_scope: r.approved_edit.as_ref().map(|e| e.authority.scope()),
        approved_resource: r.approved_edit.as_ref().map(|e| e.resource.clone()),
        grant_id,
        delegator,
        delegation_thread_id: r.delegation.map(|d| d.thread_id),
        created_at: r.created_at,
        guidance: guidance(r.status, r.id, grant_id),
    })
}

/// `GrantOut`. The delegator is its name, or null if unknown.
pub async fn grant_out(
    tx: &Tx<'_>,
    agent: &AgentRow,
    g: &GrantRow,
) -> Result<GrantOut, StoreError> {
    let delegator = match g.delegation {
        Some(d) => agents::get(tx, d.delegator_agent_id).await?.map(|a| a.name),
        None => None,
    };
    Ok(GrantOut {
        id: g.id,
        request_id: g.request_id,
        agent: agent.name.clone(),
        platform: g.platform,
        capability: g.authority.capability(),
        resource: g.resource.clone(),
        scope: g.authority.scope(),
        granted_at: g.granted_at,
        expires_at: g.expires_at,
        status: g.status,
        delegator,
        delegation_thread_id: g.delegation.map(|d| d.thread_id),
    })
}

/// The fixed order of the catalog's platforms (http-api §4).
pub const CATALOG_ORDER: [Platform; 12] = [
    Platform::Github,
    Platform::Agents,
    Platform::Sandbox,
    Platform::Hostexec,
    Platform::Mcp,
    Platform::Models,
    Platform::Homelab,
    Platform::Kubernetes,
    Platform::A2a,
    Platform::Mail,
    Platform::Pool,
    Platform::Google,
];

/// A text cut to `n` characters plus `…` when longer (audit).
#[must_use]
pub fn cut(text: &str, n: usize) -> String {
    if text.chars().count() > n {
        let mut out: String = text.chars().take(n).collect();
        out.push('…');
        out
    } else {
        text.to_owned()
    }
}
