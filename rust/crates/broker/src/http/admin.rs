//! The admin API (http-api §2.7): agents, rules, requests (decide), grant
//! revocation, projects. Every handler takes an [`AdminCaller`] (the admin
//! token, or a panel session whose allowlist and CSRF the extractor
//! checked).

use std::collections::BTreeMap;

use agent_auth_core::containment::{AgentKind, Placement};
use agent_auth_core::{AgentId, GrantId, GrantStatus, RequestId, RuleId};
use agent_auth_crypto::api_key;
use agent_auth_store::agents::{self, AgentRow, NewAgent};
use agent_auth_store::rules::{self, RuleRow};
use agent_auth_store::{StoreError, Tx, grants, requests, sandboxes};
use agent_auth_wire::admin::{
    AgentAttributesBody, AgentCreate, AgentOut, AgentRenameBody, AgentRenamed, DecideBody,
    Disabled, Patch, ProjectOut, Projects, Revoked, RuleAction, RuleOut, SetKindBody,
    SetWebhookBody,
};
use agent_auth_wire::agent::RequestOut;
use agent_auth_wire::common::SettableKind;
use agent_auth_wire::error::parse_body;
use agent_auth_wire::literal::True;
use agent_auth_wire::query::clamp_limit;
use agent_auth_wire::secret::WireSecret;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::Value;

use super::body::JsonBody;
use super::query_params;
use super::serialize::{request_out, wire_kind, wire_placement};
use crate::auth::{AdminCaller, HumanDecider};
use crate::error::{ApiError, ApiResult};
use crate::provisioners::{AnyProvisioner, not_enabled};
use crate::service::{self, HumanDecision, ServiceError};
use crate::state::AppState;

const NOT_OPERATOR: &str = "the operator's identity belongs to the admin panel's chat";
const NOT_OPERATOR_NAME: &str = "'operator' is the admin panel's name for the operator";

fn unknown_agent() -> ApiError {
    ApiError::not_found("unknown agent")
}

fn random_failed() -> ApiError {
    ApiError::internal(&"the system random number generator failed")
}

/// `AgentOut`, every key present.
pub fn agent_out(
    a: &AgentRow,
    api_key: Option<String>,
    webhook_secret: Option<String>,
) -> AgentOut {
    AgentOut {
        id: a.id,
        name: a.name.clone(),
        description: a.description.clone(),
        kind: wire_kind(a.kind),
        webhook_url: a.webhook_url.clone(),
        lldap_username: a.lldap_username.clone(),
        lldap_managed: a.lldap_password_encrypted.is_some(),
        disabled: a.disabled,
        last_seen_at: a.last_seen_at,
        parent: a.parent_agent_id,
        sandbox: a.sandbox_id,
        runtime: a.runtime.clone(),
        project: a.project.clone(),
        host: a.host.clone(),
        placement: wire_placement(a.placement),
        lease_expires_at: a.lease_expires_at,
        api_key: api_key.and_then(|k| WireSecret::new(k).ok()),
        webhook_secret: webhook_secret.and_then(|k| WireSecret::new(k).ok()),
    }
}

fn without_nulls(out: &AgentOut) -> ApiResult<Json<Value>> {
    out.without_nulls()
        .map(Json)
        .map_err(|e| ApiError::internal(&e))
}

/// By id, then (where the route allows) by name.
async fn find_agent(tx: &Tx<'_>, key: &str, by_name: bool) -> Result<Option<AgentRow>, StoreError> {
    if let Ok(id) = key.parse::<AgentId>()
        && let Some(a) = agents::get(tx, id).await?
    {
        return Ok(Some(a));
    }
    if by_name {
        return agents::by_name(tx, key).await;
    }
    Ok(None)
}

/// A webhook URL the a2a part will ping (422 otherwise).
fn check_webhook(st: &AppState, url: &str) -> ApiResult<()> {
    crate::a2a::webhook::check_url(&st.a2a.config, url)
        .map(|_| ())
        .map_err(ApiError::unprocessable)
}

fn not_operator(a: &AgentRow) -> ApiResult<()> {
    if a.kind == AgentKind::Operator {
        Err(ApiError::conflict(NOT_OPERATOR))
    } else {
        Ok(())
    }
}

async fn create_agent(
    State(st): State<AppState>,
    _admin: AdminCaller,
    JsonBody(body): JsonBody<AgentCreate>,
) -> ApiResult<Json<Value>> {
    let name = body.name.as_str();
    if name == "operator" {
        return Err(ApiError::conflict(NOT_OPERATOR_NAME));
    }
    let kind = match body.kind {
        SettableKind::Service => AgentKind::Service,
        SettableKind::Ephemeral => AgentKind::Ephemeral,
    };
    // A webhook on an ephemeral agent is never used (http-api §8.14).
    if kind == AgentKind::Ephemeral && body.webhook_url.is_some() {
        return Err(ApiError::unprocessable(
            "webhook_url is for service agents (an ephemeral agent receives nothing)",
        ));
    }
    if let Some(url) = &body.webhook_url {
        check_webhook(&st, url.as_str())?;
    }
    let key = api_key::generate().map_err(|_| random_failed())?;
    let secret = match &body.webhook_url {
        Some(_) => Some(crate::random::token_urlsafe(32).map_err(|_| random_failed())?),
        None => None,
    };
    let tx = st.store.begin().await?;
    if agents::by_name(&tx, name).await?.is_some() {
        return Err(ApiError::conflict(format!("agent '{name}' already exists")));
    }
    let row = agents::insert(
        &tx,
        &NewAgent {
            id: AgentId::new(),
            name,
            description: body.description.as_str(),
            key_id: key.key_id.as_str(),
            api_key_hash: key.hash.as_str(),
            kind,
            webhook_url: body.webhook_url.as_ref().map(|u| u.as_str()),
            webhook_secret: secret.as_deref(),
            lldap_username: body.lldap_username.as_ref().map(|u| u.as_str()),
            parent_agent_id: None,
            sandbox_id: None,
            runtime: body.runtime.as_ref().map(|v| v.as_str()),
            project: body.project.as_ref().map(|v| v.as_str()),
            host: body.host.as_ref().map(|v| v.as_str()),
            placement: Placement::Host,
            lease_expires_at: None,
            last_seen_at: None,
            now: st.now(),
        },
    )
    .await
    .map_err(|e| {
        if e.is_unique_violation() {
            ApiError::conflict(format!("agent '{name}' already exists"))
        } else {
            e.into()
        }
    })?;
    tx.commit().await?;
    without_nulls(&agent_out(
        &row,
        Some(key.full_key.expose().clone()),
        secret,
    ))
}

async fn list_agents(
    State(st): State<AppState>,
    _admin: AdminCaller,
) -> ApiResult<Json<Vec<AgentOut>>> {
    let tx = st.store.begin().await?;
    Ok(Json(
        agents::list(&tx)
            .await?
            .iter()
            .map(|a| agent_out(a, None, None))
            .collect(),
    ))
}

fn patched<const M: usize>(
    p: Patch<agent_auth_wire::text::Attribute<M, true>>,
    current: Option<String>,
) -> Option<String> {
    match p {
        Patch::Keep => current,
        Patch::Set(v) => v.map(|v| v.as_str().to_owned()).filter(|s| !s.is_empty()),
    }
}

async fn attributes(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(key): Path<String>,
    JsonBody(body): JsonBody<AgentAttributesBody>,
) -> ApiResult<Json<AgentOut>> {
    let tx = st.store.begin().await?;
    let a = find_agent(&tx, &key, true)
        .await?
        .ok_or_else(unknown_agent)?;
    not_operator(&a)?;
    if a.sandbox_id.is_some() {
        return Err(ApiError::conflict(format!(
            "{} was minted in an agent VM; its fields are the broker's",
            a.name
        )));
    }
    let runtime = patched(body.runtime, a.runtime.clone());
    // A web UI connector's agent is always a human's call, keyed on its
    // runtime: it stays `web` (migration 0006 refuses it too).
    if runtime != a.runtime && agent_auth_store::oauth::is_bound(&tx, a.id).await? {
        return Err(ApiError::conflict(format!(
            "{} is a web UI connector's agent; its runtime stays web",
            a.name
        )));
    }
    let project = patched(body.project, a.project.clone());
    let host = patched(body.host, a.host.clone());
    agents::set_attributes(
        &tx,
        a.id,
        runtime.as_deref(),
        project.as_deref(),
        host.as_deref(),
        a.placement,
    )
    .await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    Ok(Json(agent_out(&row, None, None)))
}

async fn rename(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(key): Path<String>,
    JsonBody(body): JsonBody<AgentRenameBody>,
) -> ApiResult<Json<AgentRenamed>> {
    let new = body.name.as_str();
    let tx = st.store.begin().await?;
    let a = find_agent(&tx, &key, true)
        .await?
        .ok_or_else(unknown_agent)?;
    not_operator(&a)?;
    if a.sandbox_id.is_some() {
        return Err(ApiError::conflict(format!(
            "{} was minted in an agent VM; its name is the broker's",
            a.name
        )));
    }
    if new == "operator" {
        return Err(ApiError::conflict(NOT_OPERATOR_NAME));
    }
    if new == a.name {
        return Ok(Json(AgentRenamed {
            agent: agent_out(&a, None, None),
            previous_name: a.name.clone(),
            rules: 0,
            grants: 0,
        }));
    }
    if agents::by_name(&tx, new).await?.is_some() {
        return Err(ApiError::conflict(format!("agent '{new}' already exists")));
    }
    // The agent's row before its grants (the store's lock order: every
    // a2a send share-locks both agents, then the talk grant).
    agents::rename(&tx, a.id, new).await?;
    let renamed = rules::rename_agent(&tx, &a.name, new).await?;
    let grants_n = grants::rename_a2a_target(&tx, &a.name, new).await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    tracing::info!(from = %a.name, to = %new, "agent renamed");
    Ok(Json(AgentRenamed {
        agent: agent_out(&row, None, None),
        previous_name: a.name.clone(),
        rules: renamed
            .agent_pattern
            .saturating_add(renamed.delegator_pattern)
            .saturating_add(renamed.a2a_resource_pattern),
        grants: grants_n,
    }))
}

async fn by_id(tx: &Tx<'_>, id: &str) -> ApiResult<AgentRow> {
    find_agent(tx, id, false).await?.ok_or_else(unknown_agent)
}

async fn rotate_key(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<AgentOut>> {
    let key = api_key::generate().map_err(|_| random_failed())?;
    let tx = st.store.begin().await?;
    let a = by_id(&tx, &id).await?;
    not_operator(&a)?;
    // Its key lives in its agent VM: a key handed to the admin would strand
    // the VM's copy (sandboxd B-10).
    if a.sandbox_id.is_some() {
        return Err(ApiError::conflict(format!(
            "{} was minted in an agent VM; its key is its sandbox's (disable it and mint it again)",
            a.name
        )));
    }
    agents::set_key(&tx, a.id, key.key_id.as_str(), key.hash.as_str()).await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    Ok(Json(agent_out(
        &row,
        Some(key.full_key.expose().clone()),
        None,
    )))
}

async fn rotate_webhook_secret(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let secret = crate::random::token_urlsafe(32).map_err(|_| random_failed())?;
    let tx = st.store.begin().await?;
    let a = by_id(&tx, &id).await?;
    not_operator(&a)?;
    if a.kind != AgentKind::Service {
        return Err(ApiError::conflict(
            "only a service agent has a webhook secret",
        ));
    }
    agents::set_webhook_secret(&tx, a.id, &secret).await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    without_nulls(&agent_out(&row, None, Some(secret)))
}

async fn rotate_lldap_password(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let platform = agent_auth_core::Platform::Homelab;
    let Some(AnyProvisioner::Homelab(lldap)) = st.registry.get(platform) else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            not_enabled(platform),
        ));
    };
    let tx = st.store.begin().await?;
    let a = by_id(&tx, &id).await?;
    not_operator(&a)?;
    lldap
        .rotate_password(&tx, a.id)
        .await
        .map_err(|e| ApiError::conflict(e.to_string()))?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    without_nulls(&agent_out(&row, None, None))
}

async fn set_kind(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<SetKindBody>,
) -> ApiResult<Json<Value>> {
    let kind = match body.kind {
        SettableKind::Service => AgentKind::Service,
        SettableKind::Ephemeral => AgentKind::Ephemeral,
    };
    let tx = st.store.begin().await?;
    let a = by_id(&tx, &id).await?;
    not_operator(&a)?;
    agents::set_kind(&tx, a.id, kind).await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    let demoted = a.kind == AgentKind::Service && kind == AgentKind::Ephemeral;
    let targeting = if demoted {
        grants::active_a2a_targeting(&tx, &a.name).await?
    } else {
        Vec::new()
    };
    tx.commit().await?;
    tracing::info!(agent = %a.name, kind = kind.as_str(), "agent kind set");
    if demoted {
        // It can no longer receive threads.
        crate::a2a::orphan_inbound(&st, a.id).await?;
    }
    let reason = format!("target '{}' reclassified ephemeral", a.name);
    for g in targeting {
        match service::revoke_grant(&st, g, &reason, "admin").await {
            Ok(_) | Err(ServiceError::Transition(_)) => {}
            Err(e) => {
                tracing::error!(grant = %g, error = %e, "revoking a grant to a demoted agent failed")
            }
        }
    }
    without_nulls(&agent_out(&row, None, None))
}

async fn set_webhook(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<SetWebhookBody>,
) -> ApiResult<Json<Value>> {
    if let Some(url) = &body.webhook_url {
        check_webhook(&st, url.as_str())?;
    }
    let secret = match &body.webhook_url {
        Some(_) => Some(crate::random::token_urlsafe(32).map_err(|_| random_failed())?),
        None => None,
    };
    let tx = st.store.begin().await?;
    let a = by_id(&tx, &id).await?;
    not_operator(&a)?;
    if a.kind != AgentKind::Service && body.webhook_url.is_some() {
        return Err(ApiError::conflict(
            "only a service agent takes a webhook (an ephemeral agent receives nothing)",
        ));
    }
    agents::set_webhook(
        &tx,
        a.id,
        body.webhook_url.as_ref().map(|u| u.as_str()),
        secret.as_deref(),
    )
    .await?;
    let row = agents::get(&tx, a.id).await?.ok_or_else(unknown_agent)?;
    tx.commit().await?;
    without_nulls(&agent_out(&row, None, secret))
}

/// Re-enable an agent (and only it): the reason it was disabled is
/// cleared. A VM agent gets a new key for its sandbox in the same
/// transaction, so the key it had when it was disabled never works again.
async fn enable(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<agent_auth_wire::admin::Enabled>> {
    let tx = st.store.begin().await?;
    let a = find_agent(&tx, &id, false)
        .await?
        .ok_or_else(|| ApiError::not_found("agent not found"))?;
    not_operator(&a)?;
    let sandbox = match (&a.sandbox_id, &st.sandboxes) {
        (None, _) => None,
        (Some(_), Some(s)) => s
            .rekey_enabled(&tx, &a, st.now())
            .await
            .map_err(|e| ApiError::conflict(format!("{}: {e}", a.name)))?,
        (Some(_), None) => {
            return Err(ApiError::conflict(format!(
                "{} runs in an agent VM and the daemon channel is off: it can't get a new key",
                a.name
            )));
        }
    };
    agent_auth_store::agents::set_disabled(&tx, a.id, false).await?;
    tx.commit().await?;
    if let (Some(d), Some(s)) = (sandbox, &st.sandboxes) {
        s.nudge(d);
    }
    Ok(Json(agent_auth_wire::admin::Enabled {
        enabled: a.name,
        key_rotated: sandbox.is_some(),
    }))
}

async fn disable(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<Disabled>> {
    let tx = st.store.begin().await?;
    let a = find_agent(&tx, &id, false)
        .await?
        .ok_or_else(|| ApiError::not_found("agent not found"))?;
    // The operator's row is the panel's own (http-api §8.13).
    not_operator(&a)?;
    let names = sandboxes::disable_tree(
        &tx,
        a.id,
        st.now(),
        agent_auth_store::agents::DisableReason::Operator,
    )
    .await?;
    tx.commit().await?;
    crate::scheduler::after_disable(&st, &names).await;
    Ok(Json(Disabled { disabled: names }))
}

fn rule_out(r: &RuleRow) -> RuleOut {
    RuleOut {
        id: r.id,
        action: match r.action {
            rules::RuleAction::AutoApprove => RuleAction::AutoApprove,
            rules::RuleAction::AutoDeny => RuleAction::AutoDeny,
        },
        agent_pattern: r.agent_pattern.clone(),
        delegator_pattern: r.delegator_pattern.clone(),
        platform: r.platform,
        capability_pattern: r
            .authority
            .as_ref()
            .map_or_else(|| "*".to_owned(), agent_auth_core::Authority::label),
        resource_pattern: r.resource_pattern.clone(),
        authority: r.authority.as_ref().and_then(|a| match a.to_json() {
            Value::Object(m) => Some(m),
            _ => None,
        }),
        max_duration_secs: r.max_duration_secs,
        enabled: r.enabled,
        created_by: r.created_by.clone(),
        notes: r.notes.clone(),
    }
}

async fn list_rules(
    State(st): State<AppState>,
    _admin: AdminCaller,
) -> ApiResult<Json<Vec<RuleOut>>> {
    let tx = st.store.begin().await?;
    Ok(Json(rules::list(&tx).await?.iter().map(rule_out).collect()))
}

async fn delete_rule(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<agent_auth_wire::common::Ok>> {
    let unknown = || ApiError::not_found("unknown rule");
    let id: RuleId = id.parse().map_err(|_| unknown())?;
    let tx = st.store.begin().await?;
    if !rules::delete(&tx, id).await? {
        return Err(unknown());
    }
    tx.commit().await?;
    Ok(Json(agent_auth_wire::common::Ok::default()))
}

async fn list_requests(
    State(st): State<AppState>,
    _admin: AdminCaller,
    uri: Uri,
) -> ApiResult<Json<Vec<RequestOut>>> {
    let params = query_params(&uri);
    let limit = match params.get("limit") {
        None => 100,
        Some(l) => l
            .trim()
            .parse::<i64>()
            .map_err(|_| ApiError::unprocessable("limit: an integer"))?,
    };
    let tx = st.store.begin().await?;
    let rows = requests::recent(&tx, i64::from(clamp_limit(limit, 500))).await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(request_out(&tx, r).await?);
    }
    Ok(Json(out))
}

/// `POST /admin/requests/{id}/decide`. A bad body is a 422 with a string
/// detail (`invalid duration 'x': ...`).
async fn decide(
    State(st): State<AppState>,
    admin: AdminCaller,
    Path(id): Path<String>,
    bytes: Bytes,
) -> ApiResult<Json<RequestOut>> {
    let body: DecideBody = parse_body(&bytes).map_err(|e| ApiError::unprocessable(e.message()))?;
    let id: RequestId = id
        .parse()
        .map_err(|_| ApiError::conflict("unknown request"))?;
    let decider = HumanDecider::from(&admin);
    let decision = HumanDecision {
        approve: body.approve,
        reason: body.reason.into_string(),
        duration_secs: body.duration.map(|d| d.get()),
        resource_override: body.resource_override.map(|r| r.into_string()),
        scope_override: body.scope_override.map(|s| s.into_map()),
        rule: None,
        totp: body.totp.map(|t| t.into_inner()),
    };
    let row = service::decide(&st, id, &decider, decision).await?;
    let tx = st.store.begin().await?;
    Ok(Json(request_out(&tx, &row).await?))
}

async fn revoke(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
    uri: Uri,
) -> ApiResult<Json<Revoked>> {
    let params = query_params(&uri);
    let reason = params
        .get("reason")
        .cloned()
        .unwrap_or_else(|| "revoked by admin".to_owned());
    let grant_id: GrantId = id
        .parse()
        .map_err(|_| ApiError::conflict("grant is not active"))?;
    service::revoke_grant(&st, grant_id, &reason, "admin").await?;
    Ok(Json(Revoked {
        ok: True,
        grant_id,
        status: GrantStatus::Revoked,
    }))
}

async fn projects(State(st): State<AppState>, _admin: AdminCaller) -> ApiResult<Json<Projects>> {
    let tx = st.store.begin().await?;
    let mut out: BTreeMap<String, ProjectOut> = st
        .policy
        .projects()
        .iter()
        .map(|(name, p)| {
            (
                name.as_str().to_owned(),
                ProjectOut {
                    description: p.description.clone(),
                    repos: p.repos.clone(),
                    in_policy: true,
                    agents: Vec::new(),
                },
            )
        })
        .collect();
    for a in agents::list_enabled(&tx).await? {
        let Some(project) = a.project.clone() else {
            continue;
        };
        out.entry(project)
            .or_insert_with(|| ProjectOut {
                description: String::new(),
                repos: Vec::new(),
                in_policy: false,
                agents: Vec::new(),
            })
            .agents
            .push(a.name);
    }
    let wiki = Some(st.policy.wiki().repo.clone()).filter(|r| !r.is_empty());
    Ok(Json(Projects {
        projects: out,
        wiki,
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/agents", post(create_agent).get(list_agents))
        .route("/admin/agents/{id}/attributes", patch(attributes))
        .route("/admin/agents/{id}/rename", post(rename))
        .route("/admin/agents/{id}/rotate-key", post(rotate_key))
        .route(
            "/admin/agents/{id}/rotate-webhook-secret",
            post(rotate_webhook_secret),
        )
        .route(
            "/admin/agents/{id}/rotate-lldap-password",
            post(rotate_lldap_password),
        )
        .route("/admin/agents/{id}/set-kind", post(set_kind))
        .route("/admin/agents/{id}/set-webhook", post(set_webhook))
        .route("/admin/agents/{id}/disable", post(disable))
        .route("/admin/agents/{id}/enable", post(enable))
        .route("/admin/rules", get(list_rules))
        .route("/admin/rules/{id}", delete(delete_rule))
        .route("/admin/requests", get(list_requests))
        .route("/admin/requests/{id}/decide", post(decide))
        .route("/admin/grants/{id}/revoke", post(revoke))
        .route("/admin/projects", get(projects))
}
