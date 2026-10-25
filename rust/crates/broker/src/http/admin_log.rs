//! The operator's read-only logs (http-api §2.7 "Admin logs"): decisions,
//! host commands, the a2a graph and one thread, model spend.

use std::collections::{BTreeMap, HashMap, HashSet};

use agent_auth_core::{AgentId, JobId, Platform, ThreadId};
use agent_auth_store::a2a::{self, ThreadRow};
use agent_auth_store::hostexec::{self, JobRow};
use agent_auth_store::{StoreError, Tx, agents, requests};
use agent_auth_wire::admin_log::{
    A2aGraph, AdminMessage, AdminThread, CommandDetail, CommandItem, DecisionItem,
    DelegatedRequest, GraphEdge, GraphNode, GraphThread,
};
use agent_auth_wire::query::{clamp_limit, decision_source};
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use time::Duration;

use super::query_params;
use super::serialize::{by_name, wire_kind, wire_placement};
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::provisioners::AnyProvisioner;
use crate::state::AppState;

const OUTPUT_TAIL: usize = 20_000;
const PAYLOAD_MAX: usize = 4_000;

pub(crate) async fn names(
    tx: &Tx<'_>,
    ids: impl IntoIterator<Item = AgentId>,
) -> Result<HashMap<AgentId, String>, StoreError> {
    let ids: Vec<AgentId> = ids
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(agents::names(tx, &ids).await?.into_iter().collect())
}

fn name(names: &HashMap<AgentId, String>, id: AgentId) -> String {
    names.get(&id).cloned().unwrap_or_else(|| "?".to_owned())
}

fn int_param(uri: &Uri, key: &str, default: i64) -> ApiResult<i64> {
    match query_params(uri).get(key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| ApiError::unprocessable(format!("{key}: an integer"))),
    }
}

async fn decisions(
    State(st): State<AppState>,
    _admin: AdminCaller,
    uri: Uri,
) -> ApiResult<Json<Vec<DecisionItem>>> {
    let params = query_params(&uri);
    let limit = clamp_limit(int_param(&uri, "limit", 200)?, 1000);
    let source = match params.get("source").filter(|s| !s.is_empty()) {
        Some(s) => Some(decision_source(s).map_err(|e| ApiError::unprocessable(e.message()))?),
        None => None,
    };
    let tx = st.store.begin().await?;
    let agent = match params.get("agent").filter(|s| !s.is_empty()) {
        Some(n) => match agents::by_name(&tx, n).await? {
            Some(a) => Some(a.id),
            None => return Ok(Json(Vec::new())),
        },
        None => None,
    };
    let rows = requests::decisions(&tx, source, agent, i64::from(limit)).await?;
    let mut ids: Vec<AgentId> = Vec::new();
    for r in &rows {
        ids.push(r.agent_id);
        if let Some(d) = r.delegation {
            ids.push(d.delegator_agent_id);
        }
    }
    let names = names(&tx, ids).await?;
    Ok(Json(
        rows.iter()
            .map(|r| DecisionItem {
                id: r.id,
                at: r.created_at,
                decided_at: r.decided_at,
                agent: name(&names, r.agent_id),
                for_: r
                    .delegation
                    .and_then(|d| names.get(&d.delegator_agent_id).cloned()),
                platform: r.platform,
                what: r
                    .authority
                    .as_ref()
                    .map_or_else(|| "*".to_owned(), |a| a.label()),
                resource: r.resource.clone(),
                status: r.status,
                source: r.decision_source,
                by: r.decided_by.clone(),
                reason: r.decision_reason.clone(),
                justification: r.justification.clone(),
                duration_secs: r
                    .approved_duration_secs
                    .unwrap_or(r.requested_duration_secs),
            })
            .collect(),
    ))
}

/// `[<template>] k=v k=v`, or the argv joined with spaces.
pub(crate) fn command_text(spec: &Value) -> String {
    if let Some(t) = spec
        .get("template")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    {
        let params: Vec<String> = spec
            .get("params")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| match v {
                        Value::String(s) => format!("{k}={s}"),
                        other => format!("{k}={other}"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        return format!("[{t}] {}", params.join(" ")).trim().to_owned();
    }
    spec.get("argv")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn command_item(j: &JobRow, names: &HashMap<AgentId, String>) -> ApiResult<CommandItem> {
    Ok(CommandItem {
        id: j.id,
        at: j.created_at,
        agent: name(names, j.agent_id),
        host: j.host.clone(),
        tier: j.tier.into(),
        shell: j.shell_id.is_some(),
        command: command_text(&j.spec),
        cwd: j.spec.get("cwd").and_then(Value::as_str).map(str::to_owned),
        status: by_name(j.status.as_str())
            .ok_or_else(|| ApiError::internal(&format!("job status {}", j.status)))?,
        via: j.via.clone(),
        exit_code: j.exit_code,
        error: j.error.clone(),
        duration_ms: j.duration_ms.and_then(|d| u64::try_from(d).ok()),
        output_bytes: j.output_bytes.map(u64::from),
        request_id: Some(j.request_id),
    })
}

async fn commands(
    State(st): State<AppState>,
    _admin: AdminCaller,
    uri: Uri,
) -> ApiResult<Json<Vec<CommandItem>>> {
    let params = query_params(&uri);
    let limit = clamp_limit(int_param(&uri, "limit", 200)?, 1000);
    let host = params.get("host").filter(|h| !h.is_empty()).cloned();
    let tx = st.store.begin().await?;
    let rows = hostexec::recent(&tx, host.as_deref(), i64::from(limit)).await?;
    let names = names(&tx, rows.iter().map(|j| j.agent_id)).await?;
    Ok(Json(
        rows.iter()
            .map(|j| command_item(j, &names))
            .collect::<ApiResult<Vec<_>>>()?,
    ))
}

async fn command(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<CommandDetail>> {
    let unknown = || ApiError::not_found("unknown command");
    let id: JobId = id.parse().map_err(|_| unknown())?;
    let tx = st.store.begin().await?;
    let job = hostexec::get(&tx, id).await?.ok_or_else(unknown)?;
    let names = names(&tx, [job.agent_id]).await?;
    let asked = requests::get(&tx, job.request_id)
        .await?
        .map(|r| r.into_row());
    let output = job.output.clone().unwrap_or_default();
    let n = output.chars().count();
    let tail: String = output.chars().skip(n.saturating_sub(OUTPUT_TAIL)).collect();
    Ok(Json(CommandDetail {
        item: command_item(&job, &names)?,
        justification: asked.as_ref().map(|r| r.justification.clone()),
        decided_by: asked.and_then(|r| r.decided_by),
        output: tail,
        output_cut: n > OUTPUT_TAIL || job.truncated,
        output_sha256: job.output_sha256.clone(),
    }))
}

fn thread_state(t: &ThreadRow) -> ApiResult<agent_auth_wire::a2a::ThreadState> {
    by_name(t.state.as_str()).ok_or_else(|| ApiError::internal(&"thread state"))
}

fn close_reason(t: &ThreadRow) -> Option<agent_auth_wire::a2a::CloseReason> {
    t.close_reason.and_then(|c| by_name(c.as_str()))
}

fn count(map: &HashMap<ThreadId, i64>, id: ThreadId) -> u32 {
    map.get(&id)
        .map_or(0, |n| u32::try_from(*n).unwrap_or(u32::MAX))
}

async fn a2a_graph(
    State(st): State<AppState>,
    _admin: AdminCaller,
    uri: Uri,
) -> ApiResult<Json<A2aGraph>> {
    let hours = int_param(&uri, "hours", 24)?.clamp(1, 24 * 30);
    let now = st.now();
    let since = now.saturating_sub(Duration::hours(hours));
    let tx = st.store.begin().await?;
    let threads = a2a::active_since(&tx, since).await?;
    let ids: Vec<ThreadId> = threads.iter().map(|t| t.id).collect();
    let counts: HashMap<ThreadId, i64> =
        a2a::message_counts(&tx, &ids).await?.into_iter().collect();
    let delegated: HashMap<ThreadId, i64> = requests::count_by_delegation_threads(&tx, &ids)
        .await?
        .into_iter()
        .collect();
    let enabled = agents::list_enabled(&tx).await?;
    let by_id: HashMap<AgentId, &agents::AgentRow> = enabled.iter().map(|a| (a.id, a)).collect();
    let threshold = st.a2a.config.liveness_threshold;
    let alive: HashSet<AgentId> = enabled
        .iter()
        .filter(|a| {
            a.last_seen_at
                .is_some_and(|s| s >= now.saturating_sub(threshold))
        })
        .map(|a| a.id)
        .collect();
    let mut edges: BTreeMap<(String, String), GraphEdge> = BTreeMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    let mut out_threads = Vec::new();
    let mut talked: HashSet<AgentId> = HashSet::new();
    for t in &threads {
        let (Some(a), Some(b)) = (
            by_id.get(&t.initiator_agent_id),
            by_id.get(&t.responder_agent_id),
        ) else {
            continue;
        };
        talked.insert(a.id);
        talked.insert(b.id);
        let state = thread_state(t)?;
        let live = matches!(
            state,
            agent_auth_wire::a2a::ThreadState::Open
                | agent_auth_wire::a2a::ThreadState::PendingOpen
        );
        let key = (a.name.clone(), b.name.clone());
        let edge = edges.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            GraphEdge {
                from: a.name.clone(),
                to: b.name.clone(),
                threads: 0,
                open: 0,
                messages: 0,
                requests: 0,
                last: t.last_activity_at,
            }
        });
        edge.threads = edge.threads.saturating_add(1);
        edge.open = edge.open.saturating_add(u32::from(live));
        edge.messages = edge.messages.saturating_add(count(&counts, t.id));
        edge.requests = edge.requests.saturating_add(count(&delegated, t.id));
        edge.last = edge.last.max(t.last_activity_at);
        out_threads.push(GraphThread {
            id: t.id,
            from: a.name.clone(),
            to: b.name.clone(),
            topic: t.topic.clone(),
            state,
            close_reason: close_reason(t),
            messages: count(&counts, t.id),
            requests: count(&delegated, t.id),
            opened: t.created_at,
            last: t.last_activity_at,
        });
    }
    let nodes = enabled
        .iter()
        .filter(|a| talked.contains(&a.id) || alive.contains(&a.id))
        .map(|a| GraphNode {
            name: a.name.clone(),
            runtime: a.runtime.clone(),
            project: a.project.clone(),
            host: a.host.clone(),
            placement: wire_placement(a.placement),
            kind: wire_kind(a.kind),
            alive: alive.contains(&a.id),
        })
        .collect();
    let edges = order.iter().filter_map(|k| edges.remove(k)).collect();
    Ok(Json(A2aGraph {
        hours: u32::try_from(hours).unwrap_or(24),
        now,
        nodes,
        edges,
        threads: out_threads,
    }))
}

fn payload_text(payload: &str) -> (Option<Value>, String, bool) {
    let parsed: Value = serde_json::from_str(payload).unwrap_or(Value::Null);
    let kind = parsed.get("type").cloned();
    let text = match parsed.get("text") {
        Some(Value::String(s)) => s.clone(),
        _ => crate::llm::dumps_indent(&parsed, 1),
    };
    let cut = text.chars().count() > PAYLOAD_MAX;
    (kind, text.chars().take(PAYLOAD_MAX).collect(), cut)
}

async fn a2a_thread(
    State(st): State<AppState>,
    _admin: AdminCaller,
    Path(id): Path<String>,
) -> ApiResult<Json<AdminThread>> {
    let unknown = || ApiError::not_found("unknown thread");
    let id: ThreadId = id.parse().map_err(|_| unknown())?;
    let tx = st.store.begin().await?;
    let t = a2a::get(&tx, id).await?.ok_or_else(unknown)?;
    let messages = a2a::messages_after(&tx, id, 0).await?;
    let delegated = requests::by_delegation_thread(&tx, id).await?;
    let names = names(&tx, [t.initiator_agent_id, t.responder_agent_id]).await?;
    Ok(Json(AdminThread {
        id: t.id,
        from: name(&names, t.initiator_agent_id),
        to: name(&names, t.responder_agent_id),
        topic: t.topic.clone(),
        state: thread_state(&t)?,
        close_reason: close_reason(&t),
        opened: t.created_at,
        messages: messages
            .iter()
            .map(|m| {
                let (kind, text, cut) = payload_text(&m.message.payload);
                AdminMessage {
                    seq: u64::from(m.message.seq),
                    at: m.message.created_at,
                    from: m.sender_name.clone(),
                    kind,
                    text,
                    cut,
                }
            })
            .collect(),
        requests: delegated
            .iter()
            .map(|r| DelegatedRequest {
                platform: r.platform,
                what: r
                    .authority
                    .as_ref()
                    .map_or_else(|| "*".to_owned(), |a| a.label()),
                resource: r.resource.clone(),
                status: r.status,
                source: r.decision_source,
            })
            .collect(),
    }))
}

/// What each agent has spent at the model gateway, by the gateway's own
/// count (list prices). Only agents that ever held a models grant.
async fn models_usage(State(st): State<AppState>, _admin: AdminCaller) -> ApiResult<Json<Value>> {
    let Some(AnyProvisioner::Models(gateway)) = st.registry.get(Platform::Models) else {
        return Ok(Json(json!({"enabled": false, "agents": []})));
    };
    let url = st.policy.platforms().models.url.clone();
    let (by_name, names) = {
        let tx = st.store.begin().await?;
        let all = agents::list(&tx).await?;
        let holders: HashSet<AgentId> =
            agent_auth_store::grants::agents_with(&tx, Platform::Models)
                .await?
                .into_iter()
                .collect();
        let mut names: Vec<String> = all
            .iter()
            .filter(|a| holders.contains(&a.id))
            .map(|a| a.name.clone())
            .collect();
        names.sort();
        let by_name: HashMap<String, agents::AgentRow> =
            all.into_iter().map(|a| (a.name.clone(), a)).collect();
        (by_name, names)
    };
    let users = match gateway.usage(&names).await {
        Ok(u) => u,
        Err(e) => {
            return Ok(Json(json!({
                "enabled": true, "gateway": url, "error": e.to_string(), "agents": []
            })));
        }
    };
    let mut rows: Vec<Value> = Vec::new();
    for u in users {
        let Some(agent) = u
            .get("user_id")
            .and_then(Value::as_str)
            .and_then(|n| by_name.get(n))
        else {
            continue; // the gateway's other users are not ours to show
        };
        rows.push(json!({
            "agent": agent.name,
            "runtime": agent.runtime,
            "project": agent.project,
            "host": agent.host,
            "placement": agent.placement.as_str(),
            "spend": u.get("spend").and_then(Value::as_f64).unwrap_or(0.0),
            "max_budget": u.get("max_budget").cloned().unwrap_or(Value::Null),
        }));
    }
    rows.sort_by(|a, b| {
        let s = |v: &Value| v.get("spend").and_then(Value::as_f64).unwrap_or(0.0);
        s(b).total_cmp(&s(a))
    });
    Ok(Json(
        json!({"enabled": true, "gateway": url, "agents": rows}),
    ))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/log/decisions", get(decisions))
        .route("/admin/log/commands", get(commands))
        .route("/admin/log/commands/{id}", get(command))
        .route("/admin/a2a/graph", get(a2a_graph))
        .route("/admin/a2a/threads/{id}", get(a2a_thread))
        .route("/admin/models/usage", get(models_usage))
}
