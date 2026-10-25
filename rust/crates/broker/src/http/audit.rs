//! `GET /v1/audit/events` (http-api §2.3): the broker's record, oldest
//! first, for the agents `audit.readers` names. To every other agent the
//! route does not exist: membership is checked before any parameter is
//! read (§8.3).

use std::collections::{BTreeMap, HashMap};

use agent_auth_store::a2a::ThreadRow;
use agent_auth_store::grants::GrantRow;
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::{a2a, agents, grants, hostexec, lockdown, requests};
use agent_auth_wire::audit::{
    A2aClosed, A2aOpened, AgentCreated, AuditEvent, AuditPage, ContainmentStanding, Created,
    GrantEnded, GrantIssued, HostJobEvent, JobPhase, RequestEvent, SecurityEvent, Standing,
};
use agent_auth_wire::timestamp::parse_query;
use axum::extract::State;
use axum::http::Uri;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::admin_log::{command_text, names};
use super::query_params;
use super::serialize::{by_name, cut, wire_kind, wire_placement};
use crate::auth::AgentCaller;
use crate::error::{ApiError, ApiResult};
use crate::service::agent_ref_of;
use crate::state::AppState;

const TEXT_MAX: usize = 2000;

fn at(e: &AuditEvent) -> OffsetDateTime {
    match e {
        AuditEvent::Request(x) => x.at,
        AuditEvent::GrantIssued(x) => x.at,
        AuditEvent::GrantEnded(x) => x.at,
        AuditEvent::HostJob(x) => x.at,
        AuditEvent::A2aOpened(x) => x.at,
        AuditEvent::A2aClosed(x) => x.at,
        AuditEvent::AgentCreated(x) => x.at,
        AuditEvent::Containment(x) => x.at,
        AuditEvent::BadKey(x)
        | AuditEvent::BadAdminToken(x)
        | AuditEvent::CredentialRefused(x)
        | AuditEvent::ContainmentLifted(x) => x.at,
    }
}

fn dedupe<T, K: Ord>(a: Vec<T>, b: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut map = BTreeMap::new();
    for item in a.into_iter().chain(b) {
        map.entry(key(&item)).or_insert(item);
    }
    map.into_values().collect()
}

async fn events(
    State(st): State<AppState>,
    caller: AgentCaller,
    uri: Uri,
) -> ApiResult<Json<AuditPage>> {
    let me = agent_ref_of(caller.agent());
    if !st.policy.audit().readers.iter().any(|p| p.matches(&me)) {
        return Err(ApiError::not_found("Not Found"));
    }
    let params = query_params(&uri);
    let limit: usize = match params.get("limit") {
        None => 500,
        Some(l) => l
            .trim()
            .parse::<i64>()
            .map_err(|_| ApiError::unprocessable("limit: an integer"))?
            .clamp(1, 2000)
            .try_into()
            .unwrap_or(500),
    };
    let now = st.now();
    let start = match params.get("since") {
        None => now.saturating_sub(Duration::hours(1)),
        Some(s) => {
            parse_query(s).map_err(|_| ApiError::unprocessable("since: an ISO 8601 time"))?
        }
    };
    let lim = i64::try_from(limit).unwrap_or(500);
    let tx = st.store.begin().await?;
    let reqs = requests::updated_since(&tx, start, lim).await?;
    let grants: Vec<GrantRow> = dedupe(
        grants::granted_since(&tx, start, lim).await?,
        grants::ended_since(&tx, start, lim).await?,
        |g| g.id,
    );
    let started = hostexec::created_since(&tx, start, lim).await?;
    let finished = hostexec::finished_since(&tx, start, lim).await?;
    let jobs: Vec<JobRow> = dedupe(started, finished, |j| j.id);
    let threads: Vec<ThreadRow> = dedupe(
        a2a::created_since(&tx, start, lim).await?,
        a2a::closed_since(&tx, start, lim).await?,
        |t| t.id,
    );
    let created = agents::created_since(&tx, start, lim).await?;
    let held = lockdown::entries(&tx).await?;
    let mut ids = Vec::new();
    for r in &reqs {
        ids.push(r.agent_id);
        if let Some(d) = r.delegation {
            ids.push(d.delegator_agent_id);
        }
    }
    ids.extend(grants.iter().map(|g| g.agent_id));
    ids.extend(jobs.iter().map(|j| j.agent_id));
    for t in &threads {
        ids.push(t.initiator_agent_id);
        ids.push(t.responder_agent_id);
    }
    ids.extend(created.iter().filter_map(|a| a.parent_agent_id));
    let names: HashMap<_, _> = names(&tx, ids).await?;
    drop(tx);
    let name = |id| names.get(&id).cloned().unwrap_or_else(|| "?".to_owned());
    let what =
        |a: Option<&agent_auth_core::Authority>| a.map_or_else(|| "*".to_owned(), |a| a.label());

    let mut out = Vec::new();
    for r in &reqs {
        out.push(AuditEvent::Request(RequestEvent {
            id: r.id,
            at: r.updated_at,
            created_at: r.created_at,
            agent: name(r.agent_id),
            for_: r
                .delegation
                .and_then(|d| names.get(&d.delegator_agent_id).cloned()),
            platform: r.platform,
            what: what(r.authority.as_ref()),
            resource: r.resource.clone(),
            status: r.status,
            source: r.decision_source,
            by: r.decided_by.clone(),
            reason: r.decision_reason.as_deref().map(|t| cut(t, TEXT_MAX)),
            justification: cut(&r.justification, TEXT_MAX),
            risk_notes: r.risk_notes.clone(),
            duration_secs: r
                .approved_duration_secs
                .unwrap_or(r.requested_duration_secs),
        }));
    }
    for g in &grants {
        if g.granted_at >= start {
            out.push(AuditEvent::GrantIssued(GrantIssued {
                at: g.granted_at,
                status: agent_auth_core::GrantStatus::Active,
                expires_at: g.expires_at,
                id: g.id,
                agent: name(g.agent_id),
                platform: g.platform,
                what: g.authority.label(),
                resource: g.resource.clone(),
                request_id: g.request_id,
            }));
        }
        if let Some(ended) = g.revoked_at.filter(|r| *r >= start) {
            out.push(AuditEvent::GrantEnded(GrantEnded {
                at: ended,
                status: g.status,
                reason: g.revoke_reason.as_deref().map(|t| cut(t, TEXT_MAX)),
                id: g.id,
                agent: name(g.agent_id),
                platform: g.platform,
                what: g.authority.label(),
                resource: g.resource.clone(),
                request_id: g.request_id,
            }));
        }
    }
    for j in &jobs {
        let base = |at, status, exit_code, error| HostJobEvent {
            at,
            status,
            id: j.id,
            created_at: j.created_at,
            agent: name(j.agent_id),
            host: j.host.clone(),
            tier: j.tier.into(),
            shell: j.shell_id.is_some(),
            command: cut(&command_text(&j.spec), TEXT_MAX),
            cwd: j.spec.get("cwd").and_then(Value::as_str).map(str::to_owned),
            via: j.via.clone(),
            exit_code,
            error,
        };
        if j.created_at >= start {
            out.push(AuditEvent::HostJob(base(
                j.created_at,
                JobPhase::Started,
                None,
                None,
            )));
        }
        if let Some(done) = j.finished_at.filter(|f| *f >= start)
            && let Some(phase) = by_name::<JobPhase>(j.status.as_str())
        {
            out.push(AuditEvent::HostJob(base(
                done,
                phase,
                j.exit_code,
                j.error.as_deref().map(|t| cut(t, TEXT_MAX)),
            )));
        }
    }
    for t in &threads {
        if t.created_at >= start {
            out.push(AuditEvent::A2aOpened(A2aOpened {
                at: t.created_at,
                status: agent_auth_wire::a2a::ThreadState::Open,
                id: t.id,
                from: name(t.initiator_agent_id),
                to: name(t.responder_agent_id),
                topic: t.topic.clone(),
                operator: t.grant_id.is_none(),
            }));
        }
        if let Some(closed) = t.closed_at.filter(|c| *c >= start) {
            out.push(AuditEvent::A2aClosed(A2aClosed {
                at: closed,
                status: agent_auth_wire::a2a::ThreadState::Closed,
                reason: t.close_reason.and_then(|c| by_name(c.as_str())),
                id: t.id,
                from: name(t.initiator_agent_id),
                to: name(t.responder_agent_id),
                topic: t.topic.clone(),
                operator: t.grant_id.is_none(),
            }));
        }
    }
    for a in &created {
        out.push(AuditEvent::AgentCreated(AgentCreated {
            id: a.id,
            at: a.created_at,
            status: Created,
            agent: a.name.clone(),
            agent_kind: wire_kind(a.kind),
            runtime: a.runtime.clone(),
            project: a.project.clone(),
            host: a.host.clone(),
            placement: wire_placement(a.placement),
            parent: a.parent_agent_id.and_then(|p| names.get(&p).cloned()),
        }));
    }
    for e in held.iter().filter(|e| e.at >= start) {
        out.push(AuditEvent::Containment(ContainmentStanding {
            id: e.id.clone(),
            at: e.at,
            status: Standing,
            matches: match &e.r#match {
                Value::Object(m) => m.clone(),
                _ => Map::new(),
            },
            reason: e.reason.clone(),
            by: e.by.clone(),
            source: e.source.as_str().to_owned(),
        }));
    }
    for e in st.security_log.since(start, limit) {
        let mut fields: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut client = None;
        let mut path = None;
        for (k, v) in e.fields {
            let v = v.as_str().map(str::to_owned);
            match k.as_str() {
                "client" => client = v,
                "path" => path = v,
                _ => {
                    fields.insert(k, v);
                }
            }
        }
        let item = SecurityEvent {
            id: e.id,
            at: e.at,
            client,
            path,
            fields,
        };
        out.push(match e.kind.as_str() {
            "security.bad_key" => AuditEvent::BadKey(item),
            "security.bad_admin_token" => AuditEvent::BadAdminToken(item),
            "security.credential_refused" => AuditEvent::CredentialRefused(item),
            "security.containment_lifted" => AuditEvent::ContainmentLifted(item),
            _ => continue,
        });
    }
    out.sort_by_key(at);
    out.truncate(limit);
    let next = out.last().map_or(start, at);
    let truncated = out.len() == limit;
    Ok(Json(AuditPage {
        events: out,
        next,
        truncated,
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/audit/events", get(events))
}
