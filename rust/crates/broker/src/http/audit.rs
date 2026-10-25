//! `GET /v1/audit/events` (http-api §2.3): the broker's record, oldest
//! first, for the agents `audit.readers` names. To every other agent the
//! route does not exist: membership is checked before any parameter is
//! read (§8.3).
//!
//! Paging: `since` and `next` are inclusive times (the Python's), which
//! cannot page through more than `limit` items sharing one time: the next
//! page starts at the same time and returns the same items. So each page
//! also carries `cursor`, the exact position of its last item (time, kind,
//! id), and `?after=<cursor>` returns what comes strictly after it: every
//! source is read keyset-paginated on (time, id), and a reader passing
//! `cursor` back always advances.

use std::collections::{BTreeMap, HashMap};

use uuid::Uuid;

use agent_auth_store::a2a::ThreadRow;
use agent_auth_store::grants::GrantRow;
use agent_auth_store::hostexec::JobRow;
use agent_auth_store::{a2a, agents, grants, hostexec, lockdown, requests};
use agent_auth_wire::audit::{
    A2aClosed, A2aOpened, AgentCreated, AuditEvent, AuditPage, ContainmentStanding, Created,
    GrantEnded, GrantIssued, HostJobEvent, JobPhase, RequestEvent, SecurityEvent, Standing,
};
use agent_auth_wire::timestamp::{parse_query, truncate_to_micros};
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

/// An item's identity within its time and kind: `None` sorts before every
/// item (a cursor that has seen nothing at its time).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum IdKey {
    None,
    Uuid(Uuid),
    Text(String),
    Seq(u64),
}

/// Where an item sits in the feed: by time, then by source (the ranks
/// below), then by id. Unique per item, so a cursor is exact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Position {
    at: OffsetDateTime,
    rank: u8,
    id: IdKey,
}

const REQUEST: u8 = 1;
const GRANT_ISSUED: u8 = 2;
const GRANT_ENDED: u8 = 3;
const JOB_STARTED: u8 = 4;
const JOB_FINISHED: u8 = 5;
const A2A_OPENED: u8 = 6;
const A2A_CLOSED: u8 = 7;
const AGENT_CREATED: u8 = 8;
const CONTAINMENT: u8 = 9;
const SECURITY: u8 = 10;
const CURSOR_MAX: usize = 256;

impl Position {
    fn uuid(at: OffsetDateTime, rank: u8, id: impl Into<Uuid>) -> Position {
        Position {
            at,
            rank,
            id: IdKey::Uuid(id.into()),
        }
    }

    /// `<time>~<rank>~<id>`.
    fn encode(&self) -> Result<String, ApiError> {
        let at = agent_auth_wire::timestamp::format(self.at)
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        let id = match &self.id {
            IdKey::None => String::new(),
            IdKey::Uuid(u) => u.to_string(),
            IdKey::Text(t) => t.clone(),
            IdKey::Seq(n) => n.to_string(),
        };
        Ok(format!("{at}~{}~{id}", self.rank))
    }

    fn decode(text: &str) -> Option<Position> {
        if text.len() > CURSOR_MAX {
            return None;
        }
        let mut parts = text.splitn(3, '~');
        let at = agent_auth_wire::timestamp::parse(parts.next()?).ok()?;
        let rank: u8 = parts.next()?.parse().ok()?;
        let id = parts.next()?;
        let id = match rank {
            0 if id.is_empty() => IdKey::None,
            REQUEST..=AGENT_CREATED => IdKey::Uuid(id.parse().ok()?),
            CONTAINMENT if !id.is_empty() => IdKey::Text(id.to_owned()),
            SECURITY => IdKey::Seq(id.parse().ok()?),
            _ => return None,
        };
        Some(Position { at, rank, id })
    }

    /// For a source of `rank` read from the store at `self.at`: the id past
    /// which rows at exactly that time count (`None`: all of them).
    fn after_for(&self, rank: u8) -> Option<Uuid> {
        match self.rank.cmp(&rank) {
            // This source's items at the cursor's time all came before it.
            std::cmp::Ordering::Greater => Some(Uuid::from_u128(u128::MAX)),
            std::cmp::Ordering::Equal => match self.id {
                IdKey::Uuid(u) => Some(u),
                _ => Some(Uuid::from_u128(u128::MAX)),
            },
            std::cmp::Ordering::Less => None,
        }
    }
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
    let cursor = match params.get("after") {
        Some(c) => Position::decode(c.trim())
            .ok_or_else(|| ApiError::unprocessable("after: a cursor from a previous page"))?,
        None => Position {
            at: match params.get("since") {
                None => truncate_to_micros(now.saturating_sub(Duration::hours(1))),
                Some(s) => parse_query(s)
                    .map_err(|_| ApiError::unprocessable("since: an ISO 8601 time"))?,
            },
            rank: 0,
            id: IdKey::None,
        },
    };
    let start = cursor.at;
    let lim = i64::try_from(limit).unwrap_or(500);
    let tx = st.store.begin().await?;
    let reqs = requests::updated_since(&tx, start, cursor.after_for(REQUEST), lim).await?;
    let issued: Vec<GrantRow> =
        grants::granted_since(&tx, start, cursor.after_for(GRANT_ISSUED), lim).await?;
    let ended: Vec<GrantRow> =
        grants::ended_since(&tx, start, cursor.after_for(GRANT_ENDED), lim).await?;
    let started: Vec<JobRow> =
        hostexec::created_since(&tx, start, cursor.after_for(JOB_STARTED), lim).await?;
    let finished: Vec<JobRow> =
        hostexec::finished_since(&tx, start, cursor.after_for(JOB_FINISHED), lim).await?;
    let opened: Vec<ThreadRow> =
        a2a::created_since(&tx, start, cursor.after_for(A2A_OPENED), lim).await?;
    let closed: Vec<ThreadRow> =
        a2a::closed_since(&tx, start, cursor.after_for(A2A_CLOSED), lim).await?;
    let created = agents::created_since(&tx, start, cursor.after_for(AGENT_CREATED), lim).await?;
    let held = lockdown::entries(&tx).await?;
    let mut ids = Vec::new();
    for r in &reqs {
        ids.push(r.agent_id);
        if let Some(d) = r.delegation {
            ids.push(d.delegator_agent_id);
        }
    }
    ids.extend(issued.iter().chain(&ended).map(|g| g.agent_id));
    ids.extend(started.iter().chain(&finished).map(|j| j.agent_id));
    for t in opened.iter().chain(&closed) {
        ids.push(t.initiator_agent_id);
        ids.push(t.responder_agent_id);
    }
    ids.extend(created.iter().filter_map(|a| a.parent_agent_id));
    let names: HashMap<_, _> = names(&tx, ids).await?;
    drop(tx);
    let name = |id| names.get(&id).cloned().unwrap_or_else(|| "?".to_owned());
    let what =
        |a: Option<&agent_auth_core::Authority>| a.map_or_else(|| "*".to_owned(), |a| a.label());

    let mut out: Vec<(Position, AuditEvent)> = Vec::new();
    for r in &reqs {
        out.push((
            Position::uuid(r.updated_at, REQUEST, r.id),
            AuditEvent::Request(RequestEvent {
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
            }),
        ));
    }
    for g in &issued {
        {
            out.push((
                Position::uuid(g.granted_at, GRANT_ISSUED, g.id),
                AuditEvent::GrantIssued(GrantIssued {
                    at: g.granted_at,
                    status: agent_auth_core::GrantStatus::Active,
                    expires_at: g.expires_at,
                    id: g.id,
                    agent: name(g.agent_id),
                    platform: g.platform,
                    what: g.authority.label(),
                    resource: g.resource.clone(),
                    request_id: g.request_id,
                }),
            ));
        }
    }
    for g in &ended {
        if let Some(ended) = g.revoked_at {
            out.push((
                Position::uuid(ended, GRANT_ENDED, g.id),
                AuditEvent::GrantEnded(GrantEnded {
                    at: ended,
                    status: g.status,
                    reason: g.revoke_reason.as_deref().map(|t| cut(t, TEXT_MAX)),
                    id: g.id,
                    agent: name(g.agent_id),
                    platform: g.platform,
                    what: g.authority.label(),
                    resource: g.resource.clone(),
                    request_id: g.request_id,
                }),
            ));
        }
    }
    let job = |j: &JobRow, at, status, exit_code, error| HostJobEvent {
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
    for j in &started {
        out.push((
            Position::uuid(j.created_at, JOB_STARTED, j.id),
            AuditEvent::HostJob(job(j, j.created_at, JobPhase::Started, None, None)),
        ));
    }
    for j in &finished {
        if let Some(done) = j.finished_at
            && let Some(phase) = by_name::<JobPhase>(j.status.as_str())
        {
            out.push((
                Position::uuid(done, JOB_FINISHED, j.id),
                AuditEvent::HostJob(job(
                    j,
                    done,
                    phase,
                    j.exit_code,
                    j.error.as_deref().map(|t| cut(t, TEXT_MAX)),
                )),
            ));
        }
    }
    for t in &opened {
        {
            out.push((
                Position::uuid(t.created_at, A2A_OPENED, t.id),
                AuditEvent::A2aOpened(A2aOpened {
                    at: t.created_at,
                    status: agent_auth_wire::a2a::ThreadState::Open,
                    id: t.id,
                    from: name(t.initiator_agent_id),
                    to: name(t.responder_agent_id),
                    topic: t.topic.clone(),
                    operator: t.grant_id.is_none(),
                }),
            ));
        }
    }
    for t in &closed {
        if let Some(closed) = t.closed_at {
            out.push((
                Position::uuid(closed, A2A_CLOSED, t.id),
                AuditEvent::A2aClosed(A2aClosed {
                    at: closed,
                    status: agent_auth_wire::a2a::ThreadState::Closed,
                    reason: t.close_reason.and_then(|c| by_name(c.as_str())),
                    id: t.id,
                    from: name(t.initiator_agent_id),
                    to: name(t.responder_agent_id),
                    topic: t.topic.clone(),
                    operator: t.grant_id.is_none(),
                }),
            ));
        }
    }
    for a in &created {
        out.push((
            Position::uuid(a.created_at, AGENT_CREATED, a.id),
            AuditEvent::AgentCreated(AgentCreated {
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
            }),
        ));
    }
    for e in &held {
        let position = Position {
            at: e.at,
            rank: CONTAINMENT,
            id: IdKey::Text(e.id.clone()),
        };
        if position <= cursor {
            continue;
        }
        out.push((
            position,
            AuditEvent::Containment(ContainmentStanding {
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
            }),
        ));
    }
    let security_after = match cursor.id {
        IdKey::Seq(n) if cursor.rank == SECURITY => Some(n),
        _ => None,
    };
    for e in st.security_log.since_after(start, security_after, limit) {
        let position = Position {
            at: e.at,
            rank: SECURITY,
            id: IdKey::Seq(e.seq),
        };
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
        out.push((
            position,
            match e.kind.as_str() {
                "security.bad_key" => AuditEvent::BadKey(item),
                "security.bad_admin_token" => AuditEvent::BadAdminToken(item),
                "security.credential_refused" => AuditEvent::CredentialRefused(item),
                "security.containment_lifted" => AuditEvent::ContainmentLifted(item),
                _ => continue,
            },
        ));
    }
    // Every source above is already past the cursor; this keeps it so
    // whatever a source does at the boundary.
    out.retain(|(p, _)| *p > cursor);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.truncate(limit);
    let truncated = out.len() == limit;
    let last = out.last().map_or(&cursor, |(p, _)| p);
    let next = last.at;
    let cursor = last.encode()?;
    Ok(Json(AuditPage {
        events: out.into_iter().map(|(_, e)| e).collect(),
        next,
        cursor,
        truncated,
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/audit/events", get(events))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn cursors_round_trip_and_order() {
        let at = time::macros::datetime!(2026-01-01 00:00:00.000001 UTC);
        for p in [
            Position {
                at,
                rank: 0,
                id: IdKey::None,
            },
            Position::uuid(at, AGENT_CREATED, Uuid::from_u128(7)),
            Position {
                at,
                rank: CONTAINMENT,
                id: IdKey::Text("c~1".to_owned()),
            },
            Position {
                at,
                rank: SECURITY,
                id: IdKey::Seq(12),
            },
        ] {
            assert_eq!(Position::decode(&p.encode().unwrap()), Some(p));
        }
        for bad in [
            "",
            "x",
            "2026-01-01T00:00:00Z~0~x",
            "2026-01-01T00:00:00Z~11~1",
            "2026-01-01T00:00:00Z~1~nope",
            "2026-01-01T00:00:00Z~9~",
        ] {
            assert_eq!(Position::decode(bad), None, "{bad}");
        }
        // Same time: the earlier source first; a store source before the
        // cursor's rank skips that time, at its rank resumes past the id.
        let c = Position::uuid(at, GRANT_ENDED, Uuid::from_u128(5));
        assert_eq!(c.after_for(REQUEST), Some(Uuid::from_u128(u128::MAX)));
        assert_eq!(c.after_for(GRANT_ENDED), Some(Uuid::from_u128(5)));
        assert_eq!(c.after_for(AGENT_CREATED), None);
    }

    proptest! {
        #[test]
        fn decoding_any_text_is_total(s in ".{0,300}") {
            let _ = Position::decode(&s);
        }
    }
}
