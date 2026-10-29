//! `/admin/evals/*`: the recorded model decisions, labels, and replays.
//! Admin only; nothing here changes a decision.

use agent_auth_store::evals::{self, CallRow, Selection};
use agent_auth_wire::evals::{
    CallDetail, CallOut, CallsPage, KindOut, KnobOut, LabelBody, LabelOut, RunCase, RunCreate,
    RunOut,
};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::routing::{get, post, put};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::{Context, Kind, recipe, replay, valid_pattern};
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::http::body::JsonBody;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/evals/kinds", get(kinds))
        .route("/admin/evals/calls", get(calls))
        .route("/admin/evals/calls/{id}", get(call))
        .route("/admin/evals/calls/{id}/label", put(label).delete(unlabel))
        .route("/admin/evals/runs", post(create_run).get(runs))
        .route("/admin/evals/runs/{id}", get(run))
}

fn kind_of(s: &str) -> ApiResult<Kind> {
    Kind::parse(s).ok_or_else(|| {
        let all: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
        ApiError::unprocessable(format!("kind is one of: {}", all.join(", ")))
    })
}

fn time_param(name: &str, v: Option<&String>) -> ApiResult<Option<OffsetDateTime>> {
    v.map(|t| {
        OffsetDateTime::parse(t, &Rfc3339)
            .map_err(|_| ApiError::unprocessable(format!("{name}: an RFC 3339 time")))
    })
    .transpose()
}

fn id_of(s: &str) -> ApiResult<Uuid> {
    s.parse()
        .map_err(|_| ApiError::not_found("no such recorded call"))
}

/// The one-sentence reason in an answer, whatever the kind calls it.
fn summary(answer: Option<&Value>) -> Option<String> {
    let a = answer?;
    ["summary", "reasoning", "reason", "topic_reason"]
        .iter()
        .find_map(|k| a.get(*k).and_then(Value::as_str))
        .map(|s| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(300)
                .collect()
        })
}

fn call_out(c: &CallRow) -> CallOut {
    CallOut {
        id: c.id.to_string(),
        kind: c.kind.clone(),
        model: c.model.clone(),
        class: c.class.clone(),
        error: c.error.clone(),
        latency_ms: c.latency_ms,
        subject: c.subject.clone(),
        label: c.label.as_ref().map(|l| LabelOut {
            expected: l.expected.clone(),
            note: l.note.clone(),
            source: l.source.clone(),
            labeled_by: l.labeled_by.clone(),
            labeled_at: l.labeled_at,
        }),
        created_at: c.created_at,
        summary: summary(c.answer.as_ref()),
    }
}

async fn kinds(_admin: AdminCaller) -> Json<Vec<KindOut>> {
    Json(
        Kind::ALL
            .iter()
            .map(|k| {
                let r = recipe(*k);
                KindOut {
                    kind: k.as_str().to_owned(),
                    classes: r.classes.iter().map(|c| (*c).to_owned()).collect(),
                    knobs: r
                        .knobs
                        .iter()
                        .map(|n| KnobOut {
                            name: n.name.to_owned(),
                            default: n.default,
                            max: n.max,
                            doc: n.doc.to_owned(),
                        })
                        .collect(),
                    system: r.default_system.to_owned(),
                    system_sha256: agent_auth_crypto::digest::sha256_hex(
                        r.default_system.as_bytes(),
                    ),
                }
            })
            .collect(),
    )
}

async fn calls(
    _admin: AdminCaller,
    State(st): State<AppState>,
    uri: Uri,
) -> ApiResult<Json<CallsPage>> {
    let q = crate::http::query_params(&uri);
    let kind = q.get("kind").map(|k| kind_of(k)).transpose()?;
    let labeled = match q.get("labeled").map(String::as_str) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Err(ApiError::unprocessable("labeled: true or false")),
    };
    let before = match q.get("before") {
        None => None,
        Some(cursor) => {
            let (t, id) = cursor
                .split_once('_')
                .ok_or_else(|| ApiError::unprocessable("before: a page's next cursor"))?;
            let t = OffsetDateTime::parse(t, &Rfc3339)
                .map_err(|_| ApiError::unprocessable("before: a page's next cursor"))?;
            let id: Uuid = id
                .parse()
                .map_err(|_| ApiError::unprocessable("before: a page's next cursor"))?;
            Some((t, id))
        }
    };
    let limit: i64 = match q.get("limit") {
        None => 50,
        Some(l) => l
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=200).contains(n))
            .ok_or_else(|| ApiError::unprocessable("limit: 1 to 200"))?,
    };
    let selection = Selection {
        kind: kind.map(|k| k.as_str().to_owned()),
        labeled,
        since: time_param("since", q.get("since"))?,
        until: time_param("until", q.get("until"))?,
        before,
        ids: None,
        limit,
    };
    let tx = st.store.begin().await?;
    let rows = evals::list_calls(&tx, &selection).await?;
    tx.commit().await?;
    // Sealed answers opened for their summaries (left out if they don't).
    let rows: Vec<CallRow> = rows
        .into_iter()
        .map(|c| match &st.models {
            Some(m) => m.opened(c.clone()).unwrap_or(CallRow { answer: None, ..c }),
            None => c,
        })
        .collect();
    let next = (i64::try_from(rows.len()).unwrap_or(0) == limit)
        .then(|| rows.last())
        .flatten()
        .and_then(|c| {
            c.created_at
                .format(&Rfc3339)
                .ok()
                .map(|t| format!("{t}_{}", c.id))
        });
    Ok(Json(CallsPage {
        calls: rows.iter().map(call_out).collect(),
        next,
    }))
}

async fn call(
    _admin: AdminCaller,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<CallDetail>> {
    let id = id_of(&id)?;
    let tx = st.store.begin().await?;
    let c = evals::get_call(&tx, id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such recorded call"))?;
    let system = evals::get_prompt(&tx, &c.system_sha256)
        .await?
        .unwrap_or_default();
    tx.commit().await?;
    // Mail's records are sealed: opened here, for the operator.
    let c = match &st.models {
        Some(m) => m.opened(c).map_err(ApiError::conflict)?,
        None => c,
    };
    Ok(Json(CallDetail {
        call: call_out(&c),
        facts: c.facts.clone(),
        context: c.context.clone(),
        system,
        system_sha256: c.system_sha256.clone(),
        user_message: c.user_message.clone(),
        answer: c.answer.clone(),
    }))
}

async fn label(
    admin: AdminCaller,
    State(st): State<AppState>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody<LabelBody>,
) -> ApiResult<Json<CallOut>> {
    let id = id_of(&id)?;
    let tx = st.store.begin().await?;
    let c = evals::get_call(&tx, id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such recorded call"))?;
    let kind = kind_of(&c.kind)?;
    let expected = body.expected.as_str();
    if !valid_pattern(kind, expected) {
        return Err(ApiError::unprocessable(format!(
            "{expected:?} is not a class of {} (one of: {}; * for any part)",
            kind.as_str(),
            recipe(kind).classes.join(", ")
        )));
    }
    let note = body.note.as_ref().map_or("", |n| n.as_str());
    evals::set_label(
        &tx,
        id,
        expected,
        note,
        "operator",
        &admin.label(),
        st.now(),
    )
    .await?;
    let c = evals::get_call(&tx, id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such recorded call"))?;
    tx.commit().await?;
    Ok(Json(call_out(&c)))
}

async fn unlabel(
    _admin: AdminCaller,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = id_of(&id)?;
    let tx = st.store.begin().await?;
    let removed = evals::delete_label(&tx, id).await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"removed": removed})))
}

async fn create_run(
    admin: AdminCaller,
    State(st): State<AppState>,
    JsonBody(body): JsonBody<RunCreate>,
) -> ApiResult<Json<RunOut>> {
    let Some(client) = st.models.clone() else {
        return Err(ApiError::unavailable(
            "no model gateway (OPENROUTER_API_KEY): nothing to replay with",
        ));
    };
    let kind = kind_of(body.kind.as_str())?;
    let context = Context::checked(kind, &body.context).map_err(ApiError::unprocessable)?;
    let cfg = st.policy.evals();
    let limit = body
        .limit
        .unwrap_or(cfg.max_replay)
        .min(cfg.max_replay)
        .max(1);
    let ids = match &body.call_ids {
        None => None,
        Some(ids) => Some(
            ids.iter()
                .map(|i| {
                    i.as_str()
                        .parse::<Uuid>()
                        .map_err(|_| ApiError::unprocessable("call_ids: recorded calls' ids"))
                })
                .collect::<ApiResult<Vec<Uuid>>>()?,
        ),
    };
    let selection = Selection {
        kind: Some(kind.as_str().to_owned()),
        labeled: body.labeled,
        since: body.since,
        until: body.until,
        before: None,
        ids,
        limit: i64::from(limit),
    };
    let id = replay::start(
        &st.store,
        &client,
        replay::Replay {
            kind,
            model: body.model.as_ref().map(|m| m.as_str().to_owned()),
            system: body.system.as_ref().map(|s| s.as_str().to_owned()),
            context,
            selection,
            note: body
                .note
                .as_ref()
                .map_or_else(String::new, |n| n.as_str().to_owned()),
        },
        cfg.replay_concurrency,
        &admin.label(),
    )
    .await
    .map_err(ApiError::unprocessable)?;
    run_out(&st, id, false).await.map(Json)
}

async fn runs(
    _admin: AdminCaller,
    State(st): State<AppState>,
    uri: Uri,
) -> ApiResult<Json<Vec<RunOut>>> {
    let q = crate::http::query_params(&uri);
    let kind = q.get("kind").map(|k| kind_of(k)).transpose()?;
    let tx = st.store.begin().await?;
    let rows = evals::list_runs(&tx, kind.map(Kind::as_str), 50).await?;
    tx.commit().await?;
    let mut out = Vec::new();
    for r in rows {
        out.push(run_out(&st, r.id, false).await?);
    }
    Ok(Json(out))
}

async fn run(
    _admin: AdminCaller,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RunOut>> {
    let id: Uuid = id
        .parse()
        .map_err(|_| ApiError::not_found("no such replay"))?;
    run_out(&st, id, true).await.map(Json)
}

async fn run_out(st: &AppState, id: Uuid, with_cases: bool) -> ApiResult<RunOut> {
    let tx = st.store.begin().await?;
    let r = evals::get_run(&tx, id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such replay"))?;
    let rows = evals::run_results(&tx, id).await?;
    tx.commit().await?;
    let cases = if with_cases {
        rows.iter()
            .map(|row| RunCase {
                call_id: row.call_id.to_string(),
                original: row.original.clone(),
                expected: row.expected.clone(),
                class: row.class.clone(),
                error: row.error.clone(),
                latency_ms: row.latency_ms,
                summary: summary(row.answer.as_ref()),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(RunOut {
        id: r.id.to_string(),
        kind: r.kind,
        model: r.model,
        system_sha256: r.system_sha256,
        context: r.context,
        selection: r.selection,
        status: r.status,
        total: r.total,
        note: r.note,
        created_by: r.created_by,
        created_at: r.created_at,
        finished_at: r.finished_at,
        summary: replay::summarize(&rows),
        cases,
    })
}
