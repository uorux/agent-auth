//! Replays: recorded calls of one kind, rebuilt from their facts under a
//! variant (model, system prompt, context settings) and asked again. A
//! replay only writes its own results (`eval_results`): nothing in it
//! reaches a request, a grant, a shell or a mail item.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_store::Store;
use agent_auth_store::evals::{self, CallRow, NewResult, NewRun, ResultRow, Selection};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{Context, Kind, ModelClient, class_matches, recipe};

/// How long one replayed call may take.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(90);

/// What to replay, and how.
#[derive(Debug, Clone)]
pub struct Replay {
    pub kind: Kind,
    /// `None`: each call's own model.
    pub model: Option<String>,
    /// `None`: the system prompt in use now.
    pub system: Option<String>,
    pub context: Context,
    pub selection: Selection,
    pub note: String,
}

/// Start a replay: the calls chosen now, asked in the background
/// (`concurrency` at a time). Its id.
pub async fn start(
    store: &Store,
    client: &Arc<ModelClient>,
    replay: Replay,
    concurrency: u8,
    by: &str,
) -> Result<Uuid, String> {
    let r = recipe(replay.kind);
    let system = replay
        .system
        .clone()
        .unwrap_or_else(|| r.default_system.to_owned());
    let sha = agent_auth_crypto::digest::sha256_hex(system.as_bytes());
    let mut selection = replay.selection.clone();
    selection.kind = Some(replay.kind.as_str().to_owned());
    let tx = store.begin().await.map_err(|e| e.to_string())?;
    let calls = evals::list_calls(&tx, &selection)
        .await
        .map_err(|e| e.to_string())?;
    if calls.is_empty() {
        return Err("no recorded calls match".to_owned());
    }
    evals::put_prompt(&tx, &sha, &system)
        .await
        .map_err(|e| e.to_string())?;
    let id = Uuid::new_v4();
    let selection_json = json!({
        "labeled": selection.labeled,
        "since": selection.since.map(|t| t.to_string()),
        "until": selection.until.map(|t| t.to_string()),
        "call_ids": selection.ids.as_ref().map(|ids| ids.len()),
        "limit": selection.limit,
    });
    evals::create_run(
        &tx,
        &NewRun {
            id,
            kind: replay.kind.as_str(),
            model: replay.model.as_deref().unwrap_or("(each call's own)"),
            system_sha256: &sha,
            context: &replay.context.to_json(),
            selection: &selection_json,
            total: i32::try_from(calls.len()).unwrap_or(i32::MAX),
            note: &replay.note,
            created_by: by,
            now: OffsetDateTime::now_utc(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let (store, client) = (store.clone(), Arc::clone(client));
    tokio::spawn(async move {
        let status = match run(&store, &client, &replay, &system, id, calls, concurrency).await {
            Ok(()) => "done",
            Err(e) => {
                tracing::warn!(run = %id, "replay failed: {e}");
                "failed"
            }
        };
        let finished = async {
            let tx = store.begin().await?;
            evals::finish_run(&tx, id, status, OffsetDateTime::now_utc()).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = finished {
            tracing::warn!(run = %id, "could not finish a replay: {e}");
        }
    });
    Ok(id)
}

async fn run(
    store: &Store,
    client: &ModelClient,
    replay: &Replay,
    system: &str,
    id: Uuid,
    calls: Vec<CallRow>,
    concurrency: u8,
) -> Result<(), agent_auth_store::StoreError> {
    let r = recipe(replay.kind);
    let permits = Arc::new(tokio::sync::Semaphore::new(usize::from(concurrency.max(1))));
    let mut tasks = Vec::new();
    for call in calls {
        let permit = Arc::clone(&permits);
        let model = replay.model.clone().unwrap_or_else(|| call.model.clone());
        tasks.push(async move {
            let _p = permit.acquire().await;
            let started = Instant::now();
            let asked = match (r.build)(&call.facts, &replay.context) {
                Ok(user) => {
                    client
                        .complete(
                            &model,
                            system,
                            &user,
                            r.schema_name,
                            (r.schema)(),
                            REPLAY_TIMEOUT,
                        )
                        .await
                }
                Err(e) => Err(format!("could not build the prompt: {e}")),
            };
            let latency = started.elapsed();
            let (answer, error) = match asked {
                Ok(a) => (Some(Value::Object(a)), None),
                Err(e) => (None, Some(e.chars().take(2000).collect::<String>())),
            };
            let class = answer
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|a| (r.classify)(a));
            // Each result as it comes: a running replay shows progress.
            let tx = store.begin().await?;
            evals::add_result(
                &tx,
                &NewResult {
                    run: id,
                    call: call.id,
                    answer: answer.as_ref(),
                    class: class.as_deref(),
                    error: error.as_deref(),
                    latency_ms: i32::try_from(latency.as_millis()).unwrap_or(i32::MAX),
                },
            )
            .await?;
            tx.commit().await
        });
    }
    for done in futures::future::join_all(tasks).await {
        done?;
    }
    Ok(())
}

/// A replay's numbers, from its cases.
#[must_use]
pub fn summarize(rows: &[ResultRow]) -> agent_auth_wire::evals::RunSummary {
    let mut s = agent_auth_wire::evals::RunSummary {
        done: 0,
        errors: 0,
        labeled: 0,
        labeled_right: 0,
        original_right: 0,
        changed: 0,
        confusion: Map::new(),
        mean_latency_ms: 0,
    };
    let mut latency: u64 = 0;
    for r in rows {
        s.done = s.done.saturating_add(1);
        latency = latency.saturating_add(u64::try_from(r.latency_ms).unwrap_or(0));
        if r.class.is_none() {
            s.errors = s.errors.saturating_add(1);
        }
        if r.class.is_some() && r.class != r.original {
            s.changed = s.changed.saturating_add(1);
        }
        if let Some(expected) = &r.expected {
            s.labeled = s.labeled.saturating_add(1);
            if r.class
                .as_deref()
                .is_some_and(|c| class_matches(expected, c))
            {
                s.labeled_right = s.labeled_right.saturating_add(1);
            }
            if r.original
                .as_deref()
                .is_some_and(|c| class_matches(expected, c))
            {
                s.original_right = s.original_right.saturating_add(1);
            }
            let got = r.class.clone().unwrap_or_else(|| "(no answer)".to_owned());
            let row = s
                .confusion
                .entry(expected.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(m) = row {
                let n = m.get(&got).and_then(Value::as_u64).unwrap_or(0);
                m.insert(got, json!(n.saturating_add(1)));
            }
        }
    }
    if s.done > 0 {
        s.mean_latency_ms =
            u32::try_from(latency.checked_div(u64::from(s.done)).unwrap_or(0)).unwrap_or(u32::MAX);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(original: Option<&str>, expected: Option<&str>, class: Option<&str>) -> ResultRow {
        ResultRow {
            call_id: Uuid::new_v4(),
            original: original.map(str::to_owned),
            expected: expected.map(str::to_owned),
            class: class.map(str::to_owned),
            answer: None,
            error: None,
            latency_ms: 100,
        }
    }

    #[test]
    fn summaries() {
        let s = summarize(&[
            row(Some("deny"), Some("approve"), Some("approve")),
            row(Some("approve"), Some("approve"), Some("approve")),
            row(Some("deny"), None, Some("approve")),
            row(Some("deny"), Some("deny"), None),
        ]);
        assert_eq!((s.done, s.errors, s.labeled), (4, 1, 3));
        assert_eq!((s.labeled_right, s.original_right), (2, 2));
        assert_eq!(s.changed, 2);
        assert_eq!(s.confusion["approve"]["approve"], 2);
        assert_eq!(s.confusion["deny"]["(no answer)"], 1);
        assert_eq!(s.mean_latency_ms, 100);
    }
}
