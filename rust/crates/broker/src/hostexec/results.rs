//! Job results from hosts (spec §9.2): output chunks, then `job.done`
//! with the hash of the whole kept output. A result is stored only if the
//! reassembled output matches the hash, it came from the host the job was
//! sent to, and the job had no result yet (INV-32); then it is acked.

use std::sync::PoisonError;

use agent_auth_core::JobId;
use agent_auth_crypto::daemon::Role;
use agent_auth_crypto::digest::sha256_hex;
use agent_auth_store::hostexec::{self as store, Finished, JobResult, JobRow};
use agent_auth_wire::daemon::channel::{Incoming, parse};
use agent_auth_wire::daemon::host::{HostToBroker, JobDone, JobOutput};
use base64::Engine as _;
use serde_json::{Map, Value, json};

use super::{HostExec, MAX_BUFFER_BYTES};
use crate::daemons::DaemonPeer;
use crate::notify::Notify as _;

impl HostExec {
    pub(super) fn on_output(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if peer.role() != Role::Host {
            return;
        }
        let Incoming::Message(HostToBroker::JobOutput(JobOutput { job_id, chunk, data })) =
            parse::<HostToBroker>(body)
        else {
            return;
        };
        let mut buffers = self.buffers.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (peer.name().to_owned(), job_id);
        if chunk == Some(0) {
            buffers.insert(key.clone(), Vec::new());
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data.as_str()) else {
            return;
        };
        let buf = buffers.entry(key).or_default();
        buf.extend_from_slice(&bytes);
        if buf.len() > MAX_BUFFER_BYTES {
            buf.clear();
        }
    }

    pub(super) async fn on_done(&self, peer: &DaemonPeer, body: Map<String, Value>) {
        if peer.role() != Role::Host {
            return;
        }
        let Incoming::Message(HostToBroker::JobDone(done)) = parse::<HostToBroker>(body) else {
            return;
        };
        let output = self
            .buffers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(peer.name().to_owned(), done.job_id))
            .unwrap_or_default();
        if sha256_hex(&output) != done.sha256.as_str() {
            // A chunk went missing (reconnect mid-result): no ack, so the
            // host sends the whole result again.
            tracing::warn!(job = %done.job_id, host = peer.name(), "result incomplete; waiting for a resend");
            return;
        }
        match self.store_result(peer.name(), &done, &output).await {
            Ok(Some((fresh, job))) => {
                let mut ack = Map::new();
                ack.insert("type".into(), json!("job.ack"));
                ack.insert("job_id".into(), json!(done.job_id.to_string()));
                self.hub.send_default(Role::Host, peer.name(), &ack).await;
                if fresh {
                    self.job_events.notify(&job.id);
                    self.job_finished(&job).await;
                }
            }
            Ok(None) => {
                tracing::warn!(host = peer.name(), job = %done.job_id, "a host reported a job that isn't its own");
            }
            Err(e) => tracing::error!(job = %done.job_id, error = %e, "result not stored"),
        }
    }

    /// `(fresh, job)`: stored now, or it already had a result. `None`: no
    /// such job on this host.
    async fn store_result(
        &self,
        host: &str,
        done: &JobDone,
        output: &[u8],
    ) -> Result<Option<(bool, JobRow)>, agent_auth_store::StoreError> {
        let now = time::OffsetDateTime::now_utc();
        // Re-validated: whatever the host says is bounded here.
        let error: Option<String> = done
            .error
            .as_ref()
            .map(|e| e.as_str().chars().take(2000).collect::<String>())
            .filter(|e| !e.is_empty());
        let duration_ms = done
            .duration_secs
            .filter(|d| d.is_finite() && (0.0..1.0e7).contains(d))
            .and_then(|d| format!("{:.0}", (d * 1000.0).floor()).parse::<i64>().ok());
        let tx = self.store.begin().await?;
        let finished = if done.lost {
            let text = error
                .clone()
                .unwrap_or_else(|| "its outcome is unknown".to_owned());
            match store::mark_lost(&tx, done.job_id, host, &text, now).await? {
                Some(row) => Finished::Stored(row),
                None => match store::get(&tx, done.job_id).await? {
                    Some(j) if j.host == host => Finished::AlreadyFinal(j),
                    _ => Finished::NotThisHosts,
                },
            }
        } else {
            let text = String::from_utf8_lossy(output);
            store::finish(
                &tx,
                done.job_id,
                host,
                &JobResult {
                    exit_code: done.exit_code,
                    error: error.as_deref(),
                    output: &text,
                    output_bytes: u32::try_from(output.len()).unwrap_or(u32::MAX),
                    output_sha256: done.sha256.as_str(),
                    truncated: done.truncated,
                    duration_ms,
                },
                now,
            )
            .await?
        };
        tx.commit().await?;
        Ok(match finished {
            Finished::NotThisHosts => None,
            Finished::AlreadyFinal(j) => Some((false, j)),
            Finished::Stored(j) => Some((true, j)),
        })
    }

    /// `notifier.job_finished(request, job)`.
    pub(crate) async fn job_finished(&self, job: &JobRow) {
        let request = async {
            let tx = self.store.begin().await?;
            let r = agent_auth_store::requests::get(&tx, job.request_id).await?;
            tx.commit().await?;
            Ok::<_, agent_auth_store::StoreError>(r)
        }
        .await;
        match request {
            Ok(Some(r)) => self.notifier.job_finished(r.row(), job).await,
            Ok(None) => {}
            Err(e) => tracing::error!(job = %job.id, error = %e, "job_finished: request not loaded"),
        }
    }

    /// Move a job that is still `starting` (never over a result that
    /// already arrived); wake waiters unless it is now running.
    pub(crate) async fn set_status(
        &self,
        job: JobId,
        host: &str,
        status: store::JobStatus,
        error: Option<&str>,
        via: Option<&str>,
    ) {
        let result = async {
            let tx = self.store.begin().await?;
            store::set_status(&tx, job, host, status, error, via).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = result {
            tracing::error!(job = %job, error = %e, "job status not stored");
        }
        if status != store::JobStatus::Running {
            self.job_events.notify(&job);
        }
    }
}
