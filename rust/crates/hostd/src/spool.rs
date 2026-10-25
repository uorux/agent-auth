//! Job results kept until the broker has them (§9.1-§9.2):
//! `{state_dir}/jobs/{id}.json`, `{"status": "running", "tier", "at"}` while
//! a job runs, then `{"status": "done", "at", "result", "output"}` (output
//! in standard base64). The id is a [`LocalId`], so the path never leaves
//! the directory (INV-28).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use agent_auth_core::Tier;
use agent_auth_core::hostd::LocalId;
use base64::Engine as _;
use serde_json::{Map, Value, json};

use crate::fsutil;

/// How long a finished job's result is kept for a broker that has not
/// acknowledged it.
pub const KEEP_SECS: f64 = 7.0 * 86400.0;
/// What a job running when hostd last stopped is reported as.
pub const LOST_ERROR: &str = "hostd restarted while the job was running; its outcome is unknown";

/// The sha256 of nothing.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone)]
pub struct Spool {
    dir: PathBuf,
}

/// A finished job as spooled.
#[derive(Debug, Clone, PartialEq)]
pub struct Done {
    /// The `job.done` message's fields (job_id, exit_code, error,
    /// duration_secs, bytes, sha256, truncated, lost).
    pub result: Map<String, Value>,
    pub output: Vec<u8>,
}

impl Spool {
    #[must_use]
    pub fn new(state_dir: &Path) -> Spool {
        Spool {
            dir: state_dir.join("jobs"),
        }
    }

    #[must_use]
    pub fn path(&self, id: &LocalId) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    #[must_use]
    pub fn exists(&self, id: &LocalId) -> bool {
        fsutil::exists_or_unknown(&self.path(id))
    }

    fn write(&self, id: &LocalId, v: &Value) -> std::io::Result<()> {
        fsutil::private_dir(&self.dir, 0o700)?;
        fsutil::write_atomic(&self.path(id), v.to_string().as_bytes(), 0o600)
    }

    pub fn write_running(&self, id: &LocalId, tier: Tier, at: f64) -> std::io::Result<()> {
        self.write(
            id,
            &json!({"status": "running", "tier": tier.as_str(), "at": at}),
        )
    }

    pub fn write_done(&self, id: &LocalId, done: &Done, at: f64) -> std::io::Result<()> {
        let output = base64::engine::general_purpose::STANDARD.encode(&done.output);
        self.write(
            id,
            &json!({"status": "done", "at": at, "result": done.result, "output": output}),
        )
    }

    fn read(&self, id: &LocalId) -> Option<Map<String, Value>> {
        let bytes = std::fs::read(self.path(id)).ok()?;
        match serde_json::from_slice(&bytes).ok()? {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }

    /// The finished result of `id`, if it is spooled as done.
    #[must_use]
    pub fn done(&self, id: &LocalId) -> Option<Done> {
        let data = self.read(id)?;
        if data.get("status").and_then(Value::as_str) != Some("done") {
            return None;
        }
        let Some(Value::Object(result)) = data.get("result") else {
            return None;
        };
        let output = base64::engine::general_purpose::STANDARD
            .decode(data.get("output").and_then(Value::as_str).unwrap_or(""))
            .ok()?;
        Some(Done {
            result: result.clone(),
            output,
        })
    }

    /// `job.ack`: drop a done result.
    pub fn ack(&self, id: &LocalId) {
        if self.done(id).is_some() {
            let _ = fsutil::remove_durably(&self.path(id));
        }
    }

    /// Spooled ids, sorted, with their files' age in seconds.
    #[must_use]
    pub fn list(&self) -> Vec<(LocalId, f64)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let now = SystemTime::now();
        let mut out: Vec<(LocalId, f64)> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = LocalId::parse(name.strip_suffix(".json")?).ok()?;
                let age = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|m| now.duration_since(m).ok())
                    .map_or(0.0, |d| d.as_secs_f64());
                Some((id, age))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// At startup: an unreadable spool goes; a job that was running is
    /// reported as lost (its outcome is unknown); anything older than a
    /// week goes. Returns the ids that were running.
    pub fn recover(&self, now: f64) -> Vec<LocalId> {
        let mut lost = Vec::new();
        for (id, _) in self.list() {
            let Some(data) = self.read(&id) else {
                let _ = std::fs::remove_file(self.path(&id));
                continue;
            };
            if data.get("status").and_then(Value::as_str) == Some("running") {
                let mut result = Map::new();
                result.insert("job_id".into(), json!(id.as_str()));
                result.insert("exit_code".into(), Value::Null);
                result.insert("error".into(), json!(LOST_ERROR));
                result.insert("duration_secs".into(), Value::Null);
                result.insert("bytes".into(), json!(0));
                result.insert("sha256".into(), json!(EMPTY_SHA256));
                result.insert("truncated".into(), json!(false));
                result.insert("lost".into(), json!(true));
                let done = Done {
                    result,
                    output: Vec::new(),
                };
                if let Err(e) = self.write_done(&id, &done, now) {
                    tracing::error!(job = %id, error = %e, "could not spool a lost job's result");
                }
                lost.push(id);
            } else if data
                .get("at")
                .and_then(Value::as_f64)
                .is_some_and(|at| now - at > KEEP_SECS)
            {
                let _ = std::fs::remove_file(self.path(&id));
            }
        }
        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;

    #[test]
    fn a_job_that_was_running_when_hostd_died_is_reported_lost() {
        let d = TestDir::new("spool");
        let spool = Spool::new(d.path());
        let id = LocalId::parse("0123abcd-0000").unwrap();
        let old = LocalId::parse("0123abcd-0001").unwrap();
        spool.write_running(&id, Tier::Root, 1000.0).unwrap();
        let done = Done {
            result: Map::new(),
            output: b"x".to_vec(),
        };
        spool.write_done(&old, &done, 1000.0).unwrap();
        std::fs::write(d.path().join("jobs/0123abcd-0002.json"), b"{nope").unwrap();
        let lost = spool.recover(1000.0 + KEEP_SECS + 1.0);
        assert_eq!(lost, vec![id.clone()]);
        let done = spool.done(&id).unwrap();
        assert_eq!(done.result["error"], json!(LOST_ERROR));
        assert_eq!(done.result["lost"], json!(true));
        assert!(done.output.is_empty());
        // The week-old result and the unreadable spool are gone.
        assert_eq!(spool.list().len(), 1);
        spool.ack(&id);
        assert!(spool.list().is_empty());
        assert_eq!(EMPTY_SHA256, agent_auth_crypto::digest::sha256_hex(b""));
    }
}
