//! A host double for tests (feature `testing`): no root, no systemd.
//!
//! Headless claude processes are an in-process fake speaking stream-json
//! (it logs what it was asked and answers a2a turns on their thread
//! through the broker); triage is a fake that answers what the test set;
//! detached units (the TUI's tmux server, codex) are real local processes
//! with `/tmp` in their argv mapped to the unit's tmp directory (systemd's
//! `BindPaths=` in the real thing). What it was asked to do to users,
//! ACLs, ownership and freezing is recorded.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_client::BrokerClient;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use crate::host::{Host, HostError, Piped, ProcExit, Tree, UnitSpec};

/// What the host was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclCall {
    Grant {
        path: PathBuf,
        uid: u32,
        write: bool,
    },
    Revoke {
        path: PathBuf,
        uid: u32,
    },
}

enum Unit {
    Fake(tokio::task::AbortHandle),
    Process(Arc<tokio::sync::Mutex<tokio::process::Child>>, u32),
}

/// The double.
pub struct FakeHost {
    /// JSON lines the fake runtimes write.
    pub log: PathBuf,
    pub users: Mutex<BTreeMap<String, u32>>,
    pub acls: Mutex<Vec<AclCall>>,
    pub chowns: Mutex<Vec<(PathBuf, u32, Vec<u32>)>>,
    pub frozen: Mutex<Vec<(String, bool)>>,
    /// What triage answers (`new` if unset).
    pub triage_answer: Mutex<Option<String>>,
    units: Mutex<HashMap<String, Unit>>,
}

impl std::fmt::Debug for FakeHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeHost")
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read the fake runtimes' log.
#[must_use]
pub fn read_log(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn note(path: &Path, v: &Value) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        let _ = writeln!(f, "{v}");
    }
}

fn arg_after(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i.saturating_add(1)))
        .cloned()
}

/// `/tmp/tmux-…` and `unix:///tmp/codex-…` as the unit would see them.
fn rebase(arg: &str, tmp: &Path) -> String {
    for prefix in ["unix://", ""] {
        let full = format!("{prefix}/tmp/");
        if let Some(rest) = arg.strip_prefix(&full)
            && (rest.starts_with("tmux-") || rest.starts_with("codex-"))
        {
            return format!("{prefix}{}", tmp.join(rest).display());
        }
    }
    arg.to_owned()
}

impl FakeHost {
    #[must_use]
    pub fn new(log: PathBuf) -> FakeHost {
        FakeHost {
            log,
            users: Mutex::new(BTreeMap::new()),
            acls: Mutex::new(Vec::new()),
            chowns: Mutex::new(Vec::new()),
            frozen: Mutex::new(Vec::new()),
            triage_answer: Mutex::new(None),
            units: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn acls(&self) -> Vec<AclCall> {
        lock(&self.acls).clone()
    }

    #[must_use]
    pub fn frozen(&self) -> Vec<(String, bool)> {
        lock(&self.frozen).clone()
    }

    pub fn clear_frozen(&self) {
        lock(&self.frozen).clear();
    }

    #[must_use]
    pub fn chowns(&self) -> Vec<(PathBuf, u32, Vec<u32>)> {
        lock(&self.chowns).clone()
    }

    #[must_use]
    pub fn user(&self, name: &str) -> Option<u32> {
        lock(&self.users).get(name).copied()
    }

    /// Stop every unit (end of a test).
    pub async fn stop_all(&self) {
        let names: Vec<String> = lock(&self.units).keys().cloned().collect();
        for n in names {
            self.stop_unit(&n).await;
        }
    }
}

async fn fake_triage(
    spec: UnitSpec,
    mut stdin: tokio::io::DuplexStream,
    mut stdout: tokio::io::DuplexStream,
    log: &Path,
    answer: Option<String>,
) {
    let mut prompt = String::new();
    let _ = stdin.read_to_string(&mut prompt).await;
    note(
        log,
        &json!({"triage": prompt, "tools": arg_after(&spec.argv, "--tools")}),
    );
    let out = json!({"type": "result", "result": answer.unwrap_or_else(|| "new".to_owned())});
    let _ = stdout.write_all(out.to_string().as_bytes()).await;
    let _ = stdout.shutdown().await;
}

async fn fake_claude(
    spec: UnitSpec,
    stdin: tokio::io::DuplexStream,
    mut stdout: tokio::io::DuplexStream,
    log: &Path,
) {
    let argv = &spec.argv;
    let resumed = argv.iter().any(|a| a == "--resume");
    let sid = arg_after(argv, "--session-id")
        .or_else(|| arg_after(argv, "--resume"))
        .unwrap_or_default();
    let env = |k: &str| spec.env.get(k).cloned().unwrap_or_default();
    note(
        log,
        &json!({"start": sid, "resumed": resumed, "cwd": spec.workdir.display().to_string(),
                "tui": false, "session": env("AGENT_AUTH_SESSION"),
                "mcp": argv.iter().any(|a| a == "--mcp-config"), "unit": spec.name,
                "uid": spec.uid, "argv": argv, "env_keys": spec.env.keys().collect::<Vec<_>>()}),
    );
    let mut line = json!({"type": "system", "subtype": "init", "session_id": sid}).to_string();
    line.push('\n');
    let _ = stdout.write_all(line.as_bytes()).await;
    let client = BrokerClient::new(agent_auth_client::Config {
        base_url: Some(env("AGENT_AUTH_URL")),
        api_key: Some(env("AGENT_AUTH_API_KEY")),
        admin_token: None,
        session_id: Some(env("AGENT_AUTH_SESSION")).filter(|s| !s.is_empty()),
    })
    .ok();
    let mut lines = BufReader::new(stdin).lines();
    while let Ok(Some(raw)) = lines.next_line().await {
        let Ok(msg) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let text = msg
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        note(
            log,
            &json!({"turn": text.chars().take(300).collect::<String>()}),
        );
        if text.contains("SLOW") {
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        if text.starts_with("[a2a] thread ") && !text.contains("is closed") {
            let tid = text.split_whitespace().nth(2).unwrap_or("").to_owned();
            let all: Vec<&str> = text.lines().collect();
            let body = all
                .get(1..all.len().saturating_sub(1))
                .map(|l| l.join(" "))
                .unwrap_or_default();
            if let Some(c) = &client {
                let mut payload = serde_json::Map::new();
                payload.insert("type".into(), json!("result"));
                payload.insert("status".into(), json!("done"));
                payload.insert("summary".into(), json!(format!("echo {body}")));
                if let Err(e) = c.a2a_send(&tid, payload).await {
                    note(log, &json!({"send_error": e.to_string()}));
                }
            }
        }
        for out in [
            json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "handled"}]}}),
            json!({"type": "result", "result": "ok", "session_id": sid}),
        ] {
            let mut l = out.to_string();
            l.push('\n');
            if stdout.write_all(l.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}

impl Host for FakeHost {
    fn ensure_user(&self, name: &str, uid: u32, _home: &Path) -> Result<(), HostError> {
        lock(&self.users).insert(name.to_owned(), uid);
        Ok(())
    }

    fn make_dirs(&self, _uid: u32, dirs: &[Tree]) -> Result<(), HostError> {
        for t in dirs {
            std::fs::create_dir_all(t.path())?;
        }
        Ok(())
    }

    async fn grant_acl(
        &self,
        tree: &Tree,
        uid: u32,
        write: bool,
        _owner: u32,
    ) -> Result<(), HostError> {
        lock(&self.acls).push(AclCall::Grant {
            path: tree.path(),
            uid,
            write,
        });
        Ok(())
    }

    async fn revoke_acl(&self, tree: &Tree, uid: u32) -> Result<(), HostError> {
        lock(&self.acls).push(AclCall::Revoke {
            path: tree.path(),
            uid,
        });
        Ok(())
    }

    async fn chown_tree(&self, tree: &Tree, uid: u32, from: &[u32]) -> Result<(), HostError> {
        lock(&self.chowns).push((tree.path(), uid, from.to_vec()));
        Ok(())
    }

    fn can_chown(&self) -> bool {
        false
    }

    async fn start_piped(&self, spec: &UnitSpec) -> Result<Piped, HostError> {
        let (stdin_w, stdin_r) = tokio::io::duplex(1 << 20);
        let (stdout_w, stdout_r) = tokio::io::duplex(1 << 20);
        let (exit, reporter) = ProcExit::channel();
        let log = self.log.clone();
        let spec2 = spec.clone();
        let answer = lock(&self.triage_answer).clone();
        let task = tokio::spawn(async move {
            if spec2.argv.iter().any(|a| a == "--no-session-persistence") {
                fake_triage(spec2, stdin_r, stdout_w, &log, answer).await;
            } else {
                fake_claude(spec2, stdin_r, stdout_w, &log).await;
            }
            reporter.exited(Some(0));
        });
        lock(&self.units).insert(spec.name.clone(), Unit::Fake(task.abort_handle()));
        Ok(Piped {
            stdin: Box::pin(stdin_w),
            stdout: Box::pin(stdout_r),
            exit,
        })
    }

    async fn start_detached(&self, spec: &UnitSpec) -> Result<(), HostError> {
        let argv: Vec<String> = spec.argv.iter().map(|a| rebase(a, &spec.tmp)).collect();
        let Some((program, args)) = argv.split_first() else {
            return Err(HostError("no command".to_owned()));
        };
        let child = tokio::process::Command::new(program)
            .args(args)
            .envs(std::env::vars())
            .envs(spec.env.iter())
            .env("FAKE_LOG", &self.log)
            .current_dir(&spec.workdir)
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let pid = child.id().unwrap_or(0);
        lock(&self.units).insert(
            spec.name.clone(),
            Unit::Process(Arc::new(tokio::sync::Mutex::new(child)), pid),
        );
        Ok(())
    }

    async fn stop_unit(&self, name: &str) {
        let unit = lock(&self.units).remove(name);
        match unit {
            None => {}
            Some(Unit::Fake(task)) => task.abort(),
            Some(Unit::Process(child, pid)) => {
                if pid != 0 {
                    let _ = tokio::process::Command::new("kill")
                        .args(["-TERM", "--", &format!("-{pid}")])
                        .status()
                        .await;
                }
                let mut c = child.lock().await;
                if tokio::time::timeout(Duration::from_secs(5), c.wait())
                    .await
                    .is_err()
                {
                    let _ = c.start_kill();
                    let _ = c.wait().await;
                }
            }
        }
    }

    async fn unit_active(&self, name: &str) -> bool {
        let unit = match lock(&self.units).get(name) {
            None => return false,
            Some(Unit::Fake(t)) => return !t.is_finished(),
            Some(Unit::Process(c, _)) => Arc::clone(c),
        };
        let mut c = unit.lock().await;
        matches!(c.try_wait(), Ok(None))
    }

    async fn freeze_unit(&self, name: &str, frozen: bool) {
        lock(&self.frozen).push((name.to_owned(), frozen));
    }

    async fn run_as(&self, _uid: u32, argv: &[String]) -> (i32, String) {
        let Some((program, args)) = argv.split_first() else {
            return (-1, String::new());
        };
        match tokio::process::Command::new(program)
            .args(args)
            .env("FAKE_LOG", &self.log)
            .stdin(std::process::Stdio::null())
            .output()
            .await
        {
            Ok(out) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                (out.status.code().unwrap_or(-1), text)
            }
            Err(e) => (-1, e.to_string()),
        }
    }
}

/// A shell script standing in for `claude` in a TUI: logs its session and
/// stays up.
pub const FAKE_TUI: &str = r#"#!/bin/sh
sid=""; resumed=false; prev=""
for a in "$@"; do
  if [ "$prev" = "--resume" ]; then sid="$a"; resumed=true; fi
  if [ "$prev" = "--session-id" ]; then sid="$a"; fi
  prev="$a"
done
printf '{"start": "%s", "resumed": %s, "tui": true}\n' "$sid" "$resumed" >> "$FAKE_LOG"
exec sleep 3600
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebases_only_unit_sockets() {
        let tmp = Path::new("/x/tmp/p");
        assert_eq!(rebase("/tmp/tmux-a.sock", tmp), "/x/tmp/p/tmux-a.sock");
        assert_eq!(
            rebase("unix:///tmp/codex-a.sock", tmp),
            "unix:///x/tmp/p/codex-a.sock"
        );
        assert_eq!(rebase("/tmp/other", tmp), "/tmp/other");
    }
}
