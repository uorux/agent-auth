//! `agent-auth-sandboxctl`: the operator's CLI inside the agent VM (root),
//! over the operator socket (sandboxd spec §4.15). `avm` on the host runs
//! it over SSH.

use std::io::{IsTerminal as _, Read as _};
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use agent_auth_daemon::localsock::{self, CallError};
use clap::{Parser, Subcommand};
use serde_json::{Map, Value, json};

use crate::{DEFAULT_OPERATOR_SOCKET, OPERATOR_SOCKET_ENV};

#[derive(Parser, Debug)]
#[command(
    name = "agent-auth-sandboxctl",
    about = "operate the agent VM (sandboxd)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    Status,
    /// Conversations: agent, state, last activity.
    Ls {
        #[arg(long, short = 'p')]
        project: Option<String>,
        #[arg(long = "all", short = 'a')]
        all: bool,
    },
    Agents,
    Projects,
    #[command(name = "project-create")]
    ProjectCreate {
        name: String,
        /// Leave it writable by the orchestrator.
        #[arg(long = "open")]
        open: bool,
    },
    /// Ask the broker (as the orchestrator) for <runtime>-<project>-<host>-sandbox.
    Mint {
        project: String,
        #[arg(long, short = 'r', default_value = "claude")]
        runtime: String,
    },
    /// New conversation of <runtime>-<project>-<host>-sandbox, attached in
    /// its TUI. Mints the agent first if it doesn't exist (the broker's
    /// policy decides; a human may be asked on Discord).
    New {
        project: String,
        #[arg(long, short = 'r', default_value = "claude")]
        runtime: String,
        #[arg(long)]
        prompt: Option<String>,
        /// Headless; don't attach.
        #[arg(long, short = 'd')]
        detach: bool,
    },
    /// Take a conversation over in its TUI (detach with tmux's prefix + d).
    Attach {
        conversation: String,
        /// Interrupt a running turn.
        #[arg(long)]
        now: bool,
    },
    Send {
        conversation: String,
        text: String,
    },
    /// The conversation's transcript as sandboxd saw it (in / out / errors).
    Logs {
        conversation: String,
        #[arg(long, short = 'f')]
        follow: bool,
    },
    /// Park it now (it resumes on its next message).
    Stop {
        conversation: String,
    },
    /// End it: its threads close and its broker session ends.
    Close {
        conversation: String,
    },
    /// A shell as the project's user, in its directory (no runtime).
    Shell {
        project: String,
    },
    /// Store a runtime credential, read from stdin (never an argument).
    #[command(name = "secret-set")]
    SecretSet {
        /// claude-oauth-token | codex-auth.json
        name: String,
    },
}

/// A failure: printed in red, exit 1.
#[derive(Debug)]
pub struct Fail(pub String);

fn socket() -> PathBuf {
    std::env::var_os(OPERATOR_SOCKET_ENV)
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_OPERATOR_SOCKET), PathBuf::from)
}

/// One operator call.
pub async fn call(method: &str, params: Value) -> Result<Value, Fail> {
    let params = match params {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    localsock::call(&socket(), method, params, None, Duration::from_secs(600))
        .await
        .map_err(|e| match e {
            CallError::Refused(m) => Fail(m),
            other => Fail(format!("sandboxd unreachable: {other}")),
        })
}

fn out(v: &Value) {
    println!(
        "{}",
        agent_auth_client::pyjson::dumps_indent(v).unwrap_or_default()
    );
}

/// `exec setpriv --reuid=uid --regid=uid --clear-groups -- argv` (in `cwd`).
fn exec_as(uid: u64, argv: &[String], cwd: Option<&str>) -> Fail {
    let mut cmd = std::process::Command::new("setpriv");
    cmd.arg(format!("--reuid={uid}"))
        .arg(format!("--regid={uid}"))
        .arg("--clear-groups")
        .arg("--")
        .args(argv);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    Fail(format!("exec setpriv: {}", cmd.exec()))
}

fn attach(info: &Value) -> Fail {
    let uid = info.get("uid").and_then(Value::as_u64).unwrap_or(u64::MAX);
    let argv: Vec<String> = info
        .get("argv")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if argv.is_empty() || uid == u64::MAX {
        return Fail("sandboxd gave no way to attach".to_owned());
    }
    exec_as(uid, &argv, None)
}

/// `HH:MM:SS` (UTC: no local time zone without libc).
fn clock(t: f64) -> String {
    let secs = if t.is_finite() && t > 0.0 {
        t.floor()
    } else {
        0.0
    };
    let day = secs.rem_euclid(86_400.0);
    let h = (day / 3600.0).floor();
    let m = ((day - h * 3600.0) / 60.0).floor();
    let s = day - h * 3600.0 - m * 60.0;
    format!("{h:02.0}:{m:02.0}:{s:02.0}")
}

/// A transcript line as `logs` prints it.
#[must_use]
pub fn log_entry(line: &str) -> Option<String> {
    let rec: Value = serde_json::from_str(line).ok()?;
    let t = rec.get("t").and_then(Value::as_f64).unwrap_or(0.0);
    let dir = rec.get("dir").and_then(Value::as_str).unwrap_or("");
    let text = rec.get("text").and_then(Value::as_str).unwrap_or("");
    Some(format!("--- {} {dir}\n{text}", clock(t)))
}

/// A conversation row of `ls`.
#[must_use]
pub fn ls_row(c: &Value, now: f64) -> String {
    let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let last = c
        .get("last_activity")
        .and_then(Value::as_f64)
        .unwrap_or(now);
    let age = (now - last).floor();
    format!(
        "{}  {:<9} {:<44} {:>6}s ago  {}",
        s("id"),
        s("state"),
        s("agent"),
        format!("{age:.0}"),
        s("title")
    )
}

async fn find_agent(project: &str, runtime: &str) -> Result<Option<String>, Fail> {
    let agents = call("agents", json!({})).await?;
    Ok(agents.as_array().and_then(|a| {
        a.iter()
            .find(|x| {
                x.get("project").and_then(Value::as_str) == Some(project)
                    && x.get("runtime").and_then(Value::as_str) == Some(runtime)
            })
            .and_then(|x| x.get("name").and_then(Value::as_str).map(str::to_owned))
    }))
}

async fn run_cmd(cmd: Cmd) -> Result<(), Fail> {
    match cmd {
        Cmd::Status => out(&call("status", json!({})).await?),
        Cmd::Agents => out(&call("agents", json!({})).await?),
        Cmd::Projects => out(&call("projects", json!({})).await?),
        Cmd::Ls { project, all } => {
            let convs = call("conversations", json!({"project": project, "all": all})).await?;
            let now = crate::store::now();
            for c in convs.as_array().into_iter().flatten() {
                println!("{}", ls_row(c, now));
            }
        }
        Cmd::ProjectCreate { name, open } => {
            out(&call("project_create", json!({"name": name, "sealed": !open})).await?);
        }
        Cmd::Mint { project, runtime } => {
            out(&call("mint", json!({"runtime": runtime, "project": project})).await?);
        }
        Cmd::New {
            project,
            runtime,
            prompt,
            detach,
        } => {
            let mut agent = find_agent(&project, &runtime).await?;
            if agent.is_none() {
                eprintln!("minting {runtime} for {project} (the broker may ask a human)…");
                let res = call(
                    "mint",
                    json!({"runtime": runtime, "project": project,
                           "why": format!("operator opened a {runtime} session on {project}")}),
                )
                .await?;
                agent = find_agent(&project, &runtime).await?;
                if agent.is_none() {
                    return Err(Fail(format!(
                        "not minted: {} {}",
                        res.get("status").and_then(Value::as_str).unwrap_or("None"),
                        res.get("reason").and_then(Value::as_str).unwrap_or("")
                    )));
                }
            }
            let res = call(
                "new",
                json!({"agent": agent, "prompt": prompt, "attach": !detach}),
            )
            .await?;
            if detach {
                out(res.get("conversation").unwrap_or(&Value::Null));
            } else {
                return Err(attach(res.get("attach").unwrap_or(&Value::Null)));
            }
        }
        Cmd::Attach { conversation, now } => {
            let info = call("attach", json!({"conversation": conversation, "now": now})).await?;
            return Err(attach(&info));
        }
        Cmd::Send { conversation, text } => {
            out(&call("send", json!({"conversation": conversation, "text": text})).await?);
        }
        Cmd::Logs {
            conversation,
            follow,
        } => {
            let path = call("log_path", json!({"conversation": conversation})).await?;
            let path = path.as_str().unwrap_or("").to_owned();
            let mut pos = 0usize;
            loop {
                if let Ok(text) = std::fs::read_to_string(&path)
                    && let Some(rest) = text.get(pos..)
                {
                    let mut consumed = 0usize;
                    for line in rest.split_inclusive('\n') {
                        if !line.ends_with('\n') {
                            break;
                        }
                        consumed = consumed.saturating_add(line.len());
                        if let Some(entry) = log_entry(line.trim_end()) {
                            println!("{entry}");
                        }
                    }
                    pos = pos.saturating_add(consumed);
                }
                if !follow {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        Cmd::Stop { conversation } => {
            out(&call("stop", json!({"conversation": conversation})).await?);
        }
        Cmd::Close { conversation } => {
            out(&call("close", json!({"conversation": conversation})).await?);
        }
        Cmd::Shell { project } => {
            let info = call("shell", json!({"project": project})).await?;
            let uid = info.get("uid").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let workdir = info
                .get("workdir")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_owned();
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_owned());
            return Err(exec_as(uid, &[shell, "-l".to_owned()], Some(&workdir)));
        }
        Cmd::SecretSet { name } => {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .map_err(|e| Fail(e.to_string()))?;
            let value = if name.ends_with(".json") {
                value
            } else {
                value.trim().to_owned()
            };
            out(&call("secret_set", json!({"name": name, "value": value})).await?);
        }
    }
    Ok(())
}

/// The CLI.
pub async fn main(cli: Cli) -> ExitCode {
    match run_cmd(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(msg)) => {
            if std::io::stderr().is_terminal() {
                eprintln!("\x1b[31m{msg}\x1b[0m");
            } else {
                eprintln!("{msg}");
            }
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_and_log_lines() {
        let c = json!({"id": "0123456789ab", "state": "parked", "agent": "a", "title": "t",
                       "last_activity": 100.0});
        let row = ls_row(&c, 160.5);
        assert!(row.starts_with("0123456789ab  parked    a "));
        assert!(row.ends_with("    60s ago  t"));
        assert_eq!(
            log_entry(r#"{"t": 3661.5, "dir": "in", "text": "hi"}"#).as_deref(),
            Some("--- 01:01:01 in\nhi")
        );
        assert!(log_entry("garbage").is_none());
    }
}
