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

/// How the operator runs `argv` as the project's user: `systemd-run
/// --pty` (see [`crate::host::pty_command`]), never on root's own tty.
#[must_use]
pub fn exec_plan(info: &Value, argv: &[String], term: Option<&str>) -> Option<Vec<String>> {
    let uid = u32::try_from(info.get("uid").and_then(Value::as_u64)?).ok()?;
    let cwd = info.get("workdir").and_then(Value::as_str).unwrap_or("/");
    let run = info
        .get("systemd_run")
        .and_then(Value::as_str)
        .unwrap_or("systemd-run");
    if argv.is_empty() {
        return None;
    }
    Some(crate::host::pty_command(run, uid, cwd, term, argv))
}

fn exec_as(info: &Value, argv: &[String]) -> Fail {
    let term = std::env::var("TERM").ok();
    let Some(plan) = exec_plan(info, argv, term.as_deref()) else {
        return Fail("sandboxd gave no way to run it".to_owned());
    };
    let Some((program, args)) = plan.split_first() else {
        return Fail("sandboxd gave no way to run it".to_owned());
    };
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", crate::host::ROOT_PATH)
        .env("LANG", "C.UTF-8");
    if let Some(t) = &term {
        cmd.env("TERM", t);
    }
    Fail(format!("exec {program}: {}", cmd.exec()))
}

fn attach(info: &Value) -> Fail {
    let argv: Vec<String> = info
        .get("argv")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    exec_as(info, &argv)
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
    Some(format!(
        "--- {} {}\n{}",
        clock(t),
        crate::names::terminal_safe(dir),
        crate::names::terminal_safe(text)
    ))
}

/// A conversation row of `ls`.
#[must_use]
pub fn ls_row(c: &Value, now: f64) -> String {
    let s = |k: &str| {
        crate::names::terminal_safe(
            &c.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace('\n', " "),
        )
    };
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
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_owned());
            return Err(exec_as(&info, &[shell, "-l".to_owned()]));
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
    fn attach_and_shell_run_on_a_pty_of_their_own() {
        let info = json!({"uid": 40001, "workdir": "/var/lib/sandbox/projects/p",
                          "systemd_run": "/bin/systemd-run",
                          "argv": ["tmux", "-S", "/s", "attach", "-t", "conv"]});
        let plan = exec_plan(&info, &["tmux".into(), "attach".into()], Some("xterm")).unwrap();
        assert_eq!(&plan[..2], ["/bin/systemd-run", "--pty"]);
        assert!(plan.contains(&"--uid=40001".to_owned()));
        assert!(exec_plan(&json!({}), &["x".into()], None).is_none());
        assert!(exec_plan(&info, &[], None).is_none());
    }

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
        // Escape sequences an agent wrote never reach the terminal.
        let e = log_entry(r#"{"t": 0, "dir": "out", "text": "\u001b]0;pwned\u0007ok"}"#).unwrap();
        assert!(!e.contains('\u{1b}') && e.contains("\\u{001b}"));
        let c = json!({"id": "x", "state": "parked", "agent": "a", "title": "t\u{1b}[2J",
                       "last_activity": 1.0});
        assert!(!ls_row(&c, 2.0).contains('\u{1b}'));
    }
}
