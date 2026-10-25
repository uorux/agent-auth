#![forbid(unsafe_code)]
//! `agent-auth-hostctl`: talk to this host's hostd over its local socket
//! (daemons-hostd §12.2). root may do everything; the user the host is
//! configured for may see the status, arm and disarm the user tier, lock
//! down, set do-not-disturb, and report desktop presence.

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use agent_auth_daemon::localsock::{CallError, call};
use agent_auth_hostd::config::default_runtime_dir;
use clap::{Parser, Subcommand};
use serde_json::{Map, Value, json};

const SOCKET_ENV: &str = "AGENT_AUTH_HOSTD_CTL";

#[derive(Parser, Debug)]
#[command(
    name = "agent-auth-hostctl",
    about = "control this host's agent-auth daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Tiers, arming, jobs, shells, lockdown, desktop presence.
    Status {
        #[arg(long = "json")]
        as_json: bool,
    },
    /// Let Discord approvals count for a tier, for a while.
    Arm {
        /// e.g. 30m, 2h (capped by this host's policy).
        #[arg(default_value = "1h")]
        duration: String,
        /// user | root (root needs sudo).
        #[arg(long, default_value = "user")]
        tier: String,
    },
    Disarm {
        /// Default: both.
        #[arg(long)]
        tier: Option<String>,
    },
    /// Refuse everything on this host, kill running jobs and shells, and
    /// freeze the agent VM. Stays in force across restarts until `unlock`.
    Lockdown {
        /// Stop the agent VM instead of freezing it.
        #[arg(long)]
        kill_vm: bool,
    },
    /// Clear a lockdown (root only).
    Unlock,
    /// Clear a TOTP secret's lock after wrong codes (root only).
    TotpUnlock {
        /// user-arm | user-direct | root-arm | root-direct | user-shell | root-shell | root-unlock
        name: String,
    },
    /// No approval prompts on this desktop for a while (they go to Discord).
    Dnd {
        /// e.g. 2h; omit to turn it off.
        duration: Option<String>,
    },
    /// Tell hostd whether you are at this desktop (hypridle, lock screen).
    Presence {
        /// idle | active | locked | unlocked
        state: String,
    },
}

/// A key of a JSON object (null when absent).
fn g<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn red(msg: &str) {
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[31m{msg}\x1b[0m");
    } else {
        eprintln!("{msg}");
    }
}

fn when(ts: Option<f64>) -> String {
    let Some(ts) = ts.filter(|t| t.is_finite() && *t > 0.0) else {
        return "-".into();
    };
    let secs = format!("{:.0}", ts.floor()).parse::<i64>().unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(time::macros::format_description!(
                "[hour]:[minute]:[second] UTC"
            ))
            .ok()
        })
        .unwrap_or_else(|| "-".into())
}

fn print_status(s: &Value) {
    if g(s, "lockdown").as_bool() == Some(true) {
        println!("LOCKED DOWN (agent-auth-hostctl unlock, as root)");
    }
    if let Some(tiers) = g(s, "tiers").as_object() {
        for (name, t) in tiers {
            if g(t, "enabled").as_bool() != Some(true) {
                println!("{name:5} disabled");
                continue;
            }
            let armed = match g(t, "armed_until").as_f64() {
                Some(u) => format!("armed until {}", when(Some(u))),
                None => "not armed".into(),
            };
            let shells = if g(t, "shell").as_bool() == Some(true) {
                "  shells on"
            } else {
                ""
            };
            let totp = if g(t, "totp").as_bool() == Some(true) {
                ""
            } else {
                "  (TOTP not enrolled)"
            };
            let locked = if g(t, "totp_locked").as_bool() == Some(true) {
                "  (TOTP LOCKED: totp-unlock)"
            } else {
                ""
            };
            println!("{name:5} {armed}{shells}{totp}{locked}");
        }
    }
    println!("jobs {}  shells {}", g(s, "jobs"), g(s, "shells"));
    if let Some(vm) = g(s, "vm").as_object() {
        println!(
            "vm {}: {}",
            vm.get("unit").and_then(Value::as_str).unwrap_or("?"),
            vm.get("state").and_then(Value::as_str).unwrap_or("?")
        );
    }
    let d = &g(s, "desktop");
    if g(d, "enabled").as_bool() == Some(true) {
        let dnd = match g(d, "dnd_until").as_f64() {
            Some(u) => format!("  do-not-disturb until {}", when(Some(u))),
            None => String::new(),
        };
        let presence = if g(d, "present").as_bool() == Some(true) {
            "present".to_owned()
        } else {
            format!(
                "away: {}",
                g(d, "away_reason").as_str().unwrap_or("unknown")
            )
        };
        println!("desktop: {presence}{dnd}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let socket = std::env::var_os(SOCKET_ENV)
        .map_or_else(|| default_runtime_dir().join("ctl.sock"), PathBuf::from);
    let (method, params) = match &cli.command {
        Cmd::Status { .. } => ("status", json!({})),
        Cmd::Arm { duration, tier } => ("arm", json!({"tier": tier, "duration": duration})),
        Cmd::Disarm { tier } => ("disarm", json!({"tier": tier})),
        Cmd::Lockdown { kill_vm } => ("lockdown", json!({"kill_vm": kill_vm})),
        Cmd::Unlock => ("unlock", json!({})),
        Cmd::TotpUnlock { name } => ("totp-unlock", json!({"name": name})),
        Cmd::Dnd { duration } => ("dnd", json!({"duration": duration})),
        Cmd::Presence { state } => ("presence", json!({"state": state})),
    };
    let params: Map<String, Value> = match params {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            red(&e.to_string());
            return ExitCode::from(1);
        }
    };
    let out = runtime.block_on(call(&socket, method, params, None, Duration::from_secs(60)));
    let out = match out {
        Ok(v) => v,
        Err(CallError::Refused(e)) => {
            red(&e);
            return ExitCode::from(1);
        }
        Err(e) => {
            red(&format!("hostd is not reachable: {e}"));
            return ExitCode::from(1);
        }
    };
    match cli.command {
        Cmd::Status { as_json: true } => {
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        }
        Cmd::Status { as_json: false } => print_status(&out),
        Cmd::Arm { tier, .. } => {
            println!(
                "{tier} tier armed until {}",
                when(g(&out, "armed_until").as_f64())
            );
        }
        Cmd::Disarm { .. } => println!("disarmed"),
        Cmd::Lockdown { .. } => match g(&out, "vm").as_str() {
            Some(vm) => println!("locked down · vm {vm}"),
            None => println!("locked down"),
        },
        Cmd::Unlock => match g(&out, "vm").as_str() {
            Some(vm) => println!("unlocked · vm {vm}"),
            None => println!("unlocked"),
        },
        Cmd::TotpUnlock { name } => println!("{name} unlocked"),
        Cmd::Dnd { .. } => match g(&out, "dnd_until").as_f64() {
            Some(u) => println!("do-not-disturb until {}", when(Some(u))),
            None => println!("do-not-disturb off"),
        },
        Cmd::Presence { .. } => {}
    }
    ExitCode::SUCCESS
}
