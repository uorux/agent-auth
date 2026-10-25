//! sandboxd's configuration: one JSON file written by its NixOS module
//! (sandboxd spec §4.2).
//!
//! Stricter than the Python: unknown keys are refused (a typo must not
//! silently drop a limit), values must have their JSON types, and a runtime
//! other than `claude` or `codex` is an error rather than ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_auth_core::sandbox::ProjectName;
use agent_auth_crypto::daemon::{DaemonName, PublicKey};
use agent_auth_daemon::BrokerUrl;
use serde::Deserialize;

pub const CONFIG_ENV: &str = "AGENT_AUTH_SANDBOXD_CONFIG";
pub const DEFAULT_CONFIG: &str = "/etc/agent-auth/sandboxd.json";

/// The runtimes sandboxd knows how to drive.
pub const RUNTIMES: [&str; 2] = ["claude", "codex"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// A runtime's binary (unwrapped) and its model.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub command: String,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    broker_url: String,
    broker_public_key: String,
    name: String,
    #[serde(default = "d_state_dir")]
    state_dir: PathBuf,
    #[serde(default = "d_sandbox_root")]
    sandbox_root: PathBuf,
    #[serde(default = "d_userdb_dir")]
    userdb_dir: PathBuf,
    #[serde(default = "d_runtime_dir")]
    runtime_dir: PathBuf,
    #[serde(default = "d_agent_socket")]
    agent_socket: PathBuf,
    #[serde(default)]
    runtimes: BTreeMap<String, RuntimeConfig>,
    #[serde(default = "d_agent_path")]
    agent_path: String,
    #[serde(default = "d_agent_auth_mcp")]
    agent_auth_mcp: String,
    #[serde(default = "d_sandbox_mcp")]
    sandbox_mcp: String,
    #[serde(default = "d_mcp_bridge")]
    mcp_bridge: String,
    #[serde(default = "d_tmux")]
    tmux: String,
    #[serde(default = "d_systemd_run")]
    systemd_run: String,
    #[serde(default = "d_systemctl")]
    systemctl: String,
    #[serde(default = "d_setfacl")]
    setfacl: String,
    #[serde(default = "d_orchestrator_runtime")]
    orchestrator_runtime: String,
    #[serde(default = "d_uid_base")]
    uid_base: u32,
    #[serde(default = "d_uid_max")]
    uid_max: u32,
    #[serde(default = "d_park_grace")]
    park_grace_secs: f64,
    #[serde(default = "d_true")]
    triage: bool,
    #[serde(default)]
    triage_runtime: Option<String>,
    #[serde(default)]
    triage_model: Option<String>,
    #[serde(default = "d_triage_timeout")]
    triage_timeout_secs: f64,
    #[serde(default = "d_idle")]
    interactive_idle_secs: f64,
    #[serde(default = "d_max_processes")]
    max_processes: u32,
    #[serde(default = "d_max_per_project")]
    max_processes_per_project: u32,
    #[serde(default = "d_memory_max")]
    unit_memory_max: String,
    #[serde(default = "d_tasks_max")]
    unit_tasks_max: u32,
    #[serde(default)]
    codex_auth_owner: Option<String>,
    #[serde(default = "d_true")]
    refuse_vm_logins_when_unreachable: bool,
}

fn d_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/sandboxd")
}
fn d_sandbox_root() -> PathBuf {
    PathBuf::from("/var/lib/sandbox")
}
fn d_userdb_dir() -> PathBuf {
    PathBuf::from("/var/lib/userdb")
}
fn d_runtime_dir() -> PathBuf {
    PathBuf::from("/run/sandboxd")
}
fn d_agent_socket() -> PathBuf {
    PathBuf::from("/run/sandboxd-agent/agent.sock")
}
fn d_agent_path() -> String {
    "/run/current-system/sw/bin".to_owned()
}
fn d_agent_auth_mcp() -> String {
    "agent-auth-mcp".to_owned()
}
fn d_sandbox_mcp() -> String {
    "agent-auth-sandbox-mcp".to_owned()
}
fn d_mcp_bridge() -> String {
    "agent-auth-mcp-bridge".to_owned()
}
fn d_tmux() -> String {
    "tmux".to_owned()
}
fn d_systemd_run() -> String {
    "systemd-run".to_owned()
}
fn d_systemctl() -> String {
    "systemctl".to_owned()
}
fn d_setfacl() -> String {
    "setfacl".to_owned()
}
fn d_orchestrator_runtime() -> String {
    "claude".to_owned()
}
fn d_uid_base() -> u32 {
    40000
}
fn d_uid_max() -> u32 {
    49999
}
fn d_park_grace() -> f64 {
    30.0
}
fn d_true() -> bool {
    true
}
fn d_triage_timeout() -> f64 {
    60.0
}
fn d_idle() -> f64 {
    1800.0
}
fn d_max_processes() -> u32 {
    16
}
fn d_max_per_project() -> u32 {
    4
}
fn d_memory_max() -> String {
    "8G".to_owned()
}
fn d_tasks_max() -> u32 {
    4096
}

/// The whole config, checked.
#[derive(Debug, Clone)]
pub struct Config {
    pub broker_url: BrokerUrl,
    pub broker_public_key: PublicKey,
    /// The physical host's name: agents are `<runtime>-<project>-<name>-sandbox`.
    pub name: DaemonName,
    pub state_dir: PathBuf,
    pub sandbox_root: PathBuf,
    pub userdb_dir: PathBuf,
    /// Root only: env files, the operator socket.
    pub runtime_dir: PathBuf,
    /// Every agent unit reaches it.
    pub agent_socket: PathBuf,
    pub runtimes: BTreeMap<String, RuntimeConfig>,
    /// PATH inside agent units.
    pub agent_path: String,
    pub agent_auth_mcp: String,
    pub sandbox_mcp: String,
    pub mcp_bridge: String,
    pub tmux: String,
    pub systemd_run: String,
    pub systemctl: String,
    pub setfacl: String,
    /// Which runtime the orchestrator runs.
    pub orchestrator_runtime: String,
    pub uid_base: u32,
    pub uid_max: u32,
    pub park_grace_secs: f64,
    pub triage: bool,
    pub triage_runtime: Option<String>,
    pub triage_model: Option<String>,
    pub triage_timeout_secs: f64,
    /// An attached TUI nobody has used for this long is ended (its
    /// conversation goes back to headless).
    pub interactive_idle_secs: f64,
    /// Agent processes (headless, TUI, triage) at once in the VM.
    pub max_processes: u32,
    /// ... and per project (the orchestrator counts as its own).
    pub max_processes_per_project: u32,
    pub unit_memory_max: String,
    pub unit_tasks_max: u32,
    /// The one project whose codex login is written back to the shared
    /// login (`secrets/codex-auth.json`); every other project gets a
    /// read-only copy. None: nobody writes it back.
    pub codex_auth_owner: Option<ProjectName>,
    /// A broker that cannot be reached (so no word on its model gateway)
    /// starts no process on the VM's own logins (default true; the Python
    /// fell back to them).
    pub refuse_vm_logins_when_unreachable: bool,
}

fn finite_positive(v: f64, what: &str) -> Result<f64, ConfigError> {
    if v.is_finite() && v > 0.0 && v <= 86_400.0 * 365.0 {
        Ok(v)
    } else {
        Err(ConfigError(format!(
            "{what} must be a positive number of seconds"
        )))
    }
}

fn absolute(p: PathBuf, what: &str) -> Result<PathBuf, ConfigError> {
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(ConfigError(format!("{what} must be an absolute path")))
    }
}

impl Config {
    /// Read and check the file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Config::from_json(&text)
    }

    /// The file's path: `--config`, else `AGENT_AUTH_SANDBOXD_CONFIG`, else
    /// `/etc/agent-auth/sandboxd.json`.
    #[must_use]
    pub fn path(given: Option<PathBuf>) -> PathBuf {
        given
            .or_else(|| {
                std::env::var_os(CONFIG_ENV)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG))
    }

    pub fn from_json(text: &str) -> Result<Config, ConfigError> {
        let raw: Raw = serde_json::from_str(text).map_err(|e| ConfigError(e.to_string()))?;
        let broker_url = BrokerUrl::parse(&raw.broker_url)
            .map_err(|e| ConfigError(format!("broker_url: {e}")))?;
        let broker_public_key = PublicKey::parse(&raw.broker_public_key)
            .map_err(|e| ConfigError(format!("broker_public_key: {e}")))?;
        let name = DaemonName::parse(&raw.name).ok_or_else(|| {
            ConfigError(format!("name {:?}: [a-z0-9][a-z0-9-]{{0,62}}", raw.name))
        })?;
        if name.as_str().contains('-') {
            return Err(ConfigError(format!(
                "name {:?}: an agent VM's name has no '-' (its agents are <runtime>-<project>-<name>-sandbox)",
                raw.name
            )));
        }
        for rt in raw.runtimes.keys() {
            if !RUNTIMES.contains(&rt.as_str()) {
                return Err(ConfigError(format!(
                    "runtimes: unknown runtime {rt:?} ({})",
                    RUNTIMES.join(", ")
                )));
            }
        }
        if raw.uid_base == 0 || raw.uid_max <= raw.uid_base {
            return Err(ConfigError(
                "uid_base must be above 0 and below uid_max".to_owned(),
            ));
        }
        if raw.max_processes == 0 || raw.max_processes_per_project == 0 {
            return Err(ConfigError(
                "max_processes and max_processes_per_project must be at least 1".to_owned(),
            ));
        }
        if raw.unit_tasks_max == 0 {
            return Err(ConfigError("unit_tasks_max must be at least 1".to_owned()));
        }
        let simple = |v: &str| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '%'))
        };
        if !simple(&raw.unit_memory_max) {
            return Err(ConfigError(format!(
                "unit_memory_max {:?} is not a size",
                raw.unit_memory_max
            )));
        }
        let codex_auth_owner = match raw.codex_auth_owner {
            None => None,
            Some(p) => Some(
                ProjectName::parse(&p)
                    .map_err(|e| ConfigError(format!("codex_auth_owner: {e}")))?,
            ),
        };
        Ok(Config {
            broker_url,
            broker_public_key,
            name,
            state_dir: absolute(raw.state_dir, "state_dir")?,
            sandbox_root: absolute(raw.sandbox_root, "sandbox_root")?,
            userdb_dir: absolute(raw.userdb_dir, "userdb_dir")?,
            runtime_dir: absolute(raw.runtime_dir, "runtime_dir")?,
            agent_socket: absolute(raw.agent_socket, "agent_socket")?,
            runtimes: raw.runtimes,
            agent_path: raw.agent_path,
            agent_auth_mcp: raw.agent_auth_mcp,
            sandbox_mcp: raw.sandbox_mcp,
            mcp_bridge: raw.mcp_bridge,
            tmux: raw.tmux,
            systemd_run: raw.systemd_run,
            systemctl: raw.systemctl,
            setfacl: raw.setfacl,
            orchestrator_runtime: raw.orchestrator_runtime,
            uid_base: raw.uid_base,
            uid_max: raw.uid_max,
            park_grace_secs: finite_positive(raw.park_grace_secs, "park_grace_secs")?,
            triage: raw.triage,
            triage_runtime: raw.triage_runtime,
            triage_model: raw.triage_model,
            triage_timeout_secs: finite_positive(raw.triage_timeout_secs, "triage_timeout_secs")?,
            interactive_idle_secs: finite_positive(
                raw.interactive_idle_secs,
                "interactive_idle_secs",
            )?,
            max_processes: raw.max_processes,
            max_processes_per_project: raw.max_processes_per_project,
            unit_memory_max: raw.unit_memory_max,
            unit_tasks_max: raw.unit_tasks_max,
            codex_auth_owner,
            refuse_vm_logins_when_unreachable: raw.refuse_vm_logins_when_unreachable,
        })
    }

    /// `state_dir/secrets`: the runtimes' logins (root 0600).
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.state_dir.join("secrets")
    }

    /// The daemon's identity key.
    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.state_dir.join("key")
    }

    /// The operator socket (root only).
    #[must_use]
    pub fn operator_socket(&self) -> PathBuf {
        self.runtime_dir.join("operator.sock")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// A real broker key (small-order points, the all-zero one among them,
    /// are refused).
    pub(crate) fn key() -> String {
        agent_auth_crypto::daemon::SigningKey::generate()
            .unwrap()
            .public_key()
            .to_text()
    }

    fn base() -> serde_json::Value {
        serde_json::json!({"broker_url": "https://broker.example", "broker_public_key": key(),
                           "name": "excelsior"})
    }

    #[test]
    fn defaults_and_strictness() {
        let c = Config::from_json(&base().to_string()).unwrap();
        assert_eq!(c.uid_base, 40000);
        assert_eq!(c.max_processes, 16);
        assert!(c.refuse_vm_logins_when_unreachable);
        assert_eq!(
            c.operator_socket(),
            PathBuf::from("/run/sandboxd/operator.sock")
        );
        let mut v = base();
        v["agnet_path"] = serde_json::json!("x");
        assert!(Config::from_json(&v.to_string()).is_err());
        let mut v = base();
        v["runtimes"] = serde_json::json!({"gemini": {"command": "g"}});
        assert!(
            Config::from_json(&v.to_string())
                .unwrap_err()
                .0
                .contains("unknown runtime")
        );
        let mut v = base();
        v["max_processes"] = serde_json::json!("16");
        assert!(Config::from_json(&v.to_string()).is_err());
        let mut v = base();
        v["park_grace_secs"] = serde_json::json!(-1);
        assert!(Config::from_json(&v.to_string()).is_err());
        let mut v = base();
        v["broker_url"] = serde_json::json!("http://broker.example");
        assert!(Config::from_json(&v.to_string()).is_err());
        let mut v = base();
        v["name"] = serde_json::json!("my-vm");
        assert!(
            Config::from_json(&v.to_string())
                .unwrap_err()
                .0
                .contains("no '-'")
        );
        let mut v = base();
        v["codex_auth_owner"] = serde_json::json!("Bad_Name");
        assert!(Config::from_json(&v.to_string()).is_err());
    }
}
