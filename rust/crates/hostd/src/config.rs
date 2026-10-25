//! hostd's configuration and local policy: one JSON file written by its
//! NixOS (or nix-darwin) module, so only an audited config change can loosen
//! it (daemons-hostd spec §13.2). The broker has no say in any of it.
//!
//! Stricter than the Python: unknown keys are refused (a typo must not
//! silently drop a deny pattern), and values must have their JSON types.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use agent_auth_core::durations::{host_duration_from_int, host_duration_secs};
use agent_auth_core::hostd::{HostPolicy, TierPolicy};
use agent_auth_core::hostexec::Template;
use agent_auth_crypto::daemon::{DaemonName, PublicKey};
use agent_auth_daemon::BrokerUrl;
use serde_json::{Map, Value};

pub const CONFIG_ENV: &str = "AGENT_AUTH_HOSTD_CONFIG";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

#[must_use]
pub fn darwin() -> bool {
    cfg!(target_os = "macos")
}

#[must_use]
pub fn default_state_dir() -> PathBuf {
    PathBuf::from(if darwin() {
        "/var/db/agent-auth-hostd"
    } else {
        "/var/lib/agent-auth-hostd"
    })
}

#[must_use]
pub fn default_runtime_dir() -> PathBuf {
    PathBuf::from(if darwin() {
        "/var/run/agent-auth-hostd"
    } else {
        "/run/agent-auth-hostd"
    })
}

#[must_use]
pub fn default_job_path() -> String {
    if darwin() {
        "/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            .to_owned()
    } else {
        "/run/wrappers/bin:/run/current-system/sw/bin".to_owned()
    }
}

/// `duration_secs(v)`: an integer > 0, or `"30m"`-style text.
pub fn duration_secs(v: &Value) -> Result<u64, ConfigError> {
    match v {
        Value::Number(n) => match n.as_i64() {
            Some(i) => host_duration_from_int(i).map_err(|e| ConfigError(e.0)),
            None => err("invalid duration"),
        },
        Value::String(s) => host_duration_secs(s).map_err(|e| ConfigError(e.0)),
        _ => err("invalid duration"),
    }
}

fn duration_u32(v: &Value, what: &str) -> Result<u32, ConfigError> {
    let secs = duration_secs(v).map_err(|e| ConfigError(format!("{what}: {e}")))?;
    u32::try_from(secs).map_err(|_| ConfigError(format!("{what}: too long")))
}

/// Where idle and lock state come from (`desktop.idle_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleSource {
    /// Only what `agent-auth-hostctl presence ...` reports.
    Hooks,
    /// logind's IdleHint/LockedHint.
    Logind,
    /// ioreg's HID idle time and console lock state.
    Macos,
}

/// Approval prompts on this host's desktop (hostd-user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopConfig {
    pub enable: bool,
    pub max_idle_secs: u64,
    pub prompt_command: Vec<String>,
    pub prompt_timeout_secs: u64,
    pub busy_command: Vec<String>,
    pub approve_user: bool,
    pub approve_root: bool,
    pub attention_command: Vec<String>,
    pub notify_command: Vec<String>,
    pub idle_source: IdleSource,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        DesktopConfig {
            enable: false,
            max_idle_secs: 300,
            prompt_command: Vec::new(),
            prompt_timeout_secs: 90,
            busy_command: Vec::new(),
            approve_user: false,
            approve_root: false,
            attention_command: Vec::new(),
            notify_command: Vec::new(),
            idle_source: IdleSource::Hooks,
        }
    }
}

/// The whole config.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub broker_url: BrokerUrl,
    pub broker_public_key: PublicKey,
    pub name: DaemonName,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    /// The account the user tier runs commands as (and whose desktop asks).
    pub user: Option<String>,
    pub policy: HostPolicy,
    pub vm_unit: Option<String>,
    pub job_path: String,
    pub systemd_run: String,
    pub systemctl: String,
    pub qrencode: String,
    pub pkcheck: String,
    pub desktop: DesktopConfig,
}

fn bool_at(map: &Map<String, Value>, key: &str, what: &str) -> Result<bool, ConfigError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => err(format!("{what}{key} must be true or false")),
    }
}

fn object<'a>(
    v: Option<&'a Value>,
    what: &str,
) -> Result<Option<&'a Map<String, Value>>, ConfigError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => err(format!("{what} must be an object")),
    }
}

fn only(map: &Map<String, Value>, keys: &[&str], what: &str) -> Result<(), ConfigError> {
    let unknown: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !keys.contains(k))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        err(format!("{what}unknown keys: {}", unknown.join(", ")))
    }
}

fn strings(v: Option<&Value>, what: &str) -> Result<Vec<String>, ConfigError> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| ConfigError(format!("{what} must be a list of strings")))
            })
            .collect(),
        Some(_) => err(format!("{what} must be a list of strings")),
    }
}

fn patterns(v: Option<&Value>, what: &str) -> Result<Vec<Vec<String>>, ConfigError> {
    let bad = || {
        ConfigError(format!(
            "{what}: a command pattern must be a non-empty list of strings"
        ))
    };
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|p| {
                let list = strings(Some(p), what).map_err(|_| bad())?;
                if list.is_empty() {
                    Err(bad())
                } else {
                    Ok(list)
                }
            })
            .collect(),
        Some(_) => Err(bad()),
    }
}

fn tier(v: Option<&Value>, name: &str) -> Result<TierPolicy, ConfigError> {
    let what = format!("tiers.{name}.");
    let mut t = TierPolicy::default();
    let Some(map) = object(v, &format!("tiers.{name}"))? else {
        return Ok(t);
    };
    only(
        map,
        &[
            "enable",
            "max_arm",
            "accept_approve_all",
            "accept_machine_approvals",
            "shell",
        ],
        &what,
    )?;
    t.enable = bool_at(map, "enable", &what)?;
    if let Some(v) = map.get("max_arm").filter(|v| !v.is_null()) {
        t.max_arm_secs = duration_u32(v, &format!("{what}max_arm"))?;
    }
    t.accept_approve_all = bool_at(map, "accept_approve_all", &what)?;
    t.accept_machine_approvals = bool_at(map, "accept_machine_approvals", &what)?;
    if let Some(shell) = object(map.get("shell"), &format!("{what}shell"))? {
        let w = format!("{what}shell.");
        only(shell, &["enable", "max_duration"], &w)?;
        t.shell_enable = bool_at(shell, "enable", &w)?;
        if let Some(v) = shell.get("max_duration").filter(|v| !v.is_null()) {
            t.shell_max_duration_secs = duration_u32(v, &format!("{w}max_duration"))?;
        }
    }
    Ok(t)
}

fn desktop(v: Option<&Value>) -> Result<DesktopConfig, ConfigError> {
    let mut d = DesktopConfig::default();
    let Some(map) = object(v, "desktop")? else {
        return Ok(d);
    };
    let w = "desktop.";
    only(
        map,
        &[
            "enable",
            "max_idle",
            "prompt_command",
            "prompt_timeout",
            "busy_command",
            "approve",
            "attention_command",
            "notify_command",
            "idle_source",
        ],
        w,
    )?;
    d.enable = bool_at(map, "enable", w)?;
    if let Some(v) = map.get("max_idle").filter(|v| !v.is_null()) {
        d.max_idle_secs = duration_secs(v)?;
    }
    if let Some(v) = map.get("prompt_timeout").filter(|v| !v.is_null()) {
        d.prompt_timeout_secs = duration_secs(v)?;
    }
    d.prompt_command = strings(map.get("prompt_command"), "desktop.prompt_command")?;
    d.busy_command = strings(map.get("busy_command"), "desktop.busy_command")?;
    d.attention_command = strings(map.get("attention_command"), "desktop.attention_command")?;
    d.notify_command = strings(map.get("notify_command"), "desktop.notify_command")?;
    if let Some(approve) = object(map.get("approve"), "desktop.approve")? {
        only(approve, &["user", "root"], "desktop.approve.")?;
        d.approve_user = bool_at(approve, "user", "desktop.approve.")?;
        d.approve_root = bool_at(approve, "root", "desktop.approve.")?;
    }
    // Anything else is "hooks", as in the Python.
    d.idle_source = match map.get("idle_source").and_then(Value::as_str) {
        Some("logind") => IdleSource::Logind,
        Some("macos") => IdleSource::Macos,
        _ => IdleSource::Hooks,
    };
    Ok(d)
}

const KEYS: &[&str] = &[
    "broker_url",
    "broker_public_key",
    "name",
    "state_dir",
    "runtime_dir",
    "user",
    "tiers",
    "auto_commands",
    "deny_commands",
    "templates",
    "env_allow",
    "vm_unit",
    "job_path",
    "default_timeout",
    "max_timeout",
    "systemd_run",
    "systemctl",
    "qrencode",
    "pkcheck",
    "desktop",
];

fn opt_string(map: &Map<String, Value>, key: &str) -> Result<Option<String>, ConfigError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => err(format!("{key} must be a string")),
    }
}

fn required(map: &Map<String, Value>, key: &str) -> Result<String, ConfigError> {
    opt_string(map, key)?.ok_or_else(|| ConfigError(format!("missing {key}")))
}

impl HostConfig {
    /// A config with no tier enabled (it only connects and reports).
    #[must_use]
    pub fn connect_only(
        broker_url: BrokerUrl,
        broker_public_key: PublicKey,
        name: DaemonName,
        state_dir: PathBuf,
    ) -> HostConfig {
        HostConfig {
            policy: HostPolicy::connect_only(name.as_str()),
            broker_url,
            broker_public_key,
            name,
            state_dir,
            runtime_dir: default_runtime_dir(),
            user: None,
            vm_unit: None,
            job_path: default_job_path(),
            systemd_run: "systemd-run".to_owned(),
            systemctl: "systemctl".to_owned(),
            qrencode: "qrencode".to_owned(),
            pkcheck: "pkcheck".to_owned(),
            desktop: DesktopConfig::default(),
        }
    }

    pub fn load(path: &Path) -> Result<HostConfig, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        let raw: Value =
            serde_json::from_str(&text).map_err(|e| ConfigError(format!("not JSON: {e}")))?;
        HostConfig::from_json(&raw, darwin())
    }

    /// Parse the module's JSON. `macos` applies the macOS refusals.
    pub fn from_json(raw: &Value, macos: bool) -> Result<HostConfig, ConfigError> {
        let Value::Object(map) = raw else {
            return err("the config must be a JSON object");
        };
        only(map, KEYS, "")?;
        let broker_url = BrokerUrl::parse(&required(map, "broker_url")?)
            .map_err(|e| ConfigError(e.to_string()))?;
        let broker_public_key = PublicKey::parse(&required(map, "broker_public_key")?)
            .map_err(|e| ConfigError(format!("broker_public_key: {e}")))?;
        let name_text = required(map, "name")?;
        let name = DaemonName::parse(&name_text).ok_or_else(|| {
            ConfigError("name must be a lowercase hostname label ([a-z0-9-], ≤63)".to_owned())
        })?;
        let tiers = object(map.get("tiers"), "tiers")?;
        if let Some(t) = tiers {
            only(t, &["user", "root"], "tiers.")?;
        }
        let mut policy = HostPolicy::connect_only(name.as_str());
        policy.user = tier(tiers.and_then(|t| t.get("user")), "user")?;
        policy.root = tier(tiers.and_then(|t| t.get("root")), "root")?;
        policy.auto_commands = patterns(map.get("auto_commands"), "auto_commands")?;
        policy.deny_commands = patterns(map.get("deny_commands"), "deny_commands")?;
        if let Some(templates) = object(map.get("templates"), "templates")? {
            let mut out = BTreeMap::new();
            for (tname, t) in templates {
                let tpl: Template = serde_json::from_value(t.clone())
                    .map_err(|e| ConfigError(format!("template {tname:?}: {e}")))?;
                out.insert(tname.clone(), tpl);
            }
            policy.templates = out;
        }
        if map.get("env_allow").is_some_and(|v| !v.is_null()) {
            policy.env_allow = strings(map.get("env_allow"), "env_allow")?
                .into_iter()
                .collect::<BTreeSet<_>>();
        }
        if let Some(v) = map.get("default_timeout").filter(|v| !v.is_null()) {
            policy.default_timeout_secs = duration_u32(v, "default_timeout")?;
        }
        if let Some(v) = map.get("max_timeout").filter(|v| !v.is_null()) {
            policy.max_timeout_secs = duration_u32(v, "max_timeout")?;
        }
        let desktop = desktop(map.get("desktop"))?;
        policy.desk_approve_user = desktop.approve_user;
        policy.desk_approve_root = desktop.approve_root;
        let user = opt_string(map, "user")?;
        let vm_unit = opt_string(map, "vm_unit")?;
        let config = HostConfig {
            state_dir: opt_string(map, "state_dir")?.map_or_else(default_state_dir, PathBuf::from),
            runtime_dir: opt_string(map, "runtime_dir")?
                .map_or_else(default_runtime_dir, PathBuf::from),
            job_path: opt_string(map, "job_path")?.unwrap_or_else(default_job_path),
            systemd_run: opt_string(map, "systemd_run")?.unwrap_or_else(|| "systemd-run".into()),
            systemctl: opt_string(map, "systemctl")?.unwrap_or_else(|| "systemctl".into()),
            qrencode: opt_string(map, "qrencode")?.unwrap_or_else(|| "qrencode".into()),
            pkcheck: opt_string(map, "pkcheck")?.unwrap_or_else(|| "pkcheck".into()),
            broker_url,
            broker_public_key,
            name,
            user,
            policy,
            vm_unit,
            desktop,
        };
        config.check(macos)?;
        Ok(config)
    }

    fn check(&self, macos: bool) -> Result<(), ConfigError> {
        if self.policy.user.enable && self.user.is_none() {
            return err("the user tier needs `user` (the account it runs commands as)");
        }
        if self.desktop.enable && self.user.is_none() {
            return err("the desktop needs `user` (whose desktop it is)");
        }
        if (self.desktop.approve_user || self.desktop.approve_root) && !self.desktop.enable {
            return err("desktop.approve needs desktop.enable");
        }
        if let Some(user) = &self.user
            && (user.is_empty() || user.contains(['/', ':', '\n', '\0']))
        {
            return err("user must be an account name");
        }
        if let Some(unit) = &self.vm_unit
            && (unit.is_empty() || unit.starts_with('-'))
        {
            return err("vm_unit must be a systemd unit name");
        }
        if macos {
            if self.vm_unit.is_some() {
                return err("vm_unit: there are no systemd units to freeze on macOS");
            }
            if self.desktop.approve_root {
                return err("desktop.approve.root needs polkit, which macOS does not have");
            }
            if self.desktop.idle_source == IdleSource::Logind {
                return err("desktop.idle_source \"logind\" is Linux; use \"macos\" or \"hooks\"");
            }
        }
        Ok(())
    }

    /// Whether this hostd does anything that needs root.
    #[must_use]
    pub fn privileged(&self) -> bool {
        self.policy.any_tier_enabled() || self.vm_unit.is_some()
    }

    #[must_use]
    pub fn totp_dir(&self) -> PathBuf {
        self.state_dir.join("totp")
    }

    #[must_use]
    pub fn ctl_socket(&self) -> PathBuf {
        self.runtime_dir.join("ctl.sock")
    }

    #[must_use]
    pub fn user_socket(&self) -> PathBuf {
        self.runtime_dir.join("user.sock")
    }

    #[must_use]
    pub fn key_path(&self) -> PathBuf {
        self.state_dir.join("key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn module_json() -> Value {
        json!({
            "broker_url": "https://broker.example",
            "broker_public_key": KEY,
            "name": "excelsior",
            "state_dir": "/var/lib/agent-auth-hostd",
            "runtime_dir": "/run/agent-auth-hostd",
            "user": "jrt",
            "tiers": {
                "user": {"enable": true, "max_arm": "8h", "accept_approve_all": true,
                         "accept_machine_approvals": false,
                         "shell": {"enable": true, "max_duration": "1h"}},
                "root": {"enable": true, "max_arm": "1h", "accept_approve_all": false,
                         "accept_machine_approvals": false,
                         "shell": {"enable": false, "max_duration": "30m"}}
            },
            "auto_commands": [["uptime"]],
            "deny_commands": [["rm", "**"]],
            "templates": {"rebuild": {"tier": "root", "argv": ["nixos-rebuild", "switch", "--flake", "{flake}"],
                                      "params": {"flake": "[a-z#:/.+-]+"}}},
            "env_allow": ["LANG"],
            "vm_unit": null,
            "job_path": "/run/wrappers/bin:/run/current-system/sw/bin",
            "default_timeout": "10m",
            "max_timeout": 3600,
            "systemd_run": "/nix/store/x/bin/systemd-run",
            "systemctl": "/nix/store/x/bin/systemctl",
            "qrencode": "qrencode",
            "pkcheck": "pkcheck",
            "desktop": {"enable": true, "max_idle": 300, "idle_source": "hooks",
                        "prompt_command": [], "prompt_timeout": "90s", "busy_command": [],
                        "approve": {"user": true, "root": false},
                        "attention_command": [], "notify_command": ["notify-send", "{title}", "{text}"]}
        })
    }

    #[test]
    fn host_config_loads_the_modules_json() {
        let c = HostConfig::from_json(&module_json(), false).unwrap();
        assert_eq!(c.name.as_str(), "excelsior");
        assert_eq!(c.policy.user.max_arm_secs, 8 * 3600);
        assert_eq!(c.policy.user.shell_max_duration_secs, 3600);
        assert_eq!(c.policy.root.shell_max_duration_secs, 1800);
        assert_eq!(c.policy.default_timeout_secs, 600);
        assert!(c.policy.templates.contains_key("rebuild"));
        assert!(c.policy.desk_approve_user && !c.policy.desk_approve_root);
        assert!(c.privileged());
        assert_eq!(
            c.ctl_socket(),
            PathBuf::from("/run/agent-auth-hostd/ctl.sock")
        );
    }

    #[test]
    fn bad_configs_are_refused() {
        let mut no_user = module_json();
        no_user["user"] = Value::Null;
        no_user["desktop"]["enable"] = json!(false);
        no_user["desktop"]["approve"] = json!({});
        assert!(
            HostConfig::from_json(&no_user, false)
                .unwrap_err()
                .0
                .contains("the user tier needs `user`")
        );
        let mut typo = module_json();
        typo["deny_comands"] = json!([["rm"]]);
        assert!(
            HostConfig::from_json(&typo, false)
                .unwrap_err()
                .0
                .contains("unknown keys")
        );
        let mut empty_pattern = module_json();
        empty_pattern["deny_commands"] = json!([[]]);
        assert!(HostConfig::from_json(&empty_pattern, false).is_err());
        let mut bad_regex = module_json();
        bad_regex["templates"]["rebuild"]["params"]["flake"] = json!("(");
        assert!(HostConfig::from_json(&bad_regex, false).is_err());
        let mut http = module_json();
        http["broker_url"] = json!("http://broker.example");
        assert!(HostConfig::from_json(&http, false).is_err());
    }

    #[test]
    fn macos_refuses_what_needs_systemd_or_polkit() {
        let mut vm = module_json();
        vm["vm_unit"] = json!("microvm@agents.service");
        assert!(HostConfig::from_json(&vm, false).is_ok());
        assert!(
            HostConfig::from_json(&vm, true)
                .unwrap_err()
                .0
                .contains("vm_unit")
        );
        let mut root = module_json();
        root["desktop"]["approve"]["root"] = json!(true);
        assert!(
            HostConfig::from_json(&root, true)
                .unwrap_err()
                .0
                .contains("polkit")
        );
        let mut logind = module_json();
        logind["desktop"]["idle_source"] = json!("logind");
        assert!(HostConfig::from_json(&logind, true).is_err());
        let mut macos = module_json();
        macos["desktop"]["idle_source"] = json!("macos");
        assert_eq!(
            HostConfig::from_json(&macos, true)
                .unwrap()
                .desktop
                .idle_source,
            IdleSource::Macos
        );
    }

    #[test]
    fn durations() {
        assert_eq!(duration_secs(&json!("8h")), Ok(28800));
        assert_eq!(duration_secs(&json!(90)), Ok(90));
        assert_eq!(duration_secs(&json!(" 2W ")), Ok(1_209_600));
        assert!(duration_secs(&json!("soon")).is_err());
        assert!(duration_secs(&json!(0)).is_err());
        assert!(duration_secs(&json!(true)).is_err());
    }

    #[test]
    fn defaults_by_platform() {
        if darwin() {
            assert_eq!(
                default_state_dir(),
                PathBuf::from("/var/db/agent-auth-hostd")
            );
        } else {
            assert_eq!(
                default_state_dir(),
                PathBuf::from("/var/lib/agent-auth-hostd")
            );
            assert_eq!(
                default_runtime_dir(),
                PathBuf::from("/run/agent-auth-hostd")
            );
            assert_eq!(
                default_job_path(),
                "/run/wrappers/bin:/run/current-system/sw/bin"
            );
        }
    }
}
