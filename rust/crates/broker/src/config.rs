//! The broker's environment (core-lifecycle-policy §9.1): what the spine
//! reads. Other parts read their own variables (GitHub, LLDAP, Kubernetes,
//! Discord, a2a timeouts, daemons, the panel) through [`Env`], so a value
//! in `./.env` counts for them too.
//!
//! As in the Python, names are case-insensitive, process environment
//! variables win over `./.env`, and unknown variables are ignored.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use agent_auth_core::Policy;
use agent_auth_crypto::Secret;

/// The process environment over `./.env` (no `set_var`: that is `unsafe`
/// in this edition). Keys upper-cased.
#[derive(Debug, Clone, Default)]
pub struct Env {
    vars: HashMap<String, String>,
}

/// One `KEY=VALUE` line of a dotenv file (`export ` prefix, quotes and
/// comments as python-dotenv takes them in the simple cases).
fn dotenv_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    let value = value.trim();
    let value = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value.get(1..value.len().saturating_sub(1)).unwrap_or("")
    } else {
        value.split(" #").next().unwrap_or("").trim_end()
    };
    Some((key.to_uppercase(), value.to_owned()))
}

impl Env {
    /// The environment, with `./.env` (if any) under it.
    #[must_use]
    pub fn load() -> Env {
        let mut env = Env::from_dotenv(Path::new(".env"));
        for (k, v) in std::env::vars() {
            env.vars.insert(k.to_uppercase(), v);
        }
        env
    }

    fn from_dotenv(path: &Path) -> Env {
        let vars = std::fs::read_to_string(path)
            .map(|text| text.lines().filter_map(dotenv_line).collect())
            .unwrap_or_default();
        Env { vars }
    }

    /// From explicit pairs (tests).
    #[must_use]
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Env {
        Env {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.to_uppercase(), v.to_owned()))
                .collect(),
        }
    }

    /// The value, `None` when unset or empty.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars
            .get(&key.to_uppercase())
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    #[must_use]
    pub fn string(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_owned()
    }

    /// A number; a value that does not parse is an error naming the key.
    pub fn number<T: std::str::FromStr>(&self, key: &str, default: T) -> Result<T, ConfigError> {
        match self.get(key) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse()
                .map_err(|_| ConfigError(format!("{key}: not a number: {v:?}"))),
        }
    }

    /// pydantic's booleans: 1/0, true/false, yes/no, on/off.
    pub fn flag(&self, key: &str, default: bool) -> Result<bool, ConfigError> {
        match self.get(key).map(str::to_lowercase).as_deref() {
            None => Ok(default),
            Some("1" | "true" | "yes" | "on" | "y" | "t") => Ok(true),
            Some("0" | "false" | "no" | "off" | "n" | "f") => Ok(false),
            Some(v) => Err(ConfigError(format!("{key}: not a boolean: {v:?}"))),
        }
    }

    #[must_use]
    pub fn secret(&self, key: &str) -> Option<Secret<String>> {
        self.get(key).map(|v| Secret::new(v.to_owned()))
    }
}

/// A configuration the broker cannot start with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// What the spine reads.
#[derive(Debug)]
pub struct Config {
    /// PostgreSQL only.
    pub database_url: Secret<String>,
    pub policy_file: PathBuf,
    pub policy_overlays: Vec<PathBuf>,
    pub listen_host: String,
    pub listen_port: u16,
    /// Empty: the admin API answers 503.
    pub admin_token: Option<Secret<String>>,
    /// Needed by GitHub, models, the panel, remote MCP, managed LLDAP
    /// accounts and VM key delivery (their parts check it).
    pub encryption_key: Option<Secret<String>>,
    /// Empty: no LLM reviewer (`llm` routes go to a human), no risk lines.
    pub openrouter_api_key: Option<Secret<String>>,
    pub openrouter_base_url: String,
    /// The daemon channel is on (`BROKER_SIGNING_KEY` set): hostexec, so
    /// the risk summarizer has something to summarize.
    pub daemons_enabled: bool,
    pub log_level: String,
    /// Trust `X-Real-IP` for the security log (a reverse proxy that sets
    /// it is in front).
    pub trust_proxy_headers: bool,
}

impl Config {
    pub fn from_env(env: &Env) -> Result<Config, ConfigError> {
        let database_url = env.get("DATABASE_URL").ok_or_else(|| {
            ConfigError("DATABASE_URL is required (a postgres:// URL)".to_owned())
        })?;
        if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
            return Err(ConfigError(
                "DATABASE_URL must be a postgres:// URL (this broker runs on PostgreSQL only)"
                    .to_owned(),
            ));
        }
        Ok(Config {
            database_url: Secret::new(database_url.to_owned()),
            policy_file: PathBuf::from(env.string("POLICY_FILE", "policy.yaml")),
            policy_overlays: env
                .string("POLICY_OVERLAYS", "")
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .collect(),
            listen_host: env.string("LISTEN_HOST", "0.0.0.0"),
            listen_port: env.number("LISTEN_PORT", 8400)?,
            admin_token: env.secret("ADMIN_TOKEN"),
            encryption_key: env.secret("ENCRYPTION_KEY"),
            openrouter_api_key: env.secret("OPENROUTER_API_KEY"),
            openrouter_base_url: env.string("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            daemons_enabled: env.get("BROKER_SIGNING_KEY").is_some(),
            log_level: env.string("LOG_LEVEL", "INFO"),
            trust_proxy_headers: env.flag("TRUST_PROXY_HEADERS", false)?,
        })
    }

    /// The policy file with its overlays. A missing base file is an error
    /// (core B-12: the Python ran on built-in defaults), as is a missing
    /// overlay.
    pub fn load_policy(&self) -> Result<Policy, ConfigError> {
        let read = |path: &Path, what: &str| {
            std::fs::read_to_string(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ConfigError(format!("{what} {} is missing", path.display()))
                } else {
                    ConfigError(format!("{what} {}: {e}", path.display()))
                }
            })
        };
        let base = read(&self.policy_file, "policy file")?;
        let mut overlays = Vec::new();
        for path in &self.policy_overlays {
            overlays.push((path.display().to_string(), read(path, "policy overlay")?));
        }
        let refs: Vec<(&str, &str)> = overlays
            .iter()
            .map(|(l, t)| (l.as_str(), t.as_str()))
            .collect();
        Policy::load(&base, &refs)
            .map_err(|e| ConfigError(format!("policy {}: {e}", self.policy_file.display())))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reads_and_defaults() {
        let env = Env::from_pairs([
            ("database_url", "postgres://x@h/db"),
            ("POLICY_OVERLAYS", " a.yaml, ,b.yaml"),
            ("LISTEN_PORT", "9000"),
            ("TRUST_PROXY_HEADERS", "yes"),
        ]);
        let c = Config::from_env(&env).unwrap();
        assert_eq!(c.listen_port, 9000);
        assert_eq!(c.listen_host, "0.0.0.0");
        assert_eq!(
            c.policy_overlays,
            vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")]
        );
        assert!(c.trust_proxy_headers);
        assert!(c.admin_token.is_none());
        assert_eq!(c.openrouter_base_url, "https://openrouter.ai/api/v1");
        assert!(Config::from_env(&Env::default()).is_err());
        let sqlite = Env::from_pairs([("DATABASE_URL", "sqlite:///x.db")]);
        assert!(Config::from_env(&sqlite).is_err());
        let bad = Env::from_pairs([("DATABASE_URL", "postgres://h/d"), ("LISTEN_PORT", "x")]);
        assert_eq!(
            Config::from_env(&bad).unwrap_err().0,
            "LISTEN_PORT: not a number: \"x\""
        );
    }

    #[test]
    fn dotenv_lines() {
        assert_eq!(
            dotenv_line("export A=\"b c\""),
            Some(("A".to_owned(), "b c".to_owned()))
        );
        assert_eq!(
            dotenv_line("k=v # note"),
            Some(("K".to_owned(), "v".to_owned()))
        );
        assert_eq!(dotenv_line("# c"), None);
        assert_eq!(dotenv_line("novalue"), None);
    }

    #[test]
    fn a_missing_policy_file_refuses_to_start() {
        let env = Env::from_pairs([
            ("DATABASE_URL", "postgres://h/d"),
            ("POLICY_FILE", "/nonexistent/policy.yaml"),
        ]);
        let err = Config::from_env(&env).unwrap().load_policy().unwrap_err();
        assert_eq!(err.0, "policy file /nonexistent/policy.yaml is missing");
    }
}
