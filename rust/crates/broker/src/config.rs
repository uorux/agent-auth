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
#[derive(Clone, Default)]
pub struct Env {
    vars: HashMap<String, String>,
}

/// Names only: the values include secrets.
impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<&String> = self.vars.keys().collect();
        keys.sort();
        f.debug_struct("Env")
            .field("keys", &keys)
            .finish_non_exhaustive()
    }
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

/// Hosts a plain-text URL may point at (as the daemons' `BrokerUrl`).
const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// The one rule for every outbound URL setting: an encrypted scheme
/// (`https`, `wss`, `ldaps`) to a named host, or its plain twin (`http`,
/// `ws`, `ldap`) only to this machine or to a host listed in
/// `PLAINTEXT_HTTP_HOSTS` (exact names). No credentials in the URL.
pub fn outbound_url(
    name: &str,
    text: &str,
    plaintext_hosts: &[String],
) -> Result<url::Url, ConfigError> {
    let bad = |why: &str| ConfigError(format!("{name} {text:?}: {why}"));
    let url = url::Url::parse(text.trim()).map_err(|_| bad("not a URL"))?;
    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(bad("no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad("credentials do not belong in the URL"));
    }
    match url.scheme() {
        "https" | "wss" | "ldaps" => Ok(url),
        "http" | "ws" | "ldap"
            if LOOPBACK.contains(&host) || plaintext_hosts.iter().any(|h| h == host) =>
        {
            Ok(url)
        }
        "http" | "ws" | "ldap" => Err(bad(
            "must be encrypted (https://, wss://, ldaps://); plain text only to localhost \
             or a host listed in PLAINTEXT_HTTP_HOSTS",
        )),
        _ => Err(bad("unsupported scheme")),
    }
}

fn loopback_host(url: &url::Url) -> bool {
    LOOPBACK.contains(&url.host_str().unwrap_or(""))
}

/// `DATABASE_URL`: a Unix socket or loopback, or TLS with the server's
/// certificate and name verified (`sslmode=verify-full`).
/// `DATABASE_ALLOW_INSECURE=1` lifts the rule (development only).
///
/// The URL is judged by what the store will connect to: it is parsed by
/// the parser the store uses (`PgConnectOptions::from_str`), so a later
/// `host=`, `hostaddr=`, `ssl-mode=`, a repeated `sslmode=` or a `PG*`
/// environment variable cannot make the checked host or mode differ from
/// the one used.
pub fn check_database_url(text: &str, allow_insecure: bool) -> Result<(), ConfigError> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    let options: PgConnectOptions = text
        .parse()
        .map_err(|_| ConfigError("DATABASE_URL is not a valid Postgres URL".to_owned()))?;
    let host = options.get_host();
    // The store connects over a Unix socket when one is set or the host is
    // a directory (sqlx's `fetch_socket`), else over TCP to `host`.
    let socket = options.get_socket().is_some() || host.starts_with('/');
    if socket || LOOPBACK.contains(&host) || host == "::1" {
        return Ok(());
    }
    if matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        return Ok(());
    }
    if allow_insecure {
        tracing::warn!(
            "!!! DATABASE_ALLOW_INSECURE is set: the database connection to {host} is not \
             verified TLS. Development only !!!"
        );
        return Ok(());
    }
    Err(ConfigError(format!(
        "DATABASE_URL: a database on {host:?} needs sslmode=verify-full (or a local socket); \
         set DATABASE_ALLOW_INSECURE=1 only for development"
    )))
}

/// Every transport setting, checked at load (one rule for all of them).
/// `PLAINTEXT_HTTP_HOSTS`: exact host names plain-text URLs may point at
/// (an in-cluster service without TLS). Each is logged at startup.
#[must_use]
pub fn plaintext_hosts(env: &Env) -> Vec<String> {
    env.string("PLAINTEXT_HTTP_HOSTS", "")
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

pub fn check_transport(env: &Env, config: &Config, policy: &Policy) -> Result<(), ConfigError> {
    let plain = plaintext_hosts(env);
    for h in &plain {
        tracing::warn!(host = %h, "PLAINTEXT_HTTP_HOSTS: outbound calls to this host may be unencrypted");
    }
    let outbound_url = |name: &str, text: &str| outbound_url(name, text, &plain);
    if let Some(t) = &config.admin_token
        && t.expose().chars().count() < 32
    {
        return Err(ConfigError(
            "ADMIN_TOKEN must be at least 32 characters".to_owned(),
        ));
    }
    check_database_url(
        config.database_url.expose(),
        env.flag("DATABASE_ALLOW_INSECURE", false)?,
    )?;
    outbound_url("OPENROUTER_BASE_URL", &config.openrouter_base_url)?;
    for key in [
        "DISCORD_API_URL",
        "DISCORD_GATEWAY_URL",
        "LLDAP_URL",
        "LLDAP_LDAP_URL",
        "GITHUB_API_URL",
        "GMAIL_API_URL",
    ] {
        if let Some(v) = env.get(key) {
            outbound_url(key, v)?;
        }
    }
    let mut k8s_loopback = true;
    if let Some(api) = env.get("KUBERNETES_API_URL")
        && api.trim() != "in-cluster"
    {
        for u in api.split(',').map(str::trim).filter(|u| !u.is_empty()) {
            let url = outbound_url("KUBERNETES_API_URL", u)?;
            k8s_loopback &= loopback_host(&url);
        }
    } else if env.get("KUBERNETES_API_URL").is_some() {
        k8s_loopback = false;
    }
    if env.flag("KUBERNETES_INSECURE_SKIP_VERIFY", false)? && !k8s_loopback {
        return Err(ConfigError(
            "KUBERNETES_INSECURE_SKIP_VERIFY is only for an API on localhost".to_owned(),
        ));
    }
    let models = &policy.platforms().models;
    for (key, v) in [
        ("platforms.models.url", Some(&models.url)),
        ("platforms.models.admin_url", models.admin_url.as_ref()),
    ] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            outbound_url(key, v)?;
        }
    }
    if policy.ui().enabled || policy.remote_mcp().enabled {
        outbound_url("ui.issuer", &policy.ui().issuer)?;
    }
    Ok(())
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
    /// New access requests per agent per hour (0: unlimited).
    pub requests_per_hour: u32,
    /// Concurrent decision long-polls per agent (0: unlimited).
    pub max_waits_per_agent: u32,
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
            requests_per_hour: env.number("REQUESTS_PER_AGENT_PER_HOUR", 60)?,
            max_waits_per_agent: env.number("MAX_WAITS_PER_AGENT", 16)?,
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
    fn outbound_urls_are_encrypted_unless_local() {
        for ok in [
            "https://openrouter.ai/api/v1",
            "wss://gateway.discord.gg",
            "ldaps://lldap.internal:6360",
            "http://127.0.0.1:8080",
            "ws://localhost:9",
            "ldap://[::1]:3890",
        ] {
            assert!(outbound_url("X", ok, &[]).is_ok(), "{ok}");
        }
        for bad in [
            "http://lldap.internal",
            "ws://gateway",
            "ldap://10.0.0.1",
            "ftp://x",
            "https://user:pw@host",
            "http://",
            "nope",
        ] {
            assert!(outbound_url("X", bad, &[]).is_err(), "{bad}");
        }
        // One setting lets plain text reach exactly the hosts it names.
        let listed = vec!["lldap".to_owned()];
        assert!(outbound_url("LLDAP_URL", "http://lldap:17170", &listed).is_ok());
        assert!(outbound_url("LLDAP_URL", "http://lldap.evil:17170", &listed).is_err());
        let env = Env::from_pairs([("PLAINTEXT_HTTP_HOSTS", " lldap, ,Gitea ")]);
        assert_eq!(
            plaintext_hosts(&env),
            vec!["lldap".to_owned(), "gitea".to_owned()]
        );
    }

    fn cfg(pairs: &[(&str, &str)]) -> (Env, Config) {
        let mut all = vec![("DATABASE_URL", "postgres://agent_auth@127.0.0.1/db")];
        all.extend_from_slice(pairs);
        let env = Env::from_pairs(all.iter().copied());
        let config = Config::from_env(&env).unwrap();
        (env, config)
    }

    #[test]
    fn transport_settings_are_checked_at_load() {
        let policy = Policy::default();
        let (env, c) = cfg(&[]);
        assert!(check_transport(&env, &c, &policy).is_ok());
        for (pairs, want) in [
            (
                vec![("ADMIN_TOKEN", "short")],
                "ADMIN_TOKEN must be at least 32 characters",
            ),
            (
                vec![("OPENROUTER_BASE_URL", "http://openrouter.example/api")],
                "OPENROUTER_BASE_URL",
            ),
            (vec![("LLDAP_URL", "http://lldap:17170")], "LLDAP_URL"),
            (
                vec![
                    ("LLDAP_URL", "http://lldap:17170"),
                    ("PLAINTEXT_HTTP_HOSTS", "gitea"),
                ],
                "LLDAP_URL",
            ),
            (
                vec![("KUBERNETES_API_URL", "http://k8s.internal:6443")],
                "KUBERNETES_API_URL",
            ),
            (
                vec![
                    ("KUBERNETES_API_URL", "https://k8s.internal:6443"),
                    ("KUBERNETES_INSECURE_SKIP_VERIFY", "1"),
                ],
                "KUBERNETES_INSECURE_SKIP_VERIFY",
            ),
            (
                vec![("DISCORD_GATEWAY_URL", "ws://gw.example")],
                "DISCORD_GATEWAY_URL",
            ),
        ] {
            let (env, c) = cfg(&pairs);
            let err = check_transport(&env, &c, &policy).unwrap_err().0;
            assert!(err.contains(want), "{err}");
        }
        let (env, c) = cfg(&[
            ("LLDAP_URL", "http://lldap:17170"),
            ("PLAINTEXT_HTTP_HOSTS", "lldap"),
            ("KUBERNETES_API_URL", "https://127.0.0.1:6443"),
            ("KUBERNETES_INSECURE_SKIP_VERIFY", "1"),
            ("ADMIN_TOKEN", "0123456789abcdef0123456789abcdef"),
        ]);
        assert!(check_transport(&env, &c, &policy).is_ok());
        // remote MCP on, panel off: the issuer is still checked.
        let p = Policy::from_yaml(
            "ui: {issuer: \"http://auth.example\", client_id: c}\nremote_mcp: {enabled: true, base_url: \"https://b.example\"}\n",
        )
        .unwrap();
        let (env, c) = cfg(&[]);
        assert!(
            check_transport(&env, &c, &p)
                .unwrap_err()
                .0
                .contains("ui.issuer")
        );
    }

    #[test]
    fn remote_databases_need_verified_tls() {
        assert!(check_database_url("postgres://u@127.0.0.1/db", false).is_ok());
        assert!(check_database_url("postgres://u@localhost/db", false).is_ok());
        assert!(check_database_url("postgres:///db?host=/run/postgresql", false).is_ok());
        // The NixOS module's default.
        assert!(
            check_database_url(
                "postgres://agent-auth@localhost/agent-auth?host=/run/postgresql",
                false
            )
            .is_ok()
        );
        assert!(
            check_database_url("postgres://u@db.internal/db?sslmode=verify-full", false).is_ok()
        );
        // Spellings sqlx accepts for verify-full count too.
        assert!(
            check_database_url("postgres://u@db.internal/db?ssl-mode=verify-full", false).is_ok()
        );
        for bad in [
            "postgres://u@db.internal/db",
            "postgres://u@db.internal/db?sslmode=require",
            // The checked host is the one connected to: a query `host` or
            // `hostaddr` overrides the URL's loopback host...
            "postgres://u@localhost/db?host=db.internal",
            "postgres://u@127.0.0.1/db?hostaddr=192.0.2.7",
            // ...and the last ssl mode wins, whatever its spelling.
            "postgres://u@db.internal/db?sslmode=verify-full&ssl-mode=disable",
            "postgres://u@db.internal/db?sslmode=verify-full&sslmode=prefer",
            "postgres://u@db.internal/db?sslmode=verify-full&ssl-mode=require",
        ] {
            assert!(check_database_url(bad, false).is_err(), "{bad}");
            assert!(check_database_url(bad, true).is_ok(), "{bad}");
        }
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
