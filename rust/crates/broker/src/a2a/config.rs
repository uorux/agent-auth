//! a2a settings (a2a spec §1.4), read from the environment.

use agent_auth_crypto::Secret;
use time::Duration;

/// Environment settings and their defaults.
#[derive(Debug)]
pub struct A2aConfig {
    /// `A2A_RELAY_ENABLED` (default true): false → every `/v1/a2a/*` and
    /// `/admin/chat/*` route answers 404 `a2a is disabled on this broker`.
    pub enabled: bool,
    /// `WEBHOOK_SIGNING_SECRET`: the HMAC key for pings to agents without
    /// their own secret. Unset or empty: such pings are not sent.
    pub webhook_signing_secret: Option<Secret<String>>,
    /// `A2A_WEBHOOK_HTTP_HOSTS`: comma-separated host names (or IPs) to which
    /// a webhook may use plain `http`. Every other webhook must be `https`.
    pub webhook_http_hosts: Vec<String>,
    /// `A2A_OPEN_TIMEOUT_SECS` (600).
    pub open_timeout: Duration,
    /// `A2A_THREAD_IDLE_TIMEOUT_SECS` (3600).
    pub thread_idle_timeout: Duration,
    /// `SESSION_IDLE_TIMEOUT_SECS` (900).
    pub session_idle_timeout: Duration,
    /// `LIVENESS_THRESHOLD_SECS` (120): `peer_alive`.
    pub liveness_threshold: Duration,
    /// `A2A_LISTEN_THRESHOLD_SECS` (300): `reachable` on `last_listen_at`.
    pub listen_threshold: Duration,
}

impl Default for A2aConfig {
    fn default() -> Self {
        A2aConfig {
            enabled: true,
            webhook_signing_secret: None,
            webhook_http_hosts: Vec::new(),
            open_timeout: Duration::seconds(600),
            thread_idle_timeout: Duration::seconds(3600),
            session_idle_timeout: Duration::seconds(900),
            liveness_threshold: Duration::seconds(120),
            listen_threshold: Duration::seconds(300),
        }
    }
}

fn boolean(name: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "t" | "y" => Ok(true),
        "0" | "false" | "no" | "off" | "f" | "n" => Ok(false),
        _ => Err(format!("{name} must be a boolean")),
    }
}

fn seconds(name: &str, value: &str) -> Result<Duration, String> {
    match value.trim().parse::<u32>() {
        Ok(n) if n > 0 => Ok(Duration::seconds(i64::from(n))),
        _ => Err(format!("{name} must be a positive number of seconds")),
    }
}

impl A2aConfig {
    /// From the process environment.
    pub fn from_env() -> Result<A2aConfig, String> {
        A2aConfig::from_lookup(|k| std::env::var(k).ok())
    }

    /// From any lookup (tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<A2aConfig, String> {
        let mut c = A2aConfig::default();
        if let Some(v) = get("A2A_RELAY_ENABLED") {
            c.enabled = boolean("A2A_RELAY_ENABLED", &v)?;
        }
        c.webhook_signing_secret = get("WEBHOOK_SIGNING_SECRET")
            .filter(|s| !s.is_empty())
            .map(Secret::new);
        c.webhook_http_hosts = get("A2A_WEBHOOK_HTTP_HOSTS")
            .map(|v| {
                v.split(',')
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        for (name, field) in [
            ("A2A_OPEN_TIMEOUT_SECS", &mut c.open_timeout),
            ("A2A_THREAD_IDLE_TIMEOUT_SECS", &mut c.thread_idle_timeout),
            ("SESSION_IDLE_TIMEOUT_SECS", &mut c.session_idle_timeout),
            ("LIVENESS_THRESHOLD_SECS", &mut c.liveness_threshold),
            ("A2A_LISTEN_THRESHOLD_SECS", &mut c.listen_threshold),
        ] {
            if let Some(v) = get(name) {
                *field = seconds(name, &v)?;
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides() {
        let c = A2aConfig::from_lookup(|_| None).unwrap();
        assert!(c.enabled);
        assert_eq!(c.listen_threshold, Duration::seconds(300));
        let c = A2aConfig::from_lookup(|k| match k {
            "A2A_RELAY_ENABLED" => Some("false".into()),
            "A2A_WEBHOOK_HTTP_HOSTS" => Some(" Hooks.Internal ,127.0.0.1,".into()),
            "SESSION_IDLE_TIMEOUT_SECS" => Some("60".into()),
            "WEBHOOK_SIGNING_SECRET" => Some(String::new()),
            _ => None,
        })
        .unwrap();
        assert!(!c.enabled);
        assert_eq!(c.webhook_http_hosts, ["hooks.internal", "127.0.0.1"]);
        assert_eq!(c.session_idle_timeout, Duration::seconds(60));
        assert!(c.webhook_signing_secret.is_none());
        assert!(
            A2aConfig::from_lookup(|k| (k == "A2A_OPEN_TIMEOUT_SECS").then(|| "0".into())).is_err()
        );
        assert!(
            A2aConfig::from_lookup(|k| (k == "A2A_RELAY_ENABLED").then(|| "maybe".into())).is_err()
        );
    }
}
