//! The channel handshake, plain JSON text frames before any envelope
//! (daemon spec §4.2):
//!
//! ```text
//! broker → {"type":"challenge","nonce": bn}
//! daemon → {"type":"hello","role","name","nonce": dn,"params": P_d,"sig": S_d}
//! broker → {"type":"welcome","params": P_b,"sig": S_b}
//! ```
//!
//! `params` are JSON *strings* signed exactly as sent, so they stay text
//! here; [`HelloParams`] and [`WelcomeParams`] read what is inside.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common::DaemonRole;
use crate::text::{Base64Url, DaemonName, Text};

/// A nonce: 32 random bytes, base64url (43 characters).
pub type Nonce = Base64Url<64>;
/// An Ed25519 signature, base64url (86 characters).
pub type Signature = Base64Url<128>;
/// Signed params text.
pub type ParamsText = Text<0, 4096>;

/// What the broker sends before the channel is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BrokerHandshake {
    #[serde(rename = "challenge")]
    Challenge(Challenge),
    #[serde(rename = "welcome")]
    Welcome(Welcome),
}

/// What the daemon sends before the channel is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonHandshake {
    #[serde(rename = "hello")]
    Hello(Hello),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: Nonce,
}

/// Anything wrong with it (a missing key, a bad role or name) closes the
/// connection with 4400 "bad hello".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub role: DaemonRole,
    pub name: DaemonName,
    pub nonce: Nonce,
    /// `{"version": "<daemon version>"}` as JSON text.
    pub params: ParamsText,
    /// Over `("daemon", role, name, bn, dn, params)`.
    pub sig: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    /// `{"heartbeat_secs": N}` as JSON text.
    pub params: ParamsText,
    /// Over `("broker", role, name, bn, dn, params)`.
    pub sig: Signature,
}

/// Inside a hello's `params`. Read leniently: the field is informational,
/// and a newer daemon may say more.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HelloParams {
    #[serde(default)]
    pub version: Option<Value>,
}

impl HelloParams {
    /// The daemon's version, if it is a plain version string
    /// (`[0-9A-Za-z.+_-]{1,64}`); anything else is not recorded.
    #[must_use]
    pub fn from_text(text: &str) -> Option<String> {
        let params: HelloParams = serde_json::from_str(text).ok()?;
        match params.version {
            Some(Value::String(v)) if version_ok(&v) => Some(v),
            _ => None,
        }
    }
}

/// A version string the broker records and shows.
#[must_use]
pub fn version_ok(v: &str) -> bool {
    (1..=64).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'_' | b'-'))
}

/// Inside a welcome's `params`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct WelcomeParams {
    #[serde(default)]
    pub heartbeat_secs: Option<Value>,
}

impl WelcomeParams {
    /// The heartbeat interval a daemon uses: the broker's, clamped to
    /// 5..=300 seconds; 30 when absent or unreadable.
    #[must_use]
    pub fn heartbeat_secs(text: &str) -> u64 {
        let Ok(params) = serde_json::from_str::<WelcomeParams>(text) else {
            return 30;
        };
        let secs = match params.heartbeat_secs {
            None => Some(30),
            Some(Value::Number(n)) => n
                .as_i64()
                .or_else(|| n.as_f64().filter(|f| f.is_finite()).map(truncate)),
            Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
            Some(_) => None,
        };
        secs.map_or(30, |s| u64::try_from(s.clamp(5, 300)).unwrap_or(30))
    }
}

/// `int(x)` for a finite float, saturating.
fn truncate(f: f64) -> i64 {
    let t = f.trunc();
    if t >= 9.2e18 {
        i64::MAX
    } else if t <= -9.2e18 {
        i64::MIN
    } else {
        // In range and integral: the decimal text parses exactly.
        format!("{t:.0}").parse().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_interval() {
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": 30}"#),
            30
        );
        assert_eq!(WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": 1}"#), 5);
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": 9999}"#),
            300
        );
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": 45.9}"#),
            45
        );
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": "60"}"#),
            60
        );
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": null}"#),
            30
        );
        assert_eq!(WelcomeParams::heartbeat_secs(r#"{}"#), 30);
        assert_eq!(WelcomeParams::heartbeat_secs("nope"), 30);
        assert_eq!(
            WelcomeParams::heartbeat_secs(r#"{"heartbeat_secs": 1e300}"#),
            300
        );
    }

    #[test]
    fn versions() {
        assert_eq!(
            HelloParams::from_text(r#"{"version": "0.4.1+nix"}"#).as_deref(),
            Some("0.4.1+nix")
        );
        assert_eq!(HelloParams::from_text(r#"{"version": "a b"}"#), None);
        assert_eq!(HelloParams::from_text(r#"{"version": 3}"#), None);
        assert_eq!(HelloParams::from_text("x"), None);
    }
}
