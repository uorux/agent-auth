//! The broker's URL as a daemon may use it (§4.1): `https://` with a host
//! name, or plain `http://` to a broker on this machine only. Envelopes are
//! signed, not encrypted: confidentiality is TLS's job.

use std::fmt;

/// A broker URL that passed [`BrokerUrl::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerUrl {
    url: url::Url,
    /// Without the trailing `/`, as configured.
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("broker URL must be https:// (plain http only for localhost): {0:?}")]
pub struct BadBrokerUrl(pub String);

const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

impl BrokerUrl {
    pub fn parse(text: &str) -> Result<BrokerUrl, BadBrokerUrl> {
        let bad = || BadBrokerUrl(text.to_owned());
        let url = url::Url::parse(text).map_err(|_| bad())?;
        let host = url.host_str().unwrap_or("");
        let ok = match url.scheme() {
            "https" => !host.is_empty(),
            "http" => LOOPBACK.contains(&host),
            _ => false,
        };
        if !ok || !url.username().is_empty() || url.password().is_some() {
            return Err(bad());
        }
        Ok(BrokerUrl {
            text: text.trim_end_matches('/').to_owned(),
            url,
        })
    }

    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.url.scheme() == "https"
    }

    /// The host name (for TLS), without brackets for IPv6.
    #[must_use]
    pub fn host(&self) -> String {
        self.url
            .host_str()
            .unwrap_or("")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port_or_known_default().unwrap_or(443)
    }

    /// `{url}/v1/daemons/pair`.
    #[must_use]
    pub fn pair_url(&self) -> String {
        format!("{}/v1/daemons/pair", self.text)
    }

    /// The channel: `wss://…/v1/daemons/connect` (`ws://` for loopback
    /// http).
    #[must_use]
    pub fn ws_url(&self) -> String {
        let rest = self
            .text
            .strip_prefix("https://")
            .map(|r| format!("wss://{r}"))
            .or_else(|| {
                self.text
                    .strip_prefix("http://")
                    .map(|r| format!("ws://{r}"))
            })
            .unwrap_or_else(|| self.text.clone());
        format!("{rest}/v1/daemons/connect")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for BrokerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_required_except_loopback_http() {
        assert!(BrokerUrl::parse("https://broker.example").is_ok());
        assert!(BrokerUrl::parse("http://localhost:8000").is_ok());
        assert!(BrokerUrl::parse("http://127.0.0.1:8000/").is_ok());
        assert!(BrokerUrl::parse("http://[::1]:8000").is_ok());
        for bad in [
            "http://broker.example",
            "http://10.0.0.1",
            "ftp://x",
            "https://",
            "nonsense",
            "http://localhost.evil.example",
            "https://user:pw@broker.example",
        ] {
            assert!(BrokerUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn channel_urls() {
        let u = BrokerUrl::parse("https://broker.example/base/").unwrap();
        assert_eq!(u.ws_url(), "wss://broker.example/base/v1/daemons/connect");
        assert_eq!(u.pair_url(), "https://broker.example/base/v1/daemons/pair");
        assert!(u.is_tls());
        assert_eq!(u.port(), 443);
        let l = BrokerUrl::parse("http://127.0.0.1:8123").unwrap();
        assert_eq!(l.ws_url(), "ws://127.0.0.1:8123/v1/daemons/connect");
        assert_eq!((l.host().as_str(), l.port()), ("127.0.0.1", 8123));
        assert_eq!(BrokerUrl::parse("http://[::1]:9").unwrap().host(), "::1");
    }
}
