//! Outbound HTTP for the provisioners and the wiki: one client per upstream
//! on the shared TLS configuration (`agent_auth_tls`: no proxy from the
//! environment, no redirects, no compression), a timeout on every call, and
//! response bodies read up to a bound.

use std::time::Duration;

use reqwest::{Method, RequestBuilder};
use serde_json::Value;

use super::setup::ConfigError;

/// Responses larger than this are refused (upstream answers are small).
pub const MAX_BODY: usize = 4 << 20;

/// A client for one upstream.
#[derive(Debug, Clone)]
pub struct Http {
    client: reqwest::Client,
}

impl Http {
    /// A client with the shared TLS roots.
    pub fn new() -> Result<Http, ConfigError> {
        let tls = agent_auth_tls::default_client_config()
            .map_err(|e| ConfigError(format!("TLS client configuration: {e}")))?;
        Http::with_tls(tls)
    }

    /// A client with this TLS configuration (e.g. a cluster's own CA).
    pub fn with_tls(tls: rustls::ClientConfig) -> Result<Http, ConfigError> {
        let client = agent_auth_tls::reqwest_builder(tls, Duration::from_secs(30))
            .build()
            .map_err(|e| ConfigError(format!("HTTP client: {e}")))?;
        Ok(Http { client })
    }

    pub fn request(&self, method: Method, url: &str) -> RequestBuilder {
        self.client.request(method, url)
    }
}

/// `url` with `query` appended, form-encoded (reqwest's `query` needs a
/// feature this workspace leaves off).
#[must_use]
pub fn with_query(url: &str, query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return url.to_owned();
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    format!("{url}?{encoded}")
}

/// A transport failure, or a body over the bound. The text carries no URL
/// (and so no query string).
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Transport(reqwest::Error),
    #[error("response too large")]
    TooLarge,
}

/// An upstream's answer: its status and (bounded) body.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    /// The body as JSON (`Value::Null` when it is not JSON).
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The first `n` characters of the body, for the broker's log.
    #[must_use]
    pub fn head(&self, n: usize) -> String {
        super::common::head(&self.body, n)
    }

    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Send with `timeout`, and read at most `max` bytes of the answer.
pub async fn send(rb: RequestBuilder, timeout: Duration, max: usize) -> Result<Reply, HttpError> {
    let mut resp = rb
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| HttpError::Transport(e.without_url()))?;
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| HttpError::Transport(e.without_url()))?
    {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(HttpError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply { status, body })
}
