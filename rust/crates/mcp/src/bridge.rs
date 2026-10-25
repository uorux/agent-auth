//! `agent-auth-mcp-bridge <server>`: a catalogued MCP server (platform
//! `mcp`) as a local stdio MCP server, for clients that cannot refresh a
//! bearer token themselves.
//!
//! It passes JSON-RPC messages between stdin/stdout and the server's
//! streamable-HTTP endpoint, adding `Authorization: Bearer <token>` from the
//! agent's own grant and fetching a new token when the old one runs out. It
//! asks for nothing: without an active grant it says so, and the agent
//! requests one. It runs as the agent with the agent's own key, holds
//! nothing the agent could not fetch itself, and sends the token only to
//! the URL the broker's catalog gives for that server.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_auth_client::{BrokerClient, ClientError, pyjson};
use agent_auth_core::Platform;
use agent_auth_core::pyfmt::repr;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// A token is replaced this many seconds before it expires.
pub const REFRESH_SECS: i64 = 60;
const ACCEPT_BOTH: &str = "application/json, text/event-stream";
/// The most one upstream answer may be.
const MAX_UPSTREAM_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// Nothing to send: no such server in the catalog, or no active grant.
    #[error("{0}")]
    NoGrant(String),
    /// The broker refused or could not be reached.
    #[error("{0}")]
    Broker(#[from] ClientError),
    /// The server's side.
    #[error("{0}")]
    Upstream(String),
}

struct Token {
    value: agent_auth_wire::agent::CredentialValue,
    /// None: the broker gave no expiry; fetched again for every message
    /// (the Python crashed on it).
    expires_at: Option<OffsetDateTime>,
}

type Out = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

pub struct Bridge {
    server: String,
    broker: BrokerClient,
    upstream: reqwest::Client,
    url: tokio::sync::Mutex<Option<String>>,
    token: tokio::sync::Mutex<Option<Token>>,
    session_id: Mutex<Option<String>>,
    protocol: Mutex<Option<String>>,
    out: Out,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The upstream HTTP client: the shared TLS config, 300 s per call, 15 s to
/// connect.
pub fn upstream_client() -> Result<reqwest::Client, String> {
    let tls = agent_auth_tls::default_client_config().map_err(|e| e.to_string())?;
    agent_auth_tls::reqwest_builder(tls, Duration::from_secs(300))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())
}

impl Bridge {
    pub fn new(
        server: impl Into<String>,
        broker: BrokerClient,
        upstream: reqwest::Client,
        out: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> Self {
        Bridge {
            server: server.into(),
            broker,
            upstream,
            url: tokio::sync::Mutex::new(None),
            token: tokio::sync::Mutex::new(None),
            session_id: Mutex::new(None),
            protocol: Mutex::new(None),
            out: Arc::new(tokio::sync::Mutex::new(out)),
        }
    }

    /// The server's URL from the catalog (looked up once).
    pub async fn url(&self) -> Result<String, BridgeError> {
        let mut url = self.url.lock().await;
        if let Some(u) = url.as_ref() {
            return Ok(u.clone());
        }
        let catalog = self.broker.catalog().await?;
        let found = catalog
            .platforms
            .iter()
            .filter(|p| p.platform == Platform::Mcp)
            .flat_map(|p| p.servers.iter().flatten())
            .find(|s| s.name == self.server)
            .map(|s| s.url.clone());
        let Some(found) = found else {
            return Err(BridgeError::NoGrant(format!(
                "agent-auth has no MCP server {} in its catalog",
                repr(&self.server)
            )));
        };
        *url = Some(found.clone());
        Ok(found)
    }

    /// A token for the server: the cached one while it has more than a
    /// minute left (unless `fresh`), else one from the widest active grant
    /// for this server, then the one that lasts longest.
    pub async fn token(&self, fresh: bool) -> Result<String, BridgeError> {
        let mut cached = self.token.lock().await;
        if !fresh
            && let Some(t) = cached.as_ref()
            && let Some(expires) = t.expires_at
            && OffsetDateTime::now_utc()
                .checked_add(time::Duration::seconds(REFRESH_SECS))
                .is_some_and(|soon| soon < expires)
        {
            return Ok(t.value.expose().to_owned());
        }
        self.url().await?;
        let grants = self.broker.grants("active").await?;
        let best = grants
            .iter()
            .filter(|g| g.platform == Platform::Mcp && g.resource == self.server)
            .max_by_key(|g| (all_tools(g.scope.get("tools")), g.expires_at));
        let Some(grant) = best else {
            return Err(BridgeError::NoGrant(format!(
                "no active agent-auth grant for MCP server {}: ask with \
                 request_access(platform=\"mcp\", capability=\"use\", resource=\"{}\")",
                repr(&self.server),
                self.server
            )));
        };
        let credential = self.broker.credential(&grant.id.to_string()).await?;
        let Some(value) = credential.value else {
            return Err(BridgeError::NoGrant(format!(
                "agent-auth gave no token for MCP server {}",
                repr(&self.server)
            )));
        };
        let token = value.expose().to_owned();
        *cached = Some(Token {
            value,
            expires_at: credential.expires_at,
        });
        Ok(token)
    }

    async fn write(&self, message: &Value) {
        let Ok(mut line) = pyjson::dumps_compact(message) else {
            return;
        };
        line.push('\n');
        let mut out = self.out.lock().await;
        let _ = out.write_all(line.as_bytes()).await;
        let _ = out.flush().await;
    }

    /// One message from the client to the server; its answers (a JSON body,
    /// or an event stream) back to the client. A request always gets an
    /// answer: on failure, a JSON-RPC error.
    pub async fn forward(&self, message: &Value) {
        if let Err(e) = self.try_forward(message).await {
            let text = format!("agent-auth-mcp-bridge: {e}");
            match message.as_object() {
                Some(m) if m.contains_key("id") && m.contains_key("method") => {
                    let id = m.get("id").cloned().unwrap_or(Value::Null);
                    self.write(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": text}}))
                        .await;
                }
                _ => eprintln!("{text}"),
            }
        }
    }

    async fn try_forward(&self, message: &Value) -> Result<(), BridgeError> {
        let body = serde_json::to_vec(message).map_err(|e| BridgeError::Upstream(e.to_string()))?;
        let initialize = message.get("method").and_then(Value::as_str) == Some("initialize");
        for attempt in 0..2 {
            let token = self.token(attempt == 1).await?;
            let url = self.url().await?;
            let mut req = self
                .upstream
                .post(&url)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(ACCEPT, ACCEPT_BOTH)
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone());
            if let Some(sid) = lock(&self.session_id).clone() {
                req = req.header("Mcp-Session-Id", sid);
            }
            if let Some(version) = lock(&self.protocol).clone() {
                req = req.header("MCP-Protocol-Version", version);
            }
            let mut resp = req
                .send()
                .await
                .map_err(|e| BridgeError::Upstream(e.to_string()))?;
            let status = resp.status().as_u16();
            if status == 401 && attempt == 0 {
                continue; // the token ran out between the check and the call
            }
            if status >= 400 {
                let body = read_some(&mut resp, 4096).await;
                let text: String = String::from_utf8_lossy(&body).chars().take(300).collect();
                return Err(BridgeError::Upstream(format!(
                    "{} answered {status}: {text}",
                    self.server
                )));
            }
            if let Some(sid) = resp
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
            {
                *lock(&self.session_id) = Some(sid.to_owned());
            }
            let kind = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            if kind.starts_with("text/event-stream") {
                let mut events = SseParser::default();
                let mut total = 0usize;
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(|e| BridgeError::Upstream(e.to_string()))?
                {
                    total = total.saturating_add(chunk.len());
                    if total > MAX_UPSTREAM_BYTES {
                        return Err(BridgeError::Upstream(format!(
                            "{} answered too much",
                            self.server
                        )));
                    }
                    for event in events.feed(&chunk) {
                        self.relay(initialize, &event).await;
                    }
                }
                if let Some(event) = events.finish() {
                    self.relay(initialize, &event).await;
                }
            } else if kind.starts_with("application/json") {
                let body = read_some(&mut resp, MAX_UPSTREAM_BYTES).await;
                let answer: Value = serde_json::from_slice(&body)
                    .map_err(|e| BridgeError::Upstream(e.to_string()))?;
                self.relay(initialize, &answer).await;
            }
            return Ok(());
        }
        Ok(())
    }

    async fn relay(&self, initialize: bool, answer: &Value) {
        if initialize
            && let Some(version) = answer
                .get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(Value::as_str)
        {
            *lock(&self.protocol) = Some(version.to_owned());
        }
        self.write(answer).await;
    }

    /// Relay stdin to the server until EOF. `initialize` is forwarded in
    /// order (the session id comes from its answer); everything else runs
    /// concurrently, and all of it is finished before returning.
    pub async fn run<R: AsyncBufRead + Unpin>(self: Arc<Self>, mut input: R) {
        let mut tasks = tokio::task::JoinSet::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            match input.read_until(b'\n', &mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let Ok(message) = serde_json::from_str::<Value>(text) else {
                continue;
            };
            if message.get("method").and_then(Value::as_str) == Some("initialize") {
                self.forward(&message).await;
                continue;
            }
            let bridge = self.clone();
            tasks.spawn(async move { bridge.forward(&message).await });
        }
        while tasks.join_next().await.is_some() {}
    }
}

/// Whether a grant's `tools` scope is every tool: absent, null, empty, or
/// containing `*`.
fn all_tools(tools: Option<&Value>) -> bool {
    match tools {
        None | Some(Value::Null) => true,
        Some(Value::Array(a)) => a.is_empty() || a.iter().any(|t| t.as_str() == Some("*")),
        Some(_) => false,
    }
}

async fn read_some(resp: &mut reqwest::Response, max: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() >= max {
            body.truncate(max);
            break;
        }
    }
    body
}

/// The JSON messages of an event stream: each event's `data:` lines joined
/// with `\n`; events end at a blank line (and at the end of the stream);
/// events that are not JSON are skipped.
#[derive(Debug, Default)]
pub struct SseParser {
    pending: Vec<u8>,
    data: Vec<String>,
}

impl SseParser {
    /// Feed bytes; the messages completed by them.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Value> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let rest = self.pending.split_off(pos.saturating_add(1));
            let mut line = std::mem::replace(&mut self.pending, rest);
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line).into_owned();
            if let Some(data) = line.strip_prefix("data:") {
                self.data.push(data.trim_start().to_owned());
            } else if line.is_empty()
                && let Some(v) = self.take()
            {
                out.push(v);
            }
        }
        out
    }

    /// The stream ended: a last event without its blank line.
    pub fn finish(&mut self) -> Option<Value> {
        let rest = std::mem::take(&mut self.pending);
        let line = String::from_utf8_lossy(&rest).into_owned();
        if let Some(data) = line.trim_end_matches('\r').strip_prefix("data:") {
            self.data.push(data.trim_start().to_owned());
        }
        self.take()
    }

    fn take(&mut self) -> Option<Value> {
        if self.data.is_empty() {
            return None;
        }
        let joined = std::mem::take(&mut self.data).join("\n");
        serde_json::from_str(&joined).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_streams() {
        let mut p = SseParser::default();
        let mut got = p.feed(b"event: message\ndata: {\"a\":\ndata: 1}\n\nda");
        got.extend(p.feed(b"ta: not json\n\n"));
        got.extend(p.feed(b"data: {\"b\": 2}\r\n\r\ndata: [3]"));
        got.extend(p.finish());
        assert_eq!(got, vec![json!({"a": 1}), json!({"b": 2}), json!([3])]);
    }

    #[test]
    fn widest_grant() {
        assert!(all_tools(None));
        assert!(all_tools(Some(&json!(null))));
        assert!(all_tools(Some(&json!([]))));
        assert!(all_tools(Some(&json!(["a", "*"]))));
        assert!(!all_tools(Some(&json!(["navigate"]))));
    }
}
