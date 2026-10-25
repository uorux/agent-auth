//! The daemon side of the broker channel (§4): a self-reconnecting signed
//! WebSocket that sends heartbeats and hands verified broker messages to a
//! [`Handler`].
//!
//! Every connection starts with the hello ([`agent_auth_crypto::daemon::hello`]);
//! only a welcome signed by the **pinned** broker key yields the envelope
//! sealer and verifier for the connection. A message that fails
//! verification ends the connection (the daemon reconnects); nothing the
//! broker (or anyone posing as it) sends ends the daemon.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_crypto::daemon::{
    DEFAULT_ENVELOPE_TTL_SECS, DaemonId, EnvelopeSealer, EnvelopeVerifier, Handshake, Nonce,
    PublicKey, SigningKey, Speaker,
};
use agent_auth_wire::daemon::handshake::WelcomeParams;
use futures::SinkExt as _;
use futures::stream::{SplitSink, StreamExt as _};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::stream::{self, Stream};
use crate::url::BrokerUrl;

/// Waiting for the broker's challenge and welcome, and for the connection.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The longest wait between reconnection attempts after network errors.
pub const MAX_BACKOFF_SECS: f64 = 60.0;
/// Not paired, or the key was replaced: retrying quickly can't help until
/// an admin acts.
pub const REJECTED_BACKOFF_SECS: f64 = 300.0;
/// Protocol pings; a broker silent for two intervals is dropped.
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
/// The broker closes with this when it does not know us.
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// Frames above this are refused (the largest real one is a 96 KiB output
/// chunk inside an envelope, about 175 KB).
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Who this daemon is, and the broker it trusts.
#[derive(Debug)]
pub struct Identity {
    pub id: DaemonId,
    key: SigningKey,
    pub broker_url: BrokerUrl,
    /// Pinned in the daemon's own config, never learned from the network.
    pub broker_key: PublicKey,
}

impl Identity {
    #[must_use]
    pub fn new(
        id: DaemonId,
        key: SigningKey,
        broker_url: BrokerUrl,
        broker_key: PublicKey,
    ) -> Identity {
        Identity {
            id,
            key,
            broker_url,
            broker_key,
        }
    }

    #[must_use]
    pub fn principal(&self) -> String {
        self.id.principal()
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub(crate) fn key(&self) -> &SigningKey {
        &self.key
    }
}

/// What a daemon does with the channel.
pub trait Handler: Send + Sync + 'static {
    /// The heartbeat's `status` (informational; the broker never decides on
    /// it). Sampled on connect and every heartbeat interval.
    fn status(&self) -> Map<String, Value>;

    /// A verified message from the broker: the envelope body (its six
    /// envelope keys included). Handled inline, in order: a slow handler
    /// delays the messages after it.
    fn on_message(&self, body: Map<String, Value>) -> impl Future<Output = ()> + Send;
}

/// Why a connection attempt ended.
#[derive(Debug)]
enum Outcome {
    /// A session ran (then ended for whatever reason).
    SessionEnded(String),
    /// The broker refused us, or did not prove the pinned key.
    Rejected(String),
    /// Network or protocol failure before the session.
    Failed(String),
}

struct Conn {
    sink: SplitSink<WebSocketStream<Stream>, Message>,
    sealer: EnvelopeSealer,
}

struct Inner {
    identity: Identity,
    version: String,
    tls: Arc<rustls::ClientConfig>,
    conn: Mutex<Option<Conn>>,
    connected: watch::Sender<bool>,
}

/// The channel. Cloning gives another handle to the same connection (for
/// sending from handlers and background tasks).
#[derive(Clone)]
pub struct Channel {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("daemon", &self.inner.identity.principal())
            .finish_non_exhaustive()
    }
}

/// `json.dumps({"version": v})`: what a Python daemon sends and signs.
fn hello_params(version: &str) -> String {
    let v = serde_json::to_string(version).unwrap_or_else(|_| "\"\"".to_owned());
    format!("{{\"version\": {v}}}")
}

/// A random factor in [0.8, 1.2) for reconnect jitter (not security
/// relevant: spreads reconnects out).
fn jitter() -> f64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    0.8 + 0.4 * f64::from(nanos % 1000) / 1000.0
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES))
        .max_frame_size(Some(MAX_FRAME_BYTES))
}

fn close_code(msg: &Message) -> Option<u16> {
    match msg {
        Message::Close(Some(frame)) => Some(u16::from(frame.code)),
        _ => None,
    }
}

impl Channel {
    #[must_use]
    pub fn new(identity: Identity, version: &str, tls: Arc<rustls::ClientConfig>) -> Channel {
        let (connected, _) = watch::channel(false);
        Channel {
            inner: Arc::new(Inner {
                identity,
                version: version.to_owned(),
                tls,
                conn: Mutex::new(None),
                connected,
            }),
        }
    }

    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.inner.identity
    }

    /// True while a verified session is up.
    #[must_use]
    pub fn connected(&self) -> watch::Receiver<bool> {
        self.inner.connected.subscribe()
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        *self.inner.connected.borrow()
    }

    /// Seal and send one message (default lifetime). False when not
    /// connected or the send failed.
    pub async fn send(&self, payload: &Map<String, Value>) -> bool {
        self.send_ttl(payload, DEFAULT_ENVELOPE_TTL_SECS).await
    }

    /// Seal and send with a lifetime. Sealing and sending happen under one
    /// lock, so the wire order is the sequence order.
    pub async fn send_ttl(&self, payload: &Map<String, Value>, ttl_secs: f64) -> bool {
        let mut guard = self.inner.conn.lock().await;
        let Some(conn) = guard.as_mut() else {
            return false;
        };
        let text = match conn.sealer.seal_now(payload, ttl_secs) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "could not seal a message for the broker");
                return false;
            }
        };
        conn.sink.send(Message::text(text)).await.is_ok()
    }

    /// Hold the connection until the task is dropped, reconnecting with
    /// backoff: network errors double the wait (1 s up to 60 s), a refusal
    /// waits 5 minutes, and a session that ran resets it (daemons bug 15:
    /// the Python slept a stale backoff after a session that had
    /// succeeded).
    pub async fn run<H: Handler>(&self, handler: Arc<H>) {
        let mut backoff = 1.0f64;
        loop {
            let delay = match self.connect_once(&handler).await {
                Outcome::SessionEnded(why) => {
                    tracing::warn!("broker connection ended: {why}");
                    backoff = 1.0;
                    1.0
                }
                Outcome::Rejected(why) => {
                    tracing::error!("broker handshake failed: {why}");
                    REJECTED_BACKOFF_SECS
                }
                Outcome::Failed(why) => {
                    tracing::warn!("broker connection failed: {why}");
                    let d = backoff;
                    backoff = (backoff * 2.0).min(MAX_BACKOFF_SECS);
                    d
                }
            };
            tokio::time::sleep(Duration::from_secs_f64(delay * jitter())).await;
        }
    }

    async fn connect_once<H: Handler>(&self, handler: &Arc<H>) -> Outcome {
        let ident = &self.inner.identity;
        let stream =
            match stream::connect(&ident.broker_url, &self.inner.tls, HANDSHAKE_TIMEOUT).await {
                Ok(s) => s,
                Err(e) => return Outcome::Failed(e.to_string()),
            };
        let url = ident.broker_url.ws_url();
        let upgrade = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(url.as_str(), stream, Some(ws_config())),
        )
        .await;
        let mut ws = match upgrade {
            Ok(Ok((ws, _))) => ws,
            Ok(Err(e)) => return Outcome::Failed(e.to_string()),
            Err(_) => return Outcome::Failed("websocket upgrade timed out".to_owned()),
        };
        let (heartbeat_secs, sealer, verifier) =
            match handshake(&mut ws, ident, &self.inner.version).await {
                Ok(v) => v,
                Err(o) => return o,
            };
        tracing::info!(daemon = %ident.principal(), "connected to the broker");
        let why = self
            .session(ws, sealer, verifier, heartbeat_secs, handler)
            .await;
        Outcome::SessionEnded(why)
    }

    async fn session<H: Handler>(
        &self,
        ws: WebSocketStream<Stream>,
        sealer: EnvelopeSealer,
        mut verifier: EnvelopeVerifier,
        heartbeat_secs: u64,
        handler: &Arc<H>,
    ) -> String {
        let (sink, mut stream) = ws.split();
        *self.inner.conn.lock().await = Some(Conn { sink, sealer });
        self.inner.connected.send_replace(true);
        let heartbeats = {
            let channel = self.clone();
            let handler = Arc::clone(handler);
            tokio::spawn(async move {
                loop {
                    let mut status = handler.status();
                    status
                        .entry("version")
                        .or_insert_with(|| Value::String(channel.inner.version.clone()));
                    let mut msg = Map::new();
                    msg.insert("type".into(), Value::String("heartbeat".into()));
                    msg.insert("status".into(), Value::Object(status));
                    channel.send(&msg).await;
                    tokio::time::sleep(Duration::from_secs(heartbeat_secs)).await;
                }
            })
        };
        let mut last_rx = Instant::now();
        let why = loop {
            let next = tokio::time::timeout(PING_INTERVAL, stream.next()).await;
            let msg = match next {
                Err(_) => {
                    if last_rx.elapsed() >= PING_INTERVAL.saturating_mul(2) {
                        break "the broker stopped answering".to_owned();
                    }
                    let mut guard = self.inner.conn.lock().await;
                    if let Some(conn) = guard.as_mut()
                        && conn
                            .sink
                            .send(Message::Ping(Vec::new().into()))
                            .await
                            .is_err()
                    {
                        break "ping failed".to_owned();
                    }
                    continue;
                }
                Ok(None) => break "closed".to_owned(),
                Ok(Some(Err(e))) => break e.to_string(),
                Ok(Some(Ok(m))) => m,
            };
            last_rx = Instant::now();
            match msg {
                Message::Text(text) => match verifier.open_now(text.as_bytes()) {
                    Ok(body) => handler.on_message(body).await,
                    Err(e) => break format!("refusing a broker message ({e}); reconnecting"),
                },
                Message::Binary(_) => break "unexpected binary frame".to_owned(),
                Message::Close(frame) => {
                    break format!(
                        "closed by the broker ({})",
                        frame.map_or_else(String::new, |f| format!(
                            "{} {}",
                            u16::from(f.code),
                            f.reason
                        ))
                    );
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        };
        heartbeats.abort();
        if let Some(mut conn) = self.inner.conn.lock().await.take() {
            let _ = conn.sink.close().await;
        }
        self.inner.connected.send_replace(false);
        why
    }
}

async fn recv_text(ws: &mut WebSocketStream<Stream>, ident: &Identity) -> Result<String, Outcome> {
    loop {
        let next = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws.next())
            .await
            .map_err(|_| Outcome::Rejected("malformed handshake: timed out".to_owned()))?;
        match next {
            None => return Err(Outcome::Failed("closed during the handshake".to_owned())),
            Some(Err(e)) => return Err(Outcome::Failed(e.to_string())),
            Some(Ok(Message::Text(t))) => return Ok(t.as_str().to_owned()),
            Some(Ok(m @ Message::Close(_))) => {
                return Err(if close_code(&m) == Some(CLOSE_UNAUTHORIZED) {
                    Outcome::Rejected(format!(
                        "broker does not recognize {} (not paired, or re-paired with another \
                         key) — run `pair` with a new code",
                        ident.principal()
                    ))
                } else {
                    Outcome::Failed(format!(
                        "closed during the handshake ({})",
                        close_code(&m).unwrap_or(0)
                    ))
                });
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
            Some(Ok(Message::Binary(_))) => {
                return Err(Outcome::Rejected(
                    "malformed handshake: binary frame".to_owned(),
                ));
            }
        }
    }
}

fn malformed(why: &str) -> Outcome {
    Outcome::Rejected(format!("malformed handshake: {why}"))
}

/// challenge → hello → welcome. Returns the heartbeat interval and the
/// connection's sealer and verifier (only from a welcome that verified
/// under the pinned broker key).
async fn handshake(
    ws: &mut WebSocketStream<Stream>,
    ident: &Identity,
    version: &str,
) -> Result<(u64, EnvelopeSealer, EnvelopeVerifier), Outcome> {
    let first = recv_text(ws, ident).await?;
    let challenge: Value =
        serde_json::from_str(&first).map_err(|_| malformed("unexpected first message"))?;
    if challenge.get("type").and_then(Value::as_str) != Some("challenge") {
        return Err(malformed("unexpected first message"));
    }
    let broker_nonce = challenge
        .get("nonce")
        .and_then(Value::as_str)
        .and_then(Nonce::parse)
        .ok_or_else(|| malformed("unexpected first message"))?;
    let daemon_nonce = Nonce::generate().map_err(|e| Outcome::Failed(e.to_string()))?;
    let hs = Handshake::new(ident.id.clone(), broker_nonce, daemon_nonce.clone());
    let params = hello_params(version);
    let sig = hs
        .sign(ident.key(), Speaker::Daemon, &params)
        .map_err(|e| Outcome::Failed(e.to_string()))?;
    let hello = serde_json::json!({
        "type": "hello",
        "role": ident.id.role.as_str(),
        "name": ident.id.name.as_str(),
        "nonce": daemon_nonce.as_str(),
        "params": params,
        "sig": sig,
    });
    ws.send(Message::text(hello.to_string()))
        .await
        .map_err(|e| Outcome::Failed(e.to_string()))?;
    let second = recv_text(ws, ident).await?;
    let welcome: Value =
        serde_json::from_str(&second).map_err(|_| malformed("welcome is not an object"))?;
    if !welcome.is_object() {
        return Err(malformed("welcome is not an object"));
    }
    let not_proven =
        || Outcome::Rejected("broker did not prove possession of the pinned key".into());
    if welcome.get("type").and_then(Value::as_str) != Some("welcome") {
        return Err(not_proven());
    }
    let (Some(broker_params), Some(broker_sig)) = (
        welcome.get("params").and_then(Value::as_str),
        welcome.get("sig").and_then(Value::as_str),
    ) else {
        return Err(not_proven());
    };
    let verified = hs
        .verify(
            &ident.broker_key,
            Speaker::Broker,
            broker_params,
            broker_sig,
        )
        .map_err(|_| not_proven())?;
    let heartbeat = WelcomeParams::heartbeat_secs(broker_params);
    let (sealer, verifier) = verified.into_channel(ident.key());
    Ok((heartbeat, sealer, verifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_params_match_python() {
        assert_eq!(hello_params("0.1.0"), r#"{"version": "0.1.0"}"#);
        assert_eq!(hello_params("a\"b"), r#"{"version": "a\"b"}"#);
    }

    #[test]
    fn jitter_is_bounded() {
        for _ in 0..100 {
            let j = jitter();
            assert!((0.8..1.2).contains(&j));
        }
    }

    #[test]
    fn close_codes() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
        let m = Message::Close(Some(CloseFrame {
            code: CloseCode::from(4401),
            reason: "x".into(),
        }));
        assert_eq!(close_code(&m), Some(CLOSE_UNAUTHORIZED));
        assert_eq!(close_code(&Message::Close(None)), None);
    }
}
