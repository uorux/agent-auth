//! The Discord gateway: a websocket that delivers interactions.
//!
//! twilight-gateway is not used (its TLS connector cannot be replaced, so
//! it would not use the shared root store; DEVIATIONS.md). This is the
//! subset the bot needs: JSON encoding, no compression (no `compress`, no
//! `zlib-stream`), intents 0 (interactions arrive regardless), a heartbeat
//! with jitter, zombie detection (a heartbeat due while the last one is
//! unacknowledged), resume with the session id, the last sequence number
//! and `resume_gateway_url`, a fresh identify after a non-resumable
//! invalid session, and backoff between connections.
//!
//! [`Machine`] is the protocol as a pure state machine (frames in,
//! actions out), tested on its own; [`run`] drives it over a socket.

use std::sync::Arc;
use std::time::Duration;

use agent_auth_crypto::Secret;
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use twilight_model::application::interaction::Interaction;

pub const DISCORD_GATEWAY: &str = "wss://gateway.discord.gg";
/// Incoming frame and message caps (interactions are a few KiB).
pub const MAX_MESSAGE: usize = 1 << 20;
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

// ------------------------------------------------------------ protocol

/// A gateway frame, as far as the bot reads it.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Hello {
        interval: Duration,
    },
    HeartbeatAck,
    /// The gateway asks for a heartbeat now (op 1).
    HeartbeatRequest,
    Dispatch {
        seq: Option<u64>,
        name: String,
        data: Value,
    },
    Reconnect,
    InvalidSession {
        resumable: bool,
    },
    /// An opcode the bot does not handle.
    Other,
}

#[derive(Deserialize)]
struct Frame {
    op: u8,
    #[serde(default)]
    d: Value,
    #[serde(default)]
    s: Option<u64>,
    #[serde(default)]
    t: Option<String>,
}

/// Read one text frame.
pub fn parse_frame(text: &str) -> Result<Event, String> {
    let f: Frame = serde_json::from_str(text).map_err(|e| format!("bad gateway frame: {e}"))?;
    Ok(match f.op {
        0 => Event::Dispatch {
            seq: f.s,
            name: f.t.unwrap_or_default(),
            data: f.d,
        },
        1 => Event::HeartbeatRequest,
        7 => Event::Reconnect,
        9 => Event::InvalidSession {
            resumable: f.d.as_bool().unwrap_or(false),
        },
        10 => {
            let ms =
                f.d.get("heartbeat_interval")
                    .and_then(Value::as_u64)
                    .filter(|ms| (1000..=600_000).contains(ms))
                    .ok_or("hello without a usable heartbeat_interval")?;
            Event::Hello {
                interval: Duration::from_millis(ms),
            }
        }
        11 => Event::HeartbeatAck,
        _ => Event::Other,
    })
}

/// What the driver must do.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Start heartbeating: the first beat after `interval × jitter`.
    StartHeartbeat(Duration),
    Identify,
    Resume {
        session_id: String,
        seq: u64,
    },
    Heartbeat {
        seq: Option<u64>,
    },
    /// READY: the application id (for followups and commands).
    Ready {
        application_id: Option<u64>,
    },
    Resumed,
    Interaction(Value),
    /// Close this connection and connect again (resuming if the machine
    /// still has a session).
    Reconnect {
        why: &'static str,
    },
}

/// How a connection ended, as far as reconnecting goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    Reconnect,
    /// The gateway refused us for good (bad token, bad intents...).
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Session {
    id: String,
    resume_url: String,
}

/// The gateway protocol, without I/O.
#[derive(Debug, Clone, Default)]
pub struct Machine {
    session: Option<Session>,
    seq: Option<u64>,
    /// This connection: heartbeating started, last beat not acknowledged.
    heartbeating: bool,
    awaiting_ack: bool,
}

impl Machine {
    #[must_use]
    pub fn new() -> Machine {
        Machine::default()
    }

    /// Whether the next connection resumes.
    #[must_use]
    pub fn resumable(&self) -> bool {
        self.session.is_some() && self.seq.is_some()
    }

    /// Where to connect: the session's resume URL, else `default`.
    #[must_use]
    pub fn url(&self, default: &str) -> String {
        let base = match &self.session {
            Some(s) if self.resumable() => s.resume_url.as_str(),
            _ => default,
        };
        format!("{}/?v=10&encoding=json", base.trim_end_matches('/'))
    }

    /// A new connection starts (per-connection state reset).
    pub fn connected(&mut self) {
        self.heartbeating = false;
        self.awaiting_ack = false;
    }

    pub fn on_event(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Hello { interval } => {
                self.heartbeating = true;
                self.awaiting_ack = false;
                let start = match (&self.session, self.seq) {
                    (Some(s), Some(seq)) => Action::Resume {
                        session_id: s.id.clone(),
                        seq,
                    },
                    _ => Action::Identify,
                };
                vec![Action::StartHeartbeat(interval), start]
            }
            Event::HeartbeatAck => {
                self.awaiting_ack = false;
                Vec::new()
            }
            Event::HeartbeatRequest => vec![Action::Heartbeat { seq: self.seq }],
            Event::Dispatch { seq, name, data } => {
                if seq.is_some() {
                    self.seq = seq;
                }
                match name.as_str() {
                    "READY" => {
                        let id = data.get("session_id").and_then(Value::as_str);
                        let url = data
                            .get("resume_gateway_url")
                            .and_then(Value::as_str)
                            // Only a TLS websocket URL is followed.
                            .filter(|u| u.starts_with("wss://") && !u.contains(['?', '#', '@']));
                        self.session = match (id, url) {
                            (Some(id), Some(url)) => Some(Session {
                                id: id.to_owned(),
                                resume_url: url.to_owned(),
                            }),
                            _ => None,
                        };
                        let application_id = data
                            .get("application")
                            .and_then(|a| a.get("id"))
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse().ok());
                        vec![Action::Ready { application_id }]
                    }
                    "RESUMED" => vec![Action::Resumed],
                    "INTERACTION_CREATE" => vec![Action::Interaction(data)],
                    _ => Vec::new(),
                }
            }
            Event::Reconnect => vec![Action::Reconnect {
                why: "the gateway asked to reconnect",
            }],
            Event::InvalidSession { resumable } => {
                if !resumable {
                    self.session = None;
                    self.seq = None;
                }
                vec![Action::Reconnect {
                    why: "invalid session",
                }]
            }
            Event::Other => Vec::new(),
        }
    }

    /// The heartbeat timer fired.
    pub fn heartbeat_due(&mut self) -> Action {
        if !self.heartbeating {
            return Action::Reconnect {
                why: "heartbeat before hello",
            };
        }
        if self.awaiting_ack {
            // A zombie connection: resume on a new one.
            self.heartbeating = false;
            return Action::Reconnect {
                why: "no heartbeat ack",
            };
        }
        self.awaiting_ack = true;
        Action::Heartbeat { seq: self.seq }
    }

    /// The gateway closed the connection with `code`.
    pub fn closed(&mut self, code: Option<u16>) -> Closed {
        self.heartbeating = false;
        match code {
            // Authentication failed, invalid shard, sharding required,
            // invalid API version, invalid or disallowed intents.
            Some(4004 | 4010 | 4011 | 4012 | 4013 | 4014) => Closed::Fatal,
            // Invalid seq, session timed out: start over.
            Some(4007 | 4009) => {
                self.session = None;
                self.seq = None;
                Closed::Reconnect
            }
            _ => Closed::Reconnect,
        }
    }
}

/// The identify payload: intents 0, no compression, no large threshold.
fn identify(token: &Secret<String>) -> String {
    json!({
        "op": 2,
        "d": {
            "token": token.expose(),
            "intents": 0,
            "properties": {"os": "linux", "browser": "agent-auth", "device": "agent-auth"},
        }
    })
    .to_string()
}

fn resume(token: &Secret<String>, session_id: &str, seq: u64) -> String {
    json!({"op": 6, "d": {"token": token.expose(), "session_id": session_id, "seq": seq}})
        .to_string()
}

fn heartbeat(seq: Option<u64>) -> String {
    json!({"op": 1, "d": seq}).to_string()
}

/// A uniform fraction in [0, 1) (jitter; not security-relevant).
fn jitter() -> f64 {
    let bits = uuid::Uuid::new_v4().as_u128() & 0xFFFF_FFFF;
    #[expect(clippy::as_conversions, reason = "a 32-bit value as a float")]
    let f = bits as f64 / 4_294_967_296.0;
    f
}

/// Reconnection delay: 1 s doubling to 60 s, with up to 1 s of jitter.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    let base = Duration::from_secs(1u64.checked_shl(attempt.min(6)).unwrap_or(64)).min(MAX_BACKOFF);
    base.saturating_add(Duration::from_secs_f64(jitter()))
}

// -------------------------------------------------------------- driver

/// What the gateway hands to the bot.
#[derive(Debug)]
pub enum Delivered {
    Ready { application_id: Option<u64> },
    Interaction(Box<Interaction>),
}

/// Connect, and keep connecting, until the gateway refuses us for good or
/// the receiver is gone.
pub async fn run(
    url: String,
    token: Secret<String>,
    tls: Arc<rustls::ClientConfig>,
    out: mpsc::Sender<Delivered>,
) {
    let mut machine = Machine::new();
    let mut attempt: u32 = 0;
    loop {
        let target = machine.url(&url);
        let outcome = session(&mut machine, &target, &token, &tls, &out, &mut attempt).await;
        match outcome {
            Ok(Closed::Fatal) => {
                tracing::error!(
                    "the Discord gateway refused the bot; the bot is off until a restart"
                );
                return;
            }
            Ok(Closed::Reconnect) => {}
            Err(e) => tracing::warn!("discord gateway: {e}"),
        }
        if out.is_closed() {
            return;
        }
        let wait = backoff(attempt);
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(wait).await;
    }
}

async fn session(
    machine: &mut Machine,
    url: &str,
    token: &Secret<String>,
    tls: &Arc<rustls::ClientConfig>,
    out: &mpsc::Sender<Delivered>,
    attempt: &mut u32,
) -> Result<Closed, String> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        url,
        Some(config),
        false,
        Some(Connector::Rustls(Arc::clone(tls))),
    );
    let (ws, _) = tokio::time::timeout(HELLO_TIMEOUT, connect)
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|e| format!("connect: {e}"))?;
    let (mut sink, mut stream) = ws.split();
    machine.connected();
    let hello_by = later(HELLO_TIMEOUT);
    let mut interval: Option<Duration> = None;
    let mut next_beat: Option<Instant> = None;
    loop {
        let deadline = next_beat.unwrap_or(hello_by);
        let frame = tokio::select! {
            frame = stream.next() => frame,
            () = tokio::time::sleep_until(deadline) => {
                if next_beat.is_none() {
                    return Err("no hello".to_owned());
                }
                let action = machine.heartbeat_due();
                next_beat = interval.map(later);
                if !perform(action, machine, &mut sink, token, out, &mut interval, &mut next_beat, attempt).await? {
                    let _ = sink.send(close_resumable()).await;
                    return Ok(Closed::Reconnect);
                }
                continue;
            }
        };
        let message = match frame {
            None => return Ok(Closed::Reconnect),
            Some(Err(e)) => return Err(format!("read: {e}")),
            Some(Ok(m)) => m,
        };
        let text = match message {
            WsMessage::Text(t) => t,
            WsMessage::Close(frame) => {
                let code = frame.map(|f| u16::from(f.code));
                tracing::info!(?code, "discord gateway closed the connection");
                return Ok(machine.closed(code));
            }
            WsMessage::Binary(_) => {
                return Err("unexpected binary frame (no compression was asked for)".to_owned());
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
        };
        let event = parse_frame(text.as_str())?;
        for action in machine.on_event(event) {
            if !perform(
                action,
                machine,
                &mut sink,
                token,
                out,
                &mut interval,
                &mut next_beat,
                attempt,
            )
            .await?
            {
                let _ = sink.send(close_resumable()).await;
                return Ok(Closed::Reconnect);
            }
        }
    }
}

/// `now + d` (saturating far in the future).
pub(crate) fn later(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).unwrap_or(now)
}

/// A close that keeps the session resumable (not 1000/1001).
fn close_resumable() -> WsMessage {
    WsMessage::Close(Some(CloseFrame {
        code: CloseCode::from(4000),
        reason: "reconnecting".into(),
    }))
}

/// Carry out one action; `false`: reconnect.
#[expect(
    clippy::too_many_arguments,
    reason = "the driver's state, threaded through"
)]
async fn perform<S>(
    action: Action,
    machine: &Machine,
    sink: &mut S,
    token: &Secret<String>,
    out: &mpsc::Sender<Delivered>,
    interval: &mut Option<Duration>,
    next_beat: &mut Option<Instant>,
    attempt: &mut u32,
) -> Result<bool, String>
where
    S: futures::Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    let send = |text: String| WsMessage::Text(text.into());
    match action {
        Action::StartHeartbeat(i) => {
            *interval = Some(i);
            *next_beat = Some(later(i.mul_f64(jitter())));
        }
        Action::Identify => {
            tracing::info!("discord gateway: identifying");
            sink.send(send(identify(token)))
                .await
                .map_err(|e| format!("send: {e}"))?;
        }
        Action::Resume { session_id, seq } => {
            tracing::info!("discord gateway: resuming");
            sink.send(send(resume(token, &session_id, seq)))
                .await
                .map_err(|e| format!("send: {e}"))?;
        }
        Action::Heartbeat { seq } => {
            sink.send(send(heartbeat(seq)))
                .await
                .map_err(|e| format!("send: {e}"))?;
        }
        Action::Ready { application_id } => {
            *attempt = 0;
            let _ = out.send(Delivered::Ready { application_id }).await;
        }
        Action::Resumed => *attempt = 0,
        Action::Interaction(data) => match serde_json::from_value::<Interaction>(data) {
            Ok(i) => {
                if out.send(Delivered::Interaction(Box::new(i))).await.is_err() {
                    return Ok(false);
                }
            }
            Err(e) => tracing::warn!("discord: an interaction that does not parse: {e}"),
        },
        Action::Reconnect { why } => {
            tracing::info!(
                resume = machine.resumable(),
                "discord gateway: reconnecting ({why})"
            );
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn ready(seq: u64) -> Event {
        Event::Dispatch {
            seq: Some(seq),
            name: "READY".to_owned(),
            data: json!({
                "session_id": "sess",
                "resume_gateway_url": "wss://resume.discord.gg",
                "application": {"id": "42"},
            }),
        }
    }

    const HELLO: Event = Event::Hello {
        interval: Duration::from_millis(41_250),
    };

    #[test]
    fn frames_parse() {
        assert_eq!(
            parse_frame(r#"{"op":10,"d":{"heartbeat_interval":41250}}"#),
            Ok(HELLO)
        );
        assert_eq!(parse_frame(r#"{"op":11}"#), Ok(Event::HeartbeatAck));
        assert_eq!(
            parse_frame(r#"{"op":9,"d":false}"#),
            Ok(Event::InvalidSession { resumable: false })
        );
        assert!(parse_frame(r#"{"op":10,"d":{"heartbeat_interval":0}}"#).is_err());
        assert!(parse_frame("not json").is_err());
    }

    #[test]
    fn identify_then_resume() {
        let mut m = Machine::new();
        m.connected();
        assert_eq!(
            m.on_event(HELLO),
            vec![
                Action::StartHeartbeat(Duration::from_millis(41_250)),
                Action::Identify
            ]
        );
        assert_eq!(
            m.on_event(ready(1)),
            vec![Action::Ready {
                application_id: Some(42)
            }]
        );
        m.on_event(Event::Dispatch {
            seq: Some(7),
            name: "INTERACTION_CREATE".to_owned(),
            data: json!({}),
        });
        assert_eq!(
            m.url(DISCORD_GATEWAY),
            "wss://resume.discord.gg/?v=10&encoding=json"
        );
        assert_eq!(m.closed(Some(1006)), Closed::Reconnect);
        m.connected();
        assert_eq!(
            m.on_event(HELLO).get(1),
            Some(&Action::Resume {
                session_id: "sess".to_owned(),
                seq: 7
            })
        );
    }

    #[test]
    fn zombie_connections_reconnect() {
        let mut m = Machine::new();
        m.connected();
        m.on_event(HELLO);
        assert_eq!(m.heartbeat_due(), Action::Heartbeat { seq: None });
        assert!(matches!(m.heartbeat_due(), Action::Reconnect { .. }));
        m.connected();
        m.on_event(HELLO);
        assert!(matches!(m.heartbeat_due(), Action::Heartbeat { .. }));
        m.on_event(Event::HeartbeatAck);
        assert!(matches!(m.heartbeat_due(), Action::Heartbeat { .. }));
    }

    #[test]
    fn invalid_session_identifies_again() {
        let mut m = Machine::new();
        m.connected();
        m.on_event(HELLO);
        m.on_event(ready(3));
        assert!(m.resumable());
        m.on_event(Event::InvalidSession { resumable: false });
        assert!(!m.resumable());
        assert_eq!(
            m.url(DISCORD_GATEWAY),
            "wss://gateway.discord.gg/?v=10&encoding=json"
        );
        m.connected();
        assert_eq!(m.on_event(HELLO).get(1), Some(&Action::Identify));
    }

    #[test]
    fn fatal_and_restart_codes() {
        let mut m = Machine::new();
        assert_eq!(m.closed(Some(4004)), Closed::Fatal);
        assert_eq!(m.closed(Some(4014)), Closed::Fatal);
        m.on_event(ready(3));
        assert_eq!(m.closed(Some(4009)), Closed::Reconnect);
        assert!(!m.resumable());
    }

    #[test]
    fn insecure_resume_urls_are_not_followed() {
        let mut m = Machine::new();
        m.on_event(Event::Dispatch {
            seq: Some(1),
            name: "READY".to_owned(),
            data: json!({"session_id": "s", "resume_gateway_url": "ws://plain.example"}),
        });
        assert!(!m.resumable());
        assert_eq!(
            m.url(DISCORD_GATEWAY),
            "wss://gateway.discord.gg/?v=10&encoding=json"
        );
    }

    #[test]
    fn payloads() {
        let t = Secret::new("tok".to_owned());
        let id: Value = serde_json::from_str(&identify(&t)).unwrap();
        assert_eq!(id["d"]["intents"], 0);
        assert!(id["d"].get("compress").is_none());
        assert_eq!(heartbeat(Some(5)), r#"{"d":5,"op":1}"#);
        assert!(backoff(0) >= Duration::from_secs(1) && backoff(0) < Duration::from_secs(2));
        assert!(backoff(30) <= Duration::from_secs(61));
    }

    #[derive(Debug, Clone)]
    enum Step {
        Connect,
        Hello,
        Ack,
        Due,
        Dispatch(u64),
        Ready(u64),
        Reconnect,
        Invalid(bool),
        Close(u16),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            Just(Step::Connect),
            Just(Step::Hello),
            Just(Step::Ack),
            Just(Step::Due),
            (1u64..1000).prop_map(Step::Dispatch),
            (1u64..1000).prop_map(Step::Ready),
            Just(Step::Reconnect),
            any::<bool>().prop_map(Step::Invalid),
            prop_oneof![
                Just(1000u16),
                Just(4000),
                Just(4004),
                Just(4007),
                Just(4009)
            ]
            .prop_map(Step::Close),
        ]
    }

    proptest! {
        /// Over any sequence of gateway events: a resume carries the last
        /// sequence number seen and the session READY gave; a non-resumable
        /// invalid session is never resumed; two heartbeats are never sent
        /// without an ack between them on one connection (the second is a
        /// reconnect instead).
        #[test]
        fn protocol_invariants(steps in proptest::collection::vec(step(), 0..60)) {
            let mut m = Machine::new();
            let mut last_seq: Option<u64> = None;
            let mut session = false;
            let mut unacked_beat = false;
            for s in steps {
                let actions = match s {
                    Step::Connect => { m.connected(); unacked_beat = false; vec![] }
                    Step::Hello => { unacked_beat = false; m.on_event(HELLO) }
                    Step::Ack => { unacked_beat = false; m.on_event(Event::HeartbeatAck) }
                    Step::Due => vec![m.heartbeat_due()],
                    Step::Dispatch(n) => { last_seq = Some(n); m.on_event(Event::Dispatch { seq: Some(n), name: "X".to_owned(), data: Value::Null }) }
                    Step::Ready(n) => { last_seq = Some(n); session = true; m.on_event(ready(n)) }
                    Step::Reconnect => m.on_event(Event::Reconnect),
                    Step::Invalid(r) => { if !r { session = false; last_seq = None; } m.on_event(Event::InvalidSession { resumable: r }) }
                    Step::Close(c) => { if matches!(c, 4007 | 4009) { session = false; last_seq = None; } m.closed(Some(c)); unacked_beat = false; vec![] }
                };
                for a in actions {
                    match a {
                        Action::Resume { session_id, seq } => {
                            prop_assert!(session);
                            prop_assert_eq!(session_id, "sess");
                            prop_assert_eq!(Some(seq), last_seq);
                        }
                        Action::Identify => prop_assert!(!(session && last_seq.is_some())),
                        Action::Heartbeat { seq } => {
                            prop_assert_eq!(seq, last_seq);
                            if matches!(s, Step::Due) {
                                prop_assert!(!unacked_beat);
                                unacked_beat = true;
                            }
                        }
                        Action::Reconnect { .. } => unacked_beat = false,
                        _ => {}
                    }
                }
            }
        }
    }
}
