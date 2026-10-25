//! One daemon connection: the hello, registration, and the receive loop
//! (spec §4.2-§4.5).

use std::sync::Arc;
use std::time::Duration;

use agent_auth_core::DaemonId;
use agent_auth_crypto::daemon::{
    DaemonId as ChannelId, DaemonName, EnvelopeVerifier, Handshake, Nonce, PublicKey, Role, Speaker,
};
use agent_auth_store::daemons::{self, DaemonRole};
use agent_auth_wire::daemon::channel::{Heartbeat, Reply};
use agent_auth_wire::daemon::handshake::{HelloParams, version_ok};
use axum::extract::ws::{Message, WebSocket};
use futures::SinkExt as _;
use futures::stream::{SplitStream, StreamExt as _};
use serde_json::{Map, Value, json};
use tokio::sync::watch;

use super::{
    CLOSE_BAD_HELLO, CLOSE_DISABLED, CLOSE_REPLACED, CLOSE_TRY_AGAIN, CLOSE_UNAUTHORIZED,
    DaemonHub, DaemonPeer, HELLO_TIMEOUT, Live, MAX_STATUS_BYTES, MISSED_HEARTBEATS, Outbound,
    close_frame, key_of,
};

fn store_role(role: Role) -> DaemonRole {
    match role {
        Role::Host => DaemonRole::Host,
        Role::Sandbox => DaemonRole::Sandbox,
    }
}

async fn close_quietly(ws: &mut WebSocket, code: u16, reason: &str) {
    let _ = ws.send(close_frame(code, reason)).await;
}

/// What a verified hello leaves.
struct Hello {
    peer: DaemonPeer,
    verifier: EnvelopeVerifier,
    sealer: agent_auth_crypto::daemon::EnvelopeSealer,
    generation: u64,
}

impl DaemonHub {
    /// Serve one WebSocket until it closes.
    /// `peer`: the client's address (handshake slots are bounded per peer
    /// and overall).
    pub async fn serve(self: Arc<Self>, mut ws: WebSocket, peer: String) {
        if self.config.signing_key.is_none() {
            close_quietly(&mut ws, CLOSE_DISABLED, "daemon channel disabled").await;
            return;
        }
        let Some(slot) = self.peer_slot(&peer) else {
            close_quietly(&mut ws, CLOSE_TRY_AGAIN, "too many pending handshakes").await;
            return;
        };
        let Ok(permit) = Arc::clone(&self.pending).try_acquire_owned() else {
            close_quietly(&mut ws, CLOSE_TRY_AGAIN, "too many pending handshakes").await;
            return;
        };
        let hello = self.handshake(&mut ws).await;
        drop(permit);
        drop(slot);
        let Some(hello) = hello else {
            return;
        };
        let (sink, stream) = ws.split();
        let (close_tx, close_rx) = watch::channel(None);
        let peer = Arc::new(hello.peer);
        let live = Arc::new(Live {
            peer: Arc::clone(&peer),
            generation: hello.generation,
            out: tokio::sync::Mutex::new(Outbound {
                sink,
                sealer: hello.sealer,
            }),
            close: close_tx,
            last_status_write: std::sync::Mutex::new(None),
        });
        let key = key_of(peer.role(), peer.name());
        // The generation check and the registration are one step under the
        // registry lock: a re-pair or unpair either happened before
        // (refused) or will find and close this entry (INV-6).
        let replaced = {
            let mut reg = self.registry();
            let current = reg.generation.get(&key).copied().unwrap_or(0);
            if current != live.generation {
                None
            } else {
                Some(reg.live.insert(key.clone(), Arc::clone(&live)))
            }
        };
        let Some(replaced) = replaced else {
            // Not 4401: a daemon re-paired a moment ago may land here with
            // its new key, and should simply reconnect.
            let mut out = live.out.lock().await;
            let _ = out
                .sink
                .send(close_frame(
                    CLOSE_REPLACED,
                    "re-paired or unpaired during handshake",
                ))
                .await;
            return;
        };
        if let Some(old) = replaced {
            old.close(CLOSE_REPLACED, "replaced by a newer connection");
        }
        tracing::info!(daemon = %peer.principal(), "daemon connected");
        let hooks: Vec<_> = self.hooks().on_connect.clone();
        for hook in hooks {
            tokio::spawn(hook(Arc::clone(&peer)));
        }
        self.receive(&live, stream, hello.verifier, close_rx).await;
        {
            let mut reg = self.registry();
            if reg.live.get(&key).is_some_and(|l| Arc::ptr_eq(l, &live)) {
                reg.live.remove(&key);
                tracing::info!(daemon = %peer.principal(), "daemon disconnected");
            }
        }
    }

    async fn receive(
        &self,
        live: &Arc<Live>,
        mut stream: SplitStream<WebSocket>,
        mut verifier: EnvelopeVerifier,
        mut close_rx: watch::Receiver<Option<(u16, String)>>,
    ) {
        let idle = Duration::from_secs(u64::from(self.config.heartbeat_secs))
            .saturating_mul(MISSED_HEARTBEATS);
        let peer = &live.peer;
        let close_with = |code: u16, reason: String| async move {
            let mut out = live.out.lock().await;
            let _ = out.sink.send(close_frame(code, &reason)).await;
        };
        loop {
            let next = tokio::select! {
                changed = close_rx.changed() => {
                    let why = if changed.is_ok() { close_rx.borrow().clone() } else { None };
                    if let Some((code, reason)) = why {
                        close_with(code, reason).await;
                    }
                    return;
                }
                next = tokio::time::timeout(idle, stream.next()) => next,
            };
            let msg = match next {
                Err(_) => {
                    tracing::warn!(daemon = %peer.principal(), "daemon sent nothing for {}s; closing", idle.as_secs());
                    close_with(CLOSE_BAD_HELLO, "heartbeat timeout".into()).await;
                    return;
                }
                Ok(None | Some(Err(_))) => return,
                Ok(Some(Ok(m))) => m,
            };
            let text = match msg {
                Message::Text(t) => t,
                Message::Close(_) => return,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Binary(_) => {
                    close_with(CLOSE_BAD_HELLO, "bad envelope".into()).await;
                    return;
                }
            };
            let body = match verifier.open_now(text.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    // An authenticated peer sending bad envelopes is a bug
                    // or an attack: stop trusting this connection.
                    tracing::warn!(daemon = %peer.principal(), error = %e, "bad envelope; closing");
                    close_with(CLOSE_BAD_HELLO, "bad envelope".into()).await;
                    return;
                }
            };
            if !self.dispatch(live, body).await {
                return;
            }
        }
    }

    /// One verified message. False: the connection was closed.
    async fn dispatch(&self, live: &Arc<Live>, mut body: Map<String, Value>) -> bool {
        for key in agent_auth_wire::daemon::channel::ENVELOPE_KEYS {
            body.remove(key);
        }
        let kind = body
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match kind.as_str() {
            "heartbeat" => return self.heartbeat(live, body).await,
            "reply" => {
                body.remove("type");
                match serde_json::from_value::<Reply>(Value::Object(body)) {
                    Ok(reply) => self.resolve(&live.peer, reply),
                    Err(e) => {
                        tracing::warn!(daemon = %live.peer.principal(), "malformed reply: {e}")
                    }
                }
            }
            _ => {
                let handler = self.hooks().handlers.get(&kind).cloned();
                match handler {
                    Some(h) => h(Arc::clone(&live.peer), body).await,
                    None => tracing::debug!(daemon = %live.peer.principal(), "ignoring {kind:?}"),
                }
            }
        }
        true
    }

    async fn heartbeat(&self, live: &Arc<Live>, mut body: Map<String, Value>) -> bool {
        // Envelopes already prove the sender; this only bounds how often a
        // chatty (or hostile) daemon makes us write.
        let now = tokio::time::Instant::now();
        let min_gap = Duration::from_secs(u64::from(self.config.heartbeat_secs))
            .checked_div(2)
            .unwrap_or_default();
        {
            let mut last = live
                .last_status_write
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last.is_some_and(|t| now.saturating_duration_since(t) < min_gap) {
                return true;
            }
            *last = Some(now);
        }
        body.remove("type");
        let status = match body.remove("status") {
            Some(Value::Object(s))
                if agent_auth_core::canonical_json::python_dumps_len(&Value::Object(s.clone()))
                    <= MAX_STATUS_BYTES =>
            {
                Value::Object(s)
            }
            _ => json!({"error": "status missing or too large"}),
        };
        // The wire type bounds it again (informational only).
        let _ = serde_json::from_value::<Heartbeat>(json!({"status": status.clone()}));
        let version = status
            .get("version")
            .and_then(Value::as_str)
            .filter(|v| version_ok(v))
            .map(str::to_owned);
        let peer = &live.peer;
        let wrote = async {
            let tx = self.store.begin().await?;
            let ok = daemons::heartbeat(
                &tx,
                peer.row,
                &peer.public_key.to_text(),
                &status,
                version.as_deref(),
                time::OffsetDateTime::now_utc(),
            )
            .await?;
            tx.commit().await?;
            Ok::<bool, agent_auth_store::StoreError>(ok)
        }
        .await;
        match wrote {
            Ok(true) => {}
            Ok(false) => {
                // Backstop for a revocation the generation check missed.
                {
                    let mut reg = self.registry();
                    let key = key_of(peer.role(), peer.name());
                    if reg.live.get(&key).is_some_and(|l| Arc::ptr_eq(l, live)) {
                        reg.live.remove(&key);
                    }
                }
                let mut out = live.out.lock().await;
                let _ = out
                    .sink
                    .send(close_frame(
                        CLOSE_UNAUTHORIZED,
                        "no longer paired with this key",
                    ))
                    .await;
                return false;
            }
            Err(e) => {
                tracing::error!(daemon = %peer.principal(), error = %e, "heartbeat not stored")
            }
        }
        let hooks: Vec<_> = self.hooks().on_heartbeat.clone();
        for hook in hooks {
            tokio::spawn(hook(Arc::clone(peer)));
        }
        true
    }

    /// challenge → hello → welcome. Closes the socket itself on failure.
    async fn handshake(&self, ws: &mut WebSocket) -> Option<Hello> {
        let key = self.config.signing_key.as_ref()?;
        let broker_nonce = Nonce::generate().ok()?;
        let challenge = json!({"type": "challenge", "nonce": broker_nonce.as_str()});
        if ws.send(Message::text(challenge.to_string())).await.is_err() {
            return None;
        }
        let parsed = match tokio::time::timeout(HELLO_TIMEOUT, ws.recv()).await {
            Ok(Some(Ok(Message::Text(t)))) => parse_hello(t.as_str()),
            _ => None,
        };
        let Some((id, daemon_nonce, params, sig)) = parsed else {
            close_quietly(ws, CLOSE_BAD_HELLO, "bad hello").await;
            return None;
        };
        let generation = self.generation(id.role, id.name.as_str());
        let verified = self
            .verify_hello(&id, broker_nonce, daemon_nonce, &params, &sig)
            .await;
        let Some((row, public_key, verified)) = verified else {
            tracing::warn!(daemon = %id.principal(), "rejected hello: not paired or bad signature");
            close_quietly(ws, CLOSE_UNAUTHORIZED, "not paired or bad signature").await;
            return None;
        };
        let welcome_params = format!("{{\"heartbeat_secs\": {}}}", self.config.heartbeat_secs);
        let sig = verified.sign_reply(key, &welcome_params).ok()?;
        let welcome = json!({"type": "welcome", "params": welcome_params, "sig": sig});
        if ws.send(Message::text(welcome.to_string())).await.is_err() {
            return None;
        }
        let (sealer, verifier) = verified.into_channel(key);
        Some(Hello {
            peer: DaemonPeer {
                row,
                id,
                public_key,
            },
            verifier,
            sealer,
            generation,
        })
    }

    async fn verify_hello(
        &self,
        id: &ChannelId,
        broker_nonce: Nonce,
        daemon_nonce: Nonce,
        params: &str,
        sig: &str,
    ) -> Option<(
        DaemonId,
        PublicKey,
        agent_auth_crypto::daemon::VerifiedHello,
    )> {
        let tx = self.store.begin().await.ok()?;
        let row = daemons::by_name(&tx, store_role(id.role), id.name.as_str())
            .await
            .ok()??;
        let public_key = PublicKey::parse(&row.public_key).ok()?;
        let verified = Handshake::new(id.clone(), broker_nonce, daemon_nonce)
            .verify(&public_key, Speaker::Daemon, params, sig)
            .ok()?;
        let version = HelloParams::from_text(params);
        daemons::hello(
            &tx,
            row.id,
            time::OffsetDateTime::now_utc(),
            version.as_deref(),
        )
        .await
        .ok()?;
        tx.commit().await.ok()?;
        Some((row.id, public_key, verified))
    }
}

/// `{"type": "hello", "role", "name", "nonce", "params", "sig"}`: all
/// strings, a valid identity and nonce; anything else is a bad hello.
fn parse_hello(text: &str) -> Option<(ChannelId, Nonce, String, String)> {
    let v: Value = serde_json::from_str(text).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("hello") {
        return None;
    }
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    let role = Role::parse(s("role")?)?;
    let name = DaemonName::parse(s("name")?)?;
    let nonce = Nonce::parse(s("nonce")?)?;
    let params = s("params")?.to_owned();
    let sig = s("sig")?.to_owned();
    if params.len() > 4096 || sig.len() > 256 {
        return None;
    }
    Some((ChannelId::new(role, name), nonce, params, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hellos() {
        let n = Nonce::generate().unwrap();
        let ok = json!({"type": "hello", "role": "host", "name": "excelsior", "nonce": n.as_str(),
                        "params": "{}", "sig": "x"});
        assert!(parse_hello(&ok.to_string()).is_some());
        for bad in [
            json!({"type": "hello", "role": "admin", "name": "x", "nonce": n.as_str(), "params": "{}", "sig": "x"}),
            json!({"type": "hello", "role": "host", "name": "x\n", "nonce": n.as_str(), "params": "{}", "sig": "x"}),
            json!({"type": "hello", "role": "host", "name": "x", "nonce": "short", "params": "{}", "sig": "x"}),
            json!({"type": "hello", "role": "host", "name": "x", "nonce": n.as_str(), "params": {}, "sig": "x"}),
            json!({"type": "welcome"}),
            json!([]),
        ] {
            assert!(parse_hello(&bad.to_string()).is_none(), "{bad}");
        }
    }
}
