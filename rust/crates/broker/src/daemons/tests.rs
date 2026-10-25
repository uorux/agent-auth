//! Pairing, the hello, envelopes and the live map, against Postgres and
//! over real loopback HTTP and WebSockets (ported from
//! `tests/test_daemons.py`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::Duration;

use agent_auth_crypto::daemon::{
    DaemonId as ChannelId, DaemonName, Handshake, Nonce, PairingKey, Role, SigningKey, Speaker,
};
use agent_auth_store::daemons::{self, DaemonRole};
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use super::testkit::{Broker, HOST, Host, wait_until};

async fn post(b: &Broker, path: &str, body: Value, admin: bool) -> (u16, Value) {
    let client = agent_auth_tls::reqwest_builder(
        agent_auth_tls::default_client_config().unwrap(),
        Duration::from_secs(10),
    )
    .build()
    .unwrap();
    let mut req = client.post(format!("{}{path}", b.url())).json(&body);
    if admin {
        req = req.bearer_auth("admin-token");
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn pair_body(code: &str, name: &str, key: &SigningKey) -> Value {
    let k = PairingKey::from_code(code);
    let id = ChannelId::new(Role::Host, DaemonName::parse(name).unwrap());
    json!({
        "role": "host", "name": name, "public_key": key.public_key().to_text(),
        "selector": k.selector(), "proof": k.daemon_proof(&id, &key.public_key()),
    })
}

async fn attempts(b: &Broker, name: &str) -> u32 {
    let tx = b.st.store.begin().await.unwrap();
    daemons::live_code(
        &tx,
        DaemonRole::Host,
        name,
        time::OffsetDateTime::now_utc(),
        100,
    )
    .await
    .unwrap()
    .map_or(u32::MAX, |c| c.failed_attempts)
}

const REFUSED: &str =
    "pairing refused: no pending code for this daemon matches (expired, used, or wrong code)";

#[sqlx::test(migrations = "../store/migrations")]
async fn pairing_binds_the_key_and_the_broker_proves_itself(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    // Through the admin route: the code is shown with the broker's key.
    let (status, issued) = post(
        &b,
        "/admin/daemons/pairing-codes",
        json!({"role": "host", "name": HOST}),
        true,
    )
    .await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(
        issued["broker_public_key"],
        json!(b.key.public_key().to_text())
    );
    let code = issued["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 14);
    let daemon = SigningKey::generate().unwrap();
    let (status, out) = post(
        &b,
        "/v1/daemons/pair",
        pair_body(&code, HOST, &daemon),
        false,
    )
    .await;
    assert_eq!(status, 200, "{out}");
    let k = PairingKey::from_code(&code);
    let id = ChannelId::new(Role::Host, DaemonName::parse(HOST).unwrap());
    assert!(k.verify_broker_proof(
        &id,
        &daemon.public_key(),
        &b.key.public_key(),
        out["proof"].as_str().unwrap()
    ));
    assert_eq!(out["fingerprint"], json!(daemon.public_key().fingerprint()));
    // Single use.
    let (status, out) = post(
        &b,
        "/v1/daemons/pair",
        pair_body(&code, HOST, &daemon),
        false,
    )
    .await;
    assert_eq!((status, out["detail"].as_str().unwrap()), (403, REFUSED));
    // Bound to its daemon's name.
    let other = b.code("other").await;
    let (status, _) = post(
        &b,
        "/v1/daemons/pair",
        pair_body(&other, HOST, &daemon),
        false,
    )
    .await;
    assert_eq!(status, 403);
    // Admin endpoints need the admin token.
    let (status, _) = post(
        &b,
        "/admin/daemons/pairing-codes",
        json!({"role": "host", "name": "x"}),
        false,
    )
    .await;
    assert_eq!(status, 401);
    let (status, out) = post(
        &b,
        "/admin/daemons/pairing-codes",
        json!({"role": "admin", "name": "x"}),
        true,
    )
    .await;
    assert_eq!(
        (status, out["detail"].as_str().unwrap()),
        (400, "role must be one of host, sandbox")
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn wrong_proofs_burn_the_code_and_each_spent_attempt_is_committed(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let code = b.code(HOST).await;
    let daemon = SigningKey::generate().unwrap();
    let mut wrong = pair_body(&code, HOST, &daemon);
    wrong["proof"] = json!("0".repeat(64));
    // A wrong selector spends nothing.
    let mut no_code = wrong.clone();
    no_code["selector"] = json!("0".repeat(32));
    for _ in 0..10 {
        let (status, out) = post(&b, "/v1/daemons/pair", no_code.clone(), false).await;
        assert_eq!((status, out["detail"].as_str().unwrap()), (403, REFUSED));
    }
    assert_eq!(attempts(&b, HOST).await, 0);
    // Each wrong proof is a committed attempt (review finding 2).
    for n in 1..=4 {
        let (status, out) = post(&b, "/v1/daemons/pair", wrong.clone(), false).await;
        assert_eq!((status, out["detail"].as_str().unwrap()), (403, REFUSED));
        assert_eq!(attempts(&b, HOST).await, n);
    }
    post(&b, "/v1/daemons/pair", wrong.clone(), false).await;
    // Burnt: even the right proof is refused now, with the same text.
    let (status, out) = post(
        &b,
        "/v1/daemons/pair",
        pair_body(&code, HOST, &daemon),
        false,
    )
    .await;
    assert_eq!((status, out["detail"].as_str().unwrap()), (403, REFUSED));
    // A malformed proof is a validation error.
    let mut bad = wrong.clone();
    bad["proof"] = json!("xyz");
    assert_eq!(post(&b, "/v1/daemons/pair", bad, false).await.0, 422);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn concurrent_wrong_proofs_respect_the_cap(pool: sqlx::PgPool) {
    let b = Arc::new(Broker::start(pool).await);
    let code = b.code(HOST).await;
    let daemon = SigningKey::generate().unwrap();
    let mut wrong = pair_body(&code, HOST, &daemon);
    wrong["proof"] = json!("0".repeat(64));
    let tries = (0..30).map(|_| {
        let b = Arc::clone(&b);
        let w = wrong.clone();
        tokio::spawn(async move { post(&b, "/v1/daemons/pair", w, false).await })
    });
    for t in futures::future::join_all(tries).await {
        assert_eq!(t.unwrap().0, 403);
    }
    let tx = b.st.store.begin().await.unwrap();
    let n: i32 = sqlx::query_scalar("SELECT max(failed_attempts) FROM daemon_pairing_codes")
        .fetch_one(b.st.store.pool())
        .await
        .unwrap();
    drop(tx);
    assert!(n <= 5, "{n} attempts evaluated");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn new_codes_supersede_old_and_unpair_burns_them(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let daemon = SigningKey::generate().unwrap();
    let old = b.code(HOST).await;
    let new = b.code(HOST).await;
    assert_eq!(
        post(
            &b,
            "/v1/daemons/pair",
            pair_body(&old, HOST, &daemon),
            false
        )
        .await
        .0,
        403
    );
    assert_eq!(
        post(
            &b,
            "/v1/daemons/pair",
            pair_body(&new, HOST, &daemon),
            false
        )
        .await
        .0,
        200
    );
    let pending = b.code(HOST).await;
    let rows = b.part.hub.list().await.unwrap();
    assert!(b.part.hub.unpair(rows[0].id).await.unwrap());
    assert!(!b.part.hub.unpair(rows[0].id).await.unwrap());
    assert_eq!(
        post(
            &b,
            "/v1/daemons/pair",
            pair_body(&pending, HOST, &daemon),
            false
        )
        .await
        .0,
        403
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn channel_end_to_end(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let host = Host::start(&b).await;
    // The first heartbeat is stored, with the daemon's version.
    let store = b.st.store.clone();
    let mut row = None;
    for _ in 0..1500 {
        let tx = store.begin().await.unwrap();
        row = daemons::by_name(&tx, DaemonRole::Host, HOST).await.unwrap();
        if row.as_ref().is_some_and(|r| r.last_status.is_some()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let row = row.unwrap();
    assert_eq!(row.version.as_deref(), Some("0.1.0"));
    assert_eq!(row.last_status.as_ref().unwrap()["role"], json!("host"));
    // A call goes to the daemon and its reply comes back.
    let data = b
        .hostexec()
        .call(
            HOST,
            json!({"type": "hostexec.precheck", "kind": "shell", "tier": "user", "duration": 60}),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(data["needs"], json!("totp"));
    // The admin list shows it online.
    let listed = b.part.hub.list().await.unwrap();
    assert!(b.part.hub.row_online(&listed[0]));
    // Unpairing drops the connection.
    assert!(b.part.hub.unpair(row.id).await.unwrap());
    wait_until(|| !b.part.hub.is_online(Role::Host, HOST)).await;
    drop(host);
}

/// A raw daemon connection, for the hello and envelope cases.
struct Raw {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl Raw {
    async fn connect(b: &Broker) -> (Raw, Nonce) {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!(
            "ws://127.0.0.1:{}/v1/daemons/connect",
            b.addr.port()
        ))
        .await
        .unwrap();
        let Some(Ok(Message::Text(t))) = ws.next().await else {
            panic!()
        };
        let v: Value = serde_json::from_str(t.as_str()).unwrap();
        assert_eq!(v["type"], json!("challenge"));
        (
            Raw { ws },
            Nonce::parse(v["nonce"].as_str().unwrap()).unwrap(),
        )
    }

    async fn send(&mut self, v: Value) {
        self.ws.send(Message::text(v.to_string())).await.unwrap();
    }

    /// The close code the broker ends with, skipping other frames.
    async fn close_code(&mut self) -> Option<u16> {
        while let Some(m) = tokio::time::timeout(Duration::from_secs(5), self.ws.next())
            .await
            .ok()?
        {
            if let Ok(Message::Close(Some(f))) = m {
                return Some(u16::from(f.code));
            }
            if m.is_err() {
                return None;
            }
        }
        None
    }

    async fn next_text(&mut self) -> Option<String> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), self.ws.next())
                .await
                .ok()??
            {
                Ok(Message::Text(t)) => return Some(t.as_str().to_owned()),
                Ok(Message::Close(_)) | Err(_) => return None,
                _ => {}
            }
        }
    }
}

async fn paired_key(b: &Broker, name: &str) -> SigningKey {
    let key = SigningKey::generate().unwrap();
    let code = b.code(name).await;
    assert_eq!(
        post(b, "/v1/daemons/pair", pair_body(&code, name, &key), false)
            .await
            .0,
        200
    );
    key
}

fn hello(id: &ChannelId, key: &SigningKey, bn: &Nonce, dn: &Nonce) -> Value {
    let params = r#"{"version": "9.9"}"#;
    let sig = Handshake::new(id.clone(), bn.clone(), dn.clone())
        .sign(key, Speaker::Daemon, params)
        .unwrap();
    json!({"type": "hello", "role": "host", "name": id.name.as_str(), "nonce": dn.as_str(),
           "params": params, "sig": sig})
}

#[sqlx::test(migrations = "../store/migrations")]
async fn hello_rejections(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let key = paired_key(&b, HOST).await;
    let id = ChannelId::new(Role::Host, DaemonName::parse(HOST).unwrap());
    // Garbage: 4400.
    let (mut raw, _) = Raw::connect(&b).await;
    raw.send(json!({"type": "hello", "role": "host"})).await;
    assert_eq!(raw.close_code().await, Some(4400));
    // Unknown daemon: 4401.
    let (mut raw, bn) = Raw::connect(&b).await;
    let ghost = ChannelId::new(Role::Host, DaemonName::parse("ghost").unwrap());
    raw.send(hello(&ghost, &key, &bn, &Nonce::generate().unwrap()))
        .await;
    assert_eq!(raw.close_code().await, Some(4401));
    // Wrong key: 4401.
    let (mut raw, bn) = Raw::connect(&b).await;
    raw.send(hello(
        &id,
        &SigningKey::generate().unwrap(),
        &bn,
        &Nonce::generate().unwrap(),
    ))
    .await;
    assert_eq!(raw.close_code().await, Some(4401));
    // A hello signed over another connection's nonce (a replay): 4401.
    let (mut raw, _) = Raw::connect(&b).await;
    let stale = Nonce::generate().unwrap();
    raw.send(hello(&id, &key, &stale, &Nonce::generate().unwrap()))
        .await;
    assert_eq!(raw.close_code().await, Some(4401));
    // Right: a welcome signed by the broker's key.
    let (mut raw, bn) = Raw::connect(&b).await;
    let dn = Nonce::generate().unwrap();
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let welcome: Value = serde_json::from_str(&raw.next_text().await.unwrap()).unwrap();
    assert_eq!(welcome["type"], json!("welcome"));
    let verified = Handshake::new(id.clone(), bn, dn).verify(
        &b.key.public_key(),
        Speaker::Broker,
        welcome["params"].as_str().unwrap(),
        welcome["sig"].as_str().unwrap(),
    );
    assert!(verified.is_ok());
}

#[sqlx::test(migrations = "../store/migrations")]
async fn bad_envelopes_close_the_connection(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let key = paired_key(&b, HOST).await;
    let id = ChannelId::new(Role::Host, DaemonName::parse(HOST).unwrap());
    let open = |raw_bn: Nonce| {
        let dn = Nonce::generate().unwrap();
        let hs = Handshake::new(id.clone(), raw_bn, dn.clone());
        (hs, dn)
    };
    let heartbeat = |n: u64| {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("heartbeat"));
        m.insert("status".into(), json!({"n": n}));
        m
    };
    async fn welcome(
        raw: &mut Raw,
        b: &Broker,
        hs: Handshake,
        key: &SigningKey,
    ) -> (
        agent_auth_crypto::daemon::EnvelopeSealer,
        agent_auth_crypto::daemon::EnvelopeVerifier,
    ) {
        let w: Value = serde_json::from_str(&raw.next_text().await.unwrap()).unwrap();
        hs.verify(
            &b.key.public_key(),
            Speaker::Broker,
            w["params"].as_str().unwrap(),
            w["sig"].as_str().unwrap(),
        )
        .unwrap()
        .into_channel(key)
    }

    // Replayed envelope.
    let (mut raw, bn) = Raw::connect(&b).await;
    let (hs, dn) = open(bn.clone());
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let (mut sealer, _) = welcome(&mut raw, &b, hs, &key).await;
    let one = sealer.seal_now(&heartbeat(1), 60.0).unwrap();
    raw.ws.send(Message::text(one.clone())).await.unwrap();
    raw.ws.send(Message::text(one)).await.unwrap();
    assert_eq!(raw.close_code().await, Some(4400));

    // Reordered.
    let (mut raw, bn) = Raw::connect(&b).await;
    let (hs, dn) = open(bn.clone());
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let (mut sealer, _) = welcome(&mut raw, &b, hs, &key).await;
    let first = sealer.seal_now(&heartbeat(1), 60.0).unwrap();
    let second = sealer.seal_now(&heartbeat(2), 60.0).unwrap();
    raw.ws.send(Message::text(second)).await.unwrap();
    raw.ws.send(Message::text(first)).await.unwrap();
    assert_eq!(raw.close_code().await, Some(4400));

    // Forged (signed by another key) and captured from an earlier
    // connection (another session id).
    let (mut raw, bn) = Raw::connect(&b).await;
    let (hs, dn) = open(bn.clone());
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let (mut old_sealer, _) = welcome(&mut raw, &b, hs, &key).await;
    let captured = old_sealer.seal_now(&heartbeat(1), 60.0).unwrap();
    drop(raw);
    let (mut raw, bn) = Raw::connect(&b).await;
    let (hs, dn) = open(bn.clone());
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let _ = welcome(&mut raw, &b, hs, &key).await;
    raw.ws.send(Message::text(captured)).await.unwrap();
    assert_eq!(raw.close_code().await, Some(4400));

    // Not an envelope at all.
    let (mut raw, bn) = Raw::connect(&b).await;
    let (hs, dn) = open(bn.clone());
    raw.send(hello(&id, &key, &bn, &dn)).await;
    let _ = welcome(&mut raw, &b, hs, &key).await;
    raw.send(json!({"type": "heartbeat"})).await;
    assert_eq!(raw.close_code().await, Some(4400));
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_newer_connection_replaces_the_older_and_silence_is_dropped(pool: sqlx::PgPool) {
    let b = Broker::start_with(pool, super::testkit::POLICY, 1).await;
    let key = paired_key(&b, HOST).await;
    let id = ChannelId::new(Role::Host, DaemonName::parse(HOST).unwrap());
    let (mut first, bn) = Raw::connect(&b).await;
    let dn = Nonce::generate().unwrap();
    first.send(hello(&id, &key, &bn, &dn)).await;
    first.next_text().await.unwrap();
    wait_until(|| b.part.hub.is_online(Role::Host, HOST)).await;
    let (mut second, bn) = Raw::connect(&b).await;
    let dn = Nonce::generate().unwrap();
    second.send(hello(&id, &key, &bn, &dn)).await;
    second.next_text().await.unwrap();
    assert_eq!(first.close_code().await, Some(4409));
    // Heartbeat 1 s: three silent seconds and it is dropped.
    assert_eq!(second.close_code().await, Some(4400));
    wait_until(|| !b.part.hub.is_online(Role::Host, HOST)).await;
}

#[sqlx::test(migrations = "../store/migrations")]
async fn a_daemon_refuses_a_broker_without_the_pinned_key(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let dir = super::testkit::tempdir("pin");
    let config = Host::config(&b, &dir, |raw| {
        raw["broker_public_key"] = json!(SigningKey::generate().unwrap().public_key().to_text());
    });
    let identity = agent_auth_hostd::identity(&config).unwrap();
    let tls = Arc::new(agent_auth_tls::default_client_config().unwrap());
    let code = b.code(HOST).await;
    let err = agent_auth_daemon::pair::pair(&identity, &code, tls)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("does not match the pinned"),
        "{err}"
    );
    std::fs::remove_dir_all(dir).ok();
}

async fn raw_from(b: &Broker, real_ip: Option<&str>) -> Raw {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    let mut req = format!("ws://127.0.0.1:{}/v1/daemons/connect", b.addr.port())
        .into_client_request()
        .unwrap();
    if let Some(ip) = real_ip {
        req.headers_mut().insert("x-real-ip", ip.parse().unwrap());
    }
    let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    Raw { ws }
}

/// Behind a trusted proxy: silent sockets from one address hold only that
/// address's slots, and are dropped after the short hello timeout.
#[sqlx::test(migrations = "../store/migrations")]
async fn silent_sockets_cannot_take_every_handshake_slot(pool: sqlx::PgPool) {
    let b = Broker::start_full(pool, super::testkit::POLICY, 30, true).await;
    let mut held = Vec::new();
    for _ in 0..super::MAX_PENDING_PER_PEER {
        held.push(raw_from(&b, Some("10.0.0.1")).await);
    }
    // A fifth from that address is told to try again...
    let mut fifth = raw_from(&b, Some("10.0.0.1")).await;
    assert_eq!(fifth.close_code().await, Some(1013));
    // ...another address gets its challenge...
    let mut other = raw_from(&b, Some("10.0.0.2")).await;
    let first = tokio::time::timeout(Duration::from_secs(5), other.ws.next())
        .await
        .unwrap();
    assert!(matches!(first, Some(Ok(Message::Text(_)))), "{first:?}");
    // ...and the silent ones are dropped after the short hello timeout,
    // which frees the slots for a real daemon.
    for mut raw in held {
        assert_eq!(raw.close_code().await, Some(4400));
    }
    let host = Host::start(&b).await;
    drop(host);
}

/// Security review 2026-10, finding 6: behind a proxy that isn't trusted,
/// every daemon shares the proxy's address, so there is no per-address cap
/// (one client could lock out all daemons), only the global one.
#[sqlx::test(migrations = "../store/migrations")]
async fn an_untrusted_address_is_not_a_handshake_cap(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let mut held = Vec::new();
    for _ in 0..super::MAX_PENDING_PER_PEER {
        held.push(raw_from(&b, Some("10.0.0.1")).await);
    }
    // More from the same (unbelieved) address still get their challenge.
    let (_raw, _nonce) = Raw::connect(&b).await;
    // The global cap still holds.
    for _ in held.len().saturating_add(1)..super::MAX_PENDING_HANDSHAKES {
        held.push(raw_from(&b, None).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut over = raw_from(&b, None).await;
    assert_eq!(over.close_code().await, Some(1013));
}

/// Review 2026-10: a daemon that stops reading its socket holds up nobody.
/// A send that can't be written within its limit drops the connection; a
/// send already waiting on it ends at once; a call fails within its own
/// timeout, as a timeout (the daemon may have read part of it).
#[sqlx::test(migrations = "../store/migrations")]
async fn a_daemon_that_stops_reading_is_dropped_and_holds_up_nobody(pool: sqlx::PgPool) {
    let b = Broker::start(pool).await;
    let vm = super::testkit::StallingDaemon::start(&b, "stuck").await;
    let flood = vm.stall(&b).await;
    let started = tokio::time::Instant::now();
    let mut ping = serde_json::Map::new();
    ping.insert("type".into(), json!("ping"));
    let err = b
        .part
        .hub
        .call(Role::Sandbox, "stuck", ping.clone(), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert!(err.timed_out, "{err:?}");
    assert!(err.message.contains("not reading"), "{err:?}");
    // The stalled sender got out too, and the connection is gone.
    let sent = tokio::time::timeout(Duration::from_secs(2), flood)
        .await
        .expect("the stalled send was not ended")
        .unwrap();
    assert!(sent > 0);
    assert!(!b.part.hub.is_online(Role::Sandbox, "stuck"));
    // Further sends find it offline at once.
    let started = tokio::time::Instant::now();
    assert!(!b.part.hub.send_default(Role::Sandbox, "stuck", &ping).await);
    let err = b
        .part
        .hub
        .call(Role::Sandbox, "stuck", ping, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        !err.timed_out && err.message == "sandbox:stuck is offline",
        "{err:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}
