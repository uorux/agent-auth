//! `agent-auth a2a serve`: a resident, sessionless a2a dispatcher
//! (core-lifecycle-policy §8.8, the Python's serve.py).
//!
//! It reconciles the broker's pending thread-opens against a receiver by
//! POSTing raw thread facts as JSON to a URL (an agent runtime's
//! conversation-start webhook). A dumb data transport: no prompts, no
//! runtime-specific logic; the receiver decides what to do with the fields.
//!
//! Level-triggered: a sessionless `/v1/a2a/events` returns every pending
//! open on every poll, and only the thread leaving `pending_open` (accepted,
//! rejected, timed out) stops redelivery. A 2xx from the receiver means "run
//! queued", not "accepted", so the attempts map is a rate limiter
//! (cooldown), never a delivery ledger.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_auth_client::{BrokerClient, ClientError, pyjson};
use agent_auth_wire::a2a::{EventsSnapshot, ThreadOut};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A dispatch POST's timeout.
pub const POST_TIMEOUT: Duration = Duration::from_secs(10);
/// Attempt records of threads no longer pending are dropped once this old
/// (about twice the broker's default open timeout).
pub const PRUNE_AGE_SECS: f64 = 1200.0;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub on_open_url: String,
    /// None: unsigned POSTs (`--insecure-no-sign`).
    pub secret: Option<String>,
    pub wait: f64,
    pub redeliver_interval: f64,
    pub failure_backoff: f64,
    pub include_activity: bool,
    /// The header carrying the signature; its format never changes
    /// (`sha256=<hex HMAC-SHA256 of the raw body>`).
    pub sig_header: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Attempt {
    /// Unix seconds.
    pub at: f64,
    pub failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickResult {
    pub cursor: Option<String>,
    pub posted: usize,
    /// Dispatchable threads in view this tick (posted or cooling down).
    pub seen: usize,
}

/// Where the threads come from (the broker, or a stub in tests).
pub trait Source {
    fn events(
        &self,
        wait: f64,
        after: Option<&str>,
    ) -> impl Future<Output = Result<EventsSnapshot, ClientError>>;
    /// The opening message's payload (seq 1), if it can be read.
    fn opening_payload(&self, thread_id: &str) -> impl Future<Output = Option<Map<String, Value>>>;
}

/// Where they go: a POST of `body` with `headers`; whether it was a 2xx.
pub trait Poster {
    fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> impl Future<Output = bool>;
}

impl Source for BrokerClient {
    async fn events(&self, wait: f64, after: Option<&str>) -> Result<EventsSnapshot, ClientError> {
        self.a2a_events(wait, after).await
    }

    async fn opening_payload(&self, thread_id: &str) -> Option<Map<String, Value>> {
        // Sessionless reads of a still-pending thread are allowed: the
        // dispatcher is the responder agent and the thread is not bound yet.
        match self.a2a_poll(thread_id, 0, 0.0).await {
            Ok(read) => read.messages.into_iter().next().map(|m| m.payload),
            Err(_) => {
                log(
                    "WARNING",
                    &format!("could not fetch opening payload for {thread_id}; omitting"),
                );
                None
            }
        }
    }
}

/// POSTs over the shared TLS configuration.
#[derive(Debug, Clone)]
pub struct HttpPoster(pub reqwest::Client);

impl HttpPoster {
    pub fn new() -> Result<Self, String> {
        let tls = agent_auth_tls::default_client_config().map_err(|e| e.to_string())?;
        agent_auth_tls::reqwest_builder(tls, POST_TIMEOUT)
            .build()
            .map(HttpPoster)
            .map_err(|e| e.to_string())
    }
}

impl Poster for HttpPoster {
    async fn post(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> bool {
        let mut req = self.0.post(url).body(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        match req.send().await {
            Ok(resp) => {
                let ok = resp.status().is_success();
                if !ok {
                    log(
                        "WARNING",
                        &format!("dispatch POST {url} -> {}", resp.status().as_u16()),
                    );
                }
                ok
            }
            Err(e) => {
                log("WARNING", &format!("dispatch POST {url} failed: {e}"));
                false
            }
        }
    }
}

/// The POSTed body: flat, stably named fields for the receiver's template.
#[derive(Debug, Serialize)]
struct Dispatch<'a> {
    event: &'a str,
    thread_id: String,
    peer: Option<&'a str>,
    topic: Option<&'a str>,
    seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Map<String, Value>>,
}

/// One reconcile pass at time `now` (unix seconds). Every attempt is
/// recorded in `attempts`, success or not.
pub async fn tick<S: Source, P: Poster>(
    source: &S,
    poster: &P,
    cursor: Option<String>,
    attempts: &mut BTreeMap<String, Attempt>,
    now: f64,
    cfg: &ServeConfig,
) -> Result<TickResult, ClientError> {
    let snap = source.events(cfg.wait, cursor.as_deref()).await?;
    let mut items: Vec<(&str, &ThreadOut)> = snap
        .pending_opens
        .iter()
        .map(|t| ("a2a_thread_open", t))
        .collect();
    if cfg.include_activity {
        let opens: Vec<_> = snap.pending_opens.iter().map(|t| t.thread_id).collect();
        items.extend(
            snap.activity
                .iter()
                .filter(|t| !opens.contains(&t.thread_id))
                .map(|t| ("a2a_thread_activity", t)),
        );
    }

    let mut posted = 0usize;
    let mut seen: Vec<String> = Vec::new();
    for (event, thread) in items {
        let tid = thread.thread_id.to_string();
        seen.push(tid.clone());
        if let Some(last) = attempts.get(&tid) {
            let cooldown = if last.failed {
                cfg.failure_backoff
            } else {
                cfg.redeliver_interval
            };
            if now - last.at < cooldown {
                continue; // rate limit only: the pending state stops redelivery
            }
        }
        let payload = if event == "a2a_thread_open" {
            source.opening_payload(&tid).await
        } else {
            None
        };
        let body = Dispatch {
            event,
            thread_id: tid.clone(),
            peer: thread.peer.as_deref(),
            topic: thread.topic.as_deref(),
            seq: thread.last_seq,
            payload,
        };
        let raw = pyjson::dumps(&body).unwrap_or_default().into_bytes();
        let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        if let Some(secret) = cfg.secret.as_deref().filter(|s| !s.is_empty()) {
            headers.push((
                cfg.sig_header.clone(),
                agent_auth_crypto::webhook::sign_body(secret.as_bytes(), &raw),
            ));
        }
        let ok = poster.post(&cfg.on_open_url, raw, headers).await;
        attempts.insert(
            tid,
            Attempt {
                at: now,
                failed: !ok,
            },
        );
        posted = posted.saturating_add(1);
    }

    // Prune: no longer in view and old enough that no cooldown could matter.
    attempts.retain(|tid, a| seen.contains(tid) || now - a.at <= PRUNE_AGE_SECS);

    let cursor = match snap.cursor {
        Some(t) => agent_auth_wire::timestamp::format(t).ok().or(cursor),
        None => cursor,
    };
    Ok(TickResult {
        cursor,
        posted,
        seen: seen.len(),
    })
}

/// `$XDG_STATE_HOME/agent-auth/a2a-serve.json` (default `~/.local/state`).
#[must_use]
pub fn default_state_path() -> PathBuf {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = var("XDG_STATE_HOME").unwrap_or_else(|| {
        var("HOME")
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local")
            .join("state")
    });
    base.join("agent-auth").join("a2a-serve.json")
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub cursor: Option<String>,
    #[serde(default)]
    pub attempts: BTreeMap<String, Attempt>,
}

/// The saved state, or a fresh one when there is none or it does not parse.
#[must_use]
pub fn load_state(path: &Path) -> State {
    std::fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

/// Save atomically: write `<name>.tmp`, then rename over the file.
pub fn save_state(path: &Path, state: &State) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let text = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// A log line as the Python's `logging.basicConfig` wrote it:
/// `2026-10-25 12:00:00,123 INFO agent_auth.serve: ...`.
pub fn log(level: &str, message: &str) {
    let now = time::OffsetDateTime::now_utc();
    let stamp = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    );
    eprintln!("{stamp} {level} agent_auth.serve: {message}");
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

fn secs(s: f64) -> Duration {
    Duration::try_from_secs_f64(s).unwrap_or_default()
}

/// Run until SIGTERM or Ctrl-C: park on the events long-poll when idle,
/// paced ticks while threads linger pending (the endpoint answers at once
/// while anything is pending, so sleeping between no-op ticks is what keeps
/// it from spinning). The long-poll doubles as the agent's liveness.
pub async fn serve_loop<P: Poster>(
    client: &BrokerClient,
    poster: &P,
    cfg: &ServeConfig,
    state_path: &Path,
    poll_interval: f64,
) {
    // Sessionless is mandatory: only a sessionless caller sees pending opens.
    let client = client.with_session(None);
    let mut state = load_state(state_path);
    log(
        "INFO",
        &format!(
            "a2a dispatcher up (sessionless): POST {}, redeliver={}s, state={}",
            cfg.on_open_url,
            agent_auth_core::canonical_json::python_float_repr(cfg.redeliver_interval),
            state_path.display()
        ),
    );
    let stop = stop_signal();
    tokio::pin!(stop);
    loop {
        let result = tokio::select! {
            () = &mut stop => break,
            r = tick(&client, poster, state.cursor.clone(), &mut state.attempts, unix_now(), cfg) => r,
        };
        let pause = match result {
            Ok(result) => {
                state.cursor = result.cursor;
                if let Err(e) = save_state(state_path, &state) {
                    log(
                        "WARNING",
                        &format!("could not save {}: {e}", state_path.display()),
                    );
                }
                // Everything in view cooling down (the next call would answer
                // at once), or work just queued: pace. Otherwise park again.
                (result.seen > 0 || result.posted > 0).then(|| secs(poll_interval))
            }
            Err(e) => {
                log("WARNING", &format!("tick failed ({e}); backing off"));
                Some(secs(poll_interval.min(5.0)))
            }
        };
        if let Some(pause) = pause {
            tokio::select! {
                () = &mut stop => break,
                () = tokio::time::sleep(pause) => {}
            }
        }
    }
    if let Err(e) = save_state(state_path, &state) {
        log(
            "WARNING",
            &format!("could not save {}: {e}", state_path.display()),
        );
    }
    log("INFO", "a2a dispatcher stopped");
}

async fn stop_signal() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = term => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[cfg(test)]
mod tests {
    //! tests/test_serve.py: no live loop, no real sleeps — a stub source,
    //! a stub poster and an injected `now`.

    use std::cell::RefCell;

    use agent_auth_client::testing::shapes;
    use serde_json::json;

    use super::*;

    const T1: &str = "c0000000-0000-4000-8000-000000000001";
    const T2: &str = "c0000000-0000-4000-8000-000000000002";

    fn thread(id: &str, state: &str) -> ThreadOut {
        let mut v = shapes::thread(id, state);
        v["peer"] = json!("claude-nixos-dots-x");
        serde_json::from_value(v).unwrap()
    }

    #[derive(Default)]
    struct Stub {
        pending: RefCell<Vec<ThreadOut>>,
        activity: RefCell<Vec<ThreadOut>>,
        poll_error: RefCell<bool>,
    }

    impl Source for Stub {
        async fn events(
            &self,
            _wait: f64,
            _after: Option<&str>,
        ) -> Result<EventsSnapshot, ClientError> {
            Ok(EventsSnapshot {
                pending_opens: self.pending.borrow().clone(),
                activity: self.activity.borrow().clone(),
                cursor: Some(agent_auth_wire::timestamp::parse(shapes::T).unwrap()),
            })
        }
        async fn opening_payload(&self, _thread_id: &str) -> Option<Map<String, Value>> {
            if *self.poll_error.borrow() {
                return None;
            }
            json!({"task": "deploy cactus"}).as_object().cloned()
        }
    }

    type Posted = (String, Vec<u8>, Vec<(String, String)>);

    struct Post {
        ok: RefCell<bool>,
        calls: RefCell<Vec<Posted>>,
    }

    impl Post {
        fn new(ok: bool) -> Self {
            Post {
                ok: RefCell::new(ok),
                calls: RefCell::default(),
            }
        }
        fn bodies(&self) -> Vec<Value> {
            self.calls
                .borrow()
                .iter()
                .map(|(_, raw, _)| serde_json::from_slice(raw).unwrap())
                .collect()
        }
    }

    impl Poster for Post {
        async fn post(&self, url: &str, body: Vec<u8>, headers: Vec<(String, String)>) -> bool {
            self.calls
                .borrow_mut()
                .push((url.to_owned(), body, headers));
            *self.ok.borrow()
        }
    }

    fn cfg() -> ServeConfig {
        ServeConfig {
            on_open_url: "http://hermes.test/start".into(),
            secret: Some("hook-secret".into()),
            wait: 60.0,
            redeliver_interval: 60.0,
            failure_backoff: 5.0,
            include_activity: false,
            sig_header: "X-Agent-Auth-Signature".into(),
        }
    }

    #[tokio::test]
    async fn level_triggered_redelivery_with_cooldown() {
        let (stub, post, cfg) = (Stub::default(), Post::new(true), cfg());
        stub.pending.borrow_mut().push(thread(T1, "pending_open"));
        let mut attempts = BTreeMap::new();

        let r = tick(&stub, &post, None, &mut attempts, 0.0, &cfg)
            .await
            .unwrap();
        assert_eq!((r.posted, r.seen), (1, 1));
        assert_eq!(r.cursor.as_deref(), Some(shapes::T));
        assert_eq!(
            post.bodies()[0],
            json!({"event": "a2a_thread_open", "thread_id": T1, "peer": "claude-nixos-dots-x",
                   "topic": null, "seq": 1, "payload": {"task": "deploy cactus"}})
        );
        // Python's json.dumps text, keys in its order.
        let raw = String::from_utf8(post.calls.borrow()[0].1.clone()).unwrap();
        assert!(raw.starts_with(&format!(
            "{{\"event\": \"a2a_thread_open\", \"thread_id\": \"{T1}\", \"peer\""
        )));

        // Still pending, inside the cooldown: suppressed, but seen.
        let r = tick(&stub, &post, r.cursor, &mut attempts, 1.0, &cfg)
            .await
            .unwrap();
        assert_eq!((r.posted, r.seen), (0, 1));
        assert_eq!(post.calls.borrow().len(), 1);

        // Past the redelivery interval and still pending: posted again.
        let r = tick(&stub, &post, r.cursor, &mut attempts, 61.0, &cfg)
            .await
            .unwrap();
        assert_eq!(r.posted, 1);
        assert_eq!(post.calls.borrow().len(), 2);

        // The thread left pending_open: dispatch stops, whatever the timers.
        stub.pending.borrow_mut().clear();
        let r = tick(&stub, &post, r.cursor, &mut attempts, 200.0, &cfg)
            .await
            .unwrap();
        assert_eq!((r.posted, r.seen), (0, 0));
        assert_eq!(post.calls.borrow().len(), 2);
    }

    #[tokio::test]
    async fn failure_backoff_retries_sooner() {
        let (stub, post, cfg) = (Stub::default(), Post::new(false), cfg());
        stub.pending.borrow_mut().push(thread(T1, "pending_open"));
        let mut attempts = BTreeMap::new();
        tick(&stub, &post, None, &mut attempts, 0.0, &cfg)
            .await
            .unwrap();
        assert!(attempts[T1].failed);
        let r = tick(&stub, &post, None, &mut attempts, 3.0, &cfg)
            .await
            .unwrap();
        assert_eq!(r.posted, 0);
        *post.ok.borrow_mut() = true;
        let r = tick(&stub, &post, None, &mut attempts, 6.0, &cfg)
            .await
            .unwrap();
        assert_eq!(r.posted, 1);
        assert!(!attempts[T1].failed);
    }

    #[tokio::test]
    async fn signature_matches_shared_contract() {
        let stub = Stub::default();
        stub.pending.borrow_mut().push(thread(T1, "pending_open"));
        let post = Post::new(true);
        tick(&stub, &post, None, &mut BTreeMap::new(), 0.0, &cfg())
            .await
            .unwrap();
        let (_, raw, headers) = post.calls.borrow()[0].clone();
        let sig = headers
            .iter()
            .find(|(k, _)| k == "X-Agent-Auth-Signature")
            .unwrap()
            .1
            .clone();
        assert_eq!(
            sig,
            agent_auth_crypto::webhook::sign_body(b"hook-secret", &raw)
        );
        assert!(agent_auth_crypto::webhook::verify_body(
            b"hook-secret",
            &raw,
            &sig
        ));

        // The header name is configurable; bytes and signature unchanged.
        let gh = Post::new(true);
        let cfg_gh = ServeConfig {
            sig_header: "X-Hub-Signature-256".into(),
            ..cfg()
        };
        tick(&stub, &gh, None, &mut BTreeMap::new(), 0.0, &cfg_gh)
            .await
            .unwrap();
        let (_, raw_gh, headers_gh) = gh.calls.borrow()[0].clone();
        assert_eq!(raw_gh, raw);
        assert!(
            !headers_gh
                .iter()
                .any(|(k, _)| k == "X-Agent-Auth-Signature")
        );
        assert_eq!(
            headers_gh
                .iter()
                .find(|(k, _)| k == "X-Hub-Signature-256")
                .unwrap()
                .1,
            sig
        );

        // Unsigned: no signature header at all.
        let unsigned = Post::new(true);
        let cfg_none = ServeConfig {
            secret: None,
            ..cfg_gh
        };
        tick(&stub, &unsigned, None, &mut BTreeMap::new(), 0.0, &cfg_none)
            .await
            .unwrap();
        let headers = unsigned.calls.borrow()[0].2.clone();
        assert_eq!(
            headers,
            [("Content-Type".to_owned(), "application/json".to_owned())]
        );
    }

    #[tokio::test]
    async fn include_activity_gating() {
        let stub = Stub::default();
        stub.pending.borrow_mut().push(thread(T1, "pending_open"));
        stub.activity
            .borrow_mut()
            .extend([thread(T1, "pending_open"), thread(T2, "open")]);

        let post = Post::new(true);
        let r = tick(&stub, &post, None, &mut BTreeMap::new(), 0.0, &cfg())
            .await
            .unwrap();
        assert_eq!(r.posted, 1);

        let post = Post::new(true);
        let cfg = ServeConfig {
            include_activity: true,
            ..cfg()
        };
        let r = tick(&stub, &post, None, &mut BTreeMap::new(), 0.0, &cfg)
            .await
            .unwrap();
        assert_eq!(r.posted, 2);
        let bodies = post.bodies();
        let events: BTreeMap<String, String> = bodies
            .iter()
            .map(|b| {
                (
                    b["thread_id"].as_str().unwrap().to_owned(),
                    b["event"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(events[T1], "a2a_thread_open");
        assert_eq!(events[T2], "a2a_thread_activity");
        let t2 = bodies.iter().find(|b| b["thread_id"] == T2).unwrap();
        assert!(t2.get("payload").is_none());
    }

    #[tokio::test]
    async fn payload_fetch_failure_omits_payload() {
        let stub = Stub::default();
        stub.pending.borrow_mut().push(thread(T1, "pending_open"));
        *stub.poll_error.borrow_mut() = true;
        let post = Post::new(true);
        let r = tick(&stub, &post, None, &mut BTreeMap::new(), 0.0, &cfg())
            .await
            .unwrap();
        assert_eq!(r.posted, 1);
        assert!(post.bodies()[0].get("payload").is_none());
    }

    #[tokio::test]
    async fn attempts_pruned_only_when_gone_and_stale() {
        let stub = Stub::default();
        let post = Post::new(true);
        let mut attempts = BTreeMap::from([
            (
                "gone-old".to_owned(),
                Attempt {
                    at: 0.0,
                    failed: false,
                },
            ),
            (
                "gone-new".to_owned(),
                Attempt {
                    at: 1990.0,
                    failed: false,
                },
            ),
        ]);
        tick(&stub, &post, None, &mut attempts, 2000.0, &cfg())
            .await
            .unwrap();
        assert!(!attempts.contains_key("gone-old"));
        assert!(attempts.contains_key("gone-new"));
    }

    #[test]
    fn state_round_trips_and_bad_state_is_fresh() {
        let dir = std::env::temp_dir().join(format!("agent-auth-serve-{}", std::process::id()));
        let path = dir.join("sub").join("a2a-serve.json");
        let state = State {
            cursor: Some(shapes::T.into()),
            attempts: BTreeMap::from([(
                T1.to_owned(),
                Attempt {
                    at: 5.5,
                    failed: true,
                },
            )]),
        };
        save_state(&path, &state).unwrap();
        let back = load_state(&path);
        assert_eq!(back.cursor, state.cursor);
        assert_eq!(back.attempts, state.attempts);
        assert!(!path.with_extension("tmp").exists());
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_state(&path).cursor.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
