//! Fake upstreams (GitHub, OpenRouter) as local HTTP servers that record
//! every call.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

/// One call a fake received.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub body: Value,
}

type Handler = dyn Fn(&Call) -> (u16, Value) + Send + Sync;

/// A recording HTTP server.
#[derive(Debug)]
pub struct Fake {
    pub url: String,
    calls: Arc<Mutex<Vec<Call>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fake {
    pub async fn start(handler: impl Fn(&Call) -> (u16, Value) + Send + Sync + 'static) -> Fake {
        let calls: Arc<Mutex<Vec<Call>>> = Arc::default();
        let handler: Arc<Handler> = Arc::new(handler);
        let recorded = calls.clone();
        let app = axum::Router::new().fallback(move |req: Request| {
            let handler = handler.clone();
            let recorded = recorded.clone();
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 1 << 20)
                    .await
                    .unwrap_or_default();
                let call = Call {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_owned(),
                    authorization: parts
                        .headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned(),
                    body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                };
                let (status, reply) = handler(&call);
                recorded.lock().unwrap().push(call);
                let body = if reply.is_null() {
                    Body::empty()
                } else {
                    Body::from(reply.to_string())
                };
                Response::builder()
                    .status(StatusCode::from_u16(status).unwrap())
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Fake { url, calls, task }
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// The calls with this method whose path ends with `suffix`.
    pub fn calls_to(&self, method: &str, suffix: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.method == method && c.path.ends_with(suffix))
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// GitHub's App API as the broker uses it: an installation per repo,
/// numbered installation tokens (`ghs_e2e_<n>`), token revocation.
pub async fn github() -> Fake {
    let n = Arc::new(AtomicUsize::new(0));
    Fake::start(move |c| match (c.method.as_str(), c.path.as_str()) {
        ("GET", p) if p.starts_with("/repos/") && p.ends_with("/installation") => {
            (200, json!({"id": 42}))
        }
        ("POST", "/app/installations/42/access_tokens") => {
            let i = n.fetch_add(1, Ordering::SeqCst) + 1;
            (
                201,
                json!({"token": format!("ghs_e2e_{i}"), "expires_at": "2099-01-01T00:00:00Z"}),
            )
        }
        ("DELETE", "/installation/token") => (204, Value::Null),
        _ => (404, json!({"message": "Not Found"})),
    })
    .await
}

/// OpenRouter's chat completions. The verdict follows a marker in the
/// agent's justification: `[llm:approve]`, `[llm:deny]`, or `[llm:garbage]`
/// (an answer that is not the schema's JSON).
pub async fn openrouter() -> Fake {
    Fake::start(|c| {
        if c.method != "POST" || c.path != "/api/v1/chat/completions" {
            return (404, json!({"error": "not found"}));
        }
        let user = c.body["messages"][1]["content"]
            .as_str()
            .unwrap_or_default();
        // Only what the agent wrote counts (not the prompt's own words).
        let justification = user
            .split("<justification>")
            .nth(1)
            .and_then(|s| s.split("</justification>").next())
            .unwrap_or_default();
        let content = if justification.contains("[llm:approve]") {
            json!({"verdict": "approve", "reasoning": "specific and proportionate"}).to_string()
        } else if justification.contains("[llm:deny]") {
            json!({"verdict": "deny", "reasoning": "too vague: say which task"}).to_string()
        } else {
            "I think this is probably fine?".to_owned()
        };
        (
            200,
            json!({"choices": [{"message": {"role": "assistant", "content": content}}]}),
        )
    })
    .await
}

/// Discord: the REST API (cards posted to channel 5 get message id 900;
/// a card read back has the embeds last posted) and a gateway that says
/// hello, answers IDENTIFY with READY (application 20), acks heartbeats
/// and delivers the interactions the test pushes.
#[derive(Debug)]
pub struct Discord {
    pub rest: Fake,
    pub gateway_url: String,
    /// What the bot sent the gateway (IDENTIFY, heartbeats).
    pub received: Arc<Mutex<Vec<Value>>>,
    push: tokio::sync::mpsc::UnboundedSender<Value>,
    gateway: tokio::task::JoinHandle<()>,
    next: AtomicUsize,
}

impl Drop for Discord {
    fn drop(&mut self) {
        self.gateway.abort();
    }
}

pub async fn discord() -> Discord {
    let embeds = Arc::new(Mutex::new(json!([])));
    let posted = embeds.clone();
    let rest = Fake::start(move |c| {
        let path = c.path.strip_prefix("/api/v10").unwrap_or(&c.path);
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        match (c.method.as_str(), parts.as_slice()) {
            ("GET", ["channels", ch]) => (200, json!({"id": ch, "guild_id": "77"})),
            ("POST", ["channels", ch, "messages"]) => {
                *posted.lock().unwrap() = c.body["embeds"].clone();
                (200, json!({"id": "900", "channel_id": ch}))
            }
            ("GET", ["channels", ch, "messages", m]) => (
                200,
                json!({"id": m, "channel_id": ch, "embeds": posted.lock().unwrap().clone()}),
            ),
            ("POST", ["interactions", ..]) => (204, Value::Null),
            ("PUT", ["applications", ..]) => (200, json!([])),
            _ => (200, json!({"id": "901", "channel_id": "5"})),
        }
    })
    .await;
    drop(embeds);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("ws://{}", listener.local_addr().unwrap());
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let (push, pushed) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let pushed = Arc::new(tokio::sync::Mutex::new(pushed));
    let seen = received.clone();
    let gateway = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = seen.clone();
            let pushed = pushed.clone();
            tokio::spawn(async move {
                let _ = gateway_connection(tcp, seen, pushed).await;
            });
        }
    });
    Discord {
        rest,
        gateway_url,
        received,
        push,
        gateway,
        next: AtomicUsize::new(1000),
    }
}

async fn gateway_connection(
    tcp: tokio::net::TcpStream,
    seen: Arc<Mutex<Vec<Value>>>,
    pushed: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Value>>>,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut ws = tokio_tungstenite::accept_async(tcp).await?;
    let text = |v: Value| Message::Text(v.to_string().into());
    ws.send(text(json!({"op": 10, "d": {"heartbeat_interval": 45000}})))
        .await?;
    let mut seq: u64 = 0;
    let mut pushed = pushed.lock().await;
    loop {
        tokio::select! {
            frame = ws.next() => {
                let Some(Ok(Message::Text(t))) = frame else { return Ok(()) };
                let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                seen.lock().unwrap().push(v.clone());
                match v["op"].as_u64() {
                    Some(2) => {
                        seq += 1;
                        ws.send(text(json!({"op": 0, "t": "READY", "s": seq, "d": {
                            "session_id": "e2e-session",
                            "resume_gateway_url": "wss://127.0.0.1:1",
                            "application": {"id": "20"},
                            "user": {"id": "20", "username": "agent-auth"},
                        }}))).await?;
                    }
                    Some(1) => ws.send(text(json!({"op": 11}))).await?,
                    _ => {}
                }
            }
            interaction = pushed.recv() => {
                let Some(d) = interaction else { return Ok(()) };
                seq += 1;
                ws.send(text(json!({"op": 0, "t": "INTERACTION_CREATE", "s": seq, "d": d}))).await?;
            }
        }
    }
}

impl Discord {
    /// Deliver an interaction from `user`; its id (the callback goes to
    /// `/interactions/<id>/tok-<id>/callback`).
    pub fn interact(&self, user: u64, kind: u8, data: Value) -> String {
        let id = self.next.fetch_add(1, Ordering::SeqCst).to_string();
        let interaction = json!({
            "id": id,
            "application_id": "20",
            "type": kind,
            "token": format!("tok-{id}"),
            "channel_id": "5",
            "data": data,
            "user": {"id": user.to_string(), "username": "jrt", "discriminator": "0", "avatar": null},
            "entitlements": [],
            "authorizing_integration_owners": {},
            "version": 1,
            "locale": "en-US",
        });
        self.push.send(interaction).unwrap();
        id
    }

    /// A button click.
    pub fn click(&self, user: u64, custom_id: &str) -> String {
        self.interact(
            user,
            3,
            json!({"custom_id": custom_id, "component_type": 2}),
        )
    }

    /// A modal submitted with these text inputs.
    pub fn submit(&self, user: u64, custom_id: &str, fields: &[(&str, &str)]) -> String {
        let components: Vec<Value> = fields
            .iter()
            .enumerate()
            .map(|(i, (k, v))| {
                json!({"type": 18, "id": i, "component": {"type": 4, "id": i + 10, "custom_id": k, "value": v}})
            })
            .collect();
        self.interact(
            user,
            5,
            json!({"custom_id": custom_id, "components": components}),
        )
    }

    /// The bodies of the interaction callbacks to interaction `id`.
    pub fn callbacks(&self, id: &str) -> Vec<Value> {
        self.rest
            .calls()
            .into_iter()
            .filter(|c| {
                c.path
                    .ends_with(&format!("/interactions/{id}/tok-{id}/callback"))
            })
            .map(|c| c.body)
            .collect()
    }
}
