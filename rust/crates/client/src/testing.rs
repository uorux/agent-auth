//! A fake broker for tests (feature `testing`): a local HTTP server that
//! answers each route with what a test programs, and records every request.
//! It also serves as a fake MCP server or webhook receiver.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::{Value, json};

/// A request the fake received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// Decoded query pairs, in order.
    pub query: Vec<(String, String)>,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON (`null` if it is not).
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// An answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    #[must_use]
    pub fn json(status: u16, value: &Value) -> Self {
        Reply {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }

    /// `{"detail": detail}` with `status`.
    #[must_use]
    pub fn detail(status: u16, detail: &str) -> Self {
        Reply::json(status, &json!({ "detail": detail }))
    }

    #[must_use]
    pub fn text(status: u16, content_type: &str, body: &str) -> Self {
        Reply {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }
}

type BoxReply = Pin<Box<dyn Future<Output = Reply> + Send>>;
type Handler = Arc<dyn Fn(Seen) -> BoxReply + Send + Sync>;

struct Route {
    method: String,
    pattern: Vec<String>,
    handler: Handler,
}

#[derive(Default)]
struct State {
    routes: Vec<Route>,
    seen: Vec<Seen>,
}

/// The fake. Dropping it stops the server.
pub struct FakeBroker {
    pub url: String,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for FakeBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeBroker")
            .field("url", &self.url)
            .finish()
    }
}

impl Drop for FakeBroker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn split(path: &str) -> Vec<String> {
    path.trim_matches('/')
        .split('/')
        .map(str::to_owned)
        .collect()
}

fn matches(pattern: &[String], path: &[String]) -> bool {
    pattern.len() == path.len() && pattern.iter().zip(path).all(|(p, s)| p == "*" || p == s)
}

impl FakeBroker {
    /// Listen on a loopback port.
    pub async fn start() -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state: Arc<Mutex<State>> = Arc::default();
        let shared = state.clone();
        let app = axum::Router::new().fallback(move |req: Request<Body>| {
            let state = shared.clone();
            async move { answer(state, req).await }
        });
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(FakeBroker {
            url: format!("http://{addr}"),
            state,
            task,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answer `method path` (segments may be `*`) with `handler`'s reply.
    /// The route added last wins.
    pub fn on_async<F, Fut>(&self, method: &str, path: &str, handler: F)
    where
        F: Fn(Seen) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Reply> + Send + 'static,
    {
        let handler: Handler = Arc::new(move |seen| Box::pin(handler(seen)));
        self.lock().routes.push(Route {
            method: method.to_owned(),
            pattern: split(path),
            handler,
        });
    }

    /// [`FakeBroker::on_async`] with a plain function.
    pub fn on<F>(&self, method: &str, path: &str, handler: F)
    where
        F: Fn(&Seen) -> Reply + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        self.on_async(method, path, move |seen| {
            let reply = handler(&seen);
            async move { reply }
        });
    }

    /// Answer `method path` with `status` and `value` every time.
    pub fn json(&self, method: &str, path: &str, status: u16, value: Value) {
        self.on(method, path, move |_| Reply::json(status, &value));
    }

    /// Every request so far.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.lock().seen.clone()
    }

    /// The requests to `method path` (a pattern as in [`FakeBroker::on`]).
    #[must_use]
    pub fn calls(&self, method: &str, path: &str) -> Vec<Seen> {
        let pattern = split(path);
        self.seen()
            .into_iter()
            .filter(|s| s.method == method && matches(&pattern, &split(&s.path)))
            .collect()
    }
}

async fn answer(state: Arc<Mutex<State>>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let query = parts
        .uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    let seen = Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query,
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body,
    };
    let handler = {
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        state.seen.push(seen.clone());
        let path = split(&seen.path);
        state
            .routes
            .iter()
            .rev()
            .find(|r| r.method == seen.method && matches(&r.pattern, &path))
            .map(|r| r.handler.clone())
    };
    let reply = match handler {
        Some(handler) => handler(seen).await,
        None => Reply::detail(404, "Not Found"),
    };
    let mut resp = Response::new(Body::from(reply.body));
    *resp.status_mut() =
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (k, v) in reply.headers {
        if let (Ok(k), Ok(v)) = (
            axum::http::HeaderName::from_bytes(k.as_bytes()),
            axum::http::HeaderValue::from_str(&v),
        ) {
            resp.headers_mut().append(k, v);
        }
    }
    resp
}

/// Answers shaped as the spec records them (http-api §2, §5).
pub mod shapes {
    use serde_json::{Value, json};

    pub const AGENT_ID: &str = "0b8e7c3e-5f0a-4b8e-9a51-6f3c2d1e0a11";
    pub const REQUEST_ID: &str = "1c9f8d4f-6a1b-4c9f-8b62-7a4d3e2f1b22";
    pub const GRANT_ID: &str = "2da09e50-7b2c-4da0-9c73-8b5e4f302c33";
    pub const THREAD_ID: &str = "3eb1af61-8c3d-4eb1-8d84-9c6f50413d44";
    pub const SESSION_ID: &str = "4fc2b072-9d4e-4fc2-9e95-ad7061524e55";
    pub const MESSAGE_ID: &str = "50d3c183-ae5f-40d3-afa6-be8172635f66";
    pub const T: &str = "2026-10-25T12:00:00.000000Z";

    /// `GET /v1/me`.
    #[must_use]
    pub fn me(kind: &str) -> Value {
        json!({
            "id": AGENT_ID, "name": "claude-x-host", "description": "", "kind": kind,
            "webhook_url": null, "lldap_username": null, "runtime": "claude",
            "project": null, "host": "excelsior", "placement": "host"
        })
    }

    /// A `RequestOut`.
    #[must_use]
    pub fn request(status: &str) -> Value {
        let granted = status == "granted";
        json!({
            "id": REQUEST_ID, "agent": "claude-x-host", "platform": "github",
            "capability": "repo", "resource": "uorux/agent-auth",
            "scope": {"permissions": {"contents": "write"}},
            "justification": "push the fix", "requested_duration_secs": 3600,
            "status": status, "attempt": 1,
            "decision_source": if granted { json!("policy") } else { Value::Null },
            "decision_reason": null,
            "approved_duration_secs": if granted { json!(3600) } else { Value::Null },
            "approved_scope": null, "approved_resource": null,
            "grant_id": if granted { json!(GRANT_ID) } else { Value::Null },
            "delegator": null, "delegation_thread_id": null,
            "created_at": T, "guidance": null
        })
    }

    /// A `GrantOut`.
    #[must_use]
    pub fn grant(
        id: &str,
        platform: &str,
        resource: &str,
        scope: Value,
        expires_at: &str,
    ) -> Value {
        json!({
            "id": id, "request_id": REQUEST_ID, "agent": "claude-x-host",
            "platform": platform, "capability": "use", "resource": resource,
            "scope": scope, "granted_at": T, "expires_at": expires_at,
            "status": "active", "delegator": null, "delegation_thread_id": null
        })
    }

    /// A `CredentialOut`.
    #[must_use]
    pub fn credential(kind: &str, value: Option<&str>, expires_at: Option<&str>) -> Value {
        json!({
            "kind": kind, "value": value, "username": null, "url": null,
            "expires_at": expires_at, "note": null
        })
    }

    /// `POST /v1/sessions`.
    #[must_use]
    pub fn session(id: &str) -> Value {
        json!({"session_id": id, "name": "task-ab12", "created_at": T})
    }

    /// A `thread_out`.
    #[must_use]
    pub fn thread(id: &str, state: &str) -> Value {
        json!({
            "thread_id": id, "peer": "hermes", "role": "responder", "topic": null,
            "state": state, "close_reason": null, "close_note": null,
            "grant_id": GRANT_ID, "last_seq": 1, "created_at": T,
            "accepted_at": null, "closed_at": null, "last_activity_at": T,
            "peer_last_seen_at": T, "peer_alive": true
        })
    }

    /// `GET /v1/a2a/threads/{id}/messages`.
    #[must_use]
    pub fn messages(id: &str, state: &str, payloads: &[Value]) -> Value {
        let messages: Vec<Value> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| {
                json!({"message_id": MESSAGE_ID, "seq": i.saturating_add(1), "from": "hermes",
                       "payload": p, "created_at": T})
            })
            .collect();
        json!({"thread": thread(id, state), "messages": messages})
    }

    /// `GET /v1/a2a/events`.
    #[must_use]
    pub fn events(pending: Vec<Value>, activity: Vec<Value>, cursor: Option<&str>) -> Value {
        json!({"pending_opens": pending, "activity": activity, "cursor": cursor})
    }

    /// A `job_out`.
    #[must_use]
    pub fn job(id: &str, status: &str) -> Value {
        let ended = matches!(status, "done" | "refused" | "lost");
        let mut job = json!({
            "job_id": id, "host": "excelsior", "tier": "user", "status": status,
            "exit_code": if ended { json!(0) } else { Value::Null },
            "error": null, "duration_ms": null, "output_bytes": null,
            "output_sha256": null, "truncated": null, "command": ["true"]
        });
        if ended && let Some(map) = job.as_object_mut() {
            map.insert("output".into(), json!("ok\n"));
        }
        job
    }

    /// `GET /v1/catalog` with one MCP server.
    #[must_use]
    pub fn catalog_with_mcp(name: &str, url: &str) -> Value {
        json!({"platforms": [
            {"platform": "github", "capability_hint": "repo", "resource_hint": "owner/repo"},
            {"platform": "mcp", "capability_hint": "use", "resource_hint": "a server",
             "servers": [{"name": name, "url": url, "description": "", "tools": null}]}
        ]})
    }

    /// An admin `AgentOut` (every key, as the list route sends it).
    #[must_use]
    pub fn agent(name: &str) -> Value {
        json!({
            "id": AGENT_ID, "name": name, "description": "", "kind": "service",
            "webhook_url": null, "lldap_username": null, "lldap_managed": false,
            "disabled": false, "last_seen_at": null, "parent": null, "sandbox": null,
            "runtime": null, "project": null, "host": null, "placement": "host",
            "lease_expires_at": null, "api_key": null, "webhook_secret": null
        })
    }
}
