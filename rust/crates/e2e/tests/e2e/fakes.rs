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
