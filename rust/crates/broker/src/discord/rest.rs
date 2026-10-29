//! Discord's REST API, the few calls the bot makes, over the shared TLS
//! stack (`agent-auth-tls`: rustls + ring, HTTP/1.1, no compression, no
//! proxy, no redirects). twilight-http is not used: it always enables
//! HTTP/2 and brings its own root store (DEVIATIONS.md).
//!
//! - The bot token is a [`Secret`], sent as a sensitive header, never
//!   logged; errors carry the method, the route and the status only.
//! - Every call has a hard timeout (the client's), and a 429 is retried
//!   after its `retry_after` (bounded, at most [`MAX_RETRIES`] times); a
//!   global limit holds every call until it passes.

use std::sync::Mutex;
use std::time::Duration;

use agent_auth_crypto::Secret;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, USER_AGENT};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::time::Instant;
use twilight_model::channel::message::Embed;

use super::model::{AttachmentMeta, Message};

pub const DISCORD_API: &str = "https://discord.com/api/v10";
/// Per attempt.
const TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RETRIES: u32 = 3;
/// The longest `retry_after` honoured; longer is an error.
const MAX_WAIT: Duration = Duration::from_secs(30);
/// Response bodies read at most this far.
const MAX_BODY: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RestError {
    #[error("discord {method} {route}: {source}")]
    Transport {
        method: Method,
        route: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("discord {method} {route}: HTTP {status}: {body}")]
    Status {
        method: Method,
        route: String,
        status: StatusCode,
        body: String,
    },
    #[error("discord {method} {route}: still rate limited after {MAX_RETRIES} retries")]
    RateLimited { method: Method, route: String },
    #[error("discord {route}: unexpected response: {detail}")]
    Decode { route: String, detail: String },
    #[error("discord client: {0}")]
    Setup(String),
}

/// The REST client.
pub struct Rest {
    http: reqwest::Client,
    base: String,
    auth: HeaderValue,
    /// A global rate limit holds every call until then.
    global_until: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for Rest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rest")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct RateLimit {
    retry_after: f64,
    #[serde(default)]
    global: bool,
}

/// A message as far as the bot reads one back.
#[derive(Debug, Deserialize)]
pub struct MessageRead {
    pub id: String,
    pub channel_id: String,
    #[serde(default)]
    pub embeds: Vec<Embed>,
}

#[derive(Deserialize)]
struct ChannelRead {
    #[serde(default)]
    guild_id: Option<String>,
}

#[derive(Deserialize)]
struct IdOnly {
    id: String,
}

enum Body {
    None,
    Json(Value),
    Multipart { boundary: String, bytes: Vec<u8> },
}

fn parse_id(route: &str, s: &str) -> Result<u64, RestError> {
    s.parse().map_err(|_| RestError::Decode {
        route: route.to_owned(),
        detail: "an id that is not a number".to_owned(),
    })
}

impl Rest {
    /// `base`: [`DISCORD_API`], or a fake server in tests.
    pub fn new(token: &Secret<String>, base: &str) -> Result<Rest, RestError> {
        let tls =
            agent_auth_tls::default_client_config().map_err(|e| RestError::Setup(e.to_string()))?;
        let http = agent_auth_tls::reqwest_builder(tls, TIMEOUT)
            .http1_only()
            .build()
            .map_err(|e| RestError::Setup(e.to_string()))?;
        let mut auth = HeaderValue::from_str(&format!("Bot {}", token.expose())).map_err(|_| {
            RestError::Setup("the bot token is not a valid header value".to_owned())
        })?;
        auth.set_sensitive(true);
        Ok(Rest {
            http,
            base: base.trim_end_matches('/').to_owned(),
            auth,
            global_until: Mutex::new(None),
        })
    }

    fn global_wait(&self) -> Option<Instant> {
        *self
            .global_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_global(&self, until: Instant) {
        let mut g = self
            .global_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *g = Some(g.map_or(until, |cur| cur.max(until)));
    }

    /// One call, with 429 handling. `route` is the path (no secrets: the
    /// interaction token is in some paths, so errors name only the route's
    /// first two segments).
    async fn send(&self, method: Method, path: &str, body: Body) -> Result<Vec<u8>, RestError> {
        let route = route_name(path);
        let url = format!("{}{path}", self.base);
        let mut retries = 0u32;
        loop {
            if let Some(until) = self.global_wait() {
                tokio::time::sleep_until(until).await;
            }
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header(AUTHORIZATION, self.auth.clone())
                .header(
                    USER_AGENT,
                    "DiscordBot (https://github.com/uorux/agent-auth, 0.1)",
                );
            req = match &body {
                Body::None => req,
                Body::Json(v) => req.json(v),
                Body::Multipart { boundary, bytes } => req
                    .header(
                        CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(bytes.clone()),
            };
            let response = req.send().await.map_err(|e| RestError::Transport {
                method: method.clone(),
                route: route.clone(),
                source: e.without_url(),
            })?;
            let status = response.status();
            let bytes = read_capped(response)
                .await
                .map_err(|e| RestError::Transport {
                    method: method.clone(),
                    route: route.clone(),
                    source: e.without_url(),
                })?;
            if status == StatusCode::TOO_MANY_REQUESTS {
                retries = retries.saturating_add(1);
                let limit: Option<RateLimit> = serde_json::from_slice(&bytes).ok();
                let wait = limit
                    .as_ref()
                    .map(|l| l.retry_after)
                    .filter(|s| s.is_finite() && *s >= 0.0)
                    .map_or(Duration::from_secs(1), Duration::from_secs_f64);
                if retries > MAX_RETRIES || wait > MAX_WAIT {
                    return Err(RestError::RateLimited { method, route });
                }
                let until = super::gateway::later(wait);
                if limit.is_some_and(|l| l.global) {
                    self.set_global(until);
                }
                tracing::debug!(%route, ?wait, "discord rate limit");
                tokio::time::sleep_until(until).await;
                continue;
            }
            if !status.is_success() {
                let text = String::from_utf8_lossy(&bytes);
                return Err(RestError::Status {
                    method,
                    route,
                    status,
                    body: text.chars().take(300).collect(),
                });
            }
            return Ok(bytes);
        }
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Body,
    ) -> Result<T, RestError> {
        let bytes = self.send(method, path, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| RestError::Decode {
            route: route_name(path),
            detail: e.to_string(),
        })
    }

    /// Post a message; its id.
    pub async fn create_message(&self, channel: u64, msg: &Message) -> Result<u64, RestError> {
        let path = format!("/channels/{channel}/messages");
        let read: IdOnly = self.json(Method::POST, &path, message_body(msg)?).await?;
        parse_id(&path, &read.id)
    }

    pub async fn edit_message(
        &self,
        channel: u64,
        message: u64,
        msg: &Message,
    ) -> Result<(), RestError> {
        let path = format!("/channels/{channel}/messages/{message}");
        self.send(Method::PATCH, &path, message_body(msg)?)
            .await
            .map(drop)
    }

    pub async fn get_message(&self, channel: u64, message: u64) -> Result<MessageRead, RestError> {
        self.json(
            Method::GET,
            &format!("/channels/{channel}/messages/{message}"),
            Body::None,
        )
        .await
    }

    /// A thread on a message; the thread's (channel) id.
    pub async fn start_thread(
        &self,
        channel: u64,
        message: u64,
        name: &str,
    ) -> Result<u64, RestError> {
        let path = format!("/channels/{channel}/messages/{message}/threads");
        let body = json!({"name": name, "auto_archive_duration": 1440});
        let read: IdOnly = self.json(Method::POST, &path, Body::Json(body)).await?;
        parse_id(&path, &read.id)
    }

    /// The guild a channel is in (none for a DM).
    pub async fn channel_guild(&self, channel: u64) -> Result<Option<u64>, RestError> {
        let path = format!("/channels/{channel}");
        let read: ChannelRead = self.json(Method::GET, &path, Body::None).await?;
        read.guild_id.map(|g| parse_id(&path, &g)).transpose()
    }

    /// Replace the application's slash commands (in a guild: instant).
    pub async fn put_commands(
        &self,
        app: u64,
        guild: Option<u64>,
        commands: &Value,
    ) -> Result<(), RestError> {
        let path = match guild {
            Some(g) => format!("/applications/{app}/guilds/{g}/commands"),
            None => format!("/applications/{app}/commands"),
        };
        self.send(Method::PUT, &path, Body::Json(commands.clone()))
            .await
            .map(drop)
    }

    /// Answer an interaction (within 3 s of receiving it).
    pub async fn respond(
        &self,
        interaction: u64,
        token: &str,
        response: &Value,
    ) -> Result<(), RestError> {
        let path = format!("/interactions/{interaction}/{token}/callback");
        self.send(Method::POST, &path, Body::Json(response.clone()))
            .await
            .map(drop)
    }

    /// Edit the interaction's original message.
    pub async fn edit_original(
        &self,
        app: u64,
        token: &str,
        msg: &Message,
    ) -> Result<(), RestError> {
        let path = format!("/webhooks/{app}/{token}/messages/@original");
        self.send(Method::PATCH, &path, message_body(msg)?)
            .await
            .map(drop)
    }

    /// A followup message after a deferred answer.
    pub async fn followup(&self, app: u64, token: &str, msg: &Message) -> Result<(), RestError> {
        let path = format!("/webhooks/{app}/{token}");
        self.send(Method::POST, &path, message_body(msg)?)
            .await
            .map(drop)
    }
}

/// The route for logs and errors: the first two path segments (an
/// interaction or webhook token is never included).
fn route_name(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .take(2)
        .map(|s| {
            if s.bytes().all(|b| b.is_ascii_digit()) {
                ":id"
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, reqwest::Error> {
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let room = MAX_BODY.saturating_sub(out.len());
        out.extend_from_slice(chunk.get(..room.min(chunk.len())).unwrap_or_default());
        if out.len() >= MAX_BODY {
            break;
        }
    }
    Ok(out)
}

/// JSON, or multipart (`payload_json` + `files[n]`) when there are files.
fn message_body(msg: &Message) -> Result<Body, RestError> {
    if msg.files.is_empty() {
        let v = serde_json::to_value(msg).map_err(|e| RestError::Setup(e.to_string()))?;
        return Ok(Body::Json(v));
    }
    let mut msg = msg.clone();
    msg.attachments = Some(
        msg.files
            .iter()
            .enumerate()
            .map(|(id, f)| AttachmentMeta {
                id,
                filename: f.name.clone(),
            })
            .collect(),
    );
    let payload = serde_json::to_string(&msg).map_err(|e| RestError::Setup(e.to_string()))?;
    let boundary = format!("agentauth{}", uuid::Uuid::new_v4().simple());
    let mut bytes = Vec::new();
    let mut part = |headers: String, body: &[u8]| {
        bytes.extend_from_slice(format!("--{boundary}\r\n{headers}\r\n\r\n").as_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\r\n");
    };
    part(
        "Content-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json"
            .to_owned(),
        payload.as_bytes(),
    );
    for (i, f) in msg.files.iter().enumerate() {
        // File names are ours (`output-1234abcd.txt`), never agent text.
        let name: String = f
            .name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
            .collect();
        part(
            format!(
                "Content-Disposition: form-data; name=\"files[{i}]\"; filename=\"{name}\"\r\nContent-Type: text/plain; charset=utf-8"
            ),
            &f.bytes,
        );
    }
    bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(Body::Multipart { boundary, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_hide_tokens() {
        assert_eq!(
            route_name("/interactions/123/secret-token/callback"),
            "interactions/:id"
        );
        assert_eq!(route_name("/webhooks/1/tok"), "webhooks/:id");
        assert_eq!(route_name("/channels/5/messages"), "channels/:id");
    }

    #[test]
    fn multipart_carries_payload_and_files() {
        let msg = Message {
            files: vec![super::super::model::File {
                name: "output-1.txt".to_owned(),
                bytes: b"hello".to_vec(),
            }],
            ..Message::text("x")
        };
        let Ok(Body::Multipart { boundary, bytes }) = message_body(&msg) else {
            panic!("multipart expected");
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("name=\"payload_json\""));
        assert!(text.contains("\"attachments\":[{\"id\":0,\"filename\":\"output-1.txt\"}]"));
        assert!(text.contains("name=\"files[0]\"; filename=\"output-1.txt\""));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
    }
}
