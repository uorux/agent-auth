//! `BrokerClient`: the broker's HTTP API, typed with the `wire` crate.

use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use agent_auth_core::canonical_json::python_float_repr;
use agent_auth_wire::secret::WireSecret;
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use url::{Host, Url};

use crate::error::{ClientError, transport};

/// Where the broker is when `AGENT_AUTH_URL` is not set.
pub const DEFAULT_URL: &str = "https://agent-auth.rooty.dev";
/// The header naming the caller's session.
pub const SESSION_HEADER: &str = "X-Agent-Session";
/// A plain call's timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The most a broker answer may be (job output and wiki pages are at most
/// 1 MiB; this leaves room).
const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;

/// Where the broker is and who is calling. [`Config::from_env`] reads
/// `AGENT_AUTH_URL`, `AGENT_AUTH_API_KEY`, `AGENT_AUTH_ADMIN_TOKEN` and
/// `AGENT_AUTH_SESSION`; an empty variable counts as unset.
#[derive(Clone, Default)]
pub struct Config {
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub admin_token: Option<String>,
    pub session_id: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field(
                "admin_token",
                &self.admin_token.as_ref().map(|_| "[redacted]"),
            )
            .field("session_id", &self.session_id)
            .finish()
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Config {
    #[must_use]
    pub fn from_env() -> Self {
        Config {
            base_url: env("AGENT_AUTH_URL"),
            api_key: env("AGENT_AUTH_API_KEY"),
            admin_token: env("AGENT_AUTH_ADMIN_TOKEN"),
            session_id: env("AGENT_AUTH_SESSION"),
        }
    }
}

/// The broker URL, if it is one this client may send keys to: `https://`,
/// or `http://` to a loopback address (a broker on the same machine, or a
/// test). Trailing slashes are dropped.
pub fn broker_url(text: &str) -> Result<Url, String> {
    let url = Url::parse(text.trim_end_matches('/'))
        .map_err(|e| format!("AGENT_AUTH_URL is not a URL ({e}): {text}"))?;
    let loopback = match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" if url.host().is_some() => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(format!(
            "AGENT_AUTH_URL must be an https:// URL (http:// only to a loopback address): {text}"
        )),
    }
}

/// Which credential a call carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    /// The agent's API key, plus its session if it has one.
    Agent,
    /// The admin token, never a session.
    Admin,
}

/// One call: method, path segments (each percent-encoded), query, body.
struct Call {
    method: Method,
    path: Vec<String>,
    query: Vec<(&'static str, String)>,
    body: Option<Value>,
    auth: Auth,
    timeout: Duration,
}

impl Call {
    fn new(method: Method, path: &[&str], auth: Auth) -> Self {
        Call {
            method,
            path: path.iter().map(|s| (*s).to_owned()).collect(),
            query: Vec::new(),
            body: None,
            auth,
            timeout: DEFAULT_TIMEOUT,
        }
    }
    fn get(path: &[&str]) -> Self {
        Call::new(Method::GET, path, Auth::Agent)
    }
    fn post(path: &[&str]) -> Self {
        Call::new(Method::POST, path, Auth::Agent)
    }
    fn admin(mut self) -> Self {
        self.auth = Auth::Admin;
        self
    }
    fn query(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.query.push((key, value.into()));
        self
    }
    fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }
    fn timeout_secs(mut self, secs: f64) -> Self {
        self.timeout = Duration::try_from_secs_f64(secs).unwrap_or(DEFAULT_TIMEOUT);
        self
    }
}

/// A body checked against the wire type the broker parses it into (same
/// limits, same messages), then sent as that type serializes it.
fn checked<T: DeserializeOwned + Serialize>(value: Value) -> Result<Value, ClientError> {
    let typed: T = agent_auth_wire::error::from_value(value)
        .map_err(|e| ClientError::invalid(e.message().to_owned()))?;
    serde_json::to_value(&typed).map_err(|e| ClientError::invalid(e.to_string()))
}

/// The broker's HTTP API as the agent (`AGENT_AUTH_API_KEY`) or the
/// operator (`AGENT_AUTH_ADMIN_TOKEN`).
///
/// Clones share the session: [`BrokerClient::create_session`] on one is
/// seen by all. [`BrokerClient::with_session`] makes a client with a
/// session of its own.
#[derive(Clone)]
pub struct BrokerClient {
    http: reqwest::Client,
    base: Result<Url, String>,
    api_key: Option<WireSecret>,
    admin_token: Option<WireSecret>,
    session: Arc<RwLock<String>>,
}

impl std::fmt::Debug for BrokerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerClient")
            .field("base", &self.base)
            .field("session", &self.session_id())
            .finish_non_exhaustive()
    }
}

impl BrokerClient {
    /// A client for `config` (see [`Config::from_env`]). A bad URL or a
    /// missing key is reported by each call (status 0), as the Python did.
    pub fn new(config: Config) -> Result<Self, ClientError> {
        let tls = agent_auth_tls::default_client_config()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let http = agent_auth_tls::reqwest_builder(tls, DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| transport(&e))?;
        Ok(Self::with_http(http, config))
    }

    /// [`BrokerClient::new`] over an existing HTTP client (shares its pool).
    #[must_use]
    pub fn with_http(http: reqwest::Client, config: Config) -> Self {
        let base = broker_url(config.base_url.as_deref().unwrap_or(DEFAULT_URL));
        let secret = |s: Option<String>| s.and_then(|s| WireSecret::new(s).ok());
        BrokerClient {
            http,
            base,
            api_key: secret(config.api_key),
            admin_token: secret(config.admin_token),
            session: Arc::new(RwLock::new(config.session_id.unwrap_or_default())),
        }
    }

    /// From the environment ([`Config::from_env`]).
    pub fn from_env() -> Result<Self, ClientError> {
        BrokerClient::new(Config::from_env())
    }

    /// The same broker and keys with a session of its own: `Some(id)` sends
    /// `X-Agent-Session: id`, `None` none. Never touches this client's.
    #[must_use]
    pub fn with_session(&self, session: Option<&str>) -> Self {
        BrokerClient {
            session: Arc::new(RwLock::new(session.unwrap_or_default().to_owned())),
            ..self.clone()
        }
    }

    /// The session sent with agent calls, if any.
    #[must_use]
    pub fn session_id(&self) -> Option<String> {
        let s = self.session.read().unwrap_or_else(PoisonError::into_inner);
        (!s.is_empty()).then(|| s.clone())
    }

    /// Send `session` (or none) from now on, on this client and its clones.
    pub fn set_session_id(&self, session: Option<&str>) {
        let mut s = self.session.write().unwrap_or_else(PoisonError::into_inner);
        *s = session.unwrap_or_default().to_owned();
    }

    /// Forget the session if it is still `session` (it may have been
    /// replaced meanwhile); whether it was.
    pub fn clear_session_if(&self, session: &str) -> bool {
        let mut s = self.session.write().unwrap_or_else(PoisonError::into_inner);
        if *s == session {
            s.clear();
            true
        } else {
            false
        }
    }

    /// The broker's base URL, or why it is unusable.
    pub fn base_url(&self) -> Result<&Url, ClientError> {
        self.base
            .as_ref()
            .map_err(|e| ClientError::broker(0, e.clone()))
    }

    fn token(&self, auth: Auth) -> Result<&WireSecret, ClientError> {
        let (token, missing) = match auth {
            Auth::Agent => (&self.api_key, "AGENT_AUTH_API_KEY not set"),
            Auth::Admin => (&self.admin_token, "AGENT_AUTH_ADMIN_TOKEN not set"),
        };
        token
            .as_ref()
            .ok_or_else(|| ClientError::broker(0, missing))
    }

    /// Fails as a call would before anything is sent (no key, bad URL).
    fn ready(&self, auth: Auth) -> Result<(), ClientError> {
        self.token(auth)?;
        self.base_url()?;
        Ok(())
    }

    async fn call<T: DeserializeOwned>(&self, call: Call) -> Result<T, ClientError> {
        let token = self.token(call.auth)?;
        // A segment is percent-encoded (`/` too), but `.` and `..` would be
        // dropped and an empty one would change the route: refuse them.
        if let Some(bad) = call
            .path
            .iter()
            .find(|s| matches!(s.as_str(), "" | "." | ".."))
        {
            return Err(ClientError::broker(0, format!("not an id: {bad:?}")));
        }
        let mut url = self.base_url()?.clone();
        url.path_segments_mut()
            .map_err(|()| ClientError::broker(0, "AGENT_AUTH_URL cannot have a path"))?
            .pop_if_empty()
            .extend(&call.path);
        if !call.query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &call.query {
                pairs.append_pair(k, v);
            }
        }
        let mut req = self
            .http
            .request(call.method, url)
            .timeout(call.timeout)
            .header(AUTHORIZATION, format!("Bearer {}", token.expose()));
        if call.auth == Auth::Agent
            && let Some(session) = self.session_id()
        {
            req = req.header(SESSION_HEADER, session);
        }
        if let Some(body) = &call.body {
            let bytes =
                serde_json::to_vec(body).map_err(|e| ClientError::invalid(e.to_string()))?;
            req = req.header(CONTENT_TYPE, "application/json").body(bytes);
        }
        let mut resp = req.send().await.map_err(|e| transport(&e))?;
        let status = resp.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| transport(&e))? {
            if bytes.len().saturating_add(chunk.len()) > MAX_ANSWER_BYTES {
                return Err(ClientError::Decode(format!(
                    "the broker's answer is over {MAX_ANSWER_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        if status.as_u16() >= 400 {
            return Err(ClientError::broker(status.as_u16(), error_detail(&bytes)));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| ClientError::Decode(format!("could not read the broker's answer: {e}")))
    }

    // ----------------------------------------------------------------- agent

    /// `GET /v1/me`.
    pub async fn me(&self) -> Result<agent_auth_wire::agent::Me, ClientError> {
        self.call(Call::get(&["v1", "me"])).await
    }

    /// `POST /v1/attention`.
    pub async fn attention(
        &self,
        text: &str,
        urgency: &str,
    ) -> Result<agent_auth_wire::agent::AttentionOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::agent::AttentionBody>(
            json!({"text": text, "urgency": urgency}),
        )?;
        self.call(Call::post(&["v1", "attention"]).body(body)).await
    }

    /// `GET /v1/catalog`.
    pub async fn catalog(&self) -> Result<agent_auth_wire::catalog::CatalogOut, ClientError> {
        self.call(Call::get(&["v1", "catalog"])).await
    }

    /// `GET /v1/wiki?prefix=`.
    pub async fn wiki_list(
        &self,
        prefix: &str,
    ) -> Result<agent_auth_wire::wiki::WikiList, ClientError> {
        self.call(Call::get(&["v1", "wiki"]).query("prefix", prefix))
            .await
    }

    /// `GET /v1/wiki/page?path=`.
    pub async fn wiki_read(
        &self,
        path: &str,
    ) -> Result<agent_auth_wire::wiki::WikiPage, ClientError> {
        self.call(Call::get(&["v1", "wiki", "page"]).query("path", path))
            .await
    }

    /// `GET /v1/wiki/search?q=&limit=`.
    pub async fn wiki_search(
        &self,
        query: &str,
        limit: i64,
    ) -> Result<agent_auth_wire::wiki::WikiSearch, ClientError> {
        self.call(
            Call::get(&["v1", "wiki", "search"])
                .query("q", query)
                .query("limit", limit.to_string()),
        )
        .await
    }

    /// `PUT /v1/wiki/page`.
    pub async fn wiki_write(
        &self,
        path: &str,
        content: &str,
        summary: &str,
        base_sha: Option<&str>,
    ) -> Result<agent_auth_wire::wiki::WikiWritten, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::wiki::PageWrite>(
            json!({"path": path, "content": content, "summary": summary, "base_sha": base_sha}),
        )?;
        self.call(Call::new(Method::PUT, &["v1", "wiki", "page"], Auth::Agent).body(body))
            .await
    }

    /// `POST /v1/wiki/delete`.
    pub async fn wiki_delete(
        &self,
        path: &str,
        summary: &str,
        base_sha: Option<&str>,
    ) -> Result<agent_auth_wire::wiki::WikiDeleted, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::wiki::PageDelete>(
            json!({"path": path, "summary": summary, "base_sha": base_sha}),
        )?;
        self.call(Call::post(&["v1", "wiki", "delete"]).body(body))
            .await
    }

    /// `POST /v1/requests`. `scope` None is `{}`.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_access(
        &self,
        platform: &str,
        capability: &str,
        resource: &str,
        justification: &str,
        duration: &str,
        scope: Option<Map<String, Value>>,
        on_behalf_of_thread: Option<&str>,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::agent::RequestCreate>(json!({
            "platform": platform,
            "capability": capability,
            "resource": resource,
            "scope": scope.unwrap_or_default(),
            "justification": justification,
            "requested_duration": duration,
            "on_behalf_of_thread": on_behalf_of_thread,
        }))?;
        self.call(Call::post(&["v1", "requests"]).body(body)).await
    }

    /// `GET /v1/requests/{id}`.
    pub async fn get_request(
        &self,
        id: &str,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        self.call(Call::get(&["v1", "requests", id])).await
    }

    /// Wait up to `total` seconds for a decision, in slices
    /// (`GET /v1/requests/{id}/wait?timeout=`).
    pub async fn wait(
        &self,
        id: &str,
        total: f64,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        crate::poll::sliced(
            total,
            |t| {
                self.call(
                    Call::get(&["v1", "requests", id, "wait"])
                        .query("timeout", python_float_repr(t))
                        .timeout_secs(t + 10.0),
                )
            },
            crate::poll::request_settled,
        )
        .await
    }

    /// `POST /v1/requests/{id}/retry`.
    pub async fn retry(
        &self,
        id: &str,
        justification: &str,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body =
            checked::<agent_auth_wire::agent::RetryBody>(json!({"justification": justification}))?;
        self.call(Call::post(&["v1", "requests", id, "retry"]).body(body))
            .await
    }

    /// `POST /v1/requests/{id}/escalate`.
    pub async fn escalate(
        &self,
        id: &str,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        self.call(Call::post(&["v1", "requests", id, "escalate"]))
            .await
    }

    /// `GET /v1/grants?status=`.
    pub async fn grants(
        &self,
        status: &str,
    ) -> Result<Vec<agent_auth_wire::agent::GrantOut>, ClientError> {
        self.call(Call::get(&["v1", "grants"]).query("status", status))
            .await
    }

    /// `GET /v1/grants/{id}/credential`.
    pub async fn credential(
        &self,
        grant: &str,
    ) -> Result<agent_auth_wire::agent::CredentialOut, ClientError> {
        self.call(Call::get(&["v1", "grants", grant, "credential"]))
            .await
    }

    /// `POST /v1/grants/{id}/release`: end one of this agent's grants now.
    pub async fn release(
        &self,
        grant: &str,
    ) -> Result<agent_auth_wire::agent::ReleaseOut, ClientError> {
        self.call(Call::post(&["v1", "grants", grant, "release"]))
            .await
    }

    // ------------------------------------------------------------------ mail

    /// `GET /v1/mail/{grant}/messages`. Each new message is screened by a
    /// model first: allow for that (180 s).
    pub async fn mail_list(
        &self,
        grant: &str,
        limit: i64,
        page: Option<&str>,
        search: Option<&str>,
    ) -> Result<agent_auth_wire::mail::MailList, ClientError> {
        let mut call = Call::get(&["v1", "mail", grant, "messages"])
            .query("limit", limit.to_string())
            .timeout_secs(180.0);
        if let Some(p) = page.filter(|p| !p.is_empty()) {
            call = call.query("page", p);
        }
        if let Some(s) = search.filter(|s| !s.is_empty()) {
            call = call.query("search", s);
        }
        self.call(call).await
    }

    /// `GET /v1/mail/{grant}/messages/{id}`.
    pub async fn mail_read(
        &self,
        grant: &str,
        message: &str,
    ) -> Result<agent_auth_wire::mail::MailMessage, ClientError> {
        self.call(Call::get(&["v1", "mail", grant, "messages", message]).timeout_secs(60.0))
            .await
    }

    /// `GET /v1/mail/{grant}/messages/{id}/attachments/{index}`.
    pub async fn mail_attachment(
        &self,
        grant: &str,
        message: &str,
        index: u64,
    ) -> Result<agent_auth_wire::mail::MailAttachment, ClientError> {
        let index = index.to_string();
        self.call(
            Call::get(&[
                "v1",
                "mail",
                grant,
                "messages",
                message,
                "attachments",
                &index,
            ])
            .timeout_secs(60.0),
        )
        .await
    }

    /// `POST /v1/mail/{grant}/send`: reviewed before it leaves.
    pub async fn mail_send(
        &self,
        grant: &str,
        body: &str,
        to: Option<&[String]>,
        subject: Option<&str>,
        reply_to: Option<&str>,
    ) -> Result<agent_auth_wire::mail::SendOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::mail::SendBody>(
            json!({"to": to, "subject": subject, "body": body, "reply_to": reply_to}),
        )?;
        self.call(
            Call::post(&["v1", "mail", grant, "send"])
                .body(body)
                .timeout_secs(120.0),
        )
        .await
    }

    /// `GET /admin/mail/held`.
    pub async fn admin_mail_held(
        &self,
    ) -> Result<Vec<agent_auth_wire::mail::MailItem>, ClientError> {
        self.call(Call::get(&["admin", "mail", "held"]).admin())
            .await
    }

    /// `POST /admin/mail/items/{id}/release|discard`.
    pub async fn admin_mail_decide(
        &self,
        item: &str,
        release: bool,
        by: &str,
    ) -> Result<agent_auth_wire::mail::MailItem, ClientError> {
        let action = if release { "release" } else { "discard" };
        let body = checked::<agent_auth_wire::mail::DecideBody>(json!({ "by": by }))?;
        self.call(
            Call::post(&["admin", "mail", "items", item, action])
                .admin()
                .body(body)
                .timeout_secs(120.0),
        )
        .await
    }

    // -------------------------------------------------------------- sessions

    /// `POST /v1/sessions`; the new session is this client's (and its
    /// clones') from now on.
    pub async fn create_session(
        &self,
        label: &str,
    ) -> Result<agent_auth_wire::a2a::SessionOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::a2a::SessionCreate>(json!({"label": label}))?;
        let out: agent_auth_wire::a2a::SessionOut = self
            .call(Call::post(&["v1", "sessions"]).body(body))
            .await?;
        self.set_session_id(Some(&out.session_id.to_string()));
        Ok(out)
    }

    /// `POST /v1/sessions/close` (the session this client sends).
    pub async fn close_session(&self) -> Result<agent_auth_wire::a2a::SessionClosed, ClientError> {
        self.call(Call::post(&["v1", "sessions", "close"])).await
    }

    // ------------------------------------------------------------------- a2a

    /// `GET /v1/a2a/check?peer=&direction=[&topic=]`.
    pub async fn a2a_check(
        &self,
        peer: &str,
        direction: &str,
        topic: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::A2aCheckOut, ClientError> {
        let mut call = Call::get(&["v1", "a2a", "check"])
            .query("peer", peer)
            .query("direction", direction);
        if let Some(topic) = topic.filter(|t| !t.is_empty()) {
            call = call.query("topic", topic);
        }
        self.call(call).await
    }

    /// `POST /v1/a2a/threads`: open a thread with its first message.
    pub async fn a2a_open(
        &self,
        to: &str,
        payload: Map<String, Value>,
        topic: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::a2a::ThreadOpenBody>(
            json!({"to": to, "topic": topic, "payload": payload}),
        )?;
        self.call(Call::post(&["v1", "a2a", "threads"]).body(body))
            .await
    }

    /// `POST /v1/a2a/threads/{id}/messages`.
    pub async fn a2a_send(
        &self,
        thread: &str,
        payload: Map<String, Value>,
    ) -> Result<agent_auth_wire::a2a::MessageSent, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::a2a::ThreadMessageBody>(json!({"payload": payload}))?;
        self.call(Call::post(&["v1", "a2a", "threads", thread, "messages"]).body(body))
            .await
    }

    /// Read a thread past `after_seq`, waiting up to `wait` seconds in
    /// slices for a message or the thread closing.
    pub async fn a2a_poll(
        &self,
        thread: &str,
        after_seq: i64,
        wait: f64,
    ) -> Result<agent_auth_wire::a2a::ThreadMessages, ClientError> {
        crate::poll::sliced(
            wait,
            |t| {
                self.call(
                    Call::get(&["v1", "a2a", "threads", thread, "messages"])
                        .query("after_seq", after_seq.to_string())
                        .query("wait", python_float_repr(t))
                        .timeout_secs(t + 10.0),
                )
            },
            crate::poll::messages_settled,
        )
        .await
    }

    /// `GET /v1/a2a/threads[?state=][&role=]`.
    pub async fn a2a_threads(
        &self,
        state: Option<&str>,
        role: Option<&str>,
    ) -> Result<Vec<agent_auth_wire::a2a::ThreadOut>, ClientError> {
        let mut call = Call::get(&["v1", "a2a", "threads"]);
        if let Some(state) = state.filter(|s| !s.is_empty()) {
            call = call.query("state", state);
        }
        if let Some(role) = role.filter(|r| !r.is_empty()) {
            call = call.query("role", role);
        }
        self.call(call).await
    }

    /// `GET /v1/a2a/threads/{id}`.
    pub async fn a2a_thread(
        &self,
        thread: &str,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.call(Call::get(&["v1", "a2a", "threads", thread]))
            .await
    }

    /// `POST /v1/a2a/threads/{id}/accept`.
    pub async fn a2a_accept(
        &self,
        thread: &str,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.call(Call::post(&["v1", "a2a", "threads", thread, "accept"]))
            .await
    }

    /// `POST /v1/a2a/threads/{id}/reject`.
    pub async fn a2a_reject(
        &self,
        thread: &str,
        reason: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::a2a::ThreadCloseBody>(json!({"reason": reason}))?;
        self.call(Call::post(&["v1", "a2a", "threads", thread, "reject"]).body(body))
            .await
    }

    /// `POST /v1/a2a/threads/{id}/close`.
    pub async fn a2a_close(
        &self,
        thread: &str,
        reason: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::a2a::ThreadCloseBody>(json!({"reason": reason}))?;
        self.call(Call::post(&["v1", "a2a", "threads", thread, "close"]).body(body))
            .await
    }

    /// Pending opens and thread activity past `after`, waiting up to
    /// `wait` seconds in slices for any (`GET /v1/a2a/events`).
    pub async fn a2a_events(
        &self,
        wait: f64,
        after: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::EventsSnapshot, ClientError> {
        crate::poll::sliced(
            wait,
            |t| {
                let mut call = Call::get(&["v1", "a2a", "events"])
                    .query("wait", python_float_repr(t))
                    .timeout_secs(t + 10.0);
                if let Some(after) = after.filter(|a| !a.is_empty()) {
                    call = call.query("after", after);
                }
                self.call(call)
            },
            crate::poll::events_settled,
        )
        .await
    }

    // --------------------------------------------------- audit, containment

    /// `GET /v1/audit/events[?since=|?after=][&limit=]` (policy
    /// `audit.readers`). `after` is a page's `cursor` (exact, exclusive);
    /// it wins over `since`.
    pub async fn audit_events(
        &self,
        since: Option<&str>,
        after: Option<&str>,
        limit: Option<i64>,
    ) -> Result<agent_auth_wire::audit::AuditPage, ClientError> {
        let mut call = Call::get(&["v1", "audit", "events"]);
        if let Some(after) = after {
            call = call.query("after", after);
        } else if let Some(since) = since {
            call = call.query("since", since);
        }
        if let Some(limit) = limit {
            call = call.query("limit", limit.to_string());
        }
        self.call(call).await
    }

    /// `POST /v1/containment` (policy `containment.agents`).
    pub async fn contain(
        &self,
        matches: Map<String, Value>,
        reason: &str,
        evidence: &str,
    ) -> Result<agent_auth_wire::containment::ContainResult, ClientError> {
        self.ready(Auth::Agent)?;
        let body = checked::<agent_auth_wire::containment::ContainBody>(
            json!({"match": matches, "reason": reason, "evidence": evidence}),
        )?;
        self.call(Call::post(&["v1", "containment"]).body(body))
            .await
    }

    /// `GET /v1/containment` (policy `containment.agents`).
    pub async fn containment(
        &self,
    ) -> Result<Vec<agent_auth_wire::containment::ContainmentEntry>, ClientError> {
        self.call(Call::get(&["v1", "containment"])).await
    }

    // -------------------------------------------------------- host commands

    /// A host job, waiting up to `wait` seconds in slices for it to end
    /// (`GET /v1/hostexec/jobs/{id}?wait=`).
    pub async fn host_job(
        &self,
        job: &str,
        wait: f64,
    ) -> Result<agent_auth_wire::hostexec::JobOut, ClientError> {
        crate::poll::sliced(
            wait,
            |t| {
                self.call(
                    Call::get(&["v1", "hostexec", "jobs", job])
                        .query("wait", python_float_repr(t))
                        .timeout_secs(t + 15.0),
                )
            },
            crate::poll::job_settled,
        )
        .await
    }

    /// Run one command in a granted shell: exactly one
    /// `POST /v1/hostexec/shells/{grant}/exec` (it must not be sent twice),
    /// waiting at most a slice there; the rest of `wait` is spent on the job
    /// it started.
    pub async fn host_shell_exec(
        &self,
        grant: &str,
        argv: &[String],
        cwd: Option<&str>,
        stdin: Option<&str>,
        timeout: Option<i64>,
        wait: f64,
    ) -> Result<agent_auth_wire::hostexec::JobOut, ClientError> {
        self.ready(Auth::Agent)?;
        let wait = crate::poll::clamp_total(wait);
        let first = wait.min(crate::poll::POLL_SLICE);
        let body = checked::<agent_auth_wire::hostexec::ShellExecBody>(json!({
            "argv": argv, "cwd": cwd, "stdin": stdin, "timeout": timeout, "wait": first,
        }))?;
        let job: agent_auth_wire::hostexec::JobOut = self
            .call(
                Call::post(&["v1", "hostexec", "shells", grant, "exec"])
                    .body(body)
                    .timeout_secs(first + 30.0),
            )
            .await?;
        if wait > first && !job.status.has_ended() {
            // The Python looked for `job["id"]`, which a job never has, so
            // it never waited past the first slice.
            return self.host_job(&job.job_id.to_string(), wait - first).await;
        }
        Ok(job)
    }

    /// `POST /v1/hostexec/shells/{grant}/close`.
    pub async fn host_shell_close(
        &self,
        grant: &str,
    ) -> Result<agent_auth_wire::hostexec::ShellClosed, ClientError> {
        self.call(Call::post(&["v1", "hostexec", "shells", grant, "close"]))
            .await
    }

    // ----------------------------------------------------------------- admin

    /// `POST /admin/agents`.
    #[allow(clippy::too_many_arguments)]
    pub async fn admin_create_agent(
        &self,
        name: &str,
        description: &str,
        webhook_url: Option<&str>,
        lldap_username: Option<&str>,
        kind: &str,
        runtime: Option<&str>,
        project: Option<&str>,
        host: Option<&str>,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::AgentCreate>(json!({
            "name": name,
            "description": description,
            "kind": kind,
            "runtime": runtime,
            "project": project,
            "host": host,
            "webhook_url": webhook_url,
            "lldap_username": lldap_username,
        }))?;
        self.call(Call::post(&["admin", "agents"]).admin().body(body))
            .await
    }

    /// `PATCH /admin/agents/{id-or-name}/attributes`: only the fields given
    /// (`Some("")` clears one).
    pub async fn admin_set_attributes(
        &self,
        agent: &str,
        runtime: Option<&str>,
        project: Option<&str>,
        host: Option<&str>,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.ready(Auth::Admin)?;
        let mut fields = Map::new();
        for (key, value) in [("runtime", runtime), ("project", project), ("host", host)] {
            if let Some(value) = value {
                fields.insert(key.to_owned(), Value::String(value.to_owned()));
            }
        }
        let body = checked::<agent_auth_wire::admin::AgentAttributesBody>(Value::Object(fields))?;
        self.call(
            Call::new(
                Method::PATCH,
                &["admin", "agents", agent, "attributes"],
                Auth::Admin,
            )
            .body(body),
        )
        .await
    }

    /// `POST /admin/agents/{id-or-name}/rename`.
    pub async fn admin_rename_agent(
        &self,
        agent: &str,
        name: &str,
    ) -> Result<agent_auth_wire::admin::AgentRenamed, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::AgentRenameBody>(json!({"name": name}))?;
        self.call(
            Call::post(&["admin", "agents", agent, "rename"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `POST /admin/agents/{id}/rotate-lldap-password`.
    pub async fn admin_rotate_lldap_password(
        &self,
        agent: &str,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.call(Call::post(&["admin", "agents", agent, "rotate-lldap-password"]).admin())
            .await
    }

    /// `POST /admin/agents/{id}/rotate-webhook-secret`.
    pub async fn admin_rotate_webhook_secret(
        &self,
        agent: &str,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.call(Call::post(&["admin", "agents", agent, "rotate-webhook-secret"]).admin())
            .await
    }

    /// `POST /admin/agents/{id}/set-webhook` (None clears it).
    pub async fn admin_set_webhook(
        &self,
        agent: &str,
        webhook_url: Option<&str>,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body =
            checked::<agent_auth_wire::admin::SetWebhookBody>(json!({"webhook_url": webhook_url}))?;
        self.call(
            Call::post(&["admin", "agents", agent, "set-webhook"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `POST /admin/agents/{id}/set-kind`.
    pub async fn admin_set_kind(
        &self,
        agent: &str,
        kind: &str,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::SetKindBody>(json!({"kind": kind}))?;
        self.call(
            Call::post(&["admin", "agents", agent, "set-kind"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `GET /admin/agents`.
    pub async fn admin_list_agents(
        &self,
    ) -> Result<Vec<agent_auth_wire::admin::AgentOut>, ClientError> {
        self.call(Call::get(&["admin", "agents"]).admin()).await
    }

    /// `POST /admin/agents/{id}/rotate-key`.
    pub async fn admin_rotate_key(
        &self,
        agent: &str,
    ) -> Result<agent_auth_wire::admin::AgentOut, ClientError> {
        self.call(Call::post(&["admin", "agents", agent, "rotate-key"]).admin())
            .await
    }

    /// `POST /admin/agents/{id}/disable`.
    pub async fn admin_disable_agent(
        &self,
        agent: &str,
    ) -> Result<agent_auth_wire::admin::Disabled, ClientError> {
        self.call(Call::post(&["admin", "agents", agent, "disable"]).admin())
            .await
    }

    /// `POST /admin/agents/{id}/enable`.
    pub async fn admin_enable_agent(
        &self,
        agent: &str,
    ) -> Result<agent_auth_wire::admin::Enabled, ClientError> {
        self.call(Call::post(&["admin", "agents", agent, "enable"]).admin())
            .await
    }

    /// `GET /admin/rules`.
    pub async fn admin_list_rules(
        &self,
    ) -> Result<Vec<agent_auth_wire::admin::RuleOut>, ClientError> {
        self.call(Call::get(&["admin", "rules"]).admin()).await
    }

    /// `DELETE /admin/rules/{id}`.
    pub async fn admin_delete_rule(
        &self,
        rule: &str,
    ) -> Result<agent_auth_wire::common::Ok, ClientError> {
        self.call(Call::new(
            Method::DELETE,
            &["admin", "rules", rule],
            Auth::Admin,
        ))
        .await
    }

    /// `GET /admin/requests?limit=`.
    pub async fn admin_list_requests(
        &self,
        limit: i64,
    ) -> Result<Vec<agent_auth_wire::agent::RequestOut>, ClientError> {
        self.call(
            Call::get(&["admin", "requests"])
                .admin()
                .query("limit", limit.to_string()),
        )
        .await
    }

    /// `POST /admin/requests/{id}/decide`.
    pub async fn admin_decide(
        &self,
        request: &str,
        approve: bool,
        reason: &str,
        duration: Option<&str>,
        totp: Option<&str>,
    ) -> Result<agent_auth_wire::agent::RequestOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::DecideBody>(
            json!({"approve": approve, "reason": reason, "duration": duration, "totp": totp}),
        )?;
        self.call(
            Call::post(&["admin", "requests", request, "decide"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `POST /admin/grants/{id}/revoke?reason=`.
    pub async fn admin_revoke_grant(
        &self,
        grant: &str,
        reason: &str,
    ) -> Result<agent_auth_wire::admin::Revoked, ClientError> {
        self.call(
            Call::post(&["admin", "grants", grant, "revoke"])
                .admin()
                .query("reason", reason),
        )
        .await
    }

    /// `GET /admin/projects`.
    pub async fn admin_projects(&self) -> Result<agent_auth_wire::admin::Projects, ClientError> {
        self.call(Call::get(&["admin", "projects"]).admin()).await
    }

    /// `POST /admin/daemons/pairing-codes`.
    pub async fn admin_create_pairing_code(
        &self,
        role: &str,
        name: &str,
    ) -> Result<agent_auth_wire::admin::PairingCodeOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::PairingCodeCreate>(
            json!({"role": role, "name": name}),
        )?;
        self.call(
            Call::post(&["admin", "daemons", "pairing-codes"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `GET /admin/daemons`.
    pub async fn admin_list_daemons(
        &self,
    ) -> Result<Vec<agent_auth_wire::admin::DaemonOut>, ClientError> {
        self.call(Call::get(&["admin", "daemons"]).admin()).await
    }

    /// `DELETE /admin/daemons/{id}`.
    pub async fn admin_unpair_daemon(
        &self,
        daemon: &str,
    ) -> Result<agent_auth_wire::common::Ok, ClientError> {
        self.call(Call::new(
            Method::DELETE,
            &["admin", "daemons", daemon],
            Auth::Admin,
        ))
        .await
    }

    /// `GET /admin/broker-key`.
    pub async fn admin_broker_key(&self) -> Result<agent_auth_wire::admin::BrokerKey, ClientError> {
        self.call(Call::get(&["admin", "broker-key"]).admin()).await
    }

    /// `GET /admin/hosts`.
    pub async fn admin_hosts(&self) -> Result<agent_auth_wire::admin::HostsOut, ClientError> {
        self.call(Call::get(&["admin", "hosts"]).admin()).await
    }

    /// `POST /admin/hosts/{name}/arm`: the host's own reply.
    pub async fn admin_arm(
        &self,
        host: &str,
        tier: &str,
        duration: &str,
        totp: &str,
    ) -> Result<Value, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::ArmBody>(
            json!({"tier": tier, "duration": duration, "totp": totp}),
        )?;
        self.call(
            Call::post(&["admin", "hosts", host, "arm"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `POST /admin/hosts/{name}/disarm[?tier=]`: the host's own reply.
    pub async fn admin_disarm(&self, host: &str, tier: Option<&str>) -> Result<Value, ClientError> {
        let mut call = Call::post(&["admin", "hosts", host, "disarm"]).admin();
        if let Some(tier) = tier.filter(|t| !t.is_empty()) {
            call = call.query("tier", tier);
        }
        self.call(call).await
    }

    /// `POST /admin/lockdown`.
    pub async fn admin_lockdown(
        &self,
        scope: &str,
        host: Option<&str>,
        kill_vm: bool,
    ) -> Result<agent_auth_wire::admin::LockdownResult, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::admin::LockdownBody>(
            json!({"scope": scope, "host": host, "kill_vm": kill_vm}),
        )?;
        self.call(Call::post(&["admin", "lockdown"]).admin().body(body))
            .await
    }

    /// `POST /admin/unlock`.
    pub async fn admin_unlock(
        &self,
        host: Option<&str>,
        totp: Option<&str>,
    ) -> Result<agent_auth_wire::admin::UnlockResult, ClientError> {
        self.ready(Auth::Admin)?;
        let body =
            checked::<agent_auth_wire::admin::UnlockBody>(json!({"host": host, "totp": totp}))?;
        self.call(Call::post(&["admin", "unlock"]).admin().body(body))
            .await
    }

    /// `GET /admin/containment`.
    pub async fn admin_containment(
        &self,
    ) -> Result<Vec<agent_auth_wire::containment::ContainmentEntry>, ClientError> {
        self.call(Call::get(&["admin", "containment"]).admin())
            .await
    }

    /// `POST /admin/containment`.
    pub async fn admin_contain(
        &self,
        matches: Map<String, Value>,
        reason: &str,
        evidence: &str,
    ) -> Result<agent_auth_wire::containment::ContainResult, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::containment::ContainBody>(
            json!({"match": matches, "reason": reason, "evidence": evidence}),
        )?;
        self.call(Call::post(&["admin", "containment"]).admin().body(body))
            .await
    }

    /// `POST /admin/containment/lift`: one entry, or (None) every one.
    pub async fn admin_contain_lift(
        &self,
        entry: Option<&str>,
    ) -> Result<agent_auth_wire::containment::Lifted, ClientError> {
        self.ready(Auth::Admin)?;
        let body = match entry {
            Some(id) => json!({"id": id}),
            None => json!({"all": true}),
        };
        let body = checked::<agent_auth_wire::containment::LiftBody>(body)?;
        self.call(
            Call::post(&["admin", "containment", "lift"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `GET /admin/connectors`.
    pub async fn admin_connectors(
        &self,
    ) -> Result<Vec<agent_auth_wire::oauth::ConnectorOut>, ClientError> {
        self.call(Call::get(&["admin", "connectors"]).admin()).await
    }

    /// `POST /admin/connectors/{id}/revoke`.
    pub async fn admin_connector_revoke(
        &self,
        client: &str,
    ) -> Result<agent_auth_wire::oauth::ConnectorRevoked, ClientError> {
        self.call(Call::post(&["admin", "connectors", client, "revoke"]).admin())
            .await
    }

    /// `GET /admin/log/decisions[?limit=][&source=][&agent=]`.
    pub async fn admin_log_decisions(
        &self,
        limit: Option<i64>,
        source: Option<&str>,
        agent: Option<&str>,
    ) -> Result<Vec<agent_auth_wire::admin_log::DecisionItem>, ClientError> {
        let mut call = Call::get(&["admin", "log", "decisions"]).admin();
        if let Some(limit) = limit {
            call = call.query("limit", limit.to_string());
        }
        if let Some(source) = source {
            call = call.query("source", source);
        }
        if let Some(agent) = agent {
            call = call.query("agent", agent);
        }
        self.call(call).await
    }

    /// `GET /admin/log/commands[?limit=][&host=]`.
    pub async fn admin_log_commands(
        &self,
        limit: Option<i64>,
        host: Option<&str>,
    ) -> Result<Vec<agent_auth_wire::admin_log::CommandItem>, ClientError> {
        let mut call = Call::get(&["admin", "log", "commands"]).admin();
        if let Some(limit) = limit {
            call = call.query("limit", limit.to_string());
        }
        if let Some(host) = host {
            call = call.query("host", host);
        }
        self.call(call).await
    }

    /// `GET /admin/log/commands/{job}`.
    pub async fn admin_log_command(
        &self,
        job: &str,
    ) -> Result<agent_auth_wire::admin_log::CommandDetail, ClientError> {
        self.call(Call::get(&["admin", "log", "commands", job]).admin())
            .await
    }

    /// `GET /admin/a2a/graph[?hours=]`.
    pub async fn admin_a2a_graph(
        &self,
        hours: Option<i64>,
    ) -> Result<agent_auth_wire::admin_log::A2aGraph, ClientError> {
        let mut call = Call::get(&["admin", "a2a", "graph"]).admin();
        if let Some(hours) = hours {
            call = call.query("hours", hours.to_string());
        }
        self.call(call).await
    }

    /// `GET /admin/a2a/threads/{id}`.
    pub async fn admin_a2a_thread(
        &self,
        thread: &str,
    ) -> Result<agent_auth_wire::admin_log::AdminThread, ClientError> {
        self.call(Call::get(&["admin", "a2a", "threads", thread]).admin())
            .await
    }

    /// `GET /admin/models/usage`.
    pub async fn admin_models_usage(
        &self,
    ) -> Result<agent_auth_wire::admin_log::ModelsUsage, ClientError> {
        self.call(Call::get(&["admin", "models", "usage"]).admin())
            .await
    }

    /// `GET /admin/chat/peers`.
    pub async fn admin_chat_peers(
        &self,
    ) -> Result<Vec<agent_auth_wire::chat::ChatPeer>, ClientError> {
        self.call(Call::get(&["admin", "chat", "peers"]).admin())
            .await
    }

    /// `GET /admin/chat/threads[?limit=]`.
    pub async fn admin_chat_threads(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<agent_auth_wire::chat::ChatThreadItem>, ClientError> {
        let mut call = Call::get(&["admin", "chat", "threads"]).admin();
        if let Some(limit) = limit {
            call = call.query("limit", limit.to_string());
        }
        self.call(call).await
    }

    /// `POST /admin/chat/threads`: the operator opens a conversation.
    pub async fn admin_chat_open(
        &self,
        to: &str,
        topic: Option<&str>,
        text: &str,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::chat::ChatOpen>(
            json!({"to": to, "topic": topic, "text": text}),
        )?;
        self.call(Call::post(&["admin", "chat", "threads"]).admin().body(body))
            .await
    }

    /// `GET /admin/chat/threads/{id}?after_seq=&wait=` (the broker caps the
    /// wait at 25 s, so one request).
    pub async fn admin_chat_thread(
        &self,
        thread: &str,
        after_seq: i64,
        wait: f64,
    ) -> Result<agent_auth_wire::chat::ChatThreadView, ClientError> {
        let wait = crate::poll::clamp_total(wait).min(crate::poll::POLL_SLICE);
        self.call(
            Call::get(&["admin", "chat", "threads", thread])
                .admin()
                .query("after_seq", after_seq.to_string())
                .query("wait", python_float_repr(wait))
                .timeout_secs(wait + 10.0),
        )
        .await
    }

    /// `POST /admin/chat/threads/{id}/messages`.
    pub async fn admin_chat_send(
        &self,
        thread: &str,
        text: &str,
    ) -> Result<agent_auth_wire::a2a::MessageSent, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::chat::ChatSend>(json!({"text": text}))?;
        self.call(
            Call::post(&["admin", "chat", "threads", thread, "messages"])
                .admin()
                .body(body),
        )
        .await
    }

    /// `POST /admin/chat/threads/{id}/close`.
    pub async fn admin_chat_close(
        &self,
        thread: &str,
        reason: Option<&str>,
    ) -> Result<agent_auth_wire::a2a::ThreadOut, ClientError> {
        self.ready(Auth::Admin)?;
        let body = checked::<agent_auth_wire::chat::ChatClose>(json!({"reason": reason}))?;
        self.call(
            Call::post(&["admin", "chat", "threads", thread, "close"])
                .admin()
                .body(body),
        )
        .await
    }
}

/// The `detail` of an error answer: the string itself, other JSON compact,
/// the body's text when there is none.
fn error_detail(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => match map.get("detail") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => text.into_owned(),
        },
        _ => text.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_urls() {
        assert!(broker_url("https://agent-auth.rooty.dev/").is_ok());
        assert!(broker_url("https://broker.example/prefix").is_ok());
        assert!(broker_url("http://127.0.0.1:8400").is_ok());
        assert!(broker_url("http://127.3.4.5").is_ok());
        assert!(broker_url("http://localhost:8400").is_ok());
        assert!(broker_url("http://[::1]:8400").is_ok());
        for bad in [
            "http://agent-auth.lan",
            "http://10.0.0.1:8400",
            "ftp://127.0.0.1",
            "agent-auth.rooty.dev",
            "",
            "http://localhost.evil.example",
        ] {
            assert!(broker_url(bad).is_err(), "{bad}");
        }
        assert_eq!(
            broker_url("https://b.example///").unwrap().as_str(),
            "https://b.example/"
        );
    }

    #[test]
    fn error_details() {
        assert_eq!(
            error_detail(br#"{"detail": "unknown agent"}"#),
            "unknown agent"
        );
        assert_eq!(
            error_detail(br#"{"detail": [{"msg": "x"}]}"#),
            r#"[{"msg":"x"}]"#
        );
        assert_eq!(error_detail(br#"{"other": 1}"#), r#"{"other": 1}"#);
        assert_eq!(error_detail(b"Bad Gateway"), "Bad Gateway");
    }
}
