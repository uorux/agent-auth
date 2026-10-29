//! Who the tools act for, and with which session.
//!
//! [`Caller`] is what the tools need from their host: a client with the
//! caller's credentials, the client for session-bound calls (minting a
//! session when the caller's kind needs one), and whether a session it
//! minted has been closed by the broker. [`LocalCaller`] is the stdio
//! server's: one agent (the environment's key) for the whole process. The
//! broker's remote MCP endpoint implements it per connector.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agent_auth_client::{BrokerClient, ClientError};
use agent_auth_wire::common::AgentKind;

/// How often a minted session is touched: well inside the broker's idle
/// timeout (15 minutes by default).
pub const KEEPALIVE: Duration = Duration::from_secs(240);

pub trait Caller: Send + Sync + 'static {
    /// The client for calls that need no session of their own
    /// (`_client()`): the caller's credentials, and its current session.
    fn client(&self) -> BrokerClient;

    /// The client for a2a and `request_access` calls made without a
    /// `session_key` (`_session_client()`): it carries the caller's
    /// session, minted on first use when the caller's kind needs one.
    fn session_client(&self) -> impl Future<Output = Result<BrokerClient, ClientError>> + Send;

    /// Whether the session this caller minted was closed by the broker; if
    /// so it is forgotten, and the next session-bound call mints another.
    fn minted_session_gone(&self) -> impl Future<Output = bool> + Send;

    /// Where `get_credential(to_file=True)` writes
    /// ([`crate::to_file::credential_dir`]).
    fn credential_dir(&self) -> std::io::Result<std::path::PathBuf> {
        crate::to_file::credential_dir()
    }
}

/// The client for one call with an explicit `session_key`: a fresh client
/// bound to that session, so nothing shared changes (several conversations
/// may share one server). Without a key, [`Caller::session_client`].
pub async fn client_for<C: Caller>(
    caller: &C,
    session_key: Option<&str>,
) -> Result<BrokerClient, ClientError> {
    match session_key.filter(|k| !k.is_empty()) {
        Some(key) => Ok(caller.client().with_session(Some(key))),
        None => caller.session_client().await,
    }
}

/// The stdio server's caller: the agent of `AGENT_AUTH_API_KEY`, one client
/// for the process (its session is `AGENT_AUTH_SESSION`, or one minted for
/// an ephemeral agent, labeled after the working directory).
#[derive(Debug)]
pub struct LocalCaller {
    client: BrokerClient,
    kind: tokio::sync::Mutex<Option<AgentKind>>,
    minted: AtomicBool,
    keepalive: Duration,
    label: String,
    credential_dir: Option<std::path::PathBuf>,
}

impl LocalCaller {
    #[must_use]
    pub fn new(client: BrokerClient) -> Self {
        LocalCaller {
            client,
            kind: tokio::sync::Mutex::new(None),
            minted: AtomicBool::new(false),
            keepalive: KEEPALIVE,
            label: agent_auth_client::default_session_label(),
            credential_dir: None,
        }
    }

    /// Touch minted sessions this often (tests).
    #[must_use]
    pub fn with_keepalive(mut self, every: Duration) -> Self {
        self.keepalive = every;
        self
    }

    /// Write credential files here instead of the default directory.
    #[must_use]
    pub fn with_credential_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.credential_dir = Some(dir);
        self
    }

    /// Take the agent's kind as known (skips the `GET /v1/me` probe).
    #[must_use]
    pub fn with_kind(self, kind: AgentKind) -> Self {
        LocalCaller {
            kind: tokio::sync::Mutex::new(Some(kind)),
            ..self
        }
    }
}

impl Caller for LocalCaller {
    fn client(&self) -> BrokerClient {
        self.client.clone()
    }

    async fn session_client(&self) -> Result<BrokerClient, ClientError> {
        if self.client.session_id().is_some() {
            return Ok(self.client.clone());
        }
        // Tools run concurrently: one session is minted, not one per call
        // that got here first.
        let mut kind = self.kind.lock().await;
        if self.client.session_id().is_some() {
            return Ok(self.client.clone());
        }
        let known = match *kind {
            Some(k) => k,
            None => {
                let k = self.client.me().await?.kind;
                *kind = Some(k);
                k
            }
        };
        // Service agents stay sessionless (agent-level threads).
        if known == AgentKind::Ephemeral {
            self.client.create_session(&self.label).await?;
            self.minted.store(true, Ordering::SeqCst);
            if let Some(session) = self.client.session_id() {
                tokio::spawn(keep_alive(self.client.clone(), session, self.keepalive));
            }
        }
        Ok(self.client.clone())
    }

    fn credential_dir(&self) -> std::io::Result<std::path::PathBuf> {
        match &self.credential_dir {
            Some(dir) => Ok(dir.clone()),
            None => crate::to_file::credential_dir(),
        }
    }

    async fn minted_session_gone(&self) -> bool {
        let Some(session) = self.client.session_id() else {
            return false;
        };
        if !self.minted.load(Ordering::SeqCst) {
            return false;
        }
        match self.client.me().await {
            Err(e) if e.is_stale_session() => {
                self.client.clear_session_if(&session);
                true
            }
            _ => false,
        }
    }
}

/// Touch `session` until it is replaced or the broker says it is gone
/// (then forget it: the next call mints another). Other errors (the broker
/// away for a moment) are ignored.
async fn keep_alive(client: BrokerClient, session: String, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        if client.session_id().as_deref() != Some(session.as_str()) {
            return;
        }
        if let Err(e) = client.me().await
            && e.is_stale_session()
        {
            client.clear_session_if(&session);
            return;
        }
    }
}
