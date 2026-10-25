//! What a call to the broker can end in, other than its answer.

/// The detail the broker answers when an `X-Agent-Session` is unknown,
/// closed or idled out (with status 401).
pub const STALE_SESSION: &str = "unknown or closed session";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The broker refused the call: its status and `detail`. Status 0 means
    /// no request was made (a missing key or an unusable broker URL); 422
    /// may also come from a body this client would not send (the same
    /// checks and messages as the broker's, applied before sending).
    /// Displays as the Python's `BrokerError`: `[{status}] {detail}`.
    #[error("[{status}] {detail}")]
    Broker { status: u16, detail: String },
    /// The broker could not be reached, or the connection failed.
    #[error("{0}")]
    Transport(String),
    /// The broker answered something that is not the expected JSON.
    #[error("{0}")]
    Decode(String),
}

impl ClientError {
    pub(crate) fn broker(status: u16, detail: impl Into<String>) -> Self {
        ClientError::Broker {
            status,
            detail: detail.into(),
        }
    }

    /// A body this client refused to send, as the broker would have (422).
    pub(crate) fn invalid(detail: impl Into<String>) -> Self {
        ClientError::broker(422, detail)
    }

    /// The broker's status, for a refusal.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            ClientError::Broker { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// 401 `unknown or closed session`: the session sent is gone.
    #[must_use]
    pub fn is_stale_session(&self) -> bool {
        matches!(self, ClientError::Broker { status: 401, detail } if detail == STALE_SESSION)
    }
}

/// A reqwest error with its causes (reqwest's own text is only the outer
/// layer: "error sending request for url (...)").
pub(crate) fn transport(e: &reqwest::Error) -> ClientError {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    ClientError::Transport(text)
}
