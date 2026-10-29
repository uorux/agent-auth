//! An agent asking for the operator's attention, outside any request
//! (a2a-wiki-desktop spec §9): a message on Discord (a ping when urgent, or
//! when nobody is at a desk) and a notification with a sound on the desks
//! the operator is at. It grants nothing and needs no approval; it is
//! rate-limited per agent (6 an hour, counted before delivery), and there
//! is no containment check: a held agent can still reach the operator.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use agent_auth_core::AgentId;
use agent_auth_wire::agent::{AttentionBody, AttentionOut};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::time::Instant;

use crate::auth::AgentCaller;
use crate::error::{ApiError, ApiResult};
use crate::notify::Notify as _;
use crate::state::AppState;

pub const PER_HOUR: usize = 6;
pub const MAX_CHARS: usize = 500;

/// Per-agent send times (in memory: a restart resets them, B19).
#[derive(Debug, Default)]
pub struct Attention {
    sent: Mutex<HashMap<AgentId, VecDeque<Instant>>>,
}

/// Why it was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttentionError {
    /// 400.
    Invalid(&'static str),
    /// 429.
    Limit,
}

impl Attention {
    /// The text as sent (one line, at most 500 characters), after the
    /// checks and the rate limit (which counts this one).
    pub fn admit(
        &self,
        agent: AgentId,
        text: &str,
        urgency: &str,
    ) -> Result<String, AttentionError> {
        let text: String = text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(MAX_CHARS)
            .collect();
        if text.is_empty() {
            return Err(AttentionError::Invalid("say what you need"));
        }
        if urgency != "normal" && urgency != "high" {
            return Err(AttentionError::Invalid("urgency is normal or high"));
        }
        let now = Instant::now();
        let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        let times = sent.entry(agent).or_default();
        while times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > Duration::from_secs(3600))
        {
            times.pop_front();
        }
        if times.len() >= PER_HOUR {
            return Err(AttentionError::Limit);
        }
        times.push_back(now);
        Ok(text)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/attention", post(attention))
}

async fn attention(
    caller: AgentCaller,
    State(st): State<AppState>,
    bytes: Bytes,
) -> ApiResult<Json<AttentionOut>> {
    let Some(part) = st.hostd.as_ref() else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "not available on this broker",
        ));
    };
    let body: AttentionBody =
        agent_auth_wire::parse_body(&bytes).map_err(|e| ApiError::unprocessable(e.message()))?;
    let agent = caller.agent();
    let text = part
        .attention
        .admit(agent.id, body.text.as_str(), body.urgency.as_str())
        .map_err(|e| match e {
            AttentionError::Invalid(m) => ApiError::bad_request(m),
            AttentionError::Limit => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "at most {PER_HOUR} notifications an hour; the operator has the earlier ones"
                ),
            ),
        })?;
    let desks = match &part.desktop {
        Some(d) => d.notify(agent, &text, body.urgency.as_str()).await,
        None => Vec::new(),
    };
    st.notifier
        .attention(agent, &text, body.urgency.as_str(), &desks)
        .await;
    Ok(Json(AttentionOut {
        sent: true,
        desktops: desks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_can_ask_for_attention_six_times_an_hour() {
        let a = Attention::default();
        let me = AgentId::new();
        assert_eq!(
            a.admit(me, "  ", "normal"),
            Err(AttentionError::Invalid("say what you need"))
        );
        assert_eq!(
            a.admit(me, "x", "urgent"),
            Err(AttentionError::Invalid("urgency is normal or high"))
        );
        assert_eq!(
            a.admit(me, "look\nhere  now", "high").as_deref(),
            Ok("look here now")
        );
        for _ in 1..PER_HOUR {
            assert!(a.admit(me, "again", "normal").is_ok());
        }
        assert_eq!(a.admit(me, "again", "normal"), Err(AttentionError::Limit));
        // Per agent.
        assert!(a.admit(AgentId::new(), "me too", "normal").is_ok());
        assert_eq!(
            a.admit(me, &"y".repeat(900), "normal").unwrap_err(),
            AttentionError::Limit
        );
        let other = AgentId::new();
        assert_eq!(
            a.admit(other, &"y".repeat(900), "normal").unwrap().len(),
            MAX_CHARS
        );
    }
}
