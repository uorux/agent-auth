//! Every model decision the broker makes, through one client.
//!
//! A decision kind is a [`Recipe`]: what its prompt is built from (the
//! *facts*, a JSON object the caller gathers), how the user message is
//! built from them under a *variant* (model, system prompt, context
//! settings), the answer's schema, and how a decision *class* is read from
//! the answer. [`ModelClient::decide`] builds, asks, classifies and
//! records the call (`model_calls`); a replay ([`replay`]) rebuilds the
//! same facts under another variant and asks again, recording only results
//! (nothing a replay does reaches a decision).
//!
//! Recording is best effort: a call that cannot be recorded is logged and
//! the decision stands.

#[cfg(test)]
mod flow_tests;
pub mod replay;
pub mod routes;

use std::time::{Duration, Instant};

use agent_auth_crypto::Secret;
use agent_auth_store::Store;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

/// The largest answer read from the model gateway.
const MAX_ANSWER_BYTES: usize = 1 << 20;

/// The decision kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The LLM reviewer of access requests.
    RequestReview,
    /// The advisory risk line on host-command cards.
    RiskLine,
    /// The mail judge, screening a message an agent would read.
    MailInbound,
    /// The mail judge, reviewing a draft an agent wants sent.
    MailOutbound,
    /// The guard of a guarded shell (or an umbrella's scope).
    ShellGuard,
    /// Whether a scoped shell's purpose is within its umbrella.
    ShellScope,
    /// The after-the-fact watcher of a watched shell's (or run's) command.
    ShellWatch,
    /// The watcher of a general shell's command (danger only).
    ShellWatchGeneral,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::RequestReview,
        Kind::RiskLine,
        Kind::MailInbound,
        Kind::MailOutbound,
        Kind::ShellGuard,
        Kind::ShellScope,
        Kind::ShellWatch,
        Kind::ShellWatchGeneral,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::RequestReview => "request_review",
            Kind::RiskLine => "risk_line",
            Kind::MailInbound => "mail_inbound",
            Kind::MailOutbound => "mail_outbound",
            Kind::ShellGuard => "shell_guard",
            Kind::ShellScope => "shell_scope",
            Kind::ShellWatch => "shell_watch",
            Kind::ShellWatchGeneral => "shell_watch_general",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// A context setting a recipe's builder reads, with its default.
#[derive(Debug, Clone, Copy)]
pub struct Knob {
    pub name: &'static str,
    pub default: u64,
    pub max: u64,
    pub doc: &'static str,
}

/// How one kind of decision is made.
#[derive(Clone, Copy)]
pub struct Recipe {
    pub kind: Kind,
    pub default_system: &'static str,
    pub schema_name: &'static str,
    pub schema: fn() -> Value,
    /// The user message from the facts and the context settings.
    pub build: fn(&Value, &Context) -> Result<String, String>,
    /// The decision class an answer means (`None`: not a usable answer).
    pub classify: fn(&Map<String, Value>) -> Option<String>,
    pub classes: &'static [&'static str],
    pub knobs: &'static [Knob],
}

impl std::fmt::Debug for Recipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recipe")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// The recipe of every kind.
#[must_use]
pub fn recipe(kind: Kind) -> Recipe {
    match kind {
        Kind::RequestReview => crate::llm::REVIEW_RECIPE,
        Kind::RiskLine => crate::llm::RISK_RECIPE,
        Kind::MailInbound => crate::mail::judge::INBOUND_RECIPE,
        Kind::MailOutbound => crate::mail::judge::OUTBOUND_RECIPE,
        Kind::ShellGuard => crate::hostexec::watcher::GUARD_RECIPE,
        Kind::ShellScope => crate::hostexec::watcher::SCOPE_RECIPE,
        Kind::ShellWatch => crate::hostexec::watcher::WATCH_RECIPE,
        Kind::ShellWatchGeneral => crate::hostexec::watcher::GENERAL_WATCH_RECIPE,
    }
}

/// Context settings, checked against a recipe's knobs (unknown names and
/// out-of-range values refused, so a typo in a replay is an error).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context(Map<String, Value>);

impl Context {
    pub fn checked(kind: Kind, raw: &Map<String, Value>) -> Result<Context, String> {
        let knobs = recipe(kind).knobs;
        for (k, v) in raw {
            let Some(knob) = knobs.iter().find(|n| n.name == k) else {
                let names: Vec<&str> = knobs.iter().map(|n| n.name).collect();
                return Err(format!(
                    "{} has no context setting {k:?} (it has: {})",
                    kind.as_str(),
                    if names.is_empty() {
                        "none".to_owned()
                    } else {
                        names.join(", ")
                    }
                ));
            };
            match v.as_u64() {
                Some(n) if n <= knob.max => {}
                _ => return Err(format!("{k}: a whole number from 0 to {}", knob.max)),
            }
        }
        Ok(Context(raw.clone()))
    }

    /// A knob's value, or its default.
    #[must_use]
    pub fn get(&self, knob: &str, kind: Kind) -> u64 {
        let default = recipe(kind)
            .knobs
            .iter()
            .find(|n| n.name == knob)
            .map_or(0, |n| n.default);
        self.0.get(knob).and_then(Value::as_u64).unwrap_or(default)
    }

    /// A knob's value as a count.
    #[must_use]
    pub fn count(&self, knob: &str, kind: Kind) -> usize {
        usize::try_from(self.get(knob, kind)).unwrap_or(usize::MAX)
    }

    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

/// A decision's outcome.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The model's object, if it answered one.
    pub answer: Option<Map<String, Value>>,
    /// The class it means (`None`: no usable answer).
    pub class: Option<String>,
}

/// The model gateway (OpenRouter's chat completions with a strict JSON
/// schema), recording every decision when a store is given.
pub struct ModelClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Secret<String>,
    store: Option<Store>,
}

impl std::fmt::Debug for ModelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelClient")
            .field("base_url", &self.base_url)
            .field("records", &self.store.is_some())
            .finish_non_exhaustive()
    }
}

impl ModelClient {
    /// `store`: where calls are recorded (`None`: not recorded).
    pub fn new(
        api_key: Secret<String>,
        base_url: &str,
        store: Option<Store>,
    ) -> anyhow::Result<Self> {
        let tls = agent_auth_tls::default_client_config()?;
        // Each call sets its own timeout; this is the ceiling.
        let client = agent_auth_tls::reqwest_builder(tls, Duration::from_secs(180)).build()?;
        Ok(ModelClient {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            store,
        })
    }

    /// One chat completion: the answer's object.
    pub async fn complete(
        &self,
        model: &str,
        system: &str,
        user: &str,
        schema_name: &str,
        schema: Value,
        timeout: Duration,
    ) -> Result<Map<String, Value>, String> {
        let body = json!({
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": true, "schema": schema},
            },
        });
        let mut response = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(self.api_key.expose())
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| e.to_string())?;
        // At most 1 MiB of answer, read in chunks (never buffered past it).
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_ANSWER_BYTES {
                return Err("answer too large".to_owned());
            }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let content = data
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| "no content in the answer".to_owned())?;
        match serde_json::from_str(content).map_err(|e| e.to_string())? {
            Value::Object(map) => Ok(map),
            _ => Err("the content is not an object".to_owned()),
        }
    }

    /// Make one decision of `kind` with the live variant (`model`, the
    /// recipe's system prompt, default context), and record it.
    pub async fn decide(
        &self,
        kind: Kind,
        model: &str,
        facts: Value,
        subject: Value,
        timeout: Duration,
    ) -> Decision {
        let r = recipe(kind);
        let context = Context::default();
        let started = Instant::now();
        let (user, outcome) = match (r.build)(&facts, &context) {
            Ok(user) => {
                let asked = self
                    .complete(
                        model,
                        r.default_system,
                        &user,
                        r.schema_name,
                        (r.schema)(),
                        timeout,
                    )
                    .await;
                (user, asked)
            }
            Err(e) => (
                String::new(),
                Err(format!("could not build the prompt: {e}")),
            ),
        };
        let (answer, error) = match outcome {
            Ok(a) => (Some(a), None),
            Err(e) => {
                tracing::warn!(kind = kind.as_str(), "model call failed: {e}");
                (None, Some(e))
            }
        };
        let class = answer.as_ref().and_then(|a| (r.classify)(a));
        let latency = started.elapsed();
        if let Some(store) = &self.store {
            let recorded = record(
                store,
                kind,
                model,
                &facts,
                &context,
                r.default_system,
                &user,
                answer.as_ref(),
                class.as_deref(),
                error.as_deref(),
                latency,
                &subject,
            )
            .await;
            if let Err(e) = recorded {
                tracing::warn!(kind = kind.as_str(), "could not record a model call: {e}");
            }
        }
        Decision { answer, class }
    }
}

#[allow(clippy::too_many_arguments)]
async fn record(
    store: &Store,
    kind: Kind,
    model: &str,
    facts: &Value,
    context: &Context,
    system: &str,
    user: &str,
    answer: Option<&Map<String, Value>>,
    class: Option<&str>,
    error: Option<&str>,
    latency: Duration,
    subject: &Value,
) -> Result<(), agent_auth_store::StoreError> {
    let sha = agent_auth_crypto::digest::sha256_hex(system.as_bytes());
    let answer = answer.map(|a| Value::Object(a.clone()));
    let error = error.map(|e| e.chars().take(2000).collect::<String>());
    let tx = store.begin().await?;
    agent_auth_store::evals::put_prompt(&tx, &sha, system).await?;
    agent_auth_store::evals::record_call(
        &tx,
        &agent_auth_store::evals::NewCall {
            id: Uuid::new_v4(),
            kind: kind.as_str(),
            model,
            facts,
            context: &context.to_json(),
            system_sha256: &sha,
            user_message: user,
            answer: answer.as_ref(),
            class,
            error: error.as_deref(),
            latency_ms: i32::try_from(latency.as_millis()).unwrap_or(i32::MAX),
            subject,
            now: OffsetDateTime::now_utc(),
        },
    )
    .await?;
    tx.commit().await
}

/// Label the newest call of `kind` whose subject has `key` = `value` with
/// what happened next (`outcome`: never over an operator's label). Best
/// effort: a failure is logged.
pub async fn label_outcome(
    store: &Store,
    kind: Kind,
    key: &str,
    value: &str,
    expected: &str,
    by: &str,
) {
    let labelled = async {
        let tx = store.begin().await?;
        if let Some(call) =
            agent_auth_store::evals::latest_for_subject(&tx, kind.as_str(), key, value).await?
        {
            agent_auth_store::evals::set_label(
                &tx,
                call,
                expected,
                "",
                "outcome",
                by,
                OffsetDateTime::now_utc(),
            )
            .await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(e) = labelled {
        tracing::warn!(kind = kind.as_str(), "could not label a model call: {e}");
    }
}

/// Does a recorded class fit a label's pattern? Parts between `/` match
/// one by one; `*` matches any part.
#[must_use]
pub fn class_matches(pattern: &str, class: &str) -> bool {
    let want: Vec<&str> = pattern.split('/').collect();
    let have: Vec<&str> = class.split('/').collect();
    want.len() == have.len() && want.iter().zip(&have).all(|(w, h)| *w == "*" || w == h)
}

/// Is `pattern` a class (or a pattern of one) that `kind` can decide?
#[must_use]
pub fn valid_pattern(kind: Kind, pattern: &str) -> bool {
    recipe(kind)
        .classes
        .iter()
        .any(|c| class_matches(pattern, c) && !pattern.split('/').all(|p| p == "*"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert!(class_matches("in_scope/*", "in_scope/none"));
        assert!(!class_matches("in_scope/*", "unclear/none"));
        assert!(!class_matches("in_scope", "in_scope/none"));
        assert!(class_matches("deny", "deny"));
        for kind in Kind::ALL {
            let r = recipe(kind);
            assert_eq!(r.kind, kind);
            assert!(!r.classes.is_empty(), "{kind:?}");
            for c in r.classes {
                assert!(valid_pattern(kind, c), "{kind:?} {c}");
            }
            assert!(!valid_pattern(kind, "nonsense"));
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        assert!(
            !valid_pattern(Kind::MailInbound, "*/*"),
            "a label must say something"
        );
        assert!(valid_pattern(Kind::MailInbound, "in_scope/*"));
    }

    #[test]
    fn contexts_are_checked() {
        let mut m = Map::new();
        m.insert("history_items".into(), json!(10));
        assert!(Context::checked(Kind::ShellGuard, &m).is_ok());
        m.insert("nope".into(), json!(1));
        assert!(Context::checked(Kind::ShellGuard, &m).is_err());
        let mut m = Map::new();
        m.insert("history_items".into(), json!(-1));
        assert!(Context::checked(Kind::ShellGuard, &m).is_err());
    }
}
