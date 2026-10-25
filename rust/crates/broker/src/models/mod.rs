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
//! Recording is best effort and bounded: a call that cannot be recorded in
//! [`RECORD_TIMEOUT`] is logged and the decision stands. The records of
//! sealed kinds (mail) are sealed with `ENCRYPTION_KEY`, as the mail they
//! hold is elsewhere; without a key they are not recorded.

#[cfg(test)]
mod flow_tests;
pub mod replay;
pub mod routes;

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_auth_crypto::Secret;
use agent_auth_crypto::secretbox::{Binding, SecretBox};
use agent_auth_store::Store;
use agent_auth_store::evals::CallRow;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

/// The largest answer read from the model gateway.
const MAX_ANSWER_BYTES: usize = 1 << 20;
/// How long recording may hold a decision up.
pub const RECORD_TIMEOUT: Duration = Duration::from_secs(2);
/// A record's facts and user message at most, together; a larger one keeps
/// its outcome but not its inputs (it cannot be replayed).
pub const RECORD_MAX_BYTES: usize = 1_000_000;
/// The key of a sealed part (`{"sealed": "<ciphertext>"}`).
const SEALED: &str = "sealed";
/// The prefix of a sealed user message.
const SEALED_PREFIX: &str = "sealed:";

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
    /// Its records hold what the broker otherwise keeps sealed (mail):
    /// facts, user message and answer are sealed with `ENCRYPTION_KEY`,
    /// and without one the kind is not recorded.
    pub sealed: bool,
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
    sealer: Option<Arc<SecretBox>>,
}

impl std::fmt::Debug for ModelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelClient")
            .field("base_url", &self.base_url)
            .field("records", &self.store.is_some())
            .field("seals", &self.sealer.is_some())
            .finish_non_exhaustive()
    }
}

/// What one record holds.
struct Recording<'a> {
    kind: Kind,
    model: &'a str,
    facts: &'a Value,
    context: &'a Context,
    system: &'a str,
    user: &'a str,
    answer: Option<&'a Map<String, Value>>,
    class: Option<&'a str>,
    error: Option<&'a str>,
    latency: Duration,
    subject: &'a Value,
}

impl ModelClient {
    /// `store`: where calls are recorded (`None`: not recorded); `sealer`:
    /// what seals the records of sealed kinds (mail; `None`: those are not
    /// recorded).
    pub fn new(
        api_key: Secret<String>,
        base_url: &str,
        store: Option<Store>,
        sealer: Option<Arc<SecretBox>>,
    ) -> anyhow::Result<Self> {
        let tls = agent_auth_tls::default_client_config()?;
        // Each call sets its own timeout; this is the ceiling.
        let client = agent_auth_tls::reqwest_builder(tls, Duration::from_secs(180)).build()?;
        Ok(ModelClient {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            store,
            sealer,
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
        let sealer = match (r.sealed, &self.sealer) {
            (false, _) => Some(None),
            (true, Some(s)) => Some(Some(s.as_ref())),
            // Never in the clear: not recorded at all.
            (true, None) => None,
        };
        if let (Some(store), Some(sealer)) = (&self.store, sealer) {
            // Best effort, and never long: the decision waits for nothing
            // but the model.
            let recorded = tokio::time::timeout(
                RECORD_TIMEOUT,
                record(
                    store,
                    sealer,
                    &Recording {
                        kind,
                        model,
                        facts: &facts,
                        context: &context,
                        system: r.default_system,
                        user: &user,
                        answer: answer.as_ref(),
                        class: class.as_deref(),
                        error: error.as_deref(),
                        latency,
                        subject: &subject,
                    },
                ),
            )
            .await;
            match recorded {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(kind = kind.as_str(), "could not record a model call: {e}");
                }
                Err(_) => tracing::warn!(kind = kind.as_str(), "recording a model call timed out"),
            }
        }
        Decision { answer, class }
    }

    /// A record as it was made: sealed parts opened (an error without the
    /// key that sealed them).
    pub fn opened(&self, mut c: CallRow) -> Result<CallRow, String> {
        let id = c.id.to_string();
        let open = |text: &str, column: &str| -> Result<String, String> {
            let sealer = self
                .sealer
                .as_ref()
                .ok_or_else(|| "this record is sealed and ENCRYPTION_KEY is not set".to_owned())?;
            sealer
                .open_str(text, &Binding::new("model_calls", column, &id))
                .map(|s| s.expose().clone())
                .map_err(|_| "this record does not open".to_owned())
        };
        if let Some(sealed) = c.facts.get(SEALED).and_then(Value::as_str) {
            c.facts = serde_json::from_str(&open(sealed, "facts")?).map_err(|e| e.to_string())?;
        }
        if let Some(sealed) = c.user_message.strip_prefix(SEALED_PREFIX) {
            c.user_message = open(sealed, "user_message")?;
        }
        if let Some(sealed) = c
            .answer
            .as_ref()
            .and_then(|a| a.get(SEALED))
            .and_then(Value::as_str)
        {
            let opened = open(sealed, "answer")?;
            c.answer = Some(serde_json::from_str(&opened).map_err(|e| e.to_string())?);
        }
        Ok(c)
    }
}

/// Text Postgres can store: no NUL (jsonb and text refuse it, and a record
/// that cannot be written is one an agent or a sender could avoid).
fn storable(text: &str) -> String {
    text.replace('\0', "\u{fffd}")
}

fn storable_json(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(storable(s)),
        Value::Array(a) => Value::Array(a.iter().map(storable_json).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (storable(k), storable_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

async fn record(
    store: &Store,
    sealer: Option<&SecretBox>,
    r: &Recording<'_>,
) -> Result<(), String> {
    let id = Uuid::new_v4();
    let row = id.to_string();
    let sha = agent_auth_crypto::digest::sha256_hex(r.system.as_bytes());
    let mut facts = storable_json(r.facts);
    let mut user = storable(r.user);
    let size = facts.to_string().len().saturating_add(user.len());
    if size > RECORD_MAX_BYTES {
        facts = json!({"omitted": "too large to record", "bytes": size});
        user = format!(
            "{}\n[... cut: a record keeps at most {RECORD_MAX_BYTES} bytes]",
            user.chars().take(64 * 1024).collect::<String>()
        );
    }
    let mut answer = r.answer.map(|a| storable_json(&Value::Object(a.clone())));
    if let Some(sealer) = sealer {
        let seal = |text: &str, column: &str| {
            sealer
                .seal_str(text, &Binding::new("model_calls", column, &row))
                .map_err(|_| "sealing failed".to_owned())
        };
        facts = json!({SEALED: seal(&facts.to_string(), "facts")?});
        user = format!("{SEALED_PREFIX}{}", seal(&user, "user_message")?);
        answer = match answer {
            Some(a) => Some(json!({SEALED: seal(&a.to_string(), "answer")?})),
            None => None,
        };
    }
    let error: Option<String> = r.error.map(|e| storable(e).chars().take(2000).collect());
    let subject = storable_json(r.subject);
    let model: String = storable(r.model).chars().take(128).collect();
    let go = async {
        let tx = store.begin().await?;
        agent_auth_store::evals::put_prompt(&tx, &sha, r.system).await?;
        agent_auth_store::evals::record_call(
            &tx,
            &agent_auth_store::evals::NewCall {
                id,
                kind: r.kind.as_str(),
                model: &model,
                facts: &facts,
                context: &r.context.to_json(),
                system_sha256: &sha,
                user_message: &user,
                answer: answer.as_ref(),
                class: r.class,
                error: error.as_deref(),
                latency_ms: i32::try_from(r.latency.as_millis()).unwrap_or(i32::MAX),
                subject: &subject,
                now: OffsetDateTime::now_utc(),
            },
        )
        .await?;
        tx.commit().await
    };
    go.await
        .map_err(|e: agent_auth_store::StoreError| e.to_string())
}

/// Label the newest call of `kind` about `subject` (a JSON object it
/// contains, e.g. `{"request_id": ...}`) with what happened next
/// (`outcome`: never over an operator's label). Best effort: a failure is
/// logged.
pub async fn label_outcome(store: &Store, kind: Kind, subject: Value, expected: &str, by: &str) {
    let by: String = by.chars().take(128).collect();
    let labelled = async {
        let tx = store.begin().await?;
        if let Some(call) =
            agent_auth_store::evals::latest_about(&tx, kind.as_str(), &subject).await?
        {
            agent_auth_store::evals::set_label(
                &tx,
                call,
                expected,
                "",
                "outcome",
                &by,
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
            // Mail, and only mail, is sealed.
            assert_eq!(
                r.sealed,
                matches!(kind, Kind::MailInbound | Kind::MailOutbound),
                "{kind:?}"
            );
            // A build from nothing fails, never a prompt about nothing.
            let built = (r.build)(&json!({}), &Context::default());
            assert!(built.is_err(), "{kind:?}: {built:?}");
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

    #[test]
    fn nul_is_storable() {
        let v = storable_json(&json!({"a\u{0}": ["x\u{0}y", 1, {"k": "\u{0}"}]}));
        assert!(!v.to_string().contains("\\u0000"), "{v}");
        assert_eq!(storable("a\u{0}b"), "a\u{fffd}b");
    }
}
