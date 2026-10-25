//! SimpleLogin's API (`mail/simplelogin.py`): finding an alias, the reverse
//! alias ("contact") through which the alias's mailbox writes to someone,
//! and creating aliases.
//!
//! SimpleLogin itself never hands out mail: it forwards each message to the
//! alias's mailbox (with `X-SimpleLogin-Envelope-To: <alias>` and the From
//! rewritten to a reverse alias), and sends as the alias whatever the
//! mailbox sends to a reverse alias. So reading is the mailbox's, and
//! sending is the mailbox writing to `contact(alias, recipient)`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agent_auth_core::mail::is_address;
use agent_auth_core::policy::mail::SimpleLoginConfig;
use reqwest::Method;
use serde_json::{Value, json};

/// An alias found stays found this long.
const ALIAS_TTL: Duration = Duration::from_secs(3600);
/// Pages of 20 aliases searched.
const PAGES: u32 = 10;
/// The largest answer read.
const MAX_ANSWER: usize = 4 << 20;
const WORDS: [&str; 20] = [
    "amber", "brook", "cedar", "delta", "ember", "fjord", "grove", "harbor", "iris", "juniper",
    "kestrel", "lumen", "maple", "nimbus", "orchid", "pebble", "quartz", "raven", "sierra",
    "tundra",
];

/// A SimpleLogin failure. The text may reach an agent: no API bodies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SlError(pub String);

/// An alias, as far as the gateway needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub id: i64,
    pub email: String,
    /// The mailboxes it forwards to (lowercase).
    pub mailboxes: Vec<String>,
}

fn alias_of(v: &Value) -> Option<Alias> {
    Some(Alias {
        id: v.get("id")?.as_i64()?,
        email: v.get("email")?.as_str()?.to_lowercase(),
        mailboxes: v
            .get("mailboxes")
            .and_then(Value::as_array)
            .map(|boxes| {
                boxes
                    .iter()
                    .filter_map(|b| b.get("email").and_then(Value::as_str))
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub struct SimpleLogin {
    base: String,
    api_key_file: String,
    client: reqwest::Client,
    aliases: Mutex<HashMap<String, (Instant, Alias)>>,
}

impl std::fmt::Debug for SimpleLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleLogin")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl SimpleLogin {
    pub fn new(
        config: &SimpleLoginConfig,
        tls: rustls::ClientConfig,
    ) -> anyhow::Result<SimpleLogin> {
        Ok(SimpleLogin {
            base: config.api_url.trim_end_matches('/').to_owned(),
            api_key_file: config.api_key_file.clone(),
            client: agent_auth_tls::reqwest_builder(tls, Duration::from_secs(10)).build()?,
            aliases: Mutex::new(HashMap::new()),
        })
    }

    /// The key, read at each call (a rotated file is picked up).
    fn key(&self) -> Result<agent_auth_crypto::Secret<String>, SlError> {
        match std::fs::read_to_string(&self.api_key_file) {
            Ok(k) => Ok(agent_auth_crypto::Secret::new(k.trim().to_owned())),
            Err(e) => {
                tracing::warn!(file = %self.api_key_file, error = %e, "simplelogin: cannot read the API key file");
                Err(SlError(
                    "simplelogin: cannot read the API key file".to_owned(),
                ))
            }
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, SlError> {
        let key = self.key()?;
        let route = path.split('?').next().unwrap_or(path).to_owned();
        let mut req = self
            .client
            .request(method.clone(), format!("{}{path}", self.base))
            .header("Authentication", key.expose());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let mut resp = req.send().await.map_err(|e| {
            tracing::warn!(error = %e, "simplelogin unreachable");
            SlError("simplelogin unreachable (see broker logs)".to_owned())
        })?;
        let status = resp.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            tracing::warn!(error = %e, "simplelogin: reading the answer failed");
            SlError("simplelogin unreachable (see broker logs)".to_owned())
        })? {
            if bytes.len().saturating_add(chunk.len()) > MAX_ANSWER {
                return Err(SlError("simplelogin: the answer was too large".to_owned()));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            tracing::warn!(%method, route, status = status.as_u16(), body = %String::from_utf8_lossy(&bytes), "simplelogin refused");
            return Err(SlError(format!(
                "simplelogin: {method} {route} answered {}",
                status.as_u16()
            )));
        }
        if bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| SlError(format!("simplelogin: {method} {route} answered nonsense")))
    }

    /// The alias with exactly this address, or None.
    pub async fn find_alias(&self, address: &str) -> Result<Option<Alias>, SlError> {
        let address = address.to_lowercase();
        if let Some((at, alias)) = self.lock().get(&address)
            && at.elapsed() < ALIAS_TTL
        {
            return Ok(Some(alias.clone()));
        }
        for page in 0..PAGES {
            let out = self
                .call(
                    Method::POST,
                    &format!("/api/v2/aliases?page_id={page}"),
                    Some(json!({"query": address})),
                )
                .await?;
            let aliases = out
                .get("aliases")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for a in &aliases {
                if let Some(alias) = alias_of(a).filter(|x| x.email == address) {
                    self.remember(&alias);
                    return Ok(Some(alias));
                }
            }
            if aliases.len() < 20 {
                break;
            }
        }
        Ok(None)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Instant, Alias)>> {
        self.aliases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remember(&self, alias: &Alias) {
        let mut cache = self.lock();
        cache.retain(|_, (at, _)| at.elapsed() < ALIAS_TTL);
        if cache.len() < 10_000 {
            cache.insert(alias.email.clone(), (Instant::now(), alias.clone()));
        }
    }

    /// The reverse alias the mailbox writes to for `address` to receive it
    /// from the alias (made if it does not exist).
    pub async fn contact(&self, alias_id: i64, address: &str) -> Result<String, SlError> {
        let out = self
            .call(
                Method::POST,
                &format!("/api/aliases/{alias_id}/contacts"),
                Some(json!({"contact": address})),
            )
            .await?;
        let reverse = out
            .get("reverse_alias_address")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .filter(|r| !r.is_empty())
            .ok_or_else(|| SlError(format!("simplelogin gave no reverse alias for {address}")))?;
        // It goes into an SMTP envelope and a header: an address, nothing else.
        if !is_address(&reverse) {
            return Err(SlError(format!(
                "simplelogin gave no usable reverse alias for {address}"
            )));
        }
        Ok(reverse)
    }

    async fn mailbox_id(&self, address: &str) -> Result<i64, SlError> {
        let out = self.call(Method::GET, "/api/v2/mailboxes", None).await?;
        for b in out
            .get("mailboxes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if b.get("email")
                .and_then(Value::as_str)
                .is_some_and(|e| e.eq_ignore_ascii_case(address))
            {
                if b.get("verified").and_then(Value::as_bool) == Some(false) {
                    return Err(SlError(format!(
                        "simplelogin: mailbox {address} is not verified"
                    )));
                }
                return b
                    .get("id")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| SlError("simplelogin: a mailbox without an id".to_owned()));
            }
        }
        Err(SlError(format!(
            "simplelogin: {address} is not one of the account's mailboxes"
        )))
    }

    /// A new alias on `domain` forwarding to the mailbox. No prefix: a word
    /// and digits.
    pub async fn create(
        &self,
        domain: &str,
        prefix: Option<&str>,
        note: &str,
        mailbox_address: &str,
    ) -> Result<Alias, SlError> {
        let options = self
            .call(Method::GET, "/api/v5/alias/options", None)
            .await?;
        if options.get("can_create").and_then(Value::as_bool) == Some(false) {
            return Err(SlError(
                "simplelogin: the account may not create more aliases".to_owned(),
            ));
        }
        let suffix = options
            .get("suffixes")
            .and_then(Value::as_array)
            .and_then(|s| {
                s.iter()
                    .find(|x| {
                        x.get("suffix")
                            .and_then(Value::as_str)
                            .is_some_and(|v| v.to_lowercase().ends_with(&format!("@{domain}")))
                    })
                    .cloned()
            })
            .ok_or_else(|| SlError(format!("simplelogin offers no alias suffix on {domain}")))?;
        let signed = suffix
            .get("signed_suffix")
            .and_then(Value::as_str)
            .ok_or_else(|| SlError(format!("simplelogin offers no alias suffix on {domain}")))?
            .to_owned();
        let prefix = match prefix {
            Some(p) => p.to_owned(),
            None => {
                let word = crate::random::token_hex(2)
                    .ok()
                    .and_then(|h| u16::from_str_radix(&h, 16).ok())
                    .unwrap_or(0);
                let idx = usize::from(word).checked_rem(WORDS.len()).unwrap_or(0);
                let num = u32::from(word)
                    .checked_rem(9000)
                    .unwrap_or(0)
                    .saturating_add(1000);
                format!("{}{num}", WORDS.get(idx).copied().unwrap_or("amber"))
            }
        };
        let mailbox = self.mailbox_id(mailbox_address).await?;
        let note: String = note.chars().take(500).collect();
        let alias = self
            .call(
                Method::POST,
                "/api/v3/alias/custom/new",
                Some(json!({
                    "alias_prefix": prefix,
                    "signed_suffix": signed,
                    "mailbox_ids": [mailbox],
                    "note": note,
                })),
            )
            .await?;
        let alias = alias_of(&alias)
            .filter(|a| is_address(&a.email) && a.email.ends_with(&format!("@{domain}")))
            .ok_or_else(|| SlError("simplelogin created no alias".to_owned()))?;
        self.remember(&alias);
        tracing::info!(alias = %alias.email, "simplelogin: created alias");
        Ok(alias)
    }
}
