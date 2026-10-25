//! Pairing from the daemon's side (§3.4): bind this daemon's key to its
//! (role, name) with a one-time code, and check that the broker answering is
//! the pinned one and knows the code too.

use std::sync::Arc;
use std::time::Duration;

use agent_auth_crypto::daemon::{PairingKey, proofs_equal};
use serde_json::{Value, json};

use crate::channel::Identity;

#[derive(Debug, thiserror::Error)]
pub enum PairingFailed {
    #[error("broker refused pairing [{status}]: {detail}")]
    Refused { status: u16, detail: String },
    #[error("the broker's pairing response is not a JSON object")]
    NotAnObject,
    #[error(
        "the broker's key does not match the pinned brokerPublicKey — wrong broker, or the pin \
         is stale. Not trusting it."
    )]
    WrongBrokerKey,
    #[error("the broker's pairing proof did not verify")]
    BadProof,
    #[error("could not reach the broker: {0}")]
    Unreachable(String),
}

/// What the broker answered (already checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paired {
    /// The daemon key's fingerprint as the broker computed it.
    pub fingerprint: String,
}

/// `POST {broker}/v1/daemons/pair` with this code. The code is only ever
/// used to derive the HMAC key; it is never sent.
pub async fn pair(
    identity: &Identity,
    code: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Paired, PairingFailed> {
    let key = PairingKey::from_code(code);
    let public = identity.public_key();
    let body = json!({
        "role": identity.id.role.as_str(),
        "name": identity.id.name.as_str(),
        "public_key": public.to_text(),
        "selector": key.selector(),
        "proof": key.daemon_proof(&identity.id, &public),
    });
    let client =
        agent_auth_tls::reqwest_builder(Arc::unwrap_or_clone(tls), Duration::from_secs(30))
            .build()
            .map_err(|e| PairingFailed::Unreachable(e.to_string()))?;
    let resp = client
        .post(identity.broker_url.pair_url())
        .json(&body)
        .send()
        .await
        .map_err(|e| PairingFailed::Unreachable(e.to_string()))?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| PairingFailed::Unreachable(e.to_string()))?;
    check_response(identity, &key, status, &text)
}

/// The broker's answer, checked: 200, an object, the pinned broker key,
/// and a broker proof over (role, name, daemon key, broker key).
pub fn check_response(
    identity: &Identity,
    key: &PairingKey,
    status: u16,
    text: &str,
) -> Result<Paired, PairingFailed> {
    let data: Option<Value> = serde_json::from_str(text).ok();
    if status != 200 {
        let detail = data
            .as_ref()
            .and_then(|d| d.get("detail"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| text.chars().take(200).collect());
        return Err(PairingFailed::Refused { status, detail });
    }
    let Some(Value::Object(data)) = data else {
        return Err(PairingFailed::NotAnObject);
    };
    let pinned = identity.broker_key.to_text();
    if data.get("broker_public_key").and_then(Value::as_str) != Some(pinned.as_str()) {
        return Err(PairingFailed::WrongBrokerKey);
    }
    let expected = key.broker_proof(&identity.id, &identity.public_key(), &identity.broker_key);
    let given = data.get("proof").and_then(Value::as_str).unwrap_or("");
    if !proofs_equal(&expected, given) {
        return Err(PairingFailed::BadProof);
    }
    Ok(Paired {
        fingerprint: identity.public_key().fingerprint(),
    })
}
