//! The daemon endpoints: pairing and the channel (unauthenticated: the
//! one-time code's proof and the hello's signature are the
//! authentication), and the admin's daemon routes (spec §3.2-§3.5).
//!
//! Public routes here: `POST /v1/daemons/pair`, `GET /v1/daemons/connect`.

use std::sync::Arc;

use agent_auth_core::DaemonId;
use agent_auth_store::daemons::DaemonRole as StoreRole;
use agent_auth_wire::admin::{BrokerKey, DaemonOut, PairingCodeCreate, PairingCodeOut};
use agent_auth_wire::common::DaemonRole;
use agent_auth_wire::daemon::pairing::{PairBody, PairResponse};
use agent_auth_wire::json::StatusObject;
use agent_auth_wire::secret::WireSecret;
use agent_auth_wire::text::LowerHex;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{delete, get, post};
use serde_json::{Value, json};

use super::pairing::{PairingError, identity};
use super::{DaemonHub, MAX_FRAME_BYTES};
use crate::auth::AdminCaller;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/daemons/pair", post(pair))
        .route("/v1/daemons/connect", get(connect))
        .route("/admin/daemons/pairing-codes", post(create_code))
        .route("/admin/daemons", get(list))
        .route("/admin/daemons/{daemon_id}", delete(unpair))
        .route("/admin/broker-key", get(broker_key))
}

const DISABLED: &str = "BROKER_SIGNING_KEY not configured";

fn hub(state: &AppState) -> ApiResult<Arc<DaemonHub>> {
    state
        .hostd
        .as_ref()
        .map(|p| Arc::clone(&p.hub))
        .ok_or_else(|| ApiError::unavailable(DISABLED))
}

impl From<PairingError> for ApiError {
    fn from(e: PairingError) -> ApiError {
        match e {
            PairingError::Disabled => ApiError::unavailable(DISABLED),
            PairingError::Invalid(m) => ApiError::bad_request(m),
            PairingError::Refused(r) => ApiError::forbidden(r.to_string()),
            PairingError::Internal(m) => ApiError::internal(&m),
        }
    }
}

fn body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> ApiResult<T> {
    agent_auth_wire::parse_body(bytes).map_err(|e| ApiError::unprocessable(e.message()))
}

async fn pair(State(state): State<AppState>, bytes: Bytes) -> ApiResult<Json<PairResponse>> {
    let hub = hub(&state)?;
    let body: PairBody = body(&bytes)?;
    let paired = hub.pair(&body).await?;
    Ok(Json(PairResponse {
        broker_public_key: paired.broker_public_key,
        proof: LowerHex::new(paired.proof).map_err(|e| ApiError::internal(&e))?,
        fingerprint: paired.fingerprint,
    }))
}

async fn connect(
    State(state): State<AppState>,
    parts: axum::http::request::Parts,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let hub = hub(&state)?;
    let peer = crate::auth::client_address(&parts, state.auth.trust_x_real_ip)
        .unwrap_or_else(|| "unknown".to_owned());
    Ok(ws
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| hub.serve(socket, peer)))
}

async fn create_code(
    _admin: AdminCaller,
    State(state): State<AppState>,
    bytes: Bytes,
) -> ApiResult<Json<PairingCodeOut>> {
    let hub = hub(&state)?;
    let body: PairingCodeCreate = body(&bytes)?;
    let id = identity(body.role.as_str(), body.name.as_str())?;
    let issued = hub.create_pairing_code(&id).await?;
    let broker = hub
        .public_key()
        .ok_or_else(|| ApiError::unavailable(DISABLED))?;
    Ok(Json(PairingCodeOut {
        role: match id.role {
            agent_auth_crypto::daemon::Role::Host => DaemonRole::Host,
            agent_auth_crypto::daemon::Role::Sandbox => DaemonRole::Sandbox,
        },
        name: agent_auth_wire::text::DaemonName::new(id.name.as_str())
            .map_err(|e| ApiError::internal(&e))?,
        code: WireSecret::new(issued.code.expose().clone()).map_err(|e| ApiError::internal(&e))?,
        expires_at: issued.expires_at,
        broker_public_key: broker.to_text(),
    }))
}

async fn list(
    _admin: AdminCaller,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<DaemonOut>>> {
    let Some(part) = state.hostd.as_ref() else {
        return Ok(Json(Vec::new()));
    };
    let rows = part.hub.list().await?;
    let out = rows
        .into_iter()
        .map(|row| {
            let fingerprint = agent_auth_crypto::daemon::PublicKey::parse(&row.public_key)
                .map(|k| k.fingerprint())
                .unwrap_or_default();
            let status = row.last_status.clone().and_then(|s| match s {
                Value::Object(m) => StatusObject::new(m).ok(),
                _ => None,
            });
            DaemonOut {
                id: row.id,
                role: match row.role {
                    StoreRole::Host => DaemonRole::Host,
                    StoreRole::Sandbox => DaemonRole::Sandbox,
                },
                online: part.hub.row_online(&row),
                name: row.name,
                fingerprint,
                paired_at: Some(row.paired_at),
                last_seen_at: row.last_seen_at,
                version: row.version,
                status,
            }
        })
        .collect();
    Ok(Json(out))
}

async fn unpair(
    _admin: AdminCaller,
    State(state): State<AppState>,
    Path(daemon_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let hub = hub(&state)?;
    let id: DaemonId = daemon_id
        .parse()
        .map_err(|_| ApiError::not_found("daemon not found"))?;
    if !hub.unpair(id).await? {
        return Err(ApiError::not_found("daemon not found"));
    }
    Ok(Json(json!({"ok": true})))
}

async fn broker_key(
    _admin: AdminCaller,
    State(state): State<AppState>,
) -> ApiResult<Json<BrokerKey>> {
    let key = hub(&state)?
        .public_key()
        .ok_or_else(|| ApiError::unavailable(DISABLED))?;
    Ok(Json(BrokerKey {
        broker_public_key: key.to_text(),
    }))
}
