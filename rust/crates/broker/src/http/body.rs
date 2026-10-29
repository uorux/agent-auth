//! Request bodies: JSON parsed into a wire type, refused with 422.
//!
//! Every body type in `agent-auth-wire` is `deny_unknown_fields` with
//! bounded fields; [`JsonBody`] turns bytes into one, after the handler's
//! other extractors (authentication first: axum runs `FromRequestParts`
//! extractors before the body). The global body limit (`http::router`)
//! bounds the bytes read.

use agent_auth_wire::BodyError;
use agent_auth_wire::error::parse_body;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::json;

/// A parsed JSON body.
#[derive(Debug, Clone)]
pub struct JsonBody<T>(pub T);

/// FastAPI's list-shaped 422 (agents read only the status and `detail`).
#[must_use]
pub fn body_error(e: &BodyError) -> Response {
    let item = match e {
        BodyError::Json(m) => json!({
            "type": "json_invalid", "loc": ["body"], "msg": "JSON decode error",
            "input": {}, "ctx": {"error": m},
        }),
        BodyError::Invalid(m) => json!({
            "type": "value_error", "loc": ["body"], "msg": m,
        }),
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "detail": [item] })),
    )
        .into_response()
}

impl<S, T> FromRequest<S> for JsonBody<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Response> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        parse_body(&bytes).map(JsonBody).map_err(|e| body_error(&e))
    }
}
