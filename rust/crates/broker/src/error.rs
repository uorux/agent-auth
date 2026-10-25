//! HTTP errors in the Python's shape: `{"detail": "..."}` with its status.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use agent_auth_store::StoreError;

/// An error answered to an HTTP caller. The detail is shown to the caller,
/// so it never carries secrets, upstream response bodies or internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub detail: String,
}

impl ApiError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> ApiError {
        ApiError { status, detail: detail.into() }
    }
    pub fn bad_request(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::BAD_REQUEST, detail)
    }
    pub fn unauthorized(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNAUTHORIZED, detail)
    }
    pub fn forbidden(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::FORBIDDEN, detail)
    }
    pub fn not_found(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::NOT_FOUND, detail)
    }
    pub fn conflict(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::CONFLICT, detail)
    }
    pub fn unprocessable(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, detail)
    }
    pub fn unavailable(detail: impl Into<String>) -> ApiError {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, detail)
    }
    /// An internal failure: logged with its cause, answered without it.
    pub fn internal(cause: &dyn std::fmt::Display) -> ApiError {
        tracing::error!(%cause, "internal error");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> ApiError {
        ApiError::internal(&e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
