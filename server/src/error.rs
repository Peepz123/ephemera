//! API error type and its mapping to HTTP status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Result alias for handlers.
pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Every way a request can be refused.
///
/// Responses carry a short machine-readable code and nothing else. Detailed
/// error text is a metadata leak: "no such user" and "wrong signature" are
/// different answers to an enumeration probe (T-21).
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Request body or parameters malformed.
    #[error("bad request")]
    BadRequest,

    /// Authentication missing, expired, or invalid.
    #[error("unauthorised")]
    Unauthorised,

    /// Resource absent, or the caller may not know whether it exists.
    #[error("not found")]
    NotFound,

    /// One-view content already retrieved (8.1).
    #[error("gone")]
    Gone,

    /// Username already registered.
    #[error("conflict")]
    Conflict,

    /// Rate limit exceeded.
    #[error("too many requests")]
    RateLimited,

    /// Database or internal failure. Never surfaced in detail to the caller.
    #[error("internal error")]
    Internal,
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::Unauthorised => StatusCode::UNAUTHORIZED,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Gone => StatusCode::GONE,
            ApiError::Conflict => StatusCode::CONFLICT,
            ApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = axum::Json(serde_json::json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}
