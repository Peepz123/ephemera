//! Attachment upload and retrieval.
//!
//! # Status: not implemented

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::error::ApiResult;
use crate::AppState;

/// Response to a successful upload.
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    /// Hex-encoded 256-bit blob identifier.
    pub blob_id: String,
}

/// Upload attachment ciphertext.
///
/// The body is opaque bytes. The server does not know the plaintext length,
/// the MIME type, or the content encryption key — all three live inside the
/// attachment descriptor in the ratcheted envelope (7.1).
#[allow(unused_variables)]
pub async fn upload(State(state): State<AppState>, body: axum::body::Bytes) -> ApiResult<Json<UploadResponse>> {
    todo!("Phase 2: PROTOCOL.md 7.1")
}

/// Retrieve a blob, consuming it if it is one-view.
///
/// # Implementation checklist
///
/// For one-view blobs the state transition MUST be a single atomic statement
/// (8.1, T-10):
///
/// ```sql
/// UPDATE blobs
///    SET state = 'consumed', consumed_at = now()
///  WHERE blob_id = $1 AND recipient_id = $2 AND state = 'unread'
/// RETURNING storage_key;
/// ```
///
/// Zero rows means already consumed → 410 Gone. A read-then-update sequence
/// is non-conformant: two concurrent requests would both succeed, and the
/// single-view guarantee — the one feature this project is built around —
/// would be false under exactly the conditions an attacker would arrange.
///
/// Object deletion from storage happens asynchronously afterwards. The state
/// flag is the enforcement point, not the object lifetime.
#[allow(unused_variables)]
pub async fn fetch(
    State(state): State<AppState>,
    Path(blob_id): Path<String>,
) -> ApiResult<Vec<u8>> {
    todo!("Phase 2: PROTOCOL.md 8.1 — atomic consume, see the note above")
}
