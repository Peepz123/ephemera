//! Registration — `POST /v1/accounts`.
//!
//! # Status: not implemented

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiResult;
use crate::AppState;

/// Registration request body. Keys are base64-encoded.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Desired username, 3–32 chars, `[a-z0-9_.-]`.
    pub username: String,
    /// Ed25519 identity key.
    pub ik_sig: String,
    /// X25519 agreement key.
    pub ik_dh: String,
    /// Signature binding `ik_dh` to `ik_sig`.
    pub ik_dh_sig: String,
}

/// Registration response.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    /// Assigned account identifier.
    pub account_id: String,
}

/// Register a new account.
///
/// # Implementation checklist
///
/// 1. Decode the three base64 fields; reject wrong lengths.
/// 2. Verify `ik_dh_sig` over `"ephemera_ikdh_v1" || ik_dh` against `ik_sig`.
///    The database cannot check this, and a bundle with a broken binding is
///    useless to every client that fetches it (3.1).
/// 3. Insert. A unique-violation on `username` is 409, not 500.
///
/// Note this verification is a courtesy: clients MUST NOT trust it, because
/// the server is untrusted (T-1). It exists to keep unusable rows out of the
/// database, not to provide a security guarantee.
#[allow(unused_variables)]
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    todo!("Phase 2: PROTOCOL.md 3.1")
}
