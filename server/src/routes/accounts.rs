//! Registration — `POST /v1/accounts`.
//!
//! # Status: not implemented
use ed25519_dalek::{Signature, Verifier};
use crate::auth;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crate::error::ApiError;
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


/// Decode a base64 field and check it is exactly `expected` bytes.
fn decode_fixed(s: &str, expected: usize) -> ApiResult<Vec<u8>> {
    let bytes = STANDARD.decode(s).map_err(|_| ApiError::BadRequest)?;
    if bytes.len() != expected {
        return Err(ApiError::BadRequest);
    }
    Ok(bytes)
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

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
        let ik_sig = decode_fixed(&req.ik_sig, 32)?;
        let ik_dh = decode_fixed(&req.ik_dh, 32)?;
        let ik_dh_sig = decode_fixed(&req.ik_dh_sig, 64)?;

            let vk = auth::parse_verifying_key(&ik_sig)?;

    let mut msg = Vec::with_capacity(16 + 32);
    msg.extend_from_slice(b"ephemera_ikdh_v1");
    msg.extend_from_slice(&ik_dh);

    let sig_bytes: [u8; 64] = ik_dh_sig
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&msg, &sig).map_err(|_| ApiError::BadRequest)?;

        let account_id = uuid::Uuid::new_v4();

    let result = sqlx::query(
        "INSERT INTO accounts (id, username, ik_sig, ik_dh, ik_dh_sig)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account_id)
    .bind(&req.username)
    .bind(&ik_sig)
    .bind(&ik_dh)
    .bind(&ik_dh_sig)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError::Conflict)
        }
        Err(e) => return Err(e.into()),
    }

    Ok(Json(RegisterResponse {
        account_id: account_id.to_string(),
    }))
}
