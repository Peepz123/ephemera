//! Challenge–response authentication endpoints.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Request a challenge.
#[derive(Deserialize)]
pub struct ChallengeRequest {
    /// Account to authenticate as.
    pub username: String,
}

/// An issued challenge.
#[derive(Serialize)]
pub struct ChallengeResponse {
    /// Base64 nonce to sign.
    pub nonce: String,
}

/// A signed challenge.
#[derive(Deserialize)]
pub struct VerifyRequest {
    /// The nonce that was issued.
    pub nonce: String,
    /// Signature over `"ephemera_auth_v1" || nonce`.
    pub signature: String,
}

/// The authenticated account.
#[derive(Serialize)]
pub struct VerifyResponse {
    /// Account identifier.
    pub account_id: String,
}

/// Issue a challenge. Succeeds whether or not the username exists (T-21).
pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state, &req.username).await?;
    Ok(Json(ChallengeResponse {
        nonce: STANDARD.encode(nonce),
    }))
}

/// Exchange a signed challenge for the caller's account id.
pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> ApiResult<Json<VerifyResponse>> {
    let nonce: [u8; 32] = STANDARD
        .decode(&req.nonce)
        .map_err(|_| ApiError::BadRequest)?
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;

    let sig_bytes: [u8; 64] = STANDARD
        .decode(&req.signature)
        .map_err(|_| ApiError::BadRequest)?
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::BadRequest)?;

    let caller = auth::verify_challenge(&state, &nonce, &Signature::from_bytes(&sig_bytes)).await?;

    Ok(Json(VerifyResponse {
        account_id: caller.account_id.to_string(),
    }))
}