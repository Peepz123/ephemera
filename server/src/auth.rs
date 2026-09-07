    //! Challenge–response authentication.
//!
//! # Status: not implemented
//!
//! A client proves control of its Ed25519 identity key by signing a
//! server-issued nonce. There is no password, no session cookie, and no
//! recoverable credential anywhere in the system (PROTOCOL.md 10).
//!
//! The server verifies signatures. It never holds a private key.

use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;
use rand_core::{OsRng, RngCore};
use crate::error::{ApiError, ApiResult};
use crate::AppState;
use sqlx::Row;
use ed25519_dalek::Verifier;

/// Domain separation for authentication challenges. Distinct from every other
/// context string in the system so a signature harvested here cannot be
/// replayed as a prekey signature or an identity binding.
pub const CTX_AUTH: &[u8] = b"ephemera_auth_v1";

/// How long an issued challenge remains valid.
pub const CHALLENGE_TTL_SECS: i64 = 60;

/// An authenticated caller.
#[derive(Debug, Clone, Copy)]
pub struct Caller {
    /// The authenticated account.
    pub account_id: Uuid,
}

/// Issue a fresh challenge for `username`.
///
/// # Implementation checklist
///
/// 1. Generate 32 random bytes from `OsRng`.
/// 2. Insert into `auth_challenges` with `expires_at = now() + CHALLENGE_TTL_SECS`.
/// 3. Return the nonce.
///
/// Issue a challenge whether or not the username exists, and take the same
/// time either way. Returning 404 here tells an attacker which usernames are
/// registered (T-21).

pub async fn issue_challenge(state: &AppState, username: &str) -> ApiResult<[u8; 32]> {
        let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    sqlx::query(
        "INSERT INTO auth_challenges (nonce, username, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))",
    )
    .bind(&nonce[..])
    .bind(username)
    .bind(CHALLENGE_TTL_SECS as f64)
    .execute(&state.db)
    .await?;

    Ok(nonce)   
}

/// Verify a signed challenge and return the authenticated caller.
///
/// # Implementation checklist
///
/// 1. Look up the nonce; reject if absent or expired.
/// 2. **Delete the row before verifying.** A challenge is single-use, and
///    deleting on lookup rather than on success stops an attacker retrying
///    signatures against the same nonce.
/// 3. Load the account's `ik_sig`, build the message as `CTX_AUTH || nonce`,
///    and verify.
/// 4. On success return the account id.

pub async fn verify_challenge(
    state: &AppState,
    nonce: &[u8; 32],
    signature: &Signature,
) -> ApiResult<Caller> {
        let row = sqlx::query(
        "DELETE FROM auth_challenges
          WHERE nonce = $1 AND expires_at > now()
      RETURNING username",
    )
    .bind(&nonce[..])
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::Unauthorised)?;

        let username: String = row.get("username");

    let account = sqlx::query("SELECT id, ik_sig FROM accounts WHERE username = $1")
        .bind(&username)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::Unauthorised)?;

    let account_id: Uuid = account.get("id");
    let ik_sig: Vec<u8> = account.get("ik_sig");

    let vk = parse_verifying_key(&ik_sig)?;

    let mut msg = Vec::with_capacity(CTX_AUTH.len() + 32);
    msg.extend_from_slice(CTX_AUTH);
    msg.extend_from_slice(nonce);

    vk.verify(&msg, signature).map_err(|_| ApiError::Unauthorised)?;

    Ok(Caller { account_id })
}

/// Parse a 32-byte Ed25519 public key from raw bytes.
pub fn parse_verifying_key(bytes: &[u8]) -> ApiResult<VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ApiError::BadRequest)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ApiError::BadRequest)
}
