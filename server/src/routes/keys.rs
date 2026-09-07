//! Prekey publication and retrieval.
//!
//! # Status: not implemented

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiResult;
use crate::AppState;

/// A signed prekey plus a batch of one-time prekeys, base64-encoded.
#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    /// Signed prekey identifier.
    pub spk_id: u32,
    /// Signed prekey public.
    pub spk_pub: String,
    /// Signature over the signed prekey.
    pub spk_sig: String,
    /// One-time prekeys as `(id, public)` pairs.
    pub one_time: Vec<(u32, String)>,
}

/// A prekey bundle handed to an initiator.
#[derive(Debug, Serialize)]
pub struct BundleResponse {
    /// Recipient identity, Ed25519.
    pub ik_sig: String,
    /// Recipient identity, X25519.
    pub ik_dh: String,
    /// Binding signature.
    pub ik_dh_sig: String,
    /// Signed prekey identifier.
    pub spk_id: u32,
    /// Signed prekey public.
    pub spk_pub: String,
    /// Signature over the signed prekey.
    pub spk_sig: String,
    /// One-time prekey identifier, `0xFFFFFFFF` when none was available.
    pub opk_id: u32,
    /// One-time prekey public, absent when none was available.
    pub opk_pub: Option<String>,
}

/// Publish a signed prekey and a batch of one-time prekeys.
///
/// Requires authentication. Replaces the caller's current signed prekey,
/// retaining the previous generation for 7 days (3.2).
#[allow(unused_variables)]
pub async fn publish(
    State(state): State<AppState>,
    Json(req): Json<PublishRequest>,
) -> ApiResult<()> {
    todo!("Phase 2: PROTOCOL.md 3.2")
}

/// Fetch a prekey bundle, consuming one one-time prekey.
///
/// # Implementation checklist
///
/// This is the most security-sensitive query in the server. The one-time
/// prekey MUST be consumed atomically — two concurrent fetches must never
/// receive the same `opk_id` (T-3). Use a single statement:
///
/// ```sql
/// DELETE FROM one_time_prekeys
///  WHERE (account_id, opk_id) IN (
///        SELECT account_id, opk_id FROM one_time_prekeys
///         WHERE account_id = $1
///         ORDER BY opk_id
///         FOR UPDATE SKIP LOCKED
///         LIMIT 1)
/// RETURNING opk_id, opk_pub;
/// ```
///
/// A SELECT followed by a DELETE is **non-conformant** — the same race as
/// T-10, in a place where it silently weakens forward secrecy rather than
/// producing a visible error.
///
/// Zero rows returned is not an error: emit `opk_id = 0xFFFFFFFF` and let the
/// initiator fall back to three-DH, surfaced to its user (T-2).
#[allow(unused_variables)]
pub async fn bundle(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> ApiResult<Json<BundleResponse>> {
    todo!("Phase 2: PROTOCOL.md 3.2, and read the note above about atomicity")
}

/// Remaining one-time prekey count, so a client knows when to replenish.
#[allow(unused_variables)]
pub async fn count(State(state): State<AppState>) -> ApiResult<Json<u32>> {
    todo!("Phase 2")
}
