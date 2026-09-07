//! Envelope stream — `WS /v1/ws`.
//!
//! # Status: not implemented

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::State;
use axum::response::Response;

use crate::AppState;

/// Upgrade to a WebSocket and stream envelopes.
///
/// # Implementation checklist
///
/// 1. Authenticate before upgrading.
/// 2. On connect, drain any queued envelopes for this account.
/// 3. Deliver live envelopes as they arrive. Postgres `LISTEN`/`NOTIFY` is
///    sufficient at this scale; no Redis needed.
/// 4. On delivery acknowledgement, **delete the row** (T-19). Retention past
///    acknowledgement is zero, and a `delivered_at` column you never clear is
///    a social graph you promised not to keep.
///
/// Inbound envelopes are validated only far enough to route them:
/// `Envelope::decode` for structural sanity and a size check. The server does
/// not and cannot check the ciphertext.
#[allow(unused_variables)]
pub async fn handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    todo!("Phase 2: PROTOCOL.md 10")
}
