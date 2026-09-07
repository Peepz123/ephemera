//! Liveness and readiness.

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::error::ApiResult;
use crate::AppState;

/// Liveness: the process is up. Does not touch the database.
pub async fn live() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Readiness: the process is up and the database answers.
pub async fn ready(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("SELECT 1").execute(&state.db).await?;
    Ok(Json(json!({ "status": "ready" })))
}
