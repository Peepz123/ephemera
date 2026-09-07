//! ephemera relay.
//!
//! A store-and-forward queue for ciphertext it cannot read. See
//! `docs/THREAT-MODEL.md` §2 for what this component is and is not trusted
//! with — the short version is that a full compromise of this process and its
//! database discloses metadata, and no message content whatsoever.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod auth;
mod config;
mod error;
mod routes;

use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use config::Config;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// Postgres connection pool.
    pub db: sqlx::PgPool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ephemera_server=debug,tower_http=debug".into()),
        )
        .init();

    let cfg = Config::from_env();

    let db = PgPoolOptions::new()
        .max_connections(16)
        .connect(&cfg.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("migrations applied");

    let state = AppState { db };

    let app = Router::new()
        .route("/health/live", get(routes::health::live))
        .route("/health/ready", get(routes::health::ready))
        .route("/v1/auth/challenge", post(routes::auth::challenge))
        .route("/v1/auth/verify", post(routes::auth::verify))
        .route("/v1/accounts", post(routes::accounts::register))
        .route("/v1/keys/prekeys", post(routes::keys::publish))
        .route("/v1/keys/count", get(routes::keys::count))
        .route("/v1/keys/:username", get(routes::keys::bundle))
        .route("/v1/blobs", post(routes::blobs::upload))
        .route("/v1/blobs/:blob_id", get(routes::blobs::fetch))
        .route("/v1/ws", get(routes::ws::handler))
        .layer(RequestBodyLimitLayer::new(cfg.max_body))
        // TraceLayer logs method, path, and status. It MUST NOT be configured
        // to log bodies or headers — that would defeat T-19 in one line.
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!(bind = %cfg.bind, "relay listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
