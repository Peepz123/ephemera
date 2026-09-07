//! Runtime configuration, read from the environment.

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string.
    pub database_url: String,
    /// Address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Maximum accepted request body, in bytes.
    pub max_body: usize,
}

impl Config {
    /// Read configuration from the environment, applying defaults.
    pub fn from_env() -> Self {
        Config {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| {
                    "postgres://ephemera:devonly@127.0.0.1:5432/ephemera".to_string()
                }),
            bind: std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            max_body: 1024 * 1024,
        }
    }
}
