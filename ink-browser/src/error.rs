//! Error types for Ink Browser and Backend abstraction.

use thiserror::Error;

/// Unified errors for Ink Browser operations across Local and Server backends.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The database directory is locked by another running process.
    #[error("Database is locked by another process: {0}")]
    DatabaseLocked(String),

    /// Access was denied by the gatekeeper or server.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// An IQL statement failed to parse or execute.
    #[error("Query execution failed: {0}")]
    QueryFailed(String),

    /// Key loading, passphrase decryption, or signature verification failed.
    #[error("Authentication/Key error: {0}")]
    KeyError(String),

    /// A requested record was not found.
    #[error("Record #{0} not found")]
    RecordNotFound(u64),

    /// Low-level IO failure.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Ink core engine error.
    #[error("Core storage error: {0}")]
    Core(#[from] ink_core::error::InkError),

    /// Ink client network error.
    #[error("Network client error: {0}")]
    Client(#[from] ink_client::ClientError),

    /// JSON serialization or deserialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Operation cancelled by user.
    #[error("Operation cancelled")]
    Cancelled,

    /// General operational failure.
    #[error("{0}")]
    Other(String),
}
