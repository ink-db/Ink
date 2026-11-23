//! Client error types for Ink database connections and commands.

use ink_proto::ProtoError;
use thiserror::Error;

/// Errors returned by the Ink client library and CLI connection engine.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Connection or network I/O error.
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol framing or codec failure.
    #[error("Protocol error: {0}")]
    Proto(#[from] ProtoError),

    /// Handshake rejected by server.
    #[error("Authentication failed: code 0x{code:04X} ({name}): {reason}")]
    AuthFailed {
        /// Wire protocol error code
        code: u16,
        /// Canonical error name
        name: String,
        /// Server reason text
        reason: String,
    },

    /// Handshake challenge timeout.
    #[error("Authentication challenge timed out after {0} ms")]
    ChallengeTimeout(u32),

    /// Key loading, decryption, or cryptographic error.
    #[error("Key error: {0}")]
    KeyError(String),

    /// Server rejected query or statement.
    #[error("Query failed: {0}")]
    QueryFailed(String),

    /// Remote signing or two-step append lease expired.
    #[error("Append lease expired: {0}")]
    LeaseExpired(String),

    /// Server reported access denied.
    #[error("Access denied by server: {0}")]
    AccessDenied(String),

    /// Server returned an unexpected frame type for the current state.
    #[error("Unexpected frame received: expected {expected:?}, got {actual:?}")]
    UnexpectedFrame {
        /// Expected frame type
        expected: ink_proto::FrameType,
        /// Actual frame type received
        actual: ink_proto::FrameType,
    },

    /// Address or URL resolution failure.
    #[error("Invalid server address '{0}': {1}")]
    InvalidAddress(String, String),

    /// Connection closed unexpectedly.
    #[error("Connection closed by remote server")]
    ConnectionClosed,
}
