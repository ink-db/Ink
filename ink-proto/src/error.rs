//! Error types for the Ink Wire Protocol (IWP).

use thiserror::Error;

/// Protocol and codec errors encountered while encoding, decoding, or processing IWP frames.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// I/O error during network or buffer read/write.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Frame does not begin with magic bytes `INK`.
    #[error("Invalid magic prefix: expected [0x49, 0x4E, 0x4B], got {0:02X?}")]
    BadMagic([u8; 3]),

    /// Unsupported protocol version.
    #[error("Unsupported protocol version: expected 1, got {0}")]
    UnsupportedVersion(u8),

    /// Header CRC32-C integrity check failed.
    #[error("Header CRC32-C mismatch: expected 0x{expected:08X}, computed 0x{computed:08X}")]
    HeaderCrcMismatch {
        /// Expected CRC recorded in header
        expected: u32,
        /// Computed CRC over header bytes 0..14
        computed: u32,
    },

    /// Payload CRC32-C integrity check failed.
    #[error("Payload CRC32-C mismatch: expected 0x{expected:08X}, computed 0x{computed:08X}")]
    PayloadCrcMismatch {
        /// Expected CRC trailing the payload
        expected: u32,
        /// Computed CRC over payload bytes
        computed: u32,
    },

    /// Frame payload length exceeds safety limit.
    #[error("Payload length {length} bytes exceeds maximum limit of {max} bytes")]
    PayloadTooLarge {
        /// Attempted payload length
        length: u32,
        /// Maximum allowed payload length
        max: u32,
    },

    /// Frame type value is not recognized.
    #[error("Unknown or invalid frame type: 0x{0:02X}")]
    InvalidFrameType(u8),

    /// Payload buffer ended prematurely.
    #[error("Incomplete payload: expected {expected} bytes, but only {actual} available")]
    IncompletePayload {
        /// Required byte count
        expected: usize,
        /// Available byte count
        actual: usize,
    },

    /// Payload text is not valid UTF-8.
    #[error("Invalid UTF-8 sequence in frame payload: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// JSON serialization or deserialization failure.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Protocol semantic or sequence violation.
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}
