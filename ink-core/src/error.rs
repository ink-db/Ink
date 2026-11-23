//! Error types for ink-core.
//!
//! All public functions in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, InkError>`.

use std::io;
use thiserror::Error;

/// Every error that can occur in ink-core operations.
#[derive(Debug, Error)]
pub enum InkError {
    // I/O and file-system errors
    /// An OS-level I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // Frame / segment integrity errors
    /// A record frame had an invalid CRC32, suggesting file corruption or tampering.
    #[error("CRC mismatch in frame at byte offset {offset} in '{path}'")]
    CrcMismatch { offset: u64, path: String },

    /// A record frame is structurally invalid even though the CRC passed.
    #[error("Corrupt record at byte offset {offset} in '{path}': {reason}")]
    CorruptRecord {
        offset: u64,
        path: String,
        reason: String,
    },

    /// The segment file header has an unexpected magic number.
    #[error("Invalid segment magic in '{path}': expected 'INKSEGMT', found 0x{found:016X}")]
    InvalidSegmentMagic { path: String, found: u64 },

    /// The format version in a file is not supported by this build.
    #[error("Unsupported format version {found} in '{path}' (maximum supported: {max})")]
    UnsupportedVersion { found: u16, max: u16, path: String },

    // Hash-chain / cryptographic integrity errors
    /// A record's stored hash does not match the hash recomputed from its fields.
    ///
    /// This indicates that the record's content was modified after it was written.
    #[error("Record #{id}: stored hash {stored} does not match recomputed hash {computed}")]
    HashMismatch {
        id: u64,
        stored: String,
        computed: String,
    },

    /// The hash chain between two consecutive records in the same table is broken.
    ///
    /// This indicates that records were inserted, removed, or reordered.
    #[error(
        "Hash chain broken at record #{id}: \
         prev_hash is {found}, expected {expected}"
    )]
    ChainBreak {
        id: u64,
        expected: String,
        found: String,
    },

    /// An Ed25519 digital signature on a record is invalid.
    #[error("Invalid signature on record #{id} by author {author}: {reason}")]
    InvalidSignature {
        id: u64,
        author: String,
        reason: String,
    },

    /// Merkle inclusion or consistency proof generation/verification error.
    #[error("Merkle proof error: {0}")]
    ProofError(String),

    // Input validation errors
    /// The table name contains invalid UTF-8.
    #[error("Invalid UTF-8 in table name at byte offset {offset}")]
    InvalidUtf8 { offset: u64 },

    /// The record payload is not valid UTF-8 JSON.
    #[error("Invalid JSON payload: {0}")]
    InvalidJson(String),

    /// The record data exceeds the maximum allowed size.
    #[error("Record data too large: {size} bytes (maximum is {max} bytes)")]
    RecordTooLarge { size: usize, max: usize },

    /// The table name exceeds the maximum allowed byte length.
    #[error("Table name too long: {len} bytes (maximum is {max} bytes)")]
    TableNameTooLong { len: usize, max: usize },

    /// The table name is empty.
    #[error("Table name must not be empty")]
    EmptyTableName,

    // Database / store errors
    /// A database already exists at the given path.
    #[error("A database already exists at '{0}'")]
    AlreadyInitialized(String),

    /// The directory does not contain a valid Ink database.
    #[error("Not an Ink database: '{0}' (run 'ink init' first)")]
    NotADatabase(String),

    /// The `ink.meta` file could not be parsed.
    #[error("Failed to parse ink.meta: {0}")]
    InvalidMeta(String),

    /// The record ID was not found in the index.
    #[error("Record #{0} does not exist in this database")]
    NotFound(u64),

    /// The table has no records (or does not exist).
    #[error("Table \"{0}\" has no records (use APPEND TO add the first one)")]
    TableNotFound(String),

    // Authentication and authorization errors
    /// Access was denied because the key lacks the necessary role or table scope.
    #[error("Access denied for key {key}: insufficient permissions to perform '{action}' on table '{table}'")]
    AccessDenied {
        key: String,
        action: String,
        table: String,
    },

    /// Authentication failed during handshake or identity verification.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// A record in the `_ink_access` system table is malformed or invalid.
    #[error("Invalid access record: {0}")]
    InvalidAccessRecord(String),
}

/// A `Result` alias for ink-core operations.
pub type Result<T> = std::result::Result<T, InkError>;
