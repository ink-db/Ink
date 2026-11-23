//! Core record type, constants, and cryptographic helpers.
//!
//! A [`Record`] is the atomic unit of data in Ink. Once written, a record is
//! never modified. The [`compute_record_hash`] function defines the canonical
//! serialization used for all hash-chain and integrity checks.

use crate::error::{InkError, Result};

// Constants

/// Maximum payload size per record (64 MiB).
pub const MAX_RECORD_DATA_SIZE: usize = 64 * 1024 * 1024;

/// Maximum table name length in bytes (UTF-8).
pub const MAX_TABLE_NAME_SIZE: usize = 255;

/// Sentinel value stored in the `correction_of` frame field when this record
/// is not a correction (`u64::MAX`).
pub const NOT_A_CORRECTION: u64 = u64::MAX;

/// Record flag: this record is a correction of a previous record.
pub const FLAG_IS_CORRECTION: u8 = 0x01;

// Record
/// A single immutable record stored in an Ink database.
///
/// Records are written once and never modified. Corrections are expressed as
/// new records with [`FLAG_IS_CORRECTION`] set in `flags` and the original
/// record's ID in `correction_of`. The original record is permanently visible.
///
/// # Hash chain
///
/// The chain is per-table: `prev_hash` is the [`record_hash`] of the
/// immediately preceding record **in the same table** (by global ID order),
/// or `[0u8; 32]` for the first record in a table.
///
/// # Signatures (Phase 2)
///
/// In Phase 1, `author` is all zeros and `signature` is all zeros. Phase 2
/// will populate both fields with real Ed25519 key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Strictly monotonic, database-global sequential identifier.
    ///
    /// IDs are assigned across all tables in insertion order. Gaps indicate
    /// that records with the missing IDs belong to other tables.
    pub id: u64,

    /// Microseconds since the Unix epoch (UTC) when this record was appended.
    pub timestamp: i64,

    /// Logical table this record belongs to (UTF-8, ≤ 255 bytes).
    pub table: String,

    /// Ed25519 public key (32 bytes) of the writer.
    ///
    /// All zeros in Phase 1 (unsigned records). Real keys are introduced in
    /// Phase 2.
    pub author: [u8; 32],

    /// Payload bytes. Must be valid UTF-8 JSON in format version 0.
    pub data: Vec<u8>,

    /// Bit flags. [`FLAG_IS_CORRECTION`] (0x01) marks a correction record.
    pub flags: u8,

    /// If this is a correction, the global ID of the record being corrected.
    pub correction_of: Option<u64>,

    /// BLAKE3 hash of the previous record in this table (zeros for the first).
    ///
    /// This field links records within a table into a tamper-evident chain.
    pub prev_hash: [u8; 32],

    /// BLAKE3 hash of this record's canonical content (see [`compute_record_hash`]).
    ///
    /// Any modification to the record's fields (id, timestamp, table, author,
    /// flags, correction_of, data, prev_hash) will produce a different hash,
    /// which is detected by [`Store::verify_table`].
    pub record_hash: [u8; 32],

    /// Ed25519 signature over `record_hash` by `author`.
    ///
    /// All zeros in Phase 1 (unsigned). Phase 2 will enforce signature
    /// verification on reads.
    pub signature: [u8; 64],
}

impl Record {
    /// Returns `true` if this record is a correction of another record.
    #[inline]
    pub fn is_correction(&self) -> bool {
        self.flags & FLAG_IS_CORRECTION != 0
    }

    /// Returns the lower-case hex-encoded `record_hash` (64 characters).
    pub fn hash_hex(&self) -> String {
        hex::encode(self.record_hash)
    }

    /// Returns the lower-case hex-encoded `author` public key (64 characters).
    pub fn author_hex(&self) -> String {
        hex::encode(self.author)
    }

    /// Returns the lower-case hex-encoded `prev_hash` (64 characters).
    pub fn prev_hash_hex(&self) -> String {
        hex::encode(self.prev_hash)
    }

    /// Returns the payload as a UTF-8 string slice, if valid.
    pub fn data_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }
}

// Canonical hash computation

/// Compute the canonical BLAKE3 hash of a record's content.
///
/// The hash is computed over a fixed-width, deterministic byte sequence
/// derived from the record's fields (see `FORMAT.md §4`). The hash and
/// signature fields are excluded from the input to avoid a circular dependency.
///
/// # Canonical input layout
///
/// ```text
/// id            (u64 LE, 8 bytes)
/// timestamp     (i64 LE, 8 bytes)
/// table_len     (u16 LE, 2 bytes)
/// table         (UTF-8, table_len bytes)
/// author        (32 bytes)
/// flags         (u8, 1 byte)
/// correction_of (u64 LE, 8 bytes; NOT_A_CORRECTION if None)
/// data_len      (u32 LE, 4 bytes)
/// data          (data_len bytes)
/// prev_hash     (32 bytes)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn compute_record_hash(
    id: u64,
    timestamp: i64,
    table: &str,
    author: &[u8; 32],
    flags: u8,
    correction_of: Option<u64>,
    data: &[u8],
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let table_bytes = table.as_bytes();
    let correction_raw = correction_of.unwrap_or(NOT_A_CORRECTION);

    let mut h = blake3::Hasher::new();
    h.update(&id.to_le_bytes());
    h.update(&timestamp.to_le_bytes());
    h.update(&(table_bytes.len() as u16).to_le_bytes());
    h.update(table_bytes);
    h.update(author.as_slice());
    h.update(&[flags]);
    h.update(&correction_raw.to_le_bytes());
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
    h.update(prev_hash.as_slice());
    *h.finalize().as_bytes()
}

// Input validation

/// Validate a table name.
///
/// Table names must be non-empty UTF-8 strings of at most
/// [`MAX_TABLE_NAME_SIZE`] bytes. They are stored verbatim; case is
/// significant.
pub fn validate_table_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(InkError::EmptyTableName);
    }
    let len = name.len();
    if len > MAX_TABLE_NAME_SIZE {
        return Err(InkError::TableNameTooLong {
            len,
            max: MAX_TABLE_NAME_SIZE,
        });
    }
    Ok(())
}

/// Validate a JSON data payload.
///
/// In format version 0, all payloads must be valid UTF-8 JSON. The size must
/// not exceed [`MAX_RECORD_DATA_SIZE`].
pub fn validate_data(data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > MAX_RECORD_DATA_SIZE {
        return Err(InkError::RecordTooLarge {
            size: len,
            max: MAX_RECORD_DATA_SIZE,
        });
    }
    let s = std::str::from_utf8(data)
        .map_err(|e| InkError::InvalidJson(format!("not valid UTF-8: {e}")))?;
    serde_json::from_str::<serde_json::Value>(s)
        .map_err(|e| InkError::InvalidJson(e.to_string()))?;
    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let author = [0u8; 32];
        let prev = [0u8; 32];
        let data = b"{\"x\": 1}";

        let h1 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, data, &prev);
        let h2 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, data, &prev);
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn hash_changes_with_data() {
        let author = [0u8; 32];
        let prev = [0u8; 32];

        let h1 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, b"{\"x\":1}", &prev);
        let h2 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, b"{\"x\":2}", &prev);
        assert_ne!(h1, h2, "different data must produce different hash");
    }

    #[test]
    fn hash_changes_with_id() {
        let author = [0u8; 32];
        let prev = [0u8; 32];
        let data = b"{\"x\": 1}";

        let h1 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, data, &prev);
        let h2 = compute_record_hash(1, 1_000_000, "sales", &author, 0, None, data, &prev);
        assert_ne!(h1, h2, "different ID must produce different hash");
    }

    #[test]
    fn hash_changes_with_prev_hash() {
        let author = [0u8; 32];
        let prev1 = [0u8; 32];
        let mut prev2 = [0u8; 32];
        prev2[0] = 1;
        let data = b"{\"x\": 1}";

        let h1 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, data, &prev1);
        let h2 = compute_record_hash(0, 1_000_000, "sales", &author, 0, None, data, &prev2);
        assert_ne!(h1, h2, "different prev_hash must produce different hash");
    }

    #[test]
    fn validate_table_name_ok() {
        assert!(validate_table_name("sales").is_ok());
        assert!(validate_table_name("my_table_123").is_ok());
        assert!(validate_table_name("a").is_ok());
    }

    #[test]
    fn validate_table_name_empty() {
        assert!(validate_table_name("").is_err());
    }

    #[test]
    fn validate_table_name_too_long() {
        let long = "x".repeat(256);
        assert!(validate_table_name(&long).is_err());
    }

    #[test]
    fn validate_data_valid_json() {
        assert!(validate_data(b"{\"key\": \"value\"}").is_ok());
        assert!(validate_data(b"{}").is_ok());
        assert!(validate_data(b"{\"n\": 42}").is_ok());
    }

    #[test]
    fn validate_data_invalid_json() {
        assert!(validate_data(b"not json").is_err());
        assert!(validate_data(b"{unclosed").is_err());
    }

    #[test]
    fn validate_data_too_large() {
        let big = vec![b'x'; MAX_RECORD_DATA_SIZE + 1];
        assert!(validate_data(&big).is_err());
    }
}
