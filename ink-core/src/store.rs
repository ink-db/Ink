//! Top-level store: the main public API for opening, writing, reading, and
//! verifying an Ink database.
//!
//! # Usage
//!
//! ```rust,no_run
//! use ink_core::Store;
//! use std::path::Path;
//!
//! // Create a new database
//! let mut store = Store::init(Path::new("./mydb")).unwrap();
//!
//! // Append a record
//! let record = store.append("sales", b"{\"customer\":\"Alice\",\"amount\":1500}").unwrap();
//! println!("Appended record #{}", record.id);
//!
//! // Read all records in a table
//! let records = store.get_records_in_table("sales", None).unwrap();
//!
//! // Verify integrity
//! let result = store.verify_table("sales").unwrap();
//! assert!(result.is_valid);
//! ```

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::auth::{
    create_genesis_admin_payload, AccessAction, AclRegistry, Role, SYSTEM_TABLE_ACCESS,
};
use crate::crypto::{verify_signature, Keypair, ANONYMOUS_AUTHOR, EMPTY_SIGNATURE};
use crate::error::{InkError, Result};
use crate::index::{InkIndex, RecordLocation};
use crate::merkle::{ConsistencyProof, InclusionProof, MerkleTree};
use crate::record::{
    compute_record_hash, validate_data, validate_table_name, Record, FLAG_IS_CORRECTION,
    MAX_RECORD_DATA_SIZE, MAX_TABLE_NAME_SIZE,
};
use crate::segment::{
    list_table_segments, now_micros, read_record_at, scan_segment, SegmentWriter,
    SEGMENT_HEADER_SIZE,
};

// Constants

/// Format version written by this implementation.
const CURRENT_FORMAT_VERSION: u16 = 0;

/// Default maximum segment size (64 MiB).
const DEFAULT_SEGMENT_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// Name of the metadata file at the database root.
const META_FILENAME: &str = "ink.meta";

/// Name of the segments subdirectory.
const SEGMENTS_DIR: &str = "segments";

// DatabaseMeta

/// Persistent metadata stored in `<data_dir>/ink.meta` (JSON).
///
/// This file is updated after each append.  It is not the source of truth —
/// the segment files always are — but it speeds up startup.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DatabaseMeta {
    /// On-disk format version.  Bump on breaking changes.
    format_version: u16,
    /// Microseconds since the Unix epoch when the database was created.
    created_at: i64,
    /// Random UUID identifying this database instance.
    database_id: String,
    /// Maximum segment file size in bytes.
    segment_size_bytes: u64,
    /// Hash algorithm used for the chain.  Currently always "blake3".
    hash_algorithm: String,
    /// Signature algorithm.  Currently "ed25519" (unsigned in Phase 1).
    signature_algorithm: String,
    /// Cached next global record ID.  Recomputed from segments on startup.
    next_global_id: u64,
}

// Public result types

/// A single verification finding.
#[derive(Debug, Clone)]
pub struct VerifyError {
    /// The record ID at which the error was detected (may be approximate if
    /// the frame could not be parsed).
    pub record_id: u64,
    /// Short machine-readable error kind.
    pub kind: VerifyErrorKind,
    /// Human-readable description with file path and byte offset.
    pub description: String,
}

/// The category of a verification finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyErrorKind {
    /// The CRC32 of a record frame does not match.
    CrcMismatch,
    /// The stored `record_hash` does not match the hash recomputed from the
    /// record's fields.
    HashMismatch,
    /// The `prev_hash` of a record does not match the `record_hash` of the
    /// preceding record in the same table.
    ChainBreak,
    /// An Ed25519 digital signature is invalid.
    InvalidSignature,
    /// The Merkle tree head does not match.
    MerkleMismatch,
    /// A frame could not be parsed even though the CRC passed.
    ParseError,
    /// A frame length field is outside the valid range.
    InvalidFrameLength,
}

/// The result of a [`Store::verify_table`] or [`Store::verify_all`] call.
#[derive(Debug)]
pub struct VerifyResult {
    /// Tables that were verified.
    pub tables_checked: Vec<String>,
    /// Total number of records successfully verified.
    pub records_checked: u64,
    /// `true` if no errors were found.
    pub is_valid: bool,
    /// All errors found, in the order they were discovered.
    pub errors: Vec<VerifyError>,
}

/// A snapshot of the database's current state.
#[derive(Debug)]
pub struct StoreStatus {
    /// Total number of records across all tables.
    pub record_count: u64,
    /// Number of distinct tables.
    pub table_count: usize,
    /// The highest record ID currently in the database, or `None` if empty.
    pub last_record_id: Option<u64>,
    /// The `record_hash` of the last appended record per table.
    pub last_hash_per_table: HashMap<String, String>,
    /// Root hash of the global Merkle tree (tree head).
    pub tree_head: String,
    /// Unique database identifier (from `ink.meta`).
    pub database_id: String,
    /// Format version (from `ink.meta`).
    pub format_version: u16,
}

// Store

/// The main handle to an Ink database.
///
/// A `Store` is **not** thread-safe.  Wrap it in `Arc<Mutex<Store>>` when
/// sharing across threads (e.g., in the HTTP server introduced in Phase 4).
pub struct Store {
    /// Root directory of the database.
    data_dir: PathBuf,
    /// Persistent metadata (kept in sync with `ink.meta`).
    meta: DatabaseMeta,
    /// Active segment writers, one per table.
    writers: HashMap<String, SegmentWriter>,
    /// In-memory index (rebuilt from segments on startup).
    index: InkIndex,
    /// BLAKE3 hash of the last record appended to each table.
    /// Used to compute `prev_hash` for the next record in that table.
    last_hash_per_table: HashMap<String, [u8; 32]>,
    /// Global Merkle tree over all records in insertion order.
    merkle_tree: MerkleTree,
    /// In-memory materialized access control registry (rebuilt from _ink_access).
    acl: AclRegistry,
}

impl Store {
    // Lifecycle

    /// Initialize a new Ink database at `data_dir`.
    ///
    /// Creates `ink.meta` and the `segments/` subdirectory.  Returns an error
    /// if a database already exists at that path.
    pub fn init(data_dir: &Path) -> Result<Self> {
        let meta_path = data_dir.join(META_FILENAME);
        if meta_path.exists() {
            return Err(InkError::AlreadyInitialized(
                data_dir.to_string_lossy().to_string(),
            ));
        }

        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(data_dir.join(SEGMENTS_DIR))?;

        let meta = DatabaseMeta {
            format_version: CURRENT_FORMAT_VERSION,
            created_at: now_micros(),
            database_id: uuid::Uuid::new_v4().to_string(),
            segment_size_bytes: DEFAULT_SEGMENT_SIZE_BYTES,
            hash_algorithm: "blake3".to_string(),
            signature_algorithm: "ed25519".to_string(),
            next_global_id: 0,
        };

        let store = Self {
            data_dir: data_dir.to_path_buf(),
            meta,
            writers: HashMap::new(),
            index: InkIndex::new(),
            last_hash_per_table: HashMap::new(),
            merkle_tree: MerkleTree::new(),
            acl: AclRegistry::new(),
        };
        store.save_meta()?;
        Ok(store)
    }

    /// Initialize a new Ink database with a genesis admin keypair,
    /// recording the initial admin grant in `_ink_access`.
    pub fn init_with_admin(data_dir: &Path, admin_key: Option<Keypair>) -> Result<(Self, Keypair)> {
        let mut store = Self::init(data_dir)?;
        let kp = admin_key.unwrap_or_else(Keypair::generate);
        store.bootstrap_admin(&kp)?;
        Ok((store, kp))
    }

    /// Bootstrap the genesis admin grant into the `_ink_access` system table.
    pub fn bootstrap_admin(&mut self, admin_key: &Keypair) -> Result<Record> {
        let payload = create_genesis_admin_payload(&admin_key.public_key());
        self.append_signed(SYSTEM_TABLE_ACCESS, &payload, Some(admin_key))
    }

    /// Open an existing Ink database at `data_dir`.
    ///
    /// Scans all segment files, performs crash recovery (truncates any partial
    /// tail write), and rebuilds the in-memory index.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let meta_path = data_dir.join(META_FILENAME);
        if !meta_path.exists() {
            return Err(InkError::NotADatabase(
                data_dir.to_string_lossy().to_string(),
            ));
        }

        let meta_bytes = fs::read(&meta_path)?;
        let mut meta: DatabaseMeta = serde_json::from_slice(&meta_bytes)
            .map_err(|e| InkError::InvalidMeta(e.to_string()))?;

        if meta.format_version > CURRENT_FORMAT_VERSION {
            return Err(InkError::UnsupportedVersion {
                found: meta.format_version,
                max: CURRENT_FORMAT_VERSION,
                path: meta_path.to_string_lossy().to_string(),
            });
        }

        let segments_dir = data_dir.join(SEGMENTS_DIR);
        let mut index = InkIndex::new();
        let mut last_hash_per_table: HashMap<String, [u8; 32]> = HashMap::new();
        let mut writers: HashMap<String, SegmentWriter> = HashMap::new();
        let mut next_global_id: u64 = 0;

        // Scan every table directory.
        if segments_dir.exists() {
            for entry in fs::read_dir(&segments_dir)? {
                let entry = entry?;
                let table_dir = entry.path();
                if !table_dir.is_dir() {
                    continue;
                }

                let table_name = match table_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .filter(|s| !s.is_empty())
                {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                let (locs, last_hash, writer) =
                    scan_and_open_table(&table_dir, &table_name, meta.segment_size_bytes)?;

                for (id, loc) in locs {
                    let correction_of = loc.correction_of;
                    next_global_id = next_global_id.max(id + 1);
                    index.insert(id, loc, correction_of);
                }

                if let Some(hash) = last_hash {
                    last_hash_per_table.insert(table_name.clone(), hash);
                }

                if let Some(w) = writer {
                    writers.insert(table_name, w);
                }
            }
        }

        // The segment files are authoritative; update the cached ID.
        meta.next_global_id = next_global_id;

        // Reconstruct global Merkle tree in sequential global ID order.
        let mut merkle_tree = MerkleTree::new();
        for id in 0..next_global_id {
            if let Some(loc) = index.get(id) {
                merkle_tree.append(&loc.record_hash);
            }
        }

        // Reconstruct materialized ACL registry from _ink_access records.
        let mut acl = AclRegistry::new();
        let access_ids = index.ids_for_table(SYSTEM_TABLE_ACCESS);
        for id in access_ids {
            if let Some(loc) = index.get(*id) {
                let seg_path = segments_dir
                    .join(SYSTEM_TABLE_ACCESS)
                    .join(format!("seg_{:06}.ink", loc.segment_seq));
                let sealed_path = segments_dir
                    .join(SYSTEM_TABLE_ACCESS)
                    .join(format!("seg_{:06}.sealed", loc.segment_seq));
                let path = if seg_path.exists() {
                    seg_path
                } else {
                    sealed_path
                };
                if let Ok(rec) = read_record_at(&path, loc.byte_offset) {
                    let _ = acl.apply_record(&rec);
                }
            }
        }

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            meta,
            writers,
            index,
            last_hash_per_table,
            merkle_tree,
            acl,
        })
    }

    // Write path

    /// Append a new record to `table` anonymously (unsigned).
    pub fn append(&mut self, table: &str, data: &[u8]) -> Result<Record> {
        self.append_signed(table, data, None)
    }

    /// Append a new record to `table` signed with an optional Ed25519 keypair.
    ///
    /// `data` must be valid UTF-8 JSON (enforced by [`validate_data`]).
    ///
    /// Returns the newly created [`Record`] (including the assigned ID, hash,
    /// and timestamp).
    pub fn append_signed(
        &mut self,
        table: &str,
        data: &[u8],
        keypair: Option<&Keypair>,
    ) -> Result<Record> {
        validate_table_name(table)?;
        validate_data(data)?;

        let id = self.meta.next_global_id;
        let timestamp = now_micros();
        let prev_hash = self
            .last_hash_per_table
            .get(table)
            .copied()
            .unwrap_or([0u8; 32]);
        let flags = 0u8;
        let correction_of: Option<u64> = None;

        let author = keypair
            .map(|kp| kp.public_key())
            .unwrap_or(ANONYMOUS_AUTHOR);

        let record_hash = compute_record_hash(
            id,
            timestamp,
            table,
            &author,
            flags,
            correction_of,
            data,
            &prev_hash,
        );

        let signature = keypair
            .map(|kp| kp.sign(&record_hash))
            .unwrap_or(EMPTY_SIGNATURE);

        let record = Record {
            id,
            timestamp,
            table: table.to_string(),
            author,
            data: data.to_vec(),
            flags,
            correction_of,
            prev_hash,
            record_hash,
            signature,
        };

        // Ensure the table directory exists.
        let table_dir = self.data_dir.join(SEGMENTS_DIR).join(table);
        fs::create_dir_all(&table_dir)?;

        // Rotate the segment if the current one is full.
        self.rotate_if_needed(table, &table_dir)?;

        // Ensure a writer exists for this table.
        if !self.writers.contains_key(table) {
            let writer = create_first_writer(&table_dir, self.meta.segment_size_bytes)?;
            self.writers.insert(table.to_string(), writer);
        }

        let writer = self.writers.get_mut(table).unwrap();
        let byte_offset = writer.append_record(&record)?;
        let seg_seq = writer.sequence();

        // Update the in-memory index.
        self.index.insert(
            id,
            RecordLocation {
                table: table.to_string(),
                segment_seq: seg_seq,
                byte_offset,
                timestamp,
                correction_of: None,
                record_hash,
            },
            None,
        );

        // Advance global Merkle tree.
        self.merkle_tree.append(&record_hash);

        // Advance the per-table chain head.
        self.last_hash_per_table
            .insert(table.to_string(), record_hash);
        // Advance the global ID counter.
        self.meta.next_global_id = id + 1;

        // If this record belongs to the access registry, update materialized ACL.
        if table == SYSTEM_TABLE_ACCESS {
            let _ = self.acl.apply_record(&record);
        }

        // Persist the updated meta (best-effort; can be rebuilt from segments).
        let _ = self.save_meta();

        Ok(record)
    }

    /// Return the next sequential global record ID that will be assigned.
    pub fn next_global_id(&self) -> u64 {
        self.meta.next_global_id
    }

    /// Return the previous record hash for `table`, or 32 zero bytes if the table is empty.
    pub fn last_hash_for_table(&self, table: &str) -> [u8; 32] {
        self.last_hash_per_table
            .get(table)
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Return the Merkle tree head root hash (32 bytes) and total leaf count.
    pub fn tree_head_info(&self) -> (u64, [u8; 32]) {
        (self.merkle_tree.size(), self.merkle_tree.root_hash())
    }

    /// Append a pre-signed record (received over network from remote client) committing to disk.
    ///
    /// Verifies author signature against `record_hash` and ensures chain continuity.
    pub fn append_signed_with_signature(
        &mut self,
        table: &str,
        data: &[u8],
        author: [u8; 32],
        signature: [u8; 64],
        assigned_id: u64,
        assigned_timestamp: i64,
    ) -> Result<Record> {
        validate_table_name(table)?;
        validate_data(data)?;

        if assigned_id != self.meta.next_global_id {
            return Err(InkError::CorruptRecord {
                offset: 0,
                path: table.to_string(),
                reason: format!(
                    "Assigned record ID {} does not match next expected ID {}",
                    assigned_id, self.meta.next_global_id
                ),
            });
        }

        let prev_hash = self.last_hash_for_table(table);
        let flags = 0u8;
        let correction_of: Option<u64> = None;

        let record_hash = compute_record_hash(
            assigned_id,
            assigned_timestamp,
            table,
            &author,
            flags,
            correction_of,
            data,
            &prev_hash,
        );

        crate::crypto::verify_signature(&author, &record_hash, &signature)?;

        let record = Record {
            id: assigned_id,
            timestamp: assigned_timestamp,
            table: table.to_string(),
            author,
            data: data.to_vec(),
            flags,
            correction_of,
            prev_hash,
            record_hash,
            signature,
        };

        // Ensure table directory exists.
        let table_dir = self.data_dir.join(SEGMENTS_DIR).join(table);
        fs::create_dir_all(&table_dir)?;

        self.rotate_if_needed(table, &table_dir)?;

        if !self.writers.contains_key(table) {
            let writer = create_first_writer(&table_dir, self.meta.segment_size_bytes)?;
            self.writers.insert(table.to_string(), writer);
        }

        let writer = self.writers.get_mut(table).unwrap();
        let byte_offset = writer.append_record(&record)?;
        let seg_seq = writer.sequence();

        self.index.insert(
            assigned_id,
            RecordLocation {
                table: table.to_string(),
                segment_seq: seg_seq,
                byte_offset,
                timestamp: assigned_timestamp,
                correction_of: None,
                record_hash,
            },
            None,
        );

        self.merkle_tree.append(&record_hash);
        self.last_hash_per_table
            .insert(table.to_string(), record_hash);
        self.meta.next_global_id = assigned_id + 1;

        if table == SYSTEM_TABLE_ACCESS {
            let _ = self.acl.apply_record(&record);
        }

        let _ = self.save_meta();

        Ok(record)
    }

    /// Append a correction record that logically supersedes an existing record.
    pub fn append_correction(
        &mut self,
        original_id: u64,
        data: &[u8],
        reason: &str,
    ) -> Result<Record> {
        self.append_correction_signed(original_id, data, reason, None)
    }

    /// Append a correction record signed with an optional Ed25519 keypair.
    pub fn append_correction_signed(
        &mut self,
        original_id: u64,
        data: &[u8],
        reason: &str,
        keypair: Option<&Keypair>,
    ) -> Result<Record> {
        // Verify the original record exists.
        let original_loc = self
            .index
            .get(original_id)
            .ok_or(InkError::NotFound(original_id))?
            .clone();
        let table = original_loc.table.clone();

        // Build correction payload: merge reason into the data JSON.
        let mut payload: serde_json::Value =
            serde_json::from_slice(data).map_err(|e| InkError::InvalidJson(e.to_string()))?;
        if let serde_json::Value::Object(ref mut map) = payload {
            map.insert(
                "_ink_reason".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
            map.insert(
                "_ink_corrects".to_string(),
                serde_json::Value::Number(serde_json::Number::from(original_id)),
            );
        }
        let merged =
            serde_json::to_vec(&payload).map_err(|e| InkError::InvalidJson(e.to_string()))?;

        validate_data(&merged)?;

        let id = self.meta.next_global_id;
        let timestamp = now_micros();
        let prev_hash = self
            .last_hash_per_table
            .get(&table)
            .copied()
            .unwrap_or([0u8; 32]);
        let flags = FLAG_IS_CORRECTION;
        let correction_of = Some(original_id);

        let author = keypair
            .map(|kp| kp.public_key())
            .unwrap_or(ANONYMOUS_AUTHOR);

        let record_hash = compute_record_hash(
            id,
            timestamp,
            &table,
            &author,
            flags,
            correction_of,
            &merged,
            &prev_hash,
        );

        let signature = keypair
            .map(|kp| kp.sign(&record_hash))
            .unwrap_or(EMPTY_SIGNATURE);

        let record = Record {
            id,
            timestamp,
            table: table.clone(),
            author,
            data: merged,
            flags,
            correction_of,
            prev_hash,
            record_hash,
            signature,
        };

        let table_dir = self.data_dir.join(SEGMENTS_DIR).join(&table);
        fs::create_dir_all(&table_dir)?;
        self.rotate_if_needed(&table, &table_dir)?;

        if !self.writers.contains_key(&table) {
            let writer = create_first_writer(&table_dir, self.meta.segment_size_bytes)?;
            self.writers.insert(table.clone(), writer);
        }

        let writer = self.writers.get_mut(&table).unwrap();
        let byte_offset = writer.append_record(&record)?;
        let seg_seq = writer.sequence();

        self.index.insert(
            id,
            RecordLocation {
                table: table.clone(),
                segment_seq: seg_seq,
                byte_offset,
                timestamp,
                correction_of,
                record_hash,
            },
            correction_of,
        );

        // Advance global Merkle tree.
        self.merkle_tree.append(&record_hash);

        self.last_hash_per_table.insert(table.clone(), record_hash);
        self.meta.next_global_id = id + 1;

        // If this record belongs to the access registry, update materialized ACL.
        if table == SYSTEM_TABLE_ACCESS {
            let _ = self.acl.apply_record(&record);
        }

        let _ = self.save_meta();

        Ok(record)
    }

    // Access control & authorization

    /// Return a reference to the in-memory materialized ACL registry.
    pub fn acl(&self) -> &AclRegistry {
        &self.acl
    }

    /// Check if a public key is authorized to perform a role action on a table.
    pub fn is_authorized(&self, key: &[u8; 32], role: Role, table: &str) -> bool {
        self.acl.is_authorized(key, role, table, now_micros())
    }

    /// Grant a role on tables to a subject key, signed by an administrator key.
    pub fn grant(
        &mut self,
        admin_key: &Keypair,
        subject_key: [u8; 32],
        label: &str,
        role: Role,
        tables: Vec<String>,
        expires_at: Option<i64>,
    ) -> Result<Record> {
        let admin_pub = admin_key.public_key();
        if !self.acl.is_admin(&admin_pub, now_micros()) {
            return Err(InkError::AccessDenied {
                key: hex::encode(admin_pub),
                action: "GRANT".to_string(),
                table: SYSTEM_TABLE_ACCESS.to_string(),
            });
        }

        let action = AccessAction::Grant {
            subject_key,
            subject_label: label.to_string(),
            role,
            tables,
            expires_at,
            granted_by: admin_pub,
        };
        let payload =
            serde_json::to_vec(&action).map_err(|e| InkError::InvalidJson(e.to_string()))?;
        self.append_signed(SYSTEM_TABLE_ACCESS, &payload, Some(admin_key))
    }

    /// Revoke a role or table access from a subject key, signed by an administrator key.
    pub fn revoke(
        &mut self,
        admin_key: &Keypair,
        subject_key: [u8; 32],
        role: Option<Role>,
        tables: Vec<String>,
        reason: &str,
    ) -> Result<Record> {
        let admin_pub = admin_key.public_key();
        if !self.acl.is_admin(&admin_pub, now_micros()) {
            return Err(InkError::AccessDenied {
                key: hex::encode(admin_pub),
                action: "REVOKE".to_string(),
                table: SYSTEM_TABLE_ACCESS.to_string(),
            });
        }

        let action = AccessAction::Revoke {
            subject_key,
            role,
            tables,
            reason: reason.to_string(),
            revoked_by: admin_pub,
        };
        let payload =
            serde_json::to_vec(&action).map_err(|e| InkError::InvalidJson(e.to_string()))?;
        self.append_signed(SYSTEM_TABLE_ACCESS, &payload, Some(admin_key))
    }

    // Read path

    /// Read a single record by its global ID.
    ///
    /// Returns [`InkError::NotFound`] if the ID does not exist.
    pub fn get_record(&self, id: u64) -> Result<Record> {
        let loc = self.index.get(id).ok_or(InkError::NotFound(id))?;
        let seg_path = self.segment_path(&loc.table, loc.segment_seq, false);
        let sealed_path = self.segment_path(&loc.table, loc.segment_seq, true);

        // Try active first, then sealed.
        let path = if seg_path.exists() {
            seg_path
        } else {
            sealed_path
        };

        read_record_at(&path, loc.byte_offset)
    }

    /// Return all records in `table`, in insertion order (oldest first).
    ///
    /// Pass `limit = Some(n)` to cap the number of returned records.
    ///
    /// Returns [`InkError::TableNotFound`] if the table has no records.
    pub fn get_records_in_table(&self, table: &str, limit: Option<usize>) -> Result<Vec<Record>> {
        let ids = self.index.ids_for_table(table);
        if ids.is_empty() {
            return Err(InkError::TableNotFound(table.to_string()));
        }

        let iter: Box<dyn Iterator<Item = &u64>> = match limit {
            Some(n) => Box::new(ids.iter().take(n)),
            None => Box::new(ids.iter()),
        };

        let mut records = Vec::new();
        for &id in iter {
            records.push(self.get_record(id)?);
        }
        Ok(records)
    }

    /// Return the full history of a record: the original plus all corrections,
    /// in chronological order.
    ///
    /// Returns [`InkError::NotFound`] if `original_id` does not exist.
    pub fn get_history(&self, original_id: u64) -> Result<Vec<Record>> {
        // Verify the original record exists.
        let original = self.get_record(original_id)?;
        let mut history = vec![original];

        // Append corrections in the order they were written.
        for &corr_id in self.index.corrections_of(original_id) {
            history.push(self.get_record(corr_id)?);
        }

        Ok(history)
    }

    /// Generate an exportable Merkle inclusion proof for record #`id`.
    ///
    /// The proof demonstrates that record #`id` is committed into the global
    /// Merkle tree head without requiring the verifier to inspect any other records.
    pub fn get_inclusion_proof(&self, id: u64) -> Result<InclusionProof> {
        let loc = self.index.get(id).ok_or(InkError::NotFound(id))?;
        self.merkle_tree
            .inclusion_proof(id, &loc.record_hash)
            .ok_or_else(|| {
                InkError::ProofError(format!(
                    "failed to generate inclusion proof for record #{id}"
                ))
            })
    }

    /// Generate an exportable Merkle consistency proof between an earlier
    /// tree size `first_size` and the current tree size.
    pub fn get_consistency_proof(&self, first_size: u64) -> Result<ConsistencyProof> {
        self.merkle_tree
            .consistency_proof(first_size)
            .ok_or_else(|| {
                InkError::ProofError(format!(
                    "failed to generate consistency proof from size {first_size}"
                ))
            })
    }

    /// Return the root hash of the global Merkle tree (tree head).
    pub fn tree_head(&self) -> String {
        self.merkle_tree.root_hash_hex()
    }

    /// Return a reference to the global Merkle tree.
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    // Verification

    /// Verify the full integrity of a single table.
    ///
    /// This method re-scans the segment files from scratch (independent of the
    /// in-memory index) and checks:
    ///
    /// 1. CRC32 of every frame.
    /// 2. `record_hash` matches the BLAKE3 recomputed from the record's fields.
    /// 3. The `prev_hash` chain is unbroken across consecutive records.
    ///
    /// Returns [`InkError::TableNotFound`] if the table directory does not exist.
    pub fn verify_table(&self, table: &str) -> Result<VerifyResult> {
        use std::io::Read;

        let table_dir = self.data_dir.join(SEGMENTS_DIR).join(table);
        if !table_dir.exists() {
            return Err(InkError::TableNotFound(table.to_string()));
        }

        let segments = list_table_segments(&table_dir)?;
        if segments.is_empty() {
            return Err(InkError::TableNotFound(table.to_string()));
        }

        let mut errors: Vec<VerifyError> = Vec::new();
        let mut records_checked: u64 = 0;
        let mut is_valid = true;
        let mut prev_record_hash: Option<[u8; 32]> = None;

        'outer: for (_seq, path, _sealed) in &segments {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);

            // Skip the segment header (already validated during open/scan).
            let mut hdr = [0u8; SEGMENT_HEADER_SIZE];
            if reader.read_exact(&mut hdr).is_err() {
                continue; // empty or corrupt segment — skip
            }

            let mut current_offset = SEGMENT_HEADER_SIZE as u64;

            loop {
                let frame_start = current_offset;

                // Read 4-byte frame length.
                let mut len_buf = [0u8; 4];
                match reader.read_exact(&mut len_buf) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(InkError::Io(e)),
                }

                let frame_len = u32::from_le_bytes(len_buf) as usize;

                let max_allowed = crate::segment::FRAME_FIXED_OVERHEAD
                    + MAX_TABLE_NAME_SIZE
                    + MAX_RECORD_DATA_SIZE;
                if !(crate::segment::FRAME_FIXED_OVERHEAD..=max_allowed).contains(&frame_len) {
                    let next_id = self.index.max_id().unwrap_or(0);
                    errors.push(VerifyError {
                        record_id: next_id,
                        kind: VerifyErrorKind::InvalidFrameLength,
                        description: format!(
                            "invalid frame length {frame_len} at offset {frame_start} in '{}'",
                            path.display()
                        ),
                    });
                    is_valid = false;
                    break 'outer;
                }

                // Read rest of frame.
                let mut rest = vec![0u8; frame_len - 4];
                match reader.read_exact(&mut rest) {
                    Ok(()) => {}
                    Err(_) => break, // partial tail — crash recovery remnant
                }

                let mut frame = Vec::with_capacity(frame_len);
                frame.extend_from_slice(&len_buf);
                frame.extend_from_slice(&rest);

                // Check 1: CRC32.
                let stored_crc = u32::from_le_bytes(frame[frame_len - 4..].try_into().unwrap());
                let computed_crc = crc32fast::hash(&frame[..frame_len - 4]);
                if stored_crc != computed_crc {
                    errors.push(VerifyError {
                        record_id: 0, // unknown — CRC prevented parsing
                        kind: VerifyErrorKind::CrcMismatch,
                        description: format!(
                            "CRC mismatch at offset {frame_start} in '{}' \
                             (stored 0x{stored_crc:08X}, computed 0x{computed_crc:08X})",
                            path.display()
                        ),
                    });
                    is_valid = false;
                    break 'outer;
                }

                // Parse the record.
                let record = match parse_verified_frame(&frame, frame_start, path) {
                    Ok(r) => r,
                    Err(e) => {
                        errors.push(VerifyError {
                            record_id: 0,
                            kind: VerifyErrorKind::ParseError,
                            description: format!(
                                "parse error at offset {frame_start} in '{}': {e}",
                                path.display()
                            ),
                        });
                        is_valid = false;
                        break 'outer;
                    }
                };

                // Check 2: record_hash.
                let computed_hash = compute_record_hash(
                    record.id,
                    record.timestamp,
                    &record.table,
                    &record.author,
                    record.flags,
                    record.correction_of,
                    &record.data,
                    &record.prev_hash,
                );
                if computed_hash != record.record_hash {
                    errors.push(VerifyError {
                        record_id: record.id,
                        kind: VerifyErrorKind::HashMismatch,
                        description: format!(
                            "record #{}: stored hash {} does not match recomputed hash {} \
                             (data was modified after the record was written)",
                            record.id,
                            hex::encode(record.record_hash),
                            hex::encode(computed_hash),
                        ),
                    });
                    is_valid = false;
                    break 'outer;
                }

                // Check 3: prev_hash chain.
                if let Some(expected) = prev_record_hash {
                    if record.prev_hash != expected {
                        errors.push(VerifyError {
                            record_id: record.id,
                            kind: VerifyErrorKind::ChainBreak,
                            description: format!(
                                "record #{}: prev_hash {} does not match previous record hash {} \
                                 (record was inserted, removed, or reordered)",
                                record.id,
                                hex::encode(record.prev_hash),
                                hex::encode(expected),
                            ),
                        });
                        is_valid = false;
                        break 'outer;
                    }
                } else if record.prev_hash != [0u8; 32] {
                    // First record in this table must have all-zero prev_hash.
                    errors.push(VerifyError {
                        record_id: record.id,
                        kind: VerifyErrorKind::ChainBreak,
                        description: format!(
                            "first record #{} in table '{}' has non-zero prev_hash {}",
                            record.id,
                            record.table,
                            hex::encode(record.prev_hash),
                        ),
                    });
                    is_valid = false;
                    break 'outer;
                }

                // Check 4: Ed25519 digital signature.
                if let Err(e) =
                    verify_signature(&record.author, &record.record_hash, &record.signature)
                {
                    errors.push(VerifyError {
                        record_id: record.id,
                        kind: VerifyErrorKind::InvalidSignature,
                        description: format!(
                            "record #{}: signature verification failed for author {}: {e}",
                            record.id,
                            hex::encode(record.author)
                        ),
                    });
                    is_valid = false;
                    break 'outer;
                }

                prev_record_hash = Some(record.record_hash);
                records_checked += 1;
                current_offset = frame_start + frame_len as u64;
            }
        }

        Ok(VerifyResult {
            tables_checked: vec![table.to_string()],
            records_checked,
            is_valid,
            errors,
        })
    }

    /// Verify the full integrity of all tables in the database.
    ///
    /// Calls [`verify_table`] for each table and aggregates the results.
    pub fn verify_all(&self) -> Result<VerifyResult> {
        let tables = self.index.tables();
        if tables.is_empty() {
            return Ok(VerifyResult {
                tables_checked: vec![],
                records_checked: 0,
                is_valid: true, // True?
                errors: vec![],
            });
        }

        let mut all_errors = Vec::new();
        let mut total_records = 0u64;
        let mut overall_valid = true;

        for table in &tables {
            match self.verify_table(table) {
                Ok(result) => {
                    total_records += result.records_checked;
                    if !result.is_valid {
                        overall_valid = false;
                    }
                    all_errors.extend(result.errors);
                }
                Err(e) => {
                    overall_valid = false;
                    all_errors.push(VerifyError {
                        record_id: 0,
                        kind: VerifyErrorKind::ParseError,
                        description: format!("error verifying table '{table}': {e}"),
                    });
                }
            }
        }

        // Verify that the global Merkle tree matches the records on disk.
        let mut expected_tree = MerkleTree::new();
        for id in 0..self.meta.next_global_id {
            if let Some(loc) = self.index.get(id) {
                expected_tree.append(&loc.record_hash);
            }
        }
        if expected_tree.root_hash() != self.merkle_tree.root_hash() {
            overall_valid = false;
            all_errors.push(VerifyError {
                record_id: 0,
                kind: VerifyErrorKind::MerkleMismatch,
                description: format!(
                    "Merkle tree head mismatch: store has {}, recomputed from records has {}",
                    self.merkle_tree.root_hash_hex(),
                    expected_tree.root_hash_hex()
                ),
            });
        }

        Ok(VerifyResult {
            tables_checked: tables,
            records_checked: total_records,
            is_valid: overall_valid,
            errors: all_errors,
        })
    }

    // Metadata / status

    /// Return the names of all tables that have at least one record.
    pub fn tables(&self) -> Vec<String> {
        self.index.tables()
    }

    /// Return a snapshot of the database's current state.
    pub fn status(&self) -> StoreStatus {
        let last_hash_per_table: HashMap<String, String> = self
            .last_hash_per_table
            .iter()
            .map(|(k, v)| (k.clone(), hex::encode(v)))
            .collect();

        StoreStatus {
            record_count: self.index.record_count(),
            table_count: self.index.table_count(),
            last_record_id: self.index.max_id(),
            last_hash_per_table,
            tree_head: self.merkle_tree.root_hash_hex(),
            database_id: self.meta.database_id.clone(),
            format_version: self.meta.format_version,
        }
    }

    /// Return the unique database identifier UUID.
    pub fn database_id(&self) -> &str {
        &self.meta.database_id
    }

    // Private helpers

    /// Rotate the active segment for `table` if it is full.
    fn rotate_if_needed(&mut self, table: &str, table_dir: &Path) -> Result<()> {
        if let Some(writer) = self.writers.get(table) {
            if !writer.is_full() {
                return Ok(());
            }
        } else {
            return Ok(()); // no writer yet — nothing to rotate
        }

        // Take the writer out, seal it, create a new one.
        let old_writer = self.writers.remove(table).unwrap();
        let new_seq = old_writer.sequence() + 1;
        old_writer.seal()?;

        let new_path = table_dir.join(format!("seg_{:06}.ink", new_seq));
        let new_writer = SegmentWriter::create(new_path, new_seq, self.meta.segment_size_bytes)?;
        self.writers.insert(table.to_string(), new_writer);
        Ok(())
    }

    /// Construct the path to a segment file.
    fn segment_path(&self, table: &str, sequence: u32, sealed: bool) -> PathBuf {
        let ext = if sealed { "sealed" } else { "ink" };
        self.data_dir
            .join(SEGMENTS_DIR)
            .join(table)
            .join(format!("seg_{:06}.{}", sequence, ext))
    }

    /// Persist `ink.meta` to disk.
    fn save_meta(&self) -> Result<()> {
        let path = self.data_dir.join(META_FILENAME);
        let json = serde_json::to_vec_pretty(&self.meta)
            .map_err(|e| InkError::InvalidMeta(e.to_string()))?;
        let tmp = self.data_dir.join("ink.meta.tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        // On Windows, fs::rename fails if destination already exists.
        // On Linux it doesn't happen (??)
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

// Module-private helpers

type TableScanResult = (
    Vec<(u64, RecordLocation)>,
    Option<[u8; 32]>,
    Option<SegmentWriter>,
);

/// Scan all segments in a table directory and open an active writer.
///
/// Returns:
/// - A list of `(record_id, RecordLocation)` pairs for every valid record.
/// - The BLAKE3 hash of the last (highest-ID) record in this table.
/// - An optional [`SegmentWriter`] for the active segment (if one exists).
fn scan_and_open_table(
    table_dir: &Path,
    table_name: &str,
    max_seg_size: u64,
) -> Result<TableScanResult> {
    let segments = list_table_segments(table_dir)?;

    let mut all_records: Vec<(u64, RecordLocation)> = Vec::new();
    let mut last_hash: Option<[u8; 32]> = None;
    let mut active_writer: Option<SegmentWriter> = None;

    for (seq, path, is_sealed) in &segments {
        let scan = scan_segment(path)?;

        // Handle crash recovery: truncate the tail if needed.
        if let Some(trunc) = scan.truncate_at {
            if *is_sealed {
                // Sealed segments shouldn't need truncation.  Log a warning
                // but proceed — the hash-chain check in verify() will catch
                // any actual tampering.
                eprintln!(
                    "ink: WARNING: sealed segment '{}' has a corrupt tail at offset {}; \
                     truncating for recovery",
                    path.display(),
                    trunc
                );
            }
            // Open in read-write mode for truncation, then close.
            {
                let f = OpenOptions::new().write(true).open(path)?;
                f.set_len(trunc)?;
                f.sync_all()?;
            }
        }

        // Collect valid records into the index.
        for (byte_offset, record) in scan.records {
            last_hash = Some(record.record_hash);
            all_records.push((
                record.id,
                RecordLocation {
                    table: table_name.to_string(),
                    segment_seq: *seq,
                    byte_offset,
                    timestamp: record.timestamp,
                    correction_of: record.correction_of,
                    record_hash: record.record_hash,
                },
            ));
        }

        // Open a writer for the active (non-sealed) segment.
        if !is_sealed {
            let writer = SegmentWriter::open(path.clone(), *seq, max_seg_size)?;
            active_writer = Some(writer);
        }
    }

    Ok((all_records, last_hash, active_writer))
}

/// Create the first segment writer for a table that has no existing segments.
fn create_first_writer(table_dir: &Path, max_seg_size: u64) -> Result<SegmentWriter> {
    let path = table_dir.join("seg_000000.ink");
    SegmentWriter::create(path, 0, max_seg_size)
}

/// Parse a record from an already CRC-verified frame buffer.
///
/// This is an alias into the segment module's private parser, exposed here
/// because the verify path in this module needs it.
fn parse_verified_frame(_frame: &[u8], file_offset: u64, path: &Path) -> Result<Record> {
    // Re-use the segment module's parser by calling read_record_at on a
    // cursor.  We build a minimal in-memory "file" that contains just this
    // frame, pre-seek-ed to the right position.
    //
    // We can't call parse_record_from_frame directly (it's private to the
    // segment module), so we route through read_record_at which re-reads the
    // frame from disk.  For verify() this is acceptable since we don't cache
    // anything else.
    //
    // TODO (Phase 3): expose parse_record_from_frame publicly to avoid the
    // extra disk seek.
    read_record_at(path, file_offset)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_store() -> (Store, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = Store::init(dir.path()).unwrap();
        (store, dir)
    }

    #[test]
    fn init_creates_meta_file() {
        let dir = tempdir().unwrap();
        let _store = Store::init(dir.path()).unwrap();
        assert!(dir.path().join("ink.meta").exists());
        assert!(dir.path().join("segments").is_dir());
    }

    #[test]
    fn init_twice_returns_error() {
        let dir = tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        assert!(matches!(
            Store::init(dir.path()),
            Err(InkError::AlreadyInitialized(_))
        ));
    }

    #[test]
    fn open_missing_dir_returns_error() {
        assert!(matches!(
            Store::open(Path::new("/nonexistent/path/xyz")),
            Err(InkError::NotADatabase(_))
        ));
    }

    #[test]
    fn append_and_read_back() {
        let (mut store, _dir) = fresh_store();

        let data = b"{\"customer\":\"Alice\",\"amount\":1500}";
        let record = store.append("sales", data).unwrap();

        assert_eq!(record.id, 0);
        assert_eq!(record.table, "sales");
        assert_eq!(record.data, data);
        assert_eq!(record.prev_hash, [0u8; 32]); // first record

        let fetched = store.get_record(0).unwrap();
        assert_eq!(fetched.id, 0);
        assert_eq!(fetched.data, data);
    }

    #[test]
    fn id_is_monotonic_across_tables() {
        let (mut store, _dir) = fresh_store();

        let r0 = store.append("sales", b"{\"n\":0}").unwrap();
        let r1 = store.append("logs", b"{\"n\":1}").unwrap();
        let r2 = store.append("sales", b"{\"n\":2}").unwrap();

        assert_eq!(r0.id, 0);
        assert_eq!(r1.id, 1);
        assert_eq!(r2.id, 2);
    }

    #[test]
    fn hash_chain_links_records_within_table() {
        let (mut store, _dir) = fresh_store();

        let r0 = store.append("sales", b"{\"n\":0}").unwrap();
        let r1 = store.append("sales", b"{\"n\":1}").unwrap();
        let r2 = store.append("sales", b"{\"n\":2}").unwrap();

        assert_eq!(r0.prev_hash, [0u8; 32]); // genesis
        assert_eq!(r1.prev_hash, r0.record_hash);
        assert_eq!(r2.prev_hash, r1.record_hash);
    }

    #[test]
    fn hash_chain_is_per_table() {
        let (mut store, _dir) = fresh_store();

        let s0 = store.append("sales", b"{\"n\":0}").unwrap();
        let _l0 = store.append("logs", b"{\"n\":0}").unwrap(); // different table
        let s1 = store.append("sales", b"{\"n\":1}").unwrap();

        // sales chain: s0 → s1 (logs record is not in the chain)
        assert_eq!(s0.prev_hash, [0u8; 32]);
        assert_eq!(s1.prev_hash, s0.record_hash);
    }

    #[test]
    fn get_records_in_table() {
        let (mut store, _dir) = fresh_store();

        for i in 0..5u64 {
            store
                .append("sales", format!("{{\"n\":{i}}}").as_bytes())
                .unwrap();
        }

        let records = store.get_records_in_table("sales", None).unwrap();
        assert_eq!(records.len(), 5);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.id, i as u64);
        }
    }

    #[test]
    fn get_records_with_limit() {
        let (mut store, _dir) = fresh_store();
        for i in 0..10u64 {
            store
                .append("t", format!("{{\"n\":{i}}}").as_bytes())
                .unwrap();
        }
        let records = store.get_records_in_table("t", Some(3)).unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn get_missing_table_returns_error() {
        let (store, _dir) = fresh_store();
        assert!(matches!(
            store.get_records_in_table("missing", None),
            Err(InkError::TableNotFound(_))
        ));
    }

    #[test]
    fn verify_clean_database() {
        let (mut store, _dir) = fresh_store();
        for i in 0..5u64 {
            store
                .append("sales", format!("{{\"n\":{i}}}").as_bytes())
                .unwrap();
        }
        let result = store.verify_table("sales").unwrap();
        assert!(result.is_valid);
        assert_eq!(result.records_checked, 5);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn verify_all_clean() {
        let (mut store, _dir) = fresh_store();
        store.append("sales", b"{\"n\":1}").unwrap();
        store.append("logs", b"{\"n\":1}").unwrap();

        let result = store.verify_all().unwrap();
        assert!(result.is_valid);
        assert_eq!(result.records_checked, 2);
    }

    #[test]
    fn persist_and_reopen() {
        let dir = tempdir().unwrap();

        // Write records, then drop the store.
        {
            let mut store = Store::init(dir.path()).unwrap();
            store.append("sales", b"{\"amount\":100}").unwrap();
            store.append("sales", b"{\"amount\":200}").unwrap();
        }

        // Reopen and verify the records are still there.
        let store = Store::open(dir.path()).unwrap();
        let records = store.get_records_in_table("sales", None).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, 0);
        assert_eq!(records[1].id, 1);
        assert_eq!(records[1].prev_hash, records[0].record_hash);
    }

    #[test]
    fn correction_links_to_original() {
        let (mut store, _dir) = fresh_store();

        let orig = store.append("sales", b"{\"amount\":100}").unwrap();
        let corr = store
            .append_correction(orig.id, b"{\"amount\":120}", "typo in amount")
            .unwrap();

        assert!(corr.is_correction());
        assert_eq!(corr.correction_of, Some(orig.id));

        let history = store.get_history(orig.id).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, orig.id);
        assert_eq!(history[1].id, corr.id);
    }

    #[test]
    fn tables_list() {
        let (mut store, _dir) = fresh_store();
        store.append("zzz", b"{}").unwrap();
        store.append("aaa", b"{}").unwrap();
        store.append("mmm", b"{}").unwrap();

        let tables = store.tables();
        assert_eq!(tables, vec!["aaa", "mmm", "zzz"]);
    }

    #[test]
    fn status_counts() {
        let (mut store, _dir) = fresh_store();
        store.append("a", b"{}").unwrap();
        store.append("b", b"{}").unwrap();
        store.append("a", b"{}").unwrap();

        let st = store.status();
        assert_eq!(st.record_count, 3);
        assert_eq!(st.table_count, 2);
        assert_eq!(st.last_record_id, Some(2));
    }

    #[test]
    fn append_signed_record_and_verify() {
        let (mut store, _dir) = fresh_store();
        let kp = Keypair::generate();

        let r = store
            .append_signed("sales", b"{\"amount\":500}", Some(&kp))
            .unwrap();

        assert_eq!(r.author, kp.public_key());
        assert_ne!(r.signature, EMPTY_SIGNATURE);

        let v = store.verify_table("sales").unwrap();
        assert!(v.is_valid);
    }

    #[test]
    fn inclusion_proof_generation_and_verification() {
        let (mut store, _dir) = fresh_store();
        for i in 0..5 {
            store
                .append("sales", format!("{{\"val\":{i}}}").as_bytes())
                .unwrap();
        }

        for id in 0..5 {
            let proof = store.get_inclusion_proof(id).unwrap();
            assert_eq!(proof.leaf_index, id);
            assert_eq!(proof.tree_size, 5);
            assert!(crate::merkle::verify_inclusion(&proof));
        }
    }

    #[test]
    fn consistency_proof_generation_and_verification() {
        let (mut store, _dir) = fresh_store();
        for i in 0..3 {
            store
                .append("sales", format!("{{\"val\":{i}}}").as_bytes())
                .unwrap();
        }
        let proof = store.get_consistency_proof(2).unwrap();
        assert_eq!(proof.first_size, 2);
        assert_eq!(proof.second_size, 3);
        assert!(crate::merkle::verify_consistency(&proof));
    }

    #[test]
    fn store_init_with_admin_and_acl_reopen() {
        let dir = tempdir().unwrap();
        let (mut store, admin_kp) = Store::init_with_admin(dir.path(), None).unwrap();

        assert!(store.acl().is_admin(&admin_kp.public_key(), now_micros()));

        let alice_kp = Keypair::generate();
        let alice_pub = alice_kp.public_key();

        // Grant Alice writer role on "sales"
        store
            .grant(
                &admin_kp,
                alice_pub,
                "alice",
                Role::Writer,
                vec!["sales".to_string()],
                None,
            )
            .unwrap();

        assert!(store.is_authorized(&alice_pub, Role::Writer, "sales"));
        assert!(!store.is_authorized(&alice_pub, Role::Writer, "invoices"));

        // Non-admin cannot grant
        let bob_kp = Keypair::generate();
        let grant_err = store.grant(
            &alice_kp,
            bob_kp.public_key(),
            "bob",
            Role::Writer,
            vec!["sales".to_string()],
            None,
        );
        assert!(grant_err.is_err());

        // Reopen store from disk and verify ACL was rebuilt from _ink_access
        let store2 = Store::open(dir.path()).unwrap();
        assert!(store2.is_authorized(&alice_pub, Role::Writer, "sales"));
        assert!(store2.acl().is_admin(&admin_kp.public_key(), now_micros()));

        // Verification of _ink_access passes
        let v = store2.verify_table(SYSTEM_TABLE_ACCESS).unwrap();
        assert!(v.is_valid);
        assert_eq!(v.records_checked, 2); // Record 0 (genesis) + Record 1 (grant alice)
    }

    #[test]
    fn store_revoke_updates_acl() {
        let dir = tempdir().unwrap();
        let (mut store, admin_kp) = Store::init_with_admin(dir.path(), None).unwrap();
        let alice_kp = Keypair::generate();
        let alice_pub = alice_kp.public_key();

        store
            .grant(
                &admin_kp,
                alice_pub,
                "alice",
                Role::Writer,
                vec!["sales".to_string()],
                None,
            )
            .unwrap();
        assert!(store.is_authorized(&alice_pub, Role::Writer, "sales"));

        // Revoke
        store
            .revoke(
                &admin_kp,
                alice_pub,
                Some(Role::Writer),
                vec!["sales".to_string()],
                "transfer",
            )
            .unwrap();
        assert!(!store.is_authorized(&alice_pub, Role::Writer, "sales"));

        // Reopen and ensure revocation persisted
        let store2 = Store::open(dir.path()).unwrap();
        assert!(!store2.is_authorized(&alice_pub, Role::Writer, "sales"));
    }
}
