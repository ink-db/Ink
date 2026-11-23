//! Backend abstraction layer for Ink Browser.
//!
//! Provides the [`Backend`] trait which decouples the desktop GUI from the underlying
//! engine, allowing both [`local::LocalBackend`] (direct storage access) and
//! remote network access (`RemoteBackend`) to present an identical API.

pub mod local;

use crate::error::BackendError;
use ink_core::auth::Role;
use ink_query::QueryResult;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::path::PathBuf;

mod hex_bytes64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "Expected 64 bytes hex, found {} bytes",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// Connection mode descriptor for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionMode {
    /// Direct local filesystem access.
    Local {
        /// Absolute directory path.
        path: PathBuf,
    },
    /// TCP / TLS client connection.
    Server {
        /// Remote hostname or IP address.
        host: String,
        /// TCP port.
        port: u16,
        /// Whether TLS 1.3 is active.
        tls: bool,
    },
}

impl fmt::Display for ConnectionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionMode::Local { path } => write!(f, "Local ({})", path.display()),
            ConnectionMode::Server { host, port, tls } => {
                let scheme = if *tls { "inks" } else { "ink" };
                write!(f, "Server ({}://{}:{})", scheme, host, port)
            }
        }
    }
}

/// Metadata describing an active user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Connection mode (local directory or remote server).
    pub mode: ConnectionMode,
    /// Client Ed25519 public key.
    pub public_key: [u8; 32],
    /// Hex-encoded client public key.
    pub public_key_hex: String,
    /// Database identifier.
    pub database_id: String,
    /// Granted roles in this database.
    pub roles: Vec<Role>,
    /// Authorized table scopes.
    pub table_scopes: Vec<String>,
    /// Network latency in milliseconds (None for local mode).
    pub latency_ms: Option<u64>,
    /// Current Merkle tree size.
    pub tree_size: u64,
    /// Current Merkle root hash.
    pub tree_head: [u8; 32],
}

impl SessionInfo {
    /// Check whether the current session holds administrator privileges.
    pub fn is_admin(&self) -> bool {
        self.roles.contains(&Role::Admin)
    }

    /// Check whether the current session can view system tables like `_ink_access`.
    pub fn can_view_access(&self) -> bool {
        self.roles.contains(&Role::Admin) || self.roles.contains(&Role::Auditor)
    }

    /// Check whether the current session can write to a specified table.
    pub fn can_write(&self, table: &str) -> bool {
        if self.is_admin() {
            return true;
        }
        if !self.roles.contains(&Role::Writer) {
            return false;
        }
        self.table_scopes.iter().any(|t| t == "*" || t == table)
    }
}

/// Information about a table and its size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableInfo {
    /// Name of the table.
    pub name: String,
    /// Total number of records in this table.
    pub record_count: u64,
}

/// Detailed representation of a committed record for UI display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordDetail {
    /// Global monotonically increasing sequence ID.
    pub id: u64,
    /// Microseconds UTC timestamp.
    pub timestamp: i64,
    /// Table name.
    pub table: String,
    /// Ed25519 author public key.
    pub author: [u8; 32],
    /// Short author hex for concise rendering.
    pub author_hex: String,
    /// Optional human-readable subject label from `_ink_access`.
    pub author_label: Option<String>,
    /// Record header flags.
    pub flags: u8,
    /// True if this record corrects a previous record.
    pub is_correction: bool,
    /// Original record ID if this is a correction.
    pub correction_of: Option<u64>,
    /// Previous record hash within this table.
    pub prev_hash: [u8; 32],
    /// Canonical BLAKE3 record hash.
    pub record_hash: [u8; 32],
    /// Ed25519 digital signature.
    #[serde(with = "hex_bytes64")]
    pub signature: [u8; 64],
    /// Raw payload string.
    pub data_json: String,
    /// Parsed JSON value for column projection.
    pub parsed_data: serde_json::Value,
}

/// Paginated result set for grid browsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResult {
    /// Target table name.
    pub table: String,
    /// Total records matching the filter in this table.
    pub total_records: u64,
    /// Starting offset.
    pub offset: usize,
    /// Maximum rows requested.
    pub limit: usize,
    /// Unified dynamic columns detected across this page.
    pub dynamic_columns: Vec<String>,
    /// Records on this page.
    pub records: Vec<RecordDetail>,
}

/// Summary returned upon successful record commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSummary {
    /// Monotonic record ID.
    pub id: u64,
    /// Canonical record hash.
    pub hash: [u8; 32],
    /// Commit timestamp in microseconds UTC.
    pub timestamp: i64,
}

/// Summary of latest tree head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeHeadInfo {
    /// Total record count covered by this root.
    pub tree_size: u64,
    /// BLAKE3 Merkle root hash.
    pub root_hash: [u8; 32],
}

/// Node data for the global Merkle tree visualizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNodeInfo {
    /// BLAKE3 hash represented by this node.
    pub hash: [u8; 32],
    /// Index of the left child in the same returned vector.
    pub left: Option<usize>,
    /// Index of the right child in the same returned vector.
    pub right: Option<usize>,
    /// Global record ID for leaf nodes.
    pub leaf_index: Option<u64>,
}

/// Inclusion proof information for a single record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofInfo {
    /// Target record ID.
    pub record_id: u64,
    /// Tree size at proof generation.
    pub tree_size: u64,
    /// Merkle root committed by this proof.
    pub root_hash: [u8; 32],
    /// Audit path sibling hashes.
    pub audit_path: Vec<[u8; 32]>,
}

/// Consistency proof between two tree snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProofInfo {
    /// First tree size.
    pub first: u64,
    /// Second tree size.
    pub second: u64,
    /// Consistency path sibling hashes.
    pub consistency_path: Vec<[u8; 32]>,
}

/// Summary of a cryptographic verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySummary {
    /// True if all chains, signatures, and roots matched perfectly.
    pub is_valid: bool,
    /// Number of records cryptographically verified.
    pub records_checked: u64,
    /// List of error descriptions if tampering was detected.
    pub errors: Vec<String>,
    /// First record ID where corruption or chain break occurred.
    pub broken_record_id: Option<u64>,
}

/// Active access grant summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessGrantInfo {
    /// Subject public key.
    pub subject_key: [u8; 32],
    /// Human-readable label (e.g. "alice").
    pub subject_label: String,
    /// Granted role.
    pub role: Role,
    /// Covered tables.
    pub tables: Vec<String>,
    /// Microseconds UTC expiration timestamp, if any.
    pub expires_at: Option<i64>,
    /// Administrator that issued the grant.
    pub granted_by: [u8; 32],
    /// Record ID in `_ink_access`.
    pub record_id: u64,
    /// True if expired relative to current clock.
    pub is_expired: bool,
}

/// High-level cluster and database status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    /// Total committed records.
    pub record_count: u64,
    /// Total tables.
    pub table_count: usize,
    /// Current hex tree head.
    pub tree_head: String,
    /// Connected replication peers.
    pub peers: Vec<String>,
    /// Replication quorum setting.
    pub quorum: usize,
}

/// Abstraction trait for all database operations in Ink Browser.
///
/// Decouples the UI views from storage engines or network protocols.
pub trait Backend: Send + Sync {
    /// Execute an arbitrary IQL statement string through the authorization gatekeeper.
    fn execute_iql(&self, query: &str) -> Result<QueryResult, BackendError>;

    /// List all visible tables with record counts.
    fn list_tables(&self) -> Result<Vec<TableInfo>, BackendError>;

    /// Fetch a paginated slice of records with optional filter and sort.
    fn read_page(
        &self,
        table: &str,
        filter: Option<&str>,
        order: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PageResult, BackendError>;

    /// Fetch a single record by its global sequence ID.
    fn get_record(&self, id: u64) -> Result<RecordDetail, BackendError>;

    /// Fetch the full version history (original + all corrections) for a record.
    fn get_history(&self, id: u64) -> Result<Vec<RecordDetail>, BackendError>;

    /// Append a new record (requires Writer role on table).
    fn append_record(
        &self,
        table: &str,
        data: serde_json::Value,
    ) -> Result<RecordSummary, BackendError>;

    /// Append a cryptographically sealed correction for an existing record.
    fn correct_record(
        &self,
        orig_id: u64,
        data: serde_json::Value,
        reason: &str,
    ) -> Result<RecordSummary, BackendError>;

    /// Run full cryptographic verification across one or all tables.
    fn verify(&self, target_table: Option<&str>) -> Result<VerifySummary, BackendError>;

    /// Retrieve the current Merkle tree head.
    fn get_tree_head(&self) -> Result<TreeHeadInfo, BackendError>;

    /// Retrieve the global Merkle tree nodes for an authorized full-tree reader.
    fn get_merkle_nodes(&self) -> Result<Vec<MerkleNodeInfo>, BackendError>;

    /// Generate an inclusion proof for a specific record ID.
    fn get_inclusion_proof(&self, record_id: u64) -> Result<InclusionProofInfo, BackendError>;

    /// Generate a consistency proof between two historical tree sizes.
    fn get_consistency_proof(
        &self,
        first: u64,
        second: u64,
    ) -> Result<ConsistencyProofInfo, BackendError>;

    /// Fetch high-level cluster and database status.
    fn get_status(&self) -> Result<ClusterStatus, BackendError>;

    /// List active role grants from `_ink_access` (Admin and Auditor only).
    fn list_access(&self) -> Result<Vec<AccessGrantInfo>, BackendError>;

    /// Issue a new grant transaction (Admin only).
    fn grant(
        &self,
        subject_key: [u8; 32],
        label: &str,
        role: Role,
        tables: Vec<String>,
        expires_at: Option<i64>,
    ) -> Result<RecordSummary, BackendError>;

    /// Issue a revocation transaction (Admin only).
    fn revoke(
        &self,
        subject_key: [u8; 32],
        role: Option<Role>,
        tables: Vec<String>,
        reason: &str,
    ) -> Result<RecordSummary, BackendError>;

    /// Session metadata (roles, public key, database ID, mode).
    fn session_info(&self) -> &SessionInfo;

    /// Disconnect and cleanly release all locks and resources.
    fn close(&mut self);
}
