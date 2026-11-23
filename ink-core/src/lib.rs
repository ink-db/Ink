//! # ink-core
//!
//! Core storage engine, cryptographic hash chain, indexing, and verification for Ink.
//!
//! Ink is an append-only, tamper-evident database where every record is cryptographically
//! sealed, and any attempt to alter or remove data is mathematically detectable.
//!
//! ## Modules
//!
//! - [`error`]: Error types and result definitions.
//! - [`auth`]: Authentication, authorization, and the `_ink_access` registry.
//! - [`record`]: Record structure, hashing, and validation.
//! - [`segment`]: Append-only segment file reader and writer.
//! - [`index`]: In-memory indexing rebuildable from segment logs.
//! - [`crypto`]: Ed25519 digital signatures and key management.
//! - [`merkle`]: RFC 6962 append-only Merkle tree, inclusion proofs, consistency proofs.
//! - [`store`]: High-level `Store` interface for database operations.

pub mod auth;
pub mod crypto;
pub mod error;
pub mod index;
pub mod merkle;
pub mod record;
pub mod segment;
pub mod store;

pub use crypto::{verify_signature, Keypair, ANONYMOUS_AUTHOR, EMPTY_SIGNATURE};
pub use error::{InkError, Result};
pub use index::{InkIndex, RecordLocation};
pub use merkle::{
    hash_children, hash_leaf, verify_consistency, verify_inclusion, ConsistencyProof,
    InclusionProof, MerkleTree,
};
pub use record::{
    compute_record_hash, validate_data, validate_table_name, Record, FLAG_IS_CORRECTION,
    MAX_RECORD_DATA_SIZE, MAX_TABLE_NAME_SIZE, NOT_A_CORRECTION,
};
pub use segment::{list_table_segments, scan_segment, ScanResult, SegmentWriter};
pub use store::{Store, StoreStatus, VerifyError, VerifyErrorKind, VerifyResult};
