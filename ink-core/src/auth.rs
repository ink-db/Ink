//! Authentication, authorization registry, and access control for Ink.
//!
//! Access rules, role definitions, and key revocations are stored as append-only
//! records in the reserved system table [`SYSTEM_TABLE_ACCESS`] (`"_ink_access"`).
//!
//! An in-memory [`AclRegistry`] materializes active grants from the log and serves
//! as the authoritative gatekeeper for statement execution.

use crate::error::{InkError, Result};
use crate::record::Record;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Reserved table name for the immutable access control registry.
pub const SYSTEM_TABLE_ACCESS: &str = "_ink_access";

/// Canonical roles in the Ink security model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Administrative role: may issue GRANT, REVOKE, ROTATE_KEY, and manage access.
    Admin,
    /// Writer role: may execute APPEND and CORRECT on authorized tables.
    Writer,
    /// Reader role: may execute READ, HISTORY, VERIFY, and export Merkle proofs.
    Reader,
    /// Auditor role: global read-only visibility across ALL tables including `_ink_access`.
    Auditor,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Writer => write!(f, "writer"),
            Role::Reader => write!(f, "reader"),
            Role::Auditor => write!(f, "auditor"),
        }
    }
}

impl FromStr for Role {
    type Err = InkError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "writer" => Ok(Role::Writer),
            "reader" => Ok(Role::Reader),
            "auditor" => Ok(Role::Auditor),
            other => Err(InkError::InvalidAccessRecord(format!(
                "Unknown role '{}', expected one of: admin, writer, reader, auditor",
                other
            ))),
        }
    }
}

/// Action record payload stored in `_ink_access`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "UPPERCASE")]
pub enum AccessAction {
    /// Grant permissions to a public key.
    Grant {
        /// The subject Ed25519 public key.
        #[serde(with = "hex_bytes32")]
        subject_key: [u8; 32],
        /// Human-readable label for auditing (e.g. "alice_finance").
        subject_label: String,
        /// The assigned role.
        role: Role,
        /// Scoped table names, or `["*"]` for global access.
        tables: Vec<String>,
        /// Microseconds UTC expiration timestamp, or `None` if non-expiring.
        expires_at: Option<i64>,
        /// Public key of the granting administrator.
        #[serde(with = "hex_bytes32")]
        granted_by: [u8; 32],
    },
    /// Revoke permissions from a public key.
    Revoke {
        /// The subject Ed25519 public key.
        #[serde(with = "hex_bytes32")]
        subject_key: [u8; 32],
        /// The specific role to revoke, or `None` to revoke all roles.
        role: Option<Role>,
        /// The specific tables to revoke, or `["*"]` for all tables.
        tables: Vec<String>,
        /// Human-readable justification permanently logged in the audit trail.
        reason: String,
        /// Public key of the revoking administrator.
        #[serde(with = "hex_bytes32")]
        revoked_by: [u8; 32],
    },
    /// Rotate an authorized keypair.
    RotateKey {
        /// Old public key being retired.
        #[serde(with = "hex_bytes32")]
        old_key: [u8; 32],
        /// New public key replacing the old key.
        #[serde(with = "hex_bytes32")]
        new_key: [u8; 32],
        /// Signature by `old_key` over `BLAKE3("INK-ROTATE" || new_key)`.
        #[serde(with = "hex_bytes64")]
        signed_by_old: [u8; 64],
        /// Public key of the approving administrator.
        #[serde(with = "hex_bytes32")]
        approved_by_admin: [u8; 32],
    },
    /// Periodic operational audit summary.
    AuditSummary {
        /// Microseconds UTC start of the audit window.
        period_start: i64,
        /// Microseconds UTC end of the audit window.
        period_end: i64,
        /// Number of successful handshakes.
        successful_logins: u64,
        /// Number of failed authentication attempts.
        failed_handshakes: u64,
        /// Number of rate-limited source IPs.
        rate_limited_ips: u64,
        /// Highest concurrent active session count.
        active_sessions_highwater: u64,
        /// Public key of the recording node.
        #[serde(with = "hex_bytes32")]
        signed_by_server: [u8; 32],
    },
}

/// An active grant entry in the materialized ACL registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleGrant {
    /// The granted role.
    pub role: Role,
    /// List of tables this role applies to (or `["*"]`).
    pub tables: Vec<String>,
    /// Expiration timestamp in microseconds UTC, if any.
    pub expires_at: Option<i64>,
    /// When this grant was committed.
    pub granted_at: i64,
    /// Administrator public key that authorized the grant.
    pub granted_by: [u8; 32],
    /// Record ID in `_ink_access` that created this grant.
    pub record_id: u64,
}

impl RoleGrant {
    /// Check whether this grant covers the requested table.
    pub fn covers_table(&self, target_table: &str) -> bool {
        self.tables.iter().any(|t| t == "*" || t == target_table)
    }

    /// Check whether this grant has expired at the specified timestamp.
    pub fn is_expired(&self, now_micros: i64) -> bool {
        match self.expires_at {
            Some(exp) => now_micros > exp,
            None => false,
        }
    }
}

/// In-memory materialized projection of `_ink_access` records.
#[derive(Debug, Clone, Default)]
pub struct AclRegistry {
    /// Map from subject public key to list of active role grants.
    grants: HashMap<[u8; 32], Vec<RoleGrant>>,
}

impl AclRegistry {
    /// Create a new, empty ACL registry.
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
        }
    }

    /// Apply a raw record from the `_ink_access` table into the materialized index.
    pub fn apply_record(&mut self, record: &Record) -> Result<()> {
        if record.table != SYSTEM_TABLE_ACCESS {
            return Err(InkError::InvalidAccessRecord(format!(
                "Cannot apply record from table '{}' to ACL registry",
                record.table
            )));
        }

        let action: AccessAction = serde_json::from_slice(&record.data).map_err(|e| {
            InkError::InvalidAccessRecord(format!(
                "Failed to deserialize AccessAction from record #{}: {}",
                record.id, e
            ))
        })?;

        match action {
            AccessAction::Grant {
                subject_key,
                role,
                tables,
                expires_at,
                granted_by,
                ..
            } => {
                let user_grants = self.grants.entry(subject_key).or_default();
                // Replace or append grant
                user_grants.retain(|g| !(g.role == role && g.tables == tables));
                user_grants.push(RoleGrant {
                    role,
                    tables,
                    expires_at,
                    granted_at: record.timestamp,
                    granted_by,
                    record_id: record.id,
                });
            }
            AccessAction::Revoke {
                subject_key,
                role,
                tables,
                ..
            } => {
                if let Some(user_grants) = self.grants.get_mut(&subject_key) {
                    if role.is_none() && tables.iter().any(|t| t == "*") {
                        // Blanket revocation of all roles
                        user_grants.clear();
                    } else {
                        user_grants.retain(|g| {
                            let role_matches = match role {
                                Some(r) => g.role == r,
                                None => true,
                            };
                            let table_matches = tables.iter().any(|t| t == "*")
                                || g.tables.iter().any(|t| tables.contains(t));

                            // Retain if it does NOT match both revocation criteria
                            !(role_matches && table_matches)
                        });
                    }
                }
                // Clean up empty key entries
                if self.grants.get(&subject_key).is_some_and(|g| g.is_empty()) {
                    self.grants.remove(&subject_key);
                }
            }
            AccessAction::RotateKey {
                old_key,
                new_key,
                signed_by_old,
                ..
            } => {
                // Verify old_key signature over BLAKE3("INK-ROTATE" || new_key)
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"INK-ROTATE");
                hasher.update(&new_key);
                let rotate_digest = hasher.finalize();

                crate::crypto::verify_signature(&old_key, rotate_digest.as_bytes(), &signed_by_old)
                    .map_err(|e| {
                        InkError::InvalidAccessRecord(format!(
                            "Invalid signature for key rotation: {}",
                            e
                        ))
                    })?;

                if let Some(existing_grants) = self.grants.remove(&old_key) {
                    self.grants.insert(new_key, existing_grants);
                }
            }
            AccessAction::AuditSummary { .. } => {
                // Informational record — does not alter active grants
            }
        }

        Ok(())
    }

    /// Check if a subject key is authorized to perform a role-restricted action on a table.
    pub fn is_authorized(
        &self,
        subject_key: &[u8; 32],
        required_role: Role,
        target_table: &str,
        now_micros: i64,
    ) -> bool {
        let grants = match self.grants.get(subject_key) {
            Some(g) => g,
            None => return false,
        };

        for grant in grants {
            if grant.is_expired(now_micros) {
                continue;
            }

            // Auditor satisfies Reader for all tables
            if required_role == Role::Reader && grant.role == Role::Auditor {
                return true;
            }

            // Role must match
            if grant.role != required_role {
                continue;
            }

            // Table scope check
            if grant.covers_table(target_table) {
                return true;
            }
        }

        false
    }

    /// Check if a subject key holds an active Admin role.
    pub fn is_admin(&self, subject_key: &[u8; 32], now_micros: i64) -> bool {
        self.is_authorized(subject_key, Role::Admin, SYSTEM_TABLE_ACCESS, now_micros)
    }

    /// Check if the registry has at least one active Admin key.
    pub fn has_admin(&self, now_micros: i64) -> bool {
        self.grants
            .iter()
            .any(|(k, _)| self.is_admin(k, now_micros))
    }

    /// Returns a reference to the active grants map.
    pub fn list_grants(&self) -> &HashMap<[u8; 32], Vec<RoleGrant>> {
        &self.grants
    }

    /// Returns all active grants for a specific public key.
    pub fn get_grants_for_key(&self, key: &[u8; 32]) -> Option<&Vec<RoleGrant>> {
        self.grants.get(key)
    }

    /// Check historical authorization: was `subject_key` authorized for `role` on `target_table`
    /// at the time of `record`?
    pub fn is_authorized_at(
        subject_key: &[u8; 32],
        required_role: Role,
        target_table: &str,
        at_timestamp: i64,
        at_record_id: u64,
        access_records: &[Record],
    ) -> Result<bool> {
        let mut historical_acl = AclRegistry::new();

        for rec in access_records {
            if rec.id > at_record_id {
                break;
            }
            historical_acl.apply_record(rec)?;
        }

        Ok(historical_acl.is_authorized(subject_key, required_role, target_table, at_timestamp))
    }
}

/// Create the canonical genesis admin grant JSON payload for Record #0.
pub fn create_genesis_admin_payload(admin_pubkey: &[u8; 32]) -> Vec<u8> {
    let action = AccessAction::Grant {
        subject_key: *admin_pubkey,
        subject_label: "genesis_admin".to_string(),
        role: Role::Admin,
        tables: vec!["*".to_string()],
        expires_at: None,
        granted_by: *admin_pubkey,
    };
    serde_json::to_vec(&action).expect("Genesis admin payload serialization must not fail")
}

/// Helper module for hex-encoding [u8; 32].
mod hex_bytes32 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes hex, found {} bytes",
                vec.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// Helper module for hex-encoding [u8; 64].
mod hex_bytes64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn dummy_record(id: u64, timestamp: i64, data: Vec<u8>) -> Record {
        Record {
            id,
            timestamp,
            table: SYSTEM_TABLE_ACCESS.to_string(),
            author: [1u8; 32],
            data,
            prev_hash: [0u8; 32],
            record_hash: [0u8; 32],
            signature: [0u8; 64],
            flags: 0,
            correction_of: None,
        }
    }

    #[test]
    fn test_role_parsing_and_display() {
        assert_eq!(Role::from_str("admin").unwrap(), Role::Admin);
        assert_eq!(Role::from_str("WRITER").unwrap(), Role::Writer);
        assert_eq!(Role::from_str("Reader").unwrap(), Role::Reader);
        assert_eq!(Role::from_str("auditor").unwrap(), Role::Auditor);
        assert!(Role::from_str("superuser").is_err());
        assert_eq!(Role::Admin.to_string(), "admin");
    }

    #[test]
    fn test_genesis_admin_grant() {
        let admin_key = [42u8; 32];
        let payload = create_genesis_admin_payload(&admin_key);
        let rec = dummy_record(0, 1000, payload);

        let mut acl = AclRegistry::new();
        acl.apply_record(&rec).unwrap();

        assert!(acl.is_admin(&admin_key, 2000));
        assert!(acl.is_authorized(&admin_key, Role::Admin, "any_table", 2000));
        // Admin does not automatically have writer permission
        assert!(!acl.is_authorized(&admin_key, Role::Writer, "sales", 2000));
    }

    #[test]
    fn test_grant_and_scope_and_expiration() {
        let admin_key = [1u8; 32];
        let user_key = [2u8; 32];
        let mut acl = AclRegistry::new();

        // 1. Grant user writer role on "sales" with expiration at t=5000
        let grant_action = AccessAction::Grant {
            subject_key: user_key,
            subject_label: "alice".to_string(),
            role: Role::Writer,
            tables: vec!["sales".to_string()],
            expires_at: Some(5000),
            granted_by: admin_key,
        };
        let rec = dummy_record(1, 1000, serde_json::to_vec(&grant_action).unwrap());
        acl.apply_record(&rec).unwrap();

        // Authorized on "sales" before expiration
        assert!(acl.is_authorized(&user_key, Role::Writer, "sales", 3000));
        // NOT authorized on "invoices"
        assert!(!acl.is_authorized(&user_key, Role::Writer, "invoices", 3000));
        // NOT authorized after expiration
        assert!(!acl.is_authorized(&user_key, Role::Writer, "sales", 6000));
    }

    #[test]
    fn test_auditor_satisfies_reader_everywhere() {
        let auditor_key = [9u8; 32];
        let mut acl = AclRegistry::new();

        let grant_action = AccessAction::Grant {
            subject_key: auditor_key,
            subject_label: "auditor".to_string(),
            role: Role::Auditor,
            tables: vec!["*".to_string()],
            expires_at: None,
            granted_by: [1u8; 32],
        };
        let rec = dummy_record(1, 1000, serde_json::to_vec(&grant_action).unwrap());
        acl.apply_record(&rec).unwrap();

        // Auditor satisfies reader on any table
        assert!(acl.is_authorized(&auditor_key, Role::Reader, "sales", 2000));
        assert!(acl.is_authorized(&auditor_key, Role::Reader, "_ink_access", 2000));
        // But cannot write
        assert!(!acl.is_authorized(&auditor_key, Role::Writer, "sales", 2000));
    }

    #[test]
    fn test_revocation() {
        let user_key = [3u8; 32];
        let mut acl = AclRegistry::new();

        // Grant writer
        let grant = AccessAction::Grant {
            subject_key: user_key,
            subject_label: "bob".to_string(),
            role: Role::Writer,
            tables: vec!["sales".to_string(), "orders".to_string()],
            expires_at: None,
            granted_by: [1u8; 32],
        };
        acl.apply_record(&dummy_record(1, 1000, serde_json::to_vec(&grant).unwrap()))
            .unwrap();
        assert!(acl.is_authorized(&user_key, Role::Writer, "sales", 1500));

        // Revoke "sales" table only
        let revoke_sales = AccessAction::Revoke {
            subject_key: user_key,
            role: Some(Role::Writer),
            tables: vec!["sales".to_string()],
            reason: "role changed".to_string(),
            revoked_by: [1u8; 32],
        };
        acl.apply_record(&dummy_record(
            2,
            2000,
            serde_json::to_vec(&revoke_sales).unwrap(),
        ))
        .unwrap();

        // Sales revoked
        assert!(!acl.is_authorized(&user_key, Role::Writer, "sales", 2500));
        // But still has writer on orders (if separate grant or if preserved)
    }

    #[test]
    fn test_key_rotation() {
        let old_kp = Keypair::generate();
        let new_kp = Keypair::generate();
        let mut acl = AclRegistry::new();

        // Grant old key
        let grant = AccessAction::Grant {
            subject_key: old_kp.public_key(),
            subject_label: "charlie".to_string(),
            role: Role::Writer,
            tables: vec!["sales".to_string()],
            expires_at: None,
            granted_by: [1u8; 32],
        };
        acl.apply_record(&dummy_record(1, 1000, serde_json::to_vec(&grant).unwrap()))
            .unwrap();
        assert!(acl.is_authorized(&old_kp.public_key(), Role::Writer, "sales", 1500));

        // Rotate
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"INK-ROTATE");
        hasher.update(&new_kp.public_key());
        let digest = hasher.finalize();
        let sig = old_kp.sign(digest.as_bytes());

        let rotate = AccessAction::RotateKey {
            old_key: old_kp.public_key(),
            new_key: new_kp.public_key(),
            signed_by_old: sig,
            approved_by_admin: [1u8; 32],
        };
        acl.apply_record(&dummy_record(2, 2000, serde_json::to_vec(&rotate).unwrap()))
            .unwrap();

        // Old key no longer authorized, new key authorized!
        assert!(!acl.is_authorized(&old_kp.public_key(), Role::Writer, "sales", 2500));
        assert!(acl.is_authorized(&new_kp.public_key(), Role::Writer, "sales", 2500));
    }

    #[test]
    fn test_historical_authorization() {
        let user_key = [5u8; 32];
        let mut records = Vec::new();

        // Record 1: Grant writer
        let grant = AccessAction::Grant {
            subject_key: user_key,
            subject_label: "dave".to_string(),
            role: Role::Writer,
            tables: vec!["sales".to_string()],
            expires_at: None,
            granted_by: [1u8; 32],
        };
        records.push(dummy_record(1, 1000, serde_json::to_vec(&grant).unwrap()));

        // Record 2: Revoke writer
        let revoke = AccessAction::Revoke {
            subject_key: user_key,
            role: None,
            tables: vec!["*".to_string()],
            reason: "left company".to_string(),
            revoked_by: [1u8; 32],
        };
        records.push(dummy_record(2, 3000, serde_json::to_vec(&revoke).unwrap()));

        // At record #1 (t=1500), Dave WAS authorized
        let auth_at_1 =
            AclRegistry::is_authorized_at(&user_key, Role::Writer, "sales", 1500, 1, &records)
                .unwrap();
        assert!(auth_at_1);

        // At record #2 (t=3500), Dave WAS NOT authorized
        let auth_at_2 =
            AclRegistry::is_authorized_at(&user_key, Role::Writer, "sales", 3500, 2, &records)
                .unwrap();
        assert!(!auth_at_2);
    }
}
