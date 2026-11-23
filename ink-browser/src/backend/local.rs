//! Local filesystem implementation of the [`Backend`] trait.
//!
//! Directly operates on an Ink database directory using `ink-core` and `ink-query`.
//! Acquires an exclusive advisory file lock on `<data_dir>/.lock` using `fs2`
//! to prevent concurrent corruption with other processes, and routes all operations
//! through the cryptographic gatekeeper against `AclRegistry`.

use super::{
    AccessGrantInfo, Backend, ClusterStatus, ConnectionMode, ConsistencyProofInfo,
    InclusionProofInfo, MerkleNodeInfo, PageResult, RecordDetail, RecordSummary, SessionInfo,
    TableInfo, TreeHeadInfo, VerifySummary,
};
use crate::error::BackendError;
use fs2::FileExt;
use ink_core::{
    auth::{Role, SYSTEM_TABLE_ACCESS},
    record::FLAG_IS_CORRECTION,
    segment::now_micros,
    Keypair, Store,
};
use ink_query::QueryResult;
use std::collections::{BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Local filesystem backend holding direct database access and exclusive lock.
pub struct LocalBackend {
    store: Arc<Mutex<Store>>,
    keypair: Keypair,
    session: SessionInfo,
    lock_file: Option<File>,
    _data_dir: PathBuf,
}

impl LocalBackend {
    /// Open a local Ink database directory with the provided authenticated keypair.
    ///
    /// # Concurrency & Security
    /// - Acquires an exclusive advisory file lock on `<data_dir>/.lock`. Fails immediately
    ///   with [`BackendError::DatabaseLocked`] if another `ink serve` or `ink-browser` process holds it.
    /// - Verifies that `keypair.public_key()` holds at least one active, non-expired role grant.
    ///   Fails with [`BackendError::AccessDenied`] if the key is unauthorized (zero anonymous access).
    pub fn open(data_dir: &Path, keypair: Keypair) -> Result<Self, BackendError> {
        let lock_path = data_dir.join(".lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                BackendError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to open lock file '{}': {}", lock_path.display(), e),
                ))
            })?;

        // Attempt non-blocking exclusive file lock
        lock_file.try_lock_exclusive().map_err(|_| {
            BackendError::DatabaseLocked(format!(
                "Database at '{}' is locked by another running process (ink serve or ink-browser)",
                data_dir.display()
            ))
        })?;

        let store = Store::open(data_dir)?;
        let pubkey = keypair.public_key();
        let pubkey_hex = hex::encode(pubkey);
        let now = now_micros();

        // Zero Anonymous Access: check that the subject key has active grants
        let grants = store.acl().get_grants_for_key(&pubkey);
        let active_grants: Vec<_> = match grants {
            Some(g) => g.iter().filter(|grant| !grant.is_expired(now)).collect(),
            None => Vec::new(),
        };

        if active_grants.is_empty() {
            return Err(BackendError::AccessDenied(format!(
                "Public key {} has no authorized grants in this database",
                pubkey_hex
            )));
        }

        let mut roles = HashSet::new();
        let mut table_scopes = BTreeSet::new();
        for grant in active_grants {
            roles.insert(grant.role);
            for t in &grant.tables {
                table_scopes.insert(t.clone());
            }
        }

        let (tree_size, root_hash) = store.tree_head_info();
        let session = SessionInfo {
            mode: ConnectionMode::Local {
                path: data_dir.to_path_buf(),
            },
            public_key: pubkey,
            public_key_hex: pubkey_hex,
            database_id: store.database_id().to_string(),
            roles: roles.into_iter().collect(),
            table_scopes: table_scopes.into_iter().collect(),
            latency_ms: None,
            tree_size,
            tree_head: root_hash,
        };

        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            keypair,
            session,
            lock_file: Some(lock_file),
            _data_dir: data_dir.to_path_buf(),
        })
    }
}

impl Drop for LocalBackend {
    fn drop(&mut self) {
        self.close();
    }
}

impl Backend for LocalBackend {
    fn execute_iql(&self, query: &str) -> Result<QueryResult, BackendError> {
        let mut st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let pubkey = self.keypair.public_key();
        ink_query::query_authenticated(&mut st, query, Some(&pubkey))
            .map_err(|e| BackendError::QueryFailed(e.to_string()))
    }

    fn list_tables(&self) -> Result<Vec<TableInfo>, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();
        let is_admin = st.acl().is_admin(&pubkey, now);
        let is_auditor = st.acl().is_authorized(&pubkey, Role::Auditor, "*", now);

        let all_tables = st.tables();
        let mut out = Vec::new();

        for tbl in all_tables {
            // System table _ink_access is strictly hidden from non-admin/non-auditor
            if tbl == SYSTEM_TABLE_ACCESS && !is_admin && !is_auditor {
                continue;
            }

            let count = st
                .get_records_in_table(&tbl, None)
                .map(|r| r.len() as u64)
                .unwrap_or(0);

            out.push(TableInfo {
                name: tbl,
                record_count: count,
            });
        }

        Ok(out)
    }

    fn read_page(
        &self,
        table: &str,
        _filter: Option<&str>,
        _order: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PageResult, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();

        if !st.acl().is_authorized(&pubkey, Role::Reader, table, now)
            && !st.acl().is_admin(&pubkey, now)
        {
            return Err(BackendError::AccessDenied(format!(
                "Access denied: insufficient permissions to read table '{}'",
                table
            )));
        }

        let records_res = st.get_records_in_table(table, None);
        let all_records = match records_res {
            Ok(recs) => recs,
            Err(ink_core::error::InkError::TableNotFound(_)) => Vec::new(),
            Err(e) => return Err(BackendError::Core(e)),
        };

        let total = all_records.len() as u64;
        let page_slice: Vec<&ink_core::Record> =
            all_records.iter().skip(offset).take(limit).collect();

        let mut dynamic_cols = BTreeSet::new();
        let mut details = Vec::new();

        for rec in page_slice {
            let json_val: serde_json::Value =
                serde_json::from_slice(&rec.data).unwrap_or(serde_json::Value::Null);

            if let serde_json::Value::Object(ref map) = json_val {
                for key in map.keys() {
                    dynamic_cols.insert(key.clone());
                }
            }

            let is_corr = (rec.flags & FLAG_IS_CORRECTION) != 0;
            let corr_of = rec.correction_of;
            let author_hex = hex::encode(rec.author);

            let author_label = st
                .acl()
                .get_grants_for_key(&rec.author)
                .and_then(|grants| grants.first())
                .map(|g| {
                    if g.role == Role::Admin {
                        "admin".to_string()
                    } else {
                        format!("key_{}", &author_hex[..8])
                    }
                });

            details.push(RecordDetail {
                id: rec.id,
                timestamp: rec.timestamp,
                table: rec.table.clone(),
                author: rec.author,
                author_hex,
                author_label,
                flags: rec.flags,
                is_correction: is_corr,
                correction_of: corr_of,
                prev_hash: rec.prev_hash,
                record_hash: rec.record_hash,
                signature: rec.signature,
                data_json: String::from_utf8_lossy(&rec.data).to_string(),
                parsed_data: json_val,
            });
        }

        Ok(PageResult {
            table: table.to_string(),
            total_records: total,
            offset,
            limit,
            dynamic_columns: dynamic_cols.into_iter().collect(),
            records: details,
        })
    }

    fn get_record(&self, id: u64) -> Result<RecordDetail, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let rec = st
            .get_record(id)
            .map_err(|_| BackendError::RecordNotFound(id))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();

        if !st
            .acl()
            .is_authorized(&pubkey, Role::Reader, &rec.table, now)
            && !st.acl().is_admin(&pubkey, now)
        {
            return Err(BackendError::AccessDenied(format!(
                "Access denied: insufficient permissions to read record #{}",
                id
            )));
        }

        let json_val = serde_json::from_slice(&rec.data).unwrap_or(serde_json::Value::Null);
        let is_corr = (rec.flags & FLAG_IS_CORRECTION) != 0;
        let corr_of = rec.correction_of;
        let author_hex = hex::encode(rec.author);

        Ok(RecordDetail {
            id: rec.id,
            timestamp: rec.timestamp,
            table: rec.table,
            author: rec.author,
            author_hex,
            author_label: None,
            flags: rec.flags,
            is_correction: is_corr,
            correction_of: corr_of,
            prev_hash: rec.prev_hash,
            record_hash: rec.record_hash,
            signature: rec.signature,
            data_json: String::from_utf8_lossy(&rec.data).to_string(),
            parsed_data: json_val,
        })
    }

    fn get_history(&self, id: u64) -> Result<Vec<RecordDetail>, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let history = st
            .get_history(id)
            .map_err(|_| BackendError::RecordNotFound(id))?;

        if let Some(first) = history.first() {
            let now = now_micros();
            let pubkey = self.keypair.public_key();
            if !st
                .acl()
                .is_authorized(&pubkey, Role::Reader, &first.table, now)
                && !st.acl().is_admin(&pubkey, now)
            {
                return Err(BackendError::AccessDenied(format!(
                    "Access denied: insufficient permissions to read history for table '{}'",
                    first.table
                )));
            }
        }

        let mut out = Vec::new();
        for rec in history {
            let json_val = serde_json::from_slice(&rec.data).unwrap_or(serde_json::Value::Null);
            let is_corr = (rec.flags & FLAG_IS_CORRECTION) != 0;
            let corr_of = rec.correction_of;
            let author_hex = hex::encode(rec.author);

            out.push(RecordDetail {
                id: rec.id,
                timestamp: rec.timestamp,
                table: rec.table,
                author: rec.author,
                author_hex,
                author_label: None,
                flags: rec.flags,
                is_correction: is_corr,
                correction_of: corr_of,
                prev_hash: rec.prev_hash,
                record_hash: rec.record_hash,
                signature: rec.signature,
                data_json: String::from_utf8_lossy(&rec.data).to_string(),
                parsed_data: json_val,
            });
        }
        Ok(out)
    }

    fn append_record(
        &self,
        table: &str,
        data: serde_json::Value,
    ) -> Result<RecordSummary, BackendError> {
        let mut st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();

        if !st.acl().is_authorized(&pubkey, Role::Writer, table, now)
            && !st.acl().is_admin(&pubkey, now)
        {
            return Err(BackendError::AccessDenied(format!(
                "Access denied: insufficient permissions to write to table '{}'",
                table
            )));
        }

        let bytes = serde_json::to_vec(&data)?;
        let rec = st.append_signed(table, &bytes, Some(&self.keypair))?;
        Ok(RecordSummary {
            id: rec.id,
            hash: rec.record_hash,
            timestamp: rec.timestamp,
        })
    }

    fn correct_record(
        &self,
        orig_id: u64,
        data: serde_json::Value,
        reason: &str,
    ) -> Result<RecordSummary, BackendError> {
        let mut st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let orig = st
            .get_record(orig_id)
            .map_err(|_| BackendError::RecordNotFound(orig_id))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();

        if !st
            .acl()
            .is_authorized(&pubkey, Role::Writer, &orig.table, now)
            && !st.acl().is_admin(&pubkey, now)
        {
            return Err(BackendError::AccessDenied(format!(
                "Access denied: insufficient permissions to correct records in table '{}'",
                orig.table
            )));
        }

        let bytes = serde_json::to_vec(&data)?;
        let rec = st.append_correction_signed(orig_id, &bytes, reason, Some(&self.keypair))?;
        Ok(RecordSummary {
            id: rec.id,
            hash: rec.record_hash,
            timestamp: rec.timestamp,
        })
    }

    fn verify(&self, target_table: Option<&str>) -> Result<VerifySummary, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();
        let scope = target_table.unwrap_or("*");
        if !st.acl().is_authorized(&pubkey, Role::Reader, scope, now) {
            return Err(BackendError::AccessDenied(
                "Access denied: a Reader grant is required to verify this scope".into(),
            ));
        }

        let v_res = match target_table {
            Some(tbl) => st.verify_table(tbl)?,
            None => st.verify_all()?,
        };

        let err_strings: Vec<String> = v_res
            .errors
            .iter()
            .map(|error| format!("Record #{}: {}", error.record_id, error.description))
            .collect();
        let broken_record_id = v_res.errors.first().map(|error| error.record_id);
        Ok(VerifySummary {
            is_valid: v_res.is_valid,
            records_checked: v_res.records_checked,
            errors: err_strings,
            broken_record_id,
        })
    }

    fn get_tree_head(&self) -> Result<TreeHeadInfo, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let (tree_size, root_hash) = st.tree_head_info();
        Ok(TreeHeadInfo {
            tree_size,
            root_hash,
        })
    }

    fn get_merkle_nodes(&self) -> Result<Vec<MerkleNodeInfo>, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();
        let has_global_read = st.acl().is_authorized(&pubkey, Role::Reader, "*", now)
            || st.acl().is_authorized(&pubkey, Role::Auditor, "*", now);
        if !has_global_read {
            return Err(BackendError::AccessDenied(
                "Access denied: a global Reader or Auditor grant is required to view the full Merkle tree".into(),
            ));
        }

        const MAX_VISUALIZED_RECORDS: u64 = 512;
        let tree_size = st.tree_head_info().0;
        if tree_size > MAX_VISUALIZED_RECORDS {
            return Err(BackendError::Other(format!(
                "Tree visualization is limited to {MAX_VISUALIZED_RECORDS} records; this database contains {tree_size}"
            )));
        }

        Ok(st
            .merkle_tree()
            .visual_nodes()
            .into_iter()
            .map(|node| MerkleNodeInfo {
                hash: node.hash,
                left: node.left,
                right: node.right,
                leaf_index: node.leaf_index,
            })
            .collect())
    }

    fn get_inclusion_proof(&self, record_id: u64) -> Result<InclusionProofInfo, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let record = st.get_record(record_id)?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();
        if !st
            .acl()
            .is_authorized(&pubkey, Role::Reader, &record.table, now)
        {
            return Err(BackendError::AccessDenied(format!(
                "Access denied: a Reader grant is required to export proofs for table '{}'",
                record.table
            )));
        }

        let proof = st.get_inclusion_proof(record_id)?;
        let root_hash = hex::decode(&proof.root_hash)
            .map_err(|e| BackendError::Other(format!("Invalid Merkle root in proof: {e}")))?
            .try_into()
            .map_err(|_| BackendError::Other("Invalid Merkle root length in proof".into()))?;
        let audit_path = proof
            .audit_path
            .iter()
            .map(|hash| {
                hex::decode(hash)
                    .map_err(|e| BackendError::Other(format!("Invalid proof path hash: {e}")))?
                    .try_into()
                    .map_err(|_| BackendError::Other("Invalid proof path hash length".into()))
            })
            .collect::<Result<Vec<[u8; 32]>, BackendError>>()?;

        Ok(InclusionProofInfo {
            record_id,
            tree_size: proof.tree_size,
            root_hash,
            audit_path,
        })
    }

    fn get_consistency_proof(
        &self,
        first: u64,
        second: u64,
    ) -> Result<ConsistencyProofInfo, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let proof = st.get_consistency_proof(first)?;
        let path: Vec<[u8; 32]> = proof
            .audit_path
            .iter()
            .filter_map(|hex_s| {
                let b = hex::decode(hex_s).ok()?;
                b.try_into().ok()
            })
            .collect();

        Ok(ConsistencyProofInfo {
            first,
            second,
            consistency_path: path,
        })
    }

    fn get_status(&self) -> Result<ClusterStatus, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let (tree_size, root_hash) = st.tree_head_info();
        Ok(ClusterStatus {
            record_count: tree_size,
            table_count: st.tables().len(),
            tree_head: hex::encode(root_hash),
            peers: Vec::new(),
            quorum: 1,
        })
    }

    fn list_access(&self) -> Result<Vec<AccessGrantInfo>, BackendError> {
        let st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let now = now_micros();
        let pubkey = self.keypair.public_key();

        if !st.acl().is_admin(&pubkey, now)
            && !st.acl().is_authorized(&pubkey, Role::Auditor, "*", now)
        {
            return Err(BackendError::AccessDenied(
                "Access denied: only Admin or Auditor roles may inspect access control grants"
                    .into(),
            ));
        }

        let mut out = Vec::new();
        for (subj, grants) in st.acl().list_grants() {
            for g in grants {
                out.push(AccessGrantInfo {
                    subject_key: *subj,
                    subject_label: format!("key_{}", &hex::encode(subj)[..8]),
                    role: g.role,
                    tables: g.tables.clone(),
                    expires_at: g.expires_at,
                    granted_by: g.granted_by,
                    record_id: g.record_id,
                    is_expired: g.is_expired(now),
                });
            }
        }
        Ok(out)
    }

    fn grant(
        &self,
        subject_key: [u8; 32],
        label: &str,
        role: Role,
        tables: Vec<String>,
        expires_at: Option<i64>,
    ) -> Result<RecordSummary, BackendError> {
        let mut st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let rec = st.grant(&self.keypair, subject_key, label, role, tables, expires_at)?;
        Ok(RecordSummary {
            id: rec.id,
            hash: rec.record_hash,
            timestamp: rec.timestamp,
        })
    }

    fn revoke(
        &self,
        subject_key: [u8; 32],
        role: Option<Role>,
        tables: Vec<String>,
        reason: &str,
    ) -> Result<RecordSummary, BackendError> {
        let mut st = self
            .store
            .lock()
            .map_err(|e| BackendError::Other(e.to_string()))?;
        let rec = st.revoke(&self.keypair, subject_key, role, tables, reason)?;
        Ok(RecordSummary {
            id: rec.id,
            hash: rec.record_hash,
            timestamp: rec.timestamp,
        })
    }

    fn session_info(&self) -> &SessionInfo {
        &self.session
    }

    fn close(&mut self) {
        if let Some(file) = self.lock_file.take() {
            let _ = file.unlock();
            drop(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Backend, ConnectionMode};
    use ink_core::auth::Role;
    use ink_core::{Keypair, Store};
    use tempfile::tempdir;

    #[test]
    fn test_local_backend_concurrency_locking() {
        let dir = tempdir().expect("Failed to create tempdir");
        let admin_kp = Keypair::generate();

        // Initialize database with admin
        let (_store, _) =
            Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("Init failed");

        // Process 1: Open LocalBackend
        let backend1 = LocalBackend::open(dir.path(), admin_kp.clone())
            .expect("First LocalBackend::open must succeed");

        assert!(matches!(
            backend1.session_info().mode,
            ConnectionMode::Local { .. }
        ));
        assert!(backend1.session_info().is_admin());

        // Process 2: Attempt concurrent open of same directory
        let concurrent_err = match LocalBackend::open(dir.path(), admin_kp.clone()) {
            Err(e) => e,
            Ok(_) => panic!("Second LocalBackend::open must fail due to lock"),
        };

        match concurrent_err {
            BackendError::DatabaseLocked(msg) => {
                assert!(msg.contains("locked by another running process"));
            }
            other => panic!("Expected DatabaseLocked error, got {:?}", other),
        }

        // Drop Process 1 (releases advisory file lock)
        drop(backend1);

        // Process 3: Now open must succeed cleanly
        let backend2 = LocalBackend::open(dir.path(), admin_kp)
            .expect("LocalBackend::open must succeed after lock is released");
        assert_eq!(backend2.session_info().roles, vec![Role::Admin]);
    }

    #[test]
    fn test_local_backend_zero_anonymous_access() {
        let dir = tempdir().expect("Failed to create tempdir");
        let admin_kp = Keypair::generate();
        let unauthorized_kp = Keypair::generate();

        // Initialize database with admin
        let (_store, _) = Store::init_with_admin(dir.path(), Some(admin_kp)).expect("Init failed");

        // Attempt open with unauthorized key (zero anonymous access)
        let err = match LocalBackend::open(dir.path(), unauthorized_kp) {
            Err(e) => e,
            Ok(_) => panic!("Unauthorized key must be rejected"),
        };

        match err {
            BackendError::AccessDenied(msg) => {
                assert!(msg.contains("no authorized grants in this database"));
            }
            other => panic!("Expected AccessDenied, got {:?}", other),
        }
    }
}
