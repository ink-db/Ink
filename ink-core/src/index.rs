//! In-memory index for fast record lookups.
//!
//! The index is always **rebuildable from the log** — the segment files are the
//! source of truth.  If the index is ever lost or corrupt, [`Store::open`]
//! rebuilds it by scanning all segment files.
//!
//! # Contents
//!
//! | Index | Key | Value |
//! |---|---|---|
//! | `by_id` | record ID | [`RecordLocation`] |
//! | `by_table` | table name | sorted `Vec<u64>` of record IDs |
//! | `corrections` | original record ID | `Vec<u64>` of correction IDs |

use std::collections::{BTreeMap, HashMap};

// RecordLocation

/// Where a record lives on disk: enough information to seek to it directly.
#[derive(Debug, Clone)]
pub struct RecordLocation {
    /// Logical table the record belongs to.
    pub table: String,
    /// Sequence number of the segment file within the table directory.
    pub segment_seq: u32,
    /// Byte offset of the frame start within the segment file.
    pub byte_offset: u64,
    /// Microseconds since the Unix epoch when the record was written.
    pub timestamp: i64,
    /// If this record is a correction, the ID of the original record.
    pub correction_of: Option<u64>,
    /// BLAKE3 hash of this record.
    pub record_hash: [u8; 32],
}

// InkIndex

/// In-memory index over all appended records.
///
/// Every mutating operation on the index is `O(log N)` amortized.  Reads are
/// `O(1)` for ID lookups and `O(1)` amortized for table scans (the per-table
/// vec is pre-sorted by insertion order, which equals ID order within a table).
#[derive(Debug, Default)]
pub struct InkIndex {
    /// Primary index: record ID → location on disk.
    by_id: BTreeMap<u64, RecordLocation>,
    /// Secondary index: table name → list of record IDs in insertion order
    /// (which equals global-ID order within the table).
    by_table: HashMap<String, Vec<u64>>,
    /// Correction index: original record ID → list of correction record IDs.
    corrections: HashMap<u64, Vec<u64>>,
}

impl InkIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a record into the index.
    ///
    /// `correction_of` is `Some(original_id)` when this record is a correction.
    pub fn insert(&mut self, id: u64, loc: RecordLocation, correction_of: Option<u64>) {
        let table = loc.table.clone();
        self.by_id.insert(id, loc);

        // Add to the per-table list.  Insertion is always in increasing ID
        // order (we scan segments sequentially), so push is sufficient.
        self.by_table.entry(table).or_default().push(id);

        // Update correction index.
        if let Some(original_id) = correction_of {
            self.corrections.entry(original_id).or_default().push(id);
        }
    }

    /// Look up a record's disk location by ID.
    pub fn get(&self, id: u64) -> Option<&RecordLocation> {
        self.by_id.get(&id)
    }

    /// Return the sorted list of record IDs for a given table.
    ///
    /// Returns an empty slice if the table does not exist.
    pub fn ids_for_table(&self, table: &str) -> &[u64] {
        self.by_table.get(table).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Return the names of all known tables.
    pub fn tables(&self) -> Vec<String> {
        let mut names: Vec<String> = self.by_table.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the highest record ID currently in the index, or `None` if
    /// the database is empty.
    pub fn max_id(&self) -> Option<u64> {
        self.by_id.keys().next_back().copied()
    }

    /// Total number of records across all tables.
    pub fn record_count(&self) -> u64 {
        self.by_id.len() as u64
    }

    /// Return the correction record IDs for a given original record.
    ///
    /// Returns an empty slice if `original_id` has no corrections.
    pub fn corrections_of(&self, original_id: u64) -> &[u64] {
        self.corrections
            .get(&original_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Number of distinct tables.
    pub fn table_count(&self) -> usize {
        self.by_table.len()
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(table: &str, seq: u32, offset: u64) -> RecordLocation {
        RecordLocation {
            table: table.to_string(),
            segment_seq: seq,
            byte_offset: offset,
            timestamp: 0,
            correction_of: None,
            record_hash: [0u8; 32],
        }
    }

    #[test]
    fn basic_insert_and_get() {
        let mut idx = InkIndex::new();
        idx.insert(0, loc("sales", 0, 32), None);
        idx.insert(1, loc("logs", 0, 32), None);
        idx.insert(2, loc("sales", 0, 450), None);

        assert!(idx.get(0).is_some());
        assert!(idx.get(1).is_some());
        assert!(idx.get(2).is_some());
        assert!(idx.get(99).is_none());
    }

    #[test]
    fn ids_for_table_sorted() {
        let mut idx = InkIndex::new();
        idx.insert(0, loc("sales", 0, 32), None);
        idx.insert(2, loc("sales", 0, 450), None);
        idx.insert(5, loc("sales", 0, 900), None);
        idx.insert(1, loc("logs", 0, 32), None);

        let ids = idx.ids_for_table("sales");
        assert_eq!(ids, &[0, 2, 5]);
        assert_eq!(idx.ids_for_table("logs"), &[1]);
        assert!(idx.ids_for_table("missing").is_empty());
    }

    #[test]
    fn tables_sorted_alphabetically() {
        let mut idx = InkIndex::new();
        idx.insert(0, loc("zzz", 0, 0), None);
        idx.insert(1, loc("aaa", 0, 0), None);
        idx.insert(2, loc("mmm", 0, 0), None);

        let tables = idx.tables();
        assert_eq!(tables, vec!["aaa", "mmm", "zzz"]);
    }

    #[test]
    fn max_id_empty_and_non_empty() {
        let mut idx = InkIndex::new();
        assert_eq!(idx.max_id(), None);

        idx.insert(5, loc("t", 0, 0), None);
        idx.insert(2, loc("t", 0, 0), None);
        idx.insert(9, loc("t", 0, 0), None);
        assert_eq!(idx.max_id(), Some(9));
    }

    #[test]
    fn corrections_index() {
        let mut idx = InkIndex::new();
        idx.insert(0, loc("t", 0, 0), None);
        // Record 3 is a correction of record 0
        let mut loc3 = loc("t", 0, 100);
        loc3.correction_of = Some(0);
        idx.insert(3, loc3, Some(0));
        // Record 7 is also a correction of record 0
        let mut loc7 = loc("t", 0, 200);
        loc7.correction_of = Some(0);
        idx.insert(7, loc7, Some(0));

        let corrs = idx.corrections_of(0);
        assert_eq!(corrs, &[3, 7]);
        assert!(idx.corrections_of(1).is_empty());
    }

    #[test]
    fn record_count_and_table_count() {
        let mut idx = InkIndex::new();
        assert_eq!(idx.record_count(), 0);
        assert_eq!(idx.table_count(), 0);

        idx.insert(0, loc("a", 0, 0), None);
        idx.insert(1, loc("b", 0, 0), None);
        idx.insert(2, loc("a", 0, 0), None);

        assert_eq!(idx.record_count(), 3);
        assert_eq!(idx.table_count(), 2);
    }
}
