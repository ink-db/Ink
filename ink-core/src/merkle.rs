//! RFC 6962 / Certificate Transparency style append-only Merkle tree.
//!
//! Provides cryptographic inclusion proofs and consistency proofs over records
//! in the database.
//!
//! # Domain Separation
//!
//! To prevent second-preimage attacks:
//! - Leaf hash: `BLAKE3(0x00 || data)`
//! - Internal node hash: `BLAKE3(0x01 || left_child || right_child)`

use serde::{Deserialize, Serialize};

/// Domain separator byte for leaf hashes.
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain separator byte for internal node hashes.
pub const NODE_PREFIX: u8 = 0x01;

/// Compute the Merkle leaf hash for raw leaf data (such as a record hash).
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Compute the Merkle internal node hash from two child hashes.
pub fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// An exportable Merkle inclusion proof proving that a specific record
/// exists at `leaf_index` within a tree of size `tree_size`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    /// 0-based index of the leaf in the tree.
    pub leaf_index: u64,
    /// Total number of leaves in the tree at the time of proof generation.
    pub tree_size: u64,
    /// The root hash (tree head) committing to the entire tree.
    pub root_hash: String,
    /// The canonical record hash being proven.
    pub record_hash: String,
    /// List of sibling hashes (in hex) along the path from leaf to root.
    pub audit_path: Vec<String>,
}

/// An exportable Merkle consistency proof proving that a prior tree of size `first_size`
/// is an append-only prefix of a subsequent tree of size `second_size`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Size of the older tree.
    pub first_size: u64,
    /// Size of the newer tree.
    pub second_size: u64,
    /// Root hash of the older tree.
    pub first_root: String,
    /// Root hash of the newer tree.
    pub second_root: String,
    /// Sibling hashes proving consistency between the two snapshots.
    pub audit_path: Vec<String>,
}

/// A node in a recursive view of the Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleVisualNode {
    /// BLAKE3 hash committed by this node.
    pub hash: [u8; 32],
    /// Index of the left child in the returned node vector.
    pub left: Option<usize>,
    /// Index of the right child in the returned node vector.
    pub right: Option<usize>,
    /// Leaf index when this node represents one record.
    pub leaf_index: Option<u64>,
}

/// An append-only Merkle tree holding leaf hashes.
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    /// Stored leaf hashes in append order (each leaf hash is already domain-separated).
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create an empty Merkle tree.
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append a raw record hash to the tree. Computes the domain-separated leaf hash.
    pub fn append(&mut self, record_hash: &[u8; 32]) {
        let leaf = hash_leaf(record_hash);
        self.leaves.push(leaf);
    }

    /// Number of leaves in the tree.
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Return `true` if the tree contains no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the current root hash (Tree Head).
    ///
    /// For an empty tree, returns an all-zero hash.
    pub fn root_hash(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        sub_tree_hash(&self.leaves)
    }

    /// Compute the root hash as a hex string.
    pub fn root_hash_hex(&self) -> String {
        hex::encode(self.root_hash())
    }

    /// Return the complete tree in root-first order for visualization.
    pub fn visual_nodes(&self) -> Vec<MerkleVisualNode> {
        if self.leaves.is_empty() {
            return Vec::new();
        }

        fn append_subtree(
            leaves: &[[u8; 32]],
            start: usize,
            nodes: &mut Vec<MerkleVisualNode>,
        ) -> (usize, [u8; 32]) {
            let node_index = nodes.len();
            nodes.push(MerkleVisualNode {
                hash: [0; 32],
                left: None,
                right: None,
                leaf_index: None,
            });

            if leaves.len() == 1 {
                nodes[node_index].hash = leaves[0];
                nodes[node_index].leaf_index = Some(start as u64);
                return (node_index, leaves[0]);
            }

            let split = largest_power_of_2_less_than(leaves.len());
            let (left_index, left_hash) = append_subtree(&leaves[..split], start, nodes);
            let (right_index, right_hash) = append_subtree(&leaves[split..], start + split, nodes);
            let hash = hash_children(&left_hash, &right_hash);
            nodes[node_index].hash = hash;
            nodes[node_index].left = Some(left_index);
            nodes[node_index].right = Some(right_index);
            (node_index, hash)
        }

        let mut nodes = Vec::with_capacity(self.leaves.len().saturating_mul(2) - 1);
        append_subtree(&self.leaves, 0, &mut nodes);
        nodes
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`.
    ///
    /// Returns `None` if `leaf_index >= self.size()`.
    pub fn inclusion_proof(
        &self,
        leaf_index: u64,
        original_record_hash: &[u8; 32],
    ) -> Option<InclusionProof> {
        let n = self.size();
        if leaf_index >= n {
            return None;
        }

        let mut path = Vec::new();
        build_inclusion_path(&self.leaves, leaf_index, &mut path);

        let audit_path = path.into_iter().map(hex::encode).collect();

        Some(InclusionProof {
            leaf_index,
            tree_size: n,
            root_hash: self.root_hash_hex(),
            record_hash: hex::encode(original_record_hash),
            audit_path,
        })
    }

    /// Generate a consistency proof between an earlier snapshot of size `m`
    /// and the current snapshot of size `n`.
    pub fn consistency_proof(&self, m: u64) -> Option<ConsistencyProof> {
        let n = self.size();
        if m == 0 || m > n {
            return None;
        }

        let first_root = hex::encode(sub_tree_hash(&self.leaves[..m as usize]));
        let second_root = self.root_hash_hex();

        let mut path = Vec::new();
        if m < n {
            build_consistency_path(&self.leaves, m, &mut path);
        }

        let audit_path = path.into_iter().map(hex::encode).collect();

        Some(ConsistencyProof {
            first_size: m,
            second_size: n,
            first_root,
            second_root,
            audit_path,
        })
    }
}

// Merkle Subtree Algorithms (RFC 6962)

/// Find the largest power of 2 smaller than `n`.
fn largest_power_of_2_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Compute the hash of a slice of leaves recursively.
fn sub_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    let n = leaves.len();
    match n {
        0 => [0u8; 32],
        1 => leaves[0],
        _ => {
            let k = largest_power_of_2_less_than(n);
            let left = sub_tree_hash(&leaves[..k]);
            let right = sub_tree_hash(&leaves[k..]);
            hash_children(&left, &right)
        }
    }
}

/// Recursively build the audit path for leaf at index `m` in `leaves`.
fn build_inclusion_path(leaves: &[[u8; 32]], m: u64, path: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = largest_power_of_2_less_than(n);
    if (m as usize) < k {
        build_inclusion_path(&leaves[..k], m, path);
        path.push(sub_tree_hash(&leaves[k..]));
    } else {
        build_inclusion_path(&leaves[k..], m - k as u64, path);
        path.push(sub_tree_hash(&leaves[..k]));
    }
}

/// Recursively build the consistency path between size `m` and `n = leaves.len()`.
fn build_consistency_path(leaves: &[[u8; 32]], m: u64, path: &mut Vec<[u8; 32]>) {
    sub_consistency(leaves, m, true, path);
}

fn sub_consistency(
    leaves: &[[u8; 32]],
    m: u64,
    start_from_old_root: bool,
    path: &mut Vec<[u8; 32]>,
) {
    let n = leaves.len();
    let m = m as usize;
    if m == n {
        if !start_from_old_root {
            path.push(sub_tree_hash(leaves));
        }
        return;
    }
    let k = largest_power_of_2_less_than(n);
    if m <= k {
        sub_consistency(&leaves[..k], m as u64, start_from_old_root, path);
        path.push(sub_tree_hash(&leaves[k..]));
    } else {
        sub_consistency(&leaves[k..], (m - k) as u64, false, path);
        path.push(sub_tree_hash(&leaves[..k]));
    }
}

// Standalone Proof Verification

/// Verify a standalone [`InclusionProof`].
///
/// Returns `true` if and only if the record hash mathematically exists
/// at `proof.leaf_index` within a tree of size `proof.tree_size` and root `proof.root_hash`.
pub fn verify_inclusion(proof: &InclusionProof) -> bool {
    let mut record_hash_bytes = [0u8; 32];
    if hex::decode_to_slice(&proof.record_hash, &mut record_hash_bytes).is_err() {
        return false;
    }

    let mut expected_root = [0u8; 32];
    if hex::decode_to_slice(&proof.root_hash, &mut expected_root).is_err() {
        return false;
    }

    let mut path = Vec::with_capacity(proof.audit_path.len());
    for s in &proof.audit_path {
        let mut arr = [0u8; 32];
        if hex::decode_to_slice(s, &mut arr).is_err() {
            return false;
        }
        path.push(arr);
    }

    if proof.leaf_index >= proof.tree_size {
        return false;
    }

    let leaf_hash = hash_leaf(&record_hash_bytes);
    match compute_inclusion_root(proof.leaf_index, proof.tree_size, leaf_hash, &path) {
        Some(computed) => computed == expected_root,
        None => false,
    }
}

fn compute_inclusion_root(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: [u8; 32],
    audit_path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let mut splits = Vec::new();
    let mut m = leaf_index;
    let mut n = tree_size;
    while n > 1 {
        let k = largest_power_of_2_less_than(n as usize) as u64;
        if m < k {
            splits.push(true); // sibling is on the right
            n = k;
        } else {
            splits.push(false); // sibling is on the left
            m -= k;
            n -= k;
        }
    }

    if splits.len() != audit_path.len() {
        return None;
    }

    // splits were generated top-down (root to leaf).
    // audit_path was generated bottom-up (leaf to root).
    // Reverse splits to match audit_path order.
    splits.reverse();

    let mut cur = leaf_hash;
    for (sibling_is_right, sibling) in splits.into_iter().zip(audit_path.iter()) {
        if sibling_is_right {
            cur = hash_children(&cur, sibling);
        } else {
            cur = hash_children(sibling, &cur);
        }
    }
    Some(cur)
}

/// Verify a standalone [`ConsistencyProof`].
pub fn verify_consistency(proof: &ConsistencyProof) -> bool {
    if proof.first_size == 0 || proof.first_size > proof.second_size {
        return false;
    }
    if proof.first_size == proof.second_size {
        return proof.first_root == proof.second_root && proof.audit_path.is_empty();
    }

    let mut expected_first = [0u8; 32];
    let mut expected_second = [0u8; 32];
    if hex::decode_to_slice(&proof.first_root, &mut expected_first).is_err()
        || hex::decode_to_slice(&proof.second_root, &mut expected_second).is_err()
    {
        return false;
    }

    let mut path = Vec::with_capacity(proof.audit_path.len());
    for s in &proof.audit_path {
        let mut arr = [0u8; 32];
        if hex::decode_to_slice(s, &mut arr).is_err() {
            return false;
        }
        path.push(arr);
    }

    let mut path_iter = path.iter().copied();
    let res = verify_sub_consistency(
        proof.first_size,
        proof.second_size,
        true,
        expected_first,
        &mut path_iter,
    );

    match res {
        Some((fr, sr)) => {
            fr == expected_first && sr == expected_second && path_iter.next().is_none()
        }
        None => false,
    }
}

fn verify_sub_consistency(
    m: u64,
    n: u64,
    start_from_old_root: bool,
    first_root: [u8; 32],
    path: &mut impl Iterator<Item = [u8; 32]>,
) -> Option<([u8; 32], [u8; 32])> {
    if m == n {
        if start_from_old_root {
            return Some((first_root, first_root));
        } else {
            let node = path.next()?;
            return Some((node, node));
        }
    }

    let k = largest_power_of_2_less_than(n as usize) as u64;
    if m <= k {
        let (fr, sr_left) = verify_sub_consistency(m, k, start_from_old_root, first_root, path)?;
        let right = path.next()?;
        let sr = hash_children(&sr_left, &right);
        Some((fr, sr))
    } else {
        let (fr_right, sr_right) = verify_sub_consistency(m - k, n - k, false, first_root, path)?;
        let left = path.next()?;
        let fr = hash_children(&left, &fr_right);
        let sr = hash_children(&left, &sr_right);
        Some((fr, sr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_record_hash(i: u64) -> [u8; 32] {
        *blake3::hash(&i.to_le_bytes()).as_bytes()
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root_hash(), [0u8; 32]);
    }

    #[test]
    fn single_leaf_tree() {
        let mut tree = MerkleTree::new();
        let r0 = fake_record_hash(0);
        tree.append(&r0);

        assert_eq!(tree.size(), 1);
        let expected = hash_leaf(&r0);
        assert_eq!(tree.root_hash(), expected);

        let proof = tree.inclusion_proof(0, &r0).unwrap();
        assert_eq!(proof.audit_path.len(), 0);
        assert!(verify_inclusion(&proof));
    }

    #[test]
    fn multi_leaf_inclusion_proofs() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<[u8; 32]> = (0..10).map(fake_record_hash).collect();

        for h in &hashes {
            tree.append(h);
        }

        assert_eq!(tree.size(), 10);

        for (idx, h) in hashes.iter().enumerate() {
            let proof = tree.inclusion_proof(idx as u64, h).unwrap();
            assert!(
                verify_inclusion(&proof),
                "Proof for leaf {} should be valid",
                idx
            );

            // Tamper with record hash
            let mut bad_proof = proof.clone();
            bad_proof.record_hash = hex::encode(fake_record_hash(999));
            assert!(!verify_inclusion(&bad_proof), "Tampered proof should fail");
        }
    }

    #[test]
    fn consistency_proof_between_snapshots() {
        let mut tree = MerkleTree::new();
        let hashes: Vec<[u8; 32]> = (0..20).map(fake_record_hash).collect();

        for h in &hashes[..8] {
            tree.append(h);
        }
        let m = tree.size();
        let root_at_8 = tree.root_hash_hex();

        for h in &hashes[8..20] {
            tree.append(h);
        }

        let proof = tree.consistency_proof(m).unwrap();
        assert_eq!(proof.first_size, 8);
        assert_eq!(proof.second_size, 20);
        assert_eq!(proof.first_root, root_at_8);
        assert_eq!(proof.second_root, tree.root_hash_hex());

        assert!(verify_consistency(&proof), "Consistency proof must verify");

        // Tamper with old root
        let mut bad_proof = proof.clone();
        bad_proof.first_root = hex::encode([0u8; 32]);
        assert!(
            !verify_consistency(&bad_proof),
            "Tampered consistency proof must fail"
        );
    }

    #[test]
    fn test_visual_nodes_structure() {
        let mut tree = MerkleTree::new();
        assert!(tree.visual_nodes().is_empty());

        let h0 = fake_record_hash(0);
        tree.append(&h0);
        let nodes1 = tree.visual_nodes();
        assert_eq!(nodes1.len(), 1);
        assert_eq!(nodes1[0].leaf_index, Some(0));
        assert_eq!(nodes1[0].hash, hash_leaf(&h0));
        assert_eq!(nodes1[0].hash, tree.root_hash());
        assert!(nodes1[0].left.is_none());
        assert!(nodes1[0].right.is_none());

        let h1 = fake_record_hash(1);
        let h2 = fake_record_hash(2);
        tree.append(&h1);
        tree.append(&h2);
        let nodes3 = tree.visual_nodes();
        assert_eq!(nodes3.len(), 5);
        // Root matches tree root
        assert_eq!(nodes3[0].hash, tree.root_hash());
        assert!(nodes3[0].leaf_index.is_none());
        assert!(nodes3[0].left.is_some());
        assert!(nodes3[0].right.is_some());
    }
}
