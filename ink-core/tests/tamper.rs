use ink_core::{Store, VerifyErrorKind};
use std::fs;
use tempfile::tempdir;

#[test]
fn tamper_detects_data_corruption() {
    let dir = tempdir().unwrap();
    let mut store = Store::init(dir.path()).unwrap();

    let _r0 = store.append("sales", b"{\"amount\": 100}").unwrap();
    let _r1 = store.append("sales", b"{\"amount\": 200}").unwrap();
    let _r2 = store.append("sales", b"{\"amount\": 300}").unwrap();

    // Verify initially passes
    let res = store.verify_table("sales").unwrap();
    assert!(res.is_valid);
    assert_eq!(res.records_checked, 3);

    // Now corrupt a byte in the middle of segment file for r1
    let seg_path = dir.path().join("segments/sales/seg_000000.ink");
    let mut data = fs::read(&seg_path).unwrap();

    // Find "200" in the raw file bytes and change it to "900"
    let needle = b"\"amount\": 200";
    let pos = data
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("should find payload in segment file");

    // Modify "200" to "900"
    data[pos + 10] = b'9';
    fs::write(&seg_path, &data).unwrap();

    // Reopen store from disk or verify directly
    let store_reopened = Store::open(dir.path()).unwrap();
    let res = store_reopened.verify_table("sales").unwrap();

    assert!(!res.is_valid, "Tampering should be detected");
    assert!(!res.errors.is_empty());
    // CRC or Hash mismatch should be reported
    let err = &res.errors[0];
    assert!(
        err.kind == VerifyErrorKind::CrcMismatch || err.kind == VerifyErrorKind::HashMismatch,
        "Expected CRC or hash mismatch, found {:?}",
        err.kind
    );
}

#[test]
fn tamper_detects_hash_tampering_when_crc_updated() {
    let dir = tempdir().unwrap();
    let mut store = Store::init(dir.path()).unwrap();

    store.append("sales", b"{\"amount\": 100}").unwrap();
    let _r1 = store.append("sales", b"{\"amount\": 200}").unwrap();

    let seg_path = dir.path().join("segments/sales/seg_000000.ink");
    let mut data = fs::read(&seg_path).unwrap();

    // Locate record 1's frame start
    // Offset for record 0: 32 (header)
    // Frame 0 size: 202 + 5 (table "sales") + 15 (data "{"amount": 100}") = 222
    // Frame 1 starts at 32 + 222 = 254
    let f1_offset = 32 + (202 + 5 + 15);
    let f1_len = u32::from_le_bytes(data[f1_offset..f1_offset + 4].try_into().unwrap()) as usize;

    // Tamper with payload byte inside frame 1
    // Data starts at 70 + table_len(5) = 75 from frame start
    data[f1_offset + 75 + 10] = b'9';

    // Recalculate CRC for this frame to simulate an attacker trying to forge CRC
    let new_crc = crc32fast::hash(&data[f1_offset..f1_offset + f1_len - 4]);
    data[f1_offset + f1_len - 4..f1_offset + f1_len].copy_from_slice(&new_crc.to_le_bytes());

    fs::write(&seg_path, &data).unwrap();

    // Now re-verify. CRC will pass, but record_hash will fail!
    let store_reopened = Store::open(dir.path()).unwrap();
    let res = store_reopened.verify_table("sales").unwrap();

    assert!(!res.is_valid, "Hash mismatch must be detected");
    assert_eq!(res.errors.len(), 1);
    assert_eq!(res.errors[0].kind, VerifyErrorKind::HashMismatch);
    assert_eq!(res.errors[0].record_id, 1);
}

#[test]
fn tamper_detects_chain_break_when_hash_forged() {
    let dir = tempdir().unwrap();
    let mut store = Store::init(dir.path()).unwrap();

    let r0 = store.append("sales", b"{\"amount\": 100}").unwrap();
    let r1 = store.append("sales", b"{\"amount\": 200}").unwrap();
    let _r2 = store.append("sales", b"{\"amount\": 300}").unwrap();

    let seg_path = dir.path().join("segments/sales/seg_000000.ink");
    let mut data = fs::read(&seg_path).unwrap();

    // Frame 1 offset:
    let f1_offset = 32 + (202 + 5 + 15);
    let f1_len = u32::from_le_bytes(data[f1_offset..f1_offset + 4].try_into().unwrap()) as usize;

    // Tamper data in frame 1
    data[f1_offset + 75 + 10] = b'9';

    // Attacker updates record_hash for frame 1 so record_hash check passes on frame 1
    let id1 = r1.id;
    let ts1 = r1.timestamp;
    let author1 = [0u8; 32];
    let flags1 = 0u8;
    let corr1 = None;
    let new_data = &data[f1_offset + 75..f1_offset + 75 + 15];
    let prev_hash1 = r0.record_hash;

    let forged_hash1 = ink_core::compute_record_hash(
        id1,
        ts1,
        "sales",
        &author1,
        flags1,
        corr1,
        new_data,
        &prev_hash1,
    );

    // Write forged hash into frame 1 (offset: 75 + 15 + 32 = 122 from frame start)
    let hash_start = f1_offset + 75 + 15 + 32;
    data[hash_start..hash_start + 32].copy_from_slice(&forged_hash1);

    // Update CRC for frame 1
    let new_crc = crc32fast::hash(&data[f1_offset..f1_offset + f1_len - 4]);
    data[f1_offset + f1_len - 4..f1_offset + f1_len].copy_from_slice(&new_crc.to_le_bytes());

    fs::write(&seg_path, &data).unwrap();

    // When verifying, frame 1's hash matches forged hash, BUT frame 2's prev_hash points to old r1.record_hash!
    // So frame 2 will fail with ChainBreak!
    let store_reopened = Store::open(dir.path()).unwrap();
    let res = store_reopened.verify_table("sales").unwrap();

    assert!(
        !res.is_valid,
        "Chain break must be detected on subsequent record"
    );
    assert!(!res.errors.is_empty());
    let chain_err = res
        .errors
        .iter()
        .find(|e| e.kind == VerifyErrorKind::ChainBreak)
        .expect("Should detect chain break");
    assert_eq!(chain_err.record_id, 2);
}

#[test]
fn tamper_detects_deletion_or_truncation() {
    let dir = tempdir().unwrap();
    let mut store = Store::init(dir.path()).unwrap();

    store.append("sales", b"{\"amount\": 100}").unwrap();
    store.append("sales", b"{\"amount\": 200}").unwrap();

    let seg_path = dir.path().join("segments/sales/seg_000000.ink");
    let data = fs::read(&seg_path).unwrap();

    // Truncate file right after record 0 (removing record 1 entirely)
    let f0_len = 202 + 5 + 15;
    let truncated_len = 32 + f0_len;
    fs::write(&seg_path, &data[..truncated_len]).unwrap();

    let store_reopened = Store::open(dir.path()).unwrap();
    assert_eq!(store_reopened.status().record_count, 1);
    assert_eq!(
        store_reopened
            .get_records_in_table("sales", None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn tamper_detects_signature_forgery() {
    use ink_core::Keypair;

    let dir = tempdir().unwrap();
    let mut store = Store::init(dir.path()).unwrap();
    let kp = Keypair::generate();

    let _r0 = store
        .append_signed("sales", b"{\"amount\": 100}", Some(&kp))
        .unwrap();

    let seg_path = dir.path().join("segments/sales/seg_000000.ink");
    let mut data = fs::read(&seg_path).unwrap();

    // In frame 0, tamper with signature bytes (starts at 154 from frame start, header is 32)
    // Offset in frame: 154..218
    let sig_byte = 32 + 154 + 5;
    data[sig_byte] ^= 0xFF;

    // Recalculate CRC so CRC passes
    let f0_len = 202 + 5 + 15;
    let new_crc = crc32fast::hash(&data[32..32 + f0_len - 4]);
    data[32 + f0_len - 4..32 + f0_len].copy_from_slice(&new_crc.to_le_bytes());
    fs::write(&seg_path, &data).unwrap();

    let store_reopened = Store::open(dir.path()).unwrap();
    let res = store_reopened.verify_table("sales").unwrap();

    assert!(!res.is_valid, "Signature forgery must be detected");
    let sig_err = res
        .errors
        .iter()
        .find(|e| e.kind == VerifyErrorKind::InvalidSignature)
        .expect("Should detect invalid signature");
    assert_eq!(sig_err.record_id, 0);
}
