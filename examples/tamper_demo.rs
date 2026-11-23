//! Example demonstrating tamper detection in Ink.
//!
//! Run with:
//! ```bash
//! cargo run --example tamper_demo
//! ```

use ink_core::Store;
use std::fs;
use tempfile::tempdir;

fn main() -> anyhow::Result<()> {
    println!("Ink Tamper Detection Demo\n");

    let dir = tempdir()?;
    let db_path = dir.path();
    println!("1. Initializing new Ink database at: {:?}", db_path);
    let mut store = Store::init(db_path)?;

    println!("\n2. Appending 3 financial records to \"sales\":");
    let r0 = store.append(
        "sales",
        br#"{"invoice": 101, "customer": "Acme Corp", "amount": 1500}"#,
    )?;
    println!("   Record #{} [hash: {}]", r0.id, r0.hash_hex());

    let r1 = store.append(
        "sales",
        br#"{"invoice": 102, "customer": "Beta Ltd", "amount": 2500}"#,
    )?;
    println!("   Record #{} [hash: {}]", r1.id, r1.hash_hex());

    let r2 = store.append(
        "sales",
        br#"{"invoice": 103, "customer": "Gamma Inc", "amount": 4200}"#,
    )?;
    println!("   Record #{} [hash: {}]", r2.id, r2.hash_hex());

    println!("\n3. Running cryptographic verification on unmodified database:");
    let verify1 = store.verify_table("sales")?;
    println!("   Records checked: {}", verify1.records_checked);
    println!("   Integrity valid: {}", verify1.is_valid);
    assert!(verify1.is_valid);
    println!("   Result: [OK] Cryptographic hash chain is fully intact.\n");

    println!("4. Simulating malicious tampering by an administrator on disk...");
    let seg_path = db_path.join("segments/sales/seg_000000.ink");
    let mut raw_bytes = fs::read(&seg_path)?;

    // Locate the invoice 101 payload and change amount 1500 -> 9500
    let needle = b"\"amount\": 1500";
    let pos = raw_bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("payload needle found in segment file");

    println!(
        "   Target found at file offset {}: altering byte '1' to '9'",
        pos + 10
    );
    raw_bytes[pos + 10] = b'9'; // "1500" -> "9500"
    fs::write(&seg_path, &raw_bytes)?;
    println!("   Disk write completed: file now contains altered data.\n");

    println!("5. Running cryptographic verification after tampering:");
    let verify2 = store.verify_table("sales")?;
    println!("   Integrity valid: {}", verify2.is_valid);

    if !verify2.is_valid {
        println!(
            "   [ALERT] TAMPERING DETECTED! Found {} violation(s):",
            verify2.errors.len()
        );
        for (i, err) in verify2.errors.iter().enumerate() {
            println!("     {}. [{:?}] {}", i + 1, err.kind, err.description);
        }
    }

    println!("\nConclusion: Even with direct raw byte access to the disk files,");
    println!("any alteration violates the cryptographic seal and is immediately detected.");

    Ok(())
}
