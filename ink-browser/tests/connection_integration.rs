//! Integration tests for connection handling with encrypted keys.

use ink_browser::{Backend, LocalBackend};
use ink_client::save_encrypted_key;
use ink_core::{Keypair, Store};
use tempfile::tempdir;

#[test]
fn test_connection_with_encrypted_inkkey() {
    let dir = tempdir().expect("tempdir");
    let admin_kp = Keypair::generate();
    let (_store, _) =
        Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("Init failed");

    // Save encrypted .inkkey file
    let key_path = dir.path().join("admin.inkkey");
    let passphrase = "correct_horse_battery_staple";
    save_encrypted_key(&key_path, &admin_kp, passphrase).expect("Save encrypted key failed");

    // 1. Loading with incorrect passphrase fails
    let bad_load = ink_client::load_key(&key_path, Some("wrong_pass"));
    assert!(bad_load.is_err());

    // 2. Loading with correct passphrase succeeds
    let loaded_kp = ink_client::load_key(&key_path, Some(passphrase)).expect("Load key failed");
    assert_eq!(loaded_kp.public_key(), admin_kp.public_key());

    // 3. Connect LocalBackend using decrypted key
    let backend = LocalBackend::open(dir.path(), loaded_kp).expect("Open failed");
    assert!(backend.session_info().is_admin());
}
