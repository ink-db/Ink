//! Client Ed25519 key loading, encrypted `.inkkey` envelopes, and memory hygiene.

use crate::error::ClientError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ink_core::Keypair;
use rand_core::{OsRng, RngCore};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Magic bytes for passphrase-encrypted client key files: ASCII "INKKEY01".
pub const INKKEY_MAGIC: [u8; 8] = [0x49, 0x4E, 0x4B, 0x4B, 0x45, 0x59, 0x30, 0x31];

/// Default Argon2id memory cost in KiB (64 MiB).
pub const DEFAULT_ARGON2_M_COST: u32 = 65536;

/// Default Argon2id iteration count.
pub const DEFAULT_ARGON2_T_COST: u32 = 3;

/// Default Argon2id parallelism degree.
pub const DEFAULT_ARGON2_P_COST: u32 = 4;

/// Load an Ed25519 keypair from a file, auto-detecting `.inkkey` encrypted envelopes vs raw keys.
pub fn load_key(path: &Path, passphrase: Option<&str>) -> Result<Keypair, ClientError> {
    let content = fs::read(path).map_err(|e| {
        ClientError::KeyError(format!("Failed to read key file {}: {}", path.display(), e))
    })?;

    // Check if it matches INKKEY encrypted envelope
    if content.len() == 136 && content.starts_with(&INKKEY_MAGIC) {
        let pass = passphrase.ok_or_else(|| {
            ClientError::KeyError(format!(
                "Key file {} is encrypted with Argon2id; passphrase is required",
                path.display()
            ))
        })?;
        return decrypt_inkkey(&content, pass);
    }

    // Otherwise, try standard unencrypted Keypair load from ink_core
    Keypair::load_from_file(path).map_err(|e| {
        ClientError::KeyError(format!(
            "Failed to load unencrypted key {}: {}",
            path.display(),
            e
        ))
    })
}

/// Decrypt an encrypted `.inkkey` 136-byte binary payload.
pub fn decrypt_inkkey(data: &[u8], passphrase: &str) -> Result<Keypair, ClientError> {
    if data.len() != 136 {
        return Err(ClientError::KeyError(format!(
            "Invalid .inkkey file size: expected 136 bytes, found {}",
            data.len()
        )));
    }

    if data[0..8] != INKKEY_MAGIC {
        return Err(ClientError::KeyError("Invalid .inkkey magic header".into()));
    }

    let kdf_alg = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let cipher_alg = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    if kdf_alg != 1 || cipher_alg != 1 {
        return Err(ClientError::KeyError(format!(
            "Unsupported algorithm suite in .inkkey: kdf={}, cipher={}",
            kdf_alg, cipher_alg
        )));
    }

    let salt = &data[16..32];
    let m_cost = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let t_cost = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
    let p_cost = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
    let nonce = &data[44..56];
    let _expected_pubkey = &data[56..88];
    let ciphertext_with_tag = &data[88..136]; // 32 bytes ciphertext + 16 bytes tag

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| ClientError::KeyError(format!("Invalid Argon2 parameters: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived_key)
        .map_err(|e| ClientError::KeyError(format!("KDF derivation failed: {}", e)))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let mut decrypted_seed = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext_with_tag)
        .map_err(|_| {
            derived_key.zeroize();
            ClientError::KeyError(
                "Decryption failed: incorrect passphrase or corrupted key file".into(),
            )
        })?;

    derived_key.zeroize();

    if decrypted_seed.len() != 32 {
        decrypted_seed.zeroize();
        return Err(ClientError::KeyError(
            "Decrypted seed length is not 32 bytes".into(),
        ));
    }

    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&decrypted_seed);
    decrypted_seed.zeroize();

    let kp = Keypair::from_bytes(&seed_arr);
    seed_arr.zeroize();

    Ok(kp)
}

/// Save an Ed25519 keypair into an encrypted `.inkkey` file using Argon2id + ChaCha20-Poly1305.
pub fn save_encrypted_key(
    path: &Path,
    keypair: &Keypair,
    passphrase: &str,
) -> Result<(), ClientError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let params = Params::new(
        DEFAULT_ARGON2_M_COST,
        DEFAULT_ARGON2_T_COST,
        DEFAULT_ARGON2_P_COST,
        Some(32),
    )
    .map_err(|e| ClientError::KeyError(format!("Argon2 params error: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| ClientError::KeyError(format!("KDF derivation failed: {}", e)))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let seed = keypair.signing_key().to_bytes();

    let ciphertext_with_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), seed.as_ref())
        .map_err(|e| {
            derived_key.zeroize();
            ClientError::KeyError(format!("Encryption failed: {}", e))
        })?;

    derived_key.zeroize();

    if ciphertext_with_tag.len() != 48 {
        return Err(ClientError::KeyError(
            "Unexpected ciphertext tag length".into(),
        ));
    }

    let mut out = [0u8; 136];
    out[0..8].copy_from_slice(&INKKEY_MAGIC);
    out[8..12].copy_from_slice(&1u32.to_le_bytes()); // Argon2id
    out[12..16].copy_from_slice(&1u32.to_le_bytes()); // ChaCha20Poly1305
    out[16..32].copy_from_slice(&salt);
    out[32..36].copy_from_slice(&DEFAULT_ARGON2_M_COST.to_le_bytes());
    out[36..40].copy_from_slice(&DEFAULT_ARGON2_T_COST.to_le_bytes());
    out[40..44].copy_from_slice(&DEFAULT_ARGON2_P_COST.to_le_bytes());
    out[44..56].copy_from_slice(&nonce);
    out[56..88].copy_from_slice(&keypair.public_key());
    out[88..136].copy_from_slice(&ciphertext_with_tag);

    fs::write(path, out)
        .map_err(|e| ClientError::KeyError(format!("Failed to write encrypted key file: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_inkkey_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("alice.inkkey");
        let kp = Keypair::generate();
        let passphrase = "correct-horse-battery-staple";

        save_encrypted_key(&key_path, &kp, passphrase).unwrap();
        assert_eq!(fs::metadata(&key_path).unwrap().len(), 136);

        // Load with correct passphrase
        let loaded = load_key(&key_path, Some(passphrase)).unwrap();
        assert_eq!(kp.public_key(), loaded.public_key());

        // Attempt load with wrong passphrase
        let wrong_err = load_key(&key_path, Some("wrong-password")).unwrap_err();
        match wrong_err {
            ClientError::KeyError(_) => {}
            other => panic!("Expected KeyError on bad passphrase, got {:?}", other),
        }

        // Attempt load with no passphrase
        let missing_err = load_key(&key_path, None).unwrap_err();
        match missing_err {
            ClientError::KeyError(_) => {}
            other => panic!("Expected KeyError on missing passphrase, got {:?}", other),
        }
    }
}
