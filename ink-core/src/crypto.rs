//! Cryptographic signing, verification, and key management using Ed25519.
//!
//! Every block/record in Ink can be cryptographically signed by an author.
//! The public key (32 bytes) is stored in the record's `author` field, and
//! the signature (64 bytes) is stored in `signature`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::fs;
use std::path::Path;

use crate::error::{InkError, Result};

/// All-zero 32-byte public key indicating an anonymous / unsigned author.
pub const ANONYMOUS_AUTHOR: [u8; 32] = [0u8; 32];

/// All-zero 64-byte signature indicating an unsigned record.
pub const EMPTY_SIGNATURE: [u8; 64] = [0u8; 64];

/// An Ed25519 keypair consisting of a private signing key and public verifying key.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &hex::encode(self.public_key()))
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl Keypair {
    /// Generate a fresh, cryptographically secure Ed25519 keypair using OS entropy.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load a keypair from raw 32 private key seed bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load a keypair from a file containing 32 raw bytes or a 64-character hex string.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read(path)?;
        // If 32 bytes binary
        if content.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&content);
            return Ok(Self::from_bytes(&arr));
        }

        // Try parsing as hex string
        let s = std::str::from_utf8(&content)
            .map_err(|e| InkError::CorruptRecord {
                offset: 0,
                path: path.to_string_lossy().to_string(),
                reason: format!("invalid UTF-8 in key file: {e}"),
            })?
            .trim();

        let decoded = hex::decode(s).map_err(|e| InkError::CorruptRecord {
            offset: 0,
            path: path.to_string_lossy().to_string(),
            reason: format!("invalid hex in key file: {e}"),
        })?;

        if decoded.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            Ok(Self::from_bytes(&arr))
        } else {
            Err(InkError::CorruptRecord {
                offset: 0,
                path: path.to_string_lossy().to_string(),
                reason: format!("key file must be 32 bytes (got {})", decoded.len()),
            })
        }
    }

    /// Save the private key as a hex string to a file.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let hex_str = hex::encode(self.signing_key.to_bytes());
        fs::write(path, hex_str.as_bytes())?;
        Ok(())
    }

    /// Return the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return the hex representation of the public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Sign a 32-byte record hash, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, hash: &[u8; 32]) -> [u8; 64] {
        let sig = self.signing_key.sign(hash);
        sig.to_bytes()
    }

    /// Return the raw 32-byte private key seed.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Return a reference to the underlying `SigningKey`.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Verify an Ed25519 signature over a 32-byte message hash against a public key.
///
/// Returns `Ok(())` if the signature is valid.
/// If `author` is `ANONYMOUS_AUTHOR` and `signature` is `EMPTY_SIGNATURE`,
/// verification succeeds (unsigned / anonymous record compatibility).
pub fn verify_signature(
    author: &[u8; 32],
    record_hash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    if author == &ANONYMOUS_AUTHOR {
        if signature == &EMPTY_SIGNATURE {
            return Ok(());
        }
        return Err(InkError::CorruptRecord {
            offset: 0,
            path: String::new(),
            reason: "anonymous author has non-empty signature".to_string(),
        });
    }

    let verifying_key = VerifyingKey::from_bytes(author).map_err(|e| InkError::CorruptRecord {
        offset: 0,
        path: String::new(),
        reason: format!("invalid public key bytes: {e}"),
    })?;

    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(record_hash, &sig)
        .map_err(|e| InkError::CorruptRecord {
            offset: 0,
            path: String::new(),
            reason: format!("signature verification failed: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sign_and_verify_valid() {
        let kp = Keypair::generate();
        let hash = blake3::hash(b"some record").into();
        let sig = kp.sign(&hash);
        let pubkey = kp.public_key();

        assert!(verify_signature(&pubkey, &hash, &sig).is_ok());
    }

    #[test]
    fn keypair_verify_detects_wrong_hash() {
        let kp = Keypair::generate();
        let hash1 = blake3::hash(b"record 1").into();
        let hash2 = blake3::hash(b"record 2").into();
        let sig = kp.sign(&hash1);
        let pubkey = kp.public_key();

        assert!(verify_signature(&pubkey, &hash2, &sig).is_err());
    }

    #[test]
    fn keypair_verify_detects_wrong_key() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let hash = blake3::hash(b"record").into();
        let sig = kp1.sign(&hash);
        let pubkey2 = kp2.public_key();

        assert!(verify_signature(&pubkey2, &hash, &sig).is_err());
    }

    #[test]
    fn anonymous_signature_valid_when_empty() {
        let hash = [0u8; 32];
        assert!(verify_signature(&ANONYMOUS_AUTHOR, &hash, &EMPTY_SIGNATURE).is_ok());
    }

    #[test]
    fn anonymous_signature_invalid_when_non_empty() {
        let hash = [0u8; 32];
        let mut bad_sig = [0u8; 64];
        bad_sig[0] = 1;
        assert!(verify_signature(&ANONYMOUS_AUTHOR, &hash, &bad_sig).is_err());
    }
}
