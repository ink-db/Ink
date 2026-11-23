# 0003 — Ed25519 Signatures, Merkle Tree, and Inclusion Proofs

**Date:** 2026-11-18  
**Area:** Integrity

## Summary

Added Ed25519-signed records, BLAKE3 Merkle leaves and internal nodes, inclusion and consistency proofs, record verification, and proof export support.

## Main components

- `ink-core/src/crypto.rs` and `ink-core/src/merkle.rs`.
- Signed record representation, proof APIs, CLI support, and tamper examples.

## Verification record

Signature, inclusion proof, consistency proof, and tamper-detection checks were recorded with this implementation.
