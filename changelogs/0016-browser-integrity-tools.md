# 0016 — Browser Integrity Verification and Proof Tools

**Date:** 2026-11-23  
**Area:** Desktop

## Summary

Added database and table integrity views, inclusion proof creation and JSON export, offline inclusion proof verification, and Reader authorization for local verification and record proof export. Proof results include the Merkle root from the same tree snapshot.

## Main components

- `ink-browser/src/ui/verify.rs` and `ink-browser/src/ui/proofs.rs`.
- Backend proof root information and Reader access checks.
- Application tab integration.

## Verification record

No local test suite or build was run for this change.
