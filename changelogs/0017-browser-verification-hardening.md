# 0017 — Verification Results and Proof File Handling

**Date:** 2026-11-23  
**Area:** Desktop integrity tools

## Summary

Improved integrity results with the actual first affected record ID, bounded offline proof file reads to 64 KiB, and clarified that a proof's embedded root is compared with a trusted tree head outside the file.

## Main components

- `ink-browser/src/backend/local.rs`.
- `ink-browser/src/ui/verify.rs`.
- `ink-browser/src/ui/proofs.rs`.

## Verification record

No local tests or builds were run.
