# 0002 — Storage Core, Hash Chain, Recovery, and CLI

**Date:** 2026-11-18  
**Area:** Storage

## Summary

Added append-only per-table segments, checksummed frames, global record IDs, BLAKE3 table hash chains, recovery scanning, indexes, and the `ink` initialization and record commands.

## Main components

- `ink-core/src/store.rs`, `segment.rs`, `record.rs`, and `index.rs`.
- `ink-server/src/main.rs` and the `tamper_demo` example.

## Verification record

Storage, recovery, and tamper-detection tests were recorded with this implementation.
