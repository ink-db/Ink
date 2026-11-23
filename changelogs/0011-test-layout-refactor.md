# 0011 — Workspace Test Layout Refactor

**Date:** 2026-11-22  
**Area:** Maintenance

## Summary

Aligned Rust unit, integration, property, and tamper tests with the workspace crate boundaries. Unit tests were placed alongside their implementation; cross-component tests remain under crate-level `tests/` directories.

## Main components

- `ink-proto` codec, frame, and message tests.
- Ink Browser settings, backend, connection, and app tests.
- Merkle tree test iteration cleanup.

## Verification record

The original entry records 90 successful tests before and after the refactor, with clean lint and formatting results.
