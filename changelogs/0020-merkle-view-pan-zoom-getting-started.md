# 0020 — Merkle View Pan/Zoom, Inclusion Path Highlight, and Getting Started Guide

**Date:** 2026-11-24  
**Area:** Desktop / Documentation / Integrity tools

## Summary

Significantly enhanced the Merkle tree visualization in `ink-browser` with adaptive zoom, drag-to-pan canvas navigation, baseline leaf alignment, record search, and interactive Merkle inclusion proof path highlighting. Added an English Getting Started guide in `docs/GETTING_STARTED.md`.

## Main components

- `ink-browser/src/ui/merkle.rs`:
  - Zoom controls (15% to 250% slider, `+`/`-`, `100%`, and dynamic `Fit View`).
  - Native 2D scrollbars combined with click-and-drag canvas panning.
  - "Align leaves at bottom" layout option to keep all record leaves on a clean horizontal baseline.
  - Record finder (`Find record #`) with direct scroll and node selection.
  - Interactive Merkle inclusion proof path tracing: selecting any node highlights its path to the root in gold and sibling audit nodes in cyan.
  - Node inspector card with full BLAKE3 hash display, clipboard copy, and parent/child navigation links.
  - Anti-clutter pill badges with level-of-detail culling when zoomed out.
  - Unit tests for layout positioning, aligned leaves, and parent/audit path calculation.
- `ink-browser/src/ui/verify.rs` and `ink-browser/src/ui/proofs.rs`:
  - Added unit test suites verifying default view state, proof file reading, size bounds, and backend execution.
- `ink-core/src/merkle.rs`:
  - Added unit test for `MerkleTree::visual_nodes`.
- `docs/GETTING_STARTED.md`:
  - Comprehensive guide covering compilation, CLI usage (`ink`), GUI workflow (`ink-browser`), network service (`ink-server`), client shell (`ink-client`), access control, and the sample database.
- `docs/QUERY_LANGUAGE.md`:
  - Added explicit language tags (`sql`, `ebnf`, `text`) to all code fences.

## Verification record

- Tests: 114 tests passed, 0 failed across workspace (`cargo test --workspace`).
- Linter: `cargo clippy --workspace --all-targets -- -D warnings` passed with 0 warnings.
- Formatter: `cargo fmt --check` passed cleanly across all packages.
