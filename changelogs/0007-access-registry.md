# 0007 — Access Registry and Query Gatekeeper

**Date:** 2026-11-21  
**Area:** Access control

## Summary

Implemented the `_ink_access` record model, materialized ACL registry, Ed25519-authenticated grants, revocations, and centralized query authorization.

## Main components

- `ink-core/src/auth.rs` and access-control integration in `store.rs`.
- `ink-query/src/evaluator.rs` authorization gate.
- CLI access management commands and documentation.

## Verification record

Access grant, revocation, and query authorization coverage was recorded with the implementation.
