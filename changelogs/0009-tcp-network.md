# 0009 — TCP Network Layer Implementation

**Date:** 2026-11-22  
**Area:** Network

## Summary

Added the IWP frame codec, TCP server, Ed25519 challenge-response authentication, rate limiting, two-step signed append leases, query transport, and the interactive client shell.

## Main components

- `ink-proto` message, frame, codec, and error modules.
- `ink-server` TCP daemon and `ink-client` connection and shell modules.
- Network integration coverage and protocol documentation.

## Verification record

The original entry records 81 successful test checks across the network and workspace components.
