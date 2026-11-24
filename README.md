# Ink

Ink is an append-only database written in Rust. Records are signed with Ed25519, linked by BLAKE3 hashes, and committed to a Merkle tree. Corrections are represented as new records that refer to earlier records.

## Capabilities

- Append-only storage with per-table segments and rebuildable indexes.
- IQL parsing and evaluation for reading, aggregation, verification, and corrections.
- Ed25519 identities and signed access-control records.
- A binary TCP protocol and client shell.
- Ink Browser, a native desktop interface for local database access, record browsing, query execution, integrity verification, and Merkle proofs.

## Workspace

| Package | Purpose |
|---|---|
| `ink-core` | Storage, hashing, signatures, Merkle structures, and access registry |
| `ink-query` | IQL parser, evaluator, and authorization gate |
| `ink-proto` | Binary frame and message encoding |
| `ink-client` | Client connection, signing, and shell |
| `ink-server` | CLI and TCP daemon |
| `ink-browser` | Native desktop application |

## Reference

- [Getting Started](docs/GETTING_STARTED.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Storage format](docs/FORMAT.md)
- [Query language](docs/QUERY_LANGUAGE.md)
- [Wire protocol](docs/PROTOCOL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Change index](changelogs/README.md)

Ink is tamper-evident. It does not encrypt stored payloads or protect files from an administrator with direct operating-system access.

The workspace includes a public sample database in [examples/demo-database](examples/demo-database) for viewing the global Merkle tree in Ink Browser.
