# Ink Architecture

## Overview

Ink is an append-only database implemented as a Rust Cargo workspace. Each stored record has a database-wide sequential ID, a per-table hash-chain link, an Ed25519 signature, and a leaf in a global Merkle tree. Corrections are additional signed records that reference earlier records.

## Workspace components

| Package | Responsibility |
|---|---|
| `ink-core` | Segment storage, record serialization, BLAKE3 hash chains, signatures, Merkle proofs, and the access registry |
| `ink-query` | IQL lexer, parser, evaluator, and statement authorization |
| `ink-proto` | Binary TCP frame codec, message encodings, and protocol error types |
| `ink-client` | Client connection, signing, and interactive shell |
| `ink-server` | `ink` command-line program and TCP server |
| `ink-browser` | Native desktop application and local database backend |

The workspace manifest is at the repository root. The project overview is in `README.md`; `SKILLS.md` contains project metadata. Format, query, protocol, and security references are in `docs/`.

## Record and storage model

Records are stored in per-table segment files under `<data_dir>/segments/`. Each record contains a global ID, timestamp, table name, author public key, payload, previous table hash, record hash, signature, and optional correction metadata. Segment frames include length and checksum fields. Index data is reconstructed from the segment records when a store is opened.

`ink.meta` stores the database identifier, format version, segment size, and algorithm names. The record segments are the source of truth. The global Merkle tree is reconstructed in global ID order when a database is opened.

## Integrity model

BLAKE3 links records within each table. Ed25519 signatures associate records with author keys. A global Merkle tree commits to record hashes in database-wide insertion order. The storage library exposes table and database verification, inclusion proofs, and consistency proofs.

These mechanisms provide tamper evidence when compared with a trusted tree head. They do not encrypt payloads or prevent an operating-system administrator from modifying database files.

## Query and authorization model

IQL supports append-only records, reads, corrections, history, verification, aggregations, table inspection, status queries, and access management. The parser and evaluator are in `ink-query`; authorization uses signed records in the reserved `_ink_access` table.

The access registry defines `admin`, `writer`, `reader`, and `auditor` roles. Administrative access management is separate from business-data read and write permissions. The current authorization and record formats are described in `docs/QUERY_LANGUAGE.md` and `docs/FORMAT.md`.

## Network model

`ink-proto` encodes IWP frames with a fixed header, bounded payload length, and checksums. `ink-server` and `ink-client` provide the TCP service and client implementation. The current TCP transport is unencrypted; TLS configuration fields are not connected to transport encryption. `docs/PROTOCOL.md` describes message layouts and `AUDIT.md` records the current security findings.

## Desktop application

Ink Browser uses `eframe` and `egui`. Its local backend opens a database directory and acquires an advisory lock. The connected interface includes record browsing, IQL execution, integrity verification, inclusion-proof export and offline verification, and a global Merkle tree view. The tree view displays leaf records, internal hashes, and the root for databases with up to 512 records. Access and Status panels are present in navigation.

The Windows executable is configured for the GUI subsystem. The `ink` command-line program retains its console subsystem.

## Build organization

The GitHub Actions workflow builds the Rust packages independently and builds the Windows desktop application on a Windows runner. Package manifests define the workspace dependencies and executable targets.
