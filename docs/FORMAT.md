# Ink On-Disk Format Reference

**Format version:** `0`
**Integer encoding:** Little-endian

This document describes the files written by the current `ink-core` implementation. The record segment files are authoritative; database metadata is reconstructed or refreshed from them when a database is opened.

## Directory layout

```text
<data_dir>/
├── ink.meta
└── segments/
    └── <table_name>/
        ├── seg_000000.ink
        ├── seg_000001.ink
        └── ...
```

A segment uses the `.ink` extension while writable and `.sealed` after sealing. Table indexes and the global Merkle tree are reconstructed in memory from segment records; the current implementation does not persist a Merkle state file or an index snapshot.

## Database metadata

`ink.meta` is JSON with these fields:

| Field | Type | Meaning |
|---|---|---|
| `format_version` | `u16` | Database format version |
| `created_at` | `i64` | Creation time in microseconds since Unix epoch |
| `database_id` | string | UUID identifying the database |
| `segment_size_bytes` | `u64` | Segment size limit |
| `hash_algorithm` | string | Current value: `blake3` |
| `signature_algorithm` | string | Current value: `ed25519` |
| `next_global_id` | `u64` | Cached next record ID; recalculated from segment files on open |

## Segment header

Each segment begins with a 32-byte header.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| `0` | 8 | Magic `INKSEGMT` | ASCII |
| `8` | 2 | Segment format version | Little-endian `u16` |
| `10` | 2 | Flags | Reserved, zero |
| `12` | 8 | Segment sequence | Little-endian `u64` |
| `20` | 8 | Creation timestamp | Little-endian `i64`, microseconds |
| `28` | 4 | Reserved | Zero |

## Record frame

Each record follows the segment header or preceding frame. The fixed frame overhead is 202 bytes, in addition to table and payload bytes.

| Relative offset | Size | Field | Encoding |
|---:|---:|---|---|
| `0` | 4 | Total frame length | Little-endian `u32`, including this field |
| `4` | 1 | Frame version | `u8`, current value `0` |
| `5` | 1 | Flags | Bit `0x01` marks a correction |
| `6` | 8 | Global record ID | Little-endian `u64` |
| `14` | 8 | Timestamp | Little-endian `i64`, microseconds since Unix epoch |
| `22` | 2 | Table name length | Little-endian `u16` |
| `24` | `N` | Table name | UTF-8 |
| `24+N` | 2 | Author key length | Little-endian `u16`, value `32` |
| `26+N` | 32 | Author public key | Ed25519 bytes |
| `58+N` | 8 | Correction target | Little-endian `u64`; all bits set means none |
| `66+N` | 4 | Payload length | Little-endian `u32` |
| `70+N` | `D` | Payload | JSON bytes in format version `0` |
| `70+N+D` | 32 | Previous table hash | BLAKE3 bytes |
| `102+N+D` | 32 | Record hash | BLAKE3 bytes |
| `134+N+D` | 64 | Author signature | Ed25519 signature over record hash |
| `198+N+D` | 4 | Frame checksum | Little-endian CRC32 |

`N` is the table-name byte length and `D` is the payload byte length. The total length is `202 + N + D`.

## Canonical record hash

`record_hash` is BLAKE3 over the following fields in order:

```text
record_id      u64 little-endian
timestamp      i64 little-endian
 table_len      u16 little-endian
 table_name     UTF-8 bytes
 author_pubkey  32 bytes
 flags          u8
 correction_of  u64 little-endian; all bits set when absent
 data_len       u32 little-endian
 data           payload bytes
 prev_hash      32 bytes
```

The record hash and signature are excluded from their own hash input. `prev_hash` links each table to its preceding record. The first record in each table uses a zero hash.

## Merkle tree

Each global Merkle leaf is `BLAKE3(0x00 || record_hash)`. Internal nodes use `BLAKE3(0x01 || left_hash || right_hash)`. The tree follows the Certificate Transparency recursive split rule, with the largest power of two smaller than the subtree size on the left. Leaves are ordered by global record ID. The root hash is the tree head, and the current implementation rebuilds the tree from the records when a database is opened.

## Version compatibility

The current implementation writes format version `0` and rejects a database with a version newer than the implementation supports. Downgrade compatibility is not provided.

## Access registry records

Role grants and revocations are append-only records in the reserved `_ink_access` table. Payloads are JSON tagged by `action`. A grant contains the subject key, label, role, table scopes, optional expiration, and granting administrator key. A revocation contains the subject key, optional role scope, table scope, reason, and revoking administrator key. The genesis administrator grant is the initial registry record.

## Encrypted client key file

The `.inkkey` envelope is 136 bytes. It uses Argon2id key derivation and ChaCha20-Poly1305 authenticated encryption.

| Offset | Size | Field |
|---:|---:|---|
| `0` | 8 | Magic `INKKEY01` |
| `8` | 4 | KDF identifier (`1` = Argon2id) |
| `12` | 4 | Cipher identifier (`1` = ChaCha20-Poly1305) |
| `16` | 16 | Random KDF salt |
| `32` | 4 | Argon2id memory cost in KiB |
| `36` | 4 | Argon2id iteration count |
| `40` | 4 | Argon2id parallelism |
| `44` | 12 | AEAD nonce |
| `56` | 32 | Ed25519 public key |
| `88` | 32 | Encrypted private key seed |
| `120` | 16 | Poly1305 authentication tag |

## Network frames

The TCP frame format and message identifiers are documented in [PROTOCOL.md](PROTOCOL.md).

