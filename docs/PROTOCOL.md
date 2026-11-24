# Ink Wire Protocol Reference (IWP/1.0)

**Protocol version:** `1` (`0x01`)
**Transport in the current server:** TCP
**Integer encoding:** Little-endian

IWP uses binary frames for authentication, IQL requests, record streaming, append reservations, Merkle proofs, and heartbeat messages. The codec is implemented in `ink-proto`; transport and session handling are implemented in `ink-client` and `ink-server`.

## Frame layout

A frame contains an 18-byte header, a payload of at most 64 MiB, and a four-byte payload checksum. Header and payload checksums use CRC32.

| Offset | Size | Field | Description |
|---|---:|---|---|
| `0..3` | 3 | Magic | ASCII `INK` |
| `3` | 1 | Version | `0x01` |
| `4` | 1 | Type | Frame type identifier |
| `5` | 1 | Flags | EOS (`0x01`) and compressed (`0x02`) bits |
| `6..10` | 4 | Stream ID | Unsigned 32-bit correlation identifier |
| `10..14` | 4 | Payload length | Unsigned 32-bit byte count, maximum 64 MiB |
| `14..18` | 4 | Header CRC32-C | Checksum over header bytes `0..14` |
| `18..18+L` | `L` | Payload | Encoded message data |
| `18+L..22+L` | 4 | Payload CRC32-C | Checksum over the payload |

The complete frame length is `22 + L` bytes. Invalid magic, version, frame type, payload bounds, or checksums produce codec errors.

## Frame types

| Value | Name | Direction | Meaning |
|---:|---|---|---|
| `0x01` | `HELLO_REQ` | Client to server | Public key, client protocol version, and capability bits |
| `0x02` | `CHALLENGE` | Server to client | Database ID, nonce, session ID, and authentication timeout |
| `0x03` | `AUTH_RESP` | Client to server | Session ID and Ed25519 challenge signature |
| `0x04` | `AUTH_OK` | Server to client | Session ID, server version, and role data |
| `0x05` | `AUTH_FAIL` | Server to client | Error code and reason |
| `0x10` | `QUERY_REQ` | Client to server | IQL statement |
| `0x11` | `ROW_HEADER` | Server to client | Result column names |
| `0x12` | `ROW_DATA` | Server to client | Result row |
| `0x13` | `QUERY_COMPLETE` | Server to client | Query completion summary |
| `0x14` | `REQ_CANCEL` | Client to server | Request cancellation |
| `0x15` | `APPEND_INIT` | Client to server | Append table and payload |
| `0x16` | `APPEND_CHALLENGE` | Server to client | Reserved ID, timestamp, previous hash, and canonical hash |
| `0x17` | `APPEND_COMMIT` | Client to server | Author signature for the reserved record |
| `0x20` | `STREAM_CHUNK` | Server to client | Streamed result chunk |
| `0x21` | `STREAM_ACK` | Client to server | Stream flow-control acknowledgment |
| `0x24` | `TREE_HEAD_REQ` | Client to server | Merkle tree head request |
| `0x25` | `TREE_HEAD_RESP` | Server to client | Tree size and root hash |
| `0x26` | `PROOF_REQ` | Client to server | Inclusion proof request |
| `0x27` | `PROOF_RESP` | Server to client | Inclusion proof response |
| `0x30..0x33` | `REPL_*` | Peer nodes | Replication frame types defined by the codec |
| `0x3A` | `HEARTBEAT_PING` | Either direction | Heartbeat request |
| `0x3B` | `HEARTBEAT_PONG` | Either direction | Heartbeat response |

The codec recognizes replication frame identifiers. The current workspace does not provide an operational replication service.

## Authentication messages

`HELLO_REQ` encodes a 32-byte client public key, a 16-bit protocol version, and 32-bit capability flags. `CHALLENGE` encodes a 16-byte database ID, a 32-byte nonce, a 16-byte session ID, and a 32-bit timeout. `AUTH_RESP` carries the session ID and a 64-byte Ed25519 signature. `AUTH_OK` carries the session ID, server version, and a length-prefixed roles JSON string. `AUTH_FAIL` carries a 16-bit error code and a length-prefixed UTF-8 reason.

The challenge digest binds the database ID, session ID, and server nonce under the `INK-AUTH-v1` domain tag. The current TCP transport does not provide TLS channel binding or transport encryption.

## Query and append messages

`QUERY_REQ` contains a 32-bit byte length followed by the UTF-8 IQL statement. Row headers and row data use their message encoders in `ink-proto/src/messages.rs`.

The append exchange is represented by `APPEND_INIT`, `APPEND_CHALLENGE`, and `APPEND_COMMIT`. The challenge contains the server-assigned record fields used in the canonical record hash; the commit contains the author's Ed25519 signature.

## Merkle proof messages

`TREE_HEAD_REQ` and `TREE_HEAD_RESP` carry the tree size and current root hash. `PROOF_REQ` and `PROOF_RESP` encode record inclusion proof data. The codec defines these message types; availability through a server connection depends on the corresponding server handler.

## Message encoding details

All integer fields use little-endian encoding. Message payloads use fixed-width fields or length-prefixed byte sequences as defined by their typed encoders in `ink-proto/src/messages.rs`. The frame codec is the source of truth for exact byte encodings.
