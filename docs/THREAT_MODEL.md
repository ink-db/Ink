# Ink Threat Model

**Version:** 0
**Status:** Security properties and implementation limits

Ink is a tamper-evident append-only database. Cryptographic checks can reveal changes to records and histories when a verifier has a trusted reference point. They do not prevent an administrator with direct storage access from replacing or deleting files.

## Protected Assets

| Asset | Description |
|---|---|
| Record content | Stored JSON payloads and their table association |
| Authorship | Public key and signature associated with each signed record |
| Ordering | Global record IDs and per-table hash chains |
| Inclusion | Merkle commitment to the record set at a given tree head |
| Access history | Signed grant and revocation records in `_ink_access` |

## Trust Boundaries

| Boundary | Security role |
|---|---|
| Signing key | Controls the identity that can author signed records |
| Running Ink process | Applies role and table authorization to application requests |
| Database files | Store plaintext payloads and cryptographic record metadata |
| External tree-head witness | Provides an independent historical reference for comparison |
| Independent verifier | Checks record signatures, hash chains, proofs, and known tree heads |

## Threat Summary

| Actor or event | Exposure | Existing protection or limit |
|---|---|---|
| Network observer | Can read and alter traffic on the current TCP transport | The current server and client use plain TCP; TLS configuration fields are not connected to the transport. Network confidentiality and server authentication are absent. |
| Unauthenticated remote client | Can attempt protocol handshakes and malformed requests | Challenge-response authentication, handshake timeout, connection cap, frame bound, and source-IP rate tracking are present. |
| Authorized writer | Can append within active writer grants | Signed append attribution and table-scoped checks associate records with a key. Expired append leases remain in the server's in-memory map until their tokens are submitted. |
| Authorized reader or writer | Can query within access scopes | The query gate applies role checks. Access-control initialization is inferred from active admin grants, so expiry of the final active admin grant can disable query authorization checks. |
| Database administrator with file access | Can inspect, alter, or delete database files | Payloads are plaintext at rest. Record hashes, signatures, and chains reveal many edits during verification, but total replacement or deletion without an external anchor is not detectable. |
| Compromised server process | Can read data and issue operations available to process memory | Records written before compromise remain independently verifiable; keys accessible to the process can be misused. |
| Lost or stolen signing key | Can prevent its owner from signing or enable impersonation | Encrypted `.inkkey` files can reduce offline theft risk. Grants remain active until expiry or revocation. |
| Simultaneous loss of all storage copies | Removes the only copies of records | Replication and external witnesses are design areas; the current workspace does not implement a replication service. |

## Cryptographic Properties

| Primitive | Use | Limitation |
|---|---|---|
| BLAKE3 | Record hashes, hash chains, and Merkle structures | No post-quantum security claim |
| Ed25519 | Record signatures and key identity | Long-term quantum resistance is not provided |
| CRC32-C | Frame corruption detection | Not an authenticity or tamper-resistance mechanism |

## Data and Process Boundaries

Database segment files contain plaintext JSON payloads. Access control is enforced by the running process and does not prevent direct operating-system file access. Independent verification is meaningful when the verifier compares against a tree head obtained from a trusted source outside the storage administrator's control.

Ink Browser uses an advisory lock for local database access. Its passphrase UI masks input, and key-loading code clears temporary key buffers. These measures reduce accidental disclosure but do not protect against a fully compromised operating system or process.
