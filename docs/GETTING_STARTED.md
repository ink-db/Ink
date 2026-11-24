# Getting Started with Ink

This guide walks you through building, configuring, and operating Ink. It covers command-line operations, interactive queries in the client shell, network server deployment, and visual inspection using Ink Browser.

---

## 1. Prerequisites and Installation

Ink requires the stable Rust toolchain (Rust 2021 edition, version 1.75 or later).

### Build from Source

Clone the repository and compile all workspace packages:

```sh
git clone https://github.com/ink-db/Ink.git
cd Ink
cargo build --workspace --release
```

After compilation, the following binaries are available in `target/release/`:
- `ink`: Command-line interface and TCP daemon (`ink-server`)
- `ink-browser`: Cross-platform desktop application (`ink-browser`)
- `ink-client`: Standalone interactive client shell (`ink-client`)

To verify the installation:

```sh
./target/release/ink --version
```

---

## 2. Quick Start with the CLI (`ink`)

The `ink` CLI provides subcommands for identity generation, storage initialization, record appends, IQL execution, and cryptographic verification.

### Step 1: Generate an Author Keypair

All operations in Ink are cryptographically signed. Generate an encrypted `.inkkey` keypair:

```sh
cargo run -p ink-server --bin ink -- keygen --output admin.inkkey
```

You will be prompted to enter a passphrase. The resulting `.inkkey` file uses Argon2id key derivation and ChaCha20-Poly1305 authenticated encryption to protect the Ed25519 seed.

For automated testing or development where passphrases are not required, an unencrypted 32-byte raw seed key can also be used (see `examples/demo-database/demo-admin.key`).

### Step 2: Initialize a New Database

Create a new database directory with your keypair designated as the genesis administrator:

```sh
cargo run -p ink-server --bin ink -- init --dir ./data --admin-key admin.inkkey
```

This creates `./data/ink.meta` and initializes the append-only access control table (`_ink_access`) with a genesis administrator grant.

### Step 3: Append Records

Append JSON records to a table (tables are created automatically when the first record is appended):

```sh
cargo run -p ink-server --bin ink -- append \
  --dir ./data \
  --key admin.inkkey \
  --table orders \
  --data '{"order_id": 1001, "customer": "Acme Corp", "amount": 1250.50, "status": "completed"}'
```

Every appended record receives a database-wide monotonic ID, a microsecond timestamp, an Ed25519 signature, a per-table BLAKE3 hash link, and is committed as a new leaf in the global Merkle tree.

### Step 4: Query Records with IQL

Execute queries using the Ink Query Language (IQL):

```sh
# Read all records from the orders table
cargo run -p ink-server --bin ink -- query \
  --dir ./data \
  --key admin.inkkey \
  -q 'READ FROM "orders"'

# Filter records with conditions
cargo run -p ink-server --bin ink -- query \
  --dir ./data \
  --key admin.inkkey \
  -q 'READ FROM "orders" WHERE amount > 1000 ORDER BY amount DESC'

# Calculate aggregations
cargo run -p ink-server --bin ink -- query \
  --dir ./data \
  --key admin.inkkey \
  -q 'SUM amount FROM "orders"'
```

### Step 5: Issue a Correction

Because Ink is strictly append-only, existing records cannot be modified or deleted. To rectify inaccurate data, append a signed correction record:

```sh
cargo run -p ink-server --bin ink -- query \
  --dir ./data \
  --key admin.inkkey \
  -q 'CORRECT record #1 WITH {"order_id": 1001, "customer": "Acme Corp", "amount": 1200.00, "status": "adjusted"}, reason: "settlement discount applied"'
```

### Step 6: Trace Record History

Inspect the complete audit trail of an entity through its lifecycle:

```sh
cargo run -p ink-server --bin ink -- query \
  --dir ./data \
  --key admin.inkkey \
  -q 'HISTORY OF record #1'
```

This returns both the original record and the subsequent correction, showing timestamps, author signatures, and the recorded business reason.

### Step 7: Cryptographically Verify Storage Integrity

Verify that records have not been altered, deleted, or reordered on disk:

```sh
cargo run -p ink-server --bin ink -- verify --dir ./data
```

The verifier traverses every segment frame, recomputes BLAKE3 hash chains, validates Ed25519 signatures, and verifies consistency with the global Merkle tree head.

---

## 3. Getting Started with Ink Browser (Desktop GUI)

Ink Browser is a native desktop application built with `eframe` and `egui`. It allows administrators and auditors to navigate data, build visual filters, inspect Merkle trees, and verify proofs.

### Launching the Application

Run Ink Browser directly or point it to a database directory:

```sh
cargo run -p ink-browser
```

### Opening a Database

1. In the **Connection** tab, select **Open Local Database**.
2. Click **Browse Directory** and select your database folder (e.g., `./data` or the included sample `./examples/demo-database/database`).
3. Select your author key file (e.g., `admin.inkkey` or `examples/demo-database/demo-admin.key`).
4. If the key is encrypted, enter your passphrase.
5. Click **Open Database**.

### Exploring the Views

- **Browse Data**:
  - Select any table from the sidebar.
  - View paginated rows with dynamic schema column discovery.
  - Click **Filter Builder** to visually construct multi-clause query filters (`AND`, `OR`, comparison operators).
  - Check **Latest versions only** to automatically collapse corrected records.
  - Click **Details** on any row to inspect canonical hashes, raw JSON, and author public keys.
  - Click **History** to view the timeline of corrections.
  - Click **Correct** to submit a new signed correction record.

- **Execute IQL**:
  - Run arbitrary IQL statements (`READ`, `APPEND`, `CORRECT`, `HISTORY`, `COUNT`, `SUM`, `TABLES`, `STATUS`).
  - Access statement history with deduplication and FIFO navigation.
  - Mutating SQL keywords (`UPDATE`, `DELETE`, `DROP`, `TRUNCATE`) are blocked by the safety analyzer before evaluation.

- **Global Merkle Tree**:
  - Inspect the visual structure of the global tree.
  - Use the **Zoom** slider (20% to 250%), **Fit View**, or **100%** to adjust the viewport.
  - Toggle **Align leaves at bottom** to align all record leaves along a clean baseline.
  - Click any node to inspect its full BLAKE3 hash, depth, and child links.
  - Selecting a leaf highlights its **Inclusion Proof Path** to the root in gold and highlights sibling audit nodes in cyan.
  - Use **Find record #** to locate any committed record in large trees.

- **Integrity Verification**:
  - Run one-click cryptographic verification of individual tables or the entire database.
  - Results show total records checked, validation status, and the exact ID of any corrupted record.

- **Inclusion Proofs**:
  - Enter a record ID to generate an RFC 6962 inclusion proof.
  - Export proofs as standardized JSON files.
  - Use **Verify Proof File** for offline verification of proof files against a known tree head.

- **Access Management & Status**:
  - Administrators and auditors can view active role grants in `_ink_access`.
  - Check replication status, peer connectivity, and tree head digests.

---

## 4. Running the Network Server and Client Shell

Ink supports client-server operations over the binary Ink Wire Protocol (IWP).

### Starting the TCP Server

Start `ink-server` listening on a TCP address:

```sh
cargo run -p ink-server --bin ink -- serve --dir ./data --bind 127.0.0.1:7443
```

### Connecting with the Interactive Shell (`ink-client`)

In a separate terminal, launch the interactive shell:

```sh
cargo run -p ink-client -- --connect 127.0.0.1:7443 --key admin.inkkey
```

Once connected, the shell provides an interactive prompt with history and command completion:

```text
ink> TABLES
ink> READ FROM "orders" LIMIT 5
ink> STATUS
```

---

## 5. Access Control and Roles

Ink enforces role-based access control (RBAC) stored as immutable records in the reserved `_ink_access` table.

### Available Roles

| Role | Scope | Description |
|---|---|---|
| `admin` | Global (`*`) | Can issue grants, revocations, and perform all storage operations |
| `writer` | Scoped tables or `*` | Can append records and issue corrections |
| `reader` | Scoped tables or `*` | Can read records, run queries, and export inclusion proofs |
| `auditor` | Global (`*`) | Can inspect `_ink_access`, view all tables, and verify the Merkle tree |

### Granting Access

An administrator can grant access to another user's public key using IQL or the CLI:

```sql
GRANT writer ON "orders" TO "3b6a2...pubkey" WITH label: "bob", expires: 1735689600000000
```

### Revoking Access

To revoke permissions:

```sql
REVOKE writer ON "orders" FROM "3b6a2...pubkey", reason: "project reassignment"
```

---

## 6. Public Sample Database

The repository includes a ready-to-use sample database located at `examples/demo-database/`.

To inspect it immediately in Ink Browser:
1. Launch `cargo run -p ink-browser`.
2. Select database directory: `examples/demo-database/database`.
3. Select key file: `examples/demo-database/demo-admin.key` (unencrypted sample key).
4. Leave the passphrase blank and click **Open Database**.
5. Navigate to the **Global Merkle Tree** tab to view the live tree for the 11 sample records across `orders`, `inventory`, and `customers`.

---

## 7. Further Documentation

For detailed technical specifications, refer to the following documents in `docs/`:

- [Architecture Reference](ARCHITECTURE.md): Component interactions, storage lifecycle, and security model.
- [On-Disk Storage Format](FORMAT.md): Binary layout of segment files, headers, records, and `.inkkey` envelopes.
- [Ink Query Language (IQL)](QUERY_LANGUAGE.md): Grammar, filter syntax, aggregations, and execution rules.
- [Ink Wire Protocol (IWP)](PROTOCOL.md): TCP framing, handshake sequence, and binary message definitions.
- [Threat Model](THREAT_MODEL.md): Security boundaries, adversary capabilities, and tamper-evidence guarantees.
