# Ink Query Language (IQL) Specification

**Version**: 0  
**Status**: Query language reference for the current IQL implementation.

---

## 1. Language Characteristics

| Goal | Detail |
|---|---|
| Readable | A non-programmer can understand a statement at a glance |
| Minimal | Only the operations that an append-only database can honestly support |
| Safe | UPDATE, DELETE, DROP are syntax errors, not missing features |
| Composable | Filters, ordering, and aggregations chain naturally |

---

## 2. Intentionally Omitted Features

The following SQL features are **deliberately absent** from IQL:

| Absent feature | Reason |
|---|---|
| `UPDATE` | Would silently overwrite history; corrections are appended as new records |
| `DELETE` | Would destroy records — corrections remain forever |
| `DROP TABLE` | Tables are virtual views over the log; deleting the log violates immutability |
| `ALTER TABLE` | Ink is schemaless; payloads are free-form JSON |
| `TRUNCATE` | Same reason as DELETE |
| `CREATE TABLE` | Tables are created implicitly on first `APPEND` |
| `JOIN` | Not implemented in the current language version |
| `TRANSACTION` (write) | Each `APPEND` is atomic; multi-record atomicity is not implemented |
| SQL `GRANT` / `REVOKE` | Ink manages access cryptographically via signed records in `_ink_access` and the `ink access` CLI |

---

## 3. Data Types

IQL payloads are JSON objects. Supported literal types in filter expressions:

| Type | Example |
|---|---|
| Integer | `42`, `-7` |
| Float | `3.14` |
| String | `"hello"` |
| Boolean | `true`, `false` |
| Null | `null` |
| Date/time | `2024-01-15`, `2024-01-15T10:30:00Z` |

---

## 4. Statements

### 4.1 `APPEND`

Append a new record to a table.

```
APPEND TO "<table>" { <json_object> }
APPEND TO "<table>" { <json_object> } SIGNED WITH "<key_path>"
```

**Examples**:
```sql
APPEND TO "sales" { customer: "John", amount: 1500, currency: "USD" }
APPEND TO "access_log" { user: "alice", action: "login", ip: "10.0.0.1" } SIGNED WITH "~/.ink/alice.pem"
```

- The `SIGNED WITH` clause specifies the Ed25519 private key file. If omitted, Ink uses the default key configured in the environment or config file.
- Table names are created implicitly when the first record is appended.

---

### 4.2 `READ`

Query records. The result is always a subset of the immutable log — no mutation occurs.

```
READ FROM "<table>"
READ FROM "<table>" WHERE <filter>
READ FROM "<table>" WHERE <filter> ORDER BY <field> [NEWEST FIRST | OLDEST FIRST | ASC | DESC]
READ FROM "<table>" WHERE <filter> LIMIT <n>
READ FROM "<table>" WHERE <filter> LIMIT <n> OFFSET <m>
```

**Examples**:
```sql
READ FROM "sales"
READ FROM "sales" WHERE amount > 1000
READ FROM "sales" WHERE customer = "John" AND amount > 500
READ FROM "sales" WHERE date >= 2024-01-01 AND date < 2024-02-01
READ FROM "sales" ORDER BY amount DESC
READ FROM "sales" ORDER BY date NEWEST FIRST
READ FROM "sales" WHERE amount > 1000 ORDER BY date NEWEST FIRST LIMIT 10
```

#### Filter Expressions

```
<filter>  ::= <expr> (AND <expr>)*
            | <expr> (OR <expr>)*
            | NOT <expr>
            | ( <filter> )

<expr>    ::= <field> <op> <value>
            | <field> IN ( <value>, ... )
            | <field> BETWEEN <value> AND <value>
            | <field> CONTAINS "<substring>"
            | <field> EXISTS
            | <field> IS NULL
            | <field> IS NOT NULL
            | id = <n>
            | author = "<pubkey_hex>"
            | date BETWEEN <date> AND <date>

<op>      ::= = | != | < | <= | > | >= | LIKE
```

#### Special Read-Only Fields

These fields are set by Ink and are always available in filters and ORDER BY:

| Field | Type | Description |
|---|---|---|
| `id` | u64 | Record ID |
| `timestamp` | datetime | When the record was written |
| `date` | date | Calendar date portion of timestamp |
| `author` | string (hex) | Hex-encoded Ed25519 public key |
| `is_correction` | bool | Whether this record is a correction |
| `correction_of` | u64 | ID of the corrected record (if applicable) |

---

### 4.3 `CORRECT`

Append a correction record that logically supersedes an existing record. The original record is **never modified**.

```
CORRECT record #<id> WITH { <json_object> }, reason: "<explanation>"
CORRECT record #<id> WITH { <json_object> }, reason: "<explanation>" SIGNED WITH "<key_path>"
```

**Examples**:
```sql
CORRECT record #42 WITH { customer: "John", amount: 1200 }, reason: "typo in amount"
CORRECT record #17 WITH { status: "refunded" }, reason: "customer requested refund on 2024-02-01"
```

- Internally this appends a new record with `flags |= 0x01` (is_correction) and `correction_of = 42`.
- The `reason` field is embedded in the payload alongside the corrected data.
- Chains of corrections are supported (correcting a correction).
- The original record remains immutable and permanently visible.

---

### 4.4 `HISTORY`

Show a record and all subsequent corrections to it, in order.

```
HISTORY OF record #<id>
```

**Example**:
```sql
HISTORY OF record #42
```

Output: the original record #42, followed by any records that corrected it, in chronological order. If a correction was itself corrected, the full chain is shown.

---

### 4.5 `VERIFY`

Verify cryptographic integrity of a table or the whole database.

```
VERIFY "<table>"
VERIFY ALL
VERIFY record #<id>
```

**Examples**:
```sql
VERIFY "sales"
VERIFY ALL
VERIFY record #42
```

Output:
```
Verifying table "sales"... 1,042 records
  ✓ Hash chain intact
  ✓ All signatures valid
  ✓ Merkle tree consistent
  ✓ Tree head: a3f9b2...c741

Overall: INTEGRITY VERIFIED
```

If tampering is detected:
```
  ✗ Hash chain broken at record #317
    Expected prev_hash: 9f3a...bc
    Found prev_hash:    0000...00
    → Records #317 through #1042 cannot be trusted
```

---

### 4.6 Aggregations

```
COUNT FROM "<table>" WHERE <filter>
SUM <field> FROM "<table>" WHERE <filter>
AVG <field> FROM "<table>" WHERE <filter>
MIN <field> FROM "<table>" WHERE <filter>
MAX <field> FROM "<table>" WHERE <filter>
```

**Examples**:
```sql
COUNT FROM "sales" WHERE amount > 1000
SUM amount FROM "sales" WHERE date >= 2024-01-01
AVG amount FROM "sales"
```

---

### 4.7 `GROUP BY`

```
READ FROM "<table>" WHERE <filter> GROUP BY <field> [COUNT | SUM <field>]
```

**Examples**:
```sql
READ FROM "sales" GROUP BY customer COUNT
READ FROM "sales" GROUP BY currency SUM amount
```

---

### 4.8 `TABLES`

List all tables in the database.

```
TABLES
```

---

### 4.9 `STATUS`

Show database status (tree head, record count, last write time).

```
STATUS
```

---

### 4.10 Access Control Context

Access-control mutations are signed by an administrator's Ed25519 key and stored in the `_ink_access` system log.

The current IQL grammar does not include access-management statements. The corresponding records and authorization model are described in `FORMAT.md`.

#### Authorization Model
The query evaluator checks active access grants for protected operations. `APPEND` and `CORRECT` map to `writer`; `READ`, `HISTORY`, aggregations, and proofs map to `reader` or `auditor`; `VERIFY` maps to `reader` or `auditor`. Access-management statements are outside the IQL grammar.

---

## 5. Grammar (EBNF)

```ebnf
statement    = append | read | correct | history | verify
             | count | sum | avg | min | max | tables | status ;

append       = "APPEND" "TO" table_name json_object
               [ "SIGNED" "WITH" string ] ;

read         = "READ" "FROM" table_name
               [ "WHERE" filter ]
               [ "ORDER" "BY" order_expr ]
               [ "LIMIT" integer ]
               [ "OFFSET" integer ] ;

correct      = "CORRECT" "record" "#" integer
               "WITH" json_object "," "reason" ":" string
               [ "SIGNED" "WITH" string ] ;

history      = "HISTORY" "OF" "record" "#" integer ;

verify       = "VERIFY" ( table_name | "ALL" | "record" "#" integer ) ;

count        = "COUNT" "FROM" table_name [ "WHERE" filter ] ;
sum          = "SUM" field "FROM" table_name [ "WHERE" filter ] ;
avg          = "AVG" field "FROM" table_name [ "WHERE" filter ] ;
min          = "MIN" field "FROM" table_name [ "WHERE" filter ] ;
max          = "MAX" field "FROM" table_name [ "WHERE" filter ] ;

filter       = expr { ("AND" | "OR") expr } | "NOT" expr | "(" filter ")" ;

expr         = field op value
             | field "IN" "(" value { "," value } ")"
             | field "BETWEEN" value "AND" value
             | field "CONTAINS" string
             | field "EXISTS"
             | field "IS" ["NOT"] "NULL"
             | "id" "=" integer
             | "author" "=" string
             | "date" "BETWEEN" date "AND" date ;

op           = "=" | "!=" | "<" | "<=" | ">" | ">=" | "LIKE" ;

order_expr   = field [ "NEWEST" "FIRST" | "OLDEST" "FIRST" | "ASC" | "DESC" ] ;

table_name   = '"' identifier '"' ;
field        = identifier | identifier "." identifier ;
value        = integer | float | string | "true" | "false" | "null" | date ;
date         = /\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}Z?)?/ ;
string       = '"' { any_char } '"' ;
integer      = /[0-9]+/ ;
float        = /[0-9]+\.[0-9]+/ ;
identifier   = /[a-zA-Z_][a-zA-Z0-9_]*/ ;
```

---

## 6. Error Messages

IQL parser and evaluator errors use the following descriptions:

| Error | Message |
|---|---|
| User writes `UPDATE ...` | `Error: UPDATE is not supported by Ink. Corrections are represented by appended CORRECT records.` |
| User writes `DELETE ...` | `Error: DELETE is not supported by Ink. Records are permanent.` |
| User writes `DROP TABLE ...` | `Error: DROP TABLE is not supported. Tables in Ink are immutable views over the log.` |
| Record not found | `Error: Record #<id> does not exist in this database.` |
| Table not found | `Error: Table "<name>" has no records yet.` |
| Signature verification failure | `Error: Signature on record #<id> is invalid. The record may have been tampered with.` |
| Authentication failure | `Error: Authentication failed: invalid credentials or unauthorized identity` |
| Access denied (RBAC) | `Error: Access denied: insufficient permissions for target operation` |
