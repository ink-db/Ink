use ink_server::{cli, server};

use anyhow::{Context, Result};
use clap::Parser;
use cli::{AccessCommands, Cli, Commands};
use ink_core::{
    auth::{Role, SYSTEM_TABLE_ACCESS},
    segment::now_micros,
    verify_inclusion, InclusionProof, Keypair, Store,
};
use ink_query::{query_authenticated, QueryResult};
use std::fs;
use std::str::FromStr;

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let clean = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).context("Invalid hex string for 32-byte key")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "Key must be 32 bytes (64 hex characters), found {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Init(cmd) => {
            let admin_kp = match cmd.admin_key {
                Some(ref path) => Keypair::load_from_file(path)
                    .with_context(|| format!("Failed to load admin key from {:?}", path))?,
                None => Keypair::generate(),
            };

            let admin_pub_hex = admin_kp.public_key_hex();
            let (store, _kp) = Store::init_with_admin(&args.dir, Some(admin_kp.clone()))
                .with_context(|| format!("Failed to initialize database at {:?}", args.dir))?;

            let key_dest = cmd.admin_out.unwrap_or_else(|| args.dir.join("admin.key"));
            if cmd.admin_key.is_none() {
                admin_kp
                    .save_to_file(&key_dest)
                    .with_context(|| format!("Failed to save admin key to {:?}", key_dest))?;
            }

            println!("Initialized empty Ink database at {:?}", args.dir);
            println!("  Database ID: {}", store.database_id());
            println!("Genesis Admin Key established:");
            println!("  Public Key:  {}", admin_pub_hex);
            if cmd.admin_key.is_none() {
                println!("  Private Key: {:?} (keep this file secure!)", key_dest);
            }
            println!("Genesis admin grant sealed into _ink_access (Record #0)");
        }

        Commands::Keygen(cmd) => {
            let keypair = Keypair::generate();
            let pub_hex = keypair.public_key_hex();

            if let Some(out_path) = cmd.out {
                keypair
                    .save_to_file(&out_path)
                    .with_context(|| format!("Failed to save keypair to {:?}", out_path))?;
                println!("Generated new Ed25519 keypair:");
                println!("  Private key saved to: {:?}", out_path);
                println!("  Public key (author):  {}", pub_hex);
            } else {
                println!("Generated new Ed25519 keypair:");
                println!("  Public key (author): {}", pub_hex);
                println!("  Tip: Specify '--out <path>' to save private key for signing records.");
            }
        }

        Commands::Append(cmd) => {
            let mut store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

            let keypair = match &cmd.key {
                Some(p) => Some(
                    Keypair::load_from_file(p)
                        .with_context(|| format!("Failed to load signing key from {:?}", p))?,
                ),
                None => None,
            };

            let now = now_micros();
            if store.acl().has_admin(now) {
                let kp = keypair.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Access denied: authentication required. Specify --key <path_to_private_key>")
                })?;
                if !store.is_authorized(&kp.public_key(), Role::Writer, &cmd.table) {
                    anyhow::bail!(
                        "Access denied: insufficient permissions to write to table '{}'",
                        cmd.table
                    );
                }
            }

            let record = store
                .append_signed(&cmd.table, cmd.data.as_bytes(), keypair.as_ref())
                .context("Failed to append record")?;

            println!("Appended record #{}", record.id);
            println!("  Table:       {}", record.table);
            println!("  Author:      {}", record.author_hex());
            println!("  Record Hash: {}", record.hash_hex());
            println!("  Prev Hash:   {}", record.prev_hash_hex());
            println!("  Tree Head:   {}", store.tree_head());
        }

        Commands::Correct(cmd) => {
            let mut store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

            let keypair = match &cmd.key {
                Some(p) => Some(
                    Keypair::load_from_file(p)
                        .with_context(|| format!("Failed to load signing key from {:?}", p))?,
                ),
                None => None,
            };

            let now = now_micros();
            if store.acl().has_admin(now) {
                let orig = store
                    .get_record(cmd.id)
                    .context("Original record not found")?;
                let kp = keypair.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Access denied: authentication required. Specify --key <path_to_private_key>")
                })?;
                if !store.is_authorized(&kp.public_key(), Role::Writer, &orig.table) {
                    anyhow::bail!(
                        "Access denied: insufficient permissions to correct records in table '{}'",
                        orig.table
                    );
                }
            }

            let record = store
                .append_correction_signed(
                    cmd.id,
                    cmd.data.as_bytes(),
                    &cmd.reason,
                    keypair.as_ref(),
                )
                .context("Failed to append correction")?;

            println!(
                "Appended correction record #{} for original #{}",
                record.id, cmd.id
            );
            println!("  Table:       {}", record.table);
            println!("  Reason:      {}", cmd.reason);
            println!("  Author:      {}", record.author_hex());
            println!("  Record Hash: {}", record.hash_hex());
            println!("  Prev Hash:   {}", record.prev_hash_hex());
            println!("  Tree Head:   {}", store.tree_head());
        }

        Commands::Read(cmd) => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

            let keypair = match &cmd.key {
                Some(p) => Some(
                    Keypair::load_from_file(p)
                        .with_context(|| format!("Failed to load reading key from {:?}", p))?,
                ),
                None => None,
            };

            let now = now_micros();
            if store.acl().has_admin(now) {
                let kp = keypair.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Access denied: authentication required. Specify --key <path_to_private_key>")
                })?;
                if !store.is_authorized(&kp.public_key(), Role::Reader, &cmd.table) {
                    anyhow::bail!(
                        "Access denied: insufficient permissions to read table '{}'",
                        cmd.table
                    );
                }
            }

            let records = store
                .get_records_in_table(&cmd.table, cmd.limit)
                .context("Failed to read records from table")?;

            println!(
                "Read {} record(s) from table \"{}\":\n",
                records.len(),
                cmd.table
            );
            for r in records {
                let corr_note = if let Some(orig) = r.correction_of {
                    format!(" [CORRECTION of #{}]", orig)
                } else {
                    String::new()
                };
                let payload = r.data_str().unwrap_or("<binary>");
                println!("#{} (ts: {}){}:", r.id, r.timestamp, corr_note);
                println!("  author:      {}", r.author_hex());
                println!("  data:        {}", payload);
                println!("  hash:        {}", r.hash_hex());
                println!("  prev_hash:   {}", r.prev_hash_hex());
                println!();
            }
        }

        Commands::History(cmd) => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;
            let history = store
                .get_history(cmd.id)
                .context("Failed to get record history")?;

            println!("History for record #{}:", cmd.id);
            for (idx, r) in history.iter().enumerate() {
                let role = if idx == 0 { "ORIGINAL" } else { "CORRECTION" };
                println!(
                    "  [{}] #{} (author: {}) hash: {}",
                    role,
                    r.id,
                    &r.author_hex()[..16],
                    r.hash_hex()
                );
                println!("    data: {}", r.data_str().unwrap_or("<binary>"));
            }
        }

        Commands::ExportProof(cmd) => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;
            let proof = store
                .get_inclusion_proof(cmd.id)
                .with_context(|| format!("Failed to create proof for record #{}", cmd.id))?;

            let json = serde_json::to_string_pretty(&proof)?;
            if let Some(out_path) = cmd.out {
                fs::write(&out_path, &json)
                    .with_context(|| format!("Failed to write proof to {:?}", out_path))?;
                println!(
                    "Exported inclusion proof for record #{} to {:?}",
                    cmd.id, out_path
                );
            } else {
                println!("{}", json);
            }
        }

        Commands::VerifyProof(cmd) => {
            let json_str = if std::path::Path::new(&cmd.proof).exists() {
                fs::read_to_string(&cmd.proof)?
            } else {
                cmd.proof
            };

            let proof: InclusionProof =
                serde_json::from_str(&json_str).context("Failed to parse inclusion proof JSON")?;

            let valid = verify_inclusion(&proof);
            println!("Inclusion Proof Verification:");
            println!("  Leaf Index:  {}", proof.leaf_index);
            println!("  Tree Size:   {}", proof.tree_size);
            println!("  Record Hash: {}", proof.record_hash);
            println!("  Tree Head:   {}", proof.root_hash);
            println!("  Path Length: {} sibling(s)", proof.audit_path.len());

            if valid {
                println!("\n[OK] PROOF VERIFIED: Record exists in the committed tree head.");
            } else {
                println!("\n[FAIL] INVALID PROOF: Record does not match the committed tree head!");
                std::process::exit(1);
            }
        }

        Commands::Verify(cmd) => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

            let result = if let Some(table) = cmd.table {
                store
                    .verify_table(&table)
                    .with_context(|| format!("Verification failed for table \"{}\"", table))?
            } else {
                store
                    .verify_all()
                    .context("Verification failed across tables")?
            };

            println!("Verification Results:");
            println!("  Tables checked:  {}", result.tables_checked.join(", "));
            println!("  Records checked: {}", result.records_checked);
            println!("  Tree Head:       {}", store.tree_head());

            if result.is_valid {
                println!("\n[OK] INTEGRITY VERIFIED - All hash chains, signatures, Merkle heads, and CRCs match.");
            } else {
                println!(
                    "\n[FAIL] TAMPERING DETECTED! Found {} issue(s):",
                    result.errors.len()
                );
                for (i, err) in result.errors.iter().enumerate() {
                    println!(
                        "  {}. Record #{:?}: {}",
                        i + 1,
                        err.record_id,
                        err.description
                    );
                }
                std::process::exit(1);
            }
        }

        Commands::Status => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;
            let status = store.status();

            println!("Ink Database Status:");
            println!("  Database ID:    {}", status.database_id);
            println!("  Format Version: {}", status.format_version);
            println!("  Total Records:  {}", status.record_count);
            println!("  Total Tables:   {}", status.table_count);
            println!("  Tree Head:      {}", status.tree_head);
            if let Some(last_id) = status.last_record_id {
                println!("  Last Record ID: #{}", last_id);
            }
            println!("\nTables and Chain Heads:");
            for (table, hash) in status.last_hash_per_table {
                println!("  - {:<16} : {}", table, hash);
            }
        }

        Commands::Query(cmd) => {
            let mut store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

            let keypair = match &cmd.key {
                Some(p) => Some(
                    Keypair::load_from_file(p)
                        .with_context(|| format!("Failed to load key from {:?}", p))?,
                ),
                None => None,
            };

            let query_str = cmd
                .query
                .or(cmd.args)
                .context("No query provided. Usage: ink query \"<IQL statement>\"")?;

            let caller_pub = keypair.as_ref().map(|k| k.public_key());
            let result = query_authenticated(&mut store, &query_str, caller_pub.as_ref())
                .map_err(anyhow::Error::msg)
                .context("Failed to execute query")?;

            match result {
                QueryResult::Records(records) => {
                    println!("Read {} record(s):\n", records.len());
                    for r in &records {
                        let corr_note = match r.correction_of {
                            Some(orig) => format!(" [CORRECTION of #{}]", orig),
                            None => String::new(),
                        };
                        println!("#{} (ts: {}){}:", r.id, r.timestamp, corr_note);
                        println!("  table:       {}", r.table);
                        println!("  author:      {}", r.author);
                        println!("  data:        {}", r.data);
                        println!("  hash:        {}", r.hash);
                        println!("  prev_hash:   {}", r.prev_hash);
                        println!();
                    }
                }

                QueryResult::Appended(r) => {
                    println!("Appended record #{}", r.id);
                    println!("  Table:       {}", r.table);
                    println!("  Author:      {}", r.author);
                    println!("  Record Hash: {}", r.hash);
                    println!("  Prev Hash:   {}", r.prev_hash);
                    println!("  Tree Head:   {}", store.tree_head());
                }

                QueryResult::Corrected(r) => {
                    match r.correction_of {
                        Some(orig) => println!(
                            "Appended correction record #{} for original #{}",
                            r.id, orig
                        ),
                        None => println!("Appended correction record #{}", r.id),
                    }
                    println!("  Table:       {}", r.table);
                    println!("  Author:      {}", r.author);
                    println!("  Record Hash: {}", r.hash);
                    println!("  Prev Hash:   {}", r.prev_hash);
                    println!("  Tree Head:   {}", store.tree_head());
                }

                QueryResult::Scalar(v) => {
                    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
                        println!("{}", v as i64);
                    } else {
                        println!("{}", v);
                    }
                }

                QueryResult::Grouped(groups) => {
                    if groups.is_empty() {
                        println!("(no groups)");
                    }
                    for (key, value) in &groups {
                        println!("  {:<16} : {}", key, value);
                    }
                }

                QueryResult::Verification(v) => {
                    println!("Verification Results:");
                    println!("  Tables checked:  {}", v.tables_checked.join(", "));
                    println!("  Records checked: {}", v.records_checked);
                    println!("  Tree Head:       {}", store.tree_head());

                    if v.is_valid {
                        println!("\n[OK] INTEGRITY VERIFIED - All hash chains, signatures, Merkle heads, and CRCs match.");
                    } else {
                        println!(
                            "\n[FAIL] TAMPERING DETECTED! Found {} issue(s):",
                            v.errors.len()
                        );
                        for (i, err) in v.errors.iter().enumerate() {
                            println!("  {}. {}", i + 1, err);
                        }
                        std::process::exit(1);
                    }
                }

                QueryResult::Tables(tables) => {
                    println!("Tables ({}):", tables.len());
                    for t in &tables {
                        println!("  - {}", t);
                    }
                }

                QueryResult::Status(s) => {
                    println!("Ink Database Status:");
                    println!("  Total Records:  {}", s.record_count);
                    println!("  Total Tables:   {}", s.table_count);
                    println!("  Tree Head:      {}", s.tree_head);
                    if let Some(last_id) = s.last_record_id {
                        println!("  Last Record ID: #{}", last_id);
                    }
                    println!("\nTables and Chain Heads:");
                    for (table, hash) in &s.tables {
                        println!("  - {:<16} : {}", table, hash);
                    }
                }

                QueryResult::History(history) => {
                    println!("History ({} entries):", history.len());
                    for (idx, r) in history.iter().enumerate() {
                        let role = if idx == 0 { "ORIGINAL" } else { "CORRECTION" };
                        let author = r.author.get(..16).unwrap_or(&r.author);
                        println!(
                            "  [{}] #{} (author: {}) hash: {}",
                            role, r.id, author, r.hash
                        );
                        println!("    data: {}", r.data);
                    }
                }
            }
        }

        Commands::Access(cmd) => match cmd {
            AccessCommands::Grant(grant_args) => {
                let mut store = Store::open(&args.dir)
                    .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

                let admin_kp =
                    Keypair::load_from_file(&grant_args.admin_key).with_context(|| {
                        format!("Failed to load admin key from {:?}", grant_args.admin_key)
                    })?;

                let subject_key = parse_hex_32(&grant_args.subject_key)?;
                let role = Role::from_str(&grant_args.role)
                    .map_err(|e| anyhow::anyhow!("Invalid role: {}", e))?;

                let rec = store.grant(
                    &admin_kp,
                    subject_key,
                    &grant_args.label,
                    role,
                    grant_args.tables.clone(),
                    grant_args.expires_at,
                )?;

                println!("Granted role '{}' to {}", role, grant_args.subject_key);
                println!("  Tables:      {:?}", grant_args.tables);
                println!("  Label:       {}", grant_args.label);
                println!("  Expires:     {:?}", grant_args.expires_at);
                println!("  Record ID:   #{} in _ink_access", rec.id);
                println!("  Record Hash: {}", rec.hash_hex());
            }

            AccessCommands::Revoke(revoke_args) => {
                let mut store = Store::open(&args.dir)
                    .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

                let admin_kp =
                    Keypair::load_from_file(&revoke_args.admin_key).with_context(|| {
                        format!("Failed to load admin key from {:?}", revoke_args.admin_key)
                    })?;

                let subject_key = parse_hex_32(&revoke_args.subject_key)?;
                let role = match revoke_args.role {
                    Some(r) => Some(
                        Role::from_str(&r).map_err(|e| anyhow::anyhow!("Invalid role: {}", e))?,
                    ),
                    None => None,
                };

                let rec = store.revoke(
                    &admin_kp,
                    subject_key,
                    role,
                    revoke_args.tables.clone(),
                    &revoke_args.reason,
                )?;

                println!("Revoked permissions from {}", revoke_args.subject_key);
                if let Some(r) = role {
                    println!("  Role:        {}", r);
                } else {
                    println!("  Role:        * (all roles)");
                }
                println!("  Tables:      {:?}", revoke_args.tables);
                println!("  Reason:      {}", revoke_args.reason);
                println!("  Record ID:   #{} in _ink_access", rec.id);
            }

            AccessCommands::List(list_args) => {
                let store = Store::open(&args.dir)
                    .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

                let filter_key = match list_args.subject_key {
                    Some(ref k) => Some(parse_hex_32(k)?),
                    None => None,
                };

                let grants = store.acl().list_grants();
                let now = now_micros();
                println!("Active Access Registry Grants ({} subjects):", grants.len());
                println!("{:-<100}", "");
                println!(
                    "{:<64} | {:<8} | {:<20} | {:<8}",
                    "PUBLIC KEY", "ROLE", "TABLES", "STATUS"
                );
                println!("{:-<100}", "");

                for (key, user_grants) in grants {
                    if let Some(ref fk) = filter_key {
                        if key != fk {
                            continue;
                        }
                    }
                    let key_hex = hex::encode(key);
                    for g in user_grants {
                        let status = if g.is_expired(now) {
                            "EXPIRED"
                        } else {
                            "ACTIVE"
                        };
                        let tables_str = g.tables.join(", ");
                        println!(
                            "{:<64} | {:<8} | {:<20} | {:<8}",
                            key_hex,
                            g.role.to_string(),
                            tables_str,
                            status
                        );
                    }
                }
                println!("{:-<100}", "");
            }

            AccessCommands::Log(log_args) => {
                let store = Store::open(&args.dir)
                    .with_context(|| format!("Failed to open database at {:?}", args.dir))?;

                println!("Access Registry Audit Log (_ink_access):");
                match store.get_records_in_table(SYSTEM_TABLE_ACCESS, Some(log_args.tail)) {
                    Ok(records) => {
                        for r in records {
                            let action_json: serde_json::Value =
                                serde_json::from_slice(&r.data).unwrap_or(serde_json::Value::Null);
                            println!("#{} [{}] Author: {}", r.id, r.timestamp, r.author_hex());
                            println!("   Action: {}", action_json);
                        }
                    }
                    Err(ink_core::InkError::TableNotFound(_)) => {
                        println!("  No access records logged yet.");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        },

        Commands::Serve(cmd) => {
            let store = Store::open(&args.dir)
                .with_context(|| format!("Failed to open database at {:?}", args.dir))?;
            let daemon = server::TcpDaemon::new(store, cmd.bind, cmd.max_unauth_conns);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("Failed to build Tokio runtime")?;
            rt.block_on(daemon.run())?;
        }

        Commands::Connect(cmd) => {
            let keypair = ink_client::load_key(&cmd.key, cmd.passphrase.as_deref())
                .with_context(|| format!("Failed to load key from {:?}", cmd.key))?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("Failed to build Tokio runtime")?;
            rt.block_on(ink_client::run_shell(&cmd.host, &keypair, None))
                .map_err(|e| anyhow::anyhow!("Shell error: {}", e))?;
        }
    }

    Ok(())
}
