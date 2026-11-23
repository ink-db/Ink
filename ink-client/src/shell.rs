//! Interactive terminal shell engine for `ink connect`.

use crate::connection::Connection;
use crate::error::ClientError;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use ink_core::Keypair;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::path::PathBuf;

/// Run the interactive CLI shell session connected to an Ink database server.
pub async fn run_shell(
    addr: &str,
    keypair: &Keypair,
    server_cert_hash: Option<[u8; 32]>,
) -> Result<(), ClientError> {
    println!("Connecting to Ink server at {}...", addr);
    let mut conn = Connection::connect(addr, keypair, server_cert_hash).await?;

    let pubkey_hex = hex::encode(keypair.public_key());
    let db_id_hex = hex::encode(conn.database_id());
    let session_hex = hex::encode(conn.session_id());

    println!("Successfully connected and authenticated to Ink daemon.");
    println!("  Database ID: {}", db_id_hex);
    println!("  Session ID:  {}", &session_hex[..16]);
    println!("  Identity:    {}...", &pubkey_hex[..16]);
    println!("  Roles:       {:?}", conn.roles());
    println!();
    println!("Type IQL statements ending with ';' or 'HELP;' for commands, 'QUIT;' to exit.\n");

    let mut rl =
        DefaultEditor::new().map_err(|e| ClientError::Io(std::io::Error::other(e.to_string())))?;

    let history_path = dirs_fallback_history_path();
    if let Some(ref path) = history_path {
        let _ = rl.load_history(path);
    }

    let mut buffer = String::new();
    let mut current_table = String::from("default");

    loop {
        let prompt = if buffer.is_empty() {
            format!("ink:{}> ", current_table)
        } else {
            format!("ink:{}...> ", current_table)
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                buffer.push_str(trimmed);
                buffer.push(' ');

                if !buffer.trim_end().ends_with(';') {
                    // Multi-line statement continuation
                    continue;
                }

                let stmt = buffer.trim_end().trim_end_matches(';').trim().to_string();
                let full_history_entry = buffer.trim().to_string();
                buffer.clear();

                let _ = rl.add_history_entry(full_history_entry);

                // Handle shell built-ins
                let upper = stmt.to_uppercase();
                if upper == "QUIT" || upper == "EXIT" || upper == "\\Q" {
                    println!("Goodbye.");
                    break;
                } else if upper == "HELP" {
                    print_help();
                    continue;
                } else if upper == "PING" {
                    match conn.ping().await {
                        Ok(dur) => println!(
                            "Pong! Round-trip latency: {:.2} ms",
                            dur.as_secs_f64() * 1000.0
                        ),
                        Err(e) => eprintln!("Ping error: {}", e),
                    }
                    continue;
                } else if upper.starts_with("USE ") {
                    let parts: Vec<&str> = stmt.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let tbl = parts[1].trim_matches('"').trim_matches('\'');
                        current_table = tbl.to_string();
                        println!("Context switched to table \"{}\"", current_table);
                    } else {
                        println!("Usage: USE <table_name>;");
                    }
                    continue;
                }

                // Check if statement is an APPEND command
                if upper.starts_with("APPEND TO ") {
                    // Execute two-step append flow
                    match parse_and_execute_append(&mut conn, &stmt).await {
                        Ok(res) => {
                            println!("Record #{} appended successfully.", res.record_id);
                            println!("  Hash:      {}", res.record_hash);
                            println!("  Timestamp: {}", res.timestamp_us);
                        }
                        Err(e) => eprintln!("Error: {}", e),
                    }
                    continue;
                }

                // Regular IQL Query Execution (READ, VERIFY, etc.)
                let query_stmt = format!("{};", stmt);
                match conn.query(&query_stmt).await {
                    Ok(result) => {
                        render_query_results(&result);
                    }
                    Err(e) => {
                        eprintln!("Error executing query: {}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                buffer.clear();
            }
            Err(ReadlineError::Eof) => {
                println!("\nGoodbye.");
                break;
            }
            Err(err) => {
                eprintln!("Readline error: {:?}", err);
                break;
            }
        }
    }

    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    Ok(())
}

fn dirs_fallback_history_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".ink_history"))
}

fn print_help() {
    println!("Ink Interactive Shell Help");
    println!("--------------------------");
    println!("  READ FROM <table> [WHERE ...] [LIMIT n];     Read records with optional filtering");
    println!(
        "  APPEND TO <table> DATA '<json>';            Append and cryptographically sign a record"
    );
    println!(
        "  VERIFY [<table>];                           Verify cryptographic chain and Merkle root"
    );
    println!("  USE <table_name>;                           Change active table prompt context");
    println!("  PING;                                       Test server round-trip latency");
    println!("  QUIT; or EXIT;                              Exit interactive shell");
    println!();
}

async fn parse_and_execute_append(
    conn: &mut Connection,
    stmt: &str,
) -> Result<crate::connection::ClientAppendResult, ClientError> {
    // Basic parser for APPEND TO "table" DATA '...'
    let upper = stmt.to_uppercase();
    let data_idx = upper.find("DATA").ok_or_else(|| {
        ClientError::QueryFailed("Missing DATA clause in APPEND statement".into())
    })?;

    let table_part = stmt["APPEND TO".len()..data_idx].trim();
    let table_name = table_part.trim_matches('"').trim_matches('\'').trim();

    let json_part = stmt[data_idx + 4..].trim();
    let json_data = json_part
        .trim_start_matches('\'')
        .trim_end_matches('\'')
        .trim_start_matches('"')
        .trim_end_matches('"');

    conn.append(table_name, json_data).await
}

fn render_query_results(result: &crate::connection::ClientQueryResult) {
    if result.columns.is_empty() && result.rows.is_empty() {
        println!("Query executed successfully (0 rows).");
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    let header_cells: Vec<Cell> = result
        .columns
        .iter()
        .map(|c| Cell::new(c).fg(Color::Cyan))
        .collect();
    table.set_header(header_cells);

    for row_val in &result.rows {
        let mut row_cells = Vec::new();
        match row_val {
            serde_json::Value::Object(map) => {
                for col in &result.columns {
                    let cell_str = match map.get(col) {
                        Some(serde_json::Value::String(s)) => s.clone(),
                        Some(other) => other.to_string(),
                        None => String::new(),
                    };
                    row_cells.push(Cell::new(cell_str));
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    row_cells.push(Cell::new(v.to_string()));
                }
            }
            other => {
                row_cells.push(Cell::new(other.to_string()));
            }
        }
        table.add_row(Row::from(row_cells));
    }

    println!("{table}");
    println!(
        "{} rows returned in {:.2} ms.\n",
        result.rows_returned,
        result.execution_time_us as f64 / 1000.0
    );
}
