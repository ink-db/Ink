//! IQL query execution and evaluation engine against an Ink `Store`.

use crate::ast::*;
use ink_core::auth::Role;
use ink_core::{segment::now_micros, Keypair, Record, Store, StoreStatus, VerifyResult};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

/// Result returned from executing an IQL statement.
#[derive(Debug, Serialize, Deserialize)]
pub enum QueryResult {
    /// Read query result containing matching records.
    Records(Vec<RecordSummary>),
    /// Record was successfully appended.
    Appended(RecordSummary),
    /// Record was successfully corrected.
    Corrected(RecordSummary),
    /// Numeric aggregation result (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`).
    Scalar(f64),
    /// Grouped aggregation result (`field_value` -> numeric result).
    Grouped(Vec<(String, f64)>),
    /// Table verification results.
    Verification(VerifySummary),
    /// List of tables in database.
    Tables(Vec<String>),
    /// Database status.
    Status(StatusSummary),
    /// History of a record and its corrections.
    History(Vec<RecordSummary>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSummary {
    pub id: u64,
    pub timestamp: i64,
    pub table: String,
    pub author: String,
    pub data: serde_json::Value,
    pub flags: u8,
    pub is_correction: bool,
    pub correction_of: Option<u64>,
    pub hash: String,
    pub prev_hash: String,
}

impl From<&Record> for RecordSummary {
    fn from(r: &Record) -> Self {
        let json_val = serde_json::from_slice(&r.data).unwrap_or(serde_json::Value::Null);
        Self {
            id: r.id,
            timestamp: r.timestamp,
            table: r.table.clone(),
            author: r.author_hex(),
            data: json_val,
            flags: r.flags,
            is_correction: r.is_correction(),
            correction_of: r.correction_of,
            hash: r.hash_hex(),
            prev_hash: r.prev_hash_hex(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifySummary {
    pub tables_checked: Vec<String>,
    pub records_checked: u64,
    pub is_valid: bool,
    pub errors: Vec<String>,
}

impl From<VerifyResult> for VerifySummary {
    fn from(v: VerifyResult) -> Self {
        let errors = v
            .errors
            .into_iter()
            .map(|e| format!("Record #{:?}: {}", e.record_id, e.description))
            .collect();
        Self {
            tables_checked: v.tables_checked,
            records_checked: v.records_checked,
            is_valid: v.is_valid,
            errors,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusSummary {
    pub record_count: u64,
    pub table_count: usize,
    pub last_record_id: Option<u64>,
    pub tree_head: String,
    pub tables: BTreeMap<String, String>,
}

impl From<StoreStatus> for StatusSummary {
    fn from(s: StoreStatus) -> Self {
        let tables = s.last_hash_per_table.into_iter().collect();
        Self {
            record_count: s.record_count,
            table_count: s.table_count,
            last_record_id: s.last_record_id,
            tree_head: s.tree_head,
            tables,
        }
    }
}

/// Authorize an AST statement against the database's materialized `_ink_access` registry.
///
/// If access controls are active in the database (i.e. at least one admin exists) and the caller
/// lacks the required role or table grant, returns an uniform error without leaking information.
pub fn authorize_statement(
    stmt: &Statement,
    store: &Store,
    caller_key: Option<&[u8; 32]>,
) -> Result<(), String> {
    let now = now_micros();
    // If the database has no admin / no access controls configured, allow open operation
    if !store.acl().has_admin(now) {
        return Ok(());
    }

    let key = match caller_key {
        Some(k) => k,
        None => {
            return Err(
                "Access denied: authentication required (database has active access control)"
                    .to_string(),
            )
        }
    };

    match stmt {
        Statement::Append { table, .. } => {
            if !store.acl().is_authorized(key, Role::Writer, table, now) {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
        Statement::Correct { original_id, .. } => {
            if let Ok(orig) = store.get_record(*original_id) {
                if !store
                    .acl()
                    .is_authorized(key, Role::Writer, &orig.table, now)
                {
                    return Err(
                        "Access denied: insufficient permissions for target operation".to_string(),
                    );
                }
            } else {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
        Statement::Read { table, .. }
        | Statement::Count { table, .. }
        | Statement::Aggregate { table, .. } => {
            if !store.acl().is_authorized(key, Role::Reader, table, now) {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
        Statement::History { id } => {
            if let Ok(orig) = store.get_record(*id) {
                if !store
                    .acl()
                    .is_authorized(key, Role::Reader, &orig.table, now)
                {
                    return Err(
                        "Access denied: insufficient permissions for target operation".to_string(),
                    );
                }
            } else {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
        Statement::Verify { target } => {
            let table = match target {
                VerifyTarget::Table(t) => t.as_str(),
                VerifyTarget::All => "*",
                VerifyTarget::Record(id) => {
                    if let Ok(orig) = store.get_record(*id) {
                        return if store
                            .acl()
                            .is_authorized(key, Role::Reader, &orig.table, now)
                        {
                            Ok(())
                        } else {
                            Err(
                                "Access denied: insufficient permissions for target operation"
                                    .to_string(),
                            )
                        };
                    } else {
                        return Err(
                            "Access denied: insufficient permissions for target operation"
                                .to_string(),
                        );
                    }
                }
            };
            if !store.acl().is_authorized(key, Role::Reader, table, now) {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
        Statement::Tables | Statement::Status => {
            if store.acl().get_grants_for_key(key).is_none() {
                return Err(
                    "Access denied: insufficient permissions for target operation".to_string(),
                );
            }
        }
    }

    Ok(())
}

/// Execute an AST statement against an open `Store`.
pub fn execute(stmt: Statement, store: &mut Store) -> Result<QueryResult, String> {
    match stmt {
        Statement::Append {
            table,
            data,
            signed_with,
        } => {
            let keypair = match signed_with {
                Some(p) => Some(
                    Keypair::load_from_file(Path::new(&p))
                        .map_err(|e| format!("Failed to load key {p}: {e}"))?,
                ),
                None => None,
            };

            let raw_data =
                serde_json::to_vec(&data).map_err(|e| format!("Serialization error: {e}"))?;

            let record = store
                .append_signed(&table, &raw_data, keypair.as_ref())
                .map_err(|e| format!("Append failed: {e}"))?;

            Ok(QueryResult::Appended(RecordSummary::from(&record)))
        }

        Statement::Correct {
            original_id,
            data,
            reason,
            signed_with,
        } => {
            let keypair = match signed_with {
                Some(p) => Some(
                    Keypair::load_from_file(Path::new(&p))
                        .map_err(|e| format!("Failed to load key {p}: {e}"))?,
                ),
                None => None,
            };

            let raw_data =
                serde_json::to_vec(&data).map_err(|e| format!("Serialization error: {e}"))?;

            let record = store
                .append_correction_signed(original_id, &raw_data, &reason, keypair.as_ref())
                .map_err(|e| format!("Correction failed: {e}"))?;

            Ok(QueryResult::Corrected(RecordSummary::from(&record)))
        }

        Statement::History { id } => {
            let history = store
                .get_history(id)
                .map_err(|e| format!("History lookup failed: {e}"))?;
            let summaries = history.iter().map(RecordSummary::from).collect();
            Ok(QueryResult::History(summaries))
        }

        Statement::Tables => {
            let tables = store.tables();
            Ok(QueryResult::Tables(tables))
        }

        Statement::Status => {
            let status = store.status();
            Ok(QueryResult::Status(StatusSummary::from(status)))
        }

        Statement::Verify { target } => {
            let res = match target {
                VerifyTarget::All => store
                    .verify_all()
                    .map_err(|e| format!("Verification failed: {e}"))?,
                VerifyTarget::Table(t) => store
                    .verify_table(&t)
                    .map_err(|e| format!("Verification failed for table {t}: {e}"))?,
                VerifyTarget::Record(id) => {
                    let r = store
                        .get_record(id)
                        .map_err(|e| format!("Record #{id} not found: {e}"))?;
                    store
                        .verify_table(&r.table)
                        .map_err(|e| format!("Verification failed: {e}"))?
                }
            };
            Ok(QueryResult::Verification(VerifySummary::from(res)))
        }

        Statement::Count { table, filter } => {
            let records = store
                .get_records_in_table(&table, None)
                .map_err(|e| format!("{e}"))?;

            let count = records
                .into_iter()
                .filter(|r| evaluate_filter(r, filter.as_ref()))
                .count();

            Ok(QueryResult::Scalar(count as f64))
        }

        Statement::Aggregate {
            op,
            field,
            table,
            filter,
        } => {
            let records = store
                .get_records_in_table(&table, None)
                .map_err(|e| format!("{e}"))?;

            let values: Vec<f64> = records
                .into_iter()
                .filter(|r| evaluate_filter(r, filter.as_ref()))
                .filter_map(|r| extract_numeric_field(&r, &field))
                .collect();

            if values.is_empty() {
                return Ok(QueryResult::Scalar(0.0));
            }

            let res = match op {
                AggOp::Sum => values.iter().sum(),
                AggOp::Avg => values.iter().sum::<f64>() / values.len() as f64,
                AggOp::Min => values
                    .into_iter()
                    .min_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
                    .unwrap_or(0.0),
                AggOp::Max => values
                    .into_iter()
                    .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
                    .unwrap_or(0.0),
            };

            Ok(QueryResult::Scalar(res))
        }

        Statement::Read {
            table,
            filter,
            order_by,
            limit,
            offset,
            group_by,
        } => {
            let records = store
                .get_records_in_table(&table, None)
                .map_err(|e| format!("{e}"))?;

            let mut filtered: Vec<Record> = records
                .into_iter()
                .filter(|r| evaluate_filter(r, filter.as_ref()))
                .collect();

            // Handle GROUP BY if present
            if let Some(gb) = group_by {
                let mut groups: BTreeMap<String, Vec<Record>> = BTreeMap::new();
                for r in filtered {
                    let key = extract_field_as_string(&r, &gb.field)
                        .unwrap_or_else(|| "null".to_string());
                    groups.entry(key).or_default().push(r);
                }

                let mut result_groups = Vec::new();
                for (key, group_records) in groups {
                    let val = match &gb.agg {
                        Some(GroupAgg::Count) | None => group_records.len() as f64,
                        Some(GroupAgg::Sum(f)) => group_records
                            .iter()
                            .filter_map(|r| extract_numeric_field(r, f))
                            .sum(),
                    };
                    result_groups.push((key, val));
                }

                return Ok(QueryResult::Grouped(result_groups));
            }

            // Ordering
            if let Some(ob) = order_by {
                filtered.sort_by(|a, b| {
                    let ord = compare_records_by_field(a, b, &ob.field);
                    if ob.direction == OrderDirection::Desc {
                        ord.reverse()
                    } else {
                        ord
                    }
                });
            }

            // Offset & Limit
            let start = offset.unwrap_or(0);
            let iter = filtered.into_iter().skip(start);
            let final_records: Vec<RecordSummary> = match limit {
                Some(n) => iter.take(n).map(|r| RecordSummary::from(&r)).collect(),
                None => iter.map(|r| RecordSummary::from(&r)).collect(),
            };

            Ok(QueryResult::Records(final_records))
        }
    }
}

// Filter Evaluation

fn evaluate_filter(record: &Record, filter: Option<&FilterExpr>) -> bool {
    match filter {
        None => true,
        Some(f) => eval_expr(record, f),
    }
}

fn eval_expr(r: &Record, f: &FilterExpr) -> bool {
    match f {
        FilterExpr::And(left, right) => eval_expr(r, left) && eval_expr(r, right),
        FilterExpr::Or(left, right) => eval_expr(r, left) || eval_expr(r, right),
        FilterExpr::Not(expr) => !eval_expr(r, expr),

        FilterExpr::Exists { field } => extract_field(r, field).is_some(),

        FilterExpr::IsNull { field, negated } => {
            let is_null = matches!(
                extract_field(r, field),
                None | Some(serde_json::Value::Null)
            );
            if *negated {
                !is_null
            } else {
                is_null
            }
        }

        FilterExpr::Contains { field, substring } => {
            if let Some(val_str) = extract_field_as_string(r, field) {
                val_str.contains(substring)
            } else {
                false
            }
        }

        FilterExpr::In { field, values } => {
            if let Some(actual) = extract_field(r, field) {
                values.iter().any(|v| values_equal(&actual, v))
            } else {
                false
            }
        }

        FilterExpr::Between { field, min, max } => {
            if let Some(actual) = extract_field(r, field) {
                let gte_min = compare_json_to_literal(&actual, min)
                    .map(|o| o == Ordering::Greater || o == Ordering::Equal)
                    .unwrap_or(false);
                let lte_max = compare_json_to_literal(&actual, max)
                    .map(|o| o == Ordering::Less || o == Ordering::Equal)
                    .unwrap_or(false);
                gte_min && lte_max
            } else {
                false
            }
        }

        FilterExpr::Comparison { field, op, value } => {
            let actual = match extract_field(r, field) {
                Some(v) => v,
                None => return false,
            };

            match op {
                CmpOp::Eq => values_equal(&actual, value),
                CmpOp::Neq => !values_equal(&actual, value),
                CmpOp::Lt => compare_json_to_literal(&actual, value) == Some(Ordering::Less),
                CmpOp::Lte => {
                    let ord = compare_json_to_literal(&actual, value);
                    ord == Some(Ordering::Less) || ord == Some(Ordering::Equal)
                }
                CmpOp::Gt => compare_json_to_literal(&actual, value) == Some(Ordering::Greater),
                CmpOp::Gte => {
                    let ord = compare_json_to_literal(&actual, value);
                    ord == Some(Ordering::Greater) || ord == Some(Ordering::Equal)
                }
                CmpOp::Like => {
                    if let (Some(actual_str), LiteralValue::String(pattern)) =
                        (actual.as_str(), value)
                    {
                        pattern_matches(actual_str, pattern)
                    } else {
                        false
                    }
                }
            }
        }
    }
}

// Field Extraction & Value Comparison

fn extract_field(r: &Record, path: &str) -> Option<serde_json::Value> {
    // Special built-in system fields
    match path.to_lowercase().as_str() {
        "id" => return Some(serde_json::Value::Number(r.id.into())),
        "timestamp" => return Some(serde_json::Value::Number(r.timestamp.into())),
        "date" => {
            let dt = chrono::DateTime::from_timestamp(r.timestamp / 1_000_000, 0)?;
            return Some(serde_json::Value::String(dt.format("%Y-%m-%d").to_string()));
        }
        "author" => return Some(serde_json::Value::String(r.author_hex())),
        "is_correction" => return Some(serde_json::Value::Bool(r.is_correction())),
        "correction_of" => {
            return r
                .correction_of
                .map(|id| serde_json::Value::Number(id.into()))
                .or(Some(serde_json::Value::Null));
        }
        "table" => return Some(serde_json::Value::String(r.table.clone())),
        _ => {}
    }

    // JSON payload fields (supports nested dotted paths like customer.name)
    let json_val: serde_json::Value = serde_json::from_slice(&r.data).ok()?;
    let mut current = &json_val;
    for part in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

fn extract_field_as_string(r: &Record, path: &str) -> Option<String> {
    match extract_field(r, path)? {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn extract_numeric_field(r: &Record, path: &str) -> Option<f64> {
    match extract_field(r, path)? {
        serde_json::Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

fn values_equal(json: &serde_json::Value, lit: &LiteralValue) -> bool {
    match (json, lit) {
        (serde_json::Value::Number(n), LiteralValue::Integer(i)) => n.as_i64() == Some(*i),
        (serde_json::Value::Number(n), LiteralValue::Float(f)) => n
            .as_f64()
            .map(|v| (v - f).abs() < f64::EPSILON)
            .unwrap_or(false),
        (serde_json::Value::String(s), LiteralValue::String(lit_str)) => s == lit_str,
        (serde_json::Value::Bool(b), LiteralValue::Boolean(lit_b)) => b == lit_b,
        (serde_json::Value::Null, LiteralValue::Null) => true,
        _ => false,
    }
}

fn compare_json_to_literal(json: &serde_json::Value, lit: &LiteralValue) -> Option<Ordering> {
    match (json, lit) {
        (serde_json::Value::Number(n), LiteralValue::Integer(i)) => {
            let actual = n.as_i64()?;
            Some(actual.cmp(i))
        }
        (serde_json::Value::Number(n), LiteralValue::Float(f)) => {
            let actual = n.as_f64()?;
            actual.partial_cmp(f)
        }
        (serde_json::Value::String(s), LiteralValue::String(lit_str)) => Some(s.cmp(lit_str)),
        _ => None,
    }
}

fn compare_records_by_field(a: &Record, b: &Record, field: &str) -> Ordering {
    let val_a = extract_field(a, field);
    let val_b = extract_field(b, field);

    match (val_a, val_b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(serde_json::Value::Number(na)), Some(serde_json::Value::Number(nb))) => {
            let fa = na.as_f64().unwrap_or(0.0);
            let fb = nb.as_f64().unwrap_or(0.0);
            fa.partial_cmp(&fb).unwrap_or(Ordering::Equal)
        }
        (Some(serde_json::Value::String(sa)), Some(serde_json::Value::String(sb))) => sa.cmp(&sb),
        (Some(serde_json::Value::Bool(ba)), Some(serde_json::Value::Bool(bb))) => ba.cmp(&bb),
        _ => Ordering::Equal,
    }
}

fn pattern_matches(text: &str, pattern: &str) -> bool {
    let regex_pattern = pattern.replace('%', ".*").replace('_', ".");
    if let Ok(re) = regex_syntax::Parser::new().parse(&regex_pattern) {
        let _ = re;
    }
    // Simple substring or prefix/suffix check for %
    if pattern.starts_with('%') && pattern.ends_with('%') && pattern.len() > 1 {
        let needle = &pattern[1..pattern.len() - 1];
        text.contains(needle)
    } else if let Some(suffix) = pattern.strip_prefix('%') {
        text.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('%') {
        text.starts_with(prefix)
    } else {
        text == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use tempfile::tempdir;

    #[test]
    fn test_execute_append_read_and_aggregate() {
        let dir = tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();

        // 1. Append
        let q1 = Parser::parse_str(r#"APPEND TO "sales" { "customer": "Alice", "amount": 1500 }"#)
            .unwrap();
        let res1 = execute(q1, &mut store).unwrap();
        assert!(matches!(res1, QueryResult::Appended(_)));

        let q2 = Parser::parse_str(r#"APPEND TO "sales" { "customer": "Bob", "amount": 2500 }"#)
            .unwrap();
        execute(q2, &mut store).unwrap();

        let q3 = Parser::parse_str(r#"APPEND TO "sales" { "customer": "Charlie", "amount": 500 }"#)
            .unwrap();
        execute(q3, &mut store).unwrap();

        // 2. Read with WHERE amount > 1000
        let q_read =
            Parser::parse_str(r#"READ FROM "sales" WHERE amount > 1000 ORDER BY amount DESC"#)
                .unwrap();
        let res_read = execute(q_read, &mut store).unwrap();
        if let QueryResult::Records(recs) = res_read {
            assert_eq!(recs.len(), 2);
            assert_eq!(recs[0].data["customer"], "Bob");
            assert_eq!(recs[1].data["customer"], "Alice");
        } else {
            panic!("Expected records");
        }

        // 3. Count
        let q_count = Parser::parse_str(r#"COUNT FROM "sales" WHERE amount >= 1500"#).unwrap();
        let res_count = execute(q_count, &mut store).unwrap();
        if let QueryResult::Scalar(c) = res_count {
            assert_eq!(c, 2.0);
        } else {
            panic!("Expected scalar");
        }

        // 4. Sum
        let q_sum = Parser::parse_str(r#"SUM amount FROM "sales""#).unwrap();
        let res_sum = execute(q_sum, &mut store).unwrap();
        if let QueryResult::Scalar(s) = res_sum {
            assert_eq!(s, 4500.0);
        } else {
            panic!("Expected scalar");
        }
    }

    #[test]
    fn test_execute_correct_and_history() {
        let dir = tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();

        let q1 = Parser::parse_str(r#"APPEND TO "sales" { "customer": "Alice", "amount": 1000 }"#)
            .unwrap();
        execute(q1, &mut store).unwrap();

        let q_corr = Parser::parse_str(r#"CORRECT record #0 WITH { "customer": "Alice", "amount": 1200 }, reason: "correction of typo""#).unwrap();
        let res_corr = execute(q_corr, &mut store).unwrap();
        assert!(matches!(res_corr, QueryResult::Corrected(_)));

        let q_hist = Parser::parse_str(r#"HISTORY OF record #0"#).unwrap();
        let res_hist = execute(q_hist, &mut store).unwrap();
        if let QueryResult::History(h) = res_hist {
            assert_eq!(h.len(), 2);
            assert_eq!(h[0].data["amount"], 1000);
            assert_eq!(h[1].data["amount"], 1200);
        } else {
            panic!("Expected history");
        }
    }

    #[test]
    fn test_authenticated_query_enforcement() {
        let dir = tempdir().unwrap();
        let (mut store, admin_kp) = Store::init_with_admin(dir.path(), None).unwrap();

        let alice_kp = Keypair::generate();
        let bob_kp = Keypair::generate();

        // Admin grants Alice writer on "sales"
        store
            .grant(
                &admin_kp,
                alice_kp.public_key(),
                "alice",
                Role::Writer,
                vec!["sales".to_string()],
                None,
            )
            .unwrap();

        // Admin grants Bob reader on "sales"
        store
            .grant(
                &admin_kp,
                bob_kp.public_key(),
                "bob",
                Role::Reader,
                vec!["sales".to_string()],
                None,
            )
            .unwrap();

        // 1. Anonymous query fails
        let res_anon =
            crate::query_authenticated(&mut store, r#"APPEND TO "sales" { "amount": 100 }"#, None);
        assert!(res_anon.is_err());
        assert!(res_anon.unwrap_err().contains("Access denied"));

        // 2. Bob (reader) attempting to append fails
        let res_bob_write = crate::query_authenticated(
            &mut store,
            r#"APPEND TO "sales" { "amount": 100 }"#,
            Some(&bob_kp.public_key()),
        );
        assert!(res_bob_write.is_err());
        assert!(res_bob_write.unwrap_err().contains("Access denied"));

        // 3. Alice (writer) appending succeeds
        let res_alice_write = crate::query_authenticated(
            &mut store,
            r#"APPEND TO "sales" { "amount": 100 }"#,
            Some(&alice_kp.public_key()),
        );
        assert!(res_alice_write.is_ok());

        // 4. Alice (writer) reading fails (separation of duties!)
        let res_alice_read = crate::query_authenticated(
            &mut store,
            r#"READ FROM "sales""#,
            Some(&alice_kp.public_key()),
        );
        assert!(res_alice_read.is_err());

        // 5. Bob (reader) reading succeeds!
        let res_bob_read = crate::query_authenticated(
            &mut store,
            r#"READ FROM "sales""#,
            Some(&bob_kp.public_key()),
        );
        assert!(res_bob_read.is_ok());

        // 6. Bob reading unauthorized table "invoices" fails
        let res_bob_invoices = crate::query_authenticated(
            &mut store,
            r#"READ FROM "invoices""#,
            Some(&bob_kp.public_key()),
        );
        assert!(res_bob_invoices.is_err());
    }
}
