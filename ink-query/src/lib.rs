//! # ink-query
//!
//! Query language (IQL) parser and evaluator for the Ink immutable database.
//!
//! Provides near-natural-language query syntax:
//! - `APPEND TO "sales" { customer: "John", amount: 1500 } [SIGNED WITH "key"]`
//! - `READ FROM "sales" WHERE amount > 1000 ORDER BY date NEWEST FIRST LIMIT 10`
//! - `CORRECT record #42 WITH { amount: 1200 }, reason: "typo"`
//! - `HISTORY OF record #42`
//! - `VERIFY "sales"`
//! - `COUNT FROM "sales" WHERE amount > 500`
//! - `SUM amount FROM "sales" WHERE date >= 2024-01-01`
//! - `TABLES`
//! - `STATUS`

pub mod ast;
pub mod evaluator;
pub mod lexer;
pub mod parser;

pub use ast::{FilterExpr, LiteralValue, OrderBy, OrderDirection, Statement};
pub use evaluator::{
    authorize_statement, execute, QueryResult, RecordSummary, StatusSummary, VerifySummary,
};
pub use parser::Parser;

use ink_core::Store;

/// Parse an IQL query string and execute it against an open database `Store` without credentials.
///
/// If the database has active access controls configured in `_ink_access`, this will fail with
/// an authentication error. For authenticated execution, use [`query_authenticated`].
pub fn query(store: &mut Store, query_str: &str) -> Result<QueryResult, String> {
    query_authenticated(store, query_str, None)
}

/// Parse an IQL query string, validate permissions against the database's `_ink_access`
/// registry using the caller's Ed25519 public key, and execute the statement.
pub fn query_authenticated(
    store: &mut Store,
    query_str: &str,
    caller_key: Option<&[u8; 32]>,
) -> Result<QueryResult, String> {
    let statement: Statement = Parser::parse_str(query_str)?;
    authorize_statement(&statement, store, caller_key)?;
    execute(statement, store)
}
