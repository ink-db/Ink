//! Abstract Syntax Tree (AST) definitions for IQL (Ink Query Language).

use serde::{Deserialize, Serialize};

/// Top-level statements in IQL.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// `APPEND TO "table" { json } [SIGNED WITH "key_path"]`
    Append {
        table: String,
        data: serde_json::Value,
        signed_with: Option<String>,
    },

    /// `READ FROM "table" [WHERE filter] [ORDER BY field [ASC|DESC]] [LIMIT n] [OFFSET m] [GROUP BY field ...]`
    Read {
        table: String,
        filter: Option<FilterExpr>,
        order_by: Option<OrderBy>,
        limit: Option<usize>,
        offset: Option<usize>,
        group_by: Option<GroupBy>,
    },

    /// `CORRECT record #42 WITH { json }, reason: "text" [SIGNED WITH "key_path"]`
    Correct {
        original_id: u64,
        data: serde_json::Value,
        reason: String,
        signed_with: Option<String>,
    },

    /// `HISTORY OF record #42`
    History { id: u64 },

    /// `VERIFY "table"` or `VERIFY ALL` or `VERIFY record #42`
    Verify { target: VerifyTarget },

    /// `COUNT FROM "table" [WHERE filter]`
    Count {
        table: String,
        filter: Option<FilterExpr>,
    },

    /// `SUM|AVG|MIN|MAX field FROM "table" [WHERE filter]`
    Aggregate {
        op: AggOp,
        field: String,
        table: String,
        filter: Option<FilterExpr>,
    },

    /// `TABLES`
    Tables,

    /// `STATUS`
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyTarget {
    All,
    Table(String),
    Record(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggOp {
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrderBy {
    pub field: String,
    pub direction: OrderDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupBy {
    pub field: String,
    pub agg: Option<GroupAgg>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GroupAgg {
    Count,
    Sum(String),
}

/// Filter expressions used in `WHERE` clauses.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
    Comparison {
        field: String,
        op: CmpOp,
        value: LiteralValue,
    },
    In {
        field: String,
        values: Vec<LiteralValue>,
    },
    Between {
        field: String,
        min: LiteralValue,
        max: LiteralValue,
    },
    Contains {
        field: String,
        substring: String,
    },
    Exists {
        field: String,
    },
    IsNull {
        field: String,
        negated: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    Like,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LiteralValue {
    Integer(i64),
    Float(f64),
    String(String),
    Boolean(bool),
    Null,
}
