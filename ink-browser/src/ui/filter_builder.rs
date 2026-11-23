//! Visual filter builder and safe IQL query generator.
//!
//! Provides the structured filter model (`FilterCondition`, `FilterOperator`, `FilterBuilder`)
//! that safely constructs parameterized IQL `WHERE` clauses without injection risks.

use std::fmt;

/// Comparison and predicate operators supported in the visual filter builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOperator {
    /// Equal (`=`)
    Eq,
    /// Not Equal (`!=`)
    Neq,
    /// Less Than (`<`)
    Lt,
    /// Less Than or Equal (`<=`)
    Lte,
    /// Greater Than (`>`)
    Gt,
    /// Greater Than or Equal (`>=`)
    Gte,
    /// Substring match (`CONTAINS`)
    Contains,
    /// Pattern match (`LIKE`)
    Like,
    /// Check if field is null (`IS NULL`)
    IsNull,
    /// Check if field is not null (`IS NOT NULL`)
    IsNotNull,
    /// Check if field exists (`EXISTS`)
    Exists,
}

impl FilterOperator {
    /// List of all operators for dropdown UI selection.
    pub const ALL: [FilterOperator; 11] = [
        FilterOperator::Eq,
        FilterOperator::Neq,
        FilterOperator::Lt,
        FilterOperator::Lte,
        FilterOperator::Gt,
        FilterOperator::Gte,
        FilterOperator::Contains,
        FilterOperator::Like,
        FilterOperator::IsNull,
        FilterOperator::IsNotNull,
        FilterOperator::Exists,
    ];

    /// User-facing label in the UI dropdown.
    pub fn label(&self) -> &'static str {
        match self {
            FilterOperator::Eq => "= (equals)",
            FilterOperator::Neq => "!= (not equals)",
            FilterOperator::Lt => "< (less than)",
            FilterOperator::Lte => "<= (less than or equal)",
            FilterOperator::Gt => "> (greater than)",
            FilterOperator::Gte => ">= (greater than or equal)",
            FilterOperator::Contains => "contains (substring)",
            FilterOperator::Like => "like (wildcard)",
            FilterOperator::IsNull => "is null",
            FilterOperator::IsNotNull => "is not null",
            FilterOperator::Exists => "exists",
        }
    }

    /// Whether this operator expects a user-supplied value.
    pub fn requires_value(&self) -> bool {
        !matches!(
            self,
            FilterOperator::IsNull | FilterOperator::IsNotNull | FilterOperator::Exists
        )
    }
}

impl fmt::Display for FilterOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterOperator::Eq => write!(f, "="),
            FilterOperator::Neq => write!(f, "!="),
            FilterOperator::Lt => write!(f, "<"),
            FilterOperator::Lte => write!(f, "<="),
            FilterOperator::Gt => write!(f, ">"),
            FilterOperator::Gte => write!(f, ">="),
            FilterOperator::Contains => write!(f, "CONTAINS"),
            FilterOperator::Like => write!(f, "LIKE"),
            FilterOperator::IsNull => write!(f, "IS NULL"),
            FilterOperator::IsNotNull => write!(f, "IS NOT NULL"),
            FilterOperator::Exists => write!(f, "EXISTS"),
        }
    }
}

/// A single predicate condition in the filter builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterCondition {
    /// Field path to filter on (e.g. `customer` or `user.email` or `id`).
    pub field: String,
    /// Comparison operator.
    pub op: FilterOperator,
    /// User-entered string value.
    pub value: String,
}

impl FilterCondition {
    /// Create a new condition.
    pub fn new(field: impl Into<String>, op: FilterOperator, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op,
            value: value.into(),
        }
    }

    /// Render this single condition into an injection-safe IQL expression.
    pub fn to_iql_expression(&self) -> Option<String> {
        let field_trimmed = self.field.trim();
        if field_trimmed.is_empty() {
            return None;
        }

        let safe_field = escape_field_name(field_trimmed);

        match self.op {
            FilterOperator::IsNull => Some(format!("{} IS NULL", safe_field)),
            FilterOperator::IsNotNull => Some(format!("{} IS NOT NULL", safe_field)),
            FilterOperator::Exists => Some(format!("{} EXISTS", safe_field)),
            FilterOperator::Contains => {
                let safe_val = escape_string_literal(&self.value);
                Some(format!("{} CONTAINS {}", safe_field, safe_val))
            }
            FilterOperator::Like => {
                let safe_val = escape_string_literal(&self.value);
                Some(format!("{} LIKE {}", safe_field, safe_val))
            }
            FilterOperator::Eq
            | FilterOperator::Neq
            | FilterOperator::Lt
            | FilterOperator::Lte
            | FilterOperator::Gt
            | FilterOperator::Gte => {
                let safe_val = format_literal_value(&self.value);
                Some(format!("{} {} {}", safe_field, self.op, safe_val))
            }
        }
    }
}

/// Manager for building a list of conditions and combining them with `AND`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterBuilder {
    /// List of user-defined conditions.
    pub conditions: Vec<FilterCondition>,
}

impl FilterBuilder {
    /// Create a new empty filter builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new condition.
    pub fn add_condition(&mut self, condition: FilterCondition) {
        self.conditions.push(condition);
    }

    /// Remove a condition by its index.
    pub fn remove_condition(&mut self, index: usize) {
        if index < self.conditions.len() {
            self.conditions.remove(index);
        }
    }

    /// Clear all conditions.
    pub fn clear(&mut self) {
        self.conditions.clear();
    }

    /// Check if any active conditions exist.
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Generate an injection-safe IQL `WHERE <filter>` clause string, or `None` if empty.
    pub fn to_where_clause(&self) -> Option<String> {
        let parts: Vec<String> = self
            .conditions
            .iter()
            .filter_map(|c| c.to_iql_expression())
            .collect();

        if parts.is_empty() {
            None
        } else {
            Some(format!("WHERE {}", parts.join(" AND ")))
        }
    }

    /// Generate just the filter expression (without the `WHERE` keyword).
    pub fn to_filter_expression(&self) -> Option<String> {
        let parts: Vec<String> = self
            .conditions
            .iter()
            .filter_map(|c| c.to_iql_expression())
            .collect();

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" AND "))
        }
    }
}

/// Safely escape a field name for IQL.
///
/// If the field is a standard alphanumeric/dot identifier (e.g. `amount` or `user.name`),
/// it is returned as is. Otherwise it is escaped as a double-quoted string.
fn escape_field_name(field: &str) -> String {
    let is_ident = !field.is_empty()
        && field
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');

    if is_ident {
        field.to_string()
    } else {
        escape_string_literal(field)
    }
}

/// Safely format a literal value for IQL comparisons.
///
/// If the string is a valid integer, float, or boolean, it is formatted without quotes.
/// Otherwise, it is formatted as a safely escaped double-quoted string literal.
fn format_literal_value(val: &str) -> String {
    let trimmed = val.trim();

    // Check for boolean literals
    if trimmed.eq_ignore_ascii_case("true") {
        return "true".to_string();
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return "false".to_string();
    }

    // Check for integer literals (including negative integers)
    if let Ok(_n) = trimmed.parse::<i64>() {
        return trimmed.to_string();
    }

    // Check for float literals
    if let Ok(_f) = trimmed.parse::<f64>() {
        // Ensure it contains a dot or exponent to differentiate from integers
        if trimmed.contains('.') || trimmed.contains('e') || trimmed.contains('E') {
            return trimmed.to_string();
        }
    }

    // Default to escaped string literal
    escape_string_literal(val)
}

/// Safely escape and quote a string literal for IQL syntax.
///
/// Escapes backslashes, double quotes, newlines, carriage returns, and tabs.
fn escape_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_builder_empty() {
        let fb = FilterBuilder::new();
        assert!(fb.is_empty());
        assert_eq!(fb.to_where_clause(), None);
        assert_eq!(fb.to_filter_expression(), None);
    }

    #[test]
    fn test_filter_builder_single_condition() {
        let mut fb = FilterBuilder::new();
        fb.add_condition(FilterCondition::new("amount", FilterOperator::Gt, "1000"));

        assert_eq!(
            fb.to_where_clause(),
            Some("WHERE amount > 1000".to_string())
        );
        assert_eq!(fb.to_filter_expression(), Some("amount > 1000".to_string()));
    }

    #[test]
    fn test_filter_builder_multiple_and_conditions() {
        let mut fb = FilterBuilder::new();
        fb.add_condition(FilterCondition::new(
            "customer",
            FilterOperator::Eq,
            "Acme Corp",
        ));
        fb.add_condition(FilterCondition::new("amount", FilterOperator::Gte, "500"));
        fb.add_condition(FilterCondition::new(
            "status",
            FilterOperator::Neq,
            "cancelled",
        ));

        let expected =
            "WHERE customer = \"Acme Corp\" AND amount >= 500 AND status != \"cancelled\"";
        assert_eq!(fb.to_where_clause(), Some(expected.to_string()));
    }

    #[test]
    fn test_filter_builder_operators() {
        let mut fb = FilterBuilder::new();
        fb.add_condition(FilterCondition::new(
            "description",
            FilterOperator::Contains,
            "widget",
        ));
        fb.add_condition(FilterCondition::new("code", FilterOperator::Like, "WIDG-%"));
        fb.add_condition(FilterCondition::new(
            "deleted_at",
            FilterOperator::IsNull,
            "",
        ));
        fb.add_condition(FilterCondition::new(
            "active_at",
            FilterOperator::IsNotNull,
            "",
        ));
        fb.add_condition(FilterCondition::new("metadata", FilterOperator::Exists, ""));

        let expected = "WHERE description CONTAINS \"widget\" AND code LIKE \"WIDG-%\" AND deleted_at IS NULL AND active_at IS NOT NULL AND metadata EXISTS";
        assert_eq!(fb.to_where_clause(), Some(expected.to_string()));
    }

    #[test]
    fn test_filter_builder_escapes_injection_attempts() {
        let mut fb = FilterBuilder::new();

        // SQL injection payload with quotes and comments
        let malicious_input = "Acme\"; DROP TABLE sales; --";
        fb.add_condition(FilterCondition::new(
            "name",
            FilterOperator::Eq,
            malicious_input,
        ));

        let expr = fb.to_filter_expression().expect("Expression");
        assert_eq!(expr, "name = \"Acme\\\"; DROP TABLE sales; --\"");

        // Field with spaces and special characters
        fb.clear();
        fb.add_condition(FilterCondition::new(
            "user field with spaces",
            FilterOperator::Eq,
            "test",
        ));
        let expr = fb.to_filter_expression().expect("Expression");
        assert_eq!(expr, "\"user field with spaces\" = \"test\"");
    }

    #[test]
    fn test_filter_builder_literal_types() {
        let mut fb = FilterBuilder::new();
        fb.add_condition(FilterCondition::new(
            "is_active",
            FilterOperator::Eq,
            "true",
        ));
        fb.add_condition(FilterCondition::new("ratio", FilterOperator::Lt, "0.75"));
        fb.add_condition(FilterCondition::new("count", FilterOperator::Eq, "-42"));

        let expected = "WHERE is_active = true AND ratio < 0.75 AND count = -42";
        assert_eq!(fb.to_where_clause(), Some(expected.to_string()));
    }

    #[test]
    fn test_filter_builder_mutation() {
        let mut fb = FilterBuilder::new();
        fb.add_condition(FilterCondition::new("a", FilterOperator::Eq, "1"));
        fb.add_condition(FilterCondition::new("b", FilterOperator::Eq, "2"));
        assert_eq!(fb.conditions.len(), 2);

        fb.remove_condition(0);
        assert_eq!(fb.conditions.len(), 1);
        assert_eq!(fb.conditions[0].field, "b");

        fb.clear();
        assert!(fb.is_empty());
    }
}
