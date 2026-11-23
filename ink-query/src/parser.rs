//! Parser for the Ink Query Language (IQL).

use crate::ast::*;
use crate::lexer::{Lexer, Token};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse_str(input: &str) -> Result<Statement, String> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        parser.parse_statement()
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            tok
        } else {
            Token::Eof
        }
    }

    fn expect(&mut self, expected: Token) -> Result<(), String> {
        let tok = self.advance();
        if tok == expected {
            Ok(())
        } else {
            Err(format!("Expected '{:?}', found '{:?}'", expected, tok))
        }
    }

    pub fn parse_statement(&mut self) -> Result<Statement, String> {
        match self.peek() {
            // Prohibited keywords checks with helpful advice
            Token::Update => Err(
                "UPDATE is not supported by Ink. Records are immutable. To correct a record, use:\n  CORRECT record #<id> WITH { ... }, reason: \"...\"".to_string()
            ),
            Token::Delete => Err(
                "DELETE is not supported by Ink. Records cannot be erased. To supersede a record, append a correction with:\n  CORRECT record #<id> WITH { ... }, reason: \"...\"".to_string()
            ),
            Token::Drop => Err(
                "DROP TABLE is not supported by Ink. Tables in Ink are immutable views over the append-only log.".to_string()
            ),
            Token::Truncate => Err(
                "TRUNCATE is not supported by Ink. The database log is permanent and append-only.".to_string()
            ),
            Token::Alter => Err(
                "ALTER TABLE is not supported. Ink is schemaless; JSON payloads can have arbitrary keys.".to_string()
            ),

            Token::Append => self.parse_append(),
            Token::Read => self.parse_read(),
            Token::Correct => self.parse_correct(),
            Token::History => self.parse_history(),
            Token::Verify => self.parse_verify(),
            Token::Count => self.parse_count(),
            Token::Sum | Token::Avg | Token::Min | Token::Max => self.parse_aggregate(),
            Token::Tables => {
                self.advance();
                Ok(Statement::Tables)
            }
            Token::Status => {
                self.advance();
                Ok(Statement::Status)
            }

            tok => Err(format!("Unexpected statement beginning with '{:?}'", tok)),
        }
    }

    fn parse_append(&mut self) -> Result<Statement, String> {
        self.advance(); // consume APPEND
        self.expect(Token::To)?;

        let table = self.parse_table_name()?;
        let json_raw = match self.advance() {
            Token::JsonObject(s) => s,
            tok => return Err(format!("Expected JSON object '{{...}}', found '{:?}'", tok)),
        };

        let data: serde_json::Value = serde_json::from_str(&json_raw)
            .map_err(|e| format!("Invalid JSON payload in APPEND: {e}"))?;

        let signed_with = if self.peek() == &Token::Signed {
            self.advance();
            self.expect(Token::With)?;
            Some(self.parse_string_or_ident()?)
        } else {
            None
        };

        Ok(Statement::Append {
            table,
            data,
            signed_with,
        })
    }

    fn parse_correct(&mut self) -> Result<Statement, String> {
        self.advance(); // consume CORRECT
        self.expect(Token::Record)?;
        self.expect(Token::Hash)?;

        let original_id = match self.advance() {
            Token::IntLit(n) if n >= 0 => n as u64,
            tok => return Err(format!("Expected record integer ID, found '{:?}'", tok)),
        };

        self.expect(Token::With)?;

        let json_raw = match self.advance() {
            Token::JsonObject(s) => s,
            tok => return Err(format!("Expected JSON object '{{...}}', found '{:?}'", tok)),
        };

        let data: serde_json::Value = serde_json::from_str(&json_raw)
            .map_err(|e| format!("Invalid JSON in CORRECT payload: {e}"))?;

        self.expect(Token::Comma)?;
        self.expect(Token::Reason)?;
        self.expect(Token::Colon)?;

        let reason = self.parse_string_or_ident()?;

        let signed_with = if self.peek() == &Token::Signed {
            self.advance();
            self.expect(Token::With)?;
            Some(self.parse_string_or_ident()?)
        } else {
            None
        };

        Ok(Statement::Correct {
            original_id,
            data,
            reason,
            signed_with,
        })
    }

    fn parse_history(&mut self) -> Result<Statement, String> {
        self.advance(); // consume HISTORY
        self.expect(Token::Of)?;
        self.expect(Token::Record)?;
        self.expect(Token::Hash)?;

        let id = match self.advance() {
            Token::IntLit(n) if n >= 0 => n as u64,
            tok => return Err(format!("Expected record integer ID, found '{:?}'", tok)),
        };

        Ok(Statement::History { id })
    }

    fn parse_verify(&mut self) -> Result<Statement, String> {
        self.advance(); // consume VERIFY

        let target = match self.peek() {
            Token::All => {
                self.advance();
                VerifyTarget::All
            }
            Token::Record => {
                self.advance();
                self.expect(Token::Hash)?;
                match self.advance() {
                    Token::IntLit(n) if n >= 0 => VerifyTarget::Record(n as u64),
                    tok => return Err(format!("Expected record ID, found '{:?}'", tok)),
                }
            }
            Token::StringLit(_) | Token::Ident(_) => {
                let table = self.parse_table_name()?;
                VerifyTarget::Table(table)
            }
            tok => {
                return Err(format!(
                    "Expected 'ALL', record #ID, or table name, found '{:?}'",
                    tok
                ))
            }
        };

        Ok(Statement::Verify { target })
    }

    fn parse_read(&mut self) -> Result<Statement, String> {
        self.advance(); // consume READ
        self.expect(Token::From)?;

        let table = self.parse_table_name()?;
        let mut filter = None;
        let mut order_by = None;
        let mut limit = None;
        let mut offset = None;
        let mut group_by = None;

        if self.peek() == &Token::Where {
            self.advance();
            filter = Some(self.parse_filter()?);
        }

        if self.peek() == &Token::Order {
            self.advance();
            self.expect(Token::By)?;
            order_by = Some(self.parse_order_by()?);
        }

        if self.peek() == &Token::Group {
            self.advance();
            self.expect(Token::By)?;
            group_by = Some(self.parse_group_by()?);
        }

        if self.peek() == &Token::Limit {
            self.advance();
            match self.advance() {
                Token::IntLit(n) if n >= 0 => limit = Some(n as usize),
                tok => return Err(format!("Expected integer LIMIT, found '{:?}'", tok)),
            }
        }

        if self.peek() == &Token::Offset {
            self.advance();
            match self.advance() {
                Token::IntLit(n) if n >= 0 => offset = Some(n as usize),
                tok => return Err(format!("Expected integer OFFSET, found '{:?}'", tok)),
            }
        }

        Ok(Statement::Read {
            table,
            filter,
            order_by,
            limit,
            offset,
            group_by,
        })
    }

    fn parse_count(&mut self) -> Result<Statement, String> {
        self.advance(); // consume COUNT
        self.expect(Token::From)?;
        let table = self.parse_table_name()?;

        let filter = if self.peek() == &Token::Where {
            self.advance();
            Some(self.parse_filter()?)
        } else {
            None
        };

        Ok(Statement::Count { table, filter })
    }

    fn parse_aggregate(&mut self) -> Result<Statement, String> {
        let op = match self.advance() {
            Token::Sum => AggOp::Sum,
            Token::Avg => AggOp::Avg,
            Token::Min => AggOp::Min,
            Token::Max => AggOp::Max,
            tok => unreachable!("{:?}", tok),
        };

        let field = self.parse_field_name()?;
        self.expect(Token::From)?;
        let table = self.parse_table_name()?;

        let filter = if self.peek() == &Token::Where {
            self.advance();
            Some(self.parse_filter()?)
        } else {
            None
        };

        Ok(Statement::Aggregate {
            op,
            field,
            table,
            filter,
        })
    }

    fn parse_order_by(&mut self) -> Result<OrderBy, String> {
        let field = self.parse_field_name()?;
        let mut direction = OrderDirection::Asc;

        match self.peek() {
            Token::Newest => {
                self.advance();
                let _ = self.expect(Token::First);
                direction = OrderDirection::Desc;
            }
            Token::Oldest => {
                self.advance();
                let _ = self.expect(Token::First);
                direction = OrderDirection::Asc;
            }
            Token::Desc => {
                self.advance();
                direction = OrderDirection::Desc;
            }
            Token::Asc => {
                self.advance();
                direction = OrderDirection::Asc;
            }
            _ => {}
        }

        Ok(OrderBy { field, direction })
    }

    fn parse_group_by(&mut self) -> Result<GroupBy, String> {
        let field = self.parse_field_name()?;
        let mut agg = None;

        match self.peek() {
            Token::Count => {
                self.advance();
                agg = Some(GroupAgg::Count);
            }
            Token::Sum => {
                self.advance();
                let sum_field = self.parse_field_name()?;
                agg = Some(GroupAgg::Sum(sum_field));
            }
            _ => {}
        }

        Ok(GroupBy { field, agg })
    }

    fn parse_filter(&mut self) -> Result<FilterExpr, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_and()?;

        while self.peek() == &Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_unary()?;

        while self.peek() == &Token::And {
            self.advance();
            let right = self.parse_unary()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<FilterExpr, String> {
        if self.peek() == &Token::Not {
            self.advance();
            let expr = self.parse_unary()?;
            return Ok(FilterExpr::Not(Box::new(expr)));
        }

        if self.peek() == &Token::OpenParen {
            self.advance();
            let expr = self.parse_filter()?;
            self.expect(Token::CloseParen)?;
            return Ok(expr);
        }

        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<FilterExpr, String> {
        let field = self.parse_field_name()?;

        match self.peek() {
            Token::Eq => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Eq,
                    value: val,
                })
            }
            Token::Neq => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Neq,
                    value: val,
                })
            }
            Token::Lt => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Lt,
                    value: val,
                })
            }
            Token::Lte => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Lte,
                    value: val,
                })
            }
            Token::Gt => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Gt,
                    value: val,
                })
            }
            Token::Gte => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Gte,
                    value: val,
                })
            }
            Token::Like => {
                self.advance();
                let val = self.parse_literal_value()?;
                Ok(FilterExpr::Comparison {
                    field,
                    op: CmpOp::Like,
                    value: val,
                })
            }
            Token::Contains => {
                self.advance();
                let substr = self.parse_string_or_ident()?;
                Ok(FilterExpr::Contains {
                    field,
                    substring: substr,
                })
            }
            Token::Exists => {
                self.advance();
                Ok(FilterExpr::Exists { field })
            }
            Token::Is => {
                self.advance();
                let negated = if self.peek() == &Token::Not {
                    self.advance();
                    true
                } else {
                    false
                };
                self.expect(Token::Null)?;
                Ok(FilterExpr::IsNull { field, negated })
            }
            Token::In => {
                self.advance();
                self.expect(Token::OpenParen)?;
                let mut values = Vec::new();
                loop {
                    values.push(self.parse_literal_value()?);
                    if self.peek() == &Token::Comma {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.expect(Token::CloseParen)?;
                Ok(FilterExpr::In { field, values })
            }
            Token::Between => {
                self.advance();
                let min = self.parse_literal_value()?;
                self.expect(Token::And)?;
                let max = self.parse_literal_value()?;
                Ok(FilterExpr::Between { field, min, max })
            }
            tok => Err(format!(
                "Expected comparison operator after field '{}', found '{:?}'",
                field, tok
            )),
        }
    }

    fn parse_field_name(&mut self) -> Result<String, String> {
        let mut name = self.parse_string_or_ident()?;
        while self.peek() == &Token::Dot {
            self.advance();
            let sub = self.parse_string_or_ident()?;
            name.push('.');
            name.push_str(&sub);
        }
        Ok(name)
    }

    fn parse_table_name(&mut self) -> Result<String, String> {
        self.parse_string_or_ident()
    }

    fn parse_string_or_ident(&mut self) -> Result<String, String> {
        match self.advance() {
            Token::StringLit(s) => Ok(s),
            Token::Ident(s) => Ok(s),
            tok => Err(format!("Expected string or identifier, found '{:?}'", tok)),
        }
    }

    fn parse_literal_value(&mut self) -> Result<LiteralValue, String> {
        match self.advance() {
            Token::IntLit(n) => Ok(LiteralValue::Integer(n)),
            Token::FloatLit(f) => Ok(LiteralValue::Float(f)),
            Token::StringLit(s) => Ok(LiteralValue::String(s)),
            Token::Ident(s) => Ok(LiteralValue::String(s)),
            Token::True => Ok(LiteralValue::Boolean(true)),
            Token::False => Ok(LiteralValue::Boolean(false)),
            Token::Null => Ok(LiteralValue::Null),
            tok => Err(format!("Expected literal value, found '{:?}'", tok)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_append() {
        let stmt = Parser::parse_str(r#"APPEND TO "sales" { "customer": "John", "amount": 1500 }"#)
            .unwrap();
        match stmt {
            Statement::Append { table, data, .. } => {
                assert_eq!(table, "sales");
                assert_eq!(data["customer"], "John");
                assert_eq!(data["amount"], 1500);
            }
            _ => panic!("Expected append"),
        }
    }

    #[test]
    fn test_parse_read_with_filter() {
        let stmt = Parser::parse_str(
            r#"READ FROM "sales" WHERE amount > 1000 ORDER BY date NEWEST FIRST LIMIT 10"#,
        )
        .unwrap();
        match stmt {
            Statement::Read {
                table,
                filter,
                order_by,
                limit,
                ..
            } => {
                assert_eq!(table, "sales");
                assert!(filter.is_some());
                assert_eq!(limit, Some(10));
                let ord = order_by.unwrap();
                assert_eq!(ord.field, "date");
                assert_eq!(ord.direction, OrderDirection::Desc);
            }
            _ => panic!("Expected read"),
        }
    }

    #[test]
    fn test_prohibited_update() {
        let err = Parser::parse_str("UPDATE sales SET amount = 200").unwrap_err();
        assert!(err.contains("UPDATE is not supported"));
    }

    #[test]
    fn test_prohibited_delete() {
        let err = Parser::parse_str("DELETE FROM sales WHERE id = 1").unwrap_err();
        assert!(err.contains("DELETE is not supported"));
    }
}
