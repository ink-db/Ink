//! Lexer for the Ink Query Language (IQL).

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Append,
    To,
    Signed,
    With,
    Read,
    From,
    Where,
    Order,
    By,
    Limit,
    Offset,
    Group,
    Newest,
    Oldest,
    First,
    Asc,
    Desc,
    Correct,
    Record,
    Reason,
    History,
    Of,
    Verify,
    All,
    Count,
    Sum,
    Avg,
    Min,
    Max,
    Tables,
    Status,
    And,
    Or,
    Not,
    In,
    Between,
    Contains,
    Exists,
    Is,
    Null,
    Like,
    True,
    False,

    // Prohibited keywords (for friendly errors)
    Update,
    Delete,
    Drop,
    Truncate,
    Alter,

    // Punctuation
    OpenParen,
    CloseParen,
    Comma,
    Colon,
    Hash,
    Dot,

    // Comparison Operators
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,

    // Literals
    Ident(String),
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    JsonObject(String), // Raw JSON literal string between balanced { ... }

    Eof,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Ident(s) => write!(f, "{}", s),
            Token::StringLit(s) => write!(f, "\"{}\"", s),
            Token::IntLit(n) => write!(f, "{}", n),
            Token::FloatLit(n) => write!(f, "{}", n),
            Token::JsonObject(s) => write!(f, "{{{}}}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

pub struct Lexer<'a> {
    input: &'a str,
    chars: Vec<(usize, char)>,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let chars = input.char_indices().collect();
        Self {
            input,
            chars,
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|(_, c)| *c)
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).map(|(_, c)| *c)
    }

    fn advance(&mut self) -> Option<char> {
        let res = self.chars.get(self.pos).map(|(_, c)| *c);
        if res.is_some() {
            self.pos += 1;
        }
        res
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else if c == '-' && self.peek_next() == Some('-') {
                // Line comment --
                while let Some(ch) = self.peek() {
                    self.advance();
                    if ch == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    pub fn next_token(&mut self) -> Result<Token, String> {
        self.skip_whitespace();

        let c = match self.peek() {
            Some(ch) => ch,
            None => return Ok(Token::Eof),
        };

        // Balanced JSON Object `{ ... }`
        if c == '{' {
            return self.read_json_object();
        }

        // Single punctuation & operators
        match c {
            '(' => {
                self.advance();
                return Ok(Token::OpenParen);
            }
            ')' => {
                self.advance();
                return Ok(Token::CloseParen);
            }
            ',' => {
                self.advance();
                return Ok(Token::Comma);
            }
            ':' => {
                self.advance();
                return Ok(Token::Colon);
            }
            '#' => {
                self.advance();
                return Ok(Token::Hash);
            }
            '.' => {
                self.advance();
                return Ok(Token::Dot);
            }
            '=' => {
                self.advance();
                return Ok(Token::Eq);
            }
            '!' => {
                if self.peek_next() == Some('=') {
                    self.advance();
                    self.advance();
                    return Ok(Token::Neq);
                }
            }
            '<' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    return Ok(Token::Lte);
                } else if self.peek() == Some('>') {
                    self.advance();
                    return Ok(Token::Neq);
                }
                return Ok(Token::Lt);
            }
            '>' => {
                self.advance();
                if self.peek() == Some('=') {
                    self.advance();
                    return Ok(Token::Gte);
                }
                return Ok(Token::Gt);
            }
            '"' | '\'' => {
                return self.read_string(c);
            }
            _ => {}
        }

        // Numbers (positive or negative)
        if c.is_ascii_digit()
            || (c == '-'
                && self
                    .peek_next()
                    .map(|n| n.is_ascii_digit())
                    .unwrap_or(false))
        {
            return self.read_number();
        }

        // Identifiers and Keywords
        if c.is_alphabetic() || c == '_' {
            return self.read_ident();
        }

        Err(format!("Unexpected character: '{}'", c))
    }

    fn read_json_object(&mut self) -> Result<Token, String> {
        let start = self.chars[self.pos].0;
        let mut depth = 0;
        let mut in_str = false;
        let mut escape = false;

        while let Some((_, ch)) = self.chars.get(self.pos) {
            let ch = *ch;
            self.advance();

            if in_str {
                if escape {
                    escape = false;
                } else if ch == '\\' {
                    escape = true;
                } else if ch == '"' {
                    in_str = false;
                }
            } else {
                match ch {
                    '"' => in_str = true,
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            let end = if self.pos < self.chars.len() {
                                self.chars[self.pos].0
                            } else {
                                self.input.len()
                            };
                            let raw = &self.input[start..end];
                            return Ok(Token::JsonObject(raw.to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }

        Err("Unterminated JSON object (missing closing '}')".to_string())
    }

    fn read_string(&mut self, quote: char) -> Result<Token, String> {
        self.advance(); // consume opening quote
        let mut val = String::new();
        let mut escape = false;

        while let Some(ch) = self.advance() {
            if escape {
                match ch {
                    'n' => val.push('\n'),
                    'r' => val.push('\r'),
                    't' => val.push('\t'),
                    '\\' => val.push('\\'),
                    '\'' => val.push('\''),
                    '"' => val.push('"'),
                    _ => val.push(ch),
                }
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == quote {
                return Ok(Token::StringLit(val));
            } else {
                val.push(ch);
            }
        }

        Err("Unterminated string literal".to_string())
    }

    fn read_number(&mut self) -> Result<Token, String> {
        let mut text = String::new();
        if self.peek() == Some('-') {
            text.push(self.advance().unwrap());
        }

        let mut has_dot = false;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                text.push(self.advance().unwrap());
            } else if ch == '.'
                && !has_dot
                && self
                    .peek_next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
            {
                has_dot = true;
                text.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        if has_dot {
            text.parse::<f64>()
                .map(Token::FloatLit)
                .map_err(|e| format!("Invalid float literal: {e}"))
        } else {
            text.parse::<i64>()
                .map(Token::IntLit)
                .map_err(|e| format!("Invalid integer literal: {e}"))
        }
    }

    fn read_ident(&mut self) -> Result<Token, String> {
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                name.push(self.advance().unwrap());
            } else {
                break;
            }
        }

        let upper = name.to_uppercase();
        let tok = match upper.as_str() {
            "APPEND" => Token::Append,
            "TO" => Token::To,
            "SIGNED" => Token::Signed,
            "WITH" => Token::With,
            "READ" => Token::Read,
            "FROM" => Token::From,
            "WHERE" => Token::Where,
            "ORDER" => Token::Order,
            "BY" => Token::By,
            "LIMIT" => Token::Limit,
            "OFFSET" => Token::Offset,
            "GROUP" => Token::Group,
            "NEWEST" => Token::Newest,
            "OLDEST" => Token::Oldest,
            "FIRST" => Token::First,
            "ASC" => Token::Asc,
            "DESC" => Token::Desc,
            "CORRECT" => Token::Correct,
            "RECORD" => Token::Record,
            "REASON" => Token::Reason,
            "HISTORY" => Token::History,
            "OF" => Token::Of,
            "VERIFY" => Token::Verify,
            "ALL" => Token::All,
            "COUNT" => Token::Count,
            "SUM" => Token::Sum,
            "AVG" => Token::Avg,
            "MIN" => Token::Min,
            "MAX" => Token::Max,
            "TABLES" => Token::Tables,
            "STATUS" => Token::Status,
            "AND" => Token::And,
            "OR" => Token::Or,
            "NOT" => Token::Not,
            "IN" => Token::In,
            "BETWEEN" => Token::Between,
            "CONTAINS" => Token::Contains,
            "EXISTS" => Token::Exists,
            "IS" => Token::Is,
            "NULL" => Token::Null,
            "LIKE" => Token::Like,
            "TRUE" => Token::True,
            "FALSE" => Token::False,

            // Prohibited SQL keywords
            "UPDATE" => Token::Update,
            "DELETE" => Token::Delete,
            "DROP" => Token::Drop,
            "TRUNCATE" => Token::Truncate,
            "ALTER" => Token::Alter,

            _ => Token::Ident(name),
        };

        Ok(tok)
    }

    /// Tokenize the entire input into a vector of tokens.
    pub fn tokenize(&mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            if tok == Token::Eof {
                tokens.push(Token::Eof);
                break;
            }
            tokens.push(tok);
        }
        Ok(tokens)
    }
}
