# 0004 — Ink Query Language Parser, Evaluator, and CLI

**Date:** 2026-11-19  
**Area:** Query

## Summary

Added the IQL lexer, parser, abstract syntax tree, evaluator, table reads, filters, ordering, aggregation, record correction history, verification statements, and query command integration.

## Main components

- `ink-query/src/lexer.rs`, `parser.rs`, `ast.rs`, and `evaluator.rs`.
- Query language reference and CLI integration.

## Verification record

Parser and evaluator coverage was recorded with this implementation.
