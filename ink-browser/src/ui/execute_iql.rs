//! Execute IQL statement tab for Ink Browser.
//!
//! Provides the interactive multi-line query console, Ctrl+Enter execution shortcut,
//! persistent statement history, structured result visualizer (records grid, scalar, grouped, status),
//! and educational guidance preventing prohibited SQL mutations (UPDATE, DELETE, DROP).

use crate::backend::Backend;
use crate::ui::browse::format_timestamp;
use eframe::egui::{self, Color32, RichText, Ui};
use ink_query::QueryResult;

/// Maximum number of statements retained in the in-memory history.
pub const MAX_HISTORY_ITEMS: usize = 50;

/// Information explaining why a prohibited keyword cannot be executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProhibitedKeywordWarning {
    /// Keyword detected (e.g. "UPDATE").
    pub keyword: &'static str,
    /// Educational explanation of Ink's immutability model.
    pub explanation: &'static str,
    /// Recommended alternative IQL statement.
    pub alternative: Option<&'static str>,
}

/// Detects whether an input string contains prohibited mutation keywords as standalone tokens.
pub fn detect_prohibited_keywords(input: &str) -> Option<ProhibitedKeywordWarning> {
    // Check for tokens outside of double-quoted string literals
    let mut in_str = false;
    let mut current_word = String::new();
    let mut words = Vec::new();

    for ch in input.chars() {
        if ch == '"' {
            in_str = !in_str;
            current_word.clear();
            continue;
        }

        if in_str {
            continue;
        }

        if ch.is_ascii_alphanumeric() || ch == '_' {
            current_word.push(ch);
        } else {
            if !current_word.is_empty() {
                words.push(std::mem::take(&mut current_word));
            }
        }
    }
    if !current_word.is_empty() {
        words.push(current_word);
    }

    for word in words {
        if word.eq_ignore_ascii_case("update") {
            return Some(ProhibitedKeywordWarning {
                keyword: "UPDATE",
                explanation: "UPDATE is not supported by Ink. Records are strictly immutable and historical versions can never be overwritten in-place.",
                alternative: Some("CORRECT record #<id> WITH { ... }, reason: \"...\""),
            });
        }
        if word.eq_ignore_ascii_case("delete") {
            return Some(ProhibitedKeywordWarning {
                keyword: "DELETE",
                explanation: "DELETE is not supported by Ink. Historical records cannot be erased. To supersede an obsolete record, append a signed correction.",
                alternative: Some("CORRECT record #<id> WITH { \"status\": \"superseded\" }, reason: \"...\""),
            });
        }
        if word.eq_ignore_ascii_case("drop") {
            return Some(ProhibitedKeywordWarning {
                keyword: "DROP",
                explanation: "DROP TABLE is not supported by Ink. Tables in Ink are immutable views over the permanent append-only log.",
                alternative: None,
            });
        }
        if word.eq_ignore_ascii_case("truncate") {
            return Some(ProhibitedKeywordWarning {
                keyword: "TRUNCATE",
                explanation: "TRUNCATE is not supported by Ink. The database log is permanent and tamper-evident.",
                alternative: None,
            });
        }
        if word.eq_ignore_ascii_case("alter") {
            return Some(ProhibitedKeywordWarning {
                keyword: "ALTER",
                explanation: "ALTER TABLE is not supported. Ink is schemaless; JSON payloads can have arbitrary keys on any record.",
                alternative: None,
            });
        }
    }

    None
}

/// State for the Execute IQL query tab.
pub struct ExecuteIqlView {
    /// Active query text in the multi-line editor.
    pub query_text: String,
    /// List of previously executed statements (most recent first).
    pub history: Vec<String>,
    /// Last execution result from the backend.
    pub last_result: Option<QueryResult>,
    /// Error message from last execution failure.
    pub error_message: Option<String>,
    /// Execution timing in milliseconds.
    pub execution_time_ms: Option<u128>,
    /// Educational warning if prohibited keywords are detected in the editor.
    pub prohibited_warning: Option<ProhibitedKeywordWarning>,
}

impl Default for ExecuteIqlView {
    fn default() -> Self {
        Self {
            query_text: "READ FROM \"sales\" LIMIT 50".to_string(),
            history: Vec::new(),
            last_result: None,
            error_message: None,
            execution_time_ms: None,
            prohibited_warning: None,
        }
    }
}

impl ExecuteIqlView {
    /// Render the Execute IQL view.
    pub fn show(&mut self, ui: &mut Ui, backend: &dyn Backend) {
        // 1. Prohibited keyword live check
        self.prohibited_warning = detect_prohibited_keywords(&self.query_text);

        // 2. Query Editor Header
        ui.horizontal(|ui| {
            ui.heading(RichText::new("Execute IQL Statement").strong());
            ui.add_space(15.0);

            let can_execute =
                !self.query_text.trim().is_empty() && self.prohibited_warning.is_none();

            if ui
                .add_enabled(
                    can_execute,
                    egui::Button::new(
                        RichText::new("Run (Ctrl+Enter)")
                            .color(if can_execute {
                                Color32::from_rgb(100, 220, 100)
                            } else {
                                Color32::GRAY
                            })
                            .strong(),
                    ),
                )
                .clicked()
            {
                self.execute(backend);
            }

            if ui.button("Clear").clicked() {
                self.query_text.clear();
            }

            // History dropdown
            if !self.history.is_empty() {
                ui.add_space(10.0);
                ui.menu_button("Statement History", |ui| {
                    ui.label(RichText::new("Recent Statements:").strong());
                    ui.separator();
                    let mut selected = None;
                    for (i, stmt) in self.history.iter().enumerate() {
                        let preview = if stmt.len() > 60 {
                            format!("{}...", &stmt[..57])
                        } else {
                            stmt.clone()
                        };
                        if ui
                            .selectable_label(false, format!("{}. {}", i + 1, preview))
                            .clicked()
                        {
                            selected = Some(stmt.clone());
                        }
                    }
                    if let Some(s) = selected {
                        self.query_text = s;
                    }
                });
            }

            // Execution timer
            if let Some(ms) = self.execution_time_ms {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Executed in {} ms", ms))
                            .color(Color32::GRAY)
                            .size(12.0),
                    );
                });
            }
        });

        ui.add_space(6.0);

        // 3. Educational Warning Banner for Prohibited Keywords
        if let Some(ref warn) = self.prohibited_warning {
            egui::Frame::new()
                .fill(Color32::from_rgb(80, 50, 15))
                .inner_margin(10.0)
                .corner_radius(4.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Prohibited Keyword: '{}'", warn.keyword))
                                .color(Color32::from_rgb(255, 200, 80))
                                .strong(),
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new(warn.explanation).color(Color32::WHITE));
                    if let Some(alt) = warn.alternative {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(format!("Alternative: {}", alt))
                                .color(Color32::from_rgb(180, 230, 255))
                                .monospace(),
                        );
                    }
                });
            ui.add_space(6.0);
        }

        // 4. Multi-line Query Editor
        let response = ui.add(
            egui::TextEdit::multiline(&mut self.query_text)
                .font(egui::TextStyle::Monospace)
                .desired_rows(6)
                .desired_width(f32::INFINITY)
                .hint_text(
                    "Enter IQL statement, e.g. READ FROM \"sales\" WHERE amount > 500 LIMIT 10",
                ),
        );

        // Check for Ctrl+Enter keyboard shortcut
        if response.has_focus()
            && ui.input(|i| {
                i.key_pressed(egui::Key::Enter) && (i.modifiers.ctrl || i.modifiers.command)
            })
            && self.prohibited_warning.is_none()
            && !self.query_text.trim().is_empty()
        {
            self.execute(backend);
        }

        ui.add_space(8.0);
        ui.separator();

        // 5. Error Banner
        if let Some(ref err) = self.error_message {
            ui.add_space(4.0);
            egui::Frame::new()
                .fill(Color32::from_rgb(80, 20, 20))
                .inner_margin(10.0)
                .corner_radius(4.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("Query Error: {}", err))
                            .color(Color32::WHITE)
                            .strong(),
                    );
                });
            ui.add_space(8.0);
        }

        // 6. Query Results Panel
        self.render_result(ui);
    }

    /// Execute the active statement against the backend.
    pub fn execute(&mut self, backend: &dyn Backend) {
        let trimmed = self.query_text.trim();
        if trimmed.is_empty() {
            return;
        }

        // Prohibited keywords safeguard
        if let Some(warn) = detect_prohibited_keywords(trimmed) {
            self.error_message = Some(format!(
                "Cannot execute: {} is prohibited in Ink's immutable data model.",
                warn.keyword
            ));
            return;
        }

        let start = std::time::Instant::now();
        match backend.execute_iql(trimmed) {
            Ok(result) => {
                self.execution_time_ms = Some(start.elapsed().as_millis());
                self.error_message = None;

                // Push to statement history with deduplication
                self.add_history(trimmed.to_string());
                self.last_result = Some(result);
            }
            Err(e) => {
                self.execution_time_ms = Some(start.elapsed().as_millis());
                self.error_message = Some(e.to_string());
                self.last_result = None;
            }
        }
    }

    /// Add a statement to the FIFO history.
    pub fn add_history(&mut self, stmt: String) {
        if let Some(pos) = self.history.iter().position(|s| s == &stmt) {
            self.history.remove(pos);
        }
        self.history.insert(0, stmt);
        if self.history.len() > MAX_HISTORY_ITEMS {
            self.history.truncate(MAX_HISTORY_ITEMS);
        }
    }

    fn render_result(&self, ui: &mut Ui) {
        let result = match &self.last_result {
            Some(res) => res,
            None => {
                if self.error_message.is_none() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(30.0);
                        ui.label(
                            RichText::new("Ready. Press 'Run' or Ctrl+Enter to evaluate IQL.")
                                .italics()
                                .color(Color32::GRAY),
                        );
                    });
                }
                return;
            }
        };

        match result {
            QueryResult::Records(recs) => {
                ui.horizontal(|ui| {
                    ui.heading(format!("Results ({} records)", recs.len()));
                });
                ui.add_space(6.0);

                if recs.is_empty() {
                    ui.label(
                        RichText::new("No matching records returned.")
                            .italics()
                            .color(Color32::GRAY),
                    );
                    return;
                }

                // Discover dynamic keys from the records
                let mut dyn_cols = Vec::new();
                for r in recs {
                    if let serde_json::Value::Object(map) = &r.data {
                        for k in map.keys() {
                            if !dyn_cols.contains(k) {
                                dyn_cols.push(k.clone());
                            }
                        }
                    }
                }

                egui::ScrollArea::both().show(ui, |ui| {
                    egui::Grid::new("iql_records_result_grid")
                        .striped(true)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            // Headers
                            ui.label(RichText::new("ID").strong());
                            ui.label(RichText::new("Timestamp").strong());
                            ui.label(RichText::new("Author").strong());
                            ui.label(RichText::new("Status").strong());

                            for col in &dyn_cols {
                                ui.label(
                                    RichText::new(col)
                                        .strong()
                                        .color(Color32::from_rgb(140, 200, 255)),
                                );
                            }
                            ui.end_row();

                            // Rows
                            for r in recs {
                                ui.label(RichText::new(format!("#{}", r.id)).strong());
                                ui.label(RichText::new(format_timestamp(r.timestamp)).monospace());
                                ui.label(
                                    RichText::new(format!(
                                        "key_{}...",
                                        &r.author[..8.min(r.author.len())]
                                    ))
                                    .monospace(),
                                );

                                if r.is_correction {
                                    ui.label(
                                        RichText::new("CORRECTION").color(Color32::GOLD).strong(),
                                    );
                                } else {
                                    ui.label(RichText::new("ORIGINAL").color(Color32::GREEN));
                                }

                                for col in &dyn_cols {
                                    let cell = r
                                        .data
                                        .get(col)
                                        .map(|v| match v {
                                            serde_json::Value::String(s) => s.clone(),
                                            serde_json::Value::Number(n) => n.to_string(),
                                            serde_json::Value::Bool(b) => b.to_string(),
                                            serde_json::Value::Null => "null".to_string(),
                                            other => other.to_string(),
                                        })
                                        .unwrap_or_else(|| "-".to_string());
                                    ui.label(cell);
                                }
                                ui.end_row();
                            }
                        });
                });
            }

            QueryResult::Scalar(val) => {
                ui.add_space(20.0);
                egui::Frame::new()
                    .fill(Color32::from_rgb(25, 40, 55))
                    .inner_margin(20.0)
                    .corner_radius(6.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new("Scalar Result").color(Color32::GRAY));
                        ui.add_space(6.0);
                        ui.heading(
                            RichText::new(format!("{}", val))
                                .size(28.0)
                                .color(Color32::from_rgb(120, 220, 255))
                                .strong(),
                        );
                    });
            }

            QueryResult::Grouped(pairs) => {
                ui.heading(format!("Grouped Results ({} groups)", pairs.len()));
                ui.add_space(8.0);

                egui::Grid::new("iql_grouped_grid")
                    .striped(true)
                    .spacing([20.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Group Key").strong());
                        ui.label(RichText::new("Value").strong());
                        ui.end_row();

                        for (k, v) in pairs {
                            ui.label(k);
                            ui.label(
                                RichText::new(format!("{}", v))
                                    .strong()
                                    .color(Color32::from_rgb(100, 200, 255)),
                            );
                            ui.end_row();
                        }
                    });
            }

            QueryResult::Appended(summary) => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(20, 60, 30))
                    .inner_margin(16.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.heading(
                            RichText::new(format!(
                                "Record #{} Appended Successfully",
                                summary.id
                            ))
                            .color(Color32::GREEN),
                        );
                        ui.label(format!("Table: {}", summary.table));
                        ui.label(format!("Hash: {}", summary.hash));
                        ui.label(format!(
                            "Timestamp: {}",
                            format_timestamp(summary.timestamp)
                        ));
                    });
            }

            QueryResult::Corrected(summary) => {
                egui::Frame::new()
                    .fill(Color32::from_rgb(50, 60, 20))
                    .inner_margin(16.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.heading(
                            RichText::new(format!("Correction Record #{} Committed", summary.id))
                                .color(Color32::GOLD),
                        );
                        if let Some(orig) = summary.correction_of {
                            ui.label(format!("Supersedes Record #{}", orig));
                        }
                        ui.label(format!("Table: {}", summary.table));
                        ui.label(format!("Hash: {}", summary.hash));
                    });
            }

            QueryResult::Verification(ver) => {
                let bg_color = if ver.is_valid {
                    Color32::from_rgb(20, 60, 30)
                } else {
                    Color32::from_rgb(80, 20, 20)
                };

                egui::Frame::new()
                    .fill(bg_color)
                    .inner_margin(16.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        if ver.is_valid {
                            ui.heading(
                                RichText::new("INTEGRITY VERIFIED")
                                    .color(Color32::GREEN)
                                    .strong(),
                            );
                            ui.label(format!(
                                "Total records cryptographically checked: {}",
                                ver.records_checked
                            ));
                        } else {
                            ui.heading(
                                RichText::new("TAMPERING DETECTED")
                                    .color(Color32::RED)
                                    .strong(),
                            );
                            ui.label(format!(
                                "Checked: {}, Errors: {}",
                                ver.records_checked,
                                ver.errors.len()
                            ));
                            for err in &ver.errors {
                                ui.label(
                                    RichText::new(format!("• {:?}", err)).color(Color32::WHITE),
                                );
                            }
                        }
                    });
            }

            QueryResult::Tables(tables) => {
                ui.heading(format!("Tables ({})", tables.len()));
                ui.add_space(6.0);
                for t in tables {
                    ui.label(format!("• {}", t));
                }
            }

            QueryResult::Status(stat) => {
                ui.heading("Database Status");
                ui.label(format!("Total Records: {}", stat.record_count));
                ui.label(format!("Total Tables: {}", stat.table_count));
                ui.label(format!(
                    "Last Record ID: {}",
                    stat.last_record_id
                        .map(|id| format!("#{}", id))
                        .unwrap_or_else(|| "None".to_string())
                ));
                ui.label(format!("Merkle Root: {}", stat.tree_head));
            }

            QueryResult::History(history) => {
                ui.heading(format!("Version History ({} records)", history.len()));
                for (idx, r) in history.iter().enumerate() {
                    ui.group(|ui| {
                        ui.label(format!("Version {}: Record #{}", idx + 1, r.id));
                        ui.label(format!("Timestamp: {}", format_timestamp(r.timestamp)));
                        ui.label(format!("Payload: {}", r.data));
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_prohibited_keywords() {
        // UPDATE checks
        let warn = detect_prohibited_keywords("UPDATE sales SET amount = 100")
            .expect("Must detect UPDATE");
        assert_eq!(warn.keyword, "UPDATE");

        // DELETE checks
        let warn = detect_prohibited_keywords("DELETE FROM sales WHERE id = 1")
            .expect("Must detect DELETE");
        assert_eq!(warn.keyword, "DELETE");

        // Case-insensitivity
        let warn = detect_prohibited_keywords("delete from records").expect("Must detect delete");
        assert_eq!(warn.keyword, "DELETE");

        // DROP TABLE checks
        let warn = detect_prohibited_keywords("DROP TABLE users").expect("Must detect DROP");
        assert_eq!(warn.keyword, "DROP");

        // TRUNCATE checks
        let warn = detect_prohibited_keywords("TRUNCATE table").expect("Must detect TRUNCATE");
        assert_eq!(warn.keyword, "TRUNCATE");

        // ALTER checks
        let warn =
            detect_prohibited_keywords("ALTER TABLE sales ADD col INT").expect("Must detect ALTER");
        assert_eq!(warn.keyword, "ALTER");
    }

    #[test]
    fn test_no_false_positive_prohibited_keywords() {
        // Words containing prohibited substrings should NOT trigger
        assert!(
            detect_prohibited_keywords("READ FROM \"sales\" WHERE last_updated > 100").is_none()
        );
        assert!(detect_prohibited_keywords(
            "READ FROM \"orders\" WHERE dropoff_location = \"Airport\""
        )
        .is_none());
        assert!(
            detect_prohibited_keywords("READ FROM \"logs\" WHERE is_deleted = false").is_none()
        );

        // Quoted strings containing keywords should NOT trigger
        assert!(
            detect_prohibited_keywords("READ FROM \"sales\" WHERE action = \"UPDATE\"").is_none()
        );
        assert!(detect_prohibited_keywords(
            "APPEND TO \"audit\" { \"event\": \"DELETE_REQUEST\" }"
        )
        .is_none());
    }

    #[test]
    fn test_statement_history_fifo_and_deduplication() {
        let mut view = ExecuteIqlView::default();
        view.history.clear();

        view.add_history("READ FROM \"t1\"".to_string());
        view.add_history("READ FROM \"t2\"".to_string());
        view.add_history("READ FROM \"t3\"".to_string());

        assert_eq!(view.history.len(), 3);
        assert_eq!(view.history[0], "READ FROM \"t3\"");

        // Re-adding t1 deduplicates and moves to front
        view.add_history("READ FROM \"t1\"".to_string());
        assert_eq!(view.history.len(), 3);
        assert_eq!(view.history[0], "READ FROM \"t1\"");
    }
}
