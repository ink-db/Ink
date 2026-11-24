//! Browse Data screen for Ink Browser.
//!
//! Provides the paginated data grid (LIMIT/OFFSET), dynamic JSON column projection,
//! column visibility toggles, structured filter bar with IQL preview,
//! "Latest version only" filter, Record Details inspector, History viewer,
//! and Append / Correct record dialogs with strict cryptographic audit trail.

use crate::backend::{Backend, RecordDetail};
use crate::ui::filter_builder::{FilterBuilder, FilterCondition, FilterOperator};
use eframe::egui::{self, Color32, RichText, Ui, Window};
use std::collections::HashSet;

/// Helper to format microsecond timestamps into UTC human-readable string.
pub fn format_timestamp(micros: i64) -> String {
    let secs = micros / 1_000_000;
    let nsecs = ((micros % 1_000_000).abs() * 1_000) as u32;
    if let Some(dt) = chrono::DateTime::from_timestamp(secs, nsecs) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        format!("{} µs", micros)
    }
}

/// Discovers all unique top-level JSON keys across a page of records in order of appearance.
pub fn discover_dynamic_columns(records: &[RecordDetail]) -> Vec<String> {
    let mut cols = Vec::new();
    for rec in records {
        if let serde_json::Value::Object(map) = &rec.parsed_data {
            for key in map.keys() {
                if !cols.contains(key) {
                    cols.push(key.clone());
                }
            }
        }
    }
    cols
}

/// Filters a slice of records to retain only the latest version in any correction chain.
///
/// Any record whose ID is referenced as `correction_of` by another record in the slice
/// is considered superseded and excluded.
pub fn filter_latest_versions(records: &[RecordDetail]) -> Vec<RecordDetail> {
    let superseded_ids: HashSet<u64> = records.iter().filter_map(|r| r.correction_of).collect();

    records
        .iter()
        .filter(|r| !superseded_ids.contains(&r.id))
        .cloned()
        .collect()
}

/// State for the Browse Data grid view.
pub struct BrowseView {
    /// Currently loaded records on this page.
    pub records: Vec<RecordDetail>,
    /// Unified dynamic columns detected on this page.
    pub dynamic_columns: Vec<String>,
    /// Columns chosen by the user to be hidden.
    pub hidden_columns: HashSet<String>,
    /// Total records matching filter in the table.
    pub total_records: u64,
    /// Current 0-indexed page number.
    pub current_page: usize,
    /// Page size (50, 100, 500).
    pub page_size: usize,

    /// Structured filter builder.
    pub filter_builder: FilterBuilder,
    /// Whether the collapsible filter bar is visible.
    pub show_filter_bar: bool,
    /// Filter expression currently applied to the grid.
    pub applied_filter: Option<String>,
    /// Whether "Latest version only" filter is active.
    pub latest_only: bool,

    /// Error message from last operation, if any.
    pub error_message: Option<String>,
    /// Status message (e.g. "Loaded 50 records in 4 ms").
    pub status_message: Option<String>,

    // Modals state
    /// Record selected for inspection in the Record Details modal.
    pub detail_record: Option<RecordDetail>,
    /// Record history chain loaded for the History modal.
    pub history_chain: Option<(u64, Vec<RecordDetail>)>,

    /// Append record modal state.
    pub show_append_modal: bool,
    pub append_json: String,
    pub append_error: Option<String>,

    /// Correct record modal state.
    pub correct_target: Option<RecordDetail>,
    pub correct_json: String,
    pub correct_reason: String,
    pub correct_error: Option<String>,
}

impl Default for BrowseView {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            dynamic_columns: Vec::new(),
            hidden_columns: HashSet::new(),
            total_records: 0,
            current_page: 0,
            page_size: 50,
            filter_builder: FilterBuilder::new(),
            show_filter_bar: false,
            applied_filter: None,
            latest_only: false,
            error_message: None,
            status_message: None,
            detail_record: None,
            history_chain: None,
            show_append_modal: false,
            append_json: "{\n  \"key\": \"value\"\n}".to_string(),
            append_error: None,
            correct_target: None,
            correct_json: String::new(),
            correct_reason: String::new(),
            correct_error: None,
        }
    }
}

impl BrowseView {
    /// Render the Browse Data view.
    pub fn show(&mut self, ui: &mut Ui, backend: &dyn Backend, selected_table: Option<&str>) {
        let table = match selected_table {
            Some(t) => t,
            None => {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.heading("No Table Selected");
                    ui.label("Select a table from the sidebar on the left to browse records.");
                });
                return;
            }
        };

        let can_write = backend.session_info().can_write(table);

        // 1. Top Toolbar
        ui.horizontal(|ui| {
            ui.heading(RichText::new(format!("Table: {}", table)).strong());
            ui.add_space(15.0);

            if ui.button("Refresh").clicked() {
                self.load_page(backend, table);
            }

            ui.add_space(10.0);
            let filter_btn_label = if self.show_filter_bar {
                "Hide Filter Bar"
            } else if self.applied_filter.is_some() {
                "Filter (Active)"
            } else {
                "Filter Bar"
            };
            if ui.button(filter_btn_label).clicked() {
                self.show_filter_bar = !self.show_filter_bar;
            }

            ui.add_space(10.0);
            if ui
                .checkbox(&mut self.latest_only, "Latest version only")
                .changed()
            {
                self.load_page(backend, table);
            }

            // Columns visibility popup
            ui.add_space(10.0);
            ui.menu_button("Columns", |ui| {
                ui.label(RichText::new("Toggle Dynamic Columns:").strong());
                ui.separator();
                for col in &self.dynamic_columns {
                    let mut is_visible = !self.hidden_columns.contains(col);
                    if ui.checkbox(&mut is_visible, col).changed() {
                        if is_visible {
                            self.hidden_columns.remove(col);
                        } else {
                            self.hidden_columns.insert(col.clone());
                        }
                    }
                }
                if self.dynamic_columns.is_empty() {
                    ui.label(
                        RichText::new("No dynamic columns")
                            .italics()
                            .color(Color32::GRAY),
                    );
                }
            });

            // Append button (writers only)
            if can_write {
                ui.add_space(15.0);
                if ui
                    .button(
                        RichText::new("Append Record...")
                            .color(Color32::from_rgb(100, 220, 100))
                            .strong(),
                    )
                    .clicked()
                {
                    self.show_append_modal = true;
                    self.append_error = None;
                }
            }

            // Status message
            if let Some(ref status) = self.status_message {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(status).color(Color32::GRAY).size(12.0));
                });
            }
        });

        ui.separator();

        // 2. Collapsible Filter Builder Bar
        if self.show_filter_bar {
            self.render_filter_bar(ui, backend, table);
            ui.separator();
        }

        // 3. Error Banner
        if let Some(ref err) = self.error_message {
            ui.horizontal(|ui| {
                egui::Frame::new()
                    .fill(Color32::from_rgb(80, 20, 20))
                    .inner_margin(8.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new(format!("Error: {}", err)).color(Color32::WHITE));
                    });
            });
            ui.add_space(5.0);
        }

        // 4. Data Grid
        self.render_grid(ui, backend, table, can_write);

        ui.separator();

        // 5. Pagination Bar
        self.render_pagination_bar(ui, backend, table);

        // 6. Modals
        self.render_modals(ui, backend, table);
    }

    /// Load the current page of records from the backend.
    pub fn load_page(&mut self, backend: &dyn Backend, table: &str) {
        let offset = self.current_page * self.page_size;
        let start_time = std::time::Instant::now();

        match backend.read_page(
            table,
            self.applied_filter.as_deref(),
            None,
            self.page_size,
            offset,
        ) {
            Ok(page) => {
                let displayed_records = if self.latest_only {
                    filter_latest_versions(&page.records)
                } else {
                    page.records
                };

                self.dynamic_columns = discover_dynamic_columns(&displayed_records);
                self.records = displayed_records;
                self.total_records = page.total_records;
                self.error_message = None;

                let elapsed = start_time.elapsed().as_millis();
                self.status_message = Some(format!(
                    "Showing {} records (Page {} of {}) • {} ms",
                    self.records.len(),
                    self.current_page + 1,
                    self.total_pages(),
                    elapsed
                ));
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to read table '{}': {}", table, e));
            }
        }
    }

    /// Calculate total number of pages.
    pub fn total_pages(&self) -> usize {
        if self.total_records == 0 {
            1
        } else {
            (self.total_records as usize).div_ceil(self.page_size)
        }
    }

    fn render_filter_bar(&mut self, ui: &mut Ui, backend: &dyn Backend, table: &str) {
        egui::Frame::new()
            .fill(Color32::from_rgb(30, 32, 38))
            .inner_margin(10.0)
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Visual Filter Builder").strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Clear All").clicked() {
                            self.filter_builder.clear();
                            self.applied_filter = None;
                            self.current_page = 0;
                            self.load_page(backend, table);
                        }
                        if ui
                            .button(
                                RichText::new("Apply Filter")
                                    .color(Color32::from_rgb(100, 200, 255))
                                    .strong(),
                            )
                            .clicked()
                        {
                            self.applied_filter = self.filter_builder.to_filter_expression();
                            self.current_page = 0;
                            self.load_page(backend, table);
                        }
                        if ui.button("+ Add Condition").clicked() {
                            let initial_field = self
                                .dynamic_columns
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "id".to_string());
                            self.filter_builder.add_condition(FilterCondition::new(
                                initial_field,
                                FilterOperator::Eq,
                                "",
                            ));
                        }
                    });
                });

                ui.add_space(6.0);

                // Render each condition row
                let mut to_remove = None;
                for (idx, cond) in self.filter_builder.conditions.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}:", idx + 1));

                        // Field input
                        ui.add(
                            egui::TextEdit::singleline(&mut cond.field)
                                .desired_width(140.0)
                                .hint_text("field name"),
                        );

                        // Operator dropdown
                        egui::ComboBox::from_id_salt(format!("op_{}", idx))
                            .selected_text(cond.op.label())
                            .show_ui(ui, |ui| {
                                for op in FilterOperator::ALL {
                                    ui.selectable_value(&mut cond.op, op, op.label());
                                }
                            });

                        // Value input (if operator requires value)
                        if cond.op.requires_value() {
                            ui.add(
                                egui::TextEdit::singleline(&mut cond.value)
                                    .desired_width(180.0)
                                    .hint_text("value"),
                            );
                        } else {
                            ui.label(
                                RichText::new("(no value needed)")
                                    .italics()
                                    .color(Color32::GRAY),
                            );
                        }

                        if ui.button("Remove").clicked() {
                            to_remove = Some(idx);
                        }
                    });
                }

                if let Some(idx) = to_remove {
                    self.filter_builder.remove_condition(idx);
                }

                if self.filter_builder.is_empty() {
                    ui.label(
                        RichText::new("No active filter conditions. Click '+ Add Condition' to start filtering.")
                            .italics()
                            .color(Color32::GRAY),
                    );
                } else if let Some(preview) = self.filter_builder.to_where_clause() {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("IQL Preview:").strong().color(Color32::GRAY));
                        ui.label(
                            RichText::new(preview)
                                .monospace()
                                .color(Color32::from_rgb(180, 220, 255)),
                        );
                    });
                }
            });
    }

    fn render_grid(&mut self, ui: &mut Ui, backend: &dyn Backend, _table: &str, can_write: bool) {
        if self.records.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading(RichText::new("No records found").color(Color32::GRAY));
                if self.applied_filter.is_some() {
                    ui.label("No records match the active filter criteria.");
                } else {
                    ui.label("This table is currently empty.");
                }
                ui.add_space(40.0);
            });
            return;
        }

        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("browse_records_grid")
                    .striped(true)
                    .spacing([12.0, 8.0])
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        // Header Row
                        ui.label(RichText::new("ID").strong());
                        ui.label(RichText::new("Timestamp (UTC)").strong());
                        ui.label(RichText::new("Author").strong());
                        ui.label(RichText::new("Status").strong());
                        ui.label(RichText::new("Correction Of").strong());

                        // Dynamic column headers
                        for col in &self.dynamic_columns {
                            if !self.hidden_columns.contains(col) {
                                ui.label(
                                    RichText::new(col)
                                        .strong()
                                        .color(Color32::from_rgb(140, 200, 255)),
                                );
                            }
                        }

                        ui.label(RichText::new("Actions").strong());
                        ui.end_row();

                        // Data Rows
                        let mut selected_detail = None;
                        let mut selected_history = None;
                        let mut selected_correct = None;

                        for rec in &self.records {
                            // ID
                            ui.label(RichText::new(format!("#{}", rec.id)).strong());

                            // Timestamp
                            ui.label(RichText::new(format_timestamp(rec.timestamp)).monospace());

                            // Author
                            let author_text = rec
                                .author_label
                                .clone()
                                .unwrap_or_else(|| format!("key_{}...", &rec.author_hex[..8]));
                            ui.label(RichText::new(author_text).monospace());

                            // Status badge
                            if rec.is_correction {
                                egui::Frame::new()
                                    .fill(Color32::from_rgb(160, 90, 20))
                                    .inner_margin(3.0)
                                    .corner_radius(3.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new("CORRECTION")
                                                .color(Color32::WHITE)
                                                .size(10.0)
                                                .strong(),
                                        );
                                    });
                            } else {
                                egui::Frame::new()
                                    .fill(Color32::from_rgb(30, 90, 40))
                                    .inner_margin(3.0)
                                    .corner_radius(3.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new("ORIGINAL")
                                                .color(Color32::WHITE)
                                                .size(10.0)
                                                .strong(),
                                        );
                                    });
                            }

                            // Correction Of
                            if let Some(orig) = rec.correction_of {
                                ui.label(
                                    RichText::new(format!("#{}", orig))
                                        .monospace()
                                        .color(Color32::GOLD),
                                );
                            } else {
                                ui.label(RichText::new("-").color(Color32::GRAY));
                            }

                            // Dynamic projected values
                            for col in &self.dynamic_columns {
                                if !self.hidden_columns.contains(col) {
                                    let cell_val = rec
                                        .parsed_data
                                        .get(col)
                                        .map(|v| match v {
                                            serde_json::Value::String(s) => s.clone(),
                                            serde_json::Value::Number(n) => n.to_string(),
                                            serde_json::Value::Bool(b) => b.to_string(),
                                            serde_json::Value::Null => "null".to_string(),
                                            other => other.to_string(),
                                        })
                                        .unwrap_or_else(|| "-".to_string());
                                    ui.label(cell_val);
                                }
                            }

                            // Row Action Buttons
                            ui.horizontal(|ui| {
                                if ui.button("Details").clicked() {
                                    selected_detail = Some(rec.clone());
                                }
                                if ui.button("History").clicked() {
                                    selected_history = Some(rec.id);
                                }
                                if can_write && ui.button("Correct").clicked() {
                                    selected_correct = Some(rec.clone());
                                }
                            });

                            ui.end_row();
                        }

                        // Apply modal selections
                        if let Some(det) = selected_detail {
                            self.detail_record = Some(det);
                        }
                        if let Some(hist_id) = selected_history {
                            match backend.get_history(hist_id) {
                                Ok(chain) => {
                                    self.history_chain = Some((hist_id, chain));
                                }
                                Err(e) => {
                                    self.error_message = Some(format!(
                                        "Failed to fetch history for #{}: {}",
                                        hist_id, e
                                    ));
                                }
                            }
                        }
                        if let Some(corr) = selected_correct {
                            self.correct_target = Some(corr.clone());
                            self.correct_json = serde_json::to_string_pretty(&corr.parsed_data)
                                .unwrap_or_else(|_| corr.data_json.clone());
                            self.correct_reason.clear();
                            self.correct_error = None;
                        }
                    });
            });
    }

    fn render_pagination_bar(&mut self, ui: &mut Ui, backend: &dyn Backend, table: &str) {
        ui.horizontal(|ui| {
            let total_pages = self.total_pages();

            // Page Size Selector
            ui.label("Page Size:");
            for size in [50, 100, 500] {
                if ui
                    .selectable_label(self.page_size == size, size.to_string())
                    .clicked()
                {
                    self.page_size = size;
                    self.current_page = 0;
                    self.load_page(backend, table);
                }
            }

            ui.add_space(20.0);

            // First & Prev buttons
            let can_prev = self.current_page > 0;
            if ui
                .add_enabled(can_prev, egui::Button::new("First"))
                .clicked()
            {
                self.current_page = 0;
                self.load_page(backend, table);
            }
            if ui
                .add_enabled(can_prev, egui::Button::new("Previous"))
                .clicked()
            {
                self.current_page -= 1;
                self.load_page(backend, table);
            }

            ui.label(format!(
                "Page {} of {} (Total {} records)",
                self.current_page + 1,
                total_pages,
                self.total_records
            ));

            // Next & Last buttons
            let can_next = self.current_page + 1 < total_pages;
            if ui
                .add_enabled(can_next, egui::Button::new("Next"))
                .clicked()
            {
                self.current_page += 1;
                self.load_page(backend, table);
            }
            if ui
                .add_enabled(can_next, egui::Button::new("Last"))
                .clicked()
            {
                self.current_page = total_pages.saturating_sub(1);
                self.load_page(backend, table);
            }
        });
    }

    fn render_modals(&mut self, ctx_ui: &mut Ui, backend: &dyn Backend, table: &str) {
        // 1. Record Details Modal
        if let Some(ref rec) = self.detail_record.clone() {
            let mut is_open = true;
            Window::new(format!("Record Details — #{}", rec.id))
                .open(&mut is_open)
                .resizable(true)
                .default_size([650.0, 500.0])
                .show(ctx_ui.ctx(), |ui| {
                    ui.heading(format!("Record #{} in '{}'", rec.id, rec.table));
                    ui.separator();

                    egui::Grid::new("rec_detail_grid")
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Timestamp:").strong());
                            ui.label(format!(
                                "{} ({} µs)",
                                format_timestamp(rec.timestamp),
                                rec.timestamp
                            ));
                            ui.end_row();

                            ui.label(RichText::new("Author Public Key:").strong());
                            ui.label(RichText::new(&rec.author_hex).monospace());
                            ui.end_row();

                            ui.label(RichText::new("Flags:").strong());
                            ui.label(format!(
                                "0x{:02X} (is_correction: {})",
                                rec.flags, rec.is_correction
                            ));
                            ui.end_row();

                            if let Some(orig) = rec.correction_of {
                                ui.label(RichText::new("Correction Of:").strong());
                                ui.label(
                                    RichText::new(format!("#{}", orig))
                                        .monospace()
                                        .color(Color32::GOLD),
                                );
                                ui.end_row();
                            }

                            ui.label(RichText::new("Previous Record Hash:").strong());
                            ui.label(RichText::new(hex::encode(rec.prev_hash)).monospace());
                            ui.end_row();

                            ui.label(RichText::new("Canonical Record Hash:").strong());
                            ui.label(
                                RichText::new(hex::encode(rec.record_hash))
                                    .monospace()
                                    .color(Color32::from_rgb(100, 200, 255)),
                            );
                            ui.end_row();

                            ui.label(RichText::new("Ed25519 Signature:").strong());
                            ui.label(RichText::new(hex::encode(rec.signature)).monospace());
                            ui.end_row();
                        });

                    ui.separator();
                    ui.label(RichText::new("JSON Data Payload:").strong());

                    let pretty_json = serde_json::to_string_pretty(&rec.parsed_data)
                        .unwrap_or_else(|_| rec.data_json.clone());

                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut pretty_json.as_str())
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY),
                            );
                        });

                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        self.detail_record = None;
                    }
                });

            if !is_open {
                self.detail_record = None;
            }
        }

        // 2. History Modal
        if let Some((target_id, ref chain)) = self.history_chain.clone() {
            let mut is_open = true;
            Window::new(format!("Version History — Record #{}", target_id))
                .open(&mut is_open)
                .resizable(true)
                .default_size([700.0, 450.0])
                .show(ctx_ui.ctx(), |ui| {
                    ui.heading(format!("Full Correction Chain ({} versions)", chain.len()));
                    ui.label("Ink is append-only. Historical records are immutable; corrections form an unbroken audit chain.");
                    ui.separator();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for (idx, v) in chain.iter().enumerate() {
                            let title = if idx == 0 {
                                format!("Version 1 (Original Record #{})", v.id)
                            } else {
                                format!("Version {} (Correction Record #{})", idx + 1, v.id)
                            };

                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading(RichText::new(title).size(15.0).strong());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(format_timestamp(v.timestamp)).monospace());
                                    });
                                });

                                ui.label(format!("Author: key_{}...", &v.author_hex[..8]));
                                ui.label(format!("Record Hash: {}", hex::encode(v.record_hash)));

                                if let Some(orig) = v.correction_of {
                                    ui.label(RichText::new(format!("Supersedes Record #{}", orig)).color(Color32::GOLD));
                                }

                                ui.separator();
                                ui.label(RichText::new("Payload:").strong());
                                let json_str = serde_json::to_string_pretty(&v.parsed_data)
                                    .unwrap_or_else(|_| v.data_json.clone());
                                ui.label(RichText::new(json_str).monospace());
                            });
                            ui.add_space(8.0);
                        }
                    });

                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        self.history_chain = None;
                    }
                });

            if !is_open {
                self.history_chain = None;
            }
        }

        // 3. Append Record Modal
        if self.show_append_modal {
            let mut is_open = true;
            Window::new(format!("Append New Record to '{}'", table))
                .open(&mut is_open)
                .resizable(true)
                .default_size([550.0, 380.0])
                .show(ctx_ui.ctx(), |ui| {
                    ui.heading("Append Sealed Record");
                    ui.label("Commits a signed JSON record into the tamper-evident log.");
                    ui.separator();

                    if let Some(ref err) = self.append_error {
                        ui.label(
                            RichText::new(format!("Error: {}", err))
                                .color(Color32::RED)
                                .strong(),
                        );
                        ui.add_space(6.0);
                    }

                    ui.label(RichText::new("JSON Payload:").strong());
                    ui.add(
                        egui::TextEdit::multiline(&mut self.append_json)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(10)
                            .desired_width(f32::INFINITY),
                    );

                    // Syntax validation indicator
                    let json_parse: Result<serde_json::Value, _> =
                        serde_json::from_str(&self.append_json);
                    match &json_parse {
                        Ok(_) => {
                            ui.label(RichText::new("Valid JSON syntax").color(Color32::GREEN));
                        }
                        Err(e) => {
                            ui.label(
                                RichText::new(format!("Invalid JSON: {}", e)).color(Color32::RED),
                            );
                        }
                    }

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let can_submit = json_parse.is_ok();
                        if ui
                            .add_enabled(
                                can_submit,
                                egui::Button::new(RichText::new("Commit Signed Record").strong()),
                            )
                            .clicked()
                        {
                            if let Ok(val) =
                                serde_json::from_str::<serde_json::Value>(&self.append_json)
                            {
                                match backend.append_record(table, val) {
                                    Ok(summary) => {
                                        self.show_append_modal = false;
                                        self.status_message = Some(format!(
                                            "Appended record #{} successfully",
                                            summary.id
                                        ));
                                        self.load_page(backend, table);
                                    }
                                    Err(e) => {
                                        self.append_error = Some(e.to_string());
                                    }
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_append_modal = false;
                        }
                    });
                });

            if !is_open {
                self.show_append_modal = false;
            }
        }

        // 4. Correct Record Modal
        if let Some(target) = self.correct_target.clone() {
            let mut is_open = true;
            Window::new(format!("Correct Record #{} in '{}'", target.id, table))
                .open(&mut is_open)
                .resizable(true)
                .default_size([600.0, 450.0])
                .show(ctx_ui.ctx(), |ui| {
                    ui.heading(format!("Correcting Record #{}", target.id));
                    ui.label(
                        RichText::new("Notice: Record #")
                            .color(Color32::GOLD)
                            .strong(),
                    );
                    ui.label(
                        "Ink records are immutable. This action does NOT modify or erase the existing record. \
                         It appends a new sealed correction record referencing #id, preserving the full audit trail."
                    );
                    ui.separator();

                    if let Some(ref err) = self.correct_error {
                        ui.label(
                            RichText::new(format!("Error: {}", err))
                                .color(Color32::RED)
                                .strong(),
                        );
                        ui.add_space(6.0);
                    }

                    ui.label(RichText::new("Corrected JSON Payload:").strong());
                    ui.add(
                        egui::TextEdit::multiline(&mut self.correct_json)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY),
                    );

                    let json_parse: Result<serde_json::Value, _> = serde_json::from_str(&self.correct_json);
                    match &json_parse {
                        Ok(_) => {
                            ui.label(RichText::new("Valid JSON syntax").color(Color32::GREEN));
                        }
                        Err(e) => {
                            ui.label(RichText::new(format!("Invalid JSON: {}", e)).color(Color32::RED));
                        }
                    }

                    ui.add_space(8.0);
                    ui.label(RichText::new("Correction Reason (mandatory):").strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.correct_reason)
                            .desired_width(f32::INFINITY)
                            .hint_text("e.g. Corrected invoice customer legal name typo"),
                    );

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let can_submit = json_parse.is_ok() && !self.correct_reason.trim().is_empty();
                        if ui.add_enabled(can_submit, egui::Button::new(RichText::new("Commit Correction").strong())).clicked() {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&self.correct_json) {
                                match backend.correct_record(target.id, val, &self.correct_reason) {
                                    Ok(summary) => {
                                        self.correct_target = None;
                                        self.status_message = Some(format!(
                                            "Committed correction record #{} for original #{}",
                                            summary.id, target.id
                                        ));
                                        self.load_page(backend, table);
                                    }
                                    Err(e) => {
                                        self.correct_error = Some(e.to_string());
                                    }
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.correct_target = None;
                        }
                    });
                });

            if !is_open {
                self.correct_target = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_record(
        id: u64,
        is_corr: bool,
        corr_of: Option<u64>,
        json: serde_json::Value,
    ) -> RecordDetail {
        RecordDetail {
            id,
            timestamp: 1_700_000_000_000_000,
            table: "sales".to_string(),
            author: [0u8; 32],
            author_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            author_label: Some("alice".to_string()),
            flags: if is_corr { 1 } else { 0 },
            is_correction: is_corr,
            correction_of: corr_of,
            prev_hash: [0u8; 32],
            record_hash: [1u8; 32],
            signature: [0u8; 64],
            data_json: json.to_string(),
            parsed_data: json,
        }
    }

    #[test]
    fn test_dynamic_column_discovery() {
        let rec1 = create_dummy_record(
            1,
            false,
            None,
            serde_json::json!({ "customer": "Acme", "amount": 100 }),
        );
        let rec2 = create_dummy_record(
            2,
            false,
            None,
            serde_json::json!({ "customer": "Beta", "currency": "USD" }),
        );
        let rec3 = create_dummy_record(3, false, None, serde_json::json!({ "status": "active" }));

        let cols = discover_dynamic_columns(&[rec1, rec2, rec3]);
        assert_eq!(cols, vec!["amount", "customer", "currency", "status"]);
    }

    #[test]
    fn test_filter_latest_versions() {
        let rec1 = create_dummy_record(
            1,
            false,
            None,
            serde_json::json!({ "item": "book", "qty": 1 }),
        );
        let rec2 = create_dummy_record(
            2,
            true,
            Some(1),
            serde_json::json!({ "item": "book", "qty": 2 }),
        );
        let rec3 = create_dummy_record(
            3,
            false,
            None,
            serde_json::json!({ "item": "pen", "qty": 5 }),
        );

        let all = vec![rec1, rec2, rec3];
        let latest = filter_latest_versions(&all);

        // Record #1 should be superseded by #2
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].id, 2);
        assert_eq!(latest[1].id, 3);
    }

    #[test]
    fn test_format_timestamp() {
        // Test microsecond timestamp conversion
        let formatted = format_timestamp(1_700_000_000_000_000);
        assert!(formatted.contains("UTC"));
        assert!(formatted.contains("2023-11-14"));
    }

    #[test]
    fn test_browse_view_pagination_math() {
        let mut view = BrowseView {
            total_records: 105,
            page_size: 50,
            ..Default::default()
        };

        assert_eq!(view.total_pages(), 3);

        view.total_records = 0;
        assert_eq!(view.total_pages(), 1);

        view.total_records = 50;
        assert_eq!(view.total_pages(), 1);

        view.total_records = 51;
        assert_eq!(view.total_pages(), 2);
    }
}
