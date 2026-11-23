//! Main application state and eframe event loop handler.

use super::browse::BrowseView;
use super::connection::ConnectionView;
use super::execute_iql::ExecuteIqlView;
use super::merkle::MerkleView;
use super::proofs::ProofsView;
use super::verify::VerifyView;
use crate::backend::Backend;
use crate::settings::{Settings, ThemePreference};
use eframe::egui::{self, Color32, RichText};

/// Active central navigation tab in connected mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainTab {
    /// Paginated record grid browser.
    BrowseData,
    /// Multi-line IQL statement editor.
    ExecuteIql,
    /// Cryptographic verification panel.
    Verify,
    /// Global Merkle tree visualizer.
    Merkle,
    /// Standalone inclusion proofs export and offline verification.
    Proofs,
    /// Access control management and audit log.
    Access,
    /// Cluster status and replication health.
    Status,
}

/// The top-level Ink Browser application instance.
pub struct InkBrowserApp {
    /// User settings and UI preferences.
    pub settings: Settings,
    /// Active database backend (LocalBackend or RemoteBackend).
    pub backend: Option<Box<dyn Backend>>,
    /// Connection manager view state.
    pub connection_view: ConnectionView,
    /// Browse data grid view state.
    pub browse_view: BrowseView,
    /// Execute IQL console view state.
    pub execute_iql_view: ExecuteIqlView,
    /// Cryptographic verification screen state.
    pub verify_view: VerifyView,
    /// Merkle proof export and verification screen state.
    pub proofs_view: ProofsView,
    /// Global Merkle tree view state.
    pub merkle_view: MerkleView,
    /// Currently active central tab.
    pub active_tab: MainTab,
    /// Ephemeral status bar message.
    pub status_message: String,
    /// Selected table for Browse Data view.
    pub selected_table: Option<String>,
}

impl Default for InkBrowserApp {
    fn default() -> Self {
        let settings = Settings::load();
        Self {
            settings,
            backend: None,
            connection_view: ConnectionView::default(),
            browse_view: BrowseView::default(),
            execute_iql_view: ExecuteIqlView::default(),
            verify_view: VerifyView::default(),
            proofs_view: ProofsView::default(),
            merkle_view: MerkleView::default(),
            active_tab: MainTab::BrowseData,
            status_message: "Ready".to_string(),
            selected_table: None,
        }
    }
}

impl InkBrowserApp {
    /// Construct a new Ink Browser app with custom settings.
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            backend: None,
            connection_view: ConnectionView::default(),
            browse_view: BrowseView::default(),
            execute_iql_view: ExecuteIqlView::default(),
            verify_view: VerifyView::default(),
            proofs_view: ProofsView::default(),
            merkle_view: MerkleView::default(),
            active_tab: MainTab::BrowseData,
            status_message: "Ready".to_string(),
            selected_table: None,
        }
    }

    /// Construct a new Ink Browser app pre-connected to a backend (for tests or embedded use).
    pub fn with_backend(backend: Box<dyn Backend>) -> Self {
        let settings = Settings::load();
        let mut browse_view = BrowseView::default();
        let mut selected_table = None;

        if let Ok(tables) = backend.list_tables() {
            if let Some(first) = tables.iter().find(|t| !t.name.starts_with('_')) {
                selected_table = Some(first.name.clone());
                browse_view.load_page(backend.as_ref(), &first.name);
            } else if let Some(first) = tables.first() {
                selected_table = Some(first.name.clone());
                browse_view.load_page(backend.as_ref(), &first.name);
            }
        }

        Self {
            settings,
            backend: Some(backend),
            connection_view: ConnectionView::default(),
            browse_view,
            execute_iql_view: ExecuteIqlView::default(),
            verify_view: VerifyView::default(),
            proofs_view: ProofsView::default(),
            merkle_view: MerkleView::default(),
            active_tab: MainTab::BrowseData,
            status_message: "Connected".to_string(),
            selected_table,
        }
    }

    /// Disconnect from the current database and return to the connection screen.
    pub fn disconnect(&mut self) {
        if let Some(mut b) = self.backend.take() {
            b.close();
        }
        self.status_message = "Disconnected".to_string();
        self.selected_table = None;
        self.browse_view = BrowseView::default();
        self.execute_iql_view = ExecuteIqlView::default();
        self.verify_view = VerifyView::default();
        self.proofs_view = ProofsView::default();
        self.merkle_view = MerkleView::default();
    }
}

impl eframe::App for InkBrowserApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // Apply theme preference
        match self.settings.theme {
            ThemePreference::Dark => ctx.set_visuals(egui::Visuals::dark()),
            ThemePreference::Light => ctx.set_visuals(egui::Visuals::light()),
            ThemePreference::System => {}
        }

        // Top Header Panel
        egui::Panel::top("top_header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("Ink Browser").strong());
                ui.label(RichText::new("v0.1.0").color(Color32::GRAY));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let mut should_disconnect = false;
                    if let Some(ref backend) = self.backend {
                        if ui.button("Disconnect").clicked() {
                            should_disconnect = true;
                        }

                        let session = backend.session_info();
                        ui.label(
                            RichText::new(format!(
                                "Tree Head: {} ({} records)",
                                &hex::encode(session.tree_head)[..8],
                                session.tree_size
                            ))
                            .color(Color32::LIGHT_BLUE),
                        );

                        ui.separator();

                        for role in &session.roles {
                            let (bg_color, text_color) = match role {
                                ink_core::auth::Role::Admin => {
                                    (Color32::from_rgb(180, 50, 50), Color32::WHITE)
                                }
                                ink_core::auth::Role::Writer => {
                                    (Color32::from_rgb(40, 120, 40), Color32::WHITE)
                                }
                                ink_core::auth::Role::Reader => {
                                    (Color32::from_rgb(50, 100, 160), Color32::WHITE)
                                }
                                ink_core::auth::Role::Auditor => {
                                    (Color32::from_rgb(120, 60, 160), Color32::WHITE)
                                }
                            };
                            egui::Frame::new()
                                .fill(bg_color)
                                .inner_margin(4.0)
                                .corner_radius(3.0)
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(role.to_string().to_uppercase())
                                            .color(text_color)
                                            .size(11.0)
                                            .strong(),
                                    );
                                });
                        }

                        ui.label(
                            RichText::new(format!("Key: key_{}...", &session.public_key_hex[..8]))
                                .monospace(),
                        );

                        ui.separator();
                        ui.label(
                            RichText::new(format!("{}", session.mode)).color(Color32::LIGHT_GREEN),
                        );
                    }

                    if should_disconnect {
                        self.disconnect();
                    }
                });
            });
        });

        // Bottom Status Bar Panel
        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(ref backend) = self.backend {
                        let sess = backend.session_info();
                        ui.label(format!("DB: {}", sess.database_id));
                        if let Some(lat) = sess.latency_ms {
                            ui.label(format!("{} ms", lat));
                        }
                    }
                });
            });
        });

        // Central Content Area
        if let Some(ref backend_ref) = self.backend {
            // Connected Layout: Left Sidebar + Central Tabs
            let can_view_access = backend_ref.session_info().can_view_access();

            egui::Panel::left("tables_sidebar")
                .resizable(true)
                .default_size(220.0)
                .show(ui, |ui| {
                    ui.heading("Tables");
                    ui.separator();

                    match backend_ref.list_tables() {
                        Ok(tables) => {
                            if tables.is_empty() {
                                ui.label(
                                    RichText::new("No tables found")
                                        .italics()
                                        .color(Color32::GRAY),
                                );
                            } else {
                                for table in tables {
                                    let is_sys = table.name.starts_with('_');
                                    let label = if is_sys {
                                        format!(
                                            "System table: {} ({})",
                                            table.name, table.record_count
                                        )
                                    } else {
                                        format!("{} ({})", table.name, table.record_count)
                                    };

                                    let selected =
                                        self.selected_table.as_deref() == Some(&table.name);
                                    if ui.selectable_label(selected, label).clicked() {
                                        self.selected_table = Some(table.name.clone());
                                        self.active_tab = MainTab::BrowseData;
                                        self.browse_view.current_page = 0;
                                        self.browse_view
                                            .load_page(backend_ref.as_ref(), &table.name);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            ui.label(RichText::new(format!("Error: {}", e)).color(Color32::RED));
                        }
                    }
                });

            egui::CentralPanel::default().show(ui, |ui| {
                // Navigation Tab Bar
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.active_tab,
                        MainTab::BrowseData,
                        "Browse Data",
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        MainTab::ExecuteIql,
                        "Execute an Ink Query",
                    );
                    ui.selectable_value(&mut self.active_tab, MainTab::Verify, "Verify");
                    ui.selectable_value(&mut self.active_tab, MainTab::Merkle, "Merkle Tree");
                    ui.selectable_value(&mut self.active_tab, MainTab::Proofs, "Proofs");
                    if can_view_access {
                        ui.selectable_value(&mut self.active_tab, MainTab::Access, "Access");
                    }
                    ui.selectable_value(&mut self.active_tab, MainTab::Status, "Status");
                });

                ui.separator();

                // Tab Content Renderers
                match self.active_tab {
                    MainTab::BrowseData => {
                        self.browse_view.show(ui, backend_ref.as_ref(), self.selected_table.as_deref());
                    }
                    MainTab::ExecuteIql => {
                        self.execute_iql_view.show(ui, backend_ref.as_ref());
                    }
                    MainTab::Verify => {
                        self.verify_view
                            .show(ui, backend_ref.as_ref(), self.selected_table.as_deref());
                    }
                    MainTab::Merkle => {
                        self.merkle_view.show(ui, backend_ref.as_ref());
                    }
                    MainTab::Proofs => {
                        self.proofs_view.show(ui, backend_ref.as_ref());
                    }
                    MainTab::Access => {
                        ui.heading("Access Control & Audit Log");
                        ui.label(
                            "Access registry and audit records are available through the current database backend.",
                        );
                    }
                    MainTab::Status => {
                        ui.heading("Database & Replication Status");
                        ui.label(
                            "Replication status depends on the configured database backend.",
                        );
                    }
                }
            });
        } else {
            egui::CentralPanel::default().show(ui, |ui| {
                if let Some(new_backend) = self.connection_view.show(ui, &mut self.settings) {
                    self.status_message = format!(
                        "Connected to database ({} roles granted)",
                        new_backend.session_info().roles.len()
                    );
                    if let Ok(tables) = new_backend.list_tables() {
                        if let Some(first) = tables.iter().find(|t| !t.name.starts_with('_')) {
                            self.selected_table = Some(first.name.clone());
                            self.browse_view
                                .load_page(new_backend.as_ref(), &first.name);
                        } else if let Some(first) = tables.first() {
                            self.selected_table = Some(first.name.clone());
                            self.browse_view
                                .load_page(new_backend.as_ref(), &first.name);
                        }
                    }
                    self.backend = Some(new_backend);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::LocalBackend;
    use ink_core::auth::Role;
    use ink_core::{Keypair, Store};
    use tempfile::tempdir;

    #[test]
    fn test_app_disconnect_lifecycle() {
        let dir = tempdir().expect("tempdir");
        let admin_kp = Keypair::generate();
        let (_store, _) =
            Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("Init failed");

        let backend = LocalBackend::open(dir.path(), admin_kp).expect("Open failed");
        let mut app = InkBrowserApp::with_backend(Box::new(backend));

        assert!(app.backend.is_some());
        assert_eq!(app.status_message, "Connected");

        // Disconnect releases backend and drops lock
        app.disconnect();
        assert!(app.backend.is_none());
        assert_eq!(app.status_message, "Disconnected");
        assert!(app.selected_table.is_none());
    }

    #[test]
    fn test_app_browse_and_query_integration() {
        let dir = tempdir().expect("tempdir");
        let admin_kp = Keypair::generate();
        let (mut store, _) =
            Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("Init failed");

        // Grant admin Reader on all tables so IQL queries succeed
        store
            .grant(
                &admin_kp,
                admin_kp.public_key(),
                "admin",
                Role::Reader,
                vec!["*".to_string()],
                None,
            )
            .expect("grant reader");

        // Seed records
        store
            .append_signed(
                "orders",
                br#"{"customer": "Acme", "total": 120}"#,
                Some(&admin_kp),
            )
            .expect("append 1");
        store
            .append_signed(
                "orders",
                br#"{"customer": "Beta", "total": 450}"#,
                Some(&admin_kp),
            )
            .expect("append 2");
        drop(store);

        let backend = LocalBackend::open(dir.path(), admin_kp).expect("Open failed");
        let mut app = InkBrowserApp::with_backend(Box::new(backend));

        // Auto-selected non-system table "orders"
        assert_eq!(app.selected_table, Some("orders".to_string()));
        assert_eq!(app.browse_view.records.len(), 2);
        assert_eq!(app.browse_view.total_records, 2);

        // Execute IQL query via execute_iql_view
        app.execute_iql_view.query_text = "READ FROM \"orders\" WHERE total > 200".to_string();
        app.execute_iql_view
            .execute(app.backend.as_ref().unwrap().as_ref());
        assert!(app.execute_iql_view.error_message.is_none());

        match &app.execute_iql_view.last_result {
            Some(ink_query::QueryResult::Records(recs)) => {
                assert_eq!(recs.len(), 1);
                assert_eq!(recs[0].data["customer"], "Beta");
            }
            other => panic!("Expected Records query result, got {:?}", other),
        }
    }
}
