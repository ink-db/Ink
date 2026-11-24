//! Connection manager screen for Ink Browser.
//!
//! Provides the dual-tab interface ("Open Local Database" and "Connect to Server"),
//! recent connections list, secret zeroization, and authentication handling.

use crate::backend::local::LocalBackend;
use crate::backend::Backend;
use crate::settings::Settings;
use eframe::egui::{self, Color32, RichText, Ui};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Active tab in the connection manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTab {
    /// Local filesystem database.
    Local,
    /// Remote TCP / TLS server daemon.
    Server,
}

/// State for the connection manager screen.
pub struct ConnectionView {
    /// Selected connection tab.
    pub tab: ConnectionTab,

    // Local connection fields
    pub local_dir: String,
    pub local_key_path: String,
    pub local_passphrase: String,

    // Remote connection fields
    pub remote_host: String,
    pub remote_port: String,
    pub remote_tls: bool,
    pub remote_key_path: String,
    pub remote_passphrase: String,

    /// Error message from last failed connection attempt, if any.
    pub error_message: Option<String>,
}

impl Default for ConnectionView {
    fn default() -> Self {
        Self {
            tab: ConnectionTab::Local,
            local_dir: String::new(),
            local_key_path: String::new(),
            local_passphrase: String::new(),
            remote_host: "127.0.0.1".to_string(),
            remote_port: "7777".to_string(),
            remote_tls: false,
            remote_key_path: String::new(),
            remote_passphrase: String::new(),
            error_message: None,
        }
    }
}

impl ConnectionView {
    /// Render the connection manager UI.
    ///
    /// Returns `Some(backend)` when a successful connection is established.
    pub fn show(&mut self, ui: &mut Ui, settings: &mut Settings) -> Option<Box<dyn Backend>> {
        let mut connected_backend = None;

        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading(RichText::new("Ink Browser").size(26.0).strong());
            ui.label(
                RichText::new("Append-only, tamper-evident database explorer").color(Color32::GRAY),
            );
            ui.add_space(20.0);
        });

        // Error message banner
        if let Some(ref err) = self.error_message {
            ui.horizontal(|ui| {
                ui.add_space(40.0);
                egui::Frame::new()
                    .fill(Color32::from_rgb(80, 20, 20))
                    .inner_margin(12.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!("Error: {}", err))
                                .color(Color32::WHITE)
                                .strong(),
                        );
                    });
            });
            ui.add_space(10.0);
        }

        ui.horizontal(|ui| {
            ui.add_space(40.0);

            // Left side: Connection forms
            ui.vertical(|ui| {
                ui.set_width(550.0);

                // Tab selection
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.tab == ConnectionTab::Local, "Open Local Database")
                        .clicked()
                    {
                        self.tab = ConnectionTab::Local;
                        self.error_message = None;
                    }
                    if ui
                        .selectable_label(self.tab == ConnectionTab::Server, "Connect to Server")
                        .clicked()
                    {
                        self.tab = ConnectionTab::Server;
                        self.error_message = None;
                    }
                });

                ui.separator();
                ui.add_space(10.0);

                match self.tab {
                    ConnectionTab::Local => {
                        connected_backend = self.show_local_tab(ui, settings);
                    }
                    ConnectionTab::Server => {
                        self.show_server_tab(ui, settings);
                    }
                }
            });

            ui.add_space(40.0);
            ui.separator();
            ui.add_space(20.0);

            // Right side: Recent Connections
            ui.vertical(|ui| {
                ui.heading("Recent Connections");
                ui.add_space(10.0);

                match self.tab {
                    ConnectionTab::Local => {
                        if settings.recent_local.is_empty() {
                            ui.label(
                                RichText::new("No recent local databases")
                                    .italics()
                                    .color(Color32::GRAY),
                            );
                        } else {
                            for entry in &settings.recent_local {
                                let dir_label = entry.data_dir.clone();
                                let key_label = entry.key_path.clone();
                                if ui.button(dir_label.clone()).clicked() {
                                    self.local_dir = dir_label;
                                    self.local_key_path = key_label;
                                }
                            }
                        }
                    }
                    ConnectionTab::Server => {
                        if settings.recent_remote.is_empty() {
                            ui.label(
                                RichText::new("No recent server connections")
                                    .italics()
                                    .color(Color32::GRAY),
                            );
                        } else {
                            for entry in &settings.recent_remote {
                                let host = entry.host.clone();
                                let port = entry.port;
                                let key = entry.key_path.clone();
                                let tls = entry.tls;
                                let scheme = if tls { "inks" } else { "ink" };
                                if ui
                                    .button(format!("{}://{}:{}", scheme, host, port))
                                    .clicked()
                                {
                                    self.remote_host = host;
                                    self.remote_port = port.to_string();
                                    self.remote_tls = tls;
                                    self.remote_key_path = key;
                                }
                            }
                        }
                    }
                }
            });
        });

        connected_backend
    }

    fn show_local_tab(&mut self, ui: &mut Ui, settings: &mut Settings) -> Option<Box<dyn Backend>> {
        let mut connect_now = false;

        ui.label(RichText::new("Database Directory:").strong());
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.local_dir);
            if ui.button("Browse...").clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.local_dir = folder.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(8.0);
        ui.label(RichText::new("Identity Key File (.key or .inkkey):").strong());
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.local_key_path);
            if ui.button("Browse...").clicked() {
                if let Some(file) = rfd::FileDialog::new()
                    .add_filter("Ink Key File", &["key", "inkkey"])
                    .pick_file()
                {
                    self.local_key_path = file.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(8.0);
        ui.label("Passphrase (if key is encrypted):");
        ui.add(egui::TextEdit::singleline(&mut self.local_passphrase).password(true));

        ui.add_space(16.0);
        if ui
            .button(RichText::new("Open Database").strong().size(15.0))
            .clicked()
        {
            connect_now = true;
        }

        if connect_now {
            if self.local_dir.trim().is_empty() {
                self.error_message = Some("Please select a database directory".to_string());
                return None;
            }
            if self.local_key_path.trim().is_empty() {
                self.error_message =
                    Some("Please select an identity key file (no anonymous access)".to_string());
                return None;
            }

            let key_path = Path::new(&self.local_key_path);
            let pass_opt = if self.local_passphrase.is_empty() {
                None
            } else {
                Some(self.local_passphrase.as_str())
            };

            let key_res = ink_client::load_key(key_path, pass_opt);
            // Immediately zeroize passphrase memory buffer
            self.local_passphrase.zeroize();

            let keypair = match key_res {
                Ok(kp) => kp,
                Err(e) => {
                    self.error_message = Some(format!("Failed to load key: {}", e));
                    return None;
                }
            };

            let data_dir = PathBuf::from(&self.local_dir);
            match LocalBackend::open(&data_dir, keypair) {
                Ok(backend) => {
                    settings.add_recent_local(&self.local_dir, &self.local_key_path);
                    let _ = settings.save();
                    self.error_message = None;
                    return Some(Box::new(backend));
                }
                Err(e) => {
                    self.error_message = Some(e.to_string());
                }
            }
        }

        None
    }

    fn show_server_tab(&mut self, ui: &mut Ui, _settings: &mut Settings) {
        ui.label(RichText::new("Server Host:").strong());
        ui.text_edit_singleline(&mut self.remote_host);

        ui.add_space(8.0);
        ui.label(RichText::new("Server Port:").strong());
        ui.text_edit_singleline(&mut self.remote_port);

        ui.add_space(8.0);
        ui.checkbox(&mut self.remote_tls, "Enable TLS 1.3 encryption");

        let is_loopback = self.remote_host == "127.0.0.1"
            || self.remote_host == "localhost"
            || self.remote_host == "::1";

        if !self.remote_tls && !is_loopback {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Warning: Connecting without TLS over a non-loopback network")
                    .color(Color32::from_rgb(220, 160, 40)),
            );
        }

        ui.add_space(8.0);
        ui.label(RichText::new("Identity Key File (.key or .inkkey):").strong());
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.remote_key_path);
            if ui.button("Browse...").clicked() {
                if let Some(file) = rfd::FileDialog::new()
                    .add_filter("Ink Key File", &["key", "inkkey"])
                    .pick_file()
                {
                    self.remote_key_path = file.to_string_lossy().to_string();
                }
            }
        });

        ui.add_space(8.0);
        ui.label("Passphrase (if key is encrypted):");
        ui.add(egui::TextEdit::singleline(&mut self.remote_passphrase).password(true));

        ui.add_space(16.0);
        if ui
            .button(RichText::new("Connect to Server").strong().size(15.0))
            .clicked()
        {
            // Milestone B1 note: Server connection is wired in Milestone B5 via RemoteBackend
            self.error_message = Some(
                "Remote server connections will be enabled in Milestone B5 (RemoteBackend). Please use 'Open Local Database' for local mode."
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_view_initial_state() {
        let view = ConnectionView::default();
        assert_eq!(view.tab, ConnectionTab::Local);
        assert_eq!(view.remote_host, "127.0.0.1");
        assert_eq!(view.remote_port, "7777");
        assert!(!view.remote_tls);
        assert!(view.error_message.is_none());
    }
}
