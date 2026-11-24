//! Cryptographic integrity verification view for Ink Browser.

use crate::backend::{Backend, VerifySummary};
use eframe::egui::{self, Color32, RichText, Ui};

/// State and renderer for verifying one table or the complete database.
#[derive(Default)]
pub struct VerifyView {
    result: Option<VerifySummary>,
    error: Option<String>,
}

impl VerifyView {
    /// Render verification actions and the most recent result.
    pub fn show(&mut self, ui: &mut Ui, backend: &dyn Backend, selected_table: Option<&str>) {
        ui.heading("Cryptographic Verification");
        ui.label("Verify record signatures, per-table hash chains, and the database Merkle tree.");
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            let selected_label = selected_table
                .map(|table| format!("Verify '{table}'"))
                .unwrap_or_else(|| "Verify Selected Table".to_string());
            if ui
                .add_enabled(selected_table.is_some(), egui::Button::new(selected_label))
                .clicked()
            {
                self.run(backend, selected_table);
            }

            if ui.button("Verify Entire Database").clicked() {
                self.run(backend, None);
            }
        });

        if let Some(error) = &self.error {
            ui.add_space(10.0);
            ui.label(RichText::new(format!("Verification failed: {error}")).color(Color32::RED));
        }

        if let Some(result) = &self.result {
            ui.add_space(14.0);
            let (label, color) = if result.is_valid {
                ("INTEGRITY VERIFIED", Color32::GREEN)
            } else {
                ("INTEGRITY CHECK FAILED", Color32::RED)
            };
            ui.heading(RichText::new(label).color(color).strong());
            ui.label(format!("Records checked: {}", result.records_checked));

            if let Some(record_id) = result.broken_record_id {
                ui.label(format!("First reported record: #{record_id}"));
            }

            if !result.errors.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Verification details").strong());
                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for error in &result.errors {
                            ui.label(RichText::new(error).color(Color32::LIGHT_RED));
                        }
                    });
            }
        }
    }

    fn run(&mut self, backend: &dyn Backend, target_table: Option<&str>) {
        match backend.verify(target_table) {
            Ok(result) => {
                self.result = Some(result);
                self.error = None;
            }
            Err(error) => {
                self.result = None;
                self.error = Some(error.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalBackend;
    use ink_core::auth::Role;
    use ink_core::{Keypair, Store};
    use tempfile::tempdir;

    #[test]
    fn test_verify_view_initial_state() {
        let view = VerifyView::default();
        assert!(view.result.is_none());
        assert!(view.error.is_none());
    }

    #[test]
    fn test_verify_view_run_with_backend() {
        let dir = tempdir().expect("tempdir");
        let admin_kp = Keypair::generate();
        let (mut store, _) =
            Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("init");

        // Grant admin Reader on * so verification is authorized
        store
            .grant(
                &admin_kp,
                admin_kp.public_key(),
                "admin",
                Role::Reader,
                vec!["*".into()],
                None,
            )
            .expect("grant");
        drop(store);

        let backend = LocalBackend::open(dir.path(), admin_kp).expect("open backend");

        let mut view = VerifyView::default();
        view.run(&backend, None);
        assert!(view.error.is_none());
        let res = view.result.as_ref().expect("result");
        assert!(res.is_valid);
        assert!(res.errors.is_empty());
    }
}
