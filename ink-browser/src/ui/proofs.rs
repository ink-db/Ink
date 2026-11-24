//! Merkle inclusion proof export and offline verification view.

use crate::backend::Backend;
use eframe::egui::{self, Color32, RichText, Ui};
use ink_core::InclusionProof;
use std::fs;
use std::io::Read;

const MAX_PROOF_FILE_SIZE: u64 = 64 * 1024;

/// State and renderer for creating, exporting, and verifying Merkle proofs.
#[derive(Default)]
pub struct ProofsView {
    record_id_input: String,
    proof: Option<InclusionProof>,
    proof_valid: Option<bool>,
    status: Option<String>,
    error: Option<String>,
}

impl ProofsView {
    /// Render proof generation, JSON export, and offline verification controls.
    pub fn show(&mut self, ui: &mut Ui, backend: &dyn Backend) {
        ui.heading("Merkle Inclusion Proofs");
        ui.label(
            "Export a record proof or verify a proof file against its claimed root. Compare that root with a trusted tree head before relying on the proof.",
        );
        ui.add_space(12.0);

        ui.horizontal(|ui| {
            ui.label("Record ID:");
            ui.add(
                egui::TextEdit::singleline(&mut self.record_id_input)
                    .desired_width(150.0)
                    .hint_text("e.g. 42"),
            );
            if ui.button("Generate Proof").clicked() {
                self.generate(backend);
            }
            if ui.button("Verify Proof File").clicked() {
                self.verify_file();
            }
        });

        if let Some(error) = &self.error {
            ui.add_space(8.0);
            ui.label(RichText::new(error).color(Color32::RED));
        }
        if let Some(status) = &self.status {
            ui.add_space(8.0);
            ui.label(RichText::new(status).color(Color32::LIGHT_GREEN));
        }

        if let Some(proof) = &self.proof {
            ui.add_space(14.0);
            let valid = self.proof_valid.unwrap_or(false);
            let (label, color) = if valid {
                ("PROOF VERIFIED", Color32::GREEN)
            } else {
                ("PROOF INVALID", Color32::RED)
            };
            ui.heading(RichText::new(label).color(color).strong());
            ui.label(format!("Record: #{}", proof.leaf_index));
            ui.label(format!("Tree size: {}", proof.tree_size));
            ui.label(format!("Root hash: {}", proof.root_hash));
            ui.label(format!("Record hash: {}", proof.record_hash));
            ui.label(format!("Audit path hashes: {}", proof.audit_path.len()));

            if ui.button("Export Proof as JSON...").clicked() {
                self.export_file();
            }
        }
    }

    fn generate(&mut self, backend: &dyn Backend) {
        self.error = None;
        self.status = None;
        self.proof = None;
        self.proof_valid = None;

        let record_id = match self.record_id_input.trim().parse::<u64>() {
            Ok(id) => id,
            Err(_) => {
                self.error = Some("Enter a valid non-negative record ID.".into());
                return;
            }
        };

        let record = match backend.get_record(record_id) {
            Ok(record) => record,
            Err(error) => {
                self.error = Some(format!("Could not load record #{record_id}: {error}"));
                return;
            }
        };

        let info = match backend.get_inclusion_proof(record_id) {
            Ok(info) => info,
            Err(error) => {
                self.error = Some(format!("Could not generate proof: {error}"));
                return;
            }
        };

        let proof = InclusionProof {
            leaf_index: info.record_id,
            tree_size: info.tree_size,
            root_hash: hex::encode(info.root_hash),
            record_hash: hex::encode(record.record_hash),
            audit_path: info.audit_path.iter().map(hex::encode).collect(),
        };
        self.proof_valid = Some(ink_core::verify_inclusion(&proof));
        self.proof = Some(proof);
    }

    fn export_file(&mut self) {
        let Some(proof) = &self.proof else {
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Ink Merkle proof", &["json"])
            .set_file_name(format!("ink-proof-{}.json", proof.leaf_index))
            .save_file()
        else {
            return;
        };

        match serde_json::to_vec_pretty(proof) {
            Ok(json) => match fs::write(&path, json) {
                Ok(()) => {
                    self.error = None;
                    self.status = Some(format!("Proof exported to {}", path.display()));
                }
                Err(error) => self.error = Some(format!("Could not write proof file: {error}")),
            },
            Err(error) => self.error = Some(format!("Could not serialize proof: {error}")),
        }
    }

    fn verify_file(&mut self) {
        self.error = None;
        self.status = None;
        self.proof = None;
        self.proof_valid = None;

        let Some(path) = rfd::FileDialog::new()
            .add_filter("Ink Merkle proof", &["json"])
            .pick_file()
        else {
            return;
        };

        let result = read_proof_file(&path);

        match result {
            Ok(proof) => {
                let valid = ink_core::verify_inclusion(&proof);
                self.proof_valid = Some(valid);
                self.status = Some(if valid {
                    format!("Proof file verified: {}", path.display())
                } else {
                    "Proof file is invalid or does not match its claimed root.".into()
                });
                self.proof = Some(proof);
            }
            Err(error) => self.error = Some(error),
        }
    }
}

fn read_proof_file(path: &std::path::Path) -> Result<InclusionProof, String> {
    let file =
        fs::File::open(path).map_err(|error| format!("Could not read proof file: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_PROOF_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read proof file: {error}"))?;
    if bytes.len() as u64 > MAX_PROOF_FILE_SIZE {
        return Err(format!(
            "Proof file exceeds the {} KiB size limit.",
            MAX_PROOF_FILE_SIZE / 1024
        ));
    }
    serde_json::from_slice::<InclusionProof>(&bytes)
        .map_err(|error| format!("Invalid proof JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalBackend;
    use ink_core::auth::Role;
    use ink_core::{Keypair, Store};
    use tempfile::tempdir;

    #[test]
    fn test_proofs_view_initial_state() {
        let view = ProofsView::default();
        assert!(view.record_id_input.is_empty());
        assert!(view.proof.is_none());
        assert!(view.proof_valid.is_none());
        assert!(view.status.is_none());
        assert!(view.error.is_none());
    }

    #[test]
    fn test_read_proof_file_roundtrip_and_validation() {
        let dir = tempdir().expect("tempdir");
        let valid_proof = InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            root_hash: "abcd".to_string(),
            record_hash: "ef01".to_string(),
            audit_path: vec![],
        };

        let file_path = dir.path().join("proof.json");
        fs::write(&file_path, serde_json::to_vec(&valid_proof).unwrap()).unwrap();

        let loaded = read_proof_file(&file_path).expect("Must read valid proof");
        assert_eq!(loaded, valid_proof);

        // Test invalid json
        let bad_json_path = dir.path().join("bad.json");
        fs::write(&bad_json_path, b"not valid json").unwrap();
        assert!(read_proof_file(&bad_json_path).is_err());

        // Test oversized file (> 64 KiB)
        let large_path = dir.path().join("oversized.json");
        let zeros = vec![b' '; (MAX_PROOF_FILE_SIZE + 10) as usize];
        fs::write(&large_path, zeros).unwrap();
        let err = read_proof_file(&large_path).expect_err("Must reject oversized proof file");
        assert!(err.contains("size limit"));
    }

    #[test]
    fn test_generate_proof_with_backend() {
        let dir = tempdir().expect("tempdir");
        let admin_kp = Keypair::generate();
        let (mut store, _) =
            Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("init");

        store
            .grant(
                &admin_kp,
                admin_kp.public_key(),
                "admin",
                Role::Writer,
                vec!["*".into()],
                None,
            )
            .expect("grant writer");
        store
            .grant(
                &admin_kp,
                admin_kp.public_key(),
                "admin",
                Role::Reader,
                vec!["*".into()],
                None,
            )
            .expect("grant reader");
        drop(store);

        let backend = LocalBackend::open(dir.path(), admin_kp).expect("open backend");
        let append_res = backend
            .append_record("events", serde_json::json!({ "type": "login" }))
            .expect("append");

        // Invalid record id
        let mut view = ProofsView {
            record_id_input: "not-a-number".into(),
            ..Default::default()
        };
        view.generate(&backend);
        assert!(view.error.is_some());
        assert!(view.proof.is_none());

        // Valid record id
        view.record_id_input = append_res.id.to_string();
        view.generate(&backend);
        assert!(view.error.is_none());
        assert_eq!(view.proof_valid, Some(true));
        let p = view.proof.as_ref().expect("proof");
        assert_eq!(p.leaf_index, append_res.id);
    }
}
