//! Interactive view of the global Merkle tree.

use crate::backend::{Backend, MerkleNodeInfo};
use eframe::egui::{self, Color32, Pos2, Sense, Stroke, Vec2};

#[derive(Default)]
pub struct MerkleView {
    nodes: Vec<MerkleNodeInfo>,
    error: Option<String>,
    loaded: bool,
}

impl MerkleView {
    pub fn show(&mut self, ui: &mut egui::Ui, backend: &dyn Backend) {
        ui.heading("Global Merkle Tree");
        ui.label("Each leaf represents one committed record. Internal nodes combine child hashes.");

        if ui.button("Refresh tree").clicked() || !self.loaded {
            self.loaded = true;
            match backend.get_merkle_nodes() {
                Ok(nodes) => {
                    self.nodes = nodes;
                    self.error = None;
                }
                Err(error) => {
                    self.nodes.clear();
                    self.error = Some(error.to_string());
                }
            }
        }

        if let Some(error) = &self.error {
            ui.colored_label(Color32::LIGHT_RED, error);
            return;
        }
        if self.nodes.is_empty() {
            ui.label("The database has no records.");
            return;
        }

        let root = self.nodes[0].hash;
        let leaf_count = self
            .nodes
            .iter()
            .filter_map(|node| node.leaf_index)
            .max()
            .map(|max| max + 1)
            .unwrap_or(0);
        ui.horizontal(|ui| {
            ui.label(format!("Records: {leaf_count}"));
            ui.label("Root:");
            ui.monospace(hex::encode(root));
        });
        ui.separator();

        let mut positions = vec![Pos2::ZERO; self.nodes.len()];
        let mut max_depth = 0;
        place_nodes(&self.nodes, 0, 0, leaf_count.max(1), 0, &mut positions, &mut max_depth);

        let spacing_x = 112.0_f32;
        let spacing_y = 92.0_f32;
        let width = (leaf_count.max(1) as f32 * spacing_x + 50.0).max(420.0);
        let height = (max_depth as f32 * spacing_y + 100.0).max(240.0);
        egui::ScrollArea::both().auto_shrink([false; 2]).show(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());
            let painter = ui.painter_at(rect);
            let origin = rect.min + Vec2::new(24.0, 24.0);
            for (index, node) in self.nodes.iter().enumerate() {
                for child in [node.left, node.right].into_iter().flatten() {
                    if child < positions.len() {
                        painter.line_segment(
                            [origin + positions[index].to_vec2(), origin + positions[child].to_vec2()],
                            Stroke::new(1.5, Color32::from_rgb(105, 130, 160)),
                        );
                    }
                }
            }
            for (index, node) in self.nodes.iter().enumerate() {
                let position = origin + positions[index].to_vec2();
                let leaf = node.leaf_index.is_some();
                let color = if leaf {
                    Color32::from_rgb(55, 125, 95)
                } else {
                    Color32::from_rgb(65, 100, 155)
                };
                painter.circle_filled(position, 9.0, color);
                let label = node
                    .leaf_index
                    .map(|id| format!("Record {id}"))
                    .unwrap_or_else(|| format!("{}…", &hex::encode(node.hash)[..12]));
                painter.text(
                    position + Vec2::new(0.0, 16.0),
                    egui::Align2::CENTER_TOP,
                    label,
                    egui::FontId::proportional(11.0),
                    Color32::WHITE,
                );
                painter.text(
                    position + Vec2::new(0.0, 30.0),
                    egui::Align2::CENTER_TOP,
                    &hex::encode(node.hash)[..8],
                    egui::FontId::monospace(9.0),
                    Color32::GRAY,
                );
            }
        });
    }
}

fn place_nodes(
    nodes: &[MerkleNodeInfo],
    index: usize,
    start_leaf: u64,
    leaf_count: u64,
    depth: usize,
    positions: &mut [Pos2],
    max_depth: &mut usize,
) -> f32 {
    if index >= nodes.len() {
        return 0.0;
    }
    *max_depth = (*max_depth).max(depth);
    let node = &nodes[index];
    let x = if let Some(leaf) = node.leaf_index {
        leaf as f32 * 112.0 + 32.0
    } else {
        let left_x = node.left.map(|child| {
            place_nodes(nodes, child, start_leaf, leaf_count, depth + 1, positions, max_depth)
        });
        let right_x = node.right.map(|child| {
            place_nodes(nodes, child, start_leaf, leaf_count, depth + 1, positions, max_depth)
        });
        match (left_x, right_x) {
            (Some(left), Some(right)) => (left + right) / 2.0,
            (Some(x), None) | (None, Some(x)) => x,
            (None, None) => start_leaf as f32 * 112.0 + leaf_count as f32 * 56.0,
        }
    };
    positions[index] = Pos2::new(x, depth as f32 * 92.0 + 18.0);
    x
}
