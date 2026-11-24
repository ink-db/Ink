//! Interactive view of the global Merkle tree with pan, zoom, and audit path inspection.

use crate::backend::{Backend, MerkleNodeInfo};
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2};

/// Interactive state and canvas renderer for the global Merkle tree.
pub struct MerkleView {
    nodes: Vec<MerkleNodeInfo>,
    error: Option<String>,
    loaded: bool,
    zoom: f32,
    align_leaves: bool,
    selected_node: Option<usize>,
    hovered_node: Option<usize>,
    search_record_id: String,
    search_message: Option<String>,
    copied_hash: Option<String>,
}

impl Default for MerkleView {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            error: None,
            loaded: false,
            zoom: 1.0,
            align_leaves: true,
            selected_node: None,
            hovered_node: None,
            search_record_id: String::new(),
            search_message: None,
            copied_hash: None,
        }
    }
}

impl MerkleView {
    /// Render the Merkle tree view with navigation controls and inspector.
    pub fn show(&mut self, ui: &mut Ui, backend: &dyn Backend) {
        ui.heading("Global Merkle Tree");
        ui.label(
            "Visual representation of the append-only Merkle tree. Leaves represent committed \
             records; internal nodes combine child hashes. Select a record to trace its inclusion proof path.",
        );

        if ui.button("Refresh tree").clicked() || !self.loaded {
            self.loaded = true;
            match backend.get_merkle_nodes() {
                Ok(nodes) => {
                    self.nodes = nodes;
                    self.error = None;
                    self.selected_node = None;
                    self.hovered_node = None;
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

        let root_hash = self.nodes[0].hash;
        let leaf_count = self
            .nodes
            .iter()
            .filter_map(|node| node.leaf_index)
            .max()
            .map(|max| max + 1)
            .unwrap_or(0);

        let parents = build_parents(&self.nodes);
        let layout = compute_layout(&self.nodes, leaf_count, self.align_leaves);

        // --- Toolbar ---
        ui.horizontal(|ui| {
            ui.label(format!("Records: {leaf_count}"));
            ui.separator();
            ui.label("Root:");
            ui.monospace(hex::encode(root_hash));
        });

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("Zoom:");
            if ui.button("-").clicked() {
                self.zoom = (self.zoom - 0.15).max(0.15);
            }
            ui.add(
                egui::Slider::new(&mut self.zoom, 0.15..=2.5)
                    .custom_formatter(|val, _| format!("{:.0}%", val * 100.0)),
            );
            if ui.button("+").clicked() {
                self.zoom = (self.zoom + 0.15).min(2.5);
            }
            if ui.button("100%").clicked() {
                self.zoom = 1.0;
            }

            let available_width = ui.available_width();
            if ui.button("Fit View").clicked() && layout.width > 0.0 {
                let target_zoom = (available_width - 40.0) / layout.width;
                self.zoom = target_zoom.clamp(0.15, 2.0);
            }

            ui.separator();
            ui.checkbox(&mut self.align_leaves, "Align leaves at bottom");

            ui.separator();
            ui.label("Find record #:");
            let search_edit = ui.add(
                egui::TextEdit::singleline(&mut self.search_record_id)
                    .desired_width(70.0)
                    .hint_text("ID"),
            );
            let enter_pressed =
                search_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Go").clicked() || enter_pressed {
                if let Ok(target_id) = self.search_record_id.trim().parse::<u64>() {
                    if let Some(idx) = self
                        .nodes
                        .iter()
                        .position(|n| n.leaf_index == Some(target_id))
                    {
                        self.selected_node = Some(idx);
                        self.search_message = None;
                    } else {
                        self.search_message =
                            Some(format!("Record #{target_id} not found in tree"));
                    }
                } else {
                    self.search_message = Some("Enter a valid record number".into());
                }
            }

            if let Some(msg) = &self.search_message {
                ui.colored_label(Color32::LIGHT_RED, msg);
            }
        });

        ui.separator();

        // Calculate audit path for the selected node
        let active_node = self.hovered_node.or(self.selected_node);
        let audit_info =
            active_node.map(|node_idx| compute_audit_path(node_idx, &self.nodes, &parents));

        // Render Canvas inside a 2D ScrollArea
        let scaled_width = (layout.width * self.zoom).max(400.0);
        let scaled_height = (layout.height * self.zoom).max(250.0);

        egui::ScrollArea::both()
            .auto_shrink([false; 2])
            .max_height(ui.available_height() - 140.0)
            .show(ui, |ui| {
                let (rect, response) = ui.allocate_exact_size(
                    Vec2::new(scaled_width, scaled_height),
                    Sense::click_and_drag(),
                );

                self.render_tree(ui, &response, rect, &layout, &audit_info);
            });

        // --- Bottom Inspector Card ---
        if let Some(selected_idx) = self.selected_node {
            ui.separator();
            self.render_inspector(ui, selected_idx, &parents);
        }
    }

    fn render_tree(
        &mut self,
        ui: &mut Ui,
        response: &Response,
        canvas_rect: Rect,
        layout: &MerkleLayout,
        audit_info: &Option<AuditPathInfo>,
    ) {
        let painter = ui.painter_at(canvas_rect);
        let origin = canvas_rect.min + Vec2::new(20.0 * self.zoom, 20.0 * self.zoom);
        let zoom = self.zoom;

        // Map layout positions to screen coordinates
        let screen_positions: Vec<Pos2> = layout
            .positions
            .iter()
            .map(|pos| origin + Vec2::new(pos.x * zoom, pos.y * zoom))
            .collect();

        // Draw connecting edges
        for (index, node) in self.nodes.iter().enumerate() {
            let parent_pos = screen_positions[index];
            for child in [node.left, node.right].into_iter().flatten() {
                if child < screen_positions.len() {
                    let child_pos = screen_positions[child];
                    let is_audit_edge = audit_info
                        .as_ref()
                        .map(|info| info.path_edges.contains(&(index, child)))
                        .unwrap_or(false);

                    let (color, stroke_width) = if is_audit_edge {
                        (Color32::from_rgb(255, 205, 50), 2.8 * zoom.clamp(0.8, 1.5))
                    } else {
                        (Color32::from_rgb(90, 115, 145), 1.5 * zoom.clamp(0.6, 1.2))
                    };

                    painter.line_segment([parent_pos, child_pos], Stroke::new(stroke_width, color));
                }
            }
        }

        // Determine node hit under mouse pointer
        let mouse_pos = response.hover_pos();
        let mut hovered = None;
        let hit_radius = (16.0 * zoom).max(10.0);

        if let Some(mouse) = mouse_pos {
            for (index, &pos) in screen_positions.iter().enumerate() {
                if (mouse - pos).length() <= hit_radius {
                    hovered = Some(index);
                    break;
                }
            }
        }
        self.hovered_node = hovered;

        if response.clicked() {
            self.selected_node = hovered;
            self.copied_hash = None;
        }

        // Draw Nodes
        let base_radius = (10.0 * zoom).clamp(5.0, 15.0);

        for (index, node) in self.nodes.iter().enumerate() {
            let pos = screen_positions[index];

            // Culling: skip drawing if node is far outside the visible viewport
            if !ui.clip_rect().expand(60.0).contains(pos) {
                continue;
            }

            let is_root = index == 0;
            let is_leaf = node.leaf_index.is_some();
            let is_selected = Some(index) == self.selected_node;
            let is_hovered = Some(index) == self.hovered_node;
            let is_in_path = audit_info
                .as_ref()
                .map(|info| info.path_nodes.contains(&index))
                .unwrap_or(false);
            let is_sibling = audit_info
                .as_ref()
                .map(|info| info.sibling_nodes.contains(&index))
                .unwrap_or(false);

            // Node Circle Color
            let fill_color = if is_root {
                Color32::from_rgb(225, 155, 30) // Amber / Gold for Root
            } else if is_leaf {
                Color32::from_rgb(40, 145, 90) // Emerald for Leaves
            } else {
                Color32::from_rgb(55, 110, 180) // Slate Blue for Internal Nodes
            };

            // Halo / Rings for Selection or Hover
            if is_selected {
                painter.circle_stroke(
                    pos,
                    base_radius + 4.0,
                    Stroke::new(2.5, Color32::from_rgb(255, 230, 80)),
                );
            } else if is_hovered {
                painter.circle_stroke(pos, base_radius + 3.0, Stroke::new(2.0, Color32::WHITE));
            } else if is_in_path {
                painter.circle_stroke(
                    pos,
                    base_radius + 2.5,
                    Stroke::new(2.0, Color32::from_rgb(255, 205, 50)),
                );
            } else if is_sibling {
                painter.circle_stroke(
                    pos,
                    base_radius + 2.5,
                    Stroke::new(2.0, Color32::from_rgb(80, 220, 240)),
                );
            }

            painter.circle_filled(pos, base_radius, fill_color);

            // Badges / Labels (only when zoomed in enough to prevent overlapping clutter)
            if zoom >= 0.55 {
                let (label_text, label_color) = if let Some(rec_id) = node.leaf_index {
                    (
                        format!("Record #{rec_id}"),
                        Color32::from_rgb(160, 240, 190),
                    )
                } else if is_root {
                    ("ROOT".to_string(), Color32::from_rgb(255, 215, 120))
                } else {
                    (
                        format!("{}…", &hex::encode(node.hash)[..6]),
                        Color32::from_rgb(190, 210, 235),
                    )
                };

                let font_size = (11.0 * zoom).clamp(9.0, 12.0);
                let text_pos = pos + Vec2::new(0.0, base_radius + 3.0);

                // Subtle dark background pill behind label for anti-clutter readability
                let text_layout = painter.layout_no_wrap(
                    label_text.clone(),
                    FontId::proportional(font_size),
                    label_color,
                );
                let pill_rect = Rect::from_center_size(
                    text_pos + Vec2::new(0.0, text_layout.size().y / 2.0),
                    text_layout.size() + Vec2::new(8.0, 3.0),
                );
                painter.rect_filled(
                    pill_rect,
                    3.0,
                    Color32::from_rgba_premultiplied(20, 24, 32, 215),
                );

                painter.text(
                    text_pos,
                    Align2::CENTER_TOP,
                    label_text,
                    FontId::proportional(font_size),
                    label_color,
                );

                if zoom >= 0.85 {
                    let hash_prefix = format!("{:.8}", hex::encode(node.hash));
                    painter.text(
                        text_pos + Vec2::new(0.0, font_size + 4.0),
                        Align2::CENTER_TOP,
                        hash_prefix,
                        FontId::monospace((9.0 * zoom).clamp(8.0, 10.0)),
                        Color32::from_rgb(150, 165, 185),
                    );
                }
            }
        }

        // Show rich tooltip if hovering over a node
        if let Some(hovered_idx) = self.hovered_node {
            let node = &self.nodes[hovered_idx];
            let hash_hex = hex::encode(node.hash);
            let title = if hovered_idx == 0 {
                "Root Node (Tree Head)".to_string()
            } else if let Some(id) = node.leaf_index {
                format!("Record #{id} (Leaf Node)")
            } else {
                format!("Internal Node #{hovered_idx}")
            };

            response.clone().on_hover_ui_at_pointer(|ui| {
                ui.heading(title);
                ui.label(format!("Hash: {hash_hex}"));
                if let Some(left) = node.left {
                    ui.label(format!("Left child: #{left}"));
                }
                if let Some(right) = node.right {
                    ui.label(format!("Right child: #{right}"));
                }
                ui.label("Click to select and trace proof path");
            });
        }
    }

    fn render_inspector(&mut self, ui: &mut Ui, selected_idx: usize, parents: &[Option<usize>]) {
        if selected_idx >= self.nodes.len() {
            return;
        }

        let node = &self.nodes[selected_idx];
        let hash_hex = hex::encode(node.hash);

        ui.horizontal(|ui| {
            let (badge, color) = if selected_idx == 0 {
                ("ROOT NODE", Color32::from_rgb(255, 190, 40))
            } else if node.leaf_index.is_some() {
                ("RECORD LEAF", Color32::from_rgb(60, 200, 120))
            } else {
                ("INTERNAL NODE", Color32::from_rgb(80, 150, 240))
            };

            ui.colored_label(color, format!("[{badge}]"));

            if let Some(rec_id) = node.leaf_index {
                ui.strong(format!("Record #{rec_id}"));
            } else {
                ui.strong(format!("Node #{selected_idx}"));
            }

            ui.separator();
            ui.label("Hash:");
            ui.monospace(&hash_hex);

            if ui.button("Copy Hash").clicked() {
                ui.ctx().copy_text(hash_hex.clone());
                self.copied_hash = Some(hash_hex.clone());
            }

            if self.copied_hash.is_some() {
                ui.colored_label(Color32::GREEN, "Copied!");
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear Selection").clicked() {
                    self.selected_node = None;
                    self.copied_hash = None;
                }
            });
        });

        // Navigation links
        ui.horizontal(|ui| {
            if let Some(parent_idx) = parents[selected_idx] {
                if ui.button(format!("Go to Parent (#{parent_idx})")).clicked() {
                    self.selected_node = Some(parent_idx);
                    self.copied_hash = None;
                }
            }

            if let Some(left) = node.left {
                if ui.button(format!("Left Child (#{left})")).clicked() {
                    self.selected_node = Some(left);
                    self.copied_hash = None;
                }
            }

            if let Some(right) = node.right {
                if ui.button(format!("Right Child (#{right})")).clicked() {
                    self.selected_node = Some(right);
                    self.copied_hash = None;
                }
            }
        });
    }
}

/// Computed geometry layout for the tree.
#[derive(Debug, Clone)]
pub struct MerkleLayout {
    pub positions: Vec<Pos2>,
    pub max_depth: usize,
    pub width: f32,
    pub height: f32,
}

/// Merkle audit path details for an active node.
#[derive(Debug, Clone)]
pub struct AuditPathInfo {
    pub path_nodes: Vec<usize>,
    pub sibling_nodes: Vec<usize>,
    pub path_edges: Vec<(usize, usize)>,
}

/// Compute parent indices for each node in the tree.
pub fn build_parents(nodes: &[MerkleNodeInfo]) -> Vec<Option<usize>> {
    let mut parents = vec![None; nodes.len()];
    for (idx, node) in nodes.iter().enumerate() {
        if let Some(left) = node.left {
            if left < parents.len() {
                parents[left] = Some(idx);
            }
        }
        if let Some(right) = node.right {
            if right < parents.len() {
                parents[right] = Some(idx);
            }
        }
    }
    parents
}

/// Compute the audit path from a chosen node to the root, identifying ancestor edges and siblings.
pub fn compute_audit_path(
    selected_node: usize,
    nodes: &[MerkleNodeInfo],
    parents: &[Option<usize>],
) -> AuditPathInfo {
    let mut path_nodes = Vec::new();
    let mut sibling_nodes = Vec::new();
    let mut path_edges = Vec::new();

    let mut curr = Some(selected_node);
    while let Some(idx) = curr {
        path_nodes.push(idx);
        if let Some(parent) = parents[idx] {
            path_edges.push((parent, idx));
            let parent_node = &nodes[parent];
            if parent_node.left == Some(idx) {
                if let Some(sibling) = parent_node.right {
                    sibling_nodes.push(sibling);
                }
            } else if parent_node.right == Some(idx) {
                if let Some(sibling) = parent_node.left {
                    sibling_nodes.push(sibling);
                }
            }
            curr = Some(parent);
        } else {
            curr = None;
        }
    }

    AuditPathInfo {
        path_nodes,
        sibling_nodes,
        path_edges,
    }
}

/// Compute 2D coordinates for all nodes in the tree.
pub fn compute_layout(
    nodes: &[MerkleNodeInfo],
    leaf_count: u64,
    align_leaves: bool,
) -> MerkleLayout {
    if nodes.is_empty() {
        return MerkleLayout {
            positions: Vec::new(),
            max_depth: 0,
            width: 420.0,
            height: 240.0,
        };
    }

    let mut positions = vec![Pos2::ZERO; nodes.len()];
    let mut max_depth = 0;

    let spacing_x = 96.0_f32;
    let spacing_y = 86.0_f32;

    let mut ctx = LayoutCtx {
        nodes,
        spacing_x,
        spacing_y,
        positions: &mut positions,
        max_depth: &mut max_depth,
    };

    place_nodes(&mut ctx, 0, 0, leaf_count.max(1), 0);

    if align_leaves && max_depth > 0 {
        let bottom_y = max_depth as f32 * spacing_y + 20.0;
        for (i, node) in nodes.iter().enumerate() {
            if node.leaf_index.is_some() {
                positions[i].y = bottom_y;
            }
        }
    }

    let width = (leaf_count.max(1) as f32 * spacing_x + 80.0).max(460.0);
    let height = (max_depth as f32 * spacing_y + 110.0).max(260.0);

    MerkleLayout {
        positions,
        max_depth,
        width,
        height,
    }
}

struct LayoutCtx<'a> {
    nodes: &'a [MerkleNodeInfo],
    spacing_x: f32,
    spacing_y: f32,
    positions: &'a mut [Pos2],
    max_depth: &'a mut usize,
}

fn place_nodes(
    ctx: &mut LayoutCtx<'_>,
    index: usize,
    start_leaf: u64,
    leaf_count: u64,
    depth: usize,
) -> f32 {
    if index >= ctx.nodes.len() {
        return 0.0;
    }
    *ctx.max_depth = (*ctx.max_depth).max(depth);
    let node = &ctx.nodes[index];
    let x = if let Some(leaf) = node.leaf_index {
        leaf as f32 * ctx.spacing_x + 36.0
    } else {
        let left_x = node
            .left
            .map(|child| place_nodes(ctx, child, start_leaf, leaf_count, depth + 1));
        let right_x = node
            .right
            .map(|child| place_nodes(ctx, child, start_leaf, leaf_count, depth + 1));
        match (left_x, right_x) {
            (Some(left), Some(right)) => (left + right) / 2.0,
            (Some(x), None) | (None, Some(x)) => x,
            (None, None) => {
                start_leaf as f32 * ctx.spacing_x + leaf_count as f32 * (ctx.spacing_x / 2.0)
            }
        }
    };
    ctx.positions[index] = Pos2::new(x, depth as f32 * ctx.spacing_y + 20.0);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_node(
        leaf_index: Option<u64>,
        left: Option<usize>,
        right: Option<usize>,
    ) -> MerkleNodeInfo {
        MerkleNodeInfo {
            hash: [leaf_index.unwrap_or(0) as u8; 32],
            left,
            right,
            leaf_index,
        }
    }

    #[test]
    fn test_merkle_view_initial_state() {
        let view = MerkleView::default();
        assert!(!view.loaded);
        assert_eq!(view.zoom, 1.0);
        assert!(view.align_leaves);
        assert!(view.selected_node.is_none());
    }

    #[test]
    fn test_merkle_parents_and_audit_path() {
        // Tree: Root(0) -> Left(1), Right(2)
        // Left(1) -> Leaf0(3), Leaf1(4)
        // Right(2) -> Leaf2(5), Leaf3(6)
        let nodes = vec![
            dummy_node(None, Some(1), Some(2)),
            dummy_node(None, Some(3), Some(4)),
            dummy_node(None, Some(5), Some(6)),
            dummy_node(Some(0), None, None),
            dummy_node(Some(1), None, None),
            dummy_node(Some(2), None, None),
            dummy_node(Some(3), None, None),
        ];

        let parents = build_parents(&nodes);
        assert_eq!(parents[0], None);
        assert_eq!(parents[1], Some(0));
        assert_eq!(parents[2], Some(0));
        assert_eq!(parents[3], Some(1));
        assert_eq!(parents[4], Some(1));

        let audit = compute_audit_path(3, &nodes, &parents);
        // Path from leaf 3 to root: 3 -> 1 -> 0
        assert_eq!(audit.path_nodes, vec![3, 1, 0]);
        // Siblings along path: sibling of 3 is 4, sibling of 1 is 2
        assert_eq!(audit.sibling_nodes, vec![4, 2]);
        assert_eq!(audit.path_edges, vec![(1, 3), (0, 1)]);
    }

    #[test]
    fn test_merkle_layout_aligned_leaves() {
        // Tree with uneven depth: Root(0) -> Left(1) [Leaf 0, 1], Right(2) [Leaf 2]
        let nodes = vec![
            dummy_node(None, Some(1), Some(2)),
            dummy_node(None, Some(3), Some(4)),
            dummy_node(Some(2), None, None), // Leaf 2 at depth 1
            dummy_node(Some(0), None, None), // Leaf 0 at depth 2
            dummy_node(Some(1), None, None), // Leaf 1 at depth 2
        ];

        // 1. With align_leaves = true: all leaves (nodes 2, 3, 4) should have identical Y coordinate
        let layout_aligned = compute_layout(&nodes, 3, true);
        assert_eq!(layout_aligned.max_depth, 2);
        let leaf2_y = layout_aligned.positions[2].y;
        let leaf0_y = layout_aligned.positions[3].y;
        let leaf1_y = layout_aligned.positions[4].y;
        assert_eq!(leaf2_y, leaf0_y);
        assert_eq!(leaf0_y, leaf1_y);

        // 2. With align_leaves = false: leaf 2 is higher up than leaves 0 and 1
        let layout_natural = compute_layout(&nodes, 3, false);
        assert!(layout_natural.positions[2].y < layout_natural.positions[3].y);
    }
}
