//! Ink Browser desktop application executable.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use eframe::egui;
use ink_browser::{InkBrowserApp, Settings};

fn main() -> eframe::Result<()> {
    let settings = Settings::load();
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(settings.window_size)
            .with_min_inner_size([800.0, 600.0])
            .with_title("Ink Browser"),
        ..Default::default()
    };

    eframe::run_native(
        "Ink Browser",
        native_options,
        Box::new(|_cc| Ok(Box::new(InkBrowserApp::new(settings)))),
    )
}
