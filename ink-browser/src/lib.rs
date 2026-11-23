//! Ink Browser library crate.
//!
//! Exposes the [`backend::Backend`] trait, [`backend::local::LocalBackend`],
//! user configuration management, and the `eframe`/`egui` desktop application components.

pub mod backend;
pub mod error;
pub mod settings;
pub mod ui;

pub use backend::local::LocalBackend;
pub use backend::Backend;
pub use error::BackendError;
pub use settings::Settings;
pub use ui::InkBrowserApp;
