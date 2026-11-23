//! Persistent user settings and connection history management.
//!
//! # Security & Secret Protection
//! As specified in ARCHITECTURE.md §19.3:
//! - Only file paths and server endpoints are remembered.
//! - Private key bytes, seeds, or user passphrases are NEVER stored in settings.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A remembered local database connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConnectionEntry {
    /// Filesystem path to the Ink database directory.
    pub data_dir: String,
    /// Filesystem path to the user's public or encrypted key file (`.key` or `.inkkey`).
    pub key_path: String,
    /// Last used timestamp in seconds UTC.
    pub last_used: i64,
}

/// A remembered remote server connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConnectionEntry {
    /// Remote host or IP.
    pub host: String,
    /// TCP port (default: 7777).
    pub port: u16,
    /// Whether TLS 1.3 is enabled.
    pub tls: bool,
    /// Filesystem path to the user's key file.
    pub key_path: String,
    /// Last used timestamp in seconds UTC.
    pub last_used: i64,
}

/// GUI visual theme preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemePreference {
    /// Follow host operating system dark/light mode.
    #[default]
    System,
    /// Force dark theme.
    Dark,
    /// Force light theme.
    Light,
}

/// User settings and UI state persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// History of opened local databases (max 10).
    pub recent_local: Vec<LocalConnectionEntry>,
    /// History of connected remote servers (max 10).
    pub recent_remote: Vec<RemoteConnectionEntry>,
    /// Selected theme.
    pub theme: ThemePreference,
    /// Default records per page in Browse Data grid.
    pub default_page_size: usize,
    /// Preferred window dimensions `[width, height]`.
    pub window_size: [f32; 2],
    /// Pinned known-good Merkle tree head (hex string).
    pub pinned_tree_head: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            recent_local: Vec::new(),
            recent_remote: Vec::new(),
            theme: ThemePreference::System,
            default_page_size: 50,
            window_size: [1200.0, 800.0],
            pinned_tree_head: None,
        }
    }
}

impl Settings {
    /// Record a local database connection in history.
    pub fn add_recent_local(&mut self, data_dir: &str, key_path: &str) {
        let now = chrono::Utc::now().timestamp();
        self.recent_local
            .retain(|e| !(e.data_dir == data_dir && e.key_path == key_path));
        self.recent_local.insert(
            0,
            LocalConnectionEntry {
                data_dir: data_dir.to_string(),
                key_path: key_path.to_string(),
                last_used: now,
            },
        );
        self.recent_local.truncate(10);
    }

    /// Record a remote server connection in history.
    pub fn add_recent_remote(&mut self, host: &str, port: u16, tls: bool, key_path: &str) {
        let now = chrono::Utc::now().timestamp();
        self.recent_remote
            .retain(|e| !(e.host == host && e.port == port && e.key_path == key_path));
        self.recent_remote.insert(
            0,
            RemoteConnectionEntry {
                host: host.to_string(),
                port,
                tls,
                key_path: key_path.to_string(),
                last_used: now,
            },
        );
        self.recent_remote.truncate(10);
    }

    /// Default path for storing settings file in user config directory.
    pub fn default_path() -> PathBuf {
        let mut dir = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        dir.push(".ink");
        let _ = std::fs::create_dir_all(&dir);
        dir.push("browser_settings.json");
        dir
    }

    /// Load settings from the default filesystem location or return defaults.
    pub fn load() -> Self {
        Self::load_from_path(&Self::default_path())
    }

    /// Load settings from a specific file path.
    pub fn load_from_path(path: &Path) -> Self {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(settings) = serde_json::from_slice::<Settings>(&bytes) {
                return settings;
            }
        }
        Self::default()
    }

    /// Save settings to the default filesystem location.
    pub fn save(&self) -> Result<(), std::io::Error> {
        self.save_to_path(&Self::default_path())
    }

    /// Save settings to a specific file path.
    pub fn save_to_path(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_settings_save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("test_settings.json");

        let mut settings = Settings {
            theme: ThemePreference::Dark,
            default_page_size: 100,
            window_size: [1400.0, 900.0],
            pinned_tree_head: Some("abcdef1234567890".to_string()),
            ..Default::default()
        };

        settings.add_recent_local("C:\\data\\ink1", "C:\\keys\\admin.key");
        settings.add_recent_remote("127.0.0.1", 7777, true, "C:\\keys\\alice.key");

        settings.save_to_path(&file_path).expect("Save failed");

        let loaded = Settings::load_from_path(&file_path);
        assert_eq!(loaded.theme, ThemePreference::Dark);
        assert_eq!(loaded.default_page_size, 100);
        assert_eq!(loaded.window_size, [1400.0, 900.0]);
        assert_eq!(
            loaded.pinned_tree_head,
            Some("abcdef1234567890".to_string())
        );

        assert_eq!(loaded.recent_local.len(), 1);
        assert_eq!(loaded.recent_local[0].data_dir, "C:\\data\\ink1");
        assert_eq!(loaded.recent_local[0].key_path, "C:\\keys\\admin.key");

        assert_eq!(loaded.recent_remote.len(), 1);
        assert_eq!(loaded.recent_remote[0].host, "127.0.0.1");
        assert_eq!(loaded.recent_remote[0].port, 7777);
        assert!(loaded.recent_remote[0].tls);
        assert_eq!(loaded.recent_remote[0].key_path, "C:\\keys\\alice.key");
    }

    #[test]
    fn test_settings_never_store_secrets() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("security_test_settings.json");

        let mut settings = Settings::default();
        settings.add_recent_local("/var/ink/db", "/home/user/.ink/admin.inkkey");
        settings.add_recent_remote("db.corp.net", 7777, true, "/home/user/.ink/writer.key");
        settings.save_to_path(&file_path).expect("Save failed");

        let json_text = std::fs::read_to_string(&file_path).expect("Read JSON failed");

        // Strictly ensure no passphrase or private key fields exist in serialized JSON
        assert!(!json_text.contains("passphrase"));
        assert!(!json_text.contains("password"));
        assert!(!json_text.contains("secret"));
        assert!(!json_text.contains("seed"));
        assert!(!json_text.contains("private_key"));
    }

    #[test]
    fn test_recent_connections_fifo_and_deduplication() {
        let mut settings = Settings::default();

        // Add 12 entries
        for i in 0..12 {
            settings.add_recent_local(&format!("/db/path/{}", i), &format!("/key/{}.key", i));
        }

        // Must be truncated to maximum 10
        assert_eq!(settings.recent_local.len(), 10);
        // Most recent is at index 0
        assert_eq!(settings.recent_local[0].data_dir, "/db/path/11");

        // Re-adding existing entry deduplicates and moves to front
        settings.add_recent_local("/db/path/5", "/key/5.key");
        assert_eq!(settings.recent_local.len(), 10);
        assert_eq!(settings.recent_local[0].data_dir, "/db/path/5");
    }
}
