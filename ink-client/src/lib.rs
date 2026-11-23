//! Client library and interactive shell for the Ink immutable database.

pub mod connection;
pub mod error;
pub mod key;
pub mod shell;

pub use connection::{ClientAppendResult, ClientQueryResult, Connection};
pub use error::ClientError;
pub use key::{decrypt_inkkey, load_key, save_encrypted_key, INKKEY_MAGIC};
pub use shell::run_shell;
