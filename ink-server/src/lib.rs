//! Server daemon library and CLI definitions for the Ink database.

pub mod cli;
pub mod server;

pub use server::TcpDaemon;
