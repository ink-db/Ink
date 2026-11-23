use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ink",
    about = "Ink: Write-and-read-only immutable database with cryptographic verification",
    version
)]
pub struct Cli {
    /// Database directory (defaults to current directory if not specified)
    #[arg(short, long, global = true, default_value = "./.ink_data")]
    pub dir: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new Ink database in the specified directory
    Init(InitArgs),

    /// Append a new record to a table
    Append(AppendArgs),

    /// Append a correction to an existing record
    Correct(CorrectArgs),

    /// Read records from a table
    Read(ReadArgs),

    /// Inspect the full history of a record and all of its corrections
    History(HistoryArgs),

    /// Verify cryptographic integrity of the database or a specific table
    Verify(VerifyArgs),

    /// Generate a new Ed25519 signing keypair
    Keygen(KeygenArgs),

    /// Export a cryptographic Merkle inclusion proof for a record
    ExportProof(ExportProofArgs),

    /// Verify an exportable Merkle inclusion proof
    VerifyProof(VerifyProofArgs),

    /// Show database status, table summary, and record counts
    Status,

    /// Execute an IQL query statement, e.g. READ FROM "sales" WHERE amount > 1000
    #[command(alias = "generic")]
    Query(QueryArgs),

    /// Manage cryptographic access control, roles, and grants
    #[command(subcommand)]
    Access(AccessCommands),

    /// Start the Ink TCP database server daemon (IWP/1.0)
    Serve(ServeArgs),

    /// Connect to a remote Ink database server via interactive shell
    Connect(ConnectArgs),
}

#[derive(Args, Debug, Default)]
pub struct InitArgs {
    /// Optional path to an existing Ed25519 private key to import as Genesis Admin
    #[arg(long)]
    pub admin_key: Option<PathBuf>,

    /// Path to save the generated Genesis Admin private key (defaults to <dir>/admin.key)
    #[arg(long)]
    pub admin_out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum AccessCommands {
    /// Grant permissions to an Ed25519 public key
    Grant(AccessGrantArgs),
    /// Revoke permissions from an Ed25519 public key
    Revoke(AccessRevokeArgs),
    /// List active grants and roles
    List(AccessListArgs),
    /// View access history and audit events
    Log(AccessLogArgs),
}

#[derive(Args, Debug)]
pub struct AccessGrantArgs {
    /// Path to administrator Ed25519 private key
    #[arg(long)]
    pub admin_key: PathBuf,

    /// Subject Ed25519 public key (64-character hex)
    #[arg(long)]
    pub subject_key: String,

    /// Label for audit records (e.g. alice_finance)
    #[arg(long, default_value = "user")]
    pub label: String,

    /// Role to assign: admin, writer, reader, or auditor
    #[arg(long)]
    pub role: String,

    /// Scoped table names (can be specified multiple times; defaults to "*")
    #[arg(long = "table", default_values_t = vec!["*".to_string()])]
    pub tables: Vec<String>,

    /// Optional expiration timestamp (microseconds UTC)
    #[arg(long)]
    pub expires_at: Option<i64>,
}

#[derive(Args, Debug)]
pub struct AccessRevokeArgs {
    /// Path to administrator Ed25519 private key
    #[arg(long)]
    pub admin_key: PathBuf,

    /// Subject Ed25519 public key (64-character hex)
    #[arg(long)]
    pub subject_key: String,

    /// Specific role to revoke (if omitted, revokes all roles for this key)
    #[arg(long)]
    pub role: Option<String>,

    /// Scoped table names to revoke (defaults to "*")
    #[arg(long = "table", default_values_t = vec!["*".to_string()])]
    pub tables: Vec<String>,

    /// Mandatory reason for the revocation
    #[arg(long)]
    pub reason: String,
}

#[derive(Args, Debug, Default)]
pub struct AccessListArgs {
    /// Optional subject public key filter (64-character hex)
    #[arg(long)]
    pub subject_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct AccessLogArgs {
    /// Maximum number of recent events to display
    #[arg(long, default_value_t = 50)]
    pub tail: usize,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// File path to save the private key hex (if omitted, prints to terminal)
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ExportProofArgs {
    /// Record ID to generate proof for
    #[arg(long)]
    pub id: u64,

    /// Optional file path to write the JSON proof
    #[arg(short, long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyProofArgs {
    /// Path to the JSON proof file or raw JSON string
    #[arg(short, long)]
    pub proof: String,
}

#[derive(Args, Debug)]
pub struct AppendArgs {
    /// Target table name
    #[arg(short, long)]
    pub table: String,

    /// JSON payload to store
    #[arg(long)]
    pub data: String,

    /// Optional path to Ed25519 private key file to sign this record
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CorrectArgs {
    /// ID of the original record being corrected
    #[arg(long)]
    pub id: u64,

    /// Corrected JSON data
    #[arg(long)]
    pub data: String,

    /// Reason for the correction (permanently preserved)
    #[arg(short, long)]
    pub reason: String,

    /// Optional path to Ed25519 private key file to sign this correction
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    /// Table name to read records from
    #[arg(short, long)]
    pub table: String,

    /// Optional limit on the number of records to return
    #[arg(short, long)]
    pub limit: Option<usize>,

    /// Optional path to Ed25519 private key for authenticated reading
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    /// ID of the record to inspect
    #[arg(long)]
    pub id: u64,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Table name to verify (if omitted, verifies all tables)
    #[arg(short, long)]
    pub table: Option<String>,
}

#[derive(Args, Debug)]
pub struct QueryArgs {
    /// The IQL statement to execute
    #[arg(value_name = "QUERY")]
    pub query: Option<String>,

    /// Alternative flag for passing the query string
    #[arg(short, long)]
    pub args: Option<String>,

    /// Optional path to Ed25519 private key for authenticated query execution
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Network address to bind the TCP daemon to
    #[arg(short, long, default_value = "0.0.0.0:7777")]
    pub bind: String,

    /// Optional path to TLS server certificate (PEM format)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Optional path to TLS private key (PEM format)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Maximum concurrent unauthenticated connections allowed (default: 100)
    #[arg(long, default_value = "100")]
    pub max_unauth_conns: usize,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Remote Ink daemon host address (IP:PORT or hostname:PORT)
    #[arg(long, default_value = "127.0.0.1:7777")]
    pub host: String,

    /// Path to Ed25519 private key file or passphrase-encrypted .inkkey
    #[arg(short, long)]
    pub key: PathBuf,

    /// Optional passphrase for decrypting .inkkey file
    #[arg(short, long)]
    pub passphrase: Option<String>,
}
