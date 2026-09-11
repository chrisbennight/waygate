//! CLI surface.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "mcp-files",
    about = "Waygate file helper: move a file to or from an MCP gateway without its bytes entering model context",
    version,
    long_about = None,
)]
pub struct Cli {
    /// Override where the signing key and recorded gateway live. Defaults to
    /// `mcp-files` under the user's configuration directory.
    ///
    /// Must be a location only this user can read: the signing key stored
    /// there is what keeps a relayed grant handle unusable to anyone else.
    #[arg(long, env = "MCP_FILES_CONFIG_DIR", global = true)]
    pub config_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Record the gateway that transfer addresses must belong to, and create
    /// the signing key if it does not exist yet.
    Init(InitArgs),
    /// Print the key thumbprint to pass as `helper_jkt` when preparing a
    /// transfer.
    Thumbprint,
    /// Upload a local file. Pipe the `prepare_upload` result in on stdin.
    Upload(UploadArgs),
    /// Download a gateway file. Pipe the `prepare_download` result in on stdin.
    Download(DownloadArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Base URL of the gateway, for example `https://gateway.example`.
    #[arg(long)]
    pub gateway: String,
}

#[derive(Debug, Args)]
pub struct UploadArgs {
    /// Path of the local file to send.
    #[arg(long)]
    pub file: PathBuf,

    /// How the prepare result on stdin is delimited. The default completes as
    /// soon as one JSON value is available and does not require EOF.
    #[arg(long, value_enum, default_value_t = InputFraming::Auto)]
    pub input_framing: InputFraming,
}

#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// Where to write the retrieved file.
    #[arg(long)]
    pub dest: PathBuf,

    /// How the prepare result on stdin is delimited. The default completes as
    /// soon as one JSON value is available and does not require EOF.
    #[arg(long, value_enum, default_value_t = InputFraming::Auto)]
    pub input_framing: InputFraming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InputFraming {
    /// Read the first complete JSON value without waiting for stdin to close.
    Auto,
    /// Read the prepare result until stdin closes. Compatible with pipes and heredocs.
    Eof,
    /// Read one compact JSON value terminated by a newline without waiting for EOF.
    Jsonl,
}
