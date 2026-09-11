//! `mcp-files` — the out-of-band leg of a gateway file transfer.
//!
//! The gateway's tool-fallback path deliberately hands back a grant that is
//! bound to a key rather than a bearer credential, so the handle can travel
//! back through a caller's context without becoming usable to anyone who reads
//! it. Redeeming such a grant needs a signing library, which is what this binary
//! supplies: the caller runs the `gateway-files.prepare_*` tool, pipes the
//! result here, and gets back a file URI and nothing else.
//!
//! It speaks HTTPS and JOSE only. There is no MCP client here and no gateway
//! login: the signing key authorizes nothing on its own, so this process holds
//! no credential worth stealing.

// Only Windows consults this decision, but it is compiled under `test`
// everywhere so the platform without a runner here is not also the only place
// its rules are exercised.
#[cfg(any(windows, test))]
mod acl;
#[cfg(windows)]
mod acl_windows;
mod cli;
mod config;
mod key;
mod transfer;
mod wire;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser as _;

use crate::cli::{Cli, Command, InputFraming};
use crate::config::{Config, Paths};
use crate::key::HelperKey;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let paths = Paths::resolve(cli.config_dir)?;

    match cli.command {
        Command::Init(args) => {
            let gateway = config::validate_gateway(&args.gateway)?;
            Config { gateway }.save(&paths.config())?;
            let key = HelperKey::load_or_create(&paths.key())?;
            println!("{}", key.thumbprint());
            eprintln!(
                "recorded {} — transfer addresses outside it will be refused",
                args.gateway
            );
            Ok(())
        }
        Command::Thumbprint => {
            let key = HelperKey::load_or_create(&paths.key())?;
            println!("{}", key.thumbprint());
            Ok(())
        }
        Command::Upload(args) => {
            let config = Config::load(&paths.config())?;
            let key = HelperKey::load_or_create(&paths.key())?;
            let prepared = wire::from_reader(read_prepared_input(args.input_framing)?.as_slice())?;
            let uri = transfer::upload(prepared, &args.file, &config.origin(), &key)?;
            println!("{uri}");
            Ok(())
        }
        Command::Download(args) => {
            let config = Config::load(&paths.config())?;
            let key = HelperKey::load_or_create(&paths.key())?;
            let prepared = wire::from_reader(read_prepared_input(args.input_framing)?.as_slice())?;
            let uri = transfer::download(prepared, &args.dest, &config.origin(), &key)?;
            println!("{uri}");
            Ok(())
        }
    }
}

fn read_prepared_input(framing: InputFraming) -> Result<Vec<u8>> {
    match framing {
        InputFraming::Auto => transfer::read_first_json_value_with_timeout(
            std::io::stdin(),
            std::time::Duration::from_secs(30),
        ),
        InputFraming::Eof => transfer::read_to_end(std::io::stdin().lock()),
        InputFraming::Jsonl => transfer::read_json_line_with_timeout(
            std::io::BufReader::new(std::io::stdin()),
            std::time::Duration::from_secs(30),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn upload_requires_a_file() {
        Cli::try_parse_from(["mcp-files", "upload"]).expect_err("the caller must say what to send");
    }

    #[test]
    fn init_requires_a_gateway() {
        Cli::try_parse_from(["mcp-files", "init"])
            .expect_err("there is no default gateway to fall back on");
    }

    #[test]
    fn upload_can_select_newline_delimited_input() {
        let cli = Cli::try_parse_from([
            "mcp-files",
            "upload",
            "--file",
            "report.pdf",
            "--input-framing",
            "jsonl",
        ])
        .expect("jsonl framing is accepted");
        let Command::Upload(args) = cli.command else {
            panic!("upload command");
        };
        assert_eq!(args.input_framing, InputFraming::Jsonl);
    }

    #[test]
    fn upload_defaults_to_self_delimiting_input() {
        let cli = Cli::try_parse_from(["mcp-files", "upload", "--file", "report.pdf"])
            .expect("default framing is accepted");
        let Command::Upload(args) = cli.command else {
            panic!("upload command");
        };
        assert_eq!(args.input_framing, InputFraming::Auto);
    }
}
