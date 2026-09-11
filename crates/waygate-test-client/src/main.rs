//! `mcp-test-client` — a CLI for OAuth-protected MCP gateways.
//!
//! Mirrors the auth UX of Claude Code (CIMD client_id URL + ephemeral
//! loopback callback) while also covering the `bearer` / `none` modes we use
//! in local development. Optional SEP #1888 discovery lets the operator
//! enumerate, describe, and invoke tools via the gateway's progressive
//! disclosure surface; the conformance subcommand bundles the checks into
//! a pass/fail suite.

mod auth;
mod cli;
mod conformance;
pub mod files;
mod gateway;
mod host_contract;
mod output;
mod repl;
mod sep1888;
mod tools;

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command, ToolsCommand};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `anyhow` errors render with their cause chain via the
            // alternate `{:#}` formatter — useful for "token fetch failed:
            // reqwest: connect: timeout" style traces.
            eprintln!("error: {:#}", e);
            ExitCode::from(1)
        }
    }
}

/// Install the global tracing subscriber. CLIs live on stderr so piped output
/// stays clean on stdout — matches `classify`'s convention.
fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter =
        EnvFilter::try_from_env("MCP_TEST_CLIENT_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = cli::Context::from_cli(&cli).context("resolve CLI context")?;

    match cli.command {
        Command::Discover => gateway::discover::run(&ctx).await,
        Command::Login => auth::login::run(&ctx).await,
        Command::Logout => auth::cache::logout(&ctx).await,
        Command::Tools(cmd) => match cmd {
            ToolsCommand::List => tools::list::run(&ctx).await,
            ToolsCommand::Search(args) => tools::search::run(&ctx, args).await,
            ToolsCommand::Describe(args) => tools::describe::run(&ctx, args).await,
            ToolsCommand::Call(args) => tools::call::run(&ctx, args).await,
        },
        Command::Repl => repl::run(&ctx).await,
        Command::Conformance(args) => conformance::run(&ctx, args).await,
        Command::HostContract(args) => host_contract::run(&ctx, args).await,
        Command::Raw => tools::call::run_raw_stdio(&ctx).await,
    }
}
