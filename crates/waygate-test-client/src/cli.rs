//! CLI surface — clap definitions and the shared `Context` that every
//! subcommand reads.

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use url::Url;

/// Default public gateway URL probed when `--gateway` is omitted.
pub const DEFAULT_GATEWAY_URL: &str = "http://localhost:8080";

#[derive(Debug, Parser)]
#[command(
    name = "mcp-test-client",
    about = "Waygate test client for OAuth-protected MCP gateways (CIMD login + SEP #1888)",
    version,
    long_about = None,
)]
pub struct Cli {
    /// Base URL of the gateway (no trailing `/mcp`).
    #[arg(long, env = "GATEWAY_URL", default_value = DEFAULT_GATEWAY_URL, global = true)]
    pub gateway: String,

    /// Authentication mode.
    ///
    /// `auto` (default) runs `discover` once and picks `oauth-cimd` when the
    /// gateway advertises an AS, `none` when it does not, and `bearer` when
    /// `--token` / `$GATEWAY_TOKEN` is set.
    #[arg(long, value_enum, default_value_t = AuthModeArg::Auto, global = true)]
    pub auth: AuthModeArg,

    /// Bearer token to send as `Authorization: Bearer …`. Overrides any
    /// cached token but does not itself cause `--auth bearer` to be selected
    /// unless `--auth=bearer` is passed or `--auth=auto` sees this value.
    #[arg(long, env = "GATEWAY_TOKEN", global = true, hide_env_values = true)]
    pub token: Option<String>,

    /// HTTPS URL of your hosted CIMD client-identity document. Required for
    /// a new OAuth login; bearer and unauthenticated calls do not need one.
    #[arg(long, env = "MCP_TEST_CLIENT_CIMD_URL", global = true)]
    pub cimd_url: Option<String>,

    /// Emit JSON to stdout instead of the pretty text renderer. `stderr`
    /// remains human-readable.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity (`-v` info, `-vv` debug). Overrides
    /// `MCP_TEST_CLIENT_LOG`.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum AuthModeArg {
    /// Pick based on discovery + `--token` presence.
    Auto,
    /// OAuth 2.1 authorization-code + PKCE via CIMD against the gateway AS.
    OauthCimd,
    /// Static bearer token from `--token` / `$GATEWAY_TOKEN`.
    Bearer,
    /// No Authorization header. Use against `GATEWAY_AUTH_MODE=disabled`.
    None,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Probe `/.well-known/*` endpoints and print the gateway's auth surface.
    Discover,
    /// Run the CIMD OAuth flow and cache tokens for `--gateway`.
    Login,
    /// Delete cached tokens for `--gateway`.
    Logout,
    /// Inspect and invoke MCP tools.
    #[command(subcommand)]
    Tools(ToolsCommand),
    /// Interactive picker: servers → tools → call.
    Repl,
    /// Run the conformance suite. Exits non-zero on failure.
    Conformance(ConformanceArgs),
    /// Prove that one ordinary MCP tool is listed and directly callable.
    HostContract(HostContractArgs),
    /// Debug: read a JSON-RPC request from stdin, write the response to
    /// stdout.
    Raw,
}

#[derive(Debug, Subcommand)]
pub enum ToolsCommand {
    /// `tools/list` — the flat MCP tool inventory the gateway exposes.
    List,
    /// SEP #1888 `searchTools` invocation.
    Search(SearchArgs),
    /// SEP #1888 `searchTools` in `mode=types` for a single operation.
    Describe(DescribeArgs),
    /// Invoke a tool by its fully-qualified name.
    Call(CallArgs),
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Upstream server name. When omitted, searches every upstream that
    /// exposes a `.searchTools` meta-tool.
    #[arg(long)]
    pub server: Option<String>,

    /// Free-text query passed to the gateway's BM25 index.
    #[arg(long)]
    pub query: Option<String>,

    /// Filter by resource type (SEP #1888 `filters.resourceType`).
    #[arg(long)]
    pub resource_type: Option<String>,

    /// Filter by action (SEP #1888 `filters.action`).
    #[arg(long)]
    pub action: Option<String>,

    /// Filter by scope (SEP #1888 `filters.scope`).
    #[arg(long)]
    pub scope: Option<String>,

    /// Filter by risk level.
    #[arg(long)]
    pub risk_level: Option<String>,

    /// Page size (1–500).
    #[arg(long)]
    pub limit: Option<u32>,

    /// Cursor token returned by a previous call.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Automatically follow `nextCursor` until exhausted.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct DescribeArgs {
    /// Fully-qualified operation name (`<server>.<tool>`).
    pub name: String,
}

#[derive(Debug, Args)]
pub struct CallArgs {
    /// Fully-qualified tool name (`<server>.<tool>`).
    pub name: String,

    /// JSON object of arguments. Mutually exclusive with `--stdin`.
    #[arg(long, conflicts_with = "stdin")]
    pub args: Option<String>,

    /// Read the JSON args object from stdin.
    #[arg(long)]
    pub stdin: bool,
}

#[derive(Debug, Args)]
pub struct ConformanceArgs {
    /// Run the heavy suite (cursor paging, error shapes, filter matrix,
    /// refresh-token round-trip). Implies `--light`.
    #[arg(long)]
    pub heavy: bool,
}

#[derive(Debug, Args)]
pub struct HostContractArgs {
    /// Fully-qualified ordinary tool name (`<server>.<tool>`).
    #[arg(long)]
    pub tool: String,

    /// JSON object passed directly to the tool. Defaults to `{}`.
    #[arg(long, default_value = "{}")]
    pub args: String,
}

/// Shared, validated context passed to every subcommand. Normalises the
/// gateway URL (strips a trailing slash, validates the scheme) so downstream
/// code doesn't repeat that work.
#[derive(Debug, Clone)]
pub struct Context {
    pub gateway_base: Url,
    pub auth_mode: AuthModeArg,
    pub token_override: Option<String>,
    pub cimd_url: Option<String>,
    pub json: bool,
}

impl Context {
    pub fn required_cimd_url(&self) -> Result<&str> {
        self.cimd_url.as_deref().filter(|url| !url.trim().is_empty()).context(
            "OAuth login requires --cimd-url or MCP_TEST_CLIENT_CIMD_URL pointing to your hosted client metadata document; see crates/waygate-test-client/docs/cimd-hosting.md",
        )
    }

    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let base = Url::parse(cli.gateway.trim_end_matches('/'))
            .with_context(|| format!("parse --gateway URL `{}`", cli.gateway))?;
        if !matches!(base.scheme(), "http" | "https") {
            anyhow::bail!(
                "--gateway scheme must be http or https (got `{}`)",
                base.scheme()
            );
        }
        Ok(Self {
            gateway_base: base,
            auth_mode: cli.auth,
            token_override: cli.token.clone(),
            cimd_url: cli.cimd_url.clone(),
            json: cli.json,
        })
    }

    /// Build `<gateway>/<path>` by cloning the base URL and replacing its
    /// path — avoids the `Url::join` corner-case where a path without a
    /// trailing slash loses its last segment.
    pub fn url(&self, path: &str) -> Url {
        let mut u = self.gateway_base.clone();
        u.set_path(path);
        u.set_query(None);
        u.set_fragment(None);
        u
    }

    /// The MCP endpoint (`/mcp`) the gateway mounts its streamable-HTTP
    /// service under.
    pub fn mcp_url(&self) -> Url {
        self.url("/mcp")
    }
}
