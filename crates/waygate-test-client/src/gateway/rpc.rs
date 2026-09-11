//! Construct an rmcp `RunningService<RoleClient, _>` pre-configured with
//! the Authorization header resolved by `auth::resolver`.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use rmcp::model::{ClientCapabilities, ClientInfo, Implementation, ProtocolVersion};
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{ClientLifecycleMode, ClientServiceExt, RoleClient, ServiceExt};

use crate::auth::ResolvedAuth;
use crate::cli::Context as CliContext;

/// Boxed running service — simpler than carrying the concrete transport type
/// through every caller.
pub type Client = RunningService<RoleClient, ClientInfo>;

/// Build + `initialize` an MCP client.
pub async fn connect(ctx: &CliContext, auth: &ResolvedAuth) -> Result<Client> {
    let uri = ctx.mcp_url().to_string();
    let arc_uri: Arc<str> = Arc::from(uri.clone());
    let mut config = StreamableHttpClientTransportConfig::with_uri(arc_uri);
    if let Some(token) = auth.bearer.as_deref() {
        config = config.auth_header(token.to_owned());
    }

    let transport = StreamableHttpClientTransport::from_config(config);

    let info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new(
            concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")),
            env!("CARGO_PKG_VERSION"),
        ),
    );
    let client = info
        .serve(transport)
        .await
        .with_context(|| format!("initialize MCP session against {uri}"))?;
    Ok(client)
}

/// Build a stateless MCP 2026 client through `server/discover`.
///
/// The ordinary CLI commands preserve their legacy initialized-session path.
/// The deferred-host proof deliberately takes this path because the stable
/// authorization-scoped direct catalog is the 2026 contract under test.
pub async fn connect_2026(ctx: &CliContext, auth: &ResolvedAuth) -> Result<Client> {
    let uri = ctx.mcp_url().to_string();
    let arc_uri: Arc<str> = Arc::from(uri.clone());
    let mut config = StreamableHttpClientTransportConfig::with_uri(arc_uri);
    if let Some(token) = auth.bearer.as_deref() {
        config = config.auth_header(token.to_owned());
    }
    let transport = StreamableHttpClientTransport::from_config(config);
    let info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new(
            concat!("mcp-test-client/", env!("CARGO_PKG_VERSION")),
            env!("CARGO_PKG_VERSION"),
        ),
    );
    let client = info
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .with_context(|| format!("discover stateless MCP 2026 against {uri}"))?;
    let negotiated = &client
        .peer_info()
        .context("MCP 2026 discovery returned no peer information")?
        .protocol_version;
    if negotiated != &ProtocolVersion::V_2026_07_28 {
        anyhow::bail!("expected MCP 2026-07-28, negotiated {negotiated}");
    }
    Ok(client)
}
