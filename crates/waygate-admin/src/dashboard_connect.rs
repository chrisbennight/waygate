//! Connect page — split out of `dashboard.rs` into the sibling
//! router-per-domain pattern; bodies verbatim. Routes stay mounted by
//! `dashboard::page_routes`, unchanged.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use waygate_oidc::Principal;

use super::dashboard::*;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "connect.html")]
struct ConnectPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Streamable-HTTP MCP endpoint clients connect to.
    mcp_url: String,
    /// `true` when the built-in Authorization Server is on (OAuth + CIMD
    /// available). `false` ⇒ clients authenticate with a minted API key.
    as_enabled: bool,
    as_metadata_url: String,
    authorize_url: String,
    token_url: String,
    /// Copy-paste `claude mcp add` one-liner.
    mcp_add_snippet: String,
    /// Copy-paste `.mcp.json` block.
    mcp_json_snippet: String,
}

/// `GET /connect` — read-only "Connect your MCP client" guide. Surfaces the
/// gateway's MCP endpoint + OAuth/CIMD discovery endpoints and ready-to-paste
/// client config, so a developer can wire a client without leaving the
/// dashboard for the docs.
pub(crate) async fn connect_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let base = state.public_url.trim_end_matches('/').to_string();
    let mcp_url = format!("{base}/mcp");
    let mcp_add_snippet = format!("claude mcp add --transport http gateway {mcp_url}");
    let mcp_json_snippet = format!(
        "{{\n  \"mcpServers\": {{\n    \"gateway\": {{\n      \"type\": \"http\",\n      \"url\": \"{mcp_url}\"\n    }}\n  }}\n}}"
    );
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    render(&ConnectPage {
        chrome: PageChrome::build(
            &state,
            "Connect",
            "/connect",
            &headers,
            user.map(|Extension(p)| user_display(&p)),
            tenant_ctx,
            String::new(),
        ),
        as_enabled: state.system.as_enabled,
        as_metadata_url: format!("{base}/.well-known/oauth-authorization-server"),
        authorize_url: format!("{base}/oauth/authorize"),
        token_url: format!("{base}/oauth/token"),
        mcp_url,
        mcp_add_snippet,
        mcp_json_snippet,
    })
}

// ---- policies + simulator -------------------------------------------------
