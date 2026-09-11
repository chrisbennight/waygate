//! Built-in surfaces page — `/admin/t/{tenant}/builtins`.
//!
//! Read-only operator view of the gateway's OWN built-in MCP namespaces
//! (`gateway-admin.*` / `gateway-observe.*` / `gateway-control.*`). These are
//! answered locally by the gateway rather than proxied to an upstream, so they
//! never appear on the Servers or Catalog pages — this page closes that gap so
//! an operator can see and reason about the gateway's own tool surface the same
//! way they browse upstreams: each namespace, the scope that gates it, and each
//! tool's risk classification.
//!
//! The data is the static [`waygate_mcp::BuiltinSurfaceDescriptor`] set injected
//! into [`AdminState`] at boot — no tenant data, no secrets — so the page
//! renders for any dashboard session without a scope gate (unlike the Catalog
//! page, which hides per-tenant governance data behind `mcp:admin`).

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_oidc::Principal;

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "builtins.html")]
struct BuiltinsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    surfaces: Vec<SurfaceRow>,
}

struct SurfaceRow {
    namespace: String,
    required_scope: String,
    summary: String,
    tools: Vec<ToolRow>,
}

struct ToolRow {
    name: String,
    description: String,
    risk: &'static str,
    side_effects: bool,
    pii: bool,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/builtins", get(builtins_page))
}

async fn builtins_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let surfaces = state
        .servers
        .builtin_surfaces
        .iter()
        .map(|s| SurfaceRow {
            namespace: s.namespace.clone(),
            required_scope: s.required_scope.clone(),
            summary: s.summary.clone(),
            tools: s
                .tools
                .iter()
                .map(|t| ToolRow {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    risk: t.risk.as_str(),
                    side_effects: t.side_effects,
                    pii: t.pii,
                })
                .collect(),
        })
        .collect();

    let page = BuiltinsPage {
        chrome: PageChrome::build(
            &state,
            "Built-ins",
            "/builtins",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        surfaces,
    };
    render(&page)
}
