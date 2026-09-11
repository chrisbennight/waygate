//! `/api/v1/gateway/builtins` — read-only view of the gateway's OWN built-in
//! MCP tool namespaces.
//!
//! The gateway answers three reserved namespaces itself rather than proxying
//! them to an upstream: `gateway-admin.*` (HITL propose), `gateway-observe.*`
//! (read plane), and `gateway-control.*` (direct control). Because they are
//! *not* upstreams (the manifest guard rejects an upstream named `gateway-*`),
//! they never appear in `/api/v1/servers` or the catalog. This endpoint
//! surfaces them so an operator can see and reason about the gateway's own
//! tool surface the same way they browse upstreams — what tools it exposes,
//! the scope that gates each namespace, and each tool's risk classification.
//!
//! Read-only and static (the descriptors are fixed at boot); `mcp:read`-gated.

use std::sync::Arc;

use axum::extract::State;
use axum::middleware;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use utoipa::ToSchema;

use waygate_core::RiskTier;

use crate::error::{ApiErrorBody, ApiResult};
use crate::scope::require_read;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/gateway/builtins", get(list_builtins))
        .layer(middleware::from_fn(require_read))
        .with_state(state)
}

/// One gateway-local built-in namespace and its tools.
#[derive(Debug, Serialize, ToSchema)]
pub struct BuiltinSurfaceView {
    /// Reserved namespace prefix, e.g. `gateway-observe`.
    pub namespace: String,
    /// The scope that gates this namespace (the enforced floor), e.g.
    /// `mcp:observe`.
    pub required_scope: String,
    /// One-line summary of what the namespace is for.
    pub summary: String,
    pub tools: Vec<BuiltinToolView>,
}

/// One built-in tool within a [`BuiltinSurfaceView`].
#[derive(Debug, Serialize, ToSchema)]
pub struct BuiltinToolView {
    /// Bare tool name (no namespace prefix), e.g. `query_audit`.
    pub name: String,
    pub description: String,
    pub risk: RiskTier,
    pub side_effects: bool,
    pub pii: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/gateway/builtins",
    tag = "gateway",
    responses(
        (status = 200, description = "The gateway's built-in MCP namespaces (local, not proxied)", body = Vec<BuiltinSurfaceView>),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:read", body = ApiErrorBody),
    ),
)]
async fn list_builtins(
    State(state): State<Arc<AdminState>>,
) -> ApiResult<Json<Vec<BuiltinSurfaceView>>> {
    let views = state
        .servers
        .builtin_surfaces
        .iter()
        .map(|s| BuiltinSurfaceView {
            namespace: s.namespace.clone(),
            required_scope: s.required_scope.clone(),
            summary: s.summary.clone(),
            tools: s
                .tools
                .iter()
                .map(|t| BuiltinToolView {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    risk: t.risk,
                    side_effects: t.side_effects,
                    pii: t.pii,
                })
                .collect(),
        })
        .collect();
    Ok(Json(views))
}
