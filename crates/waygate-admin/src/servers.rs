//! `/api/v1/servers` — configured upstream MCP server inspection and targeted
//! operational recovery.
//!
//! Admins use this to confirm the gateway picked up a manifest edit or to
//! browse the cached, published tool catalog without walking the upstream
//! directly. Manifest authoring remains on the versioned manifest-bundle
//! surface; this module only owns connection recovery, forced catalog refresh,
//! and drift-quarantine clearing.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_core::fmt::format_ts_rfc3339;
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_oidc::Principal;
use waygate_upstream::{CatalogRefreshReport, ToolClassification, Transport, UpstreamManifest};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::{require_admin, require_read};
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/servers", get(list_servers))
        .route("/api/v1/servers/{name}", get(get_server))
        .route("/api/v1/servers/{name}/tools", get(list_tools))
        .route("/api/v1/servers/{name}/quarantine", get(get_quarantine))
        .layer(middleware::from_fn(require_read))
        .with_state(state)
}

/// Admin-gated mutating endpoints for upstream lifecycle. Kept on its own
/// router so the read-only `router()` above can stay layered with `mcp:read`
/// while these require `mcp:admin`.
pub fn admin_router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/api/v1/servers/{name}/reconnect", post(reconnect_server))
        .route(
            "/api/v1/servers/{name}/catalog/refresh",
            post(refresh_server_catalog),
        )
        .route(
            "/api/v1/servers/{name}/quarantine/clear",
            post(clear_quarantine),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServerSummary {
    pub name: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Manifest-classified tool count, whether or not the upstream currently
    /// advertises every classification.
    pub tool_count: usize,
    /// `connected` | `degraded` | `disconnected`. This is runtime
    /// availability, not the durable catalog lifecycle.
    pub runtime_status: String,
    /// RFC 3339 time of the most recent successful connection/catalog probe.
    pub last_success_at: Option<String>,
    /// Bounded/redacted recovery classification; never a raw transport error.
    pub last_error_class: Option<String>,
    /// RFC 3339 time of the next scheduled reprobe when recovery is needed.
    pub next_retry_at: Option<String>,
    /// Compatibility transport signal. True when at least one lane is
    /// connected; use `runtime_status` to distinguish partial capacity and an
    /// unhealthy breaker.
    pub connected: bool,
    /// `closed` | `open` | `half_open`.
    pub breaker: String,
    pub connected_lanes: usize,
    pub total_lanes: usize,
    pub published_tool_count: usize,
    pub quarantined_tool_count: usize,
    /// Tools published WITHOUT the output schema this upstream advertised,
    /// because that schema's root was not `type: "object"` and so could not
    /// describe a `structuredContent` object. The tools remain callable;
    /// a non-zero count means the upstream is emitting definitions a strict
    /// MCP client would reject the entire catalog over.
    pub rejected_output_schema_count: usize,
    /// Distinct MCP protocol generations negotiated by this upstream's
    /// connected lanes (sorted; usually one, two mid-migration, empty when
    /// every lane is down).
    pub protocol_versions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServerDetail {
    pub name: String,
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub classifications: Vec<ToolClassification>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ToolListResponse {
    pub server: String,
    pub tools: Vec<ToolView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ToolView {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub risk: String,
    pub side_effects: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/servers",
    tag = "servers",
    responses(
        (status = 200, description = "Configured upstreams", body = Vec<ServerSummary>),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:read", body = ApiErrorBody),
    ),
)]
async fn list_servers(State(state): State<Arc<AdminState>>) -> ApiResult<Json<Vec<ServerSummary>>> {
    let summaries = state
        .upstreams
        .status_snapshot()
        .await
        .into_iter()
        .map(|status| ServerSummary {
            name: status.health.name,
            transport: transport_str(&status.manifest.transport).to_owned(),
            url: status.manifest.url,
            tool_count: status.manifest.tools.len(),
            runtime_status: status.health.runtime_state.as_str().to_owned(),
            last_success_at: status.health.last_success_at.map(format_ts_rfc3339),
            last_error_class: status
                .health
                .last_error_class
                .map(|class| class.as_str().to_owned()),
            next_retry_at: status.health.next_retry_at.map(format_ts_rfc3339),
            connected: status.health.connected,
            breaker: status.health.breaker.as_str().to_owned(),
            connected_lanes: status.health.connected_lanes,
            total_lanes: status.health.total_lanes,
            published_tool_count: status.health.published_tool_count,
            quarantined_tool_count: status.health.quarantined_tool_count,
            rejected_output_schema_count: status.health.rejected_output_schema_count,
            protocol_versions: status.health.protocol_versions,
        })
        .collect();
    Ok(Json(summaries))
}

#[utoipa::path(
    get,
    path = "/api/v1/servers/{name}",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Upstream detail", body = ServerDetail),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:read", body = ApiErrorBody),
    ),
)]
async fn get_server(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<ServerDetail>> {
    let manifest = find_manifest(&state, &name)?;
    Ok(Json(ServerDetail {
        name: manifest.name,
        transport: transport_str(&manifest.transport).to_owned(),
        url: manifest.url,
        classifications: manifest.tools,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/servers/{name}/tools",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Cached, classified tool inventory currently published by the gateway", body = ToolListResponse),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 500, description = "Upstream list_tools failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:read", body = ApiErrorBody),
    ),
)]
async fn list_tools(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<ToolListResponse>> {
    // 404 early if we don't know the server, instead of returning an empty
    // list that looks like a healthy upstream with no tools.
    let _ = find_manifest(&state, &name)?;

    let tools = state
        .upstreams
        .list_tools(&name)
        .await
        .map_err(|e| ApiError::Internal(format!("upstream list_tools: {e}")))?;

    let views = tools
        .into_iter()
        .map(|t| {
            let facts = state.upstreams.tool_facts(&name, &t.name);
            ToolView {
                name: t.name.to_string(),
                description: t.description.as_ref().map(|d| d.to_string()),
                risk: match facts.risk {
                    waygate_mcp::protocol::RiskTier::Low => "low",
                    waygate_mcp::protocol::RiskTier::Medium => "medium",
                    waygate_mcp::protocol::RiskTier::High => "high",
                }
                .to_owned(),
                side_effects: facts.side_effects,
            }
        })
        .collect();
    Ok(Json(ToolListResponse {
        server: name,
        tools: views,
    }))
}

/// Captured params for upstream reconnect on the direct or governed surface.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ReconnectServerParams {
    /// Upstream manifest name. Healthy sessions are left untouched.
    #[schemars(length(min = 1))]
    pub server: String,
    /// Also clear any in-process tool-drift quarantine after reconnection.
    #[serde(default)]
    pub clear_quarantine: bool,
}

#[derive(Debug, Serialize, JsonSchema, ToSchema)]
pub struct ReconnectResponse {
    /// Upstream server targeted for recovery.
    pub server: String,
    /// `true` when the upstream is connected after the recovery attempt.
    pub connected: bool,
    /// Count of drift-quarantined tools cleared; absent unless requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleared_tools: Option<usize>,
}

/// Captured params for a forced upstream catalog refresh.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RefreshServerCatalogParams {
    /// Upstream manifest name whose live MCP session should be replaced.
    #[schemars(length(min = 1))]
    pub server: String,
}

#[derive(Debug, Serialize, JsonSchema, ToSchema)]
pub struct RefreshCatalogResponse {
    /// Upstream server whose session and catalog were refreshed.
    pub server: String,
    /// `updated` | `unchanged` | `failed` | `superseded` | `removed`.
    pub outcome: String,
    pub session_replaced: bool,
    pub before_tool_count: usize,
    pub after_tool_count: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Existing tool names whose advertised descriptor, schema, or annotations changed.
    pub schema_changed: Vec<String>,
}

/// Captured params for clearing an upstream's in-process drift quarantine.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ClearUpstreamQuarantineParams {
    /// Upstream manifest name whose quarantined tools should resume dispatch.
    #[schemars(length(min = 1))]
    pub server: String,
}

impl From<CatalogRefreshReport> for RefreshCatalogResponse {
    fn from(report: CatalogRefreshReport) -> Self {
        Self {
            server: report.server,
            outcome: report.outcome.as_str().to_owned(),
            session_replaced: report.session_replaced,
            before_tool_count: report.before_tool_count,
            after_tool_count: report.after_tool_count,
            added: report.added,
            removed: report.removed,
            schema_changed: report.schema_changed,
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/servers/{name}/reconnect",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Reconnect succeeded; upstream is live", body = ReconnectResponse),
        (status = 502, description = "Reconnect attempted but the upstream did not come up", body = ApiErrorBody),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn reconnect_server(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<ReconnectResponse>> {
    reconnect_server_core(
        &state,
        &ReconnectServerParams {
            server: name,
            clear_quarantine: false,
        },
    )
    .await
    .map(Json)
}

#[utoipa::path(
    post,
    path = "/api/v1/servers/{name}/catalog/refresh",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Fresh MCP session attempted and catalog refresh outcome returned", body = RefreshCatalogResponse),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn refresh_server_catalog(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(name): Path<String>,
) -> ApiResult<Json<RefreshCatalogResponse>> {
    refresh_server_catalog_core(&state, &actor, &RefreshServerCatalogParams { server: name })
        .await
        .map(Json)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineView {
    pub server: String,
    /// Tools currently auto-quarantined by the drift detector. Cleared on
    /// gateway restart, or explicitly via
    /// `POST /api/v1/servers/{name}/quarantine/clear`.
    pub tools: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema, ToSchema)]
pub struct ClearQuarantineResponse {
    /// Upstream server whose drift quarantine was cleared.
    pub server: String,
    /// Number of tools that were quarantined before the clear (zero if
    /// the upstream had no quarantined tools, which is the steady-state).
    pub cleared: usize,
}

#[utoipa::path(
    get,
    path = "/api/v1/servers/{name}/quarantine",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Currently-quarantined tools on this upstream", body = QuarantineView),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:read", body = ApiErrorBody),
    ),
)]
async fn get_quarantine(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<QuarantineView>> {
    let tools = state
        .upstreams
        .quarantined_tools(&name)
        .await
        .ok_or(ApiError::NotFound("server"))?;
    Ok(Json(QuarantineView {
        server: name,
        tools,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/servers/{name}/quarantine/clear",
    tag = "servers",
    params(("name" = String, Path, description = "Upstream manifest name")),
    responses(
        (status = 200, description = "Quarantine cleared; calls resume on next dispatch", body = ClearQuarantineResponse),
        (status = 404, description = "No such upstream", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn clear_quarantine(
    State(state): State<Arc<AdminState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<ClearQuarantineResponse>> {
    let response = clear_upstream_quarantine_core(
        &state,
        &ClearUpstreamQuarantineParams {
            server: name.clone(),
        },
    )
    .await?;
    // Emit an operator-readable recovery event without exposing tool inputs.
    tracing::info!(
        server = %name,
        cleared = response.cleared,
        "operator cleared upstream tool quarantine via admin API",
    );
    Ok(Json(response))
}

/// Shared reconnect operation used by REST, direct MCP control, and the
/// governed change executor. All validation happens before the optional
/// quarantine clear; a failed re-dial never restores quarantined tools.
pub async fn reconnect_server_core(
    state: &Arc<AdminState>,
    params: &ReconnectServerParams,
) -> ApiResult<ReconnectResponse> {
    validate_server_name(&params.server)?;
    let _ = find_manifest(state, &params.server)?;
    let connected = state.upstreams.reconnect_one(&params.server).await;
    if !connected {
        return Err(ApiError::BadGateway(format!(
            "upstream `{}` is still disconnected after re-dial; check gateway logs",
            params.server
        )));
    }
    let cleared_tools = if params.clear_quarantine {
        Some(
            state
                .upstreams
                .clear_quarantine(&params.server)
                .await
                .ok_or(ApiError::NotFound("server"))?,
        )
    } else {
        None
    };
    Ok(ReconnectResponse {
        server: params.server.clone(),
        connected,
        cleared_tools,
    })
}

/// Shared forced-refresh operation. The pool keeps the old session and
/// inventory if every replacement dial fails.
pub async fn refresh_server_catalog_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    params: &RefreshServerCatalogParams,
) -> ApiResult<RefreshCatalogResponse> {
    validate_server_name(&params.server)?;
    let _ = find_manifest(state, &params.server)?;
    let report = state
        .upstreams
        .refresh_server_catalog(&params.server, actor)
        .await
        .ok_or(ApiError::NotFound("server"))?;
    Ok(RefreshCatalogResponse::from(report))
}

/// Shared in-process drift-quarantine recovery operation.
pub async fn clear_upstream_quarantine_core(
    state: &Arc<AdminState>,
    params: &ClearUpstreamQuarantineParams,
) -> ApiResult<ClearQuarantineResponse> {
    validate_server_name(&params.server)?;
    let _ = find_manifest(state, &params.server)?;
    let cleared = state
        .upstreams
        .clear_quarantine(&params.server)
        .await
        .ok_or(ApiError::NotFound("server"))?;
    Ok(ClearQuarantineResponse {
        server: params.server.clone(),
        cleared,
    })
}

fn find_manifest(state: &AdminState, name: &str) -> ApiResult<UpstreamManifest> {
    state
        .upstreams
        .manifests()
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| ApiError::NotFoundDyn(format!("upstream server `{name}`")))
}

fn validate_server_name(name: &str) -> ApiResult<()> {
    if name.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "server must be a non-empty upstream manifest name".to_owned(),
        ));
    }
    Ok(())
}

fn transport_str(t: &Transport) -> &'static str {
    match t {
        Transport::Http => "http",
        Transport::Sse => "sse",
        Transport::Stdio => "stdio",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn disconnected_state() -> Arc<AdminState> {
        let manifest = UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            name: "fetchlayer".to_owned(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some("http://127.0.0.1:9/mcp".to_owned()),
            command: None,
            tools: Vec::new(),
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        };
        let pool = Arc::new(waygate_upstream::UpstreamPool::from_manifests_disconnected(
            BTreeMap::from([(manifest.name.clone(), manifest)]),
        ));
        Arc::new(AdminState::new(
            pool,
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".to_owned(),
        ))
    }

    #[tokio::test]
    async fn reconnect_failure_is_loud_and_does_not_report_quarantine_clear() {
        let error = reconnect_server_core(
            &disconnected_state(),
            &ReconnectServerParams {
                server: "fetchlayer".to_owned(),
                clear_quarantine: true,
            },
        )
        .await
        .expect_err("unreachable upstream must not produce a success result");
        assert!(matches!(error, ApiError::BadGateway(_)));
    }

    #[tokio::test]
    async fn operational_cores_reject_empty_server_before_pool_access() {
        let state = disconnected_state();
        let error = clear_upstream_quarantine_core(
            &state,
            &ClearUpstreamQuarantineParams {
                server: "  ".to_owned(),
            },
        )
        .await
        .expect_err("blank server name must be invalid input");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn quarantine_clear_distinguishes_known_and_unknown_upstreams() {
        let state = disconnected_state();
        let response = clear_upstream_quarantine_core(
            &state,
            &ClearUpstreamQuarantineParams {
                server: "fetchlayer".to_owned(),
            },
        )
        .await
        .expect("known upstream has an empty steady-state quarantine");
        assert_eq!(response.server, "fetchlayer");
        assert_eq!(response.cleared, 0);

        let error = clear_upstream_quarantine_core(
            &state,
            &ClearUpstreamQuarantineParams {
                server: "missing".to_owned(),
            },
        )
        .await
        .expect_err("unknown upstream must fail before pool mutation");
        assert!(matches!(error, ApiError::NotFoundDyn(_)));
    }
}
