//! Read-only upstream compatibility evidence for configuration administrators.

use std::{sync::Arc, time::Duration};

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use waygate_core::fmt::format_ts_rfc3339;
use waygate_oidc::Principal;
use waygate_upstream::{UpstreamStatus, UpstreamStatusObservation};

use crate::{
    error::{ApiError, ApiErrorBody, ApiResult},
    state::AdminState,
    tenant_ctx::TenantContext,
};

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamCompatibilityReport {
    pub server: String,
    pub observed_at: String,
    /// Current, stale, mixed, unavailable, or temporarily busy evidence.
    pub evidence_status: String,
    pub configured_transport: Option<String>,
    pub configured_protocol: Option<String>,
    pub runtime_status: Option<String>,
    /// Availability evidence only; never used as a conformance result.
    pub last_success_at: Option<String>,
    pub lanes: Vec<LaneCompatibilityView>,
    pub lanes_truncated: bool,
    pub resource_prefixes_configured: Option<bool>,
    pub gateway_long_running_tools_configured: Option<bool>,
    pub output_schema_refusal_count: Option<usize>,
    pub explanations: Vec<CompatibilityExplanation>,
    /// No operational conformance tests are run or inferred by this report.
    pub explicitly_tested_behavior: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LaneCompatibilityView {
    pub lane: usize,
    pub current: bool,
    pub connection_observed_at: String,
    pub catalog_age_seconds: u64,
    pub protocol_version: Option<String>,
    pub implementation_name: Option<String>,
    pub implementation_version: Option<String>,
    pub tools_advertised: Option<bool>,
    pub resources_advertised: Option<bool>,
    pub tasks_advertised: Option<bool>,
    pub skills_advertised: Option<bool>,
    pub input_schema_warning_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompatibilityExplanation {
    pub capability: String,
    pub explanation: String,
}

pub(crate) fn authorize(
    actor: Option<&Principal>,
    tenant: Option<&TenantContext>,
) -> Result<(), ApiError> {
    crate::dashboard_settings::require_global_settings_admin(actor, tenant)
}

pub(crate) async fn report(
    state: &AdminState,
    server: &str,
) -> ApiResult<UpstreamCompatibilityReport> {
    if server.len() > 512 {
        return Err(ApiError::BadRequest("Server name is too long".into()));
    }
    let observation = state
        .upstreams
        .server_status_within(server, Duration::from_millis(250))
        .await
        .ok_or(ApiError::NotFound("Upstream not configured"))?;
    Ok(from_observation(observation))
}

fn from_observation(observation: UpstreamStatusObservation) -> UpstreamCompatibilityReport {
    let (server, status) = match observation {
        UpstreamStatusObservation::Observed(status) => (status.health.name.clone(), Some(status)),
        UpstreamStatusObservation::Busy { name } => (name, None),
    };
    let mut result = UpstreamCompatibilityReport {
        server,
        observed_at: format_ts_rfc3339(time::OffsetDateTime::now_utc()),
        evidence_status: if status.is_some() {
            "unavailable"
        } else {
            "busy"
        }
        .into(),
        configured_transport: None,
        configured_protocol: None,
        runtime_status: None,
        last_success_at: None,
        lanes: Vec::new(),
        lanes_truncated: false,
        resource_prefixes_configured: None,
        gateway_long_running_tools_configured: None,
        output_schema_refusal_count: None,
        explanations: Vec::new(),
        explicitly_tested_behavior: "not_recorded".into(),
    };
    if let Some(status) = status {
        fill_observed(&mut result, *status);
    }
    for (capability, explanation) in [
        ("Evidence", "Peer names, versions and capabilities are self-reported declarations. A successful tools/list is catalog evidence, not conformance. Connection timestamps and catalog age describe different observations. Old declarations are not revalidated by reading this report. Known-closed connections and open breakers mark retained declarations stale; eviction makes them unavailable. Last success is availability history only."),
        ("Tasks", "An advertised tasks extension does not prove task delivery. Native task access requires current bindings and caller capabilities. Gateway-run tasks additionally require configured long_running_tools. Subscription completion delivery remains limited by released SDK support."),
        ("Elicitation", "Elicitation is a caller capability, not a server declaration. The gateway mirrors permitted request input capabilities on compatible modern dials; legacy or undeclared input flows are refused. This report does not exercise an elicitation."),
        ("Files", "Draft file authorization support cannot be established from the SDK's retained server declarations. File operations still require governed authorization and matching caller capabilities. Actual transfer compatibility is unknown here."),
        ("Resources", "An upstream resource declaration and configured URI-prefix ownership are separate evidence. Without configured ownership, native resource reads and listings do not reach this upstream. No resource read is performed by this report."),
        ("Schemas", "Input-schema warnings identify live tools that strict tool-calling clients may reject. Output-schema refusals describe omitted invalid output contracts. Client projection is opt-in and never replaces authoritative invocation validation; neither count proves a particular client accepts the catalog."),
        ("Skills and Apps", "A Skills declaration is an upstream claim; Waygate's governed Skills catalog has its own distribution contract. This report does not enable upstream Skills relay or MCP Apps negotiation."),
    ] {
        result.explanations.push(CompatibilityExplanation { capability: capability.into(), explanation: explanation.into() });
    }
    result
}

fn fill_observed(report: &mut UpstreamCompatibilityReport, status: UpstreamStatus) {
    use waygate_upstream::Transport;
    report.configured_transport = Some(
        match status.manifest.transport {
            Transport::Http => "http",
            Transport::Sse => "sse",
            Transport::Stdio => "stdio",
        }
        .into(),
    );
    report.configured_protocol = Some(status.manifest.protocol.as_str().into());
    report.runtime_status = Some(status.health.runtime_state.as_str().into());
    report.last_success_at = status.health.last_success_at.map(format_ts_rfc3339);
    report.resource_prefixes_configured = Some(!status.manifest.resources.is_empty());
    report.gateway_long_running_tools_configured =
        Some(!status.manifest.long_running_tools.is_empty());
    report.output_schema_refusal_count = Some(status.health.rejected_output_schema_count);
    let current = status
        .compatibility
        .iter()
        .filter(|lane| lane.current)
        .count();
    report.evidence_status = match (status.compatibility.len(), current) {
        (0, _) => "unavailable",
        (_, 0) => "stale_connection",
        (total, current) if total == current => "current_connection",
        _ => "mixed_connections",
    }
    .into();
    report.lanes_truncated = status.compatibility.len() > 32;
    report.lanes = status
        .compatibility
        .into_iter()
        .take(32)
        .map(|lane| LaneCompatibilityView {
            lane: lane.lane,
            current: lane.current,
            connection_observed_at: format_ts_rfc3339(lane.connected_at),
            catalog_age_seconds: lane.catalog_age_seconds,
            protocol_version: lane.protocol_version,
            implementation_name: lane.implementation_name,
            implementation_version: lane.implementation_version,
            tools_advertised: lane.tools_advertised,
            resources_advertised: lane.resources_advertised,
            tasks_advertised: lane.tasks_advertised,
            skills_advertised: lane.skills_advertised,
            input_schema_warning_count: lane.input_schema_warning_count,
        })
        .collect();
    if matches!(status.manifest.transport, Transport::Sse) {
        report.explanations.push(CompatibilityExplanation { capability: "Legacy transport".into(), explanation: "This upstream still requires legacy HTTP+SSE. Migrate its dependency to supported Streamable HTTP or a qualified external adapter before removing gateway SSE support. SSE framing inside Streamable HTTP and inference streams is separate.".into() });
    }
}

#[utoipa::path(
    get, path = "/api/v1/servers/{name}/compatibility", tag = "servers",
    params(("name" = String, Path, description = "Configured upstream name")),
    responses(
        (status = 200, description = "Read-only compatibility evidence; no conformance probes", body = UpstreamCompatibilityReport),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "Requires the upstream configuration tenant administrator", body = ApiErrorBody),
        (status = 404, description = "No such upstream", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_report(
    State(state): State<Arc<AdminState>>,
    actor: Option<Extension<Principal>>,
    Path(server): Path<String>,
) -> ApiResult<Json<UpstreamCompatibilityReport>> {
    authorize(actor.as_ref().map(|Extension(p)| p), None)?;
    report(&state, &server).await.map(Json)
}

#[derive(Deserialize)]
pub(crate) struct ReportQuery {
    server: String,
}

#[derive(Template)]
#[template(path = "upstream_compatibility.html")]
struct CompatibilityFragment {
    report: UpstreamCompatibilityReport,
}

pub(crate) async fn report_fragment(
    State(state): State<Arc<AdminState>>,
    actor: Option<Extension<Principal>>,
    tenant: Option<Extension<TenantContext>>,
    Query(query): Query<ReportQuery>,
) -> Response {
    if let Err(error) = authorize(
        actor.as_ref().map(|Extension(p)| p),
        tenant.as_ref().map(|Extension(t)| t),
    ) {
        return error.into_response();
    }
    match report(&state, &query.server).await {
        Ok(report) => crate::dashboard::render(&CompatibilityFragment { report }),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn report_distinguishes_current_stale_mixed_and_unavailable_declarations() {
        let manifest: waygate_upstream::UpstreamManifest = serde_json::from_value(
            serde_json::json!({"name":"fixture","transport":"http","url":"http://127.0.0.1:9/mcp","trust":"internal"}),
        )
        .unwrap();
        let pool = waygate_upstream::UpstreamPool::from_manifests_disconnected(
            std::collections::BTreeMap::from([("fixture".into(), manifest)]),
        );
        let mut status = pool.status_snapshot().await.remove(0);
        let convert =
            |status| from_observation(UpstreamStatusObservation::Observed(Box::new(status)));
        assert_eq!(convert(status.clone()).evidence_status, "unavailable");
        let lane = waygate_upstream::pool::health::LaneCompatibility {
            lane: 0,
            current: false,
            connected_at: time::OffsetDateTime::UNIX_EPOCH,
            catalog_age_seconds: 100,
            protocol_version: Some("2026-07-28".into()),
            implementation_name: None,
            implementation_version: None,
            tools_advertised: Some(true),
            resources_advertised: None,
            tasks_advertised: None,
            skills_advertised: None,
            input_schema_warning_count: 0,
        };
        status.compatibility.push(lane.clone());
        let stale = convert(status.clone());
        assert_eq!(stale.evidence_status, "stale_connection");
        assert!(!stale.lanes[0].current);
        assert_eq!(
            stale.lanes[0].connection_observed_at,
            "1970-01-01T00:00:00Z"
        );
        status.compatibility[0].current = true;
        assert_eq!(
            convert(status.clone()).evidence_status,
            "current_connection"
        );
        status.compatibility.push(lane);
        assert_eq!(convert(status).evidence_status, "mixed_connections");
    }
}
