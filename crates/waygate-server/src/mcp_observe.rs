//! Built-in `gateway-observe` MCP namespace — the read-only analysis plane.
//!
//! A monitoring agent holding `mcp:observe` (or `mcp:admin`) can interrogate
//! the gateway's own durable signals over MCP without any mutate authority:
//!
//! - `query_audit` — filtered audit-log rows (who called what, when, allowed or
//!   denied, which policies fired).
//! - `activity_summary` — pre-aggregated rollups over a window (counts by
//!   outcome / risk / category / server, plus the top tools by volume).
//! - `simulate_authorization` — "would this principal be allowed to call
//!   `server.tool`?" run through the live Cedar engine.
//! - `triage_digest` — one-call health digest composing the durable signals
//!   (denials/errors, catalog lifecycle, runtime upstream availability, drift,
//!   active break-glass) into a severity-ranked findings list for pull-based
//!   alerting.
//!
//! ## Why this lives in `waygate-server`, not `waygate-admin`
//!
//! Like [`crate::mcp_builtin`], the logic is the same store/engine the REST
//! surface uses — `AuditReader::query_events` / `rollup_*`
//! ([`waygate_storage::audit`]) and the `policies::simulate_*` converters
//! ([`waygate_admin::policies`]) — but producing the rmcp `CallToolResult` /
//! `Tool` wire types is MCP-wire work, and `waygate-admin` keeps `rmcp` a
//! dev-only dependency. So the rmcp-typed adapter lives here, sharing the same
//! deferred `AdminState` cell the change-proposal tools already use.
//!
//! ## Authorization
//!
//! Every tool requires a non-peer principal holding `mcp:observe` OR `mcp:admin`
//! (operators can read). A federated Tier-C peer is excluded even with the
//! scope — it carries its own operator on the far side, mirroring
//! [`crate::mcp_builtin`]'s maker exclusion. `list_tools` hides the tools from
//! non-holders (UX); `call` re-checks (the boundary). Every query is
//! tenant-scoped from the principal, never from arguments, and returns metadata
//! only — no tokens, ciphertext, or PEM. The diagnostic fields a read caller
//! sees (policy IDs, deny reasons) are already in the `audit_log` rows
//! `query_audit` returns, so `simulate_authorization` exposes nothing the read
//! plane doesn't already surface. The REST `/policies/simulate` endpoint was
//! moved to the same `mcp:observe` scope (design decision) so the two
//! simulators sit at one read-grade tier; both stamp the caller's tenant on the
//! hypothetical principal (`simulate_inputs_for`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ErrorCode, JsonObject, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use serde::Serialize;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use waygate_admin::policies::{
    authz_result_to_response, required_scope_for_simulation, simulate_request_to_inputs,
    SimulateRequest, SimulateResponse,
};
use waygate_admin::resource_catalog::{read, resource_catalog as resource_entries, ReadError};
use waygate_admin::AdminState;
use waygate_authz::{Action as AuthzAction, AuthzEngine, BreakGlassLifecycle, ResourceSpec};
use waygate_catalog::{CatalogServerStatus, CatalogServerSummary};
use waygate_core::RiskTier;
use waygate_mcp::authz::{BuiltinAuthz, SharedAuthz, ToolFacts};
use waygate_mcp::{
    AssistReadTool, AssistReadTools, BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinTools,
    CatalogTool, SharedBuiltinTools,
};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_storage::audit::{AuditQuery, AuditRow};
use waygate_upstream::{UpstreamHealth, UpstreamRuntimeState};

use crate::mcp_builtin::{parse_opt_u32, schema_obj, structured};
use waygate_core::fmt::format_ts_rfc3339;

/// The reserved namespace this handler answers, aliased to the cross-crate
/// source of truth so dispatch and the load-time guard agree.
pub const NAMESPACE: &str = waygate_core::OBSERVE_BUILTIN_NAMESPACE;

/// Built-in read-only MCP tools backing the `gateway-observe.*` analysis plane.
/// Holds only the deferred `AdminState` cell (set once at boot, before any
/// connection can invoke a tool) — every reader/engine it needs hangs off
/// `AdminState`, so there are no other construction deps.
pub struct ObserveTools {
    admin_state: Arc<OnceLock<Arc<AdminState>>>,
}

impl ObserveTools {
    pub fn new(admin_state: Arc<OnceLock<Arc<AdminState>>>) -> Self {
        Self { admin_state }
    }

    /// Resolve the deferred `AdminState`. `None` only in the unreachable
    /// pre-boot window (the cell is filled before the server accepts
    /// connections); surfaced as a clean internal error rather than a panic.
    fn state(&self) -> Result<&Arc<AdminState>, McpError> {
        self.admin_state
            .get()
            .ok_or_else(|| McpError::internal_error("observe plane not yet initialised", None))
    }
}

/// An observer is a non-peer principal holding `mcp:observe` or `mcp:admin`.
///
/// The peer exclusion mirrors [`crate::mcp_builtin`]'s `is_maker`: a federated
/// Tier-C peer is not an observer of THIS gateway. Read scopes are otherwise
/// peer-safe (`mcp:observe` is deliberately absent from
/// `PEER_FORBIDDEN_SCOPE_PREFIXES`), but the built-in surface is gateway-local
/// administration, so it stays operator/observer-only here.
fn may_observe(p: &Principal) -> bool {
    p.auth_method != AuthMethod::PeerAssertion
        && (p.has_scope(Scope::McpObserve.as_str()) || p.has_scope(Scope::McpAdmin.as_str()))
}

#[async_trait]
impl BuiltinTools for ObserveTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        // UX filter only — `call` re-checks (a client can invoke a name it
        // never saw listed).
        if principal.is_some_and(may_observe) {
            self.catalog().definitions()
        } else {
            Vec::new()
        }
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        // Authorization boundary.
        let principal = match principal {
            Some(p) if may_observe(p) => p,
            _ => return Err(insufficient_scope()),
        };
        let args = arguments.unwrap_or_default();
        match tool {
            "query_audit" => self.query_audit(principal, &args).await,
            "activity_summary" => self.activity_summary(principal, &args).await,
            "simulate_authorization" => self.simulate_authorization(principal, &args).await,
            "triage_digest" => self.triage_digest(principal, &args).await,
            "describe_resource" => self.describe_resource(&args),
            "read_resource" => self.read_resource(principal, &args).await,
            other => Err(McpError::invalid_params(
                format!("unknown {NAMESPACE} tool: {other}"),
                None,
            )),
        }
    }
}

impl ObserveTools {
    async fn query_audit(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state()?;
        let audit = state
            .observability
            .audit
            .get()
            .ok_or_else(|| McpError::internal_error("no audit reader configured", None))?;
        let limit = i64::from(parse_opt_u32(args, "limit")?.unwrap_or(20).min(200));
        let since = resolve_since(args, "since", Duration::hours(24))?;
        let query = AuditQuery {
            tenant_id: Some(principal.tenant.as_str().to_owned()),
            server: opt_string(args, "server")?,
            outcome: opt_string(args, "outcome")?,
            risk_level: opt_string(args, "risk")?,
            category: opt_string(args, "category")?,
            principal_substr: opt_string(args, "principal")?,
            since,
            ..Default::default()
        };
        let rows = audit
            .query_events(&query, limit, None)
            .await
            .map_err(|e| db_error("audit query", e))?;
        let events: Vec<AuditRowView> = rows.iter().map(AuditRowView::from_row).collect();
        Ok(structured(&QueryAuditResponse {
            count: events.len(),
            events,
        }))
    }

    async fn activity_summary(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state()?;
        let audit = state
            .observability
            .audit
            .get()
            .ok_or_else(|| McpError::internal_error("no audit reader configured", None))?;
        let window = opt_string(args, "window")?.unwrap_or_else(|| "7d".to_owned());
        let dur = parse_duration(&window).ok_or_else(|| {
            McpError::invalid_params(
                format!("`window` is not a duration like 24h/7d: {window}"),
                None,
            )
        })?;
        let top = i64::from(parse_opt_u32(args, "top")?.unwrap_or(10).min(50));
        let query = AuditQuery {
            tenant_id: Some(principal.tenant.as_str().to_owned()),
            since: Some(OffsetDateTime::now_utc() - dur),
            ..Default::default()
        };
        // Pre-aggregated rollups (audit_rollup_hourly) — cheap over wide
        // windows. Facets show the full categorical landscape; tool_stats the
        // top tools by volume with error/denial counts.
        let facets = audit
            .rollup_facets(&query)
            .await
            .map_err(|e| db_error("activity facets", e))?;
        let tools = audit
            .rollup_tool_stats(&query, top)
            .await
            .map_err(|e| db_error("activity tool stats", e))?;
        let top_tools: Vec<TopToolStat> = tools
            .iter()
            .map(|t| TopToolStat {
                server: t.server.clone(),
                tool: t.tool.clone(),
                total: t.total,
                errors: t.errors,
                denied: t.denied,
                p95_latency_ms: t.p95_latency_ms,
            })
            .collect();
        Ok(structured(&ActivitySummaryResponse {
            window,
            by_outcome: label_counts(&facets.outcome),
            by_risk: label_counts(&facets.risk),
            by_category: label_counts(&facets.category),
            by_server: label_counts(&facets.server),
            top_tools,
        }))
    }

    async fn simulate_authorization(
        &self,
        caller: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state()?;
        let engine = state
            .policy
            .cedar
            .get()
            .ok_or_else(|| McpError::internal_error("no cedar engine configured", None))?;
        let req: SimulateRequest =
            serde_json::from_value(Value::Object(args.clone())).map_err(|e| {
                McpError::invalid_params(format!("simulate_authorization args: {e}"), None)
            })?;
        // Reuse the exact REST converters + the fail-closed trait impl so the
        // MCP and REST simulators can't drift; `simulate_inputs_for` tenant-
        // scopes the hypothetical principal to the caller.
        let (principal, action, resource) = simulate_inputs_for(caller, req);
        // Surface the structured trace + step-up scope through the MCP
        // simulate tool too, so it can't drift from the REST/dashboard
        // simulators. Pin ONE snapshot for both the decision and the trace
        // metadata so a SIGHUP reload between `evaluate` and `list_policies`
        // can't join the fired policy_ids to a different policy set.
        let snap = engine.snapshot_for_tenant(caller.tenant.as_str());
        let result = AuthzEngine::evaluate(snap.as_ref(), &principal, &action, &resource);
        let required_scope = required_scope_for_simulation(&action, &resource);
        Ok(structured(&authz_result_to_response(
            result,
            &snap.list_policies(),
            required_scope,
        )))
    }

    async fn triage_digest(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state()?;
        let tenant = principal.tenant.as_str();
        let window = opt_string(args, "window")?.unwrap_or_else(|| "24h".to_owned());
        let dur = parse_duration(&window).ok_or_else(|| {
            McpError::invalid_params(
                format!("`window` is not a duration like 24h/7d: {window}"),
                None,
            )
        })?;
        let since = OffsetDateTime::now_utc() - dur;
        let mut findings: Vec<TriageFinding> = Vec::new();

        // 1. Authz health — denials / execution errors over the window, from the
        // pre-aggregated rollup. Best-effort: a store error is logged and the
        // section is omitted so the rest of the digest stays useful.
        if let Some(audit) = state.observability.audit.get() {
            let query = AuditQuery {
                tenant_id: Some(tenant.to_owned()),
                since: Some(since),
                ..Default::default()
            };
            match audit.rollup_facets(&query).await {
                Ok(facets) => {
                    let count = |name: &str| {
                        facets
                            .outcome
                            .iter()
                            .find(|(o, _)| o == name)
                            .map(|(_, c)| *c)
                            .unwrap_or(0)
                    };
                    let denied = count("denied");
                    let errors = count("execution_error");
                    let total: i64 = facets.outcome.iter().map(|(_, c)| *c).sum();
                    findings.push(TriageFinding {
                        area: "authz",
                        severity: if denied > 0 || errors > 0 {
                            "warning"
                        } else {
                            "info"
                        },
                        summary: format!(
                            "{total} events in {window}: {denied} denied, {errors} execution errors"
                        ),
                        detail: json!({
                            "total": total,
                            "denied": denied,
                            "execution_errors": errors,
                            "by_outcome": facets.outcome,
                        }),
                    });
                }
                Err(e) => tracing::warn!(error = %e, "triage authz rollup failed"),
            }
        }

        // 2. Catalog health — configured quarantined servers (out of dispatch)
        // and recent tool behavior drift.
        if let Some(catalog) = state.servers.catalog.get() {
            match catalog.list_servers(tenant).await {
                Ok(servers) => {
                    let runtime = state.upstreams.health_snapshot().await;
                    if let Some(finding) = runtime_health_finding(&servers, &runtime) {
                        findings.push(finding);
                    }
                    if let Some(finding) = catalog_quarantine_finding(&servers, &runtime) {
                        findings.push(finding);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "triage catalog list_servers failed"),
            }
            match catalog.list_drift_events(tenant, since, 100).await {
                Ok(drift) if !drift.is_empty() => findings.push(TriageFinding {
                    area: "catalog",
                    severity: "warning",
                    summary: format!("{} tool behavior drift event(s) in {window}", drift.len()),
                    detail: json!({ "count": drift.len() }),
                }),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "triage catalog list_drift_events failed"),
            }
        }

        // 3. Break-glass — overrides in effect right now (an active token means a
        // principal is bypassing the policy gate).
        if let Some(bg) = state.policy.break_glass.get() {
            match bg
                .list(tenant, Some(BreakGlassLifecycle::Active), 100, 0)
                .await
            {
                Ok(active) if !active.is_empty() => {
                    let tokens: Vec<Value> = active
                        .iter()
                        .map(|t| {
                            json!({
                                "issued_to": t.issued_to,
                                "reason": t.reason,
                                "expires_at": format_ts_rfc3339(t.expires_at),
                            })
                        })
                        .collect();
                    findings.push(TriageFinding {
                        area: "break_glass",
                        severity: "warning",
                        summary: format!(
                            "{} active break-glass override(s) in effect",
                            active.len()
                        ),
                        detail: json!({ "active": tokens }),
                    });
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "triage break_glass list failed"),
            }
        }

        // Severity-rank the findings (most severe first) so the list is
        // actually ordered by urgency, not by which section produced it. Stable
        // sort, so ties keep their source order.
        findings.sort_by_key(|f| severity_rank(f.severity));
        let ok = !findings
            .iter()
            .any(|f| matches!(f.severity, "warning" | "critical"));
        Ok(structured(&TriageDigestResponse {
            ok,
            window,
            finding_count: findings.len(),
            findings,
        }))
    }

    /// `describe_resource` — the read-side twin of `describe_action`. Returns
    /// the catalog of resource types `read_resource` can list, each with the
    /// JSON Schema of its `filters` and of one row. Schemas only, so no
    /// `AdminState` access is needed.
    fn describe_resource(&self, args: &JsonObject) -> Result<CallToolResult, McpError> {
        let catalog = resource_entries();
        let resources: Vec<ResourceEntryView> =
            match args.get("resource_type").and_then(|v| v.as_str()) {
                None => catalog
                    .into_iter()
                    .map(ResourceEntryView::from_entry)
                    .collect(),
                Some(rt) => match catalog.into_iter().find(|e| e.resource_type == rt) {
                    Some(e) => vec![ResourceEntryView::from_entry(e)],
                    None => return Err(unknown_resource(rt)),
                },
            };
        Ok(structured(&DescribeResourceResponse { resources }))
    }

    /// `read_resource` — list rows of one control-plane resource, tenant-scoped
    /// to the caller. Enforces the resource's access tier (the namespace's
    /// `mcp:observe` gate is only the floor; sensitive resources require
    /// `mcp:admin`) BEFORE any store read, then delegates to
    /// [`waygate_admin::resource_catalog::read`].
    async fn read_resource(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let resource_type = match args.get("resource_type").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Err(McpError::invalid_params(
                    format!(
                        "missing required string `resource_type`; readable resources: {}",
                        resource_types_joined()
                    ),
                    None,
                ))
            }
        };
        // Look the resource up in the catalog: this validates the type (teach on
        // unknown) and yields its access tier to enforce.
        let entry = resource_entries()
            .into_iter()
            .find(|e| e.resource_type == resource_type)
            .ok_or_else(|| unknown_resource(&resource_type))?;
        // Per-resource scope split: a sensitive resource requires mcp:admin
        // even though the namespace floor is mcp:observe — the resource
        // catalog's `AccessTier::Admin` entries (e.g. `api_key`,
        // `break_glass_token`) are gated here.
        if entry.min_scope == Scope::McpAdmin.as_str()
            && !principal.has_scope(Scope::McpAdmin.as_str())
        {
            return Err(need_scope(Scope::McpAdmin.as_str(), &resource_type));
        }
        let limit = parse_opt_u32(args, "limit")?.unwrap_or(50);
        let offset = parse_opt_u32(args, "offset")?.unwrap_or(0);
        let filters = match args.get("filters") {
            None | Some(Value::Null) => serde_json::Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => {
                return Err(McpError::invalid_params(
                    "`filters` must be an object (its keys are resource-specific — call \
                     describe_resource)",
                    None,
                ))
            }
        };
        // Resolve state only after authz passes — the resource lookup and the
        // per-resource scope check above need no state, so an observe-only caller
        // gets a clean insufficient_scope rather than the (unreachable in prod)
        // pre-boot "not yet initialised", and the admin gate is unit-testable.
        let state = self.state()?;
        let page = read(
            state,
            &resource_type,
            principal.tenant.as_str(),
            &filters,
            limit,
            offset,
        )
        .await
        .map_err(map_read_err)?;
        Ok(structured(&ReadResourceResponse {
            resource_type,
            count: page.rows.len(),
            rows: page.rows,
            limit: page.limit,
            offset: page.offset,
        }))
    }
}

/// Sort key for [`TriageFinding`] severity — lower sorts first, so a
/// `sort_by_key` yields most-severe-first. Unknown strings rank as `info`.
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "warning" => 1,
        _ => 2,
    }
}

/// One line of the [`triage_digest`](ObserveTools::triage_digest) — a single
/// health signal with a severity (`info` | `warning` | `critical`) the agent
/// can route on.
#[derive(Serialize, schemars::JsonSchema)]
struct TriageFinding {
    #[schemars(with = "String")]
    area: &'static str,
    #[schemars(with = "String")]
    severity: &'static str,
    summary: String,
    detail: Value,
}

/// Report configured servers whose durable lifecycle blocks dispatch. Catalog
/// rows retained after manifest removal remain authoritative deny records, but
/// they are historical rather than an operational condition on this replica.
fn catalog_quarantine_finding(
    servers: &[CatalogServerSummary],
    runtime: &[UpstreamHealth],
) -> Option<TriageFinding> {
    let configured: BTreeSet<&str> = runtime.iter().map(|health| health.name.as_str()).collect();
    let quarantined: Vec<&str> = servers
        .iter()
        .filter(|server| {
            server.status == CatalogServerStatus::Quarantined
                && configured.contains(server.name.as_str())
        })
        .map(|server| server.name.as_str())
        .collect();
    if quarantined.is_empty() {
        return None;
    }
    Some(TriageFinding {
        area: "catalog",
        severity: "warning",
        summary: format!(
            "{} configured upstream server(s) quarantined (out of dispatch)",
            quarantined.len()
        ),
        detail: json!({ "quarantined": quarantined }),
    })
}

/// Compare durable catalog-live rows with this replica's authoritative pool
/// snapshot. The catalog list is the visibility boundary: runtime-only server
/// names are never emitted to a tenant that cannot see the corresponding
/// catalog row.
fn runtime_health_finding(
    servers: &[CatalogServerSummary],
    runtime: &[UpstreamHealth],
) -> Option<TriageFinding> {
    let runtime: BTreeMap<&str, &UpstreamHealth> = runtime
        .iter()
        .map(|health| (health.name.as_str(), health))
        .collect();
    let mut missing = Vec::new();
    let mut disconnected = Vec::new();
    let mut degraded = Vec::new();

    let mut live: Vec<&CatalogServerSummary> = servers
        .iter()
        .filter(|server| server.status == CatalogServerStatus::Live)
        .collect();
    live.sort_by(|a, b| a.name.cmp(&b.name));
    for server in live {
        let Some(health) = runtime.get(server.name.as_str()) else {
            missing.push(server.name.clone());
            continue;
        };
        let detail = json!({
            "name": server.name.as_str(),
            "runtime_status": health.runtime_state.as_str(),
            "connected_lanes": health.connected_lanes,
            "configured_lanes": health.total_lanes,
            "breaker": health.breaker.as_str(),
            "last_success_at": health.last_success_at.map(format_ts_rfc3339),
            "last_error_class": health.last_error_class.map(|class| class.as_str()),
            "next_retry_at": health.next_retry_at.map(format_ts_rfc3339),
        });
        match health.runtime_state {
            UpstreamRuntimeState::Connected => {}
            UpstreamRuntimeState::Degraded => degraded.push(detail),
            UpstreamRuntimeState::Disconnected => disconnected.push(detail),
        }
    }

    let unavailable = missing.len() + disconnected.len();
    if unavailable == 0 && degraded.is_empty() {
        return None;
    }
    let (severity, summary) = if unavailable > 0 {
        (
            "critical",
            format!(
                "{unavailable} catalog-live upstream(s) have no usable runtime; {} degraded",
                degraded.len()
            ),
        )
    } else {
        (
            "warning",
            format!("{} catalog-live upstream(s) degraded", degraded.len()),
        )
    };
    Some(TriageFinding {
        area: "upstream_runtime",
        severity,
        summary,
        detail: json!({
            "missing_from_runtime": missing,
            "disconnected": disconnected,
            "degraded": degraded,
        }),
    })
}

/// Build the Cedar evaluation inputs for a simulate request, stamping the
/// SIMULATED principal's tenant with the CALLER's tenant.
///
/// The shared converter `simulate_request_to_inputs` stamps
/// `TenantId::default()` (it predates a per-tenant simulate caller). The
/// observe contract is tenant-scoped from the principal, and Cedar policies can
/// branch on `principal.tenant`, so a non-default tenant must evaluate against
/// its OWN policies — otherwise the simulation would return the wrong
/// allow/deny/step-up for any caller outside the default tenant.
fn simulate_inputs_for(
    caller: &Principal,
    req: SimulateRequest,
) -> (Principal, AuthzAction, ResourceSpec) {
    let (mut principal, action, resource) = simulate_request_to_inputs(req);
    principal.tenant = caller.tenant.clone();
    (principal, action, resource)
}

/// Compact projection of an [`AuditRow`] for the wire — drops the bulky
/// identity/SCIM/tenant columns a monitoring agent doesn't need per row,
/// keeping `tools/call` responses token-efficient.
#[derive(Serialize, schemars::JsonSchema)]
struct AuditRowView {
    ts: String,
    category: String,
    action: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    /// The operation the call selected, when the tool carries many behind one
    /// name. Two rows through one executor are otherwise indistinguishable to
    /// an investigator reading this surface, and the `risk` beside them
    /// describes the operation rather than the tool. Omitted when absent, so a
    /// tool classified by name alone costs no tokens for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    /// What the event acted on, when that is not a tool. A native resource
    /// decision names no tool — the URI is the subject — so without this an
    /// investigator sees that a resource read was decided but not which
    /// resource. Omitted when absent, so a tool-call row costs no tokens for
    /// it.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
}

/// Output of `query_audit`: a compact, newest-first page of audit rows.
#[derive(Serialize, schemars::JsonSchema)]
struct QueryAuditResponse {
    count: usize,
    events: Vec<AuditRowView>,
}

/// One `(label, count)` pair in an `activity_summary` facet rollup.
#[derive(Serialize, schemars::JsonSchema)]
struct LabelCount {
    label: String,
    count: i64,
}

/// One row of `activity_summary`'s busiest-tools table.
#[derive(Serialize, schemars::JsonSchema)]
struct TopToolStat {
    server: String,
    tool: String,
    total: i64,
    errors: i64,
    denied: i64,
    p95_latency_ms: Option<f64>,
}

/// Output of `activity_summary`: facet rollups + the busiest tools.
#[derive(Serialize, schemars::JsonSchema)]
struct ActivitySummaryResponse {
    window: String,
    by_outcome: Vec<LabelCount>,
    by_risk: Vec<LabelCount>,
    by_category: Vec<LabelCount>,
    by_server: Vec<LabelCount>,
    top_tools: Vec<TopToolStat>,
}

/// Output of `triage_digest`: an `ok` flag + severity-ranked findings.
#[derive(Serialize, schemars::JsonSchema)]
struct TriageDigestResponse {
    ok: bool,
    window: String,
    finding_count: usize,
    findings: Vec<TriageFinding>,
}

/// Map a facet's `(label, count)` rows into the typed wire shape.
fn label_counts(facet: &[(String, i64)]) -> Vec<LabelCount> {
    facet
        .iter()
        .map(|(label, count)| LabelCount {
            label: label.clone(),
            count: *count,
        })
        .collect()
}

impl AuditRowView {
    fn from_row(r: &AuditRow) -> Self {
        Self {
            ts: format_ts_rfc3339(r.ts),
            // NULL category counts as "invocation" (migration 0006), matching
            // the AuditQuery filter semantics.
            category: r
                .category
                .clone()
                .unwrap_or_else(|| "invocation".to_owned()),
            action: r.action.clone(),
            outcome: r.outcome.clone(),
            principal: r.principal_sub.clone(),
            server: r.server.clone(),
            tool: r.tool.clone(),
            target: r.target.clone(),
            operation: r.operation.clone(),
            risk: r.risk_level.clone(),
            reason: r.reason.clone(),
            latency_ms: r.latency_ms,
            policy_ids: r.policy_ids.clone(),
            trace_id: r.trace_id.clone(),
        }
    }
}

/// Static descriptor for the operator visibility surface and the dispatch-time
/// Cedar classification. Derived from [`tool_defs`] so it can't drift from the
/// tools actually served. Every observe tool is read-only (`Low` risk, no side
/// effects), but three surface identity-bearing data and so carry
/// `pii: true`: `query_audit` returns `principal_sub`,
/// `triage_digest` surfaces active break-glass `issued_to` / `reason`, and
/// `read_resource` can return identity-bearing rows (e.g. an rbac_assignment's
/// `subject_sub`). `describe_resource` (schemas only), the aggregate
/// (`activity_summary`), and the simulator (`simulate_authorization`, which
/// only echoes a caller-supplied hypothetical principal) do not.
pub fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let tools = tool_defs()
        .into_iter()
        .map(|t| {
            let prefix = format!("{NAMESPACE}.");
            let full = t.name.as_ref();
            let name = full.strip_prefix(&prefix).unwrap_or(full);
            let pii = matches!(name, "query_audit" | "triage_digest" | "read_resource");
            CatalogTool::builtin(NAMESPACE, t, RiskTier::Low, false, pii)
        })
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        Scope::McpObserve.as_str(),
        "Read-only analysis plane: filtered audit queries, pre-aggregated activity rollups, \
         authorization simulation, and a one-call health digest.",
        tools,
    )
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(
            format!("{NAMESPACE}.query_audit"),
            "Query the gateway's audit log for recent activity — who called which tool when, the \
             outcome (success / denied / step_up_required / execution_error), and on a denial the \
             policy IDs and reason. Filters: `server`, `outcome`, `category`, `risk`, `principal` \
             (substring of sub/email), `since` (relative window, default 24h). Tenant-scoped to \
             you. Returns compact rows, newest first.",
            query_audit_schema(),
        )
        .with_title("Query the audit log")
        .with_output_schema::<QueryAuditResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.activity_summary"),
            "Pre-aggregated activity rollup over a window: call counts by outcome, risk, category, \
             and server, plus the top tools by volume with their error and denial counts. Backed \
             by the hourly rollup so it's cheap over wide windows. Use this for \"what's the shape \
             of traffic / where are the denials\" before drilling in with query_audit.",
            activity_summary_schema(),
        )
        .with_title("Activity summary")
        .with_output_schema::<ActivitySummaryResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.simulate_authorization"),
            "Ask the live Cedar engine whether a hypothetical principal would be allowed to call a \
             tool, read an MCP resource, list/search, or perform a supported admin action, without \
             making the call. Returns the decision \
             (allow | deny | step_up), the diagnostic reasons, and the matched policy IDs. Use it \
             to reason about access before attempting a call, or to answer \"why was X denied?\".",
            simulate_schema(),
        )
        .with_title("Simulate authorization")
        .with_output_schema::<SimulateResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.triage_digest"),
            "One-call health digest: composes the gateway's durable signals — recent denials and \
             execution errors (last `window`, default 24h), catalog lifecycle, live upstream \
             availability (connected / degraded / disconnected), tool behavior drift events, and \
             active break-glass overrides — into a compact list of `{area, severity, summary, \
             detail}` plus an `ok` flag. Run it on a loop to triage \"is anything wrong right \
             now?\" in a single call. Tenant-scoped to you.",
            triage_schema(),
        )
        .with_title("Triage digest")
        .with_output_schema::<TriageDigestResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.describe_resource"),
            "List the gateway control-plane resources you can read with `read_resource`, each \
             with the JSON Schema of its `filters` and of one row. Call with no arguments for the \
             full catalog, or pass `resource_type` for one. Use this to discover what you can \
             list and to build a valid `read_resource` call — the filter keys are \
             resource-specific, the same way `describe_action` documents `propose_change.params`.",
            describe_resource_schema(),
        )
        .with_title("Describe readable resources")
        .with_output_schema::<DescribeResourceResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
        Tool::new(
            format!("{NAMESPACE}.read_resource"),
            format!(
                "List rows of a gateway control-plane resource, tenant-scoped to you. {} \
                 Each row carries its `id` and fields — use it to find the identifier a \
                 `propose_change` action needs (e.g. read `rate_limit_policy` for the `policy_id` \
                 of `rate_limit.update`, or `api_key` for the `api_key_id`). `resource_type` is \
                 required; call `describe_resource` for each resource's filter/row schema. \
                 Read-only.",
                resource_scope_summary()
            ),
            read_resource_schema(),
        )
        .with_title("Read a control-plane resource")
        .with_output_schema::<ReadResourceResponse>()
        .annotate(ToolAnnotations::new().read_only(true)),
    ]
}

fn query_audit_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "since": {"type": "string", "description": "Relative window, e.g. `24h`, `7d`, `30m`, `2w`. Default 24h."},
            "server": {"type": "string", "description": "Exact upstream server name."},
            "outcome": {"type": "string", "description": "Exact outcome: success | denied | step_up_required | execution_error."},
            "category": {"type": "string", "description": "Exact event category, e.g. invocation | admin_mutation | auth_attempt | policy_reload."},
            "risk": {"type": "string", "description": "Exact tool risk tier: low | medium | high."},
            "principal": {"type": "string", "description": "Case-sensitive substring matched against principal sub OR email."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max rows (default 20, cap 200)."}
        }
    }))
}

fn activity_summary_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "window": {"type": "string", "description": "Relative window, e.g. `24h`, `7d`, `30d`. Default 7d."},
            "top": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Number of top tools to return (default 10, cap 50)."}
        }
    }))
}

fn simulate_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "required": ["principal", "action", "resource"],
        "properties": {
            "principal": {
                "type": "object",
                "required": ["sub"],
                "properties": {
                    "sub": {"type": "string"},
                    "email": {"type": "string"},
                    "groups": {"type": "array", "items": {"type": "string"}},
                    "scopes": {"type": "array", "items": {"type": "string"}},
                    "auth_method": {"type": "string", "enum": ["oauth", "api_key", "peer_assertion"], "description": "Hypothetical authentication method. Default oauth."},
                    "roles": {"type": "array", "items": {"type": "string"}}
                },
                "description": "The hypothetical caller. Only `sub` is required; scopes/groups/roles default empty."
            },
            "action": {
                "description": "The hypothetical Cedar action. Use read_resource with an mcp_resource entity for a native resource read.",
                "oneOf": [
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "list_tools", "description": "List the tools visible on a server."}}},
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "search_tools", "description": "Search the tools visible on a server."}}},
                    {"type": "object", "required": ["type", "name"], "properties": {
                        "type": {"const": "call_tool"},
                        "name": {"type": "string", "description": "Unqualified tool name."},
                        "risk": {"type": "string", "enum": ["low", "medium", "high"], "description": "Governed tool risk. Default low."}
                    }},
                    {"type": "object", "required": ["type", "uri"], "properties": {
                        "type": {"const": "read_resource"},
                        "uri": {"type": "string", "description": "Exact resource URI being read; must match resource.uri."}
                    }},
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "admin_manage_policies"}}},
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "admin_manage_servers"}}},
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "admin_view_telemetry"}}},
                    {"type": "object", "required": ["type"], "properties": {"type": {"const": "grant_cross_app_access", "description": "EMA ID-JAG grant evaluated against a server resource."}}}
                ]
            },
            "resource": {
                "description": "The Cedar resource entity paired with the action.",
                "oneOf": [
                    {"type": "object", "required": ["type", "name"], "properties": {
                        "type": {"const": "server"},
                        "name": {"type": "string", "description": "Exact upstream server name."}
                    }},
                    {"type": "object", "required": ["type", "server", "name"], "properties": {
                        "type": {"const": "tool"},
                        "server": {"type": "string", "description": "Exact upstream server name."},
                        "name": {"type": "string", "description": "Unqualified tool name."},
                        "risk": {"type": "string", "enum": ["low", "medium", "high"], "description": "Governed tool risk. Default low."},
                        "side_effects": {"type": "boolean", "description": "Whether the tool has side effects. Default false."},
                        "pii": {"type": "boolean", "description": "Whether the tool surfaces PII. Default false."},
                        "operation": {"type": "string", "description": "Optional selected discriminator value."}
                    }},
                    {"type": "object", "required": ["type", "server", "uri"], "properties": {
                        "type": {"const": "mcp_resource"},
                        "server": {"type": "string", "description": "Exact owning upstream server name."},
                        "uri": {"type": "string", "description": "Exact resource URI; must match action.uri."},
                        "risk": {"type": "string", "enum": ["low", "medium", "high"], "description": "Governed resource risk. Default low."}
                    }}
                ]
            }
        }
    }))
}

fn triage_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "window": {"type": "string", "description": "Relative window for the audit-derived signals, e.g. `24h`, `7d`. Default 24h. (Quarantine and break-glass signals are point-in-time and ignore this.)"}
        }
    }))
}

/// Resolve an optional relative window argument into an inclusive lower bound
/// on `ts` (`now - duration`). Absent → `now - default`; present-but-malformed
/// → `invalid_params`.
fn resolve_since(
    args: &JsonObject,
    key: &str,
    default: Duration,
) -> Result<Option<OffsetDateTime>, McpError> {
    let dur = match opt_string(args, key)? {
        Some(w) => parse_duration(&w).ok_or_else(|| {
            McpError::invalid_params(format!("`{key}` is not a duration like 24h/7d: {w}"), None)
        })?,
        None => default,
    };
    Ok(Some(OffsetDateTime::now_utc() - dur))
}

/// Parse a relative duration like `30m`, `24h`, `7d`, `2w`. Returns `None` for
/// any malformed input (negative, non-integer, unknown unit, missing unit).
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| c.is_ascii_alphabetic())?;
    if split == 0 {
        return None;
    }
    let n: i64 = s[..split].parse().ok()?;
    if n < 0 {
        return None;
    }
    match &s[split..] {
        "m" => Some(Duration::minutes(n)),
        "h" => Some(Duration::hours(n)),
        "d" => Some(Duration::days(n)),
        "w" => Some(Duration::weeks(n)),
        _ => None,
    }
}

/// Read an optional string argument, rejecting a present-but-wrong-type value
/// (so the MCP path validates as strictly as a typed REST query).
fn opt_string(args: &JsonObject, key: &str) -> Result<Option<String>, McpError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(McpError::invalid_params(
            format!("`{key}` must be a string"),
            None,
        )),
    }
}

/// Map a store read failure to a generic MCP internal error — the underlying
/// error (a `sqlx::Error` that can name columns / SQL) is logged, never
/// returned. Generic over `Display` so this crate needn't name `sqlx`.
fn db_error<E: std::fmt::Display>(what: &str, e: E) -> McpError {
    tracing::warn!(error = %e, "gateway-observe {what} failed");
    McpError::internal_error(format!("{what} failed"), None)
}

/// Structured insufficient-scope error mirroring the maker surface's step-up
/// shape, so a client can detect it programmatically and re-authorize.
fn insufficient_scope() -> McpError {
    let data = json!({
        "error": "insufficient_scope",
        "required_scope": Scope::McpObserve.as_str(),
        "reason": "the gateway-observe namespace requires the mcp:observe (or mcp:admin) scope",
    });
    McpError::new(
        ErrorCode::INVALID_REQUEST,
        format!(
            "step-up required (scope `{}`): the gateway-observe namespace requires mcp:observe \
             or mcp:admin",
            Scope::McpObserve.as_str()
        ),
        Some(data),
    )
}

// --- describe_resource / read_resource wire shapes ---------------------------

/// One row of `describe_resource`: a readable resource type with the scope it
/// reads under, whether it is tenant-scoped, and the JSON Schemas of its
/// `filters` and its row. The read-plane analogue of `describe_action`'s
/// `ActionEntry`.
#[derive(Serialize, schemars::JsonSchema)]
struct ResourceEntryView {
    /// Pass as `read_resource.resource_type` (e.g. `rate_limit_policy`).
    resource_type: String,
    /// Scope required to read it: `mcp:observe` or `mcp:admin`.
    min_scope: String,
    /// `false` for operator-global resources whose list crosses tenants.
    tenant_scoped: bool,
    /// JSON Schema of the `filters` object this resource accepts.
    filter_schema: Value,
    /// JSON Schema of one row this resource returns.
    row_schema: Value,
}

impl ResourceEntryView {
    fn from_entry(e: waygate_admin::resource_catalog::ResourceCatalogEntry) -> Self {
        Self {
            resource_type: e.resource_type.to_owned(),
            min_scope: e.min_scope.to_owned(),
            tenant_scoped: e.tenant_scoped,
            filter_schema: e.filter_schema,
            row_schema: e.row_schema,
        }
    }
}

/// Output of `describe_resource`: always a list of [`ResourceEntryView`] (the
/// full catalog, or a single-element list when `resource_type` is supplied) —
/// uniform like `DescribeActionResponse`.
#[derive(Serialize, schemars::JsonSchema)]
struct DescribeResourceResponse {
    resources: Vec<ResourceEntryView>,
}

/// Output of `read_resource`: a page of rows. The per-row schema is generic
/// here (`rows: Vec<Value>`) on purpose — the strong row schema is served by
/// `describe_resource`, the same way `propose_change.params` is generic and the
/// strong schema lives in `describe_action`.
#[derive(Serialize, schemars::JsonSchema)]
struct ReadResourceResponse {
    resource_type: String,
    count: usize,
    rows: Vec<Value>,
    /// Applied page size (after the per-resource cap).
    limit: u32,
    offset: u32,
}

fn describe_resource_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "properties": {
            "resource_type": {"type": "string", "description": "Resource type whose filter + row schema you want, e.g. `rate_limit_policy` or `peer`. Omit for the full catalog of readable resources."}
        }
    }))
}

fn read_resource_schema() -> Arc<JsonObject> {
    let resource_description = format!(
        "Which resource to list. {} Call `describe_resource` for each resource's filter/row schema.",
        resource_scope_summary()
    );
    schema_obj(json!({
        "type": "object",
        "required": ["resource_type"],
        "properties": {
            "resource_type": {"type": "string", "description": resource_description},
            "filters": {"type": "object", "description": "Optional filters; the keys are specific to the resource_type (call `describe_resource` for that resource's filter schema — mirrors propose_change.params ↔ describe_action). Most resources take none."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max rows (default 50, cap 200)."},
            "offset": {"type": "integer", "minimum": 0, "description": "Pagination offset (default 0)."}
        }
    }))
}

fn resource_scope_summary() -> String {
    let catalog = resource_entries();
    let joined = |scope: &str| {
        catalog
            .iter()
            .filter(|entry| entry.min_scope == scope)
            .map(|entry| format!("`{}`", entry.resource_type))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    format!(
        "Low-sensitivity resources (`mcp:observe`): {}. Sensitive resources (`mcp:admin`): {}.",
        joined("mcp:observe"),
        joined("mcp:admin")
    )
}

/// The readable resource types, comma-joined — the teach-list for an unknown
/// `resource_type`.
fn resource_types_joined() -> String {
    resource_entries()
        .into_iter()
        .map(|e| e.resource_type)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `invalid_params` for an unknown `resource_type`, naming the valid set.
fn unknown_resource(rt: &str) -> McpError {
    McpError::invalid_params(
        format!(
            "unknown resource_type {rt:?}; readable resources: {}",
            resource_types_joined()
        ),
        None,
    )
}

/// Structured insufficient-scope error for a resource whose access tier is
/// above the namespace floor (mirrors [`insufficient_scope`] but names the
/// stricter scope + the resource).
fn need_scope(required: &str, resource_type: &str) -> McpError {
    let data = json!({
        "error": "insufficient_scope",
        "required_scope": required,
        "reason": format!("reading `{resource_type}` requires the {required} scope"),
    });
    McpError::new(
        ErrorCode::INVALID_REQUEST,
        format!(
            "step-up required (scope `{required}`): reading `{resource_type}` requires {required}"
        ),
        Some(data),
    )
}

/// Map a [`ReadError`] from the resource registry to an MCP error. Store
/// failures were already logged (with the column-naming detail) inside
/// `waygate_admin::resource_catalog::read`.
fn map_read_err(e: ReadError) -> McpError {
    match e {
        ReadError::UnknownResource(valid) => McpError::invalid_params(
            format!(
                "unknown resource_type; readable resources: {}",
                valid.join(", ")
            ),
            None,
        ),
        ReadError::BadFilter(msg) => McpError::invalid_params(msg, None),
        ReadError::Unavailable(msg) => McpError::internal_error(msg.to_owned(), None),
        ReadError::Store(msg) => McpError::internal_error(msg, None),
    }
}

/// Governed read-built-in caller for the in-app contextual assistant.
/// Wraps the read-only `gateway-observe` [`BuiltinTools`] with the SAME
/// Cedar forbid-overlay the MCP request path applies (`authorize_builtin_call`),
/// then the namespace scope-floor self-gate inside [`BuiltinTools::call`] — so an
/// allowlisted `gateway-observe.*` chat-agent call is governed identically to a
/// direct MCP call. Read-only by construction: a side-effecting tool is refused
/// here even if one were ever added to the namespace.
pub struct GovernedObserveCaller {
    authz: SharedAuthz,
    observe: SharedBuiltinTools,
}

impl GovernedObserveCaller {
    pub fn new(authz: SharedAuthz, observe: SharedBuiltinTools) -> Self {
        Self { authz, observe }
    }
}

#[async_trait]
impl AssistReadTools for GovernedObserveCaller {
    async fn read_tools(&self, principal: Option<&Principal>) -> Vec<AssistReadTool> {
        // list_tools is the principal-filtered, schema-bearing view; describe()
        // carries the side_effects fact per tool. NOTE: list_tools yields
        // FULLY-QUALIFIED names (`gateway-observe.query_audit`) while describe()
        // keys by BARE names (`query_audit`) — so use the fq name as-is and
        // strip the prefix only for the side_effects lookup; never re-prefix.
        // Keep only read-only tools (the namespace is all-read today).
        let desc = self.observe.describe();
        let prefix = format!("{}.", desc.namespace);
        let se: std::collections::HashMap<&str, bool> = desc
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.side_effects))
            .collect();
        self.observe
            .list_tools(principal)
            .await
            .into_iter()
            .filter_map(|t| {
                let fq = t.name.as_ref();
                let bare = fq.strip_prefix(&prefix).unwrap_or(fq);
                if *se.get(bare).unwrap_or(&false) {
                    return None; // never offer a side-effecting tool here
                }
                // API-key profile confinement: hide a built-in the principal's
                // profile excludes, mirroring the MCP request path's list_tools
                // gate so the agent never offers an unreachable tool.
                if principal.is_some_and(|p| {
                    waygate_mcp::server::profile_blocks_builtin(p, &desc.namespace, bare)
                }) {
                    return None;
                }
                Some(AssistReadTool {
                    name: fq.to_owned(),
                    description: t.description.as_deref().unwrap_or_default().to_owned(),
                    input_schema: (*t.input_schema).clone(),
                    side_effects: false,
                })
            })
            .collect()
    }

    async fn call(
        &self,
        name: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        let desc = self.observe.describe();
        // Strip the `<namespace>.` prefix; reject anything outside this seam's
        // read namespace.
        let Some(tool) = name
            .strip_prefix(&desc.namespace)
            .and_then(|rest| rest.strip_prefix('.'))
        else {
            return Err(McpError::invalid_params(
                format!("{name} is not a {} read tool", desc.namespace),
                None,
            ));
        };
        let Some(t) = desc.tools.iter().find(|t| t.name == tool) else {
            return Err(McpError::invalid_params(
                format!("unknown built-in tool `{name}`"),
                None,
            ));
        };
        // Defense in depth: this assistant seam is read-only. The observe
        // namespace contains no side-effecting tools today; refuse one outright
        // rather than ever routing a mutation through the agent.
        if t.side_effects {
            return Err(McpError::invalid_params(
                format!("`{name}` is not a read-only tool"),
                None,
            ));
        }

        // Same governance ORDER as the MCP request path: API-key profile
        // confinement first, then the Cedar forbid-overlay. `None` principal
        // skips both, matching that path; the agent always supplies the operator.
        if let Some(p) = principal {
            // Profile restriction: refuse a built-in the principal's profile
            // excludes — identical to the request-path gate.
            if waygate_mcp::server::profile_blocks_builtin(p, &desc.namespace, tool) {
                return Err(McpError::invalid_params(
                    format!("`{name}` is not permitted by this principal's profile"),
                    None,
                ));
            }
            let facts = ToolFacts {
                server: desc.namespace.clone(),
                name: tool.to_owned(),
                risk: t.risk,
                side_effects: t.side_effects,
                pii: t.pii,
                requires_approval: false,
                requires_approval_known: true,
            };
            match self.authz.authorize_builtin_call(p, &facts).await {
                BuiltinAuthz::Proceed => {}
                BuiltinAuthz::Forbidden { reason, .. } => {
                    return Err(McpError::invalid_params(
                        format!("forbidden by policy: {reason}"),
                        None,
                    ));
                }
                BuiltinAuthz::StepUpRequired { required_scope, .. } => {
                    return Err(McpError::invalid_params(
                        format!("requires step-up to `{required_scope}`"),
                        None,
                    ));
                }
                BuiltinAuthz::Indeterminate { reason } => {
                    return Err(McpError::internal_error(
                        format!("authorization unavailable: {reason}"),
                        None,
                    ));
                }
            }
        }

        // Scope-floor self-gate lives inside `call`.
        self.observe.call(tool, arguments, principal).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_resource_description_names_every_catalog_resource() {
        let schema = read_resource_schema();
        let schema_description = schema["properties"]["resource_type"]["description"]
            .as_str()
            .expect("resource_type description");
        let tool_description = tool_defs()
            .into_iter()
            .find(|tool| tool.name.ends_with(".read_resource"))
            .expect("read_resource tool")
            .description
            .expect("read_resource description");
        for entry in resource_entries() {
            assert!(
                schema_description.contains(&format!("`{}`", entry.resource_type)),
                "read_resource schema description missing `{}`",
                entry.resource_type
            );
            assert!(
                tool_description.contains(&format!("`{}`", entry.resource_type)),
                "read_resource tool description missing `{}`",
                entry.resource_type
            );
        }
    }

    #[test]
    fn observe_tools_advertise_output_schema_and_title() {
        // Every observe tool is a read — it MUST carry a title and an
        // output_schema (SOP points 4 + 5) so a client knows the result shape
        // without parsing prose, and be marked read_only.
        for t in tool_defs() {
            assert!(t.title.is_some(), "{} missing title", t.name);
            assert!(
                t.output_schema.is_some(),
                "{} missing output_schema",
                t.name
            );
            assert_eq!(
                t.annotations.as_ref().and_then(|a| a.read_only_hint),
                Some(true),
                "{} should be read_only",
                t.name
            );
        }
    }

    #[test]
    fn observe_output_schemas_validate_sample_content() {
        // SOP (`docs/agents/mcp-tool-docs.md`): a read tool isn't done until a
        // test asserts the returned structuredContent validates against the
        // advertised output_schema. These schemas are *derived* from the
        // response types, so this pins that serde and schemars agree on the wire
        // shape — a sample that serializes but fails its own schema is a
        // schemars/serde drift, which the presence test alone would not catch.
        // The vecs are populated (not empty) so the nested item schemas
        // (`LabelCount`, `TopToolStat`, including the `Option` p95 field) are
        // actually exercised — empty arrays validate trivially.
        fn assert_validates<T: serde::Serialize + schemars::JsonSchema>(sample: &T) {
            let schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes");
            let validator = jsonschema::validator_for(&schema).expect("output_schema compiles");
            let instance = serde_json::to_value(sample).expect("sample serializes");
            let errors: Vec<String> = validator
                .iter_errors(&instance)
                .map(|e| e.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "sample does not validate against its own output_schema: {errors:?}"
            );
        }

        assert_validates(&QueryAuditResponse {
            count: 0,
            events: Vec::new(),
        });
        assert_validates(&ActivitySummaryResponse {
            window: "24h".to_string(),
            by_outcome: vec![LabelCount {
                label: "allow".to_string(),
                count: 3,
            }],
            by_risk: vec![LabelCount {
                label: "low".to_string(),
                count: 3,
            }],
            by_category: Vec::new(),
            by_server: Vec::new(),
            top_tools: vec![
                TopToolStat {
                    server: "srv".to_string(),
                    tool: "a".to_string(),
                    total: 5,
                    errors: 0,
                    denied: 0,
                    p95_latency_ms: Some(12.5),
                },
                TopToolStat {
                    server: "srv".to_string(),
                    tool: "b".to_string(),
                    total: 1,
                    errors: 1,
                    denied: 0,
                    p95_latency_ms: None,
                },
            ],
        });
        assert_validates(&TriageDigestResponse {
            ok: true,
            window: "24h".to_string(),
            finding_count: 0,
            findings: Vec::new(),
        });
        // Populated (non-empty) so the nested ResourceEntryView / row schemas
        // are exercised, not just the envelope.
        assert_validates(&DescribeResourceResponse {
            resources: vec![ResourceEntryView {
                resource_type: "rate_limit_policy".to_string(),
                min_scope: "mcp:observe".to_string(),
                tenant_scoped: true,
                filter_schema: json!({"type": "object"}),
                row_schema: json!({"type": "object"}),
            }],
        });
        assert_validates(&ReadResourceResponse {
            resource_type: "rate_limit_policy".to_string(),
            count: 1,
            rows: vec![json!({"id": "00000000-0000-0000-0000-000000000000", "name": "default"})],
            limit: 50,
            offset: 0,
        });
    }

    #[test]
    fn surface_descriptor_matches_served_tools() {
        // The descriptor must enumerate exactly the tools `tool_defs()` serves,
        // with the gating scope — so the operator view and the Cedar
        // classification can't drift from the wire.
        let prefix = format!("{NAMESPACE}.");
        let served: Vec<String> = tool_defs()
            .into_iter()
            .map(|t| t.name.as_ref().strip_prefix(&prefix).unwrap().to_owned())
            .collect();
        let d = surface_descriptor();
        let described: Vec<String> = d.tools.iter().map(|t| t.name.clone()).collect();
        assert_eq!(described, served);
        assert_eq!(d.namespace, NAMESPACE);
        assert_eq!(d.required_scope, Scope::McpObserve.as_str());
        // Observe tools are reads — Low risk, no side effects.
        assert!(d
            .tools
            .iter()
            .all(|t| t.risk == RiskTier::Low && !t.side_effects));
        // The identity-bearing reads must be flagged pii (Cedar inputs); the
        // aggregate and the hypothetical-only simulator must not.
        let pii = |n: &str| d.tools.iter().find(|t| t.name == n).unwrap().pii;
        assert!(pii("query_audit"));
        assert!(pii("triage_digest"));
        assert!(pii("read_resource"));
        assert!(!pii("activity_summary"));
        assert!(!pii("simulate_authorization"));
        assert!(!pii("describe_resource"));
    }

    #[test]
    fn simulate_schema_publishes_native_resource_shapes() {
        let schema = simulate_schema();
        let variants_contain = |field: &str, tag: &str| {
            schema["properties"][field]["oneOf"]
                .as_array()
                .expect("polymorphic field publishes oneOf")
                .iter()
                .any(|variant| variant["properties"]["type"]["const"] == tag)
        };

        assert!(variants_contain("action", "read_resource"));
        assert!(variants_contain("resource", "mcp_resource"));
    }

    fn tools() -> ObserveTools {
        // Empty AdminState cell: these tests exercise the authorization gate
        // and dispatch routing, which run BEFORE any state access.
        ObserveTools::new(Arc::new(OnceLock::new()))
    }

    fn principal(scopes: &[&str]) -> Principal {
        Principal {
            sub: "agent".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[tokio::test]
    async fn list_tools_gated_on_observe_or_admin_scope() {
        let t = tools();
        assert!(t.list_tools(None).await.is_empty());
        assert!(t
            .list_tools(Some(&principal(&["mcp:invoke"])))
            .await
            .is_empty());
        // mcp:observe sees the read tools.
        let observed: Vec<String> = t
            .list_tools(Some(&principal(&["mcp:observe"])))
            .await
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(
            observed,
            vec![
                "gateway-observe.query_audit",
                "gateway-observe.activity_summary",
                "gateway-observe.simulate_authorization",
                "gateway-observe.triage_digest",
                "gateway-observe.describe_resource",
                "gateway-observe.read_resource",
            ]
        );
        // mcp:admin satisfies the read gate too (operators can read).
        assert_eq!(
            t.list_tools(Some(&principal(&["mcp:admin"]))).await.len(),
            6
        );
    }

    #[tokio::test]
    async fn peer_assertion_is_not_an_observer_even_with_scope() {
        // A federated Tier-C peer carrying mcp:observe must NOT reach the read
        // plane — same posture as the maker surface.
        let t = tools();
        let mut peer = principal(&["mcp:observe"]);
        peer.auth_method = AuthMethod::PeerAssertion;
        assert!(t.list_tools(Some(&peer)).await.is_empty());
        let err = t
            .call("query_audit", None, Some(&peer))
            .await
            .expect_err("peer must be refused");
        assert!(format!("{err}").contains("mcp:observe"), "got: {err}");
    }

    #[tokio::test]
    async fn call_without_scope_is_insufficient_scope() {
        let t = tools();
        // No principal.
        let err = t
            .call("query_audit", None, None)
            .await
            .expect_err("no scope");
        assert!(format!("{err}").contains("mcp:observe"), "got: {err}");
        // Principal without the scope.
        let err = t
            .call("query_audit", None, Some(&principal(&["mcp:invoke"])))
            .await
            .expect_err("wrong scope");
        assert!(format!("{err}").contains("mcp:observe"), "got: {err}");
    }

    #[tokio::test]
    async fn unknown_tool_is_invalid_params_not_state_access() {
        // A scoped caller hitting an unknown tool gets invalid_params from the
        // dispatch arm — proving the unknown-tool path doesn't depend on the
        // (here-empty) AdminState cell.
        let t = tools();
        let err = t
            .call("bogus", None, Some(&principal(&["mcp:observe"])))
            .await
            .expect_err("unknown tool");
        assert!(
            format!("{err}").contains("unknown gateway-observe tool"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn read_resource_admin_tier_requires_mcp_admin() {
        // `api_key` is an mcp:admin resource. An observe-only caller clears
        // the namespace floor but must be refused at the per-resource
        // gate — and BEFORE any state access, so the unset-state cell can't
        // mask the insufficient_scope.
        let t = tools();
        let mut args = serde_json::Map::new();
        args.insert("resource_type".into(), json!("api_key"));
        let err = t
            .call(
                "read_resource",
                Some(args.clone()),
                Some(&principal(&["mcp:observe"])),
            )
            .await
            .expect_err("observe-only must be refused for an admin resource");
        assert!(format!("{err}").contains("mcp:admin"), "got: {err}");

        // An mcp:admin caller clears the gate and only then hits the unset-state
        // guard — proving the admin tier is what gated the observe caller.
        let err = t
            .call(
                "read_resource",
                Some(args),
                Some(&principal(&["mcp:admin"])),
            )
            .await
            .expect_err("unset state after passing the admin gate");
        assert!(
            format!("{err}").contains("not yet initialised"),
            "got: {err}"
        );

        // A low-sensitivity (observe-tier) resource is reachable by an
        // observe-only caller, reaching the state guard rather than the gate.
        let mut obs = serde_json::Map::new();
        obs.insert("resource_type".into(), json!("rate_limit_policy"));
        let err = t
            .call(
                "read_resource",
                Some(obs),
                Some(&principal(&["mcp:observe"])),
            )
            .await
            .expect_err("unset state");
        assert!(
            format!("{err}").contains("not yet initialised"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn known_tool_with_unset_state_is_internal_error() {
        // A scoped caller on a known tool passes the gate, then hits the
        // unset-state guard (the cell is empty in this test) — proving the
        // scope check is not what blocks here.
        let t = tools();
        let err = t
            .call("query_audit", None, Some(&principal(&["mcp:observe"])))
            .await
            .expect_err("unset state");
        assert!(
            format!("{err}").contains("not yet initialised"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_duration_accepts_units_and_rejects_garbage() {
        assert_eq!(parse_duration("24h"), Some(Duration::hours(24)));
        assert_eq!(parse_duration("7d"), Some(Duration::days(7)));
        assert_eq!(parse_duration("30m"), Some(Duration::minutes(30)));
        assert_eq!(parse_duration("2w"), Some(Duration::weeks(2)));
        assert_eq!(parse_duration(" 1h "), Some(Duration::hours(1)));
        assert!(parse_duration("h").is_none());
        assert!(parse_duration("12").is_none());
        assert!(parse_duration("-3h").is_none());
        assert!(parse_duration("3y").is_none());
        assert!(parse_duration("").is_none());
    }

    #[test]
    fn simulate_stamps_caller_tenant_not_default() {
        // The simulated principal must carry the CALLER's tenant, not the
        // converter's `TenantId::default()` — Cedar can branch on
        // `principal.tenant`, so a non-default tenant would otherwise get
        // decisions evaluated against the wrong tenant's policies.
        let mut caller = principal(&["mcp:observe"]);
        caller.tenant = waygate_core::TenantId::parse("acme").expect("valid tenant");
        let req: SimulateRequest = serde_json::from_value(json!({
            "principal": {"sub": "someone-else", "scopes": ["mcp:invoke"]},
            "action": {"type": "list_tools"},
            "resource": {"type": "server", "name": "example-messages"},
        }))
        .expect("valid simulate request");
        let (sim, _action, _resource) = simulate_inputs_for(&caller, req);
        assert_eq!(
            sim.tenant.as_str(),
            "acme",
            "simulation must be scoped to the caller's tenant, not the default"
        );
        assert_ne!(
            sim.tenant.as_str(),
            waygate_core::TenantId::default().as_str()
        );
        // Only the tenant is overridden — the hypothetical principal's identity
        // is preserved.
        assert_eq!(sim.sub, "someone-else");
    }

    #[test]
    fn severity_rank_orders_most_severe_first() {
        // triage_digest sorts findings by this key, so the returned list is
        // urgency-ordered (critical → warning → info), not source-ordered.
        assert!(severity_rank("critical") < severity_rank("warning"));
        assert!(severity_rank("warning") < severity_rank("info"));
        // Unknown severities sort with info (last).
        assert_eq!(severity_rank("bogus"), severity_rank("info"));
    }

    fn catalog_server(name: &str, status: CatalogServerStatus) -> CatalogServerSummary {
        CatalogServerSummary {
            id: uuid::Uuid::new_v4(),
            tenant_id: "default".into(),
            name: name.into(),
            transport: "http".into(),
            status,
            visibility: waygate_catalog::CatalogVisibility::TenantOnly,
            owner: None,
        }
    }

    fn upstream_health(
        name: &str,
        runtime_state: UpstreamRuntimeState,
        connected_lanes: usize,
        total_lanes: usize,
    ) -> UpstreamHealth {
        UpstreamHealth {
            name: name.into(),
            runtime_state,
            last_success_at: (runtime_state == UpstreamRuntimeState::Connected)
                .then_some(OffsetDateTime::UNIX_EPOCH),
            last_error_class: (runtime_state == UpstreamRuntimeState::Disconnected)
                .then_some(waygate_upstream::UpstreamErrorClass::Dns),
            next_retry_at: (runtime_state != UpstreamRuntimeState::Connected)
                .then_some(OffsetDateTime::UNIX_EPOCH + Duration::minutes(1)),
            connected: connected_lanes > 0,
            breaker: waygate_upstream::BreakerState::Closed,
            connected_lanes,
            total_lanes,
            published_tool_count: 1,
            quarantined_tool_count: 0,
            rejected_output_schema_count: 0,
            protocol_versions: Vec::new(),
        }
    }

    #[test]
    fn triage_reports_catalog_live_runtime_outages_without_cross_tenant_leakage() {
        let servers = vec![
            catalog_server("down", CatalogServerStatus::Live),
            catalog_server("partial", CatalogServerStatus::Live),
            catalog_server("not-loaded", CatalogServerStatus::Live),
            catalog_server("catalog-blocked", CatalogServerStatus::Quarantined),
        ];
        let runtime = vec![
            upstream_health("down", UpstreamRuntimeState::Disconnected, 0, 4),
            upstream_health("partial", UpstreamRuntimeState::Degraded, 2, 4),
            // A runtime-only name is outside the tenant-scoped catalog
            // boundary and must never appear in this finding.
            upstream_health("other-tenant", UpstreamRuntimeState::Disconnected, 0, 1),
        ];

        let finding = runtime_health_finding(&servers, &runtime).expect("runtime finding");
        assert_eq!(finding.area, "upstream_runtime");
        assert_eq!(finding.severity, "critical");
        assert_eq!(
            finding.detail["missing_from_runtime"],
            json!(["not-loaded"])
        );
        assert_eq!(finding.detail["disconnected"][0]["name"], "down");
        assert_eq!(finding.detail["disconnected"][0]["last_error_class"], "dns");
        assert_eq!(
            finding.detail["disconnected"][0]["next_retry_at"],
            "1970-01-01T00:01:00Z"
        );
        assert_eq!(finding.detail["degraded"][0]["name"], "partial");
        assert!(
            !finding.detail.to_string().contains("other-tenant"),
            "runtime-only names must stay outside the catalog visibility boundary",
        );
        assert!(
            !finding.detail.to_string().contains("catalog-blocked"),
            "catalog quarantine is reported by the separate lifecycle finding",
        );
    }

    #[test]
    fn triage_omits_runtime_finding_when_every_catalog_live_server_is_connected() {
        let servers = vec![catalog_server("healthy", CatalogServerStatus::Live)];
        let runtime = vec![upstream_health(
            "healthy",
            UpstreamRuntimeState::Connected,
            4,
            4,
        )];
        assert!(runtime_health_finding(&servers, &runtime).is_none());
    }

    #[test]
    fn triage_reports_only_configured_catalog_quarantines() {
        let servers = vec![
            catalog_server("configured-quarantine", CatalogServerStatus::Quarantined),
            catalog_server("removed-quarantine", CatalogServerStatus::Quarantined),
        ];
        let runtime = vec![upstream_health(
            "configured-quarantine",
            UpstreamRuntimeState::Connected,
            4,
            4,
        )];

        let finding =
            catalog_quarantine_finding(&servers, &runtime).expect("configured quarantine");
        assert_eq!(finding.area, "catalog");
        assert_eq!(finding.severity, "warning");
        assert_eq!(
            finding.detail["quarantined"],
            json!(["configured-quarantine"]),
            "removed catalog history must not become an operational warning",
        );

        assert!(
            catalog_quarantine_finding(&servers[1..], &[]).is_none(),
            "a retained row with no configured upstream is historical, not unhealthy",
        );
    }

    #[tokio::test]
    async fn governed_observe_read_tools_are_fully_qualified_once() {
        // list_tools yields already-fully-qualified names; read_tools must
        // echo them verbatim, not re-prefix the namespace. The agent indexes
        // its allowlist by these names, so a doubled prefix would silently
        // drop every observe tool.
        let caller = GovernedObserveCaller::new(
            Arc::new(waygate_mcp::AllowAllGate) as SharedAuthz,
            Arc::new(tools()) as SharedBuiltinTools,
        );
        let names: Vec<String> = caller
            .read_tools(Some(&principal(&["mcp:observe"])))
            .await
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert!(
            names.contains(&"gateway-observe.query_audit".to_owned()),
            "{names:?}"
        );
        assert!(
            names.iter().all(|n| n.starts_with("gateway-observe.")
                && !n.starts_with("gateway-observe.gateway-observe.")),
            "names must be singly fully-qualified: {names:?}"
        );
        // The observe namespace is all read-only, so every advertised tool is
        // offered (none filtered as side-effecting).
        assert_eq!(
            names.len(),
            caller.observe.describe().tools.len(),
            "all read-only observe tools should be offered: {names:?}"
        );
    }

    #[tokio::test]
    async fn governed_observe_honors_api_key_profile_restriction() {
        // The seam must apply the SAME api_key_profile confinement the MCP
        // request path does. A principal whose profile excludes
        // gateway-observe gets no read tools offered, and a direct call is
        // refused — even though the principal holds mcp:observe.
        let caller = GovernedObserveCaller::new(
            Arc::new(waygate_mcp::AllowAllGate) as SharedAuthz,
            Arc::new(tools()) as SharedBuiltinTools,
        );
        let mut p = principal(&["mcp:observe"]);
        p.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "pid".into(),
            profile_name: "read_only".into(),
            // Permits some other server, not gateway-observe ⇒ observe is blocked.
            allowed_servers: Some(vec!["example-messages".into()]),
            allowed_tools: None,
        });
        assert!(
            caller.read_tools(Some(&p)).await.is_empty(),
            "a profile that excludes gateway-observe must offer no read tools"
        );
        let err = caller
            .call("gateway-observe.query_audit", None, Some(&p))
            .await
            .expect_err("profile-excluded call must be refused");
        assert!(format!("{err}").contains("profile"), "got: {err}");
    }
}
