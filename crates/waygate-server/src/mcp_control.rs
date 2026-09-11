//! Built-in `gateway-control` MCP namespace — direct `mcp:admin` operational
//! levers.
//!
//! Unlike the HITL `gateway-admin.propose_change` surface (which queues a
//! change for a human to approve), these tools **execute immediately** under
//! the caller's own `mcp:admin` authority. They are therefore deliberately
//! limited to **reversible, low-blast-radius operational actions**:
//!
//! - `quarantine_server` — pull an upstream out of dispatch (incident response).
//!   One-directional: restoring a durably quarantined server to live requires
//!   the version-bound `catalog.server.unquarantine` change action, so it stays
//!   on the dashboard / propose path rather than this direct surface.
//! - `reconnect_server` — recover a flapping upstream, optionally clearing its
//!   tool-drift quarantine. A healthy session is deliberately left untouched.
//! - `refresh_server_catalog` — replace a healthy or unhealthy upstream session
//!   and atomically republish a fresh classified tool inventory.
//! - `reload_config` — nudge the policy / manifest reload doorbell so every
//!   replica reconciles to the active pointer. Idempotent.
//!
//! Secret- and privilege-bearing actions (api-key mint, RBAC, policy/manifest
//! *publish*, break-glass mint) stay on the propose path and are **not** here.
//!
//! ## Authorization
//!
//! Every tool requires a **non-peer** principal holding `mcp:admin` (a
//! federated Tier-C peer is excluded even with the scope, mirroring the maker
//! surface — it carries its own operator on the far side). `list_tools` hides
//! the tools from non-admins (UX); `call` re-checks (the boundary).
//!
//! `quarantine_server` and `reload_config` are **tenant-scoped** from the
//! principal (catalog rows and policy/manifest pointers are per-tenant).
//! `reconnect_server` and `refresh_server_catalog` act on the
//! **gateway-global** upstream pool — the runtime upstream set is global today
//! (see the manifest-bundle docs), so they are `mcp:admin`-gated but not
//! tenant-partitioned; if the upstream set ever becomes per-tenant, these tools
//! must grow a tenant filter.
//!
//! ## Audit
//!
//! Each tool records a non-failing `AdminMutation` (or `UpstreamHealth`)
//! evidence row attributing the agent principal, action, tenant, and target.
//! Quarantine attribution is chained best effort; recovery/reload attribution
//! stays unchained best effort so it does not contend on the tenant chain.
//! (`quarantine_server` *additionally* writes the catalog's own
//! `catalog_approvals` row inside `set_server_status`; reconnect also emits
//! pool-health evidence. Catalog refresh schedules its attributed event inside
//! the pool's no-yield post-commit return path so request cancellation cannot
//! separate the committed session swap from its actor evidence. `reload_config`
//! has no core attribution.)

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ErrorCode, JsonObject, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use waygate_admin::config_reload::{reload_config_core, ConfigReloadParams, ConfigReloadResponse};
use waygate_admin::error::ApiError;
use waygate_admin::servers::{
    reconnect_server_core, refresh_server_catalog_core, ReconnectResponse, ReconnectServerParams,
    RefreshCatalogResponse, RefreshServerCatalogParams,
};
use waygate_admin::AdminState;
use waygate_catalog::CatalogServerStatus;
use waygate_core::RiskTier;
use waygate_mcp::{
    AuditEvent, AuditOutcome, BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinTools, CatalogTool,
    EvidenceCategory,
};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::mcp_builtin::{schema_obj, structured};

/// The reserved namespace this handler answers, aliased to the cross-crate
/// source of truth so dispatch and the load-time guard agree.
pub const NAMESPACE: &str = waygate_core::CONTROL_BUILTIN_NAMESPACE;

/// Built-in direct-control MCP tools backing the `gateway-control.*` surface.
/// Holds only the deferred `AdminState` cell — every store/pool it needs hangs
/// off `AdminState`.
pub struct ControlTools {
    admin_state: Arc<OnceLock<Arc<AdminState>>>,
}

#[derive(Clone, Copy)]
enum ControlEvidencePosture {
    ChainedBestEffort,
    BestEffort,
}

impl ControlTools {
    pub fn new(admin_state: Arc<OnceLock<Arc<AdminState>>>) -> Self {
        Self { admin_state }
    }

    fn state(&self) -> Result<&Arc<AdminState>, McpError> {
        self.admin_state
            .get()
            .ok_or_else(|| McpError::internal_error("control plane not yet initialised", None))
    }

    /// Record a non-failing attribution row using the action's classified
    /// reliability posture. A null sink is a no-op; a real sink measures and
    /// logs delivery failures.
    async fn record(
        &self,
        principal: &Principal,
        category: EvidenceCategory,
        posture: ControlEvidencePosture,
        action: &str,
        target: impl Into<String>,
        reason: Option<&str>,
    ) {
        let Ok(state) = self.state() else { return };
        let mut ev = AuditEvent::new(action, AuditOutcome::Success)
            .with_category(category)
            .with_principal(Some(principal))
            .with_tenant(principal.tenant.clone())
            .with_target(target.into());
        if let Some(r) = reason {
            ev = ev.with_reason(r);
        }
        match posture {
            ControlEvidencePosture::ChainedBestEffort => {
                state.evidence.record_chained_best_effort(ev).await;
            }
            ControlEvidencePosture::BestEffort => {
                state.evidence.record_best_effort(ev).await;
            }
        }
    }
}

/// An admin is a non-peer principal holding `mcp:admin`. The peer exclusion
/// mirrors [`crate::mcp_builtin`]'s `is_maker`: a federated Tier-C peer is not
/// an operator of THIS gateway, so it can't drive the direct-control surface
/// even if its token carries `mcp:admin` (the REST `require_admin` gate and the
/// `PeerJwtValidator` strip enforce the same on their side).
fn may_admin(p: &Principal) -> bool {
    p.auth_method != AuthMethod::PeerAssertion && p.has_scope(Scope::McpAdmin.as_str())
}

#[async_trait]
impl BuiltinTools for ControlTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        if principal.is_some_and(may_admin) {
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
            Some(p) if may_admin(p) => p,
            _ => return Err(insufficient_scope()),
        };
        let args = arguments.unwrap_or_default();
        match tool {
            "quarantine_server" => self.quarantine_server(principal, &args).await,
            "reconnect_server" => self.reconnect_server(principal, &args).await,
            "refresh_server_catalog" => self.refresh_server_catalog(principal, &args).await,
            "reload_config" => self.reload_config(principal, &args).await,
            other => Err(McpError::invalid_params(
                format!("unknown {NAMESPACE} tool: {other}"),
                None,
            )),
        }
    }
}

impl ControlTools {
    async fn quarantine_server(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let state = self.state()?;
        let catalog = state
            .servers
            .catalog
            .get()
            .ok_or_else(|| McpError::internal_error("no catalog store configured", None))?;
        let tenant = principal.tenant.as_str();
        let server = req_string(args, "server")?;
        let reason = opt_string(args, "reason")?;

        // ONE-DIRECTIONAL by design: this tool only sets `Quarantined`
        // (removes a server from dispatch), never `Live`. Restoring/promoting
        // to live from durable quarantine is the narrow governed
        // `catalog.server.unquarantine` change action. Its proposal binds an
        // exact quarantined row version and its approval may only perform
        // `quarantined -> live`. The dashboard/REST direct approve path rejects
        // durable quarantine while retaining its other legacy transitions, so
        // neither surface bypasses recovery review. Quarantining is always safe: it
        // only ever pulls a server OUT of dispatch, on any current status,
        // with no approval gate (mirroring the REST quarantine path).

        // Resolve name → id. There's no name lookup; list the tenant's servers
        // and filter — the same shape the REST handler uses.
        let servers = catalog
            .list_servers(tenant)
            .await
            .map_err(|e| ctl_error("catalog list_servers", e))?;
        // Prefer the caller's own tenant row over a same-named GLOBAL row.
        // `list_servers` orders by (tenant_id, name) and includes global rows,
        // so a bare first-match could pick the global row and then fail the
        // tenant-scoped `set_server_status` — leaving the operator unable to
        // quarantine their tenant override by name. This mirrors the dispatch
        // resolver's tenant-over-global preference.
        let target = servers
            .iter()
            .find(|s| s.name == server && s.tenant_id == tenant)
            .or_else(|| servers.iter().find(|s| s.name == server))
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("no catalog server named `{server}` in your tenant"),
                    None,
                )
            })?;
        // The store writes its own catalog_approvals audit row atomically.
        let updated = catalog
            .set_server_status(
                tenant,
                target.id,
                CatalogServerStatus::Quarantined,
                &principal.sub,
                reason.as_deref(),
            )
            .await
            .map_err(|e| ctl_error("set_server_status", e))?;
        if !updated {
            return Err(McpError::invalid_params(
                format!("server `{server}` not found (it may have been removed concurrently)"),
                None,
            ));
        }
        state.upstreams.tool_catalog_epoch().mark_changed();
        self.record(
            principal,
            EvidenceCategory::AdminMutation,
            ControlEvidencePosture::ChainedBestEffort,
            "ServerQuarantined",
            server.clone(),
            reason.as_deref(),
        )
        .await;
        Ok(structured(&QuarantineResponse {
            server,
            state: "quarantined".to_owned(),
            updated: true,
        }))
    }

    async fn reconnect_server(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let params: ReconnectServerParams = parse_control_args(
            args,
            "reconnect_server",
            r#"{"server":"fetchlayer","clear_quarantine":true}"#,
        )?;
        let response = reconnect_server_core(self.state()?, &params)
            .await
            .map_err(|e| core_error("reconnect_server", e))?;
        self.record(
            principal,
            EvidenceCategory::UpstreamHealth,
            ControlEvidencePosture::BestEffort,
            "UpstreamReconnect",
            params.server.clone(),
            None,
        )
        .await;
        Ok(structured(&response))
    }

    async fn refresh_server_catalog(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let params: RefreshServerCatalogParams =
            parse_control_args(args, "refresh_server_catalog", r#"{"server":"fetchlayer"}"#)?;
        let response = refresh_server_catalog_core(self.state()?, principal, &params)
            .await
            .map_err(|e| core_error("refresh_server_catalog", e))?;
        Ok(structured(&response))
    }

    async fn reload_config(
        &self,
        principal: &Principal,
        args: &JsonObject,
    ) -> Result<CallToolResult, McpError> {
        let params: ConfigReloadParams =
            parse_control_args(args, "reload_config", r#"{"target":"both"}"#)?;
        let response = reload_config_core(self.state()?, principal.tenant.as_str(), &params)
            .await
            .map_err(|e| core_error("reload_config", e))?;
        self.record(
            principal,
            EvidenceCategory::AdminMutation,
            ControlEvidencePosture::BestEffort,
            "ConfigReloadTriggered",
            response.target.clone(),
            None,
        )
        .await;
        Ok(structured(&response))
    }
}

/// Static descriptor for the operator visibility surface and the dispatch-time
/// Cedar classification. Derived from [`tool_defs`] so it can't drift; every
/// control tool is a mutating operational lever — `High` risk with side
/// effects (none handle PII).
pub fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let tools = tool_defs()
        .into_iter()
        .map(|tool| CatalogTool::builtin(NAMESPACE, tool, RiskTier::High, true, false))
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        Scope::McpAdmin.as_str(),
        "Direct operational control levers (execute immediately under mcp:admin): quarantine an \
         upstream, recover a flapping upstream, refresh a healthy upstream's tool catalog, or \
         force a config reload.",
        tools,
    )
}

/// `quarantine_server` result — the server was pulled out of dispatch.
#[derive(Serialize, schemars::JsonSchema)]
struct QuarantineResponse {
    /// Catalog server name that was quarantined.
    server: String,
    /// Always `"quarantined"` on success (this tool is one-directional).
    state: String,
    /// `true` when the catalog status row was updated.
    updated: bool,
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(
            format!("{NAMESPACE}.quarantine_server"),
            "Quarantine an upstream server — pull it out of the per-call dispatch path now. \
             Incident-response lever for a misbehaving upstream; executes immediately under your \
             `mcp:admin` authority and is audited. Tenant-scoped. One-directional: RESTORING a \
             durably quarantined server to live requires the version-bound \
             `catalog.server.unquarantine` change action and is NOT exposed here — propose it \
             via the dashboard or `gateway-admin.propose_change`.",
            quarantine_server_schema(),
        )
        .with_title("Quarantine an upstream server")
        .with_output_schema::<QuarantineResponse>()
        // Pulls a server out of dispatch — disrupts live traffic (reversible via
        // reconnect, but impactful), so flag it destructive for confirmation UX.
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.reconnect_server"),
            "Recover a flapping or disconnected upstream server, optionally clearing its \
             tool-drift quarantine (`clear_quarantine: true`). A healthy connection is left \
             untouched; use `refresh_server_catalog` to replace a healthy session and fetch a \
             fresh tool inventory. Returns the resulting connection state and how many \
             drift-quarantined tools were cleared. Audited.",
            input_schema::<ReconnectServerParams>(),
        )
        .with_title("Reconnect an upstream server")
        .with_output_schema::<ReconnectResponse>()
        // Recovery / additive — restores a server, doesn't tear one down.
        .annotate(ToolAnnotations::new().read_only(false).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.refresh_server_catalog"),
            "Replace an upstream's MCP session even when it is healthy, fetch a fresh \
             `tools/list`, and atomically republish the manifest-classified inventory. The old \
             session keeps serving if every replacement dial fails. Use this when an upstream \
             added or removed tools without changing its manifest connection settings. Audited.",
            input_schema::<RefreshServerCatalogParams>(),
        )
        .with_title("Refresh an upstream tool catalog")
        .with_output_schema::<RefreshCatalogResponse>()
        // Replaces and drops a live MCP session even when it is healthy.
        .annotate(ToolAnnotations::new().read_only(false).destructive(true)),
        Tool::new(
            format!("{NAMESPACE}.reload_config"),
            "Nudge the policy and/or manifest reload doorbell so every gateway replica reconciles \
             to its active published pointer (force a reload without waiting for the periodic poll). \
             `target` = `policy` | `manifest` | `both` (default both). Idempotent; a target with \
             no published bundle is a no-op. Audited.",
            input_schema::<ConfigReloadParams>(),
        )
        .with_title("Reload policy / manifest config")
        .with_output_schema::<ConfigReloadResponse>()
        // Nudges a reconcile to the active published pointer; the description
        // notes it's idempotent and a no-op when nothing is published.
        .annotate(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(true),
        ),
    ]
}

fn quarantine_server_schema() -> Arc<JsonObject> {
    schema_obj(json!({
        "type": "object",
        "required": ["server"],
        "properties": {
            "server": {"type": "string", "description": "Catalog server name (in your tenant) to pull out of dispatch."},
            "reason": {"type": "string", "description": "Operator-readable justification, recorded in the audit row."}
        }
    }))
}

fn input_schema<T: schemars::JsonSchema>() -> Arc<JsonObject> {
    schema_obj(
        serde_json::to_value(schemars::schema_for!(T))
            .expect("schemars input schema serializes to JSON"),
    )
}

fn parse_control_args<T: DeserializeOwned>(
    args: &JsonObject,
    action: &str,
    example: &str,
) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(args.clone())).map_err(|e| {
        McpError::invalid_params(
            format!(
                "invalid `{action}` arguments: {e}; inspect this tool's inputSchema. Example: {example}"
            ),
            None,
        )
    })
}

fn core_error(what: &str, e: ApiError) -> McpError {
    match e {
        ApiError::NotFound(detail) => McpError::invalid_params(detail, None),
        ApiError::NotFoundDyn(detail)
        | ApiError::BadRequest(detail)
        | ApiError::UnprocessableEntity(detail) => McpError::invalid_params(detail, None),
        ApiError::BadGateway(detail) => McpError::internal_error(detail, None),
        other => {
            tracing::warn!(detail = %other.detail(), "gateway-control {what} failed");
            McpError::internal_error(format!("{what} failed"), None)
        }
    }
}

/// Map a control-action store failure to a generic MCP internal error — the
/// underlying error (which can name SQL/columns) is logged, never returned.
fn ctl_error<E: std::fmt::Display>(what: &str, e: E) -> McpError {
    tracing::warn!(error = %e, "gateway-control {what} failed");
    McpError::internal_error(format!("{what} failed"), None)
}

/// Read a REQUIRED non-empty string argument.
fn req_string(args: &JsonObject, key: &str) -> Result<String, McpError> {
    match args.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        _ => Err(McpError::invalid_params(
            format!("missing required non-empty string field `{key}`"),
            None,
        )),
    }
}

/// Read an optional string argument, rejecting a present-but-wrong-type value.
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

/// Structured insufficient-scope error mirroring the other built-in surfaces'
/// step-up shape.
fn insufficient_scope() -> McpError {
    let data = json!({
        "error": "insufficient_scope",
        "required_scope": Scope::McpAdmin.as_str(),
        "reason": "the gateway-control namespace requires the mcp:admin scope",
    });
    McpError::new(
        ErrorCode::INVALID_REQUEST,
        format!(
            "step-up required (scope `{}`): the gateway-control namespace requires mcp:admin",
            Scope::McpAdmin.as_str()
        ),
        Some(data),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use waygate_upstream::UpstreamPool;

    use super::*;

    #[test]
    fn surface_descriptor_matches_served_tools() {
        let prefix = format!("{NAMESPACE}.");
        let served: Vec<String> = tool_defs()
            .into_iter()
            .map(|t| t.name.as_ref().strip_prefix(&prefix).unwrap().to_owned())
            .collect();
        let d = surface_descriptor();
        let described: Vec<String> = d.tools.iter().map(|t| t.name.clone()).collect();
        assert_eq!(described, served);
        assert_eq!(d.namespace, NAMESPACE);
        assert_eq!(d.required_scope, Scope::McpAdmin.as_str());
        // Control tools are mutating operational levers — High risk + side effects.
        assert!(d
            .tools
            .iter()
            .all(|t| t.risk == RiskTier::High && t.side_effects));
    }

    #[test]
    fn control_tools_advertise_output_schema_and_title() {
        // Every control tool carries a title + output_schema (SOP points 4 + 5)
        // so a client knows the result shape without parsing prose. They are
        // mutations, so each is explicitly NOT read_only.
        for t in tool_defs() {
            assert!(t.title.is_some(), "{} missing title", t.name);
            assert!(
                t.output_schema.is_some(),
                "{} missing output_schema",
                t.name
            );
            assert_eq!(
                t.annotations.as_ref().and_then(|a| a.read_only_hint),
                Some(false),
                "{} is a mutation, not read_only",
                t.name
            );
        }
    }

    #[test]
    fn control_tools_advertise_derived_input_schemas() {
        let by_name: std::collections::HashMap<String, Arc<JsonObject>> = tool_defs()
            .into_iter()
            .map(|tool| (tool.name.to_string(), tool.input_schema))
            .collect();
        let properties = |name: &str| {
            by_name[name]
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} input schema has no properties"))
        };

        let reconnect = properties("gateway-control.reconnect_server");
        assert!(reconnect.contains_key("server"));
        assert!(reconnect.contains_key("clear_quarantine"));
        let refresh = properties("gateway-control.refresh_server_catalog");
        assert!(refresh.contains_key("server"));
        let reload = properties("gateway-control.reload_config");
        assert!(reload.contains_key("target"));
    }

    #[test]
    fn control_output_schemas_validate_sample_content() {
        // SOP (`docs/agents/mcp-tool-docs.md`): a tool's returned
        // structuredContent must validate against its advertised output_schema.
        // The schemas are derived from these response types, so this pins
        // serde↔schemars agreement on the wire shape — a sample that serializes
        // but fails its own schema is a drift the presence test wouldn't catch.
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

        assert_validates(&QuarantineResponse {
            server: "srv".to_owned(),
            state: "quarantined".to_owned(),
            updated: true,
        });
        // Both `cleared_tools` arms (Some / None) so the Option schema is exercised.
        assert_validates(&ReconnectResponse {
            server: "srv".to_owned(),
            connected: true,
            cleared_tools: Some(3),
        });
        assert_validates(&ReconnectResponse {
            server: "srv".to_owned(),
            connected: false,
            cleared_tools: None,
        });
        assert_validates(&RefreshCatalogResponse {
            server: "srv".to_owned(),
            outcome: "updated".to_owned(),
            session_replaced: true,
            before_tool_count: 1,
            after_tool_count: 2,
            added: vec!["new_tool".to_owned()],
            removed: Vec::new(),
            schema_changed: Vec::new(),
        });
        assert_validates(&ConfigReloadResponse {
            target: "both".to_owned(),
            triggered: vec!["policy".to_owned(), "manifest".to_owned()],
            fleet_wide: true,
        });
    }

    fn tools() -> ControlTools {
        // Empty AdminState cell: these tests exercise the authorization gate and
        // dispatch routing, which run BEFORE any state access.
        ControlTools::new(Arc::new(OnceLock::new()))
    }

    fn tools_with_empty_state() -> ControlTools {
        let state = Arc::new(AdminState::new(
            Arc::new(UpstreamPool::from_manifests_disconnected(BTreeMap::new())),
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".to_owned(),
        ));
        let cell = Arc::new(OnceLock::new());
        assert!(cell.set(state).is_ok());
        ControlTools::new(cell)
    }

    fn principal(scopes: &[&str]) -> Principal {
        Principal {
            sub: "operator".into(),
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
    async fn list_tools_gated_on_admin_scope() {
        let t = tools();
        assert!(t.list_tools(None).await.is_empty());
        // mcp:observe (read scope) does NOT unlock the control surface.
        assert!(t
            .list_tools(Some(&principal(&["mcp:observe"])))
            .await
            .is_empty());
        let admin: Vec<String> = t
            .list_tools(Some(&principal(&["mcp:admin"])))
            .await
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(
            admin,
            vec![
                "gateway-control.quarantine_server",
                "gateway-control.reconnect_server",
                "gateway-control.refresh_server_catalog",
                "gateway-control.reload_config",
            ]
        );
    }

    #[test]
    fn refresh_catalog_is_annotated_as_destructive() {
        let refresh = tool_defs()
            .into_iter()
            .find(|tool| tool.name.ends_with(".refresh_server_catalog"))
            .expect("refresh tool definition");

        assert_eq!(
            refresh
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.destructive_hint),
            Some(true),
            "replacing a healthy session must request confirmation UX",
        );
    }

    #[tokio::test]
    async fn peer_assertion_is_not_an_admin_even_with_scope() {
        // A federated Tier-C peer carrying mcp:admin must NOT drive control.
        let t = tools();
        let mut peer = principal(&["mcp:admin"]);
        peer.auth_method = AuthMethod::PeerAssertion;
        assert!(t.list_tools(Some(&peer)).await.is_empty());
        let err = t
            .call("reconnect_server", None, Some(&peer))
            .await
            .expect_err("peer must be refused");
        assert!(format!("{err}").contains("mcp:admin"), "got: {err}");
    }

    #[tokio::test]
    async fn call_without_admin_is_insufficient_scope() {
        let t = tools();
        let err = t
            .call("reload_config", None, None)
            .await
            .expect_err("no scope");
        assert!(format!("{err}").contains("mcp:admin"), "got: {err}");
        // A read-only observer cannot drive control.
        let err = t
            .call("reload_config", None, Some(&principal(&["mcp:observe"])))
            .await
            .expect_err("observe is not admin");
        assert!(format!("{err}").contains("mcp:admin"), "got: {err}");
    }

    #[tokio::test]
    async fn unknown_tool_is_invalid_params() {
        let t = tools();
        let err = t
            .call("bogus", None, Some(&principal(&["mcp:admin"])))
            .await
            .expect_err("unknown tool");
        assert!(
            format!("{err}").contains("unknown gateway-control tool"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn known_tool_with_unset_state_is_internal_error() {
        // A scoped caller on a known tool passes the gate, then hits the
        // unset-state guard — proving the scope check is not what blocks here.
        let t = tools();
        let args =
            serde_json::from_value(json!({"server": "fetchlayer"})).expect("valid reconnect args");
        let err = t
            .call(
                "reconnect_server",
                Some(args),
                Some(&principal(&["mcp:admin"])),
            )
            .await
            .expect_err("unset state");
        assert!(
            format!("{err}").contains("not yet initialised"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn reload_config_returns_structured_fleet_no_op() {
        let result = tools_with_empty_state()
            .call("reload_config", None, Some(&principal(&["mcp:admin"])))
            .await
            .expect("reload without published pointers is a no-op");
        assert_eq!(
            result.structured_content,
            Some(json!({
                "target": "both",
                "triggered": [],
                "fleet_wide": false,
            }))
        );
    }

    #[tokio::test]
    async fn refresh_catalog_teaches_unknown_upstream_error() {
        let args =
            serde_json::from_value(json!({"server": "fetchlayer"})).expect("valid refresh args");
        let error = tools_with_empty_state()
            .call(
                "refresh_server_catalog",
                Some(args),
                Some(&principal(&["mcp:admin"])),
            )
            .await
            .expect_err("unknown upstream must be rejected");
        assert!(
            format!("{error}").contains("upstream server `fetchlayer`"),
            "got: {error}"
        );
    }
}
