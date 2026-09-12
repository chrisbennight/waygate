//! Per-request `GatewayServer` construction for the streamable-HTTP mount.
//!
//! The composition root gathers the shared handles once into
//! [`McpServerFactory`]; rmcp invokes [`McpServerFactory::build`] for every
//! legacy session and every stateless 2026-07-28 request. Everything here
//! is `Arc`-backed, so a build is cheap; state that must outlive one build
//! (such as the catalog epoch) lives in the factory and is shared into each
//! `GatewayServer`.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use waygate_mcp::GatewayServer;

use crate::config::CodeModeResultStorage;
use crate::{mcp_builtin, mcp_codemode, mcp_control, mcp_discovery, mcp_observe};

/// Shared dependencies for building one `GatewayServer` per rmcp request or
/// session. Field meanings match the composition-root bindings in
/// `main.rs`; see each consumer for the deeper contracts.
pub(crate) struct McpServerFactory {
    pub catalog: waygate_mcp::SharedCatalog,
    pub catalog_store: Option<waygate_catalog::SharedCatalogStore>,
    pub authz: waygate_mcp::SharedAuthz,
    pub audit: waygate_mcp::SharedEvidence,
    pub index: Option<waygate_mcp::SearchIndex>,
    pub tool_catalog_epoch: waygate_mcp::ToolCatalogEpoch,
    pub audit_mode: waygate_mcp::AuditMode,
    pub result_storage: CodeModeResultStorage,
    pub execution_limit: std::time::Duration,
    pub execution_capacity: Arc<mcp_codemode::CodeModeExecutionCapacity>,
    pub quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    pub hitl_hub: Arc<waygate_admin::hitl_ws::ApprovalHub>,
    pub inspectors: Vec<waygate_mcp::inspection::SharedInspector>,
    pub resource_response_max_bytes: usize,
    pub file_input_processor: Option<waygate_mcp::files::SharedFileInputProcessor>,
    pub file_output_processor: Option<waygate_mcp::files::SharedFileOutputProcessor>,
    pub source_file_reader: Option<crate::file_transfer::SharedStoredTextReader>,
    /// Seals MRTR continuation state; `None` when no key is configured.
    pub continuation_sealer: Option<Arc<waygate_mcp::invocation::continuation::ContinuationSealer>>,
    /// Authenticates stateless tool-list cursors across request-scoped server
    /// instances and, when a deployment key is configured, replicas.
    pub tool_list_cursor_sealer: waygate_mcp::SharedToolListCursorSealer,
    pub skills: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    pub reviewed_skills: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    /// Authenticates gateway-discovery search cursors across request-scoped
    /// handlers and replicas while keeping them bound to one authorized view.
    pub discovery_cursor_sealer: Arc<mcp_discovery::DiscoveryCursorSealer>,
    pub gateway_file_tools: Option<waygate_mcp::builtin::SharedBuiltinTools>,
    pub native_file_download_authorizer: Option<waygate_mcp::files::SharedFileDownloadAuthorizer>,
    pub native_file_upload_authorizer: Option<waygate_mcp::files::SharedFileUploadAuthorizer>,
    pub llm_deps: Option<crate::llm::LlmDeps>,
    pub llm_usage_store: Option<waygate_mcp::SharedLlmUsage>,
    pub llm_budget_gate: Option<waygate_mcp::SharedLlmBudgetGate>,
    pub llm_cache_store: Option<waygate_mcp::cache::SharedLlmCache>,
    pub schema_validator_cache: Arc<waygate_mcp::SchemaValidatorCache>,
    /// The built-in `gateway-admin.*` MCP tool surface needs the same
    /// change-request store the REST surface uses plus the public URL for
    /// the approval link; `audit` doubles as the evidence sink for the
    /// propose audit, and the same out-of-band notifier fires so an
    /// MCP-proposed change pushes a heads-up too.
    pub change_request_store: Option<waygate_changeset::SharedChangeRequestStore>,
    pub codemode_db_pool: Option<sqlx::PgPool>,
    pub change_notifier: Option<waygate_admin::change_notify::SharedChangeNotifier>,
    pub public_url: String,
    /// Deferred `AdminState` cell: each built `ChangeProposalTools` /
    /// `ObserveTools` / `ControlTools` shares the one handle the
    /// composition root fills after building `AdminState`.
    pub admin_state_cell: Arc<OnceLock<Arc<waygate_admin::AdminState>>>,
    pub eager_tools_list: bool,
    pub eager_tools_clients: Vec<String>,
    pub codemode_only_tools_clients: Vec<String>,
    pub audit_discovery: bool,
    pub idjag_advertise_ema: bool,
    pub mcp_ping_interval: Option<Duration>,
}

impl McpServerFactory {
    /// Build one `GatewayServer`. Fail-closed wiring: the operator's
    /// `GATEWAY_AUDIT_MODE` posture threads into the per-build
    /// `DefaultInvocationService` so the `record_pre_call` stage can branch
    /// on it. Construction is delegated to the shared
    /// `build_default_invocation_service` helper so the admin dashboard's
    /// governed "Try this tool" surface gets a byte-for-byte identical
    /// pipeline (same audit_mode, catalog_store, quota, HITL notifier,
    /// inspector chain). A new governance stage added there lands on both
    /// paths; the try-it surface can never silently run a weaker one.
    pub fn build(&self) -> Result<GatewayServer, std::io::Error> {
        let invocation = waygate_mcp::build_default_invocation_service(
            self.catalog.clone(),
            self.authz.clone(),
            self.audit.clone(),
            self.audit_mode,
            self.catalog_store.clone(),
            self.quota.clone(),
            Some(self.hitl_hub.clone() as waygate_invocation::SharedHitlNotifier),
            self.inspectors.clone(),
            self.file_input_processor.clone(),
            self.file_output_processor.clone(),
            self.continuation_sealer.clone(),
            self.schema_validator_cache.clone(),
            self.llm_deps.as_ref().map(crate::llm::deps_as_dyn),
            self.llm_usage_store.clone(),
            self.llm_budget_gate.clone(),
            self.llm_cache_store.clone(),
        );
        let mut server =
            GatewayServer::with_deps(self.catalog.clone(), self.authz.clone(), self.audit.clone())
                .with_eager_tools_list(self.eager_tools_list)
                .with_eager_tools_clients(self.eager_tools_clients.clone())
                .with_codemode_only_tools_clients(self.codemode_only_tools_clients.clone())
                .with_audit_discovery(self.audit_discovery)
                .with_ema_capability_advert(self.idjag_advertise_ema)
                .with_client_ping_interval(self.mcp_ping_interval)
                .with_tool_catalog_epoch(&self.tool_catalog_epoch)
                .with_tool_list_cursor_sealer(self.tool_list_cursor_sealer.clone())
                .with_skill_catalog(self.skills.clone())
                .with_reviewed_skills(self.reviewed_skills.clone())
                .with_file_download_authorizer(self.native_file_download_authorizer.clone())
                .with_file_upload_authorizer(self.native_file_upload_authorizer.clone())
                .with_file_output_processor(self.file_output_processor.clone())
                .with_resource_response_max_bytes(self.resource_response_max_bytes)
                .with_resource_inspectors(self.inspectors.clone())
                .with_invocation_service(invocation.clone());
        if let Some(idx) = self.index.as_ref() {
            server = server.with_index(idx.clone());
        }
        let registry = waygate_mcp::BuiltinRegistry::default();
        let mut builtins: Vec<waygate_mcp::SharedBuiltinTools> = Vec::new();
        if self.skills.is_some() {
            builtins.push(Arc::new(waygate_mcp::server::skill_tools::SkillTools::new(
                server.clone(),
            )));
        }
        if let Some(tools) = self.gateway_file_tools.as_ref() {
            builtins.push(tools.clone());
        }
        // The built-in `gateway-admin.*` MCP tools (propose /
        // get_change_status / list_my_changes) mount when the
        // change-request store is configured. REST and MCP share one queue.
        if let Some(store) = self.change_request_store.as_ref() {
            builtins.push(Arc::new(mcp_builtin::ChangeProposalTools::new(
                store.clone(),
                self.audit.clone(),
                self.public_url.clone(),
                self.change_notifier.clone(),
                self.quota.clone(),
                self.admin_state_cell.clone(),
            )));
        }
        // The read-only `gateway-observe.*` MCP tools (query_audit /
        // activity_summary / simulate_authorization / triage_digest), gated
        // on `mcp:observe` (or `mcp:admin`). They read whatever the shared
        // `AdminState` exposes (audit reader, Cedar engine, catalog,
        // break-glass), so they share the same deferred cell as the
        // change-proposal tools and need no store gate of their own — a
        // missing store surfaces as a clean per-call error.
        builtins.push(Arc::new(mcp_observe::ObserveTools::new(
            self.admin_state_cell.clone(),
        )));
        // The direct `gateway-control.*` MCP tools (quarantine_server /
        // reconnect_server / refresh_server_catalog / reload_config), gated
        // on `mcp:admin`. They execute immediately under the caller's
        // authority (reversible operational levers only — promoting a
        // server to live stays a governed approval action) and record an
        // attribution evidence row. Same deferred `AdminState` cell.
        builtins.push(Arc::new(mcp_control::ControlTools::new(
            self.admin_state_cell.clone(),
        )));
        // Build discovery before Code Mode so the latter can retain every
        // non-recursive gateway-local handler for detached execution.
        let discovery = Arc::new(
            mcp_discovery::DiscoveryTools::new(
                waygate_mcp::AuthorizedCatalog::new(
                    self.catalog.clone(),
                    self.authz.clone(),
                    registry.clone(),
                ),
                self.tool_catalog_epoch.clone(),
            )
            .with_cursor_sealer(self.discovery_cursor_sealer.clone()),
        ) as waygate_mcp::SharedBuiltinTools;
        builtins.push(discovery);
        builtins.push(mcp_codemode::configured_tools(
            self.catalog.clone(),
            self.authz.clone(),
            invocation,
            self.codemode_db_pool.clone(),
            mcp_codemode::CodeModeSourceProviders {
                builtins: registry.clone(),
                builtin_handlers: builtins.clone(),
                audit: self.audit.clone(),
                source_file_reader: self.source_file_reader.clone(),
                skill_catalog: self.skills.clone(),
                reviewed_skills: self.reviewed_skills.clone(),
            },
            self.quota.clone(),
            mcp_codemode::CodeModeSettings {
                result_storage: self.result_storage,
                execution_limit: self.execution_limit,
                execution_capacity: self.execution_capacity.clone(),
                tool_catalog_epoch: self.tool_catalog_epoch.clone(),
                search_cursor_sealer: self.discovery_cursor_sealer.clone(),
            },
        ));
        // Discovery observes every live built-in through weak handles. The
        // server takes strong ownership of the complete set; Code Mode retains
        // its sibling handlers independently for detached work.
        registry.replace(&builtins);
        for builtin in builtins {
            server = server.with_builtin_tools(builtin);
        }
        Ok(server)
    }
}
