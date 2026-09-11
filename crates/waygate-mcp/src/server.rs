//! `GatewayServer` — the `rmcp::ServerHandler` the gateway mounts at `/mcp`.
//!
//! `list_tools` projects one stable full catalog for MCP 2026 clients and the
//! legacy session-local `searchTools` compatibility view for older clients.
//! `call_tool` either services a search invocation directly or proxies a
//! fully-qualified `<server>.<tool>` call to the upstream pool.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ClientCapabilities,
    CreateTaskResult, CustomRequest, CustomResult, DetailedTask, ElicitRequest,
    ElicitRequestParams, ElicitationSchema, ExtensionCapabilities, GetTaskParams, GetTaskResult,
    Implementation, InputRequest, InputRequiredResult, JsonObject, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, ResourceContents,
    ResultType, ServerCapabilities, ServerInfo, TaskPayload, TaskStatus, Tool, ToolAnnotations,
    UpdateTaskParams, TASKS_EXTENSION_ID,
};
use rmcp::service::{Peer, RequestContext};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use waygate_oidc::Principal;

use crate::audit::{AuditEvent, AuditOutcome, EvidenceCategory, NullSink, SharedEvidence};
use crate::authz::{
    profile_blocks_resources, profile_blocks_server, profile_blocks_tool, AllowAllGate,
    AuthzVerdict, BuiltinAuthz, SharedAuthz, SkillAccessFacts,
};
#[path = "skill_tools.rs"]
pub mod skill_tools;

use crate::builtin::{BuiltinCatalog, BuiltinProfileScope};
use crate::catalog::{
    AdmittedResourceReadError, ResolvedInvocationTool, ResourceClaim, ResourceReadAdmission,
    SharedCatalog,
};
use crate::catalog_changes::ToolCatalogEpoch;
use crate::compat::search_tools_v1::{
    self, Mode, OperationDescriptor, OperationsResponse, SearchToolsRequest, SearchToolsResponse,
    TypesResponse,
};
use crate::disclosed::{DisclosedStore, DisclosedTools};
use crate::discovery::CatalogTool;
use crate::index::{self, SearchIndex};
use crate::invocation::DefaultInvocationService;
use crate::protocol::RiskTier;
use crate::request_meta::{ClientContext, ProtocolGeneration};
use crate::tool_schema::{
    input_schema_has_object_root, make_tool_schemas_portable, portable_schema_object,
};
use waygate_invocation::{InvocationError, InvocationRequest, SharedInvocation};

const SEARCH_TOOLS_SUFFIX: &str = ".searchTools";
const MAX_CATALOG_SNAPSHOT_RETRIES: usize = 3;
const MAX_RESOURCE_CURSOR_BYTES: usize = 4096;
const MAX_RESOURCE_RESOLUTION_PAGES: usize = 50;
const MAX_RESOURCE_TEMPLATES: usize = 4096;
const MAX_RESOURCE_TEMPLATE_BYTES: usize = 4 * 1024 * 1024;
const RESOURCE_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default raw response budget for one native `resources/read` request.
/// Governed file responses still fit because the bounded body carries only
/// the descriptor; the file service applies its independent storage limit to
/// the transferred bytes.
pub const DEFAULT_RESOURCE_RESPONSE_MAX_BYTES: usize = 4 * 1024 * 1024;
const RESOURCE_INSPECTION_BLOCKED_ERROR: &str = "response_inspection_blocked";
const FULL_CATALOG_INSTRUCTIONS: &str =
    "Call tools as `<server>.<toolName>`; the authorized catalog is in `tools/list`.";
const LEGACY_SEARCH_INSTRUCTIONS: &str =
    "Use `<server>.searchTools` to discover tools or schemas; call results as `<server>.<toolName>`.";
const CODEMODE_ONLY_INSTRUCTIONS: &str =
    "Use `codemode.search` to discover governed operations and `codemode.describe` for exact schemas. `codemode.execute` can invoke every operation this client is directly authorized to call; `codemode.mutate` is a compatibility alias with the same authority. Upstream tools are not listed directly for this client.";

/// Audit actions for native MCP resource access. These match the Cedar action
/// names evaluated by the gate, so Decision Log rows use the same vocabulary
/// operators write in policy.
const READ_RESOURCE_ACTION: &str = "ReadResource";
const LIST_SKILLS_ACTION: &str = "ListSkills";
const FETCH_SKILL_RESOURCE_ACTION: &str = "FetchSkillResource";
const READ_SKILL_ACTION: &str = "ReadSkill";
const GATEWAY_SKILLS_SERVER: &str = waygate_core::SKILLS_SERVER_NAMESPACE;

/// Apply the same Cedar forbid overlay used by ordinary built-in dispatch.
///
/// Built-in handlers retain their namespace-specific scope floor. This helper
/// applies the operator's current Cedar restrictions and records accountable
/// refusals. Nested orchestrators may supply their invocation hierarchy so the
/// decision remains attributable to its parent execution.
pub async fn authorize_builtin_call(
    authz: &SharedAuthz,
    audit: &SharedEvidence,
    catalog: &BuiltinCatalog,
    tool: &str,
    principal: Option<&Principal>,
    hierarchy: Option<waygate_core::InvocationHierarchy>,
) -> Result<(), McpError> {
    let Some(p) = principal else { return Ok(()) };
    let Some(record) = catalog
        .tools
        .iter()
        .find(|entry| entry.identity.name == tool)
    else {
        return Err(McpError::internal_error(
            format!(
                "built-in catalog has no governance record for {}.{tool}",
                catalog.namespace
            ),
            Some(serde_json::json!({
                "error": "builtin_catalog_inconsistent",
            })),
        ));
    };
    let facts = record.facts.clone();
    let (di_scopes, di_auth_method, di_roles, di_side_effects) =
        crate::invocation::decision_inputs(Some(p), &facts);
    match authz.authorize_builtin_call(p, &facts).await {
        BuiltinAuthz::Proceed => Ok(()),
        BuiltinAuthz::Forbidden {
            reason,
            policy_ids,
            reasons,
        } => {
            audit
                .record_chained_best_effort(
                    AuditEvent::new("CallTool", AuditOutcome::Denied)
                        .with_principal(Some(p))
                        .with_tool(catalog.namespace.as_str(), tool)
                        .with_risk(facts.risk)
                        .with_pii(facts.pii)
                        .with_policies(policy_ids.clone())
                        .with_decision_inputs(di_scopes, di_auth_method, di_roles, di_side_effects)
                        .with_invocation_hierarchy(hierarchy)
                        .with_reason(&reason),
                )
                .await;
            let data = serde_json::json!({
                "error": "forbidden",
                "reason": reason,
                "policy_ids": policy_ids,
                "reasons": reasons,
            });
            Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("forbidden: {}.{} — {}", catalog.namespace, tool, reason),
                Some(data),
            ))
        }
        BuiltinAuthz::StepUpRequired {
            required_scope,
            reason,
            policy_ids,
        } => {
            audit
                .record_chained_best_effort(
                    AuditEvent::new("CallTool", AuditOutcome::StepUpRequired)
                        .with_principal(Some(p))
                        .with_tool(catalog.namespace.as_str(), tool)
                        .with_risk(facts.risk)
                        .with_pii(facts.pii)
                        .with_policies(policy_ids)
                        .with_decision_inputs(di_scopes, di_auth_method, di_roles, di_side_effects)
                        .with_invocation_hierarchy(hierarchy)
                        .with_reason(format!("scope {required_scope}: {reason}")),
                )
                .await;
            let data = serde_json::json!({
                "error": "insufficient_scope",
                "required_scope": required_scope,
                "reason": reason,
            });
            Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("step-up required (scope `{required_scope}`): {reason}"),
                Some(data),
            ))
        }
        BuiltinAuthz::Indeterminate { reason } => {
            audit
                .record_chained_best_effort(
                    AuditEvent::new("CallTool", AuditOutcome::Denied)
                        .with_principal(Some(p))
                        .with_tool(catalog.namespace.as_str(), tool)
                        .with_risk(facts.risk)
                        .with_pii(facts.pii)
                        .with_invocation_hierarchy(hierarchy)
                        .with_reason(format!(
                            "authorization unavailable (failed closed): {reason}"
                        )),
                )
                .await;
            let data = serde_json::json!({
                "error": "authorization_unavailable",
                "reason": reason,
            });
            Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!(
                    "authorization unavailable for {}.{}; failing closed",
                    catalog.namespace, tool
                ),
                Some(data),
            ))
        }
    }
}

/// Which direct-tool projection a `tools/list` request receives.
///
/// The 2026 protocol uses `Full`: one stable, authorization-filtered catalog
/// that is independent of prior calls. Legacy sessions may still use their
/// session-local disclosure record for the closed-draft `searchTools`
/// compatibility adapter.
#[derive(Clone, Copy)]
enum ToolProjection<'a> {
    Full { canonical_order: bool },
    SessionDisclosed(&'a DisclosedTools),
    BuiltinsOnly { canonical_order: bool },
}

/// Resolution of the one qualified name shared by the compatibility adapter
/// and a possible ordinary upstream `searchTools` tool.
enum SearchToolsNameResolution {
    /// The caller cannot discover the upstream itself. Return the same shape
    /// as an unknown server before inspecting either meaning of the name.
    ServerHidden,
    /// No caller-visible, admitted ordinary tool occupies the name.
    Adapter,
    /// A caller-visible, admitted ordinary upstream tool occupies the name.
    DirectTool,
}

/// The answer for a URI no upstream this caller can see advertises — and,
/// deliberately, the same answer an outright denial gets. A caller with no
/// standing on a resource learns nothing about whether it exists; the denial
/// is accountable in its audit row instead.
fn unadvertised_resource() -> McpError {
    McpError::resource_not_found("resource URI is not advertised by a visible upstream", None)
}

/// The common shape of a resource-read decision row: attributable to the
/// principal, naming the URI it acted on, and carrying the inputs a Cedar
/// decision can branch on so a recorded read can be re-evaluated the way a
/// recorded tool call can.
///
/// `server` is left to the caller — some outcomes resolve to exactly one
/// upstream, some to none, and an ambiguous read to several. `side_effects` is
/// None rather than false: a read carries no side-effect classification, and
/// claiming one would put a fact in the row that no policy actually saw.
fn resource_decision_event(principal: &Principal, uri: &str, outcome: AuditOutcome) -> AuditEvent {
    AuditEvent::new(READ_RESOURCE_ACTION, outcome)
        .with_category(EvidenceCategory::Invocation)
        .with_principal(Some(principal))
        .with_tenant(principal.tenant.clone())
        .with_target(uri.to_owned())
        .with_decision_inputs(
            principal.scopes.clone(),
            Some(principal.auth_method.as_str().to_owned()),
            principal.roles.clone(),
            None,
        )
}

fn skill_catalog_facts(snapshot: &waygate_skills::SkillCatalogSnapshot) -> SkillAccessFacts {
    SkillAccessFacts {
        source_origin: snapshot.source().origin.clone(),
        artifact_digest: snapshot.source().resolved_digest.clone(),
        source_tree_digest: snapshot.source().resolved_tree_digest.clone(),
        skill_uri: None,
        resource_uri: None,
        revision_digest: None,
        content_digest: None,
        source_path: None,
        source_object: None,
    }
}

fn skill_resource_facts(identity: &waygate_skills::SkillResourceIdentity) -> SkillAccessFacts {
    SkillAccessFacts {
        source_origin: identity.revision.source_origin.clone(),
        artifact_digest: identity.revision.artifact_digest.clone(),
        source_tree_digest: identity.revision.source_tree_digest.clone(),
        skill_uri: Some(identity.revision.skill_uri.clone()),
        resource_uri: Some(identity.resource_uri.clone()),
        revision_digest: Some(identity.revision.revision_digest.clone()),
        content_digest: Some(identity.resource_digest.clone()),
        source_path: Some(identity.source_path.clone()),
        source_object: Some(identity.source_object.clone()),
    }
}

fn skill_resource_fetch_facts(
    snapshot: &waygate_skills::SkillCatalogSnapshot,
    descriptor: &waygate_skills::SkillResourceDescriptor,
) -> SkillAccessFacts {
    let revision = snapshot
        .revision_identity(&descriptor.uri)
        .expect("verified resource has an owning skill revision");
    SkillAccessFacts {
        source_origin: revision.source_origin,
        artifact_digest: revision.artifact_digest,
        source_tree_digest: revision.source_tree_digest,
        skill_uri: Some(revision.skill_uri),
        resource_uri: Some(descriptor.uri.clone()),
        revision_digest: Some(revision.revision_digest),
        content_digest: None,
        source_path: Some(descriptor.source_path.clone()),
        source_object: Some(descriptor.source_object.clone()),
    }
}

fn skill_catalog_target(snapshot: &waygate_skills::SkillCatalogSnapshot) -> String {
    json!({
        "source_origin": snapshot.source().origin,
        "artifact_digest": snapshot.source().resolved_digest,
        "source_tree_digest": snapshot.source().resolved_tree_digest,
    })
    .to_string()
}

fn skill_resource_target(identity: &waygate_skills::SkillResourceIdentity) -> String {
    serde_json::to_string(identity).expect("verified skill identity is serializable")
}

fn skill_resource_fetch_target(facts: &SkillAccessFacts) -> String {
    json!({
        "source_origin": facts.source_origin,
        "artifact_digest": facts.artifact_digest,
        "source_tree_digest": facts.source_tree_digest,
        "skill_uri": facts.skill_uri,
        "resource_uri": facts.resource_uri,
        "revision_digest": facts.revision_digest,
        "source_path": facts.source_path,
        "source_object": facts.source_object,
    })
    .to_string()
}

fn post_authorization_skill_refusal_reason(error: &McpError) -> String {
    format!(
        "{}{}",
        waygate_core::SKILL_POST_AUTHORIZATION_REFUSAL_PREFIX,
        error.message
    )
}

fn skill_list_decision_event(
    principal: &Principal,
    snapshot: &waygate_skills::SkillCatalogSnapshot,
    outcome: AuditOutcome,
) -> AuditEvent {
    AuditEvent::new(LIST_SKILLS_ACTION, outcome)
        .with_category(EvidenceCategory::Invocation)
        .with_principal(Some(principal))
        .with_tenant(principal.tenant.clone())
        .with_target(skill_catalog_target(snapshot))
        .with_server(GATEWAY_SKILLS_SERVER)
        .with_risk(RiskTier::Low)
        .with_decision_inputs(
            principal.scopes.clone(),
            Some(principal.auth_method.as_str().to_owned()),
            principal.roles.clone(),
            None,
        )
}

fn skill_read_decision_event(
    principal: &Principal,
    identity: &waygate_skills::SkillResourceIdentity,
    outcome: AuditOutcome,
) -> AuditEvent {
    AuditEvent::new(READ_SKILL_ACTION, outcome)
        .with_category(EvidenceCategory::Invocation)
        .with_principal(Some(principal))
        .with_tenant(principal.tenant.clone())
        .with_target(skill_resource_target(identity))
        .with_server(GATEWAY_SKILLS_SERVER)
        .with_risk(RiskTier::Low)
        .with_decision_inputs(
            principal.scopes.clone(),
            Some(principal.auth_method.as_str().to_owned()),
            principal.roles.clone(),
            None,
        )
}

fn skill_fetch_decision_event(
    principal: &Principal,
    facts: &SkillAccessFacts,
    outcome: AuditOutcome,
) -> AuditEvent {
    AuditEvent::new(FETCH_SKILL_RESOURCE_ACTION, outcome)
        .with_category(EvidenceCategory::Invocation)
        .with_principal(Some(principal))
        .with_tenant(principal.tenant.clone())
        .with_target(skill_resource_fetch_target(facts))
        .with_server(GATEWAY_SKILLS_SERVER)
        .with_risk(RiskTier::Low)
        .with_decision_inputs(
            principal.scopes.clone(),
            Some(principal.auth_method.as_str().to_owned()),
            principal.roles.clone(),
            None,
        )
}

fn skill_refusal(verdict: &AuthzVerdict) -> (AuditOutcome, &[String], String) {
    match verdict {
        AuthzVerdict::Deny {
            reason, policy_ids, ..
        } => (AuditOutcome::Denied, policy_ids, reason.clone()),
        AuthzVerdict::StepUpRequired {
            required_scope,
            reason,
            policy_ids,
        } => (
            AuditOutcome::StepUpRequired,
            policy_ids,
            format!("scope {required_scope}: {reason}"),
        ),
        AuthzVerdict::ApprovalRequired { reason, policy_ids } => (
            AuditOutcome::Denied,
            policy_ids,
            format!("approval required: {reason}"),
        ),
        AuthzVerdict::Allow { policy_ids } => {
            (AuditOutcome::Success, policy_ids, "authorized".to_owned())
        }
    }
}

/// How much a refusal gives the caller to act on, so a URI served by several
/// upstreams answers with the most useful of their verdicts rather than with
/// whichever one the fleet listed first. A condition the caller can satisfy
/// outranks one they cannot.
fn verdict_actionability(verdict: &AuthzVerdict) -> u8 {
    match verdict {
        AuthzVerdict::Allow { .. } => 3,
        AuthzVerdict::StepUpRequired { .. } => 2,
        AuthzVerdict::ApprovalRequired { .. } => 1,
        AuthzVerdict::Deny { .. } => 0,
    }
}

/// Reported only once the caller is known to be able to read more than one of
/// the advertising upstreams, so it discloses nothing `resources/list` would
/// not already show them.
fn ambiguous_resource(uri: &str) -> McpError {
    McpError::invalid_params(
        format!("resource URI `{uri}` is advertised by multiple upstreams"),
        None,
    )
}

fn public_resource_read_error(error: AdmittedResourceReadError) -> McpError {
    error.into_mcp_error()
}

fn resource_inspection_error(inspector_name: &'static str, reason: String) -> McpError {
    McpError::internal_error(
        "resource response was blocked by output inspection",
        Some(json!({
            "error": RESOURCE_INSPECTION_BLOCKED_ERROR,
            "tool": "resources/read",
            "inspector_name": inspector_name,
            "reason": reason,
        })),
    )
}

struct ResourceInspectionBlock {
    inspector_name: &'static str,
    reason: String,
}

#[derive(Debug, Clone)]
struct ResourceOwner {
    server: String,
    risk: RiskTier,
    admission: ResourceReadAdmission,
}

fn resource_result_has_file_contents(result: &ReadResourceResult) -> bool {
    result.contents.iter().any(|contents| {
        let meta = match contents {
            ResourceContents::TextResourceContents { meta, .. }
            | ResourceContents::BlobResourceContents { meta, .. } => meta.as_ref(),
            _ => None,
        };
        meta.is_some_and(|meta| meta.contains_key(crate::files::FILE_RESOURCE_CONTENT_META_KEY))
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct ResourceCursor {
    server: String,
    upstream_cursor: Option<String>,
    #[serde(default = "default_resource_pages_remaining")]
    pages_remaining: usize,
    #[serde(default)]
    seen_upstream_cursors: Vec<String>,
}

const fn default_resource_pages_remaining() -> usize {
    MAX_RESOURCE_RESOLUTION_PAGES
}

fn resource_cursor_fingerprint(cursor: &str) -> String {
    blake3::hash(cursor.as_bytes()).to_hex()[..32].to_owned()
}

/// SEP-1724 extension identifier for MCP Enterprise-Managed Authorization
/// (`io.modelcontextprotocol/enterprise-managed-authorization`). Advertised in
/// `ServerCapabilities.extensions` (with an empty settings object) when EMA is
/// enabled, so EMA-aware clients discover the gateway accepts ID-JAGs. See
/// [`GatewayServer::with_ema_capability_advert`].
pub const EMA_EXTENSION_ID: &str = "io.modelcontextprotocol/enterprise-managed-authorization";

#[derive(Clone)]
pub struct GatewayServer {
    catalog: SharedCatalog,
    /// Authz gate retained on `GatewayServer` (alongside being threaded
    /// into `DefaultInvocationService`) because the discovery / list
    /// paths consult `may_discover_server` / `may_call_tool` directly to
    /// filter the meta-tool catalog and search results. Those paths
    /// don't go through `InvocationService` (yet — `discover` lands in
    /// a later phase per the plan), so the gate has to stay reachable
    /// from here too.
    authz: SharedAuthz,
    /// BM25 index used when `searchTools` carries a `query`. `None` means the
    /// handler falls back to a linear substring scan — acceptable in tests
    /// that don't bother wiring an index, fail-open rather than empty
    /// result set in production.
    index: Option<SearchIndex>,
    /// Tools this session has discovered via `searchTools`. Surfaced in
    /// subsequent `tools/list` responses so strict clients (which refuse to
    /// invoke tools that never appeared in `tools/list`) can still call them.
    /// Per-session isolation is provided by the `StreamableHttpService`
    /// factory, which creates a fresh `GatewayServer` per session.
    disclosed: DisclosedTools,
    /// Transitional composition seam retained until the obsolete stateless
    /// store is removed. No 2026 request reads or writes it; legacy clients
    /// use only [`Self::disclosed`], their session-local record.
    _disclosed_store: Arc<DisclosedStore>,
    /// When true, legacy-session `tools/list` returns the full upstream
    /// catalog alongside the meta-tools. The 2026 projection is always full.
    eager_tools_list: bool,
    /// Exact MCP `clientInfo.name` matches that opt only their own legacy
    /// session into eager discovery while other legacy clients stay progressive.
    eager_tools_clients: Vec<String>,
    /// Set during `initialize` when this session's client name matches
    /// [`Self::eager_tools_clients`]. Shared across clones of this one session.
    client_eager_tools_list: Arc<AtomicBool>,
    /// Exact MCP `clientInfo.name` matches whose tool catalog contains only
    /// authorized gateway built-ins. This keeps the Code Mode facade available
    /// to clients that can neither accept the full upstream catalog nor refresh
    /// a progressively disclosed direct-tool list.
    codemode_only_tools_clients: Vec<String>,
    /// Set during legacy `initialize` when the session selected the compact
    /// Code Mode-only projection. Stateless requests match their inline client
    /// name independently.
    client_codemode_only_tools_list: Arc<AtomicBool>,
    /// The `InvocationService` handle. The constructors below
    /// build a `DefaultInvocationService` from the same `catalog` /
    /// `authz` / `audit` deps callers used to pass in; the
    /// [`with_invocation_service`](Self::with_invocation_service)
    /// setter lets a future composition root swap in a decorator
    /// (fail-closed wrapper, quota-gated wrapper, etc.) without
    /// touching this crate.
    invocation: SharedInvocation,
    /// Audit sink for SEP #1888 discovery events. The same handle
    /// the invocation service uses, retained here because the discovery
    /// path does not go through `InvocationService`, so it needs its own
    /// way to record a best-effort `Discovery` row. Gated by
    /// `audit_discovery`.
    audit: SharedEvidence,
    /// When true, each `searchTools` call records a best-effort `Discovery`
    /// audit row. Off by default (discovery is high-volume; opt in via
    /// `GATEWAY_AUDIT_DISCOVERY`). See
    /// [`with_audit_discovery`](Self::with_audit_discovery).
    audit_discovery: bool,
    /// Gateway-local tool namespaces (e.g. `gateway-admin.*`,
    /// `gateway-observe.*`, `gateway-control.*`). Calls whose name is in one of
    /// these namespaces are answered by the gateway itself instead of proxied
    /// to an upstream, and each namespace's tools are appended to `tools/list`
    /// (scope-gated by the impl). Empty ⇒ no built-in tools (proxy-only
    /// behavior). Each handle owns a distinct `namespace()`; the load-time guard
    /// in `waygate_upstream` keeps an upstream from colliding with any of them.
    builtins: Vec<crate::builtin::SharedBuiltinTools>,
    /// When true, `get_info` advertises the EMA capability:
    /// `io.modelcontextprotocol/enterprise-managed-authorization` extension in
    /// `ServerCapabilities.extensions` (SEP-1724) so EMA-aware clients discover
    /// the gateway accepts ID-JAG token-exchange/redeem. Off by default until an
    /// operator opts in (`GATEWAY_AS_IDJAG_ADVERTISE=true`, and only when the AS
    /// and EMA deps are actually wired) — advertising a grant the AS can't
    /// service would break discovery for the working OAuth/API-key path.
    advertise_ema: bool,
    /// Interval between server-initiated MCP `ping` requests to this
    /// session's client (the spec's connection-health probe). `None` (the
    /// default) spawns no loop; the composition root sets it from
    /// `GATEWAY_MCP_PING_INTERVAL_SECONDS`. See [`crate::ping`] for the
    /// loop's timeout and stop semantics.
    client_ping_interval: Option<std::time::Duration>,
    /// Counters the ping loop reports into. Shared so tests (and any
    /// diagnostic surface) can observe loop progress; operators get the
    /// same signal via the `mcp_client_pings_total` Prometheus counter.
    ping_stats: Arc<crate::ping::PingStats>,
    /// Process-wide upstream catalog notifications. Each per-session server owns a
    /// receiver subscribed at construction, so only later publications notify
    /// this client; earlier publications are its initial baseline.
    tool_catalog_changes: Option<tokio::sync::watch::Receiver<u64>>,
    /// Shared serving-state epoch used to fence each multi-await tools/list
    /// authorization projection. The receiver above is only the client
    /// notification path; retaining the epoch itself proves the response was
    /// constructed under one policy/catalog generation.
    tool_catalog_epoch: Option<ToolCatalogEpoch>,
    /// Authenticated stateless cursor protection. The composition root shares
    /// one sealer across request-scoped server instances; embedders get a
    /// process-local fallback from the base constructor.
    tool_list_cursor_sealer: crate::SharedToolListCursorSealer,
    /// Last-known-good verified skill catalog. `None` leaves the experimental
    /// extension absent and all draft methods unmounted.
    skill_catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    reviewed_skills: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    file_upload_authorizer: Option<crate::files::SharedFileUploadAuthorizer>,
    file_download_authorizer: Option<crate::files::SharedFileDownloadAuthorizer>,
    file_output_processor: Option<crate::files::SharedFileOutputProcessor>,
    resource_response_max_bytes: usize,
    resource_inspectors: Vec<crate::inspection::SharedInspector>,
}

/// Existing skill resource authorization and decision audit shared by resource
/// delivery and Code Mode source loading. This grants no execution authority.
pub struct SkillResourceAccess<'a> {
    authz: &'a SharedAuthz,
    audit: &'a SharedEvidence,
}

impl<'a> SkillResourceAccess<'a> {
    pub fn new(authz: &'a SharedAuthz, audit: &'a SharedEvidence) -> Self {
        Self { authz, audit }
    }

    /// Authorize fetching an indexed resource before source I/O.
    pub async fn authorize_fetch(
        &self,
        principal: &Principal,
        snapshot: &waygate_skills::SkillCatalogSnapshot,
        uri: &str,
    ) -> Result<(), McpError> {
        let descriptor = snapshot.resource(uri).ok_or_else(unadvertised_resource)?;
        let facts = skill_resource_fetch_facts(snapshot, descriptor);
        self.authorize_gateway_skill_fetch(Some(principal), &facts)
            .await
    }
    pub async fn authorize_gateway_skill_read(
        &self,
        principal: Option<&Principal>,
        identity: &waygate_skills::SkillResourceIdentity,
    ) -> Result<Option<Vec<String>>, McpError> {
        let Some(principal) = principal else {
            return Ok(None);
        };
        if profile_blocks_resources(principal, GATEWAY_SKILLS_SERVER) {
            self.record_gateway_skill_read(
                principal,
                identity,
                &[],
                AuditOutcome::Denied,
                Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON),
            )
            .await;
            return Err(unadvertised_resource());
        }
        match self
            .authz
            .authorize_skill_read(principal, &skill_resource_facts(identity))
            .await
        {
            AuthzVerdict::Allow { policy_ids } => Ok(Some(policy_ids)),
            AuthzVerdict::Deny {
                reason, policy_ids, ..
            } => {
                self.record_gateway_skill_read(
                    principal,
                    identity,
                    &policy_ids,
                    AuditOutcome::Denied,
                    Some(&reason),
                )
                .await;
                Err(unadvertised_resource())
            }
            AuthzVerdict::StepUpRequired {
                required_scope,
                reason,
                policy_ids,
            } => {
                self.record_gateway_skill_read(
                    principal,
                    identity,
                    &policy_ids,
                    AuditOutcome::StepUpRequired,
                    Some(&format!("scope {required_scope}: {reason}")),
                )
                .await;
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!(
                        "reading `{}` requires re-authorization with scope `{required_scope}`: {reason}",
                        identity.resource_uri
                    ),
                    Some(serde_json::json!({
                        "error": "insufficient_scope",
                        "required_scope": required_scope,
                        "reason": reason,
                    })),
                ))
            }
            AuthzVerdict::ApprovalRequired { reason, policy_ids } => {
                self.record_gateway_skill_read(
                    principal,
                    identity,
                    &policy_ids,
                    AuditOutcome::Denied,
                    Some(&format!("approval required: {reason}")),
                )
                .await;
                Err(McpError::invalid_request(
                    format!(
                        "reading `{}` is gated on a per-call approval grant, which skill reads cannot claim: {reason}",
                        identity.resource_uri
                    ),
                    None,
                ))
            }
        }
    }

    async fn authorize_gateway_skill_fetch(
        &self,
        principal: Option<&Principal>,
        facts: &SkillAccessFacts,
    ) -> Result<(), McpError> {
        let Some(principal) = principal else {
            return Ok(());
        };
        if profile_blocks_resources(principal, GATEWAY_SKILLS_SERVER) {
            self.record_gateway_skill_fetch(
                principal,
                facts,
                &[],
                AuditOutcome::Denied,
                Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON),
            )
            .await;
            return Err(unadvertised_resource());
        }
        match self.authz.authorize_skill_fetch(principal, facts).await {
            AuthzVerdict::Allow { policy_ids } => {
                self.record_gateway_skill_fetch(
                    principal,
                    facts,
                    &policy_ids,
                    AuditOutcome::Success,
                    None,
                )
                .await;
                Ok(())
            }
            verdict => {
                let (outcome, policy_ids, reason) = skill_refusal(&verdict);
                self.record_gateway_skill_fetch(
                    principal,
                    facts,
                    policy_ids,
                    outcome,
                    Some(&reason),
                )
                .await;
                Err(unadvertised_resource())
            }
        }
    }

    pub async fn record_gateway_skill_read(
        &self,
        principal: &Principal,
        identity: &waygate_skills::SkillResourceIdentity,
        policy_ids: &[String],
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) {
        let event = skill_read_decision_event(principal, identity, outcome)
            .with_policies(policy_ids.to_vec());
        self.audit
            .record_chained_best_effort(match reason {
                Some(reason) => event.with_reason(reason),
                None => event,
            })
            .await;
    }

    async fn record_gateway_skill_fetch(
        &self,
        principal: &Principal,
        facts: &SkillAccessFacts,
        policy_ids: &[String],
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) {
        let event = skill_fetch_decision_event(principal, facts, outcome)
            .with_policies(policy_ids.to_vec());
        self.audit
            .record_chained_best_effort(match reason {
                Some(reason) => event.with_reason(reason),
                None => event,
            })
            .await;
    }
}

impl GatewayServer {
    pub fn new(catalog: SharedCatalog) -> Self {
        Self::build(catalog, Arc::new(AllowAllGate), Arc::new(NullSink))
    }

    pub fn with_authz(catalog: SharedCatalog, authz: SharedAuthz) -> Self {
        Self::build(catalog, authz, Arc::new(NullSink))
    }

    pub fn with_deps(catalog: SharedCatalog, authz: SharedAuthz, audit: SharedEvidence) -> Self {
        Self::build(catalog, authz, audit)
    }

    /// Shared constructor body. Centralises the
    /// `DefaultInvocationService::new(catalog, authz, audit)` wiring so
    /// every entry point gets a consistent invocation handle, and
    /// retains an `authz` handle on the struct for the discovery / list
    /// paths (see the `authz` field doc above).
    fn build(catalog: SharedCatalog, authz: SharedAuthz, audit: SharedEvidence) -> Self {
        let invocation: SharedInvocation = Arc::new(DefaultInvocationService::new(
            catalog.clone(),
            authz.clone(),
            audit.clone(),
        ));
        Self {
            catalog,
            authz,
            index: None,
            disclosed: DisclosedTools::new(),
            _disclosed_store: Arc::new(DisclosedStore::new()),
            eager_tools_list: false,
            eager_tools_clients: Vec::new(),
            client_eager_tools_list: Arc::new(AtomicBool::new(false)),
            codemode_only_tools_clients: Vec::new(),
            client_codemode_only_tools_list: Arc::new(AtomicBool::new(false)),
            invocation,
            audit,
            audit_discovery: false,
            builtins: Vec::new(),
            advertise_ema: false,
            client_ping_interval: None,
            ping_stats: Arc::new(crate::ping::PingStats::default()),
            tool_catalog_changes: None,
            tool_catalog_epoch: None,
            tool_list_cursor_sealer: crate::tool_list_pagination::shared_process_local_sealer(),
            skill_catalog: None,
            reviewed_skills: None,
            file_upload_authorizer: None,
            file_download_authorizer: None,
            file_output_processor: None,
            resource_response_max_bytes: DEFAULT_RESOURCE_RESPONSE_MAX_BYTES,
            resource_inspectors: Vec::new(),
        }
    }

    /// Swap in a different `InvocationService` implementation. Used by
    /// future decorators of the dispatch (fail-closed audit,
    /// quota / approval / output-inspection stages). The
    /// default (built by the constructors above) is always a
    /// `DefaultInvocationService`.
    #[must_use]
    pub fn with_invocation_service(mut self, invocation: SharedInvocation) -> Self {
        self.invocation = invocation;
        self
    }

    #[must_use]
    pub fn with_file_download_authorizer(
        mut self,
        authorizer: Option<crate::files::SharedFileDownloadAuthorizer>,
    ) -> Self {
        self.file_download_authorizer = authorizer;
        self
    }

    #[must_use]
    pub fn with_file_upload_authorizer(
        mut self,
        authorizer: Option<crate::files::SharedFileUploadAuthorizer>,
    ) -> Self {
        self.file_upload_authorizer = authorizer;
        self
    }

    #[must_use]
    pub fn with_file_output_processor(
        mut self,
        processor: Option<crate::files::SharedFileOutputProcessor>,
    ) -> Self {
        self.file_output_processor = processor;
        self
    }

    #[must_use]
    pub fn with_resource_response_max_bytes(mut self, limit_bytes: usize) -> Self {
        self.resource_response_max_bytes = limit_bytes;
        self
    }

    #[must_use]
    pub fn with_resource_inspectors(
        mut self,
        inspectors: Vec<crate::inspection::SharedInspector>,
    ) -> Self {
        self.resource_inspectors = inspectors;
        self
    }

    /// Attach a populated [`SearchIndex`] for BM25-ranked `searchTools`.
    /// Must be called before the server is handed to rmcp — the index is
    /// cheap to clone (`Arc` under the hood) but swapping it at runtime
    /// would require a lock the hot path doesn't need.
    #[must_use]
    pub fn with_index(mut self, index: SearchIndex) -> Self {
        self.index = Some(index);
        self
    }

    /// Share deployment-scoped protection across stateless request handlers.
    #[must_use]
    pub fn with_tool_list_cursor_sealer(
        mut self,
        sealer: crate::SharedToolListCursorSealer,
    ) -> Self {
        self.tool_list_cursor_sealer = sealer;
        self
    }

    /// Mount the draft Skills extension over a verified reloadable catalog.
    #[must_use]
    pub fn with_skill_catalog(
        mut self,
        catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    ) -> Self {
        self.skill_catalog = catalog;
        self
    }

    #[must_use]
    pub fn with_reviewed_skills(
        mut self,
        catalog: Option<Arc<waygate_skills::distribution::ReviewedSkillCatalog>>,
    ) -> Self {
        self.reviewed_skills = catalog;
        self
    }

    async fn resolve_approved_skill(
        &self,
        uri: &str,
        revision: Option<&str>,
        principal: Option<&Principal>,
    ) -> Result<Arc<waygate_skills::SkillCatalogSnapshot>, McpError> {
        let principal = principal.ok_or_else(unadvertised_resource)?;
        self.reviewed_skills
            .as_ref()
            .ok_or_else(unadvertised_resource)?
            .resolve(principal.tenant.as_str(), uri, revision)
            .await
            .map_err(skill_distribution_error)
    }

    async fn check_skill_approval(
        &self,
        snapshot: &waygate_skills::SkillCatalogSnapshot,
        uri: &str,
        principal: Option<&Principal>,
    ) -> Result<(), McpError> {
        let principal = principal.ok_or_else(unadvertised_resource)?;
        self.reviewed_skills
            .as_ref()
            .ok_or_else(unadvertised_resource)?
            .check(principal.tenant.as_str(), snapshot, uri)
            .await
            .map_err(skill_distribution_error)
    }

    #[cfg(test)]
    fn with_approved_skill_fixture(
        self,
        catalog: Option<Arc<waygate_skills::ReloadableSkillCatalog>>,
    ) -> Self {
        let approved = catalog.as_ref().map(|catalog| {
            waygate_test_support::skills::approved_catalog(
                catalog.clone(),
                waygate_core::TenantId::DEFAULT,
            )
        });
        self.with_skill_catalog(catalog)
            .with_reviewed_skills(approved)
    }

    /// Return the full upstream catalog from `tools/list` instead of gating
    /// discovery behind `searchTools`. Opt-in escape hatch for MCP clients
    /// that ignore `notifications/tools/list_changed` — turning it on means
    /// every connected client pays the full-catalog context cost on its first
    /// `tools/list`, so the default stays off.
    #[must_use]
    pub fn with_eager_tools_list(mut self, enabled: bool) -> Self {
        self.eager_tools_list = enabled;
        self
    }

    /// Return the full authorized upstream catalog only for legacy sessions
    /// whose MCP `clientInfo.name` matches one of `clients`. Matching is exact
    /// and ASCII-case-insensitive. The process-wide
    /// [`Self::with_eager_tools_list`] override still wins.
    #[must_use]
    pub fn with_eager_tools_clients(mut self, clients: Vec<String>) -> Self {
        self.eager_tools_clients = clients;
        self
    }

    /// Return only authorized gateway built-ins to clients whose MCP
    /// `clientInfo.name` matches one of `clients`. Matching is exact and
    /// ASCII-case-insensitive. Code Mode remains directly listed and provides
    /// governed discovery and invocation without expanding `tools/list`.
    #[must_use]
    pub fn with_codemode_only_tools_clients(mut self, clients: Vec<String>) -> Self {
        self.codemode_only_tools_clients = clients;
        self
    }

    /// Retain the former process-wide stateless disclosure-store wiring while
    /// composition cleanup lands separately. The stable 2026 request path
    /// deliberately never reads or writes this store.
    #[must_use]
    pub fn with_disclosed_store(mut self, store: Arc<DisclosedStore>) -> Self {
        self._disclosed_store = store;
        self
    }

    fn eager_tools_list_active(&self) -> bool {
        self.eager_tools_list || self.client_eager_tools_list.load(Ordering::Relaxed)
    }

    fn client_name_matches(client_name: Option<&str>, allowed: &[String]) -> bool {
        client_name.is_some_and(|client_name| {
            allowed
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(client_name))
        })
    }

    fn codemode_only_tools_list_active(&self, client: Option<&ClientContext>) -> bool {
        self.client_codemode_only_tools_list.load(Ordering::Relaxed)
            || client.is_some_and(|client| {
                Self::client_name_matches(
                    client.client_name.as_deref(),
                    &self.codemode_only_tools_clients,
                )
            })
    }

    /// Resolve the shared `searchTools` name at the same authorization and
    /// admission boundary as `tools/list`. Distinguishing a hidden server from
    /// a hidden direct tool matters: the former must look unknown, while the
    /// latter leaves the gateway-owned adapter visible.
    async fn resolve_search_tools_name(
        &self,
        principal: Option<&Principal>,
        server: &str,
    ) -> SearchToolsNameResolution {
        if let Some(principal) = principal {
            if profile_blocks_server(principal, server)
                || !self.authz.may_discover_server(principal, server).await
            {
                return SearchToolsNameResolution::ServerHidden;
            }
            if profile_blocks_tool(principal, server, "searchTools") {
                return SearchToolsNameResolution::Adapter;
            }
        }
        let Ok(tools) = self.catalog.list_tools(server).await else {
            return SearchToolsNameResolution::Adapter;
        };
        if !tools.iter().any(|tool| tool.name == "searchTools") {
            return SearchToolsNameResolution::Adapter;
        }
        let tenant = principal
            .map(|principal| principal.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        let ResolvedInvocationTool::Ready(snapshot) = self
            .catalog
            .resolve_discovery_tool(tenant, server, "searchTools")
            .await
        else {
            return SearchToolsNameResolution::Adapter;
        };
        match principal {
            Some(principal)
                if !self
                    .authz
                    .may_call_tool(principal, snapshot.facts())
                    .await
                    .is_discoverable() =>
            {
                SearchToolsNameResolution::Adapter
            }
            _ if CatalogTool::from_upstream_snapshot(server, snapshot).is_some() => {
                SearchToolsNameResolution::DirectTool
            }
            _ => SearchToolsNameResolution::Adapter,
        }
    }

    /// SEP-2549 cache hints for a gateway-owned result, stamped only for
    /// the stateless generation (the legacy wire stays byte-identical:
    /// serde skips `None`). `cacheScope` is always `private` — the catalog
    /// and resource visibility are authorization-filtered per principal, so
    /// a shared-cache `public` scope would leak visibility across
    /// principals. `ttlMs: 0` (do not cache) remains conservative until a
    /// later caching change binds a nonzero lifetime to catalog invalidation
    /// and authorization freshness; the stable projection alone does not
    /// make those independent inputs cache-safe.
    fn stamp_cache_hints(
        &self,
        client: &ClientContext,
        ttl_ms: &mut Option<u64>,
        cache_scope: &mut Option<rmcp::model::CacheScope>,
    ) {
        if client.generation == ProtocolGeneration::Stateless2026 {
            *ttl_ms = Some(0);
            *cache_scope = Some(rmcp::model::CacheScope::Private);
        }
    }

    /// Resolve the per-request client context and record the
    /// per-generation request counter that the legacy-removal decision
    /// (deprecation clock) reads.
    fn client_context(&self, ctx: &RequestContext<RoleServer>) -> ClientContext {
        let client = ClientContext::from_ctx(ctx);
        waygate_telemetry::metrics::record_protocol_generation(match client.generation {
            ProtocolGeneration::Legacy => "legacy",
            ProtocolGeneration::Stateless2026 => "2026-07-28",
        });
        client
    }

    /// Enable best-effort `Discovery` audit rows for each `searchTools`
    /// call. Off by default (discovery is high-volume and non-security-
    /// critical); the composition root flips it on from
    /// `GATEWAY_AUDIT_DISCOVERY`.
    #[must_use]
    pub fn with_audit_discovery(mut self, enabled: bool) -> Self {
        self.audit_discovery = enabled;
        self
    }

    /// Register a gateway-local tool namespace (e.g. the HITL `gateway-admin.*`
    /// surface, or the `gateway-observe.*` read plane). Calls in the namespace
    /// are answered locally and its tools appear in `tools/list`; see
    /// [`crate::builtin::BuiltinTools`]. Call once per namespace — the handles
    /// accumulate. Wired by the composition root, which owns the stores each
    /// impl needs. No registrations (the default) keeps the proxy-only
    /// behavior.
    ///
    /// Namespaces must be distinct; if two handles report the same
    /// `namespace()`, dispatch resolves to whichever was registered first (the
    /// load-time guard in `waygate_upstream` prevents an *upstream* collision,
    /// but registration order is the composition root's responsibility).
    #[must_use]
    pub fn with_builtin_tools(mut self, builtin: crate::builtin::SharedBuiltinTools) -> Self {
        self.builtins.push(builtin);
        self
    }

    /// Opt in to advertising the EMA
    /// `io.modelcontextprotocol/enterprise-managed-authorization` capability in
    /// `ServerCapabilities.extensions`. The composition root passes `true` only
    /// when `GATEWAY_AS_IDJAG_ADVERTISE=true` AND the AS + EMA deps are wired, so
    /// the gateway never advertises a grant it can't service. Default off.
    #[must_use]
    pub fn with_ema_capability_advert(mut self, enabled: bool) -> Self {
        self.advertise_ema = enabled;
        self
    }

    /// Periodically send MCP `ping` requests to this session's client at
    /// the given interval (`None` disables — the default). The loop spawns
    /// when the client sends `notifications/initialized`; pong timeouts and
    /// stop semantics live in [`crate::ping`]. The composition root sets
    /// this from `GATEWAY_MCP_PING_INTERVAL_SECONDS`.
    #[must_use]
    pub fn with_client_ping_interval(mut self, interval: Option<std::time::Duration>) -> Self {
        self.client_ping_interval = interval;
        self
    }

    /// Replace the ping-loop counter handle. Integration tests inject a
    /// handle they retain so they can observe loop progress from outside
    /// the per-session server the rmcp factory builds; production leaves
    /// the per-instance default and watches `mcp_client_pings_total`.
    #[must_use]
    pub fn with_ping_stats(mut self, stats: Arc<crate::ping::PingStats>) -> Self {
        self.ping_stats = stats;
        self
    }

    /// Subscribe this downstream session to successful changes in the shared
    /// upstream tool catalog. The watcher starts after MCP initialization.
    #[must_use]
    pub fn with_tool_catalog_epoch(mut self, epoch: &ToolCatalogEpoch) -> Self {
        self.tool_catalog_changes = Some(epoch.subscribe());
        self.tool_catalog_epoch = Some(epoch.clone());
        self
    }

    /// Access the session's [`DisclosedTools`] record. Exposed so integration
    /// tests can assert disclosure/notification behavior; production callers
    /// should not need this.
    pub fn disclosed(&self) -> &DisclosedTools {
        &self.disclosed
    }

    fn make_search_tool(server: &str) -> Tool {
        let description =
            format!("Search callable operations and type schemas on the `{server}` upstream.");
        Tool::new(
            format!("{server}{SEARCH_TOOLS_SUFFIX}"),
            description,
            search_tools_v1::input_schema(),
        )
        .with_title(format!("{server} — search tools"))
        .with_raw_output_schema(search_tools_v1::output_schema())
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    /// Dispatch a `tools/call` independent of the rmcp `RequestContext`. The
    /// `ServerHandler::call_tool` impl is a thin wrapper around this so that
    /// tests can exercise the meta-tool and proxy paths directly.
    ///
    /// `principal` is `None` in the `disabled` auth mode tests; the
    /// [`AllowAllGate`] is forgiving there, but a real [`AuthzGate`] must be
    /// prepared to handle a missing principal (fail closed or treat as
    /// anonymous per policy).
    pub async fn dispatch_tool_call(
        &self,
        request: CallToolRequestParams,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        // The direct seam has no client context, so it dispatches as a
        // caller that can answer no server-initiated request: MRTR
        // projection is off and every result is a complete one (a pause
        // would have been refused fail-closed inside the pipeline).
        match self
            .dispatch_tool_call_with(
                request,
                principal,
                ProtocolGeneration::Legacy,
                Some(&self.disclosed),
                &MrtrCaller::CANNOT,
            )
            .await?
        {
            CallToolResponse::Complete(result) => Ok(result),
            _ => Err(McpError::internal_error(
                "tool dispatch produced a non-final response for a caller that declared no \
                 input capabilities",
                None,
            )),
        }
    }

    /// [`Self::dispatch_tool_call`] with an optional legacy disclosure record.
    /// Stateless 2026 calls pass `None`, so `searchTools` remains callable as
    /// a compatibility/search surface without mutating subsequent lists.
    /// `caller` is the downstream client's MRTR posture: whether an
    /// `input_required` pause may be returned to it at all, and which
    /// capabilities the upstream leg may rely on it answering.
    async fn dispatch_tool_call_with(
        &self,
        mut request: CallToolRequestParams,
        principal: Option<&Principal>,
        generation: ProtocolGeneration,
        disclosed: Option<&DisclosedTools>,
        caller: &MrtrCaller,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.as_ref();

        // Built-in namespaces (e.g. `gateway-admin.propose_change`,
        // `gateway-observe.query_audit`): answered by the gateway itself, not
        // proxied. Intercepted FIRST so each reserved namespace is hermetic — a
        // probe of `gateway-admin.foo` (or even `gateway-admin.searchTools`)
        // lands in the built-in handler's unknown-tool path rather than leaking
        // through the upstream catalog or the SEP #1888 meta-tool path. The
        // impl re-checks authorization. First matching namespace wins.
        if let Some((builtin, tool)) = self.authorized_builtin(name, principal).await? {
            return builtin
                .call(tool, request.arguments, principal)
                .await
                .map(Into::into);
        }

        if let Some(server) = name.strip_suffix(SEARCH_TOOLS_SUFFIX) {
            // The closed-draft adapter and an ordinary upstream tool named
            // `searchTools` share one qualified name. Standard 2026 clients
            // get the direct tool when that valid upstream shape exists;
            // a legacy peer cannot disambiguate the shared name, so fail with
            // a stable, instructive collision error instead of silently
            // shadowing either contract.
            let name_resolution = self.resolve_search_tools_name(principal, server).await;
            if matches!(name_resolution, SearchToolsNameResolution::ServerHidden) {
                return Err(McpError::invalid_params(
                    format!("unknown upstream: {server}"),
                    None,
                ));
            }
            let visible_upstream_collision =
                matches!(name_resolution, SearchToolsNameResolution::DirectTool);
            if generation == ProtocolGeneration::Stateless2026 && visible_upstream_collision {
                // Fall through to the ordinary governed direct-tool pipeline.
            } else if generation == ProtocolGeneration::Legacy && visible_upstream_collision {
                return Err(McpError::invalid_params(
                    format!(
                        "legacy searchTools adapter name collision: `{server}.searchTools` is \
                         also an ordinary upstream tool; use MCP 2026 for direct-tool \
                         precedence or rename the upstream tool"
                    ),
                    Some(json!({
                        "error": "legacy_search_tools_name_collision",
                        "adapter": {
                            "id": search_tools_v1::ADAPTER_ID,
                            "version": search_tools_v1::ADAPTER_VERSION,
                        },
                        "tool": format!("{server}.searchTools"),
                    })),
                ));
            } else {
                let args = request.arguments.unwrap_or_default();
                let req: SearchToolsRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|e| {
                        McpError::invalid_params(format!("searchTools args: {e}"), None)
                    })?;
                req.validate().map_err(|reason| {
                    McpError::invalid_params(
                        format!("searchTools args: {reason}"),
                        Some(json!({
                            "error": "invalid_search_tools_arguments",
                            "adapter": {
                                "id": search_tools_v1::ADAPTER_ID,
                                "version": search_tools_v1::ADAPTER_VERSION,
                            },
                            "reason": reason,
                        })),
                    )
                })?;
                return self
                    .handle_search_tools(server, req, principal, disclosed)
                    .await
                    .map(Into::into);
            }
        }

        let (server, tool_name) = name.split_once('.').ok_or_else(|| {
            McpError::invalid_params(
                format!("tool `{name}` is not fully qualified (expected `<server>.<tool>`)"),
                None,
            )
        })?;

        // Dispatch + authz + audit live in `InvocationService`.
        // The body that used to be inline here is now in
        // `DefaultInvocationService::invoke`. This adapter only:
        // 1. builds the transport-neutral `InvocationRequest`,
        // 2. calls the service,
        // 3. maps the typed `InvocationError` back to the MCP wire
        //    shape so the rmcp client sees the same response shape
        //    as before the refactor. Step (3) is the key reason this adapter
        //    exists: the typed errors let future non-MCP consumers
        //    (an admin "dry-run tool call" endpoint, a federated
        //    Tier-C gateway hop) map them to their own wire shape
        //    without re-running authz + audit logic.
        // MRTR continuation fields exist only on the 2026 generation: a
        // legacy request carrying them keeps having them ignored, exactly as
        // before MRTR existed, so legacy dispatch stays byte-identical. For
        // a 2026 caller, the gateway's own approval ask travels under a
        // reserved input-request key whose answer is addressed to the
        // gateway, not the upstream — strip it (the retry is authorized by
        // the operator's grant claim, not by the elicitation answer) and
        // forward the rest verbatim.
        let (input_responses, request_state) = if caller.capabilities.is_some() {
            let responses = request.input_responses.take().and_then(|mut responses| {
                responses.remove(APPROVAL_INPUT_REQUEST_KEY);
                (!responses.is_empty()).then_some(responses)
            });
            (responses, request.request_state.take())
        } else {
            (None, None)
        };
        let invocation_request = InvocationRequest::new(server, tool_name)
            .with_arguments(request.arguments)
            .with_mrtr_retry(input_responses, request_state)
            .with_caller_capabilities(caller.capabilities.clone());
        match self.invocation.invoke(principal, invocation_request).await {
            // The MCP tool-call path is unary and MCP-shaped. The streaming and
            // raw-JSON (LLM) response shapes come only from the inference plane,
            // which has its own HTTP egress and never routes through this
            // adapter, so either here is a wiring bug — surface it as an
            // internal error, not a panic.
            Ok(crate::InvocationResponse::Unary(result)) => Ok(result.into()),
            // An upstream MRTR pause the pipeline already verified the caller
            // can answer — relayed verbatim, opaque `requestState` included.
            Ok(crate::InvocationResponse::InputRequired(pause)) => {
                Ok(CallToolResponse::InputRequired(pause))
            }
            Ok(crate::InvocationResponse::Stream(_)) => Err(McpError::internal_error(
                "streaming invocation response is not supported on the MCP tool-call path",
                None,
            )),
            Ok(crate::InvocationResponse::UnaryValue(_)) => Err(McpError::internal_error(
                "raw-JSON (LLM) invocation response is not supported on the MCP tool-call path",
                None,
            )),
            Err(InvocationError::Forbidden {
                reason,
                policy_ids,
                reasons,
            }) => {
                // "Explain this denial":
                // surface Cedar's `policy_ids` + per-policy
                // `reasons` in the JSON-RPC `data` envelope
                // so an operator looking at a denied call
                // (e.g. via the admin audit deep-link) can
                // see *which* forbid policies fired and
                // their human-readable reason without
                // re-running the gate offline. The
                // human-readable `message` stays unchanged
                // for clients that don't parse `data`.
                let data = serde_json::json!({
                    "error": "forbidden",
                    "reason": reason,
                    "policy_ids": policy_ids,
                    "reasons": reasons,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!("forbidden: {server}.{tool_name} — {reason}"),
                    Some(data),
                ))
            }
            Err(InvocationError::StepUpRequired {
                required_scope,
                reason,
            }) => {
                // Structured `data` so MCP clients can programmatically
                // detect insufficient_scope and re-authorize via OAuth
                // without parsing the human-readable message. The shape
                // mirrors OAuth 2.0's `error` / `scope` conventions.
                let data = serde_json::json!({
                    "error": "insufficient_scope",
                    "required_scope": required_scope,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!("step-up required (scope `{required_scope}`): {reason}"),
                    Some(data),
                ))
            }
            Err(InvocationError::Upstream(err)) => {
                // The typed `McpError` flows through unchanged — same
                // JSON-RPC code, message, and `data` envelope the
                // catalog raised. Regression guard: previously
                // the catalog's invalid-params guard returned
                // `invalid_params` to the client; stringifying via
                // Upstream(String) had collapsed every variant to
                // `internal_error`. The typed carry preserves the
                // pre-refactor contract.
                Err(err)
            }
            Err(InvocationError::InvalidArguments(detail)) => {
                Err(McpError::invalid_params(detail, None))
            }
            Err(InvocationError::InputSchemaViolation { tool, reason }) => {
                let data = serde_json::json!({
                    "error": "input_schema_violation",
                    "tool": tool,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("input schema violation on `{tool}`: {reason}"),
                    Some(data),
                ))
            }
            Err(InvocationError::InputSchemaInvalid { tool }) => {
                let data = serde_json::json!({
                    "error": "input_schema_invalid",
                    "tool": tool,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("input schema for `{tool}` is unavailable or invalid"),
                    Some(data),
                ))
            }
            Err(InvocationError::ReadOnlyRequired { tool }) => Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("operation `{tool}` is not admitted for read-only execution"),
                Some(serde_json::json!({
                    "error": "read_only_required",
                    "tool": tool,
                })),
            )),
            // Names the discriminator and the value so the caller can tell this
            // apart from the whole tool being excluded: the remedy is a
            // reviewed classification for this operation, not a different tool.
            Err(InvocationError::ReadOnlyOperationRequired {
                tool,
                discriminator,
                operation,
            }) => Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!(
                    "`{tool}` dispatches by `{discriminator}` and `{operation}` is not an \
                     operation it reviewed for read-only execution"
                ),
                Some(serde_json::json!({
                    "error": "read_only_operation_required",
                    "tool": tool,
                    "discriminator": discriminator,
                    "operation": operation,
                })),
            )),
            Err(InvocationError::AuditUnavailable(detail)) => {
                // Emitted by the `record_pre_call` stage when
                // `GATEWAY_AUDIT_MODE=fail_closed` and the side-effecting
                // call's pre-call required-record write failed. The
                // upstream dispatch never ran — a "fail_closed for
                // compliance" deployment must surface this as a 5xx so
                // the client retries (or the operator investigates)
                // rather than silently proceeding without evidence.
                Err(McpError::internal_error(
                    format!("audit unavailable: {detail}"),
                    None,
                ))
            }
            Err(InvocationError::ApprovalRequired {
                tool,
                reason,
                satisfiable,
            }) => {
                // MRTR projection (SEP-2322): when the refusal is the one a
                // granted approval + identical retry can cure AND the caller
                // declared it can answer elicitation, return an
                // `input_required` pause carrying the approval ask instead of
                // a terminal error. No gateway `requestState` — the grant
                // claim authorizes the retry (the plan's locked decision) —
                // and the reserved-key answer is stripped on that retry
                // above. Legacy-generation and non-elicitation callers keep
                // the structured error byte-for-byte.
                if satisfiable && caller.elicitation_capable() {
                    return Ok(CallToolResponse::InputRequired(approval_input_required(
                        &tool, &reason,
                    )));
                }
                // Structured MCP error so clients can
                // surface the human-in-the-loop UX (prompt for
                // approval, wait, retry) rather than parsing a
                // human-readable string. Shape mirrors the step-up
                // error envelope so clients that already handle
                // OAuth-style structured errors can reuse the same
                // detection branch.
                let data = serde_json::json!({
                    "error": "approval_required",
                    "tool": tool,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!("approval required for `{tool}`: {reason}"),
                    Some(data),
                ))
            }
            Err(InvocationError::RateLimited {
                policy_id,
                policy_name,
                retry_after_seconds,
            }) => {
                // Structured MCP error so clients
                // can detect rate-limit responses and back off
                // without parsing the human-readable message.
                // `retry_after_seconds` mirrors HTTP 429's
                // `Retry-After` header per RFC 6585 §4 — this
                // path can't set the HTTP header directly
                // (the rmcp adapter returns a JSON-RPC error,
                // not an HTTP response), but the body field
                // carries the same hint for client backoff
                // logic. A future HTTP-layer adapter (the
                // step-up 403 work will do similar
                // for status codes) can promote this to the
                // header when an HTTP transport is in use.
                let data = serde_json::json!({
                    "error": "rate_limited",
                    "policy_id": policy_id.to_string(),
                    "policy_name": policy_name,
                    "retry_after_seconds": retry_after_seconds,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!(
                        "rate-limited by policy `{policy_name}`; retry after {retry_after_seconds}s"
                    ),
                    Some(data),
                ))
            }
            Err(InvocationError::ProfileServerNotAllowed {
                profile_id,
                profile_name,
                server,
            }) => {
                // Structured MCP error so
                // clients can distinguish profile-driven server
                // denial from a Cedar-policy deny. The
                // mcp_http_promote middleware does NOT promote
                // this to HTTP 403 today (the classifier targets
                // insufficient_scope/rate_limited specifically);
                // a follow-up can add this kind to the
                // promotion list if operators want OAuth-style
                // signalling here too.
                let data = serde_json::json!({
                    "error": "profile_restricts_server",
                    "profile_id": profile_id,
                    "profile_name": profile_name,
                    "server": server,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!("api-key profile `{profile_name}` does not permit server `{server}`"),
                    Some(data),
                ))
            }
            Err(InvocationError::ProfileToolNotAllowed {
                profile_id,
                profile_name,
                tool,
            }) => {
                let data = serde_json::json!({
                    "error": "profile_restricts_tool",
                    "profile_id": profile_id,
                    "profile_name": profile_name,
                    "tool": tool,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!("api-key profile `{profile_name}` does not permit tool `{tool}`"),
                    Some(data),
                ))
            }
            Err(InvocationError::OutputSchemaViolation { tool, reason }) => {
                // The upstream returned a payload
                // that didn't match the approved JSON Schema.
                // INTERNAL_ERROR rather than INVALID_REQUEST —
                // the caller's request was fine; the failure is
                // server-side (upstream out-of-contract). The
                // sanitized `reason` (validator message + JSON
                // pointer) is safe to surface — never the full
                // payload, which could leak PII/secrets.
                let data = serde_json::json!({
                    "error": "output_schema_violation",
                    "tool": tool,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("output schema violation on `{tool}`: {reason}"),
                    Some(data),
                ))
            }
            Err(InvocationError::ToolSchemaInvalid { tool }) => {
                let data = serde_json::json!({
                    "error": "tool_schema_invalid",
                    "tool": tool,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("approved output schema for `{tool}` is invalid"),
                    Some(data),
                ))
            }
            Err(InvocationError::ResponseInspectionBlocked {
                tool,
                inspector_name,
                reason,
            }) => {
                // A response inspector (PII /
                // secret / poisoning marker) refused the
                // upstream payload. INTERNAL_ERROR mirrors the
                // c1 schema-violation shape: the caller's
                // request was fine; the gateway refused to
                // forward the upstream's response. The
                // sanitized `reason` carries only the rule
                // label (e.g. "matched PII rule `US_SSN`") —
                // never the matched payload, per the same
                // discipline c1 applies to schema messages.
                let data = serde_json::json!({
                    "error": "response_inspection_blocked",
                    "tool": tool,
                    "inspector_name": inspector_name,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!(
                        "response blocked by inspector `{inspector_name}` on `{tool}`: {reason}"
                    ),
                    Some(data),
                ))
            }
            Err(InvocationError::ResponseMaterializationLimit {
                tool,
                minimum_response_bytes,
                limit_bytes,
            }) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!(
                    "retained response for `{tool}` exceeds this caller's materialization budget"
                ),
                Some(serde_json::json!({
                    "error": "connector_result_too_large",
                    "tool": tool,
                    "minimum_response_bytes": minimum_response_bytes,
                    "limit_bytes": limit_bytes,
                })),
            )),
            // The LLM budget gate runs only on the inference fast
            // path (`invoke_llm`), whose calls return via the `/v1` egress, not
            // this MCP tool-call adapter — so a budget rejection cannot reach
            // here. Handled for exhaustiveness; if it ever does, surface it as
            // an internal error rather than silently mapping to success.
            Err(InvocationError::BudgetExceeded { dimension, reason }) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("llm budget exhausted ({dimension}): {reason}"),
                None,
            )),
        }
    }

    /// Resolve one built-in name through the same profile confinement and
    /// Cedar forbid overlay used by ordinary tool dispatch. Task submission
    /// uses this helper so augmentation cannot bypass the tool's normal
    /// governance boundary.
    async fn authorized_builtin<'a>(
        &'a self,
        name: &'a str,
        principal: Option<&Principal>,
    ) -> Result<Option<(&'a crate::builtin::SharedBuiltinTools, &'a str)>, McpError> {
        for builtin in &self.builtins {
            let Some(tool) = name
                .strip_prefix(builtin.namespace())
                .and_then(|rest| rest.strip_prefix('.'))
            else {
                continue;
            };
            let catalog = builtin.catalog();
            if !catalog
                .tools
                .iter()
                .any(|entry| entry.identity.name == tool)
            {
                // The canonical catalog is the governance authority for every
                // callable built-in. Letting the handler accept an unlisted
                // name would bypass its profile facts and Cedar overlay.
                return Err(McpError::invalid_params(
                    format!("unknown tool: {name}"),
                    None,
                ));
            }
            let governance_tool = builtin.governance_tool(tool);
            if let Some(p) =
                principal.filter(|_| builtin.profile_scope() == BuiltinProfileScope::Namespace)
            {
                if profile_blocks_server(p, builtin.namespace())
                    || profile_blocks_tool(p, builtin.namespace(), governance_tool)
                {
                    return Err(McpError::invalid_params(
                        format!("unknown tool: {name}"),
                        None,
                    ));
                }
            }
            self.authorize_builtin_overlay(&catalog, governance_tool, principal)
                .await?;
            return Ok(Some((builtin, tool)));
        }
        Ok(None)
    }

    /// Forbid-overlay governance: the Cedar overlay consulted before a
    /// built-in tool runs. Returns `Ok(())` to let the call proceed (the
    /// namespace's own scope self-gate inside
    /// [`call`](crate::builtin::BuiltinTools::call) is still the authoritative
    /// floor) or an `McpError` to block it.
    ///
    /// **The overlay can only NARROW.** The scope self-gate is the floor; Cedar
    /// is an *additional* restriction layered on top:
    ///
    /// - A determining Cedar **`forbid`** ⇒ **block**, even for a caller the
    ///   scope floor would admit. This is the whole point of the overlay — an
    ///   operator can author `forbid (… ) when { resource.server ==
    ///   "gateway-control" }` to restrict a built-in beyond its scope.
    /// - A **clean baseline default-deny** (Cedar evaluated, no policy mentioned
    ///   the namespace) ⇒ **proceed**. Built-ins have no `permit` policies of
    ///   their own, so a deny-by-default must NOT block them, or every built-in
    ///   would break on a policy set that simply omits them. This mirrors the
    ///   gateway's "a broken/empty policy set must not lock the operator out"
    ///   posture: the self-gate still governs.
    /// - `StepUpRequired` ⇒ surfaced as an `insufficient_scope` error so an
    ///   operator can gate a built-in behind a step-up scope.
    /// - An **engine error** (`BuiltinAuthz::Indeterminate`) ⇒ **fail closed**.
    ///   A clean baseline deny and an authorization-engine failure are
    ///   byte-identical through `AuthzVerdict` (both a `Deny` with empty
    ///   `policy_ids`); [`AuthzGate::authorize_builtin_call`] consults the
    ///   engine's error-preserving path so the two are distinguishable here —
    ///   we must never proceed on the error.
    ///
    /// No principal (the `disabled` auth mode) skips the overlay. Unknown tool
    /// names are refused before this helper, and a missing governance record is
    /// an internal catalog invariant failure that fails closed.
    async fn authorize_builtin_overlay(
        &self,
        catalog: &BuiltinCatalog,
        tool: &str,
        principal: Option<&Principal>,
    ) -> Result<(), McpError> {
        authorize_builtin_call(&self.authz, &self.audit, catalog, tool, principal, None).await
    }

    async fn visible_upstream_servers(&self, principal: Option<&Principal>) -> Vec<String> {
        let servers = self.catalog.list_servers().await;
        let mut visible = Vec::with_capacity(servers.len());
        for server in servers {
            if let Some(p) = principal {
                if profile_blocks_server(p, &server) {
                    continue;
                }
                if !self.authz.may_discover_server(p, &server).await {
                    continue;
                }
            }
            visible.push(server);
        }
        visible
    }

    async fn visible_resource_servers(&self, principal: Option<&Principal>) -> Vec<String> {
        self.visible_upstream_servers(principal)
            .await
            .into_iter()
            .filter(|server| {
                !principal.is_some_and(|principal| profile_blocks_resources(principal, server))
            })
            .filter(|server| self.catalog.resource_operations_supported(server))
            .collect()
    }

    async fn declared_resource_server_visible(
        &self,
        principal: Option<&Principal>,
        server: &str,
    ) -> bool {
        if !self.catalog.resource_operations_supported(server) {
            return false;
        }
        let Some(principal) = principal else {
            return true;
        };
        if profile_blocks_server(principal, server) || profile_blocks_resources(principal, server) {
            return false;
        }
        self.authz.may_discover_server(principal, server).await
    }

    async fn visible_resource_list_servers(&self, principal: Option<&Principal>) -> Vec<String> {
        let servers = self.visible_resource_servers(principal).await;
        let Some(principal) = principal else {
            return servers;
        };
        let mut allowed = Vec::with_capacity(servers.len());
        for server in servers {
            if self.authz.may_list_resources(principal, &server).await {
                allowed.push(server);
            }
        }
        allowed
    }

    /// Same indirection for `tools/list` — build the meta-tool list without a
    /// `RequestContext`. When a principal is supplied we filter servers to
    /// only those the caller can discover.
    pub async fn list_meta_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        self.visible_upstream_servers(principal)
            .await
            .into_iter()
            .map(|server| Self::make_search_tool(&server))
            .collect()
    }

    fn decode_resource_cursor(cursor: &str) -> Result<ResourceCursor, McpError> {
        if cursor.len() > MAX_RESOURCE_CURSOR_BYTES {
            return Err(McpError::invalid_params(
                "resource cursor exceeds the 4096-byte limit",
                None,
            ));
        }
        let decoded: ResourceCursor = serde_json::from_str(cursor)
            .map_err(|_| McpError::invalid_params("invalid resource cursor", None))?;
        if decoded.pages_remaining > MAX_RESOURCE_RESOLUTION_PAGES {
            return Err(McpError::invalid_params(
                "invalid resource cursor page budget",
                None,
            ));
        }
        if decoded.seen_upstream_cursors.len() > MAX_RESOURCE_RESOLUTION_PAGES
            || decoded.seen_upstream_cursors.iter().any(|fingerprint| {
                fingerprint.len() != 32 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(McpError::invalid_params(
                "invalid resource cursor history",
                None,
            ));
        }
        Ok(decoded)
    }

    fn encode_resource_cursor(cursor: &ResourceCursor) -> Result<String, McpError> {
        let encoded = serde_json::to_string(cursor)
            .map_err(|_| McpError::internal_error("failed to encode resource cursor", None))?;
        if encoded.len() > MAX_RESOURCE_CURSOR_BYTES {
            return Err(McpError::internal_error(
                "upstream resource cursor exceeds the gateway limit",
                None,
            ));
        }
        Ok(encoded)
    }

    pub async fn list_visible_resources(
        &self,
        params: Option<PaginatedRequestParams>,
        principal: Option<&Principal>,
    ) -> Result<ListResourcesResult, McpError> {
        tokio::time::timeout(
            RESOURCE_RESOLUTION_TIMEOUT,
            self.list_visible_resources_inner(params, principal),
        )
        .await
        .map_err(|_| {
            McpError::internal_error("resource listing exceeded the 30-second deadline", None)
        })?
    }

    async fn list_visible_resources_inner(
        &self,
        params: Option<PaginatedRequestParams>,
        principal: Option<&Principal>,
    ) -> Result<ListResourcesResult, McpError> {
        let servers = self.visible_resource_list_servers(principal).await;
        let requested = match params.and_then(|params| params.cursor) {
            Some(cursor) => Some(Self::decode_resource_cursor(&cursor)?),
            None => None,
        };
        let (start, mut upstream_cursor, mut pages_remaining, mut seen_upstream_cursors) =
            match requested {
                Some(cursor) => {
                    let start = servers
                        .iter()
                        .position(|server| server == &cursor.server)
                        .ok_or_else(|| {
                            McpError::invalid_params("resource cursor server is unavailable", None)
                        })?;
                    (
                        start,
                        cursor.upstream_cursor,
                        cursor.pages_remaining,
                        cursor.seen_upstream_cursors,
                    )
                }
                None => (0, None, MAX_RESOURCE_RESOLUTION_PAGES, Vec::new()),
            };

        for (index, server) in servers.iter().enumerate().skip(start) {
            loop {
                if pages_remaining == 0 {
                    return Err(McpError::internal_error(
                        format!(
                            "resource listing exceeded the \
                             {MAX_RESOURCE_RESOLUTION_PAGES}-page sequence limit"
                        ),
                        None,
                    ));
                }
                pages_remaining -= 1;
                let sent_cursor = upstream_cursor.take();
                if let Some(cursor) = sent_cursor.as_deref() {
                    let fingerprint = resource_cursor_fingerprint(cursor);
                    if !seen_upstream_cursors.contains(&fingerprint) {
                        seen_upstream_cursors.push(fingerprint);
                    }
                }
                let listed = match self
                    .catalog
                    .list_resources(
                        server,
                        Some(PaginatedRequestParams::default().with_cursor(sent_cursor.clone())),
                        principal,
                    )
                    .await
                {
                    Ok(listed) => listed,
                    Err(error) if error.code == rmcp::model::ErrorCode::METHOD_NOT_FOUND => break,
                    Err(error) => return Err(error),
                };
                let next_upstream_cursor =
                    listed.next_cursor.clone().filter(|next| !next.is_empty());
                if let Some(next) = next_upstream_cursor.as_deref() {
                    let fingerprint = resource_cursor_fingerprint(next);
                    if seen_upstream_cursors.contains(&fingerprint) {
                        return Err(McpError::internal_error(
                            format!("upstream `{server}` repeated a resources/list cursor"),
                            None,
                        ));
                    }
                    seen_upstream_cursors.push(fingerprint);
                }

                // Empty metadata-free pages carry no downstream information.
                // Advance inside this request so an empty upstream does not
                // consume one of the client's pagination slots.
                if listed.resources.is_empty() && listed.meta.is_none() {
                    match next_upstream_cursor {
                        Some(next) => {
                            upstream_cursor = Some(next);
                            continue;
                        }
                        None => break,
                    }
                }

                let next_cursor = match next_upstream_cursor {
                    Some(cursor) => Some(Self::encode_resource_cursor(&ResourceCursor {
                        server: server.clone(),
                        upstream_cursor: Some(cursor),
                        pages_remaining,
                        seen_upstream_cursors: seen_upstream_cursors.clone(),
                    })?),
                    None if index + 1 < servers.len() => {
                        Some(Self::encode_resource_cursor(&ResourceCursor {
                            server: servers[index + 1].clone(),
                            upstream_cursor: None,
                            pages_remaining,
                            seen_upstream_cursors: Vec::new(),
                        })?)
                    }
                    None => None,
                };
                return Ok(ListResourcesResult {
                    result_type: Some(ResultType::COMPLETE),
                    resources: listed.resources,
                    next_cursor,
                    meta: listed.meta,
                    ttl_ms: None,
                    cache_scope: None,
                });
            }
            upstream_cursor = None;
            seen_upstream_cursors.clear();
        }

        Ok(ListResourcesResult {
            result_type: Some(ResultType::COMPLETE),
            resources: Vec::new(),
            next_cursor: None,
            meta: None,
            ttl_ms: None,
            cache_scope: None,
        })
    }

    pub async fn list_visible_resource_templates(
        &self,
        principal: Option<&Principal>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        tokio::time::timeout(RESOURCE_RESOLUTION_TIMEOUT, async {
            let mut templates = Vec::new();
            let mut template_bytes = 0_usize;
            let mut pages_remaining = MAX_RESOURCE_RESOLUTION_PAGES;
            for server in self.visible_resource_list_servers(principal).await {
                let mut cursor = None;
                let mut seen = HashSet::new();
                loop {
                    if pages_remaining == 0 {
                        return Err(McpError::internal_error(
                            format!(
                                "resource-template listing exceeded the \
                                 {MAX_RESOURCE_RESOLUTION_PAGES}-page fleet limit"
                            ),
                            None,
                        ));
                    }
                    pages_remaining -= 1;
                    let listed = match self
                        .catalog
                        .list_resource_templates(
                            &server,
                            Some(PaginatedRequestParams::default().with_cursor(cursor)),
                            principal,
                        )
                        .await
                    {
                        Ok(listed) => listed,
                        Err(error) if error.code == rmcp::model::ErrorCode::METHOD_NOT_FOUND => {
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    let next_count = templates
                        .len()
                        .checked_add(listed.resource_templates.len())
                        .ok_or_else(|| {
                            McpError::internal_error(
                                "resource-template listing exceeded the fleet item limit",
                                None,
                            )
                        })?;
                    if next_count > MAX_RESOURCE_TEMPLATES {
                        return Err(McpError::internal_error(
                            format!(
                                "resource-template listing exceeded the \
                                 {MAX_RESOURCE_TEMPLATES}-item fleet limit"
                            ),
                            None,
                        ));
                    }
                    for template in &listed.resource_templates {
                        let encoded_bytes = serde_json::to_vec(template)
                            .map_err(|_| {
                                McpError::internal_error(
                                    "upstream resource template could not be measured",
                                    None,
                                )
                            })?
                            .len();
                        template_bytes =
                            template_bytes.checked_add(encoded_bytes).ok_or_else(|| {
                                McpError::internal_error(
                                    "resource-template listing exceeded the fleet byte limit",
                                    None,
                                )
                            })?;
                        if template_bytes > MAX_RESOURCE_TEMPLATE_BYTES {
                            return Err(McpError::internal_error(
                                format!(
                                    "resource-template listing exceeded the \
                                     {MAX_RESOURCE_TEMPLATE_BYTES}-byte fleet limit"
                                ),
                                None,
                            ));
                        }
                    }
                    templates.extend(listed.resource_templates);
                    match listed.next_cursor.filter(|next| !next.is_empty()) {
                        Some(next) => {
                            if !seen.insert(next.clone()) {
                                return Err(McpError::internal_error(
                                    format!(
                                        "upstream `{server}` repeated a \
                                         resources/templates/list cursor"
                                    ),
                                    None,
                                ));
                            }
                            cursor = Some(next);
                        }
                        None => break,
                    }
                }
            }
            Ok(ListResourceTemplatesResult::with_all_items(templates))
        })
        .await
        .map_err(|_| {
            McpError::internal_error(
                "resource-template listing exceeded the 30-second deadline",
                None,
            )
        })?
    }

    async fn authorize_skill_catalog_list(
        &self,
        principal: Option<&Principal>,
        snapshot: &waygate_skills::SkillCatalogSnapshot,
    ) -> Result<Option<Vec<String>>, McpError> {
        let Some(principal) = principal else {
            return Ok(None);
        };
        if profile_blocks_resources(principal, GATEWAY_SKILLS_SERVER) {
            self.record_skill_catalog_list(
                principal,
                snapshot,
                &[],
                AuditOutcome::Denied,
                Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON),
            )
            .await;
            return Err(McpError::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                crate::skills::LIST_METHOD,
                None,
            ));
        }
        match self
            .authz
            .authorize_skill_list(principal, &skill_catalog_facts(snapshot))
            .await
        {
            AuthzVerdict::Allow { policy_ids } => Ok(Some(policy_ids)),
            verdict => {
                let (outcome, policy_ids, reason) = skill_refusal(&verdict);
                self.record_skill_catalog_list(
                    principal,
                    snapshot,
                    policy_ids,
                    outcome,
                    Some(&reason),
                )
                .await;
                Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    crate::skills::LIST_METHOD,
                    None,
                ))
            }
        }
    }

    async fn record_skill_catalog_list(
        &self,
        principal: &Principal,
        snapshot: &waygate_skills::SkillCatalogSnapshot,
        policy_ids: &[String],
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) {
        let event = skill_list_decision_event(principal, snapshot, outcome)
            .with_policies(policy_ids.to_vec());
        self.audit
            .record_chained_best_effort(match reason {
                Some(reason) => event.with_reason(reason),
                None => event,
            })
            .await;
    }

    async fn authorize_gateway_skill_read(
        &self,
        principal: Option<&Principal>,
        identity: &waygate_skills::SkillResourceIdentity,
    ) -> Result<Option<Vec<String>>, McpError> {
        SkillResourceAccess::new(&self.authz, &self.audit)
            .authorize_gateway_skill_read(principal, identity)
            .await
    }

    async fn authorize_gateway_skill_fetch(
        &self,
        principal: Option<&Principal>,
        facts: &SkillAccessFacts,
    ) -> Result<(), McpError> {
        SkillResourceAccess::new(&self.authz, &self.audit)
            .authorize_gateway_skill_fetch(principal, facts)
            .await
    }

    async fn record_gateway_skill_read(
        &self,
        principal: &Principal,
        identity: &waygate_skills::SkillResourceIdentity,
        policy_ids: &[String],
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) {
        SkillResourceAccess::new(&self.authz, &self.audit)
            .record_gateway_skill_read(principal, identity, policy_ids, outcome, reason)
            .await
    }

    async fn ensure_skill_catalog_origin_isolation(
        &self,
        snapshot: &waygate_skills::SkillCatalogSnapshot,
    ) -> Result<(), McpError> {
        let routing = self.catalog.resource_routing_snapshot().await;
        let collision = snapshot.skills().iter().any(|skill| {
            skill.resources.iter().any(|resource| {
                routing
                    .claims
                    .iter()
                    .any(|(_, claim)| resource.uri.starts_with(&claim.uri_prefix))
            })
        });
        if collision {
            return Err(McpError::invalid_params(
                "gateway skill catalog overlaps an upstream resource reservation",
                None,
            ));
        }
        Ok(())
    }

    async fn read_verified_skill_resource(
        &self,
        uri: &str,
        principal: Option<&Principal>,
        include_cache_hints: bool,
    ) -> Result<Option<ReadResourceResult>, McpError> {
        if !uri.starts_with("skill://") {
            return Ok(None);
        }
        // The gateway owns this URI scheme even after a skill is withdrawn.
        // A stale reference must never acquire a different upstream provenance.
        let snapshot = self.resolve_approved_skill(uri, None, principal).await?;
        self.read_skill_snapshot_resource(&snapshot, uri, principal, include_cache_hints)
            .await
    }

    async fn read_skill_snapshot_resource(
        &self,
        snapshot: &Arc<waygate_skills::SkillCatalogSnapshot>,
        uri: &str,
        principal: Option<&Principal>,
        include_cache_hints: bool,
    ) -> Result<Option<ReadResourceResult>, McpError> {
        let Some(catalog) = self.skill_catalog.as_ref() else {
            return Ok(None);
        };
        let Some(descriptor) = snapshot.resource(uri) else {
            return Ok(None);
        };
        self.check_skill_approval(snapshot, uri, principal).await?;
        let fetch_facts = skill_resource_fetch_facts(snapshot, descriptor);
        self.authorize_gateway_skill_fetch(principal, &fetch_facts)
            .await?;
        let loaded = catalog
            .load_resource(snapshot, uri)
            .await
            .map_err(|_| {
                McpError::internal_error(
                    "skill resource could not be loaded from its indexed Git revision",
                    None,
                )
            })?
            .expect("resource membership was checked in the same immutable snapshot");
        let identity = snapshot
            .resource_identity(uri, loaded.content_digest.clone())
            .expect("resource membership has an owning skill identity");

        let permit = self
            .authorize_gateway_skill_read(principal, &identity)
            .await?;
        let access = async {
            self.ensure_skill_catalog_origin_isolation(snapshot).await?;
            let result = crate::skills::render_loaded_resource(&loaded, include_cache_hints);

            match self
                .inspect_resource_result(result, principal, GATEWAY_SKILLS_SERVER, RiskTier::Low)
                .await
            {
                Ok((verified, redactions)) if redactions.is_empty() => {
                    self.check_skill_approval(snapshot, uri, principal).await?;
                    Ok(verified)
                }
                Ok((_, redactions)) => {
                    let inspector_name = redactions[0].0;
                    let reason = "redaction would invalidate the skill resource digest".to_owned();
                    waygate_telemetry::metrics::record_response_inspector_block(
                        GATEWAY_SKILLS_SERVER,
                        "resources/read",
                        inspector_name,
                    );
                    Err(resource_inspection_error(inspector_name, reason))
                }
                Err(block) => Err(resource_inspection_error(
                    block.inspector_name,
                    block.reason,
                )),
            }
        }
        .await;

        if let (Some(principal), Some(policy_ids)) = (principal, permit.as_deref()) {
            let outcome = match &access {
                Ok(_) => AuditOutcome::Success,
                Err(error) if error.code == rmcp::model::ErrorCode::INTERNAL_ERROR => {
                    AuditOutcome::ExecutionError
                }
                Err(_) => AuditOutcome::Denied,
            };
            let reason = access
                .as_ref()
                .err()
                .map(post_authorization_skill_refusal_reason);
            self.record_gateway_skill_read(
                principal,
                &identity,
                policy_ids,
                outcome,
                reason.as_deref(),
            )
            .await;
        }
        if access.is_ok() {
            if let Err(error) = self.check_skill_approval(snapshot, uri, principal).await {
                if let (Some(principal), Some(policy_ids)) = (principal, permit.as_deref()) {
                    self.record_gateway_skill_read(principal, &identity, policy_ids, AuditOutcome::Denied, Some("Skill distribution was refused after the initial authorization audit; no content was released")).await;
                }
                return Err(error);
            }
        }
        access.map(Some)
    }

    pub async fn read_visible_resource(
        &self,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
    ) -> Result<ReadResourceResult, McpError> {
        self.read_visible_resource_with_transfer(params, principal, false)
            .await
    }

    async fn read_visible_resource_with_transfer(
        &self,
        mut params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        governed_file_transfer: bool,
    ) -> Result<ReadResourceResult, McpError> {
        params.meta.get_or_insert_with(Default::default).insert(
            crate::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY.to_owned(),
            json!(self.resource_response_max_bytes),
        );
        let resolved = match tokio::time::timeout(
            RESOURCE_RESOLUTION_TIMEOUT,
            self.resolve_resource_owners(&params.uri, principal),
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(_) => Err(McpError::internal_error(
                "resource ownership resolution exceeded the 30-second deadline",
                None,
            )),
        };
        let owners = match resolved {
            Ok(owners) => owners,
            Err(error) => {
                // Resolution itself failed — a deadline, an upstream that could
                // not list, a repeated cursor, an exhausted page budget. The
                // caller still asked to read this URI, and an attempt that
                // leaves no evidence is exactly what a caller probing an
                // unhealthy fleet would rely on. Recorded as an execution
                // error, because upstreams were reached and one of them is why
                // this failed.
                if let Some(principal) = principal {
                    self.audit
                        .record_chained_best_effort(
                            resource_decision_event(
                                principal,
                                &params.uri,
                                AuditOutcome::ExecutionError,
                            )
                            .with_reason(format!(
                                "resource ownership resolution failed: {}",
                                error.message
                            )),
                        )
                        .await;
                }
                return Err(error);
            }
        };
        let Some(principal) = principal else {
            // No auth context (disabled mode / anonymous transport): there is
            // no principal to decide against or attribute a decision to, so
            // the pre-authorization ambiguity contract is the whole contract.
            return match owners.as_slice() {
                [] => Err(unadvertised_resource()),
                [owner] => {
                    let result = self
                        .catalog
                        .read_resource_admitted(&owner.server, params, principal, &owner.admission)
                        .await
                        .map_err(public_resource_read_error)?;
                    match self
                        .inspect_resource_result(result, principal, &owner.server, owner.risk)
                        .await
                    {
                        Ok((result, redactions)) => {
                            if resource_result_has_file_contents(&result) {
                                Err(McpError::internal_error(
                                    "upstream returned file-backed resource content without a negotiated governed download capability",
                                    None,
                                ))
                            } else {
                                Self::record_resource_redactions(&owner.server, &redactions);
                                Ok(result)
                            }
                        }
                        Err(block) => Err(resource_inspection_error(
                            block.inspector_name,
                            block.reason,
                        )),
                    }
                }
                _ => Err(ambiguous_resource(&params.uri)),
            };
        };
        self.decide_and_read_resource(owners, params, principal, governed_file_transfer)
            .await
    }

    async fn inspect_resource_result(
        &self,
        mut result: ReadResourceResult,
        principal: Option<&Principal>,
        server: &str,
        risk: RiskTier,
    ) -> Result<(ReadResourceResult, Vec<(&'static str, u32)>), ResourceInspectionBlock> {
        if self.resource_inspectors.is_empty()
            || !result
                .contents
                .iter()
                .any(|content| matches!(content, ResourceContents::TextResourceContents { .. }))
        {
            return Ok((result, Vec::new()));
        }
        let tenant = principal
            .map(|principal| principal.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        let inspector_ctx = crate::inspection::InspectionContext {
            tenant,
            principal_sub: principal.map(|principal| principal.sub.as_str()),
            server,
            tool: "resources/read",
            risk,
            pii_classified: false,
        };
        let mut redactions = Vec::new();
        for inspector in &self.resource_inspectors {
            let projected = CallToolResult::success(
                result
                    .contents
                    .iter()
                    .filter_map(|content| match content {
                        ResourceContents::TextResourceContents { text, .. } => {
                            Some(rmcp::model::ContentBlock::text(text.clone()))
                        }
                        _ => None,
                    })
                    .collect(),
            );
            match inspector.inspect(&inspector_ctx, &projected).await {
                crate::inspection::Decision::Pass => {}
                crate::inspection::Decision::Block { reason } => {
                    let inspector_name = inspector.name();
                    tracing::info!(
                        server,
                        tool = "resources/read",
                        tenant,
                        user = ?inspector_ctx.principal_sub,
                        inspector = inspector_name,
                        reason,
                        "response_inspection_blocked: refusing to forward resource response",
                    );
                    waygate_telemetry::metrics::record_response_inspector_block(
                        server,
                        "resources/read",
                        inspector_name,
                    );
                    return Err(ResourceInspectionBlock {
                        inspector_name,
                        reason,
                    });
                }
                crate::inspection::Decision::Redact {
                    redacted,
                    findings_count,
                } => {
                    let inspector_name = inspector.name();
                    let replacement_texts: Option<Vec<String>> = redacted
                        .content
                        .iter()
                        .map(|content| content.as_text().map(|text| text.text.clone()))
                        .collect();
                    let text_count = result
                        .contents
                        .iter()
                        .filter(|content| {
                            matches!(content, ResourceContents::TextResourceContents { .. })
                        })
                        .count();
                    let Some(replacement_texts) = replacement_texts.filter(|texts| {
                        texts.len() == text_count
                            && findings_count > 0
                            && redacted.structured_content.is_none()
                            && redacted.is_error == Some(false)
                            && redacted.meta.is_none()
                            && redacted.result_type == Some(ResultType::COMPLETE)
                    }) else {
                        let reason = "inspector returned a malformed resource redaction".to_owned();
                        tracing::info!(
                            server,
                            tool = "resources/read",
                            tenant,
                            user = ?inspector_ctx.principal_sub,
                            inspector = inspector_name,
                            reason,
                            "response_inspection_blocked: refusing malformed resource redaction",
                        );
                        waygate_telemetry::metrics::record_response_inspector_block(
                            server,
                            "resources/read",
                            inspector_name,
                        );
                        return Err(ResourceInspectionBlock {
                            inspector_name,
                            reason,
                        });
                    };
                    for (text, replacement) in result
                        .contents
                        .iter_mut()
                        .filter_map(|content| match content {
                            ResourceContents::TextResourceContents { text, .. } => Some(text),
                            _ => None,
                        })
                        .zip(replacement_texts)
                    {
                        *text = replacement;
                    }
                    tracing::info!(
                        server,
                        tool = "resources/read",
                        tenant,
                        user = ?inspector_ctx.principal_sub,
                        inspector = inspector_name,
                        findings_count,
                        "response_inspector_redacted: applied to resource response (pending forward confirmation)",
                    );
                    redactions.push((inspector_name, findings_count));
                }
            }
        }
        Ok((result, redactions))
    }

    fn record_resource_redactions(server: &str, redactions: &[(&'static str, u32)]) {
        for (inspector_name, findings_count) in redactions {
            waygate_telemetry::metrics::record_response_inspector_redaction(
                server,
                "resources/read",
                inspector_name,
                *findings_count,
            );
        }
    }

    /// Narrow the advertising upstreams to the ones this caller may actually
    /// read, then authorize, record the decision, and dispatch on an allow.
    ///
    /// Narrowing before reporting ambiguity is what keeps a multi-owner URI
    /// from disclosing an upstream the caller has no standing on: a URI served
    /// by one readable upstream and one denied one is served, not ambiguous.
    /// Ambiguity is only reported when the caller could read more than one,
    /// which tells them nothing `resources/list` would not.
    async fn decide_and_read_resource(
        &self,
        owners: Vec<ResourceOwner>,
        params: ReadResourceRequestParams,
        principal: &Principal,
        governed_file_transfer: bool,
    ) -> Result<ReadResourceResult, McpError> {
        let uri = params.uri.clone();
        let mut decided: Vec<(ResourceOwner, AuthzVerdict)> = Vec::with_capacity(owners.len());
        for owner in owners {
            let verdict = self
                .authz
                .authorize_resource_read(principal, &owner.server, &uri, owner.risk)
                .await;
            decided.push((owner, verdict));
        }
        // One identifier joins the authorization decision to every governed
        // file-transfer row produced by this read. Build each possible verdict
        // event with that same id; exactly one branch records it.
        let decision_id = uuid::Uuid::now_v7();
        let event = |outcome| {
            let mut event = resource_decision_event(principal, &uri, outcome);
            event.id = decision_id;
            event
        };

        let readable: Vec<&(ResourceOwner, AuthzVerdict)> = decided
            .iter()
            .filter(|(_, verdict)| verdict.is_allow())
            .collect();
        if readable.len() > 1 {
            // Policy allowed this read on more than one upstream and the
            // gateway cannot choose between them, so nothing was served.
            //
            // Recorded as denied, not as an execution error: an execution
            // error means the attempt reached an upstream and something there
            // went wrong, and the overview, Decision Log, ECS and OCSF paths
            // all read it as a system failure. This refusal never reached an
            // upstream, so classifying it that way would inflate error
            // reporting with a deterministic configuration problem.
            //
            // The permits DO ride along. They are not what refused the read,
            // but they are why it became ambiguous — each one is a policy that
            // made another upstream readable — so a reverse lookup on any of
            // them has to find this decision. Without them the row can say a
            // resource read was refused but not which policies produced the
            // conflict. `server` stays unset because there are several by
            // definition; the reason names them all.
            let servers: Vec<&str> = readable
                .iter()
                .map(|(owner, _)| owner.server.as_str())
                .collect();
            let policy_ids: Vec<String> = readable
                .iter()
                .flat_map(|(_, verdict)| verdict.policy_ids().to_vec())
                .collect();
            self.audit
                .record_chained_best_effort(
                    event(AuditOutcome::Denied)
                        .with_policies(policy_ids)
                        .with_reason(format!(
                            "readable on multiple upstreams ({}); no owner could be selected",
                            servers.join(", ")
                        )),
                )
                .await;
            return Err(ambiguous_resource(&uri));
        }
        // Every policy that participated, not only the selected verdict's.
        // Two owners can refuse a URI for different reasons, and each of those
        // policies helped make it unreadable — a reverse lookup on any of them
        // has to reach this decision, and picking one verdict to answer the
        // caller must not silently drop the rest of the explanation.
        let all_policy_ids: Vec<String> = decided
            .iter()
            .flat_map(|(_, verdict)| verdict.policy_ids().to_vec())
            .collect();
        // One allow settles it. Otherwise the most actionable refusal wins,
        // NOT whichever upstream the fleet happened to list first: if one owner
        // says approval-gated and another says forbidden, the caller has a way
        // forward and should be told about it, and the same fleet must not
        // answer differently just because its listing order changed.
        let Some((owner, verdict)) = readable
            .first()
            .copied()
            .or_else(|| {
                decided
                    .iter()
                    .max_by_key(|(_, verdict)| verdict_actionability(verdict))
            })
            .map(|(owner, verdict)| (owner.clone(), verdict.clone()))
        else {
            // No visible upstream advertises this URI — either it exists
            // nowhere, or every upstream that serves it is hidden from this
            // caller. Nothing was authorized, so no policy ids ride along, but
            // the attempt is still recorded: a caller sweeping the gateway for
            // resource URIs would otherwise leave no evidence at all, and
            // "nobody serves that" is exactly the answer such a sweep is
            // looking for.
            self.audit
                .record_chained_best_effort(
                    event(AuditOutcome::Denied)
                        .with_reason("no visible upstream advertises this resource URI"),
                )
                .await;
            return Err(unadvertised_resource());
        };
        let owner_risk = owner.risk;
        let owner_admission = owner.admission.clone();
        let owner = owner.server.as_str();

        match verdict {
            AuthzVerdict::Allow { .. } => {
                let started = std::time::Instant::now();
                let upstream_result = self
                    .catalog
                    .read_resource_admitted(owner, params, Some(principal), &owner_admission)
                    .await;
                let routing_changed = matches!(
                    &upstream_result,
                    Err(AdmittedResourceReadError::RoutingChanged)
                );
                let bounded_unsupported = matches!(
                    &upstream_result,
                    Err(AdmittedResourceReadError::BoundedUnsupported { .. })
                );
                let upstream_result = upstream_result.map_err(public_resource_read_error);
                let mut redactions = Vec::new();
                let mut blocked_inspector = None;
                let inspected = match upstream_result {
                    Ok(result) => match self
                        .inspect_resource_result(result, Some(principal), owner, owner_risk)
                        .await
                    {
                        Ok((result, pending)) => {
                            redactions = pending;
                            Ok(result)
                        }
                        Err(block) => {
                            blocked_inspector = Some(block.inspector_name);
                            Err(resource_inspection_error(
                                block.inspector_name,
                                block.reason,
                            ))
                        }
                    },
                    Err(error) => Err(error),
                };
                let result = match (
                    inspected,
                    governed_file_transfer,
                    &self.file_output_processor,
                ) {
                    (Ok(result), true, Some(processor)) => {
                        let prepared = processor
                            .prepare_resource(
                                crate::files::FileOutputContext {
                                    principal: Some(principal.clone()),
                                    server: owner.to_owned(),
                                    tool: "resources/read".to_owned(),
                                    invocation_id: decision_id.to_string(),
                                },
                                result,
                            )
                            .await;
                        match prepared {
                            Ok(prepared) => {
                                if let Some(batch_id) = prepared.batch_id.as_deref() {
                                    if let Err(error) =
                                        processor.publish(batch_id, prepared.file_count).await
                                    {
                                        processor.discard(batch_id).await;
                                        Err(error)
                                    } else {
                                        Ok(prepared.result)
                                    }
                                } else {
                                    Ok(prepared.result)
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                    (Ok(result), _, _)
                        if resource_result_has_file_contents(&result) =>
                    {
                        Err(McpError::internal_error(
                            "upstream returned file-backed resource content without a negotiated governed download capability",
                            None,
                        ))
                    }
                    (result, _, _) => result,
                };
                let inspection_blocked = blocked_inspector.is_some();
                let outcome = if result.is_ok() {
                    AuditOutcome::Success
                } else if routing_changed || bounded_unsupported {
                    // These local governance checks refuse before dispatch.
                    AuditOutcome::Denied
                } else {
                    // Every other failure follows an attempted upstream read,
                    // including response inspection, file processing, and an
                    // HTTP response that crossed the byte budget.
                    AuditOutcome::ExecutionError
                };
                let decision = event(outcome)
                    .with_server(owner)
                    .with_risk(owner_risk)
                    .with_policies(all_policy_ids)
                    .with_latency_ms(
                        i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
                    );
                let decision = if routing_changed {
                    decision.with_reason("resource routing changed after authorization")
                } else if bounded_unsupported {
                    decision.with_reason("bounded resource reads are unsupported by this transport")
                } else if inspection_blocked {
                    decision.with_reason(format!(
                        "response inspector `{}` blocked the resource response",
                        blocked_inspector.unwrap_or("unknown"),
                    ))
                } else if result.is_ok() && !redactions.is_empty() {
                    decision.with_reason(
                        redactions
                            .iter()
                            .map(|(name, count)| {
                                format!("response inspector `{name}` redacted {count} finding(s)")
                            })
                            .collect::<Vec<_>>()
                            .join("; "),
                    )
                } else {
                    decision
                };
                if result.is_ok() {
                    // File publication, when negotiated, has completed at this
                    // point. Only now may telemetry claim a redaction reached
                    // the caller-facing result.
                    Self::record_resource_redactions(owner, &redactions);
                }
                self.audit.record_chained_best_effort(decision).await;
                result
            }
            AuthzVerdict::Deny {
                reason,
                policy_ids,
                reasons,
            } => {
                tracing::info!(
                    user = %principal.sub,
                    server = %owner,
                    reason = %reason,
                    policies = ?policy_ids,
                    cedar_reasons = ?reasons,
                    "resource read denied",
                );
                self.audit
                    .record_chained_best_effort(
                        event(AuditOutcome::Denied)
                            .with_server(owner)
                            .with_risk(owner_risk)
                            .with_policies(all_policy_ids)
                            .with_reason(&reason),
                    )
                    .await;
                // The row above carries the real reason and the policies that
                // produced it; the caller gets the answer an unserved URI gets.
                Err(unadvertised_resource())
            }
            AuthzVerdict::StepUpRequired {
                required_scope,
                reason,
                policy_ids,
            } => {
                tracing::info!(
                    user = %principal.sub,
                    server = %owner,
                    %required_scope,
                    reason = %reason,
                    policies = ?policy_ids,
                    "resource read requires step-up",
                );
                self.audit
                    .record_chained_best_effort(
                        event(AuditOutcome::StepUpRequired)
                            .with_server(owner)
                            .with_risk(owner_risk)
                            .with_policies(all_policy_ids)
                            .with_reason(format!("scope {required_scope}: {reason}")),
                    )
                    .await;
                // Named so the caller can re-authorize and retry rather than
                // reading the refusal as final.
                let data = serde_json::json!({
                    "error": "insufficient_scope",
                    "required_scope": required_scope,
                    "reason": reason,
                });
                Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_REQUEST,
                    format!(
                        "reading `{uri}` requires re-authorization with scope `{required_scope}`: \
                         {reason}"
                    ),
                    Some(data),
                ))
            }
            AuthzVerdict::ApprovalRequired { reason, policy_ids } => {
                // The tool plane answers this by carrying the call into an
                // approval stage that claims a live grant. The resource path
                // has no such stage, so the honest answer is a refusal that
                // names the gate instead of a dispatch that ignores it.
                tracing::info!(
                    user = %principal.sub,
                    server = %owner,
                    reason = %reason,
                    policies = ?policy_ids,
                    "resource read is approval-gated by policy",
                );
                self.audit
                    .record_chained_best_effort(
                        event(AuditOutcome::Denied)
                            .with_server(owner)
                            .with_risk(owner_risk)
                            .with_policies(all_policy_ids)
                            .with_reason(format!("approval required: {reason}")),
                    )
                    .await;
                Err(McpError::invalid_request(
                    format!(
                        "reading `{uri}` is gated on a per-call approval grant, which resource \
                         reads cannot claim: {reason}"
                    ),
                    None,
                ))
            }
        }
    }

    /// Caller-visible upstreams advertising `uri`, in fleet order.
    async fn resolve_resource_owners(
        &self,
        uri: &str,
        principal: Option<&Principal>,
    ) -> Result<Vec<ResourceOwner>, McpError> {
        if crate::files::is_reserved_file_uri(uri) {
            return Ok(Vec::new());
        }
        let routing = self.catalog.resource_routing_snapshot().await;
        let declared: Vec<(String, ResourceClaim)> = routing
            .claims
            .iter()
            .filter(|(_, claim)| uri.starts_with(&claim.uri_prefix))
            .cloned()
            .collect();
        if !declared.is_empty() {
            let mut owners = Vec::with_capacity(declared.len());
            for (server, claim) in declared {
                if !self
                    .declared_resource_server_visible(principal, &server)
                    .await
                {
                    continue;
                }
                owners.push(ResourceOwner {
                    risk: claim.risk,
                    admission: ResourceReadAdmission {
                        generation: routing.generation,
                        server: server.clone(),
                        claim: Some(claim),
                    },
                    server,
                });
            }
            return Ok(owners);
        }

        let visible = self.visible_resource_servers(principal).await;
        let mut owners: Vec<ResourceOwner> = Vec::new();
        let mut pages_remaining = MAX_RESOURCE_RESOLUTION_PAGES;
        for server in visible {
            // A declaring upstream owns only the URI spaces it registered.
            // Enumeration remains solely as the compatibility path for
            // existing resource servers whose manifests declare nothing.
            if routing
                .claims
                .iter()
                .any(|(claimed_server, _)| claimed_server == &server)
            {
                continue;
            }
            let mut cursor = None;
            let mut seen = HashSet::new();
            loop {
                if pages_remaining == 0 {
                    return Err(McpError::internal_error(
                        format!(
                            "resource ownership resolution exceeded the \
                             {MAX_RESOURCE_RESOLUTION_PAGES}-page fleet limit"
                        ),
                        None,
                    ));
                }
                pages_remaining -= 1;
                let listed = match self
                    .catalog
                    .list_resources(
                        &server,
                        Some(PaginatedRequestParams::default().with_cursor(cursor.clone())),
                        principal,
                    )
                    .await
                {
                    Ok(listed) => listed,
                    Err(error) if error.code == rmcp::model::ErrorCode::METHOD_NOT_FOUND => break,
                    Err(error) => return Err(error),
                };
                if listed.resources.iter().any(|resource| resource.uri == uri)
                    && !owners.iter().any(|existing| existing.server == server)
                {
                    owners.push(ResourceOwner {
                        server: server.clone(),
                        risk: RiskTier::Low,
                        admission: ResourceReadAdmission {
                            generation: routing.generation,
                            server: server.clone(),
                            claim: None,
                        },
                    });
                }
                match listed.next_cursor {
                    Some(next) if !next.is_empty() => {
                        if !seen.insert(next.clone()) {
                            return Err(McpError::internal_error(
                                format!("upstream `{server}` repeated a resources/list cursor"),
                                None,
                            ));
                        }
                        cursor = Some(next);
                    }
                    _ => break,
                }
            }
        }

        Ok(owners)
    }

    /// The full `tools/list` payload for this session: meta-tools plus any
    /// upstream tools already disclosed via `searchTools`. Authorization is
    /// re-evaluated per call so tools whose policy flipped to deny after
    /// disclosure drop out. Tools are renamed to their fully-qualified
    /// `<server>.<tool>` form so the `tools/call` dispatcher can route them.
    ///
    /// When the process-wide eager override is set, or this session's MCP
    /// client name matched the configured fallback allowlist, the full
    /// upstream catalog is appended regardless of what the session has
    /// disclosed. Authorization and runtime-admission filters still apply.
    pub async fn list_visible_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        let projection = if self.eager_tools_list_active() {
            ToolProjection::Full {
                canonical_order: true,
            }
        } else {
            ToolProjection::SessionDisclosed(&self.disclosed)
        };
        self.list_visible_tools_with(principal, projection).await
    }

    /// Build one exact authorization/catalog generation for protocol
    /// tools/list. Durable catalog commits, local policy/catalog publications,
    /// and authoritative per-tool read failures each invalidate the attempt.
    async fn stable_list_visible_tools_with(
        &self,
        principal: Option<&Principal>,
        projection: ToolProjection<'_>,
    ) -> Result<Vec<Tool>, McpError> {
        for _ in 0..MAX_CATALOG_SNAPSHOT_RETRIES {
            let durable_before = self.catalog.discovery_generation().await?;
            let errors_before = self.catalog.discovery_error_generation();
            let local_generation = match self.tool_catalog_epoch.as_ref() {
                Some(epoch) => match epoch.stable_generation() {
                    Some(generation) => Some(generation),
                    None => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                },
                None => None,
            };
            let visible = self.list_visible_tools_with(principal, projection).await;
            let durable_after = self.catalog.discovery_generation().await?;
            let errors_after = self.catalog.discovery_error_generation();
            if catalog_projection_is_stable(
                self.tool_catalog_epoch.as_ref(),
                local_generation,
                durable_before,
                durable_after,
                errors_before,
                errors_after,
            ) {
                return Ok(visible);
            }
            tokio::task::yield_now().await;
        }
        Err(McpError::internal_error(
            "the governed tool catalog changed or became unavailable during tools/list; retry the request",
            Some(json!({"error": "catalog_changing", "retryable": true})),
        ))
    }

    /// [`Self::list_visible_tools`] with the protocol projection resolved by
    /// the caller. The enum prevents a 2026 request from accidentally
    /// consulting legacy session disclosure memory.
    async fn list_visible_tools_with(
        &self,
        principal: Option<&Principal>,
        projection: ToolProjection<'_>,
    ) -> Vec<Tool> {
        let (include_meta_tools, full_projection, canonical_order) = match projection {
            ToolProjection::Full { canonical_order } => (true, true, canonical_order),
            ToolProjection::SessionDisclosed(_) => (true, false, false),
            ToolProjection::BuiltinsOnly { canonical_order } => (false, false, canonical_order),
        };
        let mut out = if include_meta_tools {
            self.list_meta_tools(principal).await
        } else {
            Vec::new()
        };

        // Built-in (gateway-local) tools, listed directly rather than behind a
        // searchTools meta-tool: the set is small and fixed, and each impl
        // gates its tools on its own scope (HITL `gateway-admin.*` needs
        // `mcp:propose`; the `gateway-observe.*` read plane needs
        // `mcp:observe`), so a caller without that scope sees nothing extra.
        // Appended here — alongside the always-available meta-tools and
        // *before* the session-disclosure logic — because built-ins are not
        // session-disclosed and the disclosure path can `return out` early
        // for a fresh session that has revealed nothing yet.
        for builtin in &self.builtins {
            // Namespace-scoped built-ins are hidden from a principal confined
            // to another server. A delegated data-plane surface applies that
            // profile to every resource it returns, so the outer facade stays
            // visible and usable without adding its namespace to every
            // upstream profile.
            let ns = builtin.namespace();
            if let Some(p) =
                principal.filter(|_| builtin.profile_scope() == BuiltinProfileScope::Namespace)
            {
                if profile_blocks_server(p, ns) {
                    continue;
                }
            }
            let catalog = builtin.catalog();
            for tool in builtin.list_tools(principal).await {
                let bare = tool
                    .name
                    .strip_prefix(ns)
                    .and_then(|rest| rest.strip_prefix('.'))
                    .unwrap_or(tool.name.as_ref());
                if let Some(p) =
                    principal.filter(|_| builtin.profile_scope() == BuiltinProfileScope::Namespace)
                {
                    // Tool-level allow-list parity with upstream discovery.
                    if profile_blocks_tool(p, ns, bare) {
                        continue;
                    }
                }
                let Some(canonical_record) = catalog
                    .tools
                    .iter()
                    .find(|record| record.identity.name == bare)
                else {
                    // A handler's principal-filtered list selects which
                    // canonical records are visible; it never supplies a
                    // second definition authority, including in disabled
                    // auth mode.
                    continue;
                };
                if let Some(p) = principal {
                    let governance_tool = builtin.governance_tool(bare);
                    let Some(governance_record) = catalog
                        .tools
                        .iter()
                        .find(|record| record.identity.name == governance_tool)
                    else {
                        // Continuation aliases carry the authority of their
                        // originating operation. A broken mapping must hide
                        // the alias rather than authorizing it under weaker
                        // alias-local facts.
                        continue;
                    };
                    // Match upstream discovery: a step-up result remains
                    // discoverable so the client can re-authenticate, while a
                    // determining deny never exposes the definition. Use the
                    // same governance identity dispatch resolves for aliases.
                    let discoverable = matches!(
                        self.authz
                            .authorize_builtin_call(p, &governance_record.facts)
                            .await,
                        BuiltinAuthz::Proceed | BuiltinAuthz::StepUpRequired { .. }
                    );
                    if !discoverable {
                        continue;
                    }
                }
                out.push(canonical_record.definition.clone());
            }
        }

        if matches!(projection, ToolProjection::BuiltinsOnly { .. }) {
            retain_publishable_tools(&mut out);
            if canonical_order {
                out.sort_unstable_by(|left, right| left.name.cmp(&right.name));
            }
            return out;
        }

        // Which `<server>.<tool>` names to surface in `tools/list` beyond the
        // meta-tools. Eager mode uses the whole catalog; the SEP #1888 path
        // uses just what this session has disclosed via `searchTools`.
        // Keys/values are owned so borrow lifetimes stay tidy across the
        // async loop below.
        let mut by_server: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        if full_projection {
            for server in self.catalog.list_servers().await {
                if let Ok(tools) = self.catalog.list_tools(&server).await {
                    by_server.insert(server, tools.iter().map(|t| t.name.to_string()).collect());
                }
            }
        } else {
            let ToolProjection::SessionDisclosed(disclosed) = projection else {
                unreachable!("the full projection returned above")
            };
            let revealed = disclosed.snapshot();
            if revealed.is_empty() {
                retain_publishable_tools(&mut out);
                return out;
            }
            for fq in revealed {
                if let Some((server, tool_name)) = fq.split_once('.') {
                    by_server
                        .entry(server.to_owned())
                        .or_default()
                        .push(tool_name.to_owned());
                }
            }
        }

        for (server, wanted) in by_server {
            if let Some(p) = principal {
                // Same profile filter
                // as list_meta_tools — skip whole-server.
                if profile_blocks_server(p, &server) {
                    continue;
                }
                if !self.authz.may_discover_server(p, &server).await {
                    continue;
                }
            }
            let Ok(upstream_tools) = self.catalog.list_tools(&server).await else {
                continue;
            };
            for tool_name in &wanted {
                let Some(t) = upstream_tools.iter().find(|t| t.name == *tool_name) else {
                    continue;
                };
                if let Some(p) = principal {
                    // Skip per-tool
                    // when the profile pins allowed_tools.
                    if profile_blocks_tool(p, &server, &t.name) {
                        continue;
                    }
                }
                let tenant = principal
                    .map(|p| p.tenant.as_str())
                    .unwrap_or(waygate_core::TenantId::DEFAULT);
                // A quarantined/retired server's tools are hidden from
                // discovery (and refused at dispatch); only an admitted snapshot is
                // listable.
                let ResolvedInvocationTool::Ready(snapshot) = self
                    .catalog
                    .resolve_discovery_tool(tenant, &server, tool_name)
                    .await
                else {
                    continue;
                };
                let facts = snapshot.facts();
                if let Some(p) = principal {
                    // `is_discoverable()` mirrors searchTools: step-up tools
                    // stay listed so the client can re-auth and retry.
                    if !self.authz.may_call_tool(p, facts).await.is_discoverable() {
                        continue;
                    }
                }
                let Some(record) = CatalogTool::from_upstream_snapshot(&server, snapshot) else {
                    // Discovery publishes only the schema contract admitted
                    // for invocation together with a definition captured by
                    // the same resolution.
                    continue;
                };
                if canonical_order
                    && record.identity.name == "searchTools"
                    && tool_has_publishable_input_schema(&record.definition)
                {
                    let adapter_name = format!("{server}{SEARCH_TOOLS_SUFFIX}");
                    out.retain(|tool| tool.name != adapter_name);
                }
                out.push(record.definition);
            }
        }
        retain_publishable_tools(&mut out);
        if canonical_order {
            // Catalog publication compares descriptor sets by name and does
            // not emit a change for an upstream-only reorder. Canonicalize the
            // whole full projection so such a reorder cannot change the 2026
            // wire array without a corresponding list-changed notification.
            out.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        }
        out
    }

    async fn handle_search_tools(
        &self,
        server: &str,
        req: SearchToolsRequest,
        principal: Option<&Principal>,
        disclosed: Option<&DisclosedTools>,
    ) -> Result<CallToolResult, McpError> {
        let result = match req.mode {
            Mode::Operations => {
                self.handle_operations(server, &req, principal, disclosed)
                    .await
            }
            // handle_types needs
            // the principal to apply profile + Cedar gates.
            // Without it a profile-restricted key could request
            // a disallowed tool's schema via mode=types.
            Mode::Types => self.handle_types(server, &req, principal).await,
        };
        // Best-effort `Discovery` audit. `searchTools` was previously
        // unaudited, so SEP #1888 discovery never appeared in the Activity
        // feed at all. Best-effort because discovery is high-volume and
        // non-security-critical — an audit hiccup must never fail a
        // discovery call. Gated by `GATEWAY_AUDIT_DISCOVERY` (off by
        // default). Records server + outcome + mode; no result payload.
        if self.audit_discovery {
            let mode = match req.mode {
                Mode::Operations => "operations",
                Mode::Types => "types",
            };
            let outcome = if result.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::ExecutionError
            };
            self.audit
                .record_best_effort(
                    AuditEvent::new("SearchTools", outcome)
                        .with_category(EvidenceCategory::Discovery)
                        .with_principal(principal)
                        .with_tool(server, "searchTools")
                        .with_reason(format!("mode={mode}")),
                )
                .await;
        }
        result
    }

    async fn handle_operations(
        &self,
        server: &str,
        req: &SearchToolsRequest,
        principal: Option<&Principal>,
        disclosed: Option<&DisclosedTools>,
    ) -> Result<CallToolResult, McpError> {
        let query = req
            .filters
            .as_ref()
            .and_then(|f| f.query.as_deref())
            .filter(|q| !q.trim().is_empty());

        // BM25 path: ask the index for a ranked list of tool names, then
        // reorder the catalog view to match. `limit + 1` gives pagination a
        // little headroom without fetching the full corpus on every query.
        // The index generation fences the separately-awaited catalog snapshot:
        // a refresh that lands between them forces a retry, and sustained churn
        // falls back to filtering one fresh catalog snapshot without BM25.
        // If the index rejects the query (parse error, empty input) we fall
        // back to substring match so weird user input still surfaces
        // something sensible.
        let tools = match (self.index.as_ref(), query) {
            (Some(idx), Some(q)) => {
                let mut stable = None;
                for _ in 0..MAX_CATALOG_SNAPSHOT_RETRIES {
                    let generation = idx.generation();
                    let tools = self.catalog.list_tools(server).await?;
                    let (ranked, fallback) = match idx.search(server, q, 500) {
                        Ok(Some(names)) => (index::reorder_by_names(tools, &names), None),
                        Ok(None) => (
                            tools
                                .into_iter()
                                .filter(|t| index::matches(t, req.filters.as_ref()))
                                .collect(),
                            Some(waygate_telemetry::metrics::DiscoveryIndexFallback::NoOpinion),
                        ),
                        Err(_) => (
                            tools
                                .into_iter()
                                .filter(|t| index::matches(t, req.filters.as_ref()))
                                .collect(),
                            Some(waygate_telemetry::metrics::DiscoveryIndexFallback::QueryError),
                        ),
                    };
                    if idx.is_stable_generation(generation) {
                        if let Some(reason) = fallback {
                            waygate_telemetry::metrics::record_discovery_index_fallback(reason);
                        }
                        stable = Some(ranked);
                        break;
                    }
                }
                match stable {
                    Some(tools) => tools,
                    None => {
                        waygate_telemetry::metrics::record_discovery_index_fallback(
                            waygate_telemetry::metrics::DiscoveryIndexFallback::GenerationChurn,
                        );
                        self.catalog
                            .list_tools(server)
                            .await?
                            .into_iter()
                            .filter(|t| index::matches(t, req.filters.as_ref()))
                            .collect()
                    }
                }
            }
            (None, Some(_)) => {
                waygate_telemetry::metrics::record_discovery_index_fallback(
                    waygate_telemetry::metrics::DiscoveryIndexFallback::Unavailable,
                );
                self.catalog
                    .list_tools(server)
                    .await?
                    .into_iter()
                    .filter(|t| index::matches(t, req.filters.as_ref()))
                    .collect()
            }
            (_, None) => self
                .catalog
                .list_tools(server)
                .await?
                .into_iter()
                .filter(|t| index::matches(t, req.filters.as_ref()))
                .collect(),
        };

        let risk_filter = req.filters.as_ref().and_then(|f| f.risk_level);
        // SEP #1888 `scope` facet: filter to tools whose required OAuth scope
        // matches. Applied here (not in `matches_non_query`) because the
        // scope is derived from the tool's resolved risk facts — same place
        // and reason `risk_level` is applied.
        let scope_filter = req
            .filters
            .as_ref()
            .and_then(|f| f.scope.as_deref())
            .map(str::to_owned);
        let mut matched: Vec<OperationDescriptor> = Vec::with_capacity(tools.len());
        let tenant = principal
            .map(|p| p.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        for t in tools
            .iter()
            .filter(|t| index::matches_non_query(t, req.filters.as_ref()))
        {
            // Quarantined/retired servers' tools are hidden from search
            // results (and refused at dispatch); only an admitted snapshot is listable.
            let ResolvedInvocationTool::Ready(snapshot) = self
                .catalog
                .resolve_discovery_tool(tenant, server, &t.name)
                .await
            else {
                continue;
            };
            let facts = snapshot.facts();
            if let Some(target) = risk_filter {
                if facts.risk != target {
                    continue;
                }
            }
            if let Some(want) = scope_filter.as_deref() {
                if crate::authz::required_scope_for(facts.risk) != Some(want) {
                    continue;
                }
            }
            if let Some(p) = principal {
                // Profile-restricted
                // keys must not even SEE disallowed servers/
                // tools in searchTools results. The dispatch
                // gate would refuse later, but discovery still
                // leaks the existence of tools the operator
                // has bound the key away from.
                if profile_blocks_server(p, server) || profile_blocks_tool(p, server, &t.name) {
                    continue;
                }
                // Step-up tools stay discoverable on purpose: the whole
                // point of step-up is that the client can re-authorize
                // and then call, so hiding the tool would defeat the UX.
                if !self.authz.may_call_tool(p, facts).await.is_discoverable() {
                    continue;
                }
            }
            let Some(record) = CatalogTool::from_upstream_snapshot(server, snapshot) else {
                tracing::warn!(
                    %server,
                    tool = %t.name,
                    "withholding tool whose admitted input schema is not publishable",
                );
                continue;
            };
            matched.push(tool_to_descriptor(&record));
        }

        let (operations, next_cursor) = index::paginate(matched, req.cursor.as_deref(), req.limit);

        // Record each operation surfaced in this response as disclosed for the
        // session. Names are already fully qualified. Any newly-disclosed tool
        // arms `pending_notify` so `call_tool` emits `tools/list_changed`.
        // Done BEFORE the verbosity projection so disclosure tracking is
        // independent of how much detail the client asked for.
        if let Some(disclosed) = disclosed {
            disclosed.record(operations.iter().map(|op| op.name.clone()));
        }

        // Project to the requested verbosity (default `Full` = unchanged).
        let detail = req.detail.unwrap_or_default();
        let operations: Vec<OperationDescriptor> = operations
            .into_iter()
            .map(|op| op.project(detail))
            .collect();

        let resp = SearchToolsResponse::Operations(OperationsResponse {
            operations,
            next_cursor,
        });
        structured_ok(&resp)
    }

    async fn handle_types(
        &self,
        server: &str,
        req: &SearchToolsRequest,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        let Some(name) = req.name.as_deref() else {
            return Err(McpError::invalid_params("mode=types requires `name`", None));
        };

        // Type lookup resolves to the tool's own input_schema,
        // addressable by its (server-qualified) name. Dot-notation into nested
        // type definitions lands alongside the tantivy index upgrade.
        let tools = self.catalog.list_tools(server).await?;
        let qualified = name.strip_prefix(&format!("{server}.")).unwrap_or(name);
        // SEP #1888 type names carry an optional `#input` / `#output` role suffix
        // — exactly what the operation descriptor advertises as `input_type` /
        // `output_type`. Split it off so the advertised `output_type` is actually
        // resolvable here; a bare name defaults to the input schema (preserved
        // behavior, so existing `{server}.{tool}` lookups are unchanged).
        let (bare, want_output, echo_suffix) = match qualified.rsplit_once('#') {
            Some((n, "input")) => (n, false, "#input"),
            Some((n, "output")) => (n, true, "#output"),
            Some(_) => {
                return Err(McpError::invalid_params(
                    format!("unknown type: {name}"),
                    None,
                ))
            }
            None => (qualified, false, ""),
        };
        let Some(t) = tools.iter().find(|t| t.name == bare) else {
            return Err(McpError::invalid_params(
                format!("unknown type: {name}"),
                None,
            ));
        };
        // Gate the type-fetch on the same profile, runtime-admission, and
        // Cedar checks as the operations path. Return the same "unknown type"
        // shape for every withheld case so the response cannot distinguish a
        // missing tool from one the caller may not discover.
        if let Some(p) = principal {
            if profile_blocks_server(p, server) || profile_blocks_tool(p, server, &t.name) {
                return Err(McpError::invalid_params(
                    format!("unknown type: {name}"),
                    None,
                ));
            }
        }
        let tenant = principal
            .map(|principal| principal.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        let ResolvedInvocationTool::Ready(snapshot) = self
            .catalog
            .resolve_discovery_tool(tenant, server, &t.name)
            .await
        else {
            return Err(McpError::invalid_params(
                format!("unknown type: {name}"),
                None,
            ));
        };
        if let Some(p) = principal {
            if !self
                .authz
                .may_call_tool(p, snapshot.facts())
                .await
                .is_discoverable()
            {
                return Err(McpError::invalid_params(
                    format!("unknown type: {name}"),
                    None,
                ));
            }
        }
        let Some(record) = CatalogTool::from_upstream_snapshot(server, snapshot) else {
            return Err(McpError::invalid_params(
                format!("unknown type: {name}"),
                None,
            ));
        };
        let definition = &record.definition;
        // Resolve the schema for the requested role. The same
        // validation-equivalent portability projection used by `tools/list`
        // applies here so the advertised type handle cannot return a schema a
        // client then refuses. A non-self-contained remote reference cannot be
        // projected without inventing its target and remains unavailable.
        let schema: JsonObject = if want_output {
            match definition.output_schema.as_ref() {
                Some(s) => portable_schema_object(s).ok_or_else(|| {
                    McpError::invalid_params(
                        format!(
                            "{server}.{} publishes an output schema with an unresolved remote reference",
                            record.identity.name
                        ),
                        None,
                    )
                })?,
                None => {
                    return Err(McpError::invalid_params(
                        format!(
                            "{server}.{} publishes no output schema — the upstream \
                             declared none, declared one whose root did not describe \
                             an object, or the serving sessions disagreed about it",
                            record.identity.name
                        ),
                        None,
                    ))
                }
            }
        } else {
            portable_schema_object(&definition.input_schema)
                .ok_or_else(|| McpError::invalid_params(format!("unknown type: {name}"), None))?
        };
        let resp = SearchToolsResponse::Types(TypesResponse {
            name: format!("{}{echo_suffix}", record.identity.qualified_name()),
            references: schema_def_names(&schema),
            json_schema: Value::Object(schema),
        });
        structured_ok(&resp)
    }
}

fn catalog_projection_is_stable(
    epoch: Option<&ToolCatalogEpoch>,
    local_generation: Option<u64>,
    durable_before: Option<i64>,
    durable_after: Option<i64>,
    errors_before: u64,
    errors_after: u64,
) -> bool {
    let local_stable = match (epoch, local_generation) {
        (Some(epoch), Some(generation)) => epoch.is_stable(generation),
        (None, None) => true,
        _ => false,
    };
    durable_before == durable_after && errors_before == errors_after && local_stable
}

#[cfg(test)]
mod catalog_projection_tests {
    use super::*;

    #[test]
    fn standard_tools_list_rejects_each_catalog_coherence_change() {
        let epoch = ToolCatalogEpoch::new();
        let generation = epoch.stable_generation().expect("stable catalog epoch");

        assert!(catalog_projection_is_stable(
            Some(&epoch),
            Some(generation),
            Some(9),
            Some(9),
            3,
            3,
        ));
        assert!(!catalog_projection_is_stable(
            Some(&epoch),
            Some(generation),
            Some(9),
            Some(10),
            3,
            3,
        ));
        assert!(!catalog_projection_is_stable(
            Some(&epoch),
            Some(generation),
            Some(9),
            Some(9),
            3,
            4,
        ));

        epoch.mark_changed();
        assert!(!catalog_projection_is_stable(
            Some(&epoch),
            Some(generation),
            Some(9),
            Some(9),
            3,
            3,
        ));
    }
}

#[derive(Default)]
struct SerializedSizeWriter(usize);

impl std::io::Write for SerializedSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("serialized byte count overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Count the exact compact JSON bytes serde emits for the MCP result without
/// allocating a second catalog-sized buffer. The rmcp transport adds the
/// request-specific JSON-RPC envelope and any HTTP/SSE framing afterward.
fn serialized_list_tools_result_size(result: &ListToolsResult) -> Option<usize> {
    let mut writer = SerializedSizeWriter::default();
    serde_json::to_writer(&mut writer, result).ok()?;
    Some(writer.0)
}

fn tool_has_publishable_input_schema(tool: &Tool) -> bool {
    input_schema_has_object_root(&tool.input_schema)
        && portable_schema_object(&tool.input_schema).is_some()
}

fn retain_publishable_tools(tools: &mut Vec<Tool>) {
    // This runs on every tools/list, so the withheld set is reported once per
    // call rather than once per tool per call — a large catalog with a broken
    // upstream would otherwise emit a line per offending tool to every
    // listing client. The names stay in the record; only the repetition goes.
    let mut withheld: Vec<String> = Vec::new();
    let mut omitted_output_schemas: Vec<String> = Vec::new();
    tools.retain_mut(|tool| {
        let had_output_schema = tool.output_schema.is_some();
        let publishable =
            input_schema_has_object_root(&tool.input_schema) && make_tool_schemas_portable(tool);
        if !publishable {
            withheld.push(tool.name.to_string());
        } else if had_output_schema && tool.output_schema.is_none() {
            omitted_output_schemas.push(tool.name.to_string());
        }
        publishable
    });
    if !withheld.is_empty() {
        tracing::warn!(
            tools = %withheld.join(", "),
            withheld = withheld.len(),
            "withholding tools whose input schema is not publishable to portable MCP clients",
        );
    }
    if !omitted_output_schemas.is_empty() {
        tracing::warn!(
            tools = %omitted_output_schemas.join(", "),
            omitted = omitted_output_schemas.len(),
            "omitting optional output schemas with unresolved remote references",
        );
    }
}

/// Whether the principal's API-key profile restriction excludes a built-in
/// `<namespace>.<tool>` — the SAME server + tool confinement the MCP request path
/// applies to built-ins (the dispatch + `list_tools` gates above). Exposed so the
/// assistant's governed read-built-in seam (`waygate-server`) applies the
/// identical gate instead of diverging.
pub fn profile_blocks_builtin(p: &Principal, namespace: &str, tool: &str) -> bool {
    profile_blocks_server(p, namespace) || profile_blocks_tool(p, namespace, tool)
}

fn tool_to_descriptor(tool: &CatalogTool) -> OperationDescriptor {
    let qualified_name = tool.identity.qualified_name();
    OperationDescriptor {
        name: qualified_name.clone(),
        description: tool.definition.description.as_ref().map(|d| d.to_string()),
        risk_level: tool.facts.risk,
        resource_type: None,
        action: None,
        // The step-up scope the tool's risk tier maps to (what a
        // StepUpRequired verdict advises), exposed for client visibility and
        // filtering. Same `required_scope_for` mapping; actual enforcement is
        // the deployment's Cedar policy.
        scope: crate::authz::required_scope_for(tool.facts.risk).map(str::to_owned),
        input_type: Some(format!("{qualified_name}#input")),
        output_type: tool.definition.output_schema.as_ref().and_then(|schema| {
            portable_schema_object(schema).map(|_| format!("{qualified_name}#output"))
        }),
        side_effects: Some(tool.facts.side_effects),
    }
}

/// Names declared under a schema's `$defs` / `definitions` blocks, sorted and
/// de-duplicated. Surfaced as `TypesResponse.references` so a `mode=types`
/// caller can see the named sub-types a tool's input schema declares (the
/// definitions themselves are already inlined in `json_schema`; this is the
/// index into them). Empty for the common flat schema with no nested defs —
/// which is why this replaced the previous unconditional `Vec::new()`.
fn schema_def_names(schema: &JsonObject) -> Vec<String> {
    let mut names: Vec<String> = ["$defs", "definitions"]
        .into_iter()
        .filter_map(|k| schema.get(k))
        .filter_map(|v| v.as_object())
        .flat_map(|defs| defs.keys().cloned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Build the URL-mode elicitation that sends the present operator straight to a
/// just-queued change's approval page — or `None` when it doesn't apply.
///
/// Fires only for a SUCCESSFUL `gateway-admin.propose_change` whose result
/// carries an `approval_url`, and only when the client advertised the
/// elicitation capability (a server must not send a request the client didn't
/// negotiate). It is a pure accelerator: the binding code + approval URL are
/// already in the tool-result text, so a client without elicitation — or one
/// that declines — loses nothing. Form-mode elicitation (collecting missing
/// params in-session) is deliberately NOT wired: propose-time validation already
/// checks params and `describe_action` teaches the shape up front.
/// The gateway's reserved approval-ask key. One definition beside the
/// pipeline's relay-side collision refusal, so the retry-side strip below
/// and that refusal can never disagree about which key is reserved.
use crate::invocation::mrtr::APPROVAL_INPUT_REQUEST_KEY;

/// The downstream caller's MRTR posture for one `tools/call`.
///
/// `capabilities` is `Some` only for a 2026-07-28 stateless request — the
/// SDK refuses to serialize an `input_required` result to a legacy peer, so
/// a legacy session must dispatch as a caller that can answer nothing (its
/// wire contract stays byte-identical).
struct MrtrCaller {
    capabilities: Option<ClientCapabilities>,
}

impl MrtrCaller {
    /// A caller that can answer no server-initiated request: MRTR
    /// projection and passthrough are both off.
    const CANNOT: Self = Self { capabilities: None };

    fn from_client(client: &ClientContext) -> Self {
        Self {
            // A 2026 caller that declared no capabilities still receives
            // pauses (a pure `requestState` round trip needs no capability),
            // so it carries `Some(empty)` — distinct from `None`, a caller
            // whose transport cannot receive an `input_required` result at
            // all.
            capabilities: (client.generation == ProtocolGeneration::Stateless2026)
                .then(|| client.capabilities.clone().unwrap_or_default()),
        }
    }

    fn elicitation_capable(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.elicitation.is_some())
    }
}

/// Build the MRTR pause for a satisfiable approval refusal: one form-mode
/// elicitation under the reserved gateway key, no `requestState` (the
/// approval grant is the durable anchor; the retry is an ordinary call the
/// grant claim authorizes).
fn approval_input_required(tool: &str, reason: &str) -> InputRequiredResult {
    let requested_schema = ElicitationSchema::builder()
        .required_bool_property("approved", |schema| {
            schema
                .title("Approval obtained")
                .description("Confirm once an operator has granted approval for this exact call")
        })
        // Static, known-valid schema: one required boolean property.
        .build_unchecked();
    let elicit = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
        meta: None,
        message: format!(
            "`{tool}` requires human approval: {reason}. Ask a gateway operator to grant \
             approval for this exact call (same tool, same arguments), then confirm to retry. \
             The retry succeeds only while the grant is live and unconsumed."
        ),
        requested_schema,
    });
    let mut requests = rmcp::model::InputRequests::new();
    requests.insert(
        APPROVAL_INPUT_REQUEST_KEY.to_owned(),
        InputRequest::Elicitation(elicit),
    );
    InputRequiredResult::from_input_requests(requests)
}

fn approval_elicitation(
    tool_name: &str,
    result: &Result<CallToolResponse, McpError>,
    client_supports_elicitation: bool,
) -> Option<ElicitRequestParams> {
    if !client_supports_elicitation {
        return None;
    }
    if tool_name
        != format!(
            "{}.propose_change",
            waygate_core::RESERVED_BUILTIN_NAMESPACE
        )
    {
        return None;
    }
    // Only a complete result carries the queued change's structured content;
    // this accelerator is legacy-generation-only, where dispatch never
    // produces a pause or task envelope.
    let res = match result.as_ref().ok()? {
        CallToolResponse::Complete(res) => res,
        _ => return None,
    };
    if res.is_error == Some(true) {
        return None;
    }
    let sc = res.structured_content.as_ref()?;
    let url = sc.get("approval_url")?.as_str()?.to_owned();
    let id = sc.get("change_request_id")?.as_str()?.to_owned();
    let code = sc
        .get("binding_code")
        .and_then(|c| c.as_str())
        .unwrap_or("(see the tool result)");
    Some(ElicitRequestParams::UrlElicitationParams {
        meta: None,
        message: format!(
            "A control-plane change was queued for your approval (binding code {code}). \
             Open the approval page to review it, then approve or deny."
        ),
        url,
        elicitation_id: id,
    })
}

fn structured_ok<T: serde::Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let json = serde_json::to_value(value)
        .map_err(|e| McpError::internal_error(format!("serialize response: {e}"), None))?;
    Ok(CallToolResult::structured(json))
}

/// Pull the `Principal` out of a rmcp `RequestContext`, which carries the
/// axum-layer `http::request::Parts` (including its typed extensions).
/// Returns `None` on calls that arrived over a non-HTTP transport or when
/// the bearer middleware wasn't layered.
pub fn principal_from_ctx(ctx: &RequestContext<RoleServer>) -> Option<Principal> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<Principal>().cloned()
}

/// Refuse a native file method with a message shaped by the caller's wire
/// profile. Every message names the missing declaration; the legacy-draft
/// variant additionally explains why a session-negotiated capability was not
/// honored and how a dual-version client can still proceed.
fn native_file_capability_error(
    caller: &crate::files::ClassifiedFileCaller,
    method: &str,
    operation: &str,
) -> McpError {
    let message = match caller.profile {
        crate::files::FileWireProfile::LegacyDraft => format!(
            "{method} requires declared {operation} support over HTTPS; this connection \
             negotiated a legacy initialization session whose file capabilities are not \
             readable by this server — redeclare file capabilities in the request `_meta`"
        ),
        _ => format!("{method} requires declared {operation} support over HTTPS"),
    };
    crate::files::invalid_file_request(
        crate::files::FileTransferReason::UnsupportedCapability,
        message,
    )
}

fn skill_distribution_error(error: waygate_skills::distribution::DistributionError) -> McpError {
    use waygate_skills::distribution::DistributionError;
    match error {
        DistributionError::Unavailable | DistributionError::Store(_) => {
            McpError::internal_error("Skill distribution approval is unavailable", None)
        }
        DistributionError::NotApproved | DistributionError::NotFound => unadvertised_resource(),
    }
}

impl ServerHandler for GatewayServer {
    async fn on_custom_request(
        &self,
        request: CustomRequest,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        let raw_params = request.params.unwrap_or(Value::Null);
        if crate::skills::is_method(&request.method) {
            self.skill_catalog
                .as_ref()
                .and_then(|catalog| catalog.current())
                .ok_or_else(|| {
                    McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        request.method.clone(),
                        None,
                    )
                })?;
            let client = self.client_context(&ctx);
            let principal = principal_from_ctx(&ctx);
            let result = if request.method == crate::skills::LIST_METHOD {
                skill_tools::SkillTools::new(self.clone())
                    .custom_list(
                        raw_params,
                        principal.as_ref(),
                        client.generation == ProtocolGeneration::Stateless2026,
                    )
                    .await
            } else {
                let uri = raw_params
                    .get("uri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        McpError::invalid_params("skills/get requires a string uri parameter", None)
                    })?
                    .to_owned();
                let snapshot = self
                    .resolve_approved_skill(&uri, None, principal.as_ref())
                    .await?;
                let identity = snapshot
                    .known_content_digest(&uri)
                    .and_then(|digest| snapshot.resource_identity(&uri, digest.to_owned()))
                    .ok_or_else(unadvertised_resource)?;
                let permit = self
                    .authorize_gateway_skill_read(principal.as_ref(), &identity)
                    .await?;
                let mut result = match self.ensure_skill_catalog_origin_isolation(&snapshot).await {
                    Ok(()) => crate::skills::handle_custom(
                        &snapshot,
                        &request.method,
                        raw_params,
                        principal.as_ref(),
                        &self.tool_list_cursor_sealer,
                        client.generation == ProtocolGeneration::Stateless2026,
                    ),
                    Err(error) => Err(error),
                };
                if let Ok(value) = &result {
                    if let Err(error) = skill_tools::SkillTools::new(self.clone())
                        .inspect_metadata(value, principal.as_ref())
                        .await
                    {
                        result = Err(error);
                    }
                }
                if let (Some(principal), Some(policy_ids)) = (principal.as_ref(), permit.as_deref())
                {
                    let outcome = match &result {
                        Ok(_) => AuditOutcome::Success,
                        Err(error) if error.code == rmcp::model::ErrorCode::INTERNAL_ERROR => {
                            AuditOutcome::ExecutionError
                        }
                        Err(_) => AuditOutcome::Denied,
                    };
                    let reason = result
                        .as_ref()
                        .err()
                        .map(post_authorization_skill_refusal_reason);
                    self.record_gateway_skill_read(
                        principal,
                        &identity,
                        policy_ids,
                        outcome,
                        reason.as_deref(),
                    )
                    .await;
                }
                if result.is_ok() {
                    if let Err(error) = self
                        .check_skill_approval(&snapshot, &uri, principal.as_ref())
                        .await
                    {
                        if let (Some(principal), Some(policy_ids)) =
                            (principal.as_ref(), permit.as_deref())
                        {
                            self.record_gateway_skill_read(principal, &identity, policy_ids, AuditOutcome::Denied, Some("Skill distribution was refused after the initial authorization audit; no content was released")).await;
                        }
                        return Err(error);
                    }
                }
                result
            };
            return result.map(CustomResult::new);
        }
        let capability_source = if raw_params.get("_meta").is_some() {
            raw_params.clone()
        } else {
            serde_json::json!({"_meta": ctx.meta.0.clone()})
        };
        let request_local =
            crate::files::request_file_capabilities(&capability_source).map_err(|_| {
                crate::files::invalid_file_request(
                    crate::files::FileTransferReason::UnsupportedCapability,
                    "invalid client file-capability declaration",
                )
            })?;
        // The wire profile is classified once, here at the MCP edge. A
        // request-local declaration is authoritative (stateless-native); a
        // connection that negotiated a legacy `initialize` session is
        // legacy-draft, though the pinned MCP library drops the draft `files`
        // member from the typed initialize capabilities, so that session
        // state arrives unobservable until the library can carry it.
        let negotiation = if ctx.peer.peer_info().is_some() {
            crate::files::DownstreamNegotiation::LegacySession(None)
        } else {
            crate::files::DownstreamNegotiation::Stateless
        };
        let caller = crate::files::classify_downstream_caller(request_local, negotiation);
        let principal = principal_from_ctx(&ctx);
        let result = match request.method.as_str() {
            crate::files::AUTHORIZE_UPLOAD_METHOD => {
                crate::files::require_file_capability(
                    caller.capabilities.as_ref(),
                    crate::files::FileOperation::Upload,
                )
                .map_err(|_| {
                    native_file_capability_error(&caller, "files/authorizeUpload", "upload")
                })?;
                if self
                    .authorized_builtin(crate::files::PREPARE_UPLOAD_TOOL, principal.as_ref())
                    .await?
                    .is_none()
                {
                    return Err(McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        crate::files::AUTHORIZE_UPLOAD_METHOD,
                        Some(serde_json::json!({
                            crate::files::FILE_TRANSFER_REASON_KEY:
                                crate::files::FileTransferReason::NotEnabled.as_str()
                        })),
                    ));
                }
                let authorizer = self.file_upload_authorizer.as_ref().ok_or_else(|| {
                    McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        crate::files::AUTHORIZE_UPLOAD_METHOD,
                        Some(serde_json::json!({
                            crate::files::FILE_TRANSFER_REASON_KEY:
                                crate::files::FileTransferReason::NotEnabled.as_str()
                        })),
                    )
                })?;
                let params = serde_json::from_value(raw_params).map_err(|_| {
                    crate::files::invalid_file_request(
                        crate::files::FileTransferReason::InvalidFileInput,
                        "invalid files/authorizeUpload parameters",
                    )
                })?;
                serde_json::to_value(
                    authorizer
                        .authorize_upload(principal.as_ref(), params)
                        .await?,
                )
            }
            crate::files::AUTHORIZE_DOWNLOAD_METHOD => {
                crate::files::require_file_capability(
                    caller.capabilities.as_ref(),
                    crate::files::FileOperation::Download,
                )
                .map_err(|_| {
                    native_file_capability_error(&caller, "files/authorizeDownload", "download")
                })?;
                if self
                    .authorized_builtin(crate::files::PREPARE_DOWNLOAD_TOOL, principal.as_ref())
                    .await?
                    .is_none()
                {
                    return Err(McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        crate::files::AUTHORIZE_DOWNLOAD_METHOD,
                        Some(serde_json::json!({
                            crate::files::FILE_TRANSFER_REASON_KEY:
                                crate::files::FileTransferReason::NotEnabled.as_str()
                        })),
                    ));
                }
                let authorizer = self.file_download_authorizer.as_ref().ok_or_else(|| {
                    McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        crate::files::AUTHORIZE_DOWNLOAD_METHOD,
                        Some(serde_json::json!({
                            crate::files::FILE_TRANSFER_REASON_KEY:
                                crate::files::FileTransferReason::NotEnabled.as_str()
                        })),
                    )
                })?;
                let params = serde_json::from_value(raw_params).map_err(|_| {
                    crate::files::invalid_file_request(
                        crate::files::FileTransferReason::InvalidFileInput,
                        "invalid files/authorizeDownload parameters",
                    )
                })?;
                serde_json::to_value(
                    authorizer
                        .authorize_download(principal.as_ref(), params)
                        .await?,
                )
            }
            _ => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    request.method,
                    None,
                ));
            }
        };
        result.map(CustomResult::new).map_err(|_| {
            crate::files::file_transfer_failure(
                crate::files::FileTransferReason::TransferFailed,
                "file authorization could not be serialized",
            )
        })
    }

    // The tasks surface serves the SEP-2663 extension shape: `tasks/get`
    // carries the status-specific payload inline (including the terminal
    // result, replacing the removed `tasks/result` method) and
    // `tasks/cancel` acknowledges with an empty result. The rmcp router
    // gates both on the client having declared the tasks extension
    // capability and this server advertising it.
    async fn get_task(
        &self,
        request: GetTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        let _client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        for builtin in &self.builtins {
            let Some(tool) = builtin.task_tool() else {
                continue;
            };
            let catalog = builtin.catalog();
            self.authorize_builtin_overlay(&catalog, tool, principal.as_ref())
                .await?;
            if let Some(task) = builtin
                .get_task(&request.task_id, principal.as_ref())
                .await?
            {
                let payload = match task.status {
                    TaskStatus::Completed => {
                        // The status read and the result read are separate
                        // awaits, and retention can expire between them —
                        // in which case this is the ordinary expiry
                        // outcome (the same "Task not found" a fresh
                        // `tasks/get` would return), not a server fault.
                        let Some(result) = builtin
                            .get_task_result(&request.task_id, principal.as_ref())
                            .await?
                        else {
                            return Err(McpError::resource_not_found("Task not found", None));
                        };
                        let value = serde_json::to_value(result).map_err(|error| {
                            McpError::internal_error(
                                format!("Could not encode task result: {error}"),
                                None,
                            )
                        })?;
                        let object = match value {
                            Value::Object(map) => map,
                            other => {
                                let mut map = JsonObject::new();
                                map.insert("result".to_owned(), other);
                                map
                            }
                        };
                        TaskPayload::Completed { result: object }
                    }
                    TaskStatus::Failed => {
                        let mut error = JsonObject::new();
                        if let Some(message) = task.status_message.clone() {
                            error.insert("message".to_owned(), Value::String(message));
                        }
                        TaskPayload::Failed { error }
                    }
                    // The continuation contract travels in the task's
                    // status message and the self-documenting continuation
                    // tools, and `tasks/update` accepts the continuation
                    // keyed by its tool name. `inputRequests` stays empty
                    // because the continuation input is untyped JSON that
                    // the elicitation/sampling/roots request union cannot
                    // honestly describe — an empty map is the truthful wire
                    // shape, not a gap.
                    TaskStatus::InputRequired => TaskPayload::InputRequired {
                        input_requests: Default::default(),
                    },
                    TaskStatus::Cancelled => TaskPayload::Cancelled,
                    // `TaskStatus` is non-exhaustive; an unknown future
                    // status degrades to Working — the client keeps polling
                    // rather than mis-reading a terminal state.
                    TaskStatus::Working | _ => TaskPayload::Working,
                };
                return Ok(GetTaskResult::new(DetailedTask::new(task, payload)));
            }
        }
        Err(McpError::resource_not_found("Task not found", None))
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let _client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        for builtin in &self.builtins {
            let Some(tool) = builtin.cancel_task_tool() else {
                continue;
            };
            let catalog = builtin.catalog();
            self.authorize_builtin_overlay(&catalog, tool, principal.as_ref())
                .await?;
            if builtin
                .cancel_task(&request.task_id, principal.as_ref())
                .await?
                .is_some()
            {
                return Ok(());
            }
        }
        Err(McpError::resource_not_found("Task not found", None))
    }

    // SEP-2663 `tasks/update`: client-to-server input for a paused task.
    // Unlike `tasks/get`/`tasks/cancel`, the Cedar overlay is NOT taken
    // from `task_tool()` wholesale: the namespace first names which
    // continuation this update advances, and the overlay runs for THAT
    // continuation's governance tool — so an update that advances a
    // mutation continuation is governed exactly like the direct mutation
    // path, neither bypassing nor over-restricting it.
    async fn update_task(
        &self,
        request: UpdateTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let _client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        for builtin in &self.builtins {
            if builtin.task_tool().is_none() {
                continue;
            }
            let Some(continuation) = builtin
                .update_task_continuation(&request.task_id, principal.as_ref())
                .await?
            else {
                continue;
            };
            let governance = builtin.governance_tool(continuation);
            let catalog = builtin.catalog();
            self.authorize_builtin_overlay(&catalog, governance, principal.as_ref())
                .await?;
            return builtin
                .update_task(
                    &request.task_id,
                    request.input_responses,
                    principal.as_ref(),
                )
                .await;
        }
        Err(McpError::resource_not_found("Task not found", None))
    }

    // Catalog subscriptions wake on the process-wide epoch. Configured skills
    // add prompt changes; search calls do not mutate either catalog.
    fn accepted_subscription_filter(
        &self,
        requested: &rmcp::model::SubscriptionFilter,
    ) -> Option<rmcp::model::SubscriptionFilter> {
        Some(crate::subscriptions::accepted_filter(
            requested,
            self.skill_catalog.is_some() && self.tool_catalog_epoch.is_some(),
        ))
    }

    async fn listen(&self, context: rmcp::service::SubscriptionContext) -> Result<(), McpError> {
        let _client = self.client_context(context.request_context());
        crate::subscriptions::run_subscription(context, self.tool_catalog_changes.clone()).await
    }

    async fn discover(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::DiscoverResult, McpError> {
        // Counted like every other served method; derivation matches the
        // SDK default except for one capability edit below.
        let client = self.client_context(&ctx);
        let mut info = self.get_info();
        info.instructions = Some(
            if self.codemode_only_tools_list_active(Some(&client)) {
                CODEMODE_ONLY_INSTRUCTIONS
            } else {
                FULL_CATALOG_INSTRUCTIONS
            }
            .to_owned(),
        );
        if self.skill_catalog.is_some() {
            info.instructions = Some(format!(
                "{} {}",
                skill_tools::GUIDANCE,
                info.instructions.unwrap_or_default()
            ));
        }
        // `tools.listChanged` is advertised to the stateless generation
        // too: `subscriptions/listen` is its delivery channel (1.2
        // stripped the flag here while no such channel existed).
        Ok(rmcp::model::DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            info,
        ))
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        // Both generations are served: 2026-07-28 statelessly with a stable
        // authorization-filtered tool projection, 2025-11-25 and earlier on
        // sessions. Derived from `SUPPORTED_MCP_SPEC_VERSIONS` so the
        // advertised set, the conformance suite, and the README move in
        // lockstep (the guard test in `lib.rs` enforces it).
        std::borrow::Cow::Owned(
            crate::SUPPORTED_MCP_SPEC_VERSIONS
                .iter()
                .map(|version| {
                    ProtocolVersion::KNOWN_VERSIONS
                        .iter()
                        .find(|known| known.as_str() == *version)
                        .cloned()
                        .expect("SUPPORTED_MCP_SPEC_VERSIONS entries are rmcp-known versions")
                })
                .collect(),
        )
    }

    fn initialize(
        &self,
        request: rmcp::model::InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::InitializeResult, McpError>> + Send + '_
    {
        waygate_telemetry::metrics::record_protocol_generation("legacy");
        let client_name = request.client_info.name.as_str();
        let codemode_only =
            Self::client_name_matches(Some(client_name), &self.codemode_only_tools_clients);
        let client_fallback = !codemode_only
            && !self.eager_tools_list
            && self
                .eager_tools_clients
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(client_name));
        if codemode_only {
            self.client_codemode_only_tools_list
                .store(true, Ordering::Relaxed);
            tracing::info!(
                client_name,
                client_version = %request.client_info.version,
                "enabled per-session Code Mode-only tool catalog"
            );
        } else if client_fallback {
            self.client_eager_tools_list.store(true, Ordering::Relaxed);
            tracing::info!(
                client_name,
                client_version = %request.client_info.version,
                "enabled per-session eager tool discovery fallback"
            );
        }
        context.peer.set_peer_info(request);
        std::future::ready(Ok(self.get_info()))
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, McpError> {
        let principal = principal_from_ctx(&context);
        if self.skill_catalog.is_some() {
            skill_tools::require_read(principal.as_ref())?;
        }
        let mut listed = if self
            .skill_catalog
            .as_ref()
            .and_then(|catalog| catalog.current())
            .is_none()
        {
            rmcp::model::ListPromptsResult::default()
        } else {
            skill_tools::SkillTools::new(self.clone())
                .prompts(
                    request.as_ref().and_then(|r| r.cursor.as_deref()),
                    principal.as_ref(),
                )
                .await?
        };
        self.stamp_cache_hints(
            &self.client_context(&context),
            &mut listed.ttl_ms,
            &mut listed.cache_scope,
        );
        Ok(listed)
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, McpError> {
        let principal = principal_from_ctx(&context);
        skill_tools::SkillTools::new(self.clone())
            .prompt(request, principal.as_ref())
            .await
            .map(Into::into)
    }

    fn get_info(&self) -> ServerInfo {
        // `enable_tool_list_changed` arms the capability so strict clients
        // (those that gate tool invocation on presence in the latest
        // `tools/list`) know to re-fetch after a `searchTools` call reveals
        // new tools. SEP #1888-aware clients ignore the notification.
        let caps = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_tool_list_changed();
        // Advertise the SEP-1724 EMA extension only when the operator
        // opted in (and the AS + EMA deps are wired — the composition root folds
        // both into `advertise_ema`). An empty settings object signals "supported,
        // no settings". The two builder branches have distinct const-generic types,
        // so each calls `.build()` to converge on `ServerCapabilities`.
        let mut capabilities = caps.build();
        // Tasks are the SEP-2663 extension: advertised in the extensions
        // capability map (the pre-extension `tasks` capability field no
        // longer exists on the wire), and only when a built-in actually
        // serves a durable task tool.
        let tasks_enabled = self
            .builtins
            .iter()
            .any(|builtin| builtin.supports_tasks() && builtin.task_tool().is_some());
        // SEP-2640 remains experimental. Advertise only list/get (empty
        // settings object, no directoryRead claim), and only while a complete
        // verified snapshot is actually available to serve.
        let skills_enabled = self
            .skill_catalog
            .as_ref()
            .and_then(|catalog| catalog.current())
            .is_some();
        if self.skill_catalog.is_some() {
            capabilities
                .prompts
                .get_or_insert_with(Default::default)
                .list_changed = Some(self.tool_catalog_epoch.is_some());
        }
        if tasks_enabled || self.advertise_ema || skills_enabled {
            let extensions = capabilities
                .extensions
                .get_or_insert_with(ExtensionCapabilities::new);
            if tasks_enabled {
                extensions.insert(TASKS_EXTENSION_ID.to_owned(), JsonObject::new());
            }
            if self.advertise_ema {
                extensions.insert(EMA_EXTENSION_ID.to_owned(), JsonObject::new());
            }
            if skills_enabled {
                extensions.insert(crate::skills::EXTENSION_ID.to_owned(), JsonObject::new());
            }
        }
        // Native file-transfer support is deliberately NOT advertised here
        // yet. This method is the single server-capability projection point —
        // the legacy initialize result and the stateless `server/discover`
        // response both derive from it — so when the file-transfer standard
        // (or its extension registration) settles a server-side capability
        // shape, it is populated in exactly one place. Emitting an invented
        // shape early would teach clients an experiment as if it were the
        // standard and force this server to carry both forever. Until then,
        // native availability is learned from the methods' precise
        // machine-readable errors, and the fallback stays independently
        // discoverable: `gateway-files.prepare_upload` / `prepare_download`
        // in `tools/list` are the portable declaration that governed file
        // transfer exists.
        let instructions = if self.codemode_only_tools_list_active(None) {
            CODEMODE_ONLY_INSTRUCTIONS
        } else if self.eager_tools_list_active() {
            FULL_CATALOG_INSTRUCTIONS
        } else {
            LEGACY_SEARCH_INSTRUCTIONS
        };
        ServerInfo::new(capabilities)
            .with_server_info(
                Implementation::new("mcp-tool-search-gateway", env!("CARGO_PKG_VERSION"))
                    .with_title("Waygate"),
            )
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_instructions(if self.skill_catalog.is_some() {
                format!("{} {instructions}", skill_tools::GUIDANCE)
            } else {
                instructions.to_owned()
            })
    }

    fn on_initialized(
        &self,
        context: rmcp::service::NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        // Spawn the per-session server-initiated ping loop once the client
        // completes the handshake. Detached: every exit path is bounded
        // (session close surfaces as a send error; an unresponsive client
        // stops the loop) — see `crate::ping` for the full contract.
        if let Some(interval) = self.client_ping_interval {
            crate::ping::spawn_ping_loop(context.peer.clone(), interval, self.ping_stats.clone());
        }
        if let Some(receiver) = self.tool_catalog_changes.clone() {
            crate::catalog_changes::spawn_tool_list_change_loop(
                receiver,
                context.peer.clone(),
                self.skill_catalog.is_some(),
            );
        }
        std::future::ready(())
    }

    // Span name + `mcp.method.name` / `otel.kind` follow the OTel MCP semantic
    // conventions (https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/).
    // The pre-semconv `mcp.method` field is retained (dual-emit) because
    // `docs/compliance.md` cites it as control evidence; drop it in a later
    // pass once the doc + any dashboards cut over.
    #[tracing::instrument(
        name = "tools/list",
        skip(self, request, ctx),
        fields(
            mcp.method = "tools/list",
            mcp.method.name = "tools/list",
            otel.kind = "server",
            user.sub = tracing::field::Empty,
        ),
    )]
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let started = std::time::Instant::now();
        // Adopt the agent's trace as our parent if it propagated W3C context
        // via `params._meta` (OTel MCP semconv); rmcp lifts the wire
        // `params._meta` onto `ctx.meta`. No-op when absent.
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &ctx.meta.0);
        let principal = principal_from_ctx(&ctx);
        if let Some(p) = principal.as_ref() {
            tracing::Span::current().record("user.sub", tracing::field::display(&p.sub));
        }
        let client = self.client_context(&ctx);
        let codemode_only = self.codemode_only_tools_list_active(Some(&client));
        let (projection, observed_projection) = match (client.generation, codemode_only) {
            (ProtocolGeneration::Legacy, true) => (
                ToolProjection::BuiltinsOnly {
                    canonical_order: true,
                },
                waygate_telemetry::metrics::ToolListProjection::LegacyCodeModeOnly,
            ),
            (ProtocolGeneration::Stateless2026, true) => (
                ToolProjection::BuiltinsOnly {
                    canonical_order: true,
                },
                waygate_telemetry::metrics::ToolListProjection::StatelessCodeModeOnly,
            ),
            (ProtocolGeneration::Legacy, false) if self.eager_tools_list => (
                ToolProjection::Full {
                    canonical_order: true,
                },
                waygate_telemetry::metrics::ToolListProjection::LegacyEagerGlobal,
            ),
            (ProtocolGeneration::Legacy, false)
                if self.client_eager_tools_list.load(Ordering::Relaxed) =>
            {
                (
                    ToolProjection::Full {
                        canonical_order: true,
                    },
                    waygate_telemetry::metrics::ToolListProjection::LegacyEagerClient,
                )
            }
            (ProtocolGeneration::Legacy, false) => (
                ToolProjection::SessionDisclosed(&self.disclosed),
                waygate_telemetry::metrics::ToolListProjection::LegacyProgressive,
            ),
            (ProtocolGeneration::Stateless2026, false) => (
                ToolProjection::Full {
                    canonical_order: true,
                },
                waygate_telemetry::metrics::ToolListProjection::Stateless2026,
            ),
        };
        let visible = self
            .stable_list_visible_tools_with(principal.as_ref(), projection)
            .await?;
        let cursor = request
            .as_ref()
            .and_then(|request| request.cursor.as_deref());
        let mut result = match client.generation {
            ProtocolGeneration::Stateless2026 => crate::tool_list_pagination::paginate(
                visible,
                cursor,
                principal.as_ref(),
                &self.tool_list_cursor_sealer,
            )
            .map(|page| {
                let mut listed = ListToolsResult::with_all_items(page.tools);
                listed.next_cursor = page.next_cursor;
                listed
            }),
            ProtocolGeneration::Legacy => {
                // The compatibility projection stays unpaginated: legacy
                // hosts that predate reliable cursor traversal must continue
                // to receive the complete session-disclosed/eager set. An
                // empty cursor is the first-page alias; no non-empty cursor is
                // ever issued on this generation, so accepting one would hide
                // a cross-operation or stale-cursor mistake.
                if cursor.is_some_and(|cursor| !cursor.is_empty()) {
                    Err(McpError::invalid_params(
                        "legacy tools/list does not issue continuation cursors; restart without a cursor",
                        None,
                    ))
                } else {
                    Ok(ListToolsResult::with_all_items(visible))
                }
            }
        };
        if let Ok(listed) = result.as_mut() {
            self.stamp_cache_hints(&client, &mut listed.ttl_ms, &mut listed.cache_scope);
            waygate_telemetry::metrics::record_tool_list_response(
                observed_projection,
                listed.tools.len(),
                serialized_list_tools_result_size(listed),
            );
        }
        waygate_telemetry::metrics::record_server_operation(
            "tools/list",
            result.is_ok(),
            started.elapsed().as_secs_f64(),
        );
        result
    }

    #[tracing::instrument(
        name = "resources/list",
        skip(self, request, ctx),
        fields(
            mcp.method.name = "resources/list",
            otel.kind = "server",
            user.sub = tracing::field::Empty,
        ),
    )]
    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let started = std::time::Instant::now();
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &ctx.meta.0);
        let client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        if let Some(principal) = principal.as_ref() {
            tracing::Span::current().record("user.sub", tracing::field::display(&principal.sub));
        }
        let result = self
            .list_visible_resources(request, principal.as_ref())
            .await
            .map(|mut listed| {
                self.stamp_cache_hints(&client, &mut listed.ttl_ms, &mut listed.cache_scope);
                listed
            });
        waygate_telemetry::metrics::record_server_operation(
            "resources/list",
            result.is_ok(),
            started.elapsed().as_secs_f64(),
        );
        result
    }

    #[tracing::instrument(
        name = "resources/templates/list",
        skip(self, request, ctx),
        fields(
            mcp.method.name = "resources/templates/list",
            otel.kind = "server",
            user.sub = tracing::field::Empty,
        ),
    )]
    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        let started = std::time::Instant::now();
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &ctx.meta.0);
        let client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        if let Some(principal) = principal.as_ref() {
            tracing::Span::current().record("user.sub", tracing::field::display(&principal.sub));
        }
        if request
            .as_ref()
            .and_then(|params| params.cursor.as_ref())
            .is_some()
        {
            return Err(McpError::invalid_params(
                "the gateway returns the complete visible resource-template set; retry without a cursor",
                None,
            ));
        }
        let result = self
            .list_visible_resource_templates(principal.as_ref())
            .await
            .map(|mut listed| {
                self.stamp_cache_hints(&client, &mut listed.ttl_ms, &mut listed.cache_scope);
                listed
            });
        waygate_telemetry::metrics::record_server_operation(
            "resources/templates/list",
            result.is_ok(),
            started.elapsed().as_secs_f64(),
        );
        result
    }

    #[tracing::instrument(
        name = "resources/read",
        skip(self, request, ctx),
        fields(
            mcp.method.name = "resources/read",
            otel.kind = "server",
            user.sub = tracing::field::Empty,
        ),
    )]
    async fn read_resource(
        &self,
        mut request: ReadResourceRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let started = std::time::Instant::now();
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &ctx.meta.0);
        let client = self.client_context(&ctx);
        let principal = principal_from_ctx(&ctx);
        if let Some(principal) = principal.as_ref() {
            tracing::Span::current().record("user.sub", tracing::field::display(&principal.sub));
        }
        match self
            .read_verified_skill_resource(
                &request.uri,
                principal.as_ref(),
                client.generation == ProtocolGeneration::Stateless2026,
            )
            .await
        {
            Ok(Some(read)) => {
                waygate_telemetry::metrics::record_server_operation(
                    "resources/read",
                    true,
                    started.elapsed().as_secs_f64(),
                );
                return Ok(read.into());
            }
            Ok(None) => {}
            Err(error) => {
                waygate_telemetry::metrics::record_server_operation(
                    "resources/read",
                    false,
                    started.elapsed().as_secs_f64(),
                );
                return Err(error);
            }
        }
        let raw_request = serde_json::to_value(&request).map_err(|_| {
            McpError::invalid_params("resource request metadata could not be read", None)
        })?;
        // rmcp lifts wire `params._meta` into `RequestContext`; retain the
        // typed-params fallback for direct/in-memory adapters that construct a
        // request without crossing that transport boundary.
        let capability_source = if raw_request.get("_meta").is_some() {
            raw_request
        } else {
            serde_json::json!({"_meta": ctx.meta.0.clone()})
        };
        let request_capabilities = crate::files::request_file_capabilities(&capability_source)
            .map_err(|_| {
                McpError::invalid_params("invalid client file-capability declaration", None)
            })?;
        let governed_file_transfer = principal.is_some()
            && self
                .file_output_processor
                .as_ref()
                .is_some_and(|processor| processor.native_https_available())
            && request_capabilities.as_ref().is_some_and(|capabilities| {
                capabilities.supports(crate::files::FileOperation::Download)
            });
        if governed_file_transfer {
            let meta = request.meta.get_or_insert_with(Default::default);
            let capabilities = meta
                .entry(crate::files::CLIENT_CAPABILITIES_META_KEY.to_owned())
                .or_insert_with(|| Value::Object(JsonObject::new()));
            let Value::Object(capabilities) = capabilities else {
                return Err(McpError::invalid_params(
                    "client capability metadata must be an object",
                    None,
                ));
            };
            capabilities.insert(
                crate::files::FILES_CAPABILITY_MEMBER.to_owned(),
                crate::files::stateless_client_file_capability(
                    crate::files::FileOperation::Download,
                ),
            );
        } else if let Some(Value::Object(capabilities)) = request
            .meta
            .as_mut()
            .and_then(|meta| meta.get_mut(crate::files::CLIENT_CAPABILITIES_META_KEY))
        {
            // Never promise an upstream that this gateway can govern a file
            // when the caller cannot consume one or the processor is absent.
            capabilities.remove(crate::files::FILES_CAPABILITY_MEMBER);
        }
        let result = self
            .read_visible_resource_with_transfer(
                request,
                principal.as_ref(),
                governed_file_transfer,
            )
            .await
            .map(|mut read| {
                if client.generation == ProtocolGeneration::Stateless2026 {
                    // Freshness is the upstream's to claim — an
                    // upstream-supplied ttl passes through, absent means
                    // do-not-cache — but scope is the gateway's: this body
                    // was resolved under the current principal's
                    // authorization, so it is NEVER shareable across
                    // authorization contexts, whatever scope the upstream
                    // declared. An upstream `public` passing through would
                    // let a shared cache serve one principal's resource to
                    // another.
                    if read.ttl_ms.is_none() {
                        read.ttl_ms = Some(0);
                    }
                    read.cache_scope = Some(rmcp::model::CacheScope::Private);
                }
                read
            });
        waygate_telemetry::metrics::record_server_operation(
            "resources/read",
            result.is_ok(),
            started.elapsed().as_secs_f64(),
        );
        result.map(Into::into)
    }

    // semconv span name `tools/call` + `mcp.method.name` / `gen_ai.tool.name`
    // / `otel.kind`. Pre-semconv `mcp.method` / `mcp.tool` retained (dual-emit)
    // for the compliance-doc evidence window. `mcp.session.id` is not yet
    // emitted — rmcp's `RequestContext` doesn't surface the streamable-HTTP
    // session id cheaply; tracked as the remaining semconv attr.
    #[tracing::instrument(
        name = "tools/call",
        skip(self, request, ctx),
        fields(
            mcp.method = "tools/call",
            mcp.method.name = "tools/call",
            mcp.tool = %request.name,
            gen_ai.tool.name = %request.name,
            otel.kind = "server",
            error.type = tracing::field::Empty,
            user.sub = tracing::field::Empty,
        ),
    )]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let started = std::time::Instant::now();
        // Adopt the agent's trace as our parent if it propagated W3C context
        // via `params._meta` (OTel MCP semconv); rmcp lifts the wire
        // `params._meta` onto `ctx.meta`. No-op when absent.
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &ctx.meta.0);
        let principal = principal_from_ctx(&ctx);
        if let Some(p) = principal.as_ref() {
            tracing::Span::current().record("user.sub", tracing::field::display(&p.sub));
        }
        // Capture the tool name before `request` is consumed by dispatch — the
        // elicitation accelerator keys on it.
        let tool_name = request.name.to_string();
        let client = self.client_context(&ctx);
        let disclosed = if client.generation == ProtocolGeneration::Legacy {
            Some(&self.disclosed)
        } else {
            None
        };
        // Task-eligible dispatch (SEP-2663): a call targeting a durable
        // built-in's task tool materializes a task instead of running
        // synchronously — but only when the client declared the tasks
        // extension, since a client that cannot poll `tasks/get` must get
        // the ordinary synchronous result. A non-eligible tool falls through
        // to synchronous dispatch; an enqueue *failure* (authorization,
        // validation, storage) is returned to the caller through the shared
        // error tail below, exactly like a synchronous dispatch failure.
        let client_declares_tasks = ctx
            .client_capabilities()
            .is_some_and(|caps| caps.supports_tasks());
        // Every exit — task handle, synchronous result, or error from
        // either path — must flow through the shared error-classification
        // and `record_server_operation` tail below, or that exit class
        // vanishes from tools/call outcome/duration metrics and the span's
        // `error.type`.
        let mut task_enqueue_error: Option<McpError> = None;
        if client_declares_tasks {
            match self
                .try_enqueue_task(&tool_name, &request, principal.as_ref())
                .await
            {
                Ok(Some(task)) => {
                    // A task handle is a successful tools/call outcome.
                    waygate_telemetry::metrics::record_server_operation(
                        "tools/call",
                        true,
                        started.elapsed().as_secs_f64(),
                    );
                    return Ok(CallToolResponse::Task(CreateTaskResult::new(task)));
                }
                // Not task-eligible: run synchronously, as for any client.
                Ok(None) => {}
                // Authorization/validation/storage failures take the same
                // tail as synchronous dispatch errors.
                Err(error) => task_enqueue_error = Some(error),
            }
        }
        let result = match task_enqueue_error {
            Some(error) => Err(error),
            None => {
                self.dispatch_tool_call_with(
                    request,
                    principal.as_ref(),
                    client.generation,
                    disclosed,
                    &MrtrCaller::from_client(&client),
                )
                .await
            }
        };
        // The list_changed nudge belongs only to the legacy session adapter.
        // A 2026 search call records no disclosure and cannot change the
        // stable direct-tool projection.
        if client.generation == ProtocolGeneration::Legacy {
            self.notify_if_disclosed_changed(&ctx.peer).await;
        }
        // When a propose_change just queued a change and the client
        // negotiated elicitation, send the present operator straight to the
        // approval page (URL-mode). Fire-and-forget + best-effort: the binding
        // code + approval URL are already in the tool-result text, so the
        // propose call returns immediately and a failed/declined elicitation
        // changes nothing.
        // Server-initiated elicitation needs the session's push channel:
        // gate on the declared capability AND the legacy generation.
        // Stateless callers already have the binding code + approval URL in
        // the tool result; MRTR is the future spec-native accelerator there.
        let supports_elicitation =
            client.elicitation_capable && client.generation == ProtocolGeneration::Legacy;
        if let Some(elicit) = approval_elicitation(&tool_name, &result, supports_elicitation) {
            let peer = ctx.peer.clone();
            tokio::spawn(async move {
                if let Err(err) = peer.create_elicitation(elicit).await {
                    tracing::debug!(%err, "approval elicitation not delivered");
                }
            });
        }
        // OTel semconv `error.type` on the span: `tool_error` when the tool
        // returned `isError`, the JSON-RPC code on a protocol error, unset on
        // success. An MRTR `input_required` pause is a successful round trip
        // (the specific classification lives in the shared helper).
        let error_type = crate::protocol::tool_call_response_error_type(&result);
        if let Some(et) = error_type.as_deref() {
            tracing::Span::current().record("error.type", et);
        }
        // `mcp.server.operation.duration`. `outcome` is `ok` exactly when there
        // is no `error.type` — so a tool-level `isError` counts as `error` in
        // the rate. The specific error class stays on the span, not as a metric
        // label (cardinality policy in `waygate-telemetry::metrics`).
        waygate_telemetry::metrics::record_server_operation(
            "tools/call",
            error_type.is_none(),
            started.elapsed().as_secs_f64(),
        );
        result
    }
}

impl GatewayServer {
    /// Attempt SEP-2663 task enqueue for a tasks-declaring client.
    /// `Ok(None)` means the call is not task-eligible — unknown or
    /// non-builtin tool, a built-in without task support, or a tool the
    /// built-in's `enqueue_task` declines — and must fall through to
    /// synchronous dispatch. Eligibility belongs to the built-in:
    /// `task_tool()` names only the primary tool, while Code Mode's
    /// `enqueue_task` accepts both `execute` and `resume`.
    async fn try_enqueue_task(
        &self,
        tool_name: &str,
        request: &CallToolRequestParams,
        principal: Option<&Principal>,
    ) -> Result<Option<rmcp::model::Task>, McpError> {
        let Some((builtin, tool)) = self.authorized_builtin(tool_name, principal).await? else {
            return Ok(None);
        };
        if !builtin.supports_tasks() {
            return Ok(None);
        }
        builtin
            .enqueue_task(tool, request.arguments.clone(), principal)
            .await
    }

    /// Fire a `notifications/tools/list_changed` on the session's peer if the
    /// last `searchTools` call revealed new tools. Swallows transport errors:
    /// the notification is a UX hint, not a correctness requirement, and the
    /// most likely failure is a client that has already disconnected.
    async fn notify_if_disclosed_changed(&self, peer: &Peer<RoleServer>) {
        if !self.disclosed.take_pending_notify() {
            return;
        }
        if let Err(err) = peer.notify_tool_list_changed().await {
            tracing::debug!(%err, "tools/list_changed notification dropped");
        }
    }
}

#[cfg(test)]
mod resource_file_correlation_tests {
    use super::*;
    use crate::catalog::UpstreamCatalog;
    use crate::files::{
        FileOutputContext, FileOutputProcessor, PreparedFileOutput, PreparedResourceOutput,
        SharedFileOutputProcessor,
    };
    use rmcp::model::ResourceContents;

    struct ResourceCatalog;

    #[async_trait::async_trait]
    impl UpstreamCatalog for ResourceCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["documents".to_owned()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        fn resource_claims(&self, server: &str) -> Vec<ResourceClaim> {
            assert_eq!(server, "documents");
            vec![ResourceClaim {
                uri_prefix: "docs://".to_owned(),
                risk: RiskTier::High,
            }]
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("resource test never dispatches a tool")
        }

        async fn read_resource(
            &self,
            server: &str,
            params: ReadResourceRequestParams,
            _principal: Option<&Principal>,
        ) -> Result<ReadResourceResult, McpError> {
            assert_eq!(server, "documents");
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                "governed body",
                params.uri,
            )]))
        }
    }

    #[derive(Default)]
    struct RecordingProcessor {
        contexts: tokio::sync::Mutex<Vec<FileOutputContext>>,
    }

    #[async_trait::async_trait]
    impl FileOutputProcessor for RecordingProcessor {
        async fn prepare(
            &self,
            _context: FileOutputContext,
            _result: CallToolResult,
        ) -> Result<PreparedFileOutput, McpError> {
            unreachable!("resource test uses prepare_resource")
        }

        async fn prepare_resource(
            &self,
            context: FileOutputContext,
            result: ReadResourceResult,
        ) -> Result<PreparedResourceOutput, McpError> {
            self.contexts.lock().await.push(context);
            Ok(PreparedResourceOutput {
                result,
                batch_id: None,
                file_count: 0,
            })
        }

        async fn publish(&self, _batch_id: &str, _file_count: usize) -> Result<(), McpError> {
            Ok(())
        }

        async fn discard(&self, _batch_id: &str) {}
    }

    fn principal() -> Principal {
        Principal {
            sub: "resource-reader".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "test".to_owned(),
            scopes: vec!["mcp:invoke:high".to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: Vec::new(),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[tokio::test]
    async fn governed_resource_files_join_the_read_resource_decision_id() {
        let sink = Arc::new(crate::audit::InMemorySink::new());
        let processor = Arc::new(RecordingProcessor::default());
        let shared_processor: SharedFileOutputProcessor = processor.clone();
        let server = GatewayServer::with_deps(
            Arc::new(ResourceCatalog),
            Arc::new(crate::authz::AllowAllGate),
            sink.clone(),
        )
        .with_file_output_processor(Some(shared_processor));

        server
            .read_visible_resource_with_transfer(
                ReadResourceRequestParams::new("docs://report"),
                Some(&principal()),
                true,
            )
            .await
            .expect("governed resource read");

        let contexts = processor.contexts.lock().await;
        let context = contexts.first().expect("file processor context");
        let rows = sink.snapshot().await;
        let decision = rows
            .iter()
            .find(|row| row.action == READ_RESOURCE_ACTION)
            .expect("ReadResource decision");
        assert_eq!(context.invocation_id, decision.id.to_string());
    }
}

#[cfg(test)]
mod elicitation_tests {
    use super::*;

    fn propose_result(approval_url: Option<&str>) -> Result<CallToolResponse, McpError> {
        let mut sc = serde_json::Map::new();
        sc.insert(
            "change_request_id".into(),
            json!("11111111-1111-1111-1111-111111111111"),
        );
        sc.insert("binding_code".into(), json!("AMBER-OTTER"));
        if let Some(u) = approval_url {
            sc.insert("approval_url".into(), json!(u));
        }
        Ok(CallToolResult::structured(Value::Object(sc)).into())
    }

    fn propose_tool() -> String {
        format!(
            "{}.propose_change",
            waygate_core::RESERVED_BUILTIN_NAMESPACE
        )
    }

    #[test]
    fn elicits_url_for_successful_propose_when_client_supports() {
        let r = propose_result(Some("https://gw.example/approve/abc"));
        let elicit = approval_elicitation(&propose_tool(), &r, true).expect("should elicit");
        match elicit {
            ElicitRequestParams::UrlElicitationParams {
                url,
                elicitation_id,
                ..
            } => {
                assert_eq!(url, "https://gw.example/approve/abc");
                assert_eq!(elicitation_id, "11111111-1111-1111-1111-111111111111");
            }
            _ => panic!("expected URL-mode elicitation"),
        }
    }

    #[test]
    fn no_elicitation_when_client_lacks_capability() {
        let r = propose_result(Some("https://gw.example/approve/abc"));
        assert!(approval_elicitation(&propose_tool(), &r, false).is_none());
    }

    #[test]
    fn no_elicitation_for_other_tools_or_missing_url_or_errors() {
        let r = propose_result(Some("https://gw.example/approve/abc"));
        // A different tool never elicits.
        assert!(approval_elicitation("example-messages.send_message", &r, true).is_none());
        // A propose with no approval_url (shouldn't happen on success) is skipped.
        assert!(approval_elicitation(&propose_tool(), &propose_result(None), true).is_none());
        // An error result never elicits.
        let err: Result<CallToolResponse, McpError> = Err(McpError::invalid_params("nope", None));
        assert!(approval_elicitation(&propose_tool(), &err, true).is_none());
    }
}

#[cfg(test)]
mod schema_def_name_tests {
    use super::*;

    fn obj(v: serde_json::Value) -> JsonObject {
        v.as_object().expect("object literal").clone()
    }

    #[test]
    fn lists_defs_sorted_and_dedups_across_blocks() {
        let schema = obj(serde_json::json!({
            "type": "object",
            "$defs": {"TrustTier": {}, "QuotaScope": {}},
            "definitions": {"QuotaScope": {}, "InspectorKind": {}},
            "properties": {"x": {"$ref": "#/$defs/TrustTier"}},
        }));
        assert_eq!(
            schema_def_names(&schema),
            vec!["InspectorKind", "QuotaScope", "TrustTier"],
        );
    }

    #[test]
    fn flat_schema_has_no_references() {
        let schema = obj(serde_json::json!({
            "type": "object",
            "properties": {"id": {"type": "string"}},
        }));
        assert!(schema_def_names(&schema).is_empty());
    }
}

#[cfg(test)]
mod profile_discovery_tests {
    use super::*;
    use waygate_oidc::{ApiKeyProfileRestrictions, AuthMethod};

    fn principal(restrictions: Option<ApiKeyProfileRestrictions>) -> Principal {
        Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::ApiKey,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: restrictions,
        }
    }

    fn restrictions(
        servers: Option<Vec<&str>>,
        tools: Option<Vec<&str>>,
    ) -> ApiKeyProfileRestrictions {
        ApiKeyProfileRestrictions {
            profile_id: "pid".into(),
            profile_name: "test_profile".into(),
            allowed_servers: servers.map(|v| v.into_iter().map(String::from).collect()),
            allowed_tools: tools.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    // Regression: discovery must
    // be gated the same way dispatch is.

    #[test]
    fn no_profile_blocks_nothing() {
        let p = principal(None);
        assert!(!profile_blocks_server(&p, "any"));
        assert!(!profile_blocks_tool(&p, "any", "x"));
    }

    #[test]
    fn empty_or_none_lists_block_nothing() {
        let p = principal(Some(restrictions(None, None)));
        assert!(!profile_blocks_server(&p, "any"));
        assert!(!profile_blocks_tool(&p, "any", "x"));
        let p = principal(Some(restrictions(Some(vec![]), Some(vec![]))));
        assert!(!profile_blocks_server(&p, "any"));
        assert!(!profile_blocks_tool(&p, "any", "x"));
    }

    #[test]
    fn allowed_servers_blocks_unlisted() {
        let p = principal(Some(restrictions(Some(vec!["email"]), None)));
        assert!(!profile_blocks_server(&p, "email"));
        assert!(profile_blocks_server(&p, "weather"));
        // allowed_tools is None — per-tool check stays unrestricted.
        assert!(!profile_blocks_tool(&p, "email", "anything"));
    }

    // When only allowed_tools is
    // pinned, profile_blocks_server must derive server
    // visibility from the tools' server prefix. A profile with
    // allowed_tools=["email.send"] must hide the weather meta-
    // tool (since no weather.* tool is reachable).
    #[test]
    fn allowed_tools_only_derives_server_block_from_prefix() {
        let p = principal(Some(restrictions(None, Some(vec!["email.send"]))));
        // email reachable (allowed_tools has email.send).
        assert!(!profile_blocks_server(&p, "email"));
        // weather NOT reachable — no weather.* in allowed_tools.
        assert!(profile_blocks_server(&p, "weather"));
        // Per-tool check unchanged.
        assert!(!profile_blocks_tool(&p, "email", "send"));
        assert!(profile_blocks_tool(&p, "email", "delete"));
        assert!(profile_blocks_tool(&p, "weather", "send"));
    }

    // When both restrictions are present,
    // server is hidden if EITHER rule blocks. (allowed_servers
    // list excludes it OR allowed_tools has no prefix for it.)
    #[test]
    fn both_restrictions_block_with_or_semantics() {
        // allowed_servers=["email","weather"] + allowed_tools=["email.send"]
        // → weather is in allowed_servers but no weather tool
        //   in allowed_tools → still blocked.
        let p = principal(Some(restrictions(
            Some(vec!["email", "weather"]),
            Some(vec!["email.send"]),
        )));
        assert!(!profile_blocks_server(&p, "email"));
        assert!(
            profile_blocks_server(&p, "weather"),
            "server in allowed_servers but with no tools in allowed_tools must still be hidden",
        );
        // billing fails both checks.
        assert!(profile_blocks_server(&p, "billing"));
    }
}

#[cfg(test)]
mod mrtr_projection_tests {
    use std::sync::Arc;

    use rmcp::model::{ErrorCode, InputRequest, InputRequiredResult, InputResponses};

    use super::*;
    use crate::catalog::UpstreamCatalog;
    use waygate_invocation::{InvocationResponse, InvocationService};

    struct EmptyCatalog;

    #[async_trait::async_trait]
    impl UpstreamCatalog for EmptyCatalog {
        async fn list_servers(&self) -> Vec<String> {
            Vec::new()
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("projection tests inject a scripted invocation service")
        }
    }

    /// Scripted invocation outcome + a record of every request received, so
    /// tests can assert what the adapter forwarded.
    struct ScriptedInvocation {
        outcome: ScriptedOutcome,
        requests: tokio::sync::Mutex<Vec<InvocationRequest>>,
    }

    enum ScriptedOutcome {
        ApprovalRequired { satisfiable: bool },
        Pause(InputRequiredResult),
        Complete,
    }

    impl ScriptedInvocation {
        fn new(outcome: ScriptedOutcome) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                requests: tokio::sync::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl InvocationService for ScriptedInvocation {
        async fn invoke(
            &self,
            _principal: Option<&Principal>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse, InvocationError> {
            self.requests.lock().await.push(request);
            match &self.outcome {
                ScriptedOutcome::ApprovalRequired { satisfiable } => {
                    Err(InvocationError::ApprovalRequired {
                        tool: "mock.send".to_owned(),
                        reason: "tool requires human approval; no matching grant".to_owned(),
                        satisfiable: *satisfiable,
                    })
                }
                ScriptedOutcome::Pause(pause) => {
                    Ok(InvocationResponse::InputRequired(pause.clone()))
                }
                ScriptedOutcome::Complete => {
                    Ok(InvocationResponse::Unary(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text("done"),
                    ])))
                }
            }
        }
    }

    fn server(invocation: Arc<ScriptedInvocation>) -> GatewayServer {
        GatewayServer::new(Arc::new(EmptyCatalog)).with_invocation_service(invocation)
    }

    fn elicitation_caller() -> MrtrCaller {
        MrtrCaller {
            capabilities: Some(
                rmcp::model::ClientCapabilities::builder()
                    .enable_elicitation()
                    .build(),
            ),
        }
    }

    /// A 2026 caller that declared no capabilities: receives pauses, answers
    /// nothing — the approval projection must not fire for it.
    fn bare_2026_caller() -> MrtrCaller {
        MrtrCaller {
            capabilities: Some(rmcp::model::ClientCapabilities::default()),
        }
    }

    fn call(name: &str) -> CallToolRequestParams {
        CallToolRequestParams::new(name.to_owned())
    }

    async fn dispatch(
        server: &GatewayServer,
        request: CallToolRequestParams,
        caller: &MrtrCaller,
    ) -> Result<CallToolResponse, McpError> {
        server
            .dispatch_tool_call_with(
                request,
                None,
                ProtocolGeneration::Legacy,
                Some(server.disclosed()),
                caller,
            )
            .await
    }

    #[tokio::test]
    async fn satisfiable_approval_projects_to_input_required_for_a_capable_caller() {
        let invocation =
            ScriptedInvocation::new(ScriptedOutcome::ApprovalRequired { satisfiable: true });
        let gw = server(Arc::clone(&invocation));
        match dispatch(&gw, call("mock.send"), &elicitation_caller()).await {
            Ok(CallToolResponse::InputRequired(pause)) => {
                assert!(
                    pause.request_state.is_none(),
                    "the gateway mints no requestState; the grant claim is the anchor",
                );
                let requests = pause.input_requests.expect("carries the approval ask");
                assert!(matches!(
                    requests.get(APPROVAL_INPUT_REQUEST_KEY),
                    Some(InputRequest::Elicitation(_)),
                ));
            }
            other => panic!("expected the approval projection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unsatisfiable_approval_stays_a_structured_error_even_for_a_capable_caller() {
        let invocation =
            ScriptedInvocation::new(ScriptedOutcome::ApprovalRequired { satisfiable: false });
        let gw = server(invocation);
        let err = dispatch(&gw, call("mock.send"), &elicitation_caller())
            .await
            .expect_err("a fail-closed refusal must not invite a doomed round trip");
        assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
        assert_eq!(
            err.data
                .as_ref()
                .and_then(|d| d.get("error"))
                .and_then(|v| v.as_str()),
            Some("approval_required"),
        );
    }

    #[tokio::test]
    async fn approval_error_shape_is_unchanged_for_callers_without_elicitation() {
        let invocation =
            ScriptedInvocation::new(ScriptedOutcome::ApprovalRequired { satisfiable: true });
        let gw = server(invocation);
        for caller in [MrtrCaller::CANNOT, bare_2026_caller()] {
            let err = dispatch(&gw, call("mock.send"), &caller)
                .await
                .expect_err("no projection without the elicitation capability");
            assert_eq!(err.code, ErrorCode::INVALID_REQUEST);
            assert_eq!(
                err.data
                    .as_ref()
                    .and_then(|d| d.get("error"))
                    .and_then(|v| v.as_str()),
                Some("approval_required"),
            );
        }
    }

    #[tokio::test]
    async fn reserved_approval_answer_is_stripped_from_the_retry() {
        let invocation = ScriptedInvocation::new(ScriptedOutcome::Complete);
        let gw = server(Arc::clone(&invocation));
        let mut responses = InputResponses::new();
        responses.insert(
            APPROVAL_INPUT_REQUEST_KEY.to_owned(),
            json!({"approved": true}),
        );
        responses.insert("q1".to_owned(), json!({"choice": "b"}));
        let mut request = call("mock.send");
        request.input_responses = Some(responses);
        request.request_state = Some("upstream-state".to_owned());
        dispatch(&gw, request, &elicitation_caller())
            .await
            .expect("completes");
        let recorded = invocation.requests.lock().await;
        let forwarded = recorded[0]
            .input_responses
            .as_ref()
            .expect("the upstream-addressed answer survives");
        assert!(!forwarded.contains_key(APPROVAL_INPUT_REQUEST_KEY));
        assert!(forwarded.contains_key("q1"));
        assert_eq!(recorded[0].request_state.as_deref(), Some("upstream-state"));
    }

    #[tokio::test]
    async fn retry_carrying_only_the_approval_answer_forwards_no_responses() {
        let invocation = ScriptedInvocation::new(ScriptedOutcome::Complete);
        let gw = server(Arc::clone(&invocation));
        let mut responses = InputResponses::new();
        responses.insert(
            APPROVAL_INPUT_REQUEST_KEY.to_owned(),
            json!({"approved": true}),
        );
        let mut request = call("mock.send");
        request.input_responses = Some(responses);
        dispatch(&gw, request, &elicitation_caller())
            .await
            .expect("the grant claim authorizes; the answer itself is not forwarded");
        let recorded = invocation.requests.lock().await;
        assert!(recorded[0].input_responses.is_none());
        assert!(recorded[0].request_state.is_none());
    }

    #[tokio::test]
    async fn legacy_caller_mrtr_fields_are_ignored_not_forwarded() {
        // MRTR continuation fields exist only on the 2026 generation. A
        // legacy request carrying them keeps having them ignored — exactly
        // the pre-MRTR behavior — so legacy dispatch stays byte-identical.
        let invocation = ScriptedInvocation::new(ScriptedOutcome::Complete);
        let gw = server(Arc::clone(&invocation));
        let mut responses = InputResponses::new();
        responses.insert("q1".to_owned(), json!({"choice": "b"}));
        let mut request = call("mock.send");
        request.input_responses = Some(responses);
        request.request_state = Some("upstream-state".to_owned());
        dispatch(&gw, request, &MrtrCaller::CANNOT)
            .await
            .expect("completes");
        let recorded = invocation.requests.lock().await;
        assert!(recorded[0].input_responses.is_none());
        assert!(recorded[0].request_state.is_none());
        assert!(recorded[0].caller_capabilities.is_none());
    }

    #[tokio::test]
    async fn upstream_pause_is_relayed_and_caller_capabilities_are_forwarded() {
        let invocation = ScriptedInvocation::new(ScriptedOutcome::Pause(
            InputRequiredResult::from_request_state("upstream-state-3"),
        ));
        let gw = server(Arc::clone(&invocation));
        match dispatch(&gw, call("mock.send"), &elicitation_caller()).await {
            Ok(CallToolResponse::InputRequired(pause)) => {
                assert_eq!(pause.request_state.as_deref(), Some("upstream-state-3"));
            }
            other => panic!("expected the pause to relay, got {other:?}"),
        }
        let recorded = invocation.requests.lock().await;
        assert!(recorded[0]
            .caller_capabilities
            .as_ref()
            .is_some_and(|caps| caps.elicitation.is_some()));
    }

    #[tokio::test]
    async fn direct_seam_refuses_a_non_final_response() {
        // `dispatch_tool_call` dispatches as a caller that can answer
        // nothing; a pause reaching it anyway (a misbehaving service) is a
        // wiring bug surfaced as an internal error, never a silent drop.
        let invocation = ScriptedInvocation::new(ScriptedOutcome::Pause(
            InputRequiredResult::from_request_state("s"),
        ));
        let gw = server(invocation);
        let err = gw
            .dispatch_tool_call(call("mock.send"), None)
            .await
            .expect_err("non-final response on the direct seam");
        assert_eq!(err.code, ErrorCode::INTERNAL_ERROR);
    }
}

#[cfg(test)]
mod skill_extension_server_tests {
    mod tool_tests {
        include!("skill_tools_tests.rs");
    }
    use std::{collections::BTreeMap, sync::Arc};

    use async_trait::async_trait;
    use rmcp::model::{CallToolResult, ContentBlock, Resource, Tool};
    use serde_json::{Map, Value};
    use waygate_skills::{
        verify_catalog_snapshot, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
        InMemorySkillResourceLoader, ReloadableSkillCatalog, SkillCatalogSnapshot,
        SkillCatalogSource, SkillResourceDescriptor, SkillResourceLoadError, SkillResourceLoader,
        SkillSourceError, CATALOG_SCHEMA_VERSION,
    };

    use super::*;
    use crate::{
        catalog::UpstreamCatalog,
        inspection::{Decision, InspectionContext, Inspector},
    };

    struct StaticSkillSource(SkillCatalogSnapshot);

    #[async_trait]
    impl SkillCatalogSource for StaticSkillSource {
        async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            Ok(self.0.clone())
        }
    }

    struct EmptyCatalog;

    #[async_trait]
    impl UpstreamCatalog for EmptyCatalog {
        async fn list_servers(&self) -> Vec<String> {
            Vec::new()
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("skill extension tests do not call tools")
        }
    }

    struct CollidingCatalog;
    struct ToolOnlyCatalog;
    struct LegacyResourceCatalog(LegacyResourceBehavior);
    struct DenySkillGate;

    enum LegacyResourceBehavior {
        Advertise(&'static str),
        Fail,
    }

    #[async_trait]
    impl UpstreamCatalog for CollidingCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["collision".into()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        fn resource_claims(&self, _server: &str) -> Vec<ResourceClaim> {
            vec![ResourceClaim {
                uri_prefix: "skill://catalog/".into(),
                risk: RiskTier::Low,
            }]
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("skill extension tests do not call tools")
        }
    }

    #[async_trait]
    impl UpstreamCatalog for LegacyResourceCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["legacy-resources".into()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        async fn list_resources(
            &self,
            _server: &str,
            _params: Option<PaginatedRequestParams>,
            _principal: Option<&Principal>,
        ) -> Result<ListResourcesResult, McpError> {
            match self.0 {
                LegacyResourceBehavior::Advertise(uri) => Ok(ListResourcesResult::with_all_items(
                    vec![Resource::new(uri.to_owned(), "legacy resource".to_owned())],
                )),
                LegacyResourceBehavior::Fail => Err(McpError::internal_error(
                    "legacy resource catalog unavailable",
                    None,
                )),
            }
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("skill extension tests do not call tools")
        }
    }

    #[async_trait]
    impl UpstreamCatalog for ToolOnlyCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["tools-only".into()]
        }

        async fn list_tools(&self, _server: &str) -> Result<Vec<Tool>, McpError> {
            Ok(Vec::new())
        }

        async fn resource_capability_advertised(&self, _server: &str) -> bool {
            false
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&crate::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("skill extension tests do not call tools")
        }
    }

    #[async_trait]
    impl crate::authz::AuthzGate for DenySkillGate {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            false
        }

        async fn may_list_resources(&self, _principal: &Principal, _server: &str) -> bool {
            false
        }

        async fn authorize_resource_read(
            &self,
            _principal: &Principal,
            _server: &str,
            _uri: &str,
            _risk: RiskTier,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "skill resource denied".into(),
                policy_ids: vec!["deny-skills".into()],
                reasons: Vec::new(),
            }
        }

        async fn authorize_skill_list(
            &self,
            _principal: &Principal,
            _facts: &crate::authz::SkillAccessFacts,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "skill catalog denied".into(),
                policy_ids: vec!["deny-skills".into()],
                reasons: Vec::new(),
            }
        }

        async fn authorize_skill_fetch(
            &self,
            _principal: &Principal,
            _facts: &crate::authz::SkillAccessFacts,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "skill source fetch denied".into(),
                policy_ids: vec!["deny-skill-fetch".into()],
                reasons: Vec::new(),
            }
        }

        async fn authorize_skill_read(
            &self,
            _principal: &Principal,
            _facts: &crate::authz::SkillAccessFacts,
        ) -> AuthzVerdict {
            AuthzVerdict::Deny {
                reason: "skill resource denied".into(),
                policy_ids: vec!["deny-skills".into()],
                reasons: Vec::new(),
            }
        }

        async fn authorize_tool_call(&self, _facts: &waygate_core::Facts) -> AuthzVerdict {
            AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }
    }

    struct AlwaysRedact;

    #[async_trait]
    impl Inspector for AlwaysRedact {
        fn name(&self) -> &'static str {
            "test_redactor"
        }

        async fn inspect(
            &self,
            _ctx: &InspectionContext<'_>,
            _result: &CallToolResult,
        ) -> Decision {
            Decision::Redact {
                redacted: CallToolResult::success(vec![ContentBlock::text("changed")]),
                findings_count: 1,
            }
        }
    }

    struct RefuseLoad;

    #[async_trait]
    impl SkillResourceLoader for RefuseLoad {
        async fn load(
            &self,
            _descriptor: &SkillResourceDescriptor,
        ) -> Result<Vec<u8>, SkillResourceLoadError> {
            panic!("source bytes must not be loaded before fetch authorization")
        }
    }

    fn skill_snapshot_with_loader(loader: Arc<dyn SkillResourceLoader>) -> SkillCatalogSnapshot {
        let skill_md = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n";
        let uri = "skill://catalog/demo/SKILL.md".to_owned();
        let resource = SkillResourceDescriptor {
            uri: uri.clone(),
            source_path: "demo/SKILL.md".into(),
            source_object: format!("git-sha1:{}", "b".repeat(40)),
            size: skill_md.len() as u64,
            media_type: "text/markdown".into(),
        };
        let mut frontmatter = Map::new();
        frontmatter.insert("name".into(), Value::String("demo".into()));
        frontmatter.insert("description".into(), Value::String("Demo skill".into()));
        verify_catalog_snapshot(
            CatalogSourceIdentity {
                origin: "git+https://git.example/team/skills".into(),
                reference: "main".into(),
                resolved_digest: format!("git-sha1:{}", "a".repeat(40)),
                resolved_tree_digest: format!("git-sha1:{}", "b".repeat(40)),
            },
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills: vec![CatalogSkill {
                    uri: uri.clone(),
                    frontmatter,
                    resources: vec![resource],
                }],
            },
            BTreeMap::from([(uri, skill_md.to_vec())]),
            loader,
        )
        .expect("valid skill snapshot")
    }

    fn skill_snapshot() -> SkillCatalogSnapshot {
        let uri = "skill://catalog/demo/SKILL.md".to_owned();
        let bytes = b"---\nname: demo\ndescription: Demo skill\n---\n# Demo\n".to_vec();
        skill_snapshot_with_loader(Arc::new(InMemorySkillResourceLoader::new(BTreeMap::from(
            [(uri, bytes)],
        ))))
    }

    async fn loaded_catalog_with_snapshot(
        snapshot: SkillCatalogSnapshot,
    ) -> Arc<ReloadableSkillCatalog> {
        let catalog = Arc::new(ReloadableSkillCatalog::default());
        catalog
            .refresh(&StaticSkillSource(snapshot))
            .await
            .expect("publish verified snapshot");
        catalog
    }

    async fn loaded_catalog() -> Arc<ReloadableSkillCatalog> {
        loaded_catalog_with_snapshot(skill_snapshot()).await
    }

    fn principal_hiding_collision() -> Principal {
        Principal {
            sub: "hidden-owner-reader".into(),
            email: None,
            groups: Vec::new(),
            issuer: "test".into(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::ApiKey,
            raw_token: None,
            roles: Vec::new(),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "hidden-owner-profile".into(),
                profile_name: "hidden owner profile".into(),
                allowed_servers: Some(vec![GATEWAY_SKILLS_SERVER.into()]),
                allowed_tools: None,
            }),
        }
    }

    fn principal_denied_skills() -> Principal {
        let mut principal = principal_hiding_collision();
        principal.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "deny-skills-profile".into(),
            profile_name: "deny skills profile".into(),
            allowed_servers: Some(vec!["another-server".into()]),
            allowed_tools: None,
        });
        principal
    }

    fn extension_is_advertised(server: &GatewayServer) -> bool {
        server
            .get_info()
            .capabilities
            .extensions
            .as_ref()
            .is_some_and(|extensions| extensions.contains_key(crate::skills::EXTENSION_ID))
    }

    #[tokio::test]
    async fn advertises_only_after_a_verified_snapshot_is_published() {
        let catalog = Arc::new(ReloadableSkillCatalog::default());
        let server = GatewayServer::new(Arc::new(EmptyCatalog))
            .with_approved_skill_fixture(Some(catalog.clone()));
        assert!(!extension_is_advertised(&server));

        catalog
            .refresh(&StaticSkillSource(skill_snapshot()))
            .await
            .expect("publish verified snapshot");
        assert!(extension_is_advertised(&server));
        assert_eq!(
            server.get_info().capabilities.extensions.as_ref().unwrap()
                [crate::skills::EXTENSION_ID],
            JsonObject::new()
        );
    }

    #[tokio::test]
    async fn skill_resource_namespace_ignores_legacy_catalogs_and_refuses_declared_collisions() {
        let skills = loaded_catalog().await;
        let uri = "skill://catalog/demo/SKILL.md";
        let snapshot = skills.current().expect("published skill snapshot");

        GatewayServer::new(Arc::new(ToolOnlyCatalog))
            .with_approved_skill_fixture(Some(skills.clone()))
            .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
            .await
            .expect("a tool-only upstream does not claim resource origin authority");

        let declared_collision_server = GatewayServer::new(Arc::new(CollidingCatalog))
            .with_approved_skill_fixture(Some(skills.clone()));
        declared_collision_server
            .ensure_skill_catalog_origin_isolation(&snapshot)
            .await
            .expect_err("a declared collision must also prevent skill listing");
        let collision = declared_collision_server
            .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
            .await
            .expect_err("gateway/upstream collision must fail closed");
        assert_eq!(collision.code, rmcp::model::ErrorCode::INVALID_PARAMS);

        let hidden_principal = principal_hiding_collision();
        assert!(profile_blocks_server(&hidden_principal, "collision"));
        assert!(!profile_blocks_resources(
            &hidden_principal,
            GATEWAY_SKILLS_SERVER
        ));
        let post_allow_sink = Arc::new(crate::audit::InMemorySink::new());
        let hidden_collision = GatewayServer::with_deps(
            Arc::new(CollidingCatalog),
            Arc::new(AllowAllGate),
            post_allow_sink.clone(),
        )
        .with_approved_skill_fixture(Some(skills.clone()))
        .read_verified_skill_resource(uri, Some(&hidden_principal), true)
        .await
        .expect_err("a hidden declared owner must still reserve its URI");
        assert_eq!(
            hidden_collision.code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        assert!(!hidden_collision.message.contains("collision"));
        let post_allow_rows = post_allow_sink.snapshot().await;
        assert!(post_allow_rows.iter().any(|row| {
            row.action == FETCH_SKILL_RESOURCE_ACTION
                && row.outcome == AuditOutcome::Success
                && row.policy_ids.is_empty()
        }));
        assert!(post_allow_rows.iter().any(|row| {
            row.action == READ_SKILL_ACTION
                && row.outcome == AuditOutcome::Denied
                && row.reason.as_deref().is_some_and(|reason| {
                    reason.starts_with(waygate_core::SKILL_POST_AUTHORIZATION_REFUSAL_PREFIX)
                })
        }));

        let unrelated_legacy_server = GatewayServer::new(Arc::new(LegacyResourceCatalog(
            LegacyResourceBehavior::Advertise("legacy://docs/readme"),
        )))
        .with_approved_skill_fixture(Some(skills.clone()));
        unrelated_legacy_server
            .ensure_skill_catalog_origin_isolation(&snapshot)
            .await
            .expect("an unrelated legacy provider must not block skill listing");
        unrelated_legacy_server
            .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
            .await
            .expect("an unrelated legacy resource must not block a verified skill read");

        GatewayServer::new(Arc::new(LegacyResourceCatalog(
            LegacyResourceBehavior::Advertise(uri),
        )))
        .with_approved_skill_fixture(Some(skills.clone()))
        .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
        .await
        .expect("the gateway owns every skill URI in its published catalog");

        GatewayServer::new(Arc::new(LegacyResourceCatalog(
            LegacyResourceBehavior::Fail,
        )))
        .with_approved_skill_fixture(Some(skills.clone()))
        .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
        .await
        .expect("a legacy provider outage cannot block a gateway-owned skill URI");

        let redaction = GatewayServer::new(Arc::new(EmptyCatalog))
            .with_approved_skill_fixture(Some(skills))
            .with_resource_inspectors(vec![Arc::new(AlwaysRedact)])
            .read_verified_skill_resource(uri, Some(&principal_hiding_collision()), true)
            .await
            .expect_err("digest-changing redaction must fail closed");
        assert_eq!(redaction.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert_eq!(
            redaction.data.as_ref().unwrap()["inspector_name"],
            "test_redactor"
        );
    }

    #[tokio::test]
    async fn skill_catalog_and_resource_reads_require_policy_and_record_denials() {
        let skills =
            loaded_catalog_with_snapshot(skill_snapshot_with_loader(Arc::new(RefuseLoad))).await;
        let sink = Arc::new(crate::audit::InMemorySink::new());
        let server = GatewayServer::with_deps(
            Arc::new(EmptyCatalog),
            Arc::new(DenySkillGate),
            sink.clone(),
        )
        .with_approved_skill_fixture(Some(skills.clone()));
        let principal = principal_hiding_collision();
        let snapshot = skills.current().expect("published snapshot");

        let list = server
            .authorize_skill_catalog_list(Some(&principal), &snapshot)
            .await
            .expect_err("skill listing requires skill-list authority");
        assert_eq!(list.code, rmcp::model::ErrorCode::METHOD_NOT_FOUND);

        let read = server
            .read_verified_skill_resource("skill://catalog/demo/SKILL.md", Some(&principal), true)
            .await
            .expect_err("skill bytes require skill-read authority");
        assert_eq!(read.code, rmcp::model::ErrorCode::RESOURCE_NOT_FOUND);

        let rows = sink.snapshot().await;
        let list_row = rows.iter().find(|row| {
            row.action == LIST_SKILLS_ACTION
                && row.server.as_deref() == Some(GATEWAY_SKILLS_SERVER)
                && row.outcome == AuditOutcome::Denied
        });
        let list_target: serde_json::Value = serde_json::from_str(
            list_row
                .and_then(|row| row.target.as_deref())
                .expect("skill list denial has a structured target"),
        )
        .expect("skill list target is JSON");
        assert_eq!(list_target["source_origin"], snapshot.source().origin);
        assert_eq!(
            list_target["artifact_digest"],
            snapshot.source().resolved_digest
        );
        assert_eq!(
            list_target["source_tree_digest"],
            snapshot.source().resolved_tree_digest
        );

        let read_row = rows.iter().find(|row| {
            row.action == FETCH_SKILL_RESOURCE_ACTION
                && row.server.as_deref() == Some(GATEWAY_SKILLS_SERVER)
                && row.outcome == AuditOutcome::Denied
                && row.policy_ids == vec!["deny-skill-fetch"]
        });
        let read_target: serde_json::Value = serde_json::from_str(
            read_row
                .and_then(|row| row.target.as_deref())
                .expect("skill read denial has a structured target"),
        )
        .expect("skill read target is JSON");
        assert_eq!(read_target["resource_uri"], "skill://catalog/demo/SKILL.md");
        assert_eq!(read_target["source_path"], "demo/SKILL.md");
        assert_eq!(
            read_target["source_object"],
            format!("git-sha1:{}", "b".repeat(40))
        );
        assert_eq!(read_target["source_origin"], snapshot.source().origin);
        assert_eq!(
            read_target["source_tree_digest"],
            snapshot.source().resolved_tree_digest
        );
        assert!(read_target["revision_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert!(read_target.get("resource_digest").is_none());
        assert!(!rows.iter().any(|row| row.action == READ_SKILL_ACTION));

        let profile_sink = Arc::new(crate::audit::InMemorySink::new());
        let profile_server = GatewayServer::with_deps(
            Arc::new(EmptyCatalog),
            Arc::new(crate::authz::AllowAllGate),
            profile_sink.clone(),
        )
        .with_approved_skill_fixture(Some(skills));
        let denied_principal = principal_denied_skills();
        let profile_read = profile_server
            .read_verified_skill_resource(
                "skill://catalog/demo/SKILL.md",
                Some(&denied_principal),
                true,
            )
            .await
            .expect_err("API-key resource profiles confine gateway skills");
        assert_eq!(
            profile_read.code,
            rmcp::model::ErrorCode::RESOURCE_NOT_FOUND
        );
        assert!(profile_sink.snapshot().await.iter().any(|row| {
            row.action == FETCH_SKILL_RESOURCE_ACTION
                && row.server.as_deref() == Some(GATEWAY_SKILLS_SERVER)
                && row.outcome == AuditOutcome::Denied
                && row.reason.as_deref() == Some(waygate_core::SKILL_PROFILE_REFUSAL_REASON)
        }));
    }
}
