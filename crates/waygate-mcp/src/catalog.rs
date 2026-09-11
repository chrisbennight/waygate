//! Bridge between the MCP server handler (in this crate) and the upstream
//! connection pool (in `waygate-upstream`).
//!
//! The handler only cares about two operations — enumerate tools for a given
//! upstream, and proxy a call. Keeping this as a trait means `waygate-mcp` has
//! no dependency on `waygate-upstream`, which sidesteps a cycle and lets tests
//! use in-memory fakes.

use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{
    CallToolResponse, CallToolResult, ClientCapabilities, InputResponses,
    ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResult, Tool,
};
use rmcp::ErrorData as McpError;
use serde_json::{Map, Value};
use uuid::Uuid;
pub use waygate_invocation::{
    InvocationContractAuthority, InvocationContractIdentity, InvocationError, InvocationRisk,
};
use waygate_oidc::Principal;

use crate::authz::ToolFacts;
use crate::files::{
    AuthorizeDownloadParams, AuthorizeUploadParams, AuthorizedFileDownload, AuthorizedFileUpload,
};
use crate::protocol::RiskTier;

/// One literal resource URI prefix declared by an upstream manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceClaim {
    pub uri_prefix: String,
    pub risk: RiskTier,
}

/// One atomically observed generation of fleet-wide resource routing claims.
///
/// Resolution may release this snapshot while Cedar evaluates the selected
/// owner. The generation is carried back into dispatch so the pool can refuse
/// before the upstream RPC if any claim or legacy-server membership changed in
/// between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRoutingSnapshot {
    pub generation: u64,
    pub claims: Vec<(String, ResourceClaim)>,
}

/// Resource ownership and risk identity admitted by the gateway handler.
///
/// `claim` is `None` only for the compatibility path where a server with no
/// declarations advertised the exact URI through `resources/list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceReadAdmission {
    pub generation: u64,
    pub server: String,
    pub claim: Option<ResourceClaim>,
}

/// Provenance-preserving result of dispatching an admitted resource read.
///
/// Routing and bounded-transport refusals are synthesized by the gateway
/// before an upstream RPC. The response-size variant is synthesized by the
/// gateway's bounded transport after dispatch. Every MCP error received from
/// an upstream remains [`Self::Upstream`], even if its wire data resembles a
/// local payload.
#[derive(Debug)]
pub enum AdmittedResourceReadError {
    /// The gateway refused before dispatch because authorization's routing
    /// identity is no longer current.
    RoutingChanged,
    /// The gateway refused before dispatch because this transport cannot
    /// enforce the request's raw response-materialization bound.
    BoundedUnsupported { transport: &'static str },
    /// The attempt reached the upstream, but the gateway stopped materializing
    /// its raw response at the request's byte ceiling.
    ResponseTooLarge { limit_bytes: usize },
    /// The admitted attempt reached the upstream dispatch path and failed.
    Upstream(McpError),
}

impl AdmittedResourceReadError {
    pub(crate) fn into_mcp_error(self) -> McpError {
        match self {
            Self::RoutingChanged => McpError::invalid_request(
                "resource routing changed after authorization; resolve and retry the read",
                Some(serde_json::json!({"error": "resource_routing_changed"})),
            ),
            Self::BoundedUnsupported { transport } => McpError::internal_error(
                format!("bounded resource reads are unsupported for {transport} transport"),
                Some(serde_json::json!({
                    "error": "bounded_resource_read_unsupported",
                    "transport": transport,
                })),
            ),
            Self::ResponseTooLarge { limit_bytes } => McpError::internal_error(
                format!("upstream resource response exceeded the {limit_bytes}-byte limit"),
                Some(serde_json::json!({
                    "error": "resource_response_too_large",
                    "limit_bytes": limit_bytes,
                })),
            ),
            Self::Upstream(error) => error,
        }
    }
}

/// Private request metadata used only between the invocation pipeline and the
/// gateway-owned upstream HTTP transport. It asks that transport to bound the
/// raw JSON-RPC response before rmcp decodes it. Upstreams may ignore the
/// extension; enforcement happens client-side.
pub const RESPONSE_MATERIALIZATION_LIMIT_META_KEY: &str =
    "io.bennight.gateway/responseMaterializationLimitBytes";

/// Compatibility marker used by the call-scoped retained-response pipeline
/// after the pool recovers a typed bounded-transport refusal. Native admitted
/// reads preserve that refusal as [`AdmittedResourceReadError::ResponseTooLarge`]
/// instead of inferring provenance from this wire-shaped value.
pub const RESPONSE_MATERIALIZATION_LIMIT_ERROR: &str = "gateway_response_materialization_limit";

/// One resource read bound to the same upstream MCP session that produced a
/// tool result. Dynamic resource links may name state owned by that session,
/// so a later catalog-level `resources/read` is not equivalent.
#[async_trait]
pub trait CallScopedResourceReader: Send + Sync {
    async fn read_resource(
        &self,
        params: ReadResourceRequestParams,
    ) -> Result<ReadResourceResult, CallScopedResourceError>;
}

/// Failure from a call-scoped resource read. MCP application errors prove the
/// transport answered; transport errors additionally make the selected pool
/// lane suspect.
#[derive(Debug)]
pub enum CallScopedResourceError {
    Mcp(McpError),
    Transport(String),
}

impl CallScopedResourceError {
    #[must_use]
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    #[must_use]
    pub fn mcp_error(&self) -> Option<&McpError> {
        match self {
            Self::Mcp(error) => Some(error),
            Self::Transport(_) => None,
        }
    }
}

/// Result processing that must run before the upstream call's session is
/// released. The invocation pipeline supplies governance; the pool supplies
/// only the session-affine resource reader.
#[async_trait]
pub trait CallToolResultProcessor: Send + Sync {
    async fn process(
        &self,
        result: CallToolResult,
        reader: &dyn CallScopedResourceReader,
    ) -> Result<CallToolResult, CallToolResultProcessingError>;
}

/// Call metadata paired with the processor that must run while the upstream
/// session is still checked out.
pub struct CallToolResultProcessing<'a> {
    pub mrtr: ToolCallMrtr,
    pub processor: &'a dyn CallToolResultProcessor,
}

/// A governed post-dispatch refusal plus whether its resource I/O proved the
/// selected upstream lane unhealthy.
#[derive(Debug)]
pub struct CallToolResultProcessingError {
    error: InvocationError,
    upstream_failure: bool,
}

impl CallToolResultProcessingError {
    #[must_use]
    pub fn new(error: InvocationError, upstream_failure: bool) -> Self {
        Self {
            error,
            upstream_failure,
        }
    }

    #[must_use]
    pub fn upstream_failure(&self) -> bool {
        self.upstream_failure
    }

    #[must_use]
    pub fn into_error(self) -> InvocationError {
        self.error
    }
}

struct CatalogResourceReader<'a, T: UpstreamCatalog + ?Sized> {
    catalog: &'a T,
    server: &'a str,
    principal: Option<&'a Principal>,
}

#[async_trait]
impl<T: UpstreamCatalog + ?Sized> CallScopedResourceReader for CatalogResourceReader<'_, T> {
    async fn read_resource(
        &self,
        params: ReadResourceRequestParams,
    ) -> Result<ReadResourceResult, CallScopedResourceError> {
        self.catalog
            .read_resource(self.server, params, self.principal)
            .await
            .map_err(CallScopedResourceError::Mcp)
    }
}

#[async_trait]
pub trait UpstreamCatalog: Send + Sync + 'static {
    /// Names of every registered upstream (e.g. `["example-messages", "example-observability"]`).
    async fn list_servers(&self) -> Vec<String>;

    /// Full `tools/list` result for a single upstream, as most-recently cached.
    async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError>;

    /// Durable generation for governed-catalog changes that can alter discovery.
    /// Static catalogs and deployments without a durable governed catalog have
    /// no cross-process generation and retain the default `None`.
    async fn discovery_generation(&self) -> Result<Option<i64>, McpError> {
        Ok(None)
    }

    /// Process-local generation advanced whenever an authoritative catalog
    /// lookup fails while constructing a discovery or invocation snapshot.
    /// Stable discovery readers compare it before and after their projection
    /// so a transient per-tool failure cannot become a valid incomplete page.
    fn discovery_error_generation(&self) -> u64 {
        0
    }

    /// Manifest-declared resource routing entries for one upstream. Empty
    /// means this is a legacy server whose ownership must still be discovered
    /// through `resources/list` for compatibility.
    fn resource_claims(&self, _server: &str) -> Vec<ResourceClaim> {
        Vec::new()
    }

    /// Fleet-wide claims visible inside an implementation-held resource
    /// routing admission. The live pool overrides this with its lock-free
    /// entry snapshot so session-affine retained-response processing can
    /// enforce cross-server ownership without re-acquiring the fair routing
    /// lock behind a queued writer. Static catalogs may keep the default and
    /// are checked against the selected server's [`Self::resource_claims`].
    fn admitted_resource_routing_claims(&self) -> Vec<(String, ResourceClaim)> {
        Vec::new()
    }

    /// Fleet-wide resource claims paired with an activation generation.
    /// Test catalogs and static implementations default to generation zero;
    /// the live upstream pool overrides this with its reload fence.
    async fn resource_routing_snapshot(&self) -> ResourceRoutingSnapshot {
        let mut claims = Vec::new();
        for server in self.list_servers().await {
            claims.extend(
                self.resource_claims(&server)
                    .into_iter()
                    .map(|claim| (server.clone(), claim)),
            );
        }
        ResourceRoutingSnapshot {
            generation: 0,
            claims,
        }
    }

    /// Proxy a call to the upstream. `tool_name` is the upstream-side name
    /// (the `<server>.` prefix has already been stripped). `principal` is
    /// forwarded so the pool can mint a per-call identity JWT for the
    /// upstream; `None` means the call arrived over a transport with no auth
    /// context (disabled mode or anonymous).
    ///
    /// `admitted` is the exact contract identity the invocation pipeline's
    /// Stage 1 resolver admitted and every earlier stage (validation,
    /// authorization, approval, Code Mode expected-contract checking)
    /// evaluated against. When present, the implementation must refuse the
    /// dispatch unless the tool's currently-resolved contract identity still
    /// equals this value at the moment the RPC is bound to a connection —
    /// otherwise a catalog/manifest change racing the pipeline could execute
    /// a contract the earlier stages never saw.
    /// Invoke `<server>.<tool>` on the upstream. Results pass through with
    /// their `result_type` untouched: a legacy upstream omits the field
    /// and, per the 2026-07-28 result discriminator's compatibility rule,
    /// an absent `resultType` MUST be treated as "complete" — no consumer
    /// may branch on its presence.
    async fn call_tool(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
    ) -> Result<CallToolResult, McpError>;

    /// [`Self::call_tool`] widened to the full MRTR round-trip contract
    /// (SEP-2322): the dispatch may return an `input_required` pause or a
    /// task envelope instead of a complete result, and a retry carries the
    /// caller's `input_responses` / `request_state` to the upstream
    /// verbatim.
    ///
    /// The default implementation serves catalogs with no MRTR passthrough
    /// (test fakes, the built-in surfaces): a first-round call delegates to
    /// [`Self::call_tool`], and a retry carrying continuation fields is
    /// refused with a teach-through error rather than silently dropping the
    /// caller's answers on the floor.
    async fn call_tool_response(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        mrtr: ToolCallMrtr,
    ) -> Result<CallToolResponse, McpError> {
        if mrtr.input_responses.is_some() || mrtr.request_state.is_some() {
            return Err(McpError::invalid_params(
                format!(
                    "`{server}.{tool_name}` did not issue an input_required pause on this \
                     surface; retry without `inputResponses`/`requestState`"
                ),
                None,
            ));
        }
        self.call_tool(server, tool_name, args, principal, admitted)
            .await
            .map(CallToolResponse::Complete)
    }

    /// Dispatch and process a complete result before its originating MCP
    /// session is released. Implementations with per-call sessions override
    /// this seam; the default preserves existing catalogs by using their
    /// ordinary resource reader.
    async fn call_tool_response_processed(
        &self,
        server: &str,
        tool_name: &str,
        args: Option<Map<String, Value>>,
        principal: Option<&Principal>,
        admitted: Option<&InvocationContractIdentity>,
        processing: CallToolResultProcessing<'_>,
    ) -> Result<CallToolResponse, InvocationError> {
        let CallToolResultProcessing { mrtr, processor } = processing;
        let response = self
            .call_tool_response(server, tool_name, args, principal, admitted, mrtr)
            .await
            .map_err(InvocationError::Upstream)?;
        let CallToolResponse::Complete(result) = response else {
            return Ok(response);
        };
        let reader = CatalogResourceReader {
            catalog: self,
            server,
            principal,
        };
        processor
            .process(result, &reader)
            .await
            .map(CallToolResponse::Complete)
            .map_err(CallToolResultProcessingError::into_error)
    }

    /// Forward one page of an upstream's MCP resource catalog.
    async fn list_resources(
        &self,
        _server: &str,
        _params: Option<PaginatedRequestParams>,
        _principal: Option<&Principal>,
    ) -> Result<ListResourcesResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ListResourcesRequestMethod,
        >())
    }

    /// Forward one page of an upstream's resource-template catalog.
    async fn list_resource_templates(
        &self,
        _server: &str,
        _params: Option<PaginatedRequestParams>,
        _principal: Option<&Principal>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ListResourceTemplatesRequestMethod,
        >())
    }

    /// Read one resource from an upstream that advertised its URI.
    async fn read_resource(
        &self,
        _server: &str,
        _params: ReadResourceRequestParams,
        _principal: Option<&Principal>,
    ) -> Result<ReadResourceResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ReadResourceRequestMethod,
        >())
    }

    /// Read a resource only if the routing identity authorized by the handler
    /// is still current when the implementation binds the RPC to a session.
    /// Static/test catalogs have no reload generation and delegate directly;
    /// the live pool overrides this seam and holds its routing read fence
    /// across the upstream call.
    async fn read_resource_admitted(
        &self,
        server: &str,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        _admitted: &ResourceReadAdmission,
    ) -> Result<ReadResourceResult, AdmittedResourceReadError> {
        self.read_resource(server, params, principal)
            .await
            .map_err(AdmittedResourceReadError::Upstream)
    }

    /// Whether this upstream can safely serve resource operations through the
    /// current gateway transport and identity configuration.
    fn resource_operations_supported(&self, _server: &str) -> bool {
        true
    }

    /// Whether a live negotiated lane advertised the MCP Resources capability.
    async fn resource_capability_advertised(&self, server: &str) -> bool {
        self.resource_operations_supported(server)
    }

    /// Ask an upstream to resolve one of its private file references to an
    /// HTTPS download. The gateway consumes the descriptor; it is never sent
    /// to the downstream caller.
    async fn authorize_file_download(
        &self,
        _server: &str,
        _params: AuthorizeDownloadParams,
        _principal: Option<&Principal>,
    ) -> Result<AuthorizedFileDownload, McpError> {
        Err(McpError::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            crate::files::AUTHORIZE_DOWNLOAD_METHOD,
            None,
        ))
    }

    /// Ask an upstream to allocate a private HTTPS destination for one file.
    /// The gateway consumes the descriptor and sends only the resulting
    /// upstream-private file reference in the eventual tool call. The
    /// implementation must bind this side effect to `admitted` before sending
    /// the authorization request, just as [`Self::call_tool`] binds dispatch.
    async fn authorize_file_upload(
        &self,
        _server: &str,
        _tool_name: &str,
        _params: AuthorizeUploadParams,
        _principal: Option<&Principal>,
        _admitted: &InvocationContractIdentity,
    ) -> Result<AuthorizedFileUpload, McpError> {
        Err(McpError::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            crate::files::AUTHORIZE_UPLOAD_METHOD,
            None,
        ))
    }

    /// Classification metadata for `<server>.<tool>`. Default is Low-risk /
    /// no-side-effects; the per-server YAML manifest loader populates
    /// real values, and test fakes can override to exercise the step-up
    /// / deny paths.
    ///
    /// Synchronous + manifest-backed. The governed-catalog read
    /// path is [`Self::resolve_invocation_tool`]; this stays as the fallback
    /// the catalog path delegates to on a catalog miss.
    fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
        ToolFacts {
            server: server.to_owned(),
            name: tool_name.to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            // Default impl: assume manifest is authoritative (no
            // catalog has demoted this from `Live`). The
            // catalog-Err fallback path in `UpstreamPool`
            // explicitly overrides to false.
            requires_approval_known: true,
        }
    }

    /// Tenant-aware classification lookup that consults
    /// the governed catalog (DB) first, falling back to the
    /// manifest-backed [`Self::tool_facts`] on a catalog miss / error.
    ///
    /// The default impl ignores `tenant` and delegates straight to the
    /// sync `tool_facts`, so existing implementations and test fakes
    /// behave exactly as before. `UpstreamPool` overrides it to add the
    /// catalog read. Async because the catalog read is a DB round-trip;
    /// discovery handlers and the invocation pipeline's resolve stage are
    /// already async.
    ///
    /// Returns [`ResolvedInvocationTool`], not bare [`ToolFacts`], so the catalog
    /// can signal an authoritative `Quarantined` block. The dispatch
    /// path turns that into a refusal; the discovery paths drop the tool
    /// from the listing. A quarantine therefore both hides the tool and
    /// blocks the call, instead of being silently rehabilitated by the
    /// manifest fallback.
    async fn resolve_invocation_tool(
        &self,
        _tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        ResolvedInvocationTool::Ready(InvocationToolSnapshot::manifest_fallback(
            self.tool_facts(server, tool_name),
            true,
        ))
    }

    /// Resolve one tool for discovery with its definition and governance facts
    /// bound into the same snapshot.
    ///
    /// The live upstream pool captures the definition inside
    /// [`Self::resolve_invocation_tool`]. Static catalogs retain a compatibility
    /// fallback that attaches their immutable listed definition here.
    async fn resolve_discovery_tool(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> ResolvedInvocationTool {
        let resolved = self
            .resolve_invocation_tool(tenant, server, tool_name)
            .await;
        let ResolvedInvocationTool::Ready(snapshot) = resolved else {
            return resolved;
        };
        if snapshot.published_definition().is_some() {
            return ResolvedInvocationTool::Ready(snapshot);
        }
        let definition = self
            .list_tools(server)
            .await
            .ok()
            .and_then(|tools| tools.into_iter().find(|tool| tool.name == tool_name));
        ResolvedInvocationTool::Ready(snapshot.with_published_definition(definition))
    }
}

/// Request-local metadata for one upstream dispatch.
///
/// The first three fields carry MRTR state (SEP-2322): `input_responses` and
/// `request_state` are the caller's retry payload,
/// forwarded to the upstream verbatim. `caller_capabilities` is the
/// downstream caller's declared server-initiated-request capability set;
/// the pool mirrors it into a per-call ephemeral dial on a 2026-07-28
/// upstream so the upstream pauses exactly when the caller can answer.
/// `None` capabilities means the caller cannot answer any pause (legacy
/// session, Code Mode, LLM surface) — shared lanes and legacy dials then
/// advertise nothing, which is the pre-MRTR behavior. `approval_gated` is
/// gateway-owned dispatch authority and never enters the upstream wire shape.
#[derive(Debug, Clone, Default)]
pub struct ToolCallMrtr {
    pub input_responses: Option<InputResponses>,
    pub request_state: Option<String>,
    pub caller_capabilities: Option<ClientCapabilities>,
    /// The governed invocation consumed approval authority, whether required
    /// by the catalog contract or a dynamic Cedar overlay. Transport setup
    /// recovery must not spend that single-use authority on a second attempt.
    pub approval_gated: bool,
}

/// Authority that admitted a tool into one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionAuthority {
    /// The governed catalog admitted the tool identity and classification.
    /// Schemas are captured in the snapshot from the catalog row or the
    /// connected upstream's published `tools/list` contract.
    Catalog { tool_id: Uuid, schema_hash: String },
    /// Manifest metadata admitted the call because no live catalog definition
    /// was available. The approval flag states whether that fallback is safe to
    /// trust for HITL enforcement.
    ManifestFallback {
        approval_requirements_known: bool,
        /// The manifest-approved behavior hash for an annotation-native
        /// upstream; `None` in legacy manifest mode. Part of the contract
        /// identity so fallback generations differing only outside the four
        /// schema hashes stay distinguishable.
        approved_behavior_hash: Option<String>,
    },
    /// The inference arm created typed model facts without resolving an MCP
    /// tool or manifest. It carries no catalog identity or MCP schemas.
    SyntheticModel,
}

impl ResolutionAuthority {
    /// Stable finite identifier for tracing and metrics.
    pub const fn id(&self) -> &'static str {
        match self {
            Self::Catalog { .. } => "catalog",
            Self::ManifestFallback {
                approval_requirements_known: true,
                ..
            } => "manifest_fallback_known",
            Self::ManifestFallback {
                approval_requirements_known: false,
                ..
            } => "manifest_fallback_unknown",
            Self::SyntheticModel => "synthetic_model",
        }
    }
}

/// Immutable tool definition admitted at invocation Stage 1.
///
/// Catalog identity, schema version, schemas, and authorization facts travel
/// together for the lifetime of the request. Later stages must consume this
/// snapshot instead of resolving the catalog again after an await.
#[derive(Debug, Clone)]
pub struct InvocationToolSnapshot {
    facts: ToolFacts,
    authority: ResolutionAuthority,
    /// Exact upstream definition captured with the published contract used to
    /// build this admission. Discovery consumes this copy rather than joining
    /// a separately listed definition to governance facts after an await.
    published_definition: Option<Arc<Tool>>,
    input_schema: Option<Arc<Value>>,
    /// Hash of the exact source schema when admission produced a usable
    /// validation-equivalent projection. Durable bindings use this value so a
    /// wire-only spelling change does not invalidate a paused execution.
    source_input_schema_hash: Option<String>,
    /// A schema was supplied at admission but could not be projected into the
    /// self-contained MCP input contract. This differs from a legacy manifest
    /// fallback that supplied no optional schema at all: the former must fail
    /// closed before authorization or dispatch.
    input_schema_unavailable: bool,
    output_schema: Option<Arc<Value>>,
    /// Source-schema identity paired with `output_schema`. It is absent when
    /// the optional source schema could not be admitted, which deliberately
    /// invalidates a durable binding whose output validation would disappear.
    source_output_schema_hash: Option<String>,
    tool_annotations: Option<Arc<Value>>,
    action_metadata: Option<Arc<Value>>,
    annotation_claims_enforced: bool,
    /// Whether the reviewed RETURN classification anticipated protected
    /// output. Result-release enforcement releases a `sensitive`-labelled
    /// result only when this is true — distinct from the combined `pii`
    /// fact, which also covers protected input. Always false outside
    /// annotation mode (result trust is only enforced there).
    anticipated_sensitive_output: bool,
    output_validator: Option<Arc<jsonschema::Validator>>,
    /// Argument field whose value selects the operation, when the tool is
    /// classified per operation. Resolution needs the call's arguments, which
    /// this admission-time snapshot does not see, so both travel to the
    /// invocation pipeline instead of being resolved here.
    discriminator: Option<String>,
    /// Classifications for individual discriminator values. Empty for every
    /// tool classified by name alone.
    operations: Vec<OperationClassification>,
}

/// Whether a character may appear in an operation name.
///
/// An allowlist, not a list of things to reject. The previous shape enumerated
/// Unicode format and bidirectional code points, which is a set that grows with
/// every Unicode release — the list was already missing several, and a name
/// carrying one would have reached Cedar and the audit column looking like a
/// different name. Naming what is permitted cannot fall behind that way.
///
/// Printable ASCII with no space: every character renders as one visible glyph
/// and means the same thing wherever the value is later shown — a policy, a log
/// line, an investigator's console. Whitespace is excluded because a name is
/// compared exactly and a leading or trailing space is invisible in most of
/// those places.
///
/// A set of permitted separators would have been narrower, but the operation
/// names an upstream chooses are its own, and refusing an unusual but perfectly
/// legible one is not this boundary's job. Legibility is.
fn is_admissible_in_operation(c: char) -> bool {
    c.is_ascii_graphic()
}

/// Longest discriminator value this server will carry.
///
/// Matches the bound the manifest loader enforces and the catalog column
/// accepts, so a value that survives here is one the catalog could have
/// classified. A longer one refuses the call rather than being truncated or
/// dropped: a truncated name would read as a different operation, and a dropped
/// one would leave the gate authorizing a request whose operation it never saw
/// while dispatch forwarded it unchanged.
const MAX_OPERATION_VALUE_LEN: usize = 256;

/// Classification admitted for one discriminator value of a tool.
///
/// Risk is a [`RiskTier`] rather than the catalog's string, so the resolved
/// facts need no further mapping on the call path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationClassification {
    pub value: String,
    pub risk: RiskTier,
    pub side_effects: bool,
    pub pii: bool,
}

/// What a call's arguments selected, and whether an operator had classified it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationResolution {
    /// The discriminator value the call carried. `None` when the tool names no
    /// discriminator, the argument is absent, or the argument is not a string.
    ///
    /// Present even when no entry classifies it: the audit trail records what
    /// was asked for, and for an executor the tool name alone no longer says.
    pub requested: Option<String>,
    /// Whether an entry named [`Self::requested`] and its classification became
    /// the facts the call is authorized under. `false` means the tool-level
    /// classification applied, which by the manifest ceiling is never weaker.
    pub classified: bool,
    /// The call named an operation this server will not carry — empty, longer
    /// than the catalog can store, or containing a character an operation name
    /// may not have.
    ///
    /// The call must be refused rather than authorized without it. Dispatch
    /// forwards the caller's arguments unchanged, so proceeding would let the
    /// upstream act on an operation no policy saw and no audit row names.
    pub inadmissible: bool,
}

fn admit_input_schema(schema: Option<Value>) -> (Option<Arc<Value>>, bool, Option<String>) {
    let Some(schema) = schema else {
        return (None, false, None);
    };
    let source_hash = waygate_catalog::validator_schema_hash(&schema);
    match crate::tool_schema::portable_input_schema_value(&schema) {
        Some(schema) => (Some(Arc::new(schema)), false, Some(source_hash)),
        None => (None, true, None),
    }
}

fn admit_output_schema(schema: Option<Value>) -> (Option<Arc<Value>>, Option<String>) {
    let Some(schema) = schema else {
        return (None, None);
    };
    let source_hash = waygate_catalog::validator_schema_hash(&schema);
    match crate::tool_schema::portable_schema_value(&schema) {
        Some(schema) => (Some(Arc::new(schema)), Some(source_hash)),
        None => (None, None),
    }
}

impl InvocationToolSnapshot {
    /// Admit the governed catalog identity and its immutable invocation-time
    /// schemas.
    pub fn catalog(
        facts: ToolFacts,
        tool_id: Uuid,
        schema_hash: String,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
    ) -> Self {
        Self::catalog_with_security_metadata(
            facts,
            tool_id,
            schema_hash,
            input_schema,
            output_schema,
            None,
            None,
        )
    }

    /// Admit a catalog version together with its reviewed MCP behavior claims.
    pub fn catalog_with_security_metadata(
        facts: ToolFacts,
        tool_id: Uuid,
        schema_hash: String,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
    ) -> Self {
        Self::catalog_with_metadata_mode(
            facts,
            tool_id,
            schema_hash,
            input_schema,
            output_schema,
            tool_annotations,
            action_metadata,
            false,
            false,
        )
    }

    /// Admit a catalog version whose runtime facts and result handling are
    /// derived from its reviewed MCP claims.
    #[allow(clippy::too_many_arguments)]
    pub fn catalog_with_annotation_claims(
        facts: ToolFacts,
        tool_id: Uuid,
        schema_hash: String,
        anticipated_sensitive_output: bool,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
    ) -> Self {
        Self::catalog_with_metadata_mode(
            facts,
            tool_id,
            schema_hash,
            input_schema,
            output_schema,
            tool_annotations,
            action_metadata,
            true,
            anticipated_sensitive_output,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn catalog_with_metadata_mode(
        mut facts: ToolFacts,
        tool_id: Uuid,
        schema_hash: String,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
        annotation_claims_enforced: bool,
        anticipated_sensitive_output: bool,
    ) -> Self {
        facts.requires_approval_known = true;
        let (input_schema, input_schema_unavailable, source_input_schema_hash) =
            admit_input_schema(input_schema);
        let (output_schema, source_output_schema_hash) = admit_output_schema(output_schema);
        Self {
            facts,
            authority: ResolutionAuthority::Catalog {
                tool_id,
                schema_hash,
            },
            published_definition: None,
            input_schema,
            source_input_schema_hash,
            input_schema_unavailable,
            output_schema,
            source_output_schema_hash,
            tool_annotations: tool_annotations.map(Arc::new),
            action_metadata: action_metadata.map(Arc::new),
            annotation_claims_enforced,
            anticipated_sensitive_output,
            output_validator: None,
            discriminator: None,
            operations: Vec::new(),
        }
    }

    /// Admit manifest facts when no live catalog definition is available.
    ///
    /// `approval_requirements_known` must be false when an unavailable catalog
    /// could have supplied stricter approval metadata; approval then fails
    /// closed later in the pipeline.
    pub fn manifest_fallback(facts: ToolFacts, approval_requirements_known: bool) -> Self {
        Self::manifest_fallback_with_input_schema(facts, approval_requirements_known, None)
    }

    /// Admit manifest governance facts with the input contract published by
    /// the connected upstream's cached `tools/list` snapshot.
    pub fn manifest_fallback_with_input_schema(
        facts: ToolFacts,
        approval_requirements_known: bool,
        input_schema: Option<Value>,
    ) -> Self {
        Self::manifest_fallback_with_contract(
            facts,
            approval_requirements_known,
            None,
            input_schema,
            None,
            None,
            None,
        )
    }

    /// Admit manifest governance facts with the complete behavior contract
    /// preserved from the connected upstream. `approved_behavior_hash` binds
    /// the annotation-native generation into the fallback identity; legacy
    /// manifest mode passes `None`.
    pub fn manifest_fallback_with_contract(
        facts: ToolFacts,
        approval_requirements_known: bool,
        approved_behavior_hash: Option<String>,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
    ) -> Self {
        Self::manifest_fallback_with_contract_mode(
            facts,
            approval_requirements_known,
            approved_behavior_hash,
            input_schema,
            output_schema,
            tool_annotations,
            action_metadata,
            false,
            false,
        )
    }

    /// Admit annotation-derived manifest facts while retaining a fail-closed
    /// marker for result trust enforcement.
    #[allow(clippy::too_many_arguments)]
    pub fn manifest_fallback_with_annotation_claims(
        facts: ToolFacts,
        approval_requirements_known: bool,
        approved_behavior_hash: Option<String>,
        anticipated_sensitive_output: bool,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
    ) -> Self {
        Self::manifest_fallback_with_contract_mode(
            facts,
            approval_requirements_known,
            approved_behavior_hash,
            input_schema,
            output_schema,
            tool_annotations,
            action_metadata,
            true,
            anticipated_sensitive_output,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest_fallback_with_contract_mode(
        mut facts: ToolFacts,
        approval_requirements_known: bool,
        approved_behavior_hash: Option<String>,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
        tool_annotations: Option<Value>,
        action_metadata: Option<Value>,
        annotation_claims_enforced: bool,
        anticipated_sensitive_output: bool,
    ) -> Self {
        facts.requires_approval_known = approval_requirements_known;
        let (input_schema, input_schema_unavailable, source_input_schema_hash) =
            admit_input_schema(input_schema);
        let (output_schema, source_output_schema_hash) = admit_output_schema(output_schema);
        Self {
            facts,
            authority: ResolutionAuthority::ManifestFallback {
                approval_requirements_known,
                approved_behavior_hash,
            },
            published_definition: None,
            input_schema,
            source_input_schema_hash,
            input_schema_unavailable,
            output_schema,
            source_output_schema_hash,
            tool_annotations: tool_annotations.map(Arc::new),
            action_metadata: action_metadata.map(Arc::new),
            annotation_claims_enforced,
            anticipated_sensitive_output,
            output_validator: None,
            discriminator: None,
            operations: Vec::new(),
        }
    }

    /// Build the synthetic facts used by the inference arm of the shared
    /// invocation pipeline.
    pub fn synthetic_model(mut facts: ToolFacts) -> Self {
        facts.requires_approval_known = true;
        Self {
            facts,
            authority: ResolutionAuthority::SyntheticModel,
            published_definition: None,
            input_schema: None,
            source_input_schema_hash: None,
            input_schema_unavailable: false,
            output_schema: None,
            source_output_schema_hash: None,
            tool_annotations: None,
            action_metadata: None,
            annotation_claims_enforced: false,
            anticipated_sensitive_output: false,
            output_validator: None,
            discriminator: None,
            operations: Vec::new(),
        }
    }

    /// Authorization and risk facts admitted for this invocation.
    pub fn facts(&self) -> &ToolFacts {
        &self.facts
    }

    /// Bind the exact upstream definition captured with this resolution.
    ///
    /// The definition remains optional because synthetic model admissions and
    /// static invocation-only catalogs have no MCP descriptor to publish.
    #[must_use]
    pub fn with_published_definition(mut self, definition: Option<Tool>) -> Self {
        if matches!(self.authority, ResolutionAuthority::ManifestFallback { .. }) {
            if let Some(definition) = definition.as_ref() {
                if self.input_schema.is_none() && !self.input_schema_unavailable {
                    (
                        self.input_schema,
                        self.input_schema_unavailable,
                        self.source_input_schema_hash,
                    ) = admit_input_schema(Some(Value::Object(
                        definition.input_schema.as_ref().clone(),
                    )));
                }
                if self.output_schema.is_none() {
                    (self.output_schema, self.source_output_schema_hash) = admit_output_schema(
                        definition
                            .output_schema
                            .as_ref()
                            .map(|schema| Value::Object(schema.as_ref().clone())),
                    );
                }
            }
        }
        self.published_definition = definition.map(Arc::new);
        self
    }

    /// Exact upstream definition captured with this admitted snapshot.
    pub fn published_definition(&self) -> Option<&Tool> {
        self.published_definition.as_deref()
    }

    /// Attach the per-operation classification admitted with this definition.
    ///
    /// Callers that resolve flags conservatively for their classification mode
    /// must pass operations already reconciled with the tool-level flags: this
    /// applies what it is given, and an entry weaker than the facts it replaces
    /// would lower the authorization posture of the call.
    #[must_use]
    pub fn with_operation_classifications(
        mut self,
        discriminator: Option<String>,
        operations: Vec<OperationClassification>,
    ) -> Self {
        self.discriminator = discriminator;
        self.operations = operations;
        self
    }

    /// The argument field selecting this tool's operation, when it has one.
    pub fn discriminator(&self) -> Option<&str> {
        self.discriminator.as_deref()
    }

    /// Whether this tool's authorization facts can vary with the call's
    /// arguments. `false` means [`Self::facts_for`] returns exactly
    /// [`Self::facts`] for *every* possible argument value (and
    /// [`Self::resolve_operation`] never names an operation), so a
    /// decision computed from the facts alone — before any arguments are
    /// parsed — holds for the call no matter what the body carries. The
    /// pre-parse routing-header gate relies on this to stay a strict
    /// subset of the pipeline's authorization: tools where arguments can
    /// select a narrower per-operation classification are never gated
    /// early.
    pub fn facts_vary_by_arguments(&self) -> bool {
        self.discriminator.is_some() || !self.operations.is_empty()
    }

    /// Match a call's arguments against this tool's operation entries.
    ///
    /// Every path that does not produce a classified match leaves the
    /// tool-level classification in force: no discriminator, an absent
    /// argument, an argument that is not a string, or a value no entry names.
    /// The manifest ceiling makes that fallback the conservative direction —
    /// the tool-level entry is at least as severe as every value it names.
    pub fn resolve_operation(
        &self,
        arguments: Option<&serde_json::Map<String, Value>>,
    ) -> OperationResolution {
        let Some(discriminator) = self.discriminator.as_deref() else {
            return OperationResolution::default();
        };
        let Some(requested) = arguments
            .and_then(|a| a.get(discriminator))
            .and_then(Value::as_str)
        else {
            return OperationResolution::default();
        };
        // The value is caller text that reaches a policy attribute and an audit
        // column, so what it may contain is bounded here. Dropping a bad value
        // would be worse than refusing it: dispatch forwards the arguments
        // unchanged, so the upstream would perform an operation the gate was
        // never shown and the trail never named.
        //
        // A control character is refused for a sharper reason than length.
        // PostgreSQL TEXT cannot hold a NUL, so an operation carrying one makes
        // the insert fail — and the final outcome is recorded best-effort after
        // dispatch, so the call would execute and lose its audit row. The
        // manifest loader refuses these names for the same reason.
        //
        // Empty names no operation and the audit column will not hold it.
        if requested.is_empty()
            || requested.chars().count() > MAX_OPERATION_VALUE_LEN
            || !requested.chars().all(is_admissible_in_operation)
        {
            return OperationResolution {
                classified: false,
                requested: None,
                inadmissible: true,
            };
        }
        OperationResolution {
            classified: self.operations.iter().any(|o| o.value == requested),
            requested: Some(requested.to_owned()),
            inadmissible: false,
        }
    }

    /// The facts this call is authorized under, refined when an operator has
    /// classified the operation the arguments select.
    pub fn facts_for(&self, arguments: Option<&serde_json::Map<String, Value>>) -> ToolFacts {
        let mut facts = self.facts.clone();
        let resolution = self.resolve_operation(arguments);
        if let Some(operation) = resolution
            .requested
            .as_deref()
            .filter(|_| resolution.classified)
            .and_then(|value| self.operations.iter().find(|o| o.value == value))
        {
            facts.risk = operation.risk;
            facts.side_effects = operation.side_effects;
            facts.pii = operation.pii;
        }
        facts
    }

    /// Source and version identity of the admitted definition.
    pub fn authority(&self) -> &ResolutionAuthority {
        &self.authority
    }

    /// Input schema admitted with the definition, when one exists.
    pub fn input_schema(&self) -> Option<&Value> {
        self.input_schema.as_deref()
    }

    /// Whether admission received an input contract that could not be safely
    /// published or validated as a self-contained MCP object schema.
    pub const fn input_schema_unavailable(&self) -> bool {
        self.input_schema_unavailable
    }

    /// Output schema admitted with the definition, when one exists.
    pub fn output_schema(&self) -> Option<&Value> {
        self.output_schema.as_deref()
    }

    /// Standard MCP annotations admitted with this invocation.
    pub fn tool_annotations(&self) -> Option<&Value> {
        self.tool_annotations.as_deref()
    }

    /// Namespaced action metadata admitted with this invocation.
    pub fn action_metadata(&self) -> Option<&Value> {
        self.action_metadata.as_deref()
    }

    /// Whether result trust labels are mandatory for this invocation.
    pub fn annotation_claims_enforced(&self) -> bool {
        self.annotation_claims_enforced
    }

    /// Whether the reviewed return classification anticipated protected
    /// output. Result-release enforcement releases a `sensitive`-labelled
    /// result only when this is true.
    pub fn anticipated_sensitive_output(&self) -> bool {
        self.anticipated_sensitive_output
    }

    /// Stable identity of every contract field that can affect validation,
    /// authorization, approval, inspection, or dispatch semantics.
    pub fn contract_identity(&self) -> InvocationContractIdentity {
        let facts = self.facts();
        InvocationContractIdentity {
            authority: match self.authority() {
                ResolutionAuthority::Catalog {
                    tool_id,
                    schema_hash,
                } => InvocationContractAuthority::Catalog {
                    tool_id: tool_id.to_string(),
                    catalog_schema_hash: schema_hash.clone(),
                },
                ResolutionAuthority::ManifestFallback {
                    approval_requirements_known,
                    approved_behavior_hash,
                } => InvocationContractAuthority::ManifestFallback {
                    approval_requirements_known: *approval_requirements_known,
                    approved_behavior_hash: approved_behavior_hash.clone(),
                },
                ResolutionAuthority::SyntheticModel => InvocationContractAuthority::SyntheticModel,
            },
            input_schema_hash: self.source_input_schema_hash.clone(),
            output_schema_hash: self.source_output_schema_hash.clone(),
            tool_annotations_hash: self
                .tool_annotations()
                .map(waygate_catalog::validator_schema_hash),
            action_metadata_hash: self
                .action_metadata()
                .map(waygate_catalog::validator_schema_hash),
            operations_hash: self.operations_hash(),
            risk: match facts.risk {
                RiskTier::Low => InvocationRisk::Low,
                RiskTier::Medium => InvocationRisk::Medium,
                RiskTier::High => InvocationRisk::High,
            },
            side_effects: facts.side_effects,
            pii: facts.pii,
            requires_approval: facts.requires_approval,
            requires_approval_known: facts.requires_approval_known,
        }
    }

    /// Hash over the reviewed per-operation definition, or `None` when the tool
    /// is classified by name alone.
    ///
    /// Entries are sorted so two resolutions of the same definition hash
    /// equal regardless of the order the source produced them.
    ///
    /// Public so a discovery surface can publish the same value the contract
    /// identity carries. A surface that describes a tool without it would
    /// advertise a contract weaker than the one that governs the call.
    pub fn operations_hash(&self) -> Option<String> {
        let discriminator = self.discriminator.as_deref()?;
        let mut operations: Vec<&OperationClassification> = self.operations.iter().collect();
        operations.sort_by(|a, b| a.value.cmp(&b.value));
        let entries: Vec<Value> = operations
            .into_iter()
            .map(|o| {
                serde_json::json!({
                    "value": o.value,
                    "risk": o.risk.as_str(),
                    "side_effects": o.side_effects,
                    "pii": o.pii,
                })
            })
            .collect();
        Some(waygate_catalog::validator_schema_hash(&serde_json::json!({
            "discriminator": discriminator,
            "operations": entries,
        })))
    }

    /// Validator compiled for the exact admitted catalog schema version.
    pub(crate) fn output_validator(&self) -> Option<&jsonschema::Validator> {
        self.output_validator.as_deref()
    }

    pub(crate) fn set_output_validator(&mut self, validator: Arc<jsonschema::Validator>) {
        self.output_validator = Some(validator);
    }
}

/// Outcome of [`UpstreamCatalog::resolve_invocation_tool`]: one admitted
/// snapshot, an intentional lifecycle block, or retryable catalog
/// unavailability.
#[derive(Debug, Clone)]
pub enum ResolvedInvocationTool {
    Ready(InvocationToolSnapshot),
    Quarantined { server: String, tool: String },
    Unavailable { server: String, tool: String },
}

pub type SharedCatalog = Arc<dyn UpstreamCatalog>;
