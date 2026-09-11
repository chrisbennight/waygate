//! Gateway-wide, authorization-filtered tool discovery.
//!
//! `search` returns compact records from the complete catalog and `inspect`
//! returns the exact current MCP contract. Neither operation executes another
//! tool: clients invoke the returned fully-qualified tool through ordinary
//! `tools/call`, preserving typed routing, authorization, and audit behavior.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rmcp::model::{CallToolResult, ErrorCode, JsonObject, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use waygate_oidc::session::{self, HasExp, SessionKey};

use waygate_core::RiskTier;
use waygate_mcp::{
    rank_visible_tools, AuthorizedCatalog, BuiltinCatalog, BuiltinProfileScope,
    BuiltinSurfaceDescriptor, BuiltinTools, CatalogAuthorization, CatalogChannel, CatalogTool,
    CatalogToolSource, ToolCatalogEpoch,
};
use waygate_oidc::{Principal, Scope};

use crate::mcp_builtin::{schema_obj, structured};

pub const NAMESPACE: &str = waygate_core::DISCOVERY_BUILTIN_NAMESPACE;
const DEFAULT_LIMIT: u16 = 20;
const MAX_LIMIT: u16 = 100;
const MAX_QUERY_LENGTH: usize = 256;
const MAX_CURSOR_LENGTH: usize = 1_024;
const MAX_SUMMARY_TITLE_CHARS: usize = 160;
const MAX_SUMMARY_DESCRIPTION_CHARS: usize = 480;
const CURSOR_KIND: &str = "gateway-discovery-search-v2";
const CURSOR_LIFETIME_SECONDS: i64 = 5 * 60;
const MAX_STABLE_CATALOG_READ_ATTEMPTS: usize = 3;

pub struct DiscoveryTools {
    catalog: AuthorizedCatalog,
    tool_catalog_epoch: ToolCatalogEpoch,
    cursor_sealer: Arc<DiscoveryCursorSealer>,
}

impl DiscoveryTools {
    pub fn new(catalog: AuthorizedCatalog, tool_catalog_epoch: ToolCatalogEpoch) -> Self {
        Self {
            catalog,
            tool_catalog_epoch,
            cursor_sealer: Arc::new(DiscoveryCursorSealer::process_local()),
        }
    }

    pub fn with_cursor_sealer(mut self, cursor_sealer: Arc<DiscoveryCursorSealer>) -> Self {
        self.cursor_sealer = cursor_sealer;
        self
    }

    async fn stable_visible_tools(
        &self,
        principal: &Principal,
    ) -> Result<Vec<CatalogTool>, McpError> {
        for _ in 0..MAX_STABLE_CATALOG_READ_ATTEMPTS {
            let durable_generation = self.catalog.discovery_generation().await?;
            let error_generation = self.catalog.discovery_error_generation();
            let Some(generation) = self.tool_catalog_epoch.stable_generation() else {
                tokio::task::yield_now().await;
                continue;
            };
            let visible = self
                .catalog
                .visible_tools(Some(principal), CatalogChannel::Direct, true)
                .await;
            let durable_after = self.catalog.discovery_generation().await?;
            let errors_after = self.catalog.discovery_error_generation();
            if catalog_read_is_stable(
                &self.tool_catalog_epoch,
                generation,
                durable_generation,
                durable_after,
                error_generation,
                errors_after,
            ) {
                return Ok(visible);
            }
            tokio::task::yield_now().await;
        }
        Err(catalog_changing())
    }

    async fn stable_visible_tool(
        &self,
        principal: &Principal,
        source: &CatalogToolSource,
        name: &str,
    ) -> Result<Option<CatalogTool>, McpError> {
        for _ in 0..MAX_STABLE_CATALOG_READ_ATTEMPTS {
            let durable_generation = self.catalog.discovery_generation().await?;
            let error_generation = self.catalog.discovery_error_generation();
            let Some(generation) = self.tool_catalog_epoch.stable_generation() else {
                tokio::task::yield_now().await;
                continue;
            };
            let record = self
                .catalog
                .visible_tool(Some(principal), CatalogChannel::Direct, source, name)
                .await;
            let durable_after = self.catalog.discovery_generation().await?;
            let errors_after = self.catalog.discovery_error_generation();
            if catalog_read_is_stable(
                &self.tool_catalog_epoch,
                generation,
                durable_generation,
                durable_after,
                error_generation,
                errors_after,
            ) {
                return Ok(record);
            }
            tokio::task::yield_now().await;
        }
        Err(catalog_changing())
    }

    async fn search(
        &self,
        principal: &Principal,
        params: SearchParams,
    ) -> Result<CallToolResult, McpError> {
        let query = params.query.trim();
        if query.is_empty() || query.len() > MAX_QUERY_LENGTH {
            return Err(McpError::invalid_params(
                "`query` must contain between 1 and 256 UTF-8 bytes",
                Some(json!({"error": "invalid_discovery_query"})),
            ));
        }
        if params
            .limit
            .is_some_and(|limit| limit == 0 || limit > MAX_LIMIT)
        {
            return Err(McpError::invalid_params(
                "`limit` must be between 1 and 100",
                Some(json!({"error": "invalid_discovery_limit"})),
            ));
        }
        if params
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            waygate_telemetry::metrics::record_discovery_cursor(
                waygate_telemetry::metrics::DiscoverySurface::Gateway,
                false,
            );
            return Err(invalid_cursor());
        }
        let limit = usize::from(params.limit.unwrap_or(DEFAULT_LIMIT));
        let visible = self.stable_visible_tools(principal).await?;
        let ranked = rank_visible_tools(query, visible);
        let cursor_supplied = params.cursor.is_some();
        let page = paginate_search(
            ranked,
            params.cursor.as_deref(),
            query,
            principal,
            limit,
            &self.cursor_sealer,
        );
        if cursor_supplied {
            waygate_telemetry::metrics::record_discovery_cursor(
                waygate_telemetry::metrics::DiscoverySurface::Gateway,
                page.is_ok(),
            );
        }
        let (ranked, next_cursor) = page?;
        Ok(structured(&SearchResponse {
            tools: ranked.into_iter().map(ToolSummary::from_tool).collect(),
            next_cursor,
        }))
    }

    async fn inspect(
        &self,
        principal: &Principal,
        params: InspectParams,
    ) -> Result<CallToolResult, McpError> {
        validate_selector(&params.source, "source")?;
        validate_selector(&params.name, "name")?;
        let source = match params.source_kind {
            SourceKind::Upstream => CatalogToolSource::Upstream(params.source),
            SourceKind::Builtin => CatalogToolSource::Builtin(params.source),
        };
        let record = self
            .stable_visible_tool(principal, &source, &params.name)
            .await?;
        let Some(record) = record else {
            return Err(unavailable_tool());
        };
        Ok(structured(&InspectResponse::from_tool(record)))
    }
}

pub(crate) fn catalog_read_is_stable(
    epoch: &ToolCatalogEpoch,
    local_generation: u64,
    durable_before: Option<i64>,
    durable_after: Option<i64>,
    errors_before: u64,
    errors_after: u64,
) -> bool {
    durable_before == durable_after
        && errors_before == errors_after
        && epoch.is_stable(local_generation)
}

/// Authenticated protection for gateway-owned discovery continuations.
///
/// Cursors carry no authority: every page rebuilds the caller's authorized
/// view before this sealer is consulted. Authentication keeps the server-
/// selected position and expiry opaque, while the claims bind that position
/// to the exact principal, query, and ranked catalog generation.
#[derive(Clone)]
pub(crate) struct DiscoveryCursorSealer {
    key: SessionKey,
}

impl DiscoveryCursorSealer {
    pub(crate) fn new(key: SessionKey) -> Self {
        Self { key }
    }

    pub(crate) fn process_local() -> Self {
        let key = SessionKey::from_encoded(&waygate_oidc::new_random_token())
            .expect("a generated 32-byte token is a valid session key");
        Self::new(key)
    }

    fn seal(&self, claims: &DiscoveryCursorClaims) -> Result<String, McpError> {
        self.seal_claims(claims)
            .map_err(|_| cursor_encoding_error())
    }

    fn open(&self, cursor: &str) -> Result<DiscoveryCursorClaims, McpError> {
        if cursor.len() > MAX_CURSOR_LENGTH {
            return Err(invalid_cursor());
        }
        self.open_claims(cursor).map_err(|_| invalid_cursor())
    }

    pub(crate) fn seal_claims<T: Serialize>(
        &self,
        claims: &T,
    ) -> Result<String, session::SessionError> {
        session::encrypt(&self.key, claims)
    }

    pub(crate) fn open_claims<T>(&self, cursor: &str) -> Result<T, session::SessionError>
    where
        T: for<'de> Deserialize<'de> + HasExp,
    {
        session::decrypt(&self.key, cursor)
    }
}

#[derive(Serialize, Deserialize)]
struct DiscoveryCursorClaims {
    kind: String,
    exp: i64,
    offset: u64,
    principal: String,
    query: String,
    view: String,
}

impl HasExp for DiscoveryCursorClaims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

#[async_trait]
impl BuiltinTools for DiscoveryTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    fn profile_scope(&self) -> BuiltinProfileScope {
        BuiltinProfileScope::DelegatedDataPlane
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        if principal.is_some_and(may_discover) {
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
        let principal = principal
            .filter(|principal| may_discover(principal))
            .ok_or_else(insufficient_scope)?;
        let arguments = arguments.unwrap_or_default();
        match tool {
            "search" => {
                let started = Instant::now();
                let result = match parse(arguments) {
                    Ok(params) => self.search(principal, params).await,
                    Err(error) => Err(error),
                };
                record_operation(
                    waygate_telemetry::metrics::DiscoveryOperation::GatewaySearch,
                    &result,
                    started,
                );
                result
            }
            "inspect" => {
                let started = Instant::now();
                let result = match parse(arguments) {
                    Ok(params) => self.inspect(principal, params).await,
                    Err(error) => Err(error),
                };
                record_operation(
                    waygate_telemetry::metrics::DiscoveryOperation::GatewayInspect,
                    &result,
                    started,
                );
                result
            }
            other => Err(McpError::invalid_params(
                format!("unknown {NAMESPACE} tool: {other}"),
                None,
            )),
        }
    }
}

fn record_operation(
    operation: waygate_telemetry::metrics::DiscoveryOperation,
    result: &Result<CallToolResult, McpError>,
    started: Instant,
) {
    use waygate_telemetry::metrics::DiscoveryOutcome;

    let outcome = match result {
        Ok(_) => DiscoveryOutcome::Ok,
        Err(error) => match error
            .data
            .as_ref()
            .and_then(|data| data.get("error"))
            .and_then(Value::as_str)
        {
            Some("tool_unavailable" | "catalog_changing" | "catalog_unavailable") => {
                DiscoveryOutcome::Unavailable
            }
            Some(
                "invalid_discovery_arguments"
                | "invalid_discovery_query"
                | "invalid_discovery_limit"
                | "invalid_discovery_cursor"
                | "invalid_discovery_selector",
            ) => DiscoveryOutcome::Invalid,
            _ => DiscoveryOutcome::Error,
        },
    };
    waygate_telemetry::metrics::record_discovery_operation(
        operation,
        outcome,
        started.elapsed().as_secs_f64(),
    );
}

fn may_discover(principal: &Principal) -> bool {
    principal.has_scope(Scope::McpRead.as_str()) || principal.has_scope(Scope::McpAdmin.as_str())
}

fn parse<T: for<'de> Deserialize<'de>>(arguments: JsonObject) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(arguments)).map_err(|error| {
        McpError::invalid_params(
            format!("invalid discovery arguments: {error}"),
            Some(json!({"error": "invalid_discovery_arguments"})),
        )
    })
}

fn validate_selector(value: &str, field: &str) -> Result<(), McpError> {
    if value.is_empty() {
        return Err(McpError::invalid_params(
            format!("`{field}` must not be empty"),
            Some(json!({"error": "invalid_discovery_selector", "field": field})),
        ));
    }
    Ok(())
}

fn insufficient_scope() -> McpError {
    McpError::new(
        ErrorCode::INVALID_REQUEST,
        "gateway discovery requires the mcp:read or mcp:admin scope",
        Some(json!({
            "error": "insufficient_scope",
            "required_scope": Scope::McpRead.as_str(),
        })),
    )
}

pub(crate) fn catalog_changing() -> McpError {
    McpError::internal_error(
        "the governed tool catalog changed during discovery; retry the request",
        Some(json!({"error": "catalog_changing", "retryable": true})),
    )
}

fn unavailable_tool() -> McpError {
    McpError::invalid_params(
        "tool is unavailable",
        Some(json!({"error": "tool_unavailable"})),
    )
}

fn invalid_cursor() -> McpError {
    McpError::invalid_params(
        "discovery cursor is no longer present; restart the search",
        Some(json!({"error": "invalid_discovery_cursor"})),
    )
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchParams {
    /// Natural-language or keyword query. Names, source names, titles, and
    /// descriptions participate in lexical relevance.
    query: String,
    /// Maximum number of compact results to return.
    #[serde(default)]
    limit: Option<u16>,
    /// Opaque continuation returned by the prior page for the same query.
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    /// Tool advertised by a configured upstream MCP server.
    Upstream,
    /// Tool implemented by the gateway in a reserved local namespace.
    Builtin,
}

impl From<&CatalogToolSource> for SourceKind {
    fn from(source: &CatalogToolSource) -> Self {
        match source {
            CatalogToolSource::Upstream(_) => Self::Upstream,
            CatalogToolSource::Builtin(_) => Self::Builtin,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct InspectParams {
    /// Whether the source is an upstream MCP server or a gateway-local surface.
    source_kind: SourceKind,
    /// Exact server name or built-in namespace returned by `search`.
    source: String,
    /// Exact bare tool name returned by `search`.
    name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct SearchResponse {
    /// Compact authorized results. Exact schemas are available through
    /// `gateway-discovery.inspect` only.
    tools: Vec<ToolSummary>,
    /// Continuation for the next page, absent on the final page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ToolSummary {
    /// Fully-qualified name to invoke through ordinary MCP `tools/call`.
    name: String,
    /// Whether `source` names an upstream server or gateway-local namespace.
    source_kind: SourceKind,
    /// Exact upstream server or gateway-local namespace.
    source: String,
    /// Exact bare tool name within the source.
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Gateway-owned safety facts bound to this catalog record.
    governance: Governance,
}

impl ToolSummary {
    fn from_tool(tool: CatalogTool) -> Self {
        let governance = Governance::from_tool(&tool);
        Self {
            name: tool.identity.qualified_name(),
            source_kind: SourceKind::from(&tool.identity.source),
            source: tool.identity.source.name().to_owned(),
            tool: tool.identity.name,
            title: compact_optional(tool.definition.title.as_deref(), MAX_SUMMARY_TITLE_CHARS),
            description: compact_optional(
                tool.definition.description.as_deref(),
                MAX_SUMMARY_DESCRIPTION_CHARS,
            ),
            governance,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct InspectResponse {
    /// Structured identity of the exact inspected catalog record.
    identity: ToolIdentity,
    /// Exact current MCP tool definition, including input/output schemas,
    /// annotations, title, description, and metadata.
    definition: Value,
    /// Gateway-owned safety facts bound to this exact definition.
    governance: Governance,
}

impl InspectResponse {
    fn from_tool(tool: CatalogTool) -> Self {
        let governance = Governance::from_tool(&tool);
        Self {
            identity: ToolIdentity {
                name: tool.identity.qualified_name(),
                source_kind: SourceKind::from(&tool.identity.source),
                source: tool.identity.source.name().to_owned(),
                tool: tool.identity.name,
            },
            definition: serde_json::to_value(&tool.definition)
                .expect("rmcp tool definitions are serializable"),
            governance,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct ToolIdentity {
    /// Fully-qualified downstream MCP tool name.
    name: String,
    /// Whether `source` names an upstream server or gateway-local namespace.
    source_kind: SourceKind,
    /// Exact upstream server or gateway-local namespace.
    source: String,
    /// Exact bare tool name within the source.
    tool: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct Governance {
    /// Gateway risk tier (`low`, `medium`, or `high`).
    risk: String,
    /// Whether the operation can change external or durable state.
    side_effects: bool,
    /// Whether the operation can handle or return personally identifiable data.
    pii: bool,
    /// Whether a live per-call approval is required before invocation.
    requires_approval: bool,
    /// Whether the catalog's approval classification is authoritative. False
    /// tells clients not to infer that approval is unnecessary.
    requires_approval_known: bool,
    /// Scope required to make the tool callable when current policy requires
    /// step-up authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    required_step_up_scope: Option<String>,
}

impl Governance {
    fn from_tool(tool: &CatalogTool) -> Self {
        let approval_required =
            matches!(tool.authorization, CatalogAuthorization::ApprovalRequired);
        let required_step_up_scope = match &tool.authorization {
            CatalogAuthorization::StepUpRequired { required_scope } => Some(required_scope.clone()),
            CatalogAuthorization::Allowed | CatalogAuthorization::ApprovalRequired => None,
        };
        Self {
            risk: tool.facts.risk.as_str().to_owned(),
            side_effects: tool.facts.side_effects,
            pii: tool.facts.pii,
            requires_approval: approval_required || tool.facts.requires_approval,
            requires_approval_known: approval_required || tool.facts.requires_approval_known,
            required_step_up_scope,
        }
    }
}

fn paginate_search(
    ranked: Vec<CatalogTool>,
    cursor: Option<&str>,
    query: &str,
    principal: &Principal,
    limit: usize,
    sealer: &DiscoveryCursorSealer,
) -> Result<(Vec<CatalogTool>, Option<String>), McpError> {
    paginate_search_at(
        ranked,
        cursor,
        query,
        principal,
        limit,
        OffsetDateTime::now_utc().unix_timestamp(),
        sealer,
    )
}

fn paginate_search_at(
    ranked: Vec<CatalogTool>,
    cursor: Option<&str>,
    query: &str,
    principal: &Principal,
    limit: usize,
    now: i64,
    sealer: &DiscoveryCursorSealer,
) -> Result<(Vec<CatalogTool>, Option<String>), McpError> {
    debug_assert!(limit > 0);
    let principal = principal_binding(principal)?;
    let query = digest_field(b"gateway-discovery-query-v2\0", query.as_bytes());
    let view = search_view_binding(&ranked)?;
    let start = match cursor {
        None => 0,
        Some(cursor) => {
            let claims = sealer.open(cursor)?;
            let offset = usize::try_from(claims.offset).map_err(|_| invalid_cursor())?;
            if claims.kind != CURSOR_KIND
                || claims.principal != principal
                || claims.query != query
                || claims.view != view
                || offset == 0
                || offset >= ranked.len()
            {
                return Err(invalid_cursor());
            }
            offset
        }
    };
    let end = start.saturating_add(limit).min(ranked.len());
    let has_more = end < ranked.len();
    let page = ranked.into_iter().skip(start).take(end - start).collect();
    let next_cursor = has_more
        .then(|| {
            let offset = u64::try_from(end).map_err(|_| cursor_encoding_error())?;
            sealer.seal(&DiscoveryCursorClaims {
                kind: CURSOR_KIND.to_owned(),
                exp: now.saturating_add(CURSOR_LIFETIME_SECONDS),
                offset,
                principal,
                query,
                view,
            })
        })
        .transpose()?;
    Ok((page, next_cursor))
}

pub(crate) fn principal_binding(principal: &Principal) -> Result<String, McpError> {
    let mut hasher = Sha256::new();
    hasher.update(b"gateway-discovery-principal-v2\0");
    serde_json::to_writer(HashWriter(&mut hasher), principal)
        .map_err(|_| cursor_encoding_error())?;
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(crate) fn search_view_binding(ranked: &[CatalogTool]) -> Result<String, McpError> {
    let mut hasher = Sha256::new();
    hasher.update(b"gateway-discovery-view-v3\0");
    let result_count = u64::try_from(ranked.len()).map_err(|_| cursor_encoding_error())?;
    hash_field(&mut hasher, &result_count.to_be_bytes());
    for tool in ranked {
        serde_json::to_writer(HashWriter(&mut hasher), &tool.identity)
            .map_err(|_| cursor_encoding_error())?;
        serde_json::to_writer(HashWriter(&mut hasher), &tool.definition)
            .map_err(|_| cursor_encoding_error())?;
        hash_field(&mut hasher, tool.facts.risk.as_str().as_bytes());
        hash_field(&mut hasher, &[u8::from(tool.facts.side_effects)]);
        hash_field(&mut hasher, &[u8::from(tool.facts.pii)]);
        hash_field(&mut hasher, &[u8::from(tool.facts.requires_approval)]);
        hash_field(&mut hasher, &[u8::from(tool.facts.requires_approval_known)]);
        match tool.invocation_snapshot() {
            Some(snapshot) => {
                hash_field(&mut hasher, b"invocation_contract");
                serde_json::to_writer(HashWriter(&mut hasher), &snapshot.contract_identity())
                    .map_err(|_| cursor_encoding_error())?;
            }
            None => {
                hash_field(&mut hasher, b"no_invocation_contract");
            }
        }
        match &tool.authorization {
            CatalogAuthorization::Allowed => hash_field(&mut hasher, b"allowed"),
            CatalogAuthorization::ApprovalRequired => hash_field(&mut hasher, b"approval_required"),
            CatalogAuthorization::StepUpRequired { required_scope } => {
                hash_field(&mut hasher, b"step_up_required");
                hash_field(&mut hasher, required_scope.as_bytes());
            }
        }
    }
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

pub(crate) fn digest_field(domain: &[u8], value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_field(&mut hasher, value);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("in-memory field length fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

struct HashWriter<'a>(&'a mut Sha256);

impl io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn cursor_encoding_error() -> McpError {
    McpError::internal_error(
        "discovery continuation could not be encoded",
        Some(json!({"error": "discovery_cursor_encoding_failed"})),
    )
}

fn compact_optional(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|value| value.chars().take(max_chars).collect())
}

fn input_schema<T: JsonSchema>() -> Arc<JsonObject> {
    schema_obj(serde_json::to_value(schema_for!(T)).expect("schema is serializable"))
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let tools = tool_defs()
        .into_iter()
        .map(|tool| CatalogTool::builtin(NAMESPACE, tool, RiskTier::Low, false, false))
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        Scope::McpRead.as_str(),
        "Authorization-filtered search and exact inspection across upstream and gateway-local MCP tools.",
        tools,
    )
}

pub(crate) fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(
            format!("{NAMESPACE}.search"),
            "Search every currently admitted upstream and gateway-local MCP tool without knowing its source first. Authorization and credential-profile restrictions are applied before lexical ranking, so hidden tools cannot affect hits or pagination. Results are compact and omit schemas; pass the returned structured source identity to `gateway-discovery.inspect` for the exact contract, then invoke the returned fully-qualified name through ordinary `tools/call`.",
            input_schema::<SearchParams>(),
        )
        .with_title("Search the governed tool catalog")
        .with_output_schema::<SearchResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
        Tool::new(
            format!("{NAMESPACE}.inspect"),
            "Return the exact current MCP definition and gateway governance facts for one tool selected by the structured `source_kind`, `source`, and bare `name` returned by `gateway-discovery.search`. Denied, quarantined, stale, and unknown selectors all return the same unavailable shape. This tool never executes the inspected operation; call its fully-qualified identity through ordinary `tools/call` so the original typed authorization and audit path remains authoritative.",
            input_schema::<InspectParams>(),
        )
        .with_title("Inspect an exact governed tool contract")
        .with_output_schema::<InspectResponse>()
        .annotate(ToolAnnotations::new().read_only(true).destructive(false)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::RwLock;

    use waygate_mcp::catalog::{InvocationToolSnapshot, ResolvedInvocationTool};
    use waygate_mcp::{AuthzGate, AuthzVerdict, BuiltinRegistry, ToolFacts, UpstreamCatalog};

    fn principal() -> Principal {
        Principal {
            sub: "reader".to_owned(),
            email: None,
            groups: vec!["operators".to_owned()],
            issuer: "https://issuer.example".to_owned(),
            scopes: vec![Scope::McpRead.as_str().to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: Some("credential-one".to_owned()),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: vec!["reader".to_owned()],
        }
    }

    type PublishedSnapshot = BTreeMap<String, Vec<(Tool, ToolFacts)>>;

    struct PublishedCatalog {
        tools: RwLock<PublishedSnapshot>,
        generation: AtomicI64,
        epoch: ToolCatalogEpoch,
    }

    impl PublishedCatalog {
        fn new(tools: PublishedSnapshot, epoch: ToolCatalogEpoch) -> Self {
            Self {
                tools: RwLock::new(tools),
                generation: AtomicI64::new(1),
                epoch,
            }
        }

        fn publish(&self, tools: PublishedSnapshot) {
            let change = self.epoch.begin_change();
            *self.tools.write().expect("published catalog poisoned") = tools;
            self.generation.fetch_add(1, Ordering::AcqRel);
            change.commit();
        }
    }

    #[async_trait]
    impl UpstreamCatalog for PublishedCatalog {
        async fn list_servers(&self) -> Vec<String> {
            self.tools
                .read()
                .expect("published catalog poisoned")
                .keys()
                .cloned()
                .collect()
        }

        async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
            self.tools
                .read()
                .expect("published catalog poisoned")
                .get(server)
                .map(|tools| {
                    tools
                        .iter()
                        .map(|(definition, _)| definition.clone())
                        .collect()
                })
                .ok_or_else(|| McpError::invalid_params("unknown test upstream", None))
        }

        async fn discovery_generation(&self) -> Result<Option<i64>, McpError> {
            Ok(Some(self.generation.load(Ordering::Acquire)))
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&waygate_mcp::catalog::InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("discovery evaluation never dispatches")
        }

        async fn resolve_discovery_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> ResolvedInvocationTool {
            let resolved = self
                .tools
                .read()
                .expect("published catalog poisoned")
                .get(server)
                .and_then(|tools| {
                    tools
                        .iter()
                        .find(|(definition, _)| definition.name == tool_name)
                })
                .cloned();
            match resolved {
                Some((definition, facts)) => ResolvedInvocationTool::Ready(
                    InvocationToolSnapshot::manifest_fallback(facts, true)
                        .with_published_definition(Some(definition)),
                ),
                None => ResolvedInvocationTool::Unavailable {
                    server: server.to_owned(),
                    tool: tool_name.to_owned(),
                },
            }
        }
    }

    struct DenyRefund;

    #[async_trait]
    impl AuthzGate for DenyRefund {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
            if facts.resource.server == "payments" && facts.resource.tool == "refund_charge" {
                AuthzVerdict::Deny {
                    reason: "refunds are not visible to this principal".to_owned(),
                    policy_ids: vec!["deny-refunds".to_owned()],
                    reasons: vec!["deny-refunds".to_owned()],
                }
            } else {
                AuthzVerdict::Allow {
                    policy_ids: Vec::new(),
                }
            }
        }
    }

    fn published_tool(server: &str, name: &str, description: &str) -> (Tool, ToolFacts) {
        (
            Tool::new(
                name.to_owned(),
                description.to_owned(),
                schema_obj(json!({
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"]
                })),
            ),
            ToolFacts {
                server: server.to_owned(),
                name: name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
        )
    }

    fn published_snapshot(inventory_description: Option<&str>) -> PublishedSnapshot {
        let mut snapshot = BTreeMap::from([
            (
                "github".to_owned(),
                vec![published_tool(
                    "github",
                    "create_issue",
                    "Create a tracked repository issue with a title and body.",
                )],
            ),
            (
                "kagi".to_owned(),
                vec![published_tool(
                    "kagi",
                    "kagi_search_fetch",
                    "Find web sources for a natural-language query.",
                )],
            ),
            (
                "payments".to_owned(),
                vec![published_tool(
                    "payments",
                    "refund_charge",
                    "Refund a customer payment charge.",
                )],
            ),
        ]);
        if let Some(description) = inventory_description {
            snapshot.insert(
                "inventory".to_owned(),
                vec![published_tool("inventory", "lookup", description)],
            );
        }
        snapshot
    }

    #[tokio::test]
    async fn production_discovery_proves_authorization_inspection_and_published_lifecycle() {
        let epoch = ToolCatalogEpoch::new();
        let catalog = Arc::new(PublishedCatalog::new(
            published_snapshot(None),
            epoch.clone(),
        ));
        let discovery = DiscoveryTools::new(
            AuthorizedCatalog::new(
                catalog.clone(),
                Arc::new(DenyRefund),
                BuiltinRegistry::default(),
            ),
            epoch.clone(),
        );

        let denied = discovery
            .search(
                &principal(),
                SearchParams {
                    query: "refund customer charge".to_owned(),
                    limit: Some(100),
                    cursor: None,
                },
            )
            .await
            .expect("authorized search");
        let denied = denied.structured_content.expect("structured search");
        assert!(denied["tools"]
            .as_array()
            .expect("search tools")
            .iter()
            .all(|tool| tool["name"] != "payments.refund_charge"));

        let denied_inspection = discovery
            .inspect(
                &principal(),
                InspectParams {
                    source_kind: SourceKind::Upstream,
                    source: "payments".to_owned(),
                    name: "refund_charge".to_owned(),
                },
            )
            .await
            .expect_err("denied tool must be unavailable");
        assert_eq!(
            denied_inspection
                .data
                .as_ref()
                .and_then(|data| data["error"].as_str()),
            Some("tool_unavailable")
        );

        let inspected = discovery
            .inspect(
                &principal(),
                InspectParams {
                    source_kind: SourceKind::Upstream,
                    source: "github".to_owned(),
                    name: "create_issue".to_owned(),
                },
            )
            .await
            .expect("exact inspection")
            .structured_content
            .expect("structured inspection");
        assert_eq!(inspected["identity"]["name"], "github.create_issue");
        assert_eq!(inspected["definition"]["name"], "github.create_issue");
        assert_eq!(
            inspected["definition"]["description"],
            "Create a tracked repository issue with a title and body."
        );

        catalog.publish(published_snapshot(Some(
            "Look up product availability by identifier.",
        )));
        let added = discovery
            .search(
                &principal(),
                SearchParams {
                    query: "product availability".to_owned(),
                    limit: Some(100),
                    cursor: None,
                },
            )
            .await
            .expect("search after add")
            .structured_content
            .expect("structured search after add");
        assert!(added["tools"]
            .as_array()
            .expect("added search tools")
            .iter()
            .any(|tool| tool["name"] == "inventory.lookup"));

        catalog.publish(published_snapshot(Some(
            "Search warehouse stock and inventory availability by identifier.",
        )));
        let changed = discovery
            .inspect(
                &principal(),
                InspectParams {
                    source_kind: SourceKind::Upstream,
                    source: "inventory".to_owned(),
                    name: "lookup".to_owned(),
                },
            )
            .await
            .expect("inspect after change")
            .structured_content
            .expect("structured inspection after change");
        assert_eq!(
            changed["definition"]["description"],
            "Search warehouse stock and inventory availability by identifier."
        );

        catalog.publish(published_snapshot(None));
        let removed = discovery
            .inspect(
                &principal(),
                InspectParams {
                    source_kind: SourceKind::Upstream,
                    source: "inventory".to_owned(),
                    name: "lookup".to_owned(),
                },
            )
            .await
            .expect_err("removed tool must be unavailable");
        assert_eq!(
            removed
                .data
                .as_ref()
                .and_then(|data| data["error"].as_str()),
            Some("tool_unavailable")
        );
        assert_eq!(epoch.current(), 3);
    }

    #[test]
    fn durable_generation_fences_a_remote_catalog_commit() {
        let epoch = ToolCatalogEpoch::new();
        let local_generation = epoch.stable_generation().expect("stable local epoch");

        assert!(catalog_read_is_stable(
            &epoch,
            local_generation,
            Some(41),
            Some(41),
            7,
            7,
        ));
        assert!(
            !catalog_read_is_stable(&epoch, local_generation, Some(41), Some(42), 7, 7),
            "a remote durable commit must reject a projection before its doorbell advances the local epoch",
        );
        assert!(
            !catalog_read_is_stable(&epoch, local_generation, Some(41), Some(41), 7, 8),
            "an authoritative per-tool read failure must reject an incomplete projection",
        );
    }

    fn record(source: &str, name: &str, description: &str) -> CatalogTool {
        CatalogTool::builtin(
            source,
            Tool::new(
                format!("{source}.{name}"),
                description.to_owned(),
                schema_obj(json!({"type": "object"})),
            ),
            RiskTier::Low,
            false,
            false,
        )
    }

    #[test]
    fn ranking_is_deterministic_and_uses_structured_identity_for_ties() {
        let make = |source: &str, name: &str| {
            CatalogTool::builtin(
                source,
                Tool::new(
                    format!("{source}.{name}"),
                    "search documents",
                    schema_obj(json!({"type": "object"})),
                ),
                RiskTier::Low,
                false,
                false,
            )
        };
        let first = rank_visible_tools(
            "search documents",
            vec![make("gateway-z", "find"), make("gateway-a", "find")],
        );
        assert_eq!(first[0].identity.source.name(), "gateway-a");
        assert_eq!(first[1].identity.source.name(), "gateway-z");
    }

    #[test]
    fn search_surface_is_compact_and_inspect_carries_exact_contract() {
        let definitions = tool_defs();
        let search = definitions
            .iter()
            .find(|tool| tool.name == "gateway-discovery.search")
            .unwrap();
        let inspect = definitions
            .iter()
            .find(|tool| tool.name == "gateway-discovery.inspect")
            .unwrap();
        let search_output = search.output_schema.as_ref().unwrap();
        let inspect_output = inspect.output_schema.as_ref().unwrap();
        assert!(!serde_json::to_string(search_output.as_ref())
            .unwrap()
            .contains("input_schema"));
        assert!(serde_json::to_string(inspect_output.as_ref())
            .unwrap()
            .contains("definition"));
    }

    #[test]
    fn inspect_serializes_the_same_portable_contract_as_other_catalog_surfaces() {
        let input = schema_obj(json!({
            "type": "object",
            "properties": {
                "anything": true,
                "nullable": {"type": ["string", "null"]}
            }
        }));
        let output = schema_obj(json!({
            "type": "object",
            "properties": {"data": {"description": "free-form payload"}}
        }));
        let upstream = Tool::new("query", "description", input).with_raw_output_schema(output);
        let record = CatalogTool::upstream(
            "remote",
            &upstream,
            waygate_mcp::ToolFacts {
                server: "remote".to_owned(),
                name: "query".to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
        )
        .expect("self-contained upstream schema is publishable");

        let definition = InspectResponse::from_tool(record).definition;
        assert!(waygate_mcp::tool_schema::inspector_portable_schema(
            &definition["inputSchema"]
        ));
        assert!(waygate_mcp::tool_schema::inspector_portable_schema(
            &definition["outputSchema"]
        ));
    }

    #[test]
    fn search_cursor_is_fixed_size_authenticated_and_bound_to_its_query() {
        let sealer = DiscoveryCursorSealer::process_local();
        let ranked = vec![
            record("gateway-test", "mail", "search mail"),
            record("gateway-test", &"tool".repeat(4_096), "search archives"),
        ];
        let (_, cursor) = paginate_search_at(
            ranked.clone(),
            None,
            "mail",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .expect("first page");
        let cursor = cursor.expect("another page exists");

        assert!(cursor.len() < MAX_CURSOR_LENGTH);
        assert!(paginate_search_at(
            ranked.clone(),
            Some(&cursor),
            "calendar",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());

        let mut tampered = cursor.into_bytes();
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(paginate_search_at(
            ranked,
            Some(&tampered),
            "mail",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());
    }

    #[test]
    fn search_cursor_rejects_catalog_definition_and_governance_changes() {
        let sealer = DiscoveryCursorSealer::process_local();
        let before = vec![
            record("gateway-test", "first", "search mail"),
            record("gateway-test", "second", "search archives"),
        ];
        let (_, cursor) = paginate_search_at(
            before.clone(),
            None,
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .expect("first page");
        let cursor = cursor.expect("another page exists");

        let mut definition_changed = before.clone();
        definition_changed[1].definition.description = Some("search changed archives".into());
        assert!(paginate_search_at(
            definition_changed,
            Some(&cursor),
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());

        let mut governance_changed = before;
        governance_changed[1].authorization = CatalogAuthorization::StepUpRequired {
            required_scope: "mcp:elevated".to_owned(),
        };
        assert!(paginate_search_at(
            governance_changed,
            Some(&cursor),
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());
    }

    #[test]
    fn search_cursor_survives_reordering_but_rejects_membership_changes() {
        let sealer = DiscoveryCursorSealer::process_local();
        let visible = vec![
            record("gateway-test", "first", "search tools"),
            record("gateway-test", "second", "search tools"),
            record("gateway-test", "third", "search tools"),
        ];
        let ranked = rank_visible_tools("search", visible.clone());
        let (_, cursor) = paginate_search_at(
            ranked,
            None,
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .expect("first page");
        let cursor = cursor.expect("another page exists");

        let reordered = rank_visible_tools(
            "search",
            vec![visible[2].clone(), visible[0].clone(), visible[1].clone()],
        );
        assert!(paginate_search_at(
            reordered,
            Some(&cursor),
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_ok());

        let mut added = visible.clone();
        added.push(record("gateway-test", "fourth", "search tools"));
        assert!(paginate_search_at(
            rank_visible_tools("search", added),
            Some(&cursor),
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());

        assert!(paginate_search_at(
            rank_visible_tools("search", visible.into_iter().take(2).collect()),
            Some(&cursor),
            "search",
            &principal(),
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());
    }

    #[test]
    fn search_cursor_binds_authorization_claims_but_not_raw_credentials() {
        let sealer = DiscoveryCursorSealer::process_local();
        let ranked = vec![
            record("gateway-test", "first", "search mail"),
            record("gateway-test", "second", "search archives"),
        ];
        let original = principal();
        let (_, cursor) = paginate_search_at(
            ranked.clone(),
            None,
            "search",
            &original,
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .expect("first page");
        let cursor = cursor.expect("another page exists");

        let mut rotated = original.clone();
        rotated.raw_token = Some("credential-two".to_owned());
        assert!(paginate_search_at(
            ranked.clone(),
            Some(&cursor),
            "search",
            &rotated,
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_ok());

        let mut reduced = original;
        reduced.groups.clear();
        assert!(paginate_search_at(
            ranked,
            Some(&cursor),
            "search",
            &reduced,
            1,
            OffsetDateTime::now_utc().unix_timestamp(),
            &sealer,
        )
        .is_err());
    }

    #[test]
    fn expired_search_cursor_is_invalid() {
        let sealer = DiscoveryCursorSealer::process_local();
        let cursor = sealer
            .seal(&DiscoveryCursorClaims {
                kind: CURSOR_KIND.to_owned(),
                exp: 0,
                offset: 1,
                principal: "principal".to_owned(),
                query: "query".to_owned(),
                view: "view".to_owned(),
            })
            .expect("seal expired fixture");
        assert!(sealer.open(&cursor).is_err());
    }

    #[test]
    fn compact_summary_bounds_prose_without_truncating_identity() {
        let long_description = "word ".repeat(MAX_SUMMARY_DESCRIPTION_CHARS * 2);
        let long_name = "n".repeat(MAX_QUERY_LENGTH * 2);
        let record = CatalogTool::builtin(
            "gateway-test",
            Tool::new(
                format!("gateway-test.{long_name}"),
                long_description,
                schema_obj(json!({"type": "object"})),
            )
            .with_title("t".repeat(MAX_SUMMARY_TITLE_CHARS * 2)),
            RiskTier::Low,
            false,
            false,
        );

        let summary = ToolSummary::from_tool(record);
        assert_eq!(summary.tool, long_name);
        assert_eq!(
            summary.title.unwrap().chars().count(),
            MAX_SUMMARY_TITLE_CHARS
        );
        assert_eq!(
            summary.description.unwrap().chars().count(),
            MAX_SUMMARY_DESCRIPTION_CHARS
        );
        assert!(validate_selector(&summary.tool, "name").is_ok());
    }

    #[test]
    fn governance_projects_live_approval_and_step_up_requirements() {
        let mut approval = CatalogTool::builtin(
            "gateway-test",
            Tool::new(
                "gateway-test.approve",
                "description",
                schema_obj(json!({"type": "object"})),
            ),
            RiskTier::Low,
            false,
            false,
        );
        approval.authorization = CatalogAuthorization::ApprovalRequired;
        let projected = Governance::from_tool(&approval);
        assert!(projected.requires_approval);
        assert!(projected.requires_approval_known);

        approval.authorization = CatalogAuthorization::StepUpRequired {
            required_scope: "mcp:elevated".to_owned(),
        };
        let projected = Governance::from_tool(&approval);
        assert_eq!(
            projected.required_step_up_scope.as_deref(),
            Some("mcp:elevated")
        );
    }

    #[test]
    fn advertised_output_schemas_validate_representative_results() {
        let samples = [
            (
                "gateway-discovery.search",
                serde_json::to_value(SearchResponse {
                    tools: vec![ToolSummary {
                        name: "kagi.search".to_owned(),
                        source_kind: SourceKind::Upstream,
                        source: "kagi".to_owned(),
                        tool: "search".to_owned(),
                        title: Some("Search the web".to_owned()),
                        description: Some("Find relevant web pages".to_owned()),
                        governance: Governance {
                            risk: "low".to_owned(),
                            side_effects: false,
                            pii: false,
                            requires_approval: false,
                            requires_approval_known: true,
                            required_step_up_scope: None,
                        },
                    }],
                    next_cursor: Some("opaque".to_owned()),
                })
                .unwrap(),
            ),
            (
                "gateway-discovery.inspect",
                serde_json::to_value(InspectResponse {
                    identity: ToolIdentity {
                        name: "gateway-observe.query_audit".to_owned(),
                        source_kind: SourceKind::Builtin,
                        source: "gateway-observe".to_owned(),
                        tool: "query_audit".to_owned(),
                    },
                    definition: json!({
                        "name": "gateway-observe.query_audit",
                        "inputSchema": {"type": "object"}
                    }),
                    governance: Governance {
                        risk: "low".to_owned(),
                        side_effects: false,
                        pii: true,
                        requires_approval: false,
                        requires_approval_known: true,
                        required_step_up_scope: None,
                    },
                })
                .unwrap(),
            ),
        ];
        for (name, sample) in samples {
            let definition = tool_defs()
                .into_iter()
                .find(|tool| tool.name == name)
                .expect("tool definition");
            let schema = Value::Object(
                definition
                    .output_schema
                    .expect("output schema")
                    .as_ref()
                    .clone(),
            );
            let validator = jsonschema::validator_for(&schema).expect("schema compiles");
            let errors: Vec<_> = validator
                .iter_errors(&sample)
                .map(|error| error.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "{name} sample violates schema: {errors:?}"
            );
        }
    }

    #[test]
    fn surface_descriptor_matches_served_tools() {
        let descriptor = surface_descriptor();
        assert_eq!(descriptor.namespace, NAMESPACE);
        assert_eq!(descriptor.required_scope, Scope::McpRead.as_str());
        assert_eq!(descriptor.tools.len(), tool_defs().len());
        assert!(descriptor
            .tools
            .iter()
            .all(|tool| tool.risk == RiskTier::Low && !tool.side_effects));
    }
}
