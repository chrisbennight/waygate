//! Canonical tool records shared by gateway discovery consumers.
//!
//! The upstream pool and built-in surfaces remain authoritative for their own
//! live definitions. This module gives search, inspection, `tools/list`, and
//! Code Mode one lossless snapshot shape over those sources. Retrieval indexes
//! are projections of these records, never a second catalog authority.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, Weak};

use rmcp::model::Tool;
use rmcp::ErrorData as McpError;
use serde::Serialize;
use waygate_oidc::Principal;

use crate::authz::{
    profile_blocks_server, profile_blocks_tool, AuthzVerdict, BuiltinAuthz, SharedAuthz, ToolFacts,
};
use crate::builtin::{BuiltinProfileScope, SharedBuiltinTools};
use crate::catalog::{InvocationToolSnapshot, ResolvedInvocationTool, SharedCatalog};
use crate::protocol::RiskTier;

/// Where one canonical tool definition originates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum CatalogToolSource {
    /// A tool advertised and admitted from a configured upstream MCP server.
    Upstream(String),
    /// A gateway-local tool from a reserved built-in namespace.
    Builtin(String),
}

impl CatalogToolSource {
    /// The upstream server name or built-in namespace.
    pub fn name(&self) -> &str {
        match self {
            Self::Upstream(name) | Self::Builtin(name) => name,
        }
    }
}

/// Stable structured identity for one tool in the aggregate gateway catalog.
///
/// Keeping source kind, source name, and bare tool name separate avoids
/// parsing a display string to make authorization or lifecycle decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CatalogToolIdentity {
    pub source: CatalogToolSource,
    pub name: String,
}

impl CatalogToolIdentity {
    /// Fully-qualified name used on the downstream MCP wire.
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.source.name(), self.name)
    }
}

/// One exact, governed tool snapshot suitable for every discovery consumer.
#[derive(Debug, Clone)]
pub struct CatalogTool {
    pub identity: CatalogToolIdentity,
    /// Downstream MCP definition. Its name is always fully qualified; title,
    /// annotations, metadata, and schema meaning are preserved from the
    /// source. Gateway-owned catalogs project legal schema spellings into the
    /// validation-equivalent subset accepted consistently by MCP clients.
    pub definition: Tool,
    /// Gateway-owned facts used for authorization and safety filtering.
    pub facts: ToolFacts,
    /// Current non-consuming authorization outcome that made this record
    /// discoverable. Dispatch re-evaluates and owns any authority claim.
    pub authorization: CatalogAuthorization,
    /// Exact upstream admission that supplied the published definition and
    /// governance facts. Built-in records do not have an upstream snapshot.
    invocation_snapshot: Option<InvocationToolSnapshot>,
}

/// Current authorization posture for a discoverable tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogAuthorization {
    Allowed,
    ApprovalRequired,
    StepUpRequired { required_scope: String },
}

impl CatalogAuthorization {
    /// Preserve the discoverable portion of a non-consuming authorization
    /// verdict for downstream catalog projections.
    pub fn from_verdict(verdict: AuthzVerdict) -> Option<Self> {
        match verdict {
            AuthzVerdict::Allow { .. } => Some(Self::Allowed),
            AuthzVerdict::ApprovalRequired { .. } => Some(Self::ApprovalRequired),
            AuthzVerdict::StepUpRequired { required_scope, .. } => {
                Some(Self::StepUpRequired { required_scope })
            }
            AuthzVerdict::Deny { .. } => None,
        }
    }
}

impl CatalogTool {
    /// Build a canonical record from one already-admitted upstream definition.
    pub fn upstream(server: &str, tool: &Tool, facts: ToolFacts) -> Option<Self> {
        debug_assert_eq!(facts.server, server);
        debug_assert_eq!(facts.name, tool.name.as_ref());
        let identity = CatalogToolIdentity {
            source: CatalogToolSource::Upstream(server.to_owned()),
            name: tool.name.to_string(),
        };
        let mut definition = tool.clone();
        definition.name = Cow::Owned(identity.qualified_name());
        definition.output_schema = definition
            .output_schema
            .as_ref()
            .map(|schema| Arc::new(crate::retained_delivery::output_schema(schema)));
        crate::tool_schema::make_tool_schemas_portable(&mut definition).then_some(Self {
            identity,
            definition,
            facts,
            authorization: CatalogAuthorization::Allowed,
            invocation_snapshot: None,
        })
    }

    pub(crate) fn from_upstream_snapshot(
        server: &str,
        snapshot: InvocationToolSnapshot,
    ) -> Option<Self> {
        let mut definition = snapshot.published_definition()?.clone();
        definition.input_schema = Arc::new(snapshot.input_schema()?.as_object()?.clone());
        definition.output_schema = match snapshot.described_output_schema() {
            Some(schema) => Some(Arc::new(schema.as_object()?.clone())),
            None => None,
        };
        let mut record = Self::upstream(server, &definition, snapshot.facts().clone())?;
        record.invocation_snapshot = Some(snapshot);
        Some(record)
    }

    /// Build a canonical record from one gateway-local definition.
    ///
    /// Built-in definitions are programmer-owned static values. A mismatched
    /// namespace is therefore an invariant violation caught by the ubiquitous
    /// built-in catalog tests rather than recovered as runtime input.
    pub fn builtin(
        namespace: &str,
        tool: Tool,
        risk: RiskTier,
        side_effects: bool,
        pii: bool,
    ) -> Self {
        let prefix = format!("{namespace}.");
        let name = tool
            .name
            .strip_prefix(&prefix)
            .unwrap_or_else(|| {
                panic!(
                    "built-in tool `{}` is outside its `{namespace}` namespace",
                    tool.name
                )
            })
            .to_owned();
        let identity = CatalogToolIdentity {
            source: CatalogToolSource::Builtin(namespace.to_owned()),
            name: name.clone(),
        };
        let facts = ToolFacts {
            server: namespace.to_owned(),
            name,
            risk,
            side_effects,
            pii,
            requires_approval: false,
            requires_approval_known: true,
        };
        Self {
            identity,
            definition: tool,
            facts,
            authorization: CatalogAuthorization::Allowed,
            invocation_snapshot: None,
        }
    }

    /// Immutable upstream admission that supplied this catalog record.
    pub fn invocation_snapshot(&self) -> Option<&InvocationToolSnapshot> {
        self.invocation_snapshot.as_ref()
    }

    fn with_authorization(mut self, authorization: CatalogAuthorization) -> Self {
        self.authorization = authorization;
        self
    }
}

/// Invocation channel whose policy overlay governs a discovery projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogChannel {
    Direct,
    CodeMode,
}

/// Process-local registry of gateway-owned tool surfaces.
///
/// Weak handles avoid making discovery own the handlers it describes and let
/// a per-request server factory assemble mutually discoverable built-ins
/// without a reference cycle. A snapshot upgrades the handles under the lock,
/// then releases it before any authorization work awaits.
#[derive(Clone, Default)]
pub struct BuiltinRegistry {
    inner: Arc<RwLock<Vec<Weak<dyn crate::builtin::BuiltinTools>>>>,
}

impl BuiltinRegistry {
    pub fn replace(&self, tools: &[SharedBuiltinTools]) {
        let mut inner = self.inner.write().expect("built-in registry poisoned");
        *inner = tools.iter().map(Arc::downgrade).collect();
    }

    pub fn snapshot(&self) -> Vec<SharedBuiltinTools> {
        self.inner
            .read()
            .expect("built-in registry poisoned")
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
}

/// One authorization-first view over upstream and gateway-local tools.
///
/// Every consumer receives records only after profile restrictions, server
/// discovery policy, current catalog admission, and tool policy have been
/// applied. Ranking is deliberately downstream of this boundary so denied
/// records cannot influence scores, result counts, or cursors.
#[derive(Clone)]
pub struct AuthorizedCatalog {
    catalog: SharedCatalog,
    authz: SharedAuthz,
    builtins: BuiltinRegistry,
}

impl AuthorizedCatalog {
    pub fn new(catalog: SharedCatalog, authz: SharedAuthz, builtins: BuiltinRegistry) -> Self {
        Self {
            catalog,
            authz,
            builtins,
        }
    }

    /// Replace the process-local built-in view while retaining the same
    /// upstream catalog and authorization gate.
    pub fn with_builtin_registry(mut self, builtins: BuiltinRegistry) -> Self {
        self.builtins = builtins;
        self
    }

    /// Read the durable governed-catalog generation through the same catalog
    /// implementation used to resolve every upstream tool.
    pub async fn discovery_generation(&self) -> Result<Option<i64>, McpError> {
        self.catalog.discovery_generation().await
    }

    /// Process-local authoritative catalog lookup-error generation.
    pub fn discovery_error_generation(&self) -> u64 {
        self.catalog.discovery_error_generation()
    }

    pub async fn visible_tools(
        &self,
        principal: Option<&Principal>,
        channel: CatalogChannel,
        include_builtins: bool,
    ) -> Vec<CatalogTool> {
        let mut out = self.visible_upstreams(principal, channel).await;
        if include_builtins && channel == CatalogChannel::Direct {
            out.extend(self.visible_builtins(principal).await);
        }
        out.sort_unstable_by(|left, right| {
            left.identity
                .qualified_name()
                .cmp(&right.identity.qualified_name())
                .then_with(|| {
                    source_order(&left.identity.source).cmp(&source_order(&right.identity.source))
                })
                .then_with(|| {
                    left.identity
                        .source
                        .name()
                        .cmp(right.identity.source.name())
                })
                .then_with(|| left.identity.name.cmp(&right.identity.name))
        });
        out
    }

    /// Resolve and authorize one structured identity without traversing the
    /// rest of the fleet. Unknown, unavailable, and denied records all return
    /// `None`; callers retain one hermetic unavailable response.
    pub async fn visible_tool(
        &self,
        principal: Option<&Principal>,
        channel: CatalogChannel,
        source: &CatalogToolSource,
        name: &str,
    ) -> Option<CatalogTool> {
        match source {
            CatalogToolSource::Upstream(server) => {
                self.visible_upstream(principal, channel, server, name)
                    .await
            }
            CatalogToolSource::Builtin(namespace) if channel == CatalogChannel::Direct => {
                self.visible_builtin(principal, namespace, name).await
            }
            CatalogToolSource::Builtin(_) => None,
        }
    }

    async fn visible_upstream(
        &self,
        principal: Option<&Principal>,
        channel: CatalogChannel,
        server: &str,
        name: &str,
    ) -> Option<CatalogTool> {
        if let Some(principal) = principal {
            if profile_blocks_server(principal, server)
                || profile_blocks_tool(principal, server, name)
                || !self.authz.may_discover_server(principal, server).await
            {
                return None;
            }
        }
        let tenant = principal
            .map(|principal| principal.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        let ResolvedInvocationTool::Ready(snapshot) = self
            .catalog
            .resolve_discovery_tool(tenant, server, name)
            .await
        else {
            return None;
        };
        let authorization = match principal {
            Some(principal) => {
                let verdict = match channel {
                    CatalogChannel::Direct => {
                        self.authz.may_call_tool(principal, snapshot.facts()).await
                    }
                    CatalogChannel::CodeMode => {
                        self.authz
                            .may_call_tool_on_channel(
                                principal,
                                snapshot.facts(),
                                waygate_core::InvocationChannelFact::CodeMode,
                            )
                            .await
                    }
                };
                CatalogAuthorization::from_verdict(verdict)?
            }
            None => CatalogAuthorization::Allowed,
        };
        CatalogTool::from_upstream_snapshot(server, snapshot)
            .map(|record| record.with_authorization(authorization))
    }

    async fn visible_builtin(
        &self,
        principal: Option<&Principal>,
        namespace: &str,
        name: &str,
    ) -> Option<CatalogTool> {
        let builtin = self
            .builtins
            .snapshot()
            .into_iter()
            .find(|builtin| builtin.namespace() == namespace)?;
        let namespace_scoped = builtin.profile_scope() == BuiltinProfileScope::Namespace;
        if principal.is_some_and(|principal| {
            namespace_scoped
                && (profile_blocks_server(principal, namespace)
                    || profile_blocks_tool(principal, namespace, name))
        }) {
            return None;
        }
        let listed = builtin.list_tools(principal).await;
        if !listed.iter().any(|listed| {
            listed
                .name
                .strip_prefix(namespace)
                .and_then(|rest| rest.strip_prefix('.'))
                .unwrap_or(listed.name.as_ref())
                == name
        }) {
            return None;
        }
        let catalog = builtin.catalog();
        let record = catalog
            .tools
            .iter()
            .find(|record| record.identity.name == name)?;
        let authorization = match principal {
            Some(principal) => {
                let governance_tool = builtin.governance_tool(name);
                let governance_record = catalog
                    .tools
                    .iter()
                    .find(|record| record.identity.name == governance_tool)?;
                match self
                    .authz
                    .authorize_builtin_call(principal, &governance_record.facts)
                    .await
                {
                    BuiltinAuthz::Proceed => CatalogAuthorization::Allowed,
                    BuiltinAuthz::StepUpRequired { required_scope, .. } => {
                        CatalogAuthorization::StepUpRequired { required_scope }
                    }
                    BuiltinAuthz::Forbidden { .. } | BuiltinAuthz::Indeterminate { .. } => {
                        return None;
                    }
                }
            }
            None => CatalogAuthorization::Allowed,
        };
        Some(record.clone().with_authorization(authorization))
    }

    async fn visible_upstreams(
        &self,
        principal: Option<&Principal>,
        channel: CatalogChannel,
    ) -> Vec<CatalogTool> {
        let mut servers = self.catalog.list_servers().await;
        servers.sort_unstable();
        let mut out = Vec::new();
        for server in servers {
            if let Some(principal) = principal {
                if profile_blocks_server(principal, &server)
                    || !self.authz.may_discover_server(principal, &server).await
                {
                    continue;
                }
            }
            let Ok(mut listed) = self.catalog.list_tools(&server).await else {
                continue;
            };
            listed.sort_unstable_by(|left, right| left.name.cmp(&right.name));
            for listed_tool in listed {
                let name = listed_tool.name.as_ref();
                if principal.is_some_and(|principal| profile_blocks_tool(principal, &server, name))
                {
                    continue;
                }
                let tenant = principal
                    .map(|principal| principal.tenant.as_str())
                    .unwrap_or(waygate_core::TenantId::DEFAULT);
                let ResolvedInvocationTool::Ready(snapshot) = self
                    .catalog
                    .resolve_discovery_tool(tenant, &server, name)
                    .await
                else {
                    continue;
                };
                let authorization = match principal {
                    Some(principal) => {
                        let verdict = match channel {
                            CatalogChannel::Direct => {
                                self.authz.may_call_tool(principal, snapshot.facts()).await
                            }
                            CatalogChannel::CodeMode => {
                                self.authz
                                    .may_call_tool_on_channel(
                                        principal,
                                        snapshot.facts(),
                                        waygate_core::InvocationChannelFact::CodeMode,
                                    )
                                    .await
                            }
                        };
                        let Some(authorization) = CatalogAuthorization::from_verdict(verdict)
                        else {
                            continue;
                        };
                        authorization
                    }
                    None => CatalogAuthorization::Allowed,
                };
                let Some(record) = CatalogTool::from_upstream_snapshot(&server, snapshot) else {
                    continue;
                };
                out.push(record.with_authorization(authorization));
            }
        }
        out
    }

    async fn visible_builtins(&self, principal: Option<&Principal>) -> Vec<CatalogTool> {
        let mut out = Vec::new();
        for builtin in self.builtins.snapshot() {
            let namespace = builtin.namespace();
            let namespace_scoped = builtin.profile_scope() == BuiltinProfileScope::Namespace;
            if principal.is_some_and(|principal| {
                namespace_scoped && profile_blocks_server(principal, namespace)
            }) {
                continue;
            }
            let catalog = builtin.catalog();
            for listed in builtin.list_tools(principal).await {
                let bare = listed
                    .name
                    .strip_prefix(namespace)
                    .and_then(|rest| rest.strip_prefix('.'))
                    .unwrap_or(listed.name.as_ref());
                if principal.is_some_and(|principal| {
                    namespace_scoped && profile_blocks_tool(principal, namespace, bare)
                }) {
                    continue;
                }
                let Some(record) = catalog
                    .tools
                    .iter()
                    .find(|record| record.identity.name == bare)
                else {
                    continue;
                };
                let authorization = if let Some(principal) = principal {
                    let governance_tool = builtin.governance_tool(bare);
                    let Some(governance_record) = catalog
                        .tools
                        .iter()
                        .find(|record| record.identity.name == governance_tool)
                    else {
                        continue;
                    };
                    match self
                        .authz
                        .authorize_builtin_call(principal, &governance_record.facts)
                        .await
                    {
                        BuiltinAuthz::Proceed => CatalogAuthorization::Allowed,
                        BuiltinAuthz::StepUpRequired { required_scope, .. } => {
                            CatalogAuthorization::StepUpRequired { required_scope }
                        }
                        BuiltinAuthz::Forbidden { .. } | BuiltinAuthz::Indeterminate { .. } => {
                            continue;
                        }
                    }
                } else {
                    CatalogAuthorization::Allowed
                };
                out.push(record.clone().with_authorization(authorization));
            }
        }
        out
    }
}

fn source_order(source: &CatalogToolSource) -> u8 {
    match source {
        CatalogToolSource::Builtin(_) => 0,
        CatalogToolSource::Upstream(_) => 1,
    }
}

/// Rank an already-authorized catalog projection with a deterministic BM25
/// baseline. Accepting canonical records instead of an index handle makes the
/// required authorization-before-ranking sequence explicit.
pub fn rank_visible_tools(query: &str, tools: Vec<CatalogTool>) -> Vec<CatalogTool> {
    let normalized_query = query.to_lowercase();
    let mut exact: Vec<_> = tools
        .iter()
        .filter(|tool| tool.identity.qualified_name().to_lowercase() == normalized_query)
        .cloned()
        .collect();
    if !exact.is_empty() {
        exact
            .sort_unstable_by(|left, right| catalog_order_key(left).cmp(&catalog_order_key(right)));
        return exact;
    }
    let query_terms = tokens(query);
    let documents: Vec<_> = tools.iter().map(document_terms).collect();
    let document_count = documents.len() as f64;
    let average_length = if documents.is_empty() {
        1.0
    } else {
        documents.iter().map(Vec::len).sum::<usize>() as f64 / document_count
    };
    let mut document_frequency = HashMap::new();
    for document in &documents {
        let unique: HashSet<_> = document.iter().collect();
        for term in unique {
            *document_frequency.entry(term.clone()).or_insert(0usize) += 1;
        }
    }
    let mut ranked: Vec<_> = tools
        .into_iter()
        .zip(documents)
        .filter_map(|(tool, document)| {
            let mut frequencies = HashMap::new();
            for term in &document {
                *frequencies.entry(term).or_insert(0usize) += 1;
            }
            let mut score = 0.0;
            for term in &query_terms {
                let frequency = frequencies.get(term).copied().unwrap_or_default() as f64;
                if frequency == 0.0 {
                    continue;
                }
                let containing = document_frequency.get(term).copied().unwrap_or_default() as f64;
                let inverse_frequency =
                    ((document_count - containing + 0.5) / (containing + 0.5) + 1.0).ln();
                let length_normalization =
                    1.2 * (0.25 + 0.75 * document.len() as f64 / average_length.max(1.0));
                score += inverse_frequency * (frequency * 2.2) / (frequency + length_normalization);
            }
            let qualified = tool.identity.qualified_name().to_lowercase();
            if qualified == normalized_query {
                score += 8.0;
            } else if qualified.contains(&normalized_query) {
                score += 2.0;
            }
            (score > 0.0).then_some((tool, score))
        })
        .collect();
    ranked.sort_by(|(left_tool, left_score), (right_tool, right_score)| {
        right_score
            .total_cmp(left_score)
            .then_with(|| catalog_order_key(left_tool).cmp(&catalog_order_key(right_tool)))
    });
    ranked.into_iter().map(|(tool, _)| tool).collect()
}

fn document_terms(tool: &CatalogTool) -> Vec<String> {
    const MAX_RANKING_TEXT_CHARS: usize = 2_048;
    let mut terms = Vec::new();
    for _ in 0..3 {
        terms.extend(tokens(&tool.identity.name));
    }
    for _ in 0..2 {
        terms.extend(tokens(tool.identity.source.name()));
    }
    terms.extend(tokens(&tool.identity.qualified_name()));
    if let Some(title) = tool.definition.title.as_deref() {
        terms.extend(tokens(
            &title
                .chars()
                .take(MAX_RANKING_TEXT_CHARS)
                .collect::<String>(),
        ));
    }
    if let Some(description) = tool.definition.description.as_deref() {
        terms.extend(tokens(
            &description
                .chars()
                .take(MAX_RANKING_TEXT_CHARS)
                .collect::<String>(),
        ));
    }
    terms
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn catalog_order_key(tool: &CatalogTool) -> (u8, &str, &str) {
    (
        source_order(&tool.identity.source),
        tool.identity.source.name(),
        &tool.identity.name,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
    use rmcp::ErrorData as McpError;
    use serde_json::json;

    use super::*;
    use crate::authz::{AuthzGate, AuthzVerdict};
    use crate::builtin::{BuiltinCatalog, BuiltinTools};
    use crate::catalog::{
        InvocationContractIdentity, InvocationToolSnapshot, ResolvedInvocationTool, UpstreamCatalog,
    };

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_owned(),
            "description".to_owned(),
            Arc::new(json!({"type": "object"}).as_object().unwrap().clone()),
        )
        .with_title("Title")
        .annotate(ToolAnnotations::new().read_only(true))
    }

    #[test]
    fn upstream_snapshot_preserves_contract_meaning_and_qualifies_the_name() {
        let upstream = tool("search");
        let facts = ToolFacts {
            server: "kagi".to_owned(),
            name: "search".to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };
        let record = CatalogTool::upstream("kagi", &upstream, facts)
            .expect("self-contained upstream schema is publishable");

        assert_eq!(record.identity.qualified_name(), "kagi.search");
        assert_eq!(record.definition.name, "kagi.search");
        assert_eq!(record.definition.title, upstream.title);
        assert_eq!(record.definition.input_schema, upstream.input_schema);
        assert_eq!(record.definition.annotations, upstream.annotations);
    }

    #[test]
    fn legacy_snapshot_describes_response_without_enabling_validation() {
        let output = json!({"type":"object","$defs":{"Material":{"type":"object","properties":{"product_name":{"type":"string"}}}},"properties":{"material":{"$ref":"#/$defs/Material"}}});
        let upstream =
            tool("search").with_raw_output_schema(Arc::new(output.as_object().unwrap().clone()));
        let snapshot = InvocationToolSnapshot::catalog(
            ToolFacts {
                server: "kagi".into(),
                name: "search".into(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            uuid::Uuid::nil(),
            "classification-only".into(),
            Some(json!({"type":"object"})),
            None,
        )
        .with_published_definition(Some(upstream));
        assert!(snapshot.output_schema().is_none());
        let record = CatalogTool::from_upstream_snapshot("kagi", snapshot).unwrap();
        let declared = json!(record.definition.output_schema.as_deref().unwrap());
        let validator = jsonschema::validator_for(&declared).unwrap();
        assert!(validator.is_valid(&json!({"material":{"product_name":"PLA Basic"}})));
        assert!(!validator.is_valid(&json!({"material":{"product_name":123}})));
        assert!(record
            .invocation_snapshot()
            .unwrap()
            .output_schema()
            .is_none());
    }

    #[test]
    fn upstream_snapshot_publishes_the_schemas_admitted_for_invocation() {
        let upstream = tool("search");
        let facts = ToolFacts {
            server: "kagi".to_owned(),
            name: "search".to_owned(),
            risk: RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };
        let admitted_input = json!({
            "type": "object",
            "required": ["admitted"]
        });
        let admitted_output = json!({
            "type": "object",
            "required": ["result"]
        });
        let snapshot = InvocationToolSnapshot::catalog(
            facts.clone(),
            uuid::Uuid::nil(),
            "schema-v1".to_owned(),
            Some(admitted_input.clone()),
            Some(admitted_output.clone()),
        )
        .with_published_definition(Some(upstream.clone()));

        let record = CatalogTool::from_upstream_snapshot("kagi", snapshot)
            .expect("the admitted schemas are publishable");
        assert_eq!(
            record.definition.input_schema.as_ref(),
            admitted_input.as_object().unwrap()
        );
        let published_output = json!(record.definition.output_schema.as_deref().unwrap());
        let client = jsonschema::validator_for(&published_output).unwrap();
        assert!(client.is_valid(&json!({"result": "upstream response"})));
        assert!(client.is_valid(&json!({"_gateway_delivery": {
            "operation_status": "succeeded", "delivery_status": "unavailable",
            "error": "retained_response_staging_failed", "retry_operation": false
        }})));
        assert!(!client.is_valid(&json!({})));
        assert_eq!(
            record.invocation_snapshot.as_ref().unwrap().output_schema(),
            Some(&admitted_output)
        );
        assert_eq!(record.definition.title, upstream.title);

        let unavailable = InvocationToolSnapshot::catalog(
            facts,
            uuid::Uuid::nil(),
            "schema-v2".to_owned(),
            Some(json!({
                "type": "object",
                "properties": {
                    "value": {"$ref": "https://schemas.example/unavailable.json"}
                }
            })),
            None,
        )
        .with_published_definition(Some(upstream));
        assert!(CatalogTool::from_upstream_snapshot("kagi", unavailable).is_none());
    }

    #[test]
    fn source_kind_is_part_of_the_stable_identity() {
        let upstream = CatalogToolIdentity {
            source: CatalogToolSource::Upstream("catalog".to_owned()),
            name: "search".to_owned(),
        };
        let builtin = CatalogToolIdentity {
            source: CatalogToolSource::Builtin("catalog".to_owned()),
            name: "search".to_owned(),
        };

        assert_ne!(upstream, builtin);
        assert_eq!(upstream.qualified_name(), builtin.qualified_name());
    }

    #[test]
    #[should_panic(expected = "outside its `gateway-observe` namespace")]
    fn builtin_snapshot_rejects_definition_outside_namespace() {
        let _ = CatalogTool::builtin(
            "gateway-observe",
            tool("other.search"),
            RiskTier::Low,
            false,
            false,
        );
    }

    struct StaticCatalog {
        tools: Vec<Tool>,
        list_calls: AtomicUsize,
    }

    #[async_trait]
    impl UpstreamCatalog for StaticCatalog {
        async fn list_servers(&self) -> Vec<String> {
            vec!["remote".to_owned()]
        }

        async fn list_tools(&self, server: &str) -> Result<Vec<Tool>, McpError> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
            if server == "remote" {
                Ok(self.tools.clone())
            } else {
                Err(McpError::invalid_params("unknown server", None))
            }
        }

        async fn call_tool(
            &self,
            _server: &str,
            _tool_name: &str,
            _args: Option<JsonObject>,
            _principal: Option<&Principal>,
            _admitted: Option<&InvocationContractIdentity>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("discovery never dispatches")
        }

        fn tool_facts(&self, server: &str, tool_name: &str) -> ToolFacts {
            ToolFacts {
                server: server.to_owned(),
                name: tool_name.to_owned(),
                risk: RiskTier::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            }
        }

        async fn resolve_discovery_tool(
            &self,
            _tenant: &str,
            server: &str,
            tool_name: &str,
        ) -> ResolvedInvocationTool {
            let definition = self
                .tools
                .iter()
                .find(|tool| tool.name == tool_name)
                .cloned();
            ResolvedInvocationTool::Ready(
                InvocationToolSnapshot::manifest_fallback(self.tool_facts(server, tool_name), true)
                    .with_published_definition(definition),
            )
        }
    }

    struct DenyHidden;

    #[async_trait]
    impl AuthzGate for DenyHidden {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(&self, facts: &waygate_core::Facts) -> AuthzVerdict {
            if facts.resource.tool == "hidden" {
                AuthzVerdict::Deny {
                    reason: "hidden".to_owned(),
                    policy_ids: vec!["hide-tool".to_owned()],
                    reasons: vec!["hidden".to_owned()],
                }
            } else {
                AuthzVerdict::Allow {
                    policy_ids: Vec::new(),
                }
            }
        }
    }

    struct LocalTools;

    #[async_trait]
    impl BuiltinTools for LocalTools {
        fn namespace(&self) -> &str {
            "gateway-local"
        }

        fn catalog(&self) -> BuiltinCatalog {
            BuiltinCatalog::new(
                self.namespace(),
                "mcp:read",
                "local",
                vec![CatalogTool::builtin(
                    self.namespace(),
                    tool("gateway-local.inspect"),
                    RiskTier::Low,
                    false,
                    false,
                )],
            )
        }

        async fn list_tools(&self, _principal: Option<&Principal>) -> Vec<Tool> {
            self.catalog().definitions()
        }

        async fn call(
            &self,
            _tool: &str,
            _arguments: Option<JsonObject>,
            _principal: Option<&Principal>,
        ) -> Result<CallToolResult, McpError> {
            unreachable!("discovery never dispatches")
        }
    }

    fn principal() -> Principal {
        Principal {
            sub: "reader".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "test".to_owned(),
            scopes: vec!["mcp:read".to_owned()],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: Vec::new(),
        }
    }

    #[tokio::test]
    async fn authorization_precedes_ranking_and_gateway_local_tools_share_the_view() {
        let upstream: SharedCatalog = Arc::new(StaticCatalog {
            tools: vec![tool("visible"), tool("hidden")],
            list_calls: AtomicUsize::new(0),
        });
        let registry = BuiltinRegistry::default();
        let local: SharedBuiltinTools = Arc::new(LocalTools);
        registry.replace(std::slice::from_ref(&local));
        let view = AuthorizedCatalog::new(upstream, Arc::new(DenyHidden), registry);

        let visible = view
            .visible_tools(Some(&principal()), CatalogChannel::Direct, true)
            .await;
        let identities: Vec<_> = visible
            .iter()
            .map(|record| record.identity.qualified_name())
            .collect();

        assert_eq!(identities, vec!["gateway-local.inspect", "remote.visible"]);
        assert_eq!(rank_visible_tools("hidden", visible.clone()).len(), 0);
        assert_eq!(rank_visible_tools("inspect", visible).len(), 1);
    }

    #[tokio::test]
    async fn exact_selection_does_not_enumerate_the_upstream_catalog() {
        let upstream = Arc::new(StaticCatalog {
            tools: vec![tool("visible"), tool("other")],
            list_calls: AtomicUsize::new(0),
        });
        let view = AuthorizedCatalog::new(
            upstream.clone(),
            Arc::new(DenyHidden),
            BuiltinRegistry::default(),
        );

        let selected = view
            .visible_tool(
                Some(&principal()),
                CatalogChannel::Direct,
                &CatalogToolSource::Upstream("remote".to_owned()),
                "visible",
            )
            .await
            .expect("selected tool is visible");

        assert_eq!(selected.identity.qualified_name(), "remote.visible");
        assert_eq!(upstream.list_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn exact_selection_hides_a_non_self_contained_input_schema() {
        let remote = Tool::new(
            "remote-ref",
            "description",
            Arc::new(
                json!({
                    "type": "object",
                    "properties": {
                        "value": {"$ref": "https://schemas.example/value.json"}
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        );
        let upstream = Arc::new(StaticCatalog {
            tools: vec![remote],
            list_calls: AtomicUsize::new(0),
        });
        let view =
            AuthorizedCatalog::new(upstream, Arc::new(DenyHidden), BuiltinRegistry::default());

        let selected = view
            .visible_tool(
                Some(&principal()),
                CatalogChannel::Direct,
                &CatalogToolSource::Upstream("remote".to_owned()),
                "remote-ref",
            )
            .await;

        assert!(selected.is_none());
    }
}
