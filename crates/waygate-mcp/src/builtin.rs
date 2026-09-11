//! Built-in (gateway-local) MCP tools — a reserved namespace whose tools the
//! gateway answers itself instead of proxying to an upstream.
//!
//! Why this seam exists: the HITL control plane needs an automated maker
//! (Claude over MCP, holding `mcp:propose`) to QUEUE a privileged admin
//! change and poll its decision *over the MCP wire*, not only over REST.
//! Those operations aren't backed by any upstream server — they're the
//! gateway's own change-request surface — so they can't ride the
//! `<upstream>.<tool>` proxy path. [`GatewayServer`](crate::GatewayServer)
//! routes calls in a reserved namespace (e.g. `gateway-admin.*`) to a
//! [`BuiltinTools`] handle instead.
//!
//! The trait lives here, in `waygate-mcp`, because the dependency edge runs
//! `waygate-admin → waygate-mcp` and never the reverse: `waygate-mcp` defines
//! the contract, `waygate-admin` (which owns the change-request store, audit
//! sink, and action registry) implements it, and the composition root injects
//! the handle via [`GatewayServer::with_builtin_tools`]. This is the same
//! builder-injection pattern `DefaultInvocationService` already uses to reach
//! admin-owned state from inside the MCP crate.

use std::sync::Arc;

use rmcp::model::{CallToolResult, JsonObject, Task, Tool};
use rmcp::ErrorData as McpError;
use serde::Serialize;

use waygate_core::RiskTier;
use waygate_oidc::Principal;

use crate::discovery::CatalogTool;

/// A static, principal-independent description of a built-in namespace and its
/// tools.
///
/// This is the single source of truth for two consumers: the operator-facing
/// **visibility** surface (`GET /api/v1/gateway/builtins` + the dashboard
/// "Built-in surfaces" view), and the per-tool **classification** the
/// dispatch path uses to build the Cedar `Tool` resource for authorization.
/// Each [`BuiltinTools`] impl returns its descriptor from
/// [`describe`](BuiltinTools::describe), derived from the same `tool_defs()` it
/// lists — so the description can't drift from the tools actually served.
#[derive(Debug, Clone, Serialize)]
pub struct BuiltinSurfaceDescriptor {
    /// Reserved namespace prefix, e.g. `"gateway-observe"`.
    pub namespace: String,
    /// The scope required to use the complete namespace, e.g. `"mcp:observe"`.
    /// Individual tools may admit a lower discovery scope; `mcp:admin`
    /// additionally satisfies the read namespaces.
    pub required_scope: String,
    /// One-line summary of what the namespace is for.
    pub summary: String,
    pub tools: Vec<BuiltinToolDescriptor>,
}

/// One tool within a [`BuiltinSurfaceDescriptor`].
#[derive(Debug, Clone, Serialize)]
pub struct BuiltinToolDescriptor {
    /// Bare tool name (no namespace prefix), e.g. `"query_audit"`.
    pub name: String,
    pub description: String,
    /// Risk classification — `Low` for the read/observe tools, `High` for the
    /// mutating `gateway-control.*` levers. Carried into the Cedar `Tool`
    /// resource so policy can gate on `resource.risk`.
    pub risk: RiskTier,
    pub side_effects: bool,
    pub pii: bool,
}

/// Canonical, principal-independent catalog for one built-in namespace.
///
/// Each record carries the exact MCP definition and the gateway-owned facts
/// that govern it. Operator descriptors, principal-filtered listings, search,
/// and exact inspection derive from this same value.
#[derive(Debug, Clone)]
pub struct BuiltinCatalog {
    pub namespace: String,
    pub required_scope: String,
    pub summary: String,
    pub tools: Vec<CatalogTool>,
}

impl BuiltinCatalog {
    pub fn new(
        namespace: impl Into<String>,
        required_scope: impl Into<String>,
        summary: impl Into<String>,
        mut tools: Vec<CatalogTool>,
    ) -> Self {
        let namespace = namespace.into();
        assert!(
            tools.iter().all(|tool| {
                matches!(
                    &tool.identity.source,
                    crate::discovery::CatalogToolSource::Builtin(source)
                        if source == &namespace
                )
            }),
            "every built-in catalog record must belong to its namespace"
        );
        for tool in &mut tools {
            let had_output_schema = tool.definition.output_schema.is_some();
            assert!(
                crate::tool_schema::make_tool_schemas_portable(&mut tool.definition),
                "built-in tool `{}` has a non-self-contained input schema",
                tool.identity.qualified_name(),
            );
            assert_eq!(
                had_output_schema,
                tool.definition.output_schema.is_some(),
                "built-in tool `{}` has a non-self-contained output schema",
                tool.identity.qualified_name(),
            );
        }
        Self {
            namespace,
            required_scope: required_scope.into(),
            summary: summary.into(),
            tools,
        }
    }

    /// Join exact MCP definitions to an existing governance descriptor.
    ///
    /// This compatibility constructor is primarily useful for small fixtures
    /// and adapters. It fails loudly on missing, duplicate, or extra names so
    /// it cannot conceal definition/descriptor drift.
    pub fn from_descriptor(descriptor: BuiltinSurfaceDescriptor, definitions: Vec<Tool>) -> Self {
        assert_eq!(
            descriptor.tools.len(),
            definitions.len(),
            "built-in descriptor and definition counts differ"
        );
        let prefix = format!("{}.", descriptor.namespace);
        let mut definitions: std::collections::HashMap<String, Tool> = definitions
            .into_iter()
            .map(|tool| {
                let name = tool
                    .name
                    .strip_prefix(&prefix)
                    .unwrap_or_else(|| {
                        panic!(
                            "built-in tool `{}` is outside its `{}` namespace",
                            tool.name, descriptor.namespace
                        )
                    })
                    .to_owned();
                (name, tool)
            })
            .collect();
        assert_eq!(
            definitions.len(),
            descriptor.tools.len(),
            "built-in definitions contain duplicate names"
        );
        let tools = descriptor
            .tools
            .iter()
            .map(|tool| {
                let definition = definitions.remove(&tool.name).unwrap_or_else(|| {
                    panic!("built-in descriptor `{}` has no definition", tool.name)
                });
                CatalogTool::builtin(
                    &descriptor.namespace,
                    definition,
                    tool.risk,
                    tool.side_effects,
                    tool.pii,
                )
            })
            .collect();
        assert!(definitions.is_empty(), "built-in definition is undescribed");
        Self::new(
            descriptor.namespace,
            descriptor.required_scope,
            descriptor.summary,
            tools,
        )
    }

    /// Exact MCP definitions served for this namespace.
    pub fn definitions(&self) -> Vec<Tool> {
        self.tools
            .iter()
            .map(|tool| tool.definition.clone())
            .collect()
    }

    /// Operator-facing projection derived without duplicating tool metadata.
    pub fn descriptor(&self) -> BuiltinSurfaceDescriptor {
        BuiltinSurfaceDescriptor {
            namespace: self.namespace.clone(),
            required_scope: self.required_scope.clone(),
            summary: self.summary.clone(),
            tools: self
                .tools
                .iter()
                .map(|tool| BuiltinToolDescriptor {
                    name: tool.identity.name.clone(),
                    description: tool
                        .definition
                        .description
                        .as_deref()
                        .unwrap_or_default()
                        .to_owned(),
                    risk: tool.facts.risk,
                    side_effects: tool.facts.side_effects,
                    pii: tool.facts.pii,
                })
                .collect(),
        }
    }
}

/// How caller profile restrictions apply to a built-in namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinProfileScope {
    /// The namespace is itself the protected resource. Profile server/tool
    /// allow-lists must name the built-in explicitly.
    Namespace,
    /// The namespace is a data-plane broker whose implementation applies the
    /// caller's profile to every resource it returns or dispatches.
    ///
    /// This is appropriate for a discovery/orchestration facade such as Code
    /// Mode. It carries no independent authority: skipping the outer namespace
    /// check is safe only because the implementation preserves the profile on
    /// every nested resource decision. The implementation may additionally
    /// require an exact outer-tool grant for individual operations that commit
    /// durable work or capacity beyond the response; that is per-operation
    /// confinement, not authority delegated by this enum.
    DelegatedDataPlane,
}

/// A reserved, gateway-local tool namespace.
///
/// Tool calls of the form `<namespace>.<tool>` are dispatched to [`call`]
/// instead of the upstream pool, and the namespace's tools are surfaced
/// **directly** in `tools/list` (gated by whatever scope the impl enforces)
/// rather than behind a `searchTools` meta-tool. The built-in set is small
/// and fixed, so SEP #1888 progressive disclosure — which exists to bound
/// large *upstream* catalogs — doesn't apply; a maker that holds the gating
/// scope should be able to call the tool without a discovery round-trip.
///
/// [`call`]: BuiltinTools::call
#[async_trait::async_trait]
pub trait BuiltinTools: Send + Sync {
    /// The reserved namespace prefix, e.g. `"gateway-admin"`. The dispatcher
    /// checks this prefix *before* the `<server>.<tool>` split, so the
    /// built-in namespace takes **precedence**: a colliding upstream would be
    /// shadowed and its calls diverted here. That collision is prevented at
    /// the source — `waygate_upstream::validate_manifest_invariants` rejects
    /// an upstream whose name equals or is nested beneath any entry in
    /// [`waygate_core::RESERVED_BUILTIN_NAMESPACES`] on every load path. A
    /// literal lookalike without the separating dot remains valid.
    fn namespace(&self) -> &str;

    /// Complete principal-independent catalog for this namespace.
    ///
    /// Scope/profile/Cedar filtering happens when a caller obtains a view;
    /// this value is the canonical definition set, not an authorization cache.
    fn catalog(&self) -> BuiltinCatalog;

    /// Where API-key / resource-binding profile confinement is enforced.
    ///
    /// Administrative and observability built-ins use the default namespace
    /// boundary. A pure data-plane broker may opt into delegated enforcement
    /// only when it applies the same profile predicates to every nested
    /// resource and never uses the outer call as authority for a nested call.
    fn profile_scope(&self) -> BuiltinProfileScope {
        BuiltinProfileScope::Namespace
    }

    /// The tools this principal may see in `tools/list`. Returns an empty vec
    /// when the principal lacks the gating scope, so the built-in tools stay
    /// invisible to ordinary callers. This is a UX filter, **not** the
    /// security boundary — [`call`](BuiltinTools::call) re-checks
    /// authorization, because a client can invoke a tool name it never saw
    /// listed.
    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool>;

    /// Invoke a built-in tool. `tool` is the bare name with the
    /// `<namespace>.` prefix already stripped. The impl MUST authorize the
    /// call itself; an unknown `tool` should return
    /// [`McpError::invalid_params`].
    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError>;

    /// Bare tool whose profile and Cedar overlay govern this operation.
    /// Continuation operations can map back to the authority of the execution
    /// they advance while still dispatching under their own wire name.
    fn governance_tool<'a>(&self, tool: &'a str) -> &'a str {
        tool
    }

    /// Whether this namespace currently has a durable implementation for
    /// task-augmented tool calls. The server advertises MCP Tasks only when at
    /// least one configured built-in returns true.
    fn supports_tasks(&self) -> bool {
        false
    }

    /// Bare tool name whose governance also applies to this namespace's task
    /// polling, result, and cancellation operations. A task-capable namespace
    /// must return the originating tool so follow-up operations re-enter the
    /// same Cedar forbid overlay as submission.
    fn task_tool(&self) -> Option<&str> {
        None
    }

    /// Bare tool whose profile and Cedar overlay govern task cancellation.
    ///
    /// Most namespaces cancel under the originating task authority. A
    /// namespace whose cancellation is a distinct side-effecting operation
    /// overrides this so `tasks/cancel` cannot inherit read-only facts.
    fn cancel_task_tool(&self) -> Option<&str> {
        self.task_tool()
    }

    /// Start a task-augmented built-in call. `Ok(None)` means this namespace
    /// does not own a task-capable tool with this bare name.
    async fn enqueue_task(
        &self,
        _tool: &str,
        _arguments: Option<JsonObject>,
        _principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        Ok(None)
    }

    /// Read one task owned by this namespace and caller.
    async fn get_task(
        &self,
        _task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        Ok(None)
    }

    /// Read the original tool result for one completed task.
    async fn get_task_result(
        &self,
        _task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<CallToolResult>, McpError> {
        Ok(None)
    }

    /// Request cancellation of one task owned by this namespace and caller.
    async fn cancel_task(
        &self,
        _task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<Task>, McpError> {
        Ok(None)
    }

    /// Bare tool name of the continuation a `tasks/update` on this task would
    /// advance, or `Ok(None)` when the task is not owned by this namespace
    /// and caller. The router applies the Cedar forbid overlay for
    /// [`governance_tool`](BuiltinTools::governance_tool) of the returned
    /// name BEFORE calling [`update_task`](BuiltinTools::update_task) — so
    /// the `tasks/update` alias carries exactly the selected continuation's
    /// governance instead of blanket-reusing
    /// [`task_tool`](BuiltinTools::task_tool)'s. A task that exists but is
    /// not awaiting client input should return an error naming that, not
    /// `None` (which reads as "not mine" and falls through to not-found).
    async fn update_task_continuation(
        &self,
        _task_id: &str,
        _principal: Option<&Principal>,
    ) -> Result<Option<&'static str>, McpError> {
        Ok(None)
    }

    /// Deliver `tasks/update` input to one task owned by this namespace and
    /// caller, advancing the continuation reported by
    /// [`update_task_continuation`](BuiltinTools::update_task_continuation).
    /// The impl MUST enforce its own scope floor and quota exactly as the
    /// direct continuation tools do; the router has already applied the
    /// continuation's Cedar overlay. The acknowledgement is eventually
    /// consistent — the client observes progress via `tasks/get`.
    async fn update_task(
        &self,
        _task_id: &str,
        _input_responses: rmcp::model::InputResponses,
        _principal: Option<&Principal>,
    ) -> Result<(), McpError> {
        Err(McpError::invalid_params(
            "this namespace does not accept tasks/update input",
            None,
        ))
    }

    /// Operator-facing projection of [`catalog`](BuiltinTools::catalog).
    fn describe(&self) -> BuiltinSurfaceDescriptor {
        self.catalog().descriptor()
    }
}

/// Shared handle to a [`BuiltinTools`] implementation, injected into
/// [`GatewayServer`](crate::GatewayServer) at the composition root.
pub type SharedBuiltinTools = Arc<dyn BuiltinTools>;

/// A narrowed, **read-only** built-in surface the in-app assistant may
/// call. The impl (in `waygate-server`) applies the SAME
/// governance the MCP request path uses for built-ins — the Cedar forbid-overlay
/// ([`crate::authz::AuthzGate::authorize_builtin_call`]) **and** the namespace
/// scope floor inside [`BuiltinTools::call`] — so the agent's reach to the
/// gateway's own read tools (audit, resources, policy simulation) is governed
/// identically to a direct MCP call. It is deliberately scoped to the read
/// (`gateway-observe`) namespace: the agent never reaches the mutating
/// propose/control built-ins through this seam.
///
/// Injected into `waygate-admin`'s `AdminState` at the composition root (same
/// builder-injection pattern as [`BuiltinTools`]); the agent loop dispatches a
/// `gateway-observe.*` allowlist entry through it.
#[async_trait::async_trait]
pub trait AssistReadTools: Send + Sync {
    /// The read built-ins this `principal` may allowlist and call — name,
    /// description, input schema (so the model can call correctly), and the
    /// `side_effects` fact. Already filtered to read-only tools the principal is
    /// entitled to see.
    async fn read_tools(&self, principal: Option<&Principal>) -> Vec<AssistReadTool>;

    /// Governed dispatch of a fully-qualified read built-in
    /// (`<namespace>.<tool>`): Cedar overlay + scope-floor self-gate, then the
    /// call. Returns [`McpError::invalid_params`] for a non-read or unknown tool.
    async fn call(
        &self,
        name: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError>;
}

/// One read built-in offered to the assistant — everything the agent loop needs
/// to advertise and dispatch it.
#[derive(Debug, Clone)]
pub struct AssistReadTool {
    /// Fully-qualified name, e.g. `gateway-observe.query_audit`.
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments (the model calls against this).
    pub input_schema: JsonObject,
    /// `false` for every tool exposed here (the seam is read-only); carried so
    /// the agent's side-effects gate stays uniform with upstream tools.
    pub side_effects: bool,
}

/// Shared handle to an [`AssistReadTools`] implementation.
pub type SharedAssistReadTools = Arc<dyn AssistReadTools>;
