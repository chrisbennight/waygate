//! `InvocationService` — the trait every per-tool-call hop flows through.
//!
//! This trait extracts the dispatch logic that previously lived inline in
//! `waygate_mcp::server::GatewayServer::dispatch_tool_call`. The concrete
//! implementation
//! (`waygate_mcp::invocation::DefaultInvocationService`) still lives in
//! `waygate-mcp` because it composes the catalog, authz gate, and evidence
//! recorder — all of which live there. Splitting the trait into its own
//! crate establishes the seam alternative implementations plug into without
//! taking a circular dependency on `waygate-mcp`.
//!
//! ## Why the trait lives here, not in `waygate-mcp`
//!
//! `waygate-mcp` depends on `waygate-oidc`. The trait needs to reference
//! `Principal` (from `waygate-oidc`) but cannot reference `SharedCatalog`
//! / `SharedAuthz` / `SharedEvidence` (which would force a circular path).
//! Putting the trait in a smaller upstream crate lets the dispatch path
//! be polymorphic over implementations — at minimum the existing
//! `DefaultInvocationService`, and potentially a fail-closed wrapper,
//! a quota-gated wrapper, an approval-gated wrapper, etc. — without each
//! decorator needing to live in `waygate-mcp`.
//!
//! ## Pipeline
//!
//! `invoke()` is the spine for these ordered named stages:
//!
//! 1. `resolve_tool` — parse `<server>.<tool>`, fetch [`ToolFacts`].
//! 2. `validate_input` — validate call arguments against the immutable input
//!    schema admitted at tool resolution.
//! 3. `extract_facts` — typed Policy Information Point output assembled from
//!    the principal and resolved tool classification.
//! 4. `authorize` — the configured `AuthzGate` decision.
//! 5. `check_profile_restrictions` — authenticated caller server/tool bounds.
//! 6. `prepare_output_validation` — compile the admitted output schema after
//!    authorization and before resource-consuming gates.
//! 7. `check_quota` — active when a quota service is configured.
//! 8. `check_approval` — active for governed tools that require a grant.
//! 9. `record_pre_call` — `EvidenceRecorder::record_required` when
//!    `GATEWAY_AUDIT_MODE=fail_closed` and the call is side-effecting
//!    (`facts.side_effects`); ensures the intent-to-call row is durable before
//!    the side-effecting dispatch.
//! 10. `dispatch` — call into the catalog's per-upstream client.
//! 11. `inspect_response` — configured DLP / secret / poisoning inspection.
//! 12. `validate_output` — schema-check the inspected/redacted result when an
//!     `output_schema` exists.
//! 13. `record_outcome` — final `EvidenceRecorder` event with risk, latency,
//!     PII, policy decisions.
//!
//! `DefaultInvocationService` implements `invoke` as the thirteen private
//! async methods enumerated above. Stage 9 (`record_pre_call`) is what makes
//! `GATEWAY_AUDIT_MODE=fail_closed` actually fail closed on side-effecting
//! calls: it calls `record_required` and surfaces
//! `InvocationError::AuditUnavailable` on persistence failure.
//! Every stage on the MCP tool path is active when its required collaborator
//! or admitted schema is present. See the per-stage documentation on
//! `DefaultInvocationService` for each gate's failure posture.

use std::collections::BTreeMap;

use async_trait::async_trait;
use futures::stream::BoxStream;
use rmcp::model::{CallToolResult, ErrorData};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use waygate_oidc::Principal;

pub use waygate_core::InvocationHierarchy;

/// Input to [`InvocationService::invoke`]. Carries the parsed
/// `<server>.<tool>` pair, the JSON arguments (already deserialized from the
/// MCP request envelope), and a free-form `metadata` bag for future
/// transport-shim use (correlation IDs, tracing context, etc.). The
/// transport-shaped `CallToolRequestParams` does not leak past the
/// `GatewayServer` adapter — every consumer of `InvocationService` sees this
/// neutral shape instead.
/// Well-known [`InvocationRequest::metadata`] key carrying the in-app agent
/// acting on behalf of the human principal (e.g. `agent:ops-chat`). The
/// invocation pipeline reads it to stamp the audit row's `acting_agent`
/// attribution; absent ⇒ a human acted directly. Defined
/// here so the producer (the agent loop) and the consumer (the pipeline) share
/// one spelling and can't drift.
pub const ACTING_AGENT_METADATA_KEY: &str = "acting_agent";

/// Additional authority constraint imposed by the invocation's caller.
///
/// The ordinary MCP path is unrestricted and relies on the governed snapshot,
/// Cedar, profiles, quota, and approvals. An explicit caller constraint is
/// checked against that same immutable snapshot during tool resolution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationMode {
    #[default]
    Unrestricted,
    ReadOnly,
}

/// The client Images API endpoint. Kept separate from the model alias so a
/// caller cannot select an image operation through a chat request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImagesSurface {
    Generations,
    Edits,
}

/// Invocation authority channel. All callers use direct
/// authority; execution provenance is carried by the invocation hierarchy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationChannel {
    /// An ordinary client call (MCP wire, LLM fast-path, agent loop).
    #[default]
    Direct,
}

/// Delivery of retained connector bodies, independent of invocation authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDelivery {
    /// Publish an owner-scoped file without exposing the body to model context.
    #[default]
    File,
    /// Materialize in the calling runtime, with file delivery when it cannot fit.
    Materialize,
}

/// Immutable tool contract that an invocation caller requires the governed
/// resolver to admit.
///
/// The concrete invocation service compares this value against the snapshot it
/// resolves inside Stage 1, then carries that same snapshot through validation
/// and dispatch. Callers can therefore bind a later invocation to an earlier
/// versioned discovery contract without introducing a preflight race.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationContractIdentity {
    pub authority: InvocationContractAuthority,
    pub input_schema_hash: Option<String>,
    pub output_schema_hash: Option<String>,
    #[serde(default)]
    pub tool_annotations_hash: Option<String>,
    #[serde(default)]
    pub action_metadata_hash: Option<String>,
    /// Binds the reviewed per-operation definition — the discriminator and the
    /// classifications keyed by its values — into the contract.
    ///
    /// Which facts a call authorizes under depends on this definition, so a
    /// change to it between admission and dispatch is a contract change and the
    /// re-check has to see it. `None` for a tool classified by name alone.
    ///
    /// The call's own arguments are deliberately absent. They select among the
    /// reviewed operations; they do not redefine them, and folding them in would
    /// make an identity the argument-free re-check could never reproduce.
    ///
    /// Skipped when absent, not rendered as `null`. Code Mode persists this
    /// identity as raw JSON and compares the stored text against a freshly
    /// serialized binding on resume, so emitting a key that earlier snapshots
    /// could not contain would fail every in-flight execution as a changed
    /// contract on the deploy that added the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations_hash: Option<String>,
    pub risk: InvocationRisk,
    pub side_effects: bool,
    pub pii: bool,
    pub requires_approval: bool,
    pub requires_approval_known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authority", rename_all = "snake_case")]
pub enum InvocationContractAuthority {
    Catalog {
        tool_id: String,
        catalog_schema_hash: String,
    },
    ManifestFallback {
        approval_requirements_known: bool,
        /// The manifest-approved behavior hash bound at admission when the
        /// upstream is annotation-native (`None` in legacy manifest mode).
        /// Without it, fallback identities from separately approved
        /// generations that differ only in fields outside the four schema
        /// hashes — description, sibling namespaced metadata — would be
        /// indistinguishable, so a generation change could cross discovery
        /// to dispatch unreported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved_behavior_hash: Option<String>,
    },
    SyntheticModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvocationRisk {
    Low,
    Medium,
    High,
}

/// Exact durable Code Mode operation that an approval-required invocation may
/// consume a grant for. Direct calls leave this absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationApprovalBinding {
    pub execution_id: uuid::Uuid,
    pub source_digest: String,
    pub call_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationRequest {
    /// Upstream server name (matches the `name:` field on a manifest entry).
    pub server: String,
    /// Bare tool name (without the `<server>.` qualifier).
    pub tool: String,
    /// JSON arguments. `None` matches the MCP wire convention of an
    /// argument-less call (some clients omit `arguments` entirely).
    pub arguments: Option<serde_json::Map<String, Value>>,
    /// Free-form metadata bag. Carries cross-cutting attributes such as
    /// [`ACTING_AGENT_METADATA_KEY`]; also reserved for correlation IDs /
    /// trace context.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Caller-imposed authority ceiling enforced against the exact admitted
    /// tool snapshot before arguments, policy, quota, approval, or dispatch.
    #[serde(default, skip_serializing_if = "is_unrestricted")]
    pub mode: InvocationMode,
    /// Exact versioned contract the Stage 1 resolver must still admit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_contract: Option<InvocationContractIdentity>,
    /// Parent execution, ordered step, stable nested-call identity, and attempt
    /// attribution. Direct calls leave this absent; orchestrated callers carry
    /// it through the ordinary invocation and evidence path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<InvocationHierarchy>,
    /// Execution-bound approval identity. It must agree with `hierarchy`; the
    /// approval gate then refuses ordinary unbound grants for this invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_binding: Option<InvocationApprovalBinding>,
    /// The gateway surface this call originated from; policies gate on it as
    /// `context.channel`. Defaults to [`InvocationChannel::Direct`].
    #[serde(default, skip_serializing_if = "is_direct")]
    pub channel: InvocationChannel,
    /// Maximum serialized bytes the caller can materialize for a retained
    /// response body. Only callers whose runtime has a stricter data boundary
    /// than the ordinary MCP transport set this value. The invocation
    /// pipeline uses it before following an upstream-owned retained resource,
    /// so a small response envelope cannot make the caller fetch a body it
    /// cannot safely consume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_materialization_limit_bytes: Option<usize>,
    #[serde(default)]
    pub response_delivery: ResponseDelivery,
    /// LLM fast-path only: `true` when the call arrived on the OpenAI Responses
    /// client surface (`POST /v1/responses`). It selects the Responses request
    /// parser in the inference fast-path and, via the canonical request's
    /// `inbound_surface`, the Responses egress. `false` (the default) for
    /// `/v1/chat/completions` and every MCP tool call.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub responses_surface: bool,
    /// LLM fast-path only: `true` when the call arrived on the OpenAI embeddings
    /// client surface (`POST /v1/embeddings`). It selects the embeddings
    /// parse/dispatch path in the inference fast-path. The pipeline rejects a
    /// surface/operation mismatch (an embeddings model hit on a chat route, or a
    /// chat model on `/v1/embeddings`) with a clean client error. Mutually
    /// exclusive with `responses_surface`; `false` (the default) for the chat
    /// surfaces and every MCP tool call.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub embeddings_surface: bool,
    /// Images API operation; absent for chat, embeddings, and MCP calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images_surface: Option<ImagesSurface>,
    /// MRTR retry (SEP-2322): the caller's answers to a previous
    /// `input_required` pause. Passed through to the upstream dispatch
    /// verbatim — the gateway neither inspects nor synthesizes entries.
    /// Absent on a first-round call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_responses: Option<rmcp::model::InputResponses>,
    /// MRTR retry: the opaque `requestState` echoed back from a previous
    /// upstream `input_required` pause. Passed through verbatim; the
    /// gateway mints no request state of its own (its durable anchors —
    /// approval grants, Code Mode execution rows — carry the state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_state: Option<String>,
    /// The capabilities the *downstream* caller declared for this request,
    /// when the caller's transport can deliver an MRTR pause back to it.
    /// The pipeline reads the elicitation declaration (the one
    /// input-request kind the gateway relays) to gate pause answerability. `None` means the caller cannot
    /// receive an `input_required` result at all — legacy-generation
    /// sessions, Code Mode, and the LLM surfaces — so any upstream pause
    /// fails closed. `Some` with an empty set is a 2026 caller that can
    /// receive a pause (and echo a pure `requestState` round trip) but
    /// answers no server-initiated input request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_capabilities: Option<rmcp::model::ClientCapabilities>,
}

impl InvocationRequest {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            arguments: None,
            metadata: BTreeMap::new(),
            mode: InvocationMode::Unrestricted,
            expected_contract: None,
            hierarchy: None,
            approval_binding: None,
            channel: InvocationChannel::Direct,
            response_materialization_limit_bytes: None,
            response_delivery: ResponseDelivery::File,
            responses_surface: false,
            embeddings_surface: false,
            images_surface: None,
            input_responses: None,
            request_state: None,
            caller_capabilities: None,
        }
    }

    pub fn with_arguments(mut self, args: Option<serde_json::Map<String, Value>>) -> Self {
        self.arguments = args;
        self
    }

    /// Attach the MRTR retry fields (SEP-2322) exactly as the caller sent
    /// them; both flow to the upstream dispatch verbatim.
    pub fn with_mrtr_retry(
        mut self,
        input_responses: Option<rmcp::model::InputResponses>,
        request_state: Option<String>,
    ) -> Self {
        self.input_responses = input_responses;
        self.request_state = request_state;
        self
    }

    /// Declare the downstream caller's server-initiated-request capabilities
    /// for this call. `Some` means an upstream `input_required` pause can be
    /// forwarded to the caller (subject to the per-request-type check);
    /// leave `None` for callers that cannot answer a pause.
    pub fn with_caller_capabilities(
        mut self,
        capabilities: Option<rmcp::model::ClientCapabilities>,
    ) -> Self {
        self.caller_capabilities = capabilities;
        self
    }

    /// Require the admitted operation to be non-side-effecting and free of an
    /// approval requirement. The default invocation pipeline enforces this
    /// after resolving the immutable snapshot, eliminating a preflight race.
    pub fn read_only(mut self) -> Self {
        self.mode = InvocationMode::ReadOnly;
        self
    }

    /// Refuse before validation, policy, quota, approval, or dispatch unless
    /// Stage 1 resolves this exact tool contract.
    pub fn with_expected_contract(mut self, expected: InvocationContractIdentity) -> Self {
        self.expected_contract = Some(expected);
        self
    }

    pub fn with_hierarchy(mut self, hierarchy: InvocationHierarchy) -> Self {
        self.hierarchy = Some(hierarchy);
        self
    }

    pub fn with_approval_binding(mut self, binding: InvocationApprovalBinding) -> Self {
        self.approval_binding = Some(binding);
        self
    }

    /// Stamp the originating gateway surface (see [`InvocationChannel`]).
    pub fn with_channel(mut self, channel: InvocationChannel) -> Self {
        self.channel = channel;
        self
    }

    /// Bound any retained response body the invocation pipeline may recover
    /// for this caller. This does not cap ordinary MCP results; it prevents a
    /// compact out-of-line envelope from bypassing the caller runtime's
    /// materialization budget.
    pub fn with_response_materialization_limit(mut self, bytes: usize) -> Self {
        self.response_materialization_limit_bytes = Some(bytes);
        self
    }

    pub fn with_response_delivery(mut self, delivery: ResponseDelivery) -> Self {
        self.response_delivery = delivery;
        self
    }

    /// Mark this as an OpenAI Responses-surface call (the `/v1/responses` route).
    pub fn with_responses_surface(mut self, responses: bool) -> Self {
        self.responses_surface = responses;
        self
    }

    /// Mark this as an OpenAI embeddings-surface call (the `/v1/embeddings` route).
    pub fn with_embeddings_surface(mut self, embeddings: bool) -> Self {
        self.embeddings_surface = embeddings;
        self
    }

    /// Gateway-Agents: tag this call as performed by an in-app agent ON BEHALF
    /// OF the human principal. Stored under [`ACTING_AGENT_METADATA_KEY`] in
    /// [`Self::metadata`] (the existing free-form bag is the single carrier), so
    /// the invocation pipeline can read it back via [`Self::acting_agent`] and
    /// stamp the audit row's `acting_agent` attribution. The human
    /// stays the principal; the agent is a delegate.
    pub fn with_acting_agent(mut self, agent: impl Into<String>) -> Self {
        self.metadata
            .insert(ACTING_AGENT_METADATA_KEY.to_owned(), agent.into());
        self
    }

    /// The in-app agent acting on behalf of the principal, if this call was
    /// initiated by one (the [`ACTING_AGENT_METADATA_KEY`] metadata value).
    /// `None` ⇒ a human acted directly.
    pub fn acting_agent(&self) -> Option<&str> {
        self.metadata
            .get(ACTING_AGENT_METADATA_KEY)
            .map(String::as_str)
    }
}

fn is_unrestricted(mode: &InvocationMode) -> bool {
    *mode == InvocationMode::Unrestricted
}

fn is_direct(channel: &InvocationChannel) -> bool {
    *channel == InvocationChannel::Direct
}

/// Typed failure modes the gateway distinguishes pre-dispatch. The
/// `GatewayServer` adapter maps these to MCP wire shapes; future
/// non-MCP consumers (an admin "dry run a tool call" endpoint, etc.)
/// can map them to whatever shape they need without duplicating the
/// reason-extraction logic.
///
/// `Upstream` carries the original `rmcp::model::ErrorData` rather
/// than a stringified message so the typed JSON-RPC code, message,
/// and `data` envelope flow through the adapter unchanged. Before this
/// trait existed the dispatch path returned the catalog's `McpError`
/// directly to the client; threading the typed value through this
/// variant preserves that contract.
#[derive(Debug, Error)]
pub enum InvocationError {
    /// Tool name didn't include a `<server>.` qualifier, or the named
    /// `<server>` isn't in the catalog.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    /// The caller's arguments did not satisfy the immutable input schema
    /// admitted for this tool invocation. Validation happens before
    /// authorization, quota, approval, evidence, or dispatch. `reason` carries
    /// schema paths and rule labels only; it never includes argument values.
    #[error("input schema violation on `{tool}`: {reason}")]
    InputSchemaViolation { tool: String, reason: String },
    /// An input schema could not be admitted or the JSON Schema compiler
    /// rejected it. The call fails before any downstream gate or dispatch, and
    /// compiler diagnostics are excluded because they can echo schema content.
    #[error("input schema for `{tool}` is unavailable or invalid")]
    InputSchemaInvalid { tool: String },
    /// The caller imposed a read-only authority ceiling but the exact admitted
    /// snapshot can cause effects, requires an approval, or cannot prove its
    /// approval requirements. This is checked as part of tool resolution,
    /// before any downstream gate or dispatch.
    #[error("operation `{tool}` is not admitted for read-only execution")]
    ReadOnlyRequired { tool: String },
    /// The caller imposed a read-only authority ceiling on a tool that
    /// dispatches by argument, and `operation` is not one the manifest
    /// reviewed. The tool-level classification a caller would otherwise fall
    /// back to describes a set the reviewer never enumerated, so under a
    /// restricted ceiling an unreviewed operation is refused rather than
    /// admitted on the dispatch tool's own flags. Checked as part of tool
    /// resolution, before any downstream gate or dispatch.
    ///
    /// Distinct from [`Self::ReadOnlyRequired`] because the operator action
    /// differs: that one means the tool is outside the ceiling entirely, this
    /// one means the operation needs a reviewed classification.
    #[error(
        "`{tool}` dispatches by `{discriminator}` and `{operation}` is not an operation it \
         reviewed for read-only execution"
    )]
    ReadOnlyOperationRequired {
        tool: String,
        discriminator: String,
        operation: String,
    },
    /// Cedar policy denied the call. `policy_ids` is the set of policies
    /// that contributed to the deny verdict (empty when the gate is
    /// `AllowAllGate`). `reasons` is the parallel set of Cedar's
    /// per-policy human-readable reason strings, surfaced in the MCP
    /// JSON-RPC `data` envelope so an operator debugging a denial can
    /// see *why* without re-running the gate offline. May be empty when
    /// the deny came from baseline forbid (no matching policy).
    #[error("forbidden: {reason}")]
    Forbidden {
        reason: String,
        policy_ids: Vec<String>,
        reasons: Vec<String>,
    },
    /// Cedar policy returned `StepUpRequired` — the caller is otherwise
    /// authenticated but missing a scope the tool's risk class requires.
    #[error("step-up required (scope `{required_scope}`): {reason}")]
    StepUpRequired {
        required_scope: String,
        reason: String,
    },
    /// The upstream returned an error or the catalog couldn't dispatch.
    /// Carries the original `ErrorData` (not a stringified message) so
    /// the typed JSON-RPC code is preserved through the adapter — see
    /// the enum-level doc comment.
    #[error("upstream: {0}")]
    Upstream(ErrorData),
    /// The `record_required` audit emit failed and the gateway is
    /// running in `GATEWAY_AUDIT_MODE=fail_closed`. Emitted by
    /// `DefaultInvocationService::record_pre_call` (stage 9) when the
    /// resolved call is side-effecting and the durable intent row could not
    /// be persisted; the upstream dispatch never happens. The adapter
    /// at `waygate-mcp::server::GatewayServer::dispatch_tool_call`
    /// maps this variant to `McpError::internal_error` so the rmcp
    /// client sees a 5xx-shape response. The carried `String` is
    /// deliberately a sanitized fixed phrase ("evidence backend
    /// unavailable") — the full sqlx error stays on the server's
    /// `tracing::error!` log so an operator can debug, but DB host /
    /// schema / auth-failure detail never reaches the wire.
    #[error("audit unavailable (fail_closed): {0}")]
    AuditUnavailable(String),
    /// The resolved tool has `requires_approval=true`
    /// and no live HITL approval grant matched the call
    /// (principal × tool × argument_hash × time window). The adapter
    /// maps this to a structured MCP error so the client can surface
    /// the human-in-the-loop UX (request approval, wait, retry).
    /// `reason` carries operator-friendly detail; the carried
    /// `tool` is the `<server>.<tool>` qualified name so clients can
    /// route the approval request to the right place.
    ///
    /// `satisfiable` is `true` only for the "no matching live grant"
    /// refusal — the one case an operator granting approval and the
    /// client retrying the identical call can cure. The fail-closed
    /// refusals (unknown approval authority, missing catalog identity,
    /// unavailable grant store, anonymous caller) set it `false`:
    /// no retry loop can succeed until the deployment itself changes,
    /// so adapters must not invite one (e.g. by projecting the refusal
    /// into an MRTR `input_required` round trip).
    #[error("approval required for `{tool}`: {reason}")]
    ApprovalRequired {
        tool: String,
        reason: String,
        satisfiable: bool,
    },
    /// At least one rate-limit policy denied the
    /// call. `policy_name` is the operator-authored label so an
    /// admin staring at a 429 in their logs can find the policy
    /// without grepping. `retry_after_seconds` is the wall-clock
    /// interval until the bucket has at least 1 token again,
    /// which the adapter surfaces as `Retry-After` per
    /// RFC 6585 §4 (the HTTP 429 spec). The numeric `policy_id`
    /// is carried for structured-log correlation.
    #[error("rate-limited by policy `{policy_name}`; retry after {retry_after_seconds}s")]
    RateLimited {
        policy_id: uuid::Uuid,
        policy_name: String,
        retry_after_seconds: u32,
    },
    /// The calling principal's API-key profile
    /// restricts the set of upstream servers it can dispatch
    /// to, and the requested `server` isn't in the list. MCP
    /// adapter maps to a structured 403 with
    /// `error="profile_restricts_server"` data so clients can
    /// detect this distinctly from a Cedar-policy deny.
    /// `profile_name` is the operator-authored label so an
    /// operator staring at the 403 in logs can find the
    /// offending profile without grepping.
    #[error("api-key profile `{profile_name}` does not permit server `{server}`")]
    ProfileServerNotAllowed {
        profile_id: String,
        profile_name: String,
        server: String,
    },
    /// Same shape for `allowed_tools` —
    /// profile permits the server but not this specific
    /// `<server>.<tool>` qualified name.
    #[error("api-key profile `{profile_name}` does not permit tool `{tool}`")]
    ProfileToolNotAllowed {
        profile_id: String,
        profile_name: String,
        tool: String,
    },
    /// The upstream's response failed
    /// JSON-schema validation against the
    /// `mcp_tool_versions.output_schema` an operator
    /// approved. The dispatch already happened (the
    /// upstream returned a result); this variant means the
    /// gateway is REFUSING to forward the result to the
    /// caller because it doesn't match the approved
    /// contract. `reason` is the sanitized first
    /// `jsonschema` rule label and schema path
    /// (operator-friendly, NOT the full schema diff —
    /// that bloats the wire). `tool` is `<server>.<tool>`
    /// for log correlation.
    #[error("output schema violation on `{tool}`: {reason}")]
    OutputSchemaViolation { tool: String, reason: String },
    /// The catalog admitted an output schema that the JSON Schema compiler
    /// rejected. Resolution fails before dispatch, and compiler diagnostics
    /// are intentionally excluded because they can echo schema contents.
    #[error("approved output schema for `{tool}` is invalid")]
    ToolSchemaInvalid { tool: String },
    /// A response inspector refused to forward
    /// the upstream's response (PII / secret / poisoning marker
    /// match). The dispatch already happened; this is the
    /// forward-side refusal.
    ///
    /// - `tool` is `<server>.<tool>` for log correlation.
    /// - `inspector_name` is the inspector that fired (e.g.
    ///   `"pii"`) — operator-facing label; SIEM filters route
    ///   by it.
    /// - `reason` names the rule that matched but NEVER
    ///   carries the matched payload (mirrors
    ///   `OutputSchemaViolation`'s sanitization discipline).
    #[error("response blocked by inspector `{inspector_name}` on `{tool}`: {reason}")]
    ResponseInspectionBlocked {
        tool: String,
        inspector_name: &'static str,
        reason: String,
    },
    /// A compact retained-body envelope declared or resolved to more bytes
    /// than the calling runtime can materialize. The upstream tool call
    /// completed, but the gateway refuses to hand the body to that runtime.
    #[error(
        "retained response for `{tool}` is at least {minimum_response_bytes} bytes, exceeding the caller's {limit_bytes}-byte materialization budget"
    )]
    ResponseMaterializationLimit {
        tool: String,
        /// A lower bound. Declaration and post-decode checks know the exact
        /// size; a streaming predecode refusal knows only the first observed
        /// byte beyond the ceiling and must not pretend it drained the body.
        minimum_response_bytes: u64,
        limit_bytes: usize,
    },
    /// The principal has already met or exceeded an LLM token/cost
    /// budget for the current window (the lagging gate, invariant I3). The
    /// dispatch never happens. `dimension` is what was exhausted (`"tokens"` /
    /// `"cost"`); `reason` carries operator-facing detail (no prompt content).
    /// The `/v1` egress maps this to HTTP 429 `insufficient_quota` (the
    /// OpenAI-idiomatic quota-exhaustion shape).
    #[error("llm budget exhausted ({dimension}): {reason}")]
    BudgetExceeded { dimension: String, reason: String },
}

impl InvocationError {
    /// Discriminator used by audit / metric emitters. Stable across
    /// `Display` text changes so dashboards keying off this don't drift.
    pub fn kind(&self) -> &'static str {
        match self {
            InvocationError::InvalidArguments(_) => "invalid_arguments",
            InvocationError::InputSchemaViolation { .. } => "input_schema_violation",
            InvocationError::InputSchemaInvalid { .. } => "input_schema_invalid",
            InvocationError::ReadOnlyRequired { .. } => "read_only_required",
            InvocationError::ReadOnlyOperationRequired { .. } => "read_only_operation_required",
            InvocationError::Forbidden { .. } => "forbidden",
            InvocationError::StepUpRequired { .. } => "step_up_required",
            InvocationError::Upstream(_) => "upstream",
            InvocationError::AuditUnavailable(_) => "audit_unavailable",
            InvocationError::ApprovalRequired { .. } => "approval_required",
            InvocationError::RateLimited { .. } => "rate_limited",
            InvocationError::ProfileServerNotAllowed { .. } => "profile_restricts_server",
            InvocationError::ProfileToolNotAllowed { .. } => "profile_restricts_tool",
            InvocationError::OutputSchemaViolation { .. } => "output_schema_violation",
            InvocationError::ToolSchemaInvalid { .. } => "tool_schema_invalid",
            InvocationError::ResponseInspectionBlocked { .. } => "response_inspection_blocked",
            InvocationError::ResponseMaterializationLimit { .. } => "connector_result_too_large",
            InvocationError::BudgetExceeded { .. } => "budget_exceeded",
        }
    }
}

/// The outcome of an [`InvocationService::invoke`] call: either a single
/// unary result (every MCP tool call today) or a streamed sequence of chunks.
///
/// Splitting the response here is the seam the inference plane fills (see
/// `docs/inference-plane.md`): an LLM completion streams, while a tool call
/// returns one `CallToolResult` — every MCP tool-call producer wraps its
/// result as [`InvocationResponse::Unary`].
/// Keeping the unary/stream split in the response type (rather than a second
/// dispatch method) is what lets the authorize / quota / inspect / audit
/// stages stay on one path for both shapes.
pub enum InvocationResponse {
    /// A complete result, available in one piece. Today's universal shape.
    Unary(CallToolResult),
    /// An MRTR pause (SEP-2322): the upstream requires client-side input
    /// before the call can complete. Produced only on the MCP tool-call
    /// path, only when the downstream caller declared it can answer every
    /// request in the pause; the adapter relays the
    /// [`rmcp::model::InputRequiredResult`] verbatim (including the
    /// upstream's opaque `requestState`) and the caller's retry re-enters
    /// the pipeline as an ordinary call.
    InputRequired(rmcp::model::InputRequiredResult),
    /// A complete non-streaming response whose body is a provider-shaped JSON
    /// value rather than an MCP [`CallToolResult`]. Produced by the inference
    /// plane's dispatch for a non-streaming LLM call (an OpenAI-shaped
    /// chat/responses body); the egress serializes it as the HTTP JSON
    /// response. The MCP tool-call path never produces it.
    UnaryValue(Value),
    /// A streamed result: an ordered sequence of chunks ending in a terminal
    /// frame. Produced by the inference plane; the MCP tool-call
    /// adapter, which is unary, rejects it.
    Stream(InvocationStream),
}

impl std::fmt::Debug for InvocationResponse {
    // Hand-written rather than derived: the `Stream` variant holds a boxed
    // trait object with no `Debug` bound. Tests assert on `invoke`'s `Result`
    // via `unwrap_err` / `expect_err` / `{:?}`, all of which require the `Ok`
    // type to be `Debug`, so the impl is part of the contract.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unary(result) => f.debug_tuple("Unary").field(result).finish(),
            Self::InputRequired(pause) => f.debug_tuple("InputRequired").field(pause).finish(),
            Self::UnaryValue(value) => f.debug_tuple("UnaryValue").field(value).finish(),
            Self::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

/// A streamed invocation response — an ordered, `Send + 'static` sequence of
/// [`InvocationChunk`]s so it can cross an async HTTP handler boundary. Each
/// item is a `Result` so a mid-stream upstream / inspection failure surfaces
/// as a terminal error rather than a silent truncation.
pub type InvocationStream = BoxStream<'static, Result<InvocationChunk, InvocationError>>;

/// One frame of a streamed response. Deliberately transport-neutral: `event`
/// is an opaque JSON value the producer has already shaped for the client's
/// surface (the LLM-specific framing — OpenAI / Anthropic SSE shapes — lives
/// in the `waygate-llm-*` crates, per invariant I6 in
/// `docs/inference-plane.md`). The pipeline's post-dispatch stages read these
/// frames incrementally to inspect / redact and to assemble the terminal
/// usage / metadata record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationChunk {
    /// Already-shaped event payload for the client surface; relayed verbatim
    /// by the egress adapter. Opaque to this crate.
    pub event: Value,
    /// Optional SSE `event:` name. `None` → an unnamed `data:` frame, and a
    /// terminal frame renders as the OpenAI `[DONE]` sentinel (the
    /// `/v1/chat/completions` transport). `Some(name)` → a *named* event
    /// (`event: <name>\ndata: {…}`), used by the `/v1/responses` transport,
    /// which has no `[DONE]` sentinel — its terminal frame is the named
    /// `response.completed` / `response.incomplete` event itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    /// `true` on the final frame — the one carrying terminal usage / metadata
    /// the `record_outcome` stage finalizes into an audit / usage row.
    pub terminal: bool,
}

/// The dispatch contract every per-tool-call hop flows through. Today only
/// `waygate_mcp::server::GatewayServer` consumes this; future consumers
/// (admin "simulate this call", a non-MCP test harness, a federated tier-C
/// gateway hop) plug in at the same boundary.
#[async_trait]
pub trait InvocationService: Send + Sync + 'static {
    async fn invoke(
        &self,
        principal: Option<&Principal>,
        req: InvocationRequest,
    ) -> Result<InvocationResponse, InvocationError>;
}

/// Type-erased handle. Cheap to clone (Arc under the hood). Used by
/// `waygate-mcp::server::GatewayServer` so the rmcp handler doesn't carry
/// a concrete impl in its type parameters.
pub type SharedInvocation = std::sync::Arc<dyn InvocationService>;

// ---------------------------------------------------------------
// HITL approval notification surface.
// ---------------------------------------------------------------
//
// When [`InvocationService`] denies a call with
// [`InvocationError::ApprovalRequired`], operators need to learn
// about the pending request without polling the admin REST
// surface. The gateway publishes a [`HitlApprovalNeeded`] event
// through whatever [`HitlNotifier`] the composition root wired up
// — today that's the WebSocket hub in `waygate-admin::hitl_ws`,
// but a Slack notifier / pager / queue could plug in here without
// touching `waygate-mcp::DefaultInvocationService`. The trait
// stays here (in `waygate-invocation`) so the invocation crate
// doesn't grow a dep on `waygate-admin`.

/// One operator-actionable HITL event the invocation pipeline
/// hands to the notifier when an `ApprovalRequired` denial would
/// be raised. The wire shape on the WebSocket side adds
/// timestamping + a TTL; this struct is the minimum identifying
/// payload (tenant + principal + tool + argument hash) so future
/// notifier implementations don't have to plumb a wider type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlApprovalNeeded {
    /// Tenant id the calling principal resolved to. Notifiers MUST
    /// filter their subscribers by this so cross-tenant operator
    /// visibility doesn't leak.
    pub tenant_id: String,
    /// OIDC `sub` of the calling principal.
    pub principal_sub: String,
    /// Issuer that minted the calling principal's `sub`. Grant minting
    /// binds ownership to tenant + issuer + subject, so the approving
    /// operator's surface must carry it through from here.
    pub principal_issuer: String,
    /// Upstream server name (matches `InvocationRequest::server`).
    pub server: String,
    /// Bare tool name (matches `InvocationRequest::tool`).
    pub tool: String,
    /// Canonical argument hash — same value the admin REST grant-
    /// creation handler computes. An operator approving the
    /// notification will mint a grant bound to this exact hash.
    pub argument_hash: String,
    /// Reviewed behavior hash of the tool version that triggered the denial.
    /// The operator echoes it when minting the grant so the authorization is
    /// bound to the contract they reviewed; if the tool's approved behavior
    /// changed by the time the grant POST lands, minting refuses.
    pub behavior_hash: String,
}

/// Best-effort notifier the invocation pipeline calls when an
/// `ApprovalRequired` denial is about to be raised. The contract
/// is fire-and-forget — a notifier failure must not affect the
/// denial path. Implementations should never block or take >a few
/// ms; queue + return.
pub trait HitlNotifier: Send + Sync + 'static {
    fn notify_approval_needed(&self, event: HitlApprovalNeeded);
}

/// Type-erased handle. Cheap to clone (Arc under the hood).
pub type SharedHitlNotifier = std::sync::Arc<dyn HitlNotifier>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builder_sets_fields() {
        let mut args = serde_json::Map::new();
        args.insert("k".into(), Value::String("v".into()));
        let req = InvocationRequest::new("example-messages", "send_msg").with_arguments(Some(args));
        assert_eq!(req.server, "example-messages");
        assert_eq!(req.tool, "send_msg");
        assert!(req.arguments.is_some());
        assert!(req.metadata.is_empty());
        // No agent tag ⇒ acting_agent() is None (a direct human call).
        assert_eq!(req.acting_agent(), None);
    }

    #[test]
    fn acting_agent_round_trips_through_metadata() {
        // The agent tag is carried in the existing metadata bag under the
        // well-known key, and read back via the typed getter — one spelling
        // shared by the producer (agent loop) and consumer (pipeline).
        let tagged =
            InvocationRequest::new("example-messages", "send").with_acting_agent("agent:ops-chat");
        assert_eq!(tagged.acting_agent(), Some("agent:ops-chat"));
        assert_eq!(
            tagged
                .metadata
                .get(ACTING_AGENT_METADATA_KEY)
                .map(String::as_str),
            Some("agent:ops-chat"),
            "the agent tag lives under the well-known metadata key",
        );
    }

    #[test]
    fn invocation_error_kind_strings_are_stable() {
        // Constructed individually because `Upstream` carries an
        // `ErrorData` (not `Clone`-able in a way that fits this
        // table-driven shape).
        assert_eq!(
            InvocationError::InvalidArguments("x".into()).kind(),
            "invalid_arguments",
        );
        assert_eq!(
            InvocationError::InputSchemaViolation {
                tool: "example-messages.send".into(),
                reason: "required field `message` is missing".into(),
            }
            .kind(),
            "input_schema_violation",
        );
        assert_eq!(
            InvocationError::InputSchemaInvalid {
                tool: "example-messages.send".into(),
            }
            .kind(),
            "input_schema_invalid",
        );
        assert_eq!(
            InvocationError::Forbidden {
                reason: "x".into(),
                policy_ids: Vec::new(),
                reasons: Vec::new(),
            }
            .kind(),
            "forbidden",
        );
        assert_eq!(
            InvocationError::StepUpRequired {
                required_scope: "x".into(),
                reason: "y".into(),
            }
            .kind(),
            "step_up_required",
        );
        assert_eq!(
            InvocationError::Upstream(ErrorData::internal_error("x", None)).kind(),
            "upstream",
        );
        assert_eq!(
            InvocationError::AuditUnavailable("x".into()).kind(),
            "audit_unavailable",
        );
        assert_eq!(
            InvocationError::ApprovalRequired {
                tool: "example-messages.send".into(),
                reason: "x".into(),
                satisfiable: true,
            }
            .kind(),
            "approval_required",
        );
        assert_eq!(
            InvocationError::OutputSchemaViolation {
                tool: "example-messages.send".into(),
                reason: "missing field `ok`".into(),
            }
            .kind(),
            "output_schema_violation",
        );
        assert_eq!(
            InvocationError::ToolSchemaInvalid {
                tool: "example-messages.send".into(),
            }
            .kind(),
            "tool_schema_invalid",
        );
        assert_eq!(
            InvocationError::ResponseInspectionBlocked {
                tool: "example-messages.send".into(),
                inspector_name: "pii",
                reason: "matched PII rule `US_SSN`".into(),
            }
            .kind(),
            "response_inspection_blocked",
        );
    }

    #[test]
    fn a_name_only_identity_serializes_exactly_as_it_did_before_operations() {
        // Code Mode stores this identity as raw JSON and compares the stored
        // text against a freshly serialized binding when an execution resumes.
        // A key that earlier snapshots could not contain would fail every
        // in-flight execution on the deploy that introduced it, so a tool
        // classified by name alone must produce the same bytes as before.
        let stored = serde_json::json!({
            "authority": {
                "authority": "catalog",
                "tool_id": "9f1c0f4e-0000-0000-0000-000000000001",
                "catalog_schema_hash": "abc",
            },
            "input_schema_hash": null,
            "output_schema_hash": null,
            "tool_annotations_hash": null,
            "action_metadata_hash": null,
            "risk": "low",
            "side_effects": false,
            "pii": false,
            "requires_approval": false,
            "requires_approval_known": true,
        });

        let identity = InvocationContractIdentity {
            authority: InvocationContractAuthority::Catalog {
                tool_id: "9f1c0f4e-0000-0000-0000-000000000001".to_owned(),
                catalog_schema_hash: "abc".to_owned(),
            },
            input_schema_hash: None,
            output_schema_hash: None,
            tool_annotations_hash: None,
            action_metadata_hash: None,
            operations_hash: None,
            risk: InvocationRisk::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };

        assert_eq!(
            serde_json::to_value(&identity).expect("identity serializes"),
            stored,
            "an absent operations hash must not appear on the wire"
        );
    }

    #[test]
    fn a_per_operation_identity_carries_its_hash() {
        let identity = InvocationContractIdentity {
            authority: InvocationContractAuthority::SyntheticModel,
            input_schema_hash: None,
            output_schema_hash: None,
            tool_annotations_hash: None,
            action_metadata_hash: None,
            operations_hash: Some("digest".to_owned()),
            risk: InvocationRisk::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };

        let rendered = serde_json::to_value(&identity).expect("identity serializes");
        assert_eq!(rendered["operations_hash"], "digest");
    }
}
