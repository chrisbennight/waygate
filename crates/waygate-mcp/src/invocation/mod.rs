//! `DefaultInvocationService` — the concrete `InvocationService` impl that
//! drives the per-tool-call pipeline.
//!
//! Composes the three load-bearing collaborators:
//!
//! - [`SharedCatalog`] — resolves `<server>.<tool>` into upstream calls
//!   and exposes per-tool classification facts (risk / side-effects / PII).
//! - [`SharedAuthz`] — Cedar (or `AllowAllGate`) verdicts.
//! - [`SharedEvidence`] — durable audit-log writes.
//!
//! ## Pipeline
//!
//! [`DefaultInvocationService::invoke`] runs fifteen named stages. Each
//! stage is a private async method on `DefaultInvocationService`, keeping
//! the rate-limit gate, HITL approval gate, output validator, and DLP
//! inspector visible in one explicit orchestrator.
//!
//! [`InvocationStage::ALL`] is the canonical identifier, order, description,
//! and implementation-status catalog. The orchestrator below pairs each
//! catalog entry with its named method at the call site; early returns stop
//! observation before later stages. The marked lifecycle table in
//! `docs/architecture.md` is checked against the catalog by a unit test, so
//! code order/status and normative prose cannot change independently.
//!
//! The orchestrator wires the stages together with explicit state carried
//! in [`InvocationContext`] — a request-scoped mutable bag that earlier
//! stages populate and later stages read. Keeping the state visible at
//! the call sites means a future "swap stage N for a decorator" change
//! reads the same shape it has today.

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rmcp::model::CallToolResult;
use rmcp::ErrorData;
use waygate_invocation::{
    InvocationChunk, InvocationError, InvocationMode, InvocationRequest, InvocationResponse,
    InvocationService, InvocationStream,
};
use waygate_llm_dispatch::{
    DispatchOutcome, LlmDispatcher, LlmModelResolver, LlmOperation, ModelRisk, ProviderSseStream,
    ResolvedModel,
};
use waygate_llm_translate::{
    parse_chat_completions, parse_embeddings, parse_responses, EmbeddingsRequest,
};
use waygate_oidc::Principal;

use crate::audit::{AuditEvent, AuditMode, AuditOutcome, EvidenceCategory, SharedEvidence};
use crate::authz::{AuthzVerdict, SharedAuthz, ToolFacts};
use crate::catalog::{
    InvocationToolSnapshot, ResolutionAuthority, ResolvedInvocationTool, SharedCatalog,
};
use crate::protocol::RiskTier;
use crate::tool_schema::input_schema_value_has_object_root;

mod approval;
mod catalog_resolution;
pub mod continuation;
mod files;
mod llm;
pub(crate) mod mrtr;
mod outcome;
mod result_trust;
mod retained_response;
mod schema_cache;
mod stage;
mod stream;
mod validation;
use schema_cache::CachedValidator;
pub use schema_cache::SchemaValidatorCache;
pub use stage::{
    InvocationStage, InvocationStageObserver, InvocationStageStatus, SharedInvocationStageObserver,
};
pub(crate) use stream::decision_inputs;
pub use validation::sanitize_validation_error;
use validation::{check_value_against_validator, SchemaCheck};

pub struct DefaultInvocationService {
    catalog: SharedCatalog,
    authz: SharedAuthz,
    audit: SharedEvidence,
    /// Failure posture the `record_pre_call` stage branches on. Defaults
    /// to [`AuditMode::BestEffort`] so the existing
    /// `DefaultInvocationService::new(catalog, authz, audit)` constructor
    /// preserves the default behaviour. Operators flip to
    /// [`AuditMode::FailClosed`] via `GATEWAY_AUDIT_MODE=fail_closed`,
    /// wired in `waygate-server::main` through the `with_audit_mode`
    /// builder.
    audit_mode: AuditMode,
    /// Governed catalog handle for the HITL approval
    /// check_approval stage. `Some` ⇒ when a resolved tool has
    /// `requires_approval=true`, the stage atomically claims a
    /// matching grant or refuses dispatch; `None` is a no-op only for
    /// snapshots that authoritatively require no approval. A required or
    /// unknown approval state fails closed without a grant store. Wired via
    /// [`Self::with_catalog_store`] from `waygate-server::main`
    /// when a Postgres pool exists.
    catalog_store: Option<waygate_catalog::SharedCatalogStore>,
    /// Rate-limit gate. `Some` ⇒ the
    /// `check_quota` stage walks every matching policy and 429s
    /// on the first denial; `None` ⇒ the stage stays a no-op
    /// (the no-op default; single-tenant / DB-less deployments
    /// don't run rate limits). Wired via [`Self::with_quota`]
    /// from `waygate-server::main` when a Postgres pool exists.
    quota: Option<std::sync::Arc<dyn waygate_quota::QuotaService>>,
    /// Best-effort notifier the `check_approval`
    /// stage hands a [`waygate_invocation::HitlApprovalNeeded`]
    /// event to whenever it's about to raise
    /// `InvocationError::ApprovalRequired`. `Some` ⇒ operators
    /// subscribed to the admin WebSocket (or whichever notifier
    /// the composition root wired) see real-time approval
    /// requests; `None` ⇒ stage stays silent on denial but still
    /// returns the same error. Wired via
    /// [`Self::with_hitl_notifier`] from `waygate-server::main`.
    hitl_notifier: Option<waygate_invocation::SharedHitlNotifier>,
    /// Response inspectors that
    /// run on the upstream's `CallToolResult` before it's
    /// forwarded to the caller. Empty by default → stage 11 is
    /// a no-op (the default). Operators opt in by
    /// wiring inspectors via [`Self::with_inspectors`];
    /// `waygate-server::main` constructs the built-ins
    /// ([`crate::inspection::pii::PiiInspector`],
    /// [`crate::inspection::secrets::SecretsInspector`],
    /// [`crate::inspection::poisoning::PoisoningInspector`]) when
    /// their respective env vars are set.
    ///
    /// Order matters: each inspector sees the response in
    /// turn; the first [`Decision::Block`](crate::inspection::Decision::Block)
    /// short-circuits the chain. A
    /// [`Decision::Redact`](crate::inspection::Decision::Redact)
    /// replaces the working result so subsequent inspectors
    /// see the redacted output (redactions compose). See
    /// [`crate::inspection`] for the full chain contract.
    inspectors: Vec<crate::inspection::SharedInspector>,
    /// Optional handler for caller-provided gateway files. It streams annotated
    /// files to the selected upstream and replaces only their private references.
    file_input_processor: Option<crate::files::SharedFileInputProcessor>,
    /// Optional handler for upstream-produced files. It saves bytes outside MCP,
    /// replaces private references, and leaves ordinary non-file calls unchanged.
    file_output_processor: Option<crate::files::SharedFileOutputProcessor>,
    /// Seals this gateway's MRTR continuation state; see [`continuation`].
    continuation_sealer: Option<Arc<continuation::ContinuationSealer>>,
    /// The inference-plane dispatch path. When both are `Some`, the
    /// `invoke` fast-path consults the resolver first; a recognized model is
    /// dispatched through the inference plane — reusing the *same* authorize /
    /// quota / approval / pre-call gates as the MCP path (invariant I1) —
    /// instead of `catalog.call_tool`. `None` ⇒ no LLM path at all (DB-less /
    /// inference-disabled deployments behave exactly as before). Wired via
    /// [`Self::with_llm`] from `waygate-server::main`.
    llm_dispatcher: Option<LlmDispatcher>,
    llm_resolver: Option<Arc<dyn LlmModelResolver>>,
    /// Per-call inference usage ledger. `Some` ⇒ the LLM path's
    /// record_outcome stage persists an [`LlmUsageRow`](crate::usage::LlmUsageRow)
    /// (tokens / served model / finish reason / latency, and later cost) for
    /// every completed call; `None` ⇒ usage is not recorded (DB-less
    /// deployments). Wired via [`Self::with_llm_usage_store`] from
    /// `waygate-server::main`. Best-effort — a ledger write never fails the
    /// already-served response.
    llm_usage: Option<crate::usage::SharedLlmUsage>,
    /// Lagging LLM budget gate. `Some` ⇒ the LLM path's check_quota
    /// stage refuses the call when the principal is already over an applicable
    /// token/cost budget (I3, reading the recorded `llm_usage` ledger); `None`
    /// ⇒ no budget enforcement. Wired via [`Self::with_llm_budget`].
    llm_budget: Option<crate::budget::SharedLlmBudgetGate>,
    /// Per-principal exact-match completion cache. `Some` ⇒ a model
    /// configured with a cache TTL checks this before dispatch (a hit replays
    /// the stored response, free) and stores a unary completion after a miss;
    /// `None` ⇒ caching is off. Wired via [`Self::with_llm_cache`].
    llm_cache: Option<crate::cache::SharedLlmCache>,
    /// Optional recorder for finite MCP-tool stage-entry events. Production
    /// leaves it unwired; contract tests use it to prove the explicit MCP
    /// orchestrator follows [`InvocationStage::ALL`] and stops at the rejecting
    /// gate. LLM-specific paths document their partial stage reuse separately.
    stage_observer: Option<SharedInvocationStageObserver>,
    /// Process-wide fixed-capacity cache of validators compiled for exact
    /// admitted input and output schemas. Production injects one shared handle
    /// into every per-session service and the admin try-it service.
    schema_validator_cache: Arc<SchemaValidatorCache>,
}

impl DefaultInvocationService {
    pub fn new(catalog: SharedCatalog, authz: SharedAuthz, audit: SharedEvidence) -> Self {
        Self {
            catalog,
            authz,
            audit,
            audit_mode: AuditMode::BestEffort,
            catalog_store: None,
            quota: None,
            hitl_notifier: None,
            inspectors: Vec::new(),
            file_input_processor: None,
            file_output_processor: None,
            continuation_sealer: None,
            llm_dispatcher: None,
            llm_resolver: None,
            llm_usage: None,
            llm_budget: None,
            llm_cache: None,
            stage_observer: None,
            schema_validator_cache: SchemaValidatorCache::shared(),
        }
    }

    /// Share one bounded validator cache across independently constructed
    /// invocation-service handles.
    #[must_use]
    pub fn with_schema_validator_cache(mut self, cache: Arc<SchemaValidatorCache>) -> Self {
        self.schema_validator_cache = cache;
        self
    }

    /// Wire the inference-plane dispatch path. Both the dispatcher
    /// and the model resolver are required for the LLM fast-path to activate;
    /// without this call, `invoke` runs the MCP tool-call path exactly as
    /// before.
    #[must_use]
    pub fn with_llm(
        mut self,
        dispatcher: LlmDispatcher,
        resolver: Arc<dyn LlmModelResolver>,
    ) -> Self {
        self.llm_dispatcher = Some(dispatcher);
        self.llm_resolver = Some(resolver);
        self
    }

    /// Wire the per-call inference usage ledger. Without this call
    /// the LLM path runs exactly as before but records no usage rows.
    #[must_use]
    pub fn with_llm_usage_store(mut self, usage: crate::usage::SharedLlmUsage) -> Self {
        self.llm_usage = Some(usage);
        self
    }

    /// Wire the lagging LLM budget gate. Without this call the LLM
    /// path enforces no token/cost budgets.
    #[must_use]
    pub fn with_llm_budget(mut self, budget: crate::budget::SharedLlmBudgetGate) -> Self {
        self.llm_budget = Some(budget);
        self
    }

    /// Wire the per-principal completion cache. Without this call the
    /// LLM path never caches (even for a model configured with a cache TTL).
    #[must_use]
    pub fn with_llm_cache(mut self, cache: crate::cache::SharedLlmCache) -> Self {
        self.llm_cache = Some(cache);
        self
    }

    /// Attach an observer for MCP-tool stage-entry contract tests or
    /// finite-label telemetry. `None` is the production default and performs
    /// no dynamic dispatch on the invocation path. The LLM arm has specialized
    /// resolve/validation/dispatch/finalization and does not emit this MCP-only
    /// catalog.
    #[must_use]
    pub fn with_stage_observer(mut self, observer: SharedInvocationStageObserver) -> Self {
        self.stage_observer = Some(observer);
        self
    }

    /// Install the response-inspector chain.
    /// Inspectors run in the order supplied, on every
    /// successful upstream response. An empty vec keeps
    /// stage 11 as a no-op (the default).
    #[must_use]
    pub fn with_inspectors(mut self, inspectors: Vec<crate::inspection::SharedInspector>) -> Self {
        self.inspectors = inspectors;
        self
    }

    /// Attach the HITL notifier so the
    /// `check_approval` stage emits a real-time event whenever a
    /// `requires_approval=true` tool denies dispatch. The contract
    /// is best-effort: a `None` notifier OR a notifier that silently
    /// drops events (e.g. no WebSocket subscribers) MUST NOT change
    /// the dispatch decision or the error returned to the caller.
    #[must_use]
    pub fn with_hitl_notifier(
        mut self,
        notifier: Option<waygate_invocation::SharedHitlNotifier>,
    ) -> Self {
        self.hitl_notifier = notifier;
        self
    }

    /// Attach the quota / rate-limit service.
    /// Without it, the `check_quota` stage stays a no-op and
    /// no rate-limit policies are enforced; with it, every
    /// invocation runs through `QuotaService::check_and_consume`
    /// and a deny becomes `InvocationError::RateLimited`. The
    /// composition root wires this when a Postgres pool exists.
    #[must_use]
    pub fn with_quota(
        mut self,
        quota: Option<std::sync::Arc<dyn waygate_quota::QuotaService>>,
    ) -> Self {
        self.quota = quota;
        self
    }

    /// Attach the governed-catalog store so the
    /// `check_approval` stage can run the HITL grant claim. Without
    /// it, the stage stays a no-op and `requires_approval=true`
    /// tools effectively dispatch unblocked — operators wanting
    /// enforcement must wire a DB-backed catalog.
    #[must_use]
    pub fn with_catalog_store(
        mut self,
        catalog_store: Option<waygate_catalog::SharedCatalogStore>,
    ) -> Self {
        self.catalog_store = catalog_store;
        self
    }

    /// Switch to `FailClosed`. When set and the resolved call is
    /// side-effecting (`facts.side_effects` — the mutating surface, incl. LLM
    /// completions), `record_pre_call` calls `record_required` and surfaces
    /// `InvocationError::AuditUnavailable` on persistence failure so the
    /// upstream call never happens without a durable evidence-of-attempt
    /// row. Read-only (`!side_effects`) calls have no required pre-call row and
    /// retain chained-best-effort final evidence — the operator opts in to
    /// "required pre-call evidence for the mutating surface," not "required
    /// evidence for everything." The gate deliberately follows
    /// `side_effects` rather than the risk tier so reclassification cannot
    /// remove the fail-closed guarantee from a mutating tool.
    #[must_use]
    pub fn with_audit_mode(mut self, mode: AuditMode) -> Self {
        self.audit_mode = mode;
        self
    }

    /// Convenience: wrap `Self` in an `Arc<dyn InvocationService>` for the
    /// `GatewayServer::with_invocation_service` setter and any future
    /// composition root that holds the trait by handle.
    pub fn shared(self) -> Arc<dyn InvocationService> {
        Arc::new(self)
    }

    #[inline]
    fn enter_stage(&self, stage: InvocationStage) {
        if let Some(observer) = self.stage_observer.as_ref() {
            observer.enter(stage);
        }
    }
}

/// Build a fully-wired [`DefaultInvocationService`] from the composition
/// root's `Arc` handles, applying every governance stage in one place.
///
/// # Why this exists
///
/// There are now **two** call sites that need an identically-governed
/// invocation service: the per-session rmcp factory in `main.rs` (the
/// real MCP-client dispatch path) and the admin dashboard's governed
/// "Try this tool" surface (`waygate-admin`). The security contract of
/// the try-it surface is that it routes a real call through the *same*
/// `authorize → step-up → quota → HITL → audit → redact` pipeline a
/// client would hit — **never a bypass with weaker stages**.
///
/// Centralising construction here makes that contract *structural*
/// rather than a convention two call sites must remember to keep in
/// sync: add a stage (a new `with_*`) and both the client path and the
/// admin try-it path pick it up. A drift between them would be exactly
/// the "dashboard launders ungoverned calls" hazard the audit warned
/// about, so the duplication is deliberately collapsed.
///
/// The service holds only `Arc` handles and carries no per-call mutable
/// state, so a single instance is safely shared across sessions and
/// across the admin surface; it is built per-session in `main.rs` only
/// because `GatewayServer` is (per-session `DisclosedTools`), not
/// because the service itself is session-scoped.
#[allow(clippy::too_many_arguments)]
pub fn build_default_invocation_service(
    catalog: SharedCatalog,
    authz: SharedAuthz,
    audit: SharedEvidence,
    audit_mode: AuditMode,
    catalog_store: Option<waygate_catalog::SharedCatalogStore>,
    quota: Option<std::sync::Arc<dyn waygate_quota::QuotaService>>,
    hitl_notifier: Option<waygate_invocation::SharedHitlNotifier>,
    inspectors: Vec<crate::inspection::SharedInspector>,
    file_input_processor: Option<crate::files::SharedFileInputProcessor>,
    file_output_processor: Option<crate::files::SharedFileOutputProcessor>,
    // Seals MRTR continuation state; see [`continuation`].
    continuation_sealer: Option<Arc<continuation::ContinuationSealer>>,
    // Process-wide admitted-schema validator cache. The composition root
    // passes the same handle to per-session MCP services and the admin try-it
    // service, keeping total residency bounded across all entry points.
    schema_validator_cache: Arc<SchemaValidatorCache>,
    // The inference-plane dispatch path. `Some` wires the LLM
    // fast-path (a recognized model dispatches through the inference plane,
    // reusing every pipeline stage); `None` keeps the MCP-only behaviour. Both
    // the client and admin try-it paths flow through here, so they pick it up
    // identically (no ungoverned bypass).
    llm: Option<(LlmDispatcher, Arc<dyn LlmModelResolver>)>,
    // Per-call inference usage ledger. `Some` ⇒ completed LLM
    // calls persist a usage row; `None` ⇒ no usage recording. Threaded through
    // here (not set out-of-band) so the client and admin try-it paths record
    // identically.
    llm_usage: Option<crate::usage::SharedLlmUsage>,
    // Lagging LLM budget gate. `Some` ⇒ the LLM path refuses calls
    // over an applicable token/cost budget; `None` ⇒ no enforcement. Threaded
    // here so client + admin try-it paths gate identically.
    llm_budget: Option<crate::budget::SharedLlmBudgetGate>,
    // Per-principal completion cache. `Some` ⇒ a model with a configured
    // cache TTL serves hits / stores misses; `None` ⇒ no caching. Threaded here
    // so client + admin try-it paths cache identically.
    llm_cache: Option<crate::cache::SharedLlmCache>,
) -> Arc<DefaultInvocationService> {
    let mut service = DefaultInvocationService::new(catalog, authz, audit)
        .with_audit_mode(audit_mode)
        .with_catalog_store(catalog_store)
        .with_quota(quota)
        .with_hitl_notifier(hitl_notifier)
        .with_inspectors(inspectors)
        .with_file_input_processor(file_input_processor)
        .with_file_output_processor(file_output_processor)
        .with_continuation_sealer(continuation_sealer)
        .with_schema_validator_cache(schema_validator_cache);
    if let Some((dispatcher, resolver)) = llm {
        service = service.with_llm(dispatcher, resolver);
    }
    if let Some(usage) = llm_usage {
        service = service.with_llm_usage_store(usage);
    }
    if let Some(budget) = llm_budget {
        service = service.with_llm_budget(budget);
    }
    if let Some(cache) = llm_cache {
        service = service.with_llm_cache(cache);
    }
    Arc::new(service)
}

/// Mutable per-invocation state threaded through the pipeline stages.
/// Earlier stages populate fields later stages depend on; keeping the
/// dependency edges visible at the call sites means a future "swap stage
/// N for a decorator" change reads the same shape it does today. Borrows
/// from the `InvocationRequest` (server / tool / arguments) so the
/// orchestrator hands stages owned strings via clones only at the moments
/// where ownership actually transfers (audit events, error variants).
struct InvocationContext<'a> {
    principal: Option<&'a Principal>,
    server: &'a str,
    tool: &'a str,
    invocation_id: uuid::Uuid,
    /// Immutable catalog/manifest view admitted by `resolve_tool`. Every later
    /// MCP stage reads facts, approval identity, and schemas from this one
    /// snapshot; no stage re-resolves governed tool state after admission.
    tool_snapshot: Option<InvocationToolSnapshot>,
    /// The admitted classification refined for the operation THIS call selects.
    ///
    /// Held beside the snapshot rather than written into it. The snapshot's own
    /// facts are part of its contract identity, which the dispatch-time
    /// re-check rebuilds without the call's arguments; refining them in place
    /// would make every per-operation call fail that comparison. Identity
    /// answers which reviewed definition is bound, this answers what the caller
    /// asked that definition to do.
    effective_facts: Option<ToolFacts>,
    /// Discriminator value this call carried, when the tool names one.
    /// Recorded for the audit trail even when no entry classified it.
    operation: Option<String>,
    /// Whether a reviewed entry classified the operation this call selected.
    ///
    /// Only meaningful when the snapshot names a discriminator; `false`
    /// otherwise, because a tool classified by name alone selects no operation
    /// at all. Distinguishes "the reviewer classified this" from "this fell
    /// back to the tool's own entry", which the read-only ceiling needs and
    /// `operation` alone cannot answer — a value is recorded for the audit
    /// trail whether or not an entry named it.
    operation_classified: bool,
    /// Typed PIP facts assembled by `extract_facts` from `facts` +
    /// `principal`. `Some` only when a `principal` is present (the
    /// authz gate is skipped for anonymous dev-mode calls). Consumed by
    /// `authorize`.
    pip_facts: Option<waygate_core::Facts>,
    /// JSON arguments handed to the upstream by `dispatch`. Owned because
    /// `dispatch` calls `catalog.call_tool` with `req.arguments`, which
    /// moves the value. The orchestrator takes the arguments out of the
    /// `InvocationRequest` once and stashes them here.
    arguments: Option<serde_json::Map<String, serde_json::Value>>,
    /// MRTR round-trip state (SEP-2322), taken from the request once like
    /// `arguments`: the caller's retry payload flows to the upstream
    /// verbatim, and the caller's declared capabilities gate whether an
    /// upstream pause may be forwarded back (and are mirrored into a
    /// per-call upstream dial so the upstream pauses only when the caller
    /// can answer). Consumed by `dispatch`; the capabilities are read
    /// again when classifying the dispatch outcome.
    mrtr: crate::catalog::ToolCallMrtr,
    /// Set by `dispatch` so `record_outcome` can stamp `latency_ms` on
    /// the row regardless of success / failure outcome.
    latency_ms: Option<i64>,
    /// Fired Cedar policy ids from the authorize stage, recorded in the
    /// success audit row — the allow-decision twin of the deny path's
    /// `.with_policies`. Populated by `authorize` on an `Allow` (the
    /// permits that matched); empty for anonymous (gate-skipped) calls and
    /// for an `AllowAllGate` allow that fired no Cedar permit.
    authz_policy_ids: Vec<String>,
    /// Per-inspector redaction
    /// records (inspector name + findings count) accumulated by
    /// `inspect_response` but NOT yet emitted as audit rows or
    /// metric bumps. The orchestrator drains this list AFTER
    /// `validate_output` confirms the redacted response will
    /// actually be forwarded — otherwise telemetry would claim
    /// "forwarded N redactions" for a response the schema
    /// validator went on to reject.
    pending_redactions: Vec<(&'static str, u32)>,
    /// The `EvidenceCategory` every audit row this call emits is stamped with.
    /// Defaults to `Invocation` (the MCP tool-call plane). The LLM fast-path
    /// flips it to `LlmCompletion` before the shared gates run, so a call's
    /// denial / step-up / rate-limit / profile / pre-call rows AND its
    /// completion row all route to the inference plane — not just the success
    /// row. One source of truth: the gate methods are shared with the MCP path,
    /// which leaves this `Invocation`, so reading it is a no-op there. Mirrors
    /// how `Invocation` already spans the whole MCP tool-call lifecycle,
    /// denials included.
    audit_category: EvidenceCategory,
    /// LLM fast-path only: the call arrived on the OpenAI Responses client surface
    /// (`POST /v1/responses`). `invoke_llm` reads it to select the Responses
    /// request parser (which sets `LlmRequest::inbound_surface`, in turn selecting
    /// the Responses egress in dispatch). `false` for `/v1/chat/completions` and
    /// every MCP tool call.
    responses_surface: bool,
    /// LLM fast-path only: the call arrived on the OpenAI embeddings client surface
    /// (`POST /v1/embeddings`). The fast-path branches to `invoke_embeddings` and
    /// uses this to reject a surface/operation mismatch (an embeddings model on a
    /// chat route, or a chat model on `/v1/embeddings`). `false` for the chat
    /// surfaces and every MCP tool call.
    embeddings_surface: bool,
    images_surface: Option<waygate_invocation::ImagesSurface>,
    /// The in-app agent acting on the human principal's
    /// behalf (`agent:<name>`), carried from `InvocationRequest::acting_agent`.
    /// Stamped onto every audit row this call emits (`AuditEvent.acting_agent`)
    /// so the log attributes the action to the agent without losing the human as
    /// the authorizing principal. `None` for a direct (non-agent) call. Borrowed
    /// from `req`, like `server` / `tool`.
    acting_agent: Option<&'a str>,
    /// Optional parent execution and nested call-attempt attribution carried
    /// by orchestrated callers. Direct calls leave this absent.
    invocation_hierarchy: Option<waygate_core::InvocationHierarchy>,
    /// Exact durable Code Mode operation whose one-time approval grant may be
    /// claimed. Direct calls leave this absent.
    approval_binding: Option<waygate_invocation::InvocationApprovalBinding>,
    /// The gateway surface this call originated from, stamped by the
    /// gateway-side producer of the request. Surfaced to Cedar as
    /// `context.channel`.
    channel: waygate_invocation::InvocationChannel,
    /// Caller-runtime budget for materializing a retained response.
    response_materialization_limit_bytes: Option<usize>,
    response_delivery: waygate_invocation::ResponseDelivery,
    retained_response: std::sync::Mutex<Option<retained_response::RecoveredResponse>>,
    retained_operation_succeeded: std::sync::atomic::AtomicBool,
    /// `Some(policy_ids)` when the authorize stage returned
    /// `ApprovalRequired`: Cedar's approval overlay is the only policy
    /// standing between this call and an allow, so `check_approval` must
    /// claim a live grant regardless of the catalog classification flag.
    cedar_approval_policies: Option<Vec<String>>,
    /// Set by `check_approval` when the claimed grant satisfied a Cedar
    /// `ApprovalRequired` verdict; the success audit row records it so
    /// decision replay reproduces the policy verdict.
    policy_gated_grant_consumed: bool,
    /// This call's continuation identity and delivery authorization.
    continuation: continuation::CallState,
    /// The cached compiled input-schema validator `validate_input` used, kept
    /// so later stages (file admission and delivery) evaluate the same
    /// admitted schema without recompiling it on the request path.
    compiled_input_validator: Option<std::sync::Arc<jsonschema::Validator>>,
}

impl<'a> InvocationContext<'a> {
    fn audit_event(&self, action: impl Into<String>, outcome: AuditOutcome) -> AuditEvent {
        let mut event = AuditEvent::new(action, outcome)
            .with_acting_agent(self.acting_agent.map(str::to_owned))
            .with_invocation_hierarchy(self.invocation_hierarchy);
        // Every audited row on this path is built here, so the operation is
        // stamped once rather than at each call site. `None` until the resolve
        // stage has run, which is right for the rows emitted before it —
        // nothing had selected an operation yet.
        event.operation = self.operation.clone();
        event
    }

    /// `ToolFacts` is populated by `resolve_tool`; the value is `Some`
    /// from stage 1 onward. Callers downstream of that stage hit this
    /// accessor; if they reach here with `None`, the orchestrator
    /// invariant is violated (always a bug, never a runtime concern).
    /// The classification this call is authorized, audited, and redacted
    /// under: the admitted facts, refined when an operator classified the
    /// operation the arguments select.
    ///
    /// Populated alongside `tool_snapshot`, so it is `Some` from stage 1 on for
    /// exactly the same reason. Paths comparing contract identity read
    /// `tool_snapshot().facts()` instead — see `effective_facts`.
    fn facts(&self) -> &ToolFacts {
        self.effective_facts.as_ref().expect(
            "stage invariant: resolve_tool must populate `effective_facts` before this stage runs",
        )
    }

    /// Admit the resolved snapshot together with the classification this call
    /// is governed under.
    ///
    /// One operation, so a path that admits a snapshot cannot leave the
    /// per-operation overlay unset and strand every later stage without facts.
    fn admit_snapshot(&mut self, snapshot: InvocationToolSnapshot) -> Result<(), InvocationError> {
        let resolution = snapshot.resolve_operation(self.arguments.as_ref());
        if resolution.inadmissible {
            // Refused rather than dropped. Dispatch forwards the caller's
            // arguments unchanged, so authorizing without the operation would
            // let the upstream act on one the gate never saw and no audit row
            // names. The value is not repeated: it is caller text of unbounded
            // length, which is the reason it was refused.
            return Err(InvocationError::InvalidArguments(format!(
                "`{}` selects an operation this server will not carry: an operation name is \
                 1 to 256 printable ASCII characters and contains no spaces",
                snapshot.discriminator().unwrap_or("operation"),
            )));
        }
        self.operation = resolution.requested;
        self.operation_classified = resolution.classified;
        self.effective_facts = Some(snapshot.facts_for(self.arguments.as_ref()));
        self.tool_snapshot = Some(snapshot);
        Ok(())
    }

    fn tool_snapshot(&self) -> &InvocationToolSnapshot {
        self.tool_snapshot.as_ref().expect(
            "stage invariant: resolve_tool must populate `tool_snapshot` before this stage runs",
        )
    }

    fn tool_snapshot_mut(&mut self) -> &mut InvocationToolSnapshot {
        self.tool_snapshot.as_mut().expect(
            "stage invariant: resolve_tool must populate `tool_snapshot` before this stage runs",
        )
    }

    /// Typed PIP facts, populated by `extract_facts` whenever a
    /// principal is present. `authorize` only reaches this after the
    /// `principal is Some` guard, so the invariant holds.
    fn pip_facts(&self) -> &waygate_core::Facts {
        self.pip_facts.as_ref().expect(
            "stage invariant: extract_facts must populate `pip_facts` when a principal is present",
        )
    }
}

#[async_trait]
impl InvocationService for DefaultInvocationService {
    async fn invoke(
        &self,
        principal: Option<&Principal>,
        req: InvocationRequest,
    ) -> Result<InvocationResponse, InvocationError> {
        // Move ownership of the arguments into the context rather than
        // cloning. The pre-refactor implementation moved `req.arguments`
        // directly into `catalog.call_tool`; using `Option::take` here
        // matches that — leaves `None` on `req` (we never read
        // `req.arguments` again from `req` after this) while keeping
        // `req.server` / `req.tool` alive for `ctx.server` / `ctx.tool`'s
        // `&str` borrows. A clone of a large JSON payload
        // would otherwise hit the hot path of every tool call.
        let mut req = req;
        let mode = req.mode;
        let expected_contract = req.expected_contract.take();
        let approval_binding = req.approval_binding.take();
        if let Some(binding) = approval_binding.as_ref() {
            let Some(hierarchy) = req.hierarchy else {
                return Err(InvocationError::InvalidArguments(
                    "execution-bound approval requires invocation hierarchy".to_owned(),
                ));
            };
            if binding.execution_id != hierarchy.parent_execution_id
                || binding.call_id != hierarchy.call_id
            {
                return Err(InvocationError::InvalidArguments(
                    "execution-bound approval does not match invocation hierarchy".to_owned(),
                ));
            }
        }
        let arguments = req.arguments.take();
        let mrtr = crate::catalog::ToolCallMrtr {
            input_responses: req.input_responses.take(),
            request_state: req.request_state.take(),
            caller_capabilities: req.caller_capabilities.take(),
            approval_gated: false,
        };
        let mut ctx = InvocationContext {
            principal,
            server: req.server.as_str(),
            tool: req.tool.as_str(),
            invocation_id: uuid::Uuid::new_v4(),
            tool_snapshot: None,
            effective_facts: None,
            operation: None,
            operation_classified: false,
            pip_facts: None,
            arguments,
            mrtr,
            latency_ms: None,
            authz_policy_ids: Vec::new(),
            pending_redactions: Vec::new(),
            // MCP tool-call plane by default; the LLM fast-path overrides this.
            audit_category: EvidenceCategory::Invocation,
            responses_surface: req.responses_surface,
            embeddings_surface: req.embeddings_surface,
            images_surface: req.images_surface,
            acting_agent: req.acting_agent(),
            invocation_hierarchy: req.hierarchy,
            approval_binding,
            channel: req.channel,
            response_materialization_limit_bytes: req.response_materialization_limit_bytes,
            response_delivery: req.response_delivery,
            retained_response: std::sync::Mutex::new(None),
            retained_operation_succeeded: std::sync::atomic::AtomicBool::new(false),
            cedar_approval_policies: None,
            policy_gated_grant_consumed: false,
            compiled_input_validator: None,
            continuation: continuation::CallState::default(),
        };

        // LLM fast-path. If a model resolver + dispatcher are wired
        // and the request targets a recognized model, dispatch it through the
        // inference plane, reusing the SAME authorize / quota / approval /
        // pre-call gates as the MCP path (invariant I1). A request on a
        // resolver-owned LLM namespace whose model is *not* configured is
        // rejected here — never allowed to fall through to the MCP tool path,
        // where a same-named upstream could otherwise shadow it. Anything on a
        // namespace the resolver doesn't own falls through unchanged.
        if let (Some(dispatcher), Some(resolver)) = (&self.llm_dispatcher, &self.llm_resolver) {
            if mode == InvocationMode::ReadOnly && resolver.owns_server(ctx.server) {
                self.record_read_only_refusal(&ctx).await;
                return Err(InvocationError::ReadOnlyRequired {
                    tool: format!("{}.{}", ctx.server, ctx.tool),
                });
            }
            if let Some(model) = resolver.resolve(ctx.server, ctx.tool) {
                return self.invoke_model(ctx, model, dispatcher).await;
            }
            if resolver.owns_server(ctx.server) {
                return Err(InvocationError::InvalidArguments(format!(
                    "unknown model `{}`",
                    ctx.tool
                )));
            }
        }

        // Stages run in the documented order. Each stage is a private
        // async method on `Self`, keeping the orchestration readable and
        // giving each concern one named implementation boundary.
        self.enter_stage(InvocationStage::ResolveTool);
        self.resolve_tool(&mut ctx).await?;
        if expected_contract
            .as_ref()
            .is_some_and(|expected| ctx.tool_snapshot().contract_identity() != *expected)
        {
            self.record_contract_drift_refusal(&ctx).await;
            return Err(InvocationError::InvalidArguments(format!(
                "operation contract changed during execution: {}.{}",
                ctx.server, ctx.tool
            )));
        }
        if let Err(error) = validation::enforce_invocation_mode(&ctx, mode) {
            // Two refusals, two remediations: the tool is outside the ceiling,
            // or the operation it selected has no reviewed classification. The
            // trail has to say which.
            if matches!(error, InvocationError::ReadOnlyOperationRequired { .. }) {
                self.record_read_only_operation_refusal(&ctx).await;
            } else {
                self.record_read_only_refusal(&ctx).await;
            }
            return Err(error);
        }
        self.enter_stage(InvocationStage::ValidateInput);
        self.validate_input(&mut ctx).await?;
        self.enter_stage(InvocationStage::ExtractFacts);
        self.extract_facts(&mut ctx).await?;
        self.enter_stage(InvocationStage::Authorize);
        self.authorize(&mut ctx).await?;
        // API-key profile call-time enforcement runs
        // AFTER Cedar authorize so a Cedar deny takes
        // precedence in the metric/audit shape (Cedar is the
        // primary access-control surface; the profile is an
        // operator's extra "this key can only call X" bound).
        // Runs BEFORE check_quota so a profile-rejected call
        // doesn't burn a token bucket.
        self.enter_stage(InvocationStage::CheckProfileRestrictions);
        self.check_profile_restrictions(&mut ctx).await?;
        // Output-schema health is catalog state. Compile only after Cedar and
        // caller-profile authorization succeed so a denied caller cannot use
        // the error shape as a catalog-state oracle. This remains before quota,
        // approval, required evidence, and dispatch so invalid operator state
        // consumes no irreversible resource.
        self.enter_stage(InvocationStage::PrepareOutputValidation);
        self.prepare_output_validation(&mut ctx).await?;
        // Approval-gated calls accept no MRTR continuation inputs — the
        // refusal must run BEFORE quota and BEFORE the one-time grant claim
        // (contract and rationale in `mrtr::refuse_continuation_inputs_when
        // _approval_gated`), or the refusal itself would burn resources the
        // caller cannot get back.
        mrtr::refuse_continuation_inputs_when_approval_gated(&ctx)?;
        self.verify_continuation(&mut ctx)?;
        // Deterministic file-input admission refuses (with denial evidence)
        // before quota and the one-time approval claim; rationale in
        // `files::admit_file_inputs`.
        self.admit_file_inputs(&mut ctx).await?;
        self.enter_stage(InvocationStage::CheckQuota);
        self.check_quota(&mut ctx).await?;
        self.enter_stage(InvocationStage::CheckApproval);
        self.check_approval(&mut ctx).await?;
        self.enter_stage(InvocationStage::RecordPreCall);
        self.record_pre_call(&mut ctx).await?;
        self.enter_stage(InvocationStage::PrepareFileInputs);
        if let Err(error) = self.prepare_and_validate_file_inputs(&mut ctx).await {
            let result = Err(error);
            self.enter_stage(InvocationStage::RecordOutcome);
            self.record_outcome(&mut ctx, &result).await;
            return result.map(InvocationResponse::Unary);
        }
        self.enter_stage(InvocationStage::Dispatch);
        let result = match self.dispatch(&mut ctx).await {
            Ok(rmcp::model::CallToolResponse::Complete(result)) => Ok(result),
            // `admit_pause` owns the full pause admission contract —
            // reserved-key collision, caller answerability, response
            // inspection — and its module docs state why an admitted pause
            // skips the remaining response stages. A refusal flows through
            // the normal error tail so it is audited like any dispatch
            // failure.
            Ok(rmcp::model::CallToolResponse::InputRequired(pause)) => {
                match self.admit_pause(&mut ctx, pause).await {
                    Ok(pause) => {
                        // The pausing leg is a completed upstream RPC and
                        // records its own outcome row — an abandoned round
                        // trip must still leave evidence.
                        self.enter_stage(InvocationStage::RecordOutcome);
                        self.record_pause_relay(&mut ctx).await;
                        return Ok(InvocationResponse::InputRequired(pause));
                    }
                    Err(refusal) => Err(refusal),
                }
            }
            // The gateway declares no tasks extension on the upstream leg, so
            // a conforming upstream never materializes a task for it. Refuse
            // loud rather than polling on the caller's behalf or forwarding a
            // handle the caller cannot redeem through the gateway.
            Ok(rmcp::model::CallToolResponse::Task(_)) => {
                Err(InvocationError::Upstream(ErrorData::internal_error(
                    format!(
                        "upstream `{}` returned a task envelope for `{}`, which the gateway \
                         did not request and cannot proxy",
                        ctx.server, ctx.tool
                    ),
                    None,
                )))
            }
            // `CallToolResponse` is non-exhaustive upstream; an unknown
            // variant is a wiring/SDK-upgrade bug, not a caller error.
            Ok(_) => Err(InvocationError::Upstream(ErrorData::internal_error(
                "upstream dispatch produced an unsupported response variant",
                None,
            ))),
            Err(error) => Err(error),
        };
        // Validate the value the
        // CALLER will see, not the upstream's original. If
        // validate_output ran first, inspect_response
        // could replace the result with a redacted version that
        // wouldn't satisfy the schema. Running inspect_response
        // FIRST means a strict schema (e.g. `pattern: ^\d{3}-\d{2}
        // -\d{4}$` on an SSN field) catches the case where
        // redaction produces `[REDACTED:US_SSN]` that breaks the
        // contract — the operator gets `output_schema_violation`
        // and can either disable redaction for that tool or
        // relax the schema.
        //
        // A Block from an inspector short-circuits here (Err
        // propagates), so validate_output never runs on a
        // blocked response — the same semantics for
        // the blocked path.
        self.enter_stage(InvocationStage::InspectResponse);
        let result = self.inspect_response(&mut ctx, result).await;
        // validate_output can still reject a redacted response
        // that violates the schema; flush_pending_redactions
        // MUST only run when the response is being forwarded.
        // Two failure modes to short-circuit:
        //   1. inspect_response returned Err (a LATER inspector
        //      blocked AFTER an earlier inspector redacted —
        //      `result.is_err()` here means the chain blocked).
        //   2. validate_output returned Err (the schema
        //      rejected the redacted output — propagated via
        //      `?`, never reaches flush).
        // Either way: the pending_redactions list is silently
        // discarded with `ctx` so no "forwarded N redactions"
        // telemetry fires for a response that wasn't forwarded.
        let result = self
            .prepare_files_and_validate_output(&mut ctx, result)
            .await?;
        if result.is_ok() {
            self.flush_pending_redactions(&mut ctx).await;
        }
        self.enter_stage(InvocationStage::RecordOutcome);
        self.record_outcome(&mut ctx, &result).await;
        // Every dispatch today is unary — wrap the collected
        // `CallToolResult` as `InvocationResponse::Unary`. The streaming arm
        // is produced by the inference plane; this keeps the
        // pipeline's authorize/quota/inspect/audit stages on one path.
        result.map(InvocationResponse::Unary)
    }
}

impl DefaultInvocationService {
    /// Stage 1 — parse and look up. The parse already happened at
    /// the adapter boundary (the `<server>.<tool>` split is done in
    /// `GatewayServer::dispatch_tool_call` before `InvocationRequest` is
    /// constructed) so the stage's job is to populate `ctx.tool_snapshot`
    /// from the catalog with manifest fallback. Catalog quarantine is enforced
    /// here; the actual upstream "tool not found" response still happens
    /// inside `call_tool` at dispatch time and surfaces as
    /// `InvocationError::Upstream`.
    async fn resolve_tool(&self, ctx: &mut InvocationContext<'_>) -> Result<(), InvocationError> {
        // Consult the governed catalog (tenant-aware)
        // with manifest fallback. Anonymous calls (no principal, e.g.
        // auth-disabled dev) use the default tenant.
        let tenant = ctx
            .principal
            .map(|p| p.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        match self
            .catalog
            .resolve_invocation_tool(tenant, ctx.server, ctx.tool)
            .await
        {
            ResolvedInvocationTool::Ready(snapshot) => {
                let authority = snapshot.authority().id();
                let schema_hash = match snapshot.authority() {
                    ResolutionAuthority::Catalog { schema_hash, .. } => Some(schema_hash.as_str()),
                    ResolutionAuthority::ManifestFallback { .. }
                    | ResolutionAuthority::SyntheticModel => None,
                };
                tracing::debug!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    authority,
                    schema_hash = schema_hash.unwrap_or("none"),
                    "admitted immutable invocation tool snapshot",
                );
                if let ResolutionAuthority::ManifestFallback {
                    approval_requirements_known,
                    ..
                } = snapshot.authority()
                {
                    waygate_telemetry::metrics::record_invocation_manifest_fallback(
                        *approval_requirements_known,
                    );
                }
                ctx.admit_snapshot(snapshot)
            }
            // The catalog has administratively quarantined (or
            // retired) the owning server. Refuse before dispatch —
            // this is the enforcement half of the quarantine admin
            // endpoint. Modeled as `Forbidden` (no policy IDs: the
            // block comes from catalog status, not a Cedar rule).
            ResolvedInvocationTool::Quarantined { server, tool } => {
                tracing::info!(%server, %tool, "refusing call: server quarantined in catalog");
                self.audit
                    .record_chained_best_effort(
                        ctx.audit_event("CallTool", AuditOutcome::Denied)
                            .with_principal(ctx.principal)
                            .with_tool(&server, &tool)
                            .with_reason("server quarantined in catalog"),
                    )
                    .await;
                Err(InvocationError::Forbidden {
                    reason: "server quarantined".into(),
                    policy_ids: Vec::new(),
                    reasons: Vec::new(),
                })
            }
            ResolvedInvocationTool::Unavailable { server, tool } => {
                Err(self.catalog_unavailable_error(ctx, &server, &tool).await)
            }
        }
    }

    /// Stage 2 — validate the caller's arguments against the exact input
    /// schema admitted at Stage 1. Missing arguments validate as an empty JSON
    /// object while retaining their original `None` dispatch shape.
    async fn validate_input(&self, ctx: &mut InvocationContext<'_>) -> Result<(), InvocationError> {
        let (schema_unavailable, authority) = {
            let snapshot = ctx.tool_snapshot();
            (
                snapshot.input_schema_unavailable()
                    || matches!(
                        (snapshot.authority(), snapshot.input_schema()),
                        (ResolutionAuthority::Catalog { .. }, None)
                    ),
                snapshot.authority().id(),
            )
        };
        if schema_unavailable {
            tracing::error!(
                server = %ctx.server,
                tool = %ctx.tool,
                authority,
                error_class = "unavailable_input_schema",
                "tool has no usable admitted input schema; refusing dispatch",
            );
            self.record_input_validation_denial(ctx, "admitted input schema is unavailable")
                .await;
            return Err(InvocationError::InputSchemaInvalid {
                tool: format!("{}.{}", ctx.server, ctx.tool),
            });
        }

        let schema_root_invalid = ctx
            .tool_snapshot()
            .input_schema()
            .is_some_and(|schema| !input_schema_value_has_object_root(schema));
        if schema_root_invalid {
            tracing::error!(
                server = %ctx.server,
                tool = %ctx.tool,
                error_class = "invalid_mcp_input_schema_root",
                "admitted input schema lacks the MCP object root; refusing dispatch",
            );
            self.record_input_validation_denial(ctx, "admitted input schema is invalid")
                .await;
            return Err(InvocationError::InputSchemaInvalid {
                tool: format!("{}.{}", ctx.server, ctx.tool),
            });
        }

        let compiled = {
            let snapshot = ctx.tool_snapshot();
            match (snapshot.authority(), snapshot.input_schema()) {
                (
                    ResolutionAuthority::Catalog {
                        tool_id,
                        schema_hash,
                    },
                    Some(schema),
                ) => Some((
                    "catalog",
                    schema_hash.clone(),
                    self.schema_validator_cache
                        .get_or_compile(*tool_id, schema_hash, schema),
                )),
                (ResolutionAuthority::ManifestFallback { .. }, Some(schema)) => {
                    let admission_key = format!("manifest:{}.{}", ctx.server, ctx.tool);
                    Some((
                        "manifest",
                        admission_key.clone(),
                        self.schema_validator_cache.get_or_compile(
                            uuid::Uuid::nil(),
                            &admission_key,
                            schema,
                        ),
                    ))
                }
                _ => None,
            }
        };
        let Some((authority, schema_hash, compiled)) = compiled else {
            return Ok(());
        };

        let validator = match compiled {
            CachedValidator::Ready(validator) => validator,
            CachedValidator::Invalid => {
                tracing::error!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    authority,
                    schema_hash,
                    error_class = "invalid_json_schema",
                    "admitted input schema cannot be compiled; refusing dispatch",
                );
                self.record_input_validation_denial(ctx, "admitted input schema is invalid")
                    .await;
                return Err(InvocationError::InputSchemaInvalid {
                    tool: format!("{}.{}", ctx.server, ctx.tool),
                });
            }
        };

        // Keep the compiled validator with the call so file admission and
        // delivery evaluate the same admitted schema without recompiling.
        ctx.compiled_input_validator = Some(validator.clone());

        // Validation requires a JSON value. Move the map into a temporary
        // object and restore it afterward so large arguments are not cloned
        // on the invocation hot path and dispatch still observes `None`
        // versus `Some(empty)` exactly as the caller supplied it.
        let arguments_were_present = ctx.arguments.is_some();
        let arguments = serde_json::Value::Object(ctx.arguments.take().unwrap_or_default());
        let validation = check_value_against_validator(&validator, &arguments);
        let serde_json::Value::Object(arguments) = arguments else {
            unreachable!("input arguments are constructed as a JSON object")
        };
        ctx.arguments = arguments_were_present.then_some(arguments);

        match validation {
            SchemaCheck::Pass => Ok(()),
            SchemaCheck::Violation(reason) => {
                self.record_input_validation_denial(
                    ctx,
                    &format!("input schema violation: {reason}"),
                )
                .await;
                Err(InvocationError::InputSchemaViolation {
                    tool: format!("{}.{}", ctx.server, ctx.tool),
                    reason,
                })
            }
        }
    }

    async fn record_input_validation_denial(&self, ctx: &InvocationContext<'_>, reason: &str) {
        let facts = ctx.facts();
        self.audit
            .record_chained_best_effort(
                ctx.audit_event("CallTool", AuditOutcome::Denied)
                    .with_category(ctx.audit_category)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_risk(facts.risk)
                    .with_pii(facts.pii)
                    .with_reason(reason),
            )
            .await;
    }

    /// Stage 3 — Policy Information Point. Assembles the
    /// typed [`Facts`](waygate_core::Facts) from the principal and the
    /// classification `resolve_tool` looked up, which `authorize` then
    /// hands to the gate. Only runs when a principal is present — the
    /// gate is skipped entirely for anonymous (auth-disabled) calls, so
    /// there's no decision to build facts for.
    async fn extract_facts(&self, ctx: &mut InvocationContext<'_>) -> Result<(), InvocationError> {
        if let Some(p) = ctx.principal {
            let mut facts = crate::authz::build_call_facts(p, ctx.facts());
            // Code execution uses the same caller authority as a direct call.
            facts.context.channel = match ctx.channel {
                waygate_invocation::InvocationChannel::Direct => {
                    waygate_core::InvocationChannelFact::Direct
                }
            };
            // The operation the arguments selected, carried whether or not an
            // operator classified it: `risk`/`side_effects`/`pii` already
            // reflect the classification that applied, so this is here for a
            // policy that has to name the operation itself.
            facts.resource.operation = ctx.operation.clone();
            facts.request = Some(waygate_core::RequestFacts {
                email_recipients: Some(waygate_core::EmailRecipients::from_arguments(
                    ctx.arguments.as_ref(),
                )),
                argument_hash: waygate_catalog::argument_hash(ctx.arguments.as_ref()),
                ..Default::default()
            });
            ctx.pip_facts = Some(facts);
        }
        Ok(())
    }

    /// Stage 4 — Cedar (or `AllowAllGate`) authorization. Records
    /// `Denied` / `StepUpRequired` audit rows
    /// on the rejection paths so the activity feed captures every
    /// blocked call even when the deny happens before dispatch.
    ///
    /// When `principal` is `None`
    /// (the `disabled` auth-mode dev path) the gate is skipped entirely.
    /// The [`AllowAllGate`] is forgiving but a real [`AuthzGate`] must
    /// still be prepared to handle a missing principal (fail closed or
    /// treat as anonymous, per its own policy).
    async fn authorize(&self, ctx: &mut InvocationContext<'_>) -> Result<(), InvocationError> {
        let Some(p) = ctx.principal else {
            return Ok(());
        };
        // Snapshot the Copy fields the audit rows need out of `facts` so the
        // immutable `pip_facts()` borrow is released before the `Allow` arm
        // mutates `ctx.authz_policy_ids` (mirrors the snapshot pattern in
        // inspect_response / flush_pending_redactions).
        let (risk, pii, side_effects) = {
            let facts = ctx.pip_facts();
            (
                facts.resource.risk,
                facts.resource.pii,
                facts.resource.side_effects,
            )
        };
        // Snapshot the principal-side decision inputs too, so
        // the Deny / StepUpRequired rows below carry the four inputs the Cedar
        // decision branched on, for exact replay. `p` is the present
        // principal (the gate is skipped above when absent).
        let req_scopes = p.scopes.clone();
        let auth_method = Some(p.auth_method.as_str().to_owned());
        let req_roles = p.roles.clone();
        match self.authz.authorize_tool_call(ctx.pip_facts()).await {
            AuthzVerdict::Allow { policy_ids } => {
                // Stash the matched permit ids so the success audit row this
                // call eventually writes (record_pre_call / record_outcome /
                // flush_pending_redactions) carries them — the allow-decision
                // twin of the Deny arm's `.with_policies`.
                ctx.authz_policy_ids = policy_ids;
                Ok(())
            }
            AuthzVerdict::Deny {
                reason,
                policy_ids,
                reasons,
            } => {
                tracing::info!(
                    user = %p.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    reason = %reason,
                    policies = ?policy_ids,
                    cedar_reasons = ?reasons,
                    "tool call denied",
                );
                self.audit
                    .record_chained_best_effort(
                        ctx.audit_event("CallTool", AuditOutcome::Denied)
                            .with_category(ctx.audit_category)
                            .with_principal(ctx.principal)
                            .with_tool(ctx.server, ctx.tool)
                            .with_risk(risk)
                            .with_pii(pii)
                            .with_policies(policy_ids.clone())
                            // Capture the inputs this Cedar deny
                            // branched on so the recorded decision can be
                            // exactly re-evaluated. Moved (not cloned):
                            // Deny / StepUpRequired are mutually-exclusive match
                            // arms, so each owns the captured inputs.
                            .with_decision_inputs(
                                req_scopes,
                                auth_method,
                                req_roles,
                                Some(side_effects),
                            )
                            .with_reason(&reason),
                    )
                    .await;
                Err(InvocationError::Forbidden {
                    reason,
                    policy_ids,
                    reasons,
                })
            }
            AuthzVerdict::StepUpRequired {
                required_scope,
                reason,
                policy_ids,
            } => {
                tracing::info!(
                    user = %p.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    %required_scope,
                    reason = %reason,
                    policies = ?policy_ids,
                    "tool call requires step-up",
                );
                self.audit
                    .record_chained_best_effort(
                        ctx.audit_event("CallTool", AuditOutcome::StepUpRequired)
                            .with_category(ctx.audit_category)
                            .with_principal(ctx.principal)
                            .with_tool(ctx.server, ctx.tool)
                            .with_risk(risk)
                            .with_pii(pii)
                            // The re-eval permits Cedar returned — recorded so
                            // the Decision Log can find step-up decisions by
                            // policy id, matching the Deny path's
                            // `.with_policies`.
                            .with_policies(policy_ids)
                            // Capture the inputs this step-up
                            // decision branched on, for exact replay.
                            .with_decision_inputs(
                                req_scopes,
                                auth_method,
                                req_roles,
                                Some(side_effects),
                            )
                            .with_reason(format!("scope {required_scope}: {reason}")),
                    )
                    .await;
                Err(InvocationError::StepUpRequired {
                    required_scope,
                    reason,
                })
            }
            AuthzVerdict::ApprovalRequired { reason, policy_ids } => {
                // Not a rejection: the approval overlay is the only policy
                // between this call and an allow, so the call proceeds into
                // `check_approval`, which requires a live grant claim before
                // dispatch. The determinative overlay ids ride on the context
                // so both the eventual success row and an approval-refusal
                // row record which policy imposed the gate.
                tracing::info!(
                    user = %p.sub,
                    server = %ctx.server,
                    tool = %ctx.tool,
                    reason = %reason,
                    policies = ?policy_ids,
                    "tool call is approval-gated by policy",
                );
                ctx.authz_policy_ids = policy_ids.clone();
                ctx.cedar_approval_policies = Some(policy_ids);
                Ok(())
            }
        }
    }

    /// Stage 7 — quota / rate-limit gate.
    ///
    /// When a [`QuotaService`] is wired, build a `QuotaContext`
    /// from the resolved invocation and call
    /// `check_and_consume`. Walks every policy matching
    /// `(tenant, action)` and short-circuits on the first
    /// denial. The action class is derived from the resolved
    /// tool's facts:
    ///
    /// - `call` always fires (every tool call goes through this
    ///   bucket if a `scope=call` policy exists).
    /// - `side_effecting_call` additionally fires when the tool is
    ///   `side_effects: true`, independently of its risk tier.
    ///
    /// `discovery` is NOT fired here — discovery traffic flows
    /// through `tools/list` / `tools/search` paths which sit
    /// outside this `invoke` orchestrator.
    ///
    /// ALL action classes the call falls under are passed in ONE
    /// `check_and_consume(&[QuotaAction])` invocation (atomic
    /// across action classes — a late denial rolls back every
    /// bucket so a 429'd request burns no tokens). Policies for
    /// different action classes are still independent buckets
    /// (matches the SQL CHECK on `action` + the UNIQUE on
    /// `(tenant, scope, scope_value, action)`).
    ///
    /// No-ops when:
    /// - no `QuotaService` is wired (DB-less / dev deployments);
    /// - the call has no principal (anonymous dev mode);
    /// - on infra error (logs WARN and lets the call through —
    ///   a DB blip on the quota path must not lock every tenant
    ///   out, same precedent as the SCIM / tenant enrichers).
    async fn check_quota(&self, ctx: &mut InvocationContext<'_>) -> Result<(), InvocationError> {
        let Some(quota) = self.quota.as_ref() else {
            return Ok(());
        };
        let Some(principal) = ctx.principal else {
            return Ok(());
        };
        let facts = ctx.facts();
        let fq_tool = format!("{}.{}", ctx.server, ctx.tool);

        // Pass ALL action classes the
        // call falls under in one `check_and_consume` invocation
        // so the service can ROLLBACK across action classes. A
        // SideEffectingCall denial must not burn the broader `call`
        // bucket.
        let mut actions: Vec<waygate_quota::QuotaAction> = vec![waygate_quota::QuotaAction::Call];
        // Calls with side effects consume their additional bucket regardless
        // of the risk tier assigned to the tool.
        if facts.side_effects {
            actions.push(waygate_quota::QuotaAction::SideEffectingCall);
        }

        let qctx = waygate_quota::QuotaContext {
            tenant_id: principal.tenant.as_str().to_owned(),
            principal_sub: Some(principal.sub.clone()),
            // Client-scoped policies are unsupported; callers do not supply an identity.
            client_id: None,
            server: ctx.server.to_owned(),
            fq_tool: fq_tool.clone(),
        };
        match quota.check_and_consume(&qctx, &actions).await {
            Ok(()) => Ok(()),
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id,
                name,
                retry_after_seconds,
            }) => {
                // Emit a durable
                // audit row when a rate-limit policy denies.
                // Before this fix only `tracing::info!` recorded
                // the denial, which is fine for live ops but
                // doesn't land in audit_log for compliance review.
                // Chained best effort because the dispatch is already
                // refused — a separate audit-sink failure here
                // shouldn't escalate to a 5xx that hides the
                // 429.
                // Stamp PII flag
                // on the denial row so downstream PII filters /
                // exporters treat rate-limit denials to PII-
                // classified tools consistently with Cedar
                // denials and success rows (both of which call
                // `.with_pii` from the existing audit paths).
                let audit_event = ctx
                    .audit_event("CallTool", AuditOutcome::Denied)
                    .with_category(ctx.audit_category)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_risk(facts.risk)
                    .with_pii(facts.pii)
                    .with_reason(format!(
                        "rate_limited by policy `{name}` ({policy_id}); \
                         retry_after_seconds={retry_after_seconds}"
                    ));
                self.audit.record_chained_best_effort(audit_event).await;
                Err(InvocationError::RateLimited {
                    policy_id,
                    policy_name: name,
                    retry_after_seconds,
                })
            }
            Err(waygate_quota::QuotaError::Sqlx(e)) => {
                tracing::warn!(
                    tenant = %principal.tenant.as_str(),
                    actions = ?actions.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                    error = %e,
                    "quota: store error; allowing this call (best-effort — a DB blip \
                     must not lock every tenant out)",
                );
                Ok(())
            }
        }
    }

    /// Stage 5 — per-principal profile call-time enforcement. Runs between
    /// `authorize` and `check_quota` so a Cedar deny takes precedence (Cedar is
    /// the primary access-control surface; the profile is an
    /// extra "this principal can only call X" bound) and so a
    /// profile-rejected call doesn't burn a quota token.
    ///
    /// Enforces `Principal.api_key_profile_restrictions`, the
    /// general server/tool allow-list — NOT gated on
    /// `AuthMethod`. It is set for API-key profiles AND
    /// for OAuth ID-JAG resource-scoped tokens, so
    /// this gate confines both.
    ///
    /// Sync (no DB hop) because the field was already resolved at
    /// bearer-validate time. No-op only when the call has no
    /// principal, or the principal carries no restrictions
    /// (`api_key_profile_restrictions == None`).
    async fn check_profile_restrictions(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let Some(principal) = ctx.principal else {
            return Ok(());
        };
        let Some(restrictions) = principal.api_key_profile_restrictions.as_ref() else {
            return Ok(());
        };
        match evaluate_profile_restrictions(restrictions, ctx.server, ctx.tool) {
            Ok(()) => Ok(()),
            Err(err) => {
                // The doc previously claimed
                // the gate logs + audits denials, but the
                // refactor that extracted the pure helper
                // dropped both. Restored — operations gets a
                // structured info! line for live dashboards,
                // and the audit log gets a chained-best-effort
                // CallTool/Denied row so compliance can answer
                // "which keys hit which profile boundaries
                // when?" without grepping app logs. Matches
                // the rate_limited denial pattern.
                let (kind, target) = match &err {
                    InvocationError::ProfileServerNotAllowed { server, .. } => {
                        ("server", server.clone())
                    }
                    InvocationError::ProfileToolNotAllowed { tool, .. } => ("tool", tool.clone()),
                    // unreachable by construction — evaluate_profile_restrictions
                    // only returns these two variants on Err.
                    _ => ("unknown", String::new()),
                };
                tracing::info!(
                    profile_id = %restrictions.profile_id,
                    profile_name = %restrictions.profile_name,
                    kind = kind,
                    requested = %target,
                    "api-key profile refused dispatch",
                );
                let facts = ctx.facts();
                let audit_event = ctx
                    .audit_event("CallTool", AuditOutcome::Denied)
                    .with_category(ctx.audit_category)
                    .with_principal(ctx.principal)
                    .with_tool(ctx.server, ctx.tool)
                    .with_risk(facts.risk)
                    .with_pii(facts.pii)
                    .with_reason(format!(
                        "profile_restricts_{kind} by `{}` ({}); requested={}",
                        restrictions.profile_name, restrictions.profile_id, target,
                    ));
                self.audit.record_chained_best_effort(audit_event).await;
                Err(err)
            }
        }
    }

    /// Stage 6 — compile the admitted output schema after authorization and
    /// profile restrictions, but before any resource-consuming or irreversible
    /// gate. Invalid catalog state is therefore invisible to callers who would
    /// be denied, while an authorized call still fails before quota, approval,
    /// required evidence, or upstream dispatch.
    async fn prepare_output_validation(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        let compiled = {
            let snapshot = ctx.tool_snapshot();
            match (snapshot.authority(), snapshot.output_schema()) {
                (
                    ResolutionAuthority::Catalog {
                        tool_id,
                        schema_hash,
                    },
                    Some(schema),
                ) => Some((
                    schema_hash.clone(),
                    self.schema_validator_cache
                        .get_or_compile(*tool_id, schema_hash, schema),
                )),
                _ => None,
            }
        };
        let Some((schema_hash, compiled)) = compiled else {
            return Ok(());
        };

        match compiled {
            CachedValidator::Ready(validator) => {
                ctx.tool_snapshot_mut().set_output_validator(validator);
                Ok(())
            }
            CachedValidator::Invalid => {
                tracing::error!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    authority = "catalog",
                    schema_hash,
                    error_class = "invalid_json_schema",
                    "approved output schema cannot be compiled; refusing dispatch",
                );
                let facts = ctx.facts();
                self.audit
                    .record_chained_best_effort(
                        ctx.audit_event("CallTool", AuditOutcome::Denied)
                            .with_category(ctx.audit_category)
                            .with_principal(ctx.principal)
                            .with_tool(ctx.server, ctx.tool)
                            .with_risk(facts.risk)
                            .with_pii(facts.pii)
                            .with_reason("approved output schema is invalid"),
                    )
                    .await;
                Err(InvocationError::ToolSchemaInvalid {
                    tool: format!("{}.{}", ctx.server, ctx.tool),
                })
            }
        }
    }

    /// Stage 9 — durable "intent to dispatch" event when the gateway
    /// is configured to fail-closed and the resolved call is
    /// side-effecting.
    ///
    /// Decision matrix. The gate follows `facts.side_effects` — the mutating
    /// surface, including LLM completions
    /// which `synthetic_model_facts` stamps `side_effects: true`):
    ///
    /// | `audit_mode`   | `facts.side_effects` | Action                                                                                              |
    /// |----------------|----------------------|-----------------------------------------------------------------------------------------------------|
    /// | `BestEffort`   | any                  | No pre-call row. The post-dispatch outcome uses chained best effort without a caller-visible failure or outbox guarantee. |
    /// | `FailClosed`   | `false` (read-only)  | No row. Operator opts in to evidence for the mutating surface, not every call.                       |
    /// | `FailClosed`   | `true` (mutating)    | `record_required(AuditEvent::CallTool/Success, EvidenceCategory::Invocation, reason="pre_call")`. Persistence failure → `InvocationError::AuditUnavailable` (HTTP 5xx at the adapter); dispatch never runs. |
    ///
    /// Why pre-call: the pre-call row is the "evidence of attempt"
    /// the auditor cares about. Even if `record_outcome` later fails
    /// to write, the pre-call row in `audit_log` proves the gateway
    /// *intended* to invoke the side-effecting call — exactly what
    /// "fail-closed for compliance" means.
    ///
    /// Reason payload deliberately stays minimal (`pre_call`) so the
    /// row is distinguishable from `record_outcome`'s post-dispatch
    /// row at SELECT time. Future filters can `WHERE reason LIKE
    /// 'pre_call%'` to see only the intent rows.
    async fn record_pre_call(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<(), InvocationError> {
        if !matches!(self.audit_mode, AuditMode::FailClosed) {
            return Ok(());
        }
        let facts = ctx.facts();
        // Fail-closed pre-call audit fires on `side_effects`, NOT the risk tier:
        // every mutating call must leave an evidence record
        // before dispatch, so a destructive tool reclassified
        // `high -> low + side_effects` keeps the fail-closed guarantee. Read-only
        // tools (`!side_effects`) stay best-effort regardless of tier.
        if !facts.side_effects {
            return Ok(());
        }
        let (scopes, auth_method, roles, side_effects) = decision_inputs(ctx.principal, facts);
        let event = ctx
            .audit_event("CallTool", AuditOutcome::Success)
            // Inherits the call's plane: `Invocation` for MCP tool calls,
            // `LlmCompletion` for the LLM fast-path (set before the gates).
            .with_category(ctx.audit_category)
            .with_principal(ctx.principal)
            .with_tool(ctx.server, ctx.tool)
            .with_risk(facts.risk)
            .with_pii(facts.pii)
            // Allow-decision twin of the deny path's `.with_policies`: the
            // fired Cedar permits from `authorize`, so the Decision Log can
            // reverse-lookup allow decisions by policy id.
            .with_policies(ctx.authz_policy_ids.clone())
            // Capture the decision inputs on the fail-closed
            // pre-call evidence row so the allowed decision is replayable.
            .with_decision_inputs(scopes, auth_method, roles, side_effects)
            .with_reason("pre_call");
        match self.audit.record_required(event).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // The full error stays on the server log (sqlx text
                // can leak DB host / schema / auth failure mode — fine
                // for the operator's `journalctl`, NOT fine for the
                // MCP client). The variant the adapter forwards to the
                // wire carries a sanitized fixed string instead.
                // The previous `e.to_string()` was an
                // information-disclosure regression.
                tracing::error!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    error = %e,
                    "fail_closed: pre-call required-record failed; refusing dispatch",
                );
                Err(InvocationError::AuditUnavailable(
                    "evidence backend unavailable".into(),
                ))
            }
        }
    }

    /// Stage 10 — call into the catalog's per-upstream client. Measures
    /// latency for `record_outcome`. Errors are propagated as
    /// `InvocationError::Upstream(rmcp::ErrorData)` so the typed
    /// JSON-RPC code reaches the adapter unchanged.
    async fn dispatch(
        &self,
        ctx: &mut InvocationContext<'_>,
    ) -> Result<rmcp::model::CallToolResponse, InvocationError> {
        let started = std::time::Instant::now();
        let args = ctx.arguments.take();
        // An approval-gated call is single-round by construction: the
        // operator's grant is claimed exactly once and must cover exactly
        // one completed effect, so the upstream leg advertises no input
        // capabilities — a conforming upstream then completes without
        // pausing (as it does for a legacy caller), and a nonconforming
        // pause fails closed downstream instead of stranding a
        // continuation whose grant the pausing leg already consumed.
        // Interactive multi-round approval-gated calls belong to the tasks
        // surface, not to a second grant per round.
        let approval_gated = {
            let facts = ctx.facts();
            facts.requires_approval || ctx.cedar_approval_policies.is_some()
        };
        if approval_gated {
            ctx.mrtr.caller_capabilities = None;
        }
        // Bind the dispatch to the Stage-1 admitted contract: the pool
        // re-resolves the tool while holding the connection it will use for
        // the RPC and refuses if the identity no longer matches, so a
        // catalog/manifest change racing this pipeline cannot execute a
        // contract that validation, authorization, and approval never saw.
        let admitted = ctx.tool_snapshot().contract_identity();
        // The retry payload moves to the upstream (like `arguments`); the
        // caller's capabilities stay on the context because the orchestrator
        // reads them again to classify an `input_required` outcome.
        let mrtr = crate::catalog::ToolCallMrtr {
            input_responses: ctx.mrtr.input_responses.take(),
            request_state: ctx.mrtr.request_state.take(),
            caller_capabilities: ctx.mrtr.caller_capabilities.clone(),
            approval_gated,
        };
        let result = retained_response::dispatch(self, ctx, args, &admitted, mrtr).await;
        ctx.latency_ms = Some(started.elapsed().as_millis().min(i64::MAX as u128) as i64);
        result
    }

    /// Stage 12 — output schema validation.
    ///
    /// When Stage 1 admitted a catalog `output_schema` for the resolved tool
    /// AND the upstream dispatch succeeded, the
    /// `structured_content` field of the response is validated
    /// against that schema. A violation returns
    /// [`InvocationError::OutputSchemaViolation`]; the upstream
    /// response never reaches the caller.
    ///
    /// What this DOESN'T do (deliberately, kept for later slices):
    ///
    /// - Inspector trait / pluggable PII redactor / secret scanner
    ///   — those land when the second inspector
    ///   needs a real abstraction.
    /// - Validate text content (only `structured_content`). The
    ///   JSON-schema contract is about structured payloads; free-
    ///   text content is the rendering of the same data and
    ///   validates against the schema indirectly.
    /// - Validate when the resolved tool has no `output_schema`
    ///   (the common case today — most MCP upstreams don't
    ///   advertise one). The stage is a no-op in that branch.
    /// - Validate when the dispatch already failed — the result
    ///   is an `InvocationError::Upstream` and there's no
    ///   structured payload to check.
    ///
    /// The admitted schema is immutable for the call. A catalog update or
    /// quarantine after dispatch starts cannot replace it or silently turn
    /// validation into a no-op.
    async fn validate_output(
        &self,
        ctx: &mut InvocationContext<'_>,
        result: &Result<CallToolResult, InvocationError>,
    ) -> Result<(), InvocationError> {
        let Ok(call_result) = result else {
            return Ok(());
        };
        // No structured payload → nothing schema-checkable.
        // Text-only responses don't roundtrip through a JSON
        // schema today.
        let Some(structured) = call_result.structured_content.as_ref() else {
            return Ok(());
        };
        let fq = format!("{}.{}", ctx.server, ctx.tool);
        let snapshot = ctx.tool_snapshot();
        let Some(validator) = ctx.response_output_validator(call_result) else {
            return Ok(());
        };
        let (authority, schema_hash) = match snapshot.authority() {
            ResolutionAuthority::Catalog { schema_hash, .. } => ("catalog", schema_hash.as_str()),
            ResolutionAuthority::ManifestFallback { .. } => ("manifest_fallback", "none"),
            ResolutionAuthority::SyntheticModel => ("synthetic_model", "none"),
        };

        match check_value_against_validator(validator, structured) {
            SchemaCheck::Pass => Ok(()),
            SchemaCheck::Violation(reason) => {
                tracing::info!(
                    server = %ctx.server,
                    tool = %ctx.tool,
                    authority,
                    schema_hash,
                    user = ?ctx.principal.map(|p| p.sub.as_str()),
                    error_class = "output_schema_violation",
                    "output_schema_violation: refusing to forward upstream response",
                );
                // Chain risk + pii from
                // the resolved facts so the audit row carries
                // the same severity metadata every other
                // CallTool/Denied row does. Without these, SIEM
                // filters keyed on `risk_level` or `pii=true`
                // would miss schema-denied calls on high-risk
                // or PII-classified tools.
                let facts = ctx.facts();
                self.audit
                    .record_chained_best_effort(
                        ctx.audit_event(ctx.response_audit_action(), AuditOutcome::Denied)
                            .with_principal(ctx.principal)
                            .with_tool(ctx.server, ctx.tool)
                            .with_risk(facts.risk)
                            .with_pii(facts.pii)
                            .with_reason("output schema violation"),
                    )
                    .await;
                waygate_telemetry::metrics::record_output_schema_violation(ctx.server, ctx.tool);
                Err(InvocationError::OutputSchemaViolation { tool: fq, reason })
            }
        }
    }

    /// Stage 11 — response inspector pipeline.
    ///
    /// Takes the dispatch `Result` by value and returns the
    /// possibly-mutated `Result` so [`Decision::Redact`]'s
    /// replacement reaches the caller. Chain semantics:
    ///
    /// - **Pass**: working result unchanged.
    /// - **Redact**: working result replaced by
    ///   `decision.redacted`; subsequent inspectors see the
    ///   redacted version (redactions compose). The
    ///   orchestrator emits ONE summary `CallTool/Success`
    ///   audit row + bumps `mcp_response_inspector_redactions_total`
    ///   per inspector that redacted.
    /// - **Block**: first Block short-circuits → returns
    ///   `Err(InvocationError::ResponseInspectionBlocked)`,
    ///   audit `CallTool/Denied`, bumps
    ///   `mcp_response_inspector_blocks_total`. Reason carries
    ///   the inspector-supplied label, NEVER the matched
    ///   payload.
    ///
    /// Annotation-native tools are checked first: every successful result must
    /// carry well-formed trust annotations, and a result labelled sensitive is
    /// released only when the admitted tool contract anticipated sensitive
    /// output. Unknown trust metadata members remain available to callers.
    ///
    /// What this stage doesn't do (deliberately):
    /// - **Empty `inspectors`** → no-op after mandatory trust-label checks;
    ///   ownership of `result` is returned unchanged.
    /// - **Failed dispatch** → no inspection. There's no
    ///   `CallToolResult` to scan; pass the `Err` through.
    /// - **Inspector panic / async error** → not yet modeled.
    ///   Built-ins return `Decision` infallibly. A fallible
    ///   `inspect` variant lands with a future external
    ///   adapter slice.
    async fn inspect_response(
        &self,
        ctx: &mut InvocationContext<'_>,
        result: Result<CallToolResult, InvocationError>,
    ) -> Result<CallToolResult, InvocationError> {
        // Pass-through on dispatch error — nothing to scan.
        let mut working = match result {
            Ok(r) => r,
            err @ Err(_) => return err,
        };
        // Snapshot Copy fields out of facts ONCE so the
        // pending_redactions mutable borrow below doesn't
        // conflict with the immutable facts borrow.
        let (risk, pii) = {
            let facts = ctx.facts();
            (facts.risk, facts.pii)
        };
        let tenant = ctx
            .principal
            .map(|p| p.tenant.as_str())
            .unwrap_or(waygate_core::TenantId::DEFAULT);
        let principal_sub = ctx.principal.map(|p| p.sub.as_str());
        // The trust gate governs every RETURNED result, error included: an
        // `is_error` result still hands its content to the caller, so
        // exempting it would leak unanticipated sensitive content. The
        // release gate keys on the reviewed RETURN classification, not `pii`.
        if ctx.tool_snapshot().annotation_claims_enforced() {
            let anticipated = ctx.tool_snapshot().anticipated_sensitive_output();
            result_trust::enforce(&self.audit, ctx, &working, anticipated).await?;
        }
        if self.inspectors.is_empty() {
            return Ok(working);
        }
        let inspector_ctx = crate::inspection::InspectionContext {
            tenant,
            principal_sub,
            server: ctx.server,
            tool: ctx.tool,
            risk,
            pii_classified: pii,
        };
        for inspector in &self.inspectors {
            match inspector.inspect(&inspector_ctx, &working).await {
                crate::inspection::Decision::Pass => continue,
                crate::inspection::Decision::Redact {
                    redacted,
                    findings_count,
                } => {
                    let inspector_name = inspector.name();
                    // tracing log is OK to emit here (logs
                    // record intent, not forwarding claims),
                    // but the audit row + metric bump are
                    // DEFERRED. The orchestrator emits them in
                    // `flush_pending_redactions` ONLY after
                    // `validate_output` confirms the response
                    // will actually be forwarded — otherwise
                    // telemetry would claim "forwarded N
                    // redactions" for a redaction that
                    // validate_output then rejected as
                    // schema-violating.
                    tracing::info!(
                        server = %ctx.server,
                        tool = %ctx.tool,
                        tenant = %tenant,
                        user = ?principal_sub,
                        inspector = %inspector_name,
                        findings_count,
                        "response_inspector_redacted: applied (pending forward confirmation)",
                    );
                    ctx.pending_redactions
                        .push((inspector_name, findings_count));
                    working = redacted;
                }
                crate::inspection::Decision::Block { reason } => {
                    let inspector_name = inspector.name();
                    return Err(result_trust::block_response(
                        &self.audit,
                        ctx,
                        inspector_name,
                        reason,
                    )
                    .await);
                }
            }
        }
        Ok(working)
    }

    /// Stage 13 — final post-dispatch evidence attempt. Uses
    /// `record_chained_best_effort` for both success and failure. A queue
    /// admission or backing-write failure here is measured and logged but
    /// doesn't surface to the caller, preserving an operational signal even
    /// when the row is dropped.
    async fn record_outcome(
        &self,
        ctx: &mut InvocationContext<'_>,
        result: &Result<CallToolResult, InvocationError>,
    ) {
        let facts = ctx.facts();
        let latency_ms = ctx.latency_ms.unwrap_or(0);
        let (scopes, auth_method, roles, side_effects) = decision_inputs(ctx.principal, facts);
        let mut base = ctx
            .audit_event("CallTool", AuditOutcome::Success)
            .with_principal(ctx.principal)
            .with_tool(ctx.server, ctx.tool)
            .with_risk(facts.risk)
            .with_pii(facts.pii)
            // Allow-decision twin of the deny path's `.with_policies`: stamp the
            // fired Cedar permits on the final success row so the Decision Log
            // can reverse-lookup allow decisions by policy id. Empty on the
            // error arms below (they overwrite `outcome`/`reason` only), which
            // is correct — `policy_ids` is meaningful for the Success outcome.
            .with_policies(ctx.authz_policy_ids.clone())
            // Capture the decision inputs on the final outcome
            // row (and, via `..base`, the execution-error arm) so every
            // recorded tool-call decision is exactly replayable.
            .with_decision_inputs(scopes, auth_method, roles, side_effects)
            .with_latency_ms(latency_ms);
        // Gateway file rows and later grants store this exact value, so an
        // operator can link them to the CallTool result.
        base.id = ctx.invocation_id;
        // A policy-gated effect's success row records that an approval
        // grant satisfied Cedar's ApprovalRequired verdict; replay uses
        // this to reproduce the recorded policy verdict faithfully.
        let base = if ctx.policy_gated_grant_consumed {
            base.with_reason("policy-gated effect: approval grant consumed")
        } else {
            base
        };

        // Exhaustive match (no wildcard) so adding a sixth
        // `InvocationError` variant fails compilation here until the
        // new stage's row-emission contract is decided.
        // The previous `Err(_) => {}` swallowed the safety property
        // the surrounding comment claimed.
        match result {
            Ok(output) => self.record_delivery_outcome(base, output).await,
            Err(InvocationError::Upstream(err)) => {
                // Keep the policy-gated marker as the reason prefix on the
                // execution-error row: decision-impact replay reads the
                // prefix to reproduce the recorded ApprovalRequired policy
                // verdict, and dropping it here would fabricate an
                // allow→approval_required transition for a failed
                // policy-gated dispatch under an unchanged bundle.
                let upstream_reason = if retained_response::is_recovery_failure(err) {
                    "retained connector response recovery failed".to_owned()
                } else {
                    err.to_string()
                };
                let reason = if ctx.policy_gated_grant_consumed {
                    format!("policy-gated effect: upstream error: {upstream_reason}")
                } else {
                    upstream_reason
                };
                self.audit
                    .record_chained_best_effort(AuditEvent {
                        outcome: AuditOutcome::ExecutionError,
                        reason: Some(reason),
                        ..base
                    })
                    .await;
            }
            // `Forbidden` and `StepUpRequired` are emitted by the
            // `authorize` stage itself — emitting a second row here
            // would double-count denials in the activity feed. The
            // explicit no-op arms are load-bearing: if a future change
            // moves the deny-emit out of `authorize`, the matching arm
            // here must move with it (or the deny row will go missing).
            Err(InvocationError::Forbidden { .. })
            | Err(InvocationError::StepUpRequired { .. }) => {}
            // Input validation owns its refusal row because it returns before
            // the final outcome stage. `AuditUnavailable` is emitted by
            // `record_pre_call` after
            // it has *already* written (or attempted to write) the
            // durable pre-call audit row that motivated the
            // fail-closed refusal — emitting a second row here would
            // double-count. `InvalidArguments` remains reserved for adapter
            // and inference parsing failures.
            Err(InvocationError::InvalidArguments(_))
            | Err(InvocationError::InputSchemaViolation { .. })
            | Err(InvocationError::InputSchemaInvalid { .. })
            | Err(InvocationError::ReadOnlyRequired { .. })
            | Err(InvocationError::ReadOnlyOperationRequired { .. })
            | Err(InvocationError::AuditUnavailable(_)) => {}
            // ApprovalRequired is emitted by `check_approval`; recording it
            // again here would double-count the gate's denial.
            Err(InvocationError::ApprovalRequired { .. }) => {}
            // RateLimited is the quota gate's refusal. The
            // gate logs at info! when it 429s with the policy_id
            // + retry_after; emitting a separate CallTool/Denied
            // row here would double-count against the (future)
            // dedicated rate-limit metric / audit category.
            Err(InvocationError::RateLimited { .. }) => {}
            // Profile-driven denials follow the same
            // "the gate that produces them owns the audit row"
            // rule. `check_profile_restrictions` emits the
            // CallTool/Denied row before returning the error,
            // so this arm
            // is a deliberate no-op to avoid double-counting.
            Err(InvocationError::ProfileServerNotAllowed { .. })
            | Err(InvocationError::ProfileToolNotAllowed { .. }) => {}
            // OutputSchemaViolation is the validate_output
            // stage's refusal. That stage records its own
            // CallTool/Denied row before returning the error,
            // matching the "the gate owns its audit row" rule.
            Err(InvocationError::OutputSchemaViolation { .. }) => {}
            // Invalid approved schemas are refused during resolution, before
            // the outcome stage is reachable. The explicit arm preserves the
            // exhaustive error-contract check for callers that construct a
            // result directly in tests or future adapters.
            Err(InvocationError::ToolSchemaInvalid { .. }) => {}
            // ResponseInspectionBlocked is the
            // inspect_response stage's refusal. That stage
            // records its own CallTool/Denied row tagged with
            // the inspector name before returning the error;
            // a second row here would double-count.
            Err(InvocationError::ResponseInspectionBlocked { .. }) => {}
            // Retained-response recovery is an extension of dispatch. The
            // upstream tool call completed, but the caller-specific materialization
            // boundary refused the follow-up body read, so record one execution
            // error rather than pretending the result was forwarded.
            Err(error @ InvocationError::ResponseMaterializationLimit { .. }) => {
                self.audit
                    .record_chained_best_effort(AuditEvent {
                        outcome: AuditOutcome::ExecutionError,
                        reason: Some(error.to_string()),
                        ..base
                    })
                    .await;
            }
            // BudgetExceeded is the LLM budget gate's refusal, produced
            // only on the inference fast-path (`invoke_llm` → `check_llm_budget`,
            // which records its own CallTool/Denied row). It cannot reach this
            // MCP-tool-call outcome match; the no-op arm satisfies exhaustiveness
            // and follows the "the gate owns its audit row" rule.
            Err(InvocationError::BudgetExceeded { .. }) => {}
        }
    }
}

/// Pure helper extracted for testability.
/// `check_profile_restrictions` is a thin wrapper that pulls
/// the restrictions off the principal + delegates here.
///
/// Order is significant: server check runs first because a
/// "wrong server" denial is the broader signal — operators
/// reading the audit row want to know "this key can't talk to
/// server X at all" before "this key can talk to X but not
/// X.tool_y". Both checks short-circuit on first failure.
pub fn evaluate_profile_restrictions(
    restrictions: &waygate_oidc::ApiKeyProfileRestrictions,
    server: &str,
    tool: &str,
) -> Result<(), InvocationError> {
    if let Some(servers) = restrictions.allowed_servers.as_deref() {
        if !servers.is_empty() && !servers.iter().any(|s| s == server) {
            return Err(InvocationError::ProfileServerNotAllowed {
                profile_id: restrictions.profile_id.clone(),
                profile_name: restrictions.profile_name.clone(),
                server: server.to_owned(),
            });
        }
    }
    if let Some(tools) = restrictions.allowed_tools.as_deref() {
        if !tools.is_empty() {
            let fq = format!("{server}.{tool}");
            if !tools.iter().any(|t| t == &fq) {
                return Err(InvocationError::ProfileToolNotAllowed {
                    profile_id: restrictions.profile_id.clone(),
                    profile_name: restrictions.profile_name.clone(),
                    tool: fq,
                });
            }
        }
    }
    Ok(())
}

/// Synthetic catalog facts for a resolved LLM model, standing in for the
/// per-model catalog entry. They make the shared authorize /
/// audit gates fire on the model as a resource: an LLM call is a billable
/// external side-effect, prompts may carry PII, and the risk tier (resolver-
/// supplied; defaults to Low → no step-up) drives the step-up scope.
///
/// `side_effects: true` is load-bearing: operational controls follow the
/// mutating-surface flag rather than `risk == High`, so this is what
/// subjects every LLM completion to the `side_effecting_call` quota bucket and (under
/// `GATEWAY_AUDIT_MODE=fail_closed`) the fail-closed pre-call audit — i.e. a
/// billable model call is rate-limitable and gets a durable evidence row before
/// dispatch. Both controls are opt-in (quota policy / audit mode), so the
/// default best-effort posture is unchanged. The gate keys on `side_effects`
/// (pinned by `tests/suite/fail_closed.rs::fail_closed_blocks_side_effecting_when_required_record_errs`,
/// which blocks a low + side_effects resource — the exact shape produced here),
/// so the inference-plane behavior follows from the model facts carrying it.
fn synthetic_model_facts(server: &str, model: &str, risk: ModelRisk) -> ToolFacts {
    ToolFacts {
        server: server.to_string(),
        name: model.to_string(),
        risk: match risk {
            ModelRisk::Low => RiskTier::Low,
            ModelRisk::Medium => RiskTier::Medium,
            ModelRisk::High => RiskTier::High,
        },
        side_effects: true,
        pii: true,
        requires_approval: false,
        requires_approval_known: true,
    }
}

/// Milliseconds elapsed since `started`, clamped to `i64`.
fn elapsed_ms(started: std::time::Instant) -> i64 {
    started.elapsed().as_millis().min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests;
