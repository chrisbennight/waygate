//! Audit trail for tool-call attempts.
//!
//! Every call that reaches `GatewayServer::dispatch_tool_call` produces one
//! [`AuditEvent`] describing what was attempted, who attempted it, and what
//! the outcome was (denied, step-up required, succeeded, or failed to
//! execute). The trait keeps the MCP layer ignorant of the sink — the real
//! Postgres implementation lives in `waygate-storage`, tests use
//! `InMemorySink`, and production with no DB configured falls back to
//! `NullSink` (log-only).

use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
};

use waygate_core::RiskTier;
use waygate_oidc::Principal;

/// Maximum retained size of the free-form audit reason. The reason is the
/// event field most likely to contain an upstream or policy error assembled
/// from untrusted input; bounding it also makes the asynchronous queue's
/// memory ceiling meaningful.
pub const MAX_EVIDENCE_REASON_BYTES: usize = 8 * 1024;

/// The production recorder uses four independently-drained chained queues so
/// one slow tenant cannot serialize all best-effort security evidence.
pub const CHAINED_EVIDENCE_QUEUE_SHARDS: usize = 4;

/// Each chained shard and the informational queue can retain at most this
/// many events. Submission uses `try_send`, so callers never wait for space.
pub const EVIDENCE_QUEUE_CAPACITY: usize = 256;

/// Workers take at most this many events from a channel per receive pass.
pub const EVIDENCE_QUEUE_BATCH_SIZE: usize = 32;

/// Shutdown closes submission and gives accepted events a short bounded drain
/// window before their tasks are aborted and the database pool is closed.
pub const EVIDENCE_QUEUE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

const EVIDENCE_QUEUE_DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Audit failure posture for the dispatch path. Lifted out of
/// `waygate-server::config` so the `InvocationService`
/// implementation (which lives in `waygate-mcp::invocation`) can
/// branch on the posture without taking a waygate-server dependency.
/// `waygate-server::config` still owns the env-var parsing
/// (`GATEWAY_AUDIT_MODE=best_effort|fail_closed`) and re-exports this
/// type so existing callers don't break.
///
/// - `BestEffort` (default) — the pre-call stage is disabled. Governed final
///   outcomes and security refusals use `record_chained_best_effort`, whose
///   write failures cannot break tool calls. Independently fail-closed
///   control-plane mutations still use `record_required`.
/// - `FailClosed` — side-effecting (`facts.side_effects`) dispatch calls
///   `record_required` for the pre-call intent event; a failed required-record
///   returns `InvocationError::AuditUnavailable` (mapped to HTTP 5xx by the
///   adapter) so the upstream call never happens without a durable
///   evidence-of-attempt row. Read-only (`!side_effects`) calls have no
///   pre-call row and retain their chained-best-effort final outcome (the
///   trade-off the operator opts into is "required pre-call evidence for the
///   mutating surface" not "required evidence for everything"). The gate
///   follows `side_effects` rather than risk so a
///   mutating tool cannot lose the guarantee when its risk tier changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditMode {
    BestEffort,
    FailClosed,
}

impl AuditMode {
    /// Parse the canonical env-var string form. `waygate-server::config`
    /// uses this to keep the env-name → enum mapping in one place; tests
    /// that want a specific posture can also reach for it.
    pub fn parse_env(s: &str) -> Option<Self> {
        match s {
            "best_effort" => Some(Self::BestEffort),
            "fail_closed" => Some(Self::FailClosed),
            _ => None,
        }
    }
}

/// What kind of event this row represents.
///
/// Was implicit before — every recorded event came from a tool-call
/// dispatch and was effectively `Invocation`. Making it explicit means
/// the same `AuditEvent` shape can carry admin actions, OAuth lifecycle,
/// policy reloads, etc. without ambiguity at read time.
///
/// Variants:
///
/// - `Invocation` — `<server>.<tool>` call (Allow / Deny / StepUp / ExecutionError).
/// - `Discovery` — `tools/list` / `searchTools` observation.
/// - `AdminMutation` — operator changed configuration via `/admin` or `/api/v1`.
/// - `AuthAttempt` — bearer validation outcome (issued tokens, refused, etc).
/// - `PolicyReload` — Cedar policy set re-loaded (SIGHUP / runtime CRUD).
/// - `ManifestReload` — upstream manifests re-loaded.
/// - `ApiKeyLifecycle` — API key minted / renamed / revoked.
/// - `OAuthEvent` — gateway-AS authorize / token / refresh / revoke.
/// - `UpstreamHealth` — connection state transition (reconnect, drop).
/// - `ApprovalLifecycle` — pre-call human-in-the-loop grant created / used / expired.
/// - `CatalogDrift` — observed tool definition diverged from approved version.
/// - `DataInspection` — response-side PII / secret redaction event.
/// - `FileTransfer` — out-of-context transfer grant, credential, and movement lifecycle.
///
/// Categories beyond `Invocation` land incrementally as the wiring is
/// added; this enum reserves the names now so downstream
/// formatters/exporters (OCSF / syslog / S3) can stabilise their
/// vocabulary without later renames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    Invocation,
    Discovery,
    /// An inference-plane LLM completion (a `/v1` model call). A
    /// distinct category from `Invocation` so usage/cost analytics and SIEM
    /// routing can separate model calls from MCP tool calls.
    LlmCompletion,
    AdminMutation,
    AuthAttempt,
    PolicyReload,
    ManifestReload,
    ApiKeyLifecycle,
    OAuthEvent,
    UpstreamHealth,
    ApprovalLifecycle,
    CatalogDrift,
    DataInspection,
    FileTransfer,
    /// Marker row written by the retention sweep
    /// immediately before it DELETEs old rows. The marker is itself
    /// a chain-bearing audit_log row (record_required path) whose
    /// `reason` field is a serialized [`RetentionMarker`] JSON
    /// payload listing the row_hashes about to be deleted. The
    /// chain verifier consumes those payloads when walking the
    /// chain: a prev_hash that doesn't match the prior walked
    /// row's row_hash is accepted as a LEGITIMATE retention gap
    /// iff the missing hash appears in some RetentionSweep
    /// marker's deleted-set; otherwise it's reported as BrokenLink.
    /// See `waygate_storage::chain_verify` for the gap-walking
    /// logic and `RetentionMarker` for the payload format.
    RetentionSweep,
}

impl EvidenceCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Invocation => "invocation",
            Self::Discovery => "discovery",
            Self::LlmCompletion => "llm_completion",
            Self::AdminMutation => "admin_mutation",
            Self::AuthAttempt => "auth_attempt",
            Self::PolicyReload => "policy_reload",
            Self::ManifestReload => "manifest_reload",
            Self::ApiKeyLifecycle => "api_key_lifecycle",
            Self::OAuthEvent => "oauth_event",
            Self::UpstreamHealth => "upstream_health",
            Self::ApprovalLifecycle => "approval_lifecycle",
            Self::CatalogDrift => "catalog_drift",
            Self::DataInspection => "data_inspection",
            Self::FileTransfer => "file_transfer",
            Self::RetentionSweep => "retention_sweep",
        }
    }
}

/// One row per persisted event. `category` discriminates the row's
/// meaning at read time; most non-`Invocation` categories leave
/// `server`/`tool`/`risk_level`/`pii` unset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub ts: time::OffsetDateTime,
    #[serde(default = "default_category")]
    pub category: EvidenceCategory,
    /// Tenant the event was emitted under. Mirrors
    /// `Principal.tenant` for principal-bearing events; defaults
    /// to [`waygate_core::TenantId::DEFAULT`] for principal-less
    /// events (boot-time policy reloads before any request lands)
    /// and stored events predating this field that deserialize
    /// through the serde default.
    #[serde(default)]
    pub tenant: waygate_core::TenantId,
    pub principal: Option<AuditPrincipal>,
    pub action: String,
    pub server: Option<String>,
    pub tool: Option<String>,
    /// The operation the call selected, for a tool that carries many behind one
    /// name. `None` for a tool classified by name alone, for a call that
    /// supplied no discriminator argument or a non-string one, and for every
    /// non-invocation category.
    ///
    /// Recorded whether or not an operator had classified the value: the trail
    /// answers what was asked for, which is a different question from what
    /// policy recognized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub outcome: AuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskTier>,
    /// Whether the called tool was declared as returning/accepting PII
    /// (mirrors `ToolFacts.pii` / `ToolClassification.pii` at the
    /// moment of the call). `None` for non-tool-call event categories
    /// added in the future (admin mutations, OAuth lifecycle, etc.)
    /// where the field has no meaning. See migration `0005_audit_pii.sql`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i64>,
    /// WHAT this event acted on, as a structured value distinct from the
    /// acting `principal` ("who"). For lifecycle events the principal is
    /// the operator who authorized the change while `target` names the
    /// subject of the change — e.g. the API key's `sub` for
    /// ApiKeyMinted/Revoked/Renamed, or the change-request `action_type`.
    /// `None` for tool-call invocations and other categories where the
    /// `server`/`tool` columns already carry the subject. Surfaced in the
    /// admin "What changed" feed / activity drawer / compare view, and
    /// included in the canonical hash when the event is recorded through the
    /// chain-bearing required path via
    /// [`waygate_storage::hashchain::canonical_audit_bytes_with_ext`]
    /// (contributes zero bytes when `None`, so legacy rows stay
    /// verifiable — same technique as the SCIM columns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The OAuth scopes the principal presented at the time
    /// of the authorization decision (`principal.scopes`). One of the four
    /// inputs a Cedar decision can branch on but that audit_log did not
    /// previously record. Captured ONLY on decision rows (CallTool /
    /// llm_completion allow/deny/step-up); non-decision categories leave it
    /// empty. Persisted in the `req_scopes` column and included in the
    /// canonical hash for chain-bearing rows via
    /// [`waygate_storage::hashchain::canonical_audit_bytes_with_ext2`]
    /// (contributes zero bytes when empty, so legacy rows stay verifiable).
    /// Read back by decision replay to reconstruct and re-evaluate the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_scopes: Vec<String>,
    /// How the principal authenticated at decision time
    /// (`principal.auth_method` — "oauth" / "api_key" / "peer_assertion").
    /// Same capture boundary + canonical hash coverage (`auth_method` column) as
    /// [`Self::req_scopes`]. `None` on non-decision rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    /// The RBAC role names the principal held at decision
    /// time (`principal.roles`). Same capture boundary + canonical hash coverage
    /// (`req_roles` column) as [`Self::req_scopes`]. Empty on non-decision
    /// rows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_roles: Vec<String>,
    /// Whether the resolved tool/model declared side effects
    /// (`resource.side_effects`) at decision time. Same capture boundary +
    /// canonical hash coverage (`side_effects` column) as [`Self::req_scopes`].
    /// `None` on non-decision rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effects: Option<bool>,
    /// The in-app LLM agent that performed this action
    /// ON BEHALF OF the human `principal` (e.g. `agent:ops-chat`). `None` when
    /// a human acted directly — the overwhelming majority of rows. The human
    /// stays the `principal` (the on-behalf-of party); the agent is a delegate
    /// acting under the human's identity and scopes, so this is additive
    /// attribution, not a replacement. Persisted in the `acting_agent` column
    /// and included in the canonical hash for chain-bearing rows via
    /// [`waygate_storage::hashchain::canonical_audit_bytes_with_ext3`]
    /// (contributes zero bytes when `None`, so legacy rows stay verifiable —
    /// same technique as the SCIM / `target` / decision-input columns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acting_agent: Option<String>,
    /// Parent execution and nested call-attempt attribution for orchestrated
    /// invocations. Direct MCP calls leave this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_hierarchy: Option<waygate_core::InvocationHierarchy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPrincipal {
    pub sub: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub issuer: String,
    /// SCIM `active` flag
    /// at audit time. `None` ⇒ no SCIM enricher ran or no SCIM
    /// row matched.
    ///
    /// ## Persistence boundary
    ///
    /// This field travels in-memory through every component that
    /// holds an `AuditPrincipal` — handlers, `EvidenceRecorder`
    /// implementations, and the OCSF / ECS / syslog exporters,
    /// which all read it explicitly and emit it in their
    /// respective shapes. The PRIMARY `audit_log` columns and
    /// the hash-chain canonical bytes do NOT yet persist this
    /// field; the durable storage path
    /// (`crates/waygate-storage/src/audit.rs`) currently drops
    /// it before INSERT.
    ///
    /// Adding chain-covered persistence requires either a
    /// `chain_version` discriminator (so the verifier picks the
    /// right canonical-bytes function for rows pre- vs post-
    /// extension) or accepting that legacy rows fail
    /// re-verification. Either approach belongs with the
    /// per-tenant audit-routing work that
    /// re-touches the chain plumbing anyway. Until then,
    /// audit-side answers to "was this user SCIM-active at the
    /// time of the call?" come from the EXPORTER stream
    /// (OCSF/ECS/syslog), not from the local audit_log table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_active: Option<bool>,
    /// SCIM group display names at audit time. Same persistence
    /// boundary as [`Self::scim_active`] — exporters carry it,
    /// primary `audit_log` does not (yet). Snapshotted at the
    /// moment of the call so the exported event remains accurate
    /// after group membership changes upstream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scim_groups: Vec<String>,
}

impl From<&Principal> for AuditPrincipal {
    fn from(p: &Principal) -> Self {
        let (scim_active, scim_groups) = match p.scim.as_ref() {
            Some(s) => (
                Some(s.active),
                s.groups.iter().map(|g| g.display_name.clone()).collect(),
            ),
            None => (None, Vec::new()),
        };
        Self {
            sub: p.sub.clone(),
            email: p.email.clone(),
            groups: p.groups.clone(),
            issuer: p.issuer.clone(),
            scim_active,
            scim_groups,
        }
    }
}

/// Mutually-exclusive outcome for a call attempt. `Success` and
/// `ExecutionError` both imply the call actually reached the upstream;
/// `Denied` and `StepUpRequired` never did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    ExecutionError,
    Denied,
    StepUpRequired,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::ExecutionError => "execution_error",
            AuditOutcome::Denied => "denied",
            AuditOutcome::StepUpRequired => "step_up_required",
        }
    }
}

fn default_category() -> EvidenceCategory {
    EvidenceCategory::Invocation
}

impl AuditEvent {
    /// Build a skeleton event with a v7 UUID (timestamp-ordered, so primary
    /// key ordering aligns with insertion order for free index-scan locality).
    ///
    /// Defaults to `EvidenceCategory::Invocation` since tool-call dispatch
    /// is the largest existing caller. Callers recording other event
    /// categories (policy reload, API-key lifecycle, etc.) chain
    /// `.with_category(...)` to override.
    pub fn new(action: impl Into<String>, outcome: AuditOutcome) -> Self {
        Self {
            id: uuid::Uuid::now_v7(),
            ts: time::OffsetDateTime::now_utc(),
            category: EvidenceCategory::Invocation,
            // Default to TenantId::DEFAULT until a
            // principal is attached via `with_principal`. Boot-
            // time + admin-system events without a principal
            // (policy reload, sweeper batch) stay in the default
            // tenant — operator-driven, not request-routed.
            tenant: waygate_core::TenantId::default(),
            principal: None,
            action: action.into(),
            server: None,
            tool: None,
            operation: None,
            outcome,
            risk_level: None,
            pii: None,
            policy_ids: Vec::new(),
            reason: None,
            trace_id: None,
            latency_ms: None,
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        }
    }

    /// Override the event category. `EvidenceCategory::Invocation` is the
    /// default; chain this when recording other categories.
    pub fn with_category(mut self, category: EvidenceCategory) -> Self {
        self.category = category;
        self
    }

    pub fn with_principal(mut self, p: Option<&Principal>) -> Self {
        // Stamp the event's tenant from the principal
        // automatically. The principal IS the source of truth for
        // tenancy on a per-request event; explicit `with_tenant`
        // overrides only the system-mutation paths (rare).
        if let Some(p) = p {
            self.tenant = p.tenant.clone();
        }
        self.principal = p.map(AuditPrincipal::from);
        self
    }

    /// Explicit tenant override for the rare system
    /// events that don't have a principal but DO know which
    /// tenant they're acting under (e.g. a per-tenant policy
    /// reload, a tenant-scoped admin operation).
    pub fn with_tenant(mut self, tenant: waygate_core::TenantId) -> Self {
        self.tenant = tenant;
        self
    }

    pub fn with_tool(mut self, server: impl Into<String>, tool: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self.tool = Some(tool.into());
        self
    }

    /// Name the upstream an event acted through WITHOUT claiming a tool.
    ///
    /// A native resource read has an upstream but no tool, and the per-tool
    /// aggregates (`tool_stats` and the hourly rollup) group by `(server,
    /// tool)` across every row where both are set. Putting a resource URI in
    /// the tool column would invent a synthetic tool and skew those volume,
    /// error, and denial figures, so a resource decision sets only the server
    /// and carries what it acted on in [`Self::with_target`].
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    pub fn with_risk(mut self, risk: RiskTier) -> Self {
        self.risk_level = Some(risk);
        self
    }

    /// Record the PII flag for a tool-call event. Tool-call dispatch
    /// chains this after `with_tool` / `with_risk`; non-tool events
    /// leave `pii` as `None`.
    pub fn with_pii(mut self, pii: bool) -> Self {
        self.pii = Some(pii);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_policies(mut self, ids: Vec<String>) -> Self {
        self.policy_ids = ids;
        self
    }

    pub fn with_latency_ms(mut self, ms: i64) -> Self {
        self.latency_ms = Some(ms);
        self
    }

    /// Record WHAT this event acted on (the subject), distinct from the
    /// acting principal. Chain lifecycle/mutation emitters call this with
    /// the API key's `sub`, the change-request `action_type`, etc.
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Capture the four authorization-decision INPUTS a Cedar
    /// policy can branch on — `principal.scopes`, `principal.auth_method`,
    /// `principal.roles`, and `resource.side_effects` — onto a decision row so
    /// the recorded decision can later be reconstructed and re-evaluated
    /// (exact decision replay). The invocation pipeline chains this on the
    /// CallTool / llm_completion allow / deny / step-up rows alongside
    /// `.with_risk` / `.with_pii` / `.with_policies`; non-decision rows leave
    /// the fields at their empty/None defaults so they contribute zero bytes
    /// to the hash chain and legacy rows stay verifiable.
    pub fn with_decision_inputs(
        mut self,
        scopes: Vec<String>,
        auth_method: Option<String>,
        roles: Vec<String>,
        side_effects: Option<bool>,
    ) -> Self {
        self.req_scopes = scopes;
        self.auth_method = auth_method;
        self.req_roles = roles;
        self.side_effects = side_effects;
        self
    }

    /// Stamp the in-app agent acting on behalf of the
    /// human `principal`. `None` is a no-op (a human acted directly). The
    /// invocation pipeline will chain this from the request's `acting_agent`
    /// metadata key once the chat agent is wired; for now callers
    /// (and tests) set it explicitly.
    pub fn with_acting_agent(mut self, acting_agent: Option<String>) -> Self {
        self.acting_agent = acting_agent;
        self
    }

    pub fn with_invocation_hierarchy(
        mut self,
        hierarchy: Option<waygate_core::InvocationHierarchy>,
    ) -> Self {
        self.invocation_hierarchy = hierarchy;
        self
    }
}

/// Failure modes for [`EvidenceRecorder::record_required`]. A
/// "persistence" failure means the underlying store rejected the
/// write (Postgres unavailable, schema mismatch, integrity violation);
/// "unavailable" means the recorder isn't backed by durable storage
/// at all (e.g. [`NullSink`]) so a required record can never land.
///
/// Fail-closed callers (`GATEWAY_AUDIT_MODE=fail_closed`) map either
/// variant to a 5xx so the caller doesn't get an ack without a
/// recorded event. Best-effort callers ignore both.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence sink has no durable backing store: {0}")]
    Unavailable(String),
    #[error("evidence write failed: {0}")]
    Persistence(String),
}

#[async_trait]
pub trait EvidenceRecorder: Send + Sync + 'static {
    /// Required persistence attempt. The recorder MUST attempt to durably
    /// persist `event` before returning. This contract does not require an
    /// internal retry, so it does not provide at-least-once delivery. On
    /// success it returns the event's id (echoes `event.id`; the value already
    /// exists, so the return is sugar for chaining at the call site). On
    /// failure the caller decides whether to abort the originating action.
    ///
    /// Use for events whose loss creates a compliance gap, including
    /// irreversible admin mutations and the pre-call intent row for a
    /// fail-closed side-effecting invocation.
    async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError>;

    /// Best-effort delivery with hash-chain coverage for every successful
    /// write. Failures are measured and log-and-drop rather than returned to
    /// the caller. Implementations may enqueue configured external delivery
    /// for hierarchy-bearing events in the same bounded persistence attempt,
    /// but callers must not infer a delivery guarantee from this method.
    /// The production decorator submits into a fixed-capacity, tenant-sharded
    /// queue and returns immediately; a full queue is itself a measured drop.
    ///
    /// Use for security and compliance decisions whose loss must not turn the
    /// originating request into an outage.
    async fn record_chained_best_effort(&self, event: AuditEvent);

    /// Best-effort delivery. Failures are log-and-drop and never reach the
    /// caller; implementations may use an unchained fast path. Use for
    /// purely informational signals where a small drop rate is acceptable
    /// (e.g. health-probe outcomes or search-query telemetry). Production uses
    /// a separate fixed-capacity queue so informational load cannot consume
    /// chained-evidence capacity.
    async fn record_best_effort(&self, event: AuditEvent);
}

pub type SharedEvidence = Arc<dyn EvidenceRecorder>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueuedEvidencePosture {
    ChainedBestEffort,
    BestEffort,
}

impl QueuedEvidencePosture {
    fn as_str(self) -> &'static str {
        match self {
            Self::ChainedBestEffort => "chained_best_effort",
            Self::BestEffort => "best_effort",
        }
    }

    fn metric(self) -> waygate_telemetry::metrics::EvidenceSubmissionPosture {
        match self {
            Self::ChainedBestEffort => {
                waygate_telemetry::metrics::EvidenceSubmissionPosture::ChainedBestEffort
            }
            Self::BestEffort => waygate_telemetry::metrics::EvidenceSubmissionPosture::BestEffort,
        }
    }
}

#[derive(Debug, Default)]
struct EvidenceQueueStats {
    chained_pending: AtomicU64,
    best_effort_pending: AtomicU64,
}

impl EvidenceQueueStats {
    fn pending(&self, posture: QueuedEvidencePosture) -> &AtomicU64 {
        match posture {
            QueuedEvidencePosture::ChainedBestEffort => &self.chained_pending,
            QueuedEvidencePosture::BestEffort => &self.best_effort_pending,
        }
    }

    fn accept(&self, posture: QueuedEvidencePosture) {
        self.pending(posture).fetch_add(1, Ordering::Relaxed);
        waygate_telemetry::metrics::evidence_submission_pending_inc(posture.metric());
    }

    fn finish(&self, posture: QueuedEvidencePosture) -> bool {
        let finished = self
            .pending(posture)
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                pending.checked_sub(1)
            })
            .is_ok();
        if finished {
            waygate_telemetry::metrics::evidence_submission_pending_dec(posture.metric());
        }
        finished
    }

    fn load(&self, posture: QueuedEvidencePosture) -> u64 {
        self.pending(posture).load(Ordering::Relaxed)
    }

    fn take(&self, posture: QueuedEvidencePosture) -> u64 {
        self.pending(posture).swap(0, Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct EvidenceQueueDropLogState {
    last_emitted: Option<Instant>,
    suppressed: u64,
}

impl EvidenceQueueDropLogState {
    fn on_drop(&mut self, now: Instant) -> Option<u64> {
        if self
            .last_emitted
            .is_none_or(|last| now.duration_since(last) >= EVIDENCE_QUEUE_DROP_LOG_INTERVAL)
        {
            self.last_emitted = Some(now);
            return Some(std::mem::take(&mut self.suppressed));
        }
        self.suppressed = self.suppressed.saturating_add(1);
        None
    }
}

#[derive(Clone, Copy)]
struct EvidenceQueueConfig {
    chained_shards: usize,
    queue_capacity: usize,
    batch_size: usize,
}

impl EvidenceQueueConfig {
    const PRODUCTION: Self = Self {
        chained_shards: CHAINED_EVIDENCE_QUEUE_SHARDS,
        queue_capacity: EVIDENCE_QUEUE_CAPACITY,
        batch_size: EVIDENCE_QUEUE_BATCH_SIZE,
    };
}

/// A bounded, non-blocking decorator for the two best-effort evidence
/// postures. Required events still call the backing recorder inline and retain
/// fail-closed semantics. Chained events are tenant-sharded; informational
/// events use a separate queue so an informational flood cannot evict a
/// security decision. Full or closed queues drop immediately with bounded
/// metrics and rate-limited metadata-only logs.
pub struct BoundedEvidenceRecorder {
    inner: SharedEvidence,
    chained_senders: Vec<mpsc::Sender<AuditEvent>>,
    best_effort_sender: mpsc::Sender<AuditEvent>,
    shard_hasher: RandomState,
    stats: Arc<EvidenceQueueStats>,
    admission_open: Arc<StdMutex<bool>>,
    chained_drop_log: StdMutex<EvidenceQueueDropLogState>,
    best_effort_drop_log: StdMutex<EvidenceQueueDropLogState>,
    queue_capacity: usize,
}

impl BoundedEvidenceRecorder {
    /// Start the fixed-capacity production workers. This must run inside a
    /// Tokio runtime. Keep the returned handle alive and call
    /// [`EvidenceQueueHandle::shutdown`] after request draining but before
    /// closing the database pool.
    pub fn spawn(inner: SharedEvidence) -> (SharedEvidence, EvidenceQueueHandle) {
        let (recorder, handle) = Self::spawn_with_config(inner, EvidenceQueueConfig::PRODUCTION);
        (recorder, handle)
    }

    fn spawn_with_config(
        inner: SharedEvidence,
        config: EvidenceQueueConfig,
    ) -> (Arc<Self>, EvidenceQueueHandle) {
        assert!(
            config.chained_shards > 0,
            "at least one chained queue shard"
        );
        assert!(
            config.queue_capacity > 0,
            "evidence queue capacity is non-zero"
        );
        assert!(
            config.batch_size > 0,
            "evidence queue batch size is non-zero"
        );

        let stats = Arc::new(EvidenceQueueStats::default());
        let admission_open = Arc::new(StdMutex::new(true));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut workers = Vec::with_capacity(config.chained_shards + 1);
        let mut chained_senders = Vec::with_capacity(config.chained_shards);
        for _ in 0..config.chained_shards {
            let (sender, receiver) = mpsc::channel(config.queue_capacity);
            chained_senders.push(sender);
            workers.push(tokio::spawn(run_evidence_queue_worker(
                inner.clone(),
                receiver,
                shutdown_rx.clone(),
                stats.clone(),
                QueuedEvidencePosture::ChainedBestEffort,
                config.batch_size,
            )));
        }
        let (best_effort_sender, best_effort_receiver) = mpsc::channel(config.queue_capacity);
        workers.push(tokio::spawn(run_evidence_queue_worker(
            inner.clone(),
            best_effort_receiver,
            shutdown_rx,
            stats.clone(),
            QueuedEvidencePosture::BestEffort,
            config.batch_size,
        )));

        // Touch both gauge series at startup so a healthy empty queue appears
        // as zero instead of an absent time series.
        waygate_telemetry::metrics::evidence_submission_pending_sub(
            QueuedEvidencePosture::ChainedBestEffort.metric(),
            0,
        );
        waygate_telemetry::metrics::evidence_submission_pending_sub(
            QueuedEvidencePosture::BestEffort.metric(),
            0,
        );

        let recorder = Arc::new(Self {
            inner,
            chained_senders,
            best_effort_sender,
            shard_hasher: RandomState::new(),
            stats: stats.clone(),
            admission_open: admission_open.clone(),
            chained_drop_log: StdMutex::new(EvidenceQueueDropLogState::default()),
            best_effort_drop_log: StdMutex::new(EvidenceQueueDropLogState::default()),
            queue_capacity: config.queue_capacity,
        });
        let handle = EvidenceQueueHandle {
            shutdown_tx,
            workers,
            stats,
            admission_open,
            shutdown_complete: false,
        };
        (recorder, handle)
    }

    fn truncate_reason(event: &mut AuditEvent) {
        let Some(reason) = event.reason.as_mut() else {
            return;
        };
        if reason.len() <= MAX_EVIDENCE_REASON_BYTES {
            return;
        }
        let mut end = MAX_EVIDENCE_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let mut bounded = String::with_capacity(end);
        bounded.push_str(&reason[..end]);
        *reason = bounded;
        waygate_telemetry::metrics::record_evidence_reason_truncation();
    }

    fn chained_shard(&self, event: &AuditEvent) -> usize {
        (self.shard_hasher.hash_one(event.tenant.as_str()) as usize) % self.chained_senders.len()
    }

    fn submit(
        &self,
        posture: QueuedEvidencePosture,
        shard: Option<usize>,
        sender: &mpsc::Sender<AuditEvent>,
        event: AuditEvent,
    ) {
        let admission_open = self
            .admission_open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*admission_open {
            drop(admission_open);
            waygate_telemetry::metrics::record_evidence_submission(
                posture.metric(),
                waygate_telemetry::metrics::EvidenceSubmissionOutcome::DroppedClosed,
                1,
            );
            self.record_drop_log(posture, shard, "dropped_closed", &event);
            return;
        }
        self.stats.accept(posture);
        let result = sender.try_send(event);
        match result {
            Ok(()) => waygate_telemetry::metrics::record_evidence_submission(
                posture.metric(),
                waygate_telemetry::metrics::EvidenceSubmissionOutcome::Queued,
                1,
            ),
            Err(error) => {
                let finished = self.stats.finish(posture);
                debug_assert!(finished, "admission failure must retire its pending event");
                let (outcome, terminal_outcome, event) = match error {
                    mpsc::error::TrySendError::Full(event) => (
                        "dropped_full",
                        waygate_telemetry::metrics::EvidenceSubmissionOutcome::DroppedFull,
                        event,
                    ),
                    mpsc::error::TrySendError::Closed(event) => (
                        "dropped_closed",
                        waygate_telemetry::metrics::EvidenceSubmissionOutcome::DroppedClosed,
                        event,
                    ),
                };
                waygate_telemetry::metrics::record_evidence_submission(
                    posture.metric(),
                    terminal_outcome,
                    1,
                );
                self.record_drop_log(posture, shard, outcome, &event);
            }
        }
        drop(admission_open);
    }

    fn record_drop_log(
        &self,
        posture: QueuedEvidencePosture,
        shard: Option<usize>,
        outcome: &'static str,
        event: &AuditEvent,
    ) {
        let state = match posture {
            QueuedEvidencePosture::ChainedBestEffort => &self.chained_drop_log,
            QueuedEvidencePosture::BestEffort => &self.best_effort_drop_log,
        };
        let Some(suppressed_since_last) = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .on_drop(Instant::now())
        else {
            return;
        };
        tracing::warn!(
            event.id = %event.id,
            category = event.category.as_str(),
            audit_outcome = event.outcome.as_str(),
            action = %event.action,
            tenant = event.tenant.as_str(),
            trace_id = ?event.trace_id,
            posture = posture.as_str(),
            submission_outcome = outcome,
            shard = ?shard,
            queue_capacity_per_channel = self.queue_capacity,
            queue_channels = if matches!(posture, QueuedEvidencePosture::ChainedBestEffort) {
                self.chained_senders.len()
            } else {
                1
            },
            pending_all_channels = self.stats.load(posture),
            suppressed_since_last,
            "bounded evidence submission dropped an event",
        );
    }
}

#[async_trait]
impl EvidenceRecorder for BoundedEvidenceRecorder {
    async fn record_required(&self, mut event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
        Self::truncate_reason(&mut event);
        self.inner.record_required(event).await
    }

    async fn record_chained_best_effort(&self, mut event: AuditEvent) {
        Self::truncate_reason(&mut event);
        let shard = self.chained_shard(&event);
        self.submit(
            QueuedEvidencePosture::ChainedBestEffort,
            Some(shard),
            &self.chained_senders[shard],
            event,
        );
    }

    async fn record_best_effort(&self, mut event: AuditEvent) {
        Self::truncate_reason(&mut event);
        self.submit(
            QueuedEvidencePosture::BestEffort,
            None,
            &self.best_effort_sender,
            event,
        );
    }
}

async fn run_evidence_queue_worker(
    inner: SharedEvidence,
    mut receiver: mpsc::Receiver<AuditEvent>,
    mut shutdown: watch::Receiver<bool>,
    stats: Arc<EvidenceQueueStats>,
    posture: QueuedEvidencePosture,
    batch_size: usize,
) {
    let mut batch = Vec::with_capacity(batch_size);
    let mut panic_log_state = EvidenceQueueDropLogState::default();
    loop {
        let received = loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow_and_update() {
                        receiver.close();
                    }
                }
                received = receiver.recv_many(&mut batch, batch_size) => break received,
            }
        };
        if received == 0 {
            return;
        }
        for event in batch.drain(..) {
            let event_id = event.id;
            let category = event.category;
            let audit_outcome = event.outcome;
            let attempt = std::panic::AssertUnwindSafe(async {
                match posture {
                    QueuedEvidencePosture::ChainedBestEffort => {
                        inner.record_chained_best_effort(event).await;
                    }
                    QueuedEvidencePosture::BestEffort => {
                        inner.record_best_effort(event).await;
                    }
                }
            })
            .catch_unwind()
            .await;
            if stats.finish(posture) {
                let outcome = if attempt.is_ok() {
                    waygate_telemetry::metrics::EvidenceSubmissionOutcome::Processed
                } else {
                    waygate_telemetry::metrics::EvidenceSubmissionOutcome::DroppedWorkerPanic
                };
                waygate_telemetry::metrics::record_evidence_submission(
                    posture.metric(),
                    outcome,
                    1,
                );
                if attempt.is_err() {
                    if let Some(suppressed_since_last) = panic_log_state.on_drop(Instant::now()) {
                        tracing::error!(
                            event.id = %event_id,
                            category = category.as_str(),
                            audit_outcome = audit_outcome.as_str(),
                            posture = posture.as_str(),
                            submission_outcome = "dropped_worker_panic",
                            suppressed_since_last,
                            "bounded evidence worker recovered from backing recorder panic; event dropped",
                        );
                    }
                }
            }
        }
    }
}

/// Result of closing the bounded recorder and waiting for accepted events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceQueueShutdownReport {
    pub timed_out: bool,
    pub worker_failures: usize,
    pub dropped_chained_best_effort: u64,
    pub dropped_best_effort: u64,
}

/// Owns the bounded recorder workers. The server shuts this down after HTTP
/// request drain and before database-pool close so accepted events get a
/// bounded final persistence opportunity.
pub struct EvidenceQueueHandle {
    shutdown_tx: watch::Sender<bool>,
    workers: Vec<JoinHandle<()>>,
    stats: Arc<EvidenceQueueStats>,
    admission_open: Arc<StdMutex<bool>>,
    shutdown_complete: bool,
}

struct EvidenceWorkerAbortGuard {
    workers: Vec<JoinHandle<()>>,
}

impl Drop for EvidenceWorkerAbortGuard {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

impl EvidenceQueueHandle {
    fn reconcile_shutdown_loss(&self) -> (u64, u64) {
        let dropped_chained_best_effort = self.stats.take(QueuedEvidencePosture::ChainedBestEffort);
        let dropped_best_effort = self.stats.take(QueuedEvidencePosture::BestEffort);
        for (posture, count) in [
            (
                QueuedEvidencePosture::ChainedBestEffort,
                dropped_chained_best_effort,
            ),
            (QueuedEvidencePosture::BestEffort, dropped_best_effort),
        ] {
            if count > 0 {
                waygate_telemetry::metrics::record_evidence_submission(
                    posture.metric(),
                    waygate_telemetry::metrics::EvidenceSubmissionOutcome::DroppedShutdown,
                    count,
                );
                waygate_telemetry::metrics::evidence_submission_pending_sub(
                    posture.metric(),
                    count,
                );
            }
        }
        (dropped_chained_best_effort, dropped_best_effort)
    }

    pub async fn shutdown(self) -> EvidenceQueueShutdownReport {
        self.shutdown_with_timeout(EVIDENCE_QUEUE_DRAIN_TIMEOUT)
            .await
    }

    async fn shutdown_with_timeout(
        mut self,
        drain_timeout: Duration,
    ) -> EvidenceQueueShutdownReport {
        *self
            .admission_open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        let _ = self.shutdown_tx.send(true);
        let mut workers = EvidenceWorkerAbortGuard {
            workers: std::mem::take(&mut self.workers),
        };
        let deadline = tokio::time::Instant::now() + drain_timeout;
        let mut timed_out = false;
        let mut worker_failures = 0;
        for index in 0..workers.workers.len() {
            match tokio::time::timeout_at(deadline, &mut workers.workers[index]).await {
                Ok(result) => {
                    if result.is_err() {
                        worker_failures += 1;
                    }
                }
                Err(_) => {
                    timed_out = true;
                    for worker in &workers.workers {
                        worker.abort();
                    }
                    // Handles before `index` were already joined. Await only
                    // the timed-out and not-yet-polled handles so abort has
                    // completed before the pending counters are reconciled.
                    for worker in workers.workers.iter_mut().skip(index) {
                        if worker.await.is_err() {
                            worker_failures += 1;
                        }
                    }
                    break;
                }
            }
        }
        workers.workers.clear();

        let (dropped_chained_best_effort, dropped_best_effort) = self.reconcile_shutdown_loss();
        self.shutdown_complete = true;

        EvidenceQueueShutdownReport {
            timed_out,
            worker_failures,
            dropped_chained_best_effort,
            dropped_best_effort,
        }
    }
}

impl Drop for EvidenceQueueHandle {
    fn drop(&mut self) {
        if self.shutdown_complete {
            return;
        }
        *self
            .admission_open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        let _ = self.shutdown_tx.send(true);
        for worker in &self.workers {
            worker.abort();
        }
        let (dropped_chained_best_effort, dropped_best_effort) = self.reconcile_shutdown_loss();
        tracing::error!(
            dropped_chained_best_effort,
            dropped_best_effort,
            "bounded evidence queue handle dropped without completed shutdown; workers aborted and accepted work accounted as shutdown loss",
        );
    }
}

/// Drops every event. The default when no DB is configured; production boots
/// refuse this combination via `GATEWAY_DEPLOYMENT_PROFILE=prod` so an
/// operator running audit-less is forced to opt in via the `dev` profile.
pub struct NullSink;

#[async_trait]
impl EvidenceRecorder for NullSink {
    async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
        // A NullSink can never satisfy a required record — that's
        // the point of choosing it. Fail-closed callers will see the
        // resulting 5xx; best-effort callers will (correctly) never
        // call this method.
        tracing::warn!(
            event.id = %event.id,
            outcome = event.outcome.as_str(),
            action = %event.action,
            "evidence required but NullSink cannot persist; \
             configure GATEWAY_DATABASE_URL or accept drops via \
             record_best_effort",
        );
        Err(EvidenceError::Unavailable("NullSink".into()))
    }

    async fn record_chained_best_effort(&self, event: AuditEvent) {
        use waygate_telemetry::metrics::ChainedBestEffortOutcome;
        waygate_telemetry::metrics::record_evidence_chained_best_effort(
            ChainedBestEffortOutcome::Attempted,
        );
        waygate_telemetry::metrics::record_evidence_chained_best_effort(
            ChainedBestEffortOutcome::Dropped,
        );
        tracing::warn!(
            event.id = %event.id,
            category = event.category.as_str(),
            outcome = event.outcome.as_str(),
            "chained best-effort evidence dropped because NullSink cannot persist",
        );
    }

    async fn record_best_effort(&self, event: AuditEvent) {
        tracing::debug!(
            event.id = %event.id,
            outcome = event.outcome.as_str(),
            action = %event.action,
            "evidence event dropped (NullSink)",
        );
    }
}

/// Test-only sink: collects events into a `Vec` for assertion.
#[derive(Default)]
pub struct InMemorySink {
    events: Mutex<Vec<RecordedEvidence>>,
}

/// Recorder method selected by a caller. Exposed by [`InMemorySink`] so
/// integration tests can assert the reliability contract, not only the event
/// payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidencePosture {
    Required,
    ChainedBestEffort,
    BestEffort,
}

/// One event captured by [`InMemorySink`] with the caller-selected posture.
#[derive(Clone, Debug)]
pub struct RecordedEvidence {
    pub event: AuditEvent,
    pub posture: EvidencePosture,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .await
            .iter()
            .map(|record| record.event.clone())
            .collect()
    }

    pub async fn snapshot_with_posture(&self) -> Vec<RecordedEvidence> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl EvidenceRecorder for InMemorySink {
    async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
        let id = event.id;
        self.events.lock().await.push(RecordedEvidence {
            event,
            posture: EvidencePosture::Required,
        });
        Ok(id)
    }

    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.events.lock().await.push(RecordedEvidence {
            event,
            posture: EvidencePosture::ChainedBestEffort,
        });
    }

    async fn record_best_effort(&self, event: AuditEvent) {
        self.events.lock().await.push(RecordedEvidence {
            event,
            posture: EvidencePosture::BestEffort,
        });
    }
}

/// Decorator over a [`SharedEvidence`] that stamps `trace_id` from the active
/// OpenTelemetry span onto every event before delegating. Wired once at the
/// sink's construction site so every category — Invocation, OAuthEvent,
/// PolicyReload, ManifestReload, ApiKeyLifecycle, AdminMutation, AuthAttempt,
/// … — is correlated to its request trace without touching each emit site.
///
/// Events that already carry a `trace_id` pass through untouched, and when no
/// tracer provider is installed (dev mode) the stamp is a no-op that leaves
/// `trace_id` as `None`. Stamping is the recorder's only behaviour; delivery
/// semantics (`record_required`, `record_chained_best_effort`, or
/// `record_best_effort`) are the inner sink's.
pub struct TraceStampingRecorder {
    inner: SharedEvidence,
}

impl TraceStampingRecorder {
    pub fn new(inner: SharedEvidence) -> Self {
        Self { inner }
    }

    /// Fill `trace_id` from the active span when the event doesn't already
    /// carry one. Idempotent and allocation-free when there is nothing to add.
    fn stamp(mut event: AuditEvent) -> AuditEvent {
        if event.trace_id.is_none() {
            event.trace_id = waygate_telemetry::correlation::current_trace_id();
        }
        event
    }
}

#[async_trait]
impl EvidenceRecorder for TraceStampingRecorder {
    async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
        self.inner.record_required(Self::stamp(event)).await
    }

    async fn record_chained_best_effort(&self, event: AuditEvent) {
        self.inner
            .record_chained_best_effort(Self::stamp(event))
            .await;
    }

    async fn record_best_effort(&self, event: AuditEvent) {
        self.inner.record_best_effort(Self::stamp(event)).await;
    }
}

#[cfg(test)]
mod tests {
    //! Pin the `EvidenceRecorder` contract on the two reference sinks
    //! every other implementation is benchmarked against: `NullSink`
    //! (no durable backing) and `InMemorySink` (test fake).
    //!
    //! - `NullSink` must reject `record_required` with
    //!   `EvidenceError::Unavailable`; both best-effort methods return
    //!   silently. Fail-closed callers see the rejection and surface
    //!   it; best-effort callers see nothing.
    //! - `InMemorySink` must accept all methods identically and round-
    //!   trip the events through `snapshot()` so test fakes can assert
    //!   what was recorded.
    //!
    //! The Postgres impl gets its own smoke test under
    //! `crates/waygate-storage/tests/suite/pg_smoke.rs`.
    use super::*;
    use std::collections::BTreeSet;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::Layer;

    #[derive(Clone)]
    struct EventFieldCapture {
        fields: Arc<StdMutex<Vec<BTreeSet<&'static str>>>>,
    }

    impl<S> Layer<S> for EventFieldCapture
    where
        S: tracing::Subscriber,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
            let mut visitor = EventFieldNameVisitor::default();
            event.record(&mut visitor);
            self.fields
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(visitor.fields);
        }
    }

    #[derive(Default)]
    struct EventFieldNameVisitor {
        fields: BTreeSet<&'static str>,
    }

    impl Visit for EventFieldNameVisitor {
        fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
            self.fields.insert(field.name());
        }
    }

    fn sample_event(category: EvidenceCategory) -> AuditEvent {
        AuditEvent::new("Test", AuditOutcome::Success).with_category(category)
    }

    struct GatedSink {
        gate: tokio::sync::Semaphore,
        started: tokio::sync::Notify,
        inner: InMemorySink,
    }

    impl GatedSink {
        fn new() -> Self {
            Self {
                gate: tokio::sync::Semaphore::new(0),
                started: tokio::sync::Notify::new(),
                inner: InMemorySink::new(),
            }
        }

        async fn wait_for_release(&self) {
            self.started.notify_one();
            self.gate
                .acquire()
                .await
                .expect("test gate remains open")
                .forget();
        }
    }

    struct PanicOnceSink {
        panic_next: std::sync::atomic::AtomicBool,
        first_attempted: tokio::sync::Notify,
        inner: InMemorySink,
    }

    impl PanicOnceSink {
        fn new() -> Self {
            Self {
                panic_next: std::sync::atomic::AtomicBool::new(true),
                first_attempted: tokio::sync::Notify::new(),
                inner: InMemorySink::new(),
            }
        }
    }

    #[async_trait]
    impl EvidenceRecorder for PanicOnceSink {
        async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
            self.inner.record_required(event).await
        }

        async fn record_chained_best_effort(&self, event: AuditEvent) {
            self.inner.record_chained_best_effort(event).await;
        }

        async fn record_best_effort(&self, event: AuditEvent) {
            if self
                .panic_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.first_attempted.notify_one();
                panic!("test backing recorder panic");
            }
            self.inner.record_best_effort(event).await;
        }
    }

    #[async_trait]
    impl EvidenceRecorder for GatedSink {
        async fn record_required(&self, event: AuditEvent) -> Result<uuid::Uuid, EvidenceError> {
            self.inner.record_required(event).await
        }

        async fn record_chained_best_effort(&self, event: AuditEvent) {
            self.wait_for_release().await;
            self.inner.record_chained_best_effort(event).await;
        }

        async fn record_best_effort(&self, event: AuditEvent) {
            self.wait_for_release().await;
            self.inner.record_best_effort(event).await;
        }
    }

    fn one_slot_queue_config() -> EvidenceQueueConfig {
        EvidenceQueueConfig {
            chained_shards: 1,
            queue_capacity: 1,
            batch_size: 1,
        }
    }

    fn submission_metric_value(posture: &str, outcome: &str) -> f64 {
        let posture_label = format!("posture=\"{posture}\"");
        let outcome_label = format!("outcome=\"{outcome}\"");
        waygate_telemetry::gather_text()
            .lines()
            .find(|line| {
                line.starts_with("mcp_evidence_submission_total{")
                    && line.contains(&posture_label)
                    && line.contains(&outcome_label)
            })
            .and_then(|line| line.split_whitespace().last())
            .map(|value| value.parse().expect("metric sample value is numeric"))
            .unwrap_or(0.0)
    }

    async fn wait_until_workers_release_inner(inner: &Arc<GatedSink>) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(inner) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted workers must release the backing recorder");
    }

    #[test]
    fn bounded_queue_constants_and_labels_are_stable() {
        assert_eq!(MAX_EVIDENCE_REASON_BYTES, 8_192);
        assert_eq!(CHAINED_EVIDENCE_QUEUE_SHARDS, 4);
        assert_eq!(EVIDENCE_QUEUE_CAPACITY, 256);
        assert_eq!(EVIDENCE_QUEUE_BATCH_SIZE, 32);
        assert_eq!(EVIDENCE_QUEUE_DRAIN_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            QueuedEvidencePosture::ChainedBestEffort.as_str(),
            "chained_best_effort",
        );
        assert_eq!(QueuedEvidencePosture::BestEffort.as_str(), "best_effort");
    }

    #[test]
    fn queue_stats_track_accept_finish_and_take() {
        let stats = EvidenceQueueStats::default();
        let posture = QueuedEvidencePosture::BestEffort;
        assert_eq!(stats.load(posture), 0);
        stats.accept(posture);
        assert_eq!(stats.load(posture), 1);
        assert!(stats.finish(posture));
        assert_eq!(stats.load(posture), 0);
        stats.accept(posture);
        assert_eq!(stats.take(posture), 1);
        assert_eq!(stats.load(posture), 0);
        assert!(
            !stats.finish(posture),
            "a reconciled event must not underflow or finish twice",
        );
        waygate_telemetry::metrics::evidence_submission_pending_dec(posture.metric());
    }

    #[test]
    fn queue_drop_log_state_is_immediate_rate_limited_and_counts_suppression() {
        let mut state = EvidenceQueueDropLogState::default();
        let started = Instant::now();
        assert_eq!(state.on_drop(started), Some(0));
        assert_eq!(state.on_drop(started + Duration::from_secs(1)), None);
        assert_eq!(state.on_drop(started + Duration::from_secs(2)), None);
        assert_eq!(
            state.on_drop(started + EVIDENCE_QUEUE_DROP_LOG_INTERVAL),
            Some(2),
        );
    }

    #[tokio::test]
    async fn queue_drop_warning_exposes_identifiers_and_capacity_without_free_form_reason() {
        let inner: SharedEvidence = Arc::new(InMemorySink::new());
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(inner, one_slot_queue_config());
        let captured = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(EventFieldCapture {
            fields: Arc::clone(&captured),
        });
        let event = sample_event(EvidenceCategory::AuthAttempt)
            .with_reason("sensitive diagnostic detail must not be logged");

        tracing::subscriber::with_default(subscriber, || {
            recorder.record_drop_log(
                QueuedEvidencePosture::ChainedBestEffort,
                Some(0),
                "dropped_full",
                &event,
            );
        });
        drop(handle);

        let captured = captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            captured.len(),
            1,
            "a dropped submission must emit one warning"
        );
        let fields = &captured[0];
        for expected in [
            "message",
            "event.id",
            "category",
            "audit_outcome",
            "action",
            "tenant",
            "trace_id",
            "posture",
            "submission_outcome",
            "shard",
            "queue_capacity_per_channel",
            "queue_channels",
            "pending_all_channels",
            "suppressed_since_last",
        ] {
            assert!(fields.contains(expected), "warning is missing {expected}");
        }
        assert!(
            !fields.contains("reason"),
            "free-form evidence reasons must never be logged",
        );
    }

    #[tokio::test]
    async fn null_sink_required_returns_unavailable() {
        let s = NullSink;
        let err = s
            .record_required(sample_event(EvidenceCategory::PolicyReload))
            .await
            .expect_err("NullSink::record_required must fail");
        assert!(
            matches!(err, EvidenceError::Unavailable(_)),
            "expected Unavailable, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn null_sink_best_effort_returns_without_error() {
        // `record_best_effort` has no Result; the contract is "never
        // surface an error to the caller." Just confirm it doesn't
        // panic.
        let s = NullSink;
        s.record_best_effort(sample_event(EvidenceCategory::Invocation))
            .await;
        s.record_chained_best_effort(sample_event(EvidenceCategory::AuthAttempt))
            .await;
        let metrics = waygate_telemetry::gather_text();
        for outcome in ["attempted", "dropped"] {
            assert!(
                metrics.lines().any(|line| {
                    line.contains("mcp_evidence_chained_best_effort_total")
                        && line.contains(&format!("outcome=\"{outcome}\""))
                }),
                "NullSink must measure the {outcome} chained best-effort transition:\n{metrics}",
            );
        }
    }

    #[tokio::test]
    async fn in_memory_sink_required_persists_and_returns_id() {
        let s = InMemorySink::new();
        let ev = sample_event(EvidenceCategory::PolicyReload);
        let expected_id = ev.id;
        let returned = s
            .record_required(ev)
            .await
            .expect("InMemorySink::record_required must succeed");
        assert_eq!(
            returned, expected_id,
            "record_required must return the event's id (sugar for chaining)",
        );
        let snap = s.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].category, EvidenceCategory::PolicyReload);
        assert_eq!(snap[0].id, expected_id);
        let recorded = s.snapshot_with_posture().await;
        assert_eq!(recorded[0].posture, EvidencePosture::Required);
    }

    #[tokio::test]
    async fn in_memory_sink_best_effort_persists() {
        let s = InMemorySink::new();
        s.record_best_effort(sample_event(EvidenceCategory::ManifestReload))
            .await;
        s.record_best_effort(sample_event(EvidenceCategory::ApiKeyLifecycle))
            .await;
        s.record_chained_best_effort(sample_event(EvidenceCategory::AuthAttempt))
            .await;
        let snap = s.snapshot().await;
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].category, EvidenceCategory::ManifestReload);
        assert_eq!(snap[1].category, EvidenceCategory::ApiKeyLifecycle);
        assert_eq!(snap[2].category, EvidenceCategory::AuthAttempt);
        let recorded = s.snapshot_with_posture().await;
        assert_eq!(recorded[0].posture, EvidencePosture::BestEffort);
        assert_eq!(recorded[1].posture, EvidencePosture::BestEffort);
        assert_eq!(recorded[2].posture, EvidencePosture::ChainedBestEffort);
    }

    #[tokio::test]
    async fn bounded_recorder_sheds_full_information_queue_without_blocking_or_cross_talk() {
        let inner = Arc::new(GatedSink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());

        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(Duration::from_secs(1), inner.started.notified())
            .await
            .expect("informational worker must take the first event");

        // The worker is blocked in the backing recorder, so this event occupies
        // the only buffered slot and the following event must shed immediately.
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(
            Duration::from_millis(50),
            recorder.record_best_effort(sample_event(EvidenceCategory::UpstreamHealth)),
        )
        .await
        .expect("a full information queue must never wait for space");

        // Chained security evidence has a separate queue and remains
        // admissible even while the informational queue is full.
        recorder
            .record_chained_best_effort(sample_event(EvidenceCategory::AuthAttempt))
            .await;

        inner.gate.add_permits(3);
        let report = handle.shutdown().await;
        assert_eq!(
            report,
            EvidenceQueueShutdownReport {
                timed_out: false,
                worker_failures: 0,
                dropped_chained_best_effort: 0,
                dropped_best_effort: 0,
            },
            "all accepted events must drain",
        );

        let recorded = inner.inner.snapshot_with_posture().await;
        assert_eq!(recorded.len(), 3, "one full-queue event must be shed");
        assert_eq!(
            recorded
                .iter()
                .filter(|event| event.posture == EvidencePosture::BestEffort)
                .count(),
            2,
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|event| event.posture == EvidencePosture::ChainedBestEffort)
                .count(),
            1,
        );
        let metrics = waygate_telemetry::gather_text();
        assert!(
            metrics.lines().any(|line| {
                line.contains("mcp_evidence_submission_total")
                    && line.contains("posture=\"best_effort\"")
                    && line.contains("outcome=\"dropped_full\"")
            }),
            "full-queue shedding must be observable:\n{metrics}",
        );
    }

    #[tokio::test]
    async fn bounded_recorder_truncates_reason_at_a_utf8_boundary_for_required_writes() {
        let inner = Arc::new(InMemorySink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        let oversized_reason = format!(
            "{}💥",
            "a".repeat(MAX_EVIDENCE_REASON_BYTES.saturating_sub(1))
        );
        let event = sample_event(EvidenceCategory::AdminMutation).with_reason(oversized_reason);

        recorder
            .record_required(event)
            .await
            .expect("required event must reach the backing recorder");
        let report = handle.shutdown().await;
        assert!(!report.timed_out);

        let events = inner.snapshot().await;
        let reason = events[0].reason.as_deref().expect("reason remains present");
        assert_eq!(reason.len(), MAX_EVIDENCE_REASON_BYTES - 1);
        assert!(reason.ends_with('a'), "truncation must preserve UTF-8");
        assert!(
            waygate_telemetry::gather_text().contains("mcp_evidence_reason_truncations_total"),
            "reason truncation must be observable",
        );
    }

    #[test]
    fn reason_truncation_releases_the_unbounded_source_allocation() {
        let mut event =
            sample_event(EvidenceCategory::AuthAttempt).with_reason("x".repeat(1024 * 1024));
        let original_capacity = event.reason.as_ref().expect("reason present").capacity();

        BoundedEvidenceRecorder::truncate_reason(&mut event);

        let reason = event.reason.as_ref().expect("reason remains present");
        assert_eq!(reason.len(), MAX_EVIDENCE_REASON_BYTES);
        assert!(
            reason.capacity() <= MAX_EVIDENCE_REASON_BYTES * 2,
            "truncation must rebuild into an allocation bounded by the configured limit: {}",
            reason.capacity(),
        );
        assert!(
            reason.capacity() < original_capacity,
            "the untrusted source allocation must not move into the queue",
        );
    }

    #[tokio::test]
    async fn bounded_recorder_aborts_stuck_worker_at_shutdown_deadline_and_counts_loss() {
        let inner = Arc::new(GatedSink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(Duration::from_secs(1), inner.started.notified())
            .await
            .expect("worker must enter the backing recorder");
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        let shutdown_drops_before = submission_metric_value("best_effort", "dropped_shutdown");

        let report = handle
            .shutdown_with_timeout(Duration::from_millis(20))
            .await;
        assert!(
            report.timed_out,
            "stuck backing write must hit the deadline"
        );
        assert_eq!(report.dropped_chained_best_effort, 0);
        assert_eq!(report.dropped_best_effort, 2);
        assert!(
            report.worker_failures >= 1,
            "the aborted worker must be reported",
        );
        assert!(inner.inner.snapshot().await.is_empty());

        assert!(
            submission_metric_value("best_effort", "dropped_shutdown") - shutdown_drops_before
                >= 2.0,
            "every event abandoned at shutdown must be counted",
        );
    }

    #[tokio::test]
    async fn bounded_recorder_accounts_for_backing_panic_and_keeps_worker_alive() {
        let inner = Arc::new(PanicOnceSink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        let panic_drops_before = submission_metric_value("best_effort", "dropped_worker_panic");
        let first_attempted = inner.first_attempted.notified();
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(Duration::from_secs(1), first_attempted)
            .await
            .expect("worker must begin the panicking attempt");
        recorder
            .record_best_effort(sample_event(EvidenceCategory::ManifestReload))
            .await;

        let report = handle.shutdown().await;
        assert_eq!(report.worker_failures, 0);
        assert_eq!(report.dropped_best_effort, 0);
        assert!(!report.timed_out);
        let events = inner.inner.snapshot().await;
        assert_eq!(events.len(), 1, "the worker must process the next event");
        assert_eq!(events[0].category, EvidenceCategory::ManifestReload);
        assert!(
            submission_metric_value("best_effort", "dropped_worker_panic") - panic_drops_before
                >= 1.0,
            "the panicked attempt must get an immediate terminal loss outcome",
        );
    }

    #[tokio::test]
    async fn dropping_queue_handle_aborts_workers_and_releases_backing_recorder() {
        let inner = Arc::new(GatedSink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        let stats = Arc::clone(&handle.stats);
        let shutdown_drops_before = submission_metric_value("best_effort", "dropped_shutdown");
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(Duration::from_secs(1), inner.started.notified())
            .await
            .expect("worker must enter the backing recorder");

        drop(recorder);
        drop(handle);
        assert_eq!(stats.load(QueuedEvidencePosture::BestEffort), 0);
        assert!(
            submission_metric_value("best_effort", "dropped_shutdown") - shutdown_drops_before
                >= 1.0,
            "forgotten-handle loss must be counted",
        );
        wait_until_workers_release_inner(&inner).await;
    }

    #[tokio::test]
    async fn cancelling_shutdown_aborts_workers_and_releases_backing_recorder() {
        let inner = Arc::new(GatedSink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        let stats = Arc::clone(&handle.stats);
        let shutdown_drops_before = submission_metric_value("best_effort", "dropped_shutdown");
        recorder
            .record_best_effort(sample_event(EvidenceCategory::UpstreamHealth))
            .await;
        tokio::time::timeout(Duration::from_secs(1), inner.started.notified())
            .await
            .expect("worker must enter the backing recorder");
        drop(recorder);

        let mut shutdown = Box::pin(handle.shutdown());
        tokio::select! {
            report = &mut shutdown => panic!("stuck worker drained unexpectedly: {report:?}"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        drop(shutdown);
        assert_eq!(stats.load(QueuedEvidencePosture::BestEffort), 0);
        assert!(
            submission_metric_value("best_effort", "dropped_shutdown") - shutdown_drops_before
                >= 1.0,
            "cancelled-shutdown loss must be counted",
        );
        wait_until_workers_release_inner(&inner).await;
    }

    #[tokio::test]
    async fn bounded_recorder_preserves_submission_order_within_a_tenant_shard() {
        let inner = Arc::new(InMemorySink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) = BoundedEvidenceRecorder::spawn(shared);
        let tenant = waygate_core::TenantId::parse("ordered-tenant").expect("tenant id valid");
        for index in 0..40 {
            recorder
                .record_chained_best_effort(
                    AuditEvent::new(format!("ordered-{index}"), AuditOutcome::Success)
                        .with_tenant(tenant.clone()),
                )
                .await;
        }

        let report = handle.shutdown().await;
        assert!(!report.timed_out);
        assert_eq!(report.dropped_chained_best_effort, 0);
        let actions: Vec<String> = inner
            .snapshot()
            .await
            .into_iter()
            .map(|event| event.action)
            .collect();
        assert_eq!(
            actions,
            (0..40)
                .map(|index| format!("ordered-{index}"))
                .collect::<Vec<_>>(),
            "one tenant's queue order must survive worker batching",
        );
    }

    #[tokio::test]
    async fn chained_sharding_uses_more_than_the_first_worker() {
        let inner: SharedEvidence = Arc::new(InMemorySink::new());
        let (recorder, handle) = BoundedEvidenceRecorder::spawn_with_config(
            inner,
            EvidenceQueueConfig {
                chained_shards: 4,
                queue_capacity: 1,
                batch_size: 1,
            },
        );
        let mut used = [false; 4];
        for index in 0..64 {
            let tenant = waygate_core::TenantId::parse(format!("shard-tenant-{index}"))
                .expect("tenant id valid");
            let event = AuditEvent::new("shard-probe", AuditOutcome::Success).with_tenant(tenant);
            used[recorder.chained_shard(&event)] = true;
        }
        assert!(
            used.into_iter().filter(|used| *used).count() > 1,
            "tenant hashing must distribute work beyond shard zero",
        );
        let report = handle.shutdown().await;
        assert!(!report.timed_out);
    }

    #[tokio::test]
    async fn bounded_recorder_rejects_submission_after_shutdown_without_waiting() {
        let inner = Arc::new(InMemorySink::new());
        let shared: SharedEvidence = inner.clone();
        let (recorder, handle) =
            BoundedEvidenceRecorder::spawn_with_config(shared, one_slot_queue_config());
        let report = handle.shutdown().await;
        assert!(!report.timed_out);

        tokio::time::timeout(
            Duration::from_millis(50),
            recorder.record_chained_best_effort(sample_event(EvidenceCategory::AuthAttempt)),
        )
        .await
        .expect("closed queue submission must return immediately");
        assert!(inner.snapshot().await.is_empty());
        let metrics = waygate_telemetry::gather_text();
        assert!(
            metrics.lines().any(|line| {
                line.contains("mcp_evidence_submission_total")
                    && line.contains("posture=\"chained_best_effort\"")
                    && line.contains("outcome=\"dropped_closed\"")
            }),
            "closed-queue loss must be observable:\n{metrics}",
        );
    }

    #[tokio::test]
    async fn trace_stamping_delegates_chained_best_effort() {
        let inner = Arc::new(InMemorySink::new());
        let rec = TraceStampingRecorder::new(inner.clone());
        let mut ev = sample_event(EvidenceCategory::OAuthEvent);
        ev.trace_id = Some("0123456789abcdef0123456789abcdef".into());

        rec.record_chained_best_effort(ev).await;

        let snap = inner.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].category, EvidenceCategory::OAuthEvent);
        assert_eq!(
            snap[0].trace_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef"),
        );
    }

    #[tokio::test]
    async fn trace_stamping_preserves_existing_trace_id() {
        // An event that already carries a trace_id passes through untouched —
        // the decorator never clobbers an explicitly-set correlation id.
        let inner = Arc::new(InMemorySink::new());
        let rec = TraceStampingRecorder::new(inner.clone());
        let mut ev = sample_event(EvidenceCategory::Invocation);
        ev.trace_id = Some("deadbeefdeadbeefdeadbeefdeadbeef".into());
        rec.record_best_effort(ev).await;
        let snap = inner.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].trace_id.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeef"),
        );
    }

    #[tokio::test]
    async fn trace_stamping_delegates_and_is_noop_without_provider() {
        // No tracer provider is installed in this unit-test binary, so
        // current_trace_id() is None: an unstamped event stays None but is
        // still delegated to (and recorded by) the inner sink. The valid
        // stamping path is covered by waygate-telemetry's trace_correlation
        // integration test.
        let inner = Arc::new(InMemorySink::new());
        let rec = TraceStampingRecorder::new(inner.clone());
        let ev = sample_event(EvidenceCategory::PolicyReload);
        let id = ev.id;
        let returned = rec
            .record_required(ev)
            .await
            .expect("decorator must delegate to the inner sink");
        assert_eq!(returned, id, "id is propagated from the inner sink");
        let snap = inner.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].trace_id, None);
    }

    #[test]
    fn audit_mode_parse_env_round_trip() {
        // Pin the env-var vocabulary `waygate-server::config` relies on:
        // exactly these two strings parse, anything else is None (which
        // config surfaces as a boot error rather than a silent default).
        assert_eq!(
            AuditMode::parse_env("best_effort"),
            Some(AuditMode::BestEffort)
        );
        assert_eq!(
            AuditMode::parse_env("fail_closed"),
            Some(AuditMode::FailClosed)
        );
        assert_eq!(AuditMode::parse_env("failclosed"), None);
        assert_eq!(AuditMode::parse_env(""), None);
    }

    #[test]
    fn audit_outcome_as_str_round_trip() {
        // Pin the wire vocabulary — the audit_log `outcome` column and the
        // exporters key off these literals, exactly like the
        // `EvidenceCategory` pin below.
        for (outcome, s) in [
            (AuditOutcome::Success, "success"),
            (AuditOutcome::ExecutionError, "execution_error"),
            (AuditOutcome::Denied, "denied"),
            (AuditOutcome::StepUpRequired, "step_up_required"),
        ] {
            assert_eq!(outcome.as_str(), s);
        }
    }

    #[test]
    fn audit_event_default_category_is_invocation() {
        // Backwards-compat: every existing `AuditEvent::new` caller in
        // the dispatch path expects an `Invocation` row without
        // chaining `with_category`. Lock that default.
        let ev = AuditEvent::new("CallTool", AuditOutcome::Success);
        assert_eq!(ev.category, EvidenceCategory::Invocation);
    }

    #[test]
    fn audit_event_with_category_overrides_default() {
        let ev = AuditEvent::new("PolicyReload", AuditOutcome::Success)
            .with_category(EvidenceCategory::PolicyReload);
        assert_eq!(ev.category, EvidenceCategory::PolicyReload);
    }

    #[test]
    fn evidence_category_as_str_round_trip() {
        // Pin the wire vocabulary — exporters (OCSF / syslog / S3) and
        // future read-side filters key off these literals, so a typo
        // here would silently break downstream pipelines.
        for (cat, s) in [
            (EvidenceCategory::Invocation, "invocation"),
            (EvidenceCategory::Discovery, "discovery"),
            (EvidenceCategory::LlmCompletion, "llm_completion"),
            (EvidenceCategory::AdminMutation, "admin_mutation"),
            (EvidenceCategory::AuthAttempt, "auth_attempt"),
            (EvidenceCategory::PolicyReload, "policy_reload"),
            (EvidenceCategory::ManifestReload, "manifest_reload"),
            (EvidenceCategory::ApiKeyLifecycle, "api_key_lifecycle"),
            (EvidenceCategory::OAuthEvent, "oauth_event"),
            (EvidenceCategory::UpstreamHealth, "upstream_health"),
            (EvidenceCategory::ApprovalLifecycle, "approval_lifecycle"),
            (EvidenceCategory::CatalogDrift, "catalog_drift"),
            (EvidenceCategory::DataInspection, "data_inspection"),
            (EvidenceCategory::RetentionSweep, "retention_sweep"),
        ] {
            assert_eq!(cat.as_str(), s);
        }
    }
}
