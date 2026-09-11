//! Durable execution state and append-only history for gateway-native Code
//! Mode.
//!
//! This is the internal execution domain. MCP Tasks can project these records
//! to clients, but its wire lifecycle does not define recovery, fencing, or
//! mutation-outcome truth.

mod store;

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_core::store::StoreError;

pub use store::{PgExecutionStore, SourceRetentionLimits};

pub type SharedExecutionStore = Arc<dyn ExecutionStore>;
pub type SharedSourceArtifactStore = Arc<dyn SourceArtifactStore>;
/// Intrinsic live retained-source budgets. Operator quota may be stricter,
/// but absence of a matching policy never removes these storage ceilings.
pub const MAX_RETAINED_SOURCES_PER_OWNER: i64 = 64;
pub const MAX_RETAINED_SOURCE_BYTES_PER_OWNER: i64 = 64 * 1024 * 1024;
pub const MAX_RETAINED_SOURCES_PER_TENANT: i64 = 1024;
pub const MAX_RETAINED_SOURCE_BYTES_PER_TENANT: i64 = 1024 * 1024 * 1024;
pub const MAX_SOURCE_LOCATORS_PER_OWNER: i64 = 256;
pub const MAX_SOURCE_LOCATORS_PER_TENANT: i64 = 4096;

/// Authenticated owner of one private retained source artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceArtifactOwner {
    pub tenant_id: String,
    pub principal_sub: String,
    pub principal_issuer: String,
}

/// Exact JavaScript bytes retained for bounded hash-based reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedSource {
    pub source: String,
    pub source_digest: String,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub trait SourceArtifactStore: Send + Sync + 'static {
    /// Retain exact validated source bytes for this owner. Re-submitting the
    /// same bytes may extend, but never shortens, their current lifetime.
    async fn retain_source(
        &self,
        owner: &SourceArtifactOwner,
        source: &str,
        source_digest: &str,
        retention: Duration,
    ) -> Result<RetainedSource, StoreError>;

    /// Resolve a live artifact under its full owner identity. Missing,
    /// expired, and differently-owned artifacts all return `None`.
    async fn resolve_source(
        &self,
        owner: &SourceArtifactOwner,
        source_digest: &str,
    ) -> Result<Option<RetainedSource>, StoreError>;

    /// Read only the current live deadline for decision-shaped responses.
    async fn resolve_source_expiry(
        &self,
        owner: &SourceArtifactOwner,
        source_digest: &str,
    ) -> Result<Option<OffsetDateTime>, StoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Submitted,
    Admitted,
    Running,
    WaitingForApproval,
    WaitingForResume,
    Compensating,
    Compensated,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
    Ambiguous,
    ReconciledApplied,
    ReconciledNotApplied,
}

impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::WaitingForResume => "waiting_for_resume",
            Self::Compensating => "compensating",
            Self::Compensated => "compensated",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Ambiguous => "ambiguous",
            Self::ReconciledApplied => "reconciled_applied",
            Self::ReconciledNotApplied => "reconciled_not_applied",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "submitted" => Self::Submitted,
            "admitted" => Self::Admitted,
            "running" => Self::Running,
            "waiting_for_approval" => Self::WaitingForApproval,
            "waiting_for_resume" => Self::WaitingForResume,
            "compensating" => Self::Compensating,
            "compensated" => Self::Compensated,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "expired" => Self::Expired,
            "ambiguous" => Self::Ambiguous,
            "reconciled_applied" => Self::ReconciledApplied,
            "reconciled_not_applied" => Self::ReconciledNotApplied,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Compensated
                | Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Expired
                | Self::ReconciledApplied
                | Self::ReconciledNotApplied
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEventKind {
    Submitted,
    Admitted,
    Claimed,
    Running,
    StepStarted,
    ConnectorCallStarted,
    ConnectorCallSucceeded,
    ConnectorCallFailed,
    ArtifactEmitted,
    WaitingForApproval,
    WaitingForResume,
    Resumed,
    CancellationRequested,
    Cancelled,
    Succeeded,
    Failed,
    Expired,
    Ambiguous,
    ReconciledApplied,
    ReconciledNotApplied,
    Compensating,
    Compensated,
}

impl ExecutionEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::StepStarted => "step_started",
            Self::ConnectorCallStarted => "connector_call_started",
            Self::ConnectorCallSucceeded => "connector_call_succeeded",
            Self::ConnectorCallFailed => "connector_call_failed",
            Self::ArtifactEmitted => "artifact_emitted",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::WaitingForResume => "waiting_for_resume",
            Self::Resumed => "resumed",
            Self::CancellationRequested => "cancellation_requested",
            Self::Cancelled => "cancelled",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Ambiguous => "ambiguous",
            Self::ReconciledApplied => "reconciled_applied",
            Self::ReconciledNotApplied => "reconciled_not_applied",
            Self::Compensating => "compensating",
            Self::Compensated => "compensated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Execution {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    /// Issuer that minted the owner's `sub`. Ownership binds
    /// tenant + issuer + subject; `None` marks a pre-upgrade row, which
    /// every owner-gated surface refuses (fail closed) and which ages out
    /// on its retention clock.
    pub principal_issuer: Option<String>,
    pub source: Option<String>,
    pub source_digest: String,
    /// Caller-supplied data the program reads. Bound at submission and
    /// replayed unchanged on every later attempt, so a resumed program sees
    /// the input the attempt it continues was given. `None` on a row
    /// submitted without input, and on rows predating the column.
    pub program_input: Option<Value>,
    pub execution_profile: Value,
    pub tool_snapshot: Option<Value>,
    pub sdk_contract_version: i32,
    pub runner_contract_version: i32,
    pub status: ExecutionStatus,
    pub terminal_reason_code: Option<String>,
    pub result_metadata: Option<Value>,
    pub result_payload: Option<Value>,
    pub resume_context: Option<Value>,
    pub claim_owner: Option<Uuid>,
    pub claim_epoch: i64,
    pub claim_expires_at: Option<OffsetDateTime>,
    pub cancellation_requested_at: Option<OffsetDateTime>,
    /// Which authority requested the pending cancellation
    /// (`cancelled_by_client` / `cancelled_by_operator`). Recorded at
    /// request time because a live claim finalizes the cancellation later,
    /// when the requester is no longer on the call path; the finalizing
    /// transition reports this value. First request wins. `None` on rows
    /// with no pending request, or whose request predates the column.
    pub cancellation_reason_code: Option<String>,
    pub submitted_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub retention_until: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewExecution {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    /// Issuer that minted the owner's `sub`; always populated on new rows.
    pub principal_issuer: String,
    pub source: Option<String>,
    pub source_digest: String,
    /// Caller-supplied data the program reads, bound durably at submission.
    pub program_input: Option<Value>,
    pub execution_profile: Value,
    pub sdk_contract_version: i32,
    pub runner_contract_version: i32,
    pub retention_until: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct StartExecution {
    pub execution: NewExecution,
    /// Gateway-derived identity for one retry-equivalent detached start.
    pub dedupe_key: String,
    /// Fixed-width identity of an immutable uploaded-file URI. When present,
    /// admission binds it to the resolved content digest for retry lookup.
    pub source_locator: Option<String>,
    /// Prior matching terminal execution the caller deliberately repeats.
    /// A retry of that repetition returns the newer matching execution.
    pub repeat_after: Option<Uuid>,
    pub owner: Uuid,
    pub lease: Duration,
    pub source: String,
    pub tool_snapshot: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StartExecutionResult {
    /// This call created and fenced the one execution a worker must run.
    Claimed {
        execution: Execution,
        claim: ExecutionClaim,
    },
    /// Matching work already exists; return its handle and start no worker.
    Existing(Execution),
    /// The deliberate-repeat handle is not a retained matching execution.
    RepeatUnavailable,
    /// The deliberate-repeat handle still has a non-terminal lifecycle.
    RepeatNotTerminal(Execution),
}

/// The durable identity that makes two detached starts retry-equivalent.
/// Every field participates: the dedupe key scopes the lookup, and the
/// remaining columns are compared in full so a key collision can never
/// merge unrelated work.
#[derive(Debug, Clone)]
pub struct RetryEquivalence {
    pub tenant_id: String,
    pub principal_sub: String,
    pub principal_issuer: String,
    pub dedupe_key: String,
    pub source_digest: String,
    pub execution_profile: Value,
}

/// The owner identity that scopes an in-flight listing. Every field narrows:
/// tenant and subject select the caller's rows, the issuer refuses a
/// same-`sub` principal minted by a different issuer (a pre-upgrade
/// issuer-less row matches nothing — fail closed), and the profile
/// confinement restricts the listing to exactly the rows the by-id surfaces
/// would serve, so enumeration can never reach an execution that retrieval
/// by identifier would refuse.
#[derive(Debug, Clone)]
pub struct OwnedInFlight {
    pub tenant_id: String,
    pub principal_sub: String,
    pub principal_issuer: String,
    pub profile_confinement: Value,
}

/// The decision-shaped subset of an execution a listing returns. This is a
/// SQL-level selection, not a projection of a full row: caller-controlled
/// payloads — source, checkpoints, results, tool snapshots — are never
/// materialized, so a page's size is bounded by its row count alone no
/// matter what the listed programs stored.
#[derive(Debug, Clone)]
pub struct InFlightExecution {
    pub id: Uuid,
    pub status: ExecutionStatus,
    pub terminal_reason_code: Option<String>,
    pub result_available: bool,
    pub cancellation_requested: bool,
    pub submitted_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub retention_until: OffsetDateTime,
}

/// The operator-facing metadata subset of an in-flight execution.
///
/// Unlike [`InFlightExecution`] this carries the owner identity and claim
/// liveness: the operator's question is "what is running here, for whom,
/// and since when", which the owner-scoped listing deliberately omits
/// because its caller already is the owner. It stays payload-free for the
/// same reason that listing does — results, checkpoints, source, and
/// snapshots are governed content whose retention is an explicit
/// information-flow decision an observability surface must not bypass.
#[derive(Debug, Clone)]
pub struct OperatorInFlightExecution {
    pub id: Uuid,
    pub principal_sub: String,
    pub principal_issuer: Option<String>,
    pub status: ExecutionStatus,
    pub cancellation_requested: bool,
    /// Whether a worker currently holds a live (unexpired) claim.
    pub claimed: bool,
    pub claim_expires_at: Option<OffsetDateTime>,
    pub submitted_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub retention_until: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ResumeExecution {
    pub tenant_id: String,
    pub principal_sub: String,
    /// The resuming caller's issuer; the resume claim binds
    /// tenant + issuer + subject, and a pre-upgrade issuer-less row
    /// matches nothing (fail closed).
    pub principal_issuer: String,
    pub id: Uuid,
    pub owner: Uuid,
    pub lease: Duration,
    pub expected_status: ExecutionStatus,
    pub resume_context: Value,
    pub expected_claim_epoch: i64,
    pub expected_resume_context: Option<Value>,
    pub expected_source_digest: String,
    pub expected_tool_snapshot: Value,
    pub expected_sdk_contract_version: i32,
    pub expected_runner_contract_version: i32,
    pub next_sdk_contract_version: i32,
    pub next_runner_contract_version: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    pub execution_id: Uuid,
    pub tenant_id: String,
    pub owner: Uuid,
    pub epoch: i64,
}

/// Deployment-wide lease for one principal's detached Code Mode attempt.
///
/// The holder token fences release and renewal: a replica whose lease expired
/// cannot release a newer replica's slot after it resumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedExecutionSlot {
    pub tenant_id: String,
    pub principal_sub: String,
    pub principal_issuer: String,
    pub holder: Uuid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub id: i64,
    pub execution_id: Uuid,
    pub tenant_id: String,
    pub kind: String,
    pub step_number: Option<i32>,
    pub call_id: Option<Uuid>,
    pub attempt: Option<i32>,
    pub detail: Value,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionArtifact {
    pub event_id: i64,
    pub execution_id: Uuid,
    pub artifact_id: Uuid,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionArtifactContent {
    pub artifact: ExecutionArtifact,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct NewExecutionEvent {
    pub kind: ExecutionEventKind,
    pub step_number: Option<i32>,
    pub call_id: Option<Uuid>,
    pub attempt: Option<i32>,
    pub detail: Value,
}

#[derive(Debug, Clone)]
pub struct ExecutionTransition {
    pub from: Vec<ExecutionStatus>,
    pub to: ExecutionStatus,
    pub event: NewExecutionEvent,
    pub terminal_reason_code: Option<String>,
    pub result_metadata: Option<Value>,
    pub result_payload: Option<Value>,
    pub resume_context: Option<Value>,
}

#[async_trait]
pub trait ExecutionStore: Send + Sync + 'static {
    async fn acquire_detached_slot(
        &self,
        slot: &DetachedExecutionSlot,
        lease: Duration,
    ) -> Result<bool, StoreError>;

    async fn release_detached_slot(&self, slot: &DetachedExecutionSlot)
        -> Result<bool, StoreError>;

    /// Extend the lease on a held detached slot without changing its holder.
    ///
    /// `false` means the holder fence refused: the lease lapsed and another
    /// attempt replaced the row, so the caller no longer owns the slot. A
    /// lapsed-but-unstolen row still carries this holder and renews normally.
    async fn renew_detached_slot(
        &self,
        slot: &DetachedExecutionSlot,
        lease: Duration,
    ) -> Result<bool, StoreError>;

    async fn submit(&self, execution: NewExecution) -> Result<Execution, StoreError>;

    /// Atomically reuse a retry-equivalent detached execution or insert and
    /// fence its replacement. Implementations must serialize on `dedupe_key`;
    /// a separate lookup followed by submission does not satisfy this contract.
    async fn start_or_reuse(
        &self,
        start: StartExecution,
    ) -> Result<StartExecutionResult, StoreError>;

    /// Retained execution(s) with this retry-equivalence identity: the
    /// newest when `id` is `None`, or the named chain member when `id`
    /// is given — under exactly the identity and retention predicate
    /// `start_or_reuse` enforces, so a NULL-keyed blocking execution or an
    /// expired row never passes as a member.
    ///
    /// Read-only convergence probe: a hit is a durable answer the caller may
    /// return without paying admission, while a miss proves nothing — only
    /// `start_or_reuse` enforces uniqueness.
    async fn find_retry_equivalent(
        &self,
        probe: &RetryEquivalence,
        id: Option<Uuid>,
    ) -> Result<Option<Execution>, StoreError>;

    /// Resolve an admitted immutable source locator to its exact content
    /// digest. The binding is private to the full owner identity and expires
    /// with the durable execution lifecycle that admitted it.
    async fn resolve_source_locator(
        &self,
        owner: &SourceArtifactOwner,
        source_locator: &str,
    ) -> Result<Option<String>, StoreError>;

    /// Bind a newly resolved immutable locator to exact source bytes. A
    /// locator can extend its lifetime but can never be rebound to new bytes.
    async fn bind_source_locator(
        &self,
        owner: &SourceArtifactOwner,
        source_locator: &str,
        source_digest: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError>;

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Execution>, StoreError>;

    async fn list_waiting_approvals(
        &self,
        tenant_id: &str,
        limit: u16,
    ) -> Result<Vec<Execution>, StoreError> {
        let _ = (tenant_id, limit);
        Ok(Vec::new())
    }

    /// List the owner's in-flight executions, newest submission first.
    ///
    /// In-flight is the store's own invariant — `completed_at` is set exactly
    /// when a transition is terminal — and rows past retention are excluded,
    /// so the listing never hands out an identifier the by-id surfaces would
    /// already treat as gone. `before` is an exclusive `(submitted_at, id)`
    /// keyset bound for paging; rows are visible as stored, without
    /// reconciliation — a caller acts on a discovered identifier through the
    /// by-id surfaces, which reconcile.
    async fn list_owned_in_flight(
        &self,
        owner: &OwnedInFlight,
        before: Option<(OffsetDateTime, Uuid)>,
        limit: u16,
    ) -> Result<Vec<InFlightExecution>, StoreError> {
        let _ = (owner, before, limit);
        Ok(Vec::new())
    }

    /// List a tenant's in-flight executions for an operator, newest
    /// submission first, optionally narrowed to one subject.
    ///
    /// Tenant-scoped by design, not owner-scoped: the operator audience
    /// answers "what is holding capacity here", so it spans principals,
    /// while [`ExecutionStore::list_owned_in_flight`] binds the full owner
    /// identity by construction. Rows past retention are excluded — the
    /// by-id surfaces already treat them as gone. Offset paging matches
    /// the admin task surface this view sits beside.
    async fn list_in_flight_for_operator(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<OperatorInFlightExecution>, StoreError> {
        let _ = (tenant_id, principal_sub, limit, offset);
        Ok(Vec::new())
    }

    async fn deny_waiting_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver: &str,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        let _ = (tenant_id, id, approver, reason);
        Ok(false)
    }

    async fn claim(
        &self,
        tenant_id: &str,
        id: Uuid,
        owner: Uuid,
        lease: Duration,
        source: String,
        tool_snapshot: Value,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError>;

    async fn resume(
        &self,
        execution: ResumeExecution,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError>;

    async fn renew(&self, claim: &ExecutionClaim, lease: Duration) -> Result<bool, StoreError>;

    /// Extend the worker lease while the one approved side effect is in
    /// flight. Unlike [`ExecutionStore::renew`], a pending cancellation
    /// request does not refuse the extension: an in-flight effect is never
    /// abandoned, so the lease must stay alive until its outcome reaches the
    /// journal, and the cancellation finalizes at the next journal boundary
    /// afterward. Owner, epoch, and completion still fence. The default
    /// delegates to `renew` for stores that never dispatch effects; a store
    /// that does must override it.
    async fn renew_effect_lease(
        &self,
        claim: &ExecutionClaim,
        lease: Duration,
    ) -> Result<bool, StoreError> {
        self.renew(claim, lease).await
    }

    async fn append_event(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<bool, StoreError>;

    /// Append the journal outcome of a side effect this claim already
    /// dispatched. Identical to [`ExecutionStore::append_event`] except a
    /// pending cancellation request does not refuse the write: the outcome
    /// of an effect that already left the gateway must reach the journal
    /// even when cancellation arrived while it was in flight. Claim fencing
    /// still applies.
    async fn append_effect_outcome(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<bool, StoreError>;

    async fn transition(
        &self,
        claim: &ExecutionClaim,
        transition: ExecutionTransition,
    ) -> Result<Option<Execution>, StoreError>;

    async fn fail_submission(
        &self,
        tenant_id: &str,
        id: Uuid,
        event: NewExecutionEvent,
        reason_code: String,
    ) -> Result<Option<Execution>, StoreError>;

    async fn request_cancellation(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        principal_issuer: &str,
        id: Uuid,
    ) -> Result<Option<Execution>, StoreError>;

    /// Request cancellation of any execution in the tenant, without owner
    /// binding — the operator's authority, the same shape as
    /// [`ExecutionStore::deny_waiting_approval`]. The recorded reason is
    /// `cancelled_by_operator` and the journal event carries the
    /// operator's subject, so an owner polling the outcome can tell an
    /// operator intervention from its own cancellation. Semantics
    /// otherwise match the owner path: an unclaimed or dead-claim row
    /// terminalizes immediately; a live claim keeps its lease and the
    /// runner observes the request. `None` means no such execution exists
    /// in this tenant.
    async fn request_cancellation_for_operator(
        &self,
        tenant_id: &str,
        id: Uuid,
        operator_sub: &str,
    ) -> Result<Option<Execution>, StoreError> {
        let _ = (tenant_id, id, operator_sub);
        Ok(None)
    }

    async fn reconcile_abandoned(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        principal_issuer: &str,
        id: Uuid,
        submission_grace: Duration,
    ) -> Result<Option<Execution>, StoreError>;

    async fn events(&self, tenant_id: &str, id: Uuid) -> Result<Vec<ExecutionEvent>, StoreError>;

    async fn list_artifacts(
        &self,
        tenant_id: &str,
        id: Uuid,
        after_event_id: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ExecutionArtifact>, StoreError>;

    async fn get_artifact(
        &self,
        tenant_id: &str,
        id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Option<ExecutionArtifactContent>, StoreError>;
}

pub fn source_digest(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_vocabulary_roundtrips() {
        for status in [
            ExecutionStatus::Submitted,
            ExecutionStatus::Admitted,
            ExecutionStatus::Running,
            ExecutionStatus::WaitingForApproval,
            ExecutionStatus::WaitingForResume,
            ExecutionStatus::Compensating,
            ExecutionStatus::Compensated,
            ExecutionStatus::Succeeded,
            ExecutionStatus::Failed,
            ExecutionStatus::Cancelled,
            ExecutionStatus::Expired,
            ExecutionStatus::Ambiguous,
            ExecutionStatus::ReconciledApplied,
            ExecutionStatus::ReconciledNotApplied,
        ] {
            assert_eq!(ExecutionStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(ExecutionStatus::parse("unknown"), None);
    }

    #[test]
    fn source_digest_is_stable_and_content_bound() {
        assert_eq!(
            source_digest("return 1;"),
            "f58b7c3af621b52a2bb7dc67d4491f9ab6c6d16e3cfa1e46e670ff4f9a301fdc"
        );
        assert_ne!(source_digest("return 1;"), source_digest("return 2;"));
    }
}
