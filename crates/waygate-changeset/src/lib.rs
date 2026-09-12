//! HITL control-plane: the change-request durable primitive.
//!
//! ## What this is
//!
//! A store for agent-proposed control-plane changes. An automated
//! caller (Claude over MCP) holding a propose-only credential captures
//! the INTENT of a privileged admin mutation — the action type, the
//! parameters, a rendered preview, a freshness etag — as a `pending`
//! row here, WITHOUT executing it. A human reviews the row in the
//! dashboard and approves or denies; only on approval does the captured
//! intent execute server-side. This is the control-plane sibling
//! of the data-plane [`waygate_catalog`] `approval_grants`: same
//! "propose -> human checks -> act" shape, but the thing being
//! authorized is a gateway admin mutation, not an upstream tool call.
//!
//! See `docs/agents/hitl-control-plane.md` for the full design.
//!
//! ## What this crate delivers (and what it doesn't)
//!
//! This crate is the durable substrate plus the *race-safe decision
//! primitive*:
//!
//! - [`ChangeRequestStore::propose`] inserts a `pending` row.
//! - [`ChangeRequestStore::get`] / [`ChangeRequestStore::list`] are the poll +
//!   full pending review rows; [`ChangeRequestStore::list_summaries`] provides
//!   bounded expired/decided history rows.
//! - [`ChangeRequestStore::try_approve`] / [`ChangeRequestStore::try_deny`]
//!   are single-use atomic transitions out of `pending` (the break_glass
//!   `try_claim` idiom): a double-click or two parallel approvers cannot
//!   double-act. Approval authority is enforced before these transitions;
//!   the store enforces the captured distinct-approval count without adding
//!   an implicit non-counted proposer.
//!
//! The `approved -> executing -> executed/failed` execution transitions
//! are `try_begin_execution` / `mark_executed` / `mark_failed`.
//! `try_approve` is the `required_approvals = 1` fast path (the
//! single-operator default); collecting M-of-N distinct approvals is
//! [`ChangeRequestStore::record_approval`].

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// Hard ceiling on [`ChangeRequestStore::list`] page size, mirroring
/// the `MAX_LIST_LIMIT` discipline in `waygate-authz`'s break_glass /
/// oauth_consent stores.
pub use waygate_core::page::MAX_LIST_LIMIT;

const HISTORY_OUTCOME_PREVIEW_CHARS: usize = 200;
const HISTORY_OUTCOME_MAX_BYTES: usize = 16 * 1024;
const STATUS_LIST_OUTCOME_MAX_BYTES: usize = 16 * 1024;

/// Lifecycle status of a change request. The DB CHECK constraint and
/// this enum must stay in lockstep — see `migrations/0039`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestStatus {
    /// Captured intent awaiting a human decision. The only state the
    /// maker can create; every transition out is a single-use atomic
    /// UPDATE.
    Pending,
    /// A human approved; awaiting execution. Used as the waypoint when
    /// a cooldown is configured; otherwise the claim goes
    /// `pending -> executing` directly at execute time.
    Approved,
    /// Execution in progress (the executor claimed the row).
    Executing,
    /// Terminal success — `execution_result` populated.
    Executed,
    /// Terminal failure — `error_message` populated. A failed execution
    /// lands here loudly rather than being tombstoned as done.
    Failed,
    /// Terminal refusal by a human — `denied_reason` populated.
    Denied,
    /// Terminal: the request lapsed without a decision before
    /// `expires_at`.
    Expired,
}

impl ChangeRequestStatus {
    /// The `TEXT` value stored in the `status` column.
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Executing => "executing",
            Self::Executed => "executed",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    /// Parse the `status` column back into the enum. `None` for an
    /// unrecognised value (the CHECK constraint makes this
    /// unreachable in practice; the row decoder maps `None` to a
    /// decode error).
    pub fn from_db_str(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "executing" => Self::Executing,
            "executed" => Self::Executed,
            "failed" => Self::Failed,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            _ => return None,
        })
    }

    /// True once the request can no longer change state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Failed | Self::Denied | Self::Expired
        )
    }
}

/// The lifecycle bucket a [`ChangeRequestStore::list`] call filters to.
/// `None` (legacy unfiltered) lists every state newest-first; a bucket
/// applies the cap WITHIN the bucket so an old pending request isn't
/// dropped behind a wall of newer terminal rows. Mirrors
/// `BreakGlassLifecycle` / `GrantLifecycle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeRequestLifecycle {
    /// `status = 'pending' AND expires_at > now()` — needs a human.
    Pending,
    /// `status = 'pending' AND expires_at <= now()` — lapsed without a
    /// decision.
    Expired,
    /// `status <> 'pending'` — approved / executed / failed / denied /
    /// expired terminal history.
    Decided,
}

impl ChangeRequestLifecycle {
    /// Bind string consumed by the `CASE` arms in the Postgres `list`.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Expired => "expired",
            Self::Decided => "decided",
        }
    }
}

/// Known approval factors a deployment can require of each approval.
/// Stored as `TEXT[]` so the set can grow without a migration; this
/// enum is the validated vocabulary the handler / dashboard use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalFactor {
    /// Explicit MFA-token assurance reported in signed `amr`; passkey
    /// evidence is intentionally distinct and does not satisfy this factor.
    Mfa,
    /// A WebAuthn / passkey assertion — the strongest single-human
    /// gesture, the preferred mobile step-up.
    Passkey,
    /// A break-glass token must back the approval — the single-user
    /// "second factor in time" for the protected/meta class.
    BreakGlass,
}

impl ApprovalFactor {
    /// The `TEXT[]` element value.
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Mfa => "mfa",
            Self::Passkey => "passkey",
            Self::BreakGlass => "break_glass",
        }
    }

    /// Parse one stored factor string. `None` for an unknown value.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Some(match s {
            "mfa" => Self::Mfa,
            "passkey" => Self::Passkey,
            "break_glass" => Self::BreakGlass,
            _ => return None,
        })
    }
}

/// The approval requirement captured onto a change request at propose
/// time, frozen so config edited mid-flight can't weaken a pending
/// request.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRequirement {
    /// Distinct human approvals needed. Default 1 — single-operator
    /// deployments work without a second human; multi-user opt up.
    pub required_approvals: i32,
    /// The role whose members may approve.
    pub eligible_role: String,
    /// What each approval must present (stored as `TEXT[]`). Empty =
    /// no extra factor beyond the dashboard session.
    pub factors: Vec<String>,
    /// Optional notified delay from proposal creation before approval may
    /// execute (the single-user "second look" in lieu of a second human).
    /// The admin approval boundary enforces it before recording a decision;
    /// the persistence layer only stores the frozen value.
    pub cooldown_seconds: Option<i32>,
}

impl ApprovalRequirement {
    /// The common single-approver requirement: one approval from
    /// `eligible_role`, no extra factors, no cooldown.
    pub fn single(eligible_role: impl Into<String>) -> Self {
        Self {
            required_approvals: 1,
            eligible_role: eligible_role.into(),
            factors: Vec::new(),
            cooldown_seconds: None,
        }
    }
}

/// Progress of an M-of-N approval collection, returned by
/// [`ChangeRequestStore::record_approval`]. `collected` distinct approvals
/// have been recorded toward `required`; `approved` is `Some` iff THIS
/// approval completed the quorum and atomically flipped the row to
/// `approved` (ready to execute), and `None` while more approvals are
/// still needed.
///
/// `recorded` is `true` iff THIS call inserted a NEW distinct approval —
/// `false` when it was a no-op (a repeat by the same approver or a
/// non-pending/expired change).
///
/// `counted` is `true` iff this approver's approval is part of the LIVE
/// quorum (the change is still pending and unexpired) — recorded on this call
/// OR a prior one. The handler audits
/// every `counted` approval (so a quorum-counting approval is never left
/// without an audit even if a post-commit audit failed and the approver
/// retried), wording it by `recorded`; a non-`counted`
/// no-op (decided / expired) is genuinely nothing and is not
/// audited.
#[derive(Debug, Clone)]
pub struct ApprovalProgress {
    pub collected: i64,
    pub required: i32,
    pub recorded: bool,
    pub counted: bool,
    pub approved: Option<ChangeRequest>,
}

const BINDING_ADJECTIVES: &[&str] = &[
    "AMBER", "AZURE", "BRAVE", "CRISP", "DUSKY", "EAGER", "FROST", "GOLD", "HAZEL", "IVORY",
    "JADE", "LUNAR", "MOSSY", "NOBLE", "OPAL", "PRISM",
];

const BINDING_NOUNS: &[&str] = &[
    "OTTER", "FALCON", "HERON", "LYNX", "MARTEN", "NEWT", "ORCA", "PUMA", "QUAIL", "RAVEN",
    "SABLE", "TERN", "URCHIN", "VOLE", "WREN", "YAK",
];

/// Derive the human-legible binding code (the CIBA `binding_message`
/// short code) from a change request's UUID. Deterministic — the same
/// id always yields the same code — and pulled from the UUIDv7 RANDOM
/// tail (bytes 10/12/14) rather than the leading timestamp bytes, so
/// two requests proposed in the same millisecond don't collide on a
/// near-identical code. The code is a confirmation aid shown on both
/// the agent side and the approval page, not a secret.
pub fn binding_code_from_uuid(id: &Uuid) -> String {
    let b = id.as_bytes();
    let adj = BINDING_ADJECTIVES[b[10] as usize % BINDING_ADJECTIVES.len()];
    let noun = BINDING_NOUNS[b[12] as usize % BINDING_NOUNS.len()];
    let num = b[14] % 100;
    format!("{adj}-{noun}-{num:02}")
}

/// Input to [`ChangeRequestStore::propose`]. The store assigns the id
/// (UUIDv7) and derives the `binding_code`; everything else is the
/// captured intent + frozen requirement.
#[derive(Debug, Clone)]
pub struct NewChangeRequest {
    pub tenant_id: String,
    /// The propose-credential `sub`. Becomes `requested_by`; it may also be an
    /// approver when that identity independently holds approval authority.
    pub requested_by: String,
    /// The OAuth client id, when present.
    pub client_id: Option<String>,
    /// Registry key, e.g. `api_key.mint`.
    pub action_type: String,
    /// The captured intent the executor replays.
    pub params: Value,
    /// The human-rendered preview computed at propose time. No per-class
    /// renderer populates this yet, so it is currently always `None`.
    pub preview: Option<Value>,
    /// Opaque freshness witness captured at propose time. Most actions store a
    /// target hash; race-safe conditional mutations may store a structured,
    /// non-secret version token instead.
    pub target_etag: Option<String>,
    /// Agent-supplied reason. Required, non-empty.
    pub justification: String,
    /// The approval requirement, frozen at propose time.
    pub requirement: ApprovalRequirement,
    /// Wall-clock expiry. A pending request past this is auto-denied
    /// (surfaced as [`ChangeRequestStatus::Expired`]).
    pub expires_at: OffsetDateTime,
}

impl NewChangeRequest {
    /// Validate the captured intent + frozen requirement before the
    /// insert (side-effects last). Rejects empty justification / action
    /// type, a sub-1 approval count, an empty `eligible_role` (a row
    /// nobody could approve), and any `required_factors` entry outside
    /// the known [`ApprovalFactor`] vocabulary — in addition to the DB
    /// CHECK constraints. This is the choke point the propose handler
    /// (`change_requests::propose_core` in `waygate-admin`) builds an
    /// [`ApprovalRequirement`] through, so the hardening lands here
    /// regardless of which handler calls it.
    pub fn validate(&self) -> Result<(), ChangeRequestError> {
        if self.justification.trim().is_empty() {
            return Err(ChangeRequestError::EmptyJustification);
        }
        if self.action_type.trim().is_empty() {
            return Err(ChangeRequestError::EmptyActionType);
        }
        if self.requirement.required_approvals < 1 {
            return Err(ChangeRequestError::InvalidApprovalCount(
                self.requirement.required_approvals,
            ));
        }
        if self.requirement.eligible_role.trim().is_empty() {
            return Err(ChangeRequestError::EmptyEligibleRole);
        }
        if let Some(cooldown_seconds) = self.requirement.cooldown_seconds {
            if cooldown_seconds < 0 {
                return Err(ChangeRequestError::InvalidCooldown(cooldown_seconds));
            }
        }
        // An unknown factor string would be silently ignored or make the bar
        // permanently unsatisfiable. New factors are added to
        // `ApprovalFactor` alongside their enforcement, never introduced as
        // free-form data.
        if let Some(bad) = self
            .requirement
            .factors
            .iter()
            .find(|f| ApprovalFactor::from_db_str(f).is_none())
        {
            return Err(ChangeRequestError::UnknownFactor(bad.clone()));
        }
        Ok(())
    }
}

/// A persisted change request. Mirrors a `change_requests` row.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeRequest {
    pub id: Uuid,
    pub tenant_id: String,
    pub requested_by: String,
    pub client_id: Option<String>,
    pub action_type: String,
    pub params: Value,
    pub preview: Option<Value>,
    /// Action-specific, opaque freshness witness. The historical `etag` name
    /// does not imply a hash: executors may persist a digest or a structured,
    /// non-secret version token, and only the owning executor may interpret it.
    pub target_etag: Option<String>,
    pub justification: String,
    pub binding_code: String,
    pub required_approvals: i32,
    pub eligible_role: String,
    pub required_factors: Vec<String>,
    pub cooldown_seconds: Option<i32>,
    pub status: ChangeRequestStatus,
    pub approver_sub: Option<String>,
    pub denied_reason: Option<String>,
    pub execution_result: Option<Value>,
    pub error_message: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub executed_at: Option<OffsetDateTime>,
}

impl ChangeRequest {
    /// The frozen approval requirement captured on this row.
    pub fn requirement(&self) -> ApprovalRequirement {
        ApprovalRequirement {
            required_approvals: self.required_approvals,
            eligible_role: self.eligible_role.clone(),
            factors: self.required_factors.clone(),
            cooldown_seconds: self.cooldown_seconds,
        }
    }

    /// The status as the poll should report it: a `pending` row past
    /// its expiry reads as [`ChangeRequestStatus::Expired`] even though
    /// no background sweep has flipped the physical column yet.
    pub fn effective_status(&self, now: OffsetDateTime) -> ChangeRequestStatus {
        if self.status == ChangeRequestStatus::Pending && now >= self.expires_at {
            ChangeRequestStatus::Expired
        } else {
            self.status
        }
    }
}

/// Bounded projection for history lists. Expired/decided dashboard rows never
/// render captured params. Successful outcomes carry a size-bounded structured
/// receipt plus a short text preview; loading full [`ChangeRequest`]s would
/// otherwise let large historical payloads consume the approval page's memory
/// budget.
#[derive(Debug, Clone)]
pub struct ChangeRequestSummary {
    pub id: Uuid,
    pub requested_by: String,
    pub action_type: String,
    pub justification: String,
    pub binding_code: String,
    pub required_approvals: i32,
    pub eligible_role: String,
    pub required_factors: Vec<String>,
    pub cooldown_seconds: Option<i32>,
    pub status: ChangeRequestStatus,
    pub approver_sub: Option<String>,
    pub denied_reason: Option<String>,
    /// Structured execution receipt when it fits the bounded history envelope.
    /// Internal executors use this for outcome-specific operator projections;
    /// large receipts stay available from the single-request endpoint while
    /// history rendering falls back to [`Self::execution_result_preview`].
    pub execution_result: Option<Value>,
    pub execution_result_preview: Option<String>,
    pub error_message: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Captured-payload-free projection for the maker's status list. The list API
/// exposes execution outcomes but never proposal params, previews, or target
/// witnesses; selecting those discarded fields would make polling memory scale
/// with the largest review payload.
#[derive(Debug, Clone)]
pub struct ChangeRequestStatusSummary {
    pub id: Uuid,
    pub requested_by: String,
    pub action_type: String,
    pub binding_code: String,
    pub status: ChangeRequestStatus,
    pub approver_sub: Option<String>,
    pub denied_reason: Option<String>,
    pub execution_result: Option<Value>,
    pub error_message: Option<String>,
    pub expires_at: OffsetDateTime,
}

impl ChangeRequestStatusSummary {
    pub fn effective_status(&self, now: OffsetDateTime) -> ChangeRequestStatus {
        if self.status == ChangeRequestStatus::Pending && now >= self.expires_at {
            ChangeRequestStatus::Expired
        } else {
            self.status
        }
    }
}

impl From<&ChangeRequest> for ChangeRequestStatusSummary {
    fn from(row: &ChangeRequest) -> Self {
        Self {
            id: row.id,
            requested_by: row.requested_by.clone(),
            action_type: row.action_type.clone(),
            binding_code: row.binding_code.clone(),
            status: row.status,
            approver_sub: row.approver_sub.clone(),
            denied_reason: row.denied_reason.clone(),
            execution_result: row
                .execution_result
                .as_ref()
                .and_then(bounded_status_result),
            error_message: row.error_message.clone(),
            expires_at: row.expires_at,
        }
    }
}

impl From<&ChangeRequest> for ChangeRequestSummary {
    fn from(row: &ChangeRequest) -> Self {
        Self {
            id: row.id,
            requested_by: row.requested_by.clone(),
            action_type: row.action_type.clone(),
            justification: row.justification.clone(),
            binding_code: row.binding_code.clone(),
            required_approvals: row.required_approvals,
            eligible_role: row.eligible_role.clone(),
            required_factors: row.required_factors.clone(),
            cooldown_seconds: row.cooldown_seconds,
            status: row.status,
            approver_sub: row.approver_sub.clone(),
            denied_reason: row.denied_reason.clone(),
            execution_result: row
                .execution_result
                .as_ref()
                .and_then(bounded_history_result),
            execution_result_preview: row.execution_result.as_ref().map(history_outcome_preview),
            error_message: row.error_message.clone(),
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for ChangeRequestSummary {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let status = status_from_row(row)?;
        Ok(Self {
            id: row.try_get("id")?,
            requested_by: row.try_get("requested_by")?,
            action_type: row.try_get("action_type")?,
            justification: row.try_get("justification")?,
            binding_code: row.try_get("binding_code")?,
            required_approvals: row.try_get("required_approvals")?,
            eligible_role: row.try_get("eligible_role")?,
            required_factors: row.try_get("required_factors")?,
            cooldown_seconds: row.try_get("cooldown_seconds")?,
            status,
            approver_sub: row.try_get("approver_sub")?,
            denied_reason: row.try_get("denied_reason")?,
            execution_result: row.try_get("execution_result")?,
            execution_result_preview: row.try_get("execution_result_preview")?,
            error_message: row.try_get("error_message")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for ChangeRequestStatusSummary {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            requested_by: row.try_get("requested_by")?,
            action_type: row.try_get("action_type")?,
            binding_code: row.try_get("binding_code")?,
            status: status_from_row(row)?,
            approver_sub: row.try_get("approver_sub")?,
            denied_reason: row.try_get("denied_reason")?,
            execution_result: row.try_get("execution_result")?,
            error_message: row.try_get("error_message")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for ChangeRequest {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let status = status_from_row(row)?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            requested_by: row.try_get("requested_by")?,
            client_id: row.try_get("client_id")?,
            action_type: row.try_get("action_type")?,
            params: row.try_get("params")?,
            preview: row.try_get("preview")?,
            target_etag: row.try_get("target_etag")?,
            justification: row.try_get("justification")?,
            binding_code: row.try_get("binding_code")?,
            required_approvals: row.try_get("required_approvals")?,
            eligible_role: row.try_get("eligible_role")?,
            required_factors: row.try_get("required_factors")?,
            cooldown_seconds: row.try_get("cooldown_seconds")?,
            status,
            approver_sub: row.try_get("approver_sub")?,
            denied_reason: row.try_get("denied_reason")?,
            execution_result: row.try_get("execution_result")?,
            error_message: row.try_get("error_message")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            decided_at: row.try_get("decided_at")?,
            executed_at: row.try_get("executed_at")?,
        })
    }
}

fn status_from_row(row: &PgRow) -> Result<ChangeRequestStatus, sqlx::Error> {
    let status_str: String = row.try_get("status")?;
    ChangeRequestStatus::from_db_str(&status_str).ok_or_else(|| sqlx::Error::ColumnDecode {
        index: "status".to_owned(),
        source: format!("unknown change_request status {status_str:?}").into(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeRequestError {
    #[error("change-request store: {0}")]
    Database(#[from] sqlx::Error),
    #[error("justification must be non-empty")]
    EmptyJustification,
    #[error("action_type must be non-empty")]
    EmptyActionType,
    #[error("required_approvals must be >= 1 (got {0})")]
    InvalidApprovalCount(i32),
    #[error("eligible_role must be non-empty")]
    EmptyEligibleRole,
    #[error("cooldown_seconds must be >= 0 (got {0})")]
    InvalidCooldown(i32),
    #[error("unknown approval factor {0:?} (expected one of: mfa, passkey, break_glass)")]
    UnknownFactor(String),
}

/// An executor-produced secret (e.g. a freshly minted API key),
/// encrypted at rest and retrievable exactly once. Returned by
/// [`ChangeRequestStore::try_burn_secret`]. The plaintext never enters
/// this crate — `ciphertext` is the AES-256-GCM envelope and `key_id` the
/// keyring id that produced it; the admin layer decrypts on retrieve.
#[derive(Debug, Clone)]
pub struct StoredSecret {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
}

/// Shared handle to a change-request store.
pub type SharedChangeRequestStore = Arc<dyn ChangeRequestStore>;

// sqlx 0.9's `SqlSafeStr` guard only accepts `&'static str` query
// literals (not `format!`-built strings), so the column list is inlined
// per query below rather than shared through a `const` + `format!`. The
// 23 columns must match the [`ChangeRequest`] `FromRow` decoder; the
// `status_db_str_roundtrips` test guards the enum half of that contract.

#[async_trait]
pub trait ChangeRequestStore: Send + Sync + 'static {
    /// Capture a proposed change as a `pending` row. Validates the
    /// intent, assigns a UUIDv7 id + a derived `binding_code`, and
    /// returns the inserted row.
    async fn propose(&self, new: NewChangeRequest) -> Result<ChangeRequest, ChangeRequestError>;

    /// Fetch one request by id, tenant-scoped. `Ok(None)` when absent
    /// or in another tenant.
    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Page through a tenant's requests. `lifecycle = Some(..)` applies
    /// the bucket predicate (cap within the bucket); `None` lists all
    /// states newest-first.
    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequest>, ChangeRequestError>;

    /// Page through bounded history metadata without selecting captured
    /// `params`, `preview`, or the target witness. Execution results are
    /// projected to a short preview instead of being loaded as full JSON.
    async fn list_summaries(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestSummary>, ChangeRequestError>;

    /// Page through ONE requester's captured-payload-free status rows. Filters
    /// by `requested_by` in SQL so pagination is over the caller's own rows: a
    /// maker can't be paginated past its own older requests by other makers'
    /// rows, and limit/offset can't leak their presence or ordering.
    async fn list_for_requester(
        &self,
        tenant_id: &str,
        requested_by: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestStatusSummary>, ChangeRequestError>;

    /// Count live pending requests up to `limit` without selecting or decoding
    /// proposal payloads. Callers can treat `count == limit` as saturation.
    async fn count_pending_up_to(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<u32, ChangeRequestError>;

    /// Single-use atomic approve. Transitions `pending -> approved` iff
    /// the row is still `pending`, not expired, AND the row requires exactly
    /// one approval (`required_approvals = 1`). Returns the
    /// updated row iff THIS caller won; `None` when the row was already
    /// decided / expired, OR the row carries a multi-approval
    /// (`required_approvals > 1`) requirement.
    ///
    /// The `required_approvals = 1` guard is a hard correctness bound,
    /// not a convenience: this single-row primitive cannot collect N
    /// distinct approvers, so it must REFUSE to mark a multi-approval
    /// requirement satisfied with one approval rather than silently
    /// under-satisfying the frozen requirement. A `required_approvals > 1`
    /// row is driven by [`Self::record_approval`] (the distinct-approver
    /// tally) instead, which `try_approve` leaves untouched.
    ///
    /// `required_factors` and `cooldown_seconds` are deliberately not
    /// enforced in the store. Factors are a property of the approver's
    /// authenticated session (an `amr` / passkey assertion the store
    /// layer never sees — it takes only an `approver_sub`, the same
    /// boundary break-glass draws for `requires_amr`). The admin approval
    /// boundary validates role, factor freshness, and the proposal-age
    /// cooldown immediately before calling this primitive, keeping the SQL
    /// transition small and atomic.
    async fn try_approve(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Record one DISTINCT approval toward a multi-approver
    /// (`required_approvals > 1`) change request, and flip it
    /// `pending -> approved` atomically once the distinct-approver count
    /// reaches `required_approvals`. A repeat approval by the same
    /// `approver_sub` is a no-op (it cannot inflate the tally toward
    /// quorum). The caller (handler) enforces approval authority before
    /// calling; the flip additionally re-guards `status = pending` and
    /// unexpired, so a stale read cannot complete a quorum it should not. The
    /// single-approver path stays [`Self::try_approve`]. Returns the
    /// collected/required counts and the approved row iff THIS call
    /// completed the quorum.
    async fn record_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<ApprovalProgress, ChangeRequestError>;

    /// The distinct approvers recorded against a change request, oldest
    /// first. Used by the execute path to attribute an M-of-N execution
    /// to *every* approver that counted toward its quorum — so the
    /// fail-closed `ChangeRequestExecute` audit names the full set even
    /// if an individual partial-approval audit failed (issue #151: the
    /// per-approval audit is post-commit, so a counting approval whose
    /// audit failed is only otherwise repaired on a retry by the same
    /// approver). Returns `[]` for an unknown request.
    async fn list_approvers(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Vec<String>, ChangeRequestError>;

    /// Single-use atomic deny. Transitions `pending -> denied` with the
    /// human's reason, iff the row is still `pending` and not expired
    /// (symmetric with `try_approve` — a lapsed request reads as
    /// `Expired` and stays that way rather than being relabeled
    /// `Denied`). Returns the updated row iff this caller won; `None`
    /// when already decided or expired. (A proposer cancelling its own live proposal is legitimate.)
    async fn try_deny(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
        reason: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Atomically claim an `approved` request for execution
    /// (`approved -> executing`). Returns the row iff THIS caller won the
    /// claim; `None` when the row isn't `approved` (already executing /
    /// executed / never approved). Single-use, so a retried or raced
    /// approve-and-execute can't double-run the side effect.
    async fn try_begin_execution(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Record a successful execution (`executing -> executed`), stamping
    /// the `result`. Returns the row iff it was `executing`.
    async fn mark_executed(
        &self,
        tenant_id: &str,
        id: Uuid,
        result: Value,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Record a failed execution (`executing -> failed`), stamping the
    /// error LOUDLY — the row lands in `failed`, never tombstoned as done.
    /// Returns the row iff it was `executing`.
    async fn mark_failed(
        &self,
        tenant_id: &str,
        id: Uuid,
        error: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError>;

    /// Persist an executor-produced secret (ALREADY encrypted) for a
    /// change request, retrievable exactly once. Called on the executed
    /// transition for a secret-producing action; the plaintext never
    /// touches this crate. One secret per change request (the table PK),
    /// so a second store for the same id is a store error, not a silent
    /// overwrite.
    async fn store_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<(), ChangeRequestError>;

    /// Single-use burn-on-read: atomically claim the stored secret,
    /// stamping it retrieved so a second read returns `None`. Returns the
    /// ciphertext + key id iff THIS caller won the claim; `None` when no
    /// secret exists for the request (a non-secret action, or wrong
    /// tenant) or it was already retrieved. The "shown once" guarantee.
    async fn try_burn_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError>;

    /// Read the stored secret WITHOUT burning it (no `retrieved_at` stamp).
    /// `None` when the request produced no secret (or wrong tenant); `Some`
    /// even if already retrieved — the row is stamped, not deleted. Lets the
    /// caller decrypt BEFORE the irreversible burn, so a key/config mistake
    /// returns an error with the one-time secret still retrievable instead of
    /// losing it. Single delivery is enforced by [`Self::try_burn_secret`],
    /// NOT by this read.
    async fn get_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError>;
}

/// Postgres-backed [`ChangeRequestStore`].
#[derive(Clone)]
pub struct PgChangeRequestStore {
    pool: PgPool,
}

impl PgChangeRequestStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChangeRequestStore for PgChangeRequestStore {
    async fn propose(&self, new: NewChangeRequest) -> Result<ChangeRequest, ChangeRequestError> {
        new.validate()?;
        let id = Uuid::now_v7();
        let binding_code = binding_code_from_uuid(&id);
        let NewChangeRequest {
            tenant_id,
            requested_by,
            client_id,
            action_type,
            params,
            preview,
            target_etag,
            justification,
            requirement,
            expires_at,
        } = new;
        let ApprovalRequirement {
            required_approvals,
            eligible_role,
            factors,
            cooldown_seconds,
        } = requirement;
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            INSERT INTO change_requests
                (id, tenant_id, requested_by, client_id, action_type, params, preview,
                 target_etag, justification, binding_code, required_approvals, eligible_role,
                 required_factors, cooldown_seconds, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
            .bind(id)
            .bind(tenant_id)
            .bind(requested_by)
            .bind(client_id)
            .bind(action_type)
            .bind(params)
            .bind(preview)
            .bind(target_etag)
            .bind(justification)
            .bind(binding_code)
            .bind(required_approvals)
            .bind(eligible_role)
            .bind(factors)
            .bind(cooldown_seconds)
            .bind(expires_at)
            .fetch_one(&self.pool)
            .await?;
        Ok(row)
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            SELECT id, tenant_id, requested_by, client_id, action_type, params, preview,
                   target_etag, justification, binding_code, required_approvals, eligible_role,
                   required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                   execution_result, error_message, created_at, expires_at, decided_at, executed_at
              FROM change_requests
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequest>, ChangeRequestError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let rows = sqlx::query_as::<_, ChangeRequest>(
            r#"
            SELECT id, tenant_id, requested_by, client_id, action_type, params, preview,
                   target_etag, justification, binding_code, required_approvals, eligible_role,
                   required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                   execution_result, error_message, created_at, expires_at, decided_at, executed_at
              FROM change_requests
             WHERE tenant_id = $1
               AND CASE
                 WHEN $2::text = 'pending' THEN status = 'pending' AND expires_at >  now()
                 WHEN $2::text = 'expired' THEN status = 'pending' AND expires_at <= now()
                 WHEN $2::text = 'decided' THEN status <> 'pending'
                 ELSE TRUE
               END
             ORDER BY created_at DESC, id
             LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(lifecycle.map(ChangeRequestLifecycle::as_sql_str))
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn count_pending_up_to(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<u32, ChangeRequestError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*)
              FROM (
                    SELECT 1
                      FROM change_requests
                     WHERE tenant_id = $1
                       AND status = 'pending'
                       AND expires_at > now()
                     LIMIT $2
                   ) AS pending
            "#,
        )
        .bind(tenant_id)
        .bind(effective_limit)
        .fetch_one(&self.pool)
        .await?;
        Ok(count as u32)
    }

    async fn list_summaries(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestSummary>, ChangeRequestError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let rows = sqlx::query_as::<_, ChangeRequestSummary>(
            r#"
            SELECT id, requested_by, action_type, justification, binding_code,
                   required_approvals, eligible_role, required_factors, cooldown_seconds,
                   status, approver_sub, denied_reason,
                   CASE
                     WHEN execution_result IS NULL THEN NULL
                     WHEN octet_length(execution_result::text) <= $5::int
                       THEN execution_result
                     ELSE NULL
                   END AS execution_result,
                   CASE
                     WHEN execution_result IS NULL THEN NULL
                     WHEN char_length(execution_result::text) <= $6::int
                       THEN execution_result::text
                     ELSE left(execution_result::text, $6::int) || '…'
                   END AS execution_result_preview,
                   error_message,
                   created_at, expires_at
              FROM change_requests
             WHERE tenant_id = $1
               AND CASE
                 WHEN $2::text = 'pending' THEN status = 'pending' AND expires_at >  now()
                 WHEN $2::text = 'expired' THEN status = 'pending' AND expires_at <= now()
                 WHEN $2::text = 'decided' THEN status <> 'pending'
                 ELSE TRUE
               END
             ORDER BY created_at DESC, id
             LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(lifecycle.map(ChangeRequestLifecycle::as_sql_str))
        .bind(effective_limit)
        .bind(offset_i)
        .bind(HISTORY_OUTCOME_MAX_BYTES as i32)
        .bind(HISTORY_OUTCOME_PREVIEW_CHARS as i32)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn list_for_requester(
        &self,
        tenant_id: &str,
        requested_by: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestStatusSummary>, ChangeRequestError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let rows = sqlx::query_as::<_, ChangeRequestStatusSummary>(
            r#"
            SELECT id, requested_by, action_type, binding_code, status, approver_sub,
                   denied_reason,
                   CASE
                     WHEN execution_result IS NULL THEN NULL
                     WHEN octet_length(execution_result::text) <= $6::int
                       THEN execution_result
                     ELSE NULL
                   END AS execution_result,
                   error_message, expires_at
              FROM change_requests
             WHERE tenant_id = $1 AND requested_by = $2
               AND CASE
                 WHEN $3::text = 'pending' THEN status = 'pending' AND expires_at >  now()
                 WHEN $3::text = 'expired' THEN status = 'pending' AND expires_at <= now()
                 WHEN $3::text = 'decided' THEN status <> 'pending'
                 ELSE TRUE
               END
             ORDER BY created_at DESC, id
             LIMIT $4 OFFSET $5
            "#,
        )
        .bind(tenant_id)
        .bind(requested_by)
        .bind(lifecycle.map(ChangeRequestLifecycle::as_sql_str))
        .bind(effective_limit)
        .bind(offset_i)
        .bind(STATUS_LIST_OUTCOME_MAX_BYTES as i32)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn try_approve(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        // Single-use + count guard in one atomic UPDATE: only one concurrent
        // caller flips `pending`; approval authority is checked by the
        // handler before this store boundary; and
        // `required_approvals = 1` refuses to mark a multi-approval
        // requirement satisfied with a single approval (multi-approver
        // rows go through `record_approval`). Both live in the WHERE
        // so a caller can't bypass them.
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'approved', approver_sub = $3, decided_at = now()
             WHERE id = $1 AND tenant_id = $2
               AND status = 'pending' AND expires_at > now()
               AND required_approvals = 1
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
            .bind(id)
            .bind(tenant_id)
            .bind(approver_sub)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    async fn record_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<ApprovalProgress, ChangeRequestError> {
        // One transaction so the insert, the count, and the conditional flip
        // see each other (CTEs in a single statement wouldn't — a
        // data-modifying CTE's rows aren't visible to a sibling read).
        let mut tx = self.pool.begin().await?;
        // `FOR UPDATE` locks the parent change request, serializing concurrent
        // approvers of the SAME request. Without it, under READ COMMITTED two
        // distinct approvers of a 2-of-N could both insert before either
        // commits; each transaction's count below would see only its own
        // uncommitted row (count = 1 < required = 2), so neither flips and the
        // change stalls `pending` despite two approvals. The lock makes the
        // second approver block until the first commits, then count its now-
        // committed row and complete the quorum.
        let gate: Option<(i32, String, OffsetDateTime)> = sqlx::query_as(
            "SELECT required_approvals, status, expires_at \
             FROM change_requests WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((required, status, expires_at)) = gate else {
            tx.rollback().await?;
            return Ok(ApprovalProgress {
                collected: 0,
                required: 0,
                recorded: false,
                counted: false,
                approved: None,
            });
        };
        // `counted`: the change is still open for THIS approver to count
        // against (pending and unexpired). Enforced here in the store — not
        // just the handler. Nothing is counted once the change is
        // denied/expired, so the ledger cannot gain phantom approvals after a
        // decision.
        // When `counted`, the handler audits this approval even on a retry,
        // so a quorum-counting approval can't be left without an audit row.
        let counted = status == "pending" && expires_at > OffsetDateTime::now_utc();
        // Record only when counted. ON CONFLICT DO NOTHING makes a repeat by
        // the same approver a no-op (can't inflate the tally); `recorded` is
        // true iff THIS call inserted a NEW row.
        let recorded = if counted {
            let ins = sqlx::query(
                "INSERT INTO change_request_approvals (id, change_request_id, tenant_id, approver_sub) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (change_request_id, approver_sub) DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(id)
            .bind(tenant_id)
            .bind(approver_sub)
            .execute(&mut *tx)
            .await?;
            ins.rows_affected() == 1
        } else {
            false
        };
        let collected: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM change_request_approvals WHERE change_request_id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        // Flip to approved iff the quorum is reached — single-use and
        // pending/unexpired are re-guarded in the WHERE so the flip cannot
        // fire twice or after the request closes.
        let approved = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'approved', approver_sub = $3, decided_at = now()
             WHERE id = $1 AND tenant_id = $2
               AND status = 'pending' AND expires_at > now()
               AND required_approvals <= $4
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(approver_sub)
        .bind(collected)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ApprovalProgress {
            collected,
            required,
            recorded,
            counted,
            approved,
        })
    }

    async fn list_approvers(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Vec<String>, ChangeRequestError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT approver_sub FROM change_request_approvals
               WHERE change_request_id = $1 AND tenant_id = $2
               ORDER BY created_at ASC"#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    async fn try_deny(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
        reason: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'denied', approver_sub = $3, denied_reason = $4, decided_at = now()
             WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
               AND expires_at > now()
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
            .bind(id)
            .bind(tenant_id)
            .bind(approver_sub)
            .bind(reason)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    async fn try_begin_execution(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'executing'
             WHERE id = $1 AND tenant_id = $2 AND status = 'approved'
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn mark_executed(
        &self,
        tenant_id: &str,
        id: Uuid,
        result: Value,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'executed', execution_result = $3, executed_at = now()
             WHERE id = $1 AND tenant_id = $2 AND status = 'executing'
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(result)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn mark_failed(
        &self,
        tenant_id: &str,
        id: Uuid,
        error: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let row = sqlx::query_as::<_, ChangeRequest>(
            r#"
            UPDATE change_requests
               SET status = 'failed', error_message = $3, executed_at = now()
             WHERE id = $1 AND tenant_id = $2 AND status = 'executing'
            RETURNING id, tenant_id, requested_by, client_id, action_type, params, preview,
                      target_etag, justification, binding_code, required_approvals, eligible_role,
                      required_factors, cooldown_seconds, status, approver_sub, denied_reason,
                      execution_result, error_message, created_at, expires_at, decided_at, executed_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn store_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<(), ChangeRequestError> {
        sqlx::query(
            r#"
            INSERT INTO change_request_secrets (change_request_id, tenant_id, ciphertext, key_id)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(ciphertext)
        .bind(key_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn try_burn_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError> {
        // Single-use claim: the `retrieved_at IS NULL` predicate + RETURNING
        // means exactly one caller can ever read the bytes; a second call (or
        // a race) updates zero rows and gets None.
        let row = sqlx::query(
            r#"
            UPDATE change_request_secrets
               SET retrieved_at = now()
             WHERE change_request_id = $1 AND tenant_id = $2 AND retrieved_at IS NULL
            RETURNING ciphertext, key_id
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| StoredSecret {
            ciphertext: r.get("ciphertext"),
            key_id: r.get("key_id"),
        }))
    }

    async fn get_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError> {
        // Read-only peek — no `retrieved_at` stamp. Returns the row even if
        // already retrieved (the burn stamps, never deletes); single delivery
        // is gated by try_burn_secret, not here.
        let row = sqlx::query(
            r#"
            SELECT ciphertext, key_id
              FROM change_request_secrets
             WHERE change_request_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| StoredSecret {
            ciphertext: r.get("ciphertext"),
            key_id: r.get("key_id"),
        }))
    }
}

fn history_outcome_preview(value: &Value) -> String {
    let serialized = value.to_string();
    if serialized.chars().count() <= HISTORY_OUTCOME_PREVIEW_CHARS {
        serialized
    } else {
        let mut preview: String = serialized
            .chars()
            .take(HISTORY_OUTCOME_PREVIEW_CHARS)
            .collect();
        preview.push('…');
        preview
    }
}

fn bounded_status_result(value: &Value) -> Option<Value> {
    (value.to_string().len() <= STATUS_LIST_OUTCOME_MAX_BYTES).then(|| value.clone())
}

fn bounded_history_result(value: &Value) -> Option<Value> {
    (value.to_string().len() <= HISTORY_OUTCOME_MAX_BYTES).then(|| value.clone())
}

fn is_live_pending(row: &ChangeRequest, tenant_id: &str, now: OffsetDateTime) -> bool {
    row.tenant_id == tenant_id && row.status == ChangeRequestStatus::Pending && row.expires_at > now
}

/// In-memory [`ChangeRequestStore`] for tests (and for any non-Pg
/// caller). Exercises the same lifecycle / single-use / distinct-quorum logic
/// as the Postgres impl without a database, so the behavioural
/// invariants are covered in `cargo test` with no `GATEWAY_*_DATABASE_URL`.
#[derive(Default)]
pub struct InMemoryChangeRequestStore {
    rows: Mutex<Vec<ChangeRequest>>,
    secrets: Mutex<Vec<InMemSecret>>,
    approvals: Mutex<Vec<InMemApproval>>,
}

/// In-memory mirror of a `change_request_approvals` row.
struct InMemApproval {
    change_request_id: Uuid,
    tenant_id: String,
    approver_sub: String,
}

/// In-memory mirror of a `change_request_secrets` row.
struct InMemSecret {
    tenant_id: String,
    change_request_id: Uuid,
    ciphertext: Vec<u8>,
    key_id: String,
    retrieved: bool,
}

impl InMemoryChangeRequestStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChangeRequestStore for InMemoryChangeRequestStore {
    async fn propose(&self, new: NewChangeRequest) -> Result<ChangeRequest, ChangeRequestError> {
        new.validate()?;
        let id = Uuid::now_v7();
        let binding_code = binding_code_from_uuid(&id);
        let row = ChangeRequest {
            id,
            tenant_id: new.tenant_id,
            requested_by: new.requested_by,
            client_id: new.client_id,
            action_type: new.action_type,
            params: new.params,
            preview: new.preview,
            target_etag: new.target_etag,
            justification: new.justification,
            binding_code,
            required_approvals: new.requirement.required_approvals,
            eligible_role: new.requirement.eligible_role,
            required_factors: new.requirement.factors,
            cooldown_seconds: new.requirement.cooldown_seconds,
            status: ChangeRequestStatus::Pending,
            approver_sub: None,
            denied_reason: None,
            execution_result: None,
            error_message: None,
            created_at: OffsetDateTime::now_utc(),
            expires_at: new.expires_at,
            decided_at: None,
            executed_at: None,
        };
        self.rows.lock().unwrap().push(row.clone());
        Ok(row)
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.id == id)
            .cloned())
    }

    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequest>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let rows = self.rows.lock().unwrap();
        let mut matched: Vec<ChangeRequest> = rows
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .filter(|r| match lifecycle {
                None => true,
                Some(ChangeRequestLifecycle::Pending) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at > now
                }
                Some(ChangeRequestLifecycle::Expired) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at <= now
                }
                Some(ChangeRequestLifecycle::Decided) => r.status != ChangeRequestStatus::Pending,
            })
            .cloned()
            .collect();
        // Newest-first, id as the stable tiebreaker — mirrors the SQL
        // ORDER BY.
        matched.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let effective_limit = limit.min(MAX_LIST_LIMIT) as usize;
        Ok(matched
            .into_iter()
            .skip(offset as usize)
            .take(effective_limit)
            .collect())
    }

    async fn count_pending_up_to(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<u32, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let effective_limit = limit.min(MAX_LIST_LIMIT) as usize;
        let count = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| is_live_pending(row, tenant_id, now))
            .take(effective_limit)
            .count();
        Ok(count as u32)
    }

    async fn list_summaries(
        &self,
        tenant_id: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestSummary>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let rows = self.rows.lock().unwrap();
        let mut matched: Vec<&ChangeRequest> = rows
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .filter(|r| match lifecycle {
                None => true,
                Some(ChangeRequestLifecycle::Pending) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at > now
                }
                Some(ChangeRequestLifecycle::Expired) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at <= now
                }
                Some(ChangeRequestLifecycle::Decided) => r.status != ChangeRequestStatus::Pending,
            })
            .collect();
        matched.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let effective_limit = limit.min(MAX_LIST_LIMIT) as usize;
        Ok(matched
            .into_iter()
            .skip(offset as usize)
            .take(effective_limit)
            .map(ChangeRequestSummary::from)
            .collect())
    }

    async fn list_for_requester(
        &self,
        tenant_id: &str,
        requested_by: &str,
        lifecycle: Option<ChangeRequestLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChangeRequestStatusSummary>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let rows = self.rows.lock().unwrap();
        let mut matched: Vec<&ChangeRequest> = rows
            .iter()
            .filter(|r| r.tenant_id == tenant_id && r.requested_by == requested_by)
            .filter(|r| match lifecycle {
                None => true,
                Some(ChangeRequestLifecycle::Pending) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at > now
                }
                Some(ChangeRequestLifecycle::Expired) => {
                    r.status == ChangeRequestStatus::Pending && r.expires_at <= now
                }
                Some(ChangeRequestLifecycle::Decided) => r.status != ChangeRequestStatus::Pending,
            })
            .collect();
        matched.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let effective_limit = limit.min(MAX_LIST_LIMIT) as usize;
        Ok(matched
            .into_iter()
            .skip(offset as usize)
            .take(effective_limit)
            .map(ChangeRequestStatusSummary::from)
            .collect())
    }

    async fn try_approve(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id
                && r.id == id
                && r.status == ChangeRequestStatus::Pending
                && r.expires_at > now
                && r.required_approvals == 1
        }) {
            r.status = ChangeRequestStatus::Approved;
            r.approver_sub = Some(approver_sub.to_owned());
            r.decided_at = Some(now);
            Ok(Some(r.clone()))
        } else {
            Ok(None)
        }
    }

    async fn record_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
    ) -> Result<ApprovalProgress, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        // Hold BOTH locks for the whole insert -> count -> flip, so the
        // sequence is atomic w.r.t. concurrent approvers — the in-memory
        // analogue of the Pg `SELECT ... FOR UPDATE` serialization.
        // `rows` is always locked before `approvals` (no other
        // method locks `approvals`), so the fixed order can't deadlock.
        let mut rows = self.rows.lock().unwrap();
        let mut apps = self.approvals.lock().unwrap();
        // Existence + the frozen required count + whether the request is
        // still open for THIS approver to record against (pending and
        // unexpired). Mirrors the Pg conditional-INSERT guard. Nothing is
        // counted after a decision/expiry.
        let (required, counted) = match rows.iter().find(|r| r.tenant_id == tenant_id && r.id == id)
        {
            Some(r) => (
                r.required_approvals,
                r.status == ChangeRequestStatus::Pending && r.expires_at > now,
            ),
            None => {
                return Ok(ApprovalProgress {
                    collected: 0,
                    required: 0,
                    recorded: false,
                    counted: false,
                    approved: None,
                })
            }
        };
        // Record only when counted. Distinct — a repeat by the same approver
        // is a no-op (mirrors ON CONFLICT DO NOTHING). `recorded` tracks
        // whether THIS call actually inserted a new row.
        let recorded = counted
            && !apps.iter().any(|a| {
                a.change_request_id == id
                    && a.tenant_id == tenant_id
                    && a.approver_sub == approver_sub
            });
        if recorded {
            apps.push(InMemApproval {
                change_request_id: id,
                tenant_id: tenant_id.to_owned(),
                approver_sub: approver_sub.to_owned(),
            });
        }
        let collected = apps
            .iter()
            .filter(|a| a.change_request_id == id && a.tenant_id == tenant_id)
            .count() as i64;
        // Flip iff quorum reached — same guards as the Pg flip.
        let approved = if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id
                && r.id == id
                && r.status == ChangeRequestStatus::Pending
                && r.expires_at > now
                && (r.required_approvals as i64) <= collected
        }) {
            r.status = ChangeRequestStatus::Approved;
            r.approver_sub = Some(approver_sub.to_owned());
            r.decided_at = Some(now);
            Some(r.clone())
        } else {
            None
        };
        Ok(ApprovalProgress {
            collected,
            required,
            recorded,
            counted,
            approved,
        })
    }

    async fn list_approvers(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Vec<String>, ChangeRequestError> {
        // Insertion order is oldest-first (records are pushed as they
        // arrive), matching the Pg `ORDER BY created_at ASC`.
        let apps = self.approvals.lock().unwrap();
        Ok(apps
            .iter()
            .filter(|a| a.change_request_id == id && a.tenant_id == tenant_id)
            .map(|a| a.approver_sub.clone())
            .collect())
    }

    async fn try_deny(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver_sub: &str,
        reason: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id
                && r.id == id
                && r.status == ChangeRequestStatus::Pending
                && r.expires_at > now
        }) {
            r.status = ChangeRequestStatus::Denied;
            r.approver_sub = Some(approver_sub.to_owned());
            r.denied_reason = Some(reason.to_owned());
            r.decided_at = Some(now);
            Ok(Some(r.clone()))
        } else {
            Ok(None)
        }
    }

    async fn try_begin_execution(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id && r.id == id && r.status == ChangeRequestStatus::Approved
        }) {
            r.status = ChangeRequestStatus::Executing;
            Ok(Some(r.clone()))
        } else {
            Ok(None)
        }
    }

    async fn mark_executed(
        &self,
        tenant_id: &str,
        id: Uuid,
        result: Value,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id && r.id == id && r.status == ChangeRequestStatus::Executing
        }) {
            r.status = ChangeRequestStatus::Executed;
            r.execution_result = Some(result);
            r.executed_at = Some(now);
            Ok(Some(r.clone()))
        } else {
            Ok(None)
        }
    }

    async fn mark_failed(
        &self,
        tenant_id: &str,
        id: Uuid,
        error: &str,
    ) -> Result<Option<ChangeRequest>, ChangeRequestError> {
        let now = OffsetDateTime::now_utc();
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| {
            r.tenant_id == tenant_id && r.id == id && r.status == ChangeRequestStatus::Executing
        }) {
            r.status = ChangeRequestStatus::Failed;
            r.error_message = Some(error.to_owned());
            r.executed_at = Some(now);
            Ok(Some(r.clone()))
        } else {
            Ok(None)
        }
    }

    async fn store_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
        ciphertext: &[u8],
        key_id: &str,
    ) -> Result<(), ChangeRequestError> {
        self.secrets.lock().unwrap().push(InMemSecret {
            tenant_id: tenant_id.to_owned(),
            change_request_id: id,
            ciphertext: ciphertext.to_owned(),
            key_id: key_id.to_owned(),
            retrieved: false,
        });
        Ok(())
    }

    async fn try_burn_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError> {
        let mut secrets = self.secrets.lock().unwrap();
        if let Some(s) = secrets
            .iter_mut()
            .find(|s| s.tenant_id == tenant_id && s.change_request_id == id && !s.retrieved)
        {
            s.retrieved = true;
            Ok(Some(StoredSecret {
                ciphertext: s.ciphertext.clone(),
                key_id: s.key_id.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_secret(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<StoredSecret>, ChangeRequestError> {
        let secrets = self.secrets.lock().unwrap();
        Ok(secrets
            .iter()
            .find(|s| s.tenant_id == tenant_id && s.change_request_id == id)
            .map(|s| StoredSecret {
                ciphertext: s.ciphertext.clone(),
                key_id: s.key_id.clone(),
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_new(requested_by: &str) -> NewChangeRequest {
        NewChangeRequest {
            tenant_id: "t1".into(),
            requested_by: requested_by.into(),
            client_id: None,
            action_type: "api_key.mint".into(),
            params: serde_json::json!({ "scopes": ["mcp:read"] }),
            preview: None,
            target_etag: None,
            justification: "nightly sync needs read-only catalog access".into(),
            requirement: ApprovalRequirement::single("dashboard-admins"),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(15),
        }
    }

    fn sample_multi(requested_by: &str, count: i32) -> NewChangeRequest {
        let mut n = sample_new(requested_by);
        n.requirement = ApprovalRequirement {
            required_approvals: count,
            eligible_role: "dashboard-admins".into(),
            factors: vec![],
            cooldown_seconds: None,
        };
        n
    }

    #[test]
    fn status_db_str_roundtrips() {
        for s in [
            ChangeRequestStatus::Pending,
            ChangeRequestStatus::Approved,
            ChangeRequestStatus::Executing,
            ChangeRequestStatus::Executed,
            ChangeRequestStatus::Failed,
            ChangeRequestStatus::Denied,
            ChangeRequestStatus::Expired,
        ] {
            assert_eq!(ChangeRequestStatus::from_db_str(s.as_db_str()), Some(s));
        }
        assert_eq!(ChangeRequestStatus::from_db_str("bogus"), None);
    }

    #[test]
    fn status_list_outcomes_are_bounded_without_dropping_small_results() {
        let small = serde_json::json!({"ok": true});
        assert_eq!(bounded_status_result(&small), Some(small));
        let large = serde_json::json!({"large": "x".repeat(STATUS_LIST_OUTCOME_MAX_BYTES)});
        assert!(bounded_status_result(&large).is_none());
    }

    #[test]
    fn binding_code_is_deterministic_and_well_formed() {
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210);
        assert_eq!(binding_code_from_uuid(&id), binding_code_from_uuid(&id));
        let code = binding_code_from_uuid(&id);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3, "code {code:?} should be ADJ-NOUN-NN");
        assert!(parts[0].chars().all(|c| c.is_ascii_uppercase()));
        assert!(parts[1].chars().all(|c| c.is_ascii_uppercase()));
        assert_eq!(parts[2].len(), 2);
        assert!(parts[2].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn binding_code_nil_uuid_is_first_words() {
        assert_eq!(binding_code_from_uuid(&Uuid::nil()), "AMBER-OTTER-00");
    }

    #[test]
    fn effective_status_reports_expired_for_lapsed_pending() {
        let new = sample_new("agent");
        let expires = new.expires_at;
        // Build a row directly to test the helper.
        let row = ChangeRequest {
            id: Uuid::now_v7(),
            tenant_id: new.tenant_id,
            requested_by: new.requested_by,
            client_id: None,
            action_type: new.action_type,
            params: new.params,
            preview: None,
            target_etag: None,
            justification: new.justification,
            binding_code: "AMBER-OTTER-00".into(),
            required_approvals: 1,
            eligible_role: "dashboard-admins".into(),
            required_factors: Vec::new(),
            cooldown_seconds: None,
            status: ChangeRequestStatus::Pending,
            approver_sub: None,
            denied_reason: None,
            execution_result: None,
            error_message: None,
            created_at: OffsetDateTime::now_utc(),
            expires_at: expires,
            decided_at: None,
            executed_at: None,
        };
        assert_eq!(
            row.effective_status(expires - time::Duration::minutes(1)),
            ChangeRequestStatus::Pending
        );
        assert_eq!(
            row.effective_status(expires + time::Duration::minutes(1)),
            ChangeRequestStatus::Expired
        );
    }

    #[tokio::test]
    async fn propose_then_get_is_pending() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        assert_eq!(cr.status, ChangeRequestStatus::Pending);
        assert!(!cr.binding_code.is_empty());
        let got = store.get("t1", cr.id).await.unwrap().unwrap();
        assert_eq!(got.id, cr.id);
        assert_eq!(got.status, ChangeRequestStatus::Pending);
    }

    #[tokio::test]
    async fn approve_is_single_use() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        let first = store.try_approve("t1", cr.id, "human").await.unwrap();
        assert_eq!(
            first.as_ref().map(|r| r.status),
            Some(ChangeRequestStatus::Approved)
        );
        assert_eq!(first.unwrap().approver_sub.as_deref(), Some("human"));
        // A second approval finds the row already decided -> None.
        let second = store.try_approve("t1", cr.id, "human2").await.unwrap();
        assert!(second.is_none(), "approval must be single-use");
    }

    #[tokio::test]
    async fn requester_can_approve_single_approval_request() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        let approved = store
            .try_approve("t1", cr.id, "agent")
            .await
            .unwrap()
            .expect("an eligible proposer satisfies a one-approval quorum");
        assert_eq!(approved.status, ChangeRequestStatus::Approved);
        assert_eq!(approved.approver_sub.as_deref(), Some("agent"));
    }

    #[tokio::test]
    async fn single_approval_cannot_satisfy_multi_approval_requirement() {
        // A row frozen with required_approvals > 1 must NOT be
        // flipped to `approved` by a
        // single try_approve — that would silently under-satisfy the
        // frozen requirement and a future executor would act on it. This
        // single-row primitive can't tally N distinct approvers, so it
        // refuses (returns None); such rows are driven by record_approval
        // instead, and stay pending under try_approve.
        let store = InMemoryChangeRequestStore::new();
        let mut new = sample_new("agent");
        new.requirement.required_approvals = 2;
        let cr = store.propose(new).await.unwrap();
        assert!(
            store
                .try_approve("t1", cr.id, "human")
                .await
                .unwrap()
                .is_none(),
            "a 2-of-N request must not be approved by one approval"
        );
        assert_eq!(
            store.get("t1", cr.id).await.unwrap().unwrap().status,
            ChangeRequestStatus::Pending,
            "the under-satisfied request must stay pending"
        );
    }

    #[tokio::test]
    async fn deny_blocks_later_approve() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        let denied = store
            .try_deny("t1", cr.id, "human", "scope too broad, use mcp:read only")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(denied.status, ChangeRequestStatus::Denied);
        assert_eq!(
            denied.denied_reason.as_deref(),
            Some("scope too broad, use mcp:read only")
        );
        assert!(store
            .try_approve("t1", cr.id, "human2")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn expired_pending_cannot_be_approved_and_lists_expired() {
        let store = InMemoryChangeRequestStore::new();
        let mut new = sample_new("agent");
        new.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
        let cr = store.propose(new).await.unwrap();
        assert!(
            store
                .try_approve("t1", cr.id, "human")
                .await
                .unwrap()
                .is_none(),
            "an expired request can't be approved"
        );
        // Deny is symmetric — a lapsed request
        // reads as Expired and can't be relabeled Denied either.
        assert!(
            store
                .try_deny("t1", cr.id, "human", "too late")
                .await
                .unwrap()
                .is_none(),
            "an expired request can't be denied either"
        );
        let expired = store
            .list("t1", Some(ChangeRequestLifecycle::Expired), 50, 0)
            .await
            .unwrap();
        assert_eq!(expired.len(), 1);
        let pending = store
            .list("t1", Some(ChangeRequestLifecycle::Pending), 50, 0)
            .await
            .unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn propose_rejects_invalid_frozen_requirement() {
        let store = InMemoryChangeRequestStore::new();

        // An empty eligible_role is a
        // row nobody could approve; reject it at the choke point.
        let mut empty_role = sample_new("agent");
        empty_role.requirement.eligible_role = "  ".into();
        assert!(matches!(
            store.propose(empty_role).await,
            Err(ChangeRequestError::EmptyEligibleRole)
        ));

        // An unknown factor would weaken the approver-session gate
        // (silently ignored / never satisfiable); reject it.
        let mut bad_factor = sample_new("agent");
        bad_factor.requirement.factors = vec!["sms".into()];
        assert!(matches!(
            store.propose(bad_factor).await,
            Err(ChangeRequestError::UnknownFactor(f)) if f == "sms"
        ));

        let mut bad_cooldown = sample_new("agent");
        bad_cooldown.requirement.cooldown_seconds = Some(-1);
        assert!(matches!(
            store.propose(bad_cooldown).await,
            Err(ChangeRequestError::InvalidCooldown(-1))
        ));

        // Known factors pass.
        let mut ok = sample_new("agent");
        ok.requirement.factors = vec!["mfa".into(), "passkey".into()];
        assert!(store.propose(ok).await.is_ok());
    }

    #[tokio::test]
    async fn list_buckets_separate_pending_from_decided() {
        let store = InMemoryChangeRequestStore::new();
        let a = store.propose(sample_new("agent")).await.unwrap();
        let _b = store.propose(sample_new("agent")).await.unwrap();
        store.try_approve("t1", a.id, "human").await.unwrap();
        let pending = store
            .list("t1", Some(ChangeRequestLifecycle::Pending), 50, 0)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        let decided = store
            .list("t1", Some(ChangeRequestLifecycle::Decided), 50, 0)
            .await
            .unwrap();
        assert_eq!(decided.len(), 1);
        let all = store.list("t1", None, 50, 0).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn list_summaries_preserves_history_metadata_without_unbounded_payloads() {
        let store = InMemoryChangeRequestStore::new();
        let mut new = sample_new("agent");
        new.params = serde_json::json!({"large": "x".repeat(384 * 1024)});
        let proposed = store.propose(new).await.unwrap();
        store
            .try_deny("t1", proposed.id, "human", "not approved")
            .await
            .unwrap();

        let executed = store.propose(sample_new("executed-agent")).await.unwrap();
        store.try_approve("t1", executed.id, "human").await.unwrap();
        store
            .try_begin_execution("t1", executed.id)
            .await
            .unwrap()
            .expect("claim approved request");
        store
            .mark_executed(
                "t1",
                executed.id,
                serde_json::json!({"large": "x".repeat(384 * 1024)}),
            )
            .await
            .unwrap()
            .expect("record large execution result");

        let pending = store.propose(sample_new("pending-agent")).await.unwrap();
        let mut expired_new = sample_new("expired-agent");
        expired_new.expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
        let expired = store.propose(expired_new).await.unwrap();
        let mut other_tenant = sample_new("other-agent");
        other_tenant.tenant_id = "t2".into();
        let other = store.propose(other_tenant).await.unwrap();
        store
            .try_deny("t2", other.id, "human", "other tenant")
            .await
            .unwrap();

        let summaries = store
            .list_summaries("t1", Some(ChangeRequestLifecycle::Decided), 50, 0)
            .await
            .unwrap();
        assert_eq!(summaries.len(), 2);
        let summary = summaries
            .iter()
            .find(|summary| summary.id == proposed.id)
            .expect("denied summary");
        assert_eq!(summary.id, proposed.id);
        assert_eq!(summary.action_type, proposed.action_type);
        assert_eq!(summary.requested_by, proposed.requested_by);
        assert_eq!(summary.status, ChangeRequestStatus::Denied);
        assert_eq!(summary.denied_reason.as_deref(), Some("not approved"));
        let outcome = summaries
            .iter()
            .find(|summary| summary.id == executed.id)
            .and_then(|summary| summary.execution_result_preview.as_deref())
            .expect("bounded execution-result preview");
        assert_eq!(outcome.chars().count(), HISTORY_OUTCOME_PREVIEW_CHARS + 1);
        assert!(outcome.ends_with('…'));
        assert!(
            summaries
                .iter()
                .find(|summary| summary.id == executed.id)
                .is_some_and(|summary| summary.execution_result.is_none()),
            "oversized structured receipts must remain outside history summaries"
        );

        let pending_summaries = store
            .list_summaries("t1", Some(ChangeRequestLifecycle::Pending), 50, 0)
            .await
            .unwrap();
        assert_eq!(pending_summaries.len(), 1);
        assert_eq!(pending_summaries[0].id, pending.id);
        let expired_summaries = store
            .list_summaries("t1", Some(ChangeRequestLifecycle::Expired), 50, 0)
            .await
            .unwrap();
        assert_eq!(expired_summaries.len(), 1);
        assert_eq!(expired_summaries[0].id, expired.id);

        let all = store.list_summaries("t1", None, 50, 0).await.unwrap();
        assert_eq!(all.len(), 4, "another tenant's summary must not leak");
        let first = store.list_summaries("t1", None, 1, 0).await.unwrap();
        let second = store.list_summaries("t1", None, 1, 1).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].id, second[0].id, "offset must advance the page");
    }

    #[tokio::test]
    async fn requester_status_listing_and_pending_count_are_scoped_and_bounded() {
        // Pagination must be over the caller's
        // OWN rows, not a tenant-wide page then filtered. With two makers
        // interleaved, agent-a's list + its pages contain only agent-a's
        // rows regardless of agent-b's.
        let store = InMemoryChangeRequestStore::new();
        let mut large = sample_new("agent-a");
        large.params = serde_json::json!({"large": "x".repeat(384 * 1024)});
        store.propose(large).await.unwrap();
        store.propose(sample_new("agent-b")).await.unwrap();
        store.propose(sample_new("agent-a")).await.unwrap();
        let mut other_tenant = sample_new("agent-a");
        other_tenant.tenant_id = "t2".into();
        store.propose(other_tenant).await.unwrap();
        let mine = store
            .list_for_requester("t1", "agent-a", None, 50, 0)
            .await
            .unwrap();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|r| r.requested_by == "agent-a"));

        // offset/limit page over agent-a's own rows only — agent-b's row
        // interleaved between them does not consume a page slot.
        let page1 = store
            .list_for_requester("t1", "agent-a", None, 1, 0)
            .await
            .unwrap();
        let page2 = store
            .list_for_requester("t1", "agent-a", None, 1, 1)
            .await
            .unwrap();
        assert_eq!(page1.len(), 1);
        assert_eq!(page2.len(), 1);
        assert_eq!(page1[0].requested_by, "agent-a");
        assert_eq!(page2[0].requested_by, "agent-a");
        assert_ne!(page1[0].id, page2[0].id);
        let mut expired = sample_new("agent-a");
        expired.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        store.propose(expired).await.unwrap();
        let boundary_now = OffsetDateTime::now_utc();
        let mut boundary = store.propose(sample_new("boundary")).await.unwrap();
        boundary.expires_at = boundary_now;
        assert!(!is_live_pending(&boundary, "t1", boundary_now));
        boundary.expires_at += time::Duration::nanoseconds(1);
        assert!(is_live_pending(&boundary, "t1", boundary_now));
        store
            .try_deny("t1", boundary.id, "human", "fixture cleanup")
            .await
            .unwrap();
        assert_eq!(store.count_pending_up_to("t1", 50).await.unwrap(), 3);
        assert_eq!(
            store.count_pending_up_to("t1", 1).await.unwrap(),
            1,
            "the count query must honor its saturation cap"
        );
    }

    #[tokio::test]
    async fn execution_lifecycle_claims_once_and_executes() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        // Can't begin execution before a human approves.
        assert!(store
            .try_begin_execution("t1", cr.id)
            .await
            .unwrap()
            .is_none());
        store.try_approve("t1", cr.id, "human").await.unwrap();
        // Claim for execution is single-use (approved -> executing once).
        let claimed = store
            .try_begin_execution("t1", cr.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.status, ChangeRequestStatus::Executing);
        assert!(
            store
                .try_begin_execution("t1", cr.id)
                .await
                .unwrap()
                .is_none(),
            "begin_execution must be single-use",
        );
        let done = store
            .mark_executed("t1", cr.id, serde_json::json!({ "ok": true }))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done.status, ChangeRequestStatus::Executed);
        assert_eq!(
            done.execution_result,
            Some(serde_json::json!({ "ok": true }))
        );
        assert!(done.executed_at.is_some());
    }

    #[tokio::test]
    async fn execution_failure_marks_failed_not_done() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        store.try_approve("t1", cr.id, "human").await.unwrap();
        store.try_begin_execution("t1", cr.id).await.unwrap();
        let failed = store
            .mark_failed("t1", cr.id, "rate-limit policy not found")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, ChangeRequestStatus::Failed);
        assert_eq!(
            failed.error_message.as_deref(),
            Some("rate-limit policy not found")
        );
        assert!(
            failed.execution_result.is_none(),
            "a failed execution must not be tombstoned as done",
        );
        // A failed row can't be resurrected to executed.
        assert!(store
            .mark_executed("t1", cr.id, serde_json::json!({}))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn operations_are_tenant_scoped() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_new("agent")).await.unwrap();
        assert!(store.get("other", cr.id).await.unwrap().is_none());
        assert!(store
            .try_approve("other", cr.id, "human")
            .await
            .unwrap()
            .is_none());
        // The cross-tenant approve attempt must not have mutated it.
        assert_eq!(
            store.get("t1", cr.id).await.unwrap().unwrap().status,
            ChangeRequestStatus::Pending
        );
    }

    #[tokio::test]
    async fn propose_rejects_invalid_intent() {
        let store = InMemoryChangeRequestStore::new();

        let mut empty_justification = sample_new("agent");
        empty_justification.justification = "   ".into();
        assert!(matches!(
            store.propose(empty_justification).await,
            Err(ChangeRequestError::EmptyJustification)
        ));

        let mut empty_action = sample_new("agent");
        empty_action.action_type = String::new();
        assert!(matches!(
            store.propose(empty_action).await,
            Err(ChangeRequestError::EmptyActionType)
        ));

        let mut bad_count = sample_new("agent");
        bad_count.requirement.required_approvals = 0;
        assert!(matches!(
            store.propose(bad_count).await,
            Err(ChangeRequestError::InvalidApprovalCount(0))
        ));
    }

    #[tokio::test]
    async fn secret_store_then_burn_is_single_use() {
        let store = InMemoryChangeRequestStore::new();
        let id = Uuid::now_v7();
        store
            .store_secret("t1", id, b"nonce-ct-tag", "v1")
            .await
            .unwrap();

        // First burn surfaces the bytes + key id.
        let first = store.try_burn_secret("t1", id).await.unwrap();
        let secret = first.expect("first burn returns the secret");
        assert_eq!(secret.ciphertext, b"nonce-ct-tag");
        assert_eq!(secret.key_id, "v1");

        // Second burn returns nothing — "shown once".
        assert!(
            store.try_burn_secret("t1", id).await.unwrap().is_none(),
            "a retrieved secret must never surface again"
        );
    }

    #[tokio::test]
    async fn burn_absent_secret_returns_none() {
        let store = InMemoryChangeRequestStore::new();
        assert!(store
            .try_burn_secret("t1", Uuid::now_v7())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn burn_is_tenant_scoped() {
        let store = InMemoryChangeRequestStore::new();
        let id = Uuid::now_v7();
        store.store_secret("t1", id, b"x", "v1").await.unwrap();
        // A different tenant cannot burn another tenant's secret...
        assert!(
            store.try_burn_secret("t2", id).await.unwrap().is_none(),
            "cross-tenant burn must not surface the secret"
        );
        // ...and the rightful tenant's single use is still intact.
        assert!(store.try_burn_secret("t1", id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn get_secret_peeks_without_burning() {
        // get_secret is the read-only peek that lets the retrieve path
        // decrypt BEFORE the irreversible burn. It must not consume the
        // single-use claim.
        let store = InMemoryChangeRequestStore::new();
        let id = Uuid::now_v7();
        store.store_secret("t1", id, b"ct", "v1").await.unwrap();
        // Peeking repeatedly does not burn.
        assert!(store.get_secret("t1", id).await.unwrap().is_some());
        assert!(store.get_secret("t1", id).await.unwrap().is_some());
        // The burn is still available after peeking...
        assert!(store.try_burn_secret("t1", id).await.unwrap().is_some());
        // ...the row survives the burn (stamped, not deleted) so a peek still
        // sees it, but the single-use burn is now spent.
        assert!(store.get_secret("t1", id).await.unwrap().is_some());
        assert!(store.try_burn_secret("t1", id).await.unwrap().is_none());
        // Cross-tenant peek sees nothing.
        assert!(store.get_secret("t2", id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn record_approval_reaches_quorum_with_distinct_approvers() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_multi("maker", 2)).await.unwrap();
        // First distinct approver: 1 of 2, not yet approved.
        let p1 = store.record_approval("t1", cr.id, "alice").await.unwrap();
        assert_eq!(p1.collected, 1);
        assert_eq!(p1.required, 2);
        assert!(p1.recorded, "a new distinct approval must report recorded");
        assert!(p1.counted, "a live, eligible approval is counted");
        assert!(
            p1.approved.is_none(),
            "one of two approvals must not satisfy the quorum"
        );
        // A second DISTINCT approver completes the quorum and flips approved.
        let p2 = store.record_approval("t1", cr.id, "bob").await.unwrap();
        assert_eq!(p2.collected, 2);
        assert!(p2.recorded);
        assert!(p2.counted);
        let approved = p2.approved.expect("quorum reached must flip to approved");
        assert_eq!(approved.status, ChangeRequestStatus::Approved);
        assert_eq!(approved.approver_sub.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn record_approval_same_approver_does_not_double_count() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_multi("maker", 2)).await.unwrap();
        let p1 = store.record_approval("t1", cr.id, "alice").await.unwrap();
        assert_eq!(p1.collected, 1);
        assert!(p1.recorded);
        // The same approver again: still 1 of 2 — a repeat can't inflate the
        // tally toward quorum, and reports recorded=false (so the handler
        // won't claim a NEW approval). But it stays `counted`,
        // so the handler still audits it ("already counted") — that's how a
        // retry after a failed post-commit audit never leaves a counting
        // approval unaudited.
        let p2 = store.record_approval("t1", cr.id, "alice").await.unwrap();
        assert_eq!(p2.collected, 1);
        assert!(!p2.recorded, "a repeat approval must report recorded=false");
        assert!(
            p2.counted,
            "but the repeat is still counted, so it's audited"
        );
        assert!(p2.approved.is_none());
    }

    #[tokio::test]
    async fn record_approval_counts_the_maker_toward_quorum() {
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_multi("maker", 2)).await.unwrap();
        store.record_approval("t1", cr.id, "alice").await.unwrap(); // 1 of 2
        let p = store.record_approval("t1", cr.id, "maker").await.unwrap();
        assert_eq!(p.collected, 2);
        assert!(p.recorded, "the maker is a distinct eligible approver");
        assert!(p.counted, "the maker counts toward the configured quorum");
        assert_eq!(
            p.approved
                .expect("the configured quorum is satisfied")
                .status,
            ChangeRequestStatus::Approved
        );
    }

    #[tokio::test]
    async fn record_approval_skips_decided_request() {
        // Nothing is recorded once the change is no longer pending — the
        // ledger can't gain phantom approvals after a deny/expiry.
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_multi("maker", 2)).await.unwrap();
        store
            .try_deny("t1", cr.id, "alice", "not needed")
            .await
            .unwrap()
            .unwrap();
        let p = store.record_approval("t1", cr.id, "bob").await.unwrap();
        assert_eq!(
            p.collected, 0,
            "no approval may be recorded against a denied change"
        );
        assert!(
            !p.recorded,
            "a no-op against a decided change is not recorded"
        );
        assert!(
            !p.counted,
            "a decided change counts nothing, so it isn't audited"
        );
        assert!(p.approved.is_none());
    }

    #[tokio::test]
    async fn record_approval_unknown_request_is_zero_progress() {
        let store = InMemoryChangeRequestStore::new();
        let p = store
            .record_approval("t1", Uuid::now_v7(), "alice")
            .await
            .unwrap();
        assert_eq!(p.collected, 0);
        assert_eq!(p.required, 0);
        assert!(p.approved.is_none());
    }

    #[tokio::test]
    async fn list_approvers_returns_distinct_recorded_subjects() {
        // Backs the M-of-N execute-audit attribution: the
        // execute path names every distinct approver that counted toward
        // quorum, so a partial approval whose post-commit audit failed is
        // still attributed at execution. Only distinct counted approvers appear;
        // repeat clicks never inflate the list.
        let store = InMemoryChangeRequestStore::new();
        let cr = store.propose(sample_multi("maker", 3)).await.unwrap();
        store.record_approval("t1", cr.id, "alice").await.unwrap();
        store.record_approval("t1", cr.id, "alice").await.unwrap(); // repeat: no-op
        store.record_approval("t1", cr.id, "maker").await.unwrap(); // proposer counts
        store.record_approval("t1", cr.id, "bob").await.unwrap();
        let approvers = store.list_approvers("t1", cr.id).await.unwrap();
        assert_eq!(
            approvers,
            vec!["alice".to_string(), "maker".to_string(), "bob".to_string(),],
            "distinct counted approvers, oldest first; proposer included, no dupes"
        );
        // Tenant-scoped + empty for an unknown request.
        assert!(store.list_approvers("t2", cr.id).await.unwrap().is_empty());
        assert!(store
            .list_approvers("t1", Uuid::now_v7())
            .await
            .unwrap()
            .is_empty());
    }
}
