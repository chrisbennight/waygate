//! Catalog domain types shared by the trait + Pg impl + future
//! callers (admin CRUD, ManifestImporter, ToolObserver, ...).
//!
//! All types are `Clone` + `Send + Sync` because the `CatalogStore`
//! trait is invoked from `axum` handlers and `tokio::spawn`-ed
//! background tasks. None of them carry secret material; the
//! sensitive ciphertext columns from other crates (api_keys,
//! user_upstream_sessions) don't have catalog analogues.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Lifecycle of an `mcp_servers` row. Tracked separately from
/// liveness (whether `gateway-runtime` is currently dialed in) —
/// a `live` server can still be disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogServerStatus {
    /// Operator added the row but no reviewer has signed off.
    /// Discovery hides it.
    Proposed,
    /// Reviewer signed off; not yet routing traffic. No admin transition
    /// currently parks a server here — `approve_server` moves `Proposed`
    /// directly to `Live` — so this is reserved for a future two-step
    /// approval flow.
    Approved,
    /// Routing traffic now. The per-call hot path only consults
    /// `live` rows.
    Live,
    /// Flipped to `quarantined` when a manifest reconcile finds the server
    /// absent from the authoritative full set, or by explicit operator/agent
    /// action (the admin quarantine endpoint or the `quarantine_server`
    /// control tool). Discovery hides it; the per-call path refuses
    /// dispatch with a clear error.
    Quarantined,
    /// Operator retired the row. Kept for audit-trail
    /// continuity (`catalog_approvals` still references it).
    Retired,
}

impl CatalogServerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Live => "live",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

/// Per-tenant visibility scope for an `mcp_servers` row. The
/// discovery surface filters by `tenant_id == principal.tenant`
/// for `TenantOnly` rows, and by anyone for `Global` rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogVisibility {
    Global,
    TenantOnly,
}

impl CatalogVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::TenantOnly => "tenant_only",
        }
    }
}

/// Subjects the `catalog_approvals` audit log can reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    Server,
    Tool,
    ToolVersion,
    Classification,
}

impl SubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Tool => "tool",
            Self::ToolVersion => "tool_version",
            Self::Classification => "classification",
        }
    }
}

/// Severity stamped on a drift observation reported via
/// [`crate::store::CatalogStore::record_drift`], surfaced on the admin
/// drift-feed for operators to triage. Distinct from
/// `waygate-upstream`'s automatic per-tool quarantine, which decides
/// from its own risk/side_effects threshold independent of this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    Info,
    Warn,
    Critical,
}

impl DriftSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

/// Lightweight view of an `mcp_servers` row for the discovery
/// surface. Omits `runtime_target` (transport detail) and
/// `signing_pubkey` (per-row crypto detail) because the
/// discovery API doesn't need them — those are reserved for a
/// future dedicated admin endpoint, not exposed today.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CatalogServerSummary {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub transport: String,
    pub status: CatalogServerStatus,
    pub visibility: CatalogVisibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// Versioned catalog-server row used by governed lifecycle transitions.
///
/// This is intentionally separate from [`CatalogServerSummary`]: discovery and
/// ordinary catalog reads do not need the mutable-row version, while a delayed
/// HITL approval must bind its status change to the exact row the maker
/// inspected. `updated_at` is therefore an opaque compare-and-swap witness,
/// not presentation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogServerTransitionTarget {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub status: CatalogServerStatus,
    pub updated_at: OffsetDateTime,
}

/// One conditional lifecycle mutation bound to a captured target row.
#[derive(Debug, Clone, Copy)]
pub struct CatalogServerStatusChange<'a> {
    pub target: &'a CatalogServerTransitionTarget,
    pub new_status: CatalogServerStatus,
    pub actor: &'a str,
    pub reason: Option<&'a str>,
}

/// Full per-tool definition: identity + currently-approved
/// schema + classification. The per-call hot path consults this
/// through [`CatalogStore::resolve_tool`] (via
/// `UpstreamPool::resolve_invocation_tool`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub tool_id: Uuid,
    pub server_id: Uuid,
    pub server_name: String,
    pub tool_name: String,
    pub schema_hash: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Canonical standard MCP annotations approved with this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_annotations: Option<serde_json::Value>,
    /// Canonical value from
    /// `io.modelcontextprotocol/action-metadata`, approved with this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_metadata: Option<serde_json::Value>,
    /// The classification mode of the manifest generation this row was
    /// imported from (`manifest` / `mcp_annotations`). String, not enum,
    /// mirroring `risk`. The resolver refuses to blend a row with a live
    /// manifest in the OTHER mode: an annotation-imported row carries
    /// forced-false legacy `side_effects`/`pii`, so overlaying it onto a
    /// legacy tool would weaken its facts.
    #[serde(default = "default_classification_mode")]
    pub classification_mode: String,
    /// Risk tier (`low`/`medium`/`high`/`critical`). String, not
    /// enum, so the catalog layer doesn't need to know about
    /// `waygate-mcp::RiskTier`. Callers map.
    pub risk: String,
    pub side_effects: bool,
    pub pii: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_class: Option<String>,
    /// When true, every dispatch of this tool by every principal needs
    /// an active grant in `approval_grants` before the call proceeds.
    /// Defaults to false (via the migration's column default) so
    /// existing imported tools are unaffected. Enforced by the
    /// invocation pipeline's `DefaultInvocationService::check_approval`
    /// stage. Carried on the Live arm so the per-call path doesn't need
    /// a second catalog round-trip after `resolve_tool`.
    #[serde(default)]
    pub requires_approval: bool,
    /// Argument field whose value selects which operation a call performs.
    ///
    /// `None` keeps the tool classified by name alone, which is every tool an
    /// operator has not opted into per-operation review. Resolution needs the
    /// call's arguments, which the catalog read does not see, so this travels
    /// with the definition to whoever holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,
    /// Classifications for individual discriminator values.
    ///
    /// A value with no entry here is classified by this row's own `risk`,
    /// `side_effects`, and `pii`, so an unrecognized operation is never weaker
    /// than the tool it arrived through.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<OperationClassification>,
}

/// Classification the catalog holds for one discriminator value of a tool.
///
/// `risk` is a string rather than an enum, mirroring
/// [`ToolDefinition::risk`]: the catalog layer does not depend on the policy
/// crate's tier type, and callers map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationClassification {
    pub value: String,
    pub risk: String,
    #[serde(default)]
    pub side_effects: bool,
    #[serde(default)]
    pub pii: bool,
}

/// Outcome of [`CatalogStore::resolve_tool`]. Distinct enum
/// shapes for the three states the per-call path branches on:
///
/// - `Live`: tool is approved, server is `live`, dispatch
///   proceeds with the carried `ToolDefinition`.
/// - `PendingApproval`: tool exists but no approved
///   schema_hash for the currently-observed live schema. The
///   per-call path refuses dispatch and returns a clear "tool
///   is awaiting re-approval" error to the caller. The admin
///   approval-grants mint endpoint also refuses (404) rather than
///   minting a grant for a tool in this state.
/// - `Quarantined`: the owning server has been administratively
///   pulled out of dispatch (status `quarantined` or `retired`).
///   This is an *authoritative deny*, distinct from
///   `PendingApproval`: the per-call path refuses the call and —
///   critically — does **not** fall back to manifest metadata, so
///   an operator's quarantine actually takes the server offline.
/// - `NotFound`: no matching `(tenant, server.tool)` in the
///   catalog. The per-call path returns an unknown-tool error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ResolvedTool {
    // Boxed: `ToolDefinition` is ~270 bytes, dwarfing the other
    // variants, so an unboxed enum would bloat every `NotFound`
    // / `PendingApproval` value to that size. The hot path
    // matches on the variant and only touches the box on the
    // Live arm.
    Live(Box<ToolDefinition>),
    PendingApproval {
        server_name: String,
        tool_name: String,
    },
    Quarantined {
        server_name: String,
        tool_name: String,
    },
    NotFound,
}

/// Observation reported by [`CatalogStore::record_drift`].
/// Intended to be constructed by a live-schema observer when an
/// upstream's live schema doesn't match the catalog's approved
/// hash; no such observer exists yet — today's schema-drift
/// detection lives in `waygate-upstream`'s in-memory per-tool
/// check instead.
#[derive(Debug, Clone)]
pub struct DriftObservation<'a> {
    pub tenant_id: &'a str,
    pub tool_id: Uuid,
    pub observed_hash: &'a str,
    /// `None` ⇒ no approved version exists; the tool is new
    /// and awaiting first-time approval. Distinct from
    /// "approved hash differs from observed."
    pub approved_hash: Option<&'a str>,
    pub severity: DriftSeverity,
}

/// One row from the `catalog_drift_events` table for admin
/// inspection.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DriftEvent {
    pub id: Uuid,
    pub tenant_id: String,
    pub tool_id: Uuid,
    pub observed_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_hash: Option<String>,
    pub severity: DriftSeverity,
    pub observed_at: OffsetDateTime,
}

/// Append-only audit row for [`CatalogStore::record_approval`].
/// Maps to a `catalog_approvals` insert.
#[derive(Debug, Clone)]
pub struct ApprovalAction<'a> {
    pub tenant_id: &'a str,
    pub subject_type: SubjectType,
    pub subject_id: Uuid,
    /// Schema hash that disambiguates a `tool_version` subject.
    /// `mcp_tool_versions` has a composite PK
    /// `(tool_id, schema_hash)`, so `subject_id` (the tool_id)
    /// alone can't say which version was approved. MUST be
    /// `Some` when `subject_type == ToolVersion` and `None`
    /// otherwise — the DB CHECK constraint enforces the pairing,
    /// and the Pg impl returns a wrapped error if a caller
    /// violates it.
    pub subject_version_hash: Option<&'a str>,
    /// String not enum because the action vocabulary may grow
    /// across phases (`approved`, `rejected`, `quarantined`,
    /// `retired`, `signed_off`, ...) and the catalog crate
    /// shouldn't need a re-release per new action. The Pg impl
    /// validates against the CHECK constraint on the column.
    pub action: &'a str,
    pub actor: &'a str,
    pub reason: Option<&'a str>,
}

/// A pre-approved (principal × tool version × arguments × time-window)
/// grant for a tool whose classification has
/// `requires_approval = true`. Returned by
/// [`crate::store::CatalogStore::find_grant`] when an active grant
/// matches the call; the invocation pipeline's HITL enforcement
/// stage (`DefaultInvocationService::check_approval`) uses the
/// (presence of) result to permit dispatch.
#[derive(Debug, Clone)]
pub struct ApprovalGrant {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    /// Issuer that minted the requester's `sub`. Ownership binds
    /// tenant + issuer + subject; `None` marks a pre-upgrade row, which no
    /// claim or find can match (fail closed) and which ages out on its
    /// expiry clock.
    pub principal_issuer: Option<String>,
    pub client_id: Option<String>,
    pub server_id: Uuid,
    pub tool_id: Uuid,
    /// Historical column name; new grants store an approval-binding digest
    /// covering both the approved behavior hash and canonical arguments.
    pub argument_hash: String,
    /// Present only for a grant scoped to one connector call in a durable Code
    /// Mode execution. Ordinary direct-call grants leave this absent.
    pub execution_binding: Option<ApprovalGrantExecutionBinding>,
    pub expires_at: OffsetDateTime,
    /// One-time-use bound. `None` while the grant is live; set to
    /// consumption time by the HITL enforcement gate's atomic-claim
    /// `UPDATE ... RETURNING` (`CatalogStore::claim_grant`).
    /// `find_grant` only returns rows where this is `None`, so a
    /// row returned here is by construction not yet consumed.
    pub consumed_at: Option<OffsetDateTime>,
    pub approver: String,
    pub reason: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrantExecutionBinding {
    pub execution_id: Uuid,
    pub source_digest: String,
    pub call_id: Uuid,
}

#[derive(Debug, Clone, Copy)]
pub struct GrantExecutionBinding<'a> {
    pub execution_id: Uuid,
    pub source_digest: &'a str,
    pub call_id: Uuid,
}

/// Lookup key for [`crate::store::CatalogStore::find_grant`].
/// `client_id` is the *caller's* client_id (or None); a grant
/// matches when it was minted with `client_id = None` (any client
/// for this principal) OR with `client_id = caller_client_id`
/// (locked-down service-account flow). See `approval_grants` in
/// `0013_tool_governance.sql` for the binding rationale.
#[derive(Debug, Clone, Copy)]
pub struct GrantLookup<'a> {
    pub tenant_id: &'a str,
    pub principal_sub: &'a str,
    /// The caller's issuer. Matched exactly against the grant's recorded
    /// requester issuer — a pre-upgrade issuer-less grant matches nothing.
    pub principal_issuer: &'a str,
    pub client_id: Option<&'a str>,
    pub tool_id: Uuid,
    /// Approval-binding digest covering behavior version and arguments.
    pub argument_hash: &'a str,
    /// `None` matches only ordinary direct-call grants. `Some` matches only
    /// the exact durable execution binding.
    pub execution_binding: Option<GrantExecutionBinding<'a>>,
}

/// Insert payload for
/// [`crate::store::CatalogStore::create_grant`]. Mirrors the
/// `approval_grants` column shape minus the server-set fields
/// (`id`, `created_at`, `consumed_at`).
#[derive(Debug, Clone, Copy)]
pub struct NewApprovalGrant<'a> {
    pub tenant_id: &'a str,
    pub principal_sub: &'a str,
    /// Issuer that minted the requester's `sub` — from the surface where
    /// the requester's identity was observed (the approval-needed event or
    /// the bound execution row), never inferred.
    pub principal_issuer: &'a str,
    pub client_id: Option<&'a str>,
    pub server_id: Uuid,
    pub tool_id: Uuid,
    /// Approval-binding digest covering behavior version and arguments.
    pub argument_hash: &'a str,
    pub execution_binding: Option<GrantExecutionBinding<'a>>,
    pub expires_at: OffsetDateTime,
    pub approver: &'a str,
    pub reason: Option<&'a str>,
}

/// Filter for
/// [`crate::store::CatalogStore::list_grants`]. `tenant_id` is
/// always required at the call site (no cross-tenant listing in
/// v1); the other fields are optional narrowing predicates.
///
/// Lifecycle gate (two paths, set ONE):
///
/// * `lifecycle = Some(...)` — precise bucket: `Active`, `Expired`,
///   or `Consumed`. Each bucket gets its own 200-row store window
///   so callers fetching multiple buckets don't crowd each other
///   out. Consumed orders by `consumed_at DESC` so "recently
///   consumed" surfaces the actual latest consumptions, not the
///   latest-created-then-consumed-ages-ago.
/// * `lifecycle = None` (legacy): `include_consumed=false` (the
///   default) restricts to live grants — the operator's "what's
///   currently pending?" view; set `true` for an unfiltered
///   per-tenant history view. Kept for the public REST endpoint
///   `GET /api/v1/admin/approval_grants?include_consumed=` so the
///   externally documented query param stays stable.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrantFilter<'a> {
    pub principal_sub: Option<&'a str>,
    pub tool_id: Option<Uuid>,
    pub server_id: Option<Uuid>,
    pub include_consumed: bool,
    pub lifecycle: Option<GrantLifecycle>,
}

/// Precise lifecycle bucket for
/// [`CatalogStore::list_grants`]. Each variant compiles to a
/// distinct SQL predicate, letting the dashboard fetch each bucket
/// in its own 200-row store window without lifecycle states
/// crowding each other out of the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLifecycle {
    /// `consumed_at IS NULL AND expires_at > now()` — waiting for
    /// the user to invoke.
    Active,
    /// `consumed_at IS NULL AND expires_at <= now()` — admin minted
    /// a grant but the caller never used it. Useful for spotting
    /// too-short TTLs. The periodic grant sweeper
    /// (`grant_sweeper::run_grant_sweeper`) eventually deletes these.
    Expired,
    /// `consumed_at IS NOT NULL` — grant was used (or revoked).
    /// Ordered by `consumed_at DESC` so "recently consumed" is
    /// surface-true.
    Consumed,
}

impl GrantLifecycle {
    /// SQL bind string. Matches the `CASE` arms in
    /// [`crate::store::PgCatalogStore::list_grants`]. `&'static str`
    /// so `Option::map` is cheap.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Consumed => "consumed",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog store: {0}")]
    Database(#[source] sqlx::Error),
    #[error("invalid catalog input: {0}")]
    InvalidInput(String),
    #[error("unknown {0}")]
    Unknown(&'static str),
}

fn default_classification_mode() -> String {
    "manifest".to_owned()
}

#[cfg(test)]
mod tests {
    use super::GrantLifecycle;

    #[test]
    fn grant_lifecycle_sql_strs_are_stable() {
        // The SQL CASE in PgCatalogStore::list_grants matches on the
        // literals `'active' / 'expired' / 'consumed'`. A rename here
        // without updating the SQL would silently route every
        // lifecycle filter into the legacy include_consumed branch.
        assert_eq!(GrantLifecycle::Active.as_sql_str(), "active");
        assert_eq!(GrantLifecycle::Expired.as_sql_str(), "expired");
        assert_eq!(GrantLifecycle::Consumed.as_sql_str(), "consumed");
    }
}
