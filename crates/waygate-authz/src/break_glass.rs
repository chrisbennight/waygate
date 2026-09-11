//! Break-glass override store.
//!
//! ## What this is
//!
//! Emergency operator-issued bypass tokens. A token has:
//!
//! - `issued_to` — the principal `sub` the token authorizes.
//! - `scope_pattern` — `server.tool` FQN or `server.*`
//!   wildcard the token applies to.
//! - `requires_amr` — the AMR set the principal's JWT
//!   `amr` claim MUST contain at use-time.
//! - `expires_at` — wall-clock TTL.
//! - `used_at` — single-use marker; the runtime claim
//!   sets this via a conditional UPDATE.
//!
//! When the Cedar gate returns Deny, the invocation
//! pipeline's `authorize` stage calls [`ClaimQuery`] on
//! this store. If a matching row exists AND the
//! principal's AMR satisfies `requires_amr` AND the
//! conditional UPDATE succeeds (single-use), the call
//! proceeds and the audit event is stamped with the
//! claimed token id + the minting reason.
//!
//! ## Why a separate store (not Cedar policy)
//!
//! Cedar is the right place for "what's the normal
//! authorization shape" but the wrong place for "who's
//! authorized themselves through a one-off override":
//! the latter is per-principal, time-bounded, and
//! single-use — three shapes Cedar policy expression
//! handles poorly. A bespoke table also keeps the audit
//! trail single-sourced: every break-glass use produces
//! one row mutation here PLUS one audit event downstream,
//! and the two reconcile by token id.
//!
//! ## Why break-glass uses a separate event, not the verdict
//!
//! The override happens BETWEEN authz evaluation and
//! dispatch, in the `authorize` stage of the invocation
//! pipeline. Rather than encode the override through the
//! authorization decision itself (e.g. a dedicated
//! override-allow `AuthzVerdict` variant), the pipeline
//! stage emits a separate `BreakGlassUse` AdminMutation
//! event when it claims a token, and the Invocation event
//! picks up the marker via the pipeline's
//! `InvocationContext`. A break-glass override therefore
//! returns an ordinary `AuthzVerdict::Allow` — with EMPTY
//! `policy_ids`, since no Cedar permit fired; the
//! `BreakGlassUse` row attributes the token + minting
//! admin instead. (`AuthzVerdict::Allow` carries a
//! `policy_ids` field to attribute the fired permits on a
//! normal allow; that is orthogonal to break-glass, which
//! has no permit to record — see `break_glass_gate.rs`.)

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// Precise lifecycle bucket for
/// [`BreakGlassStore::list`]. When set, the store applies a
/// SQL predicate so the row cap applies WITHIN the bucket
/// rather than across the unfiltered created_at window — an
/// active token older than 200 newer used/expired tokens still
/// appears in the Active result. Mirrors
/// [`waygate_catalog::GrantLifecycle`].
///
/// Without this bucketing, the dashboard's "Active" section
/// can silently drop old active tokens on a high-churn
/// tenant — the unfiltered `list` returns the 200
/// most-recently-created rows, which may all be
/// used/expired on a busy tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakGlassLifecycle {
    /// `used_at IS NULL AND expires_at > now()` — currently
    /// overriding the policy gate.
    Active,
    /// `used_at IS NULL AND expires_at <= now()` — timed out
    /// before being claimed.
    Expired,
    /// `used_at IS NOT NULL` — terminal state (caller-used
    /// OR operator-revoked; the store reuses `used_at` for
    /// both because `delete` hard-removes rather than
    /// soft-revokes — see `revoke_token` in the admin
    /// handler).
    Used,
}

impl BreakGlassLifecycle {
    /// SQL bind string consumed by the `CASE` arms in
    /// [`PgBreakGlassStore::list`]. `&'static str` so
    /// `Option::map` is allocation-free.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Used => "used",
        }
    }
}

/// Decoupled store surface. Tests use an in-memory
/// variant; production uses [`PgBreakGlassStore`].
#[async_trait]
pub trait BreakGlassStore: Send + Sync + 'static {
    /// Mint a new token. Returns the inserted row so the
    /// admin handler can return the canonical UUID + the
    /// stamped `created_at` to the caller.
    async fn mint(&self, mint: NewBreakGlassToken<'_>) -> Result<BreakGlassToken, BreakGlassError>;

    /// Page through tokens for a tenant. Hard-capped at
    /// [`MAX_LIST_LIMIT`] inside the Pg impl, same
    /// MAX_LIST_LIMIT-echo discipline as `oauth_consent`.
    ///
    /// Lifecycle gate:
    ///
    /// * `lifecycle = Some(...)` — precise bucket
    ///   (`Active` / `Expired` / `Used`). Cap applies
    ///   WITHIN the bucket; an active token older than the
    ///   limit's worth of newer used/expired tokens still
    ///   appears. Use this for any "is X active?" query.
    /// * `lifecycle = None` — legacy unfiltered listing,
    ///   ordered by `created_at DESC` across all states.
    ///   The REST endpoint
    ///   `GET /api/v1/admin/break_glass` keeps this shape
    ///   for backward compat with documented behavior; new
    ///   callers should prefer the bucket form.
    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<BreakGlassLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError>;

    /// Hard-delete a token by id. The admin handler does
    /// this as the revoke path (rather than soft-revoke)
    /// because the audit event captures the revocation
    /// and keeping the row would force a "was this
    /// revoked or used" disambiguation the audit log
    /// already covers. Returns `true` iff a row was
    /// removed.
    async fn delete(&self, tenant_id: &str, token_id: Uuid) -> Result<bool, BreakGlassError>;

    /// Hot-path claim: find every usable token for
    /// `(tenant_id, principal_sub)` that matches the
    /// requested `server.tool` FQN, returning all
    /// candidates so the caller can do the AMR check
    /// in-memory (the JWT's amr claim isn't in the DB).
    /// The actual single-use claim is
    /// [`Self::try_claim`] — separated so the caller
    /// can do the AMR check after the lookup but BEFORE
    /// committing the use, avoiding a wasted single-use
    /// burn on a token the principal's amr can't
    /// satisfy.
    async fn list_candidates(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        fq_tool_name: &str,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError>;

    /// Conditional UPDATE that flips `used_at` from NULL
    /// to `now()`. Returns the updated row iff THIS
    /// caller won the claim; returns `None` when the row
    /// was already used / already expired / already
    /// deleted. Race-safe single-use: if two parallel
    /// tool calls both find the same candidate via
    /// `list_candidates`, only one's `try_claim` flips
    /// the row; the other gets `None` and falls back to
    /// the original Deny.
    async fn try_claim(&self, token_id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError>;
}

#[derive(Debug)]
pub struct NewBreakGlassToken<'a> {
    pub tenant_id: &'a str,
    pub issued_to: &'a str,
    pub issued_by: &'a str,
    pub reason: &'a str,
    pub scope_pattern: &'a str,
    pub requires_amr: &'a [String],
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct BreakGlassToken {
    pub id: Uuid,
    pub tenant_id: String,
    pub issued_to: String,
    pub issued_by: String,
    pub reason: String,
    pub scope_pattern: String,
    pub requires_amr: Vec<String>,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

pub type SharedBreakGlassStore = Arc<dyn BreakGlassStore>;

/// Hard ceiling on [`BreakGlassStore::list`] page size,
/// mirroring [`crate::oauth_consent::MAX_LIST_LIMIT`]
/// (and the same shape as `oauth_consent` /
/// `upstream_sessions`).
pub use waygate_core::page::MAX_LIST_LIMIT;

#[derive(Debug, thiserror::Error)]
pub enum BreakGlassError {
    #[error("break-glass store: {0}")]
    Database(#[source] sqlx::Error),
}

/// True iff every entry in `required` appears in
/// `presented`. An empty `required` set is vacuously
/// satisfied — the token's other gates (TTL, scope,
/// issued_to) are the operator's intentional posture.
/// Comparison is case-sensitive: AMR values are defined
/// by RFC 8176 as lower-case identifiers; an upstream
/// IdP emitting "MFA" instead of "mfa" is an IdP
/// configuration bug, not a string-handling concern.
pub fn amr_subset_satisfied(required: &[String], presented: &[String]) -> bool {
    required.iter().all(|r| presented.iter().any(|p| p == r))
}

/// True iff `fq_tool_name` is covered by `pattern`.
/// Exact equality OR a `server.*` wildcard that matches
/// the FQN's `server.` prefix. An empty pattern matches
/// no tool (the admin handler refuses to mint empty
/// patterns; this is defensive in the runtime path).
pub fn scope_pattern_matches(pattern: &str, fq_tool_name: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern == fq_tool_name {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // `server.*` matches `server.<anything-without-`.`>`.
        // The simpler rule "anything starting with prefix.
        // + at least one more character" is what the admin
        // handler's mint-time validation also enforces.
        if let Some(rest) = fq_tool_name.strip_prefix(prefix) {
            return rest.starts_with('.') && rest.len() > 1;
        }
    }
    false
}

/// Postgres-backed [`BreakGlassStore`].
#[derive(Clone)]
pub struct PgBreakGlassStore {
    pool: PgPool,
}

impl PgBreakGlassStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BreakGlassStore for PgBreakGlassStore {
    async fn mint(&self, mint: NewBreakGlassToken<'_>) -> Result<BreakGlassToken, BreakGlassError> {
        let row = sqlx::query(
            r#"
            INSERT INTO break_glass_tokens
                (tenant_id, issued_to, issued_by, reason, scope_pattern,
                 requires_amr, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, tenant_id, issued_to, issued_by, reason, scope_pattern,
                      requires_amr, expires_at, used_at, created_at
            "#,
        )
        .bind(mint.tenant_id)
        .bind(mint.issued_to)
        .bind(mint.issued_by)
        .bind(mint.reason)
        .bind(mint.scope_pattern)
        .bind(mint.requires_amr)
        .bind(mint.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(BreakGlassError::Database)?;
        Ok(row_to_token(&row))
    }

    async fn list(
        &self,
        tenant_id: &str,
        lifecycle: Option<BreakGlassLifecycle>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        // Precise lifecycle predicate via CASE when
        // `lifecycle` is set, else legacy unfiltered.
        // Mirrors the GrantLifecycle SQL pattern in
        // crates/waygate-catalog/src/store.rs:list_grants —
        // see that file for the design rationale.
        //
        // When `lifecycle = Some(Used)` we ALSO order by
        // `used_at DESC` so "recently used" surfaces the
        // most-recently-CLAIMED rows rather than the most-
        // recently-CREATED. Created_at DESC stays the
        // secondary key for ties (and the only key for the
        // other two lifecycles, since `used_at IS NULL` in
        // both Active and Expired).
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, issued_to, issued_by, reason, scope_pattern,
                   requires_amr, expires_at, used_at, created_at
              FROM break_glass_tokens
             WHERE tenant_id = $1
               AND CASE
                 WHEN $2::text = 'active'  THEN used_at IS NULL AND expires_at >  now()
                 WHEN $2::text = 'expired' THEN used_at IS NULL AND expires_at <= now()
                 WHEN $2::text = 'used'    THEN used_at IS NOT NULL
                 ELSE TRUE
               END
             ORDER BY
               CASE WHEN $2::text = 'used' THEN used_at END DESC NULLS LAST,
               created_at DESC, id
             LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(lifecycle.map(BreakGlassLifecycle::as_sql_str))
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await
        .map_err(BreakGlassError::Database)?;
        Ok(rows.iter().map(row_to_token).collect())
    }

    async fn delete(&self, tenant_id: &str, token_id: Uuid) -> Result<bool, BreakGlassError> {
        // Tenant-scoped DELETE: refuses to delete a token
        // outside the caller's tenant even if the id
        // collides. Same pattern as oauth_consent's
        // revoke path.
        let result = sqlx::query(
            r#"
            DELETE FROM break_glass_tokens
             WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(token_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(BreakGlassError::Database)?;
        Ok(result.rows_affected() == 1)
    }

    async fn list_candidates(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        fq_tool_name: &str,
    ) -> Result<Vec<BreakGlassToken>, BreakGlassError> {
        // Pull every UNUSED, UNEXPIRED token issued to
        // this principal in this tenant; filter by scope
        // pattern in-memory because the pattern language
        // (`server.tool` exact OR `server.*` wildcard)
        // doesn't translate cleanly to a SQL predicate.
        // The expected fan-out per (tenant, sub) is tiny
        // (operator mints one or two tokens per
        // incident), so the in-memory filter cost is
        // bounded.
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, issued_to, issued_by, reason, scope_pattern,
                   requires_amr, expires_at, used_at, created_at
              FROM break_glass_tokens
             WHERE tenant_id = $1
               AND issued_to = $2
               AND used_at IS NULL
               AND expires_at > now()
            "#,
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(BreakGlassError::Database)?;
        Ok(rows
            .iter()
            .map(row_to_token)
            .filter(|t| scope_pattern_matches(&t.scope_pattern, fq_tool_name))
            .collect())
    }

    async fn try_claim(&self, token_id: Uuid) -> Result<Option<BreakGlassToken>, BreakGlassError> {
        // Single-use atomically: UPDATE with `used_at IS
        // NULL AND expires_at > now()` in the WHERE
        // makes only one concurrent caller win. The
        // RETURNING gives the winning row's snapshot
        // back; rows_affected = 0 ⇒ already claimed /
        // expired / revoked and the caller falls back
        // to the original Deny.
        let row = sqlx::query(
            r#"
            UPDATE break_glass_tokens
               SET used_at = now()
             WHERE id = $1
               AND used_at IS NULL
               AND expires_at > now()
            RETURNING id, tenant_id, issued_to, issued_by, reason, scope_pattern,
                      requires_amr, expires_at, used_at, created_at
            "#,
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(BreakGlassError::Database)?;
        Ok(row.as_ref().map(row_to_token))
    }
}

fn row_to_token(row: &sqlx::postgres::PgRow) -> BreakGlassToken {
    BreakGlassToken {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        issued_to: row.get("issued_to"),
        issued_by: row.get("issued_by"),
        reason: row.get("reason"),
        scope_pattern: row.get("scope_pattern"),
        requires_amr: row.get("requires_amr"),
        expires_at: row.get("expires_at"),
        used_at: row.get("used_at"),
        created_at: row.get("created_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amr_subset_empty_required_is_vacuously_satisfied() {
        assert!(amr_subset_satisfied(&[], &[]));
        assert!(amr_subset_satisfied(&[], &["mfa".into()]));
    }

    #[test]
    fn amr_subset_requires_every_entry() {
        assert!(amr_subset_satisfied(
            &["mfa".into(), "hwk".into()],
            &["mfa".into(), "hwk".into(), "pwd".into()]
        ));
        assert!(!amr_subset_satisfied(
            &["mfa".into(), "hwk".into()],
            &["mfa".into()],
        ));
        assert!(!amr_subset_satisfied(&["mfa".into()], &["pwd".into()],));
    }

    #[test]
    fn amr_subset_is_case_sensitive() {
        // RFC 8176 defines AMR identifiers as lowercase.
        // A presented "MFA" doesn't satisfy a required
        // "mfa" — that's an IdP config bug, surface it.
        assert!(!amr_subset_satisfied(&["mfa".into()], &["MFA".into()]));
    }

    #[test]
    fn scope_pattern_exact_match() {
        assert!(scope_pattern_matches("billing.charge", "billing.charge"));
        assert!(!scope_pattern_matches("billing.charge", "billing.refund"));
        assert!(!scope_pattern_matches("billing.charge", "billing"));
    }

    #[test]
    fn scope_pattern_wildcard_matches_any_tool_on_server() {
        assert!(scope_pattern_matches("billing.*", "billing.charge"));
        assert!(scope_pattern_matches("billing.*", "billing.refund"));
        // Doesn't span servers — `billing.*` must not
        // match `treasury.charge`.
        assert!(!scope_pattern_matches("billing.*", "treasury.charge"));
        // Must have a tool after the dot — bare `billing`
        // shouldn't satisfy `billing.*`.
        assert!(!scope_pattern_matches("billing.*", "billing"));
        // Edge: `billing.*` must not match
        // `billingsvc.charge` (substring trap — the
        // strip_prefix must verify the dot follows).
        assert!(!scope_pattern_matches("billing.*", "billingsvc.charge"));
    }

    #[test]
    fn scope_pattern_empty_matches_nothing() {
        // Defensive: the admin handler refuses to mint
        // empty patterns, but if one ever slips through
        // (legacy row, manual SQL insert), the runtime
        // check must NOT silently allow every tool.
        assert!(!scope_pattern_matches("", "billing.charge"));
        assert!(!scope_pattern_matches("", ""));
    }
}
