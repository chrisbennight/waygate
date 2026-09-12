//! Per-tenant token-bucket rate limiting.
//!
//! Backs migration `0025_rate_limits.sql`. Provides the
//! [`QuotaService`] trait that `waygate-mcp::DefaultInvocationService::check_quota`
//! consults at gate time, plus a [`PgQuotaService`] Postgres impl
//! that runs the token-bucket math as a single atomic UPDATE so
//! two concurrent dispatches can't double-spend a token.
//!
//! ## Surface
//!
//! Callers build a [`QuotaContext`] from the resolved
//! invocation (tenant, principal, server, and fully-qualified tool name) and call
//! [`QuotaService::check_and_consume`]. The service walks every
//! policy matching the tenant + action class, attempts to
//! consume one token from each matching bucket atomically, and
//! returns:
//!
//! - `Ok(())` — every matching policy allowed the call (or no
//!   policies matched).
//! - `Err(QuotaError::RateLimited { policy_id, retry_after_seconds })`
//!   — at least one policy denied. `retry_after_seconds` is
//!   the time until the bucket has at least 1 token again,
//!   computed from `(1 - tokens_remaining) / refill_per_second`
//!   ceiling. The adapter surfaces this in a `Retry-After`
//!   header per RFC 6585 §4.
//!
//! ## Admin CRUD
//!
//! [`RateLimitPolicyStore`] (in `store.rs`) exposes the write
//! surface the admin handler at
//! `waygate-admin::rate_limit_policies` consumes. Split from
//! [`QuotaService`] because the hot path only consumes tokens —
//! it doesn't need any of CRUD's structured error mapping.
//!
//! Supported scopes are tenant, principal, server, and tool. Supported actions
//! are call, side_effecting_call, and discovery. Stored client-scoped or
//! cost_bearing policies are inactive: they remain readable and deletable, but
//! creation and updates reject them.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

mod store;
pub use store::{
    PgRateLimitPolicyStore, RateLimitPolicy, RateLimitPolicyStore, RateLimitStoreError,
};

// f64 not NUMERIC: see the migration's column comment. f64
// precision is fine for typical refill rates and lets the
// workspace skip the sqlx bigdecimal feature.

/// What the policy's `scope_value` identifies. Matches the
/// SQL-layer CHECK constraint exactly; see migration 0025.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScope {
    Tenant,
    Principal,
    /// Stored policies only; production callers do not supply client IDs.
    Client,
    Server,
    Tool,
}

impl QuotaScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            QuotaScope::Tenant => "tenant",
            QuotaScope::Principal => "principal",
            QuotaScope::Client => "client",
            QuotaScope::Server => "server",
            QuotaScope::Tool => "tool",
        }
    }
}

/// Which class of invocation the policy applies to. Matches
/// the SQL-layer CHECK exactly.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuotaAction {
    /// Every tool call (the broadest bucket).
    Call,
    /// Side-effecting calls (`side_effects: true`) — the mutating surface.
    /// Includes billable LLM completions and applies independently of risk tier.
    SideEffectingCall,
    /// Stored policies only; no production invocation selects this action.
    CostBearing,
    /// `tools/list` + `tools/search` traffic (separate bucket
    /// so chatty discovery can't starve real calls).
    Discovery,
}

impl QuotaAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            QuotaAction::Call => "call",
            QuotaAction::SideEffectingCall => "side_effecting_call",
            QuotaAction::CostBearing => "cost_bearing",
            QuotaAction::Discovery => "discovery",
        }
    }
}

/// Per-invocation facts the gate hands the quota service to
/// pick which bucket(s) to debit. Owned String fields so the
/// gate can build this once per call without lifetime tangling.
///
/// The action class deliberately lives in the
/// [`QuotaService::check_and_consume`] parameter list, not in
/// this context. A single context with a `&[QuotaAction]` lets
/// the service do all matching policies across all applicable
/// action classes in one transaction — atomicity that a
/// split-by-action loop in the gate couldn't provide.
#[derive(Debug, Clone)]
pub struct QuotaContext {
    pub tenant_id: String,
    /// `Some` for authenticated calls; `None` when the gateway
    /// runs with `AUTH_MODE=disabled` (dev). The service skips
    /// `principal`-scoped policies in that case.
    pub principal_sub: Option<String>,
    /// Production callers provide `None`; client-scoped policies are unsupported.
    pub client_id: Option<String>,
    /// Upstream MCP server name (the `<server>` half of the
    /// fully-qualified tool name). The service uses this for
    /// `scope = 'server'` policies.
    pub server: String,
    /// `<server>.<tool>` fully-qualified name. Used for
    /// `scope = 'tool'` policies.
    pub fq_tool: String,
}

#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// At least one policy denied the call. `policy_id` is the
    /// FIRST policy to deny (the service returns early); other
    /// policies for the same context may also have denied, but
    /// the operator-visible reason only needs one. `name` is
    /// the policy's human-readable label for the operator
    /// (rendered into the WWW-Authenticate-style detail).
    /// `retry_after_seconds` is the wall-clock interval until
    /// the bucket has at least 1 token; the adapter surfaces
    /// this in a Retry-After header per RFC 6585 §4.
    #[error("rate-limited by policy `{name}` ({policy_id}); retry after {retry_after_seconds}s")]
    RateLimited {
        policy_id: Uuid,
        name: String,
        retry_after_seconds: u32,
    },
}

/// Hot-path trait the gate consults. Build a [`QuotaContext`]
/// from the resolved invocation and call [`Self::check_and_consume`].
#[async_trait]
pub trait QuotaService: Send + Sync {
    /// Atomically (across all matching policies in all listed
    /// `actions`) attempt to consume one token from each bucket.
    /// Either every matching policy's bucket is debited (success)
    /// or none are (denial — `Err(RateLimited)` carrying the
    /// first denying policy).
    ///
    /// A "one action per call, deny-after-first-denial,
    /// debit-up-to-that-policy" shape would leak partial debits
    /// when (a) layered policies inside the same action denied
    /// late or (b) the caller invoked twice (Call then
    /// SideEffectingCall) for the same invocation. Both classes of
    /// leak are prevented by:
    ///
    /// - Accepting `&[QuotaAction]` so all action classes the
    ///   call falls under run in one go.
    /// - Wrapping the per-policy debits in a single transaction
    ///   that ROLLBACKs on any denial, so a request that goes
    ///   on to be 429'd hasn't burned tokens from any policy.
    /// - ORDER BY id on the policy list so retries see the same
    ///   visit order and the deny detail is stable.
    async fn check_and_consume(
        &self,
        ctx: &QuotaContext,
        actions: &[QuotaAction],
    ) -> Result<(), QuotaError>;

    /// Non-consuming probe: would [`QuotaService::check_and_consume`] deny
    /// this call right now? Never debits any bucket — the answer is
    /// advisory (tokens may refill or be spent between the probe and the
    /// real consume), so callers may only use a denial to refuse *early*,
    /// never an allowance to skip the consuming check. Default: allow,
    /// so a service that doesn't implement the probe simply never enables
    /// early refusal.
    async fn check(&self, _ctx: &QuotaContext, _actions: &[QuotaAction]) -> Result<(), QuotaError> {
        Ok(())
    }
}

/// Postgres-backed [`QuotaService`]. One query per matching
/// policy in the worst case (typically 1-3 policies per
/// invocation in realistic configurations). The token-bucket
/// math is a single atomic UPDATE so concurrent dispatches
/// can't double-spend.
pub struct PgQuotaService {
    pool: PgPool,
}

impl PgQuotaService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The policies matching `(tenant, action ∈ actions)` whose scope
    /// applies to this invocation, with their resolved bucket keys.
    /// Shared by the consuming check and the non-consuming probe so the
    /// two can never disagree about which policies govern a call.
    async fn applicable_policies(
        &self,
        ctx: &QuotaContext,
        actions: &[QuotaAction],
    ) -> Result<Vec<ApplicablePolicy>, QuotaError> {
        let action_strs: Vec<String> = actions.iter().map(|a| a.as_str().to_owned()).collect();
        let policies = sqlx::query(
            r#"
            SELECT id, name, scope, scope_value, bucket_capacity, refill_per_second
              FROM rate_limit_policies
             WHERE tenant_id = $1 AND action = ANY($2)
             ORDER BY id
            "#,
        )
        .bind(&ctx.tenant_id)
        .bind(&action_strs)
        .fetch_all(&self.pool)
        .await?;

        let mut applicable: Vec<ApplicablePolicy> = Vec::with_capacity(policies.len());
        for row in policies {
            let policy_id: Uuid = row.get("id");
            let name: String = row.get("name");
            let scope: String = row.get("scope");
            let scope_value: Option<String> = row.get("scope_value");
            let capacity: i32 = row.get("bucket_capacity");
            let refill_per_second: f64 = row.get("refill_per_second");

            let bucket_key = match scope.as_str() {
                "tenant" => Some(ctx.tenant_id.clone()),
                "principal" => ctx.principal_sub.clone(),
                "client" => ctx.client_id.clone(),
                "server" => Some(ctx.server.clone()),
                "tool" => Some(ctx.fq_tool.clone()),
                other => {
                    tracing::warn!(
                        policy_id = %policy_id,
                        scope = %other,
                        "quota: unknown scope value in DB; skipping policy",
                    );
                    continue;
                }
            };
            let Some(bucket_key) = bucket_key else {
                continue;
            };
            if let Some(required) = scope_value.as_deref() {
                if required != bucket_key {
                    continue;
                }
            }
            applicable.push(ApplicablePolicy {
                policy_id,
                name,
                scope,
                bucket_key,
                capacity: f64::from(capacity),
                refill_per_second,
            });
        }
        Ok(applicable)
    }
}

/// One rate-limit policy that governs a specific invocation, with the
/// bucket key its scope resolved to.
struct ApplicablePolicy {
    policy_id: Uuid,
    name: String,
    scope: String,
    bucket_key: String,
    capacity: f64,
    refill_per_second: f64,
}

#[async_trait]
impl QuotaService for PgQuotaService {
    async fn check_and_consume(
        &self,
        ctx: &QuotaContext,
        actions: &[QuotaAction],
    ) -> Result<(), QuotaError> {
        if actions.is_empty() {
            return Ok(());
        }
        let applicable = self.applicable_policies(ctx, actions).await?;
        if applicable.is_empty() {
            return Ok(());
        }

        // Wrap the per-policy debits in a single transaction.
        // On any denial, drop the tx
        // (Postgres auto-ROLLBACKs) so no policy's bucket is
        // debited for a request that ultimately 429s. The atomic
        // conditional UPSERT inside each policy still prevents
        // concurrent double-spends on the same bucket; the
        // outer transaction adds cross-policy atomicity.
        let mut tx = self.pool.begin().await?;
        for app in &applicable {
            let outcome = sqlx::query(
                r#"
                INSERT INTO rate_limit_counters (policy_id, scope_value, tokens_remaining, last_refill)
                VALUES ($1, $2, $3 - 1, now())
                ON CONFLICT (policy_id, scope_value) DO UPDATE
                  SET tokens_remaining = LEAST(
                        $3,
                        rate_limit_counters.tokens_remaining
                          + EXTRACT(EPOCH FROM (now() - rate_limit_counters.last_refill)) * $4
                      ) - 1,
                      last_refill = now()
                  WHERE LEAST(
                          $3,
                          rate_limit_counters.tokens_remaining
                            + EXTRACT(EPOCH FROM (now() - rate_limit_counters.last_refill)) * $4
                        ) >= 1
                RETURNING tokens_remaining
                "#,
            )
            .bind(app.policy_id)
            .bind(&app.bucket_key)
            .bind(app.capacity)
            .bind(app.refill_per_second)
            .fetch_optional(&mut *tx)
            .await?;

            if outcome.is_none() {
                // Denial. Read the current bucket state INSIDE
                // the transaction so the Retry-After calculation
                // sees what the failing UPDATE saw. Then drop
                // the tx (auto-ROLLBACK) — every prior policy's
                // debit in this transaction is undone, so the
                // 429'd request didn't spend tokens from any
                // bucket.
                let cur: Option<(f64, time::OffsetDateTime)> = sqlx::query_as(
                    "SELECT tokens_remaining, last_refill FROM rate_limit_counters
                       WHERE policy_id = $1 AND scope_value = $2",
                )
                .bind(app.policy_id)
                .bind(&app.bucket_key)
                .fetch_optional(&mut *tx)
                .await?;
                let retry_after_seconds = compute_retry_after_seconds(cur, app.refill_per_second);
                tracing::info!(
                    policy_id = %app.policy_id,
                    name = %app.name,
                    scope = %app.scope,
                    bucket_key = %app.bucket_key,
                    retry_after_seconds,
                    "quota: rate-limited (transaction rolled back, no prior buckets debited)",
                );
                // Explicit rollback (vs implicit drop) for clarity
                // — error case is the high-frequency path; we
                // want it to be visible.
                tx.rollback().await?;
                return Err(QuotaError::RateLimited {
                    policy_id: app.policy_id,
                    name: app.name.clone(),
                    retry_after_seconds,
                });
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read-only probe: same policy matching as the consuming path (via
    /// the shared [`PgQuotaService::applicable_policies`]), but the bucket
    /// state is only SELECTed — never inserted, never updated. A missing
    /// counter row means a never-used (full) bucket. The has-a-token
    /// decision is computed **in PostgreSQL with the same
    /// `LEAST(capacity, tokens + elapsed * refill)` expression and the
    /// same `now()` clock** the consuming UPDATE uses — a gateway-side
    /// clock could lag the database's and deny a call the consuming
    /// check would have allowed. Only the Retry-After *hint* is computed
    /// gateway-side, exactly as the consuming denial path does.
    async fn check(&self, ctx: &QuotaContext, actions: &[QuotaAction]) -> Result<(), QuotaError> {
        if actions.is_empty() {
            return Ok(());
        }
        let applicable = self.applicable_policies(ctx, actions).await?;
        for app in &applicable {
            let cur: Option<(f64, time::OffsetDateTime, f64)> = sqlx::query_as(
                r#"
                SELECT tokens_remaining, last_refill,
                       LEAST(
                         $3,
                         tokens_remaining
                           + EXTRACT(EPOCH FROM (now() - last_refill)) * $4
                       )::float8 AS tokens_now
                  FROM rate_limit_counters
                 WHERE policy_id = $1 AND scope_value = $2
                "#,
            )
            .bind(app.policy_id)
            .bind(&app.bucket_key)
            .bind(app.capacity)
            .bind(app.refill_per_second)
            .fetch_optional(&self.pool)
            .await?;
            let Some((tokens, last_refill, tokens_now)) = cur else {
                // Never-used bucket: full at `capacity` (≥ 1 by the SQL
                // CHECK), so this policy allows.
                continue;
            };
            // Deny only when even a full second of refill cannot produce
            // a token. A continuously refilling bucket sitting just under
            // one token can legitimately cross the threshold in the
            // interval between this SELECT and the consuming path's
            // conditional UPDATE — an advisory probe must lean allow
            // across that window, so the denials it does issue are ones
            // the consuming check would still issue up to a full second
            // later. (refill ≥ 1 token/s ⇒ the probe never denies: any
            // denial of such a bucket is stale within a second.)
            if tokens_now + app.refill_per_second < 1.0 {
                let retry_after_seconds =
                    compute_retry_after_seconds(Some((tokens, last_refill)), app.refill_per_second);
                tracing::info!(
                    policy_id = %app.policy_id,
                    name = %app.name,
                    scope = %app.scope,
                    bucket_key = %app.bucket_key,
                    retry_after_seconds,
                    "quota: non-consuming probe denied (no bucket touched)",
                );
                return Err(QuotaError::RateLimited {
                    policy_id: app.policy_id,
                    name: app.name.clone(),
                    retry_after_seconds,
                });
            }
        }
        Ok(())
    }
}

/// Compute the Retry-After integer seconds for a denied
/// bucket. Uses ceiling so the client doesn't retry one
/// fractional second too early. Caps at 3600 (one hour) so
/// a misconfigured policy with a tiny refill rate can't park
/// a client for a day; the client can always poll sooner if
/// it wants.
///
/// `None` ⇒ the counter row vanished between the failed
/// UPDATE and the SELECT (a concurrent admin DELETE);
/// return a small default so the client doesn't think the
/// bucket is permanent.
fn compute_retry_after_seconds(
    cur: Option<(f64, time::OffsetDateTime)>,
    refill_per_second: f64,
) -> u32 {
    let default = 1u32;
    let Some((tokens, last_refill)) = cur else {
        return default;
    };
    // tokens_now = tokens + elapsed_secs * refill
    let elapsed = (time::OffsetDateTime::now_utc() - last_refill).as_seconds_f64();
    if refill_per_second <= 0.0 {
        return 3600;
    }
    let tokens_now = tokens + elapsed * refill_per_second;
    let needed = 1.0 - tokens_now;
    if needed <= 0.0 {
        // Race: by the time we computed Retry-After the bucket
        // would have allowed it. Tell the client to retry now.
        return default;
    }
    let secs = (needed / refill_per_second).ceil();
    let clamped = secs.clamp(1.0, 3600.0);
    clamped as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_scope_round_trips_against_sql_check_values() {
        // Migration 0025 pins the CHECK to exactly these five
        // values. If the Rust enum drifts, the SQL INSERT will
        // reject — this test makes the drift impossible to
        // merge.
        assert_eq!(QuotaScope::Tenant.as_str(), "tenant");
        assert_eq!(QuotaScope::Principal.as_str(), "principal");
        assert_eq!(QuotaScope::Client.as_str(), "client");
        assert_eq!(QuotaScope::Server.as_str(), "server");
        assert_eq!(QuotaScope::Tool.as_str(), "tool");
    }

    #[test]
    fn quota_action_round_trips_against_sql_check_values() {
        assert_eq!(QuotaAction::Call.as_str(), "call");
        assert_eq!(
            QuotaAction::SideEffectingCall.as_str(),
            "side_effecting_call"
        );
        assert_eq!(QuotaAction::CostBearing.as_str(), "cost_bearing");
        assert_eq!(QuotaAction::Discovery.as_str(), "discovery");
    }

    #[test]
    fn retry_after_clamps_to_at_least_one() {
        let cur = (0.99, time::OffsetDateTime::now_utc());
        // Refill 100/sec → would be ~0.01 sec, but the floor
        // is 1 (whole seconds, never zero).
        let r = compute_retry_after_seconds(Some(cur), 100.0);
        assert!(r >= 1);
    }

    #[test]
    fn retry_after_caps_at_one_hour() {
        let cur = (0.0, time::OffsetDateTime::now_utc());
        // Refill 0.0001/sec → would be ~10000 sec; clamp to
        // 3600 so a fat-fingered policy can't park a client
        // for a day.
        let r = compute_retry_after_seconds(Some(cur), 0.0001);
        assert_eq!(r, 3600);
    }

    #[test]
    fn retry_after_missing_row_returns_default() {
        let r = compute_retry_after_seconds(None, 1.0);
        assert_eq!(r, 1);
    }
}
