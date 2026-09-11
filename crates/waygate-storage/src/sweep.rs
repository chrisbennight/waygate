//! Retention sweep mechanics.
//!
//! Consumes the stored retention policies (the
//! `evidence_retention_policy` table + [`crate::retention`]
//! CRUD) and produces the [`RetentionMarker`] chain
//! attestations the chain verifier understands. One sweep
//! invocation = one `(tenant_id, category)` pair, atomically:
//!
//! 1. Acquire the per-tenant `pg_advisory_xact_lock` the
//!    recorder also takes, so a sweep can't interleave with
//!    a concurrent `record_required` (the recorder's lock
//!    serialises chain head reads + chain writes).
//! 2. SELECT the oldest bounded batch matching the requested tenant/category
//!    scope and cutoff. Both chain-bearing and unchained best-effort rows are
//!    eligible; `retention_sweep` markers are always excluded.
//! 3. Group the chain-bearing candidates into CONTIGUOUS
//!    chain segments: a new segment starts whenever the
//!    current candidate's `prev_hash` does not equal the
//!    prior candidate's `row_hash` (i.e. some surviving row
//!    sits between them in the chain). One marker per
//!    segment.
//! 4. INSERT one chain-bearing `RetentionSweep` marker per
//!    segment, each with `RetentionMarker.deleted_rows`
//!    populated from the segment. Markers' own chain links:
//!    `M1.prev_hash` = pre-sweep chain head's `row_hash`,
//!    each subsequent marker's `prev_hash` = the previous
//!    marker's `row_hash` (markers form a tail at the chain
//!    head). `M1.prev_hash` may itself be a deleted row's
//!    hash if the sweep includes the pre-sweep head — the
//!    verifier handles that via marker bridging
//!    (self-bootstrap when M1's own `deleted_rows` covers
//!    its prev_hash; transitive bridge otherwise).
//! 5. Call `audit_log_sweep_delete($tenant, $ids, $marker_ids)` — the
//!    SECURITY DEFINER function migration 0074 ships. The
//!    function runs as `audit_log_sweep_role`, satisfying
//!    the no-mutate trigger's `current_user` check; no
//!    other DELETE path exists. It expands only the exact marker rows written
//!    in this transaction, so permanent marker history cannot increase a
//!    batch's authorization cost. (A session-GUC bypass was deliberately
//!    rejected: it would be a bypass surface usable by anyone holding the
//!    gateway's DB credential.)
//! 6. Commit.
//!
//! On any error inside the TX, ROLLBACK leaves the chain
//! exactly as it was. Markers are never written without their
//! corresponding deletes and vice versa.
//!
//! ## Forbidden categories
//!
//! The sweep MUST
//! NOT delete prior `retention_sweep` marker rows — those
//! markers carry the chain bridges the chain verifier needs
//! to authorise OLDER deletion gaps. Deleting them would
//! make previously valid chains unverifiable even though
//! they appeared internally consistent at the time the new
//! marker was written.
//!
//! [`FORBIDDEN_SWEEP_CATEGORY`] is the single hard-coded
//! refusal; the admin endpoint rejects the same string at
//! the request boundary, and the SQL SELECT adds an explicit
//! `category != ...` predicate as defense-in-depth.
//!
//! A single call deletes at most [`RETENTION_SWEEP_BATCH_ROWS`] rows. Callers
//! use [`SweepReport::batch_limit_reached`] to decide whether another batch is
//! warranted. This bounds both the in-process candidate vector and the time a
//! sweep holds the per-tenant chain lock.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use tokio::pin;
use tokio::time::interval;
use uuid::Uuid;

use crate::chain_verify::{DeletedRow, DeletedUnchainedRow, RetentionMarker};
use crate::hashchain::{canonical_audit_bytes, compute_row_hash};
use crate::retention::{lock_tenant_policy, RetentionPolicy, RetentionStore};

/// Maximum audit rows deleted by one sweep transaction. Candidate selection
/// reads one additional look-ahead row to report whether more work exists.
/// The scheduler may run several transactions per policy tick, but releases
/// the tenant chain lock between them.
pub const RETENTION_SWEEP_BATCH_ROWS: usize = 500;

const RETENTION_SWEEP_QUERY_ROWS: usize = RETENTION_SWEEP_BATCH_ROWS + 1;

/// Maximum transactions one policy may consume in one scheduler tick. A
/// policy with more backlog is reported and resumes on the next tick instead
/// of monopolising the control-plane pool.
const RETENTION_SWEEP_MAX_BATCHES_PER_TICK: usize = 10;

/// Outcome of the fleet-wide scheduler claim for one retention tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionSchedulerTick {
    Completed,
    AlreadyClaimed,
}

/// Object-safe abstraction over the sweep call shape. The
/// admin endpoint, the scheduler, and tests all consume via
/// `Arc<dyn Sweeper>` instead of a concrete pool wrapper, so a
/// pure-Rust test can supply a fake without standing up
/// Postgres.
#[async_trait::async_trait]
pub trait Sweeper: Send + Sync + 'static {
    async fn sweep(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: OffsetDateTime,
    ) -> Result<SweepReport, SweepError>;

    /// Sweep categories governed by a wildcard policy, excluding categories
    /// that have more-specific policies for the same tenant.
    async fn sweep_remaining_categories(
        &self,
        tenant_id: &str,
        excluded_categories: &[String],
        cutoff: OffsetDateTime,
    ) -> Result<SweepReport, SweepError>;

    /// Sweep one concrete category only while the policy that authorised its
    /// cutoff is still the effective policy for that category.
    async fn sweep_if_policy_current(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: OffsetDateTime,
        expected_policy: &RetentionPolicy,
    ) -> Result<SweepReport, SweepError>;

    /// Sweep a wildcard scope only while the tenant's full policy snapshot is
    /// unchanged, including the explicit categories excluded from the scope.
    async fn sweep_remaining_categories_if_policies_current(
        &self,
        tenant_id: &str,
        excluded_categories: &[String],
        cutoff: OffsetDateTime,
        expected_policies: &[RetentionPolicy],
    ) -> Result<SweepReport, SweepError>;
}

/// Pool-bound sweep runner. Thin wrapper so the admin layer
/// and the scheduler can hold an `Option<Arc<dyn Sweeper>>`
/// in state without dragging `PgPool` references through
/// every handler signature. Constructed by `waygate-server`
/// when a Postgres pool exists.
pub struct PgSweeper {
    pool: sqlx::PgPool,
}

impl PgSweeper {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl Sweeper for PgSweeper {
    /// Convenience method: run a sweep against the wrapped
    /// pool. Same semantics as the free
    /// [`run_retention_sweep`] function.
    async fn sweep(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: OffsetDateTime,
    ) -> Result<SweepReport, SweepError> {
        run_retention_sweep(&self.pool, tenant_id, category, cutoff).await
    }

    async fn sweep_remaining_categories(
        &self,
        tenant_id: &str,
        excluded_categories: &[String],
        cutoff: OffsetDateTime,
    ) -> Result<SweepReport, SweepError> {
        run_retention_sweep_selection(
            &self.pool,
            tenant_id,
            SweepSelection::RemainingCategories(excluded_categories),
            cutoff,
            None,
        )
        .await
    }

    async fn sweep_if_policy_current(
        &self,
        tenant_id: &str,
        category: &str,
        cutoff: OffsetDateTime,
        expected_policy: &RetentionPolicy,
    ) -> Result<SweepReport, SweepError> {
        run_retention_sweep_selection(
            &self.pool,
            tenant_id,
            SweepSelection::ExactCategory(category),
            cutoff,
            Some(PolicyGuard::Effective {
                target_category: category,
                expected_policy,
            }),
        )
        .await
    }

    async fn sweep_remaining_categories_if_policies_current(
        &self,
        tenant_id: &str,
        excluded_categories: &[String],
        cutoff: OffsetDateTime,
        expected_policies: &[RetentionPolicy],
    ) -> Result<SweepReport, SweepError> {
        run_retention_sweep_selection(
            &self.pool,
            tenant_id,
            SweepSelection::RemainingCategories(excluded_categories),
            cutoff,
            Some(PolicyGuard::WildcardTenant { expected_policies }),
        )
        .await
    }
}

/// Outcome of a single `(tenant_id, category)` sweep
/// invocation. Returned to the caller for observability
/// (admin endpoint, scheduler logs).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SweepReport {
    pub tenant_id: String,
    pub category: String,
    #[serde(with = "time::serde::rfc3339")]
    pub cutoff: OffsetDateTime,
    /// Number of `RetentionSweep` marker rows written. Zero
    /// when no candidates matched.
    pub markers_written: usize,
    /// Number of candidate rows DELETEd from `audit_log`.
    pub rows_deleted: u64,
    /// True when the transaction filled its candidate batch. There may be more
    /// eligible rows; a follow-up batch is required to prove the scope drained.
    pub batch_limit_reached: bool,
}

/// Sweep failure modes the caller should surface to the
/// operator. `Sqlx` wraps any underlying Postgres error; the
/// transaction has already rolled back by the time the
/// caller sees this.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Refused
    /// because the caller asked to sweep
    /// `retention_sweep`-category rows, which would delete
    /// the markers the chain verifier depends on for older
    /// chain bridges.
    #[error("category '{0}' must not be swept (would delete chain-bridge markers)")]
    ForbiddenCategory(String),
    /// Refused because the policy snapshot used to calculate the destructive
    /// cutoff is no longer current.
    #[error("retention policy changed before sweep for tenant='{tenant_id}' scope='{scope}'")]
    PolicyChanged { tenant_id: String, scope: String },
}

/// Categories the sweep is hard-coded to refuse. Currently
/// just the marker category itself — deleting prior markers
/// would destroy the chain bridges the chain verifier uses
/// to authorise older retention gaps. The admin endpoint
/// rejects the same string at the request boundary; this
/// constant is the runtime fallback.
pub const FORBIDDEN_SWEEP_CATEGORY: &str = "retention_sweep";

/// One row's chain-fingerprint snapshot captured from the
/// SELECT pass. Used to build the marker `deleted_rows`
/// payload before the DELETE drops the source data.
#[derive(Debug, Clone, sqlx::FromRow)]
struct CandidateRow {
    id: Uuid,
    chain_seq: i64,
    prev_hash: Option<String>,
    row_hash: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum SweepSelection<'a> {
    ExactCategory(&'a str),
    RemainingCategories(&'a [String]),
}

#[derive(Debug, Clone, Copy)]
enum PolicyGuard<'a> {
    Effective {
        target_category: &'a str,
        expected_policy: &'a RetentionPolicy,
    },
    WildcardTenant {
        expected_policies: &'a [RetentionPolicy],
    },
}

impl SweepSelection<'_> {
    fn report_label(self) -> String {
        match self {
            Self::ExactCategory(category) => category.to_owned(),
            Self::RemainingCategories(_) => "*".to_owned(),
        }
    }
}

async fn validate_policy_guard(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    guard: PolicyGuard<'_>,
) -> Result<(), SweepError> {
    let current = sqlx::query_as::<_, RetentionPolicy>(
        r#"
        SELECT tenant_id, category, delete_after_days, created_at, updated_at
          FROM evidence_retention_policy
         WHERE tenant_id = $1
         ORDER BY category ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let scope = match guard {
        PolicyGuard::Effective {
            target_category,
            expected_policy,
        } => {
            let effective = current
                .iter()
                .find(|policy| policy.category == target_category)
                .or_else(|| current.iter().find(|policy| policy.category == "*"));
            if effective != Some(expected_policy) {
                return Err(SweepError::PolicyChanged {
                    tenant_id: tenant_id.to_owned(),
                    scope: target_category.to_owned(),
                });
            }
            return Ok(());
        }
        PolicyGuard::WildcardTenant { expected_policies } => {
            let mut expected = expected_policies.to_vec();
            expected.sort_unstable_by(|left, right| left.category.cmp(&right.category));
            if current == expected {
                return Ok(());
            }
            "*"
        }
    };

    Err(SweepError::PolicyChanged {
        tenant_id: tenant_id.to_owned(),
        scope: scope.to_owned(),
    })
}

/// Run one retention sweep cycle for the given
/// `(tenant_id, category)`. Returns a [`SweepReport`]
/// describing what happened; an empty report (`markers_written
/// = 0`, `rows_deleted = 0`) is a normal no-op when no
/// candidates match the cutoff.
///
/// Callers supply `cutoff` explicitly so the same primitive
/// composes under a scheduler that derives `cutoff` from a
/// policy's `delete_after_days` and under an admin endpoint
/// that wants to test a specific instant.
pub async fn run_retention_sweep(
    pool: &PgPool,
    tenant_id: &str,
    category: &str,
    cutoff: OffsetDateTime,
) -> Result<SweepReport, SweepError> {
    // Runtime refusal
    // for the marker category. The admin endpoint also rejects
    // this string at the request boundary; both checks together
    // make the property "the sweep never deletes prior markers"
    // hold regardless of how the function is reached.
    if category == FORBIDDEN_SWEEP_CATEGORY {
        return Err(SweepError::ForbiddenCategory(category.to_owned()));
    }

    run_retention_sweep_selection(
        pool,
        tenant_id,
        SweepSelection::ExactCategory(category),
        cutoff,
        None,
    )
    .await
}

async fn run_retention_sweep_selection(
    pool: &PgPool,
    tenant_id: &str,
    selection: SweepSelection<'_>,
    cutoff: OffsetDateTime,
    policy_guard: Option<PolicyGuard<'_>>,
) -> Result<SweepReport, SweepError> {
    let mut tx = pool.begin().await?;

    if let Some(guard) = policy_guard {
        // Policy CRUD takes the same lock, so the validation below remains
        // current until this destructive transaction commits or rolls back.
        lock_tenant_policy(&mut tx, tenant_id).await?;
        validate_policy_guard(&mut tx, tenant_id, guard).await?;
    }

    // Per-tenant advisory lock — same key (`hashtext(tenant_id)`)
    // the recorder takes in `record_required`. Serialises
    // sweep ↔ recorder; concurrent sweeps for the same tenant
    // are also pairwise-serialised. Released on commit/rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    // Select oldest-first through the existing `(tenant_id, ts DESC)` index.
    // One look-ahead row distinguishes a full-but-drained batch from a real
    // backlog without a full count or an extra transaction.
    let mut candidates: Vec<CandidateRow> = match selection {
        SweepSelection::ExactCategory(category) => {
            sqlx::query_as::<_, CandidateRow>(
                r#"
                SELECT id, chain_seq, prev_hash, row_hash
                  FROM audit_log
                 WHERE tenant_id = $1
                   AND COALESCE(category, 'invocation') = $2
                   AND COALESCE(category, 'invocation') <> 'retention_sweep'
                   AND ts < $3
                 ORDER BY ts ASC
                 LIMIT $4
                "#,
            )
            .bind(tenant_id)
            .bind(category)
            .bind(cutoff)
            .bind(RETENTION_SWEEP_QUERY_ROWS as i64)
            .fetch_all(&mut *tx)
            .await?
        }
        SweepSelection::RemainingCategories(excluded_categories) => {
            sqlx::query_as::<_, CandidateRow>(
                r#"
                SELECT id, chain_seq, prev_hash, row_hash
                  FROM audit_log
                 WHERE tenant_id = $1
                   AND COALESCE(category, 'invocation') <> 'retention_sweep'
                   AND COALESCE(category, 'invocation') <> ALL($2::TEXT[])
                   AND ts < $3
                 ORDER BY ts ASC
                 LIMIT $4
                "#,
            )
            .bind(tenant_id)
            .bind(excluded_categories)
            .bind(cutoff)
            .bind(RETENTION_SWEEP_QUERY_ROWS as i64)
            .fetch_all(&mut *tx)
            .await?
        }
    };

    let batch_limit_reached = candidates.len() > RETENTION_SWEEP_BATCH_ROWS;
    candidates.truncate(RETENTION_SWEEP_BATCH_ROWS);
    // Marker segmentation follows hash-chain order, while candidate selection
    // follows age so the existing time index can bound the query efficiently.
    candidates.sort_unstable_by_key(|candidate| candidate.chain_seq);

    if candidates.is_empty() {
        tx.commit().await?;
        return Ok(SweepReport {
            tenant_id: tenant_id.to_owned(),
            category: selection.report_label(),
            cutoff,
            markers_written: 0,
            rows_deleted: 0,
            batch_limit_reached: false,
        });
    }

    let ids: Vec<Uuid> = candidates.iter().map(|candidate| candidate.id).collect();
    let unchained_rows: Vec<DeletedUnchainedRow> = candidates
        .iter()
        .filter(|candidate| candidate.row_hash.is_none())
        .map(|candidate| DeletedUnchainedRow {
            id: candidate.id,
            chain_seq: candidate.chain_seq,
        })
        .collect();
    let mut segments = group_into_chain_segments(&candidates);
    if segments.is_empty() {
        // Unchained-only deletion still gets one chain-bearing marker so the
        // SECURITY DEFINER function can require visible id coverage.
        segments.push(Vec::new());
    }

    // Read the current chain head — the first marker's
    // `prev_hash` anchors to whatever the chain tip was
    // BEFORE the sweep inserted its markers. If the head
    // itself is a candidate, `M1.prev_hash` will point at
    // the soon-to-be-deleted head's `row_hash`; the verifier
    // self-bootstraps M1 because M1.deleted_rows will
    // contain that hash.
    let mut chain_head: Option<String> = sqlx::query_scalar(
        r#"
        SELECT row_hash
          FROM audit_log
         WHERE tenant_id = $1
           AND row_hash IS NOT NULL
         ORDER BY chain_seq DESC
         LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let mut marker_ids = Vec::with_capacity(segments.len());
    for (segment_index, segment) in segments.iter().enumerate() {
        let chain_seq_min = segment
            .first()
            .and_then(|d| chain_seq_for_row_hash(&candidates, &d.row_hash));
        let chain_seq_max = segment
            .last()
            .and_then(|d| chain_seq_for_row_hash(&candidates, &d.row_hash));
        let payload = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: segment.clone(),
            deleted_unchained_rows: if segment_index == 0 {
                unchained_rows.clone()
            } else {
                Vec::new()
            },
            deleted_chain_seq_min: chain_seq_min,
            deleted_chain_seq_max: chain_seq_max,
            policy: Some(format!(
                "retention/{}/{}",
                tenant_id,
                selection.report_label()
            )),
        };
        let reason = payload.to_reason();
        let marker_id = Uuid::new_v4();
        let marker_ts = OffsetDateTime::now_utc();

        // Empty arrays for the columns the marker doesn't
        // populate. `principal_groups` and `policy_ids` are
        // NOT NULL TEXT[] in the schema; pass empty slices.
        let empty_str: Vec<String> = Vec::new();
        let canonical_bytes = canonical_audit_bytes(
            marker_id,
            marker_ts,
            "retention_sweep",
            tenant_id,
            "retention.sweep",
            "success",
            None,
            None,
            &empty_str,
            None,
            None,
            None,
            None,
            None,
            &empty_str,
            Some(reason.as_str()),
            None,
            None,
        );
        let row_hash = compute_row_hash(chain_head.as_deref(), &canonical_bytes);

        sqlx::query(
            r#"
            INSERT INTO audit_log (
                id, ts, category, tenant_id, action, outcome,
                principal_sub, principal_email, principal_groups, issuer,
                server, tool, risk_level, pii,
                policy_ids, reason, trace_id, latency_ms,
                prev_hash, row_hash
            ) VALUES (
                $1, $2, 'retention_sweep', $3, 'retention.sweep', 'success',
                NULL, NULL, $4, NULL,
                NULL, NULL, NULL, NULL,
                $5, $6, NULL, NULL,
                $7, $8
            )
            "#,
        )
        .bind(marker_id)
        .bind(marker_ts)
        .bind(tenant_id)
        .bind(&empty_str)
        .bind(&empty_str)
        .bind(&reason)
        .bind(chain_head.as_deref())
        .bind(&row_hash)
        .execute(&mut *tx)
        .await?;

        sqlx::query("SELECT audit_retention_bridge_index_marker($1)")
            .bind(marker_id)
            .execute(&mut *tx)
            .await?;

        chain_head = Some(row_hash);
        marker_ids.push(marker_id);
    }

    // Security: bypass the
    // no-mutate trigger via the SECURITY DEFINER wrapper
    // migration 0018 ships, NOT a raw DELETE + session GUC.
    // The wrapper runs as `audit_log_sweep_role` (its owner);
    // the trigger's `current_user = 'audit_log_sweep_role'`
    // check is satisfied. Outside the function, no session
    // can set `current_user` to that role — nobody is
    // granted membership — so this is the only DELETE path.
    let rows_deleted: i64 = sqlx::query_scalar("SELECT audit_log_sweep_delete($1, $2, $3)")
        .bind(tenant_id)
        .bind(&ids)
        .bind(&marker_ids)
        .fetch_one(&mut *tx)
        .await?;
    let rows_deleted = u64::try_from(rows_deleted).unwrap_or(0);

    tx.commit().await?;

    Ok(SweepReport {
        tenant_id: tenant_id.to_owned(),
        category: selection.report_label(),
        cutoff,
        markers_written: marker_ids.len(),
        rows_deleted,
        batch_limit_reached,
    })
}

/// Group sorted candidates into contiguous chain segments.
/// A new segment starts whenever the current candidate's
/// `prev_hash` does not equal the prior candidate's
/// `row_hash` — i.e. some surviving row of a different
/// category sat between them in the chain. Each segment
/// becomes one marker; the boundary stitch
/// (`segment[0].prev_hash` → prior surviving row's
/// `row_hash`) is what walker bridging will verify.
fn group_into_chain_segments(candidates: &[CandidateRow]) -> Vec<Vec<DeletedRow>> {
    let mut segments: Vec<Vec<DeletedRow>> = Vec::new();
    let mut current: Vec<DeletedRow> = Vec::new();
    let mut last_row_hash: Option<String> = None;
    for c in candidates {
        let Some(row_hash) = c.row_hash.as_deref() else {
            continue;
        };
        let row_continuous = match (&last_row_hash, c.prev_hash.as_deref()) {
            (Some(prev), Some(this)) => prev == this,
            _ => false,
        };
        if !current.is_empty() && !row_continuous {
            segments.push(std::mem::take(&mut current));
        }
        current.push(DeletedRow {
            prev_hash: c.prev_hash.clone(),
            row_hash: row_hash.to_owned(),
        });
        last_row_hash = Some(row_hash.to_owned());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn chain_seq_for_row_hash(candidates: &[CandidateRow], row_hash: &str) -> Option<i64> {
    candidates
        .iter()
        .find(|c| c.row_hash.as_deref() == Some(row_hash))
        .map(|c| c.chain_seq)
}

/// Periodic retention sweep scheduler.
///
/// Spawned by `waygate-server` at startup when
/// `GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS` is set to a
/// non-zero value (default hourly; `0` disables; floor `60` seconds when set).
/// Every `interval_period` it lists
/// every row in `evidence_retention_policy`, computes
/// `cutoff = now - delete_after_days` per row, and runs the policy-current
/// sweep path for each `(tenant_id, category)` pair. Errors are logged and
/// continue — one failing
/// tenant/category doesn't stop the whole pass.
///
/// Wildcard policies sweep every category not covered by a more-specific row
/// for that tenant. The exclusion happens in the candidate query, preserving
/// the same most-specific-wins contract as [`crate::resolve_policy`] without a
/// table-wide distinct-category scan.
///
/// The same advisory-lock + marker-coverage guarantees the admin endpoint
/// relies on apply here. Each scheduled batch enters through a policy-current
/// sweeper method, revalidates the policy inside `run_retention_sweep_selection`,
/// then reaches the existing SECURITY DEFINER `audit_log_sweep_delete()`
/// function. No new privilege surface is introduced.
pub async fn run_retention_scheduler(
    pool: PgPool,
    sweeper: Arc<dyn Sweeper>,
    store: Arc<dyn RetentionStore>,
    interval_period: Duration,
    shutdown: impl Future<Output = ()>,
) {
    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // Same pattern as `run_outbox_drain`: skip the immediate
    // t=0 tick, wait one interval before the first sweep —
    // the policy table is usually empty at boot and any
    // startup-time chain rows aren't yet past their cutoff.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        "retention sweep scheduler started",
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("retention sweep scheduler shutting down");
                return;
            }
            _ = ticker.tick() => {
                match sweep_all_policies_if_tick_claimed(
                    &pool,
                    sweeper.as_ref(),
                    store.as_ref(),
                    interval_period,
                ).await {
                    Ok(RetentionSchedulerTick::Completed) => {}
                    Ok(RetentionSchedulerTick::AlreadyClaimed) => {
                        tracing::info!(
                            outcome = "already_claimed",
                            "retention scheduler: fleet tick already claimed by another replica",
                        );
                    }
                    Err(error) => {
                        tracing::error!(
                            outcome = "claim_failed",
                            error = %error,
                            "retention scheduler: fleet tick claim failed; retrying on next tick",
                        );
                    }
                }
            }
        }
    }
}

/// Run at most one retention scheduler tick across all gateway replicas.
///
/// A session advisory lock owns the active fleet pass until all policy work
/// finishes, including when a pass outlives its cadence. Its connection is
/// marked close-on-drop so cancellation or process failure releases the lock
/// instead of returning a locked session to the pool. The durable claim
/// deduplicates sequentially phased replica ticks after that lock is released.
pub async fn sweep_all_policies_if_tick_claimed(
    pool: &PgPool,
    sweeper: &dyn Sweeper,
    store: &dyn RetentionStore,
    interval_period: Duration,
) -> Result<RetentionSchedulerTick, sqlx::Error> {
    let interval_seconds = i64::try_from(interval_period.as_secs()).map_err(|_| {
        sqlx::Error::Protocol("retention scheduler interval exceeds PostgreSQL BIGINT".to_owned())
    })?;
    let mut claim = pool.acquire().await?;
    claim.close_on_drop();
    let active_pass_claimed: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(\
             hashtext('mcp_gateway'), hashtext('audit_retention_scheduler'))",
    )
    .fetch_one(&mut *claim)
    .await?;
    if !active_pass_claimed {
        return Ok(RetentionSchedulerTick::AlreadyClaimed);
    }

    let claimed: bool = sqlx::query_scalar("SELECT audit_retention_scheduler_claim($1)")
        .bind(interval_seconds)
        .fetch_one(&mut *claim)
        .await?;
    if !claimed {
        release_retention_scheduler_lock(&mut claim).await?;
        return Ok(RetentionSchedulerTick::AlreadyClaimed);
    }

    sweep_all_policies(sweeper, store).await;
    release_retention_scheduler_lock(&mut claim).await?;
    Ok(RetentionSchedulerTick::Completed)
}

async fn release_retention_scheduler_lock(
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let released: bool = sqlx::query_scalar(
        "SELECT pg_advisory_unlock(\
             hashtext('mcp_gateway'), hashtext('audit_retention_scheduler'))",
    )
    .fetch_one(connection)
    .await?;
    if !released {
        return Err(sqlx::Error::Protocol(
            "retention scheduler fleet lock was not owned at release".to_owned(),
        ));
    }
    Ok(())
}

/// One scheduler tick: list every retention policy, sweep
/// each. Exposed so a test can drive a single pass
/// deterministically without instantiating the interval loop.
pub async fn sweep_all_policies(sweeper: &dyn Sweeper, store: &dyn RetentionStore) {
    let policies = match store.list(None).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "retention scheduler: list policies failed; retrying on next tick",
            );
            return;
        }
    };
    if policies.is_empty() {
        tracing::warn!(
            "audit retention is unbounded: scheduler found no evidence_retention_policy rows",
        );
        return;
    }

    let mut by_tenant: BTreeMap<String, Vec<crate::retention::RetentionPolicy>> = BTreeMap::new();
    for policy in policies {
        by_tenant
            .entry(policy.tenant_id.clone())
            .or_default()
            .push(policy);
    }

    let mut tick = PolicySweepStats::default();
    for tenant_policies in by_tenant.into_values() {
        let policy_snapshot = tenant_policies.clone();
        let wildcard = tenant_policies
            .iter()
            .find(|policy| policy.category == "*")
            .cloned();
        let explicit: Vec<_> = tenant_policies
            .into_iter()
            .filter(|policy| policy.category != "*")
            .collect();

        for policy in &explicit {
            let stats = sweep_policy_batches(sweeper, policy, &policy_snapshot, None).await;
            tick.add(&stats);
        }

        if let Some(policy) = wildcard.as_ref() {
            let exclusions: Vec<String> = explicit
                .iter()
                .map(|specific| specific.category.clone())
                .collect();
            let stats =
                sweep_policy_batches(sweeper, policy, &policy_snapshot, Some(&exclusions)).await;
            tick.add(&stats);
        }
    }

    match tick_log_level(&tick) {
        TickLogLevel::Warn => {
            tracing::warn!(
                policies = tick.policies,
                batches = tick.batches,
                markers = tick.markers,
                deleted = tick.deleted,
                errors = tick.errors,
                policy_changes = tick.policy_changes,
                backlogged_policies = tick.backlogged_policies,
                batch_rows = RETENTION_SWEEP_BATCH_ROWS,
                max_batches_per_policy = RETENTION_SWEEP_MAX_BATCHES_PER_TICK,
                "retention scheduler: tick completed with remaining work",
            );
        }
        TickLogLevel::Info => {
            tracing::info!(
                policies = tick.policies,
                batches = tick.batches,
                markers = tick.markers,
                deleted = tick.deleted,
                "retention scheduler: tick completed",
            );
        }
        TickLogLevel::Debug => {
            tracing::debug!(
                policies = tick.policies,
                batches = tick.batches,
                "retention scheduler: tick complete (no eligible rows)",
            );
        }
    }
}

#[derive(Debug, Default)]
struct PolicySweepStats {
    policies: usize,
    batches: usize,
    markers: usize,
    deleted: u64,
    errors: usize,
    policy_changes: usize,
    backlogged_policies: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TickLogLevel {
    Warn,
    Info,
    Debug,
}

fn tick_log_level(stats: &PolicySweepStats) -> TickLogLevel {
    if stats.errors != 0 || stats.policy_changes != 0 || stats.backlogged_policies != 0 {
        TickLogLevel::Warn
    } else if stats.deleted != 0 {
        TickLogLevel::Info
    } else {
        TickLogLevel::Debug
    }
}

impl PolicySweepStats {
    fn add(&mut self, other: &Self) {
        self.policies += other.policies;
        self.batches += other.batches;
        self.markers += other.markers;
        self.deleted += other.deleted;
        self.errors += other.errors;
        self.policy_changes += other.policy_changes;
        self.backlogged_policies += other.backlogged_policies;
    }
}

async fn sweep_policy_batches(
    sweeper: &dyn Sweeper,
    policy: &crate::retention::RetentionPolicy,
    policy_snapshot: &[RetentionPolicy],
    wildcard_exclusions: Option<&[String]>,
) -> PolicySweepStats {
    let mut stats = PolicySweepStats {
        policies: 1,
        ..PolicySweepStats::default()
    };
    let Some(cutoff) =
        crate::retention::retention_cutoff(OffsetDateTime::now_utc(), policy.delete_after_days)
    else {
        stats.errors = 1;
        tracing::error!(
            tenant_id = %policy.tenant_id,
            category = %policy.category,
            delete_after_days = policy.delete_after_days,
            "retention scheduler: policy cutoff exceeds the supported timestamp range",
        );
        return stats;
    };

    for _ in 0..RETENTION_SWEEP_MAX_BATCHES_PER_TICK {
        let result = match wildcard_exclusions {
            Some(excluded) => {
                sweeper
                    .sweep_remaining_categories_if_policies_current(
                        &policy.tenant_id,
                        excluded,
                        cutoff,
                        policy_snapshot,
                    )
                    .await
            }
            None => {
                sweeper
                    .sweep_if_policy_current(&policy.tenant_id, &policy.category, cutoff, policy)
                    .await
            }
        };
        let report = match result {
            Ok(report) => report,
            Err(SweepError::PolicyChanged { .. }) => {
                stats.policy_changes = 1;
                tracing::warn!(
                    tenant_id = %policy.tenant_id,
                    category = %policy.category,
                    completed_batches = stats.batches,
                    deleted = stats.deleted,
                    "retention scheduler: policy changed; stopping stale sweep",
                );
                return stats;
            }
            Err(error) => {
                stats.errors = 1;
                tracing::error!(
                    tenant_id = %policy.tenant_id,
                    category = %policy.category,
                    completed_batches = stats.batches,
                    deleted = stats.deleted,
                    error = %error,
                    "retention scheduler: policy sweep failed",
                );
                return stats;
            }
        };

        stats.batches += 1;
        stats.markers += report.markers_written;
        stats.deleted += report.rows_deleted;
        if !report.batch_limit_reached {
            return stats;
        }
    }

    stats.backlogged_policies = 1;
    tracing::warn!(
        tenant_id = %policy.tenant_id,
        category = %policy.category,
        batches = stats.batches,
        deleted = stats.deleted,
        batch_rows = RETENTION_SWEEP_BATCH_ROWS,
        "retention scheduler: policy backlog remains after bounded pass",
    );
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn candidate(chain_seq: i64, prev_hash: Option<&str>, row_hash: &str) -> CandidateRow {
        CandidateRow {
            id: Uuid::from_u128(chain_seq as u128),
            chain_seq,
            prev_hash: prev_hash.map(|s| s.to_owned()),
            row_hash: Some(row_hash.to_owned()),
        }
    }

    fn retention_policy(category: &str, days: i32) -> crate::retention::RetentionPolicy {
        crate::retention::RetentionPolicy {
            tenant_id: "acme".to_owned(),
            category: category.to_owned(),
            delete_after_days: days,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    struct ScriptedSweeper {
        reports: Mutex<VecDeque<(usize, u64, bool)>>,
        cutoffs: Mutex<Vec<OffsetDateTime>>,
        guarded_calls: Mutex<usize>,
        policy_change_on_call: Option<usize>,
    }

    impl ScriptedSweeper {
        fn new(reports: impl IntoIterator<Item = (usize, u64, bool)>) -> Self {
            Self {
                reports: Mutex::new(reports.into_iter().collect()),
                cutoffs: Mutex::new(Vec::new()),
                guarded_calls: Mutex::new(0),
                policy_change_on_call: None,
            }
        }

        fn with_policy_change_on_call(
            reports: impl IntoIterator<Item = (usize, u64, bool)>,
            policy_change_on_call: usize,
        ) -> Self {
            Self {
                reports: Mutex::new(reports.into_iter().collect()),
                cutoffs: Mutex::new(Vec::new()),
                guarded_calls: Mutex::new(0),
                policy_change_on_call: Some(policy_change_on_call),
            }
        }

        fn next_report(
            &self,
            tenant_id: &str,
            category: &str,
            cutoff: OffsetDateTime,
        ) -> SweepReport {
            self.cutoffs.lock().unwrap().push(cutoff);
            let (markers_written, rows_deleted, batch_limit_reached) = self
                .reports
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must provide one report per expected sweep call");
            SweepReport {
                tenant_id: tenant_id.to_owned(),
                category: category.to_owned(),
                cutoff,
                markers_written,
                rows_deleted,
                batch_limit_reached,
            }
        }

        fn next_guarded_report(
            &self,
            tenant_id: &str,
            category: &str,
            cutoff: OffsetDateTime,
        ) -> Result<SweepReport, SweepError> {
            let mut calls = self.guarded_calls.lock().unwrap();
            *calls += 1;
            if self.policy_change_on_call == Some(*calls) {
                return Err(SweepError::PolicyChanged {
                    tenant_id: tenant_id.to_owned(),
                    scope: category.to_owned(),
                });
            }
            drop(calls);
            Ok(self.next_report(tenant_id, category, cutoff))
        }
    }

    #[async_trait::async_trait]
    impl Sweeper for ScriptedSweeper {
        async fn sweep(
            &self,
            tenant_id: &str,
            category: &str,
            cutoff: OffsetDateTime,
        ) -> Result<SweepReport, SweepError> {
            Ok(self.next_report(tenant_id, category, cutoff))
        }

        async fn sweep_remaining_categories(
            &self,
            tenant_id: &str,
            _excluded_categories: &[String],
            cutoff: OffsetDateTime,
        ) -> Result<SweepReport, SweepError> {
            Ok(self.next_report(tenant_id, "*", cutoff))
        }

        async fn sweep_if_policy_current(
            &self,
            tenant_id: &str,
            category: &str,
            cutoff: OffsetDateTime,
            _expected_policy: &RetentionPolicy,
        ) -> Result<SweepReport, SweepError> {
            self.next_guarded_report(tenant_id, category, cutoff)
        }

        async fn sweep_remaining_categories_if_policies_current(
            &self,
            tenant_id: &str,
            _excluded_categories: &[String],
            cutoff: OffsetDateTime,
            _expected_policies: &[RetentionPolicy],
        ) -> Result<SweepReport, SweepError> {
            self.next_guarded_report(tenant_id, "*", cutoff)
        }
    }

    #[test]
    fn sweep_report_labels_are_stable() {
        assert_eq!(
            SweepSelection::ExactCategory("invocation").report_label(),
            "invocation"
        );
        assert_eq!(SweepSelection::RemainingCategories(&[]).report_label(), "*",);
    }

    #[tokio::test]
    async fn scheduler_rejects_an_interval_larger_than_postgres_bigint() {
        let pool = PgPool::connect_lazy("postgres://unused:unused@localhost/unused")
            .expect("syntactically valid database URL");
        let sweeper = ScriptedSweeper::new([]);
        let store = crate::retention::PgRetentionStore::new(pool.clone());
        let error = sweep_all_policies_if_tick_claimed(
            &pool,
            &sweeper,
            &store,
            Duration::from_secs(i64::MAX as u64 + 1),
        )
        .await
        .expect_err("oversized intervals must fail before querying PostgreSQL");
        assert!(
            error
                .to_string()
                .contains("interval exceeds PostgreSQL BIGINT"),
            "got: {error}",
        );
    }

    #[test]
    fn sweep_chain_seq_lookup_matches_only_the_requested_hash() {
        let candidates = vec![candidate(7, None, "wanted"), candidate(9, None, "other")];
        assert_eq!(chain_seq_for_row_hash(&candidates, "wanted"), Some(7));
        assert_eq!(chain_seq_for_row_hash(&candidates, "absent"), None);
    }

    #[test]
    fn sweep_tick_log_level_distinguishes_idle_progress_and_remaining_work() {
        assert_eq!(
            tick_log_level(&PolicySweepStats::default()),
            TickLogLevel::Debug,
        );
        assert_eq!(
            tick_log_level(&PolicySweepStats {
                deleted: 1,
                ..PolicySweepStats::default()
            }),
            TickLogLevel::Info,
        );
        assert_eq!(
            tick_log_level(&PolicySweepStats {
                errors: 1,
                ..PolicySweepStats::default()
            }),
            TickLogLevel::Warn,
        );
        assert_eq!(
            tick_log_level(&PolicySweepStats {
                policy_changes: 1,
                ..PolicySweepStats::default()
            }),
            TickLogLevel::Warn,
        );
        assert_eq!(
            tick_log_level(&PolicySweepStats {
                deleted: 1,
                backlogged_policies: 1,
                ..PolicySweepStats::default()
            }),
            TickLogLevel::Warn,
        );
    }

    #[test]
    fn policy_sweep_stats_adds_every_counter() {
        let mut total = PolicySweepStats {
            policies: 2,
            batches: 3,
            markers: 5,
            deleted: 7,
            errors: 11,
            policy_changes: 13,
            backlogged_policies: 17,
        };
        total.add(&PolicySweepStats {
            policies: 19,
            batches: 23,
            markers: 29,
            deleted: 31,
            errors: 37,
            policy_changes: 41,
            backlogged_policies: 43,
        });

        assert_eq!(total.policies, 21);
        assert_eq!(total.batches, 26);
        assert_eq!(total.markers, 34);
        assert_eq!(total.deleted, 38);
        assert_eq!(total.errors, 48);
        assert_eq!(total.policy_changes, 54);
        assert_eq!(total.backlogged_policies, 60);
    }

    #[tokio::test]
    async fn sweep_policy_batches_accumulates_reports_and_uses_past_cutoff() {
        let sweeper = ScriptedSweeper::new([(2, 500, true), (1, 3, false)]);
        let policy = retention_policy("invocation", 30);
        let snapshot = vec![policy.clone()];
        let before = OffsetDateTime::now_utc() - time::Duration::days(30);
        let stats = sweep_policy_batches(&sweeper, &policy, &snapshot, None).await;
        let after = OffsetDateTime::now_utc() - time::Duration::days(30);

        assert_eq!(stats.policies, 1);
        assert_eq!(stats.batches, 2);
        assert_eq!(stats.markers, 3);
        assert_eq!(stats.deleted, 503);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.policy_changes, 0);
        assert_eq!(stats.backlogged_policies, 0);
        let cutoffs = sweeper.cutoffs.lock().unwrap();
        assert_eq!(cutoffs.len(), 2);
        assert!(
            cutoffs
                .iter()
                .all(|cutoff| *cutoff >= before && *cutoff <= after),
            "the policy duration must be subtracted from now",
        );
    }

    #[tokio::test]
    async fn sweep_policy_batches_caps_a_persistent_backlog() {
        let reports = std::iter::repeat_n((1, 500, true), RETENTION_SWEEP_MAX_BATCHES_PER_TICK);
        let sweeper = ScriptedSweeper::new(reports);
        let policy = retention_policy("invocation", 30);
        let snapshot = vec![policy.clone()];
        let stats = sweep_policy_batches(&sweeper, &policy, &snapshot, None).await;
        assert_eq!(stats.policies, 1);
        assert_eq!(stats.batches, RETENTION_SWEEP_MAX_BATCHES_PER_TICK);
        assert_eq!(stats.markers, RETENTION_SWEEP_MAX_BATCHES_PER_TICK);
        assert_eq!(
            stats.deleted,
            (RETENTION_SWEEP_BATCH_ROWS * RETENTION_SWEEP_MAX_BATCHES_PER_TICK) as u64,
        );
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.policy_changes, 0);
        assert_eq!(stats.backlogged_policies, 1);
    }

    #[tokio::test]
    async fn sweep_policy_batches_exact_tick_capacity_is_not_backlogged() {
        let mut reports = vec![(1, 500, true); RETENTION_SWEEP_MAX_BATCHES_PER_TICK - 1];
        reports.push((1, 500, false));
        let sweeper = ScriptedSweeper::new(reports);
        let policy = retention_policy("invocation", 30);
        let snapshot = vec![policy.clone()];

        let stats = sweep_policy_batches(&sweeper, &policy, &snapshot, None).await;

        assert_eq!(stats.batches, RETENTION_SWEEP_MAX_BATCHES_PER_TICK);
        assert_eq!(stats.deleted, 5_000);
        assert_eq!(stats.backlogged_policies, 0);
    }

    #[tokio::test]
    async fn sweep_policy_batches_stops_when_policy_changes_between_batches() {
        let sweeper = ScriptedSweeper::with_policy_change_on_call([(1, 500, true)], 2);
        let policy = retention_policy("invocation", 30);
        let snapshot = vec![policy.clone()];

        let stats = sweep_policy_batches(&sweeper, &policy, &snapshot, None).await;

        assert_eq!(stats.batches, 1);
        assert_eq!(stats.deleted, 500);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.policy_changes, 1);
        assert_eq!(stats.backlogged_policies, 0);
        assert_eq!(*sweeper.guarded_calls.lock().unwrap(), 2);
    }

    /// Single contiguous span: every candidate's prev_hash
    /// chains from the previous candidate's row_hash. One
    /// segment, one marker.
    #[test]
    fn contiguous_candidates_form_single_segment() {
        let candidates = vec![
            candidate(1, None, "h1"),
            candidate(2, Some("h1"), "h2"),
            candidate(3, Some("h2"), "h3"),
        ];
        let segs = group_into_chain_segments(&candidates);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].len(), 3);
        assert_eq!(segs[0][0].prev_hash, None);
        assert_eq!(segs[0][2].row_hash, "h3");
    }

    /// Interleaved survivors split the deletion into
    /// multiple segments. Surviving rows aren't in the
    /// candidates list; the segmentation infers them from
    /// each candidate's `prev_hash` not chaining to the
    /// prior candidate's `row_hash`.
    #[test]
    fn interleaved_survivors_split_into_two_segments() {
        // Original chain: r1(A), r2(B), r3(A), r4(B), r5(A)
        // Sweep cat A: candidates are r1, r3, r5.
        // r1.prev = None
        // r3.prev = r2.row_hash (= "h2") — NOT r1.row_hash
        // r5.prev = r4.row_hash (= "h4") — NOT r3.row_hash
        let candidates = vec![
            candidate(1, None, "h1"),
            candidate(3, Some("h2"), "h3"),
            candidate(5, Some("h4"), "h5"),
        ];
        let segs = group_into_chain_segments(&candidates);
        assert_eq!(segs.len(), 3, "three singleton segments, one per gap");
        assert_eq!(segs[0][0].row_hash, "h1");
        assert_eq!(segs[1][0].row_hash, "h3");
        assert_eq!(segs[2][0].row_hash, "h5");
    }

    /// Mixed contiguous + interleaved: r1, r2 contiguous;
    /// r5 separate. Two segments.
    #[test]
    fn mixed_contiguous_and_split() {
        let candidates = vec![
            candidate(1, None, "h1"),
            candidate(2, Some("h1"), "h2"),
            candidate(5, Some("h4"), "h5"),
        ];
        let segs = group_into_chain_segments(&candidates);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].len(), 2);
        assert_eq!(segs[1].len(), 1);
        assert_eq!(segs[0][0].prev_hash, None);
        assert_eq!(segs[0][1].row_hash, "h2");
        assert_eq!(segs[1][0].row_hash, "h5");
    }

    /// Empty candidate list → no segments.
    #[test]
    fn empty_candidates_no_segments() {
        let segs = group_into_chain_segments(&[]);
        assert!(segs.is_empty());
    }

    /// The sweep
    /// refuses to operate on `category = 'retention_sweep'`
    /// at runtime, regardless of how it's invoked. The admin
    /// endpoint rejects the same string at the request
    /// boundary; this test pins the storage-side refusal so
    /// a future caller that bypasses the admin layer still
    /// can't delete the verifier's chain bridges.
    #[tokio::test]
    async fn refuses_to_sweep_marker_category() {
        // We never reach the pool because the refusal is
        // pre-flight; pass a connection placeholder that
        // would panic if dereferenced.
        let dummy_pool: sqlx::PgPool = sqlx::Pool::<sqlx::Postgres>::connect_lazy(
            "postgres://placeholder:placeholder@127.0.0.1:1/placeholder",
        )
        .expect("lazy pool builds without connecting");
        let now = OffsetDateTime::now_utc();
        let err = run_retention_sweep(&dummy_pool, "any-tenant", "retention_sweep", now)
            .await
            .expect_err("must refuse the marker category");
        match err {
            SweepError::ForbiddenCategory(c) => assert_eq!(c, "retention_sweep"),
            other => panic!("expected ForbiddenCategory, got {other:?}"),
        }
    }

    /// Scheduler tick executes explicit and wildcard policies while passing
    /// the explicit categories as wildcard exclusions.
    #[tokio::test]
    async fn scheduler_tick_enforces_wildcard_with_explicit_precedence() {
        use std::sync::Mutex;

        struct FakeStore {
            policies: Vec<crate::retention::RetentionPolicy>,
        }
        #[async_trait::async_trait]
        impl crate::retention::RetentionStore for FakeStore {
            async fn list(
                &self,
                _tenant_id: Option<&str>,
            ) -> Result<Vec<crate::retention::RetentionPolicy>, sqlx::Error> {
                Ok(self.policies.clone())
            }
            async fn upsert(
                &self,
                _tenant_id: &str,
                _category: &str,
                _delete_after_days: i32,
            ) -> Result<crate::retention::RetentionPolicy, sqlx::Error> {
                unimplemented!("scheduler test only uses list")
            }
            async fn delete(&self, _tenant_id: &str, _category: &str) -> Result<bool, sqlx::Error> {
                unimplemented!("scheduler test only uses list")
            }
        }

        struct FakeSweeper {
            calls: Mutex<Vec<(String, String, Vec<String>)>>,
        }
        #[async_trait::async_trait]
        impl Sweeper for FakeSweeper {
            async fn sweep(
                &self,
                tenant_id: &str,
                category: &str,
                cutoff: OffsetDateTime,
            ) -> Result<SweepReport, SweepError> {
                self.calls.lock().unwrap().push((
                    tenant_id.to_owned(),
                    category.to_owned(),
                    Vec::new(),
                ));
                Ok(SweepReport {
                    tenant_id: tenant_id.to_owned(),
                    category: category.to_owned(),
                    cutoff,
                    markers_written: 0,
                    rows_deleted: 0,
                    batch_limit_reached: false,
                })
            }

            async fn sweep_remaining_categories(
                &self,
                tenant_id: &str,
                excluded_categories: &[String],
                cutoff: OffsetDateTime,
            ) -> Result<SweepReport, SweepError> {
                self.calls.lock().unwrap().push((
                    tenant_id.to_owned(),
                    "*".to_owned(),
                    excluded_categories.to_vec(),
                ));
                Ok(SweepReport {
                    tenant_id: tenant_id.to_owned(),
                    category: "*".to_owned(),
                    cutoff,
                    markers_written: 0,
                    rows_deleted: 0,
                    batch_limit_reached: false,
                })
            }

            async fn sweep_if_policy_current(
                &self,
                tenant_id: &str,
                category: &str,
                cutoff: OffsetDateTime,
                _expected_policy: &RetentionPolicy,
            ) -> Result<SweepReport, SweepError> {
                self.sweep(tenant_id, category, cutoff).await
            }

            async fn sweep_remaining_categories_if_policies_current(
                &self,
                tenant_id: &str,
                excluded_categories: &[String],
                cutoff: OffsetDateTime,
                _expected_policies: &[RetentionPolicy],
            ) -> Result<SweepReport, SweepError> {
                self.sweep_remaining_categories(tenant_id, excluded_categories, cutoff)
                    .await
            }
        }

        let now = OffsetDateTime::now_utc();
        let policy = |tenant: &str, category: &str| crate::retention::RetentionPolicy {
            tenant_id: tenant.to_owned(),
            category: category.to_owned(),
            delete_after_days: 30,
            created_at: now,
            updated_at: now,
        };
        let store = FakeStore {
            policies: vec![
                policy("acme", "invocation"),
                policy("acme", "*"),
                policy("beta", "admin_mutation"),
            ],
        };
        let sweeper = FakeSweeper {
            calls: Mutex::new(Vec::new()),
        };
        sweep_all_policies(&sweeper, &store).await;
        let calls = sweeper.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                ("acme".to_owned(), "invocation".to_owned(), Vec::new(),),
                (
                    "acme".to_owned(),
                    "*".to_owned(),
                    vec!["invocation".to_owned()],
                ),
                ("beta".to_owned(), "admin_mutation".to_owned(), Vec::new(),),
            ],
            "wildcard must run after explicit scopes and exclude them",
        );
    }

    /// Invalid policy cutoffs and per-tenant sweep failures must NOT stop the
    /// scheduler from sweeping other tenants. Otherwise one bad policy could
    /// block all retention enforcement.
    #[tokio::test]
    async fn scheduler_tick_continues_past_invalid_cutoffs_and_sweep_errors() {
        use std::sync::Mutex;

        struct FakeStore;
        #[async_trait::async_trait]
        impl crate::retention::RetentionStore for FakeStore {
            async fn list(
                &self,
                _tenant_id: Option<&str>,
            ) -> Result<Vec<crate::retention::RetentionPolicy>, sqlx::Error> {
                let now = OffsetDateTime::now_utc();
                Ok(vec![
                    crate::retention::RetentionPolicy {
                        tenant_id: "unrepresentable".to_owned(),
                        category: "invocation".to_owned(),
                        delete_after_days: i32::MAX,
                        created_at: now,
                        updated_at: now,
                    },
                    crate::retention::RetentionPolicy {
                        tenant_id: "fails".to_owned(),
                        category: "invocation".to_owned(),
                        delete_after_days: 30,
                        created_at: now,
                        updated_at: now,
                    },
                    crate::retention::RetentionPolicy {
                        tenant_id: "ok".to_owned(),
                        category: "invocation".to_owned(),
                        delete_after_days: 30,
                        created_at: now,
                        updated_at: now,
                    },
                ])
            }
            async fn upsert(
                &self,
                _tenant_id: &str,
                _category: &str,
                _delete_after_days: i32,
            ) -> Result<crate::retention::RetentionPolicy, sqlx::Error> {
                unimplemented!()
            }
            async fn delete(&self, _tenant_id: &str, _category: &str) -> Result<bool, sqlx::Error> {
                unimplemented!()
            }
        }

        struct FlakySweeper {
            calls: Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl Sweeper for FlakySweeper {
            async fn sweep(
                &self,
                tenant_id: &str,
                category: &str,
                cutoff: OffsetDateTime,
            ) -> Result<SweepReport, SweepError> {
                self.calls.lock().unwrap().push(tenant_id.to_owned());
                if tenant_id == "fails" {
                    return Err(SweepError::ForbiddenCategory("simulated".to_owned()));
                }
                Ok(SweepReport {
                    tenant_id: tenant_id.to_owned(),
                    category: category.to_owned(),
                    cutoff,
                    markers_written: 0,
                    rows_deleted: 0,
                    batch_limit_reached: false,
                })
            }

            async fn sweep_remaining_categories(
                &self,
                _tenant_id: &str,
                _excluded_categories: &[String],
                _cutoff: OffsetDateTime,
            ) -> Result<SweepReport, SweepError> {
                panic!("this fixture contains no wildcard policy")
            }

            async fn sweep_if_policy_current(
                &self,
                tenant_id: &str,
                category: &str,
                cutoff: OffsetDateTime,
                _expected_policy: &RetentionPolicy,
            ) -> Result<SweepReport, SweepError> {
                self.sweep(tenant_id, category, cutoff).await
            }

            async fn sweep_remaining_categories_if_policies_current(
                &self,
                _tenant_id: &str,
                _excluded_categories: &[String],
                _cutoff: OffsetDateTime,
                _expected_policies: &[RetentionPolicy],
            ) -> Result<SweepReport, SweepError> {
                panic!("this fixture contains no wildcard policy")
            }
        }

        let store = FakeStore;
        let sweeper = FlakySweeper {
            calls: Mutex::new(Vec::new()),
        };
        sweep_all_policies(&sweeper, &store).await;
        assert_eq!(
            sweeper.calls.lock().unwrap().clone(),
            vec!["fails".to_owned(), "ok".to_owned()],
            "the invalid cutoff must not reach the sweeper, and both later policies must run",
        );
    }

    #[test]
    fn unchained_candidates_need_no_bridge_segment() {
        let candidates = vec![CandidateRow {
            id: Uuid::from_u128(1),
            chain_seq: 1,
            prev_hash: None,
            row_hash: None,
        }];
        assert!(
            group_into_chain_segments(&candidates).is_empty(),
            "unchained evidence needs a visible deletion marker but no hash-chain bridge",
        );
    }

    /// Each emitted segment passes `RetentionMarker::validate`
    /// (the property the verifier's storage adapter checks).
    /// Pin this
    /// because the sweep's output is the verifier's input —
    /// a segmentation bug that produces malformed payloads
    /// would silently get dropped by the verifier.
    #[test]
    fn emitted_segments_pass_marker_validate() {
        let candidates = vec![
            candidate(1, None, "h1"),
            candidate(2, Some("h1"), "h2"),
            candidate(5, Some("h4"), "h5"),
        ];
        let segs = group_into_chain_segments(&candidates);
        for seg in &segs {
            let marker = RetentionMarker {
                kind: RetentionMarker::KIND.to_owned(),
                deleted_rows: seg.clone(),
                deleted_unchained_rows: Vec::new(),
                deleted_chain_seq_min: None,
                deleted_chain_seq_max: None,
                policy: None,
            };
            assert!(
                marker.validate(),
                "every emitted segment must produce a valid marker payload",
            );
        }
    }
}
