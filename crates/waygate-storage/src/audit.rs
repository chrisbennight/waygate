//! Postgres-backed [`EvidenceRecorder`].
//!
//! Writes every recorded event to the `audit_log` table. The
//! [`EvidenceRecorder`] trait exposes three write methods:
//!
//! - `record_required` — one fail-closed persistence attempt. Returns the
//!   persisted event id on success; surfaces `EvidenceError` on failure so
//!   a caller can abort before an irreversible action. The recorder does not
//!   retry, so this is not an at-least-once delivery guarantee.
//! - `record_chained_best_effort` — one hash-chained insert attempt that
//!   measures and log-and-drops failures. Successful rows share the same
//!   per-tenant chain transaction as required writes, but this path does not
//!   wait for a contended tenant lock or exceed its one-second caller
//!   deadline. Nested invocation rows also enqueue configured external
//!   delivery in that bounded transaction so execution hierarchy reaches the
//!   evidence exporters.
//! - `record_best_effort` — one independent, unchained insert attempt that
//!   log-and-drops on error. Preserves the "audit outages
//!   never become user-facing outages" posture for the bulk of
//!   informational events.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Uuid;
use thiserror::Error;
use time::OffsetDateTime;

use waygate_core::RiskTier;
use waygate_evidence::audit::{AuditEvent, EvidenceError, EvidenceRecorder};
use waygate_telemetry::metrics::{
    ChainedBestEffortFailureStage, ChainedBestEffortOutcome, ChainedBestEffortTerminalOutcome,
};

#[cfg(test)]
mod category_feed_tests;

mod notable_feed;

#[cfg(test)]
static VERIFY_MARKER_ROWS_LOADED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("connect: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[source] sqlx::migrate::MigrateError),
}

#[derive(Clone, Copy)]
enum ChainedWriteMode {
    RequiredExport,
    BestEffortLocal,
    BestEffortExport,
}

impl ChainedWriteMode {
    fn is_best_effort(self) -> bool {
        matches!(self, Self::BestEffortLocal | Self::BestEffortExport)
    }

    fn enqueues_outbox(self) -> bool {
        matches!(self, Self::RequiredExport | Self::BestEffortExport)
    }
}

/// Chained best-effort evidence must never inherit the required path's
/// unbounded willingness to wait. Tenant lock acquisition is non-blocking;
/// this deadline additionally bounds pool acquisition and the remaining write.
const CHAINED_BEST_EFFORT_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const CHAINED_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChainedWriteStage {
    TxBegin,
    ChainLock,
    ChainLockRollback,
    ChainLockContended,
    ChainSelectPrev,
    AuditInsert,
    RoutingLookup,
    PayloadSerialize,
    OutboxEnqueue,
    TxCommit,
}

impl ChainedWriteStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::TxBegin => "tx_begin",
            Self::ChainLock => "chain_lock",
            Self::ChainLockRollback => "chain_lock_rollback",
            Self::ChainLockContended => "chain_lock_contended",
            Self::ChainSelectPrev => "chain_select_prev",
            Self::AuditInsert => "audit_insert",
            Self::RoutingLookup => "routing_lookup",
            Self::PayloadSerialize => "payload_serialize",
            Self::OutboxEnqueue => "outbox_enqueue",
            Self::TxCommit => "tx_commit",
        }
    }

    fn metric_stage(self) -> ChainedBestEffortFailureStage {
        match self {
            Self::TxBegin => ChainedBestEffortFailureStage::TxBegin,
            Self::ChainLock => ChainedBestEffortFailureStage::ChainLock,
            Self::ChainLockRollback => ChainedBestEffortFailureStage::ChainLockRollback,
            Self::ChainLockContended => ChainedBestEffortFailureStage::ChainLockContended,
            Self::ChainSelectPrev => ChainedBestEffortFailureStage::ChainSelectPrev,
            Self::AuditInsert => ChainedBestEffortFailureStage::AuditInsert,
            Self::RoutingLookup => ChainedBestEffortFailureStage::RoutingLookup,
            Self::PayloadSerialize => ChainedBestEffortFailureStage::PayloadSerialize,
            Self::OutboxEnqueue => ChainedBestEffortFailureStage::OutboxEnqueue,
            Self::TxCommit => ChainedBestEffortFailureStage::TxCommit,
        }
    }
}

struct ChainedWriteError {
    stage: ChainedWriteStage,
    detail: String,
    terminal_outcome: ChainedWriteFailureOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChainedWriteFailureOutcome {
    Dropped,
    Unknown,
}

impl ChainedWriteFailureOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dropped => "dropped",
            Self::Unknown => "unknown",
        }
    }
}

impl ChainedWriteError {
    fn message(stage: ChainedWriteStage, detail: String) -> Self {
        Self {
            stage,
            detail,
            terminal_outcome: ChainedWriteFailureOutcome::Dropped,
        }
    }

    fn deadline(stage: ChainedWriteStage, terminal_outcome: ChainedWriteFailureOutcome) -> Self {
        Self {
            stage,
            detail: format!(
                "{} did not complete before the chained best-effort write deadline",
                stage.as_str()
            ),
            terminal_outcome,
        }
    }
}

#[derive(Clone, Copy)]
struct ChainedWriteDeadline(Option<tokio::time::Instant>);

impl ChainedWriteDeadline {
    fn for_mode(mode: ChainedWriteMode) -> Self {
        if mode.is_best_effort() {
            Self(Some(
                tokio::time::Instant::now() + CHAINED_BEST_EFFORT_WRITE_TIMEOUT,
            ))
        } else {
            Self(None)
        }
    }

    async fn run<T, E, F>(
        self,
        stage: ChainedWriteStage,
        terminal_outcome: ChainedWriteFailureOutcome,
        future: F,
    ) -> Result<T, ChainedWriteError>
    where
        E: std::fmt::Display,
        F: Future<Output = Result<T, E>>,
    {
        match self.0 {
            Some(deadline) => tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| ChainedWriteError::deadline(stage, terminal_outcome))?
                .map_err(|error| ChainedWriteError {
                    stage,
                    detail: error.to_string(),
                    terminal_outcome,
                }),
            None => future.await.map_err(|error| ChainedWriteError {
                stage,
                detail: error.to_string(),
                terminal_outcome,
            }),
        }
    }

    async fn commit(
        self,
        tx: sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), ChainedWriteError> {
        let map_error = |error: sqlx::Error| ChainedWriteError {
            stage: ChainedWriteStage::TxCommit,
            detail: error.to_string(),
            terminal_outcome: ChainedWriteFailureOutcome::Unknown,
        };
        let Some(deadline) = self.0 else {
            return tx.commit().await.map_err(map_error);
        };

        // Poll COMMIT first even when the deadline becomes ready in the same
        // scheduler turn. Once COMMIT has been polled, cancellation cannot
        // prove whether PostgreSQL made the transaction durable.
        tokio::select! {
            biased;
            result = tx.commit() => result.map_err(map_error),
            _ = tokio::time::sleep_until(deadline) => Err(ChainedWriteError::deadline(
                ChainedWriteStage::TxCommit,
                ChainedWriteFailureOutcome::Unknown,
            )),
        }
    }
}

#[derive(Default)]
struct ChainedFailureLogState {
    episode_started: Option<Instant>,
    last_emitted: Option<Instant>,
    last_failure: Option<Instant>,
    suppressed: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum ChainedFailureLogDecision {
    Emit { suppressed_since_last: u64 },
    Suppress,
}

struct ChainedFailureRecovery {
    duration: Duration,
    suppressed_since_last: u64,
}

impl ChainedFailureLogState {
    fn on_failure(&mut self, now: Instant) -> ChainedFailureLogDecision {
        self.last_failure = Some(now);
        let Some(last_emitted) = self.last_emitted else {
            self.episode_started = Some(now);
            self.last_emitted = Some(now);
            return ChainedFailureLogDecision::Emit {
                suppressed_since_last: 0,
            };
        };

        if now.duration_since(last_emitted) >= CHAINED_FAILURE_LOG_INTERVAL {
            self.last_emitted = Some(now);
            return ChainedFailureLogDecision::Emit {
                suppressed_since_last: std::mem::take(&mut self.suppressed),
            };
        }

        self.suppressed = self.suppressed.saturating_add(1);
        ChainedFailureLogDecision::Suppress
    }

    fn on_success(&mut self, now: Instant) -> Option<ChainedFailureRecovery> {
        let episode_started = self.episode_started?;
        let last_failure = self.last_failure?;
        if now.duration_since(last_failure) < CHAINED_FAILURE_LOG_INTERVAL {
            return None;
        }

        self.episode_started = None;
        self.last_emitted = None;
        self.last_failure = None;
        Some(ChainedFailureRecovery {
            duration: now.duration_since(episode_started),
            suppressed_since_last: std::mem::take(&mut self.suppressed),
        })
    }
}

pub struct PgAuditSink {
    pool: PgPool,
    chained_failure_log: Mutex<ChainedFailureLogState>,
    /// Target sinks the recorder's `record_required`
    /// path enqueues an outbox row for, INSIDE the same transaction
    /// as the audit INSERT. Empty (the default) preserves the
    /// prior behavior of no outbox rows — operators opt in by
    /// setting `GATEWAY_EVIDENCE_OUTBOX_TARGETS=ocsf,webhook,...`
    /// (parsed by `waygate-server::config`). Each identifier is
    /// free-form; the drain worker routes on the string.
    /// Unchained best-effort events and direct chained-best-effort events skip
    /// the outbox. Hierarchy-bearing chained events enqueue configured targets
    /// in their same bounded transaction so external evidence retains the
    /// execution-to-call relationship.
    outbox_targets: Vec<String>,
}

impl PgAuditSink {
    /// Connect, run migrations, and hand back a ready-to-use sink.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(StorageError::Connect)?;

        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .map_err(StorageError::Migrate)?;

        Ok(Self {
            pool,
            chained_failure_log: Mutex::new(ChainedFailureLogState::default()),
            outbox_targets: Vec::new(),
        })
    }

    /// Use an already-built pool. Test code and callers that want to share a
    /// pool with other storage modules skip the `connect` bootstrap.
    pub fn with_pool(pool: PgPool) -> Self {
        Self {
            pool,
            chained_failure_log: Mutex::new(ChainedFailureLogState::default()),
            outbox_targets: Vec::new(),
        }
    }

    /// Opt the recorder into the evidence outbox.
    /// Each call to `record_required` then ALSO writes one
    /// `evidence_outbox` row per `target_sink` in this list,
    /// inside the same transaction as the audit INSERT — so the
    /// audit row and its outbox companions commit atomically
    /// (the outbox pattern's correctness property).
    ///
    /// An empty `targets` list preserves the single-INSERT
    /// behavior.
    #[must_use]
    pub fn with_outbox_targets(mut self, targets: Vec<String>) -> Self {
        self.outbox_targets = targets;
        self
    }

    /// Clone of the underlying pool, for callers (e.g. `waygate-as`) that
    /// share DB access with the audit sink. `PgPool` is internally an `Arc`,
    /// so cloning is cheap.
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Run migrations against a pre-built pool. Useful for tests that want
    /// to own the pool lifecycle but still apply schema.
    pub async fn migrate(pool: &PgPool) -> Result<(), StorageError> {
        sqlx::migrate!("../../migrations")
            .run(pool)
            .await
            .map_err(StorageError::Migrate)
    }
}

impl PgAuditSink {
    /// Inner audit-row INSERT, parameterised over a SQL executor so
    /// the caller can supply either `&self.pool` (auto-commit, used
    /// by `record_best_effort`) or `&mut *tx` (recorder transaction,
    /// used by `record_required` so the audit row + outbox rows
    /// commit atomically).
    async fn insert_event<'e, E>(
        executor: E,
        event: &AuditEvent,
        prev_hash: Option<&str>,
        row_hash: Option<&str>,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        // Persist SCIM
        // facts on every audit row, including the
        // `record_best_effort` path that bypasses the outbox.
        // The exporters previously only saw events that flowed
        // through `record_required + effective_targets`; common
        // requests went through `record_best_effort` and SCIM
        // facts were lost. Two typed columns (`scim_active
        // BOOLEAN`, `scim_groups TEXT[]`) keep producer and
        // verifier hashing the same way as every other column
        // (`write_opt_bool` + `write_str_vec`) — no JSON
        // canonicalisation drift risk.
        let (sub, email, groups, issuer, scim_active, scim_groups) = match event.principal.as_ref()
        {
            Some(p) => (
                Some(p.sub.clone()),
                p.email.clone(),
                p.groups.clone(),
                Some(p.issuer.clone()),
                p.scim_active,
                p.scim_groups.clone(),
            ),
            None => (None, None, Vec::new(), None, None, Vec::new()),
        };
        let risk = event.risk_level.map(risk_str);
        // `scim_groups` ⇒ Option<&Vec<String>> bound as TEXT[].
        // Skip-binding empty as NULL (cleaner row state) by
        // wrapping in Option.
        let scim_groups_bind: Option<&Vec<String>> = if scim_groups.is_empty() {
            None
        } else {
            Some(&scim_groups)
        };

        // The four authorization-decision inputs. Bound as
        // TEXT[] / TEXT / TEXT[] / BOOLEAN; empty vecs bind as NULL (the
        // "absent" state) so a non-decision row stores NULL and hashes
        // byte-identically to the pre-0062 chain (zero-bytes-when-absent).
        let req_scopes_bind: Option<&Vec<String>> = if event.req_scopes.is_empty() {
            None
        } else {
            Some(&event.req_scopes)
        };
        let req_roles_bind: Option<&Vec<String>> = if event.req_roles.is_empty() {
            None
        } else {
            Some(&event.req_roles)
        };
        let (parent_execution_id, execution_step, execution_call_id, execution_attempt) =
            match event.invocation_hierarchy {
                Some(hierarchy) => (
                    Some(hierarchy.parent_execution_id),
                    Some(i64::from(hierarchy.step.get())),
                    Some(hierarchy.call_id),
                    Some(i64::from(hierarchy.attempt.get())),
                ),
                None => (None, None, None, None),
            };

        // `prev_hash` + `row_hash` are nullable. Unchained best-effort writes
        // pass None; required and chained-best-effort writes compute both.
        sqlx::query(
            r#"
            INSERT INTO audit_log (
                id, ts, category, tenant_id, action, outcome,
                principal_sub, principal_email, principal_groups, issuer,
                server, tool, risk_level, pii,
                policy_ids, reason,
                trace_id, latency_ms,
                prev_hash, row_hash,
                scim_active, scim_groups,
                target,
                req_scopes, auth_method, req_roles, side_effects,
                acting_agent,
                parent_execution_id, execution_step,
                execution_call_id, execution_attempt,
                operation
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16,
                $17, $18,
                $19, $20,
                $21, $22,
                $23,
                $24, $25, $26, $27,
                $28,
                $29, $30,
                $31, $32,
                $33
            )
            "#,
        )
        .bind(event.id)
        .bind(event.ts)
        .bind(event.category.as_str())
        .bind(event.tenant.as_str())
        .bind(&event.action)
        .bind(event.outcome.as_str())
        .bind(sub)
        .bind(email)
        .bind(&groups)
        .bind(issuer)
        .bind(&event.server)
        .bind(&event.tool)
        .bind(risk)
        .bind(event.pii)
        .bind(&event.policy_ids)
        .bind(&event.reason)
        .bind(&event.trace_id)
        .bind(event.latency_ms)
        .bind(prev_hash)
        .bind(row_hash)
        .bind(scim_active)
        .bind(scim_groups_bind)
        .bind(&event.target)
        .bind(req_scopes_bind)
        .bind(&event.auth_method)
        .bind(req_roles_bind)
        .bind(event.side_effects)
        .bind(&event.acting_agent)
        .bind(parent_execution_id)
        .bind(execution_step)
        .bind(execution_call_id)
        .bind(execution_attempt)
        .bind(&event.operation)
        .execute(executor)
        .await
        .map(|_| ())
    }

    /// Persist one hash-chained row. Required and chained-best-effort callers
    /// share this transaction so lock ordering, canonical hashing, and commit
    /// behavior cannot drift. Outbox work is an explicit mode rather than an
    /// implication of chain coverage.
    async fn insert_chained_event(
        &self,
        event: &AuditEvent,
        mode: ChainedWriteMode,
    ) -> Result<(), ChainedWriteError> {
        let deadline = ChainedWriteDeadline::for_mode(mode);
        let (principal_sub, principal_email, principal_groups, issuer, scim_active, scim_groups) =
            match event.principal.as_ref() {
                Some(p) => (
                    Some(p.sub.as_str()),
                    p.email.as_deref(),
                    p.groups.clone(),
                    Some(p.issuer.as_str()),
                    p.scim_active,
                    p.scim_groups.clone(),
                ),
                None => (None, None, Vec::new(), None, None, Vec::new()),
            };
        let canonical_payload = crate::hashchain::canonical_audit_bytes_with_ext5(
            event.id,
            event.ts,
            event.category.as_str(),
            event.tenant.as_str(),
            event.action.as_str(),
            event.outcome.as_str(),
            principal_sub,
            principal_email,
            &principal_groups,
            issuer,
            event.server.as_deref(),
            event.tool.as_deref(),
            event.risk_level.map(risk_str),
            event.pii,
            &event.policy_ids,
            event.reason.as_deref(),
            event.trace_id.as_deref(),
            event.latency_ms,
            scim_active,
            &scim_groups,
            event.target.as_deref(),
            &event.req_scopes,
            event.auth_method.as_deref(),
            &event.req_roles,
            event.side_effects,
            event.acting_agent.as_deref(),
            event.invocation_hierarchy.as_ref(),
            event.operation.as_deref(),
        );

        let mut tx = deadline
            .run(
                ChainedWriteStage::TxBegin,
                ChainedWriteFailureOutcome::Dropped,
                self.pool.begin(),
            )
            .await?;

        // The transaction-scoped tenant lock makes the head-read and insert
        // atomic for this tenant while retaining cross-tenant parallelism.
        // Required writes wait because their caller must fail closed. A
        // best-effort write uses PostgreSQL's non-blocking lock primitive so
        // returning at its deadline cannot leave a server-side lock request
        // occupying a pooled connection.
        let lock_acquired = if mode.is_best_effort() {
            deadline
                .run(
                    ChainedWriteStage::ChainLock,
                    ChainedWriteFailureOutcome::Dropped,
                    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                        .bind(event.tenant.as_str())
                        .fetch_one(&mut *tx),
                )
                .await?
        } else {
            deadline
                .run(
                    ChainedWriteStage::ChainLock,
                    ChainedWriteFailureOutcome::Dropped,
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                        .bind(event.tenant.as_str())
                        .execute(&mut *tx),
                )
                .await?;
            true
        };
        if !lock_acquired {
            deadline
                .run(
                    ChainedWriteStage::ChainLockRollback,
                    ChainedWriteFailureOutcome::Dropped,
                    tx.rollback(),
                )
                .await?;
            return Err(ChainedWriteError::message(
                ChainedWriteStage::ChainLockContended,
                "tenant chain lock is already held".into(),
            ));
        }

        // Caller timestamps are not insertion order. The verifier also walks
        // chain_seq, so producer and verifier agree on the durable sequence.
        let prev_hash: Option<String> = deadline
            .run(
                ChainedWriteStage::ChainSelectPrev,
                ChainedWriteFailureOutcome::Dropped,
                sqlx::query_scalar(
                    r#"
                    SELECT row_hash
                      FROM audit_log
                     WHERE tenant_id = $1
                       AND row_hash IS NOT NULL
                     ORDER BY chain_seq DESC
                     LIMIT 1
                    "#,
                )
                .bind(event.tenant.as_str())
                .fetch_optional(&mut *tx),
            )
            .await?;

        let row_hash = crate::hashchain::compute_row_hash(prev_hash.as_deref(), &canonical_payload);
        deadline
            .run(
                ChainedWriteStage::AuditInsert,
                ChainedWriteFailureOutcome::Dropped,
                Self::insert_event(
                    &mut *tx,
                    event,
                    prev_hash.as_deref(),
                    Some(row_hash.as_str()),
                ),
            )
            .await?;

        if mode.enqueues_outbox() {
            let routing = deadline
                .run(
                    ChainedWriteStage::RoutingLookup,
                    ChainedWriteFailureOutcome::Dropped,
                    crate::routing::fetch_tenant_routing(&mut *tx, event.tenant.as_str()),
                )
                .await?;
            let effective_targets =
                crate::routing::resolve_outbox_targets(&self.outbox_targets, routing.as_deref());
            if !effective_targets.is_empty() {
                let payload = serde_json::to_value(event).map_err(|error| {
                    ChainedWriteError::message(
                        ChainedWriteStage::PayloadSerialize,
                        error.to_string(),
                    )
                })?;
                for target in &effective_targets {
                    deadline
                        .run(
                            ChainedWriteStage::OutboxEnqueue,
                            ChainedWriteFailureOutcome::Dropped,
                            crate::outbox::enqueue(&mut tx, event.id, target, &payload),
                        )
                        .await?;
                }
            }
        }

        deadline.commit(tx).await?;
        Ok(())
    }
}

impl PgAuditSink {
    fn record_chained_failure_log(
        &self,
        event: &AuditEvent,
        error: &ChainedWriteError,
        elapsed: Duration,
    ) {
        let decision = self
            .chained_failure_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .on_failure(Instant::now());
        let ChainedFailureLogDecision::Emit {
            suppressed_since_last,
        } = decision
        else {
            return;
        };

        let pool_connections = self.pool.size();
        let pool_idle = self.pool.num_idle();
        match error.terminal_outcome {
            ChainedWriteFailureOutcome::Dropped => tracing::warn!(
                error = %error.detail,
                event.id = %event.id,
                category = event.category.as_str(),
                audit_outcome = event.outcome.as_str(),
                action = event.action,
                tenant = event.tenant.as_str(),
                trace_id = ?event.trace_id,
                stage = error.stage.as_str(),
                terminal_outcome = error.terminal_outcome.as_str(),
                elapsed_seconds = elapsed.as_secs_f64(),
                pool_connections,
                pool_idle,
                suppressed_since_last,
                "chained best-effort evidence writes are failing",
            ),
            ChainedWriteFailureOutcome::Unknown => tracing::error!(
                error = %error.detail,
                event.id = %event.id,
                category = event.category.as_str(),
                audit_outcome = event.outcome.as_str(),
                action = event.action,
                tenant = event.tenant.as_str(),
                trace_id = ?event.trace_id,
                stage = error.stage.as_str(),
                terminal_outcome = error.terminal_outcome.as_str(),
                elapsed_seconds = elapsed.as_secs_f64(),
                pool_connections,
                pool_idle,
                suppressed_since_last,
                "chained best-effort evidence writes are failing",
            ),
        }
    }

    fn record_chained_recovery_log(&self) {
        let recovery = self
            .chained_failure_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .on_success(Instant::now());
        if let Some(recovery) = recovery {
            tracing::info!(
                failure_episode_seconds = recovery.duration.as_secs_f64(),
                suppressed_since_last = recovery.suppressed_since_last,
                pool_connections = self.pool.size(),
                pool_idle = self.pool.num_idle(),
                "chained best-effort evidence writes recovered",
            );
        }
    }
}

#[async_trait]
impl EvidenceRecorder for PgAuditSink {
    async fn record_required(&self, event: AuditEvent) -> Result<Uuid, EvidenceError> {
        let id = event.id;
        self.insert_chained_event(&event, ChainedWriteMode::RequiredExport)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error.detail,
                    event.id = %event.id,
                    category = event.category.as_str(),
                    outcome = event.outcome.as_str(),
                    stage = error.stage.as_str(),
                    "required evidence write failed",
                );
                EvidenceError::Persistence(error.detail)
            })?;
        Ok(id)
    }

    async fn record_chained_best_effort(&self, event: AuditEvent) {
        waygate_telemetry::metrics::record_evidence_chained_best_effort(
            ChainedBestEffortOutcome::Attempted,
        );
        let started = Instant::now();
        let mode = if event.invocation_hierarchy.is_some() {
            ChainedWriteMode::BestEffortExport
        } else {
            ChainedWriteMode::BestEffortLocal
        };
        let result = self.insert_chained_event(&event, mode).await;
        let elapsed = started.elapsed();
        match result {
            Ok(()) => {
                waygate_telemetry::metrics::record_evidence_chained_best_effort(
                    ChainedBestEffortOutcome::Inserted,
                );
                waygate_telemetry::metrics::record_evidence_chained_best_effort_duration(
                    ChainedBestEffortTerminalOutcome::Inserted,
                    elapsed.as_secs_f64(),
                );
                self.record_chained_recovery_log();
            }
            Err(error) => {
                let (outcome, terminal_outcome) = match error.terminal_outcome {
                    ChainedWriteFailureOutcome::Dropped => (
                        ChainedBestEffortOutcome::Dropped,
                        ChainedBestEffortTerminalOutcome::Dropped,
                    ),
                    ChainedWriteFailureOutcome::Unknown => (
                        ChainedBestEffortOutcome::Unknown,
                        ChainedBestEffortTerminalOutcome::Unknown,
                    ),
                };
                waygate_telemetry::metrics::record_evidence_chained_best_effort(outcome);
                waygate_telemetry::metrics::record_evidence_chained_best_effort_failure(
                    error.stage.metric_stage(),
                );
                waygate_telemetry::metrics::record_evidence_chained_best_effort_duration(
                    terminal_outcome,
                    elapsed.as_secs_f64(),
                );
                self.record_chained_failure_log(&event, &error, elapsed);
            }
        }
    }

    async fn record_best_effort(&self, event: AuditEvent) {
        // The recorder deliberately keeps best-effort writes outside the
        // outbox: by contract, the caller said "ok to drop on
        // failure" — adding retry-via-outbox would amplify writes
        // for events the recorder is allowed to lose, and the
        // operator pays the per-target storage cost for events
        // they didn't pay storage for in the first place.
        // A caller needing outbox export for an event must choose
        // `record_required`; chain coverage alone does not imply delivery.
        // Best-effort writes stay out of the tamper chain.
        // Including them would require taking the per-tenant
        // advisory lock for every event the recorder is
        // explicitly allowed to drop — a synchronization cost
        // for events with no durability guarantee. A caller needing
        // chain coverage without fail-closed delivery must choose
        // `record_chained_best_effort` for that event;
        // the invocation audit-mode flag only changes the side-effecting
        // pre-call intent row.
        if let Err(e) = Self::insert_event(&self.pool, &event, None, None).await {
            tracing::error!(
                error = %e,
                event.id = %event.id,
                category = event.category.as_str(),
                outcome = event.outcome.as_str(),
                "audit insert failed; event dropped (best-effort)",
            );
        }
    }
}

fn risk_str(r: RiskTier) -> &'static str {
    match r {
        RiskTier::Low => "low",
        RiskTier::Medium => "medium",
        RiskTier::High => "high",
    }
}

pub(crate) fn invocation_hierarchy_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<waygate_core::InvocationHierarchy>, sqlx::Error> {
    use std::num::NonZeroU32;

    use sqlx::Row;

    let parent_execution_id: Option<Uuid> = row.try_get("parent_execution_id")?;
    let step: Option<i64> = row.try_get("execution_step")?;
    let call_id: Option<Uuid> = row.try_get("execution_call_id")?;
    let attempt: Option<i64> = row.try_get("execution_attempt")?;
    match (parent_execution_id, step, call_id, attempt) {
        (None, None, None, None) => Ok(None),
        (Some(parent_execution_id), Some(step), Some(call_id), Some(attempt)) => {
            let step = u32::try_from(step)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| sqlx::Error::Decode("invalid execution_step".into()))?;
            let attempt = u32::try_from(attempt)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| sqlx::Error::Decode("invalid execution_attempt".into()))?;
            Ok(Some(waygate_core::InvocationHierarchy::new(
                parent_execution_id,
                step,
                call_id,
                attempt,
            )))
        }
        _ => Err(sqlx::Error::Decode(
            "incomplete invocation hierarchy".into(),
        )),
    }
}

/// One audit row returned by [`AuditReader::recent_events`]. Kept flat so the
/// admin API can hand it directly to serde without remapping. We use `String`
/// for `outcome` / `risk_level` because their canonical wire forms match the
/// column values — no need to thread enums through the REST layer.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditRow {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Discriminator for the recorded event's category. Maps
    /// to `waygate_evidence::audit::EvidenceCategory`. Stored as the lowercase
    /// snake-case string ("invocation", "policy_reload", ...). `None`
    /// for rows written before migration `0006_audit_category.sql`; the
    /// admin view treats those as "invocation" for display purposes.
    pub category: Option<String>,
    /// Tenant the event was emitted under. `default`
    /// for events written before migration 0010 (via the column's
    /// NOT NULL DEFAULT 'default') and for principal-less system
    /// events.
    pub tenant_id: String,
    pub action: String,
    pub outcome: String,
    pub principal_sub: Option<String>,
    pub principal_email: Option<String>,
    pub principal_groups: Vec<String>,
    pub issuer: Option<String>,
    pub server: Option<String>,
    pub tool: Option<String>,
    /// The operation the call selected, for a tool carrying many behind one
    /// name. Without it a reader cannot tell two calls through the same
    /// executor apart, and the row's `risk_level` and `pii` describe the
    /// operation's classification rather than the tool's. `None` for a tool
    /// classified by name alone and for rows predating migration 0087.
    pub operation: Option<String>,
    pub risk_level: Option<String>,
    pub pii: Option<bool>,
    pub policy_ids: Vec<String>,
    pub reason: Option<String>,
    pub trace_id: Option<String>,
    pub latency_ms: Option<i64>,
    /// SCIM `active` flag at audit time.
    /// `None` for legacy rows + for principals that weren't
    /// SCIM-enriched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_active: Option<bool>,
    /// SCIM group display names at audit
    /// time. Empty for legacy rows + for non-SCIM principals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scim_groups: Vec<String>,
    /// WHAT this event acted on, distinct from the acting principal.
    /// For lifecycle/mutation rows this names the subject (an API
    /// key's `sub`, a change-request `action_type`). `None` for
    /// tool-call invocations and rows written before migration
    /// `0046_audit_target.sql`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The four authorization-decision INPUTS a Cedar
    /// decision branched on, captured on the decision row so decision replay can
    /// reconstruct and re-evaluate it. `req_scopes` = `principal.scopes`;
    /// `auth_method` = `principal.auth_method`; `req_roles` =
    /// `principal.roles`; `side_effects` = `resource.side_effects`. NULL /
    /// empty for non-decision rows and for rows written before migration
    /// `0062_audit_decision_inputs.sql`. Not a Decision-Log filter facet —
    /// carried here so the replay reader has every input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub req_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effects: Option<bool>,
    /// Parent execution, ordered step, stable nested call, and attempt.
    /// Absent for direct MCP invocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_hierarchy: Option<waygate_core::InvocationHierarchy>,
}

/// Filter predicate for the admin Activity feed, pushed down into SQL so
/// the feed queries the whole `audit_log`, not just the most-recent page.
///
/// All fields are optional; `None` means "no constraint on this dimension".
/// Built by the admin layer from its `ActivityFilters`. Before this type
/// existed the feed fetched the newest 50 rows and filtered them in memory,
/// so a `server=searxng` filter could never surface a searxng row that sat
/// beyond the newest 50 — even though it was in the table. Pushing the
/// predicate into the query (see [`AuditReader::query_events`]) fixes that.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Tenant scope. When `Some`, only rows whose `tenant_id` matches are
    /// returned/counted. This is a SECURITY boundary, not a pivotable facet:
    /// the admin layer always sets it to the active principal's tenant so a
    /// tenant-scoped Activity page (and its facet rail) can never read
    /// another tenant's audit history. `None` means no tenant constraint
    /// (cross-tenant) — reserved for a future explicitly-authorized global
    /// view; the activity feed never passes `None`.
    pub tenant_id: Option<String>,
    /// Exact match on `server`.
    pub server: Option<String>,
    /// Exact match on `outcome`.
    pub outcome: Option<String>,
    /// Inequality match on `outcome` — when `Some(v)`, only rows whose
    /// `outcome <> v` are returned. The non-success activity filter is served
    /// by the partial `audit_log (tenant_id, id DESC)` index.
    pub outcome_ne: Option<String>,
    /// Exact match on `risk_level`.
    pub risk_level: Option<String>,
    /// Exact match on `COALESCE(category, 'invocation')` — legacy NULL rows
    /// (pre-`0006_audit_category.sql`) count as `invocation`, the convention
    /// that migration documents and the row template renders.
    pub category: Option<String>,
    /// Case-sensitive substring match against `principal_sub` OR
    /// `principal_email` (mirrors the prior in-memory `str::contains`).
    pub principal_substr: Option<String>,
    /// Exact match on `pii`. `Some(true)`/`Some(false)` both exclude rows
    /// whose `pii` is NULL (non-tool-call / pre-`0005_audit_pii.sql`).
    pub pii: Option<bool>,
    /// Inclusive lower bound on `ts` (the resolved relative window).
    pub since: Option<OffsetDateTime>,
    /// Inclusive upper bound on `ts`. Reserved for the histogram
    /// drag-to-zoom; the feed leaves it `None` today.
    pub until: Option<OffsetDateTime>,
    /// Containment match on `policy_ids` — when `Some(id)`, only
    /// rows whose `policy_ids` array CONTAINS `id` are returned. This is the
    /// "decisions that matched this policy" reverse lookup, served by the GIN
    /// index `audit_log_policy_ids_gin` (migration 0059) via `policy_ids @>
    /// ARRAY[$id]`.
    pub policy_id: Option<String>,
    /// Membership match on `category` against a SET of classes.
    /// When non-empty, only rows whose category is in the set are returned
    /// (a NULL category counts as `invocation`, per migration 0006); empty
    /// imposes no constraint. The Decision Log uses this to surface both
    /// tool-call (`invocation`) and model (`llm_completion`) authorization
    /// decisions in one query while excluding non-decision categories
    /// (`admin_mutation` / `oauth_event` / `retention_sweep` / …). Distinct
    /// from the single-valued `category` above, which other callers use for a
    /// sargable exact match; this set predicate is `category = ANY($n)`.
    pub categories: Vec<String>,
    /// Inequality match on `reason` — when `Some(v)`, rows whose
    /// `reason` equals `v` are EXCLUDED (SQL `reason IS DISTINCT FROM $n`, so a
    /// NULL reason is kept). The Decision Log sets this to `"pre_call"` to drop
    /// the fail-closed pre-dispatch evidence rows, which each pair with a later
    /// outcome row and would otherwise double-count a side-effecting call under
    /// `GATEWAY_AUDIT_MODE=fail_closed` (mirrors the top-tools aggregate's own
    /// `reason IS DISTINCT FROM 'pre_call'` exclusion).
    pub reason_ne: Option<String>,
}

impl AuditQuery {
    /// In-memory twin of the SQL `WHERE` built in
    /// [`AuditReader::query_events`]. The Postgres reader filters in the
    /// query; this lets non-Pg readers (the in-memory test fake) apply the
    /// exact same predicate, and keeps the SQL semantics documented in one
    /// place. Any change here must be mirrored in the SQL and vice versa.
    pub fn matches(&self, r: &AuditRow) -> bool {
        // Tenant scope first — it's the security boundary, not a filter.
        if let Some(t) = &self.tenant_id {
            if &r.tenant_id != t {
                return false;
            }
        }
        if let Some(v) = &self.server {
            if r.server.as_deref() != Some(v.as_str()) {
                return false;
            }
        }
        if let Some(v) = &self.outcome {
            if &r.outcome != v {
                return false;
            }
        }
        if let Some(v) = &self.outcome_ne {
            if &r.outcome == v {
                return false;
            }
        }
        if let Some(v) = &self.risk_level {
            if r.risk_level.as_deref() != Some(v.as_str()) {
                return false;
            }
        }
        if let Some(v) = &self.category {
            // NULL category counts as "invocation" (migration 0006).
            let row_category = r.category.as_deref().unwrap_or("invocation");
            if row_category != v.as_str() {
                return false;
            }
        }
        if let Some(needle) = &self.principal_substr {
            let hit = r
                .principal_sub
                .as_deref()
                .map(|s| s.contains(needle.as_str()))
                .unwrap_or(false)
                || r.principal_email
                    .as_deref()
                    .map(|s| s.contains(needle.as_str()))
                    .unwrap_or(false);
            if !hit {
                return false;
            }
        }
        if let Some(want) = self.pii {
            if r.pii != Some(want) {
                return false;
            }
        }
        if let Some(lb) = self.since {
            if r.ts < lb {
                return false;
            }
        }
        if let Some(ub) = self.until {
            if r.ts > ub {
                return false;
            }
        }
        if let Some(pid) = &self.policy_id {
            // Containment: the row's fired-policy set must include this id.
            if !r.policy_ids.iter().any(|p| p == pid) {
                return false;
            }
        }
        if !self.categories.is_empty() {
            // Membership against the decision-class set. NULL category counts
            // as "invocation" (migration 0006), the in-memory twin of the
            // SQL `category = ANY($n) OR (category IS NULL AND 'invocation' = ANY($n))`.
            let row_category = r.category.as_deref().unwrap_or("invocation");
            if !self.categories.iter().any(|c| c == row_category) {
                return false;
            }
        }
        if let Some(excluded) = &self.reason_ne {
            // In-memory twin of SQL `reason IS DISTINCT FROM $n`: drop rows whose
            // reason equals the excluded value; a NULL reason is kept.
            if r.reason.as_deref() == Some(excluded.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Per-dimension value→count for the activity facet rail, computed by
/// [`AuditReader::facet_counts`] as a table-wide aggregate within the
/// query's time window. Categorical filters do NOT narrow these counts —
/// the rail shows the full landscape (every server, every outcome, …) so an
/// operator can pivot; the row query ([`AuditReader::query_events`]) is what
/// applies every filter. Values are unsorted; the admin layer sorts them and
/// maps to facet links. `pii` values are the strings `"true"` / `"false"`.
#[derive(Debug, Clone, Default)]
pub struct AuditFacets {
    pub outcome: Vec<(String, i64)>,
    pub risk: Vec<(String, i64)>,
    pub category: Vec<(String, i64)>,
    pub pii: Vec<(String, i64)>,
    pub server: Vec<(String, i64)>,
}

/// Per-(server, tool) reliability aggregate for the activity "top tools"
/// view, computed by [`AuditReader::tool_stats`] over `query`'s scope
/// (tenant + time window + any active categorical filters; the caller clears
/// `outcome` so the failure/denial counts stay meaningful). Sorted by
/// `total` descending. This surfaces per-tool call volume, failure + denial
/// counts, and tail latency — the per-tool reliability signal that otherwise
/// lives only in Prometheus metrics (which aren't wired into every Grafana).
#[derive(Debug, Clone)]
pub struct ToolStat {
    pub server: String,
    pub tool: String,
    /// Total in-scope calls.
    pub total: i64,
    /// Calls whose outcome was `execution_error` (an upstream failure).
    pub errors: i64,
    /// Calls denied by policy (`outcome = 'denied'`).
    pub denied: i64,
    /// p95 of `latency_ms` over the in-scope calls (NULL latencies ignored);
    /// `None` when no in-scope call recorded a latency.
    pub p95_latency_ms: Option<f64>,
}

/// One (time-bucket, outcome) count for the activity volume histogram,
/// computed by [`AuditReader::histogram`]. `bucket_epoch` is the bucket's
/// start time as Unix seconds (each row's `ts` is floored to a
/// `bucket_seconds`-wide bucket). Stacked by `outcome`; the caller clears
/// the `outcome` filter so every band shows. Like the other aggregates it
/// excludes fail-closed `reason='pre_call'` intent rows and is tenant-scoped.
#[derive(Debug, Clone)]
pub struct HistogramBucket {
    pub bucket_epoch: i64,
    pub outcome: String,
    pub count: i64,
}

struct MarkerAdmissionRow {
    row: crate::chain_verify::ChainVerifyRow,
    expected_prev: Option<String>,
    indexed_start: Option<String>,
    indexed_end: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for MarkerAdmissionRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            row: <crate::chain_verify::ChainVerifyRow as sqlx::FromRow<_>>::from_row(row)?,
            expected_prev: row.try_get("expected_prev")?,
            indexed_start: row.try_get("indexed_start")?,
            indexed_end: row.try_get("indexed_end")?,
        })
    }
}

const REACHABLE_RETENTION_MARKERS_SQL: &str = r#"
    WITH RECURSIVE jobs(cursor_hash, target_hash) AS (
        SELECT seed.cursor_hash, seed.target_hash
          FROM unnest($2::TEXT[], $3::TEXT[])
               AS seed(cursor_hash, target_hash)
         WHERE seed.cursor_hash IS DISTINCT FROM seed.target_hash

        UNION

        SELECT spawned.cursor_hash, spawned.target_hash
          FROM jobs job
          CROSS JOIN LATERAL (
              SELECT indexed.marker_id, indexed.tenant_id,
                     indexed.end_hash
                FROM audit_retention_bridge_index indexed
               WHERE indexed.tenant_id = $1
                 AND indexed.start_key = CASE
                         WHEN job.cursor_hash IS NULL THEN 'null'
                         ELSE 'hash:' || job.cursor_hash
                     END
               LIMIT 1
          ) bridge
          JOIN audit_log marker
            ON marker.id = bridge.marker_id
           AND marker.tenant_id = bridge.tenant_id
           AND marker.category = 'retention_sweep'
           AND marker.row_hash IS NOT NULL
          LEFT JOIN LATERAL (
              SELECT prior.row_hash AS expected_prev
                FROM audit_log prior
               WHERE prior.tenant_id = marker.tenant_id
                 AND prior.row_hash IS NOT NULL
                 AND prior.chain_seq < marker.chain_seq
               ORDER BY prior.chain_seq DESC
               LIMIT 1
          ) predecessor ON TRUE
          CROSS JOIN LATERAL (
              VALUES
                  (bridge.end_hash, job.target_hash),
                  (predecessor.expected_prev, marker.prev_hash)
          ) AS spawned(cursor_hash, target_hash)
         WHERE spawned.cursor_hash IS DISTINCT FROM spawned.target_hash
    ),
    reachable_markers AS (
        SELECT DISTINCT bridge.marker_id,
               bridge.start_hash AS indexed_start,
               bridge.end_hash AS indexed_end
          FROM jobs job
          CROSS JOIN LATERAL (
              SELECT indexed.marker_id, indexed.start_hash,
                     indexed.end_hash
                FROM audit_retention_bridge_index indexed
               WHERE indexed.tenant_id = $1
                 AND indexed.start_key = CASE
                         WHEN job.cursor_hash IS NULL THEN 'null'
                         ELSE 'hash:' || job.cursor_hash
                     END
               LIMIT 1
          ) bridge
    )
    SELECT m.id, m.chain_seq, m.ts, m.category, m.tenant_id,
           m.action, m.outcome, m.principal_sub, m.principal_email,
           m.principal_groups, m.issuer, m.server, m.tool,
           m.risk_level, m.pii, m.policy_ids, m.reason, m.trace_id,
           m.latency_ms, m.prev_hash, m.row_hash, m.scim_active,
           m.scim_groups, m.target, m.req_scopes, m.auth_method,
           m.req_roles, m.side_effects, m.acting_agent,
           m.parent_execution_id, m.execution_step,
           m.execution_call_id, m.execution_attempt, m.operation,
           reachable.indexed_start, reachable.indexed_end,
           (
               SELECT prior.row_hash
                 FROM audit_log prior
                WHERE prior.tenant_id = m.tenant_id
                  AND prior.row_hash IS NOT NULL
                  AND prior.chain_seq < m.chain_seq
                ORDER BY prior.chain_seq DESC
                LIMIT 1
           ) AS expected_prev
      FROM reachable_markers reachable
      JOIN audit_log m
        ON m.id = reachable.marker_id
       AND m.tenant_id = $1
       AND m.category = 'retention_sweep'
       AND m.row_hash IS NOT NULL
     ORDER BY m.chain_seq ASC
    "#;

/// Read-side view of the audit table, kept separate from
/// `waygate_evidence::audit::EvidenceRecorder` so the admin API can be
/// constructed even when the write-side recorder is `NullSink` (no
/// database configured — reads just 404 in that case).
#[async_trait]
pub trait AuditReader: Send + Sync + 'static {
    /// Return up to `limit` events, most recent first. If `after_id` is
    /// provided, return only rows whose UUIDv7 id sorts strictly before it
    /// (cursor-style pagination; id ordering mirrors insertion order).
    async fn recent_events(
        &self,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error>;

    /// Filtered, keyset-paginated activity rows. Same ordering and cursor
    /// semantics as [`recent_events`](AuditReader::recent_events) (most
    /// recent first; `after_id` is a strict-before UUIDv7 cursor), but every
    /// predicate in `query` is applied in the query itself. This is what the
    /// admin Activity feed uses so a filter like `server=searxng` searches
    /// the whole table rather than only the most-recent page.
    async fn query_events(
        &self,
        query: &AuditQuery,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error>;

    /// Recent non-success events for one tenant, excluding `pre_call` rows.
    /// Apply the inclusive `since` bound and order by event timestamp descending,
    /// then ID descending for ties, before taking `limit` (clamped to 1..=500).
    /// This is separate from the activity browser's ID-based cursor contract.
    async fn recent_notable(
        &self,
        tenant: &str,
        since: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error>;

    /// Most-recent `limit` events of an exact `category`, scoped to `tenant`.
    ///
    /// Used by the Overview "what changed" feed (policy reloads, manifest
    /// activations, API-key lifecycle). The Postgres implementation uses
    /// `audit_log_tenant_category_id_desc_idx` to constrain both tenant and
    /// category and read directly in descending ID order, including when the
    /// category is rare or absent. It does not scan unrelated categories or
    /// sort the matching history to find the newest rows.
    ///
    /// The default body delegates to [`query_events`](AuditReader::query_events)
    /// so in-memory implementations stay correct without duplicating the filter;
    /// only the Postgres path overrides it for the sargable fast path.
    async fn recent_by_category(
        &self,
        tenant: &str,
        category: &str,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let query = AuditQuery {
            tenant_id: Some(tenant.to_owned()),
            category: Some(category.to_owned()),
            ..Default::default()
        };
        self.query_events(&query, limit, None).await
    }

    /// Per-dimension facet counts for the activity rail. Computed as a
    /// table-wide aggregate within `query`'s time window (`since`/`until`)
    /// only — the categorical predicates are intentionally NOT applied, so
    /// the rail always shows the full set of servers/outcomes/etc. an
    /// operator can pivot to (the row query does the narrowing). See
    /// [`AuditFacets`] for the rationale.
    async fn facet_counts(&self, query: &AuditQuery) -> Result<AuditFacets, sqlx::Error>;

    /// Per-(server, tool) reliability aggregate for the activity "top tools"
    /// view — call volume, execution-error + denial counts, and p95 latency,
    /// sorted by volume and capped at `limit` rows. Scoped by `query` (tenant
    /// + time window + categorical filters); the caller clears `outcome` so
    /// the failure counts remain meaningful. See [`ToolStat`].
    async fn tool_stats(
        &self,
        query: &AuditQuery,
        limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error>;

    /// Time-bucketed event counts (stacked by `outcome`) for the activity
    /// volume histogram. Each row's `ts` is floored to a `bucket_seconds`-wide
    /// bucket within `query`'s window; scoped + `pre_call`-excluded like
    /// [`tool_stats`](AuditReader::tool_stats). The caller bounds the window
    /// (`query.since`/`until`) and clears `outcome` so every band shows. See
    /// [`HistogramBucket`].
    async fn histogram(
        &self,
        query: &AuditQuery,
        bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error>;

    /// Tier-2 wide-window variants of [`histogram`](AuditReader::histogram),
    /// [`tool_stats`](AuditReader::tool_stats), and
    /// [`facet_counts`](AuditReader::facet_counts) backed by the
    /// `audit_rollup_hourly` pre-aggregate. The dashboard calls these for WIDE
    /// windows (7d/30d/all), where scanning raw `audit_log` is slow, and the
    /// live methods for narrow windows. The default bodies delegate to the live
    /// methods so non-Postgres readers (the in-memory fake) stay correct; only
    /// `PgAuditSink` overrides them to read the rollup. The Postgres overrides
    /// fall back to live when a `principal_substr` filter is set (the rollup
    /// carries no principal dimension). p95 latency is not in the rollup, so
    /// `rollup_tool_stats` returns `None` p95.
    async fn rollup_histogram(
        &self,
        query: &AuditQuery,
        bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error> {
        self.histogram(query, bucket_seconds).await
    }

    async fn rollup_tool_stats(
        &self,
        query: &AuditQuery,
        limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error> {
        self.tool_stats(query, limit).await
    }

    async fn rollup_facets(&self, query: &AuditQuery) -> Result<AuditFacets, sqlx::Error> {
        self.facet_counts(query).await
    }

    /// Fetch a single event by id. Used by the admin dashboard drawer to show
    /// the full detail for a clicked row without paging through `recent_events`.
    async fn fetch_event(&self, id: Uuid) -> Result<Option<AuditRow>, sqlx::Error>;

    /// Count events for a given `principal_sub` newer than `since`,
    /// optionally excluding events stamped with a specific issuer label.
    ///
    /// Used by the OAuth-clients dashboard panel to render a 7-day usage
    /// figure per session. The `exclude_issuer` parameter exists so the
    /// OAuth row's count isn't padded by activity from a separate
    /// authentication path that happens to share the same `sub` —
    /// concretely, an operator with both an OAuth login and an API key
    /// minted against the same subject. Pass the API-key validator's
    /// `issuer_label` (default `"api-key"`) to filter that activity out.
    /// `None` ⇒ count every event for the sub.
    ///
    /// Backed by the existing `audit_log_principal_ts_idx`
    /// (`principal_sub`, `ts DESC`); the `issuer` predicate is a cheap
    /// post-index filter.
    async fn count_events_by_sub_since(
        &self,
        sub: &str,
        since: OffsetDateTime,
        exclude_issuer: Option<&str>,
    ) -> Result<i64, sqlx::Error>;

    /// Walk a tenant's hash chain and verify
    /// both invariants (`row_hash` recomputes; `prev_hash`
    /// links). Returns a structured report rather than
    /// `Result::Err` for the mismatch case — a tamper
    /// detection is a *successful* query that returns an
    /// unhealthy report; the admin surface needs to render
    /// it, not 500.
    ///
    /// Windowing model:
    /// `from/to` filter by `ts` and `after_chain_seq` by
    /// `chain_seq`. Both ts filters are translated to a
    /// `chain_seq` range internally (via MIN/MAX over rows
    /// matching the ts predicate), because `ts` is
    /// caller-assigned and can be out-of-order with
    /// `chain_seq`. The actual walk SELECTs every
    /// chain-bearing row in
    /// `chain_seq ∈ [effective_start, effective_end]` —
    /// never with the ts predicate applied to the walk —
    /// otherwise a row whose ts falls outside the window
    /// but whose chain_seq sits between two in-window rows
    /// would be skipped, and the walker would see a fake
    /// `BrokenLink`.
    ///
    /// `after_chain_seq` is the strict-after pagination
    /// cursor: pass `next_after_chain_seq` from a prior
    /// `Incomplete` report to walk the next slice. The
    /// adapter SELECTs `WHERE chain_seq > $cursor`, so the
    /// row at the cursor is NOT re-walked — its result
    /// already arrived in the previous page. An earlier
    /// `>= cursor` predicate +
    /// "last walked" cursor reselected the same row and
    /// blocked pagination. Field-name symmetric with the
    /// returned `next_after_chain_seq` so cursor handoff
    /// is a copy.
    ///
    /// `limit` caps the number of rows walked. When the cap
    /// is hit, status is `Incomplete` (not `Ok`) and
    /// `next_after_chain_seq` is set to the last walked
    /// row's `chain_seq` so an operator can paginate. Status
    /// `Ok` means the walk completed without truncation.
    async fn verify_chain(
        &self,
        tenant_id: &str,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
        after_chain_seq: Option<i64>,
        limit: i64,
    ) -> Result<crate::chain_verify::ChainVerifyReport, sqlx::Error>;

    /// Fetch `audit_log` rows for a
    /// `(tenant, time_window)` slice plus optional
    /// `principal_sub` / `tool` filters, ordered by `ts` ASC
    /// then `chain_seq` ASC for stable bundle output.
    ///
    /// Returns `(rows, has_more)`. The implementation
    /// internally SELECTs `limit + 1` rows; on overflow,
    /// `rows` is truncated back to `limit` and `has_more`
    /// is `true`. The bundle endpoint MUST refuse rather than sign a
    /// partial slice. The v1 signature authenticates selected bytes but does
    /// not prove database completeness; refusing `has_more` prevents the
    /// server from knowingly omitting matching rows.
    ///
    /// Ordering rationale: bundles go to compliance auditors
    /// who reason about chronological evidence; chain_seq
    /// tiebreaker keeps same-ts events in insert order so
    /// auditors see the same row sequence every export call.
    async fn fetch_events_for_bundle(
        &self,
        tenant_id: &str,
        from: OffsetDateTime,
        to: OffsetDateTime,
        principal_sub: Option<&str>,
        tool: Option<&str>,
        limit: i64,
    ) -> Result<(Vec<AuditRow>, bool), sqlx::Error>;
}

const RECENT_BY_CATEGORY_SQL: &str = r#"
    SELECT id, ts, category, tenant_id, action, outcome,
           principal_sub, principal_email, principal_groups, issuer,
           server, tool, operation, risk_level, pii,
           policy_ids, reason, trace_id, latency_ms,
           scim_active, scim_groups, target,
           req_scopes, auth_method, req_roles, side_effects,
           parent_execution_id, execution_step,
           execution_call_id, execution_attempt
    FROM audit_log
    WHERE tenant_id = $1
      AND category = $2
    ORDER BY id DESC
    LIMIT $3
"#;

#[async_trait]
impl AuditReader for PgAuditSink {
    async fn recent_notable(
        &self,
        tenant: &str,
        since: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        notable_feed::read(&self.pool, tenant, since, limit).await
    }

    async fn recent_events(
        &self,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        // Clamp to a defensible ceiling so a pathological `?limit=` can't
        // pull the whole table into memory. The admin UI paginates so this
        // doesn't hurt legitimate use.
        let limit = limit.clamp(1, 500);

        let rows = match after_id {
            Some(cursor) => {
                sqlx::query_as::<_, AuditRow>(
                    r#"
                SELECT id, ts, category, tenant_id, action, outcome,
                       principal_sub, principal_email, principal_groups, issuer,
                       server, tool, operation, risk_level, pii,
                       policy_ids, reason, trace_id, latency_ms,
                       scim_active, scim_groups, target,
                       req_scopes, auth_method, req_roles, side_effects,
                       parent_execution_id, execution_step,
                       execution_call_id, execution_attempt
                FROM audit_log
                WHERE id < $1
                ORDER BY id DESC
                LIMIT $2
                "#,
                )
                .bind(cursor)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, AuditRow>(
                    r#"
                SELECT id, ts, category, tenant_id, action, outcome,
                       principal_sub, principal_email, principal_groups, issuer,
                       server, tool, operation, risk_level, pii,
                       policy_ids, reason, trace_id, latency_ms,
                       scim_active, scim_groups, target,
                       req_scopes, auth_method, req_roles, side_effects,
                       parent_execution_id, execution_step,
                       execution_call_id, execution_attempt
                FROM audit_log
                ORDER BY id DESC
                LIMIT $1
                "#,
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    async fn query_events(
        &self,
        query: &AuditQuery,
        limit: i64,
        after_id: Option<Uuid>,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let limit = limit.clamp(1, 500);
        // One static query using the `($N IS NULL OR <pred>)` idiom (same
        // house style as `verify_chain`'s ts filter): every filter is a
        // bound `Option`, so a `None` dimension drops out of the WHERE
        // without a dynamic query builder. `strpos(col, needle) > 0` is a
        // literal, case-sensitive substring test — the exact semantics of
        // the prior in-memory `str::contains`, with no LIKE-wildcard
        // surprises (a NULL `principal_*` makes that arm NULL → false).
        // `id < $9` keeps the keyset cursor composed with the filters so
        // each page is 50 *matching* rows.
        //
        // The category predicate is the *sargable* spelling of the old
        // `COALESCE(category, 'invocation') = $4`: wrapping the column in
        // COALESCE made it un-indexable, so a rare category full-scanned the
        // table. `category = $4 OR (category IS NULL AND $4 = 'invocation')`
        // is semantically identical (NULL counts as `invocation`) but lets the
        // planner use `audit_log_category_ts_idx`. `$12` is the optional
        // `outcome <> $12` predicate (non-success activity filter); served by the
        // partial `audit_log (tenant_id, id DESC) WHERE outcome <> 'success'`.
        sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT id, ts, category, tenant_id, action, outcome,
                   principal_sub, principal_email, principal_groups, issuer,
                   server, tool, operation, risk_level, pii,
                   policy_ids, reason, trace_id, latency_ms,
                   scim_active, scim_groups, target,
                   req_scopes, auth_method, req_roles, side_effects,
                   parent_execution_id, execution_step,
                   execution_call_id, execution_attempt
            FROM audit_log
            WHERE ($1::TEXT IS NULL OR server = $1)
              AND ($2::TEXT IS NULL OR outcome = $2)
              AND ($12::TEXT IS NULL OR outcome <> $12)
              AND ($3::TEXT IS NULL OR risk_level = $3)
              AND ($4::TEXT IS NULL
                   OR category = $4
                   OR (category IS NULL AND $4 = 'invocation'))
              AND ($5::TEXT IS NULL
                   OR strpos(principal_sub, $5) > 0
                   OR strpos(principal_email, $5) > 0)
              AND ($6::BOOLEAN IS NULL OR pii = $6)
              AND ($7::TIMESTAMPTZ IS NULL OR ts >= $7)
              AND ($8::TIMESTAMPTZ IS NULL OR ts <= $8)
              AND ($9::UUID IS NULL OR id < $9)
              AND ($11::TEXT IS NULL OR tenant_id = $11)
              AND ($13::TEXT IS NULL OR policy_ids @> ARRAY[$13])
              AND (cardinality($14::TEXT[]) = 0
                   OR category = ANY($14)
                   OR (category IS NULL AND 'invocation' = ANY($14)))
              AND ($15::TEXT IS NULL OR reason IS DISTINCT FROM $15)
            ORDER BY id DESC
            LIMIT $10
            "#,
        )
        .bind(query.server.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.risk_level.as_deref())
        .bind(query.category.as_deref())
        .bind(query.principal_substr.as_deref())
        .bind(query.pii)
        .bind(query.since)
        .bind(query.until)
        .bind(after_id)
        .bind(limit)
        .bind(query.tenant_id.as_deref())
        .bind(query.outcome_ne.as_deref())
        .bind(query.policy_id.as_deref())
        .bind(query.categories.as_slice())
        .bind(query.reason_ne.as_deref())
        .fetch_all(&self.pool)
        .await
    }

    async fn recent_by_category(
        &self,
        tenant: &str,
        category: &str,
        limit: i64,
    ) -> Result<Vec<AuditRow>, sqlx::Error> {
        let limit = limit.clamp(1, 500);
        // Keep both equality predicates and ID ordering aligned with
        // audit_log_tenant_category_id_desc_idx. The tenant-only ID index can
        // walk the entire tenant history for an absent category; the category
        // timestamp index requires a sort and does not constrain the tenant.
        sqlx::query_as::<_, AuditRow>(RECENT_BY_CATEGORY_SQL)
            // Categories are highly skewed. Reusing a prepared statement can
            // switch to a generic plan that walks the primary key even with
            // the matching index; plan this infrequent feed for its parameters.
            .persistent(false)
            .bind(tenant)
            .bind(category)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
    }

    async fn tool_stats(
        &self,
        query: &AuditQuery,
        limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        // Same `($N IS NULL OR …)` filter idiom + tenant scope as
        // `query_events`, minus the keyset cursor, grouped by (server, tool).
        // The caller clears `outcome` so the FILTER counts (errors/denied)
        // see every outcome. `percentile_cont` ignores NULL `latency_ms`,
        // so non-tool-call rows (no latency) don't skew the p95.
        let rows = sqlx::query_as::<_, (String, String, i64, i64, i64, Option<f64>)>(
            r#"
            SELECT server, tool,
                   count(*) AS total,
                   count(*) FILTER (WHERE outcome = 'execution_error') AS errors,
                   count(*) FILTER (WHERE outcome = 'denied') AS denied,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95
            FROM audit_log
            WHERE ($1::TEXT IS NULL OR server = $1)
              AND ($2::TEXT IS NULL OR outcome = $2)
              AND ($3::TEXT IS NULL OR risk_level = $3)
              AND ($4::TEXT IS NULL
                   OR category = $4
                   OR (category IS NULL AND $4 = 'invocation'))
              AND ($5::TEXT IS NULL
                   OR strpos(principal_sub, $5) > 0
                   OR strpos(principal_email, $5) > 0)
              AND ($6::BOOLEAN IS NULL OR pii = $6)
              AND ($7::TIMESTAMPTZ IS NULL OR ts >= $7)
              AND ($8::TIMESTAMPTZ IS NULL OR ts <= $8)
              AND ($9::TEXT IS NULL OR tenant_id = $9)
              -- Exclude fail-closed pre-dispatch intent rows
              -- (reason='pre_call'): each pairs with a later outcome row, so
              -- counting both would double-count volume and halve the error
              -- rate for side-effecting tools under GATEWAY_AUDIT_MODE=fail_closed.
              AND reason IS DISTINCT FROM 'pre_call'
              AND server IS NOT NULL
              AND tool IS NOT NULL
            GROUP BY server, tool
            ORDER BY total DESC, server, tool
            LIMIT $10
            "#,
        )
        .bind(query.server.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.risk_level.as_deref())
        .bind(query.category.as_deref())
        .bind(query.principal_substr.as_deref())
        .bind(query.pii)
        .bind(query.since)
        .bind(query.until)
        .bind(query.tenant_id.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(server, tool, total, errors, denied, p95_latency_ms)| ToolStat {
                    server,
                    tool,
                    total,
                    errors,
                    denied,
                    p95_latency_ms,
                },
            )
            .collect())
    }

    async fn histogram(
        &self,
        query: &AuditQuery,
        bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error> {
        let bucket_seconds = bucket_seconds.max(1) as f64;
        // Floor each row's epoch to a bucket start, grouped by (bucket,
        // outcome). Same `($N IS NULL OR …)` filter idiom + tenant scope +
        // pre_call exclusion as `tool_stats`; the caller clears `outcome` so
        // the bars stack across every outcome. `$10` is the bucket width.
        let rows = sqlx::query_as::<_, (i64, String, i64)>(
            r#"
            SELECT (floor(extract(epoch FROM ts) / $10) * $10)::BIGINT AS bucket_epoch,
                   outcome,
                   count(*) AS n
            FROM audit_log
            WHERE ($1::TEXT IS NULL OR server = $1)
              AND ($2::TEXT IS NULL OR outcome = $2)
              AND ($3::TEXT IS NULL OR risk_level = $3)
              AND ($4::TEXT IS NULL
                   OR category = $4
                   OR (category IS NULL AND $4 = 'invocation'))
              AND ($5::TEXT IS NULL
                   OR strpos(principal_sub, $5) > 0
                   OR strpos(principal_email, $5) > 0)
              AND ($6::BOOLEAN IS NULL OR pii = $6)
              AND ($7::TIMESTAMPTZ IS NULL OR ts >= $7)
              AND ($8::TIMESTAMPTZ IS NULL OR ts <= $8)
              AND ($9::TEXT IS NULL OR tenant_id = $9)
              AND reason IS DISTINCT FROM 'pre_call'
            GROUP BY bucket_epoch, outcome
            ORDER BY bucket_epoch, outcome
            "#,
        )
        .bind(query.server.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.risk_level.as_deref())
        .bind(query.category.as_deref())
        .bind(query.principal_substr.as_deref())
        .bind(query.pii)
        .bind(query.since)
        .bind(query.until)
        .bind(query.tenant_id.as_deref())
        .bind(bucket_seconds)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(bucket_epoch, outcome, count)| HistogramBucket {
                bucket_epoch,
                outcome,
                count,
            })
            .collect())
    }

    async fn rollup_histogram(
        &self,
        query: &AuditQuery,
        bucket_seconds: i64,
    ) -> Result<Vec<HistogramBucket>, sqlx::Error> {
        // The rollup carries no principal dimension — fall back to the live
        // reader when a principal substring filter is active.
        if query.principal_substr.is_some() {
            return self.histogram(query, bucket_seconds).await;
        }
        crate::rollup::rollup_histogram(
            &self.pool,
            query.tenant_id.as_deref(),
            query.since,
            query.until,
            query.server.as_deref(),
            query.risk_level.as_deref(),
            query.category.as_deref(),
            query.pii,
            bucket_seconds,
        )
        .await
    }

    async fn rollup_tool_stats(
        &self,
        query: &AuditQuery,
        limit: i64,
    ) -> Result<Vec<ToolStat>, sqlx::Error> {
        if query.principal_substr.is_some() {
            return self.tool_stats(query, limit).await;
        }
        crate::rollup::rollup_tool_stats(
            &self.pool,
            query.tenant_id.as_deref(),
            query.since,
            query.until,
            query.server.as_deref(),
            query.risk_level.as_deref(),
            query.category.as_deref(),
            query.pii,
            limit,
        )
        .await
    }

    async fn rollup_facets(&self, query: &AuditQuery) -> Result<AuditFacets, sqlx::Error> {
        // Facets never narrow by principal (table-wide aggregate in the window),
        // so this always reads the rollup.
        crate::rollup::rollup_facets(
            &self.pool,
            query.tenant_id.as_deref(),
            query.since,
            query.until,
        )
        .await
    }

    async fn facet_counts(&self, query: &AuditQuery) -> Result<AuditFacets, sqlx::Error> {
        // One scan, one round-trip. A MATERIALIZED CTE bounds the window once,
        // then five UNION ALL aggregates derive every facet dimension from that
        // single scan — replacing the previous five separate full-table scans
        // (and five round-trips). Each result row is (dim, value, count), which
        // we fan back into the per-dimension Vecs.
        //
        // `since`/`until`/`tenant` bind via the same `($N IS NULL OR …)` idiom
        // the row query uses. The tenant predicate is the SECURITY scope (the
        // rail must not count another tenant's rows); categorical filters
        // deliberately do NOT narrow the rail. NULL risk/server/pii carry no
        // chip (excluded); NULL category counts as 'invocation' (migration
        // 0006); `pii` maps to the "true"/"false" strings the UI uses.
        let rows = sqlx::query_as::<_, (String, String, i64)>(
            r#"
            WITH scoped AS MATERIALIZED (
                SELECT outcome, risk_level, category, server, pii
                FROM audit_log
                WHERE ($1::TIMESTAMPTZ IS NULL OR ts >= $1)
                  AND ($2::TIMESTAMPTZ IS NULL OR ts <= $2)
                  AND ($3::TEXT IS NULL OR tenant_id = $3)
                  -- Exclude fail-closed pre-dispatch intent rows, matching
                  -- histogram / tool_stats (and the rollup fold). Each pre_call
                  -- row pairs with a later real-outcome row, so counting it in
                  -- the facet rail double-counts volume; this also keeps the
                  -- live rail equal to the rollup-backed wide-window rail.
                  AND reason IS DISTINCT FROM 'pre_call'
            )
            SELECT 'outcome' AS dim, outcome AS val, count(*) AS n
              FROM scoped GROUP BY outcome
            UNION ALL
            SELECT 'risk', risk_level, count(*)
              FROM scoped WHERE risk_level IS NOT NULL GROUP BY risk_level
            UNION ALL
            SELECT 'category', COALESCE(category, 'invocation'), count(*)
              FROM scoped GROUP BY COALESCE(category, 'invocation')
            UNION ALL
            SELECT 'server', server, count(*)
              FROM scoped WHERE server IS NOT NULL GROUP BY server
            UNION ALL
            SELECT 'pii', CASE WHEN pii THEN 'true' ELSE 'false' END, count(*)
              FROM scoped WHERE pii IS NOT NULL GROUP BY pii
            "#,
        )
        .bind(query.since)
        .bind(query.until)
        .bind(query.tenant_id.as_deref())
        .fetch_all(&self.pool)
        .await?;

        let mut facets = AuditFacets::default();
        for (dim, val, n) in rows {
            match dim.as_str() {
                "outcome" => facets.outcome.push((val, n)),
                "risk" => facets.risk.push((val, n)),
                "category" => facets.category.push((val, n)),
                "server" => facets.server.push((val, n)),
                "pii" => facets.pii.push((val, n)),
                _ => {}
            }
        }
        Ok(facets)
    }

    async fn fetch_event(&self, id: Uuid) -> Result<Option<AuditRow>, sqlx::Error> {
        sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT id, ts, category, tenant_id, action, outcome,
                   principal_sub, principal_email, principal_groups, issuer,
                   server, tool, operation, risk_level, pii,
                   policy_ids, reason, trace_id, latency_ms,
                       scim_active, scim_groups, target,
                       req_scopes, auth_method, req_roles, side_effects,
                       parent_execution_id, execution_step,
                       execution_call_id, execution_attempt
            FROM audit_log
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    async fn count_events_by_sub_since(
        &self,
        sub: &str,
        since: OffsetDateTime,
        exclude_issuer: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        // Single SQL string with an optional issuer-exclude predicate.
        // The `$3 IS NULL` guard short-circuits to "no filter" when the
        // caller passes None, so a single prepared statement covers
        // both paths without forking the query plan.
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM audit_log
            WHERE principal_sub = $1
              AND ts >= $2
              AND ($3::TEXT IS NULL OR issuer IS DISTINCT FROM $3)
            "#,
        )
        .bind(sub)
        .bind(since)
        .bind(exclude_issuer)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn verify_chain(
        &self,
        tenant_id: &str,
        from: Option<OffsetDateTime>,
        to: Option<OffsetDateTime>,
        after_chain_seq: Option<i64>,
        limit: i64,
    ) -> Result<crate::chain_verify::ChainVerifyReport, sqlx::Error> {
        // Cap the walk size. `+ 1` is the "peek-one" trick —
        // we ask for one more than the cap so a full result
        // unambiguously means "more rows exist past the cap"
        // (truncated == true), without needing a separate
        // COUNT(*) query.
        let limit = limit.clamp(1, 10_000);
        let fetch_limit = limit + 1;

        // Snapshot consistency:
        // run every verifier SELECT inside one
        // REPEATABLE READ READ ONLY transaction. Without
        // this, each `pool` query gets its own READ
        // COMMITTED snapshot — a row that commits between
        // the walk SELECT and the chain_head SELECT could
        // appear in chain_head while status stays `Ok` /
        // `truncated == false` for only the earlier walked
        // rows, presenting a tail row as verified even
        // though it was never checked. With REPEATABLE
        // READ, all four SELECTs observe the same
        // pre-transaction snapshot, and the reported
        // chain_head is guaranteed to be part of the
        // snapshot the walk verified. READ ONLY is a
        // belt-and-suspenders signal that lets Postgres
        // skip xid allocation overhead for the no-write tx.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;

        // 1. chain_head lifted
        //    above the ts-window early-return so EVERY
        //    return path carries the operator's external
        //    checkpoint value. Computed against the same
        //    snapshot as the walk, so a regression in the
        //    reported (chain_seq, row_hash) pair between
        //    runs is a real signal: either new rows have
        //    been written since the last run (chain_seq
        //    advances; row_hash changes) or the tail has
        //    been mutated/deleted (chain_seq stays or
        //    decreases; row_hash changes). See KNOWN
        //    LIMITATIONS in `chain_verify.rs` for the
        //    tail-deletion threat model.
        let chain_head: Option<crate::chain_verify::ChainHead> =
            sqlx::query_as::<_, (Option<i64>, Option<String>)>(
                r#"
                SELECT chain_seq, row_hash
                  FROM audit_log
                 WHERE tenant_id = $1
                   AND row_hash IS NOT NULL
                 ORDER BY chain_seq DESC
                 LIMIT 1
                "#,
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?
            .and_then(|(seq, hash)| match (seq, hash) {
                (Some(s), Some(h)) => Some(crate::chain_verify::ChainHead {
                    chain_seq: s,
                    row_hash: h,
                }),
                _ => None,
            });

        // 2. Translate any
        //    `from`/`to` ts predicate into a chain_seq range.
        //    `ts` is caller-assigned and can be out-of-order
        //    with `chain_seq` (see migration 0015 round-1
        //    comment), so applying ts to the walk SELECT
        //    skips interior chain rows and produces fake
        //    BrokenLink reports. Instead we widen the
        //    request: "the window touches every chain row
        //    whose chain_seq sits between the smallest and
        //    largest chain_seq of any row matching the ts
        //    predicate." The walk SELECT then runs without
        //    the ts predicate, so adjacent chain links never
        //    span a skipped row.
        //
        //    Both forms collapse to NULL when no ts filter
        //    is supplied — the MIN/MAX query then doesn't
        //    constrain the walk.
        let ts_range: Option<(Option<i64>, Option<i64>)> = if from.is_some() || to.is_some() {
            Some(
                sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
                    r#"
                    SELECT MIN(chain_seq), MAX(chain_seq)
                      FROM audit_log
                     WHERE tenant_id = $1
                       AND row_hash IS NOT NULL
                       AND ($2::TIMESTAMPTZ IS NULL OR ts >= $2)
                       AND ($3::TIMESTAMPTZ IS NULL OR ts <= $3)
                    "#,
                )
                .bind(tenant_id)
                .bind(from)
                .bind(to)
                .fetch_one(&mut *tx)
                .await?,
            )
        } else {
            None
        };
        // `(None, None)` from MIN/MAX means "ts window
        // matched zero chain-bearing rows." We can stop
        // here without a walk SELECT — the pure walker's
        // empty branch will report `Empty`. Commit the
        // (read-only) tx to release the snapshot before
        // returning. chain_head was already fetched
        // against the same snapshot.
        let chain_seq_range: Option<(i64, i64)> = match ts_range {
            Some((Some(lo), Some(hi))) => Some((lo, hi)),
            Some((None, None)) => {
                tx.commit().await?;
                return Ok(crate::chain_verify::ChainVerifyReport {
                    tenant_id: tenant_id.to_owned(),
                    from,
                    to,
                    rows_walked: 0,
                    status: crate::chain_verify::ChainVerifyStatus::Empty,
                    first_mismatch: None,
                    truncated: false,
                    next_after_chain_seq: None,
                    chain_head,
                });
            }
            // MIN+MAX over a non-empty set always returns
            // both Some, so the half-Some shapes are
            // unreachable. Treat them defensively as empty.
            Some(_) | None => None,
        };

        // 3. Walk SELECT. Two `chain_seq` predicates:
        //
        //    - `after_chain_seq` is the STRICT-AFTER
        //      pagination cursor — predicate is
        //      `chain_seq > $cursor`, never `>=`: the
        //      prior `>= cursor`
        //      + "last walked" cursor reselected the same
        //      row, so pagination couldn't advance on
        //      chains longer than the cap. The `from` ts
        //      window's lower bound (when present) IS
        //      inclusive — it's a window bound, not a
        //      cursor — and is applied separately.
        //
        //    - The ts window's chain_seq range (when
        //      present from step 2) IS inclusive on both
        //      sides — it represents "the smallest and
        //      largest chain_seq in the ts window," and the
        //      walk needs both endpoints to include the
        //      chain links that connect them.
        //
        //    Never `WHERE ts IN window` here — that's the
        //    stale ts-window bug.
        let after_cursor = after_chain_seq;
        let lo: Option<i64> = chain_seq_range.map(|(l, _)| l);
        let hi: Option<i64> = chain_seq_range.map(|(_, h)| h);

        let rows = sqlx::query_as::<_, crate::chain_verify::ChainVerifyRow>(
            r#"
            SELECT id, chain_seq, ts, category, tenant_id, action, outcome,
                   principal_sub, principal_email, principal_groups, issuer,
                   server, tool, operation, risk_level, pii,
                   policy_ids, reason, trace_id, latency_ms,
                   prev_hash, row_hash,
                   scim_active, scim_groups, target,
                   req_scopes, auth_method, req_roles, side_effects,
                   acting_agent,
                   parent_execution_id, execution_step,
                   execution_call_id, execution_attempt,
                   operation
              FROM audit_log
             WHERE tenant_id = $1
               AND row_hash IS NOT NULL
               AND ($2::BIGINT IS NULL OR chain_seq > $2)
               AND ($3::BIGINT IS NULL OR chain_seq >= $3)
               AND ($4::BIGINT IS NULL OR chain_seq <= $4)
             ORDER BY chain_seq ASC
             LIMIT $5
            "#,
        )
        .bind(tenant_id)
        .bind(after_cursor)
        .bind(lo)
        .bind(hi)
        .bind(fetch_limit)
        .fetch_all(&mut *tx)
        .await?;

        // 4. Truncation: with the peek-one trick, length >
        //    limit means more rows exist past the cap. Drop
        //    the peeked row from the walked set so the walker
        //    only verifies what we hand it.
        let truncated = (rows.len() as i64) > limit;
        let walked_rows: Vec<crate::chain_verify::ChainVerifyRow> = if truncated {
            rows.into_iter().take(limit as usize).collect()
        } else {
            rows
        };
        let next_after_chain_seq = if truncated {
            walked_rows.last().map(|r| r.chain_seq)
        } else {
            None
        };

        // 5. Mid-chain `prev_head` lookup — unchanged from
        //    round 1. The first walked row's `prev_hash`
        //    invariant needs the prior row's `row_hash` when
        //    we're not starting at the tenant's genesis.
        //    Still in the same REPEATABLE READ snapshot as
        //    every other query above.
        let prev_head: Option<String> = if let Some(first) = walked_rows.first() {
            sqlx::query_scalar(
                r#"
                SELECT row_hash
                  FROM audit_log
                 WHERE tenant_id = $1
                   AND row_hash IS NOT NULL
                   AND chain_seq < $2
                 ORDER BY chain_seq DESC
                 LIMIT 1
                "#,
            )
            .bind(tenant_id)
            .bind(first.chain_seq)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            None
        };

        // Seed marker lookup only from broken links in this bounded row window.
        // The recursive query follows each gap toward its target and recursively
        // adds the marker-link proof jobs needed to authenticate every selected
        // marker. Unrelated permanent marker history is never read. Full marker
        // rows are streamed and discarded after hash, payload, and locator
        // checks; the final walker retains only compact boundary hashes.
        let gap_jobs =
            crate::chain_verify::verification_gap_jobs(prev_head.as_deref(), &walked_rows);
        let bridges = if gap_jobs.is_empty() {
            Vec::new()
        } else {
            let (gap_starts, gap_targets): (Vec<Option<String>>, Vec<Option<String>>) =
                gap_jobs.iter().cloned().unzip();
            let mut marker_rows =
                sqlx::query_as::<_, MarkerAdmissionRow>(REACHABLE_RETENTION_MARKERS_SQL)
                    .bind(tenant_id)
                    .bind(&gap_starts)
                    .bind(&gap_targets)
                    .fetch(&mut *tx);
            let mut candidates = Vec::new();
            while let Some(marker_row) = marker_rows.try_next().await? {
                #[cfg(test)]
                VERIFY_MARKER_ROWS_LOADED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let row = marker_row.row;
                if crate::chain_verify::recompute_row_hash(&row) != row.row_hash {
                    continue;
                }
                let Some(marker) = row
                    .reason
                    .as_deref()
                    .and_then(crate::chain_verify::RetentionMarker::from_reason)
                else {
                    continue;
                };
                let Some(bridge) = marker.bridge() else {
                    continue;
                };
                if bridge.start != marker_row.indexed_start || bridge.end != marker_row.indexed_end
                {
                    continue;
                }
                candidates.push(crate::chain_verify::RetentionBridgeCandidate {
                    bridge,
                    expected_prev: marker_row.expected_prev,
                    marker_prev: row.prev_hash,
                });
            }
            drop(marker_rows);
            tracing::info!(
                tenant_id,
                gap_count = gap_jobs.len(),
                reachable_marker_count = candidates.len(),
                "audit chain verification loaded reachable retention bridges",
            );
            crate::chain_verify::admit_retention_bridges(&candidates)
        };

        // Every verification SELECT used the same snapshot; release it.
        tx.commit().await?;

        let mut report = crate::chain_verify::verify_chain_rows_with_bridges(
            tenant_id,
            from,
            to,
            prev_head.as_deref(),
            &walked_rows,
            &bridges,
        );
        // Walker doesn't know about truncation or the head
        // checkpoint — those are storage-adapter concerns;
        // patch them in here.
        report.truncated = truncated;
        report.next_after_chain_seq = next_after_chain_seq;
        report.chain_head = chain_head;
        // If the walk was truncated AND every walked row
        // passed, status must NOT be `Ok` — a downstream
        // tamper could sit past the cap. Demote to
        // `Incomplete`. Mismatch status takes precedence
        // (we already found a problem; truncation is moot).
        if truncated && report.status == crate::chain_verify::ChainVerifyStatus::Ok {
            report.status = crate::chain_verify::ChainVerifyStatus::Incomplete;
        }
        Ok(report)
    }

    async fn fetch_events_for_bundle(
        &self,
        tenant_id: &str,
        from: OffsetDateTime,
        to: OffsetDateTime,
        principal_sub: Option<&str>,
        tool: Option<&str>,
        limit: i64,
    ) -> Result<(Vec<AuditRow>, bool), sqlx::Error> {
        // Clamp to a defensible ceiling. Bundle export is
        // an admin-initiated, time-bounded compliance fetch;
        // pulling more than 100k rows in one bundle is
        // almost certainly the operator wanting "everything"
        // instead of a focused export — surface the cap so
        // they narrow the window or paginate.
        let limit = limit.clamp(1, 100_000);
        // SELECT one MORE than
        // the caller asked for so the admin handler can
        // detect overflow and refuse rather than sign a
        // partial slice. The extra row is dropped before
        // return; `has_more` carries the overflow signal.
        let fetch_n = limit.saturating_add(1);
        let mut rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT id, ts, category, tenant_id, action, outcome,
                   principal_sub, principal_email, principal_groups, issuer,
                   server, tool, operation, risk_level, pii,
                   policy_ids, reason, trace_id, latency_ms,
                       scim_active, scim_groups, target,
                       req_scopes, auth_method, req_roles, side_effects,
                       parent_execution_id, execution_step,
                       execution_call_id, execution_attempt
              FROM audit_log
             WHERE tenant_id = $1
               AND ts >= $2
               AND ts <= $3
               AND ($4::TEXT IS NULL OR principal_sub = $4)
               AND ($5::TEXT IS NULL OR tool = $5)
             ORDER BY ts ASC, chain_seq ASC NULLS LAST
             LIMIT $6
            "#,
        )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .bind(principal_sub)
        .bind(tool)
        .bind(fetch_n)
        .fetch_all(&self.pool)
        .await?;
        let has_more = (rows.len() as i64) > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        Ok((rows, has_more))
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AuditRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            ts: row.try_get("ts")?,
            category: row.try_get("category")?,
            tenant_id: row.try_get("tenant_id")?,
            action: row.try_get("action")?,
            outcome: row.try_get("outcome")?,
            principal_sub: row.try_get("principal_sub")?,
            principal_email: row.try_get("principal_email")?,
            principal_groups: row.try_get("principal_groups")?,
            issuer: row.try_get("issuer")?,
            server: row.try_get("server")?,
            tool: row.try_get("tool")?,
            operation: row.try_get("operation").ok().flatten(),
            risk_level: row.try_get("risk_level")?,
            pii: row.try_get("pii")?,
            policy_ids: row.try_get("policy_ids")?,
            reason: row.try_get("reason")?,
            trace_id: row.try_get("trace_id")?,
            latency_ms: row.try_get("latency_ms")?,
            // Nullable columns; legacy
            // rows decode to None / empty.
            scim_active: row.try_get("scim_active").ok().flatten(),
            scim_groups: row
                .try_get::<Option<Vec<String>>, _>("scim_groups")
                .ok()
                .flatten()
                .unwrap_or_default(),
            // Migration 0046: nullable; legacy rows decode to None.
            target: row.try_get("target").ok().flatten(),
            // Migration 0062: nullable decision-input
            // columns; legacy rows decode to None / empty.
            req_scopes: row
                .try_get::<Option<Vec<String>>, _>("req_scopes")
                .ok()
                .flatten()
                .unwrap_or_default(),
            auth_method: row.try_get("auth_method").ok().flatten(),
            req_roles: row
                .try_get::<Option<Vec<String>>, _>("req_roles")
                .ok()
                .flatten()
                .unwrap_or_default(),
            side_effects: row.try_get("side_effects").ok().flatten(),
            invocation_hierarchy: invocation_hierarchy_from_row(row)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_bridge_index_plan_nodes(
        value: &serde_json::Value,
        nodes: &mut Vec<(String, Option<String>)>,
    ) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_bridge_index_plan_nodes(value, nodes);
                }
            }
            serde_json::Value::Object(fields) => {
                if fields
                    .get("Relation Name")
                    .and_then(serde_json::Value::as_str)
                    == Some("audit_retention_bridge_index")
                {
                    nodes.push((
                        fields
                            .get("Node Type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("missing node type")
                            .to_owned(),
                        fields
                            .get("Index Name")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned),
                    ));
                }
                for value in fields.values() {
                    collect_bridge_index_plan_nodes(value, nodes);
                }
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn chain_verification_does_not_load_unreachable_marker_history() {
        let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
            return;
        };
        let sink = PgAuditSink::with_pool(pool.clone());
        let tenant_id = format!("verify-marker-scope-{}", Uuid::now_v7());
        let tenant = waygate_core::TenantId::parse(tenant_id.clone()).expect("tenant id valid");
        let base_ts = OffsetDateTime::from_unix_timestamp(1_700_200_000).unwrap();

        for index in 0..2 {
            let mut event = AuditEvent::new(
                format!("marker-scope-{index}"),
                waygate_evidence::audit::AuditOutcome::Success,
            )
            .with_category(waygate_evidence::audit::EvidenceCategory::Invocation)
            .with_tenant(tenant.clone());
            event.ts = base_ts + time::Duration::seconds(index);
            sink.record_required(event)
                .await
                .expect("seed chained verification row");
        }
        crate::run_retention_sweep(
            &pool,
            &tenant_id,
            "invocation",
            base_ts + time::Duration::seconds(1),
        )
        .await
        .expect("create one reachable retention bridge");

        let unrelated_count: i64 = sqlx::query_scalar(
            r#"
            WITH inserted AS (
                INSERT INTO audit_log (
                    id, ts, category, tenant_id, action, outcome, reason, row_hash
                )
                SELECT md5($1 || '-unrelated-marker-' || n::TEXT)::UUID,
                       to_timestamp(4102444800) + n * interval '1 microsecond',
                       'retention_sweep', $1, 'retention.sweep', 'success',
                       jsonb_build_object(
                           'kind', 'retention_sweep',
                           'deleted_rows', jsonb_build_array(jsonb_build_object(
                               'prev_hash', 'unrelated-start-' || n::TEXT,
                               'row_hash', 'unrelated-end-' || n::TEXT
                           ))
                       )::TEXT,
                       md5($1 || '-unrelated-row-hash-' || n::TEXT)
                  FROM generate_series(1, 1000) AS n
                RETURNING id
            )
            SELECT COUNT(*)
              FROM inserted
              CROSS JOIN LATERAL audit_retention_bridge_index_marker(inserted.id)
            "#,
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("seed indexed but unreachable marker history");
        assert_eq!(unrelated_count, 1_000);

        let gap_target: Option<String> = sqlx::query_scalar(
            r#"
            SELECT prev_hash
              FROM audit_log
             WHERE tenant_id = $1
               AND category = 'invocation'
             ORDER BY chain_seq ASC
             LIMIT 1
            "#,
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("load the retained row's gap target");
        // The only dynamic SQL component is the compile-time production query;
        // all tenant and hash values remain bind parameters.
        let explain_sql = format!("EXPLAIN (FORMAT JSON) {REACHABLE_RETENTION_MARKERS_SQL}");
        let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(explain_sql))
            .bind(&tenant_id)
            .bind(vec![None::<String>])
            .bind(vec![gap_target])
            .fetch_one(&pool)
            .await
            .expect("explain the production marker lookup");
        let mut bridge_plan_nodes = Vec::new();
        collect_bridge_index_plan_nodes(&plan, &mut bridge_plan_nodes);
        assert!(
            !bridge_plan_nodes.is_empty(),
            "the production plan must access the retention bridge index",
        );
        assert!(
            bridge_plan_nodes.iter().all(|(node_type, index_name)|
                (node_type == "Index Scan" || node_type == "Index Only Scan")
                    && index_name.as_deref() == Some("audit_retention_bridge_start_idx")),
            "each bridge frontier lookup must use the tenant-and-start-key index: {bridge_plan_nodes:?}",
        );

        VERIFY_MARKER_ROWS_LOADED.store(0, std::sync::atomic::Ordering::Relaxed);
        let report = sink
            .verify_chain(
                &tenant_id,
                None,
                Some(base_ts + time::Duration::seconds(2)),
                None,
                100,
            )
            .await
            .expect("verify through the reachable retention bridge");
        assert_eq!(report.status, crate::ChainVerifyStatus::Ok);
        assert_eq!(
            VERIFY_MARKER_ROWS_LOADED.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the recursive lookup must not load unrelated permanent markers",
        );
    }

    #[test]
    fn chained_best_effort_commit_uncertainty_is_not_classified_as_dropped() {
        let before_commit = ChainedWriteError::deadline(
            ChainedWriteStage::AuditInsert,
            ChainedWriteFailureOutcome::Dropped,
        );
        assert_eq!(
            before_commit.terminal_outcome,
            ChainedWriteFailureOutcome::Dropped
        );
        assert_eq!(before_commit.terminal_outcome.as_str(), "dropped");
        assert_eq!(before_commit.stage, ChainedWriteStage::AuditInsert);

        let commit = ChainedWriteError::deadline(
            ChainedWriteStage::TxCommit,
            ChainedWriteFailureOutcome::Unknown,
        );
        assert_eq!(commit.terminal_outcome, ChainedWriteFailureOutcome::Unknown);
        assert_eq!(commit.terminal_outcome.as_str(), "unknown");
        assert_eq!(commit.stage, ChainedWriteStage::TxCommit);
    }

    #[test]
    fn chained_write_modes_keep_reliability_and_export_axes_independent() {
        assert!(!ChainedWriteMode::RequiredExport.is_best_effort());
        assert!(ChainedWriteMode::RequiredExport.enqueues_outbox());

        assert!(ChainedWriteMode::BestEffortLocal.is_best_effort());
        assert!(!ChainedWriteMode::BestEffortLocal.enqueues_outbox());

        assert!(ChainedWriteMode::BestEffortExport.is_best_effort());
        assert!(ChainedWriteMode::BestEffortExport.enqueues_outbox());
    }

    #[test]
    fn chained_write_stage_labels_are_stable_and_complete() {
        let cases = [
            (ChainedWriteStage::TxBegin, "tx_begin"),
            (ChainedWriteStage::ChainLock, "chain_lock"),
            (ChainedWriteStage::ChainLockRollback, "chain_lock_rollback"),
            (
                ChainedWriteStage::ChainLockContended,
                "chain_lock_contended",
            ),
            (ChainedWriteStage::ChainSelectPrev, "chain_select_prev"),
            (ChainedWriteStage::AuditInsert, "audit_insert"),
            (ChainedWriteStage::RoutingLookup, "routing_lookup"),
            (ChainedWriteStage::PayloadSerialize, "payload_serialize"),
            (ChainedWriteStage::OutboxEnqueue, "outbox_enqueue"),
            (ChainedWriteStage::TxCommit, "tx_commit"),
        ];

        for (stage, expected) in cases {
            assert_eq!(stage.as_str(), expected);
        }
    }

    #[tokio::test]
    async fn precommit_deadline_reports_confirmed_drop_at_active_stage() {
        let deadline =
            ChainedWriteDeadline(Some(tokio::time::Instant::now() + Duration::from_millis(1)));
        let error = deadline
            .run(
                ChainedWriteStage::ChainSelectPrev,
                ChainedWriteFailureOutcome::Dropped,
                std::future::pending::<Result<(), &'static str>>(),
            )
            .await
            .expect_err("the stage must stop at the write deadline");

        assert_eq!(error.stage, ChainedWriteStage::ChainSelectPrev);
        assert_eq!(error.terminal_outcome, ChainedWriteFailureOutcome::Dropped);
    }

    #[test]
    fn chained_failure_logging_is_immediate_periodic_and_reports_recovery() {
        let mut state = ChainedFailureLogState::default();
        let started = Instant::now();
        assert_eq!(
            state.on_failure(started),
            ChainedFailureLogDecision::Emit {
                suppressed_since_last: 0
            }
        );
        assert_eq!(
            state.on_failure(started + Duration::from_secs(1)),
            ChainedFailureLogDecision::Suppress
        );
        assert_eq!(
            state.on_failure(started + CHAINED_FAILURE_LOG_INTERVAL),
            ChainedFailureLogDecision::Emit {
                suppressed_since_last: 1
            }
        );

        assert!(
            state
                .on_success(started + Duration::from_secs(12))
                .is_none(),
            "an interleaved success must not reset an ongoing failure episode",
        );
        let recovery = state
            .on_success(started + Duration::from_secs(20))
            .expect("ten failure-free seconds must produce one recovery summary");
        assert_eq!(recovery.duration, Duration::from_secs(20));
        assert_eq!(recovery.suppressed_since_last, 0);
        assert!(
            state
                .on_success(started + Duration::from_secs(21))
                .is_none(),
            "recovery must reset the failure episode",
        );
    }

    fn row(outcome: &str) -> AuditRow {
        AuditRow {
            operation: None,
            id: Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            category: Some("invocation".to_owned()),
            tenant_id: "default".to_owned(),
            action: "CallTool".to_owned(),
            outcome: outcome.to_owned(),
            principal_sub: None,
            principal_email: None,
            principal_groups: Vec::new(),
            issuer: None,
            server: Some("srv".to_owned()),
            tool: Some("t".to_owned()),
            risk_level: None,
            pii: None,
            policy_ids: Vec::new(),
            reason: None,
            trace_id: None,
            latency_ms: None,
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            invocation_hierarchy: None,
        }
    }

    #[test]
    fn outcome_ne_excludes_only_the_named_outcome() {
        // Setting `outcome_ne = "success"` keeps every non-success row and
        // drops success rows — the in-memory
        // twin of the SQL `outcome <> $` predicate.
        let q = AuditQuery {
            outcome_ne: Some("success".to_owned()),
            ..Default::default()
        };
        assert!(!q.matches(&row("success")), "success row excluded");
        assert!(q.matches(&row("denied")), "denied row kept");
        assert!(q.matches(&row("execution_error")), "error row kept");
        assert!(q.matches(&row("step_up_required")), "step-up row kept");
    }

    #[test]
    fn outcome_ne_unset_is_a_noop() {
        let q = AuditQuery::default();
        assert!(q.matches(&row("success")));
        assert!(q.matches(&row("denied")));
    }

    #[test]
    fn category_null_counts_as_invocation_in_matches() {
        // Mirrors the sargable SQL
        // `(category = $ OR (category IS NULL AND $ = 'invocation'))`: a
        // NULL-category row matches an "invocation" filter, and only that.
        let q = AuditQuery {
            category: Some("invocation".to_owned()),
            ..Default::default()
        };
        let mut r = row("success");
        r.category = None;
        assert!(
            q.matches(&r),
            "NULL category matches an 'invocation' filter"
        );
        r.category = Some("manifest_reload".to_owned());
        assert!(!q.matches(&r), "a different category does not match");
    }

    #[test]
    fn matches_filters_by_policy_id() {
        // The "decisions that matched this policy" reverse lookup
        // is a containment test on the row's fired-policy set.
        let q = AuditQuery {
            policy_id: Some("step-up-delete-dataset".to_owned()),
            ..Default::default()
        };
        let mut r = row("denied");
        r.policy_ids = vec![
            "baseline-readonly-tools".to_owned(),
            "step-up-delete-dataset".to_owned(),
        ];
        assert!(
            q.matches(&r),
            "row whose policy_ids contains the id matches"
        );
        r.policy_ids = vec!["baseline-readonly-tools".to_owned()];
        assert!(!q.matches(&r), "row missing the id does not match");
        // No policy_id filter ⇒ any row (even one with no fired policies) matches.
        r.policy_ids = vec![];
        assert!(AuditQuery::default().matches(&r));
    }

    #[test]
    fn matches_filters_by_categories() {
        // The Decision Log filters by a SET of decision
        // classes (invocation + llm_completion), excluding non-decision
        // categories, with a NULL category counting as invocation (0006).
        let q = AuditQuery {
            categories: vec!["invocation".to_owned(), "llm_completion".to_owned()],
            ..Default::default()
        };
        let mut r = row("success");
        r.category = Some("invocation".to_owned());
        assert!(q.matches(&r), "a tool-call decision is in the set");
        r.category = Some("llm_completion".to_owned());
        assert!(q.matches(&r), "a model decision is in the set");
        r.category = Some("admin_mutation".to_owned());
        assert!(!q.matches(&r), "a non-decision category is excluded");
        r.category = None;
        assert!(
            q.matches(&r),
            "NULL category counts as invocation → in the set"
        );
        // Empty set ⇒ no constraint: any category matches.
        r.category = Some("oauth_event".to_owned());
        assert!(
            AuditQuery::default().matches(&r),
            "an empty category set imposes no constraint"
        );
    }

    #[test]
    fn matches_excludes_reason_ne() {
        // The Decision Log drops paired `pre_call` evidence
        // rows via `reason_ne`. A row whose reason equals the excluded value is
        // filtered; a NULL reason (and any other reason) is kept.
        let q = AuditQuery {
            reason_ne: Some("pre_call".to_owned()),
            ..Default::default()
        };
        let mut r = row("success");
        r.reason = Some("pre_call".to_owned());
        assert!(!q.matches(&r), "a pre_call row is excluded");
        r.reason = Some("policy denied".to_owned());
        assert!(q.matches(&r), "a different reason is kept");
        r.reason = None;
        assert!(q.matches(&r), "a NULL reason is kept (IS DISTINCT FROM)");
    }
}
