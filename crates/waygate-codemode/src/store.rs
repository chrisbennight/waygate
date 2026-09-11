use std::time::Duration;

use serde_json::Value;
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use waygate_core::store::StoreError;

use time::OffsetDateTime;

use crate::{
    DetachedExecutionSlot, Execution, ExecutionArtifact, ExecutionArtifactContent, ExecutionClaim,
    ExecutionEvent, ExecutionStatus, ExecutionStore, ExecutionTransition, InFlightExecution,
    NewExecution, NewExecutionEvent, OperatorInFlightExecution, OwnedInFlight, ResumeExecution,
    RetainedSource, RetryEquivalence, SourceArtifactOwner, SourceArtifactStore, StartExecution,
    StartExecutionResult, MAX_RETAINED_SOURCES_PER_OWNER, MAX_RETAINED_SOURCES_PER_TENANT,
    MAX_RETAINED_SOURCE_BYTES_PER_OWNER, MAX_RETAINED_SOURCE_BYTES_PER_TENANT,
    MAX_SOURCE_LOCATORS_PER_OWNER, MAX_SOURCE_LOCATORS_PER_TENANT,
};

const RETENTION_SWEEP_BATCH_SIZE: i64 = 100;

macro_rules! execution_query {
    ($before:literal, $after:literal) => {
        sqlx::query(concat!(
            $before,
            " id, tenant_id, principal_sub, principal_issuer, source, source_digest,
              program_input, execution_profile,
              tool_snapshot, sdk_contract_version, runner_contract_version, status,
              terminal_reason_code, result_metadata, result_payload, resume_context,
              claim_owner, claim_epoch, claim_expires_at, cancellation_requested_at,
              cancellation_reason_code,
              submitted_at, updated_at, completed_at, retention_until ",
            $after
        ))
    };
}

#[derive(Clone)]
pub struct PgExecutionStore {
    pool: PgPool,
    source_limits: SourceRetentionLimits,
}

/// Live retained-source budgets enforced inside the admission transaction.
#[derive(Clone, Copy)]
pub struct SourceRetentionLimits {
    pub owner_bytes: i64,
    pub tenant_bytes: i64,
    pub owner_count: i64,
    pub tenant_count: i64,
}

impl Default for SourceRetentionLimits {
    fn default() -> Self {
        Self {
            owner_bytes: MAX_RETAINED_SOURCE_BYTES_PER_OWNER,
            tenant_bytes: MAX_RETAINED_SOURCE_BYTES_PER_TENANT,
            owner_count: MAX_RETAINED_SOURCES_PER_OWNER,
            tenant_count: MAX_RETAINED_SOURCES_PER_TENANT,
        }
    }
}

impl PgExecutionStore {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            source_limits: SourceRetentionLimits::default(),
        }
    }

    /// Install validated operator quotas without weakening transactional admission.
    pub fn with_source_limits(
        mut self,
        limits: SourceRetentionLimits,
    ) -> Result<Self, &'static str> {
        if limits.owner_bytes <= 0
            || limits.tenant_bytes < limits.owner_bytes
            || limits.owner_count <= 0
            || limits.tenant_count < limits.owner_count
        {
            return Err("invalid retained source quotas");
        }
        self.source_limits = limits;
        Ok(self)
    }

    /// The one cancellation transaction, shared by the owner and operator
    /// scopes: their semantics are identical apart from the row predicate,
    /// the recorded reason, and the request event's provenance detail. An
    /// unclaimed or dead-claim row terminalizes immediately; a live claim
    /// keeps its lease and the runner observes the request at its next
    /// journal boundary.
    async fn cancel_scoped(
        &self,
        tenant_id: &str,
        id: Uuid,
        owner: Option<(&str, &str)>,
        reason_code: &'static str,
        request_detail: Value,
    ) -> Result<Option<Execution>, StoreError> {
        let (owner_sub, owner_issuer) = match owner {
            Some((sub, issuer)) => (Some(sub), Some(issuer)),
            None => (None, None),
        };
        let mut tx = self.pool.begin().await?;
        let row = execution_query!(
            r#"
            SELECT
            "#,
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1
               AND id = $2
               -- Owner scope binds the exact subject AND issuer, so a
               -- pre-upgrade NULL-issuer row matches nothing (fail
               -- closed). Operator scope binds neither: tenant authority
               -- covers every principal's rows, legacy included.
               AND ($3::text IS NULL OR principal_sub = $3)
               AND ($4::text IS NULL OR principal_issuer = $4)
             FOR UPDATE
            "#
        )
        .bind(tenant_id)
        .bind(id)
        .bind(owner_sub)
        .bind(owner_issuer)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let execution = row_to_execution(&row);
        if execution.status.is_terminal() {
            tx.commit().await?;
            return Ok(Some(execution));
        }

        let request_already_recorded = execution.cancellation_requested_at.is_some();
        // The owner predicate is not repeated here: the SELECT above
        // verified it and holds the row lock, so tenant + id identify the
        // same row for the rest of the transaction.
        // `cancellation_reason_code` is durable provenance for a later
        // finalization: a live claim terminalizes at the runner's next
        // journal boundary, after the requester has left the call path.
        // Attribution belongs to the FIRST request, so provenance is written
        // only alongside a fresh `cancellation_requested_at` — a repeat
        // request on a row whose original request predates the provenance
        // column must not steal its cause, and such rows keep the
        // historical client attribution when they terminalize here.
        let updated = execution_query!(
            r#"
            UPDATE codemode_executions
               SET cancellation_reason_code = CASE
                       WHEN cancellation_requested_at IS NULL THEN $3::text
                       ELSE cancellation_reason_code
                   END,
                   cancellation_requested_at = COALESCE(cancellation_requested_at, now()),
                   status = CASE
                       WHEN claim_owner IS NULL OR claim_expires_at <= now()
                       THEN 'cancelled'
                       ELSE status
                   END,
                   terminal_reason_code = CASE
                       WHEN claim_owner IS NULL OR claim_expires_at <= now()
                       THEN COALESCE(
                           cancellation_reason_code,
                           CASE
                               WHEN cancellation_requested_at IS NULL THEN $3::text
                               ELSE 'cancelled_by_client'
                           END
                       )
                       ELSE terminal_reason_code
                   END,
                   completed_at = CASE
                       WHEN claim_owner IS NULL OR claim_expires_at <= now()
                       THEN now()
                       ELSE completed_at
                   END,
                   claim_owner = CASE
                       WHEN claim_owner IS NULL OR claim_expires_at <= now()
                       THEN NULL
                       ELSE claim_owner
                   END,
                   claim_expires_at = CASE
                       WHEN claim_owner IS NULL OR claim_expires_at <= now()
                       THEN NULL
                       ELSE claim_expires_at
                   END
             WHERE tenant_id = $1
               AND id = $2
               AND completed_at IS NULL
            RETURNING
            "#,
            ", status = 'cancelled' AS finished_now"
        )
        .bind(tenant_id)
        .bind(id)
        .bind(reason_code)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(updated) = updated else {
            tx.rollback().await?;
            return Ok(None);
        };
        if !request_already_recorded {
            insert_event(
                &mut tx,
                id,
                tenant_id,
                &NewExecutionEvent {
                    kind: crate::ExecutionEventKind::CancellationRequested,
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail: request_detail,
                },
            )
            .await?;
        }
        let execution = row_to_execution(&updated);
        if updated.get::<bool, _>("finished_now") {
            // The effective reason is the row's, not this call's: an
            // earlier requester's provenance wins the attribution.
            insert_event(
                &mut tx,
                id,
                tenant_id,
                &NewExecutionEvent {
                    kind: crate::ExecutionEventKind::Cancelled,
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail: serde_json::json!({
                        "reason_code": execution
                            .terminal_reason_code
                            .as_deref()
                            .unwrap_or(reason_code),
                    }),
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(execution))
    }
}

#[async_trait::async_trait]
impl SourceArtifactStore for PgExecutionStore {
    async fn retain_source(
        &self,
        owner: &SourceArtifactOwner,
        source: &str,
        source_digest: &str,
        retention: Duration,
    ) -> Result<RetainedSource, StoreError> {
        let mut tx = self.pool.begin().await?;
        // Serialize retained-source accounting per tenant across replicas.
        // The owner budget is a subset of this same lock, so both projections
        // remain exact without a wider table lock.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(\
             hashtextextended('codemode-source-artifacts' || chr(31) || $1, 0))",
        )
        .bind(&owner.tenant_id)
        .execute(&mut *tx)
        .await?;
        purge_expired_state(&mut tx).await?;
        let tenant_usage = sqlx::query(
            r#"
            SELECT count(*)::bigint AS artifact_count,
                   COALESCE(sum(octet_length(source)), 0)::bigint AS byte_count
              FROM codemode_source_artifacts
             WHERE tenant_id = $1
               AND expires_at > now()
               AND NOT (
                   principal_sub = $2
                   AND principal_issuer = $3
                   AND source_digest = $4
               )
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_digest)
        .fetch_one(&mut *tx)
        .await?;
        let owner_usage = sqlx::query(
            r#"
            SELECT count(*)::bigint AS artifact_count,
                   COALESCE(sum(octet_length(source)), 0)::bigint AS byte_count
              FROM codemode_source_artifacts
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND expires_at > now()
               AND source_digest <> $4
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_digest)
        .fetch_one(&mut *tx)
        .await?;
        let source_bytes = i64::try_from(source.len()).unwrap_or(i64::MAX);
        let tenant_count: i64 = tenant_usage.get("artifact_count");
        let tenant_bytes: i64 = tenant_usage.get("byte_count");
        let owner_count: i64 = owner_usage.get("artifact_count");
        let owner_bytes: i64 = owner_usage.get("byte_count");
        if tenant_count.saturating_add(1) > self.source_limits.tenant_count
            || tenant_bytes.saturating_add(source_bytes) > self.source_limits.tenant_bytes
            || owner_count.saturating_add(1) > self.source_limits.owner_count
            || owner_bytes.saturating_add(source_bytes) > self.source_limits.owner_bytes
        {
            return Err(StoreError::Conflict);
        }
        let row = sqlx::query(
            r#"
            INSERT INTO codemode_source_artifacts (
                tenant_id, principal_sub, principal_issuer,
                source_digest, source, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, now() + ($6 * interval '1 second'))
            ON CONFLICT (tenant_id, principal_issuer, principal_sub, source_digest)
            DO UPDATE
               SET expires_at = GREATEST(
                       codemode_source_artifacts.expires_at,
                       EXCLUDED.expires_at
                   )
            RETURNING source, source_digest, expires_at
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_digest)
        .bind(source)
        .bind(lease_seconds(retention))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row_to_retained_source(&row))
    }

    async fn resolve_source(
        &self,
        owner: &SourceArtifactOwner,
        source_digest: &str,
    ) -> Result<Option<RetainedSource>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT source, source_digest, expires_at
              FROM codemode_source_artifacts
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND source_digest = $4
               AND expires_at > now()
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_retained_source))
    }

    async fn resolve_source_expiry(
        &self,
        owner: &SourceArtifactOwner,
        source_digest: &str,
    ) -> Result<Option<OffsetDateTime>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT expires_at
              FROM codemode_source_artifacts
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND source_digest = $4
               AND expires_at > now()
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| row.get("expires_at")))
    }
}

#[async_trait::async_trait]
impl ExecutionStore for PgExecutionStore {
    async fn acquire_detached_slot(
        &self,
        slot: &DetachedExecutionSlot,
        lease: Duration,
    ) -> Result<bool, StoreError> {
        let holder = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO codemode_detached_principal_slots (
                tenant_id, principal_sub, principal_issuer, holder, lease_expires_at
            )
            VALUES ($1, $2, $3, $4, now() + ($5 * interval '1 second'))
            ON CONFLICT (tenant_id, principal_issuer, principal_sub) DO UPDATE
               SET holder = EXCLUDED.holder,
                   lease_expires_at = EXCLUDED.lease_expires_at
             WHERE codemode_detached_principal_slots.lease_expires_at <= now()
                OR codemode_detached_principal_slots.holder = EXCLUDED.holder
            RETURNING holder
            "#,
        )
        .bind(&slot.tenant_id)
        .bind(&slot.principal_sub)
        .bind(&slot.principal_issuer)
        .bind(slot.holder)
        .bind(lease_seconds(lease))
        .fetch_optional(&self.pool)
        .await?;
        Ok(holder == Some(slot.holder))
    }

    async fn release_detached_slot(
        &self,
        slot: &DetachedExecutionSlot,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM codemode_detached_principal_slots
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND holder = $4
            "#,
        )
        .bind(&slot.tenant_id)
        .bind(&slot.principal_sub)
        .bind(&slot.principal_issuer)
        .bind(slot.holder)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn renew_detached_slot(
        &self,
        slot: &DetachedExecutionSlot,
        lease: Duration,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE codemode_detached_principal_slots
               SET lease_expires_at = now() + ($5 * interval '1 second')
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND holder = $4
            "#,
        )
        .bind(&slot.tenant_id)
        .bind(&slot.principal_sub)
        .bind(&slot.principal_issuer)
        .bind(slot.holder)
        .bind(lease_seconds(lease))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn submit(&self, execution: NewExecution) -> Result<Execution, StoreError> {
        let mut tx = self.pool.begin().await?;
        purge_expired_state(&mut tx).await?;
        let row = execution_query!(
            r#"
            INSERT INTO codemode_executions (
                id, tenant_id, principal_sub, principal_issuer, source,
                source_digest, program_input, execution_profile,
                sdk_contract_version,
                runner_contract_version, status, retention_until
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'submitted', $11)
            RETURNING
            "#,
            ""
        )
        .bind(execution.id)
        .bind(&execution.tenant_id)
        .bind(&execution.principal_sub)
        .bind(&execution.principal_issuer)
        .bind(&execution.source)
        .bind(&execution.source_digest)
        .bind(&execution.program_input)
        .bind(&execution.execution_profile)
        .bind(execution.sdk_contract_version)
        .bind(execution.runner_contract_version)
        .bind(execution.retention_until)
        .fetch_one(&mut *tx)
        .await?;
        insert_event(
            &mut tx,
            execution.id,
            &execution.tenant_id,
            &NewExecutionEvent {
                kind: crate::ExecutionEventKind::Submitted,
                step_number: None,
                call_id: None,
                attempt: None,
                detail: serde_json::json!({
                    "source_digest": execution.source_digest,
                    "sdk_contract_version": execution.sdk_contract_version,
                    "runner_contract_version": execution.runner_contract_version,
                }),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(row_to_execution(&row))
    }

    async fn start_or_reuse(
        &self,
        start: StartExecution,
    ) -> Result<StartExecutionResult, StoreError> {
        let StartExecution {
            execution,
            dedupe_key,
            source_locator,
            repeat_after,
            owner,
            lease,
            source,
            tool_snapshot,
        } = start;
        let lease_seconds = lease_seconds(lease);
        let mut tx = self.pool.begin().await?;
        purge_expired_state(&mut tx).await?;

        // This lock serializes only retry-equivalent starts. A 64-bit hash
        // collision can delay unrelated work but cannot merge it: every lookup
        // below also compares the full durable identity.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&dedupe_key)
            .execute(&mut *tx)
            .await?;

        let latest = execution_query!(
            "SELECT",
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND start_dedupe_key = $4
               AND source_digest = $5
               AND execution_profile = $6
               AND retention_until > now()
             ORDER BY submitted_at DESC, id DESC
             LIMIT 1
             FOR UPDATE
            "#
        )
        .bind(&execution.tenant_id)
        .bind(&execution.principal_sub)
        .bind(&execution.principal_issuer)
        .bind(&dedupe_key)
        .bind(&execution.source_digest)
        .bind(&execution.execution_profile)
        .fetch_optional(&mut *tx)
        .await?
        .as_ref()
        .map(row_to_execution);

        if let Some(latest) = latest {
            match repeat_after {
                None => {
                    bind_source_locator_tx(&mut tx, &execution, source_locator.as_deref()).await?;
                    tx.commit().await?;
                    return Ok(StartExecutionResult::Existing(latest));
                }
                Some(repeat_after) if latest.id == repeat_after => {
                    if !latest.status.is_terminal() {
                        tx.commit().await?;
                        return Ok(StartExecutionResult::RepeatNotTerminal(latest));
                    }
                    // The caller named the latest matching terminal execution:
                    // this is a deliberate repetition and creates the next one.
                }
                Some(repeat_after) => {
                    let target = execution_query!(
                        "SELECT",
                        r#"
                          FROM codemode_executions
                         WHERE tenant_id = $1
                           AND principal_sub = $2
                           AND principal_issuer = $3
                           AND start_dedupe_key = $4
                           AND source_digest = $5
                           AND execution_profile = $6
                           AND id = $7
                           AND retention_until > now()
                         FOR UPDATE
                        "#
                    )
                    .bind(&execution.tenant_id)
                    .bind(&execution.principal_sub)
                    .bind(&execution.principal_issuer)
                    .bind(&dedupe_key)
                    .bind(&execution.source_digest)
                    .bind(&execution.execution_profile)
                    .bind(repeat_after)
                    .fetch_optional(&mut *tx)
                    .await?
                    .as_ref()
                    .map(row_to_execution);
                    let Some(target) = target else {
                        tx.commit().await?;
                        return Ok(StartExecutionResult::RepeatUnavailable);
                    };
                    if !target.status.is_terminal() {
                        tx.commit().await?;
                        return Ok(StartExecutionResult::RepeatNotTerminal(target));
                    }

                    // A newer match proves the requested repetition was
                    // already created. Return it instead of repeating again.
                    bind_source_locator_tx(&mut tx, &execution, source_locator.as_deref()).await?;
                    tx.commit().await?;
                    return Ok(StartExecutionResult::Existing(latest));
                }
            }
        } else if repeat_after.is_some() {
            tx.commit().await?;
            return Ok(StartExecutionResult::RepeatUnavailable);
        }

        let row = execution_query!(
            r#"
            INSERT INTO codemode_executions (
                id, tenant_id, principal_sub, principal_issuer, source,
                source_digest, program_input, execution_profile, tool_snapshot,
                sdk_contract_version, runner_contract_version, status,
                retention_until, start_dedupe_key, claim_owner, claim_epoch,
                claim_expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'running',
                $12, $13, $14, 1, now() + ($15 * interval '1 second')
            )
            RETURNING
            "#,
            ""
        )
        .bind(execution.id)
        .bind(&execution.tenant_id)
        .bind(&execution.principal_sub)
        .bind(&execution.principal_issuer)
        .bind(&source)
        .bind(&execution.source_digest)
        .bind(&execution.program_input)
        .bind(&execution.execution_profile)
        .bind(&tool_snapshot)
        .bind(execution.sdk_contract_version)
        .bind(execution.runner_contract_version)
        .bind(execution.retention_until)
        .bind(&dedupe_key)
        .bind(owner)
        .bind(lease_seconds)
        .fetch_one(&mut *tx)
        .await?;
        let claimed = row_to_execution(&row);
        bind_source_locator_tx(&mut tx, &execution, source_locator.as_deref()).await?;
        insert_event(
            &mut tx,
            execution.id,
            &execution.tenant_id,
            &NewExecutionEvent {
                kind: crate::ExecutionEventKind::Submitted,
                step_number: None,
                call_id: None,
                attempt: None,
                detail: serde_json::json!({
                    "source_digest": execution.source_digest,
                    "sdk_contract_version": execution.sdk_contract_version,
                    "runner_contract_version": execution.runner_contract_version,
                }),
            },
        )
        .await?;
        for kind in [
            crate::ExecutionEventKind::Admitted,
            crate::ExecutionEventKind::Claimed,
            crate::ExecutionEventKind::Running,
        ] {
            insert_event(
                &mut tx,
                execution.id,
                &execution.tenant_id,
                &NewExecutionEvent {
                    kind,
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail: if kind == crate::ExecutionEventKind::Claimed {
                        serde_json::json!({"owner": owner, "epoch": claimed.claim_epoch})
                    } else {
                        Value::Object(serde_json::Map::new())
                    },
                },
            )
            .await?;
        }
        tx.commit().await?;
        let claim = ExecutionClaim {
            execution_id: claimed.id,
            tenant_id: claimed.tenant_id.clone(),
            owner,
            epoch: claimed.claim_epoch,
        };
        Ok(StartExecutionResult::Claimed {
            execution: claimed,
            claim,
        })
    }

    async fn find_retry_equivalent(
        &self,
        probe: &RetryEquivalence,
        id: Option<Uuid>,
    ) -> Result<Option<Execution>, StoreError> {
        let row = execution_query!(
            "SELECT",
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND start_dedupe_key = $4
               AND source_digest = $5
               AND execution_profile = $6
               AND retention_until > now()
               AND ($7::uuid IS NULL OR id = $7)
             ORDER BY submitted_at DESC, id DESC
             LIMIT 1
            "#
        )
        .bind(&probe.tenant_id)
        .bind(&probe.principal_sub)
        .bind(&probe.principal_issuer)
        .bind(&probe.dedupe_key)
        .bind(&probe.source_digest)
        .bind(&probe.execution_profile)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_execution))
    }

    async fn resolve_source_locator(
        &self,
        owner: &SourceArtifactOwner,
        source_locator: &str,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT source_digest
              FROM codemode_source_locators
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND source_locator = $4
               AND expires_at > now()
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(source_locator)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| row.get("source_digest")))
    }

    async fn bind_source_locator(
        &self,
        owner: &SourceArtifactOwner,
        source_locator: &str,
        source_digest: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        purge_expired_state(&mut tx).await?;
        bind_source_locator_row(&mut tx, owner, source_locator, source_digest, expires_at).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Execution>, StoreError> {
        let row = execution_query!(
            "SELECT",
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1 AND id = $2
            "#
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_execution))
    }

    async fn list_waiting_approvals(
        &self,
        tenant_id: &str,
        limit: u16,
    ) -> Result<Vec<Execution>, StoreError> {
        let rows = execution_query!(
            "SELECT",
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1
               AND status = 'waiting_for_approval'
               AND claim_owner IS NULL
               AND cancellation_requested_at IS NULL
               AND completed_at IS NULL
               AND retention_until > now()
             ORDER BY submitted_at, id
             LIMIT $2
            "#
        )
        .bind(tenant_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_execution).collect())
    }

    async fn list_owned_in_flight(
        &self,
        owner: &OwnedInFlight,
        before: Option<(OffsetDateTime, Uuid)>,
        limit: u16,
    ) -> Result<Vec<InFlightExecution>, StoreError> {
        // The confinement predicate uses `->` deliberately: a row whose
        // profile lacks the key yields SQL NULL and matches no caller, which
        // is exactly how the by-id read treats an absent key. Coalescing the
        // gap to JSON null would make such rows enumerable by unconfined
        // callers that cannot retrieve them. The md5 predicate exists for the
        // planner: the owned in-flight index keys one fixed-width digest of
        // the whole owner triple — subject, issuer, confinement — because
        // none of those values carries a length bound and raw values in a
        // B-tree key can overflow an index tuple. The digest expression must
        // appear verbatim here for the index to bound the scan; the exact
        // equality predicates stay alongside it as the correctness filter —
        // a digest collision widens the scan, never the result. SQL NULL
        // (an issuer-less pre-upgrade row, a profile without the key) nulls
        // the digest and matches no caller, preserving fail-closed reads.
        //
        // The select list is the decision-shaped subset on purpose: source,
        // checkpoints, results, and tool snapshots are caller-controlled and
        // each may be large, so a page that materialized full rows would
        // multiply them by the row count. Existence flags carry the same
        // decision without the payload.
        let rows = sqlx::query(
            r#"
            SELECT id, status, terminal_reason_code,
                   result_payload IS NOT NULL AS result_available,
                   cancellation_requested_at IS NOT NULL AS cancellation_requested,
                   submitted_at, updated_at, completed_at, retention_until
              FROM codemode_executions
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $3
               AND md5(principal_sub || chr(31) || principal_issuer || chr(31)
                       || (execution_profile -> 'profile_confinement')::text) =
                   md5($2 || chr(31) || $3 || chr(31) || $4::text)
               AND execution_profile -> 'profile_confinement' = $4
               AND completed_at IS NULL
               AND retention_until > now()
               AND ($5::timestamptz IS NULL OR (submitted_at, id) < ($5, $6))
             ORDER BY submitted_at DESC, id DESC
             LIMIT $7
            "#,
        )
        .bind(&owner.tenant_id)
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(&owner.profile_confinement)
        .bind(before.map(|(submitted_at, _)| submitted_at))
        .bind(before.map(|(_, id)| id))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|row| {
                let status: String = row.get("status");
                InFlightExecution {
                    id: row.get("id"),
                    status: ExecutionStatus::parse(&status)
                        .expect("codemode_executions status CHECK admits only known states"),
                    terminal_reason_code: row.get("terminal_reason_code"),
                    result_available: row.get("result_available"),
                    cancellation_requested: row.get("cancellation_requested"),
                    submitted_at: row.get("submitted_at"),
                    updated_at: row.get("updated_at"),
                    completed_at: row.get("completed_at"),
                    retention_until: row.get("retention_until"),
                }
            })
            .collect())
    }

    async fn list_in_flight_for_operator(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u16,
        offset: u32,
    ) -> Result<Vec<OperatorInFlightExecution>, StoreError> {
        // Identity, ownership, state, and age only: source, checkpoints,
        // results, and snapshots are governed content whose retention is an
        // explicit information-flow decision, and an observability surface
        // must not become a way around it. The scanned set is the tenant's
        // live in-flight rows — bounded by admission quota and drained of
        // expired rows by the retention sweep — so ordering it stays
        // proportionate to what the operator is inspecting.
        let rows = sqlx::query(
            r#"
            SELECT id, principal_sub, principal_issuer, status,
                   cancellation_requested_at IS NOT NULL AS cancellation_requested,
                   (claim_owner IS NOT NULL AND claim_expires_at > now()) AS claimed,
                   claim_expires_at, submitted_at, updated_at, retention_until
              FROM codemode_executions
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR principal_sub = $2)
               AND completed_at IS NULL
               AND retention_until > now()
             ORDER BY submitted_at DESC, id DESC
             LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|row| {
                let status: String = row.get("status");
                OperatorInFlightExecution {
                    id: row.get("id"),
                    principal_sub: row.get("principal_sub"),
                    principal_issuer: row.get("principal_issuer"),
                    status: ExecutionStatus::parse(&status)
                        .expect("codemode_executions status CHECK admits only known states"),
                    cancellation_requested: row.get("cancellation_requested"),
                    claimed: row.get("claimed"),
                    claim_expires_at: row.get("claim_expires_at"),
                    submitted_at: row.get("submitted_at"),
                    updated_at: row.get("updated_at"),
                    retention_until: row.get("retention_until"),
                }
            })
            .collect())
    }

    async fn deny_waiting_approval(
        &self,
        tenant_id: &str,
        id: Uuid,
        approver: &str,
        reason: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = execution_query!(
            r#"
            UPDATE codemode_executions
               SET status = 'failed',
                   terminal_reason_code = 'approval_denied',
                   completed_at = now()
             WHERE tenant_id = $1
               AND id = $2
               AND status = 'waiting_for_approval'
               AND claim_owner IS NULL
               AND cancellation_requested_at IS NULL
               AND completed_at IS NULL
               AND retention_until > now()
            RETURNING
            "#,
            ""
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if row.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        insert_event(
            &mut tx,
            id,
            tenant_id,
            &NewExecutionEvent {
                kind: crate::ExecutionEventKind::Failed,
                step_number: None,
                call_id: None,
                attempt: None,
                detail: serde_json::json!({
                    "reason_code": "approval_denied",
                    "approver": approver,
                    "reason": reason,
                }),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn claim(
        &self,
        tenant_id: &str,
        id: Uuid,
        owner: Uuid,
        lease: Duration,
        source: String,
        tool_snapshot: Value,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
        let lease_seconds = lease_seconds(lease);
        let mut tx = self.pool.begin().await?;
        let row = execution_query!(
            r#"
            UPDATE codemode_executions
               SET status = 'running',
                   source = $4,
                   tool_snapshot = $5,
                   claim_owner = $3,
                   claim_epoch = claim_epoch + 1,
                   claim_expires_at = now() + ($6 * interval '1 second')
             WHERE tenant_id = $1
               AND id = $2
               AND status = 'submitted'
               AND claim_owner IS NULL
            RETURNING
            "#,
            ""
        )
        .bind(tenant_id)
        .bind(id)
        .bind(owner)
        .bind(&source)
        .bind(&tool_snapshot)
        .bind(lease_seconds)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let execution = row_to_execution(&row);
        for kind in [
            crate::ExecutionEventKind::Admitted,
            crate::ExecutionEventKind::Claimed,
            crate::ExecutionEventKind::Running,
        ] {
            insert_event(
                &mut tx,
                id,
                tenant_id,
                &NewExecutionEvent {
                    kind,
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail: if kind == crate::ExecutionEventKind::Claimed {
                        serde_json::json!({"owner": owner, "epoch": execution.claim_epoch})
                    } else {
                        Value::Object(serde_json::Map::new())
                    },
                },
            )
            .await?;
        }
        tx.commit().await?;
        let claim = ExecutionClaim {
            execution_id: id,
            tenant_id: tenant_id.to_owned(),
            owner,
            epoch: execution.claim_epoch,
        };
        Ok(Some((execution, claim)))
    }

    async fn renew(&self, claim: &ExecutionClaim, lease: Duration) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE codemode_executions
               SET claim_expires_at = now() + ($5 * interval '1 second')
             WHERE tenant_id = $1
               AND id = $2
               AND claim_owner = $3
               AND claim_epoch = $4
               AND claim_expires_at > now()
               AND cancellation_requested_at IS NULL
               AND completed_at IS NULL
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(claim.execution_id)
        .bind(claim.owner)
        .bind(claim.epoch)
        .bind(lease_seconds(lease))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn renew_effect_lease(
        &self,
        claim: &ExecutionClaim,
        lease: Duration,
    ) -> Result<bool, StoreError> {
        // No cancellation predicate: an in-flight effect keeps its lease so
        // abandonment reconciliation cannot terminalize the row before the
        // effect's outcome reaches the journal. The lease-liveness predicate
        // is also relaxed to "not reclaimed": the extension may race a lapse,
        // and only a changed owner/epoch or a completed row refuses it.
        let result = sqlx::query(
            r#"
            UPDATE codemode_executions
               SET claim_expires_at = now() + ($5 * interval '1 second')
             WHERE tenant_id = $1
               AND id = $2
               AND claim_owner = $3
               AND claim_epoch = $4
               AND completed_at IS NULL
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(claim.execution_id)
        .bind(claim.owner)
        .bind(claim.epoch)
        .bind(lease_seconds(lease))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn resume(
        &self,
        resume: ResumeExecution,
    ) -> Result<Option<(Execution, ExecutionClaim)>, StoreError> {
        let ResumeExecution {
            tenant_id,
            principal_sub,
            principal_issuer,
            id,
            owner,
            lease,
            expected_status,
            resume_context,
            expected_claim_epoch,
            expected_resume_context,
            expected_source_digest,
            expected_tool_snapshot,
            expected_sdk_contract_version,
            expected_runner_contract_version,
            next_sdk_contract_version,
            next_runner_contract_version,
        } = resume;
        let mut tx = self.pool.begin().await?;
        let row = execution_query!(
            r#"
            UPDATE codemode_executions
               SET status = 'running',
                   resume_context = $6,
                   claim_owner = $4,
                   claim_epoch = claim_epoch + 1,
                   claim_expires_at = now() + ($5 * interval '1 second'),
                   terminal_reason_code = NULL,
                   sdk_contract_version = $13,
                   runner_contract_version = $14
             WHERE tenant_id = $1
               AND principal_sub = $2
               -- Exact issuer binding: a pre-upgrade NULL row matches
               -- nothing (fail closed).
               AND principal_issuer = $16
               AND id = $3
               AND status = $15
               AND claim_owner IS NULL
               AND cancellation_requested_at IS NULL
               AND source IS NOT NULL
               AND source_digest = $7
               AND tool_snapshot = $8
               AND sdk_contract_version = $9
               AND runner_contract_version = $10
               AND completed_at IS NULL
               AND retention_until > now()
               AND claim_epoch = $11
               AND resume_context IS NOT DISTINCT FROM $12
            RETURNING
            "#,
            ""
        )
        .bind(&tenant_id)
        .bind(&principal_sub)
        .bind(id)
        .bind(owner)
        .bind(lease_seconds(lease))
        .bind(&resume_context)
        .bind(&expected_source_digest)
        .bind(&expected_tool_snapshot)
        .bind(expected_sdk_contract_version)
        .bind(expected_runner_contract_version)
        .bind(expected_claim_epoch)
        .bind(&expected_resume_context)
        .bind(next_sdk_contract_version)
        .bind(next_runner_contract_version)
        .bind(expected_status.as_str())
        .bind(&principal_issuer)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let execution = row_to_execution(&row);
        for (kind, detail) in [
            (
                crate::ExecutionEventKind::Claimed,
                serde_json::json!({"owner": owner, "epoch": execution.claim_epoch}),
            ),
            (
                crate::ExecutionEventKind::Resumed,
                serde_json::json!({"epoch": execution.claim_epoch}),
            ),
            (
                crate::ExecutionEventKind::Running,
                Value::Object(serde_json::Map::new()),
            ),
        ] {
            insert_event(
                &mut tx,
                id,
                &tenant_id,
                &NewExecutionEvent {
                    kind,
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail,
                },
            )
            .await?;
        }
        tx.commit().await?;
        let claim = ExecutionClaim {
            execution_id: id,
            tenant_id,
            owner,
            epoch: execution.claim_epoch,
        };
        Ok(Some((execution, claim)))
    }

    async fn append_event(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let owned = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT 1
              FROM codemode_executions
             WHERE tenant_id = $1
               AND id = $2
               AND claim_owner = $3
               AND claim_epoch = $4
               AND claim_expires_at > now()
               AND cancellation_requested_at IS NULL
               AND completed_at IS NULL
             FOR UPDATE
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(claim.execution_id)
        .bind(claim.owner)
        .bind(claim.epoch)
        .fetch_optional(&mut *tx)
        .await?;
        if owned.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        insert_event(&mut tx, claim.execution_id, &claim.tenant_id, &event).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn append_effect_outcome(
        &self,
        claim: &ExecutionClaim,
        event: NewExecutionEvent,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        // Same ownership fence as `append_event` minus the cancellation and
        // lease-expiry checks: a cancellation requested — or a lease that
        // lapsed — while the effect was in flight must not erase the record
        // of what was dispatched. Owner and epoch still fence: once another
        // worker reclaims or reconciliation terminalizes the row, the append
        // is refused.
        let owned = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT 1
              FROM codemode_executions
             WHERE tenant_id = $1
               AND id = $2
               AND claim_owner = $3
               AND claim_epoch = $4
               AND completed_at IS NULL
             FOR UPDATE
            "#,
        )
        .bind(&claim.tenant_id)
        .bind(claim.execution_id)
        .bind(claim.owner)
        .bind(claim.epoch)
        .fetch_optional(&mut *tx)
        .await?;
        if owned.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        insert_event(&mut tx, claim.execution_id, &claim.tenant_id, &event).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn transition(
        &self,
        claim: &ExecutionClaim,
        transition: ExecutionTransition,
    ) -> Result<Option<Execution>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = transition_claimed(&mut tx, claim, &transition).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        insert_event(
            &mut tx,
            claim.execution_id,
            &claim.tenant_id,
            &transition.event,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(row_to_execution(&row)))
    }

    async fn fail_submission(
        &self,
        tenant_id: &str,
        id: Uuid,
        event: NewExecutionEvent,
        reason_code: String,
    ) -> Result<Option<Execution>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = execution_query!(
            r#"
            UPDATE codemode_executions
               SET status = 'failed',
                   terminal_reason_code = $3,
                   completed_at = now(),
                   claim_owner = NULL,
                   claim_expires_at = NULL
             WHERE tenant_id = $1
               AND id = $2
               AND status = 'submitted'
               AND claim_owner IS NULL
               AND claim_expires_at IS NULL
               AND completed_at IS NULL
            RETURNING
            "#,
            ""
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&reason_code)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        insert_event(&mut tx, id, tenant_id, &event).await?;
        tx.commit().await?;
        Ok(Some(row_to_execution(&row)))
    }

    async fn request_cancellation(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        principal_issuer: &str,
        id: Uuid,
    ) -> Result<Option<Execution>, StoreError> {
        self.cancel_scoped(
            tenant_id,
            id,
            Some((principal_sub, principal_issuer)),
            "cancelled_by_client",
            Value::Object(serde_json::Map::new()),
        )
        .await
    }

    async fn request_cancellation_for_operator(
        &self,
        tenant_id: &str,
        id: Uuid,
        operator_sub: &str,
    ) -> Result<Option<Execution>, StoreError> {
        self.cancel_scoped(
            tenant_id,
            id,
            None,
            "cancelled_by_operator",
            serde_json::json!({"requested_by": "operator", "operator_sub": operator_sub}),
        )
        .await
    }

    async fn reconcile_abandoned(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        principal_issuer: &str,
        id: Uuid,
        submission_grace: Duration,
    ) -> Result<Option<Execution>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let reconciled = execution_query!(
            r#"
            UPDATE codemode_executions
               SET status = CASE
                       WHEN execution_profile->>'resumable' = 'true'
                            AND source IS NOT NULL
                            AND tool_snapshot IS NOT NULL
                            AND retention_until > now()
                       THEN 'waiting_for_resume'
                       ELSE 'expired'
                   END,
                   terminal_reason_code = CASE
                       WHEN execution_profile->>'resumable' = 'true'
                            AND source IS NOT NULL
                            AND tool_snapshot IS NOT NULL
                            AND retention_until > now()
                       THEN NULL
                       WHEN retention_until <= now() THEN 'retention_expired'
                       WHEN status = 'submitted' THEN 'worker_never_claimed'
                       ELSE 'worker_lease_expired'
                   END,
                   resume_context = CASE
                       WHEN execution_profile->>'resumable' = 'true'
                            AND source IS NOT NULL
                            AND tool_snapshot IS NOT NULL
                            AND retention_until > now()
                       THEN COALESCE(
                           resume_context,
                           '{"checkpoint":null}'::jsonb
                       )
                       ELSE resume_context
                   END,
                   completed_at = CASE
                       WHEN execution_profile->>'resumable' = 'true'
                            AND source IS NOT NULL
                            AND tool_snapshot IS NOT NULL
                            AND retention_until > now()
                       THEN NULL
                       ELSE now()
                   END,
                   claim_owner = NULL,
                   claim_expires_at = NULL
             WHERE tenant_id = $1
               AND principal_sub = $2
               -- Exact issuer binding: this read MUTATES (abandonment
               -- reconciliation), so the predicate itself must refuse a
               -- pre-upgrade NULL row or a cross-issuer subject collision.
               AND principal_issuer = $5
               AND id = $3
               AND completed_at IS NULL
               AND (
                   (
                       status = 'submitted'
                       AND claim_owner IS NULL
                       AND submitted_at <= now() - ($4 * interval '1 second')
                   )
                   OR (
                       status = 'running'
                       AND claim_owner IS NOT NULL
                       AND claim_expires_at <= now()
                   )
                   OR (
                       status IN ('waiting_for_approval', 'waiting_for_resume')
                       AND claim_owner IS NULL
                       AND retention_until <= now()
                   )
               )
            RETURNING
            "#,
            ""
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .bind(id)
        .bind(lease_seconds(submission_grace))
        .bind(principal_issuer)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = reconciled {
            let execution = row_to_execution(&row);
            let reason = if execution.status == ExecutionStatus::WaitingForResume {
                "worker_interrupted"
            } else {
                execution
                    .terminal_reason_code
                    .as_deref()
                    .expect("expired execution has a reason")
            };
            insert_event(
                &mut tx,
                id,
                tenant_id,
                &NewExecutionEvent {
                    kind: if execution.status == ExecutionStatus::WaitingForResume {
                        crate::ExecutionEventKind::WaitingForResume
                    } else {
                        crate::ExecutionEventKind::Expired
                    },
                    step_number: None,
                    call_id: None,
                    attempt: None,
                    detail: serde_json::json!({"reason_code": reason}),
                },
            )
            .await?;
            tx.commit().await?;
            return Ok(Some(execution));
        }

        let current = execution_query!(
            "SELECT",
            r#"
              FROM codemode_executions
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND principal_issuer = $4
               AND id = $3
            "#
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .bind(id)
        .bind(principal_issuer)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(current.as_ref().map(row_to_execution))
    }

    async fn events(&self, tenant_id: &str, id: Uuid) -> Result<Vec<ExecutionEvent>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT e.id, e.execution_id, e.tenant_id, e.kind, e.step_number,
                   e.call_id, e.attempt, e.detail, e.created_at
              FROM codemode_execution_events e
              JOIN codemode_executions x
                ON x.id = e.execution_id AND x.tenant_id = e.tenant_id
             WHERE x.tenant_id = $1 AND x.id = $2
             ORDER BY e.id
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_event).collect())
    }

    async fn list_artifacts(
        &self,
        tenant_id: &str,
        id: Uuid,
        after_event_id: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ExecutionArtifact>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT e.id, e.execution_id,
                   (e.detail->>'artifact_id')::uuid AS artifact_id,
                   e.created_at
              FROM codemode_execution_events e
              JOIN codemode_executions x
                ON x.id = e.execution_id AND x.tenant_id = e.tenant_id
             WHERE x.tenant_id = $1
               AND x.id = $2
               AND x.retention_until > now()
               AND e.kind = 'artifact_emitted'
               AND ($3::bigint IS NULL OR e.id > $3)
             ORDER BY e.id
             LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(after_event_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_artifact).collect())
    }

    async fn get_artifact(
        &self,
        tenant_id: &str,
        id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Option<ExecutionArtifactContent>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT e.id, e.execution_id,
                   (e.detail->>'artifact_id')::uuid AS artifact_id,
                   e.detail->'value' AS value, e.created_at
              FROM codemode_execution_events e
              JOIN codemode_executions x
                ON x.id = e.execution_id AND x.tenant_id = e.tenant_id
             WHERE x.tenant_id = $1
               AND x.id = $2
               AND x.retention_until > now()
               AND e.kind = 'artifact_emitted'
               AND e.detail->>'artifact_id' = $3
             ORDER BY e.id
             LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(artifact_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(|row| ExecutionArtifactContent {
            artifact: row_to_artifact(row),
            value: row.get("value"),
        }))
    }
}

async fn bind_source_locator_tx(
    tx: &mut Transaction<'_, Postgres>,
    execution: &crate::NewExecution,
    source_locator: Option<&str>,
) -> Result<(), StoreError> {
    let Some(source_locator) = source_locator else {
        return Ok(());
    };
    bind_source_locator_row(
        tx,
        &SourceArtifactOwner {
            tenant_id: execution.tenant_id.clone(),
            principal_sub: execution.principal_sub.clone(),
            principal_issuer: execution.principal_issuer.clone(),
        },
        source_locator,
        &execution.source_digest,
        execution.retention_until,
    )
    .await
}

async fn bind_source_locator_row(
    tx: &mut Transaction<'_, Postgres>,
    owner: &SourceArtifactOwner,
    source_locator: &str,
    source_digest: &str,
    expires_at: OffsetDateTime,
) -> Result<(), StoreError> {
    // A locator is fixed-width, but distinct upload handles are untrusted
    // cardinality. Serialize accounting across replicas before admitting a
    // new live binding; extending the same locator consumes no new slot.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(\
         hashtextextended('codemode-source-locators' || chr(31) || $1, 0))",
    )
    .bind(&owner.tenant_id)
    .execute(&mut **tx)
    .await?;
    let usage = sqlx::query(
        r#"
        SELECT count(*) FILTER (
                   WHERE NOT (
                       principal_sub = $2
                       AND principal_issuer = $3
                       AND source_locator = $4
                   )
               )::bigint AS tenant_count,
               count(*) FILTER (
                   WHERE principal_sub = $2
                     AND principal_issuer = $3
                     AND source_locator <> $4
               )::bigint AS owner_count
          FROM codemode_source_locators
         WHERE tenant_id = $1
           AND expires_at > now()
        "#,
    )
    .bind(&owner.tenant_id)
    .bind(&owner.principal_sub)
    .bind(&owner.principal_issuer)
    .bind(source_locator)
    .fetch_one(&mut **tx)
    .await?;
    let tenant_count: i64 = usage.get("tenant_count");
    let owner_count: i64 = usage.get("owner_count");
    if tenant_count.saturating_add(1) > MAX_SOURCE_LOCATORS_PER_TENANT
        || owner_count.saturating_add(1) > MAX_SOURCE_LOCATORS_PER_OWNER
    {
        return Err(StoreError::Conflict);
    }
    let bound = sqlx::query(
        r#"
        INSERT INTO codemode_source_locators (
            tenant_id, principal_sub, principal_issuer,
            source_locator, source_digest, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (tenant_id, principal_issuer, principal_sub, source_locator)
        DO UPDATE
           SET expires_at = GREATEST(
                   codemode_source_locators.expires_at,
                   EXCLUDED.expires_at
               )
         WHERE codemode_source_locators.source_digest = EXCLUDED.source_digest
        RETURNING source_digest
        "#,
    )
    .bind(&owner.tenant_id)
    .bind(&owner.principal_sub)
    .bind(&owner.principal_issuer)
    .bind(source_locator)
    .bind(source_digest)
    .bind(expires_at)
    .fetch_optional(&mut **tx)
    .await?;
    if bound.is_none() {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

async fn purge_expired_state(tx: &mut Transaction<'_, Postgres>) -> Result<(), StoreError> {
    sqlx::query("SELECT set_config('app.codemode_retention_delete', 'enabled', true)")
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        r#"
        WITH expired AS (
            SELECT tenant_id, principal_issuer, principal_sub, source_locator
              FROM codemode_source_locators
             WHERE expires_at <= now()
             ORDER BY expires_at
             FOR UPDATE SKIP LOCKED
             LIMIT $1
        )
        DELETE FROM codemode_source_locators AS locator
         USING expired
         WHERE locator.tenant_id = expired.tenant_id
           AND locator.principal_issuer = expired.principal_issuer
           AND locator.principal_sub = expired.principal_sub
           AND locator.source_locator = expired.source_locator
        "#,
    )
    .bind(RETENTION_SWEEP_BATCH_SIZE)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        r#"
        WITH expired AS (
            SELECT tenant_id, principal_issuer, principal_sub, source_digest
              FROM codemode_source_artifacts
             WHERE expires_at <= now()
             ORDER BY expires_at
             FOR UPDATE SKIP LOCKED
             LIMIT $1
        )
        DELETE FROM codemode_source_artifacts AS artifact
         USING expired
         WHERE artifact.tenant_id = expired.tenant_id
           AND artifact.principal_issuer = expired.principal_issuer
           AND artifact.principal_sub = expired.principal_sub
           AND artifact.source_digest = expired.source_digest
        "#,
    )
    .bind(RETENTION_SWEEP_BATCH_SIZE)
    .execute(&mut **tx)
    .await?;
    // Any expired row without a live claim is unrecoverable garbage:
    // listing, resume, denial, and retry-reuse all gate on
    // `retention_until > now()`, and the by-id read reconciles an expired
    // non-terminal row to a `retention_expired` tombstone it then filters
    // out, so the owner sees "gone" whether the row exists or not. Leaving
    // such rows would grow the partial in-flight indexes without bound —
    // nothing else ever removes an abandoned submitted or dead-claim
    // running row. A row whose claim is still live is left for its runner
    // to finish and terminalize. Sweeping races claim-shaped conditional
    // updates safely: a claim or renewal that finds no row loses exactly
    // like a fenced takeover.
    //
    // Two deletes, not one with an OR: the completed arm walks the 0081
    // retention index (completed rows) and the abandoned arm walks its 0096
    // counterpart (never-completed rows), so each candidate scan stays
    // bounded by its index and the batch limit rather than degrading to a
    // table scan on the pre-submission path.
    sqlx::query(
        r#"
        WITH expired AS (
            SELECT id
             FROM codemode_executions
             WHERE retention_until <= now()
               AND completed_at IS NOT NULL
             ORDER BY retention_until, id
             FOR UPDATE SKIP LOCKED
             LIMIT $1
        )
        DELETE FROM codemode_executions AS execution
         USING expired
         WHERE execution.id = expired.id
        "#,
    )
    .bind(RETENTION_SWEEP_BATCH_SIZE)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        r#"
        WITH abandoned AS (
            SELECT id
             FROM codemode_executions
             WHERE retention_until <= now()
               AND completed_at IS NULL
               AND (claim_owner IS NULL OR claim_expires_at <= now())
             ORDER BY retention_until, id
             FOR UPDATE SKIP LOCKED
             LIMIT $1
        )
        DELETE FROM codemode_executions AS execution
         USING abandoned
         WHERE execution.id = abandoned.id
        "#,
    )
    .bind(RETENTION_SWEEP_BATCH_SIZE)
    .execute(&mut **tx)
    .await?;
    // Crash-abandoned principal slots have no release path of their own:
    // graceful shutdown deletes the row and a returning principal replaces
    // it, but a principal that never comes back would leave its row forever.
    // A full day past expiry is far beyond any renewal gap, so an
    // alive-but-partitioned holder is never swept out from under a
    // recoverable attempt — and a swept holder's later renewal is fenced
    // exactly like a takeover.
    sqlx::query(
        r#"
        WITH abandoned AS (
            SELECT tenant_id, principal_issuer, principal_sub
              FROM codemode_detached_principal_slots
             WHERE lease_expires_at <= now() - interval '1 day'
             ORDER BY lease_expires_at
             FOR UPDATE SKIP LOCKED
             LIMIT $1
        )
        DELETE FROM codemode_detached_principal_slots AS slot
         USING abandoned
         WHERE slot.tenant_id = abandoned.tenant_id
           AND slot.principal_issuer = abandoned.principal_issuer
           AND slot.principal_sub = abandoned.principal_sub
        "#,
    )
    .bind(RETENTION_SWEEP_BATCH_SIZE)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn transition_claimed(
    tx: &mut Transaction<'_, Postgres>,
    claim: &ExecutionClaim,
    transition: &ExecutionTransition,
) -> Result<Option<PgRow>, StoreError> {
    let from = status_strings(&transition.from);
    let releases_claim = transition.to.is_terminal()
        || matches!(
            transition.to,
            ExecutionStatus::WaitingForApproval | ExecutionStatus::WaitingForResume
        );
    let row = execution_query!(
        r#"
        UPDATE codemode_executions
           SET status = $5,
               terminal_reason_code = $6,
               result_metadata = $7,
               result_payload = $8,
               resume_context = $9,
               completed_at = CASE WHEN $10 THEN now() ELSE NULL END,
               claim_owner = CASE WHEN $11 THEN NULL ELSE claim_owner END,
               claim_expires_at = CASE WHEN $11 THEN NULL ELSE claim_expires_at END
         WHERE tenant_id = $1
           AND id = $2
           AND claim_owner = $3
           AND claim_epoch = $4
           AND claim_expires_at > now()
           AND status = ANY($12)
           AND ($13 OR cancellation_requested_at IS NULL)
           AND completed_at IS NULL
        RETURNING
        "#,
        ""
    )
    .bind(&claim.tenant_id)
    .bind(claim.execution_id)
    .bind(claim.owner)
    .bind(claim.epoch)
    .bind(transition.to.as_str())
    .bind(&transition.terminal_reason_code)
    .bind(&transition.result_metadata)
    .bind(&transition.result_payload)
    .bind(&transition.resume_context)
    .bind(transition.to.is_terminal())
    .bind(releases_claim)
    .bind(&from)
    .bind(transition.to == ExecutionStatus::Cancelled)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

async fn insert_event(
    tx: &mut Transaction<'_, Postgres>,
    execution_id: Uuid,
    tenant_id: &str,
    event: &NewExecutionEvent,
) -> Result<(), StoreError> {
    sqlx::query(
        r#"
        INSERT INTO codemode_execution_events (
            execution_id, tenant_id, kind, step_number, call_id, attempt, detail
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(execution_id)
    .bind(tenant_id)
    .bind(event.kind.as_str())
    .bind(event.step_number)
    .bind(event.call_id)
    .bind(event.attempt)
    .bind(&event.detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn row_to_execution(row: &PgRow) -> Execution {
    let status: String = row.get("status");
    Execution {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        principal_sub: row.get("principal_sub"),
        principal_issuer: row.get("principal_issuer"),
        source: row.get("source"),
        source_digest: row.get("source_digest"),
        program_input: row.get("program_input"),
        execution_profile: row.get("execution_profile"),
        tool_snapshot: row.get("tool_snapshot"),
        sdk_contract_version: row.get("sdk_contract_version"),
        runner_contract_version: row.get("runner_contract_version"),
        status: ExecutionStatus::parse(&status)
            .expect("codemode_executions status CHECK admits only known states"),
        terminal_reason_code: row.get("terminal_reason_code"),
        result_metadata: row.get("result_metadata"),
        result_payload: row.get("result_payload"),
        resume_context: row.get("resume_context"),
        claim_owner: row.get("claim_owner"),
        claim_epoch: row.get("claim_epoch"),
        claim_expires_at: row.get("claim_expires_at"),
        cancellation_requested_at: row.get("cancellation_requested_at"),
        cancellation_reason_code: row.get("cancellation_reason_code"),
        submitted_at: row.get("submitted_at"),
        updated_at: row.get("updated_at"),
        completed_at: row.get("completed_at"),
        retention_until: row.get("retention_until"),
    }
}

fn row_to_retained_source(row: &PgRow) -> RetainedSource {
    RetainedSource {
        source: row.get("source"),
        source_digest: row.get("source_digest"),
        expires_at: row.get("expires_at"),
    }
}

fn row_to_artifact(row: &PgRow) -> ExecutionArtifact {
    ExecutionArtifact {
        event_id: row.get("id"),
        execution_id: row.get("execution_id"),
        artifact_id: row.get("artifact_id"),
        created_at: row.get("created_at"),
    }
}

fn row_to_event(row: &PgRow) -> ExecutionEvent {
    ExecutionEvent {
        id: row.get("id"),
        execution_id: row.get("execution_id"),
        tenant_id: row.get("tenant_id"),
        kind: row.get("kind"),
        step_number: row.get("step_number"),
        call_id: row.get("call_id"),
        attempt: row.get("attempt"),
        detail: row.get("detail"),
        created_at: row.get("created_at"),
    }
}

fn status_strings(statuses: &[ExecutionStatus]) -> Vec<&'static str> {
    statuses.iter().map(|status| status.as_str()).collect()
}

fn lease_seconds(lease: Duration) -> i64 {
    let seconds = lease.as_secs().max(1);
    i64::try_from(seconds).unwrap_or(i64::MAX)
}
