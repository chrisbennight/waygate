//! Admin CRUD store for `rate_limit_policies`.
//!
//! Split from the hot-path `QuotaService` (which only consumes
//! tokens) because the admin surface needs different shapes:
//!
//! - The hot path knows the (tenant, action) tuple; the admin
//!   path navigates by `(tenant, id)`.
//! - The admin path needs structured error mapping (Conflict →
//!   409, InvalidStatus → 400); the hot path treats all errors
//!   uniformly best-effort.
//! - The admin handler also needs `delete_all_for_tenant` so the
//!   `cleanup_onboarding_residue` cascade can drop a
//!   deleted tenant's policies. The counters table has
//!   ON DELETE CASCADE back to policies so the bucket state goes
//!   with the policy rows in one statement.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{QuotaAction, QuotaScope};

/// One `rate_limit_policies` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitPolicy {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub scope: QuotaScope,
    /// NULL when `scope == Tenant`; required for the other four
    /// scopes (the SQL CHECK enforces this; the admin handler
    /// rejects mismatches at the HTTP boundary so the
    /// constraint violation never reaches the operator as a
    /// raw 23514 message).
    pub scope_value: Option<String>,
    pub bucket_capacity: i32,
    pub refill_per_second: f64,
    pub action: QuotaAction,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitStoreError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// `(tenant_id, scope, COALESCE(scope_value, ''), action)`
    /// uniqueness violation. Admin maps to HTTP 409.
    #[error("conflict: a policy already exists for this (scope, scope_value, action)")]
    Conflict,
    /// CHECK constraint violation — typically `scope='tenant'`
    /// with a non-null `scope_value`, or vice versa.
    /// Admin maps to HTTP 400 with operator-visible detail.
    #[error("invalid policy shape: {0}")]
    InvalidShape(String),
}

/// Admin CRUD trait. The hot-path [`crate::QuotaService`] stays
/// separate — it only consumes tokens and doesn't need any of
/// this surface.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait RateLimitPolicyStore: Send + Sync {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        scope: QuotaScope,
        scope_value: Option<&str>,
        bucket_capacity: i32,
        refill_per_second: f64,
        action: QuotaAction,
    ) -> Result<RateLimitPolicy, RateLimitStoreError>;

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<RateLimitPolicy>, RateLimitStoreError>;

    /// Update mutable fields. Either `bucket_capacity` or
    /// `refill_per_second` can be `None` to leave it alone.
    /// scope / scope_value / action are NOT mutable — operators
    /// rotate by `DELETE` + `POST` (avoids cache-shaped weirdness
    /// where a renamed scope keeps its old counter row).
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        bucket_capacity: Option<i32>,
        refill_per_second: Option<f64>,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError>;

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RateLimitStoreError>;

    /// Cleanup arm: hard-delete every policy for a
    /// tenant. ON DELETE CASCADE on `rate_limit_counters.policy_id`
    /// (migration 0025) sweeps the counter rows in the same
    /// statement. Called from `waygate-admin::tenants::cleanup_onboarding_residue`.
    /// Returns the number of policy rows deleted.
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, RateLimitStoreError>;
}

/// Postgres-backed [`RateLimitPolicyStore`].
pub struct PgRateLimitPolicyStore {
    pool: PgPool,
}

impl PgRateLimitPolicyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RateLimitPolicyStore for PgRateLimitPolicyStore {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        scope: QuotaScope,
        scope_value: Option<&str>,
        bucket_capacity: i32,
        refill_per_second: f64,
        action: QuotaAction,
    ) -> Result<RateLimitPolicy, RateLimitStoreError> {
        let id = Uuid::now_v7();
        match sqlx::query(
            r#"
            INSERT INTO rate_limit_policies
                (id, tenant_id, name, scope, scope_value,
                 bucket_capacity, refill_per_second, action)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, tenant_id, name, scope, scope_value,
                      bucket_capacity, refill_per_second, action,
                      created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(scope.as_str())
        .bind(scope_value)
        .bind(bucket_capacity)
        .bind(refill_per_second)
        .bind(action.as_str())
        .fetch_one(&self.pool)
        .await
        {
            Ok(r) => row_to_policy(&r),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RateLimitStoreError::Conflict)
            }
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::CHECK_VIOLATION) =>
            {
                Err(RateLimitStoreError::InvalidShape(db.message().to_owned()))
            }
            Err(e) => Err(RateLimitStoreError::Sqlx(e)),
        }
    }

    async fn get(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, scope, scope_value,
                    bucket_capacity, refill_per_second, action,
                    created_at, updated_at
               FROM rate_limit_policies
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| row_to_policy(&r)).transpose()
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<RateLimitPolicy>, RateLimitStoreError> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, scope, scope_value,
                    bucket_capacity, refill_per_second, action,
                    created_at, updated_at
               FROM rate_limit_policies
              WHERE tenant_id = $1
              ORDER BY created_at ASC, id ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_policy).collect()
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        bucket_capacity: Option<i32>,
        refill_per_second: Option<f64>,
    ) -> Result<Option<RateLimitPolicy>, RateLimitStoreError> {
        // COALESCE keeps each column untouched when the input is
        // None — single round-trip regardless of which subset of
        // fields the caller wants to change. updated_at is
        // bumped by the trigger.
        let row = sqlx::query(
            r#"
            UPDATE rate_limit_policies
               SET bucket_capacity   = COALESCE($3, bucket_capacity),
                   refill_per_second = COALESCE($4, refill_per_second)
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, name, scope, scope_value,
                      bucket_capacity, refill_per_second, action,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(bucket_capacity)
        .bind(refill_per_second)
        .fetch_optional(&self.pool)
        .await
        .map_err(RateLimitStoreError::Sqlx)?;
        row.map(|r| row_to_policy(&r)).transpose()
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RateLimitStoreError> {
        let n = sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n > 0)
    }

    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, RateLimitStoreError> {
        let n = sqlx::query("DELETE FROM rate_limit_policies WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }
}

fn row_to_policy(r: &sqlx::postgres::PgRow) -> Result<RateLimitPolicy, RateLimitStoreError> {
    let scope_str: String = r.get("scope");
    let action_str: String = r.get("action");
    let scope = parse_scope(&scope_str)?;
    let action = parse_action(&action_str)?;
    Ok(RateLimitPolicy {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        scope,
        scope_value: r.get("scope_value"),
        bucket_capacity: r.get("bucket_capacity"),
        refill_per_second: r.get("refill_per_second"),
        action,
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    })
}

fn parse_scope(s: &str) -> Result<QuotaScope, RateLimitStoreError> {
    Ok(match s {
        "tenant" => QuotaScope::Tenant,
        "principal" => QuotaScope::Principal,
        "client" => QuotaScope::Client,
        "server" => QuotaScope::Server,
        "tool" => QuotaScope::Tool,
        other => {
            return Err(RateLimitStoreError::InvalidShape(format!(
                "unknown scope: {other}"
            )))
        }
    })
}

fn parse_action(s: &str) -> Result<QuotaAction, RateLimitStoreError> {
    Ok(match s {
        "call" => QuotaAction::Call,
        "high_risk_call" => QuotaAction::HighRiskCall,
        "cost_bearing" => QuotaAction::CostBearing,
        "discovery" => QuotaAction::Discovery,
        other => {
            return Err(RateLimitStoreError::InvalidShape(format!(
                "unknown action: {other}"
            )))
        }
    })
}
