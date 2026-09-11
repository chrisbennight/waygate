//! Canonical tenant registry.
//!
//! Backs migration `0024_tenants.sql`. Provides the
//! [`TenantStore`] trait + [`PgTenantStore`] for the admin REST
//! CRUD at `/api/v1/admin/tenants/*` (the handler lives in
//! `waygate-admin`).
//!
//! ## Why a separate crate
//!
//! Same pattern as `waygate-scim` and `waygate-rbac`: domain
//! types + a store trait that the admin layer consumes. Keeps
//! the storage details out of `waygate-admin` (which already
//! depends on too many things) and leaves room for a future
//! tenant-resolver that the bearer middleware could call to
//! enforce "tenant must exist + status=active" — that lives in
//! `waygate-oidc`-or-similar and doesn't need to drag the
//! admin crate into the bearer hot path.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;

mod enforce;
pub use enforce::{
    PgTenantEnricher, PgTenantResolver, TenantLookup, TenantResolveError, TenantResolver,
};

/// One tenant. Mirrors a `tenants` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow, utoipa::ToSchema)]
pub struct Tenant {
    pub id: String,
    pub display_name: String,
    /// `"active"` or `"suspended"`. Stored as plain TEXT with a
    /// CHECK constraint at the SQL layer; the [`TenantStatus`]
    /// enum below is the typed boundary the admin handler uses.
    pub status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Typed status enum the admin handler uses on input/update. The
/// SQL column is TEXT + CHECK so a typo can't quietly land a row
/// in some unexpected state; this enum keeps the boundary
/// validated at parse time too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// PG `23505` (unique violation) — tenant id collides with
    /// an existing row. Admin handler translates to HTTP 409.
    #[error("conflict: {0}")]
    Conflict(String),
    /// CHECK constraint violation on `status` (impossible if
    /// callers use the [`TenantStatus`] enum, but guarded
    /// against operators reaching for raw SQL).
    #[error("invalid status: {0}")]
    InvalidStatus(String),
}

/// Read + write surface the admin handler consumes. Trait shape
/// leaves room for a fake in tests + future non-Postgres
/// backends without touching `waygate-admin`.
#[async_trait]
pub trait TenantStore: Send + Sync {
    /// Create a tenant. Fails with [`TenantError::Conflict`] on
    /// duplicate id.
    async fn create(
        &self,
        id: &str,
        display_name: &str,
        status: TenantStatus,
    ) -> Result<Tenant, TenantError>;

    /// Fetch a single tenant by id. `Ok(None)` when not found.
    async fn get(&self, id: &str) -> Result<Option<Tenant>, TenantError>;

    /// List every tenant, alphabetised by id for stable
    /// dashboard rendering.
    async fn list(&self) -> Result<Vec<Tenant>, TenantError>;

    /// Update mutable fields. Either `display_name` or `status`
    /// can be `None` to leave the existing value alone. `Ok(None)`
    /// when the id doesn't exist.
    async fn update(
        &self,
        id: &str,
        display_name: Option<&str>,
        status: Option<TenantStatus>,
    ) -> Result<Option<Tenant>, TenantError>;

    /// Delete only the canonical registry row. Cross-domain lifecycle callers
    /// that also own tenant-scoped resources must coordinate those mutations
    /// atomically in their composition layer.
    async fn delete(&self, id: &str) -> Result<bool, TenantError>;
}

/// Postgres-backed store. Trivial one-query implementations for
/// each method — no chained tables, no triggers.
pub struct PgTenantStore {
    pool: PgPool,
}

impl PgTenantStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantStore for PgTenantStore {
    async fn create(
        &self,
        id: &str,
        display_name: &str,
        status: TenantStatus,
    ) -> Result<Tenant, TenantError> {
        match sqlx::query_as::<_, Tenant>(
            r#"
            INSERT INTO tenants (id, display_name, status)
            VALUES ($1, $2, $3)
            RETURNING id, display_name, status, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(display_name)
        .bind(status.as_str())
        .fetch_one(&self.pool)
        .await
        {
            Ok(t) => Ok(t),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(TenantError::Conflict(format!(
                    "tenant `{id}` already exists"
                )))
            }
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::CHECK_VIOLATION) =>
            {
                Err(TenantError::InvalidStatus(db.message().to_owned()))
            }
            Err(e) => Err(TenantError::Sqlx(e)),
        }
    }

    async fn get(&self, id: &str) -> Result<Option<Tenant>, TenantError> {
        sqlx::query_as::<_, Tenant>(
            r#"
            SELECT id, display_name, status, created_at, updated_at
              FROM tenants
             WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(TenantError::Sqlx)
    }

    async fn list(&self) -> Result<Vec<Tenant>, TenantError> {
        sqlx::query_as::<_, Tenant>(
            r#"
            SELECT id, display_name, status, created_at, updated_at
              FROM tenants
             ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(TenantError::Sqlx)
    }

    async fn update(
        &self,
        id: &str,
        display_name: Option<&str>,
        status: Option<TenantStatus>,
    ) -> Result<Option<Tenant>, TenantError> {
        // `COALESCE($n, column)` keeps the column untouched when
        // the input is None — single round-trip regardless of
        // which subset of fields the caller wants to change.
        // updated_at is bumped by the trigger.
        let status_str = status.map(|s| s.as_str().to_owned());
        match sqlx::query_as::<_, Tenant>(
            r#"
            UPDATE tenants
               SET display_name = COALESCE($2, display_name),
                   status       = COALESCE($3, status)
             WHERE id = $1
            RETURNING id, display_name, status, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(display_name)
        .bind(status_str)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(opt) => Ok(opt),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::CHECK_VIOLATION) =>
            {
                Err(TenantError::InvalidStatus(db.message().to_owned()))
            }
            Err(e) => Err(TenantError::Sqlx(e)),
        }
    }

    async fn delete(&self, id: &str) -> Result<bool, TenantError> {
        let mut tx = self.pool.begin().await.map_err(TenantError::Sqlx)?;
        // Tenant deletion intentionally removes its Code Mode history. The
        // journal's append-only trigger admits that cascade only when the
        // deleting transaction declares this narrow retention authority.
        sqlx::query("SET LOCAL app.codemode_retention_delete = 'enabled'")
            .execute(&mut *tx)
            .await
            .map_err(TenantError::Sqlx)?;
        let n = sqlx::query(r#"DELETE FROM tenants WHERE id = $1"#)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(TenantError::Sqlx)?
            .rows_affected();
        tx.commit().await.map_err(TenantError::Sqlx)?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_status_round_trips_through_serde() {
        let s = serde_json::to_string(&TenantStatus::Active).unwrap();
        assert_eq!(s, "\"active\"");
        let parsed: TenantStatus = serde_json::from_str("\"suspended\"").unwrap();
        assert_eq!(parsed, TenantStatus::Suspended);
    }

    #[test]
    fn tenant_status_as_str_matches_check_constraint_values() {
        // Pin: migration 0024 has `CHECK (status IN ('active',
        // 'suspended'))`. If the enum changes here, the check
        // would silently reject inserts; this assertion makes
        // the drift impossible to merge.
        assert_eq!(TenantStatus::Active.as_str(), "active");
        assert_eq!(TenantStatus::Suspended.as_str(), "suspended");
    }
}
