//! Per-tenant per-category audit_log retention POLICY STORAGE.
//!
//! This module is scoped to policy storage only: the policy
//! table CRUD + the pure [`resolve_policy`] precedence helper.
//! Enforcement — the sweep that actually DELETEs old rows and
//! the audit_log trigger bypass it needs — lives in
//! [`crate::sweep`], kept separate because its
//! security-sensitive design (chain-aware verification with
//! documented gap markers, SECURITY DEFINER + separate Postgres
//! role for the function owner) stands on its own.
//!
//! The configuration surface:
//!
//! - `GET / PUT / DELETE /api/v1/audit/retention` admin endpoints
//! - `evidence_retention_policy` table backing them
//!
//! ## Resolution semantics
//!
//! Most-specific match wins:
//!
//! - `(tenant=acme, category=invocation)` row beats
//!   `(acme, *)` for invocation rows.
//! - `(acme, *)` applies to any acme category that doesn't
//!   have an explicit row.
//! - Wildcard `*` is per-tenant only — no cross-tenant
//!   fallback. Each tenant's data is governed by that
//!   tenant's own policies.
//! - No matching policy ⇒ no deletion (retain indefinitely).
//!
//! The [`resolve_policy`] helper implements this precedence
//! and is unit-tested; the sweep consumes it at sweep time.

use time::OffsetDateTime;

/// Resolve a retention policy's relative day count into an absolute cutoff.
///
/// Stored policies are database `INT` values, whose positive range is wider
/// than [`OffsetDateTime`] can represent. Callers must treat `None` as an
/// invalid policy instead of subtracting with the panicking `Sub` operator.
pub fn retention_cutoff(now: OffsetDateTime, delete_after_days: i32) -> Option<OffsetDateTime> {
    now.checked_sub(time::Duration::days(i64::from(delete_after_days)))
}

/// One policy row, as returned by [`RetentionStore::list`] and
/// consumed by the sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub tenant_id: String,
    /// `'*'` is the wildcard. Otherwise an
    /// `EvidenceCategory.as_str()` value (`"invocation"`,
    /// `"admin_mutation"`, etc.).
    pub category: String,
    pub delete_after_days: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for RetentionPolicy {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            category: row.try_get("category")?,
            delete_after_days: row.try_get("delete_after_days")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Admin-side CRUD trait. Same pattern as
/// [`crate::routing::RoutingStore`] — kept separate from
/// `AuditReader` so admin state wires retention independently.
#[async_trait::async_trait]
pub trait RetentionStore: Send + Sync + 'static {
    async fn list(&self, tenant_id: Option<&str>) -> Result<Vec<RetentionPolicy>, sqlx::Error>;
    async fn upsert(
        &self,
        tenant_id: &str,
        category: &str,
        delete_after_days: i32,
    ) -> Result<RetentionPolicy, sqlx::Error>;
    async fn delete(&self, tenant_id: &str, category: &str) -> Result<bool, sqlx::Error>;
}

/// Postgres-backed [`RetentionStore`].
pub struct PgRetentionStore {
    pool: sqlx::PgPool,
}

impl PgRetentionStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

/// Serialise policy mutation with policy-authorised sweeps for one tenant.
/// The two-key advisory-lock namespace is distinct from the single-key tenant
/// chain lock used by the audit recorder.
pub(crate) async fn lock_tenant_policy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('audit_retention_policy'), hashtext($1))")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl RetentionStore for PgRetentionStore {
    async fn list(&self, tenant_id: Option<&str>) -> Result<Vec<RetentionPolicy>, sqlx::Error> {
        match tenant_id {
            Some(t) => {
                sqlx::query_as::<_, RetentionPolicy>(
                    r#"
                    SELECT tenant_id, category, delete_after_days,
                           created_at, updated_at
                      FROM evidence_retention_policy
                     WHERE tenant_id = $1
                     ORDER BY category ASC
                    "#,
                )
                .bind(t)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, RetentionPolicy>(
                    r#"
                    SELECT tenant_id, category, delete_after_days,
                           created_at, updated_at
                      FROM evidence_retention_policy
                     ORDER BY tenant_id ASC, category ASC
                    "#,
                )
                .fetch_all(&self.pool)
                .await
            }
        }
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        category: &str,
        delete_after_days: i32,
    ) -> Result<RetentionPolicy, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        lock_tenant_policy(&mut tx, tenant_id).await?;
        let policy = sqlx::query_as::<_, RetentionPolicy>(
            r#"
            INSERT INTO evidence_retention_policy
                (tenant_id, category, delete_after_days, updated_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (tenant_id, category) DO UPDATE
                SET delete_after_days = EXCLUDED.delete_after_days,
                    updated_at        = now()
            RETURNING tenant_id, category, delete_after_days,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(category)
        .bind(delete_after_days)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(policy)
    }

    async fn delete(&self, tenant_id: &str, category: &str) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        lock_tenant_policy(&mut tx, tenant_id).await?;
        let n = sqlx::query(
            r#"
            DELETE FROM evidence_retention_policy
             WHERE tenant_id = $1 AND category = $2
            "#,
        )
        .bind(tenant_id)
        .bind(category)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }
}

/// Pure helper: given a tenant's explicit category policies and
/// its wildcard policy (if any), return the effective policy for
/// a specific `(tenant, category)` pair. Most-specific wins.
///
/// Returns `None` when neither an explicit match nor a wildcard
/// applies — sweep would skip that pair.
///
/// Unit-tested below. The admin sweep endpoint consumes this at
/// sweep time.
pub fn resolve_policy<'a>(
    explicit: &'a [&'a RetentionPolicy],
    wildcard: Option<&'a RetentionPolicy>,
    category: &str,
) -> Option<&'a RetentionPolicy> {
    explicit
        .iter()
        .find(|p| p.category == category)
        .copied()
        .or(wildcard)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(tenant: &str, category: &str, days: i32) -> RetentionPolicy {
        RetentionPolicy {
            tenant_id: tenant.to_owned(),
            category: category.to_owned(),
            delete_after_days: days,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn retention_cutoff_rejects_days_outside_the_timestamp_range() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            retention_cutoff(now, 30),
            Some(now - time::Duration::days(30)),
        );
        assert_eq!(retention_cutoff(now, i32::MAX), None);
    }

    /// Explicit category match beats wildcard.
    #[test]
    fn resolve_explicit_wins_over_wildcard() {
        let inv = p("acme", "invocation", 30);
        let wc = p("acme", "*", 365);
        let explicit = vec![&inv];
        let chosen = resolve_policy(&explicit, Some(&wc), "invocation");
        assert_eq!(chosen.map(|x| x.delete_after_days), Some(30));
    }

    /// Wildcard applies when explicit doesn't match.
    #[test]
    fn resolve_wildcard_applies_to_unlisted_category() {
        let inv = p("acme", "invocation", 30);
        let wc = p("acme", "*", 365);
        let explicit = vec![&inv];
        let chosen = resolve_policy(&explicit, Some(&wc), "admin_mutation");
        assert_eq!(chosen.map(|x| x.delete_after_days), Some(365));
    }

    /// Neither explicit nor wildcard → None (no deletion for that pair).
    #[test]
    fn resolve_no_match_yields_none() {
        let chosen = resolve_policy(&[], None, "invocation");
        assert!(chosen.is_none());
    }

    /// Wildcard only, every category falls under it.
    #[test]
    fn resolve_wildcard_only_covers_any_category() {
        let wc = p("acme", "*", 90);
        assert_eq!(
            resolve_policy(&[], Some(&wc), "invocation").map(|x| x.delete_after_days),
            Some(90),
        );
        assert_eq!(
            resolve_policy(&[], Some(&wc), "data_inspection").map(|x| x.delete_after_days),
            Some(90),
        );
    }

    /// Multiple explicit categories: each picks its own.
    #[test]
    fn resolve_multiple_explicit_matches_independently() {
        let inv = p("acme", "invocation", 30);
        let disc = p("acme", "discovery", 7);
        let explicit = vec![&inv, &disc];
        assert_eq!(
            resolve_policy(&explicit, None, "invocation").map(|x| x.delete_after_days),
            Some(30),
        );
        assert_eq!(
            resolve_policy(&explicit, None, "discovery").map(|x| x.delete_after_days),
            Some(7),
        );
        assert!(resolve_policy(&explicit, None, "admin_mutation").is_none());
    }
}
