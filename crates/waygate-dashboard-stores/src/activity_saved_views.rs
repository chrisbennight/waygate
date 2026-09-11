//! Per-tenant activity-page saved-views store.
//!
//! The activity / audit-log page (`/admin/t/<tenant>/activity`) is
//! stateless beyond the URL — the only way to recall a filter
//! combo today is to bookmark every shape. Compliance + on-call
//! operators iterate by reapplying the SAME combos repeatedly
//! ("today's high-risk denials", "this week's PII calls from the
//! contractor groups"). Saved views let an operator name a filter
//! combo, surface it in a sidebar, and re-load it by URL
//! (`/activity?load_view=<name>`).
//!
//! This crate is a small per-domain home for the trait +
//! Postgres impl — the pattern the workspace's `waygate-rbac`,
//! `waygate-scim`, `waygate-tenants`, `playground_scenarios`,
//! and `scim_provisioning_log` stores already follow — so
//! that `waygate-admin`'s main deps don't need to pull in `sqlx`
//! directly for one read/write surface. No runtime path consults
//! the table; saved views are a dashboard-only concept and the
//! trait keeps `waygate-admin` free of any direct storage
//! dependency.
//!
//! ## Trait + Postgres impl
//!
//! [`ActivitySavedViewStore`] is the small read/write surface:
//! `list` / `get` / `save` / `delete`. The Postgres impl
//! ([`PgActivitySavedViewStore`]) is a thin wrapper over the
//! `activity_saved_views` table from migration 0036.
//!
//! Save semantics are upsert-by-(tenant,name) with a SQL-side
//! shallow JSONB merge on conflict (`filters || EXCLUDED.filters`):
//! submitted keys win, unknown forward-compat keys already on the
//! row survive, and the merge is atomic inside the statement so no
//! caller needs a read-modify-write (which would open a race
//! window). `playground_scenarios` mirrors this contract. The
//! trigger on `updated_at` keeps the freshness signal accurate.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;

/// One saved activity-page view. Mirrors an `activity_saved_views`
/// row. The opaque `filters` JSON is the activity-page filter
/// snapshot — the dashboard layer owns its shape (outcome / risk
/// / server / principal / category / pii / since). The Postgres
/// layer stays schema-agnostic so a future facet addition doesn't
/// require a migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedView {
    pub tenant_id: String,
    pub name: String,
    pub filters: Value,
    /// Principal `sub` at save time, when present. Nullable so
    /// dev-mode (no authenticated principal) doesn't fail to
    /// save.
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SavedView {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            filters: row.try_get("filters")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SavedViewError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("saved view name must be 1-64 characters; got {0} characters")]
    NameLength(usize),
    #[error("saved view name must match [a-zA-Z0-9 _-]+ (got {0:?})")]
    NameShape(String),
}

/// Compile-time bound on the name length the dashboard accepts.
/// Wide enough for any operator-friendly label, narrow enough
/// that the URL-encoded form (`?load_view=<name>`) stays well
/// below the typical 2048-byte URL ceiling.
const NAME_MAX_LEN: usize = 64;

/// Validate a name the dashboard would persist or query. Returns
/// `Ok` for the canonical operator-friendly shape
/// (`high-risk-denials`, `Contractor PII Calls`); rejects empty,
/// over-length, or names containing characters that would
/// require URL encoding past the simple `?load_view=<name>`
/// round-trip. Same posture as
/// `waygate_dashboard_stores::playground_scenarios::validate_name` — kept as a
/// separate copy rather than a shared crate so the two
/// dashboard-only concepts can drift independently if their
/// labelling conventions diverge.
pub fn validate_name(name: &str) -> Result<(), SavedViewError> {
    let len = name.chars().count();
    if len == 0 || len > NAME_MAX_LEN {
        return Err(SavedViewError::NameLength(len));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-'));
    if !ok {
        return Err(SavedViewError::NameShape(name.to_owned()));
    }
    Ok(())
}

#[async_trait]
pub trait ActivitySavedViewStore: Send + Sync + 'static {
    /// List all saved views for the tenant, alphabetised by name
    /// for stable rendering on the sidebar.
    async fn list(&self, tenant_id: &str) -> Result<Vec<SavedView>, SavedViewError>;
    /// Fetch one saved view by name. `Ok(None)` when absent — the
    /// dashboard handler maps this to the "no view named X" empty
    /// state without 404-ing the page.
    async fn get(&self, tenant_id: &str, name: &str) -> Result<Option<SavedView>, SavedViewError>;
    /// Upsert-by-name with an atomic top-level JSONB merge on
    /// overwrite: submitted keys win, existing keys not in
    /// `filters` survive (forward-compat for fields a newer
    /// dashboard version wrote). Callers therefore pass ONLY the
    /// fields they own — no pre-read needed. Caller passes the
    /// operator's principal `sub` as `created_by` when
    /// authenticated; pass `None` for dev mode. The trigger bumps
    /// `updated_at` on every overwrite.
    async fn save(
        &self,
        tenant_id: &str,
        name: &str,
        filters: Value,
        created_by: Option<&str>,
    ) -> Result<SavedView, SavedViewError>;
    /// Delete by name. Returns `true` when a row was removed,
    /// `false` when the name didn't exist in the tenant — the
    /// dashboard treats both as idempotent success.
    async fn delete(&self, tenant_id: &str, name: &str) -> Result<bool, SavedViewError>;
}

pub struct PgActivitySavedViewStore {
    pool: PgPool,
}

impl PgActivitySavedViewStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ActivitySavedViewStore for PgActivitySavedViewStore {
    async fn list(&self, tenant_id: &str) -> Result<Vec<SavedView>, SavedViewError> {
        let rows = sqlx::query_as::<_, SavedView>(
            r#"
            SELECT tenant_id, name, filters, created_by, created_at, updated_at
              FROM activity_saved_views
             WHERE tenant_id = $1
             ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn get(&self, tenant_id: &str, name: &str) -> Result<Option<SavedView>, SavedViewError> {
        validate_name(name)?;
        let row = sqlx::query_as::<_, SavedView>(
            r#"
            SELECT tenant_id, name, filters, created_by, created_at, updated_at
              FROM activity_saved_views
             WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn save(
        &self,
        tenant_id: &str,
        name: &str,
        filters: Value,
        created_by: Option<&str>,
    ) -> Result<SavedView, SavedViewError> {
        validate_name(name)?;
        // Upsert-by-name with a SQL-side shallow JSONB merge on
        // conflict. The merge MUST happen in the conflict
        // resolution (Postgres applies
        // `activity_saved_views.filters || EXCLUDED.filters`
        // inside the same statement), not as an application-layer
        // read-modify-write — the latter opens a race window
        // where a concurrent re-save of the same name can clobber
        // a freshly-written unknown key between the read and the
        // write.
        //
        // Merge semantics (`jsonb || jsonb`, top-level shallow):
        // every key in the existing row survives unless EXCLUDED
        // overrides it with a new value. So unknown forward-
        // compat keys carry through untouched (they aren't in
        // EXCLUDED), and known keys the caller submitted win
        // (their values are in EXCLUDED). This is the contract
        // tests + the dashboard form handler depend on.
        //
        // `created_by` follows COALESCE so an overwrite from a
        // fresh session attaches the new operator only when the
        // previous row didn't already carry one (avoids
        // overwriting authorship attribution on routine re-saves).
        let row = sqlx::query_as::<_, SavedView>(
            r#"
            INSERT INTO activity_saved_views (tenant_id, name, filters, created_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, name) DO UPDATE
                SET filters = activity_saved_views.filters || EXCLUDED.filters,
                    created_by = COALESCE(activity_saved_views.created_by, EXCLUDED.created_by)
            RETURNING tenant_id, name, filters, created_by, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(filters)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete(&self, tenant_id: &str, name: &str) -> Result<bool, SavedViewError> {
        validate_name(name)?;
        let result =
            sqlx::query(r#"DELETE FROM activity_saved_views WHERE tenant_id = $1 AND name = $2"#)
                .bind(tenant_id)
                .bind(name)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_allows_canonical_operator_labels() {
        for ok in [
            "high-risk-denials",
            "Contractor PII Calls",
            "ops_review_2026",
            "x",
        ] {
            assert!(validate_name(ok).is_ok(), "{ok:?} should be valid");
        }
    }

    #[test]
    fn name_rejects_empty() {
        assert!(matches!(
            validate_name(""),
            Err(SavedViewError::NameLength(0))
        ));
    }

    #[test]
    fn name_rejects_over_length() {
        let too_long = "a".repeat(65);
        assert!(matches!(
            validate_name(&too_long),
            Err(SavedViewError::NameLength(65))
        ));
    }

    #[test]
    fn name_rejects_url_unsafe_chars() {
        for bad in ["high?", "send/msg", "deny#1", "x=y"] {
            assert!(
                matches!(validate_name(bad), Err(SavedViewError::NameShape(_))),
                "{bad:?} should be invalid",
            );
        }
    }
}
