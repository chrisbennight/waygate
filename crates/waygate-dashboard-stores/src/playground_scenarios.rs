//! Per-tenant playground saved-scenarios store.
//!
//! The Cedar policy playground page is stateless by default —
//! each visit requires the operator to retype every form value.
//! This lets an operator name and save the current PARC inputs
//! (principal/action/resource/context) so they can re-run the
//! same scenario after each policy edit, surface a small library
//! of canonical "regression scenarios" per tenant, and share
//! repro setups by URL (`/playground?load=<name>`).
//!
//! This crate is a small per-domain home for the trait +
//! Postgres impl — the pattern the workspace's `waygate-rbac`,
//! `waygate-scim`, and `waygate-tenants` stores already follow —
//! so that `waygate-admin`'s main deps don't need to pull in
//! `sqlx` directly for one read/write surface. No runtime path
//! consults the table; saved scenarios are a dashboard-only
//! concept, on the same level as the command palette or the
//! activity facet sidebar, and the trait keeps `waygate-admin`
//! free of any direct storage dependency.
//!
//! ## Trait + Postgres impl
//!
//! [`PlaygroundScenarioStore`] is the small read/write surface:
//! `list` / `get` / `save` / `delete`. The Postgres impl
//! ([`PgPlaygroundScenarioStore`]) is a thin wrapper over the
//! `playground_scenarios` table from migration 0034.
//!
//! Save semantics are upsert-by-(tenant,name) with a SQL-side
//! shallow JSONB merge on conflict (`body || EXCLUDED.body`) —
//! the same atomic forward-compat contract as
//! `activity_saved_views`: known keys the caller submits win,
//! unknown keys already on the row survive, and the merge
//! happens inside the statement so no read-modify-write race
//! exists in any caller. The trigger on `updated_at` keeps the
//! freshness signal accurate.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;

/// One saved playground scenario. Mirrors a `playground_scenarios`
/// row. The opaque `body` JSON is the form snapshot — the
/// dashboard layer owns its shape (sub / groups / scopes / action
/// / resource / etc.). The Postgres layer stays schema-agnostic
/// so a future form field doesn't require a migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub tenant_id: String,
    pub name: String,
    pub body: Value,
    /// Principal `sub` at save time, when present. Nullable so
    /// dev-mode (no authenticated principal) doesn't fail to
    /// save.
    pub created_by: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for Scenario {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            body: row.try_get("body")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("scenario name must be 1-64 characters; got {0} characters")]
    NameLength(usize),
    #[error("scenario name must match [a-zA-Z0-9 _-]+ (got {0:?})")]
    NameShape(String),
}

/// Compile-time bound on the name length the dashboard accepts.
/// Wide enough for any operator-friendly label, narrow enough
/// that the URL-encoded form (`?load=<name>`) stays well below
/// the typical 2048-byte URL ceiling.
const NAME_MAX_LEN: usize = 64;

/// Validate a name the dashboard would persist or query. Returns
/// `Ok` for the canonical operator-friendly shape
/// (`alice-deny-send`, `Service Account ALLOW`); rejects empty,
/// over-length, or names containing characters that would
/// require URL encoding past the simple `?load=<name>` round-trip
/// (the URL is operator-visible — special characters there are
/// confusing more than functionally wrong).
pub fn validate_name(name: &str) -> Result<(), ScenarioError> {
    let len = name.chars().count();
    if len == 0 || len > NAME_MAX_LEN {
        return Err(ScenarioError::NameLength(len));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-'));
    if !ok {
        return Err(ScenarioError::NameShape(name.to_owned()));
    }
    Ok(())
}

#[async_trait]
pub trait PlaygroundScenarioStore: Send + Sync + 'static {
    /// List all scenarios for the tenant, alphabetised by name
    /// for stable rendering on the sidebar.
    async fn list(&self, tenant_id: &str) -> Result<Vec<Scenario>, ScenarioError>;
    /// Fetch one scenario by name. `Ok(None)` when absent — the
    /// dashboard handler maps this to the "no scenario named X"
    /// empty state without 404-ing the page.
    async fn get(&self, tenant_id: &str, name: &str) -> Result<Option<Scenario>, ScenarioError>;
    /// Upsert-by-name with an atomic top-level JSONB merge on
    /// overwrite: submitted keys win, existing keys not in
    /// `body` survive (forward-compat for fields a newer
    /// dashboard version wrote). Callers therefore pass ONLY the
    /// fields they own — no pre-read needed. Caller passes the
    /// operator's principal `sub` as `created_by` when
    /// authenticated; pass `None` for dev mode. The trigger
    /// bumps `updated_at` on every overwrite.
    async fn save(
        &self,
        tenant_id: &str,
        name: &str,
        body: Value,
        created_by: Option<&str>,
    ) -> Result<Scenario, ScenarioError>;
    /// Delete by name. Returns `true` when a row was removed,
    /// `false` when the name didn't exist in the tenant — the
    /// dashboard treats both as idempotent success.
    async fn delete(&self, tenant_id: &str, name: &str) -> Result<bool, ScenarioError>;
}

pub struct PgPlaygroundScenarioStore {
    pool: PgPool,
}

impl PgPlaygroundScenarioStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PlaygroundScenarioStore for PgPlaygroundScenarioStore {
    async fn list(&self, tenant_id: &str) -> Result<Vec<Scenario>, ScenarioError> {
        let rows = sqlx::query_as::<_, Scenario>(
            r#"
            SELECT tenant_id, name, body, created_by, created_at, updated_at
              FROM playground_scenarios
             WHERE tenant_id = $1
             ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn get(&self, tenant_id: &str, name: &str) -> Result<Option<Scenario>, ScenarioError> {
        validate_name(name)?;
        let row = sqlx::query_as::<_, Scenario>(
            r#"
            SELECT tenant_id, name, body, created_by, created_at, updated_at
              FROM playground_scenarios
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
        body: Value,
        created_by: Option<&str>,
    ) -> Result<Scenario, ScenarioError> {
        validate_name(name)?;
        // Upsert-by-name with a SQL-side shallow JSONB merge on
        // conflict — mirrors `activity_saved_views`. The merge
        // MUST happen in the conflict resolution (`body ||
        // EXCLUDED.body`, top-level shallow), not as an
        // application-layer read-modify-write — the latter opens
        // a race where a concurrent same-name save can clobber a
        // freshly-written unknown key between the read and the
        // write. Merging inside the conflict resolution is
        // atomic: submitted keys win, unknown forward-compat
        // keys survive, and callers no longer pre-read.
        //
        // `created_at` stays anchored to the original save; the
        // trigger bumps `updated_at`. `created_by` follows
        // COALESCE semantics so an overwrite from a fresh
        // session attaches the new operator only when the
        // previous row didn't already carry one (avoids
        // overwriting authorship attribution on routine
        // re-saves).
        let row = sqlx::query_as::<_, Scenario>(
            r#"
            INSERT INTO playground_scenarios (tenant_id, name, body, created_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, name) DO UPDATE
                SET body = playground_scenarios.body || EXCLUDED.body,
                    created_by = COALESCE(playground_scenarios.created_by, EXCLUDED.created_by)
            RETURNING tenant_id, name, body, created_by, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(body)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn delete(&self, tenant_id: &str, name: &str) -> Result<bool, ScenarioError> {
        validate_name(name)?;
        let result =
            sqlx::query(r#"DELETE FROM playground_scenarios WHERE tenant_id = $1 AND name = $2"#)
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
            "alice-deny-send",
            "Service Account ALLOW",
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
            Err(ScenarioError::NameLength(0))
        ));
    }

    #[test]
    fn name_rejects_over_length() {
        let too_long = "a".repeat(65);
        assert!(matches!(
            validate_name(&too_long),
            Err(ScenarioError::NameLength(65))
        ));
    }

    #[test]
    fn name_rejects_url_unsafe_chars() {
        for bad in ["alice?", "send/msg", "deny#1", "x=y", "with/slash"] {
            assert!(
                matches!(validate_name(bad), Err(ScenarioError::NameShape(_))),
                "{bad:?} should be invalid",
            );
        }
    }
}
