//! Scope registry store.
//!
//! Read surface for the `scopes` catalog table — the browsable set of
//! capability strings the gateway knows about: built-in `mcp:*` /
//! `scim:*` (global), policy-referenced (global), and
//! operator-/backfill-`local` (per-tenant). The dashboard Scopes page
//! renders [`ScopeStore::list_with_usage`]; this store also carries the
//! policy-reconcile writer and the mint-time `exists` check.
//!
//! See `migrations/0064_scope_registry.sql` for the storage shape and
//! the global-vs-tenant semantics. This is an authoring/visibility
//! layer only — Cedar still evaluates `principal.scopes` as plain
//! strings, so nothing here is on the request hot path.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

/// One `scopes` row plus how many live things reference it, for the
/// dashboard's "referenced by" column.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeView {
    pub id: Uuid,
    /// `None` ⇒ a global scope (built-in / policy-referenced);
    /// `Some(slug)` ⇒ tenant-local.
    pub tenant_id: Option<String>,
    pub name: String,
    /// `'builtin'` | `'policy'` | `'local'` — the DB CHECK pins these.
    pub source: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// Count of LIVE (non-revoked) `api_keys` in the reading tenant
    /// whose `scopes` array contains `name`.
    pub key_refs: i64,
    /// Count of `gateway_roles` in the reading tenant whose `scopes`
    /// array contains `name`.
    pub role_refs: i64,
}

/// Immutable identity, version, and live-reference counts for a tenant-local
/// scope that may be deleted.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalScopeDeleteTarget {
    pub id: Uuid,
    pub name: String,
    pub updated_at: OffsetDateTime,
    pub key_refs: i64,
    pub role_refs: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ScopeStoreError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A scope with this name is already visible to the tenant — either a
    /// global (built-in / policy) row or an existing tenant-local row. The
    /// admin handler maps this to a 4xx with the name.
    #[error("a scope named `{0}` already exists")]
    Conflict(String),
    #[error("local scope {0} was not found in this tenant")]
    NotFound(Uuid),
    #[error("scope {0} is global or non-local and cannot be deleted")]
    NotLocal(Uuid),
    #[error("local scope {0} changed since it was reviewed")]
    Changed(Uuid),
    #[error("local scope is still referenced by {key_refs} live keys and {role_refs} roles")]
    InUse { key_refs: i64, role_refs: i64 },
}

#[async_trait]
pub trait ScopeStore: Send + Sync {
    /// List every scope visible to `tenant_id` — global rows
    /// (`tenant_id IS NULL`) unioned with this tenant's local rows —
    /// each annotated with how many live api-keys and roles in this
    /// tenant reference it. Ordered by `source` then `name` for a
    /// stable render.
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<ScopeView>, ScopeStoreError>;

    /// Hard-delete every tenant-local scope row for `tenant_id`. Global
    /// rows (`tenant_id IS NULL` — built-in / policy-referenced) are
    /// never touched. Called from the tenant-DELETE cascade in
    /// `waygate-admin::tenants` so a re-created tenant id can't inherit
    /// stale `source='local'` catalog entries (mirrors the
    /// `api_key_profiles` / `rate_limit_policies` cleanup arms). Returns
    /// the number of rows deleted.
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ScopeStoreError>;

    /// Register `names` as global `source='policy'` scopes (idempotent).
    /// Called by the waygate-server reconcile at boot + on policy reload so
    /// every scope a loaded Cedar policy gates on is in the catalog — even
    /// when no key or built-in carries it — which keeps catalog-only
    /// minting from blocking a policy-required scope. Global
    /// (`tenant_id NULL`) because the Cedar policy set is global. A name
    /// already present as a built-in (or already a policy row) is left
    /// untouched by the global unique index + `ON CONFLICT DO NOTHING`, so
    /// built-ins keep `source='builtin'`. Returns the count newly inserted.
    async fn upsert_policy_scopes(&self, names: &[String]) -> Result<u64, ScopeStoreError>;

    /// Create a tenant-local scope through an operator-authorized admin path
    /// (the dashboard or an approved HITL change request).
    /// Rejects with [`ScopeStoreError::Conflict`] when the name is already
    /// visible to the tenant — a global built-in/policy row OR an existing
    /// tenant-local row — so the catalog keeps one entry per scope name per
    /// tenant view.
    async fn create_local(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), ScopeStoreError>;

    /// Load a visible scope by id and require it to be a local row owned by
    /// `tenant_id`, including current reference counts for proposal review.
    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<LocalScopeDeleteTarget, ScopeStoreError>;

    /// Delete a tenant-local scope only when its reviewed version is still
    /// current and no live API key or role references its name. The target row
    /// is locked before the final checks and delete.
    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), ScopeStoreError>;

    /// Return the subset of `names` NOT visible to `tenant_id` — i.e. names
    /// with neither a global (built-in/policy) row nor a tenant-local row.
    /// Used by catalog-only mint enforcement: a non-empty result means
    /// the mint must be rejected. Order-preserving and deduplicated is not
    /// guaranteed; the caller only checks emptiness + renders the list.
    async fn unknown_scopes(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, ScopeStoreError>;
}

/// Postgres-backed [`ScopeStore`].
pub struct PgScopeStore {
    pool: PgPool,
}

impl PgScopeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScopeStore for PgScopeStore {
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<ScopeView>, ScopeStoreError> {
        // Per-scope reference counts via correlated subqueries.
        // `jsonb_exists(arr, name)` is the function form of the JSONB
        // `?` operator — it sidesteps the `?` placeholder ambiguity the
        // driver trips on, and checks element membership for an array
        // of strings (guarded by `jsonb_typeof = 'array'` so a stray
        // scalar can't false-match). Roles store scopes as TEXT[], so
        // `= ANY(...)`. Fine for the handful of scopes a homelab runs;
        // this is a read-only governance view, not a hot path.
        let rows = sqlx::query(
            r#"
            SELECT s.id, s.tenant_id, s.name, s.source, s.description,
                   s.created_at, s.updated_at,
                   (SELECT count(*) FROM api_keys k
                     WHERE k.tenant_id = $1
                       AND k.revoked_at IS NULL
                       AND jsonb_typeof(k.scopes) = 'array'
                       AND jsonb_exists(k.scopes, s.name)) AS key_refs,
                   (SELECT count(*) FROM gateway_roles r
                     WHERE r.tenant_id = $1
                       AND s.name = ANY(r.scopes)) AS role_refs
              FROM scopes s
             WHERE s.tenant_id IS NULL OR s.tenant_id = $1
             ORDER BY s.source ASC, s.name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_view).collect())
    }

    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ScopeStoreError> {
        // `tenant_id = $1` matches only this tenant's local rows; a
        // global row's NULL tenant_id never equals a slug, so built-in
        // and policy-referenced scopes survive a tenant delete.
        let n = sqlx::query("DELETE FROM scopes WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    async fn upsert_policy_scopes(&self, names: &[String]) -> Result<u64, ScopeStoreError> {
        if names.is_empty() {
            return Ok(0);
        }
        // `NULL::text` = global. `ON CONFLICT DO NOTHING` against the global
        // unique index (`scopes_global_name_uq`) means a name that's already
        // a built-in or policy row is a no-op — built-ins keep their source.
        let n = sqlx::query(
            r#"
            INSERT INTO scopes (tenant_id, name, source)
            SELECT NULL::text, n, 'policy' FROM unnest($1::text[]) AS n
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(names)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n)
    }

    async fn create_local(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), ScopeStoreError> {
        // Insert only if the name isn't already visible to the tenant: a
        // global built-in/policy row (which the tenant-local unique index
        // can't see) OR an existing tenant-local row. The `WHERE NOT EXISTS`
        // handles the global-dup case; a concurrent tenant-local dup that
        // slips past it trips the unique index (23505) — both map to Conflict.
        let res = sqlx::query(
            r#"
            INSERT INTO scopes (tenant_id, name, source, description)
            SELECT $1, $2, 'local', $3
            WHERE NOT EXISTS (
                SELECT 1 FROM scopes
                 WHERE name = $2 AND (tenant_id IS NULL OR tenant_id = $1)
            )
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .execute(&self.pool)
        .await;
        match res {
            Ok(r) if r.rows_affected() == 1 => Ok(()),
            Ok(_) => Err(ScopeStoreError::Conflict(name.to_owned())),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(ScopeStoreError::Conflict(name.to_owned()))
            }
            Err(e) => Err(ScopeStoreError::Sqlx(e)),
        }
    }

    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<LocalScopeDeleteTarget, ScopeStoreError> {
        let row = sqlx::query(
            r#"
            SELECT s.id, s.tenant_id, s.name, s.source, s.updated_at,
                   (SELECT count(*) FROM api_keys k
                     WHERE k.tenant_id = $1
                       AND k.revoked_at IS NULL
                       AND jsonb_typeof(k.scopes) = 'array'
                       AND jsonb_exists(k.scopes, s.name)) AS key_refs,
                   (SELECT count(*) FROM gateway_roles r
                     WHERE r.tenant_id = $1
                       AND s.name = ANY(r.scopes)) AS role_refs
              FROM scopes s
             WHERE s.id = $2
               AND (s.tenant_id IS NULL OR s.tenant_id = $1)
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ScopeStoreError::NotFound(id))?;
        if row.get::<Option<String>, _>("tenant_id").as_deref() != Some(tenant_id)
            || row.get::<String, _>("source") != "local"
        {
            return Err(ScopeStoreError::NotLocal(id));
        }
        Ok(LocalScopeDeleteTarget {
            id: row.get("id"),
            name: row.get("name"),
            updated_at: row.get("updated_at"),
            key_refs: row.get("key_refs"),
            role_refs: row.get("role_refs"),
        })
    }

    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), ScopeStoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT tenant_id, name, source, updated_at
              FROM scopes
             WHERE id = $2 AND (tenant_id IS NULL OR tenant_id = $1)
             FOR UPDATE
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ScopeStoreError::NotFound(id))?;
        if row.get::<Option<String>, _>("tenant_id").as_deref() != Some(tenant_id)
            || row.get::<String, _>("source") != "local"
        {
            return Err(ScopeStoreError::NotLocal(id));
        }
        if row.get::<String, _>("name") != expected_name
            || row.get::<OffsetDateTime, _>("updated_at") != expected_updated_at
        {
            return Err(ScopeStoreError::Changed(id));
        }

        // Roles intentionally accept free-form scope strings, so they cannot
        // take a foreign-key-style lock on this catalog row. Serialize their
        // writes at the table boundary instead: a role write that started
        // first commits before the reference check; one that starts after this
        // lock is ordered after deletion and retains the documented free-form
        // behavior.
        sqlx::query("LOCK TABLE gateway_roles IN SHARE MODE")
            .execute(&mut *tx)
            .await?;

        let refs = sqlx::query(
            r#"
            SELECT (SELECT count(*) FROM api_keys k
                     WHERE k.tenant_id = $1
                       AND k.revoked_at IS NULL
                       AND jsonb_typeof(k.scopes) = 'array'
                       AND jsonb_exists(k.scopes, $2)) AS key_refs,
                   (SELECT count(*) FROM gateway_roles r
                     WHERE r.tenant_id = $1
                       AND $2 = ANY(r.scopes)) AS role_refs
            "#,
        )
        .bind(tenant_id)
        .bind(expected_name)
        .fetch_one(&mut *tx)
        .await?;
        let key_refs = refs.get("key_refs");
        let role_refs = refs.get("role_refs");
        if key_refs != 0 || role_refs != 0 {
            return Err(ScopeStoreError::InUse {
                key_refs,
                role_refs,
            });
        }

        let deleted = sqlx::query(
            r#"
            DELETE FROM scopes
             WHERE tenant_id = $1 AND id = $2 AND source = 'local'
               AND name = $3 AND updated_at = $4
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected_name)
        .bind(expected_updated_at)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if deleted != 1 {
            return Err(ScopeStoreError::Changed(id));
        }
        tx.commit().await?;
        Ok(())
    }

    async fn unknown_scopes(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, ScopeStoreError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        // Each requested name that has neither a global (tenant_id IS NULL)
        // nor a tenant-local row is "unknown".
        let unknown: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT n FROM unnest($2::text[]) AS n
             WHERE NOT EXISTS (
                 SELECT 1 FROM scopes s
                  WHERE s.name = n AND (s.tenant_id IS NULL OR s.tenant_id = $1)
             )
            "#,
        )
        .bind(tenant_id)
        .bind(names)
        .fetch_all(&self.pool)
        .await?;
        Ok(unknown)
    }
}

fn row_to_view(r: &sqlx::postgres::PgRow) -> ScopeView {
    ScopeView {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        source: r.get("source"),
        description: r.get("description"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        key_refs: r.get("key_refs"),
        role_refs: r.get("role_refs"),
    }
}
