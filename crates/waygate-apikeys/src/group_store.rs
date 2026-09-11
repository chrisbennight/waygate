//! Group catalog read-view.
//!
//! Read surface over the unified `scim_groups` table — both
//! IdP-provisioned SCIM groups (`source='scim'`) and operator/api-key
//! `'local'` groups (migration 0066) — annotating each with its mutable
//! version and how many SCIM users, live api-keys, and role mappings reference
//! it. The dashboard Groups page renders [`GroupStore::list_with_usage`].
//!
//! Distinct from `waygate_scim::ScimGroupStore`, which is the SCIM 2.0
//! CRUD surface (`/scim/v2/Groups`). This store is a cross-domain
//! *read view* for the admin catalog — same pattern as
//! [`crate::scope_store::ScopeStore`], which reads the `scopes`,
//! `api_keys`, and `gateway_roles` tables. API-key group names are
//! catalog-validated at mint time; Cedar evaluates them as
//! `principal.groups`. They are labels for Cedar policy evaluation, not
//! identity membership for RBAC group-to-role mappings.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

/// One `scim_groups` row plus member counts, for the dashboard's
/// "members" column.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupView {
    pub id: Uuid,
    pub tenant_id: String,
    pub display_name: String,
    /// `'scim'` (IdP-provisioned) | `'local'` (operator/api-key label).
    pub source: String,
    /// IdP-assigned external id — `Some` for SCIM groups that carry one,
    /// `None` for local groups (and SCIM groups without one). Surfaced so the
    /// unified Groups page is a superset of the old SCIM-page groups table.
    pub external_id: Option<String>,
    pub created_at: OffsetDateTime,
    /// Mutable row-version witness used by guarded local-group deletion.
    pub updated_at: OffsetDateTime,
    /// SCIM users in this group (via `scim_user_groups`).
    pub user_member_count: i64,
    /// LIVE (non-revoked) api-keys whose `groups` array contains
    /// `display_name`.
    pub key_member_count: i64,
    /// RBAC group-to-role mappings that reference this group.
    pub role_mapping_count: i64,
}

/// Immutable identity plus current references for a tenant-local group that
/// may be deleted. `updated_at` is the row-version witness; SCIM promotion
/// changes it and `source`, both of which the guarded delete rechecks while
/// holding the target row lock.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalGroupDeleteTarget {
    pub id: Uuid,
    pub display_name: String,
    pub updated_at: OffsetDateTime,
    pub user_member_count: i64,
    pub key_member_count: i64,
    pub role_mapping_count: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupStoreError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A group with this display_name already exists in the tenant (SCIM or
    /// local). The admin handler maps this to a 4xx with the name.
    #[error("a group named `{0}` already exists")]
    Conflict(String),
    #[error("local group {0} was not found in this tenant")]
    NotFound(Uuid),
    #[error("group {0} is SCIM-provisioned and cannot be deleted as a local group")]
    NotLocal(Uuid),
    #[error("local group {0} changed since it was reviewed")]
    Changed(Uuid),
    #[error(
        "local group is still referenced by {user_members} users, {key_members} live keys, and {role_mappings} role mappings"
    )]
    InUse {
        user_members: i64,
        key_members: i64,
        role_mappings: i64,
    },
}

#[async_trait]
pub trait GroupStore: Send + Sync {
    /// List every group in `tenant_id` — SCIM and local — annotated with
    /// SCIM-user, api-key, and role-mapping reference counts. Ordered by
    /// `source` then `display_name` for a stable render. Groups are tenant-scoped
    /// (unlike scopes, there are no global groups).
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<GroupView>, GroupStoreError>;

    /// Hard-delete every `source='local'` group for `tenant_id`. SCIM
    /// groups (`source='scim'`) are NOT touched — they follow the
    /// existing compliance-retention policy (see `waygate-admin::
    /// tenants::cleanup_onboarding_residue`). Called from the
    /// tenant-DELETE cascade so a re-created tenant id can't inherit
    /// stale local-group labels. The `scim_user_groups` membership rows
    /// cascade via `ON DELETE CASCADE` (a no-op for local groups, which
    /// have no SCIM-user members). Returns the number of groups deleted.
    async fn delete_all_local_for_tenant(&self, tenant_id: &str) -> Result<u64, GroupStoreError>;

    /// Create a tenant-local group through an operator-authorized admin path
    /// (the dashboard or an approved HITL change request).
    /// Rejects with [`GroupStoreError::Conflict`] when a group with this
    /// `display_name` already exists in the tenant — SCIM or local — via the
    /// `UNIQUE (tenant_id, display_name)` index. (An operator can't shadow a
    /// SCIM-provisioned group; that name already resolves to it.)
    async fn create_local(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<(), GroupStoreError>;

    /// Load a tenant-local group by id with every reference count relevant to
    /// deletion. SCIM groups and cross-tenant ids fail closed.
    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<LocalGroupDeleteTarget, GroupStoreError>;

    /// Delete a tenant-local group only when its reviewed identity is still
    /// current and no SCIM users, live API keys, or RBAC mappings reference
    /// it. The target row is locked before the final checks and delete.
    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_display_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), GroupStoreError>;

    /// Return the subset of `names` NOT present as a group (SCIM or local) in
    /// `tenant_id`. Used by catalog-only mint enforcement: a non-empty
    /// result means the mint must be rejected.
    async fn unknown_groups(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, GroupStoreError>;
}

/// Postgres-backed [`GroupStore`].
pub struct PgGroupStore {
    pool: PgPool,
}

impl PgGroupStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupStore for PgGroupStore {
    async fn list_with_usage(&self, tenant_id: &str) -> Result<Vec<GroupView>, GroupStoreError> {
        // Per-group member counts via correlated subqueries.
        // `jsonb_exists(arr, name)` is the function form of the JSONB `?`
        // operator (sidesteps the `?` placeholder ambiguity), guarded by
        // `jsonb_typeof = 'array'`. Fine for a homelab's handful of
        // groups; this is a read-only governance view, not a hot path.
        let rows = sqlx::query(
            r#"
            SELECT g.id, g.tenant_id, g.display_name, g.source,
                   g.external_id, g.created_at, g.updated_at,
                   (SELECT count(*) FROM scim_user_groups m
                      JOIN scim_users u ON u.id = m.user_id
                     WHERE m.tenant_id = $1 AND m.group_id = g.id
                       AND u.deleted_at IS NULL) AS user_member_count,
                   (SELECT count(*) FROM api_keys k
                     WHERE k.tenant_id = $1
                       AND k.revoked_at IS NULL
                       AND jsonb_typeof(k.groups) = 'array'
                       AND jsonb_exists(k.groups, g.display_name)) AS key_member_count,
                   (SELECT count(*) FROM group_role_mappings m
                     WHERE m.tenant_id = $1 AND m.group_id = g.id) AS role_mapping_count
              FROM scim_groups g
             WHERE g.tenant_id = $1
             ORDER BY g.source ASC, g.display_name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_view).collect())
    }

    async fn delete_all_local_for_tenant(&self, tenant_id: &str) -> Result<u64, GroupStoreError> {
        let n = sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1 AND source = 'local'")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    async fn create_local(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<(), GroupStoreError> {
        // The `UNIQUE (tenant_id, display_name)` index rejects a name that
        // already exists as a SCIM or local group (23505 → Conflict), so an
        // operator can't shadow a provisioned group.
        let res = sqlx::query(
            "INSERT INTO scim_groups (tenant_id, display_name, source) VALUES ($1, $2, 'local')",
        )
        .bind(tenant_id)
        .bind(display_name)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(GroupStoreError::Conflict(display_name.to_owned()))
            }
            Err(e) => Err(GroupStoreError::Sqlx(e)),
        }
    }

    async fn get_local_delete_target(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<LocalGroupDeleteTarget, GroupStoreError> {
        let row = sqlx::query(
            r#"
            SELECT g.id, g.display_name, g.source, g.updated_at,
                   (SELECT count(*) FROM scim_user_groups m
                      JOIN scim_users u ON u.id = m.user_id
                     WHERE m.tenant_id = $1 AND m.group_id = g.id
                       AND u.deleted_at IS NULL) AS user_member_count,
                   (SELECT count(*) FROM api_keys k
                     WHERE k.tenant_id = $1
                       AND k.revoked_at IS NULL
                       AND jsonb_typeof(k.groups) = 'array'
                       AND jsonb_exists(k.groups, g.display_name)) AS key_member_count,
                   (SELECT count(*) FROM group_role_mappings m
                     WHERE m.tenant_id = $1 AND m.group_id = g.id) AS role_mapping_count
              FROM scim_groups g
             WHERE g.tenant_id = $1 AND g.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(GroupStoreError::NotFound(id))?;
        if row.get::<String, _>("source") != "local" {
            return Err(GroupStoreError::NotLocal(id));
        }
        Ok(LocalGroupDeleteTarget {
            id: row.get("id"),
            display_name: row.get("display_name"),
            updated_at: row.get("updated_at"),
            user_member_count: row.get("user_member_count"),
            key_member_count: row.get("key_member_count"),
            role_mapping_count: row.get("role_mapping_count"),
        })
    }

    async fn delete_local_if_unchanged(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_display_name: &str,
        expected_updated_at: OffsetDateTime,
    ) -> Result<(), GroupStoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT display_name, source, updated_at
              FROM scim_groups
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(GroupStoreError::NotFound(id))?;
        if row.get::<String, _>("source") != "local" {
            return Err(GroupStoreError::NotLocal(id));
        }
        if row.get::<String, _>("display_name") != expected_display_name
            || row.get::<OffsetDateTime, _>("updated_at") != expected_updated_at
        {
            return Err(GroupStoreError::Changed(id));
        }

        let refs = sqlx::query(
            r#"
            SELECT (SELECT count(*) FROM scim_user_groups m
                     JOIN scim_users u ON u.id = m.user_id
                    WHERE m.tenant_id = $1 AND m.group_id = $2
                      AND u.deleted_at IS NULL) AS user_member_count,
                   (SELECT count(*) FROM api_keys k
                    WHERE k.tenant_id = $1
                      AND k.revoked_at IS NULL
                      AND jsonb_typeof(k.groups) = 'array'
                      AND jsonb_exists(k.groups, $3)) AS key_member_count,
                   (SELECT count(*) FROM group_role_mappings m
                    WHERE m.tenant_id = $1 AND m.group_id = $2) AS role_mapping_count
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected_display_name)
        .fetch_one(&mut *tx)
        .await?;
        let user_members = refs.get("user_member_count");
        let key_members = refs.get("key_member_count");
        let role_mappings = refs.get("role_mapping_count");
        if user_members != 0 || key_members != 0 || role_mappings != 0 {
            return Err(GroupStoreError::InUse {
                user_members,
                key_members,
                role_mappings,
            });
        }

        let deleted = sqlx::query(
            r#"
            DELETE FROM scim_groups
             WHERE tenant_id = $1 AND id = $2 AND source = 'local'
               AND display_name = $3 AND updated_at = $4
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected_display_name)
        .bind(expected_updated_at)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if deleted != 1 {
            return Err(GroupStoreError::Changed(id));
        }
        tx.commit().await?;
        Ok(())
    }

    async fn unknown_groups(
        &self,
        tenant_id: &str,
        names: &[String],
    ) -> Result<Vec<String>, GroupStoreError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let unknown: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT n FROM unnest($2::text[]) AS n
             WHERE NOT EXISTS (
                 SELECT 1 FROM scim_groups g
                  WHERE g.display_name = n AND g.tenant_id = $1
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

fn row_to_view(r: &sqlx::postgres::PgRow) -> GroupView {
    GroupView {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        display_name: r.get("display_name"),
        source: r.get("source"),
        external_id: r.get("external_id"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        user_member_count: r.get("user_member_count"),
        key_member_count: r.get("key_member_count"),
        role_mapping_count: r.get("role_mapping_count"),
    }
}
