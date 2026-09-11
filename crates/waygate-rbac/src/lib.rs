//! RBAC storage + resolver.
//!
//! Backs migration `0021_rbac.sql` (three tables —
//! `gateway_roles`, `role_assignments`, `group_role_mappings`).
//! Provides:
//!
//! - [`Role`] / [`RoleAssignment`] / [`GroupRoleMapping`] — domain
//!   types matching the columns.
//! - [`RbacStore`] trait + [`PgRbacStore`] implementation for the
//!   read path (`resolve_for_subject`).
//! - [`RbacEnricher`] — a [`waygate_oidc::PrincipalEnricher`] that
//!   reads `principal.scim.groups` (populated by the SCIM
//!   enricher), plus `principal.sub` for direct assignments,
//!   looks up all matching roles, and:
//!     * sets [`waygate_oidc::Principal::roles`] (… defined later
//!       in this crate's docs comment because we attach via the
//!       existing `scim`-style field rather than mutating
//!       `Principal` shape further)
//!     * unions role scopes into `principal.scopes`.
//!
//! The enricher is best-effort: a store outage logs and returns
//! the original principal, same contract as the SCIM enricher.
//!
//! ## Chaining with the SCIM enricher
//!
//! `BearerLayer` accepts a single [`PrincipalEnricher`], so this
//! crate exposes [`ChainedEnricher`] that composes
//! `[scim_enricher, rbac_enricher, …]` in order. SCIM must run
//! before RBAC so RBAC sees `principal.scim.groups`; the helper
//! enforces the order at construction time by accepting an
//! explicit Vec.
//!
//! ## Write path
//!
//! [`RbacStore`] also carries the admin CRUD surface for roles /
//! assignments / group mappings that the `waygate-admin` RBAC
//! handlers consume. The read path is independent of it — CRUD
//! changes don't touch `resolve_for_subject`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_core::CONTROL_PLANE_SCOPES;
use waygate_oidc::{Principal, PrincipalEnricher};

/// A per-tenant RBAC role. Mirrors a `gateway_roles` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow, utoipa::ToSchema)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// One direct (sub-keyed) role binding. Mirrors a `role_assignments`
/// row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow, utoipa::ToSchema)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub tenant_id: String,
    pub role_id: Uuid,
    pub subject_sub: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// One SCIM-group → role mapping. Mirrors a `group_role_mappings`
/// row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow, utoipa::ToSchema)]
pub struct GroupRoleMapping {
    pub tenant_id: String,
    pub group_id: Uuid,
    pub role_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// What an RBAC resolver returns for a single principal: the
/// flattened set of roles (by name) the principal holds in this
/// tenant, plus the union of scopes those roles grant. Names + scopes
/// are deduplicated; the caller can re-derive role-IDs from a
/// separate lookup if it needs them (the bearer hot path doesn't).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRoles {
    pub role_names: Vec<String>,
    pub granted_scopes: Vec<String>,
}

impl ResolvedRoles {
    pub fn is_empty(&self) -> bool {
        self.role_names.is_empty() && self.granted_scopes.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// SQL-layer uniqueness violation surfaced
    /// to the handler. Today fired on `(tenant, role_name)` and
    /// `(tenant, role_id, subject_sub)` collisions; admin
    /// handlers translate to HTTP 409.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Composite-FK violation when an
    /// admin handler references a role or group that doesn't
    /// exist in this tenant. Translated to HTTP 422 by the
    /// handler — distinct from `Conflict` (409, the row exists)
    /// and from `Ok(None)` returns (which the handler maps to
    /// 404 for the requested resource itself).
    #[error("references missing parent: {0}")]
    InvalidReference(String),
}

/// RBAC store covering both the bearer hot path
/// (`resolve_for_subject`) and the admin write surface (CRUD on
/// roles / assignments / group-mappings). Trait shape leaves room
/// for unit tests that drive a fake without Postgres.
#[async_trait]
pub trait RbacStore: Send + Sync {
    /// Resolve every role + scope the subject and its SCIM group memberships
    /// are entitled to. `scim_group_ids` comes from `principal.scim.groups`,
    /// but the Postgres implementation intersects it with current durable
    /// membership for `sub`; stale enricher state cannot preserve a revoked
    /// group grant. Direct sub-bindings still resolve when the slice is empty.
    async fn resolve_for_subject(
        &self,
        tenant_id: &str,
        sub: &str,
        scim_group_ids: &[Uuid],
    ) -> Result<ResolvedRoles, RbacError>;

    // --- Roles CRUD ----------------------------------------

    /// Create a role. `(tenant_id, name)` uniqueness is enforced
    /// at the SQL layer — `RbacError::Conflict` on duplicate.
    async fn create_role(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Role, RbacError>;

    /// Fetch a single role by id, scoped to tenant. `Ok(None)`
    /// when the id exists in another tenant — never cross-tenant
    /// reads.
    async fn get_role(&self, tenant_id: &str, id: Uuid) -> Result<Option<Role>, RbacError>;

    /// List roles for the tenant, alphabetised by name for stable
    /// dashboard rendering.
    async fn list_roles(&self, tenant_id: &str) -> Result<Vec<Role>, RbacError>;

    /// Replace mutable fields (name, description, scopes) on an
    /// existing role. `Ok(None)` when the id doesn't exist in the
    /// tenant. `Err(Conflict)` when the new name collides with
    /// another role in the same tenant.
    async fn update_role(
        &self,
        tenant_id: &str,
        id: Uuid,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Option<Role>, RbacError>;

    /// Delete a role + cascade its assignments and group mappings
    /// (FK CASCADE handles the cascade). Returns true when the
    /// row existed in the tenant.
    async fn delete_role(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError>;

    /// Bulk-delete every role for a
    /// tenant. Called from the tenant DELETE path so a re-created
    /// tenant id can't conflict on the `(tenant_id, "tenant_admin")`
    /// uniqueness when onboarding re-seeds. Composite-FK
    /// `ON DELETE CASCADE` on `role_assignments` and
    /// `group_role_mappings` (migration 0021) means the children
    /// vanish with their parent roles in the same statement.
    /// Returns the number of `gateway_roles` rows deleted so the
    /// handler can audit + log it.
    async fn delete_all_roles_for_tenant(&self, tenant_id: &str) -> Result<u64, RbacError>;

    // --- Assignments CRUD ----------------------------------

    /// Create a direct (sub-keyed) role assignment. Idempotent:
    /// re-POSTing the same `(tenant, role_id, subject_sub)` is a
    /// no-op (`RbacError::Conflict` only on a real uniqueness
    /// violation against a different existing row, which the
    /// composite UNIQUE prevents in practice).
    async fn create_assignment(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
    ) -> Result<RoleAssignment, RbacError>;

    /// Create an assignment only while the referenced role is still at the
    /// exact version reviewed by a governed change. The matching role row is
    /// locked through the insert, so a concurrent role update cannot slip
    /// between validation and the grant. `Ok(None)` means the role is absent
    /// or its version changed.
    async fn create_assignment_if_role_version(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError>;

    /// Fetch a single assignment by row id, scoped to tenant.
    /// `Ok(None)` when the id doesn't exist in the tenant —
    /// never cross-tenant reads.
    ///
    /// Exists so
    /// `delete_assignment` can prefetch the row and record
    /// `subject_sub` + `role_id` in the audit reason BEFORE
    /// the delete — once the row is gone the audit trail
    /// can't answer "which subject lost which role?"
    async fn get_assignment(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RoleAssignment>, RbacError>;

    /// List assignments for the tenant, optionally filtered by
    /// `role_id` (for "show me everyone in role X") or
    /// `subject_sub` (for "show me alice's roles").
    async fn list_assignments(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        subject_sub: Option<&str>,
    ) -> Result<Vec<RoleAssignment>, RbacError>;

    /// Delete an assignment by row id. Returns true when the row
    /// existed in the tenant.
    async fn delete_assignment(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError>;

    /// Delete an assignment only when both its role identity and the role's
    /// version still match the reviewed witness. The matching role row is
    /// locked through the delete. `Ok(None)` means the assignment is absent,
    /// points at another role, or the role changed.
    async fn delete_assignment_if_role_version(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError>;

    // --- Group mappings CRUD -------------------------------

    /// Bind a SCIM group to a role. Composite PK `(tenant, group,
    /// role)` makes re-POSTing idempotent at the SQL layer.
    async fn create_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<GroupRoleMapping, RbacError>;

    /// Create a group-to-role mapping only while the referenced role is at
    /// the reviewed version. The role is locked through the group-existence
    /// check and insert. `Ok(None)` means a parent is absent or the role
    /// changed.
    async fn create_group_mapping_if_role_version(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError>;

    /// List group mappings for the tenant. Optional filters mirror
    /// the assignments shape: `role_id` for "what groups grant role
    /// X", `group_id` for "what roles does group Y grant".
    async fn list_group_mappings(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        group_id: Option<Uuid>,
    ) -> Result<Vec<GroupRoleMapping>, RbacError>;

    /// Delete a group mapping. Returns true when the row existed.
    async fn delete_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, RbacError>;

    /// Delete only the exact mapping generation and role version captured for
    /// review. `Ok(None)` means the mapping was replaced/removed or the role
    /// changed; a stale approval never deletes the newer state.
    async fn delete_group_mapping_if_versions(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_mapping_created_at: OffsetDateTime,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError>;
}

/// Postgres-backed implementation. One UNION query per call covers
/// both the direct-assignment and group-mapping paths.
pub struct PgRbacStore {
    pool: PgPool,
}

impl PgRbacStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RbacStore for PgRbacStore {
    async fn resolve_for_subject(
        &self,
        tenant_id: &str,
        sub: &str,
        scim_group_ids: &[Uuid],
    ) -> Result<ResolvedRoles, RbacError> {
        // Single round-trip: union of direct + group-mapped roles.
        // `ANY` over an empty array yields no rows, so a subject without group
        // memberships collapses to direct assignments without a second query.
        // The EXISTS clause intersects the enricher's group-id snapshot with
        // current durable membership for this subject. A group removal that
        // races a SCIM-cache hit therefore cannot keep granting roles.
        let rows: Vec<(String, Vec<String>)> = sqlx::query_as::<_, (String, Vec<String>)>(
            r#"
            SELECT r.name, r.scopes
              FROM gateway_roles r
              JOIN role_assignments a
                ON a.role_id = r.id
               AND a.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1
               AND a.subject_sub = $2
            UNION
            SELECT r.name, r.scopes
              FROM gateway_roles r
              JOIN group_role_mappings m
                ON m.role_id = r.id
               AND m.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1
               AND m.group_id = ANY($3)
               AND EXISTS (
                    SELECT 1
                      FROM scim_user_groups ug
                      JOIN scim_users u
                        ON u.id = ug.user_id
                       AND u.tenant_id = ug.tenant_id
                     WHERE ug.tenant_id = $1
                       AND ug.group_id = m.group_id
                       AND u.deleted_at IS NULL
                       AND (u.user_name = $2 OR u.external_id = $2)
               )
            "#,
        )
        .bind(tenant_id)
        .bind(sub)
        .bind(scim_group_ids)
        .fetch_all(&self.pool)
        .await?;

        let mut role_names: BTreeSet<String> = BTreeSet::new();
        let mut granted_scopes: BTreeSet<String> = BTreeSet::new();
        for (name, scopes) in rows {
            role_names.insert(name);
            granted_scopes.extend(scopes);
        }
        Ok(ResolvedRoles {
            role_names: role_names.into_iter().collect(),
            granted_scopes: granted_scopes.into_iter().collect(),
        })
    }

    // --- Roles CRUD ----------------------------------------

    async fn create_role(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Role, RbacError> {
        match sqlx::query_as::<_, Role>(
            r#"
            INSERT INTO gateway_roles (tenant_id, name, description, scopes)
            VALUES ($1, $2, $3, $4)
            RETURNING id, tenant_id, name, description, scopes, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(scopes)
        .fetch_one(&self.pool)
        .await
        {
            Ok(r) => Ok(r),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RbacError::Conflict(format!(
                    "role `{name}` already exists in tenant `{tenant_id}`"
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn create_assignment_if_role_version(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        match sqlx::query_as::<_, RoleAssignment>(
            r#"
            WITH reviewed_role AS MATERIALIZED (
                SELECT id
                  FROM gateway_roles
                 WHERE tenant_id = $1
                   AND id = $2
                   AND updated_at = $4
                   FOR UPDATE
            )
            INSERT INTO role_assignments (tenant_id, role_id, subject_sub)
            SELECT $1, r.id, $3
              FROM reviewed_role r
            RETURNING id, tenant_id, role_id, subject_sub, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(subject_sub)
        .bind(expected_role_updated_at)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(a) => Ok(a),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RbacError::Conflict(format!(
                    "assignment for role `{role_id}` to subject `{subject_sub}` already exists \
                     in tenant `{tenant_id}`",
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn get_role(&self, tenant_id: &str, id: Uuid) -> Result<Option<Role>, RbacError> {
        sqlx::query_as::<_, Role>(
            r#"
            SELECT id, tenant_id, name, description, scopes, created_at, updated_at
              FROM gateway_roles
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    async fn list_roles(&self, tenant_id: &str) -> Result<Vec<Role>, RbacError> {
        sqlx::query_as::<_, Role>(
            r#"
            SELECT id, tenant_id, name, description, scopes, created_at, updated_at
              FROM gateway_roles
             WHERE tenant_id = $1
             ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    async fn update_role(
        &self,
        tenant_id: &str,
        id: Uuid,
        name: &str,
        description: Option<&str>,
        scopes: &[String],
    ) -> Result<Option<Role>, RbacError> {
        // updated_at is bumped by the trigger; we don't set it
        // explicitly so multi-writer races see a single
        // tenant-side timestamp source.
        match sqlx::query_as::<_, Role>(
            r#"
            UPDATE gateway_roles
               SET name = $3,
                   description = $4,
                   scopes = $5
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, name, description, scopes, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(scopes)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(opt) => Ok(opt),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RbacError::Conflict(format!(
                    "role `{name}` already exists in tenant `{tenant_id}`"
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn delete_role(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError> {
        let n = sqlx::query(r#"DELETE FROM gateway_roles WHERE tenant_id = $1 AND id = $2"#)
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(RbacError::Sqlx)?
            .rows_affected();
        Ok(n > 0)
    }

    async fn delete_all_roles_for_tenant(&self, tenant_id: &str) -> Result<u64, RbacError> {
        let n = sqlx::query(r#"DELETE FROM gateway_roles WHERE tenant_id = $1"#)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(RbacError::Sqlx)?
            .rows_affected();
        Ok(n)
    }

    // --- Assignments CRUD ----------------------------------

    async fn create_assignment(
        &self,
        tenant_id: &str,
        role_id: Uuid,
        subject_sub: &str,
    ) -> Result<RoleAssignment, RbacError> {
        match sqlx::query_as::<_, RoleAssignment>(
            r#"
            INSERT INTO role_assignments (tenant_id, role_id, subject_sub)
            VALUES ($1, $2, $3)
            RETURNING id, tenant_id, role_id, subject_sub, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(subject_sub)
        .fetch_one(&self.pool)
        .await
        {
            Ok(a) => Ok(a),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RbacError::Conflict(format!(
                    "assignment for role `{role_id}` to subject `{subject_sub}` already exists \
                     in tenant `{tenant_id}`",
                )))
            }
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::FOREIGN_KEY_VIOLATION) =>
            {
                // Composite FK violation: role_id doesn't exist in
                // this tenant. The tenant-match trigger fires
                // first for the cross-tenant case (P0001); 23503
                // is the "role just doesn't exist" case.
                Err(RbacError::InvalidReference(format!(
                    "role `{role_id}` not found in tenant `{tenant_id}`",
                )))
            }
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("P0001") => {
                // Security: the role_assignments tenant-match
                // trigger raises a message that includes both
                // tenant ids
                // (`role tenant 'X' mismatches row tenant 'Y'`)
                // — verbatim passthrough would leak the
                // referenced row's tenant id to a caller that
                // doesn't belong to it. Collapse to the same
                // generic wording the 23503 (missing-parent)
                // branch uses; the detailed message stays in
                // the gateway's WARN log for operator triage.
                // The group_role_mappings P0001 branch below
                // applies the same collapse.
                tracing::warn!(
                    detail = db.message(),
                    "RBAC role_assignments tenant-match trigger fired; \
                     surfacing as generic missing-parent",
                );
                Err(RbacError::InvalidReference(format!(
                    "role `{role_id}` not found in tenant `{tenant_id}`",
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn get_assignment(
        &self,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        sqlx::query_as::<_, RoleAssignment>(
            r#"
            SELECT id, tenant_id, role_id, subject_sub, created_at
              FROM role_assignments
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    async fn list_assignments(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        subject_sub: Option<&str>,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        sqlx::query_as::<_, RoleAssignment>(
            r#"
            SELECT id, tenant_id, role_id, subject_sub, created_at
              FROM role_assignments
             WHERE tenant_id = $1
               AND ($2::UUID IS NULL OR role_id = $2)
               AND ($3::TEXT IS NULL OR subject_sub = $3)
             ORDER BY subject_sub ASC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(subject_sub)
        .fetch_all(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    async fn delete_assignment(&self, tenant_id: &str, id: Uuid) -> Result<bool, RbacError> {
        let n = sqlx::query(r#"DELETE FROM role_assignments WHERE tenant_id = $1 AND id = $2"#)
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(RbacError::Sqlx)?
            .rows_affected();
        Ok(n > 0)
    }

    async fn delete_assignment_if_role_version(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<RoleAssignment>, RbacError> {
        sqlx::query_as::<_, RoleAssignment>(
            r#"
            WITH reviewed_role AS MATERIALIZED (
                SELECT id, tenant_id
                  FROM gateway_roles
                 WHERE tenant_id = $1
                   AND id = $3
                   AND updated_at = $4
                   FOR UPDATE
            )
            DELETE FROM role_assignments a
                  USING reviewed_role r
             WHERE a.tenant_id = $1
               AND a.id = $2
               AND a.role_id = $3
               AND r.tenant_id = a.tenant_id
               AND r.id = a.role_id
            RETURNING a.id, a.tenant_id, a.role_id, a.subject_sub, a.created_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected_role_id)
        .bind(expected_role_updated_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    // --- Group mappings CRUD -------------------------------

    async fn create_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<GroupRoleMapping, RbacError> {
        match sqlx::query_as::<_, GroupRoleMapping>(
            r#"
            INSERT INTO group_role_mappings (tenant_id, group_id, role_id)
            VALUES ($1, $2, $3)
            RETURNING tenant_id, group_id, role_id, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(role_id)
        .fetch_one(&self.pool)
        .await
        {
            Ok(m) => Ok(m),
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) => {
                Err(RbacError::Conflict(format!(
                    "group `{group_id}` ⇒ role `{role_id}` mapping already exists in tenant `{tenant_id}`",
                )))
            }
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some(waygate_core::store::FOREIGN_KEY_VIOLATION) => Err(
                RbacError::InvalidReference(format!(
                    "group `{group_id}` or role `{role_id}` not found in tenant `{tenant_id}`",
                )),
            ),
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("P0001") => {
                // Security: the
                // tenant-match trigger's RAISE message includes
                // both tenant ids verbatim, which would leak the
                // existence of the referenced row in *another*
                // tenant. Log the detail for operator triage and
                // surface the generic "not found in this tenant"
                // wording the 23503 (missing-parent) branch uses
                // — caller can't distinguish "doesn't exist" from
                // "exists in a different tenant."
                tracing::warn!(
                    detail = db.message(),
                    "RBAC tenant-match trigger fired; surfacing as generic missing-parent",
                );
                Err(RbacError::InvalidReference(format!(
                    "referenced row not found in tenant `{tenant_id}`",
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn create_group_mapping_if_role_version(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError> {
        match sqlx::query_as::<_, GroupRoleMapping>(
            r#"
            WITH reviewed_role AS MATERIALIZED (
                SELECT id, tenant_id
                  FROM gateway_roles
                 WHERE tenant_id = $1
                   AND id = $3
                   AND updated_at = $4
                   FOR UPDATE
            )
            INSERT INTO group_role_mappings (tenant_id, group_id, role_id)
            SELECT $1, g.id, r.id
              FROM scim_groups g
              JOIN reviewed_role r ON r.tenant_id = g.tenant_id
             WHERE g.tenant_id = $1
               AND g.id = $2
               AND g.source = 'scim'
            RETURNING tenant_id, group_id, role_id, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(role_id)
        .bind(expected_role_updated_at)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(m) => Ok(m),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(RbacError::Conflict(format!(
                    "group `{group_id}` ⇒ role `{role_id}` mapping already exists in tenant `{tenant_id}`",
                )))
            }
            Err(e) => Err(RbacError::Sqlx(e)),
        }
    }

    async fn list_group_mappings(
        &self,
        tenant_id: &str,
        role_id: Option<Uuid>,
        group_id: Option<Uuid>,
    ) -> Result<Vec<GroupRoleMapping>, RbacError> {
        sqlx::query_as::<_, GroupRoleMapping>(
            r#"
            SELECT tenant_id, group_id, role_id, created_at
              FROM group_role_mappings
             WHERE tenant_id = $1
               AND ($2::UUID IS NULL OR role_id = $2)
               AND ($3::UUID IS NULL OR group_id = $3)
             ORDER BY group_id ASC, role_id ASC
            "#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }

    async fn delete_group_mapping(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, RbacError> {
        let n = sqlx::query(
            r#"
            DELETE FROM group_role_mappings
             WHERE tenant_id = $1 AND group_id = $2 AND role_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(role_id)
        .execute(&self.pool)
        .await
        .map_err(RbacError::Sqlx)?
        .rows_affected();
        Ok(n > 0)
    }

    async fn delete_group_mapping_if_versions(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        role_id: Uuid,
        expected_mapping_created_at: OffsetDateTime,
        expected_role_updated_at: OffsetDateTime,
    ) -> Result<Option<GroupRoleMapping>, RbacError> {
        sqlx::query_as::<_, GroupRoleMapping>(
            r#"
            WITH reviewed_role AS MATERIALIZED (
                SELECT id, tenant_id
                  FROM gateway_roles
                 WHERE tenant_id = $1
                   AND id = $3
                   AND updated_at = $5
                   FOR UPDATE
            )
            DELETE FROM group_role_mappings m
                  USING reviewed_role r
             WHERE m.tenant_id = $1
               AND m.group_id = $2
               AND m.role_id = $3
               AND m.created_at = $4
               AND r.tenant_id = m.tenant_id
               AND r.id = m.role_id
            RETURNING m.tenant_id, m.group_id, m.role_id, m.created_at
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(role_id)
        .bind(expected_mapping_created_at)
        .bind(expected_role_updated_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(RbacError::Sqlx)
    }
}

/// Cache key for [`RbacEnricher`]. SCIM group memberships change rarely;
/// sorting the UUIDs keeps cache hits stable when the enricher returns them in
/// a different order.
type RbacCacheKey = (String, String, Vec<Uuid>);

/// [`PrincipalEnricher`] that resolves RBAC roles after the SCIM
/// enricher has populated `principal.scim`. Reads `principal.sub` and
/// `principal.scim.groups`, looks up the role/scope set, sets
/// `principal.roles`, and unions role scopes into `principal.scopes`.
///
/// Cache TTL defaults to 60s (matches the SCIM enricher's). Resolver
/// errors and resolutions containing control-plane authority are not cached,
/// so a transient outage does not stick and a committed protected-membership
/// revocation is rechecked in Postgres on the next request.
pub struct RbacEnricher {
    store: Arc<dyn RbacStore>,
    cache: Cache<RbacCacheKey, Arc<ResolvedRoles>>,
}

impl RbacEnricher {
    /// Production constructor: Postgres-backed store with the default
    /// 60-second TTL and 10_000-entry cap (mirrors the SCIM enricher).
    pub fn new(pool: PgPool) -> Self {
        Self::new_with_store(
            Arc::new(PgRbacStore::new(pool)),
            Duration::from_secs(60),
            10_000,
        )
    }

    /// Test/extension constructor that takes a custom store + cache
    /// parameters.
    pub fn new_with_store(store: Arc<dyn RbacStore>, ttl: Duration, max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();
        Self { store, cache }
    }

    async fn resolve(
        &self,
        tenant: &str,
        sub: &str,
        scim_group_ids: Vec<Uuid>,
    ) -> Arc<ResolvedRoles> {
        // Sort the group set so two requests for the same principal do not
        // miss the cache on a permutation.
        let mut key_groups = scim_group_ids.clone();
        key_groups.sort();
        key_groups.dedup();
        let key: RbacCacheKey = (tenant.to_owned(), sub.to_owned(), key_groups);

        if let Some(hit) = self.cache.get(&key).await {
            // Entries containing these scopes are never inserted by this
            // version. The defensive check also prevents a pre-upgrade cache
            // entry from extending protected authority after a rolling
            // replacement or hot reload.
            if !contains_control_plane_scope(&hit) {
                return hit;
            }
        }
        match self
            .store
            .resolve_for_subject(tenant, sub, &scim_group_ids)
            .await
        {
            Ok(resolved) => {
                let entry = Arc::new(resolved);
                if !contains_control_plane_scope(&entry) {
                    self.cache.insert(key, entry.clone()).await;
                }
                entry
            }
            Err(e) => {
                tracing::warn!(
                    tenant = tenant,
                    sub = sub,
                    error = %e,
                    "RBAC resolver lookup failed; principal will be enriched as if no roles match",
                );
                Arc::new(ResolvedRoles::default())
            }
        }
    }

    pub async fn invalidate(&self, tenant: &str, sub: &str, scim_group_ids: &[Uuid]) {
        let mut key_groups = scim_group_ids.to_vec();
        key_groups.sort();
        key_groups.dedup();
        self.cache
            .invalidate(&(tenant.to_owned(), sub.to_owned(), key_groups))
            .await;
    }

    /// Drop every process-local cached resolution. Called from admin RBAC
    /// handlers after a successful mutation to make ordinary-role changes
    /// visible promptly on this replica. Resolutions containing control-plane
    /// authority are never cached and therefore do not depend on this
    /// process-local optimization for revocation safety.
    ///
    /// Coarse: blows the whole cache, not just the affected
    /// principal. RBAC mutations are low-rate operator events;
    /// the cache-warm cost on the next request is one DB
    /// round-trip per active principal. The per-subject
    /// invalidate is theoretically tighter but RBAC mutations
    /// can affect many subjects at once (a group→role mapping
    /// change affects every member; a role's scope-set change
    /// affects everyone with the role), so the coarse path is
    /// the conservative right choice.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}

fn contains_control_plane_scope(resolved: &ResolvedRoles) -> bool {
    resolved
        .granted_scopes
        .iter()
        .any(|scope| CONTROL_PLANE_SCOPES.contains(&scope.as_str()))
}

#[async_trait]
impl PrincipalEnricher for RbacEnricher {
    async fn enrich(&self, principal: Principal) -> Principal {
        // Honor upstream enricher blocks. PgScimEnricher
        // already short-circuits on
        // `enrichment_blocked.is_some()`; the RBAC enricher
        // must honor the same contract so a
        // request the tenant gate already blocked doesn't waste
        // a DB round-trip resolving roles that will never be
        // consulted (the bearer middleware 403s the request
        // before any handler reads `principal.roles`). The final
        // deny is unchanged either way — this is a hot-path
        // efficiency + contract-consistency fix.
        if principal.enrichment_blocked.is_some() {
            return principal;
        }
        let tenant = principal.tenant.as_str().to_owned();
        let sub = principal.sub.clone();
        // SCIM groups feed the indirect-binding side. Parse UUIDs
        // up-front; malformed ids (shouldn't happen — SCIM stores
        // UUIDs — but defense in depth) are skipped with a warn.
        let scim_group_ids: Vec<Uuid> = principal
            .scim
            .as_ref()
            .map(|s| {
                s.groups
                    .iter()
                    .filter_map(|g| match Uuid::parse_str(&g.id) {
                        Ok(u) => Some(u),
                        Err(e) => {
                            tracing::warn!(
                                group_id = %g.id,
                                error = %e,
                                "RBAC enricher: principal.scim.groups[].id is not a valid UUID; \
                                 skipping for role resolution",
                            );
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // API-key and OAuth `groups` remain Cedar facts. Only durable SCIM
        // membership can feed RBAC group-to-role mappings; accepting API-key
        // catalog labels here would let ordinary key-grant changes inherit a
        // pre-existing privileged role mapping without the protected bar.
        let resolved = self.resolve(&tenant, &sub, scim_group_ids).await;
        if resolved.is_empty() {
            return principal;
        }

        // Union role-scopes into principal.scopes without duplicates.
        // BTreeSet so the output is stable for tests + logs.
        let mut all_scopes: BTreeSet<String> = principal.scopes.iter().cloned().collect();
        all_scopes.extend(resolved.granted_scopes.iter().cloned());
        let mut all_roles: BTreeSet<String> = principal.roles.iter().cloned().collect();
        all_roles.extend(resolved.role_names.iter().cloned());

        Principal {
            scopes: all_scopes.into_iter().collect(),
            roles: all_roles.into_iter().collect(),
            ..principal
        }
    }
}

/// Compose multiple enrichers into one. Runs them in the order
/// supplied — earlier enrichers' outputs are visible to later ones.
/// Use for stacking the SCIM enricher (which populates
/// `principal.scim`) and the RBAC enricher (which reads
/// `principal.scim.groups`).
pub struct ChainedEnricher {
    stages: Vec<Arc<dyn PrincipalEnricher>>,
}

impl ChainedEnricher {
    pub fn new(stages: Vec<Arc<dyn PrincipalEnricher>>) -> Self {
        Self { stages }
    }
}

#[async_trait]
impl PrincipalEnricher for ChainedEnricher {
    async fn enrich(&self, mut principal: Principal) -> Principal {
        for stage in &self.stages {
            principal = stage.enrich(principal).await;
        }
        principal
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use waygate_oidc::{AuthMethod, ScimGroupRef, ScimPrincipalAttrs};

    use super::*;

    struct FakeRbac {
        result: Mutex<Result<ResolvedRoles, ()>>,
        calls: Mutex<Vec<Vec<Uuid>>>,
    }

    impl FakeRbac {
        fn new(result: Result<ResolvedRoles, ()>) -> Self {
            Self {
                result: Mutex::new(result),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> u32 {
            self.calls.lock().unwrap().len() as u32
        }

        fn last_group_inputs(&self) -> Vec<Uuid> {
            self.calls
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("resolver was called")
        }
    }

    #[async_trait]
    impl RbacStore for FakeRbac {
        async fn resolve_for_subject(
            &self,
            _tenant: &str,
            _sub: &str,
            groups: &[Uuid],
        ) -> Result<ResolvedRoles, RbacError> {
            self.calls.lock().unwrap().push(groups.to_vec());
            match self.result.lock().unwrap().clone() {
                Ok(r) => Ok(r),
                Err(()) => Err(RbacError::Sqlx(sqlx::Error::PoolTimedOut)),
            }
        }
        // Admin CRUD stubs — the enricher tests don't exercise
        // them. If a future test needs them on the fake it can
        // stash a mutable Vec<Role>/Vec<Assignment>/etc. in
        // `FakeRbac` and have the stubs return from there.
        async fn create_role(
            &self,
            _t: &str,
            _n: &str,
            _d: Option<&str>,
            _s: &[String],
        ) -> Result<Role, RbacError> {
            unimplemented!("not used by enricher tests")
        }
        async fn get_role(&self, _t: &str, _id: Uuid) -> Result<Option<Role>, RbacError> {
            unimplemented!()
        }
        async fn list_roles(&self, _t: &str) -> Result<Vec<Role>, RbacError> {
            unimplemented!()
        }
        async fn update_role(
            &self,
            _t: &str,
            _id: Uuid,
            _n: &str,
            _d: Option<&str>,
            _s: &[String],
        ) -> Result<Option<Role>, RbacError> {
            unimplemented!()
        }
        async fn delete_role(&self, _t: &str, _id: Uuid) -> Result<bool, RbacError> {
            unimplemented!()
        }
        async fn delete_all_roles_for_tenant(&self, _t: &str) -> Result<u64, RbacError> {
            unimplemented!()
        }
        async fn create_assignment(
            &self,
            _t: &str,
            _r: Uuid,
            _s: &str,
        ) -> Result<RoleAssignment, RbacError> {
            unimplemented!()
        }
        async fn create_assignment_if_role_version(
            &self,
            _t: &str,
            _r: Uuid,
            _s: &str,
            _v: OffsetDateTime,
        ) -> Result<Option<RoleAssignment>, RbacError> {
            unimplemented!()
        }
        async fn get_assignment(
            &self,
            _t: &str,
            _id: Uuid,
        ) -> Result<Option<RoleAssignment>, RbacError> {
            unimplemented!()
        }
        async fn list_assignments(
            &self,
            _t: &str,
            _r: Option<Uuid>,
            _s: Option<&str>,
        ) -> Result<Vec<RoleAssignment>, RbacError> {
            unimplemented!()
        }
        async fn delete_assignment(&self, _t: &str, _id: Uuid) -> Result<bool, RbacError> {
            unimplemented!()
        }
        async fn delete_assignment_if_role_version(
            &self,
            _t: &str,
            _id: Uuid,
            _r: Uuid,
            _v: OffsetDateTime,
        ) -> Result<Option<RoleAssignment>, RbacError> {
            unimplemented!()
        }
        async fn create_group_mapping(
            &self,
            _t: &str,
            _g: Uuid,
            _r: Uuid,
        ) -> Result<GroupRoleMapping, RbacError> {
            unimplemented!()
        }
        async fn create_group_mapping_if_role_version(
            &self,
            _t: &str,
            _g: Uuid,
            _r: Uuid,
            _v: OffsetDateTime,
        ) -> Result<Option<GroupRoleMapping>, RbacError> {
            unimplemented!()
        }
        async fn list_group_mappings(
            &self,
            _t: &str,
            _r: Option<Uuid>,
            _g: Option<Uuid>,
        ) -> Result<Vec<GroupRoleMapping>, RbacError> {
            unimplemented!()
        }
        async fn delete_group_mapping(
            &self,
            _t: &str,
            _g: Uuid,
            _r: Uuid,
        ) -> Result<bool, RbacError> {
            unimplemented!()
        }
        async fn delete_group_mapping_if_versions(
            &self,
            _t: &str,
            _g: Uuid,
            _r: Uuid,
            _m: OffsetDateTime,
            _v: OffsetDateTime,
        ) -> Result<Option<GroupRoleMapping>, RbacError> {
            unimplemented!()
        }
    }

    fn principal(sub: &str) -> Principal {
        Principal {
            sub: sub.into(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test/".into(),
            scopes: vec!["mcp:read".into()],
            tenant: waygate_core::TenantId::default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn principal_with_scim_groups(sub: &str, group_ids: Vec<Uuid>) -> Principal {
        let mut p = principal(sub);
        p.scim = Some(ScimPrincipalAttrs {
            user_id: "u-1".into(),
            user_name: sub.into(),
            external_id: None,
            active: true,
            attrs: serde_json::Value::Null,
            groups: group_ids
                .into_iter()
                .map(|id| ScimGroupRef {
                    id: id.to_string(),
                    display_name: "g".into(),
                })
                .collect(),
        });
        p
    }

    #[tokio::test]
    async fn enricher_unions_role_scopes_into_principal_scopes() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles {
            role_names: vec!["tenant_admin".into()],
            granted_scopes: vec!["mcp:admin".into(), "mcp:invoke:high".into()],
        })));
        let enricher = RbacEnricher::new_with_store(store, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("alice")).await;
        assert!(out.scopes.contains(&"mcp:read".into()), "preserved");
        assert!(out.scopes.contains(&"mcp:admin".into()), "rbac merged");
        assert!(
            out.scopes.contains(&"mcp:invoke:high".into()),
            "all rbac scopes merged",
        );
        assert_eq!(out.roles, vec!["tenant_admin".to_string()]);
    }

    #[tokio::test]
    async fn enricher_dedupes_scopes() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles {
            role_names: vec!["reader".into()],
            // Duplicate of what's already on principal.
            granted_scopes: vec!["mcp:read".into(), "mcp:read".into()],
        })));
        let enricher = RbacEnricher::new_with_store(store, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("alice")).await;
        assert_eq!(
            out.scopes
                .iter()
                .filter(|s| s.as_str() == "mcp:read")
                .count(),
            1,
            "duplicate scopes must dedupe in the merged set",
        );
    }

    #[tokio::test]
    async fn enricher_returns_unchanged_principal_when_no_roles_match() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles::default())));
        let enricher = RbacEnricher::new_with_store(store, Duration::from_secs(60), 100);
        let p = principal("alice");
        let original_scopes = p.scopes.clone();
        let out = enricher.enrich(p).await;
        assert_eq!(out.scopes, original_scopes);
        assert!(out.roles.is_empty());
    }

    #[tokio::test]
    async fn enricher_returns_unchanged_principal_on_store_error() {
        let store = Arc::new(FakeRbac::new(Err(())));
        let enricher = RbacEnricher::new_with_store(store, Duration::from_secs(60), 100);
        let p = principal("alice");
        let original_scopes = p.scopes.clone();
        let out = enricher.enrich(p).await;
        assert_eq!(
            out.scopes, original_scopes,
            "infra error must not strip existing scopes",
        );
        assert!(out.roles.is_empty());
    }

    #[tokio::test]
    async fn enricher_passes_scim_group_ids_to_store() {
        // Pin: the resolver must receive the parsed UUIDs from
        // principal.scim.groups so group_role_mappings can match.
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles::default())));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        let gid = Uuid::new_v4();
        let p = principal_with_scim_groups("alice", vec![gid]);
        let _ = enricher.enrich(p).await;
        // We trust the FakeRbac doesn't assert internally; the
        // observable contract here is "the enricher made one call,"
        // which proves it didn't short-circuit on the empty-groups
        // path.
        assert_eq!(store.call_count(), 1);
        assert_eq!(store.last_group_inputs(), vec![gid]);
    }

    #[tokio::test]
    async fn enricher_does_not_treat_principal_group_labels_as_rbac_membership() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles::default())));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);

        let mut api_key = principal("api-key-subject");
        api_key.auth_method = AuthMethod::ApiKey;
        api_key.groups = vec!["local-operators".into()];
        let _ = enricher.enrich(api_key).await;
        assert!(store.last_group_inputs().is_empty());

        let mut oauth = principal("oauth-subject");
        oauth.groups = vec!["local-operators".into()];
        let _ = enricher.enrich(oauth).await;
        assert!(
            store.last_group_inputs().is_empty(),
            "principal group labels must remain Cedar facts, not RBAC membership",
        );
    }

    #[tokio::test]
    async fn enricher_caches_hits_within_ttl() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles {
            role_names: vec!["r".into()],
            granted_scopes: vec!["s".into()],
        })));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        for _ in 0..3 {
            let _ = enricher.enrich(principal("alice")).await;
        }
        assert_eq!(store.call_count(), 1);
    }

    #[tokio::test]
    async fn enricher_does_not_cache_store_errors() {
        let store = Arc::new(FakeRbac::new(Err(())));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        let _ = enricher.enrich(principal("alice")).await;
        *store.result.lock().unwrap() = Ok(ResolvedRoles {
            role_names: vec!["r".into()],
            granted_scopes: vec!["s".into()],
        });
        let out = enricher.enrich(principal("alice")).await;
        assert!(out.roles.contains(&"r".to_string()));
        assert_eq!(store.call_count(), 2);
    }

    #[tokio::test]
    async fn enricher_does_not_cache_control_plane_roles() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles {
            role_names: vec!["control-plane".into()],
            granted_scopes: vec!["mcp:admin".into()],
        })));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        let first = enricher.enrich(principal("alice")).await;
        assert_eq!(first.roles, vec!["control-plane"]);
        let _ = enricher.enrich(principal("alice")).await;
        assert_eq!(
            store.call_count(),
            2,
            "control-plane authority must be re-read on every request",
        );
    }

    #[tokio::test]
    async fn invalidate_all_drops_ordinary_role_resolution() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles {
            role_names: vec!["reader".into()],
            granted_scopes: vec!["mcp:read:reports".into()],
        })));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);

        let first = enricher.enrich(principal("alice")).await;
        assert_eq!(first.roles, vec!["reader"]);
        let _ = enricher.enrich(principal("alice")).await;
        assert_eq!(store.call_count(), 1, "the ordinary resolution is cached");

        enricher.invalidate_all();
        let _ = enricher.enrich(principal("alice")).await;
        assert_eq!(
            store.call_count(),
            2,
            "local invalidation must force the next request to re-resolve",
        );
    }

    #[tokio::test]
    async fn enricher_cache_key_is_group_permutation_invariant() {
        // Permutations of SCIM membership must hit the same cache entry.
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles::default())));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        let g1 = Uuid::new_v4();
        let g2 = Uuid::new_v4();
        let first = principal_with_scim_groups("alice", vec![g1, g2]);
        let _ = enricher.enrich(first).await;

        let second = principal_with_scim_groups("alice", vec![g2, g1]);
        let _ = enricher.enrich(second).await;
        assert_eq!(
            store.call_count(),
            1,
            "permutations of the same SCIM groups must reuse the cache entry",
        );
    }

    // Regression: when an upstream
    // enricher (e.g. the tenant-enforcement gate) already
    // refused the principal, the RBAC enricher must skip the
    // store lookup entirely. Without this the bearer middleware
    // still 403s the request, but every blocked request burns a
    // pool slot resolving roles nobody will read.
    #[tokio::test]
    async fn enrichment_blocked_short_circuits_store_lookup() {
        let store = Arc::new(FakeRbac::new(Ok(ResolvedRoles::default())));
        let enricher = RbacEnricher::new_with_store(store.clone(), Duration::from_secs(60), 100);
        let mut p = principal("alice");
        p.enrichment_blocked = Some("tenant_suspended".into());
        let out = enricher.enrich(p.clone()).await;
        assert_eq!(out.enrichment_blocked.as_deref(), Some("tenant_suspended"));
        assert_eq!(
            store.call_count(),
            0,
            "RBAC enricher must skip the store when an upstream enricher already blocked",
        );
    }

    #[tokio::test]
    async fn chained_enricher_runs_stages_in_order() {
        struct StageA;
        #[async_trait]
        impl PrincipalEnricher for StageA {
            async fn enrich(&self, mut p: Principal) -> Principal {
                p.scopes.push("from-a".into());
                p
            }
        }
        struct StageB;
        #[async_trait]
        impl PrincipalEnricher for StageB {
            async fn enrich(&self, mut p: Principal) -> Principal {
                // Stage B can see Stage A's output — proves ordering.
                if p.scopes.iter().any(|s| s == "from-a") {
                    p.scopes.push("saw-a".into());
                }
                p
            }
        }
        let chained = ChainedEnricher::new(vec![Arc::new(StageA), Arc::new(StageB)]);
        let out = chained.enrich(principal("alice")).await;
        assert!(out.scopes.contains(&"from-a".to_string()));
        assert!(
            out.scopes.contains(&"saw-a".to_string()),
            "stage B must see stage A's output",
        );
    }
}
