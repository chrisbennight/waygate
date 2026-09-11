//! Shared mutation cores for the tenant-local group and scope catalogs.
//!
//! The dashboard forms and the HITL change executors both call these cores so
//! input normalization, conflict handling, and fail-closed audit behavior stay
//! identical across direct and propose-on-approval paths.

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use waygate_apikeys::{GroupStoreError, ScopeStoreError};
use waygate_oidc::Principal;

use crate::error::ApiError;
use crate::state::AdminState;

/// Create one tenant-local group and return its normalized display name.
pub(crate) async fn create_local_group_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    display_name: &str,
) -> Result<String, ApiError> {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        return Err(ApiError::BadRequest(
            "`display_name` must be non-empty".into(),
        ));
    }

    state
        .identity
        .groups
        .require()?
        .create_local(tenant_id, display_name)
        .await
        .map_err(|e| map_group_store_error(e, tenant_id, "create_local"))?;

    crate::admin_mutation::record_admin_mutation(
        state,
        "groups",
        "the groups dashboard page",
        tenant_id,
        actor,
        "groups.create",
        format!("created local group `{display_name}`"),
    )
    .await?;

    Ok(display_name.to_owned())
}

/// Create one tenant-local scope and return its normalized name and
/// description. A blank description is stored as `None`.
pub(crate) async fn create_local_scope_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    name: &str,
    description: Option<&str>,
) -> Result<(String, Option<String>), ApiError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("`name` must be non-empty".into()));
    }
    let description = description
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    state
        .identity
        .scopes
        .require()?
        .create_local(tenant_id, name, description.as_deref())
        .await
        .map_err(|e| map_scope_store_error(e, tenant_id, "create_local"))?;

    crate::admin_mutation::record_admin_mutation(
        state,
        "scopes",
        "the scopes dashboard page",
        tenant_id,
        actor,
        "scopes.create",
        format!("created local scope `{name}`"),
    )
    .await?;

    Ok((name.to_owned(), description))
}

/// Delete exactly the reviewed generation of a tenant-local group. The store
/// rechecks source and references while holding the target row lock.
pub(crate) async fn delete_local_group_if_unchanged_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    expected_display_name: &str,
    expected_updated_at: OffsetDateTime,
) -> Result<String, ApiError> {
    state
        .identity
        .groups
        .require()?
        .delete_local_if_unchanged(tenant_id, id, expected_display_name, expected_updated_at)
        .await
        .map_err(|e| map_group_store_error(e, tenant_id, "delete_local"))?;

    crate::admin_mutation::record_admin_mutation(
        state,
        "groups",
        "the group catalog",
        tenant_id,
        actor,
        "groups.delete",
        format!("deleted local group id={id} name=`{expected_display_name}`"),
    )
    .await?;

    Ok(expected_display_name.to_owned())
}

/// Delete exactly the reviewed version of a tenant-local scope. The store
/// rechecks source and references while holding the target row lock.
pub(crate) async fn delete_local_scope_if_unchanged_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    expected_name: &str,
    expected_updated_at: OffsetDateTime,
) -> Result<String, ApiError> {
    state
        .identity
        .scopes
        .require()?
        .delete_local_if_unchanged(tenant_id, id, expected_name, expected_updated_at)
        .await
        .map_err(|e| map_scope_store_error(e, tenant_id, "delete_local"))?;

    crate::admin_mutation::record_admin_mutation(
        state,
        "scopes",
        "the scope catalog",
        tenant_id,
        actor,
        "scopes.delete",
        format!("deleted local scope id={id} name=`{expected_name}`"),
    )
    .await?;

    Ok(expected_name.to_owned())
}

fn map_group_store_error(error: GroupStoreError, tenant_id: &str, operation: &str) -> ApiError {
    match error {
        GroupStoreError::Conflict(name) => {
            ApiError::Conflict(format!("a group named `{name}` already exists"))
        }
        GroupStoreError::NotFound(id) => ApiError::NotFoundDyn(format!("local group {id}")),
        GroupStoreError::NotLocal(id) => {
            ApiError::BadRequest(format!("group {id} is not a tenant-local group"))
        }
        GroupStoreError::Changed(id) => {
            ApiError::Conflict(format!("local group {id} changed since review"))
        }
        GroupStoreError::InUse {
            user_members,
            key_members,
            role_mappings,
        } => ApiError::Conflict(format!(
            "local group is still referenced by {user_members} users, {key_members} live keys, and {role_mappings} role mappings"
        )),
        GroupStoreError::Sqlx(error) => {
            tracing::error!(error = %error, tenant = %tenant_id, operation, "groups store operation failed");
            ApiError::Internal("group store operation failed".into())
        }
    }
}

fn map_scope_store_error(error: ScopeStoreError, tenant_id: &str, operation: &str) -> ApiError {
    match error {
        ScopeStoreError::Conflict(name) => {
            ApiError::Conflict(format!("a scope named `{name}` already exists"))
        }
        ScopeStoreError::NotFound(id) => ApiError::NotFoundDyn(format!("local scope {id}")),
        ScopeStoreError::NotLocal(id) => {
            ApiError::BadRequest(format!("scope {id} is not a tenant-local scope"))
        }
        ScopeStoreError::Changed(id) => {
            ApiError::Conflict(format!("local scope {id} changed since review"))
        }
        ScopeStoreError::InUse {
            key_refs,
            role_refs,
        } => ApiError::Conflict(format!(
            "local scope is still referenced by {key_refs} live keys and {role_refs} roles"
        )),
        ScopeStoreError::Sqlx(error) => {
            tracing::error!(error = %error, tenant = %tenant_id, operation, "scopes store operation failed");
            ApiError::Internal("scope store operation failed".into())
        }
    }
}
