//! Tenant-local group/scope catalog change executors.

use super::*;

use serde::Serialize;
use time::OffsetDateTime;
use waygate_apikeys::{GroupStoreError, ScopeStoreError};

use crate::identity_catalog::{
    create_local_group_core, create_local_scope_core, delete_local_group_if_unchanged_core,
    delete_local_scope_if_unchanged_core,
};

pub(super) fn append_executors(
    mut executors: Vec<Box<dyn ActionExecutor>>,
) -> Vec<Box<dyn ActionExecutor>> {
    executors.push(Box::new(LocalGroupCreateExecutor));
    executors.push(Box::new(LocalCatalogDeleteExecutor::group()));
    executors.push(Box::new(LocalScopeCreateExecutor));
    executors.push(Box::new(LocalCatalogDeleteExecutor::scope()));
    executors
}

pub(super) fn append_param_schemas(
    mut schemas: Vec<(&'static str, Value)>,
) -> Vec<(&'static str, Value)> {
    schemas.push((
        "group.create_local",
        params_schema_of::<LocalGroupCreateParams>(),
    ));
    schemas.push((
        "group.delete_local",
        params_schema_of::<LocalGroupDeleteParams>(),
    ));
    schemas.push((
        "scope.create_local",
        params_schema_of::<LocalScopeCreateParams>(),
    ));
    schemas.push((
        "scope.delete_local",
        params_schema_of::<LocalScopeDeleteParams>(),
    ));
    schemas
}

/// Params for `group.create_local`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalGroupCreateParams {
    /// Tenant-local group display name. Leading and trailing whitespace is
    /// removed; the normalized value must be non-empty and must not collide
    /// with either a local or SCIM-provisioned group in the tenant.
    #[schemars(length(min = 1), regex(pattern = r"\S"))]
    pub(super) display_name: String,
}

pub(super) struct LocalGroupCreateExecutor;

#[async_trait]
impl ActionExecutor for LocalGroupCreateExecutor {
    fn action_type(&self) -> &'static str {
        "group.create_local"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let params: LocalGroupCreateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let display_name =
            create_local_group_core(state, tenant_id, Some(actor), &params.display_name)
                .await
                .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "display_name": display_name,
            "source": "local",
        })))
    }
}

/// Params for `group.delete_local`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalGroupDeleteParams {
    /// Tenant-local group id from the `group` observe resource.
    pub(super) group_id: Uuid,
    /// Exact display name shown by the `group` observe resource. The gateway
    /// verifies it against `group_id`, so the approval screen names the
    /// reviewed target instead of showing only an opaque identifier.
    #[schemars(length(min = 1), regex(pattern = r"\S"))]
    pub(super) display_name: String,
}

/// Params for `scope.create_local`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalScopeCreateParams {
    /// Tenant-local scope name. Leading and trailing whitespace is removed;
    /// the normalized value must be non-empty and unique in the tenant.
    #[schemars(length(min = 1), regex(pattern = r"\S"))]
    pub(super) name: String,
    /// Optional human-readable purpose. Blank input is stored as no
    /// description.
    #[serde(default)]
    pub(super) description: Option<String>,
}

pub(super) struct LocalScopeCreateExecutor;

#[async_trait]
impl ActionExecutor for LocalScopeCreateExecutor {
    fn action_type(&self) -> &'static str {
        "scope.create_local"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let params: LocalScopeCreateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let (name, description) = create_local_scope_core(
            state,
            tenant_id,
            Some(actor),
            &params.name,
            params.description.as_deref(),
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "name": name,
            "description": description,
            "source": "local",
        })))
    }
}

/// Params for `scope.delete_local`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalScopeDeleteParams {
    /// Tenant-local scope id from the `scope` observe resource. Global
    /// built-in and policy-discovered scopes cannot be deleted.
    pub(super) scope_id: Uuid,
    /// Exact scope name shown by the `scope` observe resource. The gateway
    /// verifies it against `scope_id` so the approval screen names the target.
    #[schemars(length(min = 1), regex(pattern = r"\S"))]
    pub(super) name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalCatalogDeleteWitness {
    id: Uuid,
    name: String,
    #[serde(with = "time::serde::rfc3339")]
    version: OffsetDateTime,
}

fn witness_token(witness: &LocalCatalogDeleteWitness) -> Result<String, ExecError> {
    serde_json::to_string(witness)
        .map_err(|e| ExecError::Store(format!("serialize local-catalog witness: {e}")))
}

fn parse_witness(
    token: Option<&str>,
    expected_id: Uuid,
    expected_name: &str,
) -> Result<LocalCatalogDeleteWitness, ExecError> {
    let token = token.ok_or_else(|| {
        ExecError::Precondition("required local-catalog target witness is missing".into())
    })?;
    let witness: LocalCatalogDeleteWitness = serde_json::from_str(token)
        .map_err(|e| ExecError::Precondition(format!("invalid local-catalog witness: {e}")))?;
    if witness.id != expected_id || witness.name != expected_name {
        return Err(ExecError::Precondition(
            "local-catalog witness identifies a different target".into(),
        ));
    }
    Ok(witness)
}

fn map_group_capture_error(error: GroupStoreError, tenant_id: &str) -> ExecError {
    match error {
        GroupStoreError::Sqlx(error) => {
            tracing::error!(error = %error, tenant = %tenant_id, "local group proposal lookup failed");
            ExecError::Store("local group lookup failed".into())
        }
        error => ExecError::Precondition(error.to_string()),
    }
}

fn map_scope_capture_error(error: ScopeStoreError, tenant_id: &str) -> ExecError {
    match error {
        ScopeStoreError::Sqlx(error) => {
            tracing::error!(error = %error, tenant = %tenant_id, "local scope proposal lookup failed");
            ExecError::Store("local scope lookup failed".into())
        }
        error => ExecError::Precondition(error.to_string()),
    }
}

#[derive(Clone, Copy)]
enum LocalCatalogDeleteKind {
    Group,
    Scope,
}

pub(super) struct LocalCatalogDeleteExecutor(LocalCatalogDeleteKind);

impl LocalCatalogDeleteExecutor {
    pub(super) fn group() -> Self {
        Self(LocalCatalogDeleteKind::Group)
    }

    pub(super) fn scope() -> Self {
        Self(LocalCatalogDeleteKind::Scope)
    }

    fn parse_params(&self, params: &Value) -> Result<(Uuid, String), ExecError> {
        match self.0 {
            LocalCatalogDeleteKind::Group => {
                let params: LocalGroupDeleteParams = serde_json::from_value(params.clone())
                    .map_err(|e| ExecError::BadParams(e.to_string()))?;
                Ok((params.group_id, params.display_name))
            }
            LocalCatalogDeleteKind::Scope => {
                let params: LocalScopeDeleteParams = serde_json::from_value(params.clone())
                    .map_err(|e| ExecError::BadParams(e.to_string()))?;
                Ok((params.scope_id, params.name))
            }
        }
    }
}

#[async_trait]
impl ActionExecutor for LocalCatalogDeleteExecutor {
    fn action_type(&self) -> &'static str {
        match self.0 {
            LocalCatalogDeleteKind::Group => "group.delete_local",
            LocalCatalogDeleteKind::Scope => "scope.delete_local",
        }
    }

    fn requires_target_etag(&self) -> bool {
        true
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        let (id, expected_name) = self.parse_params(params)?;
        let witness = match self.0 {
            LocalCatalogDeleteKind::Group => {
                let target = cap(&state.identity.groups)?
                    .get_local_delete_target(tenant_id, id)
                    .await
                    .map_err(|e| map_group_capture_error(e, tenant_id))?;
                if target.display_name != expected_name {
                    return Err(ExecError::BadParams(format!(
                        "`display_name` does not match group {id}"
                    )));
                }
                if target.user_member_count != 0
                    || target.key_member_count != 0
                    || target.role_mapping_count != 0
                {
                    return Err(ExecError::Precondition(format!(
                        "local group is still referenced by {} users, {} live keys, and {} role mappings",
                        target.user_member_count,
                        target.key_member_count,
                        target.role_mapping_count
                    )));
                }
                LocalCatalogDeleteWitness {
                    id: target.id,
                    name: target.display_name,
                    version: target.updated_at,
                }
            }
            LocalCatalogDeleteKind::Scope => {
                let target = cap(&state.identity.scopes)?
                    .get_local_delete_target(tenant_id, id)
                    .await
                    .map_err(|e| map_scope_capture_error(e, tenant_id))?;
                if target.name != expected_name {
                    return Err(ExecError::BadParams(format!(
                        "`name` does not match scope {id}"
                    )));
                }
                if target.key_refs != 0 || target.role_refs != 0 {
                    return Err(ExecError::Precondition(format!(
                        "local scope is still referenced by {} live keys and {} roles",
                        target.key_refs, target.role_refs
                    )));
                }
                LocalCatalogDeleteWitness {
                    id: target.id,
                    name: target.name,
                    version: target.updated_at,
                }
            }
        };
        Ok(Some(witness_token(&witness)?))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let witness = self.capture_etag(state, tenant_id, actor, params).await?;
        self.execute_with_target_etag(state, tenant_id, actor, params, witness.as_deref())
            .await
    }

    async fn execute_with_target_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
        target_etag: Option<&str>,
    ) -> Result<ExecOutcome, ExecError> {
        let (id, expected_name) = self.parse_params(params)?;
        let witness = parse_witness(target_etag, id, &expected_name)?;
        match self.0 {
            LocalCatalogDeleteKind::Group => {
                let display_name = delete_local_group_if_unchanged_core(
                    state,
                    tenant_id,
                    Some(actor),
                    witness.id,
                    &witness.name,
                    witness.version,
                )
                .await
                .map_err(map_core_error)?;
                Ok(ExecOutcome::result(serde_json::json!({
                    "group_id": witness.id,
                    "display_name": display_name,
                    "removed": true,
                })))
            }
            LocalCatalogDeleteKind::Scope => {
                let name = delete_local_scope_if_unchanged_core(
                    state,
                    tenant_id,
                    Some(actor),
                    witness.id,
                    &witness.name,
                    witness.version,
                )
                .await
                .map_err(map_core_error)?;
                Ok(ExecOutcome::result(serde_json::json!({
                    "scope_id": witness.id,
                    "name": name,
                    "removed": true,
                })))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_witnesses_must_be_present_well_formed_and_match_params() {
        let id = Uuid::new_v4();
        assert!(parse_witness(None, id, "responders").is_err());
        assert!(parse_witness(Some("not-json"), id, "responders").is_err());
        let other = witness_token(&LocalCatalogDeleteWitness {
            id: Uuid::new_v4(),
            name: "responders".into(),
            version: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("serialize witness");
        assert!(parse_witness(Some(&other), id, "responders").is_err());
    }

    #[test]
    fn proposal_lookup_errors_redact_database_details() {
        let sensitive = "driver detail must not reach the maker";
        let group = map_group_capture_error(
            GroupStoreError::Sqlx(sqlx::Error::Protocol(sensitive.into())),
            "tenant-a",
        );
        let scope = map_scope_capture_error(
            ScopeStoreError::Sqlx(sqlx::Error::Protocol(sensitive.into())),
            "tenant-a",
        );

        assert!(
            matches!(group, ExecError::Store(ref message) if message == "local group lookup failed")
        );
        assert!(
            matches!(scope, ExecError::Store(ref message) if message == "local scope lookup failed")
        );
        assert!(!group.message().contains(sensitive));
        assert!(!scope.message().contains(sensitive));

        let id = Uuid::new_v4();
        assert!(matches!(
            map_group_capture_error(GroupStoreError::NotFound(id), "tenant-a"),
            ExecError::Precondition(message) if message.contains(&id.to_string())
        ));
        assert!(matches!(
            map_scope_capture_error(ScopeStoreError::NotFound(id), "tenant-a"),
            ExecError::Precondition(message) if message.contains(&id.to_string())
        ));
    }
}
