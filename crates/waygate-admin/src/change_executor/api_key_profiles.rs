//! Governed API-key profile lifecycle executors.
//!
//! Profiles are intentionally immutable: create and delete are the complete
//! direct-admin mutation surface. Both executors delegate to those shared
//! cores so validation, live-key deletion guards, cache invalidation, and
//! fail-closed audit behavior stay identical.

use super::*;

use serde::Serialize;
use time::OffsetDateTime;

use crate::api_key_profiles::{
    create_profile_core, delete_profile_if_updated_at_core, CreateProfileRequest, ProfileView,
};

pub(super) fn append_executors(
    mut executors: Vec<Box<dyn ActionExecutor>>,
) -> Vec<Box<dyn ActionExecutor>> {
    executors.push(Box::new(ApiKeyProfileCreateExecutor));
    executors.push(Box::new(ApiKeyProfileDeleteExecutor));
    executors
}

pub(super) fn append_param_schemas(
    mut schemas: Vec<(&'static str, Value)>,
) -> Vec<(&'static str, Value)> {
    schemas.push((
        "api_key_profile.create",
        params_schema_of::<CreateProfileRequest>(),
    ));
    schemas.push((
        "api_key_profile.delete",
        params_schema_of::<ApiKeyProfileDeleteParams>(),
    ));
    schemas
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ApiKeyProfileDeleteParams {
    /// Profile id from the `api_key_profile` observe resource or an
    /// `api_key_profile.create` execution result.
    profile_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiKeyProfileWitness {
    profile_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

fn witness_token(witness: &ApiKeyProfileWitness) -> Result<String, ExecError> {
    serde_json::to_string(witness)
        .map_err(|e| ExecError::Store(format!("serialize API-key profile witness: {e}")))
}

fn parse_witness(
    token: Option<&str>,
    expected_id: Uuid,
) -> Result<ApiKeyProfileWitness, ExecError> {
    let token = token.ok_or_else(|| {
        ExecError::Precondition("required API-key profile target witness is missing".into())
    })?;
    let witness: ApiKeyProfileWitness = serde_json::from_str(token)
        .map_err(|e| ExecError::Precondition(format!("invalid API-key profile witness: {e}")))?;
    if witness.profile_id != expected_id {
        return Err(ExecError::Precondition(
            "API-key profile witness identifies a different target".into(),
        ));
    }
    Ok(witness)
}

async fn capture_witness(
    state: &Arc<AdminState>,
    tenant_id: &str,
    profile_id: Uuid,
) -> Result<Option<String>, ExecError> {
    let store = cap(&state.identity.api_key_profiles)?;
    let profile = store
        .get(tenant_id, profile_id)
        .await
        .map_err(|e| ExecError::Store(format!("API-key profile get: {e}")))?;
    profile
        .map(|profile| {
            witness_token(&ApiKeyProfileWitness {
                profile_id: profile.id,
                updated_at: profile.updated_at,
            })
        })
        .transpose()
}

pub(super) struct ApiKeyProfileCreateExecutor;

#[async_trait]
impl ActionExecutor for ApiKeyProfileCreateExecutor {
    fn action_type(&self) -> &'static str {
        "api_key_profile.create"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let request: CreateProfileRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let profile = create_profile_core(state, tenant_id, Some(actor), &request)
            .await
            .map_err(map_core_error)?;
        let result = serde_json::to_value(ProfileView::from(profile))
            .map_err(|e| ExecError::Store(format!("serialize API-key profile result: {e}")))?;
        Ok(ExecOutcome::result(result))
    }
}

pub(super) struct ApiKeyProfileDeleteExecutor;

#[async_trait]
impl ActionExecutor for ApiKeyProfileDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "api_key_profile.delete"
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
        let p: ApiKeyProfileDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        capture_witness(state, tenant_id, p.profile_id).await
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
        let p: ApiKeyProfileDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let witness = parse_witness(target_etag, p.profile_id)?;
        let removed = delete_profile_if_updated_at_core(
            state,
            tenant_id,
            Some(actor),
            p.profile_id,
            witness.updated_at,
        )
        .await
        .map_err(map_core_error)?;
        if !removed {
            return Err(ExecError::Precondition(
                "API-key profile changed or disappeared since review".into(),
            ));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "profile_id": p.profile_id,
            "removed": true,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_witness_must_be_present_well_formed_and_match_the_target() {
        let profile_id = Uuid::new_v4();
        assert!(parse_witness(None, profile_id).is_err());
        assert!(parse_witness(Some("not-json"), profile_id).is_err());

        let other_token = witness_token(&ApiKeyProfileWitness {
            profile_id: Uuid::new_v4(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("serialize different-target witness");
        assert!(parse_witness(Some(&other_token), profile_id).is_err());

        let matching_token = witness_token(&ApiKeyProfileWitness {
            profile_id,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        })
        .expect("serialize matching witness");
        let parsed = parse_witness(Some(&matching_token), profile_id).expect("matching witness");
        assert_eq!(parsed.updated_at, OffsetDateTime::UNIX_EPOCH);
    }
}
