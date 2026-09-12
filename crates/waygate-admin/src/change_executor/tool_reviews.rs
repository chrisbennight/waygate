//! Tool contract acceptance uses the dashboard's exact-version mutation.
use super::*;
use crate::tool_reviews::{approve_core, read_context, ToolReviewParams, ToolReviewSelector};
pub(super) struct ToolContractApproveExecutor;
#[async_trait]
impl ActionExecutor for ToolContractApproveExecutor {
    fn action_type(&self) -> &'static str {
        "tool_contract.approve"
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
        let params: ToolReviewParams = serde_json::from_value(params.clone())
            .map_err(|error| ExecError::BadParams(error.to_string()))?;
        let context = read_context(
            state,
            tenant_id,
            ToolReviewSelector {
                server: Some(params.server),
                tool: Some(params.tool),
            },
        )
        .await
        .map_err(map_core_error)?;
        let candidate = context
            .reviews
            .first()
            .ok_or_else(|| ExecError::Precondition("Tool review not found".into()))?;
        if candidate.generation != params.generation
            || candidate.observed_hash != params.observed_hash
            || candidate.manifest_hash != params.manifest_hash
        {
            return Err(ExecError::Precondition(
                "The tool or manifest changed; read the current action context and review it again"
                    .into(),
            ));
        }
        Ok(Some(format!(
            "{}:{}:{}",
            candidate.generation, candidate.observed_hash, candidate.manifest_hash
        )))
    }
    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let params: ToolReviewParams = serde_json::from_value(params.clone())
            .map_err(|error| ExecError::BadParams(error.to_string()))?;
        let review = approve_core(state, tenant_id, actor, &params)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(
            serde_json::json!({"server":review.server,"tool":review.tool,"observed_hash":review.observed_hash,"quarantined":review.quarantined}),
        ))
    }
}
