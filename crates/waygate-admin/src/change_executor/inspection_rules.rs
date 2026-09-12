//! Deletion of stored custom inspection rules.

use super::*;

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct InspectionRuleDeleteParams {
    pub(super) id: Uuid,
}

pub(super) struct InspectionRuleDeleteExecutor;

#[async_trait]
impl ActionExecutor for InspectionRuleDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "inspection_rule.delete"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: InspectionRuleDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // `Ok(false)` ⇒ the rule is already gone in this tenant (deleted
        // between propose and approve) — a precondition failure.
        let deleted = delete_rule_core(state, actor, p.id)
            .await
            .map_err(map_core_error)?;
        if !deleted {
            return Err(ExecError::Precondition(format!(
                "inspection rule {} not found in this tenant",
                p.id
            )));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "rule_id": p.id,
            "deleted": true,
        })))
    }
}
