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

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the rule's CURRENT stored fields. A rule edited between
        // propose and approve is not the one the approver reviewed, so the
        // deletion is refused. `None` (no store / rule gone) mismatches a
        // `Some` propose-time token, failing closed.
        let p: InspectionRuleDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.policy.inspection_rules.get() else {
            return Ok(None);
        };
        let rule = store
            .get(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("inspection rule get: {e}")))?;
        Ok(rule.map(|r| {
            etag_of(&serde_json::json!({
                "name": r.name,
                "inspector": r.inspector,
                "config": r.config,
                "applies_to": r.applies_to,
                "enabled": r.enabled,
            }))
        }))
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
