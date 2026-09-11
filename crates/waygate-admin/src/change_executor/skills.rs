//! Skill decisions share the same content-bound mutation core as the dashboard.

use super::*;
use crate::skill_reviews::{decide_core, SkillDecisionParams};
use waygate_skills::review::ReviewDecision;

pub(super) fn append_executors(
    mut executors: Vec<Box<dyn ActionExecutor>>,
) -> Vec<Box<dyn ActionExecutor>> {
    for decision in [
        ReviewDecision::Approve,
        ReviewDecision::Reject,
        ReviewDecision::Quarantine,
    ] {
        executors.push(Box::new(SkillDecisionExecutor(decision)));
    }
    executors
}

pub(super) fn append_param_schemas(
    mut schemas: Vec<(&'static str, Value)>,
) -> Vec<(&'static str, Value)> {
    for action in ["skill.approve", "skill.reject", "skill.quarantine"] {
        schemas.push((action, params_schema_of::<SkillDecisionParams>()));
    }
    schemas
}

struct SkillDecisionExecutor(ReviewDecision);

#[async_trait]
impl ActionExecutor for SkillDecisionExecutor {
    fn action_type(&self) -> &'static str {
        match self.0 {
            ReviewDecision::Approve => "skill.approve",
            ReviewDecision::Reject => "skill.reject",
            ReviewDecision::Quarantine => "skill.quarantine",
        }
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let params: SkillDecisionParams = serde_json::from_value(params.clone())
            .map_err(|error| ExecError::BadParams(error.to_string()))?;
        let review = decide_core(state, tenant_id, actor, &params, self.0)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(
            serde_json::json!({"skill_uri":review.skill_uri,"generation":review.generation,"candidate_status":review.candidate_status,"quarantined":review.quarantined}),
        ))
    }
}
