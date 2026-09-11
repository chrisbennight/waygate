//! Governed agent-config lifecycle executors.
//!
//! Create delegates to the same validated, fail-closed-audited core as the
//! dashboard. Update and delete additionally bind the reviewed row version
//! into their store mutation so an out-of-band edit cannot be overwritten or
//! deleted after approval.

use super::*;

use serde::Serialize;
use time::OffsetDateTime;

use crate::agent_configs::{
    create_agent_for_tenant_core, delete_agent_if_version_core, update_agent_if_version_core,
    AgentConfigInput,
};

pub(super) fn append_executors(
    mut executors: Vec<Box<dyn ActionExecutor>>,
) -> Vec<Box<dyn ActionExecutor>> {
    executors.push(Box::new(AgentConfigCreateExecutor));
    executors.push(Box::new(AgentConfigUpdateExecutor));
    executors.push(Box::new(AgentConfigDeleteExecutor));
    executors
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentConfigUpdateParams {
    /// Agent row id from the `agent_config` observe resource or a prior
    /// `agent_config.create` execution result.
    agent_id: Uuid,
    /// Complete replacement configuration. `allowed_tools` is the complete
    /// tool allowlist; an empty list permits no tool calls.
    config: AgentConfigInput,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentConfigDeleteParams {
    /// Agent row id from the `agent_config` observe resource.
    agent_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentConfigWitness {
    agent_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

fn witness_token(witness: &AgentConfigWitness) -> Result<String, ExecError> {
    serde_json::to_string(witness)
        .map_err(|e| ExecError::Store(format!("serialize agent config witness: {e}")))
}

fn parse_witness(token: Option<&str>, expected_id: Uuid) -> Result<OffsetDateTime, ExecError> {
    let token = token.ok_or_else(|| {
        ExecError::Precondition("required agent config target witness is missing".into())
    })?;
    let witness: AgentConfigWitness = serde_json::from_str(token)
        .map_err(|e| ExecError::Precondition(format!("invalid agent config witness: {e}")))?;
    if witness.agent_id != expected_id {
        return Err(ExecError::Precondition(
            "agent config witness identifies a different target".into(),
        ));
    }
    Ok(witness.updated_at)
}

async fn capture_witness(
    state: &Arc<AdminState>,
    tenant_id: &str,
    agent_id: Uuid,
) -> Result<Option<String>, ExecError> {
    let store = cap(&state.agent.agent_configs)?;
    let agent = store
        .get(tenant_id, agent_id)
        .await
        .map_err(|e| ExecError::Store(format!("agent config get: {e}")))?;
    agent
        .map(|agent| {
            witness_token(&AgentConfigWitness {
                agent_id: agent.id,
                updated_at: agent.updated_at,
            })
        })
        .transpose()
}

fn agent_result(agent: waygate_dashboard_stores::agent_config::AgentConfig) -> Value {
    serde_json::json!({
        "agent_id": agent.id,
        "updated_at": format_ts_rfc3339(agent.updated_at),
    })
}

pub(super) struct AgentConfigCreateExecutor;

#[async_trait]
impl ActionExecutor for AgentConfigCreateExecutor {
    fn action_type(&self) -> &'static str {
        "agent_config.create"
    }

    fn file_params(&self) -> &'static [FileBackedParam] {
        &[FileBackedParam {
            pointer: "/instructions",
            description: "UTF-8 text of the operator-authored system-prompt addendum",
        }]
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let input: AgentConfigInput = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let agent = create_agent_for_tenant_core(state, tenant_id, actor, &input)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(agent_result(agent)))
    }
}

pub(super) struct AgentConfigUpdateExecutor;

#[async_trait]
impl ActionExecutor for AgentConfigUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "agent_config.update"
    }

    fn file_params(&self) -> &'static [FileBackedParam] {
        &[FileBackedParam {
            pointer: "/config/instructions",
            description: "UTF-8 text of the operator-authored system-prompt addendum",
        }]
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
        let p: AgentConfigUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        capture_witness(state, tenant_id, p.agent_id).await
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
        let p: AgentConfigUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let expected_updated_at = parse_witness(target_etag, p.agent_id)?;
        let agent = update_agent_if_version_core(
            state,
            tenant_id,
            actor,
            p.agent_id,
            &p.config,
            expected_updated_at,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition("agent config changed or disappeared since review".into())
        })?;
        Ok(ExecOutcome::result(agent_result(agent)))
    }
}

pub(super) struct AgentConfigDeleteExecutor;

#[async_trait]
impl ActionExecutor for AgentConfigDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "agent_config.delete"
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
        let p: AgentConfigDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        capture_witness(state, tenant_id, p.agent_id).await
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
        let p: AgentConfigDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let expected_updated_at = parse_witness(target_etag, p.agent_id)?;
        let removed =
            delete_agent_if_version_core(state, tenant_id, actor, p.agent_id, expected_updated_at)
                .await
                .map_err(map_core_error)?;
        if !removed {
            return Err(ExecError::Precondition(
                "agent config changed or disappeared since review".into(),
            ));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "agent_id": p.agent_id,
            "removed": true,
        })))
    }
}
