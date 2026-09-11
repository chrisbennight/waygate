//! Shared cores for the Gateway-Agents config surface.
//!
//! The agent-config CRUD logic — validation, the `(tenant, name)` uniqueness
//! conflict, and the fail-closed `AdminMutation` audit — lives here as
//! `*_core` functions so the dashboard page (`dashboard_agents`) and governed
//! proposal executors share one implementation and can't drift. Tenant comes
//! from the direct actor or the frozen change request, never from params.
//!
//! No router ships here: the operator-facing surface is the dashboard
//! "Gateway Agents" tab. A scriptable REST twin is a deliberate follow-up (the
//! agent *runtime* reads configs through the store directly, not over REST, so
//! REST is not on the critical path for the feature).

use std::sync::Arc;

use schemars::JsonSchema;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_dashboard_stores::agent_config::{AgentConfigError, AgentConfigFields, AgentKind};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiResult};
use crate::state::AdminState;

/// `waygate_dashboard_stores::agent_config::AgentConfig`, re-exported for call sites that only
/// import this module.
pub use waygate_dashboard_stores::agent_config::AgentConfig;

const NAME_MIN: usize = 1;
const NAME_MAX: usize = 64;
const MODEL_ALIAS_MAX: usize = 128;
const INSTRUCTIONS_MAX: usize = 8_000;
const MAX_ALLOWED_TOOLS: usize = 200;
const TOOL_ID_MAX: usize = 256;
/// Mirrors the SQL CHECK ceilings in `migrations/0067_agent_configs.sql` so the
/// app rejects an out-of-range loop cap with a friendly message before the DB
/// would reject it with a constraint error.
const MAX_STEPS_CAP: i32 = 100;
const MAX_TOOL_CALLS_CAP: i32 = 500;

/// Owned input for the create / update cores (the dashboard form parses into
/// this; a future REST DTO would map into it too). Borrowed
/// [`AgentConfigFields`] is built from it just before the store call.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigInput {
    /// Operator-friendly name, unique within the tenant (1-64 characters).
    pub name: String,
    /// Agent role: `chat`, `policy_review`, or `classification`.
    pub kind: AgentKind,
    /// Alias of the configured LLM model this agent uses.
    pub model_alias: String,
    /// Optional operator-authored system-prompt addendum (at most 8,000
    /// characters).
    #[serde(default)]
    pub instructions: Option<String>,
    /// Complete tool allowlist using fully-qualified tool ids. Empty means the
    /// agent can call no tools; at most 200 entries.
    pub allowed_tools: Vec<String>,
    /// Maximum reasoning turns per run (1-100).
    pub max_steps: i32,
    /// Maximum tool calls per run (1-500).
    pub max_tool_calls: i32,
    /// Optional positive token budget per run.
    #[serde(default)]
    pub token_budget: Option<i32>,
    /// Whether the agent may be run. `false` keeps the config inert.
    pub enabled: bool,
}

impl AgentConfigInput {
    fn as_fields(&self) -> AgentConfigFields<'_> {
        AgentConfigFields {
            name: self.name.trim(),
            kind: self.kind,
            model_alias: self.model_alias.trim(),
            instructions: self.instructions.as_deref(),
            allowed_tools: &self.allowed_tools,
            max_steps: self.max_steps,
            max_tool_calls: self.max_tool_calls,
            token_budget: self.token_budget,
            enabled: self.enabled,
        }
    }
}

/// Validate an agent-config input before it reaches the store. Keeps the DB
/// CHECK constraints from being the first line of defense (so the operator
/// sees a friendly message, not a raw constraint error).
pub fn validate(input: &AgentConfigInput) -> Result<(), ApiError> {
    let name_len = input.name.trim().chars().count();
    if !(NAME_MIN..=NAME_MAX).contains(&name_len) {
        return Err(ApiError::BadRequest(format!(
            "name length must be between {NAME_MIN} and {NAME_MAX} chars",
        )));
    }
    let alias = input.model_alias.trim();
    if alias.is_empty() || alias.chars().count() > MODEL_ALIAS_MAX {
        return Err(ApiError::BadRequest(format!(
            "model must be set and at most {MODEL_ALIAS_MAX} chars",
        )));
    }
    if let Some(instr) = input.instructions.as_deref() {
        if instr.chars().count() > INSTRUCTIONS_MAX {
            return Err(ApiError::BadRequest(format!(
                "instructions must be at most {INSTRUCTIONS_MAX} chars",
            )));
        }
    }
    if input.allowed_tools.len() > MAX_ALLOWED_TOOLS {
        return Err(ApiError::BadRequest(format!(
            "allowed_tools must list at most {MAX_ALLOWED_TOOLS} tools",
        )));
    }
    for tool in &input.allowed_tools {
        if tool.is_empty() || tool.chars().count() > TOOL_ID_MAX {
            return Err(ApiError::BadRequest(
                "each allowed tool id must be non-empty and reasonably short".to_owned(),
            ));
        }
    }
    if !(1..=MAX_STEPS_CAP).contains(&input.max_steps) {
        return Err(ApiError::BadRequest(format!(
            "max steps must be between 1 and {MAX_STEPS_CAP}",
        )));
    }
    if !(1..=MAX_TOOL_CALLS_CAP).contains(&input.max_tool_calls) {
        return Err(ApiError::BadRequest(format!(
            "max tool calls must be between 1 and {MAX_TOOL_CALLS_CAP}",
        )));
    }
    if let Some(budget) = input.token_budget {
        if budget <= 0 {
            return Err(ApiError::BadRequest(
                "token budget, when set, must be positive".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Create path: store-check → validate → `insert` → fail-closed audit.
pub async fn create_agent_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    input: &AgentConfigInput,
) -> ApiResult<AgentConfig> {
    create_agent_for_tenant_core(state, actor.tenant.as_str(), actor, input).await
}

/// Tenant-explicit create path for execute-on-approval. The tenant is frozen
/// on the change request and never accepted in params.
pub(crate) async fn create_agent_for_tenant_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    input: &AgentConfigInput,
) -> ApiResult<AgentConfig> {
    let store = state.agent.agent_configs.require()?;
    validate(input)?;
    let agent = store
        .insert(tenant_id, input.as_fields())
        .await
        .map_err(map_store_err)?;
    crate::admin_mutation::record_admin_mutation(
        state,
        "agent_configs",
        "GET /api/v1/admin/agent_configs",
        tenant_id,
        Some(actor),
        "AgentConfigCreated",
        format!(
            "created agent id={} name={} kind={} model={} tools={} enabled={}",
            agent.id,
            agent.name,
            agent.kind.as_str(),
            agent.model_alias,
            agent.allowed_tools.len(),
            agent.enabled,
        ),
    )
    .await?;
    Ok(agent)
}

/// Update path (full replace): store-check → validate → `update` → fail-closed
/// audit. `Ok(None)` ⇒ no such agent in this tenant.
pub async fn update_agent_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    id: Uuid,
    input: &AgentConfigInput,
) -> ApiResult<Option<AgentConfig>> {
    update_agent_for_tenant_core(state, actor.tenant.as_str(), actor, id, input, None).await
}

/// Tenant-explicit, version-conditional update used by execute-on-approval.
/// `Ok(None)` means the reviewed row is missing or stale; no write occurred.
pub(crate) async fn update_agent_if_version_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: Uuid,
    input: &AgentConfigInput,
    expected_updated_at: OffsetDateTime,
) -> ApiResult<Option<AgentConfig>> {
    update_agent_for_tenant_core(
        state,
        tenant_id,
        actor,
        id,
        input,
        Some(expected_updated_at),
    )
    .await
}

async fn update_agent_for_tenant_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: Uuid,
    input: &AgentConfigInput,
    expected_updated_at: Option<OffsetDateTime>,
) -> ApiResult<Option<AgentConfig>> {
    let store = state.agent.agent_configs.require()?;
    validate(input)?;
    let updated = match expected_updated_at {
        Some(expected) => {
            store
                .update_if_updated_at_matches(tenant_id, id, expected, input.as_fields())
                .await
        }
        None => store.update(tenant_id, id, input.as_fields()).await,
    }
    .map_err(map_store_err)?;
    let Some(agent) = updated else {
        return Ok(None);
    };
    crate::admin_mutation::record_admin_mutation(
        state,
        "agent_configs",
        "GET /api/v1/admin/agent_configs",
        tenant_id,
        Some(actor),
        "AgentConfigUpdated",
        format!(
            "updated agent id={} name={} kind={} model={} tools={} enabled={}",
            agent.id,
            agent.name,
            agent.kind.as_str(),
            agent.model_alias,
            agent.allowed_tools.len(),
            agent.enabled,
        ),
    )
    .await?;
    Ok(Some(agent))
}

/// Delete path: store-check → `delete` → fail-closed audit. `Ok(false)` ⇒ no
/// such agent in this tenant.
pub async fn delete_agent_core(
    state: &Arc<AdminState>,
    actor: &Principal,
    id: Uuid,
) -> ApiResult<bool> {
    delete_agent_for_tenant_core(state, actor.tenant.as_str(), actor, id, None).await
}

/// Tenant-explicit, version-conditional delete used by execute-on-approval.
/// `Ok(false)` means the reviewed row is missing or stale; no write occurred.
pub(crate) async fn delete_agent_if_version_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: Uuid,
    expected_updated_at: OffsetDateTime,
) -> ApiResult<bool> {
    delete_agent_for_tenant_core(state, tenant_id, actor, id, Some(expected_updated_at)).await
}

async fn delete_agent_for_tenant_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: &Principal,
    id: Uuid,
    expected_updated_at: Option<OffsetDateTime>,
) -> ApiResult<bool> {
    let store = state.agent.agent_configs.require()?;
    let removed = match expected_updated_at {
        Some(expected) => {
            store
                .delete_if_updated_at_matches(tenant_id, id, expected)
                .await
        }
        None => store.delete(tenant_id, id).await,
    }
    .map_err(map_store_err)?;
    if removed {
        crate::admin_mutation::record_admin_mutation(
            state,
            "agent_configs",
            "GET /api/v1/admin/agent_configs",
            tenant_id,
            Some(actor),
            "AgentConfigDeleted",
            format!("deleted agent id={id}"),
        )
        .await?;
    }
    Ok(removed)
}

fn map_store_err(e: AgentConfigError) -> ApiError {
    match e {
        AgentConfigError::DuplicateName => {
            ApiError::Conflict("an agent with the same name already exists".to_owned())
        }
        AgentConfigError::Database(_) => ApiError::Internal(format!("agent config store: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> AgentConfigInput {
        AgentConfigInput {
            name: "chat".into(),
            kind: AgentKind::Chat,
            model_alias: "gpt-x".into(),
            instructions: None,
            allowed_tools: vec![],
            max_steps: 8,
            max_tool_calls: 16,
            token_budget: None,
            enabled: false,
        }
    }

    #[test]
    fn validate_accepts_a_minimal_config() {
        assert!(validate(&base_input()).is_ok());
    }

    #[test]
    fn validate_rejects_empty_name_and_model() {
        let mut i = base_input();
        i.name = "   ".into();
        assert!(validate(&i).is_err());
        let mut i = base_input();
        i.model_alias = "".into();
        assert!(validate(&i).is_err());
    }

    #[test]
    fn validate_rejects_out_of_range_caps() {
        let mut i = base_input();
        i.max_steps = 0;
        assert!(validate(&i).is_err());
        let mut i = base_input();
        i.max_tool_calls = MAX_TOOL_CALLS_CAP + 1;
        assert!(validate(&i).is_err());
        let mut i = base_input();
        i.token_budget = Some(0);
        assert!(validate(&i).is_err());
    }

    #[test]
    fn validate_rejects_too_many_or_empty_tools() {
        let mut i = base_input();
        i.allowed_tools = vec!["".to_owned()];
        assert!(validate(&i).is_err());
        let mut i = base_input();
        i.allowed_tools = (0..(MAX_ALLOWED_TOOLS + 1))
            .map(|n| format!("s.t{n}"))
            .collect();
        assert!(validate(&i).is_err());
    }
}
