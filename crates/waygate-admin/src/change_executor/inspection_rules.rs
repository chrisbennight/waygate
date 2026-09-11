//! Inspection-rule change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

pub(super) struct InspectionRuleCreateExecutor;

#[async_trait]
impl ActionExecutor for InspectionRuleCreateExecutor {
    fn action_type(&self) -> &'static str {
        "inspection_rule.create"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let req: CreateRuleRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // `applies_to` defaults to "any tool / any principal" exactly as the
        // REST handler does, so a proposed rule matches what an operator
        // creating it directly would get.
        let applies_to = req
            .applies_to
            .clone()
            .unwrap_or_else(|| Value::Object(Default::default()));
        // create_rule_core validates the name and maps the
        // `(tenant, inspector, name)` uniqueness conflict; the tenant comes
        // from the approver's principal, never from the params.
        let rule = create_rule_core(
            state,
            actor,
            req.inspector,
            &req.name,
            &req.config,
            &applies_to,
            req.enabled,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "rule_id": rule.id,
            "inspector": rule.inspector,
            "name": rule.name,
            "enabled": rule.enabled,
        })))
    }
}

// ---- inspection_rule.update ----

/// Params for `inspection_rule.update`: the target id plus the same optional
/// mutable fields as [`crate::inspection_rules::UpdateRuleRequest`].
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct InspectionRuleUpdateParams {
    pub(super) id: Uuid,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) config: Option<Value>,
    #[serde(default)]
    pub(super) applies_to: Option<Value>,
    #[serde(default)]
    pub(super) enabled: Option<bool>,
}

pub(super) struct InspectionRuleUpdateExecutor;

#[async_trait]
impl ActionExecutor for InspectionRuleUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "inspection_rule.update"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target rule's CURRENT mutable fields (name / config /
        // applies_to / enabled). An out-of-band edit between propose and approve
        // shifts the token and the approved update is refused rather than
        // clobbering it.
        let p: InspectionRuleUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.policy.inspection_rules.get() else {
            return Ok(None);
        };
        let rule = store
            .get(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("inspection_rule get: {e}")))?;
        Ok(rule.map(|r| {
            etag_of(&serde_json::json!({
                "name": r.name,
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
        let p: InspectionRuleUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate-before-irreversible: at least one mutable field must be
        // present, else the "update" is a no-op masquerading as a mutation.
        if p.name.is_none() && p.config.is_none() && p.applies_to.is_none() && p.enabled.is_none() {
            return Err(ExecError::BadParams(
                "at least one of name / config / applies_to / enabled is required".into(),
            ));
        }
        // `Ok(None)` ⇒ no such rule in this tenant (deleted between propose and
        // approve) — a precondition failure, not a silent success.
        let rule = update_rule_core(
            state,
            actor,
            p.id,
            p.name.as_deref(),
            p.config.as_ref(),
            p.applies_to.as_ref(),
            p.enabled,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(format!("inspection rule {} not found in this tenant", p.id))
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "rule_id": rule.id,
            "name": rule.name,
            "enabled": rule.enabled,
        })))
    }
}

// ---- oauth_consent.revoke ----

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

// ---- peer.create ----
