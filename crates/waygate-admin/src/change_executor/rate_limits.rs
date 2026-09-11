//! Rate-limit change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// Params for `rate_limit.update`: which policy, and the mutable fields
/// (`bucket_capacity` / `refill_per_second` — the only fields the store's
/// `update` accepts; scope/action are immutable, rotated via delete+create).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RateLimitUpdateParams {
    pub(super) policy_id: Uuid,
    #[serde(default)]
    pub(super) bucket_capacity: Option<i32>,
    #[serde(default)]
    pub(super) refill_per_second: Option<f64>,
}

pub(super) struct RateLimitUpdateExecutor;

#[async_trait]
impl ActionExecutor for RateLimitUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "rate_limit.update"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target policy's CURRENT mutable fields (the only ones
        // `update_policy_core` can change). If an operator retunes the policy
        // between propose and approve, this token shifts and the approved write
        // is refused rather than clobbering their change. `None` (no store /
        // policy gone) → mismatches a Some propose-time token, failing closed.
        let p: RateLimitUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.policy.rate_limit_policies.get() else {
            return Ok(None);
        };
        let policy = store
            .get(tenant_id, p.policy_id)
            .await
            .map_err(|e| ExecError::Store(format!("rate_limit get: {e}")))?;
        Ok(policy.map(|pol| {
            etag_of(&serde_json::json!({
                "bucket_capacity": pol.bucket_capacity,
                "refill_per_second": pol.refill_per_second,
            }))
        }))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RateLimitUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate BEFORE the irreversible store write: at least one field
        // must change, else the "update" is a no-op masquerading as a
        // mutation. (This no-op guard is executor-specific; update_policy_core
        // validates the per-field bounds.)
        if p.bucket_capacity.is_none() && p.refill_per_second.is_none() {
            return Err(ExecError::BadParams(
                "at least one of bucket_capacity / refill_per_second is required".into(),
            ));
        }
        // Reuse the same core the PATCH handler calls: it
        // validates the bounds, performs the UPDATE, and records the
        // fail-closed `rate_limit_policies.update` AdminMutation — so the
        // propose path and the direct-admin path produce identical audit.
        // `Ok(None)` ⇒ the policy was deleted between
        // propose and approve, a precondition failure that marks the change
        // `failed` rather than silently succeeding.
        let updated = update_policy_core(
            state,
            tenant_id,
            actor,
            &p.policy_id.to_string(),
            p.bucket_capacity,
            p.refill_per_second,
        )
        .await
        .map_err(map_core_error)?
        .ok_or_else(|| {
            ExecError::Precondition(format!(
                "rate-limit policy {} not found in this tenant",
                p.policy_id
            ))
        })?;
        Ok(ExecOutcome::result(serde_json::json!({
            "policy_id": updated.id,
            "name": updated.name,
            "bucket_capacity": updated.bucket_capacity,
            "refill_per_second": updated.refill_per_second,
        })))
    }
}

// ---- api_key.mint ----

/// `rate_limit.create` proposes a brand-new policy. Params mirror the
/// dashboard/REST create body ([`CreatePolicyRequest`]); the executor runs the
/// shared `create_policy_core`, so name/scope/positivity validation, the
/// `(tenant_id, scope, scope_value, action)` uniqueness conflict (the store's
/// actual UNIQUE constraint), and the durable audit are identical to the
/// direct-admin path.
pub(super) struct RateLimitCreateExecutor;

#[async_trait]
impl ActionExecutor for RateLimitCreateExecutor {
    fn action_type(&self) -> &'static str {
        "rate_limit.create"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let req: CreatePolicyRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // create_policy_core validates BEFORE the irreversible insert (name
        // bounds, scope_value presence, positive capacity/refill) and maps a
        // uniqueness collision to Conflict -> Precondition here.
        let p = create_policy_core(state, tenant_id, actor, &req)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "policy_id": p.id,
            "name": p.name,
            "scope": p.scope.as_str(),
            "scope_value": p.scope_value,
            "bucket_capacity": p.bucket_capacity,
            "refill_per_second": p.refill_per_second,
            "action": p.action.as_str(),
        })))
    }
}

// ---- rate_limit.delete ----

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct RateLimitDeleteParams {
    pub(super) policy_id: Uuid,
}

pub(super) struct RateLimitDeleteExecutor;

#[async_trait]
impl ActionExecutor for RateLimitDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "rate_limit.delete"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RateLimitDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // `Ok(false)` ⇒ the policy is already gone in this tenant (deleted
        // between propose and approve). That's a precondition failure — mark
        // the change `failed` rather than report a delete that did nothing.
        let deleted = delete_policy_core(state, tenant_id, actor, &p.policy_id.to_string())
            .await
            .map_err(map_core_error)?;
        if !deleted {
            return Err(ExecError::Precondition(format!(
                "rate-limit policy {} not found in this tenant",
                p.policy_id
            )));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "policy_id": p.policy_id,
            "deleted": true,
        })))
    }
}

// ---- inspection_rule.create ----
