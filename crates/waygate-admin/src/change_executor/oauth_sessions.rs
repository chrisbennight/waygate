//! OAuth-consent + upstream-session change-executors — split from
//! `change_executor.rs`. Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// Params for `oauth_consent.revoke`: which subject's grant for which client.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct OAuthConsentRevokeParams {
    pub(super) principal_sub: String,
    pub(super) client_id: String,
}

pub(super) struct OAuthConsentRevokeExecutor;

#[async_trait]
impl ActionExecutor for OAuthConsentRevokeExecutor {
    fn action_type(&self) -> &'static str {
        "oauth_consent.revoke"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: OAuthConsentRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        if p.principal_sub.is_empty() || p.client_id.is_empty() {
            return Err(ExecError::BadParams(
                "principal_sub and client_id are required".into(),
            ));
        }
        // Revoke is idempotent ("ensure this grant is revoked"): an absent /
        // already-revoked grant returns `removed = false` and is a legitimate
        // success, NOT a precondition failure. `tenant_id` is the approver's
        // own tenant, so revoke_grant_core can't cross tenants.
        let removed = revoke_grant_core(
            state,
            tenant_id,
            Some(actor),
            &p.principal_sub,
            &p.client_id,
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "principal_sub": p.principal_sub,
            "client_id": p.client_id,
            "removed": removed,
        })))
    }
}

// ---- inspection_rule.delete ----

/// Params for `upstream_session.revoke`: which user's Tier-A session against
/// which upstream IdP. Keyed by `(sub, upstream_issuer)` exactly like the
/// direct admin DELETE — the session store is not tenant-scoped.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct UpstreamSessionRevokeParams {
    pub(super) sub: String,
    pub(super) upstream_issuer: String,
}

pub(super) struct UpstreamSessionRevokeExecutor;

#[async_trait]
impl ActionExecutor for UpstreamSessionRevokeExecutor {
    fn action_type(&self) -> &'static str {
        "upstream_session.revoke"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: UpstreamSessionRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        if p.sub.is_empty() || p.upstream_issuer.is_empty() {
            return Err(ExecError::BadParams(
                "sub and upstream_issuer are required".into(),
            ));
        }
        // Revoke is idempotent ("ensure this session is burned"): an
        // already-absent session returns `removed = false` and is a legitimate
        // success, not a precondition failure. The shared core records the
        // fail-closed AdminMutation audit. `_tenant_id` is unused — the Tier-A
        // session store is keyed by (sub, upstream_issuer), not tenant, the
        // same as the direct admin DELETE.
        let removed = revoke_session_core(state, Some(actor), &p.sub, &p.upstream_issuer)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "sub": p.sub,
            "upstream_issuer": p.upstream_issuer,
            "removed": removed,
        })))
    }
}

// ---- break_glass.mint ----
