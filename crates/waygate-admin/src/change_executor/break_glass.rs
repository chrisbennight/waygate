//! Break-glass change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// `break_glass.mint` proposes a single-use, time-bound, scope-pinned Cedar
/// override token for a principal. Params mirror the dashboard/REST mint body
/// ([`MintRequest`]); the executor runs the shared `mint_token_core`, so
/// validation (issued_to / reason / scope_pattern shape, TTL cap, the
/// `requires_amr`-must-be-empty refusal) and the fail-closed `BreakGlassMint`
/// audit are identical to the direct-admin path.
///
/// Proposing a Cedar override is the most powerful non-destructive action in
/// the allowlist, but it's safe to make proposable because the review UI
/// surfaces the captured params (`/changes` + `/decisions` show `issued_to` /
/// `scope_pattern` / `reason` / `ttl_seconds` above the Approve control):
/// routing through propose adds a captured review and approval ceremony over the
/// direct admin mint, and the override stays single-use /
/// ≤24h / scope-pinned / `issued_to`-bound. The token `id` is NOT a bearer
/// string (it's the admin's revoke handle; the override auto-discovers by
/// `(tenant, issued_to, tool)` at use-time per `docs/agents/break-glass.md`),
/// so it's returned in `execution_result` exactly as the direct mint returns
/// it — there is no secret to channel.
pub(super) struct BreakGlassMintExecutor;

#[async_trait]
impl ActionExecutor for BreakGlassMintExecutor {
    fn action_type(&self) -> &'static str {
        "break_glass.mint"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let req: MintRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let token = mint_token_core(state, tenant_id, Some(actor), &req)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "token_id": token.id,
            "issued_to": token.issued_to,
            "scope_pattern": token.scope_pattern,
            "requires_amr": token.requires_amr,
            "expires_at": format_ts_rfc3339(token.expires_at),
        })))
    }
}

// ---- break_glass.revoke ----

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct BreakGlassRevokeParams {
    pub(super) token_id: Uuid,
}

pub(super) struct BreakGlassRevokeExecutor;

#[async_trait]
impl ActionExecutor for BreakGlassRevokeExecutor {
    fn action_type(&self) -> &'static str {
        "break_glass.revoke"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: BreakGlassRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Revoke is idempotent ("ensure this token is burned"): an absent /
        // already-revoked token returns `removed = false` and is a legitimate
        // success (the core still records the fail-closed revoke audit), not a
        // precondition failure.
        let removed = revoke_token_core(state, tenant_id, Some(actor), p.token_id)
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "token_id": p.token_id,
            "removed": removed,
        })))
    }
}

// ---- api_key.revoke ----
