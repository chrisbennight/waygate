//! API-key change-executors — split from `change_executor.rs`.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// Params for `api_key.mint`: the same fields the dashboard mint form
/// carries, captured as the change-request intent. The executor maps these
/// to [`crate::api_keys::MintParams`] and runs the shared `mint_core`, so
/// validation / profile enforcement / persistence / audit are identical to
/// the dashboard path. The freshly minted `mcpgw_…` secret rides the
/// encrypted burn-on-read channel back to the maker; only a non-sensitive
/// fingerprint (id + prefix) lands in `execution_result`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ApiKeyMintParams {
    name: String,
    sub: String,
    scopes: Vec<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    /// TTL token (`<N>d` / `<N>h` / `<N>y` / `never`). Empty/absent ⇒ never.
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) struct ApiKeyMintExecutor;

#[async_trait]
impl ActionExecutor for ApiKeyMintExecutor {
    fn action_type(&self) -> &'static str {
        "api_key.mint"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        // Validate-before-irreversible: refuse to mint when there's no
        // secret channel to deliver the key through, BEFORE any side effect
        // — otherwise we'd mint a key the maker could never retrieve (an
        // orphan only the operator could find and revoke). execute_approved
        // also guards the store step, but checking here means nothing is
        // minted at all when the channel is absent.
        super::cap(&state.hitl.change_secret_crypto)?;
        let p: ApiKeyMintParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Mint via the SAME core the dashboard uses (validation, profile
        // enforcement, persistence, audit). `created_by` attributes the new
        // key to the approving operator who authorized this execution; the
        // change request's audit trail records the proposing maker.
        let mint = crate::api_keys::mint_core(
            state,
            tenant_id,
            &actor.sub,
            Some(actor),
            crate::api_keys::MintParams {
                name: p.name,
                sub: p.sub,
                email: p.email,
                groups: p.groups,
                scopes: p.scopes,
                ttl_raw: p.ttl,
                profile_id: p.profile_id,
                owner: p.owner,
                reason: p.reason,
            },
        )
        .await
        .map_err(map_core_error)?;

        // execution_result carries ONLY a non-secret fingerprint (the key's
        // public prefix + id + sub + scopes). The plaintext `mcpgw_…` secret
        // goes out the encrypted burn-on-read channel, never into the result
        // JSON (which is surfaced on every poll + the decision view).
        let result = serde_json::json!({
            "api_key_id": mint.row.id,
            "key_prefix": mint.row.key_prefix,
            "sub": mint.row.sub,
            "scopes": mint.row.scopes,
            "secret_available": true,
        });
        Ok(ExecOutcome::with_secret(result, mint.secret.into_bytes()))
    }
}

// ---- rate_limit.create ----

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ApiKeyRevokeParams {
    pub(super) api_key_id: Uuid,
}

pub(super) struct ApiKeyRevokeExecutor;

#[async_trait]
impl ActionExecutor for ApiKeyRevokeExecutor {
    fn action_type(&self) -> &'static str {
        "api_key.revoke"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ApiKeyRevokeParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Tenant-bound the maker-initiated revoke: pass `Some(tenant_id)` so a
        // key in another tenant is NotFound (-> Precondition), not revocable
        // (the direct-admin dashboard revoke stays global). An existing but
        // already-revoked key is `removed = false`, an idempotent success; a
        // truly-unknown id is NotFound -> Precondition (target gone between
        // propose and approve). The result carries only a non-secret
        // fingerprint (id / prefix / sub) — revoke produces no secret.
        let out = crate::api_keys::revoke_core(state, Some(actor), p.api_key_id, Some(tenant_id))
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "api_key_id": out.row.id,
            "key_prefix": out.row.key_prefix,
            "sub": out.row.sub,
            "removed": out.removed,
        })))
    }
}

// ---- api_key.update_grants ----

/// Params for `api_key.update_grants`: the target key + the FULL replacement
/// grant set. A full replacement, not a patch (mirrors `rbac.role.update`): the
/// executor runs the shared `update_grants_core`, so normalization, catalog
/// enforcement, profile re-validation, the conditional write, and audit are
/// identical to the dashboard edit path. Tenant-bound through the change
/// request's `tenant_id` — a key in another tenant is NotFound (-> Precondition),
/// unreachable by id. Editing grants re-scopes a key in place; it never
/// re-issues the key, so there is no secret to deliver.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ApiKeyUpdateGrantsParams {
    /// The api key to re-scope — its `id` from the keys list (or an
    /// `api_key.mint` result's `api_key_id`).
    api_key_id: Uuid,
    /// The complete new scope set, replacing the key's current scopes. Every
    /// entry must already exist in the tenant's scope catalog; at least one is
    /// required.
    scopes: Vec<String>,
    /// The complete new group set, replacing the key's current groups. Every
    /// entry must already exist in the tenant's group catalog. Empty clears all
    /// group grants.
    #[serde(default)]
    groups: Vec<String>,
}

pub(super) struct ApiKeyUpdateGrantsExecutor;

#[async_trait]
impl ActionExecutor for ApiKeyUpdateGrantsExecutor {
    fn action_type(&self) -> &'static str {
        "api_key.update_grants"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target key's CURRENT scopes + groups — the full set
        // `update_grants_core` replaces. If an operator (or another maker) edits
        // either between propose and approve, the token shifts and the approved
        // stale replacement is refused (the change is marked `failed`), so a long
        // pending window can't silently clobber an out-of-band edit. Both sets are
        // sorted so a pure reorder isn't a false change. A revoked / cross-tenant /
        // missing target ⇒ `None`, which mismatches the `Some` propose token and
        // fails closed (belt-and-suspenders with `update_grants_core`'s own guards).
        let p: ApiKeyUpdateGrantsParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.identity.api_keys.get() else {
            return Ok(None);
        };
        let row = store
            .find_by_id(p.api_key_id)
            .await
            .map_err(|e| ExecError::Store(format!("api_keys find_by_id: {e}")))?;
        Ok(row
            .filter(|r| r.tenant_id == tenant_id && r.revoked_at.is_none())
            .map(|r| {
                let mut scopes = r.scopes.clone();
                scopes.sort();
                let mut groups = r.groups.clone();
                groups.sort();
                etag_of(&serde_json::json!({ "scopes": scopes, "groups": groups }))
            }))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ApiKeyUpdateGrantsParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Tenant-bound the maker-initiated edit (`Some(tenant_id)`); the shared
        // core normalizes, re-runs the catalog + profile ceiling, and does the
        // conditional write that refuses to resurrect a revoked key. Editing
        // grants produces no secret.
        let out = crate::api_keys::update_grants_core(
            state,
            Some(actor),
            p.api_key_id,
            Some(tenant_id),
            crate::api_keys::UpdateGrantsParams {
                scopes: p.scopes,
                groups: p.groups,
            },
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "api_key_id": out.row.id,
            "key_prefix": out.row.key_prefix,
            "sub": out.row.sub,
            "scopes": out.new_scopes,
            "groups": out.new_groups,
        })))
    }
}

// ---- policy.publish ----
