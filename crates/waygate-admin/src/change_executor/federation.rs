//! Federated-peer change executors.
//! Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// `peer.create` proposes a new federated peer. Params mirror the
/// dashboard/REST create body ([`CreatePeerRequest`]); the executor runs the
/// shared `create_peer_core`, so peer_name/issuer/jwks_url validation (with
/// normalization), the per-tenant name collision, and the fail-closed audit
/// are identical to the direct-admin path.
pub(super) struct PeerCreateExecutor;

#[async_trait]
impl ActionExecutor for PeerCreateExecutor {
    fn action_type(&self) -> &'static str {
        "peer.create"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let req: CreatePeerRequest = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let peer = create_peer_core(
            state,
            tenant_id,
            Some(actor),
            &req.peer_name,
            &req.issuer,
            &req.jwks_url,
        )
        .await
        .map_err(map_core_error)?;
        // Maker-visible result: non-sensitive identifiers ONLY. The issuer /
        // jwks_url URL fields are OMITTED — a pre-existing peer row can carry
        // `user:pass@host` userinfo (input validation rejects new ones, but
        // older rows / DB-level inserts can bypass it), and this result is
        // returned to the non-admin maker's poll/list path; echoing the raw
        // URLs would leak any embedded credentials. The core
        // already strips userinfo from its audit reason via
        // `sanitize_url_for_audit`; the propose result must be at least as safe.
        Ok(ExecOutcome::result(serde_json::json!({
            "peer_id": peer.id,
            "peer_name": peer.peer_name,
            "trust_tier": peer.trust_tier,
        })))
    }
}

// ---- peer.update ----

/// Params for `peer.update`: the target id plus the same optional fields as
/// [`crate::federated_peers::UpdatePeerRequest`] (unset ⇒ store COALESCE
/// preserves the current value).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerUpdateParams {
    pub(super) id: Uuid,
    #[serde(default)]
    pub(super) peer_name: Option<String>,
    #[serde(default)]
    pub(super) issuer: Option<String>,
    #[serde(default)]
    jwks_url: Option<String>,
}

pub(super) struct PeerUpdateExecutor;

#[async_trait]
impl ActionExecutor for PeerUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "peer.update"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target peer's CURRENT mutable fields. The issuer /
        // jwks_url are credential-bearing, but the token is a one-way sha256, so
        // hashing them is safe — the raw URLs never leave this function. An
        // out-of-band edit between propose and approve shifts the token and the
        // approved update is refused rather than clobbering it.
        let p: PeerUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let Some(store) = state.federation.federated_peers.get() else {
            return Ok(None);
        };
        let peer = store
            .get(tenant_id, p.id)
            .await
            .map_err(|e| ExecError::Store(format!("peer get: {e}")))?;
        Ok(peer.map(|pe| {
            etag_of(&serde_json::json!({
                "peer_name": pe.peer_name,
                "issuer": pe.issuer,
                "jwks_url": pe.jwks_url,
                "trust_tier": pe.trust_tier,
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
        let p: PeerUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Validate-before-irreversible: at least one field must change, else
        // the "update" is a no-op masquerading as a mutation.
        if p.peer_name.is_none() && p.issuer.is_none() && p.jwks_url.is_none() {
            return Err(ExecError::BadParams(
                "at least one of peer_name / issuer / jwks_url is required".into(),
            ));
        }
        // update_peer_core validates each supplied field and returns NotFound
        // when the peer is gone (mapped to Precondition by map_core_error).
        let peer = update_peer_core(
            state,
            tenant_id,
            Some(actor),
            p.id,
            p.peer_name.as_deref(),
            p.issuer.as_deref(),
            p.jwks_url.as_deref(),
        )
        .await
        .map_err(map_core_error)?;
        // Non-sensitive identifiers ONLY — see peer.create above: the
        // issuer / jwks_url URL fields are omitted so a maker proposing an
        // unrelated change (e.g. a name change) can't harvest a
        // pre-existing credential-bearing URL through execution_result.
        Ok(ExecOutcome::result(serde_json::json!({
            "peer_id": peer.id,
            "peer_name": peer.peer_name,
            "trust_tier": peer.trust_tier,
        })))
    }
}

// ---- peer.delete ----

#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct PeerDeleteParams {
    id: Uuid,
}

pub(super) struct PeerDeleteExecutor;

#[async_trait]
impl ActionExecutor for PeerDeleteExecutor {
    fn action_type(&self) -> &'static str {
        "peer.delete"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: PeerDeleteParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // `Ok(false)` ⇒ peer already gone in this tenant — precondition failure.
        let deleted = delete_peer_core(state, tenant_id, Some(actor), p.id)
            .await
            .map_err(map_core_error)?;
        if !deleted {
            return Err(ExecError::Precondition(format!(
                "federated peer {} not found in this tenant",
                p.id
            )));
        }
        Ok(ExecOutcome::result(serde_json::json!({
            "peer_id": p.id,
            "deleted": true,
        })))
    }
}

// ---- rbac.role.create ----
