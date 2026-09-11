//! Tenant + audit retention/routing change-executors — split from
//! `change_executor.rs`. Child module: shared helpers (`map_core_error`,
//! `etag_of`, ...) resolve via `use super::*;`.

use super::*;

/// Params for `tenant.update`: the new display name for the maker's OWN
/// tenant. The target is the change request's `tenant_id` (never a param), so a
/// maker can only rename the tenant it belongs to. Deliberately
/// display-name-only: `status` (active/suspended) stays operator-only via the
/// direct admin API, because letting a maker suspend its own tenant through the
/// single-approval propose path is a self-lockout footgun — and `tenant.delete`
/// is not proposable at all (a tenant delete cascades `change_requests`, so a
/// self-delete would erase the very request executing it; see
/// docs/agents/hitl-control-plane.md).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct TenantUpdateParams {
    /// New display name. Same bounds as the tenant-create path
    /// (`validate_display_name`), enforced inside `update_tenant_core`.
    display_name: String,
}

pub(super) struct TenantUpdateExecutor;

#[async_trait]
impl ActionExecutor for TenantUpdateExecutor {
    fn action_type(&self) -> &'static str {
        "tenant.update"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        _params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the ONLY field this update writes — the tenant's current
        // display_name (`status` is passed as None below, so `update_tenant_core`
        // never touches it). If an operator renames the tenant out-of-band during
        // the pending window, the token shifts and the approved stale rename is
        // refused, rather than clobbering the operator's value: the core does an
        // unconditional `UPDATE … WHERE id` with no since-version guard.
        let Some(store) = state.identity.tenants.get() else {
            return Ok(None);
        };
        let tenant = store
            .get(tenant_id)
            .await
            .map_err(|e| ExecError::Store(format!("tenants get: {e}")))?;
        Ok(tenant.map(|t| etag_of(&serde_json::json!({ "display_name": t.display_name }))))
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: TenantUpdateParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // display_name only; `status` stays None so the maker cannot suspend its
        // own tenant through propose. Target is the change request's tenant_id,
        // confining the rename to the maker's own tenant. Reuses the same
        // `update_tenant_core` the REST PATCH and dashboard edit call, so
        // validation, the status-cache invalidation, and the fail-closed
        // `tenants.update` audit are identical across surfaces. `Ok(None)` ⇒ the
        // tenant was deleted between propose and approve — a precondition failure.
        let tenant = update_tenant_core(state, tenant_id, Some(&p.display_name), None, actor)
            .await
            .map_err(map_core_error)?
            .ok_or_else(|| ExecError::Precondition(format!("tenant {tenant_id} not found")))?;
        Ok(ExecOutcome::result(serde_json::json!({
            "tenant_id": tenant.id,
            "display_name": tenant.display_name,
        })))
    }
}

// ---- audit.retention.set / clear ----

/// Fingerprint the CURRENT `(tenant, category)` retention row's state for the
/// freshness guard. Shared by the `audit.retention.set` (upsert) and `.clear`
/// (delete) `capture_etag` overrides: both target a NATURAL key whose row can
/// be created, changed, or removed between propose and approve, and the
/// upsert/delete cores carry no since-version guard, so a stale approval must
/// fail closed.
///
/// Returns **`Some` whenever the store is reachable** — absence is itself a
/// guarded state, captured as a `{present:false}` sentinel, distinct from any
/// present row's `{present:true, …}` token. A bare `None` baseline would
/// store no token, and `execute_approved`'s recheck is
/// gated on `Some(target_etag)`, so an absent-at-propose row would be left
/// UNGUARDED — a row created before approval could then be clobbered. With the
/// sentinel, absent→present (or →changed) mismatches and is refused, while
/// absent→absent matches (so `.clear` stays idempotent for the stable-absent
/// case: the no-op clear runs and reports success). `None` is returned only when
/// the store is unconfigured at capture time, which the execute path independently
/// fails closed on — matching the store-absent capture in the other executors.
async fn retention_row_etag(
    state: &Arc<AdminState>,
    tenant_id: &str,
    category: &str,
) -> Result<Option<String>, ExecError> {
    let Some(store) = state.observability.retention.get() else {
        return Ok(None);
    };
    let rows = store
        .list(Some(tenant_id))
        .await
        .map_err(|e| ExecError::Store(format!("retention list: {e}")))?;
    let row = rows.into_iter().find(|r| r.category == category);
    Ok(Some(etag_of(&match row {
        Some(r) => serde_json::json!({ "present": true, "delete_after_days": r.delete_after_days }),
        None => serde_json::json!({ "present": false }),
    })))
}

/// Fingerprint the CURRENT `(tenant, exporter_name)` routing row's state
/// (`enabled` + `config`) for the freshness guard. The routing twin of
/// [`retention_row_etag`] — see it for the always-`Some` sentinel rationale
/// and the natural-key / idempotency semantics.
async fn routing_row_etag(
    state: &Arc<AdminState>,
    tenant_id: &str,
    exporter_name: &str,
) -> Result<Option<String>, ExecError> {
    let Some(store) = state.observability.routing.get() else {
        return Ok(None);
    };
    let rows = store
        .list(Some(tenant_id))
        .await
        .map_err(|e| ExecError::Store(format!("routing list: {e}")))?;
    let row = rows.into_iter().find(|r| r.exporter_name == exporter_name);
    Ok(Some(etag_of(&match row {
        Some(r) => serde_json::json!({ "present": true, "enabled": r.enabled, "config": r.config }),
        None => serde_json::json!({ "present": false }),
    })))
}

/// Params for `audit.retention.set`: the retention window for one audit
/// category in the maker's OWN tenant. Tenant comes from the change request's
/// `tenant_id` (never a param), so a maker configures only its own retention.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct AuditRetentionSetParams {
    /// An `EvidenceCategory.as_str()` value (`"invocation"`,
    /// `"admin_mutation"`, …) or the literal `"*"` wildcard — the category
    /// whose window to set.
    category: String,
    /// Rows older than this many days are deleted once the enforcement sweep
    /// ships (today the policy is stored, not enforced). Must be > 0.
    delete_after_days: i32,
}

pub(super) struct AuditRetentionSetExecutor;

#[async_trait]
impl ActionExecutor for AuditRetentionSetExecutor {
    fn action_type(&self) -> &'static str {
        "audit.retention.set"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Natural-key upsert: fingerprint the target `(tenant, category)` row's
        // current state so an out-of-band change — or a row created under us —
        // between propose and approve fails closed rather than clobbering the
        // operator's value.
        let p: AuditRetentionSetParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        retention_row_etag(state, tenant_id, &p.category).await
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: AuditRetentionSetParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Upsert with the maker's fully-specified target value, scoped to the
        // change request's tenant. Reuses `set_retention_core` so the > 0
        // validation and the fail-closed, target-tenant-chained
        // `audit_retention.upsert` audit match the REST PUT path.
        let view = set_retention_core(
            state,
            tenant_id,
            &p.category,
            p.delete_after_days,
            Some(actor),
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(
            serde_json::to_value(view).map_err(|e| ExecError::Store(e.to_string()))?,
        ))
    }
}

/// Params for `audit.retention.clear`: remove the retention policy for one
/// category in the maker's OWN tenant (tenant from the change request).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct AuditRetentionClearParams {
    /// The category whose policy to clear (an `EvidenceCategory.as_str()` value
    /// or `"*"`).
    category: String,
}

pub(super) struct AuditRetentionClearExecutor;

#[async_trait]
impl ActionExecutor for AuditRetentionClearExecutor {
    fn action_type(&self) -> &'static str {
        "audit.retention.clear"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target `(tenant, category)` row so an out-of-band
        // edit (clearing a now-different policy) or a row created after proposal
        // fails closed; absent-at-both stays a no-op idempotent success (see
        // `retention_row_etag`).
        let p: AuditRetentionClearParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        retention_row_etag(state, tenant_id, &p.category).await
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: AuditRetentionClearParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Idempotent clear (the `.clear`/`.revoke` convention): clearing an
        // absent policy is the desired end-state already, so `removed == false`
        // is still success. `clear_retention_core` audits only on actual removal.
        let removed = clear_retention_core(state, tenant_id, &p.category, Some(actor))
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "tenant_id": tenant_id,
            "category": p.category,
            "removed": removed,
        })))
    }
}

// ---- audit.routing.set / clear ----

/// JSON `{}` — the default exporter config, mirroring the REST PUT path's
/// `default_config` so an omitted `config` means the same thing on both
/// surfaces.
fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

/// Params for `audit.routing.set`: (re)configure one evidence exporter for the
/// maker's OWN tenant. Tenant comes from the change request's `tenant_id`.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct AuditRoutingSetParams {
    /// The exporter to configure (`"ocsf"`, `"syslog"`, `"s3"`, `"webhook"`,
    /// …). One row per `(tenant, exporter_name)`.
    exporter_name: String,
    /// Whether this exporter receives the tenant's events.
    enabled: bool,
    /// Exporter-specific config; each exporter interprets its own schema.
    /// Defaults to `{}`.
    #[serde(default = "empty_object")]
    config: Value,
}

pub(super) struct AuditRoutingSetExecutor;

#[async_trait]
impl ActionExecutor for AuditRoutingSetExecutor {
    fn action_type(&self) -> &'static str {
        "audit.routing.set"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Natural-key upsert: fingerprint the target `(tenant, exporter_name)`
        // row's current `enabled`+`config` so an out-of-band reroute/disable — or
        // a row created under us — between propose and approve fails closed
        // rather than silently clobbering the operator's routing.
        let p: AuditRoutingSetParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        routing_row_etag(state, tenant_id, &p.exporter_name).await
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: AuditRoutingSetParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Upsert with the maker's fully-specified enabled+config, scoped to the
        // change request's tenant. Reuses `set_routing_core` so the validation
        // and the fail-closed, target-tenant-chained `audit_routing.upsert`
        // audit match the REST PUT path — an admin (or maker) must not silently
        // reroute or disable a tenant's evidence without a chain-covered row.
        let view = set_routing_core(
            state,
            tenant_id,
            &p.exporter_name,
            p.enabled,
            &p.config,
            Some(actor),
        )
        .await
        .map_err(map_core_error)?;
        Ok(ExecOutcome::result(
            serde_json::to_value(view).map_err(|e| ExecError::Store(e.to_string()))?,
        ))
    }
}

/// Params for `audit.routing.clear`: remove one exporter's routing row for the
/// maker's OWN tenant (tenant from the change request).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct AuditRoutingClearParams {
    /// The exporter whose routing row to remove.
    exporter_name: String,
}

pub(super) struct AuditRoutingClearExecutor;

#[async_trait]
impl ActionExecutor for AuditRoutingClearExecutor {
    fn action_type(&self) -> &'static str {
        "audit.routing.clear"
    }

    async fn capture_etag(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<Option<String>, ExecError> {
        // Fingerprint the target `(tenant, exporter_name)` row so clearing a
        // now-different routing config, or a row created after proposal, fails
        // closed; absent-at-both stays a no-op idempotent success (see
        // `routing_row_etag`).
        let p: AuditRoutingClearParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        routing_row_etag(state, tenant_id, &p.exporter_name).await
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: AuditRoutingClearParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        // Idempotent clear: removing an absent routing row is the desired
        // end-state already, so `removed == false` is still success.
        // `clear_routing_core` audits only on actual removal (the last row's
        // removal resumes the configured-targets fallback — a material change).
        let removed = clear_routing_core(state, tenant_id, &p.exporter_name, Some(actor))
            .await
            .map_err(map_core_error)?;
        Ok(ExecOutcome::result(serde_json::json!({
            "tenant_id": tenant_id,
            "exporter_name": p.exporter_name,
            "removed": removed,
        })))
    }
}

// ---- upstream_session.revoke ----
