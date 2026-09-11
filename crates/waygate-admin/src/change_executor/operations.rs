//! Governed operational controls. These executors intentionally delegate to
//! the same cores as REST and the direct `gateway-control` MCP surface so the
//! approval path cannot drift on validation or recovery ordering.

use super::*;

pub(super) fn append_param_schemas(
    mut schemas: Vec<(&'static str, Value)>,
) -> Vec<(&'static str, Value)> {
    schemas.extend([
        (
            "upstream.reconnect",
            params_schema_of::<ReconnectServerParams>(),
        ),
        (
            "upstream.refresh_catalog",
            params_schema_of::<RefreshServerCatalogParams>(),
        ),
        (
            "upstream.quarantine.clear",
            params_schema_of::<ClearUpstreamQuarantineParams>(),
        ),
        (
            "catalog.server.unquarantine",
            params_schema_of::<CatalogServerUnquarantineParams>(),
        ),
        ("config.reload", params_schema_of::<ConfigReloadParams>()),
    ]);
    schemas
}

pub(super) struct UpstreamReconnectExecutor;

#[async_trait]
impl ActionExecutor for UpstreamReconnectExecutor {
    fn action_type(&self) -> &'static str {
        "upstream.reconnect"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ReconnectServerParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let response = reconnect_server_core(state, &p)
            .await
            .map_err(map_core_error)?;
        serialize_result(response)
    }
}

pub(super) struct UpstreamRefreshCatalogExecutor;

#[async_trait]
impl ActionExecutor for UpstreamRefreshCatalogExecutor {
    fn action_type(&self) -> &'static str {
        "upstream.refresh_catalog"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: RefreshServerCatalogParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let response = refresh_server_catalog_core(state, actor, &p)
            .await
            .map_err(map_core_error)?;
        serialize_refresh_result(response)
    }
}

pub(super) struct UpstreamClearQuarantineExecutor;

#[async_trait]
impl ActionExecutor for UpstreamClearQuarantineExecutor {
    fn action_type(&self) -> &'static str {
        "upstream.quarantine.clear"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        _tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ClearUpstreamQuarantineParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let response = clear_upstream_quarantine_core(state, &p)
            .await
            .map_err(map_core_error)?;
        serialize_result(response)
    }
}

/// Governed recovery for the durable catalog lifecycle quarantine. This is
/// deliberately distinct from `upstream.quarantine.clear`, which only clears
/// the in-process per-tool drift set.
pub(super) struct CatalogServerUnquarantineExecutor;

#[async_trait]
impl ActionExecutor for CatalogServerUnquarantineExecutor {
    fn action_type(&self) -> &'static str {
        "catalog.server.unquarantine"
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
        let p: CatalogServerUnquarantineParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let catalog = cap(&state.servers.catalog)?;
        let target = catalog
            .server_transition_target(tenant_id, p.server_id)
            .await
            .map_err(|e| ExecError::Store(format!("catalog server transition target: {e}")))?
            .ok_or_else(|| {
                ExecError::Precondition(format!(
                    "catalog server {} does not exist in tenant {tenant_id}",
                    p.server_id
                ))
            })?;
        if target.name != p.expected_name {
            return Err(ExecError::BadParams(format!(
                "`expected_name` does not match catalog server {}",
                p.server_id
            )));
        }
        if target.status != waygate_catalog::CatalogServerStatus::Quarantined {
            return Err(ExecError::Precondition(format!(
                "catalog server `{}` is `{}`, not `quarantined`",
                target.name,
                target.status.as_str(),
            )));
        }
        serde_json::to_string(&target)
            .map(Some)
            .map_err(|e| ExecError::Store(format!("catalog transition witness: {e}")))
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
        let p: CatalogServerUnquarantineParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let witness = target_etag.ok_or_else(|| {
            ExecError::Precondition("catalog transition witness is missing".into())
        })?;
        let target: waygate_catalog::CatalogServerTransitionTarget = serde_json::from_str(witness)
            .map_err(|e| {
                ExecError::Precondition(format!("catalog transition witness is invalid: {e}"))
            })?;
        let response =
            unquarantine_server_if_unchanged_core(state.as_ref(), tenant_id, actor, &p, &target)
                .await
                .map_err(map_core_error)?;
        serialize_result(response)
    }
}

pub(super) struct ConfigReloadExecutor;

#[async_trait]
impl ActionExecutor for ConfigReloadExecutor {
    fn action_type(&self) -> &'static str {
        "config.reload"
    }

    async fn execute(
        &self,
        state: &Arc<AdminState>,
        tenant_id: &str,
        _actor: &Principal,
        params: &Value,
    ) -> Result<ExecOutcome, ExecError> {
        let p: ConfigReloadParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecError::BadParams(e.to_string()))?;
        let response = reload_config_core(state, tenant_id, &p)
            .await
            .map_err(map_core_error)?;
        serialize_result(response)
    }
}

fn serialize_result<T: serde::Serialize>(response: T) -> Result<ExecOutcome, ExecError> {
    serde_json::to_value(response)
        .map(ExecOutcome::result)
        .map_err(|e| ExecError::Store(format!("operation result serialization failed: {e}")))
}

fn serialize_refresh_result(
    response: crate::servers::RefreshCatalogResponse,
) -> Result<ExecOutcome, ExecError> {
    if response.outcome == "failed" {
        return Err(ExecError::Precondition(format!(
            "upstream `{}` catalog refresh failed; the prior session and inventory remain active",
            response.server
        )));
    }
    serialize_result(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refresh_response(outcome: &str) -> crate::servers::RefreshCatalogResponse {
        crate::servers::RefreshCatalogResponse {
            server: "fetchlayer".to_owned(),
            outcome: outcome.to_owned(),
            session_replaced: outcome != "failed",
            before_tool_count: 15,
            after_tool_count: 16,
            added: vec!["twitter.search".to_owned()],
            removed: Vec::new(),
            schema_changed: Vec::new(),
        }
    }

    #[test]
    fn failed_refresh_fails_the_governed_change_loudly() {
        let error = serialize_refresh_result(refresh_response("failed"))
            .expect_err("a failed replacement must not mark the change executed");
        assert!(matches!(error, ExecError::Precondition(_)));
    }

    #[test]
    fn successful_refresh_records_the_structured_result() {
        let outcome = serialize_refresh_result(refresh_response("updated"))
            .expect("a completed replacement is executable");
        assert_eq!(outcome.result["outcome"], "updated");
        assert_eq!(outcome.result["added"][0], "twitter.search");
    }
}
