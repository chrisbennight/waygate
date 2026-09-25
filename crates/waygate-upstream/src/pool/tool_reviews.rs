//! Persist observed contracts before serving replacement sessions. Durable
//! review is an additional refusal gate; it never grants catalog admission.

use super::*;
use waygate_catalog::tool_reviews::PgCatalogStore;

pub(super) fn review_contract(
    tool: &Tool,
    mode: crate::ClassificationMode,
) -> (String, serde_json::Value) {
    match mode {
        crate::ClassificationMode::Manifest => (
            waygate_catalog::schema_hash(
                tool.name.as_ref(),
                tool.description.as_deref(),
                &tool.input_schema,
            ),
            serde_json::json!({"name":tool.name,"description":tool.description,"inputSchema":tool.input_schema}),
        ),
        crate::ClassificationMode::McpAnnotations => (
            crate::security_metadata::behavior_hash(tool),
            serde_json::to_value(tool).expect("MCP tool descriptor serializes"),
        ),
    }
}

impl UpstreamPool {
    pub(super) fn runtime_quarantine_threshold(&self) -> QuarantineThreshold {
        if self.tool_reviews.is_some() {
            QuarantineThreshold::Off
        } else {
            self.quarantine_threshold
        }
    }

    /// Refresh the local refusal cache after an exact durable acceptance.
    /// The database remains authoritative at every dispatch.
    pub async fn release_accepted_tool(&self, server: &str, tool: &str, hash: &str) {
        let (Some(store), Some(entry)) = (
            self.tool_reviews.as_ref(),
            self.entries.load().get(server).cloned(),
        ) else {
            return;
        };
        if let Ok(Some(review)) = store
            .get(waygate_core::TenantId::DEFAULT, server, tool)
            .await
        {
            if !review.quarantined && review.observed_hash == hash {
                let mut quarantined = entry
                    .quarantined
                    .write()
                    .expect("upstream quarantine lock poisoned");
                if quarantined.remove(tool) {
                    self.tool_catalog_epoch.begin_change().commit();
                }
                waygate_telemetry::metrics::set_tool_quarantined(server, quarantined.len() as i64);
            }
        }
    }

    pub fn tool_review_store(&self) -> Option<&Arc<PgCatalogStore>> {
        self.tool_reviews.as_ref()
    }

    /// Called before exposing the pool. Restore durable refusal state and seed
    /// previously unobserved contracts from the initial connections.
    pub async fn with_tool_reviews(mut self, store: Arc<PgCatalogStore>) -> Self {
        self.tool_reviews = Some(store);
        let entries = self.entries.load_full();
        for (name, entry) in entries.iter() {
            for slot in &entry.slots {
                if let Some(conn) = slot.conn.read().await.as_ref() {
                    if self
                        .observe_tool_reviews(
                            entry,
                            name,
                            &entry.manifest_snapshot(),
                            &conn.live_tools,
                            true,
                        )
                        .await
                        .is_err()
                    {
                        // Admission independently refuses unrecorded or changed
                        // contracts; an oversized descriptor must not stop peers.
                        tracing::warn!(server = %name, "initial tool review observation failed; affected contracts remain unavailable");
                    }
                    break;
                }
            }
        }
        drop(entries);
        self
    }

    pub(super) async fn observe_tool_reviews(
        &self,
        entry: &UpstreamEntry,
        name: &str,
        manifest: &UpstreamManifest,
        tools: &[Tool],
        emit_evidence: bool,
    ) -> Result<(), waygate_catalog::tool_reviews::ReviewError> {
        let Some(store) = self.tool_reviews.as_ref() else {
            return Ok(());
        };
        for tool in tools {
            let Some(class) = manifest.tools.iter().find(|class| class.name == tool.name) else {
                continue;
            };
            let (hash, contract) = review_contract(tool, manifest.classification_mode);
            let side_effects = class.side_effects
                || matches!(
                    manifest.classification_mode,
                    crate::ClassificationMode::McpAnnotations
                );
            if !self.quarantine_threshold.covers(class.risk, side_effects)
                && store
                    .get(waygate_core::TenantId::DEFAULT, name, &class.name)
                    .await?
                    .is_none()
            {
                continue;
            }
            let changed = store
                .observe(
                    waygate_core::TenantId::DEFAULT,
                    name,
                    &class.name,
                    &hash,
                    &contract,
                    self.quarantine_threshold.covers(class.risk, side_effects),
                )
                .await?;
            if let Some(review) = store
                .get(waygate_core::TenantId::DEFAULT, name, &class.name)
                .await?
            {
                let mut quarantined = entry
                    .quarantined
                    .write()
                    .expect("upstream quarantine lock poisoned");
                if review.quarantined {
                    quarantined.insert(class.name.clone());
                } else {
                    quarantined.remove(&class.name);
                }
                waygate_telemetry::metrics::set_tool_quarantined(name, quarantined.len() as i64);
            }
            if changed && emit_evidence {
                if let (Some(evidence), Some(review)) = (
                    &self.evidence,
                    store
                        .get(waygate_core::TenantId::DEFAULT, name, &class.name)
                        .await?,
                ) {
                    let reports = [DriftReport {
                        tool: class.name.clone(),
                        risk: Some(class.risk),
                        side_effects,
                        quarantined: review.quarantined,
                    }];
                    Self::emit_drift_audit(
                        evidence,
                        name,
                        &reports,
                        waygate_telemetry::correlation::current_trace_id(),
                    )
                    .await;
                }
            }
        }
        Ok(())
    }

    /// Verify the reviewed identity against every connected lane's raw catalog.
    /// This also detects replacements too large to persist as review evidence.
    pub async fn review_contract_is_current(
        &self,
        server: &str,
        tool: &str,
        mode: crate::ClassificationMode,
        hash: &str,
    ) -> bool {
        let Some(entry) = self.entries.load().get(server).cloned() else {
            return false;
        };
        let mut guards = Vec::with_capacity(entry.slots.len());
        for slot in &entry.slots {
            guards.push(slot.conn.read().await);
        }
        if entry.manifest_snapshot().classification_mode != mode {
            return false;
        }
        let mut connected = false;
        for conn in guards.iter().filter_map(|guard| guard.as_ref()) {
            connected = true;
            let mut found = false;
            for descriptor in conn.live_tools.iter().filter(|item| item.name == tool) {
                found = true;
                if review_contract(descriptor, mode).0 != hash {
                    return false;
                }
            }
            if !found {
                return false;
            }
        }
        connected
    }

    pub(super) async fn review_allows(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
    ) -> bool {
        let Some(store) = self.tool_reviews.as_ref() else {
            return true;
        };
        let protected = self.entries.load().get(server).is_some_and(|entry| {
            let manifest = entry.manifest_snapshot();
            manifest
                .tools
                .iter()
                .find(|c| c.name == tool)
                .is_some_and(|c| {
                    self.quarantine_threshold.covers(
                        c.risk,
                        c.side_effects || matches!(mode, crate::ClassificationMode::McpAnnotations),
                    )
                })
        });
        let review = match store
            .review_state(waygate_core::TenantId::DEFAULT, server, tool)
            .await
        {
            Ok(review) => review,
            Err(_) => {
                tracing::warn!(
                    server,
                    tool,
                    "tool review storage unavailable; refusing admission"
                );
                return false;
            }
        };
        self.review_allows_from_state(server, tool, contract, mode, protected, review)
            .await
    }

    /// Apply the same decision to a row fetched alone or in a discovery batch.
    /// A missing protected observation keeps the existing first-observation
    /// reconciliation path; normal publication has already recorded it.
    pub(super) async fn review_allows_from_state(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
        protected: bool,
        review: Option<(String, bool)>,
    ) -> bool {
        let Some(store) = self.tool_reviews.as_ref() else {
            return true;
        };
        if !protected && review.is_none() {
            return true;
        }
        let Some(contract) = contract else {
            return false;
        };
        let (hash, value) = review_contract(contract, mode);
        if let Some((observed_hash, quarantined)) = review {
            return !quarantined && (observed_hash == hash || !protected);
        }
        if store
            .observe(
                waygate_core::TenantId::DEFAULT,
                server,
                tool,
                &hash,
                &value,
                protected,
            )
            .await
            .is_err()
        {
            return false;
        }
        match store
            .review_state(waygate_core::TenantId::DEFAULT, server, tool)
            .await
        {
            Ok(Some((observed_hash, quarantined))) => !quarantined && observed_hash == hash,
            Ok(None) => false,
            Err(_) => {
                tracing::warn!(
                    server,
                    tool,
                    "tool review storage unavailable; refusing admission"
                );
                false
            }
        }
    }
}
