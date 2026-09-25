//! Request-local discovery reads. Storage work is bounded by batches, while
//! invocation and discovery apply the same contract and review decisions.

use super::contract_binding::{snapshot_inputs_for_classification, DiscoveryReads};
use super::schema_admission::{contract_from_tool, PublishedToolContract};
use super::*;

impl UpstreamPool {
    pub(super) async fn resolve_discovery_batch(
        &self,
        tenant: &str,
        server: &str,
        names: &[String],
    ) -> Result<Vec<ResolvedInvocationTool>, McpError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let epoch = self
            .tool_catalog_epoch
            .stable_generation()
            .ok_or_else(discovery_changed)?;
        let durable = self.discovery_generation().await?;
        let entry = self.entry(server)?;
        let manifest = entry.manifest_snapshot();
        // Retain the first classification, matching the single-name resolver.
        let mut classifications = HashMap::new();
        for classification in &manifest.tools {
            classifications
                .entry(classification.name.as_str())
                .or_insert(classification);
        }
        let wanted: HashSet<&str> = names.iter().map(String::as_str).collect();
        let mut admitted: HashSet<&str> = wanted
            .iter()
            .copied()
            .filter(|name| classifications.contains_key(name))
            .collect();
        let mut published: HashMap<String, PublishedToolContract> = HashMap::new();
        let mut connected = false;
        for slot in &entry.slots {
            let connection = slot.conn.read().await;
            let Some(connection) = connection.as_ref() else {
                continue;
            };
            connected = true;
            let mut advertised = HashMap::new();
            let mut lane_admission = HashMap::new();
            for tool in &connection.live_tools {
                if !wanted.contains(tool.name.as_ref()) {
                    continue;
                }
                advertised.entry(tool.name.as_ref()).or_insert(tool);
                if manifest.classification_mode == crate::ClassificationMode::McpAnnotations {
                    let allowed = admission::tool_is_admitted(
                        classifications.get(tool.name.as_ref()).copied(),
                        manifest.classification_mode,
                        tool,
                    );
                    lane_admission
                        .entry(tool.name.as_ref())
                        .and_modify(|value| *value &= allowed)
                        .or_insert(allowed);
                }
            }
            if manifest.classification_mode == crate::ClassificationMode::McpAnnotations {
                admitted.retain(|name| lane_admission.get(name) == Some(&true));
            }
            for tool in &connection.tools {
                if !wanted.contains(tool.name.as_ref())
                    || published.contains_key(tool.name.as_ref())
                {
                    continue;
                }
                let mut contract = contract_from_tool(tool);
                let original = advertised
                    .get(tool.name.as_ref())
                    .map(|tool| contract_from_tool(tool))
                    .unwrap_or_default();
                contract.behavior_hash = original.behavior_hash;
                contract.advertised_definition = original.definition;
                published.insert(tool.name.to_string(), contract);
            }
        }
        if !connected {
            admitted.clear();
        }
        if self.tool_reviews.is_none() {
            let quarantined = entry
                .quarantined
                .read()
                .expect("upstream quarantine lock poisoned");
            admitted.retain(|name| !quarantined.contains(*name));
        }
        let mut out = Vec::with_capacity(names.len());
        for chunk in names.chunks(waygate_catalog::TOOL_RESOLUTION_BATCH_SIZE) {
            let transitions: Vec<_> = chunk
                .iter()
                .map(|name| self.catalog_transition_state(server, name))
                .collect();
            let reviews = if let Some(store) = self.tool_reviews.as_ref() {
                store
                    .review_states(waygate_core::TenantId::DEFAULT, server, chunk)
                    .await
                    .map_err(|_| {
                        self.catalog_read_error_generation
                            .fetch_add(1, Ordering::AcqRel);
                        discovery_changed()
                    })?
            } else {
                HashMap::new()
            };
            let resolved = match self.catalog.as_ref() {
                Some(catalog) => match catalog.resolve_tools(tenant, server, chunk).await {
                    Ok(rows) if rows.len() == chunk.len() => rows
                        .into_iter()
                        .map(|row| Some(Ok(row)))
                        .collect::<Vec<_>>(),
                    Ok(_) => {
                        self.catalog_read_error_generation
                            .fetch_add(1, Ordering::AcqRel);
                        return Err(discovery_changed());
                    }
                    Err(error) => {
                        let error = Arc::new(error);
                        chunk.iter().map(|_| Some(Err(error.clone()))).collect()
                    }
                },
                None => chunk.iter().map(|_| None).collect(),
            };
            for ((name, catalog), transition) in chunk.iter().zip(resolved).zip(transitions) {
                if !admitted.contains(name.as_str()) || entry.removed.load(Ordering::Acquire) {
                    out.push(ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: name.clone(),
                    });
                    continue;
                }
                let classification = classifications.get(name.as_str()).copied();
                let contract = published.get(name).cloned().unwrap_or_default();
                let protected = classification.is_some_and(|classification| {
                    self.quarantine_threshold.covers(
                        classification.risk,
                        classification.side_effects
                            || manifest.classification_mode
                                == crate::ClassificationMode::McpAnnotations,
                    )
                });
                let review_allows = self
                    .review_allows_from_state(
                        server,
                        name,
                        contract.advertised_definition.as_ref(),
                        manifest.classification_mode,
                        protected,
                        reviews.get(name).cloned(),
                    )
                    .await;
                let inputs = snapshot_inputs_for_classification(
                    Some(&manifest),
                    classification,
                    server,
                    name,
                    contract,
                );
                out.push(
                    self.resolve_snapshot_with_reads(
                        tenant,
                        server,
                        name,
                        inputs,
                        Some(DiscoveryReads {
                            review_allows,
                            catalog,
                            transition,
                        }),
                    )
                    .await,
                );
            }
        }
        if entry.removed.load(Ordering::Acquire)
            || self.tool_catalog_epoch.stable_generation() != Some(epoch)
            || self.discovery_generation().await? != durable
        {
            self.catalog_read_error_generation
                .fetch_add(1, Ordering::AcqRel);
            return Err(discovery_changed());
        }
        Ok(out)
    }
}

fn discovery_changed() -> McpError {
    McpError::internal_error(
        "the governed tool catalog changed or became unavailable during discovery; retry the request",
        Some(serde_json::json!({"error":"catalog_changing", "retryable":true})),
    )
}
