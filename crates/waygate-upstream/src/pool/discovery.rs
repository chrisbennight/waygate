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
        let annotation_mode =
            manifest.classification_mode == crate::ClassificationMode::McpAnnotations;
        let mut tallies: HashMap<&str, admission::LaneTally> = HashMap::new();
        let mut listed: HashSet<&str> = HashSet::new();
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
                let Some(&name) = wanted.get(tool.name.as_ref()) else {
                    continue;
                };
                advertised.entry(tool.name.as_ref()).or_insert(tool);
                listed.insert(name);
                if annotation_mode {
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
            if annotation_mode {
                for name in &wanted {
                    tallies
                        .entry(name)
                        .or_default()
                        .record_lane(lane_admission.get(name).copied());
                }
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
                contract.native_tasks = super::tasks::supported(connection);
                published.insert(tool.name.to_string(), contract);
            }
        }
        // The same rules as single-name admission, decided for every name
        // in the batch; discovery serves nothing from a server with no
        // connected session.
        let admissions: HashMap<&str, admission::Admission> = {
            let drift_quarantined = self.tool_reviews.is_none().then(|| {
                entry
                    .quarantined
                    .read()
                    .expect("upstream quarantine lock poisoned")
            });
            wanted
                .iter()
                .map(|&name| {
                    let classified = classifications.contains_key(name);
                    let admission = if !connected {
                        admission::Admission::Unavailable(TemporaryUnavailability::NoConnectedLane)
                    } else if annotation_mode {
                        tallies
                            .get(name)
                            .copied()
                            .unwrap_or_default()
                            .annotation_admission(classified)
                    } else if classified {
                        admission::Admission::Admitted
                    } else if listed.contains(name) {
                        admission::Admission::Refused(ToolRefusal::Unclassified)
                    } else {
                        admission::Admission::Refused(ToolRefusal::NotInCatalog)
                    };
                    let admission = if admission.is_admitted()
                        && drift_quarantined
                            .as_ref()
                            .is_some_and(|quarantined| quarantined.contains(name))
                    {
                        admission::Admission::Refused(ToolRefusal::DriftQuarantined)
                    } else {
                        admission
                    };
                    (name, admission)
                })
                .collect()
        };
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
                if entry.removed.load(Ordering::Acquire) {
                    out.push(ResolvedInvocationTool::refused(
                        server,
                        name,
                        ToolRefusal::NotInCatalog,
                    ));
                    continue;
                }
                if let Some(refusal) = admissions[name.as_str()].refusal(server, name) {
                    out.push(refusal);
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
                let review = self
                    .review_admission_from_state(
                        server,
                        name,
                        contract.advertised_definition.as_ref(),
                        manifest.classification_mode,
                        protected,
                        reviews.get(name).cloned(),
                        admission::Effects::Record,
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
                            review,
                            catalog,
                            transition,
                        }),
                        admission::Effects::Record,
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
