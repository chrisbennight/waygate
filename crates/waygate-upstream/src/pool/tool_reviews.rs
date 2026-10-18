//! Persist observed contracts before serving replacement sessions. Durable
//! review is an additional refusal gate; it never grants catalog admission.

use super::admission::Admission;
use super::*;
use waygate_catalog::tool_reviews::{PgCatalogStore, ReviewDecision};

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

/// What one pass of [`UpstreamPool::observe_tool_reviews`] left in place,
/// keyed by tool name.
#[derive(Default)]
pub(super) struct ReviewObservations {
    /// Admission decisions. A tool absent here has no recorded review.
    pub(super) decisions: HashMap<String, ReviewDecision>,
    /// Durable drift events recorded by this pass.
    pub(super) drift_events: HashMap<String, uuid::Uuid>,
}

/// Drift events recorded while observing each session of one publication.
/// A tool that changed more than once keeps none: its single Activity row
/// cannot say which of those changes it shows.
pub(super) fn publication_drift_events(
    sessions: impl IntoIterator<Item = HashMap<String, uuid::Uuid>>,
) -> HashMap<String, uuid::Uuid> {
    let mut events = HashMap::new();
    let mut changed_again = std::collections::HashSet::new();
    for session in sessions {
        for (tool, event) in session {
            if events.insert(tool.clone(), event).is_some() {
                changed_again.insert(tool);
            }
        }
    }
    events.retain(|tool, _| !changed_again.contains(tool));
    events
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

    /// Record each tool's observed contract and refresh the local refusal
    /// cache. Returns what each observation left in place, so a caller
    /// admitting the call needs no second read, and a caller that audits the
    /// change itself (`emit_evidence = false`) can name the drift event.
    pub(super) async fn observe_tool_reviews(
        &self,
        entry: &UpstreamEntry,
        name: &str,
        manifest: &UpstreamManifest,
        tools: &[Tool],
        emit_evidence: bool,
    ) -> Result<ReviewObservations, waygate_catalog::tool_reviews::ReviewError> {
        let mut observed = ReviewObservations::default();
        let Some(store) = self.tool_reviews.as_ref() else {
            return Ok(observed);
        };
        for tool in tools {
            let annotation_mode =
                manifest.classification_mode == crate::ClassificationMode::McpAnnotations;
            let class = manifest.tools.iter().find(|class| class.name == tool.name);
            if class.is_none() && !annotation_mode {
                continue;
            }
            let (hash, contract) = review_contract(tool, manifest.classification_mode);
            let side_effects = class.is_some_and(|class| class.side_effects) || annotation_mode;
            let block_changes = class
                .is_some_and(|class| self.quarantine_threshold.covers(class.risk, side_effects));
            if !annotation_mode
                && !block_changes
                && store
                    .get(waygate_core::TenantId::DEFAULT, name, tool.name.as_ref())
                    .await?
                    .is_none()
            {
                continue;
            }
            let observation = store
                .observe_decision(
                    waygate_core::TenantId::DEFAULT,
                    name,
                    tool.name.as_ref(),
                    &hash,
                    &contract,
                    block_changes,
                    annotation_mode.then_some(
                        class
                            .and_then(|class| class.approved_behavior_hash.as_deref())
                            .unwrap_or(""),
                    ),
                )
                .await?;
            if let Some(decision) = observation.decision.as_ref() {
                let mut quarantined = entry
                    .quarantined
                    .write()
                    .expect("upstream quarantine lock poisoned");
                if decision.quarantined {
                    quarantined.insert(tool.name.to_string());
                } else {
                    quarantined.remove(tool.name.as_ref());
                }
                waygate_telemetry::metrics::set_tool_quarantined(name, quarantined.len() as i64);
            }
            if let Some(decision) = observation.decision {
                observed.decisions.insert(tool.name.to_string(), decision);
            }
            if let Some(drift_event) = observation.drift_event {
                observed
                    .drift_events
                    .insert(tool.name.to_string(), drift_event);
            }
            if observation.changed && emit_evidence {
                if let (Some(evidence), Some(review)) = (
                    &self.evidence,
                    store
                        .get(waygate_core::TenantId::DEFAULT, name, tool.name.as_ref())
                        .await?,
                ) {
                    let reports = [DriftReport {
                        tool: tool.name.to_string(),
                        risk: class.map(|class| class.risk),
                        side_effects,
                        quarantined: review.quarantined,
                        drift_event: observation.drift_event,
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
        Ok(observed)
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
        self.review_admission(server, tool, contract, mode)
            .await
            .is_admitted()
    }

    /// The durable review decision for `tool`, read from the store.
    pub(super) async fn review_admission(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
    ) -> Admission {
        let Some(store) = self.tool_reviews.as_ref() else {
            return Admission::Admitted;
        };
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
                return Admission::Unavailable(TemporaryUnavailability::ReviewUnavailable);
            }
        };
        self.review_admission_with(server, tool, contract, mode, review)
            .await
    }

    /// [`Self::review_allows`] for a review decision the caller already read,
    /// such as the one an observation just returned.
    pub(super) async fn review_allows_with(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
        review: Option<ReviewDecision>,
    ) -> bool {
        self.review_admission_with(server, tool, contract, mode, review)
            .await
            .is_admitted()
    }

    /// [`Self::review_admission`] for a review decision the caller already
    /// read.
    pub(super) async fn review_admission_with(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
        review: Option<ReviewDecision>,
    ) -> Admission {
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
        self.review_admission_from_state(server, tool, contract, mode, protected, review)
            .await
    }

    /// Apply the same decision to a row fetched alone or in a discovery batch.
    /// A missing protected observation keeps the existing first-observation
    /// reconciliation path; normal publication has already recorded it.
    pub(super) async fn review_admission_from_state(
        &self,
        server: &str,
        tool: &str,
        contract: Option<&Tool>,
        mode: crate::ClassificationMode,
        protected: bool,
        review: Option<ReviewDecision>,
    ) -> Admission {
        let Some(store) = self.tool_reviews.as_ref() else {
            return Admission::Admitted;
        };
        if !protected && review.is_none() {
            return Admission::Admitted;
        }
        let Some(contract) = contract else {
            // Review compares the live contract, and no connected session
            // advertises one, so the tool is not served now. Dispatch-time
            // callers hold a connection lock, so this does not probe the
            // other lanes to tell a disconnected server apart.
            return Admission::Refused(ToolRefusal::NotInCatalog);
        };
        let (hash, value) = review_contract(contract, mode);
        if let Some(review) = review {
            return review_decision_admission(&review, &hash, protected);
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
            return Admission::Unavailable(TemporaryUnavailability::ReviewUnavailable);
        }
        match store
            .review_state(waygate_core::TenantId::DEFAULT, server, tool)
            .await
        {
            Ok(Some(review)) => review_decision_admission(&review, &hash, true),
            // Observation records nothing until catalog reconciliation has
            // created the tool's identity.
            Ok(None) => Admission::Refused(ToolRefusal::NotInCatalog),
            Err(_) => {
                tracing::warn!(
                    server,
                    tool,
                    "tool review storage unavailable; refusing admission"
                );
                Admission::Unavailable(TemporaryUnavailability::ReviewUnavailable)
            }
        }
    }
}

/// Admit the live contract `hash` against a stored review. A quarantined
/// review refuses whether or not the operator has decided; an unrecorded
/// change to a protected contract awaits review.
fn review_decision_admission(review: &ReviewDecision, hash: &str, protected: bool) -> Admission {
    if review.quarantined {
        Admission::Refused(if review.kept_blocked {
            ToolRefusal::KeptBlocked
        } else {
            ToolRefusal::ReviewRequired
        })
    } else if review.observed_hash == hash || !protected {
        Admission::Admitted
    } else {
        Admission::Refused(ToolRefusal::ReviewRequired)
    }
}
