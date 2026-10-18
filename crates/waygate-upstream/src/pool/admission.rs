//! Tool admission for manifest-classified and annotation-native upstreams.
//!
//! This module is a child of [`super`], so admission stays close to the pool
//! without expanding the pool's transport and lifecycle implementation.

use super::contract_binding::DiscoveryReads;
use super::*;
use waygate_catalog::tool_reviews::ReviewDecision;

/// Whether resolving a tool may act beyond returning its decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Effects {
    /// The call and discovery paths: log each refusal, tell concurrent
    /// discovery about an authoritative catalog read failure, and record the
    /// first observation of a protected contract.
    Record,
    /// A status query: reach the same decision and do nothing else.
    ReadOnly,
}

impl Effects {
    pub(super) fn records(self) -> bool {
        matches!(self, Self::Record)
    }
}

/// One tool's review and catalog reads, taken in a bounded batch before its
/// admission is decided.
pub(super) struct BatchReads {
    /// The stored review decision, or `Err` when the review store could not
    /// be read. `Ok(None)` when no review store is configured.
    pub(super) review: Result<Option<ReviewDecision>, ()>,
    /// The catalog row, or `None` when no catalog is configured.
    pub(super) catalog:
        Option<Result<waygate_catalog::ResolvedTool, Arc<waygate_catalog::CatalogError>>>,
    /// The manifest/catalog transition observed before the reads.
    pub(super) transition: Option<CatalogTransition>,
}

/// Where admission's review and catalog reads come from. The source also
/// decides the [`Effects`]: only the call path records anything.
pub(super) enum AdmissionSource {
    /// The call path reads through the generation cache.
    Call,
    /// A status query supplies batch reads.
    Status(BatchReads),
}

impl UpstreamPool {
    /// Decide whether `tool_name` on `server` runs, and why not. Invocation
    /// and the read-only [`UpstreamPool::refusals`] query both come here, so
    /// they apply the same checks in the same order; they differ only in
    /// where the reads come from and in whether anything is recorded.
    pub(super) async fn admit(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
        source: AdmissionSource,
    ) -> ResolvedInvocationTool {
        let effects = match source {
            AdmissionSource::Call => Effects::Record,
            AdmissionSource::Status(_) => Effects::ReadOnly,
        };
        // Without durable review storage, the in-process quarantine is the
        // authority. With storage, the snapshot resolver checks the durable
        // decision so an acceptance on another replica can take effect.
        // Clone the entry out from under the lock-free `load()` BEFORE the
        // `.await` — an `if let` scrutinee's temporary (the arc-swap guard)
        // would otherwise live across the await, holding the guard over a
        // suspension point.
        let entry = self.entries.load().get(server).cloned();
        // ONE manifest snapshot governs admission, mode, hash, and facts;
        // the separately read published contract is bound to this generation
        // inside the resolver (published behavior hash == approved hash).
        let manifest = entry.as_ref().map(|entry| entry.manifest_snapshot());
        if let (Some(entry), Some(manifest)) = (entry.as_ref(), manifest.as_ref()) {
            if self.tool_reviews.is_none() && entry.is_quarantined(tool_name).await {
                if effects.records() {
                    tracing::info!(
                        %tenant, %server, tool = %tool_name,
                        "tool is in-process quarantined (drift-triggered); refusing dispatch",
                    );
                }
                return ResolvedInvocationTool::refused(
                    server,
                    tool_name,
                    ToolRefusal::DriftQuarantined,
                );
            }
            let admission = entry_tool_admission(entry, manifest, tool_name).await;
            if let Some(refusal) = admission.refusal(server, tool_name) {
                if effects.records() {
                    tracing::info!(
                        %tenant, %server, tool = %tool_name, ?admission,
                        "tool is not admitted by the current classification mode and behavior hash",
                    );
                }
                return refusal;
            }
        }
        let published =
            schema_admission::published_tool_contract(entry.as_deref(), tool_name).await;
        let mode = manifest
            .as_ref()
            .map_or(crate::ClassificationMode::Manifest, |manifest| {
                manifest.classification_mode
            });
        let advertised = published.advertised_definition.as_ref();
        let reads = match source {
            AdmissionSource::Call => {
                self.admission_reads(tenant, server, tool_name, mode, advertised)
                    .await
            }
            AdmissionSource::Status(batch) => Some(DiscoveryReads {
                review: match batch.review {
                    Ok(review) => {
                        self.review_admission_with(
                            server,
                            tool_name,
                            advertised,
                            mode,
                            review,
                            Effects::ReadOnly,
                        )
                        .await
                    }
                    Err(()) => Admission::Unavailable(TemporaryUnavailability::ReviewUnavailable),
                },
                catalog: batch.catalog,
                transition: batch.transition,
            }),
        };
        self.resolve_snapshot_with_reads(
            tenant,
            server,
            tool_name,
            contract_binding::snapshot_inputs_for(manifest.as_ref(), server, tool_name, published),
            reads,
            effects,
        )
        .await
    }
}

/// One admission decision and, when it does not admit, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    Admitted,
    Refused(ToolRefusal),
    Unavailable(TemporaryUnavailability),
}

impl Admission {
    pub(super) fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    /// The resolution this decision forces, or `None` when it admits.
    pub(super) fn refusal(self, server: &str, tool: &str) -> Option<ResolvedInvocationTool> {
        match self {
            Self::Admitted => None,
            Self::Refused(reason) => Some(ResolvedInvocationTool::refused(server, tool, reason)),
            Self::Unavailable(reason) => {
                Some(ResolvedInvocationTool::unavailable(server, tool, reason))
            }
        }
    }
}

/// Re-check admission on the dispatch path. Publication normally filters the
/// same contract, but this independent gate prevents a stale client cache
/// from reaching a name the manifest does not classify or, in annotation
/// mode, a tool whose reviewed behavior hash no longer matches.
pub(super) async fn entry_tool_admission(
    entry: &UpstreamEntry,
    manifest: &crate::UpstreamManifest,
    tool_name: &str,
) -> Admission {
    let classification = manifest.tools.iter().find(|tool| tool.name == tool_name);
    if matches!(
        manifest.classification_mode,
        crate::ClassificationMode::Manifest
    ) {
        if classification.is_some() {
            return Admission::Admitted;
        }
        // Manifest admission is by name alone. The live sessions only tell
        // an advertised but unclassified name apart from one nobody serves.
        for slot in &entry.slots {
            let connection = slot.conn.read().await;
            if connection.as_ref().is_some_and(|connection| {
                connection
                    .live_tools
                    .iter()
                    .any(|tool| tool.name.as_ref() == tool_name)
            }) {
                return Admission::Refused(ToolRefusal::Unclassified);
            }
        }
        return Admission::Refused(ToolRefusal::NotInCatalog);
    }
    let mut tally = LaneTally::default();
    for slot in &entry.slots {
        let connection = slot.conn.read().await;
        let Some(connection) = connection.as_ref() else {
            continue;
        };
        let mut matching = connection
            .live_tools
            .iter()
            .filter(|tool| tool.name.as_ref() == tool_name)
            .peekable();
        let advertised = matching.peek().is_some();
        tally.record_lane(advertised.then(|| {
            matching
                .all(|tool| tool_is_admitted(classification, manifest.classification_mode, tool))
        }));
    }
    tally.annotation_admission(classification.is_some())
}

/// What the connected sessions advertise under one name, gathered one lane at
/// a time, for annotation-mode admission.
///
/// EVERY connected lane must admit the name, on its COMPLETE live catalog. A
/// lane that omits the name is a cross-lane disagreement: publication
/// intersects lanes, so the name would be absent from the published contract
/// Stage 1 reads — executing it anyway (from a lane that does advertise it)
/// would bind no schemas or security metadata. And a single pre-selected
/// descriptor would hide same-name duplicates, leaving the executable
/// contract ambiguous. Fail closed on either disagreement.
#[derive(Debug, Clone, Copy)]
pub(super) struct LaneTally {
    connected: bool,
    advertised: bool,
    omitted: bool,
    every_descriptor_admitted: bool,
}

impl Default for LaneTally {
    fn default() -> Self {
        Self {
            connected: false,
            advertised: false,
            omitted: false,
            every_descriptor_admitted: true,
        }
    }
}

impl LaneTally {
    /// Record one connected lane: `None` when it does not advertise the name,
    /// otherwise whether every descriptor it advertises under the name is
    /// admitted.
    pub(super) fn record_lane(&mut self, descriptors_admitted: Option<bool>) {
        self.connected = true;
        match descriptors_admitted {
            None => self.omitted = true,
            Some(admitted) => {
                self.advertised = true;
                self.every_descriptor_admitted &= admitted;
            }
        }
    }

    /// The decision once every connected lane is recorded. `classified` is
    /// whether the manifest has an entry for the name.
    pub(super) fn annotation_admission(self, classified: bool) -> Admission {
        if !self.connected {
            Admission::Unavailable(TemporaryUnavailability::NoConnectedLane)
        } else if !self.advertised {
            Admission::Refused(ToolRefusal::NotInCatalog)
        } else if self.omitted {
            Admission::Refused(ToolRefusal::LanesDisagree)
        } else if !classified {
            Admission::Refused(ToolRefusal::Unclassified)
        } else if !self.every_descriptor_admitted {
            Admission::Refused(ToolRefusal::NotAdmitted)
        } else {
            Admission::Admitted
        }
    }
}

/// Validate one named tool against a specific manifest generation and live
/// catalog. Dispatch calls this while holding the selected connection's read
/// lock, which binds the final admission decision to the exact connection used
/// for the RPC.
pub(super) fn tool_is_admitted_in_catalog(
    manifest: &crate::UpstreamManifest,
    live_tools: &[Tool],
    tool_name: &str,
) -> bool {
    let classification = manifest.tools.iter().find(|tool| tool.name == tool_name);
    if matches!(
        manifest.classification_mode,
        crate::ClassificationMode::Manifest
    ) {
        return classification.is_some();
    }
    // A later `tools/call` identifies the operation by NAME alone, so every
    // live descriptor advertising this name must match the approved
    // contract. A session that pairs an approved descriptor with a
    // different descriptor under the same name leaves the executable
    // contract ambiguous — the upstream, not the gateway, would pick which
    // one runs. Fail closed on any unapproved same-name duplicate.
    let mut matching = live_tools
        .iter()
        .filter(|tool| tool.name.as_ref() == tool_name)
        .peekable();
    matching.peek().is_some()
        && matching.all(|tool| tool_is_admitted(classification, manifest.classification_mode, tool))
}

/// Check the approved contract while the caller holds the selected
/// connection's read lock, binding admission to the connection used for RPC.
pub(super) fn dispatch_contract_is_current(
    entry: &UpstreamEntry,
    initial_manifest: &crate::UpstreamManifest,
    current_manifest: &crate::UpstreamManifest,
    live_tools: &[Tool],
    tool_name: &str,
    local_quarantine_authoritative: bool,
) -> bool {
    redial_committed_fields_eq(initial_manifest, current_manifest)
        && (!local_quarantine_authoritative
            || !entry
                .quarantined
                .read()
                .expect("upstream quarantine lock poisoned")
                .contains(tool_name))
        && tool_is_admitted_in_catalog(current_manifest, live_tools, tool_name)
}

pub(super) fn contract_changed_error(server: &str, tool_name: &str) -> McpError {
    tracing::info!(
        %server,
        %tool_name,
        "configuration or approved tool contract changed during call setup — refusing for retry",
    );
    McpError::internal_error(
        format!(
            "upstream `{server}` configuration or approved contract for \
             `{tool_name}` changed during call setup — retry the call"
        ),
        None,
    )
}

/// Apply the same admission rules to every publication path.
pub(super) fn partition_live_tools(
    classifications: &[crate::ToolClassification],
    mode: crate::ClassificationMode,
    live: &[Tool],
) -> (Vec<Tool>, Vec<String>, Vec<String>) {
    let live_names: HashSet<&str> = live.iter().map(|t| t.name.as_ref()).collect();

    // Annotation mode: a callable name is executable-ambiguous unless EVERY
    // live descriptor advertising it is admitted (`tools/call` identifies by
    // name alone, so the upstream would pick which duplicate runs). Collect
    // the names with any failing descriptor first, then quarantine the whole
    // name. Manifest mode keeps the legacy per-descriptor behavior: its
    // admission is name-based, so same-name duplicates already share one
    // decision.
    let ambiguous: HashSet<&str> = if matches!(mode, crate::ClassificationMode::McpAnnotations) {
        live.iter()
            .filter(|tool| {
                let classification = classifications
                    .iter()
                    .find(|classification| classification.name == tool.name.as_ref());
                !tool_is_admitted(classification, mode, tool)
            })
            .map(|tool| tool.name.as_ref())
            .collect()
    } else {
        HashSet::new()
    };

    let mut kept = Vec::with_capacity(live.len());
    let mut unclassified = Vec::new();
    for tool in live {
        let classification = classifications
            .iter()
            .find(|classification| classification.name == tool.name.as_ref());
        if !ambiguous.contains(tool.name.as_ref()) && tool_is_admitted(classification, mode, tool) {
            kept.push(tool.clone());
        } else {
            unclassified.push(tool.name.as_ref().to_owned());
        }
    }

    let mut ghosts: Vec<String> = classifications
        .iter()
        .filter(|c| !live_names.contains(c.name.as_str()))
        .map(|c| c.name.clone())
        .collect();
    unclassified.sort();
    unclassified.dedup();
    ghosts.sort();

    (kept, unclassified, ghosts)
}

pub(super) fn tool_is_admitted(
    classification: Option<&crate::ToolClassification>,
    mode: crate::ClassificationMode,
    tool: &Tool,
) -> bool {
    let Some(classification) = classification else {
        return false;
    };
    match mode {
        crate::ClassificationMode::Manifest => true,
        crate::ClassificationMode::McpAnnotations => {
            crate::security_metadata::normalize_tool(tool).is_ok()
                && classification
                    .approved_behavior_hash
                    .as_deref()
                    .is_some_and(|approved| {
                        approved == crate::security_metadata::behavior_hash(tool)
                    })
        }
    }
}

/// Filter a freshly-dialed connection's tool list to the admitted subset the
/// caller publishes. Emits drift warnings for every unadmitted live tool
/// (quarantined here — neither listed nor callable) and every manifest-only
/// "ghost" classification.
///
/// Called from the boot dial loop, the reconnect path, and the
/// `reload_manifests` re-publish path so a connected upstream's discovery
/// surface stays in sync with classification edits without requiring a
/// reconnect or restart.
pub(super) fn publish_classified_tools(
    name: &str,
    classifications: &[crate::ToolClassification],
    mode: crate::ClassificationMode,
    live: &[Tool],
    source: &'static str,
) -> Vec<Tool> {
    let (kept, unclassified, ghosts) = partition_live_tools(classifications, mode, live);

    for tool_name in &unclassified {
        let live_tool = live.iter().find(|tool| tool.name.as_ref() == tool_name);
        let classification = classifications
            .iter()
            .find(|classification| classification.name == *tool_name);
        match (mode, live_tool, classification) {
            (crate::ClassificationMode::McpAnnotations, Some(tool), Some(classification)) => {
                let observed_hash = crate::security_metadata::behavior_hash(tool);
                let approved_hash = classification.approved_behavior_hash.as_deref();
                let metadata_error = crate::security_metadata::normalize_tool(tool)
                    .err()
                    .map(|error| error.to_string());
                tracing::warn!(
                    server = %name,
                    tool = %tool_name,
                    source = source,
                    observed_hash = %observed_hash,
                    approved_hash = ?approved_hash,
                    metadata_error = ?metadata_error,
                    "annotation-native tool is not admitted — metadata is invalid or its behavior hash is not approved; quarantined (not listed, not callable)",
                );
            }
            _ => {
                tracing::warn!(
                    server = %name,
                    tool = %tool_name,
                    source = source,
                    classification_mode = ?mode,
                    "tool has no admitted catalog entry — quarantined (not listed, not callable)",
                );
            }
        }
    }
    for tool in &ghosts {
        tracing::warn!(
            server = %name,
            tool = %tool,
            source = source,
            "manifest classifies a tool the upstream does not advertise",
        );
    }

    kept
}
