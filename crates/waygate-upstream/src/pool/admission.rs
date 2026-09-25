//! Tool admission for manifest-classified and annotation-native upstreams.
//!
//! This module is a child of [`super`], so admission stays close to the pool
//! without expanding the pool's transport and lifecycle implementation.

use super::*;

/// Re-check annotation-native admission on the dispatch path. Publication
/// normally filters the same contract, but this independent gate prevents
/// a failed index publication or stale client cache from reaching a tool
/// whose reviewed behavior hash no longer matches.
pub(super) async fn entry_tool_is_admitted(
    entry: &UpstreamEntry,
    manifest: &crate::UpstreamManifest,
    tool_name: &str,
) -> bool {
    if matches!(
        manifest.classification_mode,
        crate::ClassificationMode::Manifest
    ) {
        return manifest.tools.iter().any(|tool| tool.name == tool_name);
    }
    let mut found = false;
    for slot in &entry.slots {
        let connection = slot.conn.read().await;
        let Some(connection) = connection.as_ref() else {
            continue;
        };
        found = true;
        // EVERY connected lane must admit the name, on its COMPLETE live
        // catalog. A lane that omits the name is a cross-lane disagreement:
        // publication intersects lanes, so the name would be absent from
        // the published contract Stage 1 reads — executing it anyway (from
        // a lane that does advertise it) would bind no schemas or security
        // metadata. And a single pre-selected descriptor would hide
        // same-name duplicates, leaving the executable contract ambiguous.
        // Fail closed on either disagreement.
        if !tool_is_admitted_in_catalog(manifest, &connection.live_tools, tool_name) {
            return false;
        }
    }
    found
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

/// Publish a freshly-dialed connection's tool list into the search index,
/// filtered to the admitted subset. Emits drift warnings for every
/// unadmitted live tool (quarantined here — neither indexed nor callable) and
/// every manifest-only "ghost" classification. Returns the kept slice only
/// when the supplied publication transaction succeeds, so the caller cannot
/// install a serving inventory that the search index rejected.
///
/// Called from the boot dial loop, the reconnect path, and the
/// `reload_manifests` re-publish path so a connected upstream's discovery
/// surface stays in sync with classification edits without requiring a
/// reconnect or restart.
pub(super) fn publish_classified_tools<E>(
    name: &str,
    classifications: &[crate::ToolClassification],
    mode: crate::ClassificationMode,
    live: &[Tool],
    source: &'static str,
    publish: impl FnOnce(&[Tool]) -> Result<(), E>,
) -> Result<Vec<Tool>, E> {
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
                    "annotation-native tool is not admitted — metadata is invalid or its behavior hash is not approved; quarantined (not indexed, not callable)",
                );
            }
            _ => {
                tracing::warn!(
                    server = %name,
                    tool = %tool_name,
                    source = source,
                    classification_mode = ?mode,
                    "tool has no admitted catalog entry — quarantined (not indexed, not callable)",
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

    publish(&kept)?;
    Ok(kept)
}
