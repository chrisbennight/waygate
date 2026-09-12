//! Completes legacy catalog rows with the input contract published by the
//! connected upstream, and records what an upstream's live schemas drifted
//! from — the two halves of deciding which advertised contract is admitted.

use rmcp::model::Tool;
use serde_json::Value;

use super::{Connection, UpstreamEntry};
use waygate_mcp::protocol::RiskTier;

use super::{DriftReport, QuarantineThreshold};

#[derive(Default)]
pub(super) struct PublishedToolContract {
    /// Exact normalized definition captured from the same connection snapshot
    /// as the contract fields below.
    pub(super) definition: Option<Tool>,
    /// Original descriptor before client-compatibility schema normalization.
    pub(super) advertised_definition: Option<Tool>,
    pub(super) input_schema: Option<Value>,
    pub(super) output_schema: Option<Value>,
    pub(super) tool_annotations: Option<Value>,
    pub(super) action_metadata: Option<Value>,
    /// The published descriptor's reviewed behavior hash, computed at
    /// capture. Annotation-mode resolution requires it to equal the
    /// manifest generation's `approved_behavior_hash`, which binds the
    /// separately read published view to the manifest snapshot governing
    /// the resolution — a reload interleaving the two reads refuses
    /// instead of returning a mixed-generation snapshot.
    pub(super) behavior_hash: Option<String>,
}

pub(super) async fn published_tool_contract(
    entry: Option<&UpstreamEntry>,
    tool_name: &str,
) -> PublishedToolContract {
    let Some(entry) = entry else {
        return PublishedToolContract::default();
    };
    for slot in &entry.slots {
        if let Some(connection) = slot.conn.read().await.as_ref() {
            if let Some(contract) = connection_tool_contract(connection, tool_name) {
                return contract;
            }
        }
    }
    PublishedToolContract::default()
}

pub(super) fn connection_tool_contract(
    connection: &Connection,
    tool_name: &str,
) -> Option<PublishedToolContract> {
    let mut contract = contract_for_tool(&connection.tools, tool_name)?;
    let advertised = contract_for_tool(&connection.live_tools, tool_name).unwrap_or_default();
    // Approval and drift bind the original descriptor. Schema normalization
    // changes only the client-facing contract, not what the upstream advertised.
    contract.behavior_hash = advertised.behavior_hash;
    contract.advertised_definition = advertised.definition;
    Some(contract)
}

pub(super) fn admit_input_schema(
    catalog_schema: Option<Value>,
    published_schema: Option<Value>,
) -> Option<Value> {
    match published_schema {
        Some(published)
            if !waygate_mcp::tool_schema::input_schema_value_has_object_root(&published) =>
        {
            // A reviewed catalog schema governs argument validation, but it
            // cannot make a currently non-conforming upstream descriptor
            // callable. Preserve the live schema so Stage 2 refuses it before
            // authorization or dispatch instead of masking it with the stored
            // object contract.
            Some(published)
        }
        published => catalog_schema.or(published),
    }
}

pub(super) fn contract_for_tool(tools: &[Tool], tool_name: &str) -> Option<PublishedToolContract> {
    let tool = tools.iter().find(|tool| tool.name.as_ref() == tool_name)?;
    let (tool_annotations, action_metadata) = crate::security_metadata::hash_components(tool);
    let behavior_hash = Some(crate::security_metadata::behavior_hash(tool));
    Some(PublishedToolContract {
        definition: Some(tool.clone()),
        advertised_definition: Some(tool.clone()),
        behavior_hash,
        input_schema: Some(Value::Object((*tool.input_schema).clone())),
        output_schema: tool
            .output_schema
            .as_ref()
            .map(|schema| Value::Object((**schema).clone())),
        tool_annotations,
        action_metadata,
    })
}

impl UpstreamEntry {
    /// Carry the in-process drift-quarantine state of the entry
    /// being REPLACED by a live slot-resize rebuild into the freshly
    /// built entry. A `build_entry` result starts with an empty quarantine set
    /// and re-seeds its behavior baseline from the new connection — so without this
    /// a rebuild would silently drop process-local quarantine and reset its
    /// observation baseline. Copy both the quarantined set and the
    /// `observed_schemas` baseline (the drift reference) so they survive the
    /// rebuild; a later reconnect re-measures drift against the carried baseline,
    /// while durable decisions remain independently authoritative. The
    /// `mcp_tool_quarantined{server}` gauge is per-server and already reflects the
    /// carried count, so it is left untouched. Nothing is carried for refused
    /// output schemas: that record is keyed by server, which a rebuild does
    /// not change, so there is nothing to hand over and no window in which a
    /// copy could go stale.
    pub(super) async fn inherit_drift_state_from(&self, old: &UpstreamEntry) {
        // Clone out from under each old-entry lock before taking the new-entry
        // locks, so the two entries' locks never overlap.
        let carried_quarantine = old
            .quarantined
            .read()
            .expect("upstream quarantine lock poisoned")
            .clone();
        let carried_schemas = old
            .observed_schemas
            .lock()
            .expect("upstream observed-schema lock poisoned")
            .clone();
        *self
            .quarantined
            .write()
            .expect("upstream quarantine lock poisoned") = carried_quarantine;
        *self
            .observed_schemas
            .lock()
            .expect("upstream observed-schema lock poisoned") = carried_schemas;
    }

    pub(super) fn record_observed_schemas_against(
        &self,
        name: &str,
        tools: &[Tool],
        source: &'static str,
        threshold: QuarantineThreshold,
        classifications: &[crate::ToolClassification],
        classification_mode: crate::ClassificationMode,
    ) -> Vec<DriftReport> {
        if tools.is_empty() {
            return Vec::new();
        }
        // Risk lookup is per-tool; do it once up front so we don't
        // re-traverse the (typically small) manifest tool list per
        // drift event.
        // (risk, side_effects) per tool: the drift-quarantine threshold keys on
        // BOTH after the campaign decoupled the operational controls from
        // `risk == High` — a side-effecting tool reclassified `high -> low +
        // side_effects` must still be quarantined on behavior drift.
        let class_for = |tool_name: &str| -> Option<(RiskTier, bool)> {
            classifications.iter().find(|c| c.name == tool_name).map(
                |c| match classification_mode {
                    crate::ClassificationMode::Manifest => (c.risk, c.side_effects),
                    // Annotation mode forbids the legacy `side_effects` flag
                    // in the manifest and presents every annotation-native
                    // tool conservatively as side-effecting until claim
                    // enforcement lands (see `manifest_tool_facts`). The
                    // drift threshold must key on the same posture — a
                    // literal `c.side_effects` here is always false in this
                    // mode and would drop low-risk annotation-native drift
                    // out of the documented quarantine band.
                    crate::ClassificationMode::McpAnnotations => (c.risk, true),
                },
            )
        };
        let mut baseline = self
            .observed_schemas
            .lock()
            .expect("upstream observed-schema lock poisoned");
        let mut newly_quarantined: Vec<String> = Vec::new();
        // Collect drift events here and emit them AFTER releasing the
        // baseline lock (never await on the evidence sink while holding it).
        let mut drift_reports: Vec<DriftReport> = Vec::new();
        for tool in tools {
            let (hash_kind, observed) = match classification_mode {
                crate::ClassificationMode::Manifest => (
                    "manifest:",
                    waygate_catalog::schema_hash(
                        tool.name.as_ref(),
                        tool.description.as_deref(),
                        &tool.input_schema,
                    ),
                ),
                crate::ClassificationMode::McpAnnotations => (
                    "mcp_annotations:",
                    crate::security_metadata::behavior_hash(tool),
                ),
            };
            let observed = format!("{hash_kind}{observed}");
            match baseline.get(tool.name.as_ref()) {
                // Changing classification authority changes which contract is
                // observed. Seed the new authority's baseline instead of
                // reporting an approved mode cutover as behavior drift.
                Some(prev) if !prev.starts_with(hash_kind) => {
                    baseline.insert(tool.name.to_string(), observed);
                }
                Some(prev) if prev != &observed => {
                    let class = class_for(tool.name.as_ref());
                    let risk = class.map(|(r, _)| r);
                    let side_effects = class.is_some_and(|(_, se)| se);
                    let should_quarantine = class.is_some_and(|(r, se)| threshold.covers(r, se));
                    tracing::warn!(
                        server = %name,
                        tool = %tool.name,
                        source = source,
                        previous_hash = %prev,
                        observed_hash = %observed,
                        risk = ?risk,
                        side_effects = side_effects,
                        quarantined = should_quarantine,
                        "tool contract drift detected — the mode-specific admitted contract differs from the last observation",
                    );
                    waygate_telemetry::metrics::record_tool_drift(name);
                    drift_reports.push(DriftReport {
                        tool: tool.name.to_string(),
                        risk,
                        side_effects,
                        quarantined: should_quarantine,
                    });
                    if should_quarantine {
                        newly_quarantined.push(tool.name.to_string());
                    }
                    baseline.insert(tool.name.to_string(), observed);
                }
                Some(_) => {} // unchanged
                None => {
                    // First observation of this tool — seed the baseline silently.
                    baseline.insert(tool.name.to_string(), observed);
                }
            }
        }
        drop(baseline);
        if !newly_quarantined.is_empty() {
            let mut q = self
                .quarantined
                .write()
                .expect("upstream quarantine lock poisoned");
            for tool in newly_quarantined {
                q.insert(tool);
            }
            let count = q.len() as i64;
            drop(q);
            waygate_telemetry::metrics::set_tool_quarantined(name, count);
        }
        drift_reports
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::model::Tool;
    use serde_json::{json, Value};

    use super::{admit_input_schema, contract_for_tool};

    fn tool(name: &str, schema: Value) -> Tool {
        Tool::new(
            name.to_owned(),
            "test tool".to_owned(),
            Arc::new(schema.as_object().cloned().expect("object schema")),
        )
    }

    #[test]
    fn published_schema_is_selected_by_exact_tool_name() {
        let tools = vec![
            tool("read", json!({"type": "object"})),
            tool("send", json!({"type": "object", "required": ["message"]})),
        ];

        assert_eq!(
            contract_for_tool(&tools, "send")
                .expect("send contract")
                .input_schema,
            Some(json!({"type": "object", "required": ["message"]}))
        );
        assert!(contract_for_tool(&tools, "missing").is_none());
    }

    #[test]
    fn catalog_schema_wins_unless_the_live_descriptor_is_nonconforming() {
        let catalog = json!({"type": "object", "required": ["approved"]});
        let published = json!({"type": "object", "required": ["live"]});
        let malformed = json!({"anyOf": [{"type": "object", "required": ["live"]}]});

        assert_eq!(
            admit_input_schema(Some(catalog.clone()), Some(published.clone())),
            Some(catalog.clone())
        );
        assert_eq!(
            admit_input_schema(None, Some(published.clone())),
            Some(published)
        );
        assert_eq!(
            admit_input_schema(Some(catalog), Some(malformed.clone())),
            Some(malformed),
            "the stored schema must not mask a malformed live descriptor",
        );
        assert_eq!(admit_input_schema(None, None), None);
    }
}
