//! Typed contract for the ordered MCP tool-invocation lifecycle.
//!
//! The orchestrator remains explicit in `invocation::mod`; this module owns
//! the finite identifiers, descriptions, and implementation statuses that
//! tests, metrics, and normative documentation can share without duplicating
//! stage order as free-form prose.

use std::sync::Arc;

/// One observable stage in the successful MCP tool-invocation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationStage {
    ResolveTool,
    ValidateInput,
    ExtractFacts,
    Authorize,
    CheckProfileRestrictions,
    PrepareOutputValidation,
    CheckQuota,
    CheckApproval,
    RecordPreCall,
    PrepareFileInputs,
    Dispatch,
    InspectResponse,
    PrepareFileOutputs,
    ValidateOutput,
    RecordOutcome,
}

impl InvocationStage {
    /// Canonical successful-path order. Inserting, removing, or reordering a
    /// stage requires updating the orchestrator and the marked architecture
    /// table in the same change.
    pub const ALL: [Self; 15] = [
        Self::ResolveTool,
        Self::ValidateInput,
        Self::ExtractFacts,
        Self::Authorize,
        Self::CheckProfileRestrictions,
        Self::PrepareOutputValidation,
        Self::CheckQuota,
        Self::CheckApproval,
        Self::RecordPreCall,
        Self::PrepareFileInputs,
        Self::Dispatch,
        Self::InspectResponse,
        Self::PrepareFileOutputs,
        Self::ValidateOutput,
        Self::RecordOutcome,
    ];

    /// Stable machine identifier used by tests, documentation, and any
    /// finite-label telemetry.
    pub const fn id(self) -> &'static str {
        match self {
            Self::ResolveTool => "resolve_tool",
            Self::ValidateInput => "validate_input",
            Self::ExtractFacts => "extract_facts",
            Self::Authorize => "authorize",
            Self::CheckProfileRestrictions => "check_profile_restrictions",
            Self::PrepareOutputValidation => "prepare_output_validation",
            Self::CheckQuota => "check_quota",
            Self::CheckApproval => "check_approval",
            Self::RecordPreCall => "record_pre_call",
            Self::PrepareFileInputs => "prepare_file_inputs",
            Self::Dispatch => "dispatch",
            Self::InspectResponse => "inspect_response",
            Self::PrepareFileOutputs => "prepare_file_outputs",
            Self::ValidateOutput => "validate_output",
            Self::RecordOutcome => "record_outcome",
        }
    }

    /// Human-readable responsibility that remains safe as a static metric or
    /// diagnostic description; it contains no request data.
    pub const fn description(self) -> &'static str {
        match self {
            Self::ResolveTool => "resolve governed tool facts",
            Self::ValidateInput => "validate request arguments against the input schema",
            Self::ExtractFacts => "assemble policy information point facts",
            Self::Authorize => "authorize the call with Cedar",
            Self::CheckProfileRestrictions => "enforce caller profile restrictions",
            Self::PrepareOutputValidation => "compile the admitted output schema for validation",
            Self::CheckQuota => "check and consume invocation quota",
            Self::CheckApproval => "enforce human approval requirements",
            Self::RecordPreCall => "record required pre-call evidence and safety gates",
            Self::PrepareFileInputs => "stream and replace annotated gateway file inputs",
            Self::Dispatch => "dispatch the call to the upstream",
            Self::InspectResponse => "inspect and redact or block the response",
            Self::PrepareFileOutputs => "save and replace upstream file references",
            Self::ValidateOutput => "validate the inspected response against its output schema",
            Self::RecordOutcome => "record the final invocation outcome",
        }
    }

    /// Whether this stage enforces its intended contract today.
    pub const fn status(self) -> InvocationStageStatus {
        InvocationStageStatus::Active
    }
}

/// Implementation status published beside every stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationStageStatus {
    Active,
    Placeholder,
}

impl InvocationStageStatus {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Placeholder => "placeholder",
        }
    }
}

/// Observer seam for executed stage entry. Production leaves this unwired;
/// tests can record the sequence without mocking private helper methods.
pub trait InvocationStageObserver: Send + Sync {
    fn enter(&self, stage: InvocationStage);
}

pub type SharedInvocationStageObserver = Arc<dyn InvocationStageObserver>;

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE_BEGIN: &str = "<!-- invocation-stages:begin -->";
    const TABLE_END: &str = "<!-- invocation-stages:end -->";

    #[test]
    fn architecture_stage_table_matches_code_order_and_status() {
        let architecture = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture.md"
        ))
        .expect("read normative architecture document");
        let (_, after_begin) = architecture
            .split_once(TABLE_BEGIN)
            .expect("invocation stage table begin marker");
        let (table, _) = after_begin
            .split_once(TABLE_END)
            .expect("invocation stage table end marker");
        assert!(
            !table.contains(TABLE_BEGIN),
            "invocation stage table begin marker is duplicated"
        );

        let documented: Vec<(&str, &str)> = table
            .lines()
            .filter_map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                if cells.len() < 5 || cells.get(1)?.parse::<usize>().is_err() {
                    return None;
                }
                Some((
                    cells.get(2)?.trim_matches('`'),
                    cells.get(3)?.trim_matches('`'),
                ))
            })
            .collect();
        let expected: Vec<(&str, &str)> = InvocationStage::ALL
            .iter()
            .map(|stage| (stage.id(), stage.status().id()))
            .collect();

        assert_eq!(
            documented, expected,
            "docs/architecture.md invocation stages must match code order and status"
        );
    }

    #[test]
    fn every_stage_has_nonempty_static_metadata() {
        for stage in InvocationStage::ALL {
            assert!(!stage.id().is_empty());
            assert!(!stage.description().is_empty());
            assert!(!stage.status().id().is_empty());
        }
    }
}
