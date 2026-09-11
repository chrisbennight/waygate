//! Typed, read-only policy/manifest effect preview for MCP proposal preparation.
//!
//! The dashboard approval queues already compute action-aware policy and
//! manifest previews. This module projects those same domain previews into a
//! stable wire DTO so `gateway-admin.preview_change` can show an MCP-only maker
//! the effect it is about to queue. No separate simulator lives here: policy
//! compilation, attached tests, decision replay, and manifest classification
//! replay remain owned by their existing shared helpers.

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

use crate::change_policy_preview::{CompileStatus, PolicyChangeKind};
use crate::manifest_change_preview::ManifestChangeKind;
use crate::state::AdminState;

/// Action-aware effect of the candidate params against current gateway state.
///
/// `domain` is the discriminator. Actions without an existing specialized
/// policy/manifest preview return no effect from the MCP response.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "domain", rename_all = "snake_case")]
pub enum ChangeEffectPreview {
    Policy {
        /// Human-readable operation resolved from the current target.
        action: String,
        /// Whether the candidate Cedar compiled.
        compile_status: PolicyCompileStatus,
        /// Cedar parse error when `compile_status` is `error`.
        #[serde(skip_serializing_if = "Option::is_none")]
        compile_error: Option<String>,
        /// Attached policy-test results when the target carries tests.
        #[serde(skip_serializing_if = "Option::is_none")]
        tests: Option<crate::policy_tests::PolicyTestReport>,
        /// Bounded replay of recent authorization decisions.
        #[serde(skip_serializing_if = "Option::is_none")]
        impact: Option<crate::impact::ImpactReport>,
        /// Why part of the preview could not be computed.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        /// Current precondition that would prevent execution or approval.
        #[serde(skip_serializing_if = "Option::is_none")]
        blocked: Option<String>,
    },
    Manifest {
        /// Human-readable operation resolved from the current target.
        action: String,
        /// Projected capability and availability outcome across manifest,
        /// runtime, catalog lifecycle, and drift-quarantine state.
        #[serde(skip_serializing_if = "Option::is_none")]
        effective: Option<crate::manifest_effect::ManifestEffectiveImpact>,
        /// Bounded classification and authorization-decision replay.
        #[serde(skip_serializing_if = "Option::is_none")]
        impact: Option<Box<crate::manifest_impact::ManifestImpactReport>>,
        /// Live behavior contracts observed for each annotation-mode server
        /// in the candidate set: per-tool observed behavior hashes, their
        /// comparison against the draft's `approved_behavior_hash` entries,
        /// and the tools admission would quarantine if this draft were
        /// published. Copy each `observed_behavior_hash` into the draft to
        /// reach `match` on every tool before proposing. Omitted when the
        /// candidate has no annotation-mode server (`default` keeps the
        /// omitted field optional in the advertised output schema).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        observed: Vec<crate::manifest_change_preview::ObservedServerContracts>,
        /// Why part of the preview could not be computed.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        /// Current precondition that would prevent execution.
        #[serde(skip_serializing_if = "Option::is_none")]
        blocked: Option<String>,
    },
}

/// Cedar compilation outcome for a policy effect preview.
#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCompileStatus {
    Ok,
    Error,
    Unknown,
}

/// Compute the existing dashboard-grade effect preview for an MCP candidate.
///
/// `tenant_id`, `params`, and `target_etag` are the same inputs the proposal
/// and approval paths use. `observer` is the authenticated caller — the
/// manifest preview's observed-contracts section is gated on it (an
/// `mcp:admin` observer sees it; anyone else, or `None`, does not). Returns
/// `None` for actions without a specialized policy/manifest effect preview.
pub async fn preview_change_effect(
    state: &AdminState,
    tenant_id: &str,
    action_type: &str,
    params: &Value,
    target_etag: Option<&str>,
    observer: Option<&waygate_oidc::Principal>,
) -> Option<ChangeEffectPreview> {
    if let Some(preview) = crate::change_policy_preview::policy_change_preview(
        state,
        tenant_id,
        action_type,
        params,
        target_etag,
    )
    .await
    {
        let action = match preview.kind {
            PolicyChangeKind::Publish { version } if version > 0 => {
                format!("Publish policy draft as version {version}")
            }
            PolicyChangeKind::Publish { .. } => "Publish policy draft".to_owned(),
            PolicyChangeKind::Rollback { version } if version > 0 => {
                format!("Roll policy forward from version {version}")
            }
            PolicyChangeKind::Rollback { .. } => "Roll policy forward".to_owned(),
            PolicyChangeKind::UpsertFragment {
                policy_id: Some(policy_id),
            } => format!("Upsert and publish policy @id={policy_id}"),
            PolicyChangeKind::UpsertFragment { .. } => {
                "Upsert and publish policy fragment".to_owned()
            }
        };
        let (compile_status, compile_error) = match preview.compile {
            CompileStatus::Ok => (PolicyCompileStatus::Ok, None),
            CompileStatus::Error(error) => (PolicyCompileStatus::Error, Some(error)),
            CompileStatus::Unknown => (PolicyCompileStatus::Unknown, None),
        };
        return Some(ChangeEffectPreview::Policy {
            action,
            compile_status,
            compile_error,
            tests: preview.tests,
            impact: preview.impact,
            note: maker_safe_note("policy", preview.note),
            blocked: preview.blocked,
        });
    }

    crate::manifest_change_preview::manifest_change_preview(
        state,
        tenant_id,
        action_type,
        params,
        observer,
    )
    .await
    .map(|preview| {
        let action = match preview.kind {
            ManifestChangeKind::Publish { version } if version > 0 => {
                format!("Publish manifest draft as version {version}")
            }
            ManifestChangeKind::Publish { .. } => "Publish manifest draft".to_owned(),
            ManifestChangeKind::Rollback { version } if version > 0 => {
                format!("Roll manifests forward from version {version}")
            }
            ManifestChangeKind::Rollback { .. } => "Roll manifests forward".to_owned(),
            ManifestChangeKind::StageAndPublish => "Publish manifest set".to_owned(),
            ManifestChangeKind::UpsertServers => "Upsert manifest servers".to_owned(),
            ManifestChangeKind::RemoveServers => "Remove manifest servers".to_owned(),
        };
        ChangeEffectPreview::Manifest {
            action,
            effective: preview.effective,
            impact: preview.impact.map(Box::new),
            observed: preview.observed,
            note: maker_safe_note("manifest", preview.note),
            blocked: preview.blocked,
        }
    })
}

fn maker_safe_note(domain: &str, note: Option<String>) -> Option<String> {
    note.map(|_| {
        format!(
            "part of the {domain} effect preview is unavailable; retry or ask an operator to \
             inspect gateway diagnostics"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::maker_safe_note;

    #[test]
    fn maker_note_preserves_availability_without_forwarding_internal_detail() {
        let note = maker_safe_note(
            "policy",
            Some("sqlx: connection refused at internal-host:5432".to_owned()),
        )
        .expect("unavailable preview stays visible");
        assert!(note.contains("policy effect preview is unavailable"));
        assert!(!note.contains("sqlx"));
        assert!(!note.contains("internal-host"));
        assert!(maker_safe_note("manifest", None).is_none());
    }
}
