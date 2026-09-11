//! Read-only projection of the effective capability impact of a manifest change.
//!
//! Classification replay answers only whether Cedar would return a different
//! verdict for an existing tool whose governed facts changed.  An operator also
//! needs to know whether the server will still be blocked by the catalog, whether
//! a drift quarantine survives the reload, and whether activation depends on a
//! future connection.  This module combines those independent state planes into
//! one explicit projection without dialing, publishing, or clearing anything.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::Serialize;

use waygate_catalog::{CatalogServerStatus, CatalogServerSummary};
use waygate_core::{RiskTier, TenantId};
use waygate_mcp::authz::{profile_blocks_server, AuthzGate};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_upstream::{parse_manifest_set, UpstreamManifest};

use crate::manifest_impact::{classification_map, diff_classifications};
use crate::state::AdminState;

/// Whether the candidate expands, restricts, or otherwise changes the
/// configured tool capability surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityChange {
    Expands,
    Restricts,
    Changes,
    ConfigurationOnly,
    None,
}

/// What must still happen after publication before the changed servers have a
/// settled runtime state.  This describes infrastructure availability only;
/// Cedar and caller-profile authorization remain separate gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActivationReadiness {
    ExpectedAvailable,
    RuntimeContingent,
    BlockedAfterChange,
    Removed,
    Mixed,
    Unknown,
    NoRuntimeChange,
}

/// Structural manifest transition for one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManifestServerChange {
    Added,
    Removed,
    Updated,
}

/// Work the approving replica's upstream pool will have to reconcile after the
/// published manifest reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEffect {
    RegisterAndConnect,
    DrainAndRemove,
    ReconcileConfiguration,
    RestartRequired,
    None,
}

/// Catalog lifecycle rendered without coupling the public preview schema to the
/// catalog crate's serialization implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogLifecycle {
    Missing,
    Proposed,
    Approved,
    Live,
    Quarantined,
    Retired,
    Unavailable,
}

impl From<CatalogServerStatus> for CatalogLifecycle {
    fn from(value: CatalogServerStatus) -> Self {
        match value {
            CatalogServerStatus::Proposed => Self::Proposed,
            CatalogServerStatus::Approved => Self::Approved,
            CatalogServerStatus::Live => Self::Live,
            CatalogServerStatus::Quarantined => Self::Quarantined,
            CatalogServerStatus::Retired => Self::Retired,
        }
    }
}

/// A deterministic reason the candidate will remain unavailable even after its
/// manifest is published.  Runtime connection uncertainty is represented by
/// [`ActivationReadiness::RuntimeContingent`], not as a blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AvailabilityBarrier {
    CatalogLifecycle { status: CatalogLifecycle },
    CatalogStateUnavailable,
    DriftQuarantine { tools: usize },
    RestartRequired,
}

/// A concrete operator check or action that remains after this manifest change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FollowUpKind {
    PromoteCatalogServer,
    ClearDriftQuarantine,
    VerifyConnection,
    RestartGateway,
    VerifyFleetConvergence,
}

/// One follow-up tied to the affected server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct FollowUpAction {
    /// Manifest server the follow-up applies to.
    pub server: String,
    /// Operator action or verification still required after publication.
    pub kind: FollowUpKind,
}

/// Projected effective state for one structurally changed server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ServerEffectiveImpact {
    /// Manifest server name.
    pub server: String,
    /// Structural change between the active and candidate manifest sets.
    pub manifest_change: ManifestServerChange,
    /// Reconciliation work this replica's runtime pool must perform.
    pub runtime_effect: RuntimeEffect,
    /// `None` means the server is not registered in this replica's pool.
    pub connected_before: Option<bool>,
    /// Durable catalog lifecycle before publication, or `unavailable` when the
    /// catalog could not be read.
    pub catalog_before: CatalogLifecycle,
    /// Projected lifecycle after manifest-to-catalog reconciliation.
    pub catalog_after: CatalogLifecycle,
    /// Drift-quarantined tools in this replica before the change.  Existing
    /// entries preserve this block across reload; a new connection may discover
    /// additional drift that preview cannot predict.
    pub drift_quarantined_before: usize,
    pub drift_quarantined_after_at_least: usize,
    /// Whether this server is expected available, contingent, blocked,
    /// removed, or unknown after publication.
    pub readiness: ActivationReadiness,
    /// Known catalog or drift conditions preventing availability.
    pub barriers: Vec<AvailabilityBarrier>,
}

/// Capability posture of the tool-set and ordinary-approval delta. Added-tool
/// posture uses the same effective facts as invocation: annotation-mode tools
/// are conservatively side-effecting and PII-handling until their reviewed
/// claims are admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ToolCapabilitySummary {
    /// Tools present only in the candidate manifest set.
    pub added: usize,
    /// Tools present only in the active manifest set.
    pub removed: usize,
    /// Existing tools whose governed classification facts change.
    pub reclassified: usize,
    /// Added tools that may produce side effects.
    pub added_side_effecting: usize,
    /// Added tools classified as handling PII.
    pub added_pii: usize,
    /// Added tools classified as high risk.
    pub added_high_risk: usize,
    /// Existing manifest-declared tools on servers changing from `per_call`
    /// to `policy_only`.
    pub approval_relaxed_manifest_tools: usize,
    /// Existing manifest-declared tools on servers changing from `policy_only`
    /// to `per_call`.
    pub approval_tightened_manifest_tools: usize,
    /// Existing servers suppressing annotation/catalog approval requirements.
    pub approval_relaxed_servers: usize,
    /// Existing servers restoring annotation/catalog approval requirements.
    pub approval_tightened_servers: usize,
}

/// Structural and risk posture of declared resource URI spaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ResourceCapabilitySummary {
    pub added: usize,
    pub removed: usize,
    pub reclassified: usize,
    pub added_high_risk: usize,
}

/// Unified, read-only effective impact shared by the MCP preparation surface and
/// the human approval queues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ManifestEffectiveImpact {
    /// Configured capability-surface direction for the candidate as a whole.
    pub capability_change: CapabilityChange,
    /// Rolled-up post-publication availability posture of changed servers.
    pub activation_readiness: ActivationReadiness,
    /// Structural and risk-posture counts for changed tool capabilities.
    pub tools: ToolCapabilitySummary,
    /// Declared resource routing/classification changes.
    pub resources: ResourceCapabilitySummary,
    /// Per-server effective-state projections, sorted by server name.
    pub servers: Vec<ServerEffectiveImpact>,
    /// Remaining actions and checks, sorted by server name.
    pub follow_up_actions: Vec<FollowUpAction>,
    /// Manifest publication notifies the fleet after the disk/ledger commit;
    /// activation is asynchronous and is not proven by approval completion.
    pub fleet_activation_asynchronous: bool,
}

impl ManifestEffectiveImpact {
    pub(crate) fn ledger_only() -> Self {
        Self {
            capability_change: CapabilityChange::None,
            activation_readiness: ActivationReadiness::NoRuntimeChange,
            tools: ToolCapabilitySummary {
                added: 0,
                removed: 0,
                reclassified: 0,
                added_side_effecting: 0,
                added_pii: 0,
                added_high_risk: 0,
                approval_relaxed_manifest_tools: 0,
                approval_tightened_manifest_tools: 0,
                approval_relaxed_servers: 0,
                approval_tightened_servers: 0,
            },
            resources: ResourceCapabilitySummary {
                added: 0,
                removed: 0,
                reclassified: 0,
                added_high_risk: 0,
            },
            servers: Vec::new(),
            follow_up_actions: Vec::new(),
            fleet_activation_asynchronous: false,
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeSnapshot {
    manifest: UpstreamManifest,
    connected: bool,
    quarantined_tools: usize,
}

enum CatalogSnapshot {
    Available(BTreeMap<String, CatalogLifecycle>),
    Unavailable,
}

/// Read the catalog and approving replica's runtime state, then project the
/// exact active-to-candidate manifest transition.  Store failures are logged and
/// represented as `unavailable`; absence is never inferred from a failed read.
pub(crate) async fn effective_manifest_impact(
    state: &AdminState,
    tenant: &TenantId,
    active_content: &str,
    candidate_content: &str,
    observer: Option<&Principal>,
) -> Result<ManifestEffectiveImpact, String> {
    if !may_disclose_effective_impact(state, tenant, active_content, candidate_content, observer)
        .await?
    {
        return Err(
            "effective-impact preview is withheld by the caller's live-state visibility boundary"
                .to_owned(),
        );
    }
    let catalog = match state.servers.catalog.get() {
        Some(store) => match store.list_servers(tenant.as_str()).await {
            Ok(rows) => CatalogSnapshot::Available(catalog_lifecycles(&rows, tenant)),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    tenant = %tenant,
                    "manifest effective-impact catalog read failed"
                );
                CatalogSnapshot::Unavailable
            }
        },
        None => CatalogSnapshot::Unavailable,
    };
    let runtime = state
        .upstreams
        .status_snapshot()
        .await
        .into_iter()
        .map(|status| {
            (
                status.manifest.name.clone(),
                RuntimeSnapshot {
                    manifest: status.manifest,
                    connected: status.health.connected,
                    quarantined_tools: status.health.quarantined_tool_count,
                },
            )
        })
        .collect();
    compute_effective_manifest_impact(active_content, candidate_content, catalog, runtime)
}

/// The effective projection contains gateway-wide runtime and catalog state.
/// Dashboard approval queues call this with no observer after their own admin
/// route gate; MCP preparation supplies the authenticated observer and must
/// match ordinary discovery before any live-state snapshot is read.
async fn may_disclose_effective_impact(
    state: &AdminState,
    tenant: &TenantId,
    active_content: &str,
    candidate_content: &str,
    observer: Option<&Principal>,
) -> Result<bool, String> {
    if tenant.as_str() != TenantId::DEFAULT {
        return Ok(false);
    }
    let Some(observer) = observer else {
        return Ok(true);
    };
    let maker_or_admin = observer.has_scope(Scope::McpPropose.as_str())
        || observer.has_scope(Scope::McpAdmin.as_str());
    if observer.tenant.as_str() != tenant.as_str()
        || !maker_or_admin
        || observer.auth_method == AuthMethod::PeerAssertion
    {
        return Ok(false);
    }

    // A tool-confined credential cannot receive aggregate connection or
    // quarantine counts: those totals may include tools its profile hides.
    if observer
        .api_key_profile_restrictions
        .as_ref()
        .and_then(|restrictions| restrictions.allowed_tools.as_ref())
        .is_some_and(|tools| !tools.is_empty())
    {
        return Ok(false);
    }

    let changed_servers = structurally_changed_server_names(active_content, candidate_content)?;
    if changed_servers
        .iter()
        .any(|server| profile_blocks_server(observer, server))
    {
        return Ok(false);
    }

    let Some(engine) = state.policy.cedar.get() else {
        // Match ordinary discovery in the unwired development/test posture.
        return Ok(true);
    };
    let gate = waygate_authz::CedarGate::new(engine.clone());
    for server in &changed_servers {
        if !gate.may_discover_server(observer, server).await {
            return Ok(false);
        }
    }
    Ok(true)
}

fn structurally_changed_server_names(
    active_content: &str,
    candidate_content: &str,
) -> Result<BTreeSet<String>, String> {
    let active = parse_manifest_set(active_content)
        .map_err(|error| format!("active manifest set does not parse: {error}"))?;
    let candidate = parse_manifest_set(candidate_content)
        .map_err(|error| format!("candidate manifest set does not parse: {error}"))?;
    Ok(active
        .keys()
        .chain(candidate.keys())
        .filter(|name| match (active.get(*name), candidate.get(*name)) {
            (None, Some(_)) | (Some(_), None) => true,
            (Some(old), Some(new)) => !manifests_equal(old, new),
            (None, None) => false,
        })
        .cloned()
        .collect())
}

fn catalog_lifecycles(
    rows: &[CatalogServerSummary],
    tenant: &TenantId,
) -> BTreeMap<String, CatalogLifecycle> {
    rows.iter()
        // Reconcile writes the manifest server into the owning tenant.  A
        // same-name global row visible to this tenant is not the row it mutates.
        .filter(|row| row.tenant_id == tenant.as_str())
        .map(|row| (row.name.clone(), row.status.into()))
        .collect()
}

fn compute_effective_manifest_impact(
    active_content: &str,
    candidate_content: &str,
    catalog: CatalogSnapshot,
    runtime: BTreeMap<String, RuntimeSnapshot>,
) -> Result<ManifestEffectiveImpact, String> {
    let active = parse_manifest_set(active_content)
        .map_err(|error| format!("active manifest set does not parse: {error}"))?;
    let candidate = parse_manifest_set(candidate_content)
        .map_err(|error| format!("candidate manifest set does not parse: {error}"))?;
    let classification_diff = diff_classifications(active_content, candidate_content)?;
    let candidate_classifications = classification_map(candidate_content)
        .map_err(|error| format!("candidate manifest set does not parse: {error}"))?;

    let mut approval_relaxed_manifest_tools = 0;
    let mut approval_tightened_manifest_tools = 0;
    let mut approval_relaxed_servers = 0;
    let mut approval_tightened_servers = 0;
    for (server, candidate_manifest) in &candidate {
        let Some(active_manifest) = active.get(server) else {
            continue;
        };
        match (
            active_manifest.approval_mode,
            candidate_manifest.approval_mode,
        ) {
            (
                waygate_upstream::ApprovalMode::PerCall,
                waygate_upstream::ApprovalMode::PolicyOnly,
            ) => {
                approval_relaxed_servers += 1;
                approval_relaxed_manifest_tools += candidate_manifest.tools.len();
            }
            (
                waygate_upstream::ApprovalMode::PolicyOnly,
                waygate_upstream::ApprovalMode::PerCall,
            ) => {
                approval_tightened_servers += 1;
                approval_tightened_manifest_tools += candidate_manifest.tools.len();
            }
            _ => {}
        }
    }

    let tools = ToolCapabilitySummary {
        added: classification_diff.added.len(),
        removed: classification_diff.removed.len(),
        reclassified: classification_diff.changed.len(),
        added_side_effecting: classification_diff
            .added
            .iter()
            .filter(|key| {
                candidate_classifications
                    .get(*key)
                    .is_some_and(|tool| tool.side_effects)
            })
            .count(),
        approval_relaxed_manifest_tools,
        approval_tightened_manifest_tools,
        approval_relaxed_servers,
        approval_tightened_servers,
        added_pii: classification_diff
            .added
            .iter()
            .filter(|key| {
                candidate_classifications
                    .get(*key)
                    .is_some_and(|tool| tool.pii)
            })
            .count(),
        added_high_risk: classification_diff
            .added
            .iter()
            .filter(|key| {
                candidate_classifications
                    .get(*key)
                    .is_some_and(|tool| matches!(tool.risk, RiskTier::High))
            })
            .count(),
    };

    let active_resources: BTreeMap<(&str, &str), RiskTier> = active
        .iter()
        .flat_map(|(server, manifest)| {
            manifest.resources.iter().map(move |resource| {
                (
                    (server.as_str(), resource.uri_prefix.as_str()),
                    resource.risk,
                )
            })
        })
        .collect();
    let candidate_resources: BTreeMap<(&str, &str), RiskTier> = candidate
        .iter()
        .flat_map(|(server, manifest)| {
            manifest.resources.iter().map(move |resource| {
                (
                    (server.as_str(), resource.uri_prefix.as_str()),
                    resource.risk,
                )
            })
        })
        .collect();
    let added_resources: Vec<_> = candidate_resources
        .iter()
        .filter(|(key, _)| !active_resources.contains_key(key))
        .collect();
    let resources = ResourceCapabilitySummary {
        added: added_resources.len(),
        removed: active_resources
            .keys()
            .filter(|key| !candidate_resources.contains_key(key))
            .count(),
        reclassified: candidate_resources
            .iter()
            .filter(|(key, risk)| active_resources.get(key).is_some_and(|old| old != *risk))
            .count(),
        added_high_risk: added_resources
            .iter()
            .filter(|(_, risk)| matches!(risk, RiskTier::High))
            .count(),
    };

    let names: BTreeSet<&str> = active
        .keys()
        .chain(candidate.keys())
        .map(String::as_str)
        .collect();
    let candidate_nonempty = !candidate.is_empty();
    let mut servers = Vec::new();
    let mut follow_up_actions = Vec::new();

    for name in names {
        let old = active.get(name);
        let new = candidate.get(name);
        let manifest_change = match (old, new) {
            (None, Some(_)) => Some(ManifestServerChange::Added),
            (Some(_), None) => Some(ManifestServerChange::Removed),
            (Some(old), Some(new)) if !manifests_equal(old, new) => {
                Some(ManifestServerChange::Updated)
            }
            _ => None,
        };
        let Some(manifest_change) = manifest_change else {
            continue;
        };

        let runtime_before = runtime.get(name);
        let restart_required = runtime_before.zip(new).is_some_and(|(current, candidate)| {
            waygate_upstream::resource_shape_change_requires_restart(&current.manifest, candidate)
        });
        let runtime_effect = match (runtime_before, new) {
            (Some(_), Some(_)) if restart_required => RuntimeEffect::RestartRequired,
            (None, Some(_)) => RuntimeEffect::RegisterAndConnect,
            (Some(_), None) => RuntimeEffect::DrainAndRemove,
            (Some(current), Some(candidate)) if !manifests_equal(&current.manifest, candidate) => {
                RuntimeEffect::ReconcileConfiguration
            }
            _ => RuntimeEffect::None,
        };
        // Availability barriers and connection work are independent. A
        // catalog- or drift-blocked server can still need a new/reconciled
        // connection once that barrier is cleared, so retain this fact instead
        // of deriving follow-up work from the single readiness headline.
        let connection_verification_required = new.is_some()
            && !restart_required
            && (runtime_before.is_none()
                || runtime_before.is_some_and(|snapshot| !snapshot.connected)
                || matches!(runtime_effect, RuntimeEffect::ReconcileConfiguration));

        let catalog_before = match &catalog {
            CatalogSnapshot::Available(rows) => {
                rows.get(name).copied().unwrap_or(CatalogLifecycle::Missing)
            }
            CatalogSnapshot::Unavailable => CatalogLifecycle::Unavailable,
        };
        let catalog_after =
            projected_catalog_lifecycle(catalog_before, new.is_some(), candidate_nonempty);
        let drift_before = runtime_before.map_or(0, |snapshot| snapshot.quarantined_tools);
        // Existing runtime entries deliberately carry quarantine through every
        // reload/rebuild.  Removed entries have no post-change block; new entries
        // have no current block but may discover drift when they connect.
        let drift_after_at_least = if new.is_some() && runtime_before.is_some() {
            drift_before
        } else {
            0
        };

        let mut barriers = Vec::new();
        if restart_required {
            barriers.push(AvailabilityBarrier::RestartRequired);
        }
        if new.is_some() {
            match catalog_after {
                CatalogLifecycle::Live => {}
                CatalogLifecycle::Unavailable => {
                    barriers.push(AvailabilityBarrier::CatalogStateUnavailable)
                }
                status => barriers.push(AvailabilityBarrier::CatalogLifecycle { status }),
            }
            if drift_after_at_least > 0 {
                barriers.push(AvailabilityBarrier::DriftQuarantine {
                    tools: drift_after_at_least,
                });
            }
        }

        let readiness = if new.is_none() {
            ActivationReadiness::Removed
        } else if barriers
            .iter()
            .any(|barrier| !matches!(barrier, AvailabilityBarrier::CatalogStateUnavailable))
        {
            ActivationReadiness::BlockedAfterChange
        } else if barriers
            .iter()
            .any(|barrier| matches!(barrier, AvailabilityBarrier::CatalogStateUnavailable))
        {
            ActivationReadiness::Unknown
        } else if connection_verification_required {
            ActivationReadiness::RuntimeContingent
        } else {
            ActivationReadiness::ExpectedAvailable
        };

        if new.is_some() {
            match catalog_after {
                CatalogLifecycle::Proposed
                | CatalogLifecycle::Approved
                | CatalogLifecycle::Quarantined
                | CatalogLifecycle::Retired => follow_up_actions.push(FollowUpAction {
                    server: name.to_owned(),
                    kind: FollowUpKind::PromoteCatalogServer,
                }),
                CatalogLifecycle::Missing
                | CatalogLifecycle::Live
                | CatalogLifecycle::Unavailable => {}
            }
        }
        if drift_after_at_least > 0 {
            follow_up_actions.push(FollowUpAction {
                server: name.to_owned(),
                kind: FollowUpKind::ClearDriftQuarantine,
            });
        }
        if connection_verification_required {
            follow_up_actions.push(FollowUpAction {
                server: name.to_owned(),
                kind: FollowUpKind::VerifyConnection,
            });
        }
        if restart_required {
            follow_up_actions.push(FollowUpAction {
                server: name.to_owned(),
                kind: FollowUpKind::RestartGateway,
            });
        }
        follow_up_actions.push(FollowUpAction {
            server: name.to_owned(),
            kind: FollowUpKind::VerifyFleetConvergence,
        });

        servers.push(ServerEffectiveImpact {
            server: name.to_owned(),
            manifest_change,
            runtime_effect,
            connected_before: runtime_before.map(|snapshot| snapshot.connected),
            catalog_before,
            catalog_after,
            drift_quarantined_before: drift_before,
            drift_quarantined_after_at_least: drift_after_at_least,
            readiness,
            barriers,
        });
    }

    let capability_change = capability_change(&servers, &tools, &resources);
    let activation_readiness = aggregate_readiness(&servers);
    Ok(ManifestEffectiveImpact {
        capability_change,
        activation_readiness,
        tools,
        resources,
        servers,
        follow_up_actions,
        fleet_activation_asynchronous: true,
    })
}

fn manifests_equal(a: &UpstreamManifest, b: &UpstreamManifest) -> bool {
    serde_json::to_value(a).expect("UpstreamManifest serialization is infallible")
        == serde_json::to_value(b).expect("UpstreamManifest serialization is infallible")
}

fn projected_catalog_lifecycle(
    before: CatalogLifecycle,
    candidate_present: bool,
    candidate_nonempty: bool,
) -> CatalogLifecycle {
    if candidate_present {
        return match before {
            CatalogLifecycle::Missing => CatalogLifecycle::Live,
            other => other,
        };
    }
    // Full-set reconcile quarantines absent LIVE rows only when the candidate
    // contains at least one server.  An empty set deliberately performs no
    // catalog-wide absence quarantine.
    if candidate_nonempty && before == CatalogLifecycle::Live {
        CatalogLifecycle::Quarantined
    } else {
        before
    }
}

fn capability_change(
    servers: &[ServerEffectiveImpact],
    tools: &ToolCapabilitySummary,
    resources: &ResourceCapabilitySummary,
) -> CapabilityChange {
    let expands = tools.added > 0
        || tools.approval_relaxed_servers > 0
        || resources.added > 0
        || servers
            .iter()
            .any(|server| server.manifest_change == ManifestServerChange::Added);
    let restricts = tools.removed > 0
        || tools.approval_tightened_servers > 0
        || resources.removed > 0
        || servers
            .iter()
            .any(|server| server.manifest_change == ManifestServerChange::Removed);
    match (expands, restricts) {
        (true, false) => CapabilityChange::Expands,
        (false, true) => CapabilityChange::Restricts,
        (true, true) => CapabilityChange::Changes,
        (false, false) if tools.reclassified > 0 || resources.reclassified > 0 => {
            CapabilityChange::Changes
        }
        (false, false) if !servers.is_empty() => CapabilityChange::ConfigurationOnly,
        (false, false) => CapabilityChange::None,
    }
}

fn aggregate_readiness(servers: &[ServerEffectiveImpact]) -> ActivationReadiness {
    let states: BTreeSet<_> = servers.iter().map(|server| server.readiness).collect();
    if states.is_empty() {
        return ActivationReadiness::NoRuntimeChange;
    }
    if states.len() == 1 {
        return *states.iter().next().expect("non-empty readiness set");
    }
    if states.contains(&ActivationReadiness::BlockedAfterChange) {
        ActivationReadiness::BlockedAfterChange
    } else if states.contains(&ActivationReadiness::Unknown) {
        ActivationReadiness::Unknown
    } else {
        ActivationReadiness::Mixed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUNDED_DOCS: &str = r#"
- name: grounded-docs
  transport: http
  url: http://grounded-docs-mcp:6280/mcp
  tools:
    - name: scrape_docs
      risk: low
      side_effects: true
      pii: false
    - name: search_docs
      risk: low
      side_effects: false
      pii: false
"#;

    fn runtime(
        content: &str,
        connected: bool,
        quarantined_tools: usize,
    ) -> BTreeMap<String, RuntimeSnapshot> {
        parse_manifest_set(content)
            .expect("fixture manifest")
            .into_iter()
            .map(|(name, manifest)| {
                (
                    name,
                    RuntimeSnapshot {
                        manifest,
                        connected,
                        quarantined_tools,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn policy_only_cutover_is_an_expansion_not_configuration_only() {
        let candidate =
            GROUNDED_DOCS.replace("  tools:\n", "  approval_mode: policy_only\n  tools:\n");
        let impact = compute_effective_manifest_impact(
            GROUNDED_DOCS,
            &candidate,
            CatalogSnapshot::Available(BTreeMap::from([(
                "grounded-docs".to_owned(),
                CatalogLifecycle::Live,
            )])),
            runtime(GROUNDED_DOCS, true, 0),
        )
        .expect("impact");

        assert_eq!(impact.capability_change, CapabilityChange::Expands);
        assert_eq!(impact.tools.reclassified, 0);
        assert_eq!(impact.tools.approval_relaxed_manifest_tools, 2);
        assert_eq!(impact.tools.approval_tightened_manifest_tools, 0);
        assert_eq!(impact.tools.approval_relaxed_servers, 1);
        assert_eq!(impact.tools.approval_tightened_servers, 0);
    }

    #[test]
    fn readding_catalog_quarantined_server_never_claims_restoration() {
        let catalog = CatalogSnapshot::Available(BTreeMap::from([(
            "grounded-docs".to_owned(),
            CatalogLifecycle::Quarantined,
        )]));
        let impact =
            compute_effective_manifest_impact("[]", GROUNDED_DOCS, catalog, BTreeMap::new())
                .expect("impact");

        assert_eq!(impact.capability_change, CapabilityChange::Expands);
        assert_eq!(impact.tools.added, 2);
        assert_eq!(impact.tools.reclassified, 0);
        assert_eq!(impact.tools.added_side_effecting, 1);
        assert_eq!(
            impact.activation_readiness,
            ActivationReadiness::BlockedAfterChange
        );
        let server = &impact.servers[0];
        assert_eq!(server.catalog_before, CatalogLifecycle::Quarantined);
        assert_eq!(server.catalog_after, CatalogLifecycle::Quarantined);
        assert_eq!(server.readiness, ActivationReadiness::BlockedAfterChange);
        assert!(server
            .barriers
            .contains(&AvailabilityBarrier::CatalogLifecycle {
                status: CatalogLifecycle::Quarantined,
            }));
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::PromoteCatalogServer,
        }));
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyConnection,
        }));
    }

    #[test]
    fn drift_quarantine_is_projected_as_preserved() {
        let active = GROUNDED_DOCS;
        let candidate = GROUNDED_DOCS.replace("risk: low", "risk: high");
        let impact = compute_effective_manifest_impact(
            active,
            &candidate,
            CatalogSnapshot::Available(BTreeMap::from([(
                "grounded-docs".to_owned(),
                CatalogLifecycle::Live,
            )])),
            runtime(active, true, 1),
        )
        .expect("impact");

        assert_eq!(impact.tools.reclassified, 2);
        let server = &impact.servers[0];
        assert_eq!(server.drift_quarantined_before, 1);
        assert_eq!(server.drift_quarantined_after_at_least, 1);
        assert_eq!(server.readiness, ActivationReadiness::BlockedAfterChange);
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::ClearDriftQuarantine,
        }));
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyConnection,
        }));
    }

    #[test]
    fn declared_resource_prefixes_are_diffed_as_capabilities() {
        let candidate = format!(
            "{GROUNDED_DOCS}  resources:\n    - uri_prefix: docs://report/\n      risk: high\n"
        );
        let impact = compute_effective_manifest_impact(
            GROUNDED_DOCS,
            &candidate,
            CatalogSnapshot::Available(BTreeMap::from([(
                "grounded-docs".to_owned(),
                CatalogLifecycle::Live,
            )])),
            runtime(GROUNDED_DOCS, true, 0),
        )
        .expect("resource impact");

        assert_eq!(impact.capability_change, CapabilityChange::Expands);
        assert_eq!(impact.resources.added, 1);
        assert_eq!(impact.resources.added_high_risk, 1);
        assert_eq!(impact.resources.removed, 0);
        assert_eq!(impact.resources.reclassified, 0);
    }

    #[test]
    fn coupled_resource_and_connection_shape_edit_previews_restart_refusal() {
        let candidate = format!(
            "{}  resources:\n    - uri_prefix: docs://report/\n      risk: high\n",
            GROUNDED_DOCS.replace(
                "http://grounded-docs-mcp:6280/mcp",
                "http://replacement-docs-mcp:6280/mcp",
            )
        );
        let impact = compute_effective_manifest_impact(
            GROUNDED_DOCS,
            &candidate,
            CatalogSnapshot::Available(BTreeMap::from([(
                "grounded-docs".to_owned(),
                CatalogLifecycle::Live,
            )])),
            runtime(GROUNDED_DOCS, true, 0),
        )
        .expect("restart-required impact");

        let server = &impact.servers[0];
        assert_eq!(server.runtime_effect, RuntimeEffect::RestartRequired);
        assert_eq!(server.readiness, ActivationReadiness::BlockedAfterChange);
        assert!(server
            .barriers
            .contains(&AvailabilityBarrier::RestartRequired));
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::RestartGateway,
        }));
        assert!(!impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyConnection,
        }));
    }

    #[test]
    fn new_server_without_catalog_row_is_live_but_connection_contingent() {
        let impact = compute_effective_manifest_impact(
            "[]",
            GROUNDED_DOCS,
            CatalogSnapshot::Available(BTreeMap::new()),
            BTreeMap::new(),
        )
        .expect("impact");
        let server = &impact.servers[0];
        assert_eq!(server.catalog_before, CatalogLifecycle::Missing);
        assert_eq!(server.catalog_after, CatalogLifecycle::Live);
        assert_eq!(server.readiness, ActivationReadiness::RuntimeContingent);
        assert!(server.barriers.is_empty());
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyConnection,
        }));
    }

    #[test]
    fn removing_the_only_server_does_not_invent_catalog_quarantine() {
        let impact = compute_effective_manifest_impact(
            GROUNDED_DOCS,
            "[]",
            CatalogSnapshot::Available(BTreeMap::from([(
                "grounded-docs".to_owned(),
                CatalogLifecycle::Live,
            )])),
            runtime(GROUNDED_DOCS, true, 0),
        )
        .expect("impact");
        let server = &impact.servers[0];
        assert_eq!(server.catalog_after, CatalogLifecycle::Live);
        assert_eq!(server.readiness, ActivationReadiness::Removed);
        assert_eq!(impact.capability_change, CapabilityChange::Restricts);
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyFleetConvergence,
        }));
    }

    #[test]
    fn removing_one_server_quarantines_without_recommending_repromotion() {
        let active = format!(
            "{GROUNDED_DOCS}\n- name: retained\n  transport: http\n  url: http://retained/mcp\n"
        );
        let candidate = "- name: retained\n  transport: http\n  url: http://retained/mcp\n";
        let impact = compute_effective_manifest_impact(
            &active,
            candidate,
            CatalogSnapshot::Available(BTreeMap::from([
                ("grounded-docs".to_owned(), CatalogLifecycle::Live),
                ("retained".to_owned(), CatalogLifecycle::Live),
            ])),
            runtime(&active, true, 0),
        )
        .expect("impact");

        let server = impact
            .servers
            .iter()
            .find(|server| server.server == "grounded-docs")
            .expect("removed server projection");
        assert_eq!(server.catalog_after, CatalogLifecycle::Quarantined);
        assert_eq!(server.readiness, ActivationReadiness::Removed);
        assert!(!impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::PromoteCatalogServer,
        }));
        assert!(impact.follow_up_actions.contains(&FollowUpAction {
            server: "grounded-docs".to_owned(),
            kind: FollowUpKind::VerifyFleetConvergence,
        }));
    }

    #[test]
    fn unavailable_catalog_is_unknown_not_missing() {
        let impact = compute_effective_manifest_impact(
            "[]",
            GROUNDED_DOCS,
            CatalogSnapshot::Unavailable,
            BTreeMap::new(),
        )
        .expect("impact");
        let server = &impact.servers[0];
        assert_eq!(server.catalog_before, CatalogLifecycle::Unavailable);
        assert_eq!(server.catalog_after, CatalogLifecycle::Unavailable);
        assert_eq!(server.readiness, ActivationReadiness::Unknown);
        assert!(server
            .barriers
            .contains(&AvailabilityBarrier::CatalogStateUnavailable));
    }

    #[test]
    fn known_block_dominates_unknown_state_in_the_rollup() {
        fn server(server: &str, readiness: ActivationReadiness) -> ServerEffectiveImpact {
            ServerEffectiveImpact {
                server: server.to_owned(),
                manifest_change: ManifestServerChange::Updated,
                runtime_effect: RuntimeEffect::ReconcileConfiguration,
                connected_before: Some(true),
                catalog_before: CatalogLifecycle::Unavailable,
                catalog_after: CatalogLifecycle::Unavailable,
                drift_quarantined_before: 0,
                drift_quarantined_after_at_least: 0,
                readiness,
                barriers: Vec::new(),
            }
        }

        assert_eq!(
            aggregate_readiness(&[
                server("known-block", ActivationReadiness::BlockedAfterChange),
                server("unknown", ActivationReadiness::Unknown),
            ]),
            ActivationReadiness::BlockedAfterChange
        );
    }
}
