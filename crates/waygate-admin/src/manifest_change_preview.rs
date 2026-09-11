//! Manifest-aware preview for a HITL `manifest.publish` / `manifest.rollback`
//! change request (server-config review parity).
//!
//! The maker-checker control plane routes a server-manifest publish / rollback
//! through propose → human approval → server-side execute (the
//! `manifest.publish` / `manifest.rollback` executors in
//! [`crate::change_executor`]). But the approver otherwise sees only the
//! captured `params` as raw JSON (`{ "bundle_id": "…" }` / `{ "version": 3 }`),
//! from which they can't tell WHAT the publish does — and a manifest edit can
//! silently flip live authorization decisions, because a tool's
//! `risk` / `pii` / `side_effects` classification feeds the Cedar `Tool` entity.
//!
//! This module computes the blast-radius the approver reviews *before*
//! approving, so they approve the EFFECT, not opaque JSON. It is the manifest
//! manifest counterpart of [`crate::change_policy_preview`].
//!
//! READ-ONLY and tenant-scoped to the CHANGE REQUEST's tenant (the executor
//! resolves the same tenant from the approver's principal). Every load is
//! best-effort: a missing draft, an unwired store, or a malformed `params` blob
//! degrades to a `note` — the review queue must always render. The preview
//! NEVER mutates: no publish, no audit write, no disk write.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use waygate_core::TenantId;
use waygate_manifest_store::ManifestStatus;
use waygate_mcp::authz::profile_blocks_server;
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_oidc::{Principal, Scope};
use waygate_upstream::{parse_manifest_set, ClassificationMode, UpstreamManifest};

use crate::manifest_impact::ManifestImpactReport;
use crate::state::AdminState;

/// Mirror of `change_executor::ManifestPublishParams`. The preview MUST parse
/// the captured params EXACTLY as the executor will, so it never previews a
/// normal effect for params the executor would reject as bad.
#[derive(Deserialize)]
struct PublishParams {
    bundle_id: Uuid,
}

/// Mirror of `change_executor::ManifestRollbackParams`. `version: i32` matters:
/// `serde` rejects an out-of-`i32`-range integer (so does the executor), where a
/// hand-rolled `as i64 as i32` would silently truncate and preview the WRONG
/// version.
#[derive(Deserialize)]
struct RollbackParams {
    version: i32,
}

/// Which manifest change a [`ManifestChangePreview`] describes (the human label
/// needs only the version; the bundle id is in the captured params).
pub(crate) enum ManifestChangeKind {
    /// `manifest.publish` of a draft bundle, published as `version`.
    Publish { version: i32 },
    /// `manifest.rollback` to a previously-published version.
    Rollback { version: i32 },
    /// `manifest.stage_and_publish` — inline content staged + published in one
    /// step. The version is assigned at execute, so it isn't known at preview.
    StageAndPublish,
    /// `manifest.upsert_servers` — a partial set merged into the live set and
    /// published as one step. The preview replays the MERGED effect; the version
    /// is assigned at execute, so it isn't known at preview.
    UpsertServers,
    /// `manifest.remove_servers` — selected names removed from the live set
    /// server-side, then published as one step.
    RemoveServers,
}

/// A manifest-aware preview of a pending `manifest.publish` / `manifest.rollback`
/// change request, for the approver's review.
pub(crate) struct ManifestChangePreview {
    pub kind: ManifestChangeKind,
    /// The blast-radius replay of the candidate's classification change against
    /// the live policy. `None` when the candidate content couldn't be loaded
    /// (see `note`); a manifest that doesn't parse surfaces inside the report's
    /// own `error` (the approver still sees "this can't land").
    pub impact: Option<ManifestImpactReport>,
    /// Effective server/tool availability projection across the on-disk
    /// manifest, runtime pool, durable catalog lifecycle, and preserved drift
    /// quarantine. Uses the same active-manifest snapshot as `impact`.
    pub effective: Option<crate::manifest_effect::ManifestEffectiveImpact>,
    /// A degradation note (missing bundle, unwired store, malformed params,
    /// preview dependency unavailable). When `Some`, the queue still renders and
    /// the approver sees why a piece is absent.
    pub note: Option<String>,
    /// Set when the executor would REFUSE this change at execute even though the
    /// content is otherwise previewable — a `manifest.publish` target that is no
    /// longer a `Draft` (the publish executor requires a draft). A
    /// `manifest.rollback` against a non-existent / draft-only version is caught
    /// at load (`get_by_version` returns `NotFound`) and surfaces as a `note`
    /// instead. When `Some`, the review renders a "will not execute" banner.
    pub blocked: Option<String>,
    /// Live behavior contracts observed for every annotation-mode server in
    /// the candidate set (empty when the candidate has none or couldn't be
    /// loaded, or when the observer may not read the raw live catalog —
    /// see [`observed_annotation_contracts`] for the gates). This is how an
    /// operator obtains correct `approved_behavior_hash` values — and a
    /// quarantine prediction — before publishing a
    /// `classification_mode: mcp_annotations` flip.
    pub observed: Vec<ObservedServerContracts>,
}

impl ManifestChangePreview {
    /// Return the fail-closed reason that prevents an approver from consuming
    /// a manifest change request. Approval requires both the authorization
    /// replay and the effective service projection to be complete for the
    /// captured candidate at approval time.
    pub(crate) fn mandatory_approval_blocker(&self) -> Option<String> {
        if let Some(reason) = &self.blocked {
            return Some(reason.clone());
        }
        if let Some(note) = &self.note {
            return Some(format!(
                "the mandatory manifest effect preview is incomplete: {note}"
            ));
        }
        match &self.impact {
            Some(report) if report.error.is_none() => {}
            Some(_) => {
                return Some("the mandatory manifest impact preview failed".to_owned());
            }
            None => {
                return Some("the mandatory manifest impact preview is unavailable".to_owned());
            }
        }
        if self.effective.is_none() {
            return Some(
                "the mandatory effective service-impact preview is unavailable".to_owned(),
            );
        }
        None
    }
}

/// Live per-tool behavior contracts for one `classification_mode:
/// mcp_annotations` server in the candidate set, compared against the
/// draft's `approved_behavior_hash` entries. Computed read-only from the
/// gateway's connected upstream sessions. Deliberately reports the RAW live
/// catalog — including tools discovery would hide — because a complete
/// annotation manifest must cover every live tool; the gates on WHO may
/// read it are documented on [`observed_annotation_contracts`].
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ObservedServerContracts {
    /// Manifest server name (the manifest set key).
    pub server: String,
    /// Whether a live report is included. When `false` no contracts are
    /// reported — the server may be unknown to the pool, have every session
    /// lane down, or the report may be refused (connection-shape-changing
    /// candidate) or withheld (profile confinement); `tools`, `draft_only`,
    /// and `would_quarantine` are empty and `note` says which.
    pub connected: bool,
    /// Why no live report is included (see `connected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// One entry per live tool name, sorted, each carrying the observed
    /// behavior hash and how it compares to the draft.
    pub tools: Vec<ObservedToolStatus>,
    /// Draft-listed tool names with no live descriptor. They are not
    /// quarantined (nothing live to refuse) but cannot be called either.
    pub draft_only: Vec<String>,
    /// Live tool names annotation-native admission would quarantine if this
    /// draft were published — every name whose status is not `match`.
    pub would_quarantine: Vec<String>,
}

/// One live tool's observed contract and its comparison against the draft.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ObservedToolStatus {
    /// Tool name as the upstream advertises it (no gateway prefix).
    pub name: String,
    /// The behavior hash the draft's `approved_behavior_hash` must equal for
    /// this tool to be admitted. Copy it verbatim; never calculate it. Absent
    /// when connected session lanes disagree about the tool's definition
    /// (status `ambiguous`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_behavior_hash: Option<String>,
    /// How the observed contract compares to the draft entry.
    pub draft_status: DraftHashStatus,
    /// Why admission would refuse this tool regardless of any approved
    /// hash: its advertised security metadata does not normalize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_error: Option<String>,
}

/// Admission outcome the draft would produce for one live tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DraftHashStatus {
    /// Draft `approved_behavior_hash` equals the observed hash — admitted.
    Match,
    /// Draft lists the tool but its `approved_behavior_hash` is absent or
    /// differs from the observed hash — quarantined. Copy
    /// `observed_behavior_hash` into the draft to fix.
    Mismatch,
    /// Live tool the draft does not list — quarantined. Add a draft entry
    /// with `observed_behavior_hash` to admit it.
    MissingFromDraft,
    /// Connected session lanes disagree about the tool's definition, so no
    /// single hash could admit it — quarantined until the upstream serves
    /// one consistent definition.
    Ambiguous,
    /// The tool's advertised security metadata is missing or malformed —
    /// quarantined regardless of hash (see `metadata_error`); fix the
    /// upstream's tool definition.
    InvalidMetadata,
}

/// Build the manifest preview for a change request, or `None` when `action_type`
/// isn't a manifest change (the caller renders the generic params JSON, or a
/// policy preview, for those).
///
/// `tenant_id` is the change request's own tenant (the SECURITY boundary — the
/// preview reads only that tenant's bundle + decisions, never a viewer's).
/// `observer` is the authenticated caller the observed-contracts section may
/// be computed for; `None` (the dashboard queues, which do not render the
/// section) skips it entirely.
pub(crate) async fn manifest_change_preview(
    state: &AdminState,
    tenant_id: &str,
    action_type: &str,
    params: &Value,
    observer: Option<&Principal>,
) -> Option<ManifestChangePreview> {
    match action_type {
        "manifest.publish" => Some(publish_preview(state, tenant_id, params, None, observer).await),
        "manifest.rollback" => {
            Some(rollback_preview(state, tenant_id, params, None, observer).await)
        }
        "manifest.stage_and_publish" => {
            Some(stage_and_publish_preview(state, tenant_id, params, None, observer).await)
        }
        "manifest.upsert_servers" => {
            Some(upsert_servers_preview(state, tenant_id, params, None, observer).await)
        }
        "manifest.remove_servers" => {
            Some(remove_servers_preview(state, tenant_id, params, observer).await)
        }
        _ => None,
    }
}

/// Build a pending request's manifest preview against the immutable live-set
/// witness captured when it was proposed. Actions that replace or reconstruct
/// the gateway-wide set must not silently preview a newer baseline.
pub(crate) async fn manifest_change_preview_for_request(
    state: &AdminState,
    tenant_id: &str,
    action_type: &str,
    params: &Value,
    target_etag: Option<&str>,
    observer: Option<&Principal>,
) -> Option<ManifestChangePreview> {
    match action_type {
        "manifest.publish" => {
            let witness = match parse_full_set_witness(target_etag) {
                Ok(witness) => witness,
                Err(reason) => {
                    let preview = publish_preview(state, tenant_id, params, None, observer).await;
                    return Some(block_for_missing_witness(preview, reason));
                }
            };
            Some(publish_preview(state, tenant_id, params, Some(&witness), observer).await)
        }
        "manifest.rollback" => {
            let witness = match parse_full_set_witness(target_etag) {
                Ok(witness) => witness,
                Err(reason) => {
                    let preview = rollback_preview(state, tenant_id, params, None, observer).await;
                    return Some(block_for_missing_witness(preview, reason));
                }
            };
            Some(rollback_preview(state, tenant_id, params, Some(&witness), observer).await)
        }
        "manifest.stage_and_publish" => {
            Some(stage_and_publish_preview(state, tenant_id, params, target_etag, observer).await)
        }
        "manifest.upsert_servers" => {
            Some(upsert_servers_preview(state, tenant_id, params, target_etag, observer).await)
        }
        "manifest.remove_servers" => {
            Some(remove_servers_preview(state, tenant_id, params, observer).await)
        }
        // Not a manifest change — the caller handles policy / generic rows.
        _ => None,
    }
}

fn parse_full_set_witness(
    target_etag: Option<&str>,
) -> Result<crate::change_executor::ManifestFullSetWitness, String> {
    let encoded = target_etag.ok_or_else(|| {
        "this pending request has no captured live-manifest witness; re-propose it before approval"
            .to_owned()
    })?;
    serde_json::from_str(encoded).map_err(|_| {
        "this pending request has an invalid live-manifest witness; re-propose it before approval"
            .to_owned()
    })
}

fn block_for_missing_witness(
    mut preview: ManifestChangePreview,
    reason: String,
) -> ManifestChangePreview {
    preview.impact = None;
    preview.effective = None;
    preview.note = None;
    preview.blocked = Some(reason);
    preview.observed.clear();
    preview
}

/// A degraded preview: content couldn't be loaded, so the impact is absent and
/// `note` says why.
fn degraded(kind: ManifestChangeKind, note: impl Into<String>) -> ManifestChangePreview {
    ManifestChangePreview {
        kind,
        impact: None,
        effective: None,
        note: Some(note.into()),
        blocked: None,
        observed: Vec::new(),
    }
}

/// Observe the live behavior contracts for every annotation-mode server in
/// the candidate set. The section reports the RAW live catalog, including
/// tools that discovery hides (unclassified, quarantined,
/// policy-restricted), because a complete annotation manifest must cover
/// every live tool or admission quarantines the omissions — a filtered
/// report would teach a maker to publish an outage. The gates therefore
/// control WHO reads it, never what it contains:
///
/// - **Default tenant only** — the pool is gateway-wide, and a non-default
///   tenant must not learn whether a guessed server is live or what tools
///   it serves (the same boundary the removal preview enforces).
/// - **Maker floor** — the observer needs `mcp:propose` (the same scope the
///   `gateway-admin` namespace's maker gate requires; the propose-only
///   automated maker is exactly who this section exists for) or
///   `mcp:admin`, and never a peer-asserted principal. This mirrors the
///   namespace gate as defense in depth for future callers.
/// - **Exact profile confinement** — a server the observer's API-key
///   profile blocks is omitted entirely, and a server where the profile
///   confines the observer to a SUBSET of the live tools gets a withheld
///   note instead of a report: partial disclosure would violate the
///   per-tool profile contract, and a filtered report is the outage trap
///   above, so the report is complete or absent.
///
/// A candidate that doesn't parse yields no section — the impact report
/// already surfaces the parse error.
async fn observed_annotation_contracts(
    state: &AdminState,
    tenant: &TenantId,
    content: &str,
    observer: Option<&Principal>,
) -> Vec<ObservedServerContracts> {
    let Some(observer) = observer else {
        return Vec::new();
    };
    let maker_or_admin = observer.has_scope(Scope::McpPropose.as_str())
        || observer.has_scope(Scope::McpAdmin.as_str());
    if tenant.as_str() != TenantId::DEFAULT
        || !maker_or_admin
        || observer.auth_method == waygate_oidc::AuthMethod::PeerAssertion
    {
        return Vec::new();
    }
    let Ok(set) = parse_manifest_set(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (server, manifest) in &set {
        if !matches!(
            manifest.classification_mode,
            ClassificationMode::McpAnnotations
        ) || profile_blocks_server(observer, server)
        {
            continue;
        }
        // Shape check and catalog read resolve on ONE pool-entry snapshot
        // (`observe_candidate_contracts`), so a concurrent structural
        // reload cannot pair one generation's shape verdict with its
        // replacement's hashes. A candidate that changes the connection
        // shape publishes against a re-dialed endpoint; hashes observed on
        // the CURRENT sessions cannot predict that catalog, so refuse to.
        let report = match state.upstreams.observe_candidate_contracts(manifest).await {
            Some(waygate_upstream::CandidateObservation::ShapeChanged) => withheld_report(
                server,
                "the candidate changes this server's connection shape (transport, protocol, \
                 url, command, auth, mTLS, session, or identity settings), so publishing \
                 re-dials a new endpoint — contracts observed on the current sessions \
                 cannot predict its catalog. Publish the shape change first, then \
                 re-preview the annotation flip for hashes",
            ),
            Some(waygate_upstream::CandidateObservation::Observed(observed)) => {
                observed_server_report(server, manifest, Some(observed))
            }
            None => observed_server_report(server, manifest, None),
        };
        // Authorization withholds run on EVERY report shape — including the
        // shape refusal and the unknown/disconnected notes, which would
        // otherwise reveal registration and liveness to a caller discovery
        // hides the server from. Cedar last, so its note wins.
        let report = withhold_if_profile_confined(observer, server, report);
        let report = withhold_if_cedar_undiscoverable(state, observer, server, report).await;
        out.push(report);
    }
    out
}

/// The withheld shape both authorization withholds share: no contracts, no
/// liveness detail, only the teach note. Nothing beyond the server name the
/// caller already wrote in their own candidate may leak past a withhold.
fn withheld_report(server: &str, note: &str) -> ObservedServerContracts {
    ObservedServerContracts {
        server: server.to_owned(),
        connected: false,
        note: Some(note.to_owned()),
        tools: Vec::new(),
        draft_only: Vec::new(),
        would_quarantine: Vec::new(),
    }
}

/// Enforce Cedar discovery parity on a completed report: an observer the
/// live policy denies `SearchTools` on the server — or leaves ANY live tool
/// undiscoverable — gets the report withheld, so this surface can never
/// enumerate what ordinary discovery hides from the same credential. The
/// whole report is withheld (never filtered — a partial report is the
/// quarantine-outage trap) and the withheld shape carries no liveness
/// detail, so a policy-denied maker learns nothing they didn't write into
/// their own candidate. Per-tool verdicts use the same `CedarGate`
/// predicates and current-manifest `tool_facts` that `tools/list` discovery
/// evaluates. When no Cedar engine is wired the MCP discovery surface
/// itself runs unfiltered, so the preview matches it rather than inventing
/// a stricter dev-mode boundary.
async fn withhold_if_cedar_undiscoverable(
    state: &AdminState,
    observer: &Principal,
    server: &str,
    report: ObservedServerContracts,
) -> ObservedServerContracts {
    use waygate_mcp::authz::AuthzGate;
    let Some(engine) = state.policy.cedar.get() else {
        return report;
    };
    let gate = waygate_authz::CedarGate::new(engine.clone());
    let mut undiscoverable = !gate.may_discover_server(observer, server).await;
    if !undiscoverable {
        let classified: BTreeSet<String> = state
            .upstreams
            .manifests()
            .into_iter()
            .find(|m| m.name == server)
            .map(|m| m.tools.into_iter().map(|t| t.name).collect())
            .unwrap_or_default();
        let quarantined: BTreeSet<String> = state
            .upstreams
            .quarantined_tools(server)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        for tool in &report.tools {
            let governed = state.upstreams.tool_facts(server, &tool.name);
            let facts = cedar_parity_facts(
                governed,
                classified.contains(tool.name.as_str()),
                quarantined.contains(tool.name.as_str()),
            );
            if !gate.may_call_tool(observer, &facts).await.is_discoverable() {
                undiscoverable = true;
                break;
            }
        }
    }
    if !undiscoverable {
        return report;
    }
    withheld_report(
        server,
        "the live authorization policy does not let this credential discover this server's \
         full catalog; the observed-contracts report is deliberately complete and is \
         withheld rather than filtered — preview with a credential the policy allows to \
         discover every tool on the server",
    )
}

/// Facts the Cedar parity check evaluates for one observed live tool. A
/// currently-classified, non-quarantined name is judged on its governed
/// facts — the same ones ordinary discovery authorizes. An unclassified or
/// drift-quarantined live name has NO trustworthy governed facts, and the
/// catalog fallback defaults to the PERMISSIVE low/no-side-effects baseline
/// — which would let exactly the tools discovery hides pass the parity
/// check — so those names are judged at the most sensitive contract the
/// server could serve: the observer sees them only when the policy would
/// let them discover a worst-case tool here.
fn cedar_parity_facts(
    governed: waygate_mcp::authz::ToolFacts,
    currently_classified: bool,
    currently_quarantined: bool,
) -> waygate_mcp::authz::ToolFacts {
    if currently_classified && !currently_quarantined {
        return governed;
    }
    waygate_mcp::authz::ToolFacts {
        server: governed.server,
        name: governed.name,
        risk: waygate_core::RiskTier::High,
        side_effects: true,
        pii: true,
        requires_approval: false,
        requires_approval_known: true,
    }
}

/// Enforce the exact per-tool profile contract on a completed report: if the
/// observer's API-key profile blocks ANY live tool on `server`, the whole
/// report is withheld with a teach note. Partial disclosure would violate
/// the profile contract, and a silently filtered report would teach a maker
/// to publish a manifest that quarantines the hidden tools — complete or
/// absent are the only honest shapes.
fn withhold_if_profile_confined(
    observer: &Principal,
    server: &str,
    report: ObservedServerContracts,
) -> ObservedServerContracts {
    let confined = report
        .tools
        .iter()
        .any(|tool| waygate_mcp::authz::profile_blocks_tool(observer, server, &tool.name));
    if !confined {
        return report;
    }
    withheld_report(
        server,
        "your API-key profile confines you to a subset of this server's live tools; the \
         observed-contracts report is deliberately complete and is withheld rather than \
         filtered — preview with a credential whose profile does not confine this \
         server's tools",
    )
}

/// Compare one server's observed live contracts against its draft manifest.
/// Pure so the status classification is testable without a connected pool.
fn observed_server_report(
    server: &str,
    manifest: &UpstreamManifest,
    observed: Option<waygate_upstream::ObservedContracts>,
) -> ObservedServerContracts {
    let unobservable = |note: &str| ObservedServerContracts {
        server: server.to_owned(),
        connected: false,
        note: Some(note.to_owned()),
        tools: Vec::new(),
        draft_only: Vec::new(),
        would_quarantine: Vec::new(),
    };
    let observed = match observed {
        None => {
            return unobservable(
                "server is not registered with the gateway's upstream pool (it may be newly \
                 added by this draft) — live behavior hashes cannot be observed until it is \
                 published and connected",
            );
        }
        Some(o) if !o.connected => {
            return unobservable(
                "no upstream session is currently connected — live behavior hashes cannot be \
                 observed; reconnect the server and preview again",
            );
        }
        Some(o) => o,
    };

    let draft: BTreeMap<&str, Option<&str>> = manifest
        .tools
        .iter()
        .map(|c| (c.name.as_str(), c.approved_behavior_hash.as_deref()))
        .collect();
    let live_names: BTreeSet<&str> = observed.tools.iter().map(|t| t.name.as_str()).collect();

    let mut tools = Vec::with_capacity(observed.tools.len());
    let mut would_quarantine = Vec::new();
    for tool in &observed.tools {
        // Priority mirrors admission: metadata must normalize AND the hash
        // must match; an ambiguous cross-lane definition can satisfy
        // neither, so it outranks the draft comparison.
        let draft_status = if tool.metadata_error.is_some() {
            DraftHashStatus::InvalidMetadata
        } else if tool.behavior_hash.is_none() {
            DraftHashStatus::Ambiguous
        } else {
            match draft.get(tool.name.as_str()) {
                None => DraftHashStatus::MissingFromDraft,
                Some(approved) if *approved == tool.behavior_hash.as_deref() => {
                    DraftHashStatus::Match
                }
                Some(_) => DraftHashStatus::Mismatch,
            }
        };
        if draft_status != DraftHashStatus::Match {
            would_quarantine.push(tool.name.clone());
        }
        tools.push(ObservedToolStatus {
            name: tool.name.clone(),
            observed_behavior_hash: tool.behavior_hash.clone(),
            draft_status,
            metadata_error: tool.metadata_error.clone(),
        });
    }
    let mut draft_only: Vec<String> = manifest
        .tools
        .iter()
        .filter(|c| !live_names.contains(c.name.as_str()))
        .map(|c| c.name.clone())
        .collect();
    // Deterministic order regardless of how the caller ordered the observed
    // catalog or the draft entries.
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    would_quarantine.sort();
    draft_only.sort();
    ObservedServerContracts {
        server: server.to_owned(),
        connected: true,
        note: None,
        tools,
        draft_only,
        would_quarantine,
    }
}

/// Preview for `manifest.publish` — params mirror `ManifestPublishParams`
/// (`{ "bundle_id": Uuid }`). Loads the draft, then replays its content.
async fn publish_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    witness: Option<&crate::change_executor::ManifestFullSetWitness>,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    let bundle_id = match serde_json::from_value::<PublishParams>(params.clone()) {
        Ok(p) => p.bundle_id,
        Err(e) => {
            return degraded(
                ManifestChangeKind::Publish { version: 0 },
                format!("params do not match the publish action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let unknown = || ManifestChangeKind::Publish { version: 0 };

    let Some(store) = state.servers.manifest_store.get() else {
        return degraded(
            unknown(),
            "manifest store not configured — cannot load the draft to preview",
        );
    };
    let bundle = match store.get(tenant_id, bundle_id).await {
        Ok(b) => b,
        Err(e) => return degraded(unknown(), format!("could not load the draft bundle: {e}")),
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(unknown(), "change request carries an invalid tenant id");
    };

    // Precondition parity: the publish core requires a `Draft` target (a
    // non-draft fails at execute). Mirror it so the approver doesn't approve a
    // "will publish" effect that can't happen.
    let blocked = (!matches!(bundle.status, ManifestStatus::Draft))
        .then(|| {
            "the target bundle is no longer a draft — the manifest publish executor requires a \
             draft, so approval would fail at execute; re-propose against the current draft."
                .to_owned()
        })
        .or_else(|| {
            witness
                .is_some_and(|captured| captured.target_content_hash != bundle.content_hash)
                .then(|| {
                    "the manifest draft changed after this request was proposed; re-propose it \
                     before approval"
                        .to_owned()
                })
        });

    build_preview(
        state,
        &tenant,
        ManifestChangeKind::Publish {
            version: bundle.version,
        },
        &bundle.content,
        blocked,
        witness.and_then(|captured| captured.live_base_hash.as_deref()),
        observer,
    )
    .await
}

/// Preview for `manifest.rollback` — params mirror `ManifestRollbackParams`
/// (`{ "version": i32 }`). Resolves the target version's content exactly as the
/// rollback core does (`get_by_version`, which returns `NotFound` for an absent
/// / draft-only / wrong-tenant version — so a successful load IS the validity
/// check), then replays it.
async fn rollback_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    witness: Option<&crate::change_executor::ManifestFullSetWitness>,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    let version = match serde_json::from_value::<RollbackParams>(params.clone()) {
        Ok(p) => p.version,
        Err(e) => {
            return degraded(
                ManifestChangeKind::Rollback { version: 0 },
                format!("params do not match the rollback action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let kind = || ManifestChangeKind::Rollback { version };

    let Some(store) = state.servers.manifest_store.get() else {
        return degraded(
            kind(),
            "manifest store not configured — cannot load the target version to preview",
        );
    };
    let target = match store.get_by_version(tenant_id, version).await {
        Ok(b) => b,
        Err(e) => {
            return degraded(
                kind(),
                format!(
                    "no previously-published manifest version {version} in this tenant — rollback \
                     requires a published version (the executor would fail at execute): {e}"
                ),
            );
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(kind(), "change request carries an invalid tenant id");
    };

    let blocked = witness
        .is_some_and(|captured| captured.target_content_hash != target.content_hash)
        .then(|| {
            "the rollback target changed after this request was proposed; re-propose it before \
             approval"
                .to_owned()
        });

    build_preview(
        state,
        &tenant,
        kind(),
        &target.content,
        blocked,
        witness.and_then(|captured| captured.live_base_hash.as_deref()),
        observer,
    )
    .await
}

/// Mirror of `change_executor::ManifestStageAndPublishParams` — only the
/// `content` the preview replays (`author` and `base_hash` do not change the
/// candidate itself).
#[derive(Deserialize)]
struct StageAndPublishPreviewParams {
    content: String,
}

/// Preview for `manifest.stage_and_publish` — the candidate content is inline in
/// the params (no draft to load), so it replays directly. A set that doesn't
/// parse would be rejected by the executor's own `parse_manifest_set` at execute;
/// that surfaces inside the replay report's own `error` (the approver still sees
/// "this can't land"), so there's no separate `blocked` precondition here.
async fn stage_and_publish_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    expected_base_hash: Option<&str>,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    let content = match serde_json::from_value::<StageAndPublishPreviewParams>(params.clone()) {
        Ok(p) => p.content,
        Err(e) => {
            return degraded(
                ManifestChangeKind::StageAndPublish,
                format!("params do not match the stage-and-publish action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(
            ManifestChangeKind::StageAndPublish,
            "change request carries an invalid tenant id",
        );
    };
    build_preview(
        state,
        &tenant,
        ManifestChangeKind::StageAndPublish,
        &content,
        None,
        expected_base_hash,
        observer,
    )
    .await
}

/// Preview for `manifest.upsert_servers` — the params carry only the servers to
/// add/replace, so (unlike stage-and-publish) the approver must see the MERGED
/// effect. This replays the reconstructed full set (`merge_upserts_into_live_set`,
/// the exact merge the executor performs) against live policy. A merge failure
/// (bad upsert set, or an unreadable live on-disk set) degrades to a `note`; the
/// executor would surface the same error at approval.
async fn upsert_servers_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    expected_base_hash: Option<&str>,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    // Reuse the content-only params mirror (`author` doesn't affect blast radius).
    let content = match serde_json::from_value::<StageAndPublishPreviewParams>(params.clone()) {
        Ok(p) => p.content,
        Err(e) => {
            return degraded(
                ManifestChangeKind::UpsertServers,
                format!("params do not match the upsert-servers action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(
            ManifestChangeKind::UpsertServers,
            "change request carries an invalid tenant id",
        );
    };
    // Merge the upserts into the live on-disk set to get the effective full set the
    // approver is really deciding on. `ApiError` has no `Display`, so degrade with
    // a generic note; the executor surfaces the specific error at approval.
    // The preview only replays the merged set — discard the CAS base hash (`.0`).
    let merged = match crate::manifest_bundles::merge_upserts_into_live_set(state, &content) {
        Ok((m, _base_hash)) => m,
        Err(_e) => {
            return degraded(
                ManifestChangeKind::UpsertServers,
                "could not compute the merged manifest set to preview (the servers may be invalid or the live on-disk set unreadable); the executor would surface the same error at approval",
            );
        }
    };
    build_preview(
        state,
        &tenant,
        ManifestChangeKind::UpsertServers,
        &merged,
        None,
        expected_base_hash,
        observer,
    )
    .await
}

#[derive(Deserialize)]
struct RemoveServersPreviewParams {
    base_hash: String,
    server_names: Vec<String>,
}

/// Preview the exact full set produced by removing the requested names from the
/// live snapshot. The shared transformation also rejects unknown names, so an
/// approver never sees a successful effect for a no-op removal.
async fn remove_servers_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    if tenant_id != TenantId::DEFAULT {
        return degraded(
            ManifestChangeKind::RemoveServers,
            "manifest server removal preview is available only to the default tenant because the \
             live on-disk manifest set is gateway-wide",
        );
    }
    let parsed = match serde_json::from_value::<RemoveServersPreviewParams>(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return degraded(
                ManifestChangeKind::RemoveServers,
                format!("params do not match the remove-servers action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(
            ManifestChangeKind::RemoveServers,
            "change request carries an invalid tenant id",
        );
    };
    let (updated, _current_base) = match crate::manifest_bundles::remove_servers_from_live_set(
        state,
        &parsed.server_names,
        Some(parsed.base_hash.as_str()),
    ) {
        Ok(pair) => pair,
        Err(crate::error::ApiError::Conflict(_)) => {
            return ManifestChangePreview {
                kind: ManifestChangeKind::RemoveServers,
                impact: None,
                effective: None,
                note: None,
                blocked: Some(
                    "the live manifest set changed after this removal was prepared — approval \
                     would fail at execute; call gateway-admin.get_action_context again and \
                     re-propose against the current base_hash"
                        .to_owned(),
                ),
                observed: Vec::new(),
            };
        }
        Err(_e) => {
            return degraded(
                    ManifestChangeKind::RemoveServers,
                    "could not compute the manifest set after removal (a server name may be invalid or absent, or the live on-disk set unreadable); the executor would surface the same error at approval",
                );
        }
    };
    build_preview(
        state,
        &tenant,
        ManifestChangeKind::RemoveServers,
        &updated,
        None,
        Some(parsed.base_hash.as_str()),
        observer,
    )
    .await
}

/// Replay the already-loaded candidate `content` against the live policy +
/// on-disk active manifest set. A preview-dependency failure (no engine / audit
/// store, unreadable disk) degrades to a `note`; a candidate that doesn't parse
/// surfaces inside the returned report's own `error`.
async fn build_preview(
    state: &AdminState,
    tenant: &TenantId,
    kind: ManifestChangeKind,
    content: &str,
    blocked: Option<String>,
    expected_base_hash: Option<&str>,
    observer: Option<&Principal>,
) -> ManifestChangePreview {
    let ledger_only = tenant.as_str() != TenantId::DEFAULT
        && matches!(
            &kind,
            ManifestChangeKind::Publish { .. } | ManifestChangeKind::Rollback { .. }
        );
    if ledger_only {
        return ManifestChangePreview {
            kind,
            impact: Some(ManifestImpactReport::ledger_only(content)),
            effective: Some(crate::manifest_effect::ManifestEffectiveImpact::ledger_only()),
            note: None,
            blocked,
            observed: Vec::new(),
        };
    }
    let mut notes = Vec::new();
    let (impact, effective) = match crate::manifest_impact::active_manifest_snapshot(state) {
        Ok((active, current_base_hash)) => {
            if expected_base_hash
                .is_some_and(|expected| current_base_hash.as_deref() != Some(expected))
            {
                return ManifestChangePreview {
                    kind,
                    impact: None,
                    effective: None,
                    note: None,
                    blocked: Some(
                        "the live manifest set changed after this effect was prepared — approval \
                         would execute against a different baseline; call \
                         gateway-admin.get_action_context again and re-propose"
                            .to_owned(),
                    ),
                    observed: Vec::new(),
                };
            }
            let impact = match crate::manifest_impact::replay_manifest_impact_against(
                state, tenant, &active, content,
            )
            .await
            {
                Ok(report) => Some(report),
                Err(error) => {
                    notes.push(format!(
                        "classification replay unavailable: {}",
                        error.detail()
                    ));
                    None
                }
            };
            let effective = match crate::manifest_effect::effective_manifest_impact(
                state, tenant, &active, content, observer,
            )
            .await
            {
                Ok(report) => Some(report),
                Err(error) => {
                    notes.push(format!("effective-impact preview unavailable: {error}"));
                    None
                }
            };
            (impact, effective)
        }
        Err(error) => {
            notes.push(format!("manifest baseline unavailable: {}", error.detail()));
            (None, None)
        }
    };
    let observed = observed_annotation_contracts(state, tenant, content, observer).await;
    ManifestChangePreview {
        kind,
        impact,
        effective,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
        blocked,
        observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use serde_json::json;
    use waygate_upstream::pool::UpstreamPool;

    /// An `AdminState` with NO manifest store wired. The dispatch + degradation
    /// paths all decide BEFORE touching a store (action-type match, params
    /// parse, `state.servers.manifest_store.is_none()`), so they're exercisable without
    /// standing up a `ManifestStore`; the store-backed happy path is covered
    /// through the `/changes` dashboard router tests.
    async fn no_store_state_with_servers_dir(
        servers_dir: Option<std::path::PathBuf>,
    ) -> Arc<AdminState> {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: waygate_mcp::audit::SharedEvidence =
            Arc::new(waygate_mcp::audit::InMemorySink::default());
        let state = AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        );
        Arc::new(match servers_dir {
            Some(dir) => state.with_servers_dir(dir),
            None => state,
        })
    }

    async fn no_store_state() -> Arc<AdminState> {
        no_store_state_with_servers_dir(None).await
    }

    #[tokio::test]
    async fn non_manifest_action_has_no_preview() {
        let state = no_store_state().await;
        let p = manifest_change_preview(
            &state,
            "default",
            "policy.publish",
            &json!({ "bundle_id": "x" }),
            None,
        )
        .await;
        assert!(
            p.is_none(),
            "only manifest.publish/rollback get a manifest preview"
        );
    }

    #[tokio::test]
    async fn publish_without_bundle_id_degrades_not_panics() {
        let state = no_store_state().await;
        let p = manifest_change_preview(&state, "default", "manifest.publish", &json!({}), None)
            .await
            .expect("a manifest action always yields Some(preview)");
        assert!(p.impact.is_none());
        assert!(
            p.note.as_deref().unwrap_or("").contains("bundle_id"),
            "note names the missing field"
        );
        assert!(p.blocked.is_none());
    }

    #[tokio::test]
    async fn publish_with_store_unwired_degrades() {
        let state = no_store_state().await;
        let id = uuid::Uuid::now_v7();
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.publish",
            &json!({ "bundle_id": id.to_string() }),
            None,
        )
        .await
        .expect("Some");
        assert!(p.impact.is_none());
        assert!(
            p.note.as_deref().unwrap_or("").contains("manifest store"),
            "note explains the store is unwired"
        );
    }

    #[tokio::test]
    async fn rollback_without_version_degrades() {
        let state = no_store_state().await;
        let p = manifest_change_preview(&state, "default", "manifest.rollback", &json!({}), None)
            .await
            .expect("Some");
        assert!(p.impact.is_none());
        assert!(p.note.as_deref().unwrap_or("").contains("version"));
    }

    #[tokio::test]
    async fn rollback_out_of_i32_range_version_degrades_not_truncates() {
        let state = no_store_state().await;
        // 2^40 is valid JSON but out of i32 range; the executor rejects it, so
        // the preview must degrade rather than truncate to a bogus version.
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.rollback",
            &json!({ "version": 1_099_511_627_776i64 }),
            None,
        )
        .await
        .expect("Some");
        assert!(p.note.is_some());
        assert!(
            p.blocked.is_none(),
            "a bad-params degrade is not a precondition block"
        );
    }

    #[tokio::test]
    async fn stage_and_publish_without_content_degrades() {
        let state = no_store_state().await;
        // No `content` field: the executor would reject the params, so the
        // preview degrades (parsed before any store touch) rather than panics.
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &json!({}),
            None,
        )
        .await
        .expect("a manifest action always yields Some(preview)");
        assert!(p.impact.is_none());
        assert!(
            p.note.as_deref().unwrap_or("").contains("content")
                || p.note.as_deref().unwrap_or("").contains("schema"),
            "note explains the missing/invalid content: {:?}",
            p.note
        );
        assert!(p.blocked.is_none());
    }

    #[tokio::test]
    async fn stage_preview_keeps_capability_projection_when_replay_is_unavailable() {
        let state = no_store_state().await;
        let params = json!({
            "content": "- name: grounded-docs\n  transport: http\n  url: http://grounded-docs/mcp\n  tools:\n    - name: search_docs\n      risk: low\n"
        });
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            None,
        )
        .await
        .expect("manifest action preview");

        assert!(p.impact.is_none(), "policy/audit replay is unwired");
        let effective = p
            .effective
            .expect("capability projection does not depend on replay");
        assert_eq!(
            effective.capability_change,
            crate::manifest_effect::CapabilityChange::Expands
        );
        assert_eq!(effective.tools.added, 1);
        assert_eq!(
            effective.activation_readiness,
            crate::manifest_effect::ActivationReadiness::Unknown
        );
        assert!(p
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("classification replay unavailable"));

        let tenant_local = manifest_change_preview(
            &state,
            "tenant-b",
            "manifest.stage_and_publish",
            &params,
            None,
        )
        .await
        .expect("non-default manifest action preview");
        assert!(
            tenant_local.effective.is_none(),
            "a tenant-local ledger publication cannot claim gateway-wide runtime effects"
        );
    }

    #[tokio::test]
    async fn effective_projection_requires_live_state_visibility_for_mcp_observers() {
        let state = no_store_state().await;
        let params = json!({
            "content": "- name: grounded-docs\n  transport: http\n  url: http://grounded-docs/mcp\n  tools:\n    - name: search_docs\n      risk: low\n"
        });
        let maker = observer_with(vec!["mcp:read", "mcp:propose"]);
        let visible = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&maker),
        )
        .await
        .expect("maker preview");
        assert!(visible.effective.is_some());

        let reader = observer_with(vec!["mcp:read"]);
        let below_floor = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&reader),
        )
        .await
        .expect("reader preview");
        assert!(below_floor.effective.is_none());

        let mut peer = maker.clone();
        peer.auth_method = waygate_oidc::AuthMethod::PeerAssertion;
        let peer_preview = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&peer),
        )
        .await
        .expect("peer preview");
        assert!(peer_preview.effective.is_none());

        let mut server_confined = maker.clone();
        server_confined.api_key_profile_restrictions =
            Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "p-server".into(),
                profile_name: "example-messages-only".into(),
                allowed_servers: Some(vec!["example-messages".into()]),
                allowed_tools: None,
            });
        let server_confined_preview = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&server_confined),
        )
        .await
        .expect("server-confined preview");
        assert!(server_confined_preview.effective.is_none());

        let mut tool_confined = maker;
        tool_confined.api_key_profile_restrictions =
            Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "p-tool".into(),
                profile_name: "one-tool".into(),
                allowed_servers: Some(vec!["grounded-docs".into()]),
                allowed_tools: Some(vec!["grounded-docs.search_docs".into()]),
            });
        let tool_confined_preview = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&tool_confined),
        )
        .await
        .expect("tool-confined preview");
        assert!(tool_confined_preview.effective.is_none());
    }

    #[tokio::test]
    async fn upsert_servers_degrades_on_bad_params_and_no_live_set() {
        let state = no_store_state().await;
        // (a) No `content` → the executor would reject the params, so the preview
        // degrades on the schema mismatch (parsed before any store/disk touch).
        let bad = manifest_change_preview(
            &state,
            "default",
            "manifest.upsert_servers",
            &json!({}),
            None,
        )
        .await
        .expect("a manifest action always yields Some(preview)");
        assert!(bad.impact.is_none());
        assert!(
            bad.note.as_deref().unwrap_or("").contains("schema")
                || bad.note.as_deref().unwrap_or("").contains("params"),
            "note explains the bad params: {:?}",
            bad.note
        );
        assert!(bad.blocked.is_none());

        // (b) Valid partial set, but no `servers_dir` wired in the test state, so
        // the live set can't be read to merge into → the preview degrades on the
        // merge (the same error the executor would surface at approval), it does
        // not panic.
        let ok_params = json!({ "content": "- name: x\n  transport: http\n  url: http://x/mcp\n" });
        let merged = manifest_change_preview(
            &state,
            "default",
            "manifest.upsert_servers",
            &ok_params,
            None,
        )
        .await
        .expect("a manifest action always yields Some(preview)");
        assert!(merged.impact.is_none());
        assert!(
            merged.note.as_deref().unwrap_or("").contains("merged"),
            "note explains the merge could not be computed: {:?}",
            merged.note
        );
        assert!(merged.blocked.is_none());
    }

    #[tokio::test]
    async fn remove_servers_degrades_when_names_or_live_set_are_unavailable() {
        let state = no_store_state().await;
        let bad = manifest_change_preview(
            &state,
            "default",
            "manifest.remove_servers",
            &json!({}),
            None,
        )
        .await
        .expect("a manifest action always yields Some(preview)");
        assert!(bad.impact.is_none());
        assert!(bad.note.is_some());

        let no_live = manifest_change_preview(
            &state,
            "default",
            "manifest.remove_servers",
            &json!({"base_hash": "snapshot", "server_names": ["alpha"]}),
            None,
        )
        .await
        .expect("a manifest action always yields Some(preview)");
        assert!(no_live.impact.is_none());
        assert!(
            no_live
                .note
                .as_deref()
                .unwrap_or("")
                .contains("after removal"),
            "note explains why the removal effect cannot be computed: {:?}",
            no_live.note
        );
    }

    fn annotation_manifest(tools: Vec<waygate_upstream::ToolClassification>) -> UpstreamManifest {
        UpstreamManifest {
            classification_mode: ClassificationMode::McpAnnotations,
            approval_mode: Default::default(),
            name: "anno".into(),
            transport: waygate_upstream::Transport::Http,
            protocol: Default::default(),
            url: Some("http://anno.test/mcp".into()),
            command: None,
            tools,
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        }
    }

    fn draft_entry(name: &str, approved: Option<&str>) -> waygate_upstream::ToolClassification {
        waygate_upstream::ToolClassification {
            approved_behavior_hash: approved.map(str::to_owned),
            ..waygate_upstream::ToolClassification::new(
                name,
                waygate_mcp::protocol::RiskTier::Low,
                false,
                false,
            )
        }
    }

    fn live(
        name: &str,
        hash: Option<&str>,
        metadata_error: Option<&str>,
    ) -> waygate_upstream::ObservedToolContract {
        waygate_upstream::ObservedToolContract {
            name: name.to_owned(),
            behavior_hash: hash.map(str::to_owned),
            metadata_error: metadata_error.map(str::to_owned),
        }
    }

    /// The status classification IS the admission prediction: only a live
    /// tool whose metadata normalizes AND whose draft hash equals the
    /// observed hash is admitted; everything else lands in
    /// `would_quarantine`, and draft entries with no live descriptor are
    /// `draft_only` (unreachable, not quarantined).
    #[test]
    fn observed_report_classifies_every_admission_outcome() {
        let manifest = annotation_manifest(vec![
            draft_entry("good", Some("aaaa")),
            draft_entry("stale", Some("bbbb")),
            draft_entry("hashless", None),
            draft_entry("ghost", Some("cccc")),
        ]);
        let observed = waygate_upstream::ObservedContracts {
            connected: true,
            tools: vec![
                live("ambiguous", None, None),
                live("good", Some("aaaa"), None),
                live(
                    "malformed",
                    Some("dddd"),
                    Some("standard MCP annotations are missing"),
                ),
                live("stale", Some("eeee"), None),
                live("unlisted", Some("ffff"), None),
                live("hashless", Some("1111"), None),
            ],
        };
        let report = observed_server_report("anno", &manifest, Some(observed));

        assert!(report.connected);
        assert!(report.note.is_none());
        let status: BTreeMap<&str, DraftHashStatus> = report
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.draft_status))
            .collect();
        assert_eq!(status["good"], DraftHashStatus::Match);
        assert_eq!(status["stale"], DraftHashStatus::Mismatch);
        assert_eq!(status["hashless"], DraftHashStatus::Mismatch);
        assert_eq!(status["unlisted"], DraftHashStatus::MissingFromDraft);
        assert_eq!(status["ambiguous"], DraftHashStatus::Ambiguous);
        assert_eq!(status["malformed"], DraftHashStatus::InvalidMetadata);
        assert_eq!(
            report.would_quarantine,
            vec!["ambiguous", "hashless", "malformed", "stale", "unlisted"],
            "every non-match live tool is predicted quarantined, sorted"
        );
        assert_eq!(report.draft_only, vec!["ghost"]);
        // The mismatch rows carry the hash to copy into the draft.
        let stale = report.tools.iter().find(|t| t.name == "stale").unwrap();
        assert_eq!(stale.observed_behavior_hash.as_deref(), Some("eeee"));
    }

    #[test]
    fn observed_report_is_honest_when_nothing_is_observable() {
        let manifest = annotation_manifest(vec![draft_entry("t", Some("aaaa"))]);

        let unknown = observed_server_report("anno", &manifest, None);
        assert!(!unknown.connected);
        assert!(unknown
            .note
            .as_deref()
            .unwrap_or("")
            .contains("not registered"));
        assert!(unknown.tools.is_empty() && unknown.would_quarantine.is_empty());

        let down = observed_server_report(
            "anno",
            &manifest,
            Some(waygate_upstream::ObservedContracts {
                connected: false,
                tools: Vec::new(),
            }),
        );
        assert!(!down.connected);
        assert!(down.note.as_deref().unwrap_or("").contains("connected"));
        assert!(down.tools.is_empty() && down.would_quarantine.is_empty());
    }

    fn observer_with(scopes: Vec<&str>) -> Principal {
        Principal {
            sub: "tester".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.into_iter().map(String::from).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn annotation_candidate_params() -> serde_json::Value {
        let hash = "a".repeat(64);
        let content = format!(
            "- name: anno\n  transport: http\n  url: http://anno.test/mcp\n\
             \x20 classification_mode: mcp_annotations\n  tools:\n\
             \x20   - name: t1\n      risk: low\n      approved_behavior_hash: {hash}\n"
        );
        json!({ "content": content })
    }

    /// The observed section rides the stage-and-publish preview for a maker
    /// (`mcp:propose` — the propose-only automated maker is exactly who the
    /// section exists for) or an `mcp:admin` observer in the default
    /// tenant, and is withheld from everyone else: other tenants (the pool
    /// is gateway-wide, and liveness of a guessed server must not leak —
    /// the same boundary the removal preview enforces), observers below the
    /// maker floor, peer-asserted principals, observer-less callers (the
    /// dashboard queues), and servers the observer's API-key profile
    /// confines them away from.
    #[tokio::test]
    async fn observed_section_requires_default_tenant_and_maker_floor() {
        let params = annotation_candidate_params();
        let maker = observer_with(vec!["mcp:read", "mcp:propose"]);

        let state = no_store_state().await;
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&maker),
        )
        .await
        .expect("Some");
        assert_eq!(
            p.observed.len(),
            1,
            "a propose-only maker gets the section — it exists for them"
        );
        assert_eq!(p.observed[0].server, "anno");
        assert!(!p.observed[0].connected, "server unknown to the empty pool");
        assert!(p.observed[0].note.is_some());

        let admin = observer_with(vec!["mcp:read", "mcp:admin"]);
        let for_admin = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&admin),
        )
        .await
        .expect("Some");
        assert_eq!(for_admin.observed.len(), 1, "mcp:admin also qualifies");

        let other = manifest_change_preview(
            &state,
            "tenant-b",
            "manifest.stage_and_publish",
            &params,
            Some(&maker),
        )
        .await
        .expect("Some");
        assert!(
            other.observed.is_empty(),
            "non-default tenants must not learn gateway-wide liveness"
        );

        let reader = observer_with(vec!["mcp:read"]);
        let below_floor = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&reader),
        )
        .await
        .expect("Some");
        assert!(
            below_floor.observed.is_empty(),
            "below the maker floor there is no section"
        );

        let mut peer = observer_with(vec!["mcp:read", "mcp:propose"]);
        peer.auth_method = waygate_oidc::AuthMethod::PeerAssertion;
        let peer_asserted = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&peer),
        )
        .await
        .expect("Some");
        assert!(
            peer_asserted.observed.is_empty(),
            "a peer-asserted principal never reads the raw catalog (mirrors the maker gate)"
        );

        let observerless = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            None,
        )
        .await
        .expect("Some");
        assert!(
            observerless.observed.is_empty(),
            "no observer (dashboard queues) means no section"
        );

        let mut confined = observer_with(vec!["mcp:read", "mcp:admin"]);
        confined.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "p1".into(),
            profile_name: "not-anno".into(),
            allowed_servers: Some(vec!["example-messages".into()]),
            allowed_tools: None,
        });
        let blocked = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&confined),
        )
        .await
        .expect("Some");
        assert!(
            blocked.observed.is_empty(),
            "a profile-confined observer's blocked server is omitted entirely"
        );

        // A manifest-mode candidate has no observed section at all.
        let manifest_mode = json!({
            "content": "- name: plain\n  transport: http\n  url: http://plain.test/mcp\n"
        });
        let plain = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &manifest_mode,
            Some(&admin),
        )
        .await
        .expect("Some");
        assert!(plain.observed.is_empty());
    }

    /// A profile that confines the observer to a SUBSET of the server's live
    /// tools withholds the whole report: partial disclosure would violate
    /// the per-tool profile contract, and a filtered report would teach a
    /// maker to publish a manifest that quarantines the hidden tools.
    #[test]
    fn per_tool_profile_confinement_withholds_the_whole_report() {
        let report = ObservedServerContracts {
            server: "anno".into(),
            connected: true,
            note: None,
            tools: vec![
                ObservedToolStatus {
                    name: "allowed".into(),
                    observed_behavior_hash: Some("aaaa".into()),
                    draft_status: DraftHashStatus::Match,
                    metadata_error: None,
                },
                ObservedToolStatus {
                    name: "hidden".into(),
                    observed_behavior_hash: Some("bbbb".into()),
                    draft_status: DraftHashStatus::MissingFromDraft,
                    metadata_error: None,
                },
            ],
            draft_only: Vec::new(),
            would_quarantine: vec!["hidden".into()],
        };

        let mut confined = observer_with(vec!["mcp:read", "mcp:propose"]);
        confined.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "p1".into(),
            profile_name: "one-tool".into(),
            allowed_servers: None,
            allowed_tools: Some(vec!["anno.allowed".into()]),
        });
        let withheld = withhold_if_profile_confined(&confined, "anno", report.clone());
        assert!(!withheld.connected);
        assert!(
            withheld
                .note
                .as_deref()
                .unwrap_or("")
                .contains("withheld rather than filtered"),
            "withholding must teach why: {:?}",
            withheld.note
        );
        assert!(
            withheld.tools.is_empty() && withheld.would_quarantine.is_empty(),
            "nothing may leak past the withhold — not even the allowed tool"
        );

        let unconfined = observer_with(vec!["mcp:read", "mcp:propose"]);
        assert_eq!(
            withhold_if_profile_confined(&unconfined, "anno", report.clone()),
            report,
            "no confinement passes the report through untouched"
        );
    }

    /// The parity check must never judge a hidden tool on the permissive
    /// low/no-side-effects catalog fallback: unclassified and
    /// drift-quarantined live names are evaluated at the worst-case
    /// contract, while a governed name keeps its governed facts untouched.
    #[test]
    fn cedar_parity_facts_are_conservative_for_hidden_tools() {
        let governed = || waygate_mcp::authz::ToolFacts {
            server: "anno".into(),
            name: "t".into(),
            risk: waygate_mcp::protocol::RiskTier::Low,
            side_effects: false,
            pii: false,
            requires_approval: false,
            requires_approval_known: true,
        };

        let kept = cedar_parity_facts(governed(), true, false);
        assert_eq!(kept.risk, waygate_mcp::protocol::RiskTier::Low);
        assert!(!kept.side_effects && !kept.pii);

        for (classified, quarantined) in [(false, false), (false, true), (true, true)] {
            let conservative = cedar_parity_facts(governed(), classified, quarantined);
            assert_eq!(
                conservative.risk,
                waygate_mcp::protocol::RiskTier::High,
                "hidden tools are judged at the most sensitive contract"
            );
            assert!(conservative.side_effects && conservative.pii);
            assert_eq!(conservative.server, "anno");
            assert_eq!(conservative.name, "t");
        }
    }

    /// Cedar discovery parity: an observer the live policy denies server
    /// discovery gets a withheld report — including in place of the
    /// unknown/disconnected notes, which would otherwise reveal
    /// registration and liveness to a caller discovery hides the server
    /// from. An empty policy set denies all discovery; a permit-all set
    /// passes the report (here the unknown-server note) through.
    #[tokio::test]
    async fn cedar_undiscoverable_observer_gets_a_withheld_report() {
        async fn state_with_policies(source: &str) -> Arc<AdminState> {
            let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
            let evidence: waygate_mcp::audit::SharedEvidence =
                Arc::new(waygate_mcp::audit::InMemorySink::default());
            let engine = waygate_authz::CedarEngine::from_source(source).expect("cedar compiles");
            let cedar = Arc::new(waygate_authz::ReloadableCedar::new(engine));
            Arc::new(AdminState::new(
                pool,
                Some(cedar),
                None,
                evidence,
                None,
                None,
                None,
                None,
                "http://127.0.0.1:0".into(),
            ))
        }
        let params = annotation_candidate_params();
        let maker = observer_with(vec!["mcp:read", "mcp:propose"]);

        let deny_all = state_with_policies("").await;
        let withheld = manifest_change_preview(
            &deny_all,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&maker),
        )
        .await
        .expect("Some");
        assert_eq!(withheld.observed.len(), 1);
        assert!(!withheld.observed[0].connected);
        assert!(
            withheld.observed[0]
                .note
                .as_deref()
                .unwrap_or("")
                .contains("authorization policy"),
            "a policy-denied observer must get the withheld note, not liveness detail: {:?}",
            withheld.observed[0].note
        );
        assert!(withheld.observed[0].tools.is_empty());
        assert!(
            withheld.effective.is_none(),
            "Cedar-denied server discovery must also withhold runtime and catalog state"
        );

        let permit_all = state_with_policies("permit(principal, action, resource);").await;
        let passed = manifest_change_preview(
            &permit_all,
            "default",
            "manifest.stage_and_publish",
            &params,
            Some(&maker),
        )
        .await
        .expect("Some");
        assert_eq!(passed.observed.len(), 1);
        assert!(
            passed.observed[0]
                .note
                .as_deref()
                .unwrap_or("")
                .contains("not registered"),
            "a policy-allowed observer keeps the real report: {:?}",
            passed.observed[0].note
        );
        assert!(
            passed.effective.is_some(),
            "Cedar-allowed server discovery admits the effective projection"
        );
    }

    /// A candidate that also changes the server's connection shape gets an
    /// explicit unobservable note instead of a prediction: publish re-dials
    /// the new shape, so contracts observed on the current sessions cannot
    /// stand for the redialed catalog.
    #[tokio::test]
    async fn observed_section_refuses_to_predict_across_a_shape_change() {
        let mut map = BTreeMap::new();
        map.insert(
            "anno".to_string(),
            waygate_upstream::UpstreamManifest {
                classification_mode: ClassificationMode::Manifest,
                approval_mode: Default::default(),
                name: "anno".into(),
                transport: waygate_upstream::Transport::Http,
                protocol: Default::default(),
                url: Some("http://current.test/mcp".into()),
                command: None,
                tools: vec![],
                resources: vec![],
                exchange: None,
                auth: None,
                mtls: None,
                tier_a_required: false,
                tier_c_peer: None,
                session: None,
            },
        );
        let pool = Arc::new(UpstreamPool::from_manifests_disconnected(map));
        let evidence: waygate_mcp::audit::SharedEvidence =
            Arc::new(waygate_mcp::audit::InMemorySink::default());
        let state = Arc::new(AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        ));
        let admin = observer_with(vec!["mcp:admin"]);

        // Same server name, DIFFERENT url ⇒ publish would re-dial.
        let p = manifest_change_preview(
            &state,
            "default",
            "manifest.stage_and_publish",
            &annotation_candidate_params(),
            Some(&admin),
        )
        .await
        .expect("Some");
        assert_eq!(p.observed.len(), 1);
        assert!(!p.observed[0].connected);
        assert!(
            p.observed[0]
                .note
                .as_deref()
                .unwrap_or("")
                .contains("connection shape"),
            "shape-changing candidates must refuse to predict: {:?}",
            p.observed[0].note
        );
        assert!(p.observed[0].tools.is_empty() && p.observed[0].would_quarantine.is_empty());
    }

    #[tokio::test]
    async fn remove_servers_marks_a_preview_reconstructed_from_a_newer_base_as_blocked() {
        let dir =
            std::env::temp_dir().join(format!("manifest-remove-preview-{}", uuid::Uuid::now_v7()));
        let initial = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://alpha/mcp\n\
             - name: beta\n  transport: http\n  url: http://beta/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &initial).unwrap();
        let state = no_store_state_with_servers_dir(Some(dir.clone())).await;
        let Some(Ok((_set, prepared_base))) = state.read_manifest_set_from_disk() else {
            panic!("expected readable initial manifest set");
        };

        let changed = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://alpha/mcp\n\
             - name: beta\n  transport: http\n  url: http://beta-v2/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &changed).unwrap();

        let preview = manifest_change_preview(
            &state,
            "default",
            "manifest.remove_servers",
            &json!({"base_hash": prepared_base.clone(), "server_names": ["alpha"]}),
            None,
        )
        .await
        .expect("manifest removal has a preview");
        assert!(
            preview
                .blocked
                .as_deref()
                .is_some_and(|reason| reason.contains("get_action_context")),
            "preview must disclose that execution will refuse the stale removal: {:?}",
            preview.blocked
        );

        let absent_stale_preview = manifest_change_preview(
            &state,
            "default",
            "manifest.remove_servers",
            &json!({"base_hash": prepared_base, "server_names": ["not-live"]}),
            None,
        )
        .await
        .expect("manifest removal has a preview");
        assert_eq!(
            preview.blocked, absent_stale_preview.blocked,
            "a stale witness must be rejected before requested-name membership is checked"
        );
        assert!(absent_stale_preview.impact.is_none() && absent_stale_preview.note.is_none());

        let existing_probe = manifest_change_preview(
            &state,
            "another-tenant",
            "manifest.remove_servers",
            &json!({"base_hash": "guess", "server_names": ["alpha"]}),
            None,
        )
        .await
        .expect("manifest removal has a preview");
        let absent_probe = manifest_change_preview(
            &state,
            "another-tenant",
            "manifest.remove_servers",
            &json!({"base_hash": "guess", "server_names": ["not-live"]}),
            None,
        )
        .await
        .expect("manifest removal has a preview");
        assert!(existing_probe.impact.is_none() && absent_probe.impact.is_none());
        assert_eq!(
            existing_probe.note, absent_probe.note,
            "non-default tenants must not learn whether a guessed gateway-wide server is live"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pending_replace_and_upsert_previews_refuse_a_newer_live_baseline() {
        let dir = std::env::temp_dir().join(format!(
            "manifest-pending-preview-stale-base-{}",
            uuid::Uuid::now_v7()
        ));
        let initial = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://alpha/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &initial).unwrap();
        let state = no_store_state_with_servers_dir(Some(dir.clone())).await;
        let Some(Ok((_set, prepared_base))) = state.read_manifest_set_from_disk() else {
            panic!("expected readable initial manifest set");
        };

        let changed = waygate_upstream::parse_manifest_set(
            "- name: alpha\n  transport: http\n  url: http://alpha-v2/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &changed).unwrap();

        for (action, content) in [
            (
                "manifest.stage_and_publish",
                "- name: beta\n  transport: http\n  url: http://beta/mcp\n",
            ),
            (
                "manifest.upsert_servers",
                "- name: beta\n  transport: http\n  url: http://beta/mcp\n",
            ),
        ] {
            let preview = manifest_change_preview_for_request(
                &state,
                "default",
                action,
                &json!({"content": content}),
                Some(&prepared_base),
                None,
            )
            .await
            .expect("manifest action has a preview");
            assert!(
                preview
                    .blocked
                    .as_deref()
                    .is_some_and(|reason| reason.contains("different baseline")),
                "{action} must disclose that its captured live baseline is stale: {:?}",
                preview.blocked
            );
            assert!(preview.impact.is_none() && preview.effective.is_none());
        }

        std::fs::remove_dir_all(dir).unwrap();
    }
}
