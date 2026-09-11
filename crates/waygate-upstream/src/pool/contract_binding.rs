//! Dispatch-time contract binding for the upstream pool.
//!
//! Child of [`super`] so the Stage-1 resolution rules, the dispatch-time
//! identity re-check, and the shared session catalog reader live together
//! without growing the pool's transport and lifecycle module.

use super::*;

/// Manifest-derived governance facts for one tool, computed against an
/// explicit manifest snapshot so a dispatch-time re-check binds to the same
/// snapshot it admits against instead of re-reading mutable pool state.
///
/// Unknown server / unknown tool falls through to the safe default
/// (Low / no-side-effects / no-pii); see [`UpstreamCatalog::tool_facts`]
/// on [`UpstreamPool`] for why that branch stays conservative.
pub(super) fn manifest_tool_facts(
    manifest: Option<&UpstreamManifest>,
    server: &str,
    tool_name: &str,
) -> ToolFacts {
    let (risk, side_effects, pii) = manifest
        .and_then(|m| {
            let mode = m.classification_mode;
            m.tools
                .iter()
                .find(|t| t.name == tool_name)
                .map(|c| match mode {
                    crate::ClassificationMode::Manifest => (c.risk, c.side_effects, c.pii),
                    // This synchronous fallback cannot see the live annotations
                    // (bound only in the async resolver), so it stays
                    // conservatively side-effecting/PII for annotation-native
                    // tools. Enforcement uses the resolved snapshot; UX
                    // consumers that need the derived side-effect fact call
                    // `UpstreamPool::resolved_side_effects` instead.
                    crate::ClassificationMode::McpAnnotations => (c.risk, true, true),
                })
        })
        .unwrap_or((RiskTier::Low, false, false));
    ToolFacts {
        server: server.to_owned(),
        name: tool_name.to_owned(),
        risk,
        side_effects,
        pii,
        // Manifests don't carry requires_approval (the flag is set
        // in the catalog admin UI). Fallback defaults to
        // false — same posture as the legacy single-tier path.
        requires_approval: false,
        // Manifest is the source of truth on this path (catalog
        // either not wired or returned a deliberate transitional
        // state — PendingApproval/NotFound). The catalog-Err
        // fallback in `resolve_invocation_tool` explicitly overrides
        // to false to signal the gate.
        requires_approval_known: true,
    }
}

/// Map the catalog's per-operation classifications onto the tier type, keeping
/// them within the facts they refine.
///
/// This function is where the ceiling invariant lives. The migration that
/// created these columns records that storage does not enforce it and says the
/// enforcement will arrive with the code that reads the rows — that code is
/// here. A trigger is still worth adding when the catalog gains a write path for
/// operation rows, but it would be a second line of defence rather than the
/// first: rows can predate any trigger, and this read is what turns them into
/// authorization inputs.
///
/// Risk may narrow: the manifest ceiling already holds an operation at or below
/// its tool, and both authorities agreed on the tool's risk before this arm was
/// reached.
///
/// The behavior and sensitivity flags may only narrow in manifest mode. In
/// annotation mode [`manifest_tool_facts`] forces them true regardless of what
/// the row says, because the reviewed claims are not yet bound into the
/// snapshot; an operation entry validated against a manifest that forces the
/// tool-level flags clear would carry `false` and lower that posture. Pinning
/// each entry to the resolved tool-level flags keeps refinement to the one
/// dimension the generation check has agreed on.
pub(super) fn operation_classifications(
    facts: &ToolFacts,
    annotation_mode: bool,
    operations: Vec<waygate_catalog::OperationClassification>,
) -> Vec<waygate_mcp::catalog::OperationClassification> {
    operations
        .into_iter()
        .filter(|o| {
            // Test the row as stored, before any normalization. The manifest
            // loader refuses an operation more severe than its tool and the
            // catalog columns do not, so this read is where the ceiling has to
            // hold or an unnamed value would be classified more severely than a
            // named one — the fallback inverted.
            //
            // Order matters here. Pinning the flags first would launder a row
            // that exceeds them into one that passes, and it would keep the
            // narrower risk that came with it: an annotation-mode tool whose
            // derived flags are clear would admit a `side_effects` row as
            // `low/false` and authorize the call at the lower tier. Dropping the
            // entry leaves the tool-level classification in force, which is the
            // severe direction.
            let within = facts.risk.covers(catalog_risk_to_tier(&o.risk))
                && (facts.side_effects || !o.side_effects)
                && (facts.pii || !o.pii);
            if !within {
                tracing::warn!(
                    tool = %facts.name,
                    operation = %o.value,
                    operation_risk = %o.risk,
                    tool_risk = ?facts.risk,
                    "ignoring an operation classification more severe than the tool it \
                     refines; the tool-level classification stands",
                );
            }
            within
        })
        .map(|o| waygate_mcp::catalog::OperationClassification {
            value: o.value,
            risk: catalog_risk_to_tier(&o.risk),
            side_effects: if annotation_mode {
                facts.side_effects
            } else {
                o.side_effects
            },
            pii: if annotation_mode { facts.pii } else { o.pii },
        })
        .collect()
}

impl UpstreamPool {
    /// Resolver-derived side-effect fact for allowlist/UX consumers (the agent
    /// chat allowlist). Unlike the synchronous [`UpstreamPool::tool_facts`]
    /// fallback — which cannot see live annotations and so stays conservatively
    /// side-effecting for annotation-native tools — this resolves the same way
    /// invocation does: the operator manifest governs in manifest mode, the
    /// reviewed claims in annotation mode. A tool that will not resolve is
    /// reported as side-effecting so the consumer routes it through approval;
    /// invocation refuses it regardless.
    pub async fn resolved_side_effects(&self, tenant: &str, server: &str, tool_name: &str) -> bool {
        self.resolved_contract_identity(tenant, server, tool_name)
            .await
            .is_none_or(|contract| contract.side_effects)
    }

    /// Resolver-derived contract identity for the agent-chat allowlist, so a
    /// later call can be PINNED to the exact contract whose `side_effects` drove
    /// the operator-approval decision. Returns `None` when the tool will not
    /// resolve (quarantined); the consumer then treats it as side-effecting and
    /// invocation refuses it regardless. Pinning this identity into the
    /// `InvocationRequest` makes the pipeline refuse (at the resolve stage,
    /// atomically before authorize/approval/dispatch) if a reload changes the
    /// contract — e.g. read-only to side-effecting — between the listing-time
    /// approval decision and execution, rather than trusting the cached
    /// listing-time fact.
    pub async fn resolved_contract_identity(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
    ) -> Option<InvocationContractIdentity> {
        match self
            .resolve_invocation_tool(tenant, server, tool_name)
            .await
        {
            ResolvedInvocationTool::Ready(snapshot) => Some(snapshot.contract_identity()),
            ResolvedInvocationTool::Quarantined { .. }
            | ResolvedInvocationTool::Unavailable { .. } => None,
        }
    }
}

/// Maximum number of `tools/list` pages accepted from one initialized MCP
/// session. This matches the repository's conformance-client traversal bound
/// and prevents a distinct-cursor stream from growing requests and memory
/// without limit.
const MAX_TOOLS_LIST_PAGES: usize = 50;

/// One session's complete paged `tools/list`, with the freshness hint the
/// upstream attached to it.
pub struct ListedCatalog {
    /// Every tool across all pages, in upstream page order.
    pub tools: Vec<Tool>,
    /// The strictest (minimum) SEP-2549 `ttlMs` hint present on any page,
    /// or `None` when no page carried one — absent means absent, never a
    /// default: a legacy upstream that says nothing must not look like one
    /// that promised freshness. Pages may disagree; the listing is only as
    /// fresh as its stalest page. `cacheScope` is deliberately not
    /// captured: the gateway re-serves every list under its own
    /// `private` scope, so an upstream's scope can never widen reuse.
    pub ttl_hint_ms: Option<u64>,
    /// When the paged read *began* — taken before the first page request,
    /// so it is no later than any page's production time. Anchoring the
    /// freshness countdown here means time spent fetching later pages can
    /// never extend an earlier page's deadline.
    pub listed_at: std::time::Instant,
}

/// Page through an MCP session's complete `tools/list`, bounded to
/// [`MAX_TOOLS_LIST_PAGES`] pages with cursor-loop detection. Shared by the
/// boot/reconnect dial, the per-call/reuse executing-session contract check,
/// AND the `classify` scaffold CLI — one reader, so operator tooling can
/// never see a different catalog than the serving path (a scaffold missing
/// later pages would quarantine every later-page tool at annotation-mode
/// cutover).
pub async fn list_all_tools(
    client: &RunningService<RoleClient, ClientInfo>,
) -> Result<ListedCatalog, String> {
    let listed_at = std::time::Instant::now();
    let mut live_tools = Vec::new();
    let mut ttl_hint_ms: Option<u64> = None;
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();
    let mut pages = 0usize;
    loop {
        if pages == MAX_TOOLS_LIST_PAGES {
            return Err(format!(
                "upstream exceeded the {MAX_TOOLS_LIST_PAGES}-page tools/list limit"
            ));
        }
        let listed = client
            .list_tools(Some(
                PaginatedRequestParams::default().with_cursor(cursor.clone()),
            ))
            .await
            .map_err(|e| e.to_string())?;
        pages += 1;
        ttl_hint_ms = match (ttl_hint_ms, listed.ttl_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        live_tools.extend(listed.tools);
        match listed.next_cursor {
            Some(next) => {
                if !seen_cursors.insert(next.clone()) {
                    return Err(format!("upstream repeated tools/list cursor `{next}`"));
                }
                cursor = Some(next);
            }
            None => break,
        }
    }
    Ok(ListedCatalog {
        tools: live_tools,
        ttl_hint_ms,
        listed_at,
    })
}

/// Build [`SnapshotInputs`] from one manifest snapshot (or none, for an
/// unknown server), deriving mode, approved hash, and facts together.
pub(super) fn snapshot_inputs_for(
    manifest: Option<&UpstreamManifest>,
    server: &str,
    tool_name: &str,
    published: schema_admission::PublishedToolContract,
) -> SnapshotInputs {
    let annotation_mode = manifest.is_some_and(|m| {
        matches!(
            m.classification_mode,
            crate::ClassificationMode::McpAnnotations
        )
    });
    let approved_behavior_hash = manifest.and_then(|m| approved_hash_for(m, tool_name));
    let approval_mode = manifest.map_or(crate::ApprovalMode::PerCall, |m| m.approval_mode);
    let manifest_version_hash = manifest.and_then(|m| {
        if !matches!(m.classification_mode, crate::ClassificationMode::Manifest) {
            return None;
        }
        m.tools
            .iter()
            .find(|tool| tool.name == tool_name)
            .map(|tool| {
                // The refinement is part of the version identity, so the hash
                // computed here has to see it too — otherwise this fallback
                // and the importer would disagree about which version a
                // manifest describes.
                let operations: Vec<waygate_catalog::ClassifiedOperation<'_>> = tool
                    .operations
                    .iter()
                    .map(|operation| waygate_catalog::ClassifiedOperation {
                        value: &operation.value,
                        risk: operation.risk.as_str(),
                        side_effects: operation.side_effects,
                        pii: operation.pii,
                    })
                    .collect();
                waygate_catalog::manifest_classification_hash(
                    &tool.name,
                    tool.risk.as_str(),
                    tool.side_effects,
                    tool.pii,
                    tool.discriminator.as_deref(),
                    &operations,
                )
            })
    });
    // Read in every classification mode. Whether a tool dispatches by argument
    // is a property of the tool, not of which authority classifies it.
    let manifest_tool = manifest.and_then(|m| m.tools.iter().find(|tool| tool.name == tool_name));
    let manifest_discriminator = manifest_tool.and_then(|tool| tool.discriminator.clone());
    let manifest_operations = manifest_tool
        .map(|tool| {
            tool.operations
                .iter()
                .map(|operation| waygate_catalog::OperationClassification {
                    value: operation.value.clone(),
                    risk: operation.risk.as_str().to_owned(),
                    side_effects: operation.side_effects,
                    pii: operation.pii,
                })
                .collect()
        })
        .unwrap_or_default();
    SnapshotInputs {
        manifest_facts: manifest_tool_facts(manifest, server, tool_name),
        annotation_mode,
        approval_mode,
        approved_behavior_hash,
        manifest_version_hash,
        manifest_discriminator,
        manifest_operations,
        published,
    }
}

/// Inputs to [`UpstreamPool::resolve_snapshot_from`] that all derive from ONE
/// manifest snapshot, so classification mode, the approved hash, and the
/// governance facts cannot mix two generations inside a single resolution.
pub(super) struct SnapshotInputs {
    pub(super) manifest_facts: ToolFacts,
    pub(super) annotation_mode: bool,
    pub(super) approval_mode: crate::ApprovalMode,
    pub(super) approved_behavior_hash: Option<String>,
    pub(super) manifest_version_hash: Option<String>,
    /// The manifest's own dispatch declaration, carried so the fallback arm
    /// describes the same reviewed operation set the catalog arm does.
    ///
    /// Without it a manifest-declared lane resolves through fallback looking
    /// like a tool classified by name alone, and every operation it dispatches
    /// — reviewed or not — inherits the tool-level entry. Callers that admit a
    /// tool on that entry alone would then be reasoning about a set the
    /// manifest never described.
    pub(super) manifest_discriminator: Option<String>,
    pub(super) manifest_operations: Vec<waygate_catalog::OperationClassification>,
    pub(super) published: schema_admission::PublishedToolContract,
}

impl UpstreamPool {
    /// Resolve the governed snapshot for one tool from explicit inputs.
    ///
    /// Shared by [`UpstreamCatalog::resolve_invocation_tool`] (the Stage-1
    /// admission read) and the dispatch-time re-check in
    /// [`Self::admitted_contract_is_current`], so both produce identities
    /// through the identical resolution rules and an equality comparison
    /// between the two results is meaningful.
    ///
    /// `approved_behavior_hash` is the manifest's reviewed hash for the tool
    /// (annotation mode only; `None` in manifest mode). A catalog `Live` row
    /// whose version identity differs is a different contract GENERATION —
    /// the reload paths update the pool and the catalog non-atomically, so
    /// blending one authority's facts with the other's contract would let a
    /// tool execute under stale or premature risk. Mixed generations fail
    /// closed until both authorities activate the same reviewed contract.
    pub(super) async fn resolve_snapshot_from(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
        inputs: SnapshotInputs,
    ) -> ResolvedInvocationTool {
        let SnapshotInputs {
            manifest_facts,
            annotation_mode,
            approval_mode,
            approved_behavior_hash,
            manifest_version_hash,
            manifest_discriminator,
            manifest_operations,
            mut published,
        } = inputs;
        // A reload publishes manifest fields and reconciles the governed
        // catalog in separate commits. The reload generation is armed before
        // the manifest becomes observable and settled only after the matching
        // full-set import succeeds, so only tools crossing that boundary fail
        // closed. Once settled, the catalog remains authoritative and may
        // intentionally override the manifest classification.
        let catalog_transition = self.catalog_transition_state(server, tool_name);
        if catalog_transition.is_some_and(|transition| transition.pending) {
            tracing::warn!(
                %tenant, %server, tool = %tool_name,
                "manifest authorization inputs are awaiting catalog convergence; quarantined",
            );
            return ResolvedInvocationTool::Quarantined {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            };
        }
        // Annotation mode requires the COMPLETE published contract. An
        // admitted live descriptor always publishes at least its input
        // schema, so an empty published contract means the entry's manifest
        // and its published inventory have diverged — e.g. a classification
        // reload committed a new manifest but its index publication failed
        // and the stale inventory was retained. A snapshot built from
        // nothing would dispatch with no schemas or metadata bound; fail
        // closed until publication converges with the manifest.
        // Bind the separately read published view to THIS resolution's
        // manifest generation: the published descriptor's own behavior hash
        // must equal the generation's approved hash. Whatever reload
        // interleaving produced the pair, a mixed generation refuses here
        // rather than flowing into validation, authorization, or Code Mode
        // discovery as a snapshot no single generation ever admitted.
        if annotation_mode && published.behavior_hash != approved_behavior_hash {
            tracing::warn!(
                %tenant, %server, tool = %tool_name,
                published = ?published.behavior_hash,
                approved = ?approved_behavior_hash,
                "published contract is not the approved behavior generation; \
                 refusing until the published inventory converges",
            );
            return ResolvedInvocationTool::Quarantined {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            };
        }
        if annotation_mode && published.input_schema.is_none() {
            tracing::warn!(
                %tenant, %server, tool = %tool_name,
                "annotation mode has no published contract for an admitted tool; \
                 refusing until the published inventory converges with the manifest",
            );
            return ResolvedInvocationTool::Quarantined {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            };
        }
        // Annotation-mode policy facts now DERIVE from the reviewed claims
        // instead of the bridge's conservative always-side-effecting
        // posture: side-effect behavior from the standard hints, sensitivity
        // from the input/return classifications, and the approval requirement
        // from `requiresReview`, subject to the manifest's explicit approval
        // mode. Claims that cannot produce facts fail closed: the
        // descriptor passed hash admission, so a derivation failure means the
        // reviewed metadata itself cannot be trusted to govern the call.
        let (manifest_facts, anticipated_sensitive_output) = if annotation_mode {
            match claims_facts(approval_mode, manifest_facts, &published) {
                Ok(derived) => derived,
                Err(error) => {
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name,
                        error_class = %error,
                        "admitted annotation metadata could not produce policy facts; quarantined",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
            }
        } else {
            (manifest_facts, false)
        };
        // Fallback snapshot shape is mode-dependent. Annotation mode carries
        // the complete published contract (schemas plus security metadata) —
        // that contract IS the reviewed behavior. Manifest mode keeps the
        // legacy fallback shape: input schema only, no output schema and no
        // metadata, because Stages 6/12 enforce every carried output schema
        // and legacy deployments never had that enforcement on the fallback
        // path — attaching it would newly reject calls whose upstream
        // advertises an invalid output schema or returns nonconforming
        // structured content.
        //
        // The manifest's dispatch declaration rides along on both shapes. It
        // is classification, not schema, so the output-schema reasoning above
        // does not apply to it — and a fallback snapshot that dropped it would
        // present a lane as a tool classified by name alone, which is the
        // permissive direction for any caller that reasons about the reviewed
        // set. It passes the same ceiling filter as the catalog arm, so an
        // entry more severe than its tool is dropped identically.
        let fallback = |published: &mut schema_admission::PublishedToolContract,
                        facts: ToolFacts,
                        approval_known: bool| {
            let definition = published.definition.take();
            let operations =
                operation_classifications(&facts, annotation_mode, manifest_operations.clone());
            let snapshot = if annotation_mode {
                InvocationToolSnapshot::manifest_fallback_with_annotation_claims(
                    facts,
                    approval_known,
                    approved_behavior_hash.clone(),
                    anticipated_sensitive_output,
                    published.input_schema.take(),
                    published.output_schema.take(),
                    published.tool_annotations.take(),
                    published.action_metadata.take(),
                )
            } else {
                InvocationToolSnapshot::manifest_fallback_with_input_schema(
                    facts,
                    approval_known,
                    published.input_schema.take(),
                )
            };
            snapshot
                .with_operation_classifications(manifest_discriminator.clone(), operations)
                .with_published_definition(definition)
        };
        let Some(catalog) = self.catalog.as_ref() else {
            return ResolvedInvocationTool::Ready(fallback(&mut published, manifest_facts, true));
        };
        let fq = format!("{server}.{tool_name}");
        let resolved = catalog.resolve_tool(tenant, &fq).await;
        let catalog_transition_after = self.catalog_transition_state(server, tool_name);
        if catalog_transition_after != catalog_transition
            || catalog_transition_after.is_some_and(|transition| transition.pending)
        {
            tracing::warn!(
                %tenant, %server, tool = %tool_name,
                "manifest/catalog generation changed during resolution; quarantined",
            );
            return ResolvedInvocationTool::Quarantined {
                server: server.to_owned(),
                tool: tool_name.to_owned(),
            };
        }
        match resolved {
            Ok(waygate_catalog::ResolvedTool::Live(def)) => {
                let def = *def;
                // The row's classification mode is part of its generation: a
                // row imported from a manifest in the OTHER mode must not
                // lend its facts to this tool. Annotation-imported rows in
                // particular carry forced-false legacy `side_effects`/`pii`
                // (annotation manifests forbid the legacy flags), so
                // overlaying one onto a legacy-mode tool would weaken its
                // facts; the reverse split hides a legacy row's flags from
                // an annotation tool. Refuse either split.
                let catalog_annotation_mode = def.classification_mode == "mcp_annotations";
                if catalog_annotation_mode != annotation_mode {
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name,
                        catalog_mode = %def.classification_mode,
                        live_annotation_mode = annotation_mode,
                        "catalog row and live manifest disagree on classification mode;                          refusing until both authorities activate the same generation",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                // Annotation mode: the catalog row's `schema_hash` IS the
                // reviewed behavior hash recorded at import, and the catalog
                // row's risk mirrors the manifest risk the reconcile
                // imported. BOTH must match the current manifest before the
                // row's facts overlay the live contract: the hash alone
                // would wave through a risk-only manifest change (the hash
                // is unchanged), letting calls authorize under the prior —
                // possibly lower — risk while the reconcile is pending or
                // failed. Refuse mixed generations (see the method docs).
                if annotation_mode
                    && (approved_behavior_hash.as_deref() != Some(&def.schema_hash)
                        || catalog_risk_to_tier(&def.risk) != manifest_facts.risk)
                {
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name,
                        catalog_version = %def.schema_hash,
                        approved = ?approved_behavior_hash,
                        catalog_risk = %def.risk,
                        manifest_risk = ?manifest_facts.risk,
                        "catalog identity or risk does not match the manifest-approved \
                         generation; refusing until both authorities activate the same \
                         contract generation",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                // Legacy manifest rows carry the hash of the source manifest
                // tuple that produced the catalog version. Compare that
                // provenance across the shared catalog boundary so a replica
                // still serving an older manifest cannot borrow facts from a
                // newer generation reconciled by a peer. This deliberately
                // does NOT compare catalog facts with manifest facts: the
                // catalog may retain intentional operator overrides while its
                // source-generation hash remains bound to the live manifest.
                if !annotation_mode
                    && manifest_version_hash
                        .as_deref()
                        .is_some_and(|hash| hash != def.schema_hash)
                {
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name,
                        catalog_version = %def.schema_hash,
                        manifest_version = ?manifest_version_hash,
                        "catalog row was produced from a different manifest generation; \
                         refusing until this replica and the shared catalog converge",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                let definition = published.definition.take();
                let input_schema = if annotation_mode {
                    published.input_schema.take()
                } else {
                    schema_admission::admit_input_schema(
                        def.input_schema,
                        published.input_schema.take(),
                    )
                };
                let output_schema = if annotation_mode {
                    published.output_schema.take()
                } else {
                    def.output_schema
                };
                let tool_annotations = if annotation_mode {
                    published.tool_annotations.take()
                } else {
                    def.tool_annotations
                };
                let action_metadata = if annotation_mode {
                    published.action_metadata.take()
                } else {
                    def.action_metadata
                };
                let facts = {
                    let mut facts = manifest_facts;
                    facts.risk = catalog_risk_to_tier(&def.risk);
                    if annotation_mode {
                        if approval_mode.uses_per_call_requirements() {
                            // Claims may already require approval; the catalog
                            // can only add the requirement, never remove it.
                            facts.requires_approval |= def.requires_approval;
                        } else {
                            facts.requires_approval = false;
                        }
                    } else {
                        // The catalog remains authoritative for legacy
                        // manifest classification facts in both approval
                        // modes. Policy-only suppresses only the ordinary
                        // approval source; it must not suppress Cedar inputs.
                        facts.requires_approval =
                            approval_mode.uses_per_call_requirements() && def.requires_approval;
                        facts.side_effects = def.side_effects;
                        facts.pii = def.pii;
                    }
                    facts.requires_approval_known = true;
                    facts
                };
                let operations = operation_classifications(&facts, annotation_mode, def.operations);
                let snapshot = if annotation_mode {
                    InvocationToolSnapshot::catalog_with_annotation_claims(
                        facts,
                        def.tool_id,
                        def.schema_hash,
                        anticipated_sensitive_output,
                        input_schema,
                        output_schema,
                        tool_annotations,
                        action_metadata,
                    )
                } else {
                    InvocationToolSnapshot::catalog_with_security_metadata(
                        facts,
                        def.tool_id,
                        def.schema_hash,
                        input_schema,
                        output_schema,
                        tool_annotations,
                        action_metadata,
                    )
                };
                ResolvedInvocationTool::Ready(
                    snapshot
                        .with_operation_classifications(def.discriminator, operations)
                        .with_published_definition(definition),
                )
            }
            Ok(waygate_catalog::ResolvedTool::Quarantined { .. }) => {
                tracing::info!(
                    %tenant, %server, tool = %tool_name,
                    "catalog server is quarantined/retired; refusing dispatch \
                     (no manifest fallback)",
                );
                ResolvedInvocationTool::Quarantined {
                    server: server.to_owned(),
                    tool: tool_name.to_owned(),
                }
            }
            Ok(waygate_catalog::ResolvedTool::PendingApproval { .. }) => {
                if self.catalog_strict_pending_approval {
                    // Strict mode is the right end-state once the
                    // catalog is reliably populated — an un-approved
                    // schema means "do not dispatch."
                    tracing::info!(
                        %tenant, %server, tool = %tool_name,
                        "catalog returned PendingApproval and strict mode is on; refusing dispatch",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                tracing::warn!(
                    %tenant, %server, tool = %tool_name,
                    "catalog has tool but no approved version (PendingApproval); \
                     falling back to manifest classification during transition",
                );
                ResolvedInvocationTool::Ready(fallback(&mut published, manifest_facts, true))
            }
            Ok(waygate_catalog::ResolvedTool::NotFound) => {
                if self.catalog_authoritative {
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name,
                        "tool is absent from the authoritative governed catalog; refusing dispatch",
                    );
                    return ResolvedInvocationTool::Quarantined {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                tracing::warn!(
                    %tenant, %server, tool = %tool_name,
                    "tool not in governed catalog; falling back to manifest \
                     classification (run --import-manifests to populate the catalog)",
                );
                ResolvedInvocationTool::Ready(fallback(&mut published, manifest_facts, true))
            }
            Err(e) => {
                if self.catalog_authoritative {
                    self.catalog_read_error_generation
                        .fetch_add(1, Ordering::AcqRel);
                    tracing::warn!(
                        %tenant, %server, tool = %tool_name, error = %e,
                        "authoritative governed catalog lookup failed; refusing dispatch",
                    );
                    return ResolvedInvocationTool::Unavailable {
                        server: server.to_owned(),
                        tool: tool_name.to_owned(),
                    };
                }
                tracing::warn!(
                    %tenant, %server, tool = %tool_name, error = %e,
                    "catalog resolve_tool failed; falling back to manifest classification \
                     (HITL `requires_approval_known=false` — `check_approval` will \
                     refuse this non-authoritative snapshot)",
                );
                // Explicitly mark the HITL signal as UNTRUSTED so
                // `check_approval`
                // doesn't silently dispatch a tool that the catalog
                // declared requires_approval=true. Construct the
                // ToolFacts inline rather than via `tool_facts`
                // (which sets known=true for the no-catalog-wired
                // path); the catalog WAS wired but currently
                // unavailable, so we can't trust the manifest's
                // requires_approval=false here.
                ResolvedInvocationTool::Ready(fallback(&mut published, manifest_facts, false))
            }
        }
    }
}

impl UpstreamPool {
    /// Re-resolve the tool's contract identity from the exact state the RPC
    /// will execute under — the held connection's published contract, the
    /// supplied manifest snapshot, and a fresh governed-catalog read — and
    /// compare it against the Stage-1 admitted identity. The caller holds the
    /// selected connection's read lock, so a re-dial cannot swap the
    /// connection between this comparison and the RPC. A `false` result means
    /// the contract the pipeline validated and authorized is no longer the
    /// contract this dispatch would execute; the call must be refused.
    pub(super) async fn admitted_contract_is_current(
        &self,
        tenant: &str,
        server: &str,
        tool_name: &str,
        current_manifest: &UpstreamManifest,
        conn: &Connection,
        admitted: &InvocationContractIdentity,
    ) -> bool {
        let published =
            schema_admission::contract_for_tool(&conn.tools, tool_name).unwrap_or_default();
        match self
            .resolve_snapshot_from(
                tenant,
                server,
                tool_name,
                snapshot_inputs_for(Some(current_manifest), server, tool_name, published),
            )
            .await
        {
            ResolvedInvocationTool::Ready(snapshot) => snapshot.contract_identity() == *admitted,
            ResolvedInvocationTool::Quarantined { .. }
            | ResolvedInvocationTool::Unavailable { .. } => false,
        }
    }
}

/// Annotation-mode policy facts derived from the published (reviewed)
/// claims: side-effect behavior from the standard hints, sensitivity from
/// the input and return classifications, and the approval requirement from
/// `requiresReview`, subject to the manifest's explicit approval mode.
/// Replaces the bridge's conservative
/// always-side-effecting posture now that enforcement derives from claims.
/// Returns the derived facts together with the reviewed OUTPUT-sensitivity
/// bit, which result-release enforcement uses to decide whether a
/// `sensitive`-labelled result was anticipated — distinct from the combined
/// `pii` projection.
fn claims_facts(
    approval_mode: crate::ApprovalMode,
    mut facts: ToolFacts,
    published: &schema_admission::PublishedToolContract,
) -> Result<(ToolFacts, bool), crate::security_metadata::SecurityMetadataError> {
    let (Some(annotations), Some(action_metadata)) = (
        published.tool_annotations.as_ref(),
        published.action_metadata.as_ref(),
    ) else {
        return Err(crate::security_metadata::SecurityMetadataError::MissingAnnotations);
    };
    let claims = crate::security_metadata::behavior_claims(annotations, action_metadata)?;
    facts.side_effects = claims.side_effects;
    facts.pii = claims.protected_data();
    facts.requires_approval = claims.requires_approval(approval_mode);
    Ok((facts, claims.output_sensitive))
}

/// The manifest's reviewed behavior hash for one tool, when annotation mode
/// governs the upstream; `None` in manifest mode, where the separate legacy
/// manifest source-generation hash binds the catalog row instead.
pub(super) fn approved_hash_for(manifest: &UpstreamManifest, tool_name: &str) -> Option<String> {
    if !matches!(
        manifest.classification_mode,
        crate::ClassificationMode::McpAnnotations
    ) {
        return None;
    }
    manifest
        .tools
        .iter()
        .find(|tool| tool.name == tool_name)
        .and_then(|tool| tool.approved_behavior_hash.clone())
}

pub(super) struct SessionToolsReadError {
    detail: String,
    error_class: UpstreamErrorClass,
}

impl SessionToolsReadError {
    pub(super) fn error_class(&self) -> UpstreamErrorClass {
        self.error_class
    }
}

impl std::fmt::Display for SessionToolsReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl UpstreamPool {
    /// The dispatch-path session catalog read: [`list_all_tools`] bounded by
    /// the pool's upstream call timeout. The read happens while a connection
    /// lane is checked out, so an unbounded wedged `tools/list` would hold
    /// the lane forever and eventually exhaust every lane — the same hazard
    /// the RPC timeout exists for.
    pub(super) async fn session_tools_bounded(
        &self,
        client: &RunningService<RoleClient, ClientInfo>,
        timeout: Option<std::time::Duration>,
    ) -> Result<Vec<Tool>, SessionToolsReadError> {
        let listed = match timeout {
            Some(d) => match tokio::time::timeout(d, list_all_tools(client)).await {
                Ok(result) => result.map_err(|detail| SessionToolsReadError {
                    detail,
                    error_class: UpstreamErrorClass::Protocol,
                }),
                Err(_) => Err(SessionToolsReadError {
                    detail: format!("tools/list did not complete within {}s", d.as_secs()),
                    error_class: UpstreamErrorClass::Timeout,
                }),
            },
            None => list_all_tools(client)
                .await
                .map_err(|detail| SessionToolsReadError {
                    detail,
                    error_class: UpstreamErrorClass::Protocol,
                }),
        };
        // The contract re-check only compares tool shapes; the freshness
        // hint is captured at dial/refresh time, not on this read.
        listed.map(|l| l.tools)
    }
}
