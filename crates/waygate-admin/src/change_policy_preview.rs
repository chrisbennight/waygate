//! Policy-aware preview for HITL policy publish, rollback, and inline-fragment
//! upsert requests.
//!
//! The maker-checker control plane already routes a policy-bundle publish (or
//! rollback) through propose → human approval → server-side execute: the
//! policy executors in
//! [`crate::change_executor`] call `publish_bundle_core` /
//! `rollback_bundle_core`. But the approver only sees the captured `params` as
//! raw JSON (`{ "bundle_id": "…" }` / `{ "version": 3 }`) — from which they
//! cannot tell WHAT the publish does. This module computes a policy-specific
//! preview the approver reviews *before* approving, so they approve the EFFECT,
//! not opaque JSON:
//!
//! - **compile** — does the proposed Cedar parse? A non-parsing draft would
//!   fail the publish gate at execute anyway; surfacing it here means the
//!   approver never approves a publish that can't land.
//! - **tests** — do the draft's attached policy tests pass (the publish
//!   gate)? `publish` only; a rollback re-publishes already-vetted content.
//! - **impact** — the blast radius: replaying the tenant's recent recorded
//!   decisions against the proposed content, how many flip (allow→deny, …).
//!
//! READ-ONLY and tenant-scoped to the CHANGE REQUEST's tenant (the executor
//! resolves the same tenant from the approver's principal, so the preview and
//! the eventual execute judge the same content in the same tenant). Every load
//! is best-effort: a missing draft, an unwired store, or a malformed `params`
//! blob degrades to a `note` on legacy bundle actions — the review queue must
//! always render. Inline-fragment authoring is stricter: any missing exact
//! preview dependency also sets `blocked`, and both approval queues suppress
//! approval. The preview NEVER mutates: no publish, no audit write, no disk
//! write.

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use waygate_authz::CedarEngine;
use waygate_core::TenantId;
use waygate_policy::PolicyStatus;

use crate::impact::ImpactReport;
use crate::policy_bundles::replay_recent_decisions;
use crate::policy_tests::{run_policy_tests, PolicyTestCase, PolicyTestReport};
use crate::state::AdminState;

/// Mirror of `change_executor::PolicyPublishParams`. The preview MUST parse the
/// captured params EXACTLY as the executor will (`serde_json::from_value`), so it
/// never previews a normal effect for params the executor would reject as bad.
#[derive(Deserialize)]
struct PublishParams {
    bundle_id: Uuid,
}

/// Mirror of `change_executor::PolicyRollbackParams`. `version: i32` matters:
/// `serde` rejects an out-of-`i32`-range integer (so does the executor), where a
/// hand-rolled `as i64 as i32` would silently truncate and preview the WRONG
/// version for a change the executor will fail as bad params.
#[derive(Deserialize)]
struct RollbackParams {
    version: i32,
}

/// Which policy change a [`PolicyChangePreview`] describes. Opaque identifiers
/// remain in the captured params shown below the preview; the kind carries only
/// what the human label needs.
pub(crate) enum PolicyChangeKind {
    /// `policy.publish` of a draft bundle, published as `version`.
    Publish { version: i32 },
    /// `policy.rollback` to a previously-published version (a roll-forward of
    /// that version's content).
    Rollback { version: i32 },
    /// `policy.upsert_fragment` — one `@id`-addressed statement merged into the
    /// live full set and published after mandatory impact replay.
    UpsertFragment { policy_id: Option<String> },
}

/// Whether the proposed Cedar content parses. Three states so the template can
/// distinguish "compiles", "won't compile" (a publish that can't land), and
/// "couldn't be evaluated" (the content couldn't be loaded — see `note`).
pub(crate) enum CompileStatus {
    Ok,
    Error(String),
    Unknown,
}

/// A policy-aware preview of a pending publish, rollback, or fragment-upsert
/// change request, for the approver's review.
pub(crate) struct PolicyChangePreview {
    pub kind: PolicyChangeKind,
    /// Whether the proposed Cedar content parses.
    pub compile: CompileStatus,
    /// The attached-test report — `publish` only, and only when the draft
    /// carries (parseable, non-empty) tests. `None` for a rollback, a draft
    /// with no tests, or a malformed test blob (the executor's gate still
    /// catches a malformed blob at execute).
    pub tests: Option<PolicyTestReport>,
    /// The blast-radius replay against the proposed content. `None` when the
    /// content doesn't parse (no engine to replay — the compile status already
    /// tells the approver it can't land) or the audit store is unwired (see
    /// `note`).
    pub impact: Option<ImpactReport>,
    /// A degradation note (missing draft, unwired store, malformed params,
    /// audit store unavailable). When `Some`, one or more pieces above couldn't
    /// be computed; the queue still renders and the approver sees why.
    pub note: Option<String>,
    /// Set when the executor would REFUSE this change at execute even though the
    /// content is otherwise previewable — a precondition the executor enforces
    /// that the preview MUST mirror, so an approver never approves an effect that
    /// can't actually happen: a `policy.publish` target that is no longer a
    /// `Draft` (the executor requires a draft), a `policy.rollback` target that
    /// IS a `Draft` (the executor requires a previously-published version), or a
    /// draft whose attached tests are malformed (the publish gate refuses them).
    /// When `Some`, the review renders a prominent "will not execute" banner.
    pub blocked: Option<String>,
}

impl PolicyChangePreview {
    /// Return the fail-closed reason that prevents an approver from consuming
    /// a policy-fragment request. `blocked` carries exact construction and
    /// precondition failures; the structured checks keep the approval contract
    /// explicit even if preview construction changes later.
    pub(crate) fn mandatory_approval_blocker(&self) -> Option<String> {
        if let Some(reason) = &self.blocked {
            return Some(reason.clone());
        }
        if !matches!(self.compile, CompileStatus::Ok) {
            return Some("the mandatory policy effect preview did not compile".to_owned());
        }
        if self.tests.as_ref().is_some_and(|report| !report.all_passed) {
            return Some(
                "the mandatory policy effect preview has failing attached tests".to_owned(),
            );
        }
        match &self.impact {
            Some(report) if report.error.is_none() => None,
            Some(_) => Some("the mandatory policy impact preview failed".to_owned()),
            None => Some("the mandatory policy impact preview is unavailable".to_owned()),
        }
    }
}

/// Build the policy preview for a change request, or `None` when `action_type`
/// isn't a previewable policy change (the caller renders generic params JSON).
///
/// `tenant_id` is the change request's own tenant (the SECURITY boundary — the
/// preview reads only that tenant's draft + decisions, never a viewer's).
pub(crate) async fn policy_change_preview(
    state: &AdminState,
    tenant_id: &str,
    action_type: &str,
    params: &Value,
    target_etag: Option<&str>,
) -> Option<PolicyChangePreview> {
    match action_type {
        "policy.publish" => Some(publish_preview(state, tenant_id, params).await),
        "policy.rollback" => Some(rollback_preview(state, tenant_id, params).await),
        "policy.upsert_fragment" => {
            Some(upsert_fragment_preview(state, tenant_id, params, target_etag).await)
        }
        // Not a policy change — the approver sees the generic params JSON.
        _ => None,
    }
}

#[derive(Deserialize)]
struct UpsertFragmentParams {
    statement: String,
}

/// Preview the exact reconstructed full set for a proposed fragment upsert.
/// Unlike legacy bundle previews, every missing dependency is a blocking state:
/// this action cannot execute without a successful blast-radius replay.
async fn upsert_fragment_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
    target_etag: Option<&str>,
) -> PolicyChangePreview {
    let statement = match serde_json::from_value::<UpsertFragmentParams>(params.clone()) {
        Ok(p) => p.statement,
        Err(e) => {
            let mut preview = degraded(
                PolicyChangeKind::UpsertFragment { policy_id: None },
                format!("params do not match the policy-fragment action's schema: {e}"),
            );
            preview.blocked = Some(
                "the proposed fragment parameters are invalid, so the mandatory preview cannot run"
                    .to_owned(),
            );
            return preview;
        }
    };
    if tenant_id != TenantId::DEFAULT {
        let mut preview = degraded(
            PolicyChangeKind::UpsertFragment { policy_id: None },
            "policy fragment upsert currently supports only the default tenant",
        );
        preview.blocked = preview.note.clone();
        return preview;
    }
    let merged = match crate::policy_bundles::merge_policy_fragment_into_live_set(state, &statement)
    {
        Ok(merged) => merged,
        Err(_) => {
            let mut preview = degraded(
                PolicyChangeKind::UpsertFragment { policy_id: None },
                "could not construct the merged live policy set; the fragment or live set is not safely addressable",
            );
            preview.blocked = Some(
                "the exact merged policy effect cannot be previewed, so approval is unavailable"
                    .to_owned(),
            );
            return preview;
        }
    };
    let kind = PolicyChangeKind::UpsertFragment {
        policy_id: Some(merged.policy_id.clone()),
    };
    let mut precondition = match target_etag {
        Some(captured) if captured == merged.base_hash => None,
        Some(_) => Some(
            "the live policy set changed after this fragment was proposed — re-propose against the current set"
                .to_owned(),
        ),
        None => Some(
            "the proposal is missing its captured live-policy-set witness".to_owned(),
        ),
    };

    let tests = match state.policy.policy_store.get() {
        Some(store) => match store.active_bundle(tenant_id).await {
            Ok(active)
                if waygate_policy::policy_sources_equivalent(
                    &active.content,
                    &merged.base_source,
                ) =>
            {
                active.tests
            }
            Ok(_) => {
                precondition.get_or_insert_with(|| {
                    "the policy ledger has not reconciled to the live on-disk set".to_owned()
                });
                None
            }
            Err(_) => {
                precondition.get_or_insert_with(|| {
                    "the active policy bundle could not be loaded for exact preview".to_owned()
                });
                None
            }
        },
        None => {
            precondition.get_or_insert_with(|| "policy store not configured".to_owned());
            None
        }
    };
    let tenant = TenantId::default_id();
    build_preview(
        state,
        &tenant,
        kind,
        &merged.content,
        PreviewGate {
            tests_json: tests.as_ref(),
            run_tests: true,
            precondition,
            mandatory_impact: true,
        },
    )
    .await
}

/// A degraded preview: content couldn't be loaded, so compile is `Unknown` and
/// every computed piece is absent — `note` says why.
fn degraded(kind: PolicyChangeKind, note: impl Into<String>) -> PolicyChangePreview {
    PolicyChangePreview {
        kind,
        compile: CompileStatus::Unknown,
        tests: None,
        impact: None,
        note: Some(note.into()),
        blocked: None,
    }
}

/// Preview for `policy.publish` — params mirror `PolicyPublishParams`
/// (`{ "bundle_id": Uuid }`). Loads the draft, then computes compile + tests +
/// impact against its content.
async fn publish_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
) -> PolicyChangePreview {
    // Parse EXACTLY as the executor does — a params blob the executor would
    // reject as bad must degrade here, not preview a normal effect.
    let bundle_id = match serde_json::from_value::<PublishParams>(params.clone()) {
        Ok(p) => p.bundle_id,
        Err(e) => {
            return degraded(
                PolicyChangeKind::Publish { version: 0 },
                format!("params do not match the publish action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let kind_unknown = || PolicyChangeKind::Publish { version: 0 };

    let Some(store) = state.policy.policy_store.get() else {
        return degraded(
            kind_unknown(),
            "policy store not configured — cannot load the draft to preview",
        );
    };
    let bundle = match store.get(tenant_id, bundle_id).await {
        Ok(b) => b,
        Err(e) => {
            return degraded(
                kind_unknown(),
                format!("could not load the draft bundle: {e}"),
            );
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(
            kind_unknown(),
            "change request carries an invalid tenant id",
        );
    };

    // Precondition parity: `publish_bundle_core` refuses a non-`Draft` target
    // (`Conflict` ⇒ the change fails at execute). Mirror it so the approver
    // doesn't approve a "will publish" effect that can't happen.
    let precondition = (bundle.status != PolicyStatus::Draft).then(|| {
        "the target bundle is no longer a draft — the publish executor requires a \
         draft, so approval would fail at execute; re-propose against the current draft."
            .to_owned()
    });

    let kind = PolicyChangeKind::Publish {
        version: bundle.version,
    };
    build_preview(
        state,
        &tenant,
        kind,
        &bundle.content,
        PreviewGate {
            tests_json: bundle.tests.as_ref(),
            run_tests: true,
            precondition,
            mandatory_impact: false,
        },
    )
    .await
}

/// Preview for `policy.rollback` — params mirror `PolicyRollbackParams`
/// (`{ "version": i32 }`). Resolves the target version's content the same way
/// `rollback_bundle_core` does (no get-by-version exists: list, then fetch the
/// unique match), then computes compile + impact. No tests: a rollback
/// re-publishes already-vetted content.
async fn rollback_preview(
    state: &AdminState,
    tenant_id: &str,
    params: &Value,
) -> PolicyChangePreview {
    // Parse EXACTLY as the executor does. `version: i32` via serde rejects an
    // out-of-`i32`-range integer (the executor too), where `as i64 as i32` would
    // silently truncate and preview the wrong version.
    let version = match serde_json::from_value::<RollbackParams>(params.clone()) {
        Ok(p) => p.version,
        Err(e) => {
            return degraded(
                PolicyChangeKind::Rollback { version: 0 },
                format!("params do not match the rollback action's schema (the executor would reject them as bad params): {e}"),
            );
        }
    };
    let kind = || PolicyChangeKind::Rollback { version };

    let Some(store) = state.policy.policy_store.get() else {
        return degraded(
            kind(),
            "policy store not configured — cannot load the target version to preview",
        );
    };
    let summaries = match store.list_bundles(tenant_id).await {
        Ok(s) => s,
        Err(e) => return degraded(kind(), format!("could not list policy bundles: {e}")),
    };
    let Some(target) = summaries.into_iter().find(|b| b.version == version) else {
        return degraded(
            kind(),
            format!("no policy bundle at version {version} in this tenant"),
        );
    };
    // Precondition parity: `rollback_bundle_core` refuses a `Draft` target (only
    // previously-published content is a valid roll-forward).
    let precondition = (target.status == PolicyStatus::Draft).then(|| {
        format!(
            "version {version} is a draft, not a previously-published version — \
             rollback requires a published version, so approval would fail at execute."
        )
    });
    let content = match store.get(tenant_id, target.id).await {
        Ok(b) => b.content,
        Err(e) => {
            return degraded(kind(), format!("could not load version {version}: {e}"));
        }
    };
    let Ok(tenant) = TenantId::parse(tenant_id) else {
        return degraded(kind(), "change request carries an invalid tenant id");
    };

    build_preview(
        state,
        &tenant,
        kind(),
        &content,
        PreviewGate {
            tests_json: None,
            run_tests: false,
            precondition,
            mandatory_impact: false,
        },
    )
    .await
}

/// Gate settings for an already-loaded policy candidate. Grouped so adding a
/// fail-closed preview condition does not turn `build_preview` into an opaque
/// positional-boolean call.
struct PreviewGate<'a> {
    tests_json: Option<&'a Value>,
    run_tests: bool,
    precondition: Option<String>,
    mandatory_impact: bool,
}

/// Compute compile + (optional) tests + (optional) impact for already-loaded
/// `content`. `gate.run_tests` is true only for publish-like actions; rollback
/// re-publishes previously-vetted content.
async fn build_preview(
    state: &AdminState,
    tenant: &TenantId,
    kind: PolicyChangeKind,
    content: &str,
    gate: PreviewGate<'_>,
) -> PolicyChangePreview {
    // A precondition the executor enforces (non-draft publish target / draft
    // rollback target) is the operative "won't execute" reason; a malformed
    // test blob below only sets it when no precondition already has.
    let mut blocked = gate.precondition;

    // Compile: does the proposed Cedar parse? (Same engine the publish gate and
    // the live SIGHUP reload use.)
    let compile = match CedarEngine::from_source(content) {
        Ok(_) => CompileStatus::Ok,
        Err(e) => CompileStatus::Error(e.to_string()),
    };

    // Tests (publish only): run the draft's attached cases against its content,
    // in the change's own tenant context.
    let tests = if gate.run_tests {
        match gate.tests_json {
            None => None,
            Some(v) => match serde_json::from_value::<Vec<PolicyTestCase>>(v.clone()) {
                Ok(cases) if !cases.is_empty() => Some(run_policy_tests(content, &cases, tenant)),
                // Empty cases ⇒ no gate (matches `evaluate_publish_gate`).
                Ok(_) => None,
                // Parity: `evaluate_publish_gate` REFUSES a malformed test blob
                // ("publish refused"). Surface it as a "won't execute" reason so
                // the approver isn't shown a silent "no tests" for a publish that
                // can't land.
                Err(e) => {
                    if blocked.is_none() {
                        blocked = Some(format!(
                            "the draft's attached policy tests are malformed — the publish \
                             gate will refuse this at execute: {e}"
                        ));
                    }
                    None
                }
            },
        }
    } else {
        None
    };
    if gate.mandatory_impact
        && tests.as_ref().is_some_and(|report| !report.all_passed)
        && blocked.is_none()
    {
        blocked =
            Some("the merged policy's attached tests fail, so publish would be refused".to_owned());
    }

    // Impact: only when the content parses — a broken engine has nothing to
    // replay, and the compile error already tells the approver it can't land.
    let mut note = None;
    let impact = if matches!(compile, CompileStatus::Ok) {
        match replay_recent_decisions(state, tenant, content).await {
            Ok(r) => Some(r),
            Err(e) => {
                note = Some(format!("blast-radius preview unavailable: {}", e.detail()));
                if gate.mandatory_impact && blocked.is_none() {
                    blocked = Some(
                        "the mandatory impact preview is unavailable, so approval is unavailable"
                            .to_owned(),
                    );
                }
                None
            }
        }
    } else {
        if gate.mandatory_impact && blocked.is_none() {
            blocked = Some(
                "the merged policy does not compile, so the mandatory impact preview cannot run"
                    .to_owned(),
            );
        }
        None
    };

    PolicyChangePreview {
        kind,
        compile,
        tests,
        impact,
        note,
        blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use serde_json::json;
    use waygate_upstream::pool::UpstreamPool;

    fn complete_mandatory_preview() -> PolicyChangePreview {
        PolicyChangePreview {
            kind: PolicyChangeKind::UpsertFragment {
                policy_id: Some("example-security".to_owned()),
            },
            compile: CompileStatus::Ok,
            tests: None,
            impact: Some(ImpactReport {
                error: None,
                considered: 0,
                replayed: 0,
                unchanged: 0,
                changed: 0,
                not_replayable: 0,
                deltas: Vec::new(),
                samples: Vec::new(),
            }),
            note: None,
            blocked: None,
        }
    }

    #[test]
    fn mandatory_approval_blocker_rejects_each_incomplete_effect() {
        assert!(complete_mandatory_preview()
            .mandatory_approval_blocker()
            .is_none());

        let mut blocked = complete_mandatory_preview();
        blocked.blocked = Some("captured precondition failed".to_owned());
        assert_eq!(
            blocked.mandatory_approval_blocker().as_deref(),
            Some("captured precondition failed")
        );

        let mut compile_failed = complete_mandatory_preview();
        compile_failed.compile = CompileStatus::Error("bad Cedar".to_owned());
        assert!(compile_failed.mandatory_approval_blocker().is_some());

        let mut tests_failed = complete_mandatory_preview();
        tests_failed.tests = Some(PolicyTestReport {
            total: 1,
            passed: 0,
            failed: 1,
            all_passed: false,
            results: Vec::new(),
        });
        assert!(tests_failed.mandatory_approval_blocker().is_some());

        let mut impact_missing = complete_mandatory_preview();
        impact_missing.impact = None;
        assert!(impact_missing.mandatory_approval_blocker().is_some());

        let mut impact_failed = complete_mandatory_preview();
        impact_failed.impact.as_mut().unwrap().error = Some("replay failed".to_owned());
        assert!(impact_failed.mandatory_approval_blocker().is_some());
    }

    /// An `AdminState` with NO policy or audit store wired. The dispatch + the
    /// degradation paths all decide BEFORE touching a store (action-type match,
    /// params parse, `state.policy.policy_store.is_none()`), so they're exercisable
    /// without standing up the 13-method `PolicyStore` — the store-backed happy
    /// path is covered end-to-end through the `/changes` dashboard in
    /// `tests/policy_bundles_api.rs`.
    async fn no_store_state() -> Arc<AdminState> {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: waygate_mcp::audit::SharedEvidence =
            Arc::new(waygate_mcp::audit::InMemorySink::default());
        Arc::new(AdminState::new(
            pool,
            None,
            None,
            evidence,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        ))
    }

    #[tokio::test]
    async fn non_policy_action_has_no_preview() {
        let state = no_store_state().await;
        // A non-policy change keeps the generic params JSON — no policy preview.
        let p = policy_change_preview(
            &state,
            "default",
            "rate_limit.update",
            &json!({ "id": "abc" }),
            None,
        )
        .await;
        assert!(p.is_none(), "only previewable policy actions get a preview");
    }

    #[tokio::test]
    async fn publish_without_bundle_id_degrades_not_panics() {
        let state = no_store_state().await;
        let p = policy_change_preview(&state, "default", "policy.publish", &json!({}), None)
            .await
            .expect("a policy action always yields Some(preview)");
        // Malformed params → degraded, never a panic; the approver sees why.
        assert!(matches!(p.compile, CompileStatus::Unknown));
        assert!(p.impact.is_none());
        assert!(p.tests.is_none());
        assert!(
            p.note.as_deref().unwrap_or("").contains("bundle_id"),
            "note names the missing field"
        );
    }

    #[tokio::test]
    async fn publish_with_store_unwired_degrades() {
        let state = no_store_state().await;
        let id = uuid::Uuid::now_v7();
        let p = policy_change_preview(
            &state,
            "default",
            "policy.publish",
            &json!({ "bundle_id": id.to_string() }),
            None,
        )
        .await
        .expect("Some");
        assert!(matches!(p.compile, CompileStatus::Unknown));
        assert!(
            p.note.as_deref().unwrap_or("").contains("policy store"),
            "note explains the store is unwired"
        );
    }

    #[tokio::test]
    async fn rollback_without_version_degrades() {
        let state = no_store_state().await;
        let p = policy_change_preview(&state, "default", "policy.rollback", &json!({}), None)
            .await
            .expect("Some");
        assert!(matches!(p.compile, CompileStatus::Unknown));
        assert!(p.note.as_deref().unwrap_or("").contains("version"));
    }

    #[tokio::test]
    async fn rollback_out_of_i32_range_version_degrades_not_truncates() {
        let state = no_store_state().await;
        // 2^40 is a valid JSON integer but out of i32 range. The executor
        // deserializes `version: i32` and rejects it; the preview must mirror
        // that (degrade) rather than truncate to a bogus in-range version.
        let p = policy_change_preview(
            &state,
            "default",
            "policy.rollback",
            &json!({ "version": 1_099_511_627_776i64 }),
            None,
        )
        .await
        .expect("Some");
        assert!(
            matches!(p.compile, CompileStatus::Unknown),
            "out-of-i32-range version must degrade, not preview a truncated version"
        );
        assert!(p.note.is_some());
        assert!(
            p.blocked.is_none(),
            "a bad-params degrade is not a precondition block"
        );
    }

    #[tokio::test]
    async fn fragment_upsert_blocks_when_exact_preview_cannot_be_built() {
        let state = no_store_state().await;
        let p = policy_change_preview(
            &state,
            "default",
            "policy.upsert_fragment",
            &json!({
                "statement": "@id(\"example-security\") permit(principal, action, resource);"
            }),
            Some("captured-live-hash"),
        )
        .await
        .expect("policy fragment action always yields a preview");
        assert!(matches!(p.compile, CompileStatus::Unknown));
        assert!(p.impact.is_none());
        assert!(
            p.blocked
                .as_deref()
                .unwrap_or("")
                .contains("approval is unavailable"),
            "missing exact impact preview must block approval"
        );
    }
}
