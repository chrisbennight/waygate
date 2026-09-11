//! `/api/v1/policy_bundles/*` — admin surface over the durable policy
//! store.
//!
//! For the default tenant, the on-disk `policies/*.cedar` set is the SOURCE OF
//! TRUTH that the gate loads at boot and on reload (`resolve_policies`); the
//! Postgres-backed, versioned policy store is the durable HISTORY / RECOVERY
//! ledger beside it. A default-tenant publish or rollback therefore MIRRORS the
//! chosen bundle back onto disk before recording the ledger transition. For
//! non-default tenants, the latest published ledger bundle is itself the live
//! source and reload swaps the complete tenant-engine registry atomically.
//! These endpoints let an operator inspect and stage policy versions over HTTP
//! instead of hand-editing files:
//!
//! - `GET /api/v1/policy_bundles` — every bundle for the caller's
//!   tenant (summaries, newest version first).
//! - `GET /api/v1/policy_bundles/active` — the bundle currently in
//!   force (the most recently published one), including its Cedar
//!   source.
//! - `POST /api/v1/policy_bundles` — stage a new draft from a Cedar
//!   source body. Drafts are not evaluated by the gate until published.
//! - `POST /api/v1/policy_bundles/{id}/publish` — promote a draft to published;
//!   the default tenant is mirrored to `policies/*.cedar`, while non-default
//!   tenants are activated directly from the ledger on reload.
//! - `POST /api/v1/policy_bundles/{version}/rollback` — re-activate a
//!   previously-published version by re-publishing it as a new bundle
//!   (append-only roll-forward), with the same tenant-specific activation path.
//! - `POST /api/v1/policy_bundles/{id}/run_tests` — run a draft's attached
//!   policy tests against its content WITHOUT publishing (the read-only
//!   preview of the publish gate); returns a structured pass/fail report.
//!
//! The mutating endpoints (create / publish / rollback) are gated by
//! `mcp:admin`; the read-only `run_tests` is gated by `mcp:observe`, matching
//! `policies::simulate` (which covers live-engine simulation). All are scoped
//! to the caller's tenant.
//!
//! The runtime gate selects the caller's tenant engine when that tenant has a
//! published bundle and falls back to the default engine otherwise.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{middleware, Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use waygate_core::TenantId;
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};
use waygate_oidc::Principal;
use waygate_policy::{
    PolicyBundle, PolicyBundleSummary, PolicyError, PolicyStatus, SharedPolicyStore,
};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::impact::{compute_impact, ImpactReport};
use crate::policies::{SimulateRequest, SimulateResponse};
use crate::scope::require_admin;
use crate::state::{AdminState, PolicyCommitError};

pub fn router(state: Arc<AdminState>) -> Router<()> {
    // Most policy-bundle endpoints MUTATE the durable policy set, so they stay
    // `mcp:admin`. `run_tests` is the read-only "would this draft's attached
    // tests pass?" preview — the same tier as the simulator
    // (`POST /api/v1/policies/simulate`, gated `mcp:observe`) — so it sits in its
    // own `require_observe` sub-router (with `mcp:admin` satisfying it too), not
    // behind the admin gate. Tenant-scoped to the caller like the rest.
    let admin = Router::new()
        .route(
            "/api/v1/policy_bundles",
            axum::routing::get(list_bundles).post(create_draft),
        )
        .route(
            "/api/v1/policy_bundles/active",
            axum::routing::get(active_bundle),
        )
        .route(
            "/api/v1/policy_bundles/validate",
            axum::routing::post(validate_bundle),
        )
        .route(
            "/api/v1/policy_bundles/preview_simulate",
            axum::routing::post(preview_simulate),
        )
        .route(
            "/api/v1/policy_bundles/{id}/publish",
            axum::routing::post(publish_bundle),
        )
        .route(
            "/api/v1/policy_bundles/{version}/rollback",
            axum::routing::post(rollback_bundle),
        )
        .layer(middleware::from_fn(require_admin));
    let observe = Router::new()
        .route(
            "/api/v1/policy_bundles/{id}/run_tests",
            axum::routing::post(run_tests),
        )
        // Exact decision replay / impact analysis. Read-only — it loads
        // the draft, fetches the tenant's recent recorded decisions, and replays
        // them against the draft in memory; it never publishes or mutates audit.
        // Same `mcp:observe` tier as `run_tests` / the simulator.
        .route(
            "/api/v1/policy_bundles/{id}/preview_impact",
            axum::routing::post(preview_impact),
        )
        .layer(middleware::from_fn(crate::scope::require_observe));
    admin.merge(observe).with_state(state)
}

/// Bound on the recent recorded decisions the impact replay considers. The
/// blast-radius report covers this many newest decisions for the tenant —
/// enough to be representative without scanning the whole `audit_log`. Matches
/// the cap the grounding calls for.
const IMPACT_REPLAY_LIMIT: i64 = 500;

/// The caller's tenant, or the default tenant for the auth-disabled dev
/// path (no principal).
fn caller_tenant(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned())
}

/// The caller's tenant as a typed [`TenantId`] (the [`caller_tenant`] twin) —
/// for the policy-test runner, which must judge a draft under its OWN tenant
/// (`principal.tenant`), not the simulator-converter's default stamp. Derived
/// from the same principal as `caller_tenant`, so the two never disagree.
fn caller_tenant_id(principal: Option<&Principal>) -> TenantId {
    principal
        .map(|p| p.tenant.clone())
        .unwrap_or_else(TenantId::default_id)
}

/// Chained-best-effort `Denied` AdminMutation audit for a publish the policy-test
/// gate BLOCKED — whether by a failing assertion OR a malformed/tampered
/// stored tests blob — so a gated publish is as auditable as a successful
/// one. Chained best-effort: a dropped audit row must not fail the
/// (already-rejected) request.
async fn record_blocked_publish_audit(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    reason: &str,
) {
    state
        .evidence
        .record_chained_best_effort(
            AuditEvent::new("policy_bundle.publish", AuditOutcome::Denied)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(principal)
                .with_reason(reason.to_owned()),
        )
        .await;
}

/// Best-effort AdminMutation evidence for a newly-staged policy draft. Shared
/// by the REST draft endpoint and approved inline-fragment execution so both
/// authoring paths leave the same audit evidence.
async fn record_created_draft_audit(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    bundle: &PolicyBundle,
) {
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("policy_bundle.create_draft", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(principal)
                .with_reason(format!(
                    "created policy draft version={} hash={}",
                    bundle.version, bundle.content_hash
                )),
        )
        .await;
}

/// The caller's `sub` for publish provenance, or a dev sentinel.
fn caller_actor(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned())
}

fn policy_store(state: &AdminState) -> ApiResult<&SharedPolicyStore> {
    state.policy.policy_store.require()
}

/// Refuse a REST policy MUTATION when editing is disabled for the
/// deployment (`GATEWAY_POLICY_EDITING=off`, or the policies dir isn't
/// writable). Mirrors the dashboard's `gate_policy_editing` middleware so the
/// scriptable surface and the HTML twin agree: with editing off, every write
/// (`create_draft` / `publish` / `rollback` / approved fragment upsert) 403s
/// with the operator-facing reason, while reads (list / active / validate /
/// preview) stay open. Called FIRST in each mutating handler, before any store
/// work — a disabled deployment never half-applies a write. Returns `Ok(())`
/// when allowed.
fn ensure_editing_enabled(state: &AdminState) -> ApiResult<()> {
    match state.policy.policy_editing.off_reason() {
        Some(reason) => Err(ApiError::ForbiddenDyn(format!(
            "policy editing is disabled — {reason}"
        ))),
        None => Ok(()),
    }
}

/// Map a `PolicyError` to the HTTP surface: a missing subject is 404,
/// everything else is an opaque 500 (the sqlx detail stays in the
/// server log, not the wire response).
fn map_policy_err(e: PolicyError) -> ApiError {
    match e {
        PolicyError::NotFound(m) => ApiError::NotFound(m),
        other => ApiError::Internal(format!("policy store: {other}")),
    }
}

/// Map the atomic mirror-then-ledger commit outcome
/// ([`AdminState::mirror_then`]) onto the HTTP surface. A `Mirror` failure (the
/// disk write was refused/failed before the ledger) and a `DiskAhead` double
/// fault both surface their operator-actionable detail via
/// `InternalOperatorVisible` (the detail is config text, not a secret); a
/// `Ledger` failure preserves the underlying `PolicyError` mapping so a
/// `NotFound` still becomes a 404.
fn map_commit_err(e: PolicyCommitError) -> ApiError {
    match e {
        PolicyCommitError::Mirror(m) => {
            tracing::error!(error = %m, "policy_bundles: on-disk mirror write failed");
            ApiError::InternalOperatorVisible(format!(
                "writing policy bundle to policies/ failed: {m}. The change was not recorded \
                 (ledger unchanged)."
            ))
        }
        PolicyCommitError::Ledger(pe) => map_policy_err(pe),
        PolicyCommitError::DiskAhead(m) => {
            tracing::error!(error = %m, "policy_bundles: disk may be ahead of ledger");
            ApiError::InternalOperatorVisible(m)
        }
        // Turnstile LOST: another replica advanced the on-disk policy
        // set; the edit is stale and nothing was written. 409, reload and retry.
        PolicyCommitError::Conflict(m) => ApiError::Conflict(m),
        // No change: the bundle's content already matches the live on-disk set,
        // so there is nothing to apply (and recording a competing ledger row
        // could race a cross-replica writer). 409 — a no-op refusal.
        PolicyCommitError::NoChange(m) => ApiError::Conflict(m),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BundleListResponse {
    pub bundles: Vec<PolicyBundleSummary>,
}

#[utoipa::path(
    get,
    path = "/api/v1/policy_bundles",
    tag = "policy_bundles",
    responses(
        (status = 200, description = "Policy bundles for the caller's tenant, newest version first", body = BundleListResponse),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Policy store query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_bundles(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<BundleListResponse>> {
    let store = policy_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let bundles = store.list_bundles(&tenant).await.map_err(map_policy_err)?;
    Ok(Json(BundleListResponse { bundles }))
}

#[utoipa::path(
    get,
    path = "/api/v1/policy_bundles/active",
    tag = "policy_bundles",
    responses(
        (status = 200, description = "The tenant's active (most recently published) policy bundle. Non-default bundles are enforced by that tenant's runtime Cedar engine after reload.", body = PolicyBundle),
        (status = 404, description = "No published bundle for the tenant", body = ApiErrorBody),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn active_bundle(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<PolicyBundle>> {
    let store = policy_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let bundle = store.active_bundle(&tenant).await.map_err(map_policy_err)?;
    Ok(Json(bundle))
}

/// Body for `POST /api/v1/policy_bundles`: the Cedar policy-set source
/// for the new draft, plus an optional author label and optional policy
/// tests that gate the draft's publish.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDraftBody {
    /// Full Cedar policy-set source for the draft.
    pub content: String,
    /// Optional author label recorded on the bundle.
    #[serde(default)]
    pub author: Option<String>,
    /// Optional policy-test assertions attached to the draft. Typed on the
    /// wire so a malformed case is a 400 at create time, not a surprise at
    /// publish time. Each is run against the draft's Cedar content by the
    /// publish gate; a failing case rejects the publish and keeps the prior
    /// published set untouched. Serialized to the reserved `tests JSONB`
    /// column (the store stays content-agnostic about the shape). `None`
    /// stages a draft with no gate.
    #[serde(default)]
    pub tests: Option<Vec<crate::policy_tests::PolicyTestCase>>,
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles",
    tag = "policy_bundles",
    request_body = CreateDraftBody,
    responses(
        (status = 201, description = "Draft bundle created", body = PolicyBundle),
        (status = 400, description = "Empty policy content, or source that doesn't parse as Cedar", body = ApiErrorBody),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Policy store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_draft(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<CreateDraftBody>,
) -> ApiResult<(StatusCode, Json<PolicyBundle>)> {
    ensure_editing_enabled(&state)?;
    let store = policy_store(&state)?;
    // Reject an empty draft up front — an empty Cedar set is deny-all,
    // and staging it by accident shouldn't be a one-keystroke mistake.
    if body.content.trim().is_empty() {
        return Err(ApiError::BadRequest("policy content is empty".into()));
    }
    // Validate the source parses as Cedar BEFORE storing, mirroring
    // `--import-policies`. A draft's content is immutable (publish only
    // flips status), so validating here means a published bundle is
    // always loadable — the API never reports success for a bundle the
    // gate would reject and silently fall back from on reload.
    let engine = waygate_authz::CedarEngine::from_source(&body.content)
        .map_err(|e| ApiError::BadRequest(format!("policy does not parse as Cedar: {e}")))?;
    if engine.list_policies().is_empty() {
        return Err(ApiError::BadRequest(
            "policy content contains no policies".to_owned(),
        ));
    }
    // Serialize the typed test cases to the JSON the store round-trips into the
    // reserved `tests` column. The cases already deserialized cleanly (typed on
    // the wire), so re-serializing them is infallible in practice; treat a
    // serialize failure as a 500 rather than silently dropping the gate.
    let tests_json = match &body.tests {
        Some(cases) => Some(
            serde_json::to_value(cases)
                .map_err(|e| ApiError::Internal(format!("serialize policy tests: {e}")))?,
        ),
        None => None,
    };
    let actor = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(actor);
    let bundle = store
        .create_draft(
            &tenant,
            &body.content,
            tests_json.as_ref(),
            body.author.as_deref(),
        )
        .await
        .map_err(map_policy_err)?;
    // AdminMutation evidence so a policy draft is auditable like the
    // other mutating admin endpoints. Best-effort: a dropped audit row
    // shouldn't fail an otherwise-successful create.
    record_created_draft_audit(&state, actor, &bundle).await;
    Ok((StatusCode::CREATED, Json(bundle)))
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/{id}/publish",
    tag = "policy_bundles",
    params(("id" = String, Path, description = "Draft bundle UUID")),
    responses(
        (status = 200, description = "Draft mirrored to policies/*.cedar (source of truth) and published to the ledger; active on next boot/SIGHUP reload", body = PolicyBundle),
        (status = 409, description = "Bundle is not a draft (already published / rolled back), OR the bundle's content already matches the live on-disk policy set (nothing to apply — no-op), OR the cross-replica write turnstile was lost (another replica changed the on-disk policy set since this edit's base — reload and retry)", body = ApiErrorBody),
        (status = 404, description = "No draft bundle with that id in the caller's tenant", body = ApiErrorBody),
        (status = 422, description = "The draft's attached policy tests failed, or its stored tests blob is malformed — the policy-test gate refused the publish BEFORE any disk write; the prior published set is kept. The body names the failing case(s).", body = ApiErrorBody),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Policy store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn publish_bundle(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<PolicyBundle>> {
    ensure_editing_enabled(&state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(publish_bundle_core(&state, p, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/{id}/run_tests",
    tag = "policy_bundles",
    params(("id" = String, Path, description = "Draft (or any) bundle UUID")),
    responses(
        (status = 200, description = "Report of the bundle's attached policy tests run against its own Cedar content. A draft with no attached tests reports total=0, all_passed=true. This is read-only — it does not publish.", body = crate::policy_tests::PolicyTestReport),
        (status = 404, description = "No bundle with that id in the caller's tenant", body = ApiErrorBody),
        (status = 422, description = "The bundle's stored tests JSON is malformed and cannot be evaluated", body = ApiErrorBody),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:observe", body = ApiErrorBody),
    ),
)]
async fn run_tests(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<crate::policy_tests::PolicyTestReport>> {
    let store = policy_store(&state)?;
    // Tenant-scope the read to the caller, exactly like the other bundle
    // handlers — a bookmarked `/{id}/run_tests` from one tenant must not run
    // another tenant's bundle.
    let actor = principal.as_ref().map(|Extension(p)| p);
    let tenant_id = caller_tenant_id(actor);
    let bundle = store
        .get(tenant_id.as_str(), id)
        .await
        .map_err(map_policy_err)?;
    // Deserialize the stored tests; a malformed blob is a 422 (same fail-closed
    // posture as the publish gate), not a panic. Absent ⇒ empty ⇒ a vacuous
    // all-passed report.
    let cases: Vec<crate::policy_tests::PolicyTestCase> = match &bundle.tests {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
            ApiError::UnprocessableEntity(format!(
                "bundle v{} has malformed stored tests: {e}",
                bundle.version
            ))
        })?,
        None => Vec::new(),
    };
    // Evaluate under the bundle's tenant (same fix as the publish gate) so a
    // per-tenant policy is previewed in its own authorization context.
    let report = crate::policy_tests::run_policy_tests(&bundle.content, &cases, &tenant_id);
    Ok(Json(report))
}

/// Shared publish path: turnstile lock → draft-status precheck →
/// mirror-then-ledger (disk-wins) → AdminMutation audit. The REST
/// [`publish_bundle`] handler and the `policy.publish` propose executor both
/// call this, so the turnstile, the mirror-before-ledger ordering, the
/// conflict mapping, and the audit are IDENTICAL across the direct-admin and
/// propose paths — a maker-proposed publish can't drift from the API one.
/// Tenant + publisher are resolved from `principal` (the same
/// `caller_tenant` / `caller_actor` the handler used), so the executor passes
/// the approver and a publish lands in the approver's tenant under the
/// approver's `sub`. Returns the newly-published bundle. (The dashboard
/// `publish_form` retains its own PRG/flash-shaped copy.)
pub(crate) async fn publish_bundle_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    id: Uuid,
) -> ApiResult<PolicyBundle> {
    // The editing gate lives HERE, at the chokepoint every publish path
    // funnels through — the REST wrapper, the dashboard `publish_form`, AND the
    // HITL change-request executor (`change_executor`'s `policy.publish`). The
    // REST/dashboard surfaces also refuse earlier, but the HITL executor calls
    // this core directly, so without the gate here an approved `policy.publish`
    // would still mirror onto `policies/*.cedar` with `GATEWAY_POLICY_EDITING=off`.
    // Refuse before taking the write lock or touching disk.
    ensure_editing_enabled(state)?;
    // Serialize the mirror + ledger transition within this replica (shared with
    // the dashboard path via `state.policy.policy_write_lock`); cross-replica
    // coordination is handled separately by the turnstile CAS below.
    let _guard = state.policy.policy_write_lock.lock().await;
    publish_bundle_locked(state, principal, id, None).await
}

/// Publish body for callers that already hold `policy_write_lock`. Derived
/// policy writes keep the lock across read → merge → impact replay → publish and
/// pass the exact on-disk base they merged into. Calling the re-locking
/// [`publish_bundle_core`] from such a path would deadlock the non-reentrant
/// mutex.
async fn publish_bundle_locked(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    id: Uuid,
    expected_base: Option<&str>,
) -> ApiResult<PolicyBundle> {
    let store = policy_store(state)?;
    let tenant = caller_tenant(principal);
    let actor = caller_actor(principal);

    // Mirror the draft onto `policies/*.cedar` (the boot/SIGHUP source) BEFORE
    // the ledger publish — file-as-truth: disk is authoritative, the ledger is
    // recovery/history. Refuse a non-draft up front (mirrors `publish`'s own
    // precondition) so we don't needlessly overwrite the live on-disk set with
    // an already-published version's content for a publish the ledger rejects.
    let draft = store.get(&tenant, id).await.map_err(map_policy_err)?;
    if draft.status != PolicyStatus::Draft {
        return Err(ApiError::Conflict(format!(
            "bundle v{} is {}, not a draft",
            draft.version,
            draft.status.as_str()
        )));
    }
    // POLICY-TEST PUBLISH GATE. If the draft carries attached tests, run
    // them against the draft's Cedar content BEFORE the irreversible
    // `mirror_then` (validate-before-side-effect). A failing assertion REJECTS
    // the publish here, so nothing is written to `policies/*.cedar` and the prior
    // published set stays live — mirroring the load-time invariant a broken
    // `.cedar` already enforces (keep the previous set, never lock the operator
    // out). Still under the `policy_write_lock` held above.
    //
    // A malformed stored test blob or a failing assertion fails CLOSED via the
    // shared `evaluate_publish_gate` choke point (the same one tenant creation
    // uses) — evaluated under the bundle's OWN tenant (the draft was fetched for
    // `tenant`) so per-tenant policies that branch on `principal.tenant` are
    // judged in the right context. The block is audited `Denied` before the 422.
    if let Err(summary) = crate::policy_tests::evaluate_publish_gate(
        &draft.content,
        draft.tests.as_ref(),
        &caller_tenant_id(principal),
    ) {
        record_blocked_publish_audit(
            state,
            principal,
            &format!(
                "publish of policy bundle v{} id={} BLOCKED: {summary}",
                draft.version, draft.id
            ),
        )
        .await;
        return Err(ApiError::UnprocessableEntity(summary));
    }
    // Turnstile + mirror + ledger (disk-wins): claim the turnstile, mirror the
    // draft onto policies/*.cedar, then publish to the ledger. A ledger failure
    // leaves disk applied (disk is the source of truth; it reconciles to the
    // ledger) and surfaces a DiskAhead error.
    let bundle = state
        .mirror_then_from_base(&tenant, &draft.content, &actor, expected_base, || {
            store.publish(&tenant, id, &actor)
        })
        .await
        .map_err(map_commit_err)?;
    // AdminMutation evidence: publishing changes the active
    // authorization policy, so it's the most security-relevant action
    // here and must land in the audit trail.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("policy_bundle.publish", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(principal)
                .with_reason(format!(
                    "published policy bundle version={} id={} hash={}",
                    bundle.version, bundle.id, bundle.content_hash
                )),
        )
        .await;
    Ok(bundle)
}

/// Exact full-set candidate produced by merging one `@id`-addressed Cedar
/// statement into the live on-disk policy source.
#[derive(Debug)]
pub(crate) struct MergedPolicyFragment {
    pub(crate) content: String,
    pub(crate) base_hash: String,
    pub(crate) base_source: String,
    pub(crate) policy_id: String,
}

/// Canonical 503 detail for paths that require the on-disk Cedar source.
pub(crate) const POLICY_POLICIES_DIR_UNAVAILABLE: &str = "policy policies_dir is not configured";

/// Merge exactly one `@id`-annotated Cedar policy statement into the live
/// file-as-truth set. Existing ids are replaced; new ids are appended. The
/// verified segmenter preserves every unrelated source byte and refuses
/// ambiguous policy text. The returned base hash binds the later publish CAS so
/// a concurrent writer cannot be overwritten from a stale merge.
pub(crate) fn merge_policy_fragment_into_live_set(
    state: &AdminState,
    statement: &str,
) -> ApiResult<MergedPolicyFragment> {
    waygate_authz::segment::ensure_single_policy(statement, None).map_err(ApiError::BadRequest)?;
    let submitted = waygate_authz::segment::segment_verified(statement)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let policy_id = submitted
        .first()
        .and_then(|fragment| fragment.id.clone())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "the submitted policy must carry a unique @id(\"…\") annotation".to_owned(),
            )
        })?;

    let dir = state
        .policy
        .policies_dir
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable(
            POLICY_POLICIES_DIR_UNAVAILABLE,
        ))?;
    let live = waygate_policy::read_policy_dir(dir).map_err(|e| {
        ApiError::InternalOperatorVisible(format!(
            "could not read the live policy set to merge into: {e}"
        ))
    })?;
    let engine = waygate_authz::CedarEngine::from_source(&live.source).map_err(|e| {
        ApiError::Conflict(format!(
            "the live policy set is not usable, so a fragment cannot be merged safely: {e}"
        ))
    })?;
    if engine.list_policies().is_empty() {
        return Err(ApiError::Conflict(
            "the live policy set is empty, so a fragment cannot be merged safely".to_owned(),
        ));
    }

    let live_fragments = waygate_authz::segment::segment_verified(&live.source).map_err(|e| {
        ApiError::Conflict(format!(
            "the live policy set cannot be addressed safely by @id: {e}"
        ))
    })?;
    let content = if live_fragments
        .iter()
        .any(|fragment| fragment.id.as_deref() == Some(policy_id.as_str()))
    {
        waygate_authz::segment::replace_policy(&live.source, &policy_id, statement)
    } else {
        waygate_authz::segment::append_policy(&live.source, statement)
    }
    .map_err(|e| ApiError::Conflict(format!("could not merge the policy fragment: {e}")))?;

    let merged_engine = waygate_authz::CedarEngine::from_source(&content).map_err(|e| {
        ApiError::BadRequest(format!(
            "the merged policy set does not parse as Cedar: {e}"
        ))
    })?;
    if merged_engine.list_policies().is_empty() {
        return Err(ApiError::BadRequest(
            "the merged policy set is empty".to_owned(),
        ));
    }

    let base_hash = waygate_policy::content_hash(&live.source);
    Ok(MergedPolicyFragment {
        content,
        base_hash,
        base_source: live.source,
        policy_id,
    })
}

/// Successful approved fragment upsert: the published bundle and addressed
/// policy id. The mandatory replay is intentionally not carried into the
/// maker-visible execution result because it contains audit-derived data.
pub(crate) struct PolicyFragmentPublishOutcome {
    pub(crate) bundle: PolicyBundle,
    pub(crate) policy_id: String,
}

/// Merge one proposed policy statement into the live set, require an exact
/// impact replay, stage the reconstructed full set, and publish it as one
/// approved operation. The proposal's captured live-set hash is checked before
/// preview and threaded into the turnstile CAS, closing both the pending-review
/// window and the final cross-replica read→write race.
pub(crate) async fn upsert_policy_fragment_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    statement: &str,
    author: Option<&str>,
    proposed_base: &str,
) -> ApiResult<PolicyFragmentPublishOutcome> {
    ensure_editing_enabled(state)?;
    let store = policy_store(state)?;
    let tenant = caller_tenant(principal);
    if tenant != TenantId::DEFAULT {
        return Err(ApiError::BadRequest(
            "policy fragment upsert currently supports only the default tenant because that editor operates on the default tenant's live on-disk policy set"
                .to_owned(),
        ));
    }
    let tenant_id = caller_tenant_id(principal);
    let _guard = state.policy.policy_write_lock.lock().await;
    let merged = merge_policy_fragment_into_live_set(state, statement)?;
    if merged.base_hash != proposed_base {
        return Err(ApiError::Conflict(
            "the live policy set changed after this fragment was proposed — review and propose it again against the current set"
                .to_owned(),
        ));
    }

    // Preserve the active bundle's attached test gate only when the ledger and
    // live source describe the same set. Carrying tests from a stale ledger row
    // would test the wrong policy; dropping them would silently weaken the gate.
    let active = store.active_bundle(&tenant).await.map_err(map_policy_err)?;
    if !waygate_policy::policy_sources_equivalent(&active.content, &merged.base_source) {
        return Err(ApiError::Conflict(
            "the policy ledger has not reconciled to the live on-disk set — retry after reload reconciliation"
                .to_owned(),
        ));
    }
    if let Err(summary) = crate::policy_tests::evaluate_publish_gate(
        &merged.content,
        active.tests.as_ref(),
        &tenant_id,
    ) {
        record_blocked_publish_audit(
            state,
            principal,
            &format!(
                "publish of policy fragment @id={} BLOCKED: {summary}",
                merged.policy_id
            ),
        )
        .await;
        return Err(ApiError::UnprocessableEntity(summary));
    }

    // Mandatory blast-radius gate: unlike best-effort dashboard previews for
    // legacy bundle actions, this authoring path refuses before staging when the
    // audit reader/query is unavailable.
    let impact = replay_recent_decisions(state, &tenant_id, &merged.content).await?;
    if let Some(error) = impact.error.as_deref() {
        return Err(ApiError::BadRequest(format!(
            "the merged policy could not be impact-previewed: {error}"
        )));
    }

    let draft = store
        .create_draft(&tenant, &merged.content, active.tests.as_ref(), author)
        .await
        .map_err(map_policy_err)?;
    record_created_draft_audit(state, principal, &draft).await;
    let bundle = publish_bundle_locked(state, principal, draft.id, Some(&merged.base_hash)).await?;
    Ok(PolicyFragmentPublishOutcome {
        bundle,
        policy_id: merged.policy_id,
    })
}

/// Parse-only validate. Same Cedar `from_source` check
/// that `create_draft` runs as its pre-store guard, but without
/// touching the database. The editor calls this on every Validate
/// click so an operator can confirm the source parses before
/// committing to a `Save draft` (and the matching audit row).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateBundleBody {
    /// Cedar policy-set source to parse-check.
    pub content: String,
}

/// `200 OK` response from `POST /api/v1/policy_bundles/validate`.
/// `ok` is always `true` on a 200 — parse failures land on the
/// 400 path with `ApiErrorBody`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateBundleResponse {
    pub ok: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/validate",
    tag = "policy_bundles",
    request_body = ValidateBundleBody,
    responses(
        (status = 200, description = "Source parses as a Cedar policy set", body = ValidateBundleResponse),
        (status = 400, description = "Empty source, or source that doesn't parse as Cedar", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn validate_bundle(
    Json(body): Json<ValidateBundleBody>,
) -> ApiResult<Json<ValidateBundleResponse>> {
    if body.content.trim().is_empty() {
        return Err(ApiError::BadRequest("policy content is empty".into()));
    }
    if let Err(e) = waygate_authz::CedarEngine::from_source(&body.content) {
        return Err(ApiError::BadRequest(format!(
            "policy does not parse as Cedar: {e}"
        )));
    }
    Ok(Json(ValidateBundleResponse { ok: true }))
}

/// Run a simulator request against an *ephemeral* engine
/// built from a candidate bundle source — Preview against draft.
/// Mirrors the `SimulateRequest` shape used by
/// `POST /api/v1/policies/simulate`, with `content` carrying the
/// candidate Cedar source. The candidate is NOT persisted; the
/// engine is constructed in-handler, the decision is returned,
/// and the engine drops.
///
/// Differs from the live simulator in two ways: (a) policy_ids
/// reflect the candidate's policy set, not the published one, and
/// (b) step-up scope re-eval semantics still apply because the
/// `CedarEngine::evaluate` path is the same.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewSimulateBody {
    /// Candidate Cedar policy-set source to evaluate against.
    pub content: String,
    /// The simulator request to run — same shape as
    /// `POST /api/v1/policies/simulate` minus the wrapping.
    #[serde(flatten)]
    pub request: SimulateRequest,
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/preview_simulate",
    tag = "policy_bundles",
    request_body = PreviewSimulateBody,
    responses(
        (status = 200, description = "Decision under the candidate bundle, with reasons + matched candidate policy IDs", body = SimulateResponse),
        (status = 400, description = "Candidate content is empty or fails to parse", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
        (status = 500, description = "Cedar evaluator failed on the candidate — e.g. a forbid whose condition cannot be evaluated for the simulated facts", body = ApiErrorBody),
    ),
)]
async fn preview_simulate(
    Extension(caller): Extension<Principal>,
    Json(body): Json<PreviewSimulateBody>,
) -> ApiResult<Json<SimulateResponse>> {
    if body.content.trim().is_empty() {
        return Err(ApiError::BadRequest("policy content is empty".into()));
    }
    let engine = waygate_authz::CedarEngine::from_source(&body.content)
        .map_err(|e| ApiError::BadRequest(format!("policy does not parse as Cedar: {e}")))?;
    let facts = crate::policies::simulate_request_to_facts(body.request, caller.tenant);
    let required_scope = facts.action.required_scope.clone();
    // Direct `CedarEngine::evaluate_facts` (not the trait) so a Cedar
    // evaluator error surfaces as a 500 here rather than the
    // ReloadableCedar trait impl's fail-closed deny — a Preview
    // failure should be loud, not silently rendered as "deny."
    let result = engine
        .evaluate_facts(&facts)
        .map_err(|e| ApiError::Internal(format!("cedar evaluator failed: {e}")))?;
    // Trace metadata comes from the CANDIDATE engine, so a preview reflects the
    // draft bundle's layers/descriptions, not the live set.
    Ok(Json(crate::policies::authz_result_to_response(
        result,
        &engine.list_policies(),
        required_scope,
    )))
}

/// Shared decision-replay / impact core. Loads the draft (tenant-scoped),
/// fetches the tenant's recent recorded decisions, and replays them against the
/// draft's Cedar content in memory — returning the blast-radius
/// [`ImpactReport`]. The REST [`preview_impact`] handler and the dashboard
/// "Preview impact" action both call this so the two surfaces compute the SAME
/// report (the dashboard delegates to the REST core, like every other
/// dashboard action).
///
/// READ-ONLY: no publish, no audit mutation, no disk write — it is a pure read
/// of the draft + recent decisions plus an in-memory eval against an ephemeral
/// candidate engine.
///
/// 503 when either store is unwired (the impact view needs BOTH the policy
/// store, to load the draft, and the audit store, to fetch decisions); 404 when
/// no draft with `id` exists in the caller's tenant. The decision query is
/// tenant-scoped to the caller via [`crate::audit::decision_store_query`] — the
/// same SECURITY boundary the Decision Log enforces.
pub(crate) async fn compute_impact_for_draft(
    state: &AdminState,
    principal: Option<&Principal>,
    id: Uuid,
) -> ApiResult<ImpactReport> {
    let store = policy_store(state)?;
    let tenant_id = caller_tenant_id(principal);

    // Load the draft tenant-scoped — a bookmarked `/{id}/preview_impact` from
    // one tenant must not read another tenant's bundle.
    let bundle = store
        .get(tenant_id.as_str(), id)
        .await
        .map_err(map_policy_err)?;

    replay_recent_decisions(state, &tenant_id, &bundle.content).await
}

/// Replay `tenant`'s recent recorded decisions against `content` (already-loaded
/// candidate Cedar) and return the blast radius. The shared replay-fetch core
/// behind both [`compute_impact_for_draft`] (the REST `/preview_impact` and the
/// dashboard policy-bundles action) and the HITL change-request policy preview
/// ([`crate::change_policy_preview`]) — so every surface scopes the decision
/// query identically and computes the SAME report against the same candidate
/// content. `tenant` is the SECURITY boundary: callers pass the bundle/change's
/// own tenant, never a viewer's, so a replay can't read another tenant's audit
/// history.
///
/// READ-ONLY: a pure read of the recent decisions plus an in-memory eval against
/// an ephemeral candidate engine — no publish, no audit mutation, no disk write.
/// 503 when the audit store is unwired (the impact view needs it to fetch the
/// decisions to replay).
pub(crate) async fn replay_recent_decisions(
    state: &AdminState,
    tenant: &TenantId,
    content: &str,
) -> ApiResult<ImpactReport> {
    let reader = state.observability.audit.require()?;

    // Fetch the tenant's recent recorded decisions, scoped to the tenant exactly
    // like the Decision Log (categories invocation+llm_completion, `pre_call`
    // excluded). Replay filters down to the replayable subset and reports the
    // excluded count, so passing both decision categories here is fine — the
    // model rows are surfaced as "not replayable" rather than dropped silently.
    let query = crate::audit::decision_store_query(tenant.as_str(), None, None, None, None);
    let rows = reader
        .query_events(&query, IMPACT_REPLAY_LIMIT, None)
        .await
        .map_err(|e| ApiError::Internal(format!("audit query: {e}")))?;

    Ok(compute_impact(content, tenant, &rows))
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/{id}/preview_impact",
    tag = "policy_bundles",
    params(("id" = String, Path, description = "Draft (or any) bundle UUID")),
    responses(
        (status = 200, description = "Blast-radius report: replaying the tenant's recent recorded decisions against this draft, how many would change (allow→deny, deny→allow, →step-up) vs stay the same, plus the count of decisions that aren't replayable (legacy rows without the migration-0062-captured inputs, or model decisions). A candidate that doesn't parse returns a 200 with `error` set and nothing evaluated (`replayed`/`changed`/`unchanged` are 0, `deltas`/`samples` empty); `considered` and `not_replayable` still report the rows that were fetched.", body = ImpactReport),
        (status = 404, description = "No bundle with that id in the caller's tenant", body = ApiErrorBody),
        (status = 503, description = "Policy store or audit store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:observe", body = ApiErrorBody),
    ),
)]
async fn preview_impact(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ImpactReport>> {
    let actor = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(compute_impact_for_draft(&state, actor, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/policy_bundles/{version}/rollback",
    tag = "policy_bundles",
    params(("version" = i32, Path, description = "Previously-published version to roll back to")),
    responses(
        (status = 200, description = "Rolled back: target version's content mirrored to policies/*.cedar and re-published as a new active bundle", body = PolicyBundle),
        (status = 404, description = "No bundle at that version in the caller's tenant", body = ApiErrorBody),
        (status = 409, description = "Target version was never published (draft, not a valid rollback target), OR its content already matches the live on-disk policy set (nothing to apply — no-op), OR the cross-replica write turnstile was lost (another replica changed the on-disk policy set — reload and retry)", body = ApiErrorBody),
        (status = 503, description = "Policy store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Policy store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn rollback_bundle(
    State(state): State<Arc<AdminState>>,
    Path(version): Path<i32>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<PolicyBundle>> {
    ensure_editing_enabled(&state)?;
    let p = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(rollback_bundle_core(&state, p, version).await?))
}

/// Shared rollback path: turnstile lock → resolve target version → reject a
/// never-published (draft) target → mirror-then-ledger (disk-wins) →
/// AdminMutation audit. The REST [`rollback_bundle`] handler and the
/// `policy.rollback` propose executor both call this (same no-drift rationale
/// as [`publish_bundle_core`]). Tenant + actor are resolved from `principal`.
/// Returns the new active bundle (a roll-forward of the target's content).
pub(crate) async fn rollback_bundle_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    version: i32,
) -> ApiResult<PolicyBundle> {
    // Editing gate at the chokepoint — same reasoning as
    // `publish_bundle_core`. The HITL `policy.rollback` executor calls this core
    // directly (bypassing the REST/dashboard surface gates), so the read-only
    // posture is only complete if the refusal lives here too.
    ensure_editing_enabled(state)?;
    let store = policy_store(state)?;
    let tenant = caller_tenant(principal);
    let actor = caller_actor(principal);

    // Serialize the mirror + ledger transition within this replica (same
    // reasoning as `publish_bundle_core`).
    let _guard = state.policy.policy_write_lock.lock().await;

    // Resolve the target version's content BEFORE the ledger transition so we
    // mirror it onto `policies/*.cedar` first. No get-by-version exists, so find
    // the (unique) bundle at `version` via the summary list, then fetch it.
    let target = store
        .list_bundles(&tenant)
        .await
        .map_err(map_policy_err)?
        .into_iter()
        .find(|b| b.version == version)
        .ok_or_else(|| ApiError::NotFoundDyn(format!("no policy bundle at version {version}")))?;
    // rollback_to re-activates only vetted (previously-published) content; a
    // never-published draft is not a valid target. Pre-check so we don't mirror
    // a draft for a rollback the ledger would reject.
    if target.status == PolicyStatus::Draft {
        return Err(ApiError::Conflict(format!(
            "version {version} was never published; cannot roll back to a draft"
        )));
    }
    let content = store
        .get(&tenant, target.id)
        .await
        .map_err(map_policy_err)?
        .content;
    // Turnstile + mirror + ledger, same disk-wins handling as publish (a ledger
    // failure leaves disk applied and reconciles to the ledger).
    let bundle = state
        .mirror_then(&tenant, &content, &actor, || {
            store.rollback_to(&tenant, version, &actor)
        })
        .await
        .map_err(map_commit_err)?;
    // AdminMutation evidence: rollback re-activates an older policy
    // set, equally security-relevant as publish. Record the version
    // rolled back FROM (the request) and the new active version.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("policy_bundle.rollback", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(principal)
                .with_reason(format!(
                    "rolled back to policy version={version}; new active version={} hash={}",
                    bundle.version, bundle.content_hash
                )),
        )
        .await;
    Ok(bundle)
}

#[cfg(test)]
mod fragment_merge_tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use uuid::Uuid;
    use waygate_upstream::pool::UpstreamPool;

    use super::merge_policy_fragment_into_live_set;
    use crate::error::ApiError;
    use crate::state::AdminState;

    struct TmpDir(std::path::PathBuf);

    impl TmpDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("policy-fragment-merge-{}", Uuid::now_v7()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn state_with_live(source: &str) -> (Arc<AdminState>, TmpDir) {
        let dir = TmpDir::new();
        std::fs::write(dir.0.join("10-live.cedar"), source).unwrap();
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let state = Arc::new(
            AdminState::new(
                pool,
                None,
                None,
                AdminState::null_evidence(),
                None,
                None,
                None,
                None,
                "http://127.0.0.1:0".into(),
            )
            .with_policies_dir(dir.0.clone()),
        );
        (state, dir)
    }

    #[tokio::test]
    async fn fragment_upsert_replaces_only_matching_id_and_preserves_live_base() {
        let live = "// retained context\n@id(\"keep\") permit(principal, action, resource);\n\n@id(\"example-security\") forbid(principal, action, resource);\n";
        let (state, dir) = state_with_live(live).await;
        let replacement =
            "@id(\"example-security\") permit(principal, action, resource) when { true };";

        let merged = merge_policy_fragment_into_live_set(&state, replacement).unwrap();

        assert_eq!(merged.policy_id, "example-security");
        let disk_source = waygate_policy::read_policy_dir(&dir.0).unwrap().source;
        assert_eq!(merged.base_hash, waygate_policy::content_hash(&disk_source));
        assert!(merged.content.contains("// retained context"));
        assert!(merged.content.contains("@id(\"keep\") permit"));
        assert!(merged.content.contains(replacement));
        assert!(!merged.content.contains("@id(\"example-security\") forbid"));
    }

    #[tokio::test]
    async fn fragment_upsert_requires_one_addressable_policy() {
        let live = "@id(\"keep\") permit(principal, action, resource);\n";
        let (state, _dir) = state_with_live(live).await;

        let err =
            merge_policy_fragment_into_live_set(&state, "permit(principal, action, resource);")
                .expect_err("an unaddressed statement must be refused");
        assert!(matches!(err, ApiError::BadRequest(_)));

        let err = merge_policy_fragment_into_live_set(
            &state,
            "@id(\"one\") permit(principal, action, resource);\n@id(\"two\") permit(principal, action, resource);",
        )
        .expect_err("a multi-policy fragment must be refused");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}

#[cfg(test)]
mod editing_gate_tests {
    //! The publish, rollback, and fragment-upsert cores are the chokepoint every
    //! mutation surface funnels through — the REST wrappers, the dashboard form
    //! handlers, AND the HITL change-request executor (`change_executor`'s
    //! policy mutation action, which calls these cores directly and
    //! so bypass the surface-level gates). The read-only posture is only real if
    //! the cores themselves refuse, so pin it here: with editing disabled both
    //! cores fail with `ForbiddenDyn` BEFORE any store/disk work — the gate is
    //! the first statement, so no store wiring (or valid bundle) is needed.
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use uuid::Uuid;
    use waygate_upstream::pool::UpstreamPool;

    use super::{publish_bundle_core, rollback_bundle_core, upsert_policy_fragment_core};
    use crate::error::ApiError;
    use crate::state::AdminState;

    async fn editing_off_state() -> Arc<AdminState> {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        Arc::new(
            AdminState::new(
                pool,
                None,
                None,
                AdminState::null_evidence(),
                None,
                None,
                None,
                None,
                "http://127.0.0.1:0".into(),
            )
            .with_policy_editing_off_reason(Some("the policies directory is not writable".into())),
        )
    }

    #[tokio::test]
    async fn publish_core_refuses_when_editing_disabled() {
        // The HITL `policy.publish` executor reaches this core with no
        // surface-level gate in front of it — the core must refuse on its own.
        let state = editing_off_state().await;
        let err = publish_bundle_core(&state, None, Uuid::now_v7())
            .await
            .expect_err("publish core must refuse when editing is disabled");
        match err {
            ApiError::ForbiddenDyn(reason) => assert!(
                reason.contains("policy editing is disabled"),
                "reason must name the disabled-editing posture: {reason}",
            ),
            other => panic!("expected ForbiddenDyn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rollback_core_refuses_when_editing_disabled() {
        let state = editing_off_state().await;
        let err = rollback_bundle_core(&state, None, 1)
            .await
            .expect_err("rollback core must refuse when editing is disabled");
        assert!(
            matches!(err, ApiError::ForbiddenDyn(_)),
            "expected ForbiddenDyn, got {err:?}",
        );
    }

    #[tokio::test]
    async fn fragment_upsert_core_refuses_when_editing_disabled() {
        let state = editing_off_state().await;
        let result = upsert_policy_fragment_core(
            &state,
            None,
            "@id(\"example-security\") permit(principal, action, resource);",
            None,
            "captured-base",
        )
        .await;
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("fragment upsert core must refuse when editing is disabled"),
        };
        assert!(
            matches!(err, ApiError::ForbiddenDyn(_)),
            "expected ForbiddenDyn, got {err:?}",
        );
    }
}
