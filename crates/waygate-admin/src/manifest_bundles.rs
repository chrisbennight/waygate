//! `/api/v1/server_manifests/*` — admin surface over the durable
//! server-manifest store.
//!
//! The manifest store is the Postgres-backed, versioned home of the
//! gateway's upstream-server set (the durable overlay for the on-disk
//! `servers/*.yaml` files). These endpoints let an
//! operator inspect and stage manifest-set versions over HTTP instead of
//! editing files and sending SIGHUP — the exact analogue of
//! `/api/v1/policy_bundles/*`:
//!
//! - `GET  /api/v1/server_manifests` — every bundle for the caller's
//!   tenant (summaries, newest version first).
//! - `GET  /api/v1/server_manifests/active` — the bundle currently in
//!   force (the most recently published one), including its YAML source.
//! - `POST /api/v1/server_manifests/validate` — parse-only check of a
//!   candidate manifest set; no DB write.
//! - `POST /api/v1/server_manifests` — stage a new draft from a YAML
//!   manifest-set body. Drafts are not built into the pool until
//!   published.
//! - `POST /api/v1/server_manifests/{id}/publish` — promote a draft to
//!   published; boot/SIGHUP picks it up on the next reload.
//! - `POST /api/v1/server_manifests/{version}/rollback` — re-activate a
//!   previously-published version by re-publishing its content as a new
//!   bundle (append-only roll-forward).
//!
//! All are gated by `mcp:admin` and scoped to the caller's tenant.
//!
//! Tenant caveat (mirrors policy bundles): these endpoints operate on the
//! caller's tenant, but under file-as-truth the runtime loader
//! (`resolve_manifests`) loads the on-disk `servers/*.yaml` dir — the
//! single GLOBAL upstream set (the pool is gateway-wide). So
//! `publish`/`rollback` mirror to disk only for the DEFAULT tenant; a
//! non-default tenant's bundle is recorded in its ledger but does not
//! touch the global dir. In the present single-tenant deployment every
//! principal is the default tenant, so the two coincide.
//!
//! Prod-safety caveat: `transport: stdio` under the `prod` deployment
//! profile is refused both at **activation** time (boot + SIGHUP) AND at the
//! **disk mirror**, which runs BEFORE the ledger transition on
//! publish/rollback — disk is the boot source of truth, so a
//! prod-unsafe set must never reach it. `validate` and draft creation check
//! only the set's *shape* (it parses, passes the invariant checks, no
//! duplicate names), so a `transport: stdio` draft can be staged; but
//! publishing or rolling to it under `prod` is refused at the pre-ledger
//! mirror step, so the publish/rollback fails outright and is **not recorded**
//! — not "recorded but inert". The activation gate is the backstop on reload.
//! There is therefore no "publish silently breaks prod" path.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{middleware, Extension, Json, Router};
use waygate_core::TenantId;
use waygate_manifest_store::{
    ManifestBundle, ManifestBundleSummary, ManifestError, SharedManifestStore,
};
use waygate_mcp::{AuditEvent, AuditOutcome, EvidenceCategory};

use crate::dashboard_server_manifests::{
    canonical_disk_hash, turnstile_cas, turnstile_rollback, TurnstileClaim, TurnstileError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/server_manifests",
            axum::routing::get(list_bundles).post(create_draft),
        )
        .route(
            "/api/v1/server_manifests/active",
            axum::routing::get(active_bundle),
        )
        .route(
            "/api/v1/server_manifests/validate",
            axum::routing::post(validate_bundle),
        )
        .route(
            "/api/v1/server_manifests/{id}/publish",
            axum::routing::post(publish_bundle),
        )
        .route(
            "/api/v1/server_manifests/{version}/rollback",
            axum::routing::post(rollback_bundle),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

/// The caller's tenant, or the default tenant for the auth-disabled dev
/// path (no principal).
fn caller_tenant(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| TenantId::DEFAULT.to_owned())
}

/// The caller's `sub` for publish provenance, or a dev sentinel.
fn caller_actor(principal: Option<&Principal>) -> String {
    principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned())
}

fn manifest_store(state: &AdminState) -> ApiResult<&SharedManifestStore> {
    state.servers.manifest_store.require()
}

/// Map a `ManifestError` to the HTTP surface: a missing subject is 404,
/// everything else is an opaque 500 (the sqlx detail stays in the server
/// log, not the wire response).
fn map_manifest_err(e: ManifestError) -> ApiError {
    match e {
        ManifestError::NotFound(m) => ApiError::NotFound(m),
        other => ApiError::Internal(format!("manifest store: {other}")),
    }
}

/// Map a turnstile refusal to the right HTTP status: a lost CAS is the client's
/// to retry after reloading (409 Conflict), while a backing-store failure is an
/// internal error (500) a retry won't resolve — keeping 409 reserved for
/// `TurnstileOutcome::Lost`.
fn map_turnstile_err(e: TurnstileError) -> ApiError {
    match e {
        TurnstileError::Lost(m) => ApiError::Conflict(m),
        TurnstileError::Store(m) => ApiError::Internal(m),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ManifestBundleListResponse {
    pub bundles: Vec<ManifestBundleSummary>,
}

#[utoipa::path(
    get,
    path = "/api/v1/server_manifests",
    tag = "server_manifests",
    responses(
        (status = 200, description = "Manifest bundles for the caller's tenant, newest version first", body = ManifestBundleListResponse),
        (status = 503, description = "Manifest store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Manifest store query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_bundles(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ManifestBundleListResponse>> {
    let store = manifest_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let bundles = store
        .list_bundles(&tenant)
        .await
        .map_err(map_manifest_err)?;
    Ok(Json(ManifestBundleListResponse { bundles }))
}

#[utoipa::path(
    get,
    path = "/api/v1/server_manifests/active",
    tag = "server_manifests",
    responses(
        (status = 200, description = "The tenant's active (most recently published) manifest bundle. Note: the runtime loader reads only the default tenant's bundle (upstreams are global today).", body = ManifestBundle),
        (status = 404, description = "No published bundle for the tenant", body = ApiErrorBody),
        (status = 503, description = "Manifest store not configured (no database)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn active_bundle(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ManifestBundle>> {
    let store = manifest_store(&state)?;
    let tenant = caller_tenant(principal.as_ref().map(|Extension(p)| p));
    let bundle = store
        .active_bundle(&tenant)
        .await
        .map_err(map_manifest_err)?;
    Ok(Json(bundle))
}

/// Body for `POST /api/v1/server_manifests`: the YAML manifest-set source
/// for the new draft, plus an optional author label.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ManifestCreateDraftBody {
    /// Full manifest-set source for the draft: a YAML sequence of
    /// upstream manifests (the form `parse_manifest_set` accepts).
    pub content: String,
    /// Optional author label recorded on the bundle.
    #[serde(default)]
    pub author: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/server_manifests",
    tag = "server_manifests",
    request_body = ManifestCreateDraftBody,
    responses(
        (status = 201, description = "Draft bundle created", body = ManifestBundle),
        (status = 400, description = "Empty content, or a set that doesn't parse / fails an invariant / has duplicate names", body = ApiErrorBody),
        (status = 503, description = "Manifest store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Manifest store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_draft(
    State(state): State<Arc<AdminState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<ManifestCreateDraftBody>,
) -> ApiResult<(StatusCode, Json<ManifestBundle>)> {
    let store = manifest_store(&state)?;
    // Reject an empty draft up front — an empty set is "no upstreams",
    // and staging it by accident shouldn't be a one-keystroke mistake.
    if body.content.trim().is_empty() {
        return Err(ApiError::BadRequest("manifest content is empty".into()));
    }
    // Validate the set parses (and passes per-entry invariants + dup-name
    // rejection) BEFORE storing, mirroring `--import-server-bundle`. A
    // draft's content is immutable (publish only flips status), so
    // validating here means a published bundle is always loadable — the
    // API never reports success for a bundle the loader would reject and
    // silently fall back from on reload.
    if let Err(e) = waygate_upstream::parse_manifest_set(&body.content) {
        return Err(ApiError::BadRequest(format!(
            "manifest set is not valid: {e}"
        )));
    }
    let actor = principal.as_ref().map(|Extension(p)| p);
    let tenant = caller_tenant(actor);
    let bundle = store
        .create_draft(&tenant, &body.content, body.author.as_deref())
        .await
        .map_err(map_manifest_err)?;
    // AdminMutation evidence so a manifest draft is auditable like the
    // other mutating admin endpoints. Best-effort: a dropped audit row
    // shouldn't fail an otherwise-successful create.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("server_manifest.create_draft", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(actor)
                .with_reason(format!(
                    "created manifest draft version={} hash={}",
                    bundle.version, bundle.content_hash
                )),
        )
        .await;
    Ok((StatusCode::CREATED, Json(bundle)))
}

/// Parse-only validate. The same `parse_manifest_set` check that
/// `create_draft` runs as its pre-store guard, but without touching the
/// database. The dashboard editor calls this on every Validate click so
/// an operator can confirm the set is well-formed before committing to
/// a `Save draft` (and the matching audit row).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ManifestValidateBundleBody {
    /// Manifest-set source to parse-check.
    pub content: String,
}

/// `200 OK` response from `POST /api/v1/server_manifests/validate`. `ok`
/// is always `true` on a 200 — parse/invariant failures land on the 400
/// path with `ApiErrorBody`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ManifestValidateBundleResponse {
    pub ok: bool,
    /// Number of upstreams in the parsed set (a quick sanity signal for
    /// the editor: "12 upstreams" vs an accidental near-empty paste).
    pub upstream_count: usize,
}

#[utoipa::path(
    post,
    path = "/api/v1/server_manifests/validate",
    tag = "server_manifests",
    request_body = ManifestValidateBundleBody,
    responses(
        (status = 200, description = "Source parses as a valid manifest set", body = ManifestValidateBundleResponse),
        (status = 400, description = "Empty source, or a set that doesn't parse / fails an invariant / has duplicate names", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn validate_bundle(
    Json(body): Json<ManifestValidateBundleBody>,
) -> ApiResult<Json<ManifestValidateBundleResponse>> {
    if body.content.trim().is_empty() {
        return Err(ApiError::BadRequest("manifest content is empty".into()));
    }
    let set = waygate_upstream::parse_manifest_set(&body.content)
        .map_err(|e| ApiError::BadRequest(format!("manifest set is not valid: {e}")))?;
    Ok(Json(ManifestValidateBundleResponse {
        ok: true,
        upstream_count: set.len(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/server_manifests/{id}/publish",
    tag = "server_manifests",
    params(("id" = String, Path, description = "Draft bundle UUID")),
    responses(
        (status = 200, description = "Draft published; active on next reload", body = ManifestBundle),
        (status = 404, description = "No draft bundle with that id in the caller's tenant", body = ApiErrorBody),
        (status = 409, description = "Turnstile lost: another replica changed the on-disk config since this draft's base; reload and retry", body = ApiErrorBody),
        (status = 422, description = "No-op: the draft already matches the live on-disk set; nothing to publish", body = ApiErrorBody),
        (status = 503, description = "Manifest store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Manifest store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn publish_bundle(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<Uuid>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ManifestBundle>> {
    let p = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(publish_bundle_core(&state, p, id).await?))
}

/// Shared manifest-publish path: write lock → draft precheck → turnstile CAS →
/// mirror-to-disk → ledger publish → doorbell → AdminMutation audit. The REST
/// [`publish_bundle`] handler calls this with no proposal-time base. The
/// `manifest.publish` executor calls [`publish_bundle_core_from_base`] with its
/// captured base; both converge on the same locked turnstile/mirror/ledger/audit
/// path. Tenant + publisher are resolved from `principal` (the executor passes
/// the approver, so a publish lands in the approver's tenant). Returns the
/// newly-published bundle. (The dashboard `publish_form` retains its own
/// PRG/flash-shaped copy.)
pub(crate) async fn publish_bundle_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    id: Uuid,
) -> ApiResult<ManifestBundle> {
    publish_bundle_core_from_base(state, principal, id, None).await
}

/// Publish a full-set draft only while the live manifest still matches the
/// proposal-time base. `expected_base` is `None` for direct dashboard/REST
/// publishes, which intentionally keep their existing re-read-now behavior.
pub(crate) async fn publish_bundle_core_from_base(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    id: Uuid,
    expected_base: Option<&str>,
) -> ApiResult<ManifestBundle> {
    // File-as-truth (server-config redesign): serialize with the
    // other manifest write paths and mirror the published set onto the
    // on-disk source of truth so boot/SIGHUP load it. Without this a REST
    // publish updates only the ledger while disk — what actually loads —
    // stays stale. The lock is held across `publish_bundle_locked`; a caller
    // that ALREADY holds it (e.g. `upsert_servers_core`, which reads its merge
    // base under the same lock so the read→publish is atomic) calls
    // `publish_bundle_locked` directly — re-entering this wrapper would deadlock
    // the non-reentrant mutex.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    publish_bundle_locked(state, principal, id, expected_base).await
}

/// The publish core body, run with `state.servers.manifest_write_lock` ALREADY held by
/// the caller. NEVER call without the lock: it mirrors the set onto the on-disk
/// source of truth and MUST be serialized with every other manifest write. Split
/// out of `publish_bundle_core` so `upsert_servers_core` can hold the lock across
/// its read-merge-then-publish (making that read→write atomic) — which calling
/// the re-locking `publish_bundle_core` cannot do.
async fn publish_bundle_locked(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    id: Uuid,
    // The on-disk hash the draft was derived from, for the turnstile CAS base.
    // `None` for a direct full-set publish (re-read the current disk hash);
    // `Some` for governed full-set or derived writes so a concurrent publish
    // since proposal/merge loses the CAS instead of being silently clobbered.
    expected_base: Option<&str>,
) -> ApiResult<ManifestBundle> {
    let store = manifest_store(state)?;
    let p = principal;
    let tenant = caller_tenant(principal);
    let actor = caller_actor(principal);
    // Turnstile + mirror BEFORE the ledger transition, so a lost CAS
    // leaves the ledger untouched (fail-closed). The draft's content is what
    // publish records, so claim/mirror it first; publish is last.
    let draft = store.get(&tenant, id).await.map_err(map_manifest_err)?;
    // Only a DRAFT may be published. `store.get` does not filter by status and
    // the draft-only guard lives in `store.publish`'s UPDATE — verify HERE,
    // before the CAS + mirror, so a non-draft id fails closed instead of
    // writing that bundle's content to disk + notifying first.
    if draft.status != waygate_manifest_store::ManifestStatus::Draft {
        return Err(ApiError::NotFound(
            "no draft manifest bundle with that id in tenant",
        ));
    }
    // The turnstile pointer tracks the on-disk (CANONICAL) hash the mirror
    // writes, not the raw bundle hash; compute it from the draft content (also
    // fails closed here if it can't parse) and use it for the CAS, rollback, and
    // doorbell so the pointer always matches what disk hashes to.
    let disk_hash = canonical_disk_hash(&draft.content).map_err(|e| {
        ApiError::Internal(format!("draft content is not a valid manifest set: {e}"))
    })?;
    // A lost CAS is the client's to retry (409); a backing-store failure is an
    // internal error (500) that a retry won't fix — don't conflate them (#301).
    let won_base = match turnstile_cas(state, store, &tenant, &disk_hash, &actor, expected_base)
        .await
        .map_err(map_turnstile_err)?
    {
        TurnstileClaim::Won(base) => Some(base),
        TurnstileClaim::NoTurnstile => None,
        // No-op publish (disk already equals this draft). Refusing it — rather
        // than mirroring identical content — is what keeps the turnstile a real
        // mutual-exclusion claim (a no-op CAS would falsely win; see #301). 422,
        // NOT 409: there is no conflict to retry, there is simply nothing to do.
        TurnstileClaim::AlreadyCurrent => {
            return Err(ApiError::UnprocessableEntity(
                "the draft already matches the live on-disk set — nothing to publish".into(),
            ))
        }
    };
    let mirror_result = match expected_base {
        Some(base) => {
            match state.mirror_manifest_set_to_disk_from_base(&tenant, &draft.content, base) {
                Err(waygate_upstream::UpstreamError::StaleBase) => {
                    turnstile_rollback(store, won_base, &disk_hash, &actor).await;
                    return Err(ApiError::Conflict(
                        "the live manifest set changed after the write turnstile was claimed; \
                         call gateway-admin.get_action_context and propose the change again"
                            .to_owned(),
                    ));
                }
                result => result.map_err(|error| error.to_string()),
            }
        }
        None => state.mirror_manifest_set_to_disk(&tenant, &draft.content),
    };
    if let Err(e) = mirror_result {
        turnstile_rollback(store, won_base, &disk_hash, &actor).await;
        return Err(ApiError::Internal(format!(
            "the on-disk write failed: {e}. The publish was not recorded \
             (ledger unchanged); if the write failed partway, the next reload \
             reconciles the on-disk set."
        )));
    }
    let bundle = store
        .publish(&tenant, id, &actor)
        .await
        .map_err(map_manifest_err)?;
    // Doorbell: notify AFTER the ledger append, per the doorbell contract — so
    // a ledger failure never tells the fleet to reload an unrecorded change. The
    // hash is the canonical on-disk hash (matches the pointer/disk), not the raw
    // bundle hash.
    let _ = store.notify_reload(&disk_hash).await;
    // AdminMutation evidence: publishing changes which manifest set boot
    // and SIGHUP will activate, so it's the most operationally-relevant
    // action here and must land in the audit trail.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("server_manifest.publish", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(p)
                .with_reason(format!(
                    "published manifest bundle version={} id={} hash={}",
                    bundle.version, bundle.id, bundle.content_hash
                )),
        )
        .await;
    Ok(bundle)
}

/// Stage a manifest-set draft from inline `content` and immediately publish it —
/// the propose-path equivalent of the dashboard's "Save draft" + "Publish" as ONE
/// step. Validates (non-empty + `parse_manifest_set`), stages the draft in the
/// caller's tenant, then publishes under the shared write lock with
/// `proposed_base` as the turnstile CAS base. The mirror-to-disk / ledger
/// ordering and audit remain identical to a dashboard publish, while an agent
/// proposal is bound to the live snapshot it inspected. A no-op (content already
/// == the live on-disk set) surfaces as the same 422 the REST publish returns; a
/// failed publish leaves the staged draft behind (unpublished — harmless, like a
/// dashboard "Save draft" that was never published).
pub(crate) async fn stage_and_publish_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    content: &str,
    author: Option<&str>,
    proposed_base: &str,
) -> ApiResult<ManifestBundle> {
    let store = manifest_store(state)?;
    if content.trim().is_empty() {
        return Err(ApiError::BadRequest("manifest content is empty".into()));
    }
    // Validate the set parses (+ per-entry invariants + dup-name rejection) BEFORE
    // staging — the same guard `create_draft` runs — so we never stage a draft the
    // loader would later reject.
    waygate_upstream::parse_manifest_set(content)
        .map_err(|e| ApiError::BadRequest(format!("manifest set is not valid: {e}")))?;
    let tenant = caller_tenant(principal);
    let draft = store
        .create_draft(&tenant, content, author)
        .await
        .map_err(map_manifest_err)?;
    // Bind the approved replacement to the snapshot the maker inspected. The
    // turnstile performs the authoritative check after the draft is staged but
    // before any live-disk or ledger mutation.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    publish_bundle_locked(state, principal, draft.id, Some(proposed_base)).await
}

/// Canonical 503 detail for paths that require the on-disk manifest source.
pub(crate) const MANIFEST_SERVERS_DIR_UNAVAILABLE: &str = "manifest servers_dir is not configured";

/// Merge a PARTIAL manifest set (`content` — the servers to add or replace, keyed
/// by `name`) into the current on-disk set. Returns `(merged_yaml, base_hash)`:
/// the reconstructed full-set YAML, and the canonical hash of the on-disk set it
/// merged INTO — the turnstile CAS base, so the publish can fail closed if a
/// concurrent write moved the live set off that base (see `upsert_servers_core`).
/// The on-disk set is the source of truth (`read_manifest_set_from_disk`), so the
/// result reflects everything currently deployed plus the upserts. Shared by
/// [`upsert_servers_core`] (which publishes the result) and the
/// `manifest.upsert_servers` preview (which replays it, discarding the hash), so
/// the previewed effect is exactly what executes. Add/replace only; selected-name
/// removal uses `manifest.remove_servers`.
pub(crate) fn merge_upserts_into_live_set(
    state: &AdminState,
    content: &str,
) -> ApiResult<(String, String)> {
    if content.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "no servers to upsert (empty content)".into(),
        ));
    }
    // Validate the upsert set (per-entry invariants + dup-name rejection WITHIN the
    // upserts) before touching the live set.
    let upserts = waygate_upstream::parse_manifest_set(content)
        .map_err(|e| ApiError::BadRequest(format!("servers to upsert are not valid: {e}")))?;
    if upserts.is_empty() {
        return Err(ApiError::BadRequest(
            "no servers to upsert (empty manifest set)".into(),
        ));
    }
    // Base = the live on-disk set (source of truth), NOT the ledger active bundle,
    // so a concurrent out-of-band `servers/*.yaml` edit is the merge base rather
    // than something the reconstructed publish silently clobbers. Capture its hash
    // as the CAS base the publish will require.
    let (mut set, base_hash) = match state.read_manifest_set_from_disk() {
        Some(Ok(pair)) => pair,
        Some(Err(e)) => {
            return Err(ApiError::Internal(format!(
                "could not read the live manifest set to merge into: {e}"
            )));
        }
        // No `servers_dir` wired (dev/test) — nothing to merge into or mirror to.
        None => {
            return Err(ApiError::ServiceUnavailable(
                MANIFEST_SERVERS_DIR_UNAVAILABLE,
            ));
        }
    };
    // Upsert by name: an existing name is replaced, a new name is added.
    for (name, manifest) in upserts {
        set.insert(name, manifest);
    }
    let merged = waygate_upstream::serialize_manifest_set(&set).map_err(|e| {
        ApiError::Internal(format!("could not serialize the merged manifest set: {e}"))
    })?;
    Ok((merged, base_hash))
}

/// Remove named servers from the current on-disk manifest set. Returns the
/// reconstructed full-set YAML and the canonical hash of the live set it was
/// derived from, so publication can be bound to that exact snapshot.
///
/// Every requested name must exist. Silently ignoring an unknown name would
/// let an approved proposal claim a removal that did not occur.
pub(crate) fn remove_servers_from_live_set(
    state: &AdminState,
    server_names: &[String],
    expected_base: Option<&str>,
) -> ApiResult<(String, String)> {
    if server_names.is_empty() {
        return Err(ApiError::BadRequest(
            "no servers to remove (empty server_names)".into(),
        ));
    }
    let mut requested = BTreeSet::new();
    for name in server_names {
        if name.is_empty() || name.trim() != name {
            return Err(ApiError::BadRequest(
                "server_names entries must be non-empty and have no surrounding whitespace".into(),
            ));
        }
        if !requested.insert(name.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "server_names contains duplicate entry {name:?}"
            )));
        }
    }

    let (mut set, base_hash) = match state.read_manifest_set_from_disk() {
        Some(Ok(pair)) => pair,
        Some(Err(e)) => {
            return Err(ApiError::Internal(format!(
                "could not read the live manifest set to remove from: {e}"
            )));
        }
        None => {
            return Err(ApiError::ServiceUnavailable(
                MANIFEST_SERVERS_DIR_UNAVAILABLE,
            ));
        }
    };
    // Check the authorized preparation witness before name membership. Context
    // discovery can withhold a snapshot whose names violate the manifest
    // exposure contract; a caller without that current witness must not turn
    // removal validation into an exact-name membership oracle.
    if expected_base.is_some_and(|expected| expected != base_hash) {
        return Err(ApiError::Conflict(
            "the live manifest set changed after these server removals were prepared — call \
             gateway-admin.get_action_context again and re-prepare the proposal"
                .to_owned(),
        ));
    }
    let missing: Vec<_> = requested
        .iter()
        .filter(|name| !set.contains_key(**name))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "cannot remove servers that are not in the live manifest set: {}",
            missing.join(", ")
        )));
    }
    for name in requested {
        set.remove(name);
    }
    let updated = waygate_upstream::serialize_manifest_set(&set).map_err(|e| {
        ApiError::Internal(format!(
            "could not serialize the manifest set after removal: {e}"
        ))
    })?;
    Ok((updated, base_hash))
}

/// Upsert one or more servers into the live manifest set and publish the result —
/// the small-`params` authoring path. `content` carries only the CHANGED servers
/// (a partial set), which are merged into the live on-disk set server-side; the
/// reconstructed full set is then published with the same turnstile /
/// mirror-before-ledger / doorbell / audit as every publish. `proposed_base`
/// is the preparation-context hash and must still match the base read under the
/// write lock. This is the path for large deployments and the common
/// single-server edit: unlike `stage_and_publish`, which carries the whole set
/// in `params`, the params here scale with the change, not the set — both
/// actions share one ceiling, so what differs is how much of the deployment a
/// change has to resend. This merge only adds or replaces; selected-name
/// removal uses `manifest.remove_servers`.
///
/// Concurrency — a concurrent publish must not silently clobber this upsert's
/// merge base. Two guards, mirroring the dashboard per-server edit path:
/// - **process-local**: hold `manifest_write_lock` across the read→publish so two
///   requests in THIS replica serialize (the second re-reads the updated base
///   instead of losing the CAS);
/// - **cross-replica**: bind the publish turnstile CAS to `base_hash` — the
///   on-disk hash the merge read — so if another REPLICA published since (the
///   lock is process-local, the NFS `servers/*.yaml` is shared), the CAS is Lost
///   (→ `Precondition`, re-propose) instead of overwriting their change from a
///   stale base. The write lock alone is NOT enough across replicas — that is the
///   whole reason `base_hash` is threaded into `publish_bundle_locked`.
///
/// We call the lock-free [`publish_bundle_locked`] directly (holding the lock; the
/// re-locking `publish_bundle_core` would deadlock the non-reentrant mutex).
pub(crate) async fn upsert_servers_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    content: &str,
    author: Option<&str>,
    proposed_base: &str,
) -> ApiResult<ManifestBundle> {
    let store = manifest_store(state)?;
    let tenant = caller_tenant(principal);
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Read the merge base + serialize the reconstructed set UNDER the lock; keep
    // the base hash for the CAS.
    let (merged, base_hash) = merge_upserts_into_live_set(state, content)?;
    if base_hash != proposed_base {
        return Err(ApiError::Conflict(
            "the live manifest set changed after these server updates were prepared — call \
             gateway-admin.get_action_context again and re-prepare the proposal"
                .to_owned(),
        ));
    }
    // Stage the reconstructed full set, then publish it via the lock-free core (we
    // already hold the lock), binding the CAS to `base_hash` so a concurrent
    // publish since the merge read loses rather than clobbers. A no-op (merged ==
    // base) surfaces as the same 422 the publish path returns.
    let draft = store
        .create_draft(&tenant, &merged, author)
        .await
        .map_err(map_manifest_err)?;
    publish_bundle_locked(state, principal, draft.id, Some(&base_hash)).await
}

/// Remove selected servers from the live manifest set and publish the
/// reconstructed full set through the same conditional mirror and ledger path
/// as other manifest changes.
pub(crate) async fn remove_servers_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    server_names: &[String],
    author: Option<&str>,
    proposed_base: &str,
) -> ApiResult<ManifestBundle> {
    let store = manifest_store(state)?;
    let tenant = caller_tenant(principal);
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    let (updated, base_hash) =
        remove_servers_from_live_set(state, server_names, Some(proposed_base))?;
    let draft = store
        .create_draft(&tenant, &updated, author)
        .await
        .map_err(map_manifest_err)?;
    publish_bundle_locked(state, principal, draft.id, Some(&base_hash)).await
}

#[utoipa::path(
    post,
    path = "/api/v1/server_manifests/{version}/rollback",
    tag = "server_manifests",
    params(("version" = i32, Path, description = "Previously-published version to roll back to")),
    responses(
        (status = 200, description = "Rolled back: target version's content re-published as a new active bundle", body = ManifestBundle),
        (status = 404, description = "No previously-published bundle at that version in the caller's tenant", body = ApiErrorBody),
        (status = 409, description = "Turnstile lost: another replica changed the on-disk config since this page loaded; reload and retry", body = ApiErrorBody),
        (status = 422, description = "No-op: that version already matches the live on-disk set; nothing to roll back", body = ApiErrorBody),
        (status = 503, description = "Manifest store not configured (no database)", body = ApiErrorBody),
        (status = 500, description = "Manifest store write failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn rollback_bundle(
    State(state): State<Arc<AdminState>>,
    Path(version): Path<i32>,
    principal: Option<Extension<Principal>>,
) -> ApiResult<Json<ManifestBundle>> {
    let p = principal.as_ref().map(|Extension(p)| p);
    Ok(Json(rollback_bundle_core(&state, p, version).await?))
}

/// Shared manifest-rollback path: write lock → resolve target version →
/// turnstile CAS → mirror-to-disk → ledger rollback (roll-forward) → doorbell →
/// AdminMutation audit. The REST [`rollback_bundle`] handler calls this with no
/// proposal-time base; the `manifest.rollback` executor calls
/// [`rollback_bundle_core_from_base`] with its captured base. Both converge on
/// the same locked mutation path. Tenant + actor are resolved from `principal`.
/// Returns the new active bundle.
pub(crate) async fn rollback_bundle_core(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    version: i32,
) -> ApiResult<ManifestBundle> {
    rollback_bundle_core_from_base(state, principal, version, None).await
}

/// Roll forward a historical full set only while the live manifest still
/// matches the proposal-time base. Direct dashboard/REST rollback passes no
/// expected base and preserves its existing re-read-now behavior.
pub(crate) async fn rollback_bundle_core_from_base(
    state: &Arc<AdminState>,
    principal: Option<&Principal>,
    version: i32,
    expected_base: Option<&str>,
) -> ApiResult<ManifestBundle> {
    let store = manifest_store(state)?;
    let p = principal;
    let tenant = caller_tenant(principal);
    let actor = caller_actor(principal);
    // File-as-truth: serialize and mirror the rolled-back set onto the
    // on-disk source of truth so the rollback actually takes effect on
    // boot/SIGHUP, not just in the ledger.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Turnstile + mirror BEFORE the ledger transition. Fetch version
    // V's content first; rollback_to re-publishes it as a new active version.
    let target = store
        .get_by_version(&tenant, version)
        .await
        .map_err(map_manifest_err)?;
    // Canonical on-disk hash for the turnstile, same as publish_bundle (#301).
    let disk_hash = canonical_disk_hash(&target.content).map_err(|e| {
        ApiError::Internal(format!("target content is not a valid manifest set: {e}"))
    })?;
    let won_base = match turnstile_cas(state, store, &tenant, &disk_hash, &actor, expected_base)
        .await
        .map_err(map_turnstile_err)?
    {
        TurnstileClaim::Won(base) => Some(base),
        TurnstileClaim::NoTurnstile => None,
        // No-op rollback (disk already equals this version) — see publish_bundle.
        TurnstileClaim::AlreadyCurrent => {
            return Err(ApiError::UnprocessableEntity(
                "that version already matches the live on-disk set — nothing to roll back".into(),
            ))
        }
    };
    let mirror_result = match expected_base {
        Some(base) => {
            match state.mirror_manifest_set_to_disk_from_base(&tenant, &target.content, base) {
                Err(waygate_upstream::UpstreamError::StaleBase) => {
                    turnstile_rollback(store, won_base, &disk_hash, &actor).await;
                    return Err(ApiError::Conflict(
                    "the live manifest set changed after the write turnstile was claimed; call \
                     gateway-admin.get_action_context and propose the rollback again"
                        .to_owned(),
                ));
                }
                result => result.map_err(|error| error.to_string()),
            }
        }
        None => state.mirror_manifest_set_to_disk(&tenant, &target.content),
    };
    if let Err(e) = mirror_result {
        turnstile_rollback(store, won_base, &disk_hash, &actor).await;
        return Err(ApiError::Internal(format!(
            "the on-disk write failed: {e}. The rollback was not recorded \
             (ledger unchanged); if the write failed partway, the next reload \
             reconciles the on-disk set."
        )));
    }
    let bundle = store
        .rollback_to(&tenant, version, &actor)
        .await
        .map_err(map_manifest_err)?;
    // Doorbell: notify AFTER the ledger append (see publish_bundle); canonical
    // on-disk hash, not the raw bundle hash (#301).
    let _ = store.notify_reload(&disk_hash).await;
    // AdminMutation evidence: rollback re-activates an older manifest
    // set, equally operationally-relevant as publish. Record the version
    // rolled back FROM (the request) and the new active version.
    state
        .evidence
        .record_best_effort(
            AuditEvent::new("server_manifest.rollback", AuditOutcome::Success)
                .with_category(EvidenceCategory::AdminMutation)
                .with_principal(p)
                .with_reason(format!(
                    "rolled back to manifest version={version}; new active version={} hash={}",
                    bundle.version, bundle.content_hash
                )),
        )
        .await;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use waygate_mcp::audit::{InMemorySink, SharedEvidence};
    use waygate_upstream::pool::UpstreamPool;

    /// Write a manifest-set YAML to a fresh unique tmpdir (one file per manifest,
    /// the canonical on-disk layout the gateway loads). Caller removes it.
    fn write_servers_dir(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mbtest-servers-{}", Uuid::new_v4()));
        let set = waygate_upstream::parse_manifest_set(content).unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &set).unwrap();
        dir
    }

    async fn state_with_servers_dir(dir: std::path::PathBuf) -> Arc<AdminState> {
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let evidence: SharedEvidence = Arc::new(InMemorySink::default());
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
        Arc::new(state.with_servers_dir(dir))
    }

    const S0: &str = "\
- name: alpha
  transport: http
  url: http://alpha/mcp
";

    #[tokio::test]
    async fn merge_preserves_live_set_and_returns_its_hash_as_cas_base() {
        // Live on-disk set = one server, `alpha`.
        let dir = write_servers_dir(S0);
        let state = state_with_servers_dir(dir.clone()).await;

        // The base the CAS must bind to is the hash of the CURRENT on-disk set.
        let Some(Ok((_live, expected_base))) = state.read_manifest_set_from_disk() else {
            panic!("expected a readable on-disk set");
        };

        // Upsert a NEW server `beta`.
        let upsert = "- name: beta\n  transport: http\n  url: http://beta/mcp\n";
        let (merged, base_hash) =
            merge_upserts_into_live_set(&state, upsert).expect("merge succeeds");

        // (1) base_hash IS the live-set hash — so the publish CAS fails closed if a
        // concurrent write moved the live set off THIS base, instead of clobbering
        // it from a stale base.
        assert_eq!(
            base_hash, expected_base,
            "base_hash must be the live on-disk set's hash"
        );

        // (2) The merge PRESERVES `alpha` and ADDS `beta` — an upsert merges into
        // the live set, it never replaces it (the anti-clobber property).
        let set = waygate_upstream::parse_manifest_set(&merged).unwrap();
        assert!(
            set.contains_key("alpha"),
            "upsert must preserve the live server"
        );
        assert!(set.contains_key("beta"), "upsert must add the new server");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn merge_replaces_an_existing_server_by_name() {
        let dir = write_servers_dir(S0);
        let state = state_with_servers_dir(dir.clone()).await;

        // Upsert `alpha` with a new url — replaces the existing entry by name,
        // does not duplicate it.
        let upsert = "- name: alpha\n  transport: http\n  url: http://alpha-v2/mcp\n";
        let (merged, _base) = merge_upserts_into_live_set(&state, upsert).expect("merge succeeds");

        let set = waygate_upstream::parse_manifest_set(&merged).unwrap();
        assert_eq!(set.len(), 1, "replacing alpha must not add a duplicate");
        assert!(
            merged.contains("alpha-v2"),
            "the replaced entry must carry the new url: {merged}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn remove_selected_servers_preserves_the_rest_and_binds_the_live_base() {
        let dir = write_servers_dir(
            "\
- name: alpha
  transport: http
  url: http://alpha/mcp
- name: beta
  transport: http
  url: http://beta/mcp
",
        );
        let state = state_with_servers_dir(dir.clone()).await;
        let Some(Ok((_live, expected_base))) = state.read_manifest_set_from_disk() else {
            panic!("expected a readable on-disk set");
        };

        let (updated, base_hash) =
            remove_servers_from_live_set(&state, &["alpha".to_owned()], None)
                .expect("remove succeeds");
        let set = waygate_upstream::parse_manifest_set(&updated).unwrap();

        assert_eq!(base_hash, expected_base);
        assert!(!set.contains_key("alpha"), "selected server is removed");
        assert!(set.contains_key("beta"), "unselected server is preserved");

        let err = remove_servers_from_live_set(&state, &["missing".to_owned()], None)
            .expect_err("unknown server must fail instead of becoming a false-success removal");
        assert!(
            err.detail().contains("missing"),
            "error identifies the server that is not live"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
