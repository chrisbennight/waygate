//! `/api/v1/admin/tenants/*` — canonical tenants registry CRUD.
//!
//! Companion to `waygate_tenants::PgTenantStore`.
//! Endpoints:
//!
//! - `GET    /api/v1/admin/tenants`        — list every tenant
//! - `POST   /api/v1/admin/tenants`        — create
//! - `GET    /api/v1/admin/tenants/{id}`   — read
//! - `PATCH  /api/v1/admin/tenants/{id}`   — update display_name and/or status
//! - `DELETE /api/v1/admin/tenants/{id}`   — hard-delete
//!
//! ## Scope
//!
//! Unlike SCIM / RBAC handlers, the tenants registry is GLOBAL
//! (not per-tenant scoped). It lives outside the per-tenant
//! authorization fabric — only operators with `mcp:admin` see
//! it. The registry is the source of truth the bearer
//! middleware joins against (`waygate_tenants::enforce`) to
//! enforce "tenant exists + status=active" on every
//! authenticated request.
//!
//! ## Audit posture
//!
//! Tenant lifecycle events are compliance-significant
//! (creating a tenant grants access to a whole new fabric;
//! suspending one cuts every principal off). Same fail-closed
//! `record_required` discipline as RBAC: audit failure
//! → HTTP 500 with operator-visible "verify via list" detail.
//! The transactional-audit refactor tracked in issue #151
//! would tighten this further.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use waygate_core::TenantId;
use waygate_oidc::Principal;
use waygate_tenants::{Tenant, TenantError, TenantStatus};

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

/// Result of the authorization-safe tenant lifecycle transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantDeleteOutcome {
    pub tenant_deleted: bool,
    pub policy_bundles_deleted: u64,
}

/// Cross-domain tenant deletion seam. The composition layer owns this
/// transaction because it spans the canonical tenant registry and the policy
/// bundle ledger, which remain owned by their respective domain crates.
#[async_trait]
pub trait TenantLifecycleStore: Send + Sync {
    async fn delete_with_policy_bundles(
        &self,
        id: &str,
    ) -> Result<TenantDeleteOutcome, TenantError>;
}

pub struct PgTenantLifecycleStore {
    pool: sqlx::PgPool,
}

impl PgTenantLifecycleStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantLifecycleStore for PgTenantLifecycleStore {
    async fn delete_with_policy_bundles(
        &self,
        id: &str,
    ) -> Result<TenantDeleteOutcome, TenantError> {
        let mut tx = self.pool.begin().await.map_err(TenantError::Sqlx)?;
        // Tenant deletion intentionally removes its Code Mode history. The
        // journal's append-only trigger admits that cascade only when the
        // deleting transaction declares this narrow retention authority.
        sqlx::query("SET LOCAL app.codemode_retention_delete = 'enabled'")
            .execute(&mut *tx)
            .await
            .map_err(TenantError::Sqlx)?;
        // Lock the parent before counting or deleting children. Foreign-key
        // checks for concurrent policy-bundle inserts take a conflicting key
        // share lock, so an in-flight writer either commits before this count
        // or waits and then fails after the parent deletion commits.
        let tenant_exists =
            sqlx::query_scalar::<_, String>(r#"SELECT id FROM tenants WHERE id = $1 FOR UPDATE"#)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(TenantError::Sqlx)?
                .is_some();
        if !tenant_exists {
            tx.commit().await.map_err(TenantError::Sqlx)?;
            return Ok(TenantDeleteOutcome {
                tenant_deleted: false,
                policy_bundles_deleted: 0,
            });
        }
        let policy_bundles_deleted = sqlx::query_scalar::<_, i64>(
            r#"SELECT count(*) FROM policy_bundles WHERE tenant_id = $1"#,
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(TenantError::Sqlx)?
        .try_into()
        .expect("COUNT(*) is non-negative");
        let tenant_deleted = sqlx::query(r#"DELETE FROM tenants WHERE id = $1"#)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(TenantError::Sqlx)?
            .rows_affected()
            > 0;
        tx.commit().await.map_err(TenantError::Sqlx)?;
        Ok(TenantDeleteOutcome {
            tenant_deleted,
            policy_bundles_deleted,
        })
    }
}

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/tenants",
            get(list_tenants).post(create_tenant),
        )
        .route(
            "/api/v1/admin/tenants/{id}",
            get(get_tenant).patch(update_tenant).delete(delete_tenant),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// Tenant id. Validated against [`TenantId::parse`] —
    /// alphanumeric + dash, length cap. The same string is used
    /// as the `tenant_id` column value everywhere else in the
    /// schema.
    pub id: String,
    pub display_name: String,
    /// Optional initial status. Defaults to `active`. Lets
    /// operators provision a tenant in `suspended` state for
    /// pre-flight checks before opening access.
    #[serde(default = "default_status")]
    pub status: TenantStatus,
}

fn default_status() -> TenantStatus {
    TenantStatus::Active
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    /// `null` ⇒ leave display_name unchanged.
    #[serde(default)]
    pub display_name: Option<String>,
    /// `null` ⇒ leave status unchanged. Use this to
    /// activate / suspend an existing tenant.
    #[serde(default)]
    pub status: Option<TenantStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TenantListResponse {
    pub items: Vec<Tenant>,
}

/// Response shape for POST /api/v1/admin/tenants.
/// Adds an `onboarding` block alongside the tenant row so
/// operators see immediately which side-effects fired, which
/// were skipped (because the relevant store wasn't wired up),
/// and which failed (with reason).
///
/// The plaintext SCIM API key is included exactly once here on
/// success — it cannot be re-fetched. Operators must capture it
/// during the response and hand it to their IdP's SCIM client
/// config. On failure to mint, the field is `None` and the
/// `scim_api_key.status` says why.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantOnboardingResponse {
    pub tenant: Tenant,
    pub onboarding: OnboardingReport,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OnboardingReport {
    /// Result of cloning the `default` tenant's currently-active
    /// policy bundle as v1 of the new tenant's bundle history.
    pub policy_bundle: SideEffectStatus,
    /// Result of seeding a `tenant_admin` role granting
    /// mcp:read + mcp:invoke + mcp:admin + scim:read.
    pub tenant_admin_role: SideEffectStatus,
    /// Result of minting a SCIM provisioning API key with
    /// scope=`scim:write scim:read` scoped to the new tenant.
    pub scim_api_key: ScimApiKeyOutcome,
    /// Result of seeding the default API-key mint
    /// profiles (read_only, developer, service_account). No
    /// default `admin` profile by design — operators must
    /// explicitly create one to mint admin-scoped keys.
    pub api_key_profiles: SideEffectStatus,
    /// Pending reviews of the already-loaded skill catalog; never approvals.
    pub skill_reviews: SideEffectStatus,
}

/// One side-effect's outcome. `"seeded"` ⇒ ran successfully.
/// `"skipped"` ⇒ the relevant store wasn't wired up (e.g. no
/// PolicyStore in this deployment) or a precondition didn't hold
/// (e.g. `default` has no active bundle to clone from). `"failed"`
/// ⇒ the store call returned an error; the tenant row itself was
/// still created, but the operator should investigate before
/// handing this tenant out.
#[derive(Debug, Serialize, ToSchema)]
pub struct SideEffectStatus {
    pub status: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SideEffectStatus {
    fn seeded() -> Self {
        Self {
            status: "seeded",
            detail: None,
        }
    }
    fn skipped(detail: impl Into<String>) -> Self {
        Self {
            status: "skipped",
            detail: Some(detail.into()),
        }
    }
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: "failed",
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScimApiKeyOutcome {
    pub status: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The plaintext `mcpgw_…` API key. Returned exactly once,
    /// on the create response. Operators must capture it now.
    /// `None` when status is not `seeded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// The minted key's row id. Useful for operators who want to
    /// rotate or revoke this provisioning key later. `None` when
    /// status is not `seeded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants",
    tag = "tenants",
    responses(
        (status = 200, description = "Every registered tenant, alphabetised by id", body = TenantListResponse),
        (status = 503, description = "Tenants store not configured (no Postgres pool)", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_tenants(
    State(state): State<Arc<AdminState>>,
    Extension(_principal): Extension<Principal>,
) -> ApiResult<Json<TenantListResponse>> {
    let store = state.identity.tenants.require()?;
    let items = store.list().await.map_err(map_tenant_err)?;
    Ok(Json(TenantListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tenants",
    tag = "tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created. Body includes the tenant row and an `onboarding` report describing which side-effects (policy bundle clone, tenant_admin role seed, SCIM API key mint, default api_key_profiles seed of read_only/developer/service_account, pending skill reviews) succeeded. The SCIM API key plaintext is included here exactly once; capture it now.", body = TenantOnboardingResponse),
        (status = 400, description = "Invalid input (bad tenant id format, empty display_name)", body = ApiErrorBody),
        (status = 409, description = "Tenant id already exists", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed (mutation committed; verify via GET /tenants)", body = ApiErrorBody),
        (status = 503, description = "Tenants store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_tenant(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreateTenantRequest>,
) -> Response {
    let store = match state.identity.tenants.require() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = validate_tenant_input(&req.id, &req.display_name) {
        return e.into_response();
    }
    let tenant = match store.create(&req.id, &req.display_name, req.status).await {
        Ok(t) => t,
        Err(e) => return map_tenant_err(e).into_response(),
    };
    // create_tenant must also invalidate the bearer-layer cache. A
    // token whose `tenant` claim hit the resolver before this row
    // existed would have cached `Missing → tenant_not_found`; without
    // invalidation that principal stays denied for up to the 60s TTL
    // even after the operator creates the tenant. Same ordering as
    // update/delete: drop before audit so the new tenant is usable
    // immediately even if the audit sink hiccups.
    invalidate_tenant_cache(&state, &tenant.id).await;
    if let Err(e) = crate::admin_mutation::record_admin_mutation(
        &state,
        "tenants",
        "GET /api/v1/admin/tenants",
        &tenant.id,
        Some(&principal),
        "tenants.create",
        format!(
            "tenant id={} display_name={} status={}",
            tenant.id, tenant.display_name, tenant.status
        ),
    )
    .await
    {
        return e.into_response();
    }

    // Onboarding side-effects.
    //
    // Each one runs unconditionally (no opt-out flag yet — the
    // scope is "every fresh tenant gets these"), captures
    // its outcome in the response, and audits separately. Tenant
    // creation itself has already succeeded by the time we
    // reach here, so a side-effect failure does NOT roll the
    // tenant row back — the operator gets a 201 with an
    // `onboarding` block telling them what worked and what
    // didn't, and can DELETE + retry or fix the failing store
    // and re-seed manually. Issue #151's transactional refactor
    // would tighten this; for now best-effort with structured
    // reporting is the right shape for compliance-significant
    // mutations that can't easily share a single DB transaction
    // across the four stores.
    let policy_bundle = seed_policy_bundle(&state, &tenant.id, &principal).await;
    let tenant_admin_role = seed_tenant_admin_role(&state, &tenant.id, &principal).await;
    let scim_api_key = mint_scim_api_key(&state, &tenant.id, &principal).await;
    let api_key_profiles = seed_default_api_key_profiles(&state, &tenant.id, &principal).await;
    let skill_reviews = crate::skill_reviews::seed_tenant(&state, &tenant.id).await;

    // The response body contains the one-shot plaintext SCIM API
    // key in `scim_api_key.api_key` on the happy path. Even though the
    // POST is mcp:admin-gated, intermediary caches (corporate
    // egress proxies, browser back-button stacks) could persist
    // the response and let a later observer extract the secret.
    // Mark the response no-store with the same headers the
    // existing dashboard reveal at `api_keys::reveal` uses, so
    // the "shown once" property the response carries is also
    // enforced at the HTTP layer. Always — even on `skipped` /
    // `failed` outcomes — because (a) the operator's request
    // intent is "mint a key" regardless of result, and
    // (b) `failed`/`skipped` paths still contain operator-
    // visible detail strings that shouldn't be retained by
    // shared caches.
    let mut resp = (
        StatusCode::CREATED,
        Json(TenantOnboardingResponse {
            tenant,
            onboarding: OnboardingReport {
                policy_bundle,
                tenant_admin_role,
                scim_api_key,
                api_key_profiles,
                skill_reviews,
            },
        }),
    )
        .into_response();
    crate::api_keys::no_store(&mut resp);
    resp
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants/{id}",
    tag = "tenants",
    params(("id" = String, Path, description = "Tenant id")),
    responses(
        (status = 200, description = "Tenant", body = Tenant),
        (status = 404, description = "Tenant not found", body = ApiErrorBody),
        (status = 503, description = "Tenants store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn get_tenant(
    State(state): State<Arc<AdminState>>,
    Extension(_principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Tenant>> {
    let store = state.identity.tenants.require()?;
    match store.get(&id).await.map_err(map_tenant_err)? {
        Some(t) => Ok(Json(t)),
        None => Err(ApiError::NotFoundDyn(format!("tenant {id}"))),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/tenants/{id}",
    tag = "tenants",
    params(("id" = String, Path, description = "Tenant id")),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "Updated tenant", body = Tenant),
        (status = 400, description = "Invalid input (empty display_name)", body = ApiErrorBody),
        (status = 404, description = "Tenant not found", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Tenants store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn update_tenant(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Response {
    match update_tenant_core(
        &state,
        &id,
        req.display_name.as_deref(),
        req.status,
        &principal,
    )
    .await
    {
        Ok(Some(t)) => Json(t).into_response(),
        Ok(None) => ApiError::NotFoundDyn(format!("tenant {id}")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared tenant-update path: validate → `store.update` →
/// invalidate the bearer-layer tenant-status cache → audit. Both the
/// REST `update_tenant` handler and the dashboard's inline edit form
/// call this so the HTML and JSON surfaces can't drift. `Ok(None)` ⇒
/// no such tenant id.
///
/// The display_name bounds enforced here are
/// the same `validate_display_name` the POST create path uses — a
/// tenant created with a valid name can't be patched to oversized junk.
///
/// Cache-then-audit ordering is preserved: the bearer-layer
/// status cache is invalidated BEFORE the audit write, so a freshly
/// suspended tenant cuts off immediately even if the audit-sink INSERT
/// then fails (which surfaces as an `Err` → 500 on REST / error banner
/// on the dashboard), rather than staying accessible for up to 60s on
/// an audit hiccup.
pub(crate) async fn update_tenant_core(
    state: &Arc<AdminState>,
    id: &str,
    display_name: Option<&str>,
    status: Option<TenantStatus>,
    actor: &Principal,
) -> Result<Option<Tenant>, ApiError> {
    let store = state.identity.tenants.require()?;
    if let Some(name) = display_name {
        validate_display_name(name)?;
    }
    match store.update(id, display_name, status).await {
        Ok(Some(t)) => {
            invalidate_tenant_cache(state, &t.id).await;
            crate::admin_mutation::record_admin_mutation(
                state,
                "tenants",
                "GET /api/v1/admin/tenants",
                &t.id,
                Some(actor),
                "tenants.update",
                format!(
                    "tenant id={} display_name={} status={}",
                    t.id, t.display_name, t.status
                ),
            )
            .await?;
            Ok(Some(t))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(map_tenant_err(e)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/tenants/{id}",
    tag = "tenants",
    params(("id" = String, Path, description = "Tenant id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Tenant not found", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Tenants store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_tenant(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    match delete_tenant_core(&state, &id, &principal).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => ApiError::NotFoundDyn(format!("tenant {id}")).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared tenant-delete path: prefetch (for the audit reason) → best-effort
/// onboarding-residue cleanup → atomic tenant + policy cleanup → cache
/// invalidate → audit. Both the REST `delete_tenant` handler and the dashboard's
/// per-row delete form call this so the destructive cascade can't be
/// reimplemented (or forgotten) on one surface. `Ok(false)` ⇒ no such
/// tenant id.
///
/// The onboarding side-effects create child rows in api_keys,
/// gateway_roles and API keys that have no cascading FK to `tenants`.
/// [`cleanup_onboarding_residue`] sweeps ordinary residue before the parent
/// mutation. Policy bundles cascade from the tenant registry row in the same
/// store transaction, so a concurrent policy write cannot leave an orphan or
/// expose an active tenant to the default-policy fallback. Routing the
/// dashboard delete through this core is the whole point: an inline delete
/// that skipped the cleanup would reopen the credential-resurrection hole.
pub(crate) async fn delete_tenant_core(
    state: &Arc<AdminState>,
    id: &str,
    actor: &Principal,
) -> Result<bool, ApiError> {
    let store = state.identity.tenants.require()?;
    let lifecycle = state.identity.tenant_lifecycle.require()?;
    // Establish existence and the audit description before any cleanup side
    // effect. A read failure or unknown id must leave every child store alone.
    let Some(pre) = store.get(id).await.map_err(map_tenant_err)? else {
        return Ok(false);
    };
    cleanup_onboarding_residue(state, id, actor).await;
    let deleted = lifecycle
        .delete_with_policy_bundles(id)
        .await
        .map_err(map_tenant_err)?;
    if deleted.tenant_deleted {
        // The lifecycle transaction is committed, so this replica must stop
        // serving the removed tenant's engine before the identifier can be
        // reused. Other replicas converge through the doorbell and poll below.
        if let Some(cedar) = state.policy.cedar.get() {
            let epoch = state.upstreams.tool_catalog_epoch();
            let change = epoch.begin_change();
            if cedar.remove_tenant(id) {
                change.commit();
            }
        }
        // Notify only after the transaction commits. Every replica must evict
        // the removed tenant engine, including when no bundle row was visible
        // to this transaction but an older replica still has one loaded.
        if let Some(policy_store) = state.policy.policy_store.get() {
            if let Err(error) = policy_store
                .notify_reload(&waygate_policy::content_hash(id))
                .await
            {
                tracing::warn!(%error, tenant = id, "tenant policy delete doorbell notify failed (poll backstop active)");
            }
        }
        if deleted.policy_bundles_deleted > 0 {
            let _ = crate::admin_mutation::record_admin_mutation(
                state,
                "tenants",
                "GET /api/v1/admin/tenants",
                id,
                Some(actor),
                "tenants.delete.cascade.policy_bundles_deleted",
                format!(
                    "deleted {} policy_bundles row(s) on tenant delete",
                    deleted.policy_bundles_deleted
                ),
            )
            .await;
        }
        let reason = format!(
            "tenant id={} display_name={} status={}",
            pre.id, pre.display_name, pre.status
        );
        // Invalidate before audit, so a deleted tenant cuts off
        // immediately even on audit-sink failure.
        invalidate_tenant_cache(state, id).await;
        crate::admin_mutation::record_admin_mutation(
            state,
            "tenants",
            "GET /api/v1/admin/tenants",
            id,
            Some(actor),
            "tenants.delete",
            reason,
        )
        .await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---- helpers --------------------------------------------------

/// Drop the bearer-layer tenant-status cache entry for
/// `id`. Awaited (moka invalidate is async) but in-process and
/// cheap — single moka segment-lock — so blocking the response
/// path on it is fine. No-op when the enricher isn't wired
/// (single-tenant deployments without DB, dev mode).
async fn invalidate_tenant_cache(state: &Arc<AdminState>, id: &str) {
    if let Some(enricher) = state.identity.tenant_enricher.as_ref() {
        enricher.invalidate(id).await;
    }
}

/// Cascade
/// cleanup of the rows the onboarding side-effects
/// (`seed_*` / `mint_*`) created. Called from the tenant DELETE
/// path BEFORE the tenants row goes away. Best-effort per remaining store:
/// a single store failure logs WARN but doesn't abort the other
/// cleanups or the parent delete — the alternative would leave
/// the operator unable to delete a tenant at all, which is
/// worse. Policy bundles are excluded from this contract and are removed in
/// the atomic parent transaction. Each cleanup is audited individually so the trail
/// records exactly which rows were swept by the cascade and
/// which (if any) lingered for operator follow-up.
async fn cleanup_onboarding_residue(state: &Arc<AdminState>, tenant_id: &str, actor: &Principal) {
    // 1. API keys — SOFT revoke. Hard-deleting would lose the
    // audit chain ("key X existed; was revoked"). Soft revoke
    // makes the rows fail the bearer lookup
    // (`revoked_at IS NULL`) so a re-created tenant id cannot
    // resurrect them. Includes the IdP-facing SCIM
    // provisioning key minted by `mint_scim_api_key` AND any
    // other operator-minted keys for this tenant.
    if let Some(api_keys) = state.identity.api_keys.get() {
        match api_keys.revoke_all_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.api_keys_revoked",
                    format!("soft-revoked {n} api_keys row(s) on tenant delete"),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: revoke_all_for_tenant failed; keys may remain valid \
                 if this tenant id is recreated — operator should investigate",
            ),
        }
    }
    // 2. RBAC — hard delete roles. ON DELETE CASCADE on the
    // composite FKs (migration 0021) handles role_assignments
    // and group_role_mappings in the same statement.
    if let Some(rbac) = state.identity.rbac.get() {
        match rbac.delete_all_roles_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.roles_deleted",
                    format!(
                        "deleted {n} gateway_roles row(s) on tenant delete (cascades to \
                         role_assignments + group_role_mappings)"
                    ),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: delete_all_roles_for_tenant failed",
            ),
        }
    }
    // Flush the RBAC
    // resolver cache so stale role/scope mappings don't keep
    // authorizing requests for the cache TTL (60s) after the
    // rows are gone. Matches the `invalidate_all()` pattern
    // RBAC mutations use elsewhere.
    if let Some(enricher) = state.identity.rbac_enricher.as_ref() {
        enricher.invalidate_all();
    }
    // Flush the API-key
    // validator's principal cache for the same reason. Without
    // this, a freshly-revoked SCIM key (or any other key for
    // this tenant) keeps authenticating against the in-memory
    // cache for the validator's TTL — re-creating the tenant
    // id inside that window resurrects the bearer despite the
    // DB row being revoked.
    if let Some(validator) = state.identity.api_key_validator.as_ref() {
        validator.invalidate_all().await;
    }
    // 3. API-key mint profiles. api_keys.profile_id is
    // ON DELETE SET NULL (migration 0026), so deleting a
    // tenant's profiles leaves existing keys intact (they got
    // soft-revoked by the api_keys cascade arm above) but
    // detached. A re-created tenant id starts with no
    // profiles, forcing the operator to re-author them rather
    // than inheriting orphan templates.
    if let Some(profiles) = state.identity.api_key_profiles.get() {
        match profiles.delete_all_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.api_key_profiles_deleted",
                    format!("deleted {n} api_key_profiles row(s) on tenant delete"),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: delete_all_api_key_profiles_for_tenant failed",
            ),
        }
    }
    // Rate-limit policies. ON DELETE CASCADE on
    // rate_limit_counters.policy_id (migration 0025) sweeps
    // the bucket state in the same statement. Skipped silently
    // when the store isn't wired (DB-less deployments).
    if let Some(rl) = state.policy.rate_limit_policies.get() {
        match rl.delete_all_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.rate_limit_policies_deleted",
                    format!(
                        "deleted {n} rate_limit_policies row(s) on tenant delete (cascades \
                         to rate_limit_counters via ON DELETE CASCADE)"
                    ),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: delete_all_rate_limit_policies_for_tenant failed",
            ),
        }
    }
    // Scope registry. Hard-delete the tenant's
    // local scope rows. `scopes.tenant_id` has no
    // FK cascade — consistent with api_keys / gateway_roles, whose
    // tenant cleanup is also app-code arms here — so without this a
    // re-created tenant id would inherit stale `source='local'` catalog
    // entries via `list_with_usage`'s `tenant_id = $1` match. Global
    // built-in / policy rows (tenant_id IS NULL) are untouched. Mirrors
    // the api_key_profiles arm above.
    if let Some(scopes) = state.identity.scopes.get() {
        match scopes.delete_all_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.scopes_deleted",
                    format!("deleted {n} tenant-local scopes row(s) on tenant delete"),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: delete_all_scopes_for_tenant failed",
            ),
        }
    }
    // Group catalog. Hard-delete only the
    // tenant's LOCAL groups (source='local', backfilled from api-key
    // labels / operator-defined) for the same reason as the scopes arm
    // — a re-created tenant id must not inherit stale local-group labels
    // that `GroupStore::list_with_usage` would surface via its
    // `tenant_id = $1` match. SCIM-provisioned groups (source='scim')
    // are deliberately left in place (see the note below). The
    // `scim_user_groups` membership cascades via ON DELETE CASCADE.
    if let Some(groups) = state.identity.groups.get() {
        match groups.delete_all_local_for_tenant(tenant_id).await {
            Ok(n) if n > 0 => {
                let _ = crate::admin_mutation::record_admin_mutation(
                    state,
                    "tenants",
                    "GET /api/v1/admin/tenants",
                    tenant_id,
                    Some(actor),
                    "tenants.delete.cascade.local_groups_deleted",
                    format!("deleted {n} tenant-local group row(s) on tenant delete"),
                )
                .await;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                tenant = tenant_id,
                error = ?e,
                "tenant delete cascade: delete_all_local_groups_for_tenant failed",
            ),
        }
    }
    // Note: scim_users and SCIM-provisioned (source='scim') scim_groups
    // are NOT cascaded. The tenant gate blocks any token claiming this
    // tenant, and a re-created tenant inheriting orphan SCIM rows would
    // have NO role/group mappings (those vanished with the roles in
    // step 2), so they cannot grant unintended access. Leaving SCIM rows
    // in place lets operators introspect the prior tenant's user list for
    // compliance after deletion. (LOCAL groups are swept by the arm
    // above — they're the api-key-label catalog, not provisioned identity.)
}

// ---- Tenant onboarding side-effects ----------------------------

/// Scopes granted to the seeded `tenant_admin` role. Mirrors the
/// dev synthetic admin's scope set minus `scim:write` — that
/// scope is reserved for the SCIM provisioning API key the IdP
/// uses, not for human admins logging into the dashboard. A
/// future follow-up could let operators override via env
/// or a config file; for now this pin keeps the contract simple.
const TENANT_ADMIN_SCOPES: &[&str] = &["mcp:invoke", "mcp:read", "mcp:admin", "scim:read"];

/// Scopes granted to the minted SCIM provisioning API key. Just
/// enough for an IdP's outbound SCIM client to provision +
/// inspect users in the new tenant; deliberately does NOT
/// include `mcp:admin` so the key can't escalate beyond its
/// SCIM scope even if leaked.
const SCIM_API_KEY_SCOPES: &[&str] = &["scim:write", "scim:read"];

/// Clone the `default` tenant's currently-active policy bundle
/// as v1 of the new tenant's bundle history (then publish so it's
/// live immediately). Skipped — not an error — when:
///
/// - The PolicyStore isn't wired (no Postgres pool / disabled policy storage,
///   so there is no tenant-scoped ledger source to clone or enforce).
/// - The new tenant *is* `default` (which would be self-clone).
/// - `default` has no published bundle yet (first-boot before
///   any imports). Operator can publish later via the regular
///   policy bundle endpoints.
///
/// On store error (cloning succeeded but publish failed, or vice
/// versa), the bundle is left in whatever partial state the
/// store wrote and the report carries the error detail. Operator
/// can inspect via `GET /api/v1/admin/policy_bundles` and decide.
async fn seed_policy_bundle(
    state: &Arc<AdminState>,
    new_tenant_id: &str,
    actor: &Principal,
) -> SideEffectStatus {
    let Some(policy_store) = state.policy.policy_store.get() else {
        return SideEffectStatus::skipped("policy store not configured");
    };
    if new_tenant_id == waygate_core::TenantId::default().as_str() {
        return SideEffectStatus::skipped("new tenant is `default`; nothing to clone from");
    }
    let default_active = match policy_store.active_bundle("default").await {
        Ok(b) => b,
        Err(e) => {
            // Distinguish NotFound (legitimate first-boot
            // state) from real errors; the policy-store's
            // PolicyError surfaces NotFound as a specific
            // variant we can match on. For unknown shapes,
            // log + skip rather than fail — the tenant is
            // still onboarded, just without a starter
            // bundle.
            let msg = e.to_string();
            if msg.contains("no published policy bundle") {
                return SideEffectStatus::skipped(
                    "default tenant has no published bundle yet; operator must publish one for \
                     this tenant manually",
                );
            }
            tracing::warn!(
                tenant = new_tenant_id,
                error = %e,
                "tenant onboarding: clone-from-default failed reading default's active bundle",
            );
            return SideEffectStatus::failed(format!("read default's bundle: {e}"));
        }
    };
    let actor_sub = actor.sub.as_str();
    let draft = match policy_store
        .create_draft(
            new_tenant_id,
            &default_active.content,
            // Clone the default tenant's attached policy tests into the new
            // tenant's seed bundle so a clone-from-default carries the gate.
            default_active.tests.as_ref(),
            Some(actor_sub),
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                tenant = new_tenant_id,
                error = %e,
                "tenant onboarding: create_draft failed",
            );
            return SideEffectStatus::failed(format!("create_draft: {e}"));
        }
    };
    // Publish gate — the SAME choke point the REST/dashboard/propose path
    // uses. The seed bundle clones the default tenant's content + attached
    // tests, but those tests evaluate under the NEW tenant here; a policy that
    // branches on `principal.tenant` can flip, so a clone that passed for the
    // default tenant may not hold for this one. Run the gate before the ledger
    // publish: a failing or malformed set BLOCKS the seed publish (the tenant
    // onboards without a starter bundle — the draft is left for the operator to
    // fix and publish manually) rather than silently publishing a bundle that
    // fails its own tests with no gate and no Denied audit.
    let new_tenant = match waygate_core::TenantId::parse(new_tenant_id) {
        Ok(t) => t,
        Err(e) => return SideEffectStatus::failed(format!("invalid new tenant id: {e}")),
    };
    if let Err(summary) = crate::policy_tests::evaluate_publish_gate(
        &draft.content,
        draft.tests.as_ref(),
        &new_tenant,
    ) {
        state
            .evidence
            .record_chained_best_effort(
                waygate_mcp::AuditEvent::new(
                    "policy_bundle.publish",
                    waygate_mcp::AuditOutcome::Denied,
                )
                .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                .with_principal(Some(actor))
                .with_reason(format!(
                    "clone-from-default seed publish for tenant {new_tenant_id} BLOCKED by \
                     its attached policy tests (evaluated under the new tenant): {summary}"
                )),
            )
            .await;
        return SideEffectStatus::failed(format!(
            "seed bundle blocked by its attached policy tests under the new tenant: {summary}"
        ));
    }
    let published = match policy_store
        .publish(new_tenant_id, draft.id, actor_sub)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                tenant = new_tenant_id,
                draft_id = %draft.id,
                error = %e,
                "tenant onboarding: publish failed; draft left intact for operator to inspect",
            );
            return SideEffectStatus::failed(format!("publish: {e}"));
        }
    };
    if let Err(error) = policy_store.notify_reload(&published.content_hash).await {
        tracing::warn!(%error, tenant = new_tenant_id, "tenant policy seed doorbell notify failed (poll backstop active)");
    }
    // Audit-of-record is best-effort here — the policy bundle is
    // already published and the tenant create already audited;
    // an additional audit row for the side-effect is a nice-to-
    // have but its absence shouldn't fail the onboarding.
    if let Err(e) = crate::admin_mutation::record_admin_mutation(
        state,
        "tenants",
        "GET /api/v1/admin/tenants",
        new_tenant_id,
        Some(actor),
        "tenants.onboarding.policy_bundle.seeded",
        format!(
            "cloned default's bundle (v{}, content_hash={}) as new tenant's v{}",
            default_active.version, default_active.content_hash, published.version,
        ),
    )
    .await
    {
        tracing::warn!(error = ?e, "tenant onboarding: policy_bundle seed audit failed");
    }
    SideEffectStatus::seeded()
}

/// Seed a `tenant_admin` role with the canonical admin scope set
/// for the new tenant. Idempotent on retry: the
/// `(tenant_id, name)` UNIQUE constraint surfaces a Conflict
/// the second time, which the report renders as `"failed"` with
/// the detail. Operators retrying onboarding after a partial
/// failure should DELETE the tenant first.
async fn seed_tenant_admin_role(
    state: &Arc<AdminState>,
    new_tenant_id: &str,
    actor: &Principal,
) -> SideEffectStatus {
    let Some(rbac) = state.identity.rbac.get() else {
        return SideEffectStatus::skipped("rbac store not configured");
    };
    let scopes: Vec<String> = TENANT_ADMIN_SCOPES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let description = Some("Seeded by tenant onboarding at create time");
    let role = match rbac
        .create_role(new_tenant_id, "tenant_admin", description, &scopes)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                tenant = new_tenant_id,
                error = %e,
                "tenant onboarding: tenant_admin role seed failed",
            );
            return SideEffectStatus::failed(e.to_string());
        }
    };
    if let Err(e) = crate::admin_mutation::record_admin_mutation(
        state,
        "tenants",
        "GET /api/v1/admin/tenants",
        new_tenant_id,
        Some(actor),
        "tenants.onboarding.tenant_admin_role.seeded",
        format!(
            "seeded tenant_admin role id={} with scopes={}",
            role.id,
            scopes.join(",")
        ),
    )
    .await
    {
        tracing::warn!(error = ?e, "tenant onboarding: tenant_admin role seed audit failed");
    }
    SideEffectStatus::seeded()
}

/// Mint a SCIM provisioning API key for the new tenant and
/// return its plaintext on success. The plaintext is only ever
/// returned here (the store hashes it with Argon2id before
/// persistence); operators must capture it during the POST
/// response and hand it to their IdP's SCIM client config. The
/// `sub` is the synthetic `system:scim-provisioner:<tenant>` so
/// audit rows attributing actions to this key are
/// distinguishable from human-driven traffic.
/// Seed the default API-key mint profiles for a fresh
/// tenant. Three profiles by design:
///
/// - `read_only` (mcp:read; 7d TTL; requires owner+reason) —
///   the safest mint operators reach for first.
/// - `developer` (mcp:invoke+mcp:read; 30d TTL; requires
///   owner+reason) — typical engineering use.
/// - `service_account` (mcp:invoke+mcp:read; 90d TTL; requires
///   owner+reason) — longer-lived automation.
///
/// No default `admin` profile. Operators must explicitly
/// create one before they can mint admin-scoped keys via the
/// profile flow. Makes "mint a key that can do anything" a
/// deliberate step, matching the security posture established
/// for the SCIM provisioning key.
async fn seed_default_api_key_profiles(
    state: &Arc<AdminState>,
    new_tenant_id: &str,
    actor: &Principal,
) -> SideEffectStatus {
    let Some(profiles) = state.identity.api_key_profiles.get() else {
        return SideEffectStatus::skipped("profile store not configured");
    };
    let seeds: &[(&str, &str, i32, &[&str])] = &[
        (
            "read_only",
            "Read-only access (mcp:read).",
            7 * 24 * 3600,
            &["mcp:read"],
        ),
        (
            "developer",
            "Typical engineering use (mcp:invoke + mcp:read).",
            30 * 24 * 3600,
            &["mcp:invoke", "mcp:read"],
        ),
        (
            "service_account",
            "Longer-lived automation (mcp:invoke + mcp:read).",
            90 * 24 * 3600,
            &["mcp:invoke", "mcp:read"],
        ),
    ];
    let mut seeded = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for (name, desc, ttl, scopes) in seeds {
        let scope_vec: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        match profiles
            .create(
                new_tenant_id,
                name,
                Some(desc),
                *ttl,
                &scope_vec,
                None,
                None,
                true, // requires_reason
                true, // requires_owner
            )
            .await
        {
            Ok(_) => seeded += 1,
            Err(e) => {
                tracing::warn!(
                    tenant = new_tenant_id,
                    profile = name,
                    error = ?e,
                    "tenant onboarding: default profile seed failed",
                );
                failures.push(format!("{name}: {e}"));
            }
        }
    }
    if failures.is_empty() {
        if let Err(e) = crate::admin_mutation::record_admin_mutation(
            state,
            "tenants",
            "GET /api/v1/admin/tenants",
            new_tenant_id,
            Some(actor),
            "tenants.onboarding.api_key_profiles.seeded",
            format!("seeded {seeded} default api_key_profiles"),
        )
        .await
        {
            tracing::warn!(error = ?e, "tenant onboarding: api_key_profiles seed audit failed");
        }
        SideEffectStatus::seeded()
    } else {
        SideEffectStatus::failed(format!("partial seed: {}", failures.join("; ")))
    }
}

async fn mint_scim_api_key(
    state: &Arc<AdminState>,
    new_tenant_id: &str,
    actor: &Principal,
) -> ScimApiKeyOutcome {
    // Gate the onboarding SCIM key mint on `api_keys_enabled`, not
    // just store presence: `state.identity.api_keys` is
    // always-present with a DB pool so tenant cleanup works
    // regardless of runtime auth state; without this extra check,
    // onboarding would mint a SCIM API key that can't authenticate
    // because the bearer chain validator isn't installed. Skipping
    // with a clear message lets operators see why and re-run
    // onboarding after enabling the flag.
    if !state.identity.api_keys_feature.enabled() {
        return ScimApiKeyOutcome {
            status: "skipped",
            detail: Some(
                "GATEWAY_API_KEYS_ENABLED=false — bearer chain has no API-key validator, so a \
                 SCIM API key minted now would 401 every request. Enable API-key auth and \
                 re-run onboarding."
                    .into(),
            ),
            api_key: None,
            api_key_id: None,
        };
    }
    let Some(api_keys) = state.identity.api_keys.get() else {
        return ScimApiKeyOutcome {
            status: "skipped",
            detail: Some("api_keys store not configured".into()),
            api_key: None,
            api_key_id: None,
        };
    };
    let minted = match waygate_apikeys::token::mint() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                tenant = new_tenant_id,
                error = %e,
                "tenant onboarding: SCIM key mint failed (entropy or argon2 error)",
            );
            return ScimApiKeyOutcome {
                status: "failed",
                detail: Some(format!("mint: {e}")),
                api_key: None,
                api_key_id: None,
            };
        }
    };
    let row = waygate_apikeys::store::ApiKeyRow {
        id: uuid::Uuid::new_v4(),
        key_prefix: minted.key_prefix.clone(),
        key_hash: minted.key_hash.clone(),
        name: format!(
            "SCIM provisioning key for tenant `{new_tenant_id}` (seeded by tenant onboarding)"
        ),
        sub: format!("system:scim-provisioner:{new_tenant_id}"),
        tenant_id: new_tenant_id.to_owned(),
        email: None,
        groups: vec![],
        scopes: SCIM_API_KEY_SCOPES
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        created_by: actor.sub.clone(),
        created_at: time::OffsetDateTime::now_utc(),
        last_used_at: None,
        expires_at: None,
        revoked_at: None,
        // This SCIM key is a system-issued key (not operator-minted
        // via dashboard), so it doesn't fit the profile model.
        // Leaving the profile fields None keeps the dashboard
        // rendering it as a "legacy / no profile" row — accurate
        // description.
        profile_id: None,
        owner: Some("system".to_owned()),
        reason: Some("SCIM provisioning key seeded by tenant onboarding".to_owned()),
        rotation_due_at: None,
    };
    if let Err(e) = api_keys.insert(&row).await {
        tracing::warn!(
            tenant = new_tenant_id,
            error = %e,
            "tenant onboarding: SCIM key insert failed",
        );
        return ScimApiKeyOutcome {
            status: "failed",
            detail: Some(format!("insert: {e}")),
            api_key: None,
            api_key_id: None,
        };
    }
    // Audit the mint with the row id ONLY — never the plaintext
    // or the prefix-only portion of the key. (Logging the prefix
    // would let an attacker who later sees a partial token in a
    // log line correlate it back to this audit row's scope.)
    if let Err(e) = crate::admin_mutation::record_admin_mutation(
        state,
        "tenants",
        "GET /api/v1/admin/tenants",
        new_tenant_id,
        Some(actor),
        "tenants.onboarding.scim_api_key.minted",
        format!(
            "minted SCIM provisioning key id={} scopes={}",
            row.id,
            SCIM_API_KEY_SCOPES.join(",")
        ),
    )
    .await
    {
        tracing::warn!(error = ?e, "tenant onboarding: scim api key mint audit failed");
    }
    ScimApiKeyOutcome {
        status: "seeded",
        detail: None,
        api_key: Some(minted.display.clone()),
        api_key_id: Some(row.id.to_string()),
    }
}

/// Dashboard-surface tenant create + composition-root seeding. Shares the
/// REST `create_tenant` orchestration (validate → create → cache-invalidate →
/// fail-closed audit → best-effort policy / admin-role / api-key-profile
/// seeds) so the in-page form and the REST onboarding stay in lockstep.
///
/// The one-shot SCIM sync key is intentionally NOT minted here: it's a
/// reveal-once secret that needs the secret page + no-store cache headers the
/// REST 201 response carries. Operators provisioning IdP sync use the REST
/// onboarding (`POST /api/v1/admin/tenants`) for the key.
pub(crate) async fn create_and_seed_tenant_dashboard(
    state: &Arc<AdminState>,
    id: &str,
    display_name: &str,
    principal: &Principal,
) -> Result<(), ApiError> {
    let store = state.identity.tenants.require()?;
    validate_tenant_input(id, display_name)?;
    let tenant = store
        .create(id, display_name, TenantStatus::Active)
        .await
        .map_err(map_tenant_err)?;
    // Drop the bearer-layer cache before audit so the new tenant is usable
    // immediately even if the audit sink hiccups.
    invalidate_tenant_cache(state, &tenant.id).await;
    crate::admin_mutation::record_admin_mutation(
        state,
        "tenants",
        "GET /api/v1/admin/tenants",
        &tenant.id,
        Some(principal),
        "tenants.create",
        format!(
            "dashboard create tenant id={} display_name={}",
            tenant.id, tenant.display_name
        ),
    )
    .await?;
    // Best-effort seeds: a failure does not roll back the tenant (each seed
    // audits its own outcome) — mirrors the REST handler.
    let _ = seed_policy_bundle(state, &tenant.id, principal).await;
    let _ = seed_tenant_admin_role(state, &tenant.id, principal).await;
    let _ = seed_default_api_key_profiles(state, &tenant.id, principal).await;
    let _ = crate::skill_reviews::seed_tenant(state, &tenant.id).await;
    Ok(())
}

fn validate_tenant_input(id: &str, display_name: &str) -> Result<(), ApiError> {
    // TenantId::parse enforces the alphanumeric+dash format
    // every tenant_id column already accepts. Reject at the
    // boundary so a typo can't create a row no JWT will ever
    // match.
    if let Err(e) = TenantId::parse(id) {
        return Err(ApiError::BadRequest(format!("invalid tenant id: {e}")));
    }
    validate_display_name(display_name)
}

/// Shared display_name bounds, used
/// by both POST (create) and PATCH (update). Without this
/// PATCH could quietly raise a tenant's display_name past the
/// 256-byte cap that create-time enforces.
fn validate_display_name(display_name: &str) -> Result<(), ApiError> {
    if display_name.is_empty() {
        return Err(ApiError::BadRequest(
            "`display_name` must be non-empty".into(),
        ));
    }
    if display_name.len() > 256 {
        return Err(ApiError::BadRequest(
            "`display_name` must be ≤256 chars".into(),
        ));
    }
    Ok(())
}

fn map_tenant_err(e: TenantError) -> ApiError {
    match e {
        TenantError::Conflict(msg) => ApiError::Conflict(msg),
        TenantError::InvalidStatus(msg) => ApiError::BadRequest(msg),
        TenantError::Sqlx(e) => {
            tracing::error!(error = %e, "tenants store error");
            ApiError::Internal("tenants store error".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tenant_input_accepts_minimum() {
        assert!(validate_tenant_input("acme", "Acme Corp").is_ok());
        assert!(validate_tenant_input("acme-prod", "x").is_ok());
    }

    #[test]
    fn validate_tenant_input_rejects_bad_id() {
        // Uppercase + special chars rejected by TenantId::parse.
        assert!(matches!(
            validate_tenant_input("Acme", "x"),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            validate_tenant_input("acme!", "x"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_tenant_input_rejects_empty_display_name() {
        assert!(matches!(
            validate_tenant_input("acme", ""),
            Err(ApiError::BadRequest(_))
        ));
    }

    // ---- Tenant onboarding contract pins ---------------------

    // tenant_admin gets full admin reach inside its tenant
    // (mcp:invoke + mcp:read + mcp:admin + scim:read) but NOT
    // scim:write — that scope belongs to the IdP's SCIM
    // provisioning key, not human admins. Pin the scope set so
    // an accidental escalation (or a drop that locks operators
    // out) shows up in CI.
    #[test]
    fn tenant_admin_scopes_pin() {
        assert_eq!(
            TENANT_ADMIN_SCOPES,
            ["mcp:invoke", "mcp:read", "mcp:admin", "scim:read"],
        );
        assert!(
            !TENANT_ADMIN_SCOPES.contains(&"scim:write"),
            "scim:write must NOT be in tenant_admin — that scope belongs to the SCIM key",
        );
    }

    // SCIM provisioning key gets just enough to manage SCIM
    // resources in its own tenant. NEVER mcp:admin — even if the
    // key leaks it must not escalate to dashboard/admin reach.
    #[test]
    fn scim_api_key_scopes_pin() {
        assert_eq!(SCIM_API_KEY_SCOPES, ["scim:write", "scim:read"]);
        assert!(
            !SCIM_API_KEY_SCOPES.contains(&"mcp:admin"),
            "SCIM provisioning key must NOT carry mcp:admin",
        );
        assert!(
            !SCIM_API_KEY_SCOPES.contains(&"mcp:invoke"),
            "SCIM provisioning key must NOT carry mcp:invoke",
        );
    }

    #[test]
    fn side_effect_status_seeded_omits_detail_in_json() {
        let s = serde_json::to_value(SideEffectStatus::seeded()).unwrap();
        assert_eq!(s, serde_json::json!({"status": "seeded"}));
    }

    #[test]
    fn side_effect_status_skipped_includes_detail() {
        let s = serde_json::to_value(SideEffectStatus::skipped("no store")).unwrap();
        assert_eq!(
            s,
            serde_json::json!({"status": "skipped", "detail": "no store"}),
        );
    }

    #[test]
    fn scim_outcome_seeded_carries_plaintext_and_id() {
        let o = ScimApiKeyOutcome {
            status: "seeded",
            detail: None,
            api_key: Some("mcpgw_xyz".into()),
            api_key_id: Some("00000000-0000-0000-0000-000000000001".into()),
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["status"], "seeded");
        assert_eq!(v["api_key"], "mcpgw_xyz");
        assert!(v.get("detail").is_none(), "detail must be elided when None");
    }

    #[test]
    fn scim_outcome_failed_omits_plaintext() {
        let o = ScimApiKeyOutcome {
            status: "failed",
            detail: Some("entropy: bad".into()),
            api_key: None,
            api_key_id: None,
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(v["detail"], "entropy: bad");
        assert!(
            v.get("api_key").is_none(),
            "api_key plaintext must NOT appear in failure responses",
        );
        assert!(v.get("api_key_id").is_none());
    }

    #[test]
    fn validate_tenant_input_rejects_oversized_display_name() {
        let huge = "x".repeat(257);
        assert!(matches!(
            validate_tenant_input("acme", &huge),
            Err(ApiError::BadRequest(_))
        ));
    }

    // PATCH must reject
    // oversized display_name with the same 256-byte cap as POST.
    #[test]
    fn validate_display_name_helper_matches_create_bounds() {
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name(&"x".repeat(257)).is_err());
        assert!(validate_display_name(&"x".repeat(256)).is_ok());
        assert!(validate_display_name("ok").is_ok());
    }

    #[test]
    fn map_tenant_err_routes_conflict_to_409() {
        let e = map_tenant_err(TenantError::Conflict("dup".into()));
        assert!(matches!(e, ApiError::Conflict(_)));
    }

    #[test]
    fn map_tenant_err_routes_invalid_status_to_400() {
        let e = map_tenant_err(TenantError::InvalidStatus("bad".into()));
        assert!(matches!(e, ApiError::BadRequest(_)));
    }
}
