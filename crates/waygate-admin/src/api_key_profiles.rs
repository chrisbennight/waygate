//! `/api/v1/admin/api_key_profiles/*` — admin CRUD for the
//! per-tenant API-key mint profiles.
//!
//! Endpoints (all mcp:admin-gated):
//!
//! - `GET    /api/v1/admin/api_key_profiles`        — list
//! - `POST   /api/v1/admin/api_key_profiles`        — create
//! - `GET    /api/v1/admin/api_key_profiles/{id}`   — read
//! - `DELETE /api/v1/admin/api_key_profiles/{id}`   — delete
//!
//! ## Tenant scoping
//!
//! Per-tenant: each operator only sees + modifies their own
//! tenant's profiles (read from `principal.tenant`). The store
//! filters `WHERE tenant_id = $1` on every query.
//!
//! ## Why no PATCH
//!
//! Profile semantics intentionally don't allow mutation —
//! changing `allowed_scopes` on a profile would let
//! previously-minted keys keep their now-disallowed scopes
//! (since the validation runs at mint time only). Rather than
//! make that disconnect implicit, the admin surface requires
//! DELETE + POST: operators consciously rotate the profile,
//! which then forces a fresh mint cycle for keys that should
//! follow the new template.
//!
//! ## DELETE refuses if any live key still references it
//!
//! The schema's `api_keys.profile_id ON DELETE SET NULL`
//! would silently detach `allowed_servers`/`allowed_tools`
//! enforcement from every key minted under a deleted profile
//! (validator treats `profile_id IS NULL` as "no
//! restrictions"). The `api_key_profiles_block_delete_if_referenced`
//! BEFORE DELETE trigger (migration 0027) refuses the DELETE
//! when any live (non-revoked, non-expired) `api_keys` row
//! references the profile. The trigger runs inside the
//! EXCLUSIVE row lock the DELETE acquires, so the check is
//! atomic vs. concurrent mints — a handler-side "SELECT
//! COUNT then DELETE" would leave a race window. DB-level
//! enforcement also means the guard applies regardless of
//! which crate surfaces wired up the ApiKeyStore, since a
//! handler-side guard would only run when
//! `state.identity.api_keys` is populated (API-key auth
//! enabled). The handler maps the trigger's
//! `ProfileStoreError::Blocked` variant to HTTP 409 with
//! the live-reference count and recovery steps. The FK SET
//! NULL is preserved as a defensive fallback for revoked
//! rows that legitimately don't matter anymore.
//!
//! ## Audit posture
//!
//! Same fail-closed `record_required` discipline as RBAC and
//! tenants.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_apikeys::{Profile, ProfileStoreError};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;
use waygate_core::fmt::format_ts_rfc3339;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/api_key_profiles",
            get(list_profiles).post(create_profile),
        )
        .route(
            "/api/v1/admin/api_key_profiles/{id}",
            get(get_profile).delete(delete_profile),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

#[derive(Debug, Deserialize, JsonSchema, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProfileRequest {
    /// Tenant-unique profile name, 1–128 characters after trimming.
    pub name: String,
    /// Optional operator-facing explanation of the profile's purpose.
    #[serde(default)]
    pub description: Option<String>,
    /// Maximum lifetime, in seconds, of any key minted under this profile.
    pub max_ttl_seconds: i32,
    /// Non-empty ceiling of scopes a key minted under this profile may request.
    pub allowed_scopes: Vec<String>,
    /// Optional server allowlist; absent or empty means any server.
    #[serde(default)]
    pub allowed_servers: Option<Vec<String>>,
    /// Optional fully-qualified `<server>.<tool>` allowlist; absent or empty
    /// means any tool within the server ceiling.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// Whether a non-empty reason is required when minting under this profile.
    #[serde(default = "default_true")]
    pub requires_reason: bool,
    /// Whether a non-empty owner is required when minting under this profile.
    #[serde(default = "default_true")]
    pub requires_owner: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileListResponse {
    pub items: Vec<ProfileView>,
}

/// View shape returned by the API. Mirrors [`Profile`] but
/// with timestamp fields rendered as RFC 3339 strings so the
/// OpenAPI surface doesn't drag the `time::OffsetDateTime`
/// native shape in.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub max_ttl_seconds: i32,
    pub allowed_scopes: Vec<String>,
    pub allowed_servers: Option<Vec<String>>,
    pub allowed_tools: Option<Vec<String>>,
    pub requires_reason: bool,
    pub requires_owner: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Profile> for ProfileView {
    fn from(p: Profile) -> Self {
        Self {
            id: p.id.to_string(),
            tenant_id: p.tenant_id,
            name: p.name,
            description: p.description,
            max_ttl_seconds: p.max_ttl_seconds,
            allowed_scopes: p.allowed_scopes,
            allowed_servers: p.allowed_servers,
            allowed_tools: p.allowed_tools,
            requires_reason: p.requires_reason,
            requires_owner: p.requires_owner,
            created_at: format_ts_rfc3339(p.created_at),
            updated_at: format_ts_rfc3339(p.updated_at),
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/api_key_profiles",
    tag = "api_key_profiles",
    responses(
        (status = 200, description = "Every profile in the calling principal's tenant", body = ProfileListResponse),
        (status = 503, description = "Profile store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn list_profiles(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Json<ProfileListResponse>> {
    let store = state.identity.api_key_profiles.require()?;
    let items = store
        .list(principal.tenant.as_str())
        .await
        .map_err(map_store_err)?
        .into_iter()
        .map(ProfileView::from)
        .collect();
    Ok(Json(ProfileListResponse { items }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/api_key_profiles",
    tag = "api_key_profiles",
    request_body = CreateProfileRequest,
    responses(
        (status = 201, description = "Profile created", body = ProfileView),
        (status = 400, description = "Invalid input", body = ApiErrorBody),
        (status = 409, description = "A profile already exists with this name in this tenant", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed", body = ApiErrorBody),
        (status = 503, description = "Profile store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn create_profile(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(req): Json<CreateProfileRequest>,
) -> Response {
    let tenant_id = principal.tenant.as_str();
    match create_profile_core(&state, tenant_id, Some(&principal), &req).await {
        Ok(p) => (StatusCode::CREATED, Json(ProfileView::from(p))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared create path: store-check → `validate_create` → `store.create` →
/// `record_mutation` (fail-closed `AdminMutation` audit). Both the REST
/// `create_profile` handler and the dashboard's in-page form call this, so
/// the JSON and HTML surfaces can never drift on validation, the store call,
/// or the audit. Returns the created [`Profile`] or a typed [`ApiError`]
/// (each caller maps it to its own wire shape).
pub(crate) async fn create_profile_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    req: &CreateProfileRequest,
) -> Result<Profile, ApiError> {
    let store = state.identity.api_key_profiles.require()?;
    validate_create(req)?;
    let p = store
        .create(
            tenant_id,
            &req.name,
            req.description.as_deref(),
            req.max_ttl_seconds,
            &req.allowed_scopes,
            req.allowed_servers.as_deref(),
            req.allowed_tools.as_deref(),
            req.requires_reason,
            req.requires_owner,
        )
        .await
        .map_err(map_store_err)?;
    crate::admin_mutation::record_admin_mutation(
        state,
        "api_key_profiles",
        "GET /api/v1/admin/api_key_profiles",
        tenant_id,
        actor,
        "api_key_profiles.create",
        format!(
            "profile id={} name={} max_ttl_seconds={} scopes=[{}] \
             requires_reason={} requires_owner={}",
            p.id,
            p.name,
            p.max_ttl_seconds,
            p.allowed_scopes.join(","),
            p.requires_reason,
            p.requires_owner,
        ),
    )
    .await?;
    Ok(p)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/api_key_profiles/{id}",
    tag = "api_key_profiles",
    params(("id" = String, Path, description = "Profile id (UUID)")),
    responses(
        (status = 200, description = "Profile", body = ProfileView),
        (status = 404, description = "Profile not found", body = ApiErrorBody),
        (status = 503, description = "Profile store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn get_profile(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Json<ProfileView>> {
    let store = state.identity.api_key_profiles.require()?;
    let uuid = parse_uuid(&id)?;
    match store
        .get(principal.tenant.as_str(), uuid)
        .await
        .map_err(map_store_err)?
    {
        Some(p) => Ok(Json(ProfileView::from(p))),
        None => Err(ApiError::NotFoundDyn(format!(
            "api_key_profile {id} in tenant `{}`",
            principal.tenant.as_str()
        ))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/api_key_profiles/{id}",
    tag = "api_key_profiles",
    params(("id" = String, Path, description = "Profile id (UUID)")),
    responses(
        (status = 204, description = "Deleted. No live api_keys row referenced this profile, so no restriction stripping occurred."),
        (status = 404, description = "Profile not found", body = ApiErrorBody),
        (status = 409, description = "Profile still referenced by one or more live api_keys rows; revoke or rotate them first (deletion would otherwise silently strip allowed_servers/allowed_tools enforcement)", body = ApiErrorBody),
        (status = 500, description = "Audit-of-record persistence failed, or api_keys reference count failed", body = ApiErrorBody),
        (status = 503, description = "Profile store not configured", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
pub async fn delete_profile(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    // Store-not-configured is checked BEFORE the uuid parse so an unwired
    // profile store returns 503 regardless of id validity — preserving the
    // 503-before-400 REST ordering. `delete_profile_core` also guards the
    // store (it's reused by the dashboard form, which has no such
    // pre-check), so this is an intentional belt-and-suspenders for the REST
    // contract, not dead code.
    if let Err(e) = state.identity.api_key_profiles.require() {
        return e.into_response();
    }
    let uuid = match parse_uuid(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let tenant_id = principal.tenant.as_str();
    match delete_profile_core(&state, tenant_id, Some(&principal), uuid).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => ApiError::NotFoundDyn(format!("api_key_profile {id} in tenant `{tenant_id}`"))
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Shared delete path: store-check → prefetch (for the audit reason) →
/// `store.delete` → on success flush the API-key validator cache BEFORE the
/// fail-closed `AdminMutation` audit. Both the REST `delete_profile` handler
/// and the dashboard's per-row delete form call this, so the JSON and HTML
/// surfaces can never drift on the trigger guard, the cache flush, or the
/// audit. Returns `Ok(true)` = deleted, `Ok(false)` = no such profile in
/// this tenant; `Err` carries a typed [`ApiError`] (incl. the 409 live-
/// reference conflict) each caller maps to its own wire shape.
pub(crate) async fn delete_profile_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
) -> Result<bool, ApiError> {
    delete_profile_with_guard(state, tenant_id, actor, id, ProfileDeleteGuard::Any).await
}

/// Governed-delete variant whose reviewed row version participates in the
/// store mutation predicate. A concurrent update after approval recapture
/// therefore returns `Ok(false)` without deleting the newer row.
pub(crate) async fn delete_profile_if_updated_at_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    expected_updated_at: OffsetDateTime,
) -> Result<bool, ApiError> {
    delete_profile_with_guard(
        state,
        tenant_id,
        actor,
        id,
        ProfileDeleteGuard::UpdatedAt(expected_updated_at),
    )
    .await
}

enum ProfileDeleteGuard {
    Any,
    UpdatedAt(OffsetDateTime),
}

async fn delete_profile_with_guard(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    guard: ProfileDeleteGuard,
) -> Result<bool, ApiError> {
    let store = state.identity.api_key_profiles.require()?;
    let pre = store.get(tenant_id, id).await.ok().flatten();
    // The live-reference check lives in the
    // `api_key_profiles_block_delete_if_referenced` BEFORE DELETE
    // trigger (migration 0027). Two reasons it's in the DB, not the handler:
    //   1. Atomicity: the trigger runs inside the same transaction as the
    //      DELETE, after the EXCLUSIVE row lock is acquired. Concurrent mints
    //      take a SHARE lock via the FK, so they either commit before the
    //      trigger evaluates (count sees them → trigger raises) or wait until
    //      after our DELETE commits (FK violation against the now-gone
    //      profile). The previous handler-side "SELECT COUNT then DELETE" had
    //      a race window where a mint landing between the two statements
    //      escaped the guard and ended up with profile_id NULL after FK SET
    //      NULL.
    //   2. Always-on: the handler-side guard was conditional on `state.identity.api_keys`
    //      being wired (only when API-key auth is enabled). A DB-level trigger
    //      applies whenever the profile store is wired.
    // The trigger raises `ProfileStoreError::Blocked`; `map_store_err`
    // translates that to HTTP 409 with the live-reference count.
    let removed = match guard {
        ProfileDeleteGuard::Any => store.delete(tenant_id, id).await,
        ProfileDeleteGuard::UpdatedAt(expected) => {
            store.delete_if_updated_at(tenant_id, id, expected).await
        }
    }
    .map_err(map_store_err)?;
    if !removed {
        return Ok(false);
    }
    // Flush the API-key validator's principal cache BEFORE the audit
    // write, not after. The DB delete has already
    // committed; if `record_mutation` errors and we early-return without
    // invalidating, recently-used keys keep enforcing the now-deleted
    // profile's restrictions until cache_ttl. Cache integrity tracks the DB
    // state and must not depend on best-effort audit success.
    //
    // `CachedEntry` holds a resolved Principal whose
    // `api_key_profile_restrictions` is frozen at insert time; ON DELETE SET
    // NULL detaches `api_keys.profile_id` but the cached resolved form is
    // untouched. Whole-cache flush matches the tenant-DELETE pattern (the
    // operator-rare path absorbs the cold-cache cost; the cache key is the
    // opaque token, so we can't enumerate only matching entries).
    if let Some(validator) = state.identity.api_key_validator.as_ref() {
        validator.invalidate_all().await;
    }
    let reason = match pre.as_ref() {
        Some(p) => format!("profile id={} name={}", p.id, p.name),
        None => format!("profile id={id} (prefetch failed)"),
    };
    crate::admin_mutation::record_admin_mutation(
        state,
        "api_key_profiles",
        "GET /api/v1/admin/api_key_profiles",
        tenant_id,
        actor,
        "api_key_profiles.delete",
        reason,
    )
    .await?;
    Ok(true)
}

// ---- helpers --------------------------------------------------

fn parse_uuid(id: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(id).map_err(|e| ApiError::BadRequest(format!("invalid profile id: {e}")))
}

fn validate_create(req: &CreateProfileRequest) -> Result<(), ApiError> {
    if req.name.trim().is_empty() || req.name.len() > 128 {
        return Err(ApiError::BadRequest(
            "`name` must be non-empty and ≤128 chars".into(),
        ));
    }
    if req.max_ttl_seconds <= 0 {
        return Err(ApiError::BadRequest(
            "`max_ttl_seconds` must be > 0 (profiles always bound TTL — operators wanting \
             never-expiring keys must use the legacy dashboard mint until that path is removed)"
                .into(),
        ));
    }
    if req.allowed_scopes.is_empty() {
        return Err(ApiError::BadRequest(
            "`allowed_scopes` must contain at least one scope".into(),
        ));
    }
    // allowed_servers / allowed_tools are enforced at call time by
    // `waygate-mcp::DefaultInvocationService::check_profile_restrictions`.
    // Lightly validate the shape: each allowed_servers entry must be
    // non-empty, each allowed_tools entry must look like a
    // `<server>.<tool>` qualified name (the check_profile path
    // compares against `format!("{server}.{tool}")` so a
    // misformatted entry would silently never match).
    if let Some(servers) = req.allowed_servers.as_deref() {
        if servers.iter().any(|s| s.is_empty()) {
            return Err(ApiError::BadRequest(
                "`allowed_servers` entries must be non-empty".into(),
            ));
        }
    }
    if let Some(tools) = req.allowed_tools.as_deref() {
        if tools
            .iter()
            .any(|t| !t.contains('.') || t.starts_with('.') || t.ends_with('.'))
        {
            return Err(ApiError::BadRequest(
                "`allowed_tools` entries must be `<server>.<tool>` fully-qualified names with non-empty parts".into(),
            ));
        }
    }
    Ok(())
}

fn map_store_err(e: ProfileStoreError) -> ApiError {
    match e {
        ProfileStoreError::Conflict => {
            ApiError::Conflict("a profile already exists with this name in this tenant".into())
        }
        ProfileStoreError::InvalidShape(msg) => ApiError::BadRequest(msg),
        // Live-reference guard fired in the DB trigger.
        ProfileStoreError::Blocked { live_refs } => ApiError::Conflict(format!(
            "profile is referenced by {live_refs} live api_keys row(s); revoke or rotate them \
             first (DELETE /api/v1/admin/api_keys/<id>), then retry"
        )),
        ProfileStoreError::Sqlx(e) => {
            tracing::error!(error = %e, "api_key_profiles store error");
            ApiError::Internal("api_key_profiles store error".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> CreateProfileRequest {
        CreateProfileRequest {
            name: "read_only".into(),
            description: None,
            max_ttl_seconds: 3600,
            allowed_scopes: vec!["mcp:read".into()],
            allowed_servers: None,
            allowed_tools: None,
            requires_reason: true,
            requires_owner: true,
        }
    }

    #[test]
    fn validate_create_accepts_minimal_valid() {
        assert!(validate_create(&req()).is_ok());
    }

    #[test]
    fn validate_create_rejects_empty_or_oversized_name() {
        let mut r = req();
        r.name = "".into();
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.name = "   ".into();
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.name = "x".repeat(129);
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.name = "x".repeat(128);
        assert!(validate_create(&r).is_ok());
    }

    #[test]
    fn validate_create_rejects_non_positive_ttl() {
        let mut r = req();
        r.max_ttl_seconds = 0;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        r.max_ttl_seconds = -1;
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn validate_create_rejects_empty_allowed_scopes() {
        let mut r = req();
        r.allowed_scopes = vec![];
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
    }

    // allowed_servers / allowed_tools are accepted (and enforced
    // at call time in
    // waygate-mcp::DefaultInvocationService::check_profile_restrictions).
    // Empty arrays / None pass (no restriction); non-empty values
    // pass too, since only the shape is validated here.
    #[test]
    fn validate_create_accepts_non_empty_allowed_servers() {
        let mut r = req();
        r.allowed_servers = Some(vec!["email".into()]);
        assert!(validate_create(&r).is_ok());
        // Empty entries still rejected.
        r.allowed_servers = Some(vec!["".into()]);
        assert!(matches!(validate_create(&r), Err(ApiError::BadRequest(_))));
        // Empty list + None continue to pass (no restriction).
        r.allowed_servers = Some(vec![]);
        assert!(validate_create(&r).is_ok());
        r.allowed_servers = None;
        assert!(validate_create(&r).is_ok());
    }

    #[test]
    fn validate_create_accepts_qualified_allowed_tools() {
        let mut r = req();
        r.allowed_tools = Some(vec!["email.send".into()]);
        assert!(validate_create(&r).is_ok());
        // Reject non-qualified entries (would never match in
        // the call-time check which formats `server.tool`).
        for bad in ["nodot", ".send", "email.", ".", ""] {
            r.allowed_tools = Some(vec![bad.into()]);
            assert!(
                matches!(validate_create(&r), Err(ApiError::BadRequest(_))),
                "should reject malformed tool `{bad}`",
            );
        }
        r.allowed_tools = Some(vec![]);
        assert!(validate_create(&r).is_ok());
        r.allowed_tools = None;
        assert!(validate_create(&r).is_ok());
    }

    #[test]
    fn map_store_err_conflict_to_409() {
        assert!(matches!(
            map_store_err(ProfileStoreError::Conflict),
            ApiError::Conflict(_)
        ));
    }

    #[test]
    fn map_store_err_invalid_shape_to_400() {
        assert!(matches!(
            map_store_err(ProfileStoreError::InvalidShape("x".into())),
            ApiError::BadRequest(_)
        ));
    }
}
