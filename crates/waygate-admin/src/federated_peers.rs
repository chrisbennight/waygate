//! `/api/v1/admin/federated_peers` — federated gateway peer
//! registry.
//!
//! Operators enroll, edit, and delete remote MCP gateways
//! this gateway federates with (Tier-C identity
//! chaining). Every endpoint is behind `mcp:admin` and
//! tenant-scoped via `principal.tenant` (NOT via anything
//! in the request).
//!
//! Every mutating handler emits an `AdminMutation`
//! evidence row via `record_required` — config CRUD with
//! security impact MUST be durably audited fail-closed.
//!
//! ## Runtime consumption
//!
//! This module is admin CRUD only; the JWKS fetcher +
//! peer-assertion validator that consume these rows at
//! dispatch time live in `waygate-federation` and are wired
//! into the bearer chain in `waygate-server`. A newly
//! enrolled or edited row is picked up on the runtime's next
//! JWKS refresh, not synchronously with the admin write.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use waygate_federation::{
    FederatedPeer, NewFederatedPeer, PeerError, PeerFilter, PeerUpdate, TrustTier, MAX_LIST_LIMIT,
};
use waygate_oidc::Principal;

use crate::error::{ApiError, ApiErrorBody, ApiResult};
use crate::scope::require_admin;
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route(
            "/api/v1/admin/federated_peers",
            get(list_peers).post(create_peer),
        )
        .route(
            "/api/v1/admin/federated_peers/{id}",
            get(get_peer).patch(update_peer).delete(delete_peer),
        )
        .layer(middleware::from_fn(require_admin))
        .with_state(state)
}

// --- DTOs --------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePeerRequest {
    /// Operator-friendly label; unique within tenant.
    /// 1–128 chars.
    pub peer_name: String,
    /// Peer's OIDC `iss` claim. Must be a non-empty URL —
    /// the runtime JWT validator pivots on it.
    pub issuer: String,
    /// Peer's JWKS endpoint URL — where this gateway
    /// fetches signing keys. HTTPS enforcement lives at
    /// the runtime layer; storage stays opaque
    /// to keep local-dev / proxy shapes accessible.
    pub jwks_url: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdatePeerRequest {
    pub peer_name: Option<String>,
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerListResponse {
    pub peers: Vec<FederatedPeer>,
    /// Echoed page size after `MAX_LIST_LIMIT` clamp.
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    #[serde(default)]
    pub peer_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default = "waygate_core::page::default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

// --- Validation --------------------------------------------------

const NAME_MIN: usize = 1;
const NAME_MAX: usize = 128;

// `validate_peer_name_trim` (below) returns the trimmed form so
// handlers store the normalized value, not the original request
// string.

/// Reject malformed
/// issuer strings up front AND return the normalized form
/// so handlers store the same string the validator
/// validated. The runtime JWT validator pivots
/// on `iss` claim equality; an unparseable issuer stored
/// here would silently never match any token, and an
/// untrimmed-or-not-normalized issuer would have the same
/// failure mode.
///
/// Validation:
/// - non-empty (after trim)
/// - ≤2048 chars (Pg-side limits are happy with any TEXT
///   value but the operator-visible cap keeps audit-row
///   reasons + UI tables manageable)
/// - parses as an absolute URL with `http` or `https` scheme
///   (OIDC issuers are URLs per RFC 8414 §3 / OpenID Connect
///   Discovery 1.0 §3; non-URL issuers exist in the wild
///   but aren't useful for a federated-peer registry that
///   needs to fetch JWKS over HTTP/S anyway)
///
/// Returns the **trimmed** issuer (NOT the URL serializer's
/// output):
/// `url::Url::parse("https://gw.example").to_string()`
/// returns `"https://gw.example/"` — the serializer adds a
/// trailing slash on bare-authority URLs. The OIDC `iss`
/// claim is matched byte-for-byte at JWT validation time,
/// so canonicalizing here would silently break the lookup
/// against tokens issued by the peer (whose `iss` claim is
/// the exact string the peer published, not Rust's
/// reserialization of it).
///
/// The parse step still runs as a validation gate; we just
/// don't persist its output. Trim is the only normalization.
fn validate_issuer(issuer: &str) -> Result<String, ApiError> {
    let trimmed = issuer.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("issuer must be non-empty".into()));
    }
    if issuer.len() > 2048 {
        return Err(ApiError::BadRequest("issuer must be ≤2048 chars".into()));
    }
    let parsed = url::Url::parse(trimmed)
        .map_err(|e| ApiError::BadRequest(format!("issuer must be an absolute URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ApiError::BadRequest(format!(
            "issuer URL scheme must be `http` or `https` (got `{scheme}`)",
        )));
    }
    // Refuse URLs that carry
    // userinfo. The OIDC issuer claim is never a credential-
    // bearing URL — an operator who registers
    // `https://user:pass@peer/` is at best confused and at
    // worst about to leak that secret into the audit log
    // (the create/update handlers persist the value verbatim
    // in the shared admin-mutation reason strings). Refuse it
    // up front; the operator's response is to remove the
    // userinfo and use a separate auth mechanism if needed.
    reject_url_userinfo(&parsed, "issuer")?;
    Ok(trimmed.to_owned())
}

/// Same URL-shape validation as [`validate_issuer`] —
/// `jwks_url` MUST parse as an absolute http(s) URL. The
/// runtime fetcher enforces HTTPS-only
/// (with the local-dev http://localhost / 127.0.0.1
/// exception); the admin layer accepts http here so
/// local-dev seeding works.
///
/// Returns the **trimmed** jwks_url. Same reasoning as
/// [`validate_issuer`] for not using `Url::to_string` —
/// the runtime fetcher will GET this exact
/// URL; the operator typed it the way the peer publishes
/// it, and silently rewriting it (adding trailing slashes,
/// lowercasing the host's case-sensitive path component,
/// etc.) could break the fetch against peers that are
/// strict about request shape.
fn validate_jwks_url(url: &str) -> Result<String, ApiError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("jwks_url must be non-empty".into()));
    }
    if url.len() > 2048 {
        return Err(ApiError::BadRequest("jwks_url must be ≤2048 chars".into()));
    }
    let parsed = ::url::Url::parse(trimmed)
        .map_err(|e| ApiError::BadRequest(format!("jwks_url must be an absolute URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ApiError::BadRequest(format!(
            "jwks_url scheme must be `http` or `https` (got `{scheme}`)",
        )));
    }
    // Refuse URLs with userinfo.
    // The runtime fetcher's tracing fields elide the URL
    // bytes (log-exposure hardening), but the admin
    // CRUD audit reason strings persist `jwks_url` verbatim.
    // A URL like `https://user:pass@peer/.well-known/jwks.json`
    // would leak the credentials into audit storage + every
    // exporter. JWKS endpoints SHOULD never need
    // request-line credentials (the OIDC contract is that the
    // JWKS document is public). Refuse rather than try to
    // sanitize.
    reject_url_userinfo(&parsed, "jwks_url")?;
    Ok(trimmed.to_owned())
}

/// Refuse `https://user:pass@host/`
/// shapes anywhere we accept an operator-supplied URL. The
/// `url` crate exposes `username()` (returns `""` when
/// unset) and `password()` (returns `None` when unset).
fn reject_url_userinfo(parsed: &url::Url, field_name: &str) -> Result<(), ApiError> {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must not contain URL userinfo (the `user:pass@` form is rejected to \
             prevent credential leakage into audit logs)",
        )));
    }
    Ok(())
}

/// Belt-and-suspenders sanitizer
/// for URL fields persisted into AdminMutation evidence rows.
/// Input-side `reject_url_userinfo` refuses new
/// rows that carry userinfo, but a pre-existing row (created
/// before that validator existed, or written by a migration / DB-level
/// INSERT bypassing the validator) can still carry
/// `https://user:pass@host/...`. Any audit reason string that
/// formats `peer.issuer` or `peer.jwks_url` verbatim would
/// then leak those bytes through `record_required` into the
/// audit log + every configured exporter.
///
/// This helper parses the URL; on success it returns the
/// userinfo-stripped serialization, on parse failure it
/// returns a `<sanitization-failed>` placeholder rather than
/// the original value. Operators who see the placeholder in
/// audit rows know to inspect the row directly.
fn sanitize_url_for_audit(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            // `set_password(None)` + `set_username("")`
            // unconditionally remove the credential bits;
            // both APIs are documented infallible for
            // schemes that accept authority.
            let _ = u.set_password(None);
            let _ = u.set_username("");
            u.to_string()
        }
        Err(_) => "<sanitization-failed>".to_owned(),
    }
}

/// Trim + length-validate the operator-friendly peer_name.
/// Returns the trimmed form so handlers can't accidentally
/// persist `" acme-prod "` and then have list-by-name
/// lookups silently miss.
fn validate_peer_name_trim(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    let len = trimmed.chars().count();
    if !(NAME_MIN..=NAME_MAX).contains(&len) {
        return Err(ApiError::BadRequest(format!(
            "peer_name length (after trim) must be between {NAME_MIN} and {NAME_MAX} chars",
        )));
    }
    Ok(trimmed.to_owned())
}

// --- Handlers ----------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/federated_peers",
    tag = "federated_peers",
    request_body = CreatePeerRequest,
    responses(
        (status = 201, description = "Peer created", body = FederatedPeer),
        (status = 400, description = "Invalid peer fields", body = ApiErrorBody),
        (status = 409, description = "Duplicate (tenant, peer_name) OR (tenant, issuer)", body = ApiErrorBody),
        (status = 503, description = "Peers store not configured", body = ApiErrorBody),
        (status = 500, description = "Peers store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn create_peer(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Json(body): Json<CreatePeerRequest>,
) -> ApiResult<(StatusCode, Json<FederatedPeer>)> {
    let peer = create_peer_core(
        &state,
        actor.tenant.as_str(),
        Some(&actor),
        &body.peer_name,
        &body.issuer,
        &body.jwks_url,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(peer)))
}

/// Shared create path: store-check → validate (peer_name / issuer /
/// jwks_url, each returning the normalized form) → `store.insert` →
/// fail-closed `AdminMutation` audit. Both the REST `create_peer`
/// handler and the dashboard's in-page form call this, so the JSON
/// and HTML surfaces can't drift on validation, the store call, or
/// the audit. URL fields are sanitized before they enter the audit
/// reason.
pub(crate) async fn create_peer_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    peer_name: &str,
    issuer: &str,
    jwks_url: &str,
) -> Result<FederatedPeer, ApiError> {
    let store = state.federation.federated_peers.require()?;
    // Validators return the normalized
    // (trimmed) form; persist THAT, not the original request strings,
    // or an admin could store `" https://gw.example "` which passes
    // validation but silently never matches at runtime.
    let peer_name = validate_peer_name_trim(peer_name)?;
    let issuer = validate_issuer(issuer)?;
    let jwks_url = validate_jwks_url(jwks_url)?;
    let peer = store
        .insert(NewFederatedPeer {
            tenant_id,
            peer_name: &peer_name,
            issuer: &issuer,
            jwks_url: &jwks_url,
            trust_tier: TrustTier::Full,
        })
        .await
        .map_err(map_store_err)?;
    crate::admin_mutation::record_admin_mutation(
        state,
        "federated_peers",
        "GET /api/v1/admin/federated_peers",
        tenant_id,
        actor,
        "FederatedPeerCreated",
        // Include jwks_url so an audit reader
        // reconstructing key-source provenance can read it from the
        // evidence row alone, without joining to a (mutable, deletable)
        // federated_peers row.
        format!(
            "created peer id={} name={} issuer={} jwks_url={} trust_tier={}",
            peer.id,
            peer.peer_name,
            sanitize_url_for_audit(&peer.issuer),
            sanitize_url_for_audit(&peer.jwks_url),
            peer.trust_tier.as_str(),
        ),
    )
    .await?;
    Ok(peer)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/federated_peers",
    tag = "federated_peers",
    params(ListQuery),
    responses(
        (status = 200, description = "Peers in the caller's tenant", body = PeerListResponse),
        (status = 503, description = "Peers store not configured", body = ApiErrorBody),
        (status = 500, description = "Peers query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn list_peers(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<PeerListResponse>> {
    let store = state.federation.federated_peers.require()?;
    let tenant_id = actor.tenant.as_str();
    let effective_limit = q.limit.min(MAX_LIST_LIMIT);
    let filter = PeerFilter {
        peer_name: q.peer_name.as_deref(),
        issuer: q.issuer.as_deref(),
        trust_tier: None,
    };
    let peers = store
        .list(tenant_id, filter, effective_limit, q.offset)
        .await
        .map_err(map_store_err)?;
    Ok(Json(PeerListResponse {
        peers,
        limit: effective_limit,
        offset: q.offset,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/federated_peers/{id}",
    tag = "federated_peers",
    params(("id" = Uuid, Path, description = "Peer UUID")),
    responses(
        (status = 200, description = "Peer detail", body = FederatedPeer),
        (status = 404, description = "Peer not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Peers store not configured", body = ApiErrorBody),
        (status = 500, description = "Peers query failed", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn get_peer(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<FederatedPeer>> {
    let store = state.federation.federated_peers.require()?;
    let peer = store
        .get(actor.tenant.as_str(), id)
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("federated peer"))?;
    Ok(Json(peer))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/federated_peers/{id}",
    tag = "federated_peers",
    params(("id" = Uuid, Path, description = "Peer UUID")),
    request_body = UpdatePeerRequest,
    responses(
        (status = 200, description = "Peer updated", body = FederatedPeer),
        (status = 400, description = "Invalid peer fields", body = ApiErrorBody),
        (status = 404, description = "Peer not found in this tenant", body = ApiErrorBody),
        (status = 409, description = "Rename collides with existing", body = ApiErrorBody),
        (status = 503, description = "Peers store not configured", body = ApiErrorBody),
        (status = 500, description = "Peers store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn update_peer(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePeerRequest>,
) -> ApiResult<Json<FederatedPeer>> {
    let peer = update_peer_core(
        &state,
        actor.tenant.as_str(),
        Some(&actor),
        id,
        body.peer_name.as_deref(),
        body.issuer.as_deref(),
        body.jwks_url.as_deref(),
    )
    .await?;
    Ok(Json(peer))
}

/// Shared update path: store-check → validate each supplied field
/// (unset stays `None` so the store's COALESCE preserves it) →
/// `store.update` → conditional JWKS-cache invalidation → fail-closed
/// `AdminMutation` audit. Both the REST `update_peer` handler and the
/// dashboard's per-row edit form call this. Cache invalidation gates
/// on whether issuer / jwks_url were SUPPLIED (not a
/// value diff): re-asserting the same issuer intentionally re-confirms
/// it on the next refresh. NotFound when the peer
/// isn't in this tenant.
pub(crate) async fn update_peer_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
    peer_name: Option<&str>,
    issuer: Option<&str>,
    jwks_url: Option<&str>,
) -> Result<FederatedPeer, ApiError> {
    let store = state.federation.federated_peers.require()?;
    let peer_name = match peer_name {
        Some(n) => Some(validate_peer_name_trim(n)?),
        None => None,
    };
    let issuer = match issuer {
        Some(i) => Some(validate_issuer(i)?),
        None => None,
    };
    let jwks_url = match jwks_url {
        Some(u) => Some(validate_jwks_url(u)?),
        None => None,
    };
    let peer = store
        .update(
            tenant_id,
            id,
            PeerUpdate {
                peer_name: peer_name.as_deref(),
                issuer: issuer.as_deref(),
                jwks_url: jwks_url.as_deref(),
                trust_tier: None,
            },
        )
        .await
        .map_err(map_store_err)?
        .ok_or(ApiError::NotFound("federated peer"))?;
    // Invalidate when issuer or jwks_url were supplied. The validated locals are `Some` iff the
    // caller supplied the field, so they track REQUEST-supplied (not a
    // value diff) — the contract the REST handler pinned.
    let cache_affected = issuer.is_some() || jwks_url.is_some();
    if cache_affected {
        invalidate_peer_cache(state, peer.id, tenant_id, "PATCH").await;
    }
    crate::admin_mutation::record_admin_mutation(
        state,
        "federated_peers",
        "GET /api/v1/admin/federated_peers",
        tenant_id,
        actor,
        "FederatedPeerUpdated",
        format!(
            "updated peer id={} name={} issuer={} jwks_url={} trust_tier={}",
            peer.id,
            peer.peer_name,
            sanitize_url_for_audit(&peer.issuer),
            sanitize_url_for_audit(&peer.jwks_url),
            peer.trust_tier.as_str(),
        ),
    )
    .await?;
    Ok(peer)
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/federated_peers/{id}",
    tag = "federated_peers",
    params(("id" = Uuid, Path, description = "Peer UUID")),
    responses(
        (status = 204, description = "Peer deleted"),
        (status = 404, description = "Peer not found in this tenant", body = ApiErrorBody),
        (status = 503, description = "Peers store not configured", body = ApiErrorBody),
        (status = 500, description = "Peers store error", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid bearer token", body = ApiErrorBody),
        (status = 403, description = "Bearer token lacks mcp:admin", body = ApiErrorBody),
    ),
)]
async fn delete_peer(
    State(state): State<Arc<AdminState>>,
    Extension(actor): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if delete_peer_core(&state, actor.tenant.as_str(), Some(&actor), id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("federated peer"))
    }
}

/// Shared delete path: store-check → `store.delete` → on success
/// invalidate the JWKS cache (so a rotated-away peer can't keep
/// validating until the next refresh tick) →
/// fail-closed `AdminMutation` audit. Both the REST `delete_peer`
/// handler and the dashboard's per-row delete form call this.
/// `Ok(true)` = deleted, `Ok(false)` = no such peer in this tenant.
pub(crate) async fn delete_peer_core(
    state: &Arc<AdminState>,
    tenant_id: &str,
    actor: Option<&Principal>,
    id: Uuid,
) -> Result<bool, ApiError> {
    let store = state.federation.federated_peers.require()?;
    let removed = store.delete(tenant_id, id).await.map_err(map_store_err)?;
    if removed {
        invalidate_peer_cache(state, id, tenant_id, "DELETE").await;
        crate::admin_mutation::record_admin_mutation(
            state,
            "federated_peers",
            "GET /api/v1/admin/federated_peers",
            tenant_id,
            actor,
            "FederatedPeerDeleted",
            format!("deleted peer id={id}"),
        )
        .await?;
    }
    Ok(removed)
}

/// Invalidate the in-memory peer
/// JWKS cache entry for `peer_id` after a successful PATCH
/// or DELETE so the OLD `issuer` / `jwks_url`
/// can't continue validating peer-asserted JWTs until the
/// refresher's next cycle. The refresher's `list_all_for_refresh`
/// scan would notice the change eventually, but for
/// rotation-away-from-compromised semantics that window is
/// unacceptable.
///
/// Eviction is unconditional rather than diffing fields:
/// eviction is cheap, the refresher re-populates from the
/// current store on its next tick, and "peer renamed but
/// keys unchanged" is a no-op extra fetch — still cheaper
/// than mis-attributing under a stale tenant.
///
/// Best-effort: when the cache isn't wired (test builds, dev
/// loop without federation infra) this returns immediately
/// without emitting a log line.
async fn invalidate_peer_cache(state: &AdminState, peer_id: Uuid, tenant: &str, op: &str) {
    if let Some(cache) = state.federation.federated_peers_cache.as_ref() {
        let evicted = cache.invalidate(peer_id).await;
        tracing::info!(
            %peer_id,
            %tenant,
            op,
            evicted,
            "federated peer cache entry invalidated",
        );
    }
}

fn map_store_err(e: PeerError) -> ApiError {
    match e {
        PeerError::DuplicateName => ApiError::Conflict(
            "peer with the same (tenant, peer_name) OR (tenant, issuer) already exists".to_owned(),
        ),
        PeerError::Database(_) => ApiError::Internal(format!("federated peers store: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the URL-shape contract AND the "validators return
    // normalized form" contract for issuer + jwks_url +
    // peer_name so future regressions fail tests.

    #[test]
    fn peer_inputs_reject_unenforced_authority_choices() {
        let create = serde_json::json!({
            "peer_name": "peer", "issuer": "https://peer.example",
            "jwks_url": "https://peer.example/jwks"
        });
        assert!(serde_json::from_value::<CreatePeerRequest>(create.clone()).is_ok());
        for label in ["restricted", "full"] {
            let mut body = create.clone();
            body["trust_tier"] = serde_json::json!(label);
            assert!(serde_json::from_value::<CreatePeerRequest>(body).is_err());
            assert!(
                serde_json::from_value::<UpdatePeerRequest>(serde_json::json!({
                    "trust_tier": label
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn validate_issuer_accepts_https_url() {
        assert!(validate_issuer("https://gw.acme.example").is_ok());
        assert!(validate_issuer("https://gw.acme.example/realm/123").is_ok());
    }

    #[test]
    fn validate_issuer_accepts_http_url_for_local_dev() {
        assert!(validate_issuer("http://localhost:8080").is_ok());
        assert!(validate_issuer("http://127.0.0.1:9000/iss").is_ok());
    }

    #[test]
    fn validate_issuer_rejects_empty() {
        let err = validate_issuer("").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
        let err = validate_issuer("   ").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn validate_issuer_rejects_non_url() {
        let err = validate_issuer("not-a-url").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(
                msg.contains("absolute URL"),
                "msg should mention URL shape, got: {msg}",
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_issuer_rejects_non_http_scheme() {
        let cases = [
            "ftp://gw.acme.example",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ];
        for c in cases {
            let err = validate_issuer(c).unwrap_err();
            match err {
                ApiError::BadRequest(msg) => assert!(
                    msg.contains("scheme"),
                    "msg should mention scheme for {c}, got: {msg}",
                ),
                other => panic!("expected BadRequest for {c}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_issuer_rejects_over_length() {
        let long = format!("https://a.example/{}", "x".repeat(3000));
        let err = validate_issuer(&long).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn validate_jwks_url_accepts_https() {
        assert!(validate_jwks_url("https://gw.acme.example/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn validate_jwks_url_accepts_http_for_local_dev() {
        assert!(validate_jwks_url("http://localhost:8080/jwks").is_ok());
    }

    #[test]
    fn validate_jwks_url_rejects_non_url() {
        let err = validate_jwks_url("not-a-url").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(
                msg.contains("absolute URL"),
                "msg should mention URL shape, got: {msg}",
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_jwks_url_rejects_non_http_scheme() {
        let err = validate_jwks_url("file:///etc/passwd").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(
                msg.contains("scheme"),
                "msg should mention scheme, got: {msg}",
            ),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// The audit
    /// reason strings sanitize URLs before formatting, so a
    /// pre-existing row that carries userinfo (created
    /// before the input-side reject existed, or written via
    /// migration / direct SQL) can't leak the credentials
    /// into AdminMutation evidence.
    #[test]
    fn sanitize_url_for_audit_strips_userinfo() {
        assert_eq!(
            sanitize_url_for_audit("https://user:pass@peer.example/.well-known/jwks.json"),
            "https://peer.example/.well-known/jwks.json",
        );
        assert_eq!(
            sanitize_url_for_audit("https://user@peer.example/"),
            "https://peer.example/",
        );
    }

    #[test]
    fn sanitize_url_for_audit_passes_clean_urls_through() {
        // A clean URL round-trips through Url::parse +
        // to_string; trailing slash on bare authority is
        // expected (it's the URL serializer's canonicalization,
        // used ONLY for the audit reason; the stored value
        // preserves the original byte sequence).
        let out = sanitize_url_for_audit("https://gw.example/.well-known/jwks.json");
        assert_eq!(out, "https://gw.example/.well-known/jwks.json");
    }

    #[test]
    fn sanitize_url_for_audit_handles_unparseable_input() {
        // A weird row value that won't parse falls back to
        // the placeholder rather than leaking the original
        // bytes into the audit row.
        let out = sanitize_url_for_audit("not-a-url");
        assert_eq!(out, "<sanitization-failed>");
    }

    /// Refuse URLs
    /// with userinfo at validation time so credentials never
    /// land in the admin-mutation audit reason strings.
    #[test]
    fn validate_issuer_rejects_userinfo() {
        for url in [
            "https://user:pass@gw.acme.example/",
            "https://user@gw.acme.example/",
            "https://operator:@gw.acme.example/",
        ] {
            let err = validate_issuer(url).expect_err("userinfo must be rejected");
            match err {
                ApiError::BadRequest(msg) => assert!(
                    msg.contains("userinfo"),
                    "msg must explain the rejection: {msg}",
                ),
                other => panic!("expected BadRequest for {url}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_jwks_url_rejects_userinfo() {
        for url in [
            "https://user:pass@peer.example/.well-known/jwks.json",
            "https://user@peer.example/.well-known/jwks.json",
        ] {
            let err = validate_jwks_url(url).expect_err("userinfo must be rejected");
            match err {
                ApiError::BadRequest(msg) => assert!(
                    msg.contains("userinfo"),
                    "msg must explain the rejection: {msg}",
                ),
                other => panic!("expected BadRequest for {url}, got {other:?}"),
            }
        }
    }

    // PATCH and
    // DELETE handlers must evict the in-memory peer JWKS
    // cache entry so an OLD `issuer` / `jwks_url` cannot validate peer-asserted JWTs
    // after the operator rotated. The trait method itself is
    // covered in `waygate_federation::jwks::tests`; this test
    // pins the wiring (helper actually reads the cache off
    // AdminState + delegates).
    #[tokio::test]
    async fn invalidate_peer_cache_drops_entry_when_wired() {
        use crate::state::AdminState;
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use time::OffsetDateTime;
        use waygate_federation::jwks::{
            CachedJwks, InMemoryPeerJwksCache, PeerJwksCache, SharedPeerJwksCache,
        };
        use waygate_federation::TrustTier;
        use waygate_upstream::UpstreamPool;

        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let cache_arc = Arc::new(InMemoryPeerJwksCache::new());
        let shared: SharedPeerJwksCache = cache_arc.clone();
        // `PeerJwksCache` trait must be in scope for the
        // `.len()` / `.is_empty()` async methods on the
        // `SharedPeerJwksCache` (Arc<dyn>) — bind to a `_`
        // to keep clippy quiet about the seemingly-unused
        // import.
        let _trait_in_scope = std::marker::PhantomData::<&dyn PeerJwksCache>;
        let state = AdminState::new(
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
        .with_federated_peers_cache(Some(shared.clone()));

        let peer_id = Uuid::new_v4();
        cache_arc.upsert(CachedJwks {
            peer_id,
            tenant_id: "default".into(),
            issuer: "https://peer.example/".into(),
            trust_tier: TrustTier::Full,
            // Empty JwkSet — the test exercises eviction, not
            // signature verification; an empty keys vec is
            // sufficient.
            keys: serde_json::from_str(r#"{"keys":[]}"#).unwrap(),
            fetched_at: OffsetDateTime::now_utc(),
        });
        assert_eq!(shared.len().await, 1, "cache must be populated pre-evict");

        invalidate_peer_cache(&state, peer_id, "default", "PATCH").await;
        assert!(
            shared.is_empty().await,
            "cache must be empty after invalidate"
        );

        // Calling again on a missing entry is a no-op — `invalidate`
        // returns false but the helper doesn't surface it; the
        // refresher's re-population path is what eventually
        // re-fetches.
        invalidate_peer_cache(&state, peer_id, "default", "DELETE").await;
        assert!(shared.is_empty().await, "double-invalidate must stay empty");
    }

    #[tokio::test]
    async fn invalidate_peer_cache_is_noop_when_no_cache_wired() {
        // Test builds / dev loop without federation infra:
        // helper exits without panic.
        use crate::state::AdminState;
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use waygate_upstream::UpstreamPool;
        let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
        let state = AdminState::new(
            pool,
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        );
        // No `.with_federated_peers_cache(...)` chained.
        invalidate_peer_cache(&state, Uuid::new_v4(), "default", "PATCH").await;
        // No panic = pass.
    }

    // --- Validator-normalization regression pins ---------
    // Validators return the trimmed string; handlers must persist
    // that returned value, never the original untrimmed request
    // string. The persisted value MUST equal the value the
    // validator validated.

    #[test]
    fn validate_issuer_returns_trimmed_form() {
        // Whitespace-padded request — validator trims
        // before parse, returns the trimmed form. The returned
        // value MUST equal trimmed input byte-for-byte: an
        // implementation that instead returned `Url::to_string`
        // would have canonicalized `https://gw.acme.example` to
        // `https://gw.acme.example/` (trailing slash) —
        // breaking the byte-exact OIDC iss-claim match.
        let out = validate_issuer("  https://gw.acme.example  ").expect("trim+parse ok");
        assert_eq!(
            out, "https://gw.acme.example",
            "MUST be trimmed input byte-for-byte (no URL canonicalization)",
        );
    }

    #[test]
    fn validate_issuer_preserves_path_and_no_trailing_slash() {
        // The most-load-bearing case: bare-authority issuer
        // like Authentik / Keycloak / Okta publish in their
        // iss claim. The URL serializer would add `/`; we
        // MUST preserve the exact input.
        let cases = [
            "https://gw.acme.example",
            "https://gw.acme.example/realm/foo",
            "http://localhost:8080",
        ];
        for c in cases {
            let out = validate_issuer(c).expect(c);
            assert_eq!(out, c, "issuer MUST round-trip byte-for-byte: {c}");
        }
    }

    #[test]
    fn validate_jwks_url_returns_trimmed_form() {
        // Same byte-for-byte preservation contract for
        // jwks_url — the runtime fetcher GETs the exact
        // URL stored; silently canonicalizing could break
        // the fetch against peers that are strict about
        // request shape.
        let out = validate_jwks_url(" https://gw.acme.example/.well-known/jwks.json\n")
            .expect("trim+parse ok");
        assert_eq!(out, "https://gw.acme.example/.well-known/jwks.json");
    }

    #[test]
    fn validate_jwks_url_preserves_bare_authority() {
        let out = validate_jwks_url("https://gw.acme.example").expect("ok");
        assert_eq!(
            out, "https://gw.acme.example",
            "jwks_url MUST preserve bare-authority shape (no Url::to_string slash)",
        );
    }

    #[test]
    fn validate_peer_name_trim_returns_trimmed() {
        let out = validate_peer_name_trim("  acme-prod  ").expect("trim ok");
        assert_eq!(out, "acme-prod");
    }

    #[test]
    fn validate_peer_name_trim_rejects_whitespace_only() {
        let err = validate_peer_name_trim("    ").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn validate_peer_name_trim_length_after_trim() {
        // 130 chars with 2 leading + 2 trailing spaces:
        // trimmed length is 126, which fits 1..=128.
        let inp = format!("  {}  ", "x".repeat(126));
        let out = validate_peer_name_trim(&inp).expect("under cap after trim");
        assert_eq!(out.chars().count(), 126);
        // 130 chars all non-whitespace: trimmed length is
        // 130, over the 128 cap.
        let too_long = "x".repeat(130);
        let err = validate_peer_name_trim(&too_long).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }
}
