//! `/scim/v2/Users` SCIM 2.0 endpoint.
//!
//! Implements the minimal subset of RFC 7644 §3 needed for
//! Okta / Authentik / EntraID to provision the gateway's
//! tenant with users:
//!
//! - `POST /scim/v2/Users` — create.
//! - `GET /scim/v2/Users/{id}` — read.
//! - `GET /scim/v2/Users?filter=...&startIndex=N&count=M` — list with
//!   pagination + minimal filter (`userName eq` / `externalId eq`).
//! - `PUT /scim/v2/Users/{id}` — full-resource replace.
//! - `PATCH /scim/v2/Users/{id}` — partial update, scoped to
//!   `replace` of `active` (activate/deactivate), the one op Authentik emits.
//! - `DELETE /scim/v2/Users/{id}` — soft delete. The row is
//!   retained as a tombstone (`active = false, deleted_at = now()`) so the
//!   enricher's tombstone-fallback keeps blocking the deprovisioned user;
//!   GET/LIST/PUT filter `deleted_at IS NULL`, so the resource still 404s
//!   to the IdP. See `docs/agents/ema.md`.
//!
//! Plus the constant introspection endpoints required by
//! every SCIM client at first contact:
//!
//! - `GET /scim/v2/ServiceProviderConfig` — capabilities.
//! - `GET /scim/v2/Schemas` — schema enumeration.
//! - `GET /scim/v2/ResourceTypes` — resource enumeration.
//!
//! ## Out of scope
//!
//! - **Filter beyond `userName eq` / `externalId eq`.** The
//!   subset covers bootstrap probes; richer filter support
//!   is not implemented.
//!
//! Groups live in `scim_groups.rs` (`/scim/v2/Groups` plus the
//! `scim_groups` + `scim_user_groups` tables), not this module.
//! Attribute enrichment onto `Principal` (bearer-validate-time lookup
//! of `scim_users` by `sub` or `external_id`) is handled by
//! `waygate_scim::enricher::PgScimEnricher`.
//!
//! ## Tenancy
//!
//! Every handler resolves `tenant_id` from the caller's
//! `Principal.tenant` (populated by the bearer validator
//! from the API key's `tenant_id` column). SCIM rows are
//! always tenant-scoped at the SQL layer; cross-tenant
//! access is structurally impossible.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use waygate_oidc::Principal;
use waygate_scim::{parse_user_filter, ListParams, ScimError, ScimUser, SCIM_SCHEMA_USER_URN};

use crate::scope::{require_scim_read, require_scim_write};
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    // Read endpoints are scim:read; mutations are scim:write.
    // Constants (ServiceProviderConfig, Schemas, ResourceTypes)
    // are gated by scim:read too — IdPs probing without any
    // SCIM scope shouldn't see the gateway's SCIM surface
    // shape.
    Router::new()
        .route("/scim/v2/Users", get(list_users))
        .route("/scim/v2/Users/{id}", get(get_user))
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(resource_types))
        .route("/scim/v2/Schemas", get(schemas))
        .layer(middleware::from_fn(require_scim_read))
        .merge(
            Router::new()
                .route("/scim/v2/Users", post(create_user))
                .route("/scim/v2/Users/{id}", put(replace_user))
                .route("/scim/v2/Users/{id}", patch(patch_user))
                .route("/scim/v2/Users/{id}", delete(delete_user))
                .layer(middleware::from_fn(require_scim_write)),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<i64>,
    #[serde(default)]
    pub count: Option<i64>,
}

async fn list_users(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let filter = match parse_user_filter(q.filter.as_deref().unwrap_or("")) {
        Ok(f) => f,
        Err(e) => return scim_error_response(e),
    };
    let params = ListParams {
        start_index: q.start_index.unwrap_or(1),
        count: q.count.unwrap_or(50),
    };
    let tenant = principal.tenant.as_str();
    match store.list(tenant, filter, params).await {
        Ok(result) => Json(scim_list_response(result, params)).into_response(),
        Err(e) => scim_error_response(e),
    }
}

async fn get_user(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let tenant = principal.tenant.as_str();
    match store.get(tenant, id).await {
        Ok(Some(u)) => Json(user_to_scim_resource(&u)).into_response(),
        Ok(None) => scim_error_response(ScimError::NotFound(format!("user {id}"))),
        Err(e) => scim_error_response(e),
    }
}

async fn create_user(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let parsed = match parse_user_request(&body) {
        Ok(p) => p,
        Err(e) => return scim_error_response(e),
    };
    let tenant = principal.tenant.as_str();
    let result = store
        .create(
            tenant,
            parsed.external_id.as_deref(),
            &parsed.user_name,
            parsed.active,
            parsed.attrs,
        )
        .await;
    match result {
        Ok(u) => {
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_users",
                &u.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_users.create",
                scim_user_reason(&u),
            )
            .await;
            // Structured provisioning-log entry. Same
            // best-effort posture as the shared logged-disposition recorder
            // (mutation already committed; failure logs +
            // drops). `detail` carries the active flag so the
            // dashboard timeline can distinguish provision-
            // active vs. provision-deactivated at a glance.
            crate::scim_provisioning::append(
                &state,
                tenant,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
                u.id,
                &u.user_name,
                u.external_id.as_deref(),
                "create",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                serde_json::json!({ "active": u.active }),
            )
            .await;
            let resp = Json(user_to_scim_resource(&u));
            (StatusCode::CREATED, resp).into_response()
        }
        Err(e) => scim_error_response(e),
    }
}

async fn replace_user(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let parsed = match parse_user_request(&body) {
        Ok(p) => p,
        Err(e) => return scim_error_response(e),
    };
    // If the body carries an
    // `id`, it MUST match the URL id. RFC 7644 §3.5.1 says
    // PUT replaces "the entire resource"; a client sending
    // a body with a different `id` is asking to mutate a
    // different resource through the wrong URL — almost
    // always a client bug, and silently coercing it would
    // mask the bug. Reject as InvalidResource (400).
    if let Some(body_id) = parsed.body_id.as_deref() {
        if body_id != id.to_string() {
            return scim_error_response(ScimError::InvalidResource(format!(
                "body `id` ({body_id}) does not match URL id ({id})"
            )));
        }
    }
    let tenant = principal.tenant.as_str();
    let result = store
        .replace(
            tenant,
            id,
            parsed.external_id.as_deref(),
            &parsed.user_name,
            parsed.active,
            parsed.attrs,
        )
        .await;
    match result {
        Ok(Some(u)) => {
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_users",
                &u.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_users.replace",
                scim_user_reason(&u),
            )
            .await;
            crate::scim_provisioning::append(
                &state,
                tenant,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
                u.id,
                &u.user_name,
                u.external_id.as_deref(),
                "replace",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                serde_json::json!({ "active": u.active }),
            )
            .await;
            Json(user_to_scim_resource(&u)).into_response()
        }
        Ok(None) => scim_error_response(ScimError::NotFound(format!("user {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// RFC 7644 §3.5.2 PATCH for Users — tightly scoped to the one operation
/// Authentik emits for user lifecycle: `replace` of `active`
/// (activate/deactivate). Both shapes are accepted:
/// `{op:replace, path:"active", value:<bool>}` and the no-path form
/// `{op:replace, value:{"active":<bool>}}`. Any other op or path is rejected
/// (400 `invalidValue`) — we don't model partial updates of other attributes,
/// and silently accepting them would mask an IdP misconfiguration.
///
/// NOTE: a PATCH deactivation here is a soft state flip (`active=false`). It does
/// NOT replace the deprovisioning tombstone — scope-exit remains a DELETE
/// (soft-delete with `deleted_at`), and the bearer enricher still fails closed on
/// an inactive OR deleted directory row.
async fn patch_user(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let new_active = match parse_active_patch(&body) {
        Ok(a) => a,
        Err(e) => return scim_error_response(e),
    };
    let tenant = principal.tenant.as_str();
    // Fetch the current row so PATCH modifies ONLY `active` and preserves
    // user_name / external_id / attrs (PATCH is partial; `replace` rewrites the
    // whole row, so we feed the unchanged fields back in).
    let current = match store.get(tenant, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return scim_error_response(ScimError::NotFound(format!("user {id}"))),
        Err(e) => return scim_error_response(e),
    };
    if current.active == new_active {
        // Idempotent PATCH: nothing to change, return the resource as-is.
        return Json(user_to_scim_resource(&current)).into_response();
    }
    let result = store
        .replace(
            tenant,
            id,
            current.external_id.as_deref(),
            &current.user_name,
            new_active,
            current.attrs.clone(),
        )
        .await;
    match result {
        Ok(Some(u)) => {
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_users",
                &u.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_users.patch",
                scim_user_reason(&u),
            )
            .await;
            crate::scim_provisioning::append(
                &state,
                tenant,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
                u.id,
                &u.user_name,
                u.external_id.as_deref(),
                "patch",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                serde_json::json!({ "active": u.active }),
            )
            .await;
            // `active` is an authorization-
            // relevant fact the bearer SCIM enricher caches (≤60s TTL). Evict it
            // so a PATCH deactivation blocks on the NEXT request, not after the
            // TTL — same eviction `delete_user` does. The resolver keys on
            // (tenant, sub) where sub is external_id OR user_name, so evict both.
            if let Some(enricher) = state.identity.scim_enricher.as_ref() {
                enricher.invalidate(tenant, &u.user_name).await;
                if let Some(ext) = u.external_id.as_deref() {
                    enricher.invalidate(tenant, ext).await;
                }
            }
            Json(user_to_scim_resource(&u)).into_response()
        }
        Ok(None) => scim_error_response(ScimError::NotFound(format!("user {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// Extract the new `active` value from a SCIM PatchOp body, accepting ONLY the
/// `replace`-of-`active` shapes. Errors (400 `invalidValue`) on an empty op list,
/// an unsupported op/path, or a non-boolean value.
fn parse_active_patch(body: &Value) -> Result<bool, ScimError> {
    let ops = body
        .get("Operations")
        .or_else(|| body.get("operations"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ScimError::InvalidResource("PATCH requires a non-empty `Operations` array".into())
        })?;
    let mut active: Option<bool> = None;
    for op in ops {
        let op_kind = op
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if op_kind != "replace" {
            return Err(ScimError::InvalidResource(format!(
                "unsupported PATCH op `{op_kind}` (Users PATCH supports only `replace` of `active`)"
            )));
        }
        let path = op.get("path").and_then(Value::as_str).map(str::trim);
        let value = match path {
            Some("active") => op.get("value").cloned().unwrap_or(Value::Null),
            None | Some("") => op
                .get("value")
                .and_then(|v| v.get("active"))
                .cloned()
                .unwrap_or(Value::Null),
            Some(other) => {
                return Err(ScimError::InvalidResource(format!(
                    "unsupported PATCH path `{other}` (Users PATCH supports only `active`)"
                )));
            }
        };
        active = Some(coerce_scim_bool(&value).ok_or_else(|| {
            ScimError::InvalidResource("PATCH `active` value must be a boolean".into())
        })?);
    }
    active.ok_or_else(|| ScimError::InvalidResource("PATCH did not set `active`".into()))
}

/// SCIM clients occasionally send booleans as JSON strings ("true"/"false").
fn coerce_scim_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

async fn delete_user(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(store) = state.identity.scim_users.get() else {
        return scim_503(state.identity.scim_users.unavailable_msg());
    };
    let tenant_str = principal.tenant.as_str();
    // Capture the user BEFORE deleting so the
    // AdminMutation event records `user_name` (not just
    // the id). Compliance reviews of "who deprovisioned
    // X" need the human-readable name.
    //
    // Distinguish "row was absent"
    // from "get errored". On the error case, log a warn and
    // proceed — we still want to record the delete (even
    // with id-only target info) if the row really did exist.
    // Silently collapsing both cases would erase the record of a
    // successful delete if Postgres flaps transiently.
    let pre_delete: Option<waygate_scim::ScimUser> = match store.get(tenant_str, id).await {
        Ok(maybe) => maybe,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant = %tenant_str,
                user_id = %id,
                "scim_users.delete: pre-delete get failed; proceeding with id-only record on success",
            );
            None
        }
    };
    let result = store.delete(tenant_str, id).await;
    match result {
        Ok(true) => {
            // Record the delete either way. When `pre_delete`
            // is Some we get the full target identifiers; when
            // None (get errored before delete succeeded) we
            // fall back to the URL id as the display string.
            // Either way the operator sees a timeline entry
            // for the successful delete.
            match pre_delete.as_ref() {
                Some(u) => {
                    crate::admin_mutation::record_admin_mutation_logged(
                        &state,
                        "scim_users",
                        &u.id.to_string(),
                        principal.tenant.as_str(),
                        Some(&principal),
                        "scim_users.delete",
                        scim_user_reason(u),
                    )
                    .await;
                    crate::scim_provisioning::append(
                        &state,
                        tenant_str,
                        Some(&principal),
                        waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
                        u.id,
                        &u.user_name,
                        u.external_id.as_deref(),
                        "delete",
                        waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                        None,
                        serde_json::json!({ "active": u.active }),
                    )
                    .await;
                }
                None => {
                    // r4: emit the id-only audit_log row so the
                    // compliance chain captures the delete even
                    // when the pre-delete read failed. The
                    // provisioning_log keeps its own id-only
                    // row; both surfaces now agree on the event.
                    crate::admin_mutation::record_admin_mutation_logged(
                        &state,
                        "scim_users",
                        &id.to_string(),
                        principal.tenant.as_str(),
                        Some(&principal),
                        "scim_users.delete",
                        format!("scim user id={id} (pre-delete get failed; id-only record)"),
                    )
                    .await;
                    crate::scim_provisioning::append(
                        &state,
                        tenant_str,
                        Some(&principal),
                        waygate_dashboard_stores::scim_provisioning_log::TargetKind::User,
                        id,
                        &id.to_string(),
                        None,
                        "delete",
                        waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                        None,
                        serde_json::json!({ "pre_delete_get_failed": true }),
                    )
                    .await;
                }
            }
            // Evict the bearer SCIM
            // enricher cache for this user so the soft-delete blocks on
            // the NEXT request, not after the ≤60s cache TTL. The
            // resolver keys on (tenant, external_id OR user_name), so
            // evict both possible keys. Best-effort: when the pre-delete
            // read failed we have no identifiers and fall back to the TTL
            // bound (the row is already tombstoned in the DB).
            if let (Some(enricher), Some(u)) =
                (state.identity.scim_enricher.as_ref(), pre_delete.as_ref())
            {
                enricher.invalidate(tenant_str, &u.user_name).await;
                if let Some(ext) = u.external_id.as_deref() {
                    enricher.invalidate(tenant_str, ext).await;
                }
            }
            // RFC 7644 §3.6: 204 No Content on successful delete.
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => scim_error_response(ScimError::NotFound(format!("user {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// Rich audit-reason line for a SCIM user row — what the shared recorder
/// stamps on the `AdminMutation` event (`admin_mutation` module; SCIM uses
/// the logged disposition).
fn scim_user_reason(user: &waygate_scim::ScimUser) -> String {
    format!(
        "scim user id={} user_name={} external_id={} active={}",
        user.id,
        user.user_name,
        user.external_id.as_deref().unwrap_or(""),
        user.active,
    )
}

/// RFC 7644 §4: capability descriptor. Tells the IdP what
/// optional SCIM features the gateway implements. Round 1
/// answers "no PATCH, no bulk, no e-tag, no sort, no
/// password change, filter capped at 1 condition" — the
/// minimum that lets a SCIM client run.
async fn service_provider_config(
    State(_): State<Arc<AdminState>>,
    Extension(_principal): Extension<Principal>,
) -> Response {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        // SCIM discovery
        // (this endpoint) + GET / LIST require
        // `scim:read`; POST / PUT / DELETE require
        // `scim:write`. IdPs typically mint one API key
        // carrying BOTH scopes so the same key works for
        // the initial probe AND for provisioning. The
        // descriptor below names both so operators don't
        // mint a write-only key and 403 on every read.
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication via a gateway-issued API key. Mint with BOTH `scim:read` (required for this discovery endpoint + all GET / LIST calls) AND `scim:write` (required for POST / PUT / DELETE provisioning) — most IdPs only support a single bearer per SCIM connection.",
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750",
                "type": "oauthbearertoken",
                "primary": true
            }
        ]
    }))
    .into_response()
}

/// RFC 7644 §4: resource type enumeration. Lists User (this module)
/// and Group (`scim_groups.rs`).
async fn resource_types(
    State(_): State<Arc<AdminState>>,
    Extension(_principal): Extension<Principal>,
) -> Response {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "Account / identity user resource",
                "schema": SCIM_SCHEMA_USER_URN
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Identity group resource (membership of Users)",
                "schema": waygate_scim::SCIM_SCHEMA_GROUP_URN
            }
        ]
    }))
    .into_response()
}

/// RFC 7643 §8.7: schema descriptors. We return only the
/// User schema; clients filter by `id`.
async fn schemas(
    State(_): State<Arc<AdminState>>,
    Extension(_principal): Extension<Principal>,
) -> Response {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
                "id": SCIM_SCHEMA_USER_URN,
                "name": "User",
                "description": "SCIM Core User",
                "attributes": [
                    { "name": "userName", "type": "string", "required": true, "uniqueness": "server" },
                    { "name": "externalId", "type": "string", "required": false, "uniqueness": "server" },
                    { "name": "active", "type": "boolean", "required": false },
                    { "name": "name", "type": "complex", "required": false },
                    { "name": "emails", "type": "complex", "multiValued": true, "required": false },
                    { "name": "displayName", "type": "string", "required": false }
                ]
            },
            {
                "id": waygate_scim::SCIM_SCHEMA_GROUP_URN,
                "name": "Group",
                "description": "SCIM Core Group with members[] referencing Users",
                "attributes": [
                    { "name": "displayName", "type": "string", "required": true, "uniqueness": "server" },
                    { "name": "externalId", "type": "string", "required": false, "uniqueness": "server" },
                    {
                        "name": "members",
                        "type": "complex",
                        "multiValued": true,
                        "required": false,
                        "subAttributes": [
                            { "name": "value", "type": "string", "required": true, "description": "User id" },
                            { "name": "$ref", "type": "reference", "required": false },
                            { "name": "display", "type": "string", "required": false },
                            { "name": "type", "type": "string", "required": false }
                        ]
                    }
                ]
            }
        ]
    }))
    .into_response()
}

// --- parse / render helpers ----------------------------

#[derive(Debug)]
struct ParsedUserRequest {
    user_name: String,
    external_id: Option<String>,
    active: bool,
    /// Body-supplied `id`
    /// captured BEFORE the strip pass below so the PUT
    /// handler can validate it matches the URL id. POSTs
    /// must not carry one (server-assigned); PUTs may
    /// carry one but it MUST match the URL id.
    body_id: Option<String>,
    /// Everything other than `userName` / `externalId` /
    /// `active` / `schemas` / `id` (the fields we control
    /// at the column level). Stored verbatim so the
    /// round-trip preserves IdP-emitted fields.
    attrs: Value,
}

fn parse_user_request(body: &Value) -> Result<ParsedUserRequest, ScimError> {
    let obj = body
        .as_object()
        .ok_or_else(|| ScimError::InvalidResource("request body must be a JSON object".into()))?;
    // RFC 7644 §3.3: `schemas` array must include the
    // resource type's URN. Some IdPs omit it; we accept
    // omitted but reject explicit-wrong.
    if let Some(schemas) = obj.get("schemas") {
        let arr = schemas
            .as_array()
            .ok_or_else(|| ScimError::InvalidResource("`schemas` must be an array".into()))?;
        if !arr.is_empty() && !arr.iter().any(|s| s.as_str() == Some(SCIM_SCHEMA_USER_URN)) {
            return Err(ScimError::InvalidResource(format!(
                "`schemas` does not include `{SCIM_SCHEMA_USER_URN}`"
            )));
        }
    }
    let user_name = obj
        .get("userName")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ScimError::InvalidResource("missing required `userName` (RFC 7643 §4.1.1)".into())
        })?
        .to_owned();
    let external_id = obj
        .get("externalId")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let active = obj.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
    let body_id = obj.get("id").and_then(|v| v.as_str()).map(str::to_owned);
    // Strip the column-level fields from `attrs` so we
    // don't double-store them; whatever else the IdP sent
    // (name, emails, etc.) stays.
    let mut attrs = body.clone();
    if let Some(o) = attrs.as_object_mut() {
        o.remove("userName");
        o.remove("externalId");
        o.remove("active");
        o.remove("schemas");
        o.remove("id");
        o.remove("meta");
    }
    Ok(ParsedUserRequest {
        user_name,
        external_id,
        active,
        body_id,
        attrs,
    })
}

/// Render a [`ScimUser`] as the on-wire SCIM resource JSON:
/// stamp `schemas`, `id`, the column fields, and `meta`,
/// then splat `attrs` on top so the IdP gets everything
/// they sent back.
fn user_to_scim_resource(u: &ScimUser) -> Value {
    let mut resource = serde_json::Map::new();
    // Start with the persisted attrs so any IdP-emitted
    // fields (name, emails, ...) are present...
    if let Some(o) = u.attrs.as_object() {
        for (k, v) in o {
            resource.insert(k.clone(), v.clone());
        }
    }
    // ...then overlay the column-authoritative fields so a
    // tampered `attrs` can't spoof `id` / `userName` /
    // `active`.
    resource.insert("schemas".into(), json!([SCIM_SCHEMA_USER_URN]));
    resource.insert("id".into(), json!(u.id.to_string()));
    resource.insert("userName".into(), json!(u.user_name));
    if let Some(eid) = u.external_id.as_deref() {
        resource.insert("externalId".into(), json!(eid));
    }
    resource.insert("active".into(), json!(u.active));
    resource.insert(
        "meta".into(),
        json!({
            "resourceType": "User",
            "created": u.created_at,
            "lastModified": u.updated_at,
            "location": format!("/scim/v2/Users/{}", u.id),
        }),
    );
    Value::Object(resource)
}

/// SCIM `ListResponse` per RFC 7644 §3.4.2.
fn scim_list_response(result: waygate_scim::ListResult, params: ListParams) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": result.total_results,
        "startIndex": params.start_index.max(1),
        "itemsPerPage": result.resources.len(),
        "Resources": result.resources.iter().map(user_to_scim_resource).collect::<Vec<_>>(),
    })
}

/// SCIM error response shape per RFC 7644 §3.12.
fn scim_error_response(e: ScimError) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": e.http_status().to_string(),
        "detail": e.to_string(),
    });
    if let (Some(scim_type), Some(obj)) = (e.scim_type(), body.as_object_mut()) {
        obj.insert("scimType".into(), json!(scim_type));
    }
    (status, Json(body)).into_response()
}

fn scim_503(detail: &str) -> Response {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "503",
        "detail": detail,
    });
    (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_request_minimum() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_USER_URN],
            "userName": "alice@example.test"
        });
        let p = parse_user_request(&body).unwrap();
        assert_eq!(p.user_name, "alice@example.test");
        assert!(p.active, "active defaults to true per RFC 7643");
        assert!(p.external_id.is_none());
    }

    #[test]
    fn parse_user_request_strips_column_fields_from_attrs() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_USER_URN],
            "userName": "alice",
            "externalId": "okta-abc",
            "active": false,
            "name": { "givenName": "Alice", "familyName": "Example" },
            "emails": [{ "value": "alice@example.test", "primary": true }]
        });
        let p = parse_user_request(&body).unwrap();
        assert_eq!(p.user_name, "alice");
        assert_eq!(p.external_id.as_deref(), Some("okta-abc"));
        assert!(!p.active);
        // attrs must still contain name + emails, must NOT
        // contain userName / externalId / active / schemas.
        let attrs = p.attrs.as_object().unwrap();
        assert!(attrs.contains_key("name"));
        assert!(attrs.contains_key("emails"));
        assert!(!attrs.contains_key("userName"));
        assert!(!attrs.contains_key("externalId"));
        assert!(!attrs.contains_key("active"));
        assert!(!attrs.contains_key("schemas"));
    }

    #[test]
    fn parse_user_request_missing_username_rejected() {
        let body = json!({ "schemas": [SCIM_SCHEMA_USER_URN] });
        let err = parse_user_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    #[test]
    fn parse_user_request_wrong_schema_rejected() {
        let body = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "userName": "alice"
        });
        let err = parse_user_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    /// PUT body's `id` (when
    /// present) MUST match the URL id. Pinning the
    /// parse-time capture so the handler's mismatch check
    /// always has the body id available; if a future
    /// refactor drops the capture, this test fails before
    /// it ships.
    #[test]
    fn parse_user_request_captures_body_id_for_put_mismatch_check() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_USER_URN],
            "id": "11111111-1111-1111-1111-111111111111",
            "userName": "alice"
        });
        let p = parse_user_request(&body).unwrap();
        assert_eq!(
            p.body_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        // Body id must also be stripped from attrs — the
        // column-authoritative field wins on render and we
        // don't double-store.
        assert!(!p.attrs.as_object().unwrap().contains_key("id"));
    }

    /// Column-authoritative fields override anything the IdP
    /// might smuggle into `attrs`. A tampered attrs blob
    /// can't change `id` / `userName` / `active` on the
    /// rendered resource.
    #[test]
    fn user_to_scim_resource_column_fields_win() {
        let u = ScimUser {
            id: Uuid::from_u128(1),
            tenant_id: "default".into(),
            external_id: Some("ext-1".into()),
            user_name: "alice".into(),
            active: true,
            attrs: json!({
                "userName": "spoofed",
                "active": false,
                "id": "00000000-0000-0000-0000-000000000000",
                "name": { "givenName": "Alice" }
            }),
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let r = user_to_scim_resource(&u);
        assert_eq!(r["userName"], json!("alice"));
        assert_eq!(r["active"], json!(true));
        assert_eq!(r["id"], json!(u.id.to_string()));
        // attrs-supplied non-overlapping field survives.
        assert_eq!(r["name"]["givenName"], json!("Alice"));
    }

    // --- PATCH active parsing ---

    fn patch_op(ops: Value) -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": ops,
        })
    }

    #[test]
    fn patch_active_replace_with_path() {
        let b = patch_op(json!([{ "op": "replace", "path": "active", "value": false }]));
        assert!(!parse_active_patch(&b).unwrap());
        let b = patch_op(json!([{ "op": "replace", "path": "active", "value": true }]));
        assert!(parse_active_patch(&b).unwrap());
    }

    #[test]
    fn patch_active_replace_no_path_value_object() {
        // Authentik's deactivation shape: {op:replace, value:{active:false}}.
        let b = patch_op(json!([{ "op": "replace", "value": { "active": false } }]));
        assert!(!parse_active_patch(&b).unwrap());
    }

    #[test]
    fn patch_active_accepts_string_boolean() {
        let b = patch_op(json!([{ "op": "replace", "path": "active", "value": "false" }]));
        assert!(!parse_active_patch(&b).unwrap());
    }

    #[test]
    fn patch_rejects_non_replace_op() {
        let b = patch_op(json!([{ "op": "add", "path": "active", "value": true }]));
        assert!(matches!(
            parse_active_patch(&b).unwrap_err(),
            ScimError::InvalidResource(_)
        ));
    }

    #[test]
    fn patch_rejects_unsupported_path() {
        let b = patch_op(json!([{ "op": "replace", "path": "userName", "value": "bob" }]));
        assert!(matches!(
            parse_active_patch(&b).unwrap_err(),
            ScimError::InvalidResource(_)
        ));
    }

    #[test]
    fn patch_rejects_non_bool_active() {
        let b = patch_op(json!([{ "op": "replace", "path": "active", "value": "maybe" }]));
        assert!(parse_active_patch(&b).is_err());
    }

    #[test]
    fn patch_rejects_empty_operations() {
        let b = patch_op(json!([]));
        assert!(parse_active_patch(&b).is_err());
        let b = json!({ "schemas": [] });
        assert!(parse_active_patch(&b).is_err());
    }
}
