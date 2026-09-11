//! `/scim/v2/Groups` SCIM 2.0 endpoint.
//!
//! Companion to [`crate::scim_users`]. Implements:
//!
//! - `POST /scim/v2/Groups` — create with members.
//! - `GET /scim/v2/Groups/{id}` — read (members rendered).
//! - `GET /scim/v2/Groups?filter=...` — list with
//!   `displayName eq` / `externalId eq`.
//! - `PUT /scim/v2/Groups/{id}` — full replace
//!   (group fields + membership set).
//! - `PATCH /scim/v2/Groups/{id}` — partial membership delta:
//!   `add`/`remove`/`replace` on `members`, the ops Authentik emits.
//! - `DELETE /scim/v2/Groups/{id}` — cascades memberships.
//!
//! ## Cross-tenant defense
//!
//! Member references in the inbound body are user UUIDs.
//! The migration-0020 `scim_user_groups_tenant_match`
//! trigger enforces both sides' tenants match the row's
//! tenant; a cross-tenant member id surfaces as a SCIM
//! `invalidValue` 400 to the client (handled in the
//! store's `insert_memberships` error mapping).
//!
//! ## Audit
//!
//! Same SCIM-disposition AdminMutation recording (the shared
//! `admin_mutation::record_admin_mutation_logged`)
//! evidence as scim_users, except the helper is local
//! (group-specific reason string carrying display_name +
//! member count).

use std::collections::BTreeSet;
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
use waygate_scim::{parse_group_filter, ListParams, ScimError, ScimGroup, SCIM_SCHEMA_GROUP_URN};

use crate::scope::{require_scim_read, require_scim_write};
use crate::state::AdminState;

pub fn router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/scim/v2/Groups", get(list_groups))
        .route("/scim/v2/Groups/{id}", get(get_group))
        .layer(middleware::from_fn(require_scim_read))
        .merge(
            Router::new()
                .route("/scim/v2/Groups", post(create_group))
                .route("/scim/v2/Groups/{id}", put(replace_group))
                .route("/scim/v2/Groups/{id}", patch(patch_group))
                .route("/scim/v2/Groups/{id}", delete(delete_group))
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

async fn list_groups(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Query(q): Query<ListQuery>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let filter = match parse_group_filter(q.filter.as_deref().unwrap_or("")) {
        Ok(f) => f,
        Err(e) => return scim_error_response(e),
    };
    let params = ListParams {
        start_index: q.start_index.unwrap_or(1),
        count: q.count.unwrap_or(50),
    };
    let tenant = principal.tenant.as_str();
    match store.list(tenant, filter, params).await {
        Ok(result) => {
            // Resolve members per group (joins
            // scim_user_groups → scim_users). Sequential
            // because typical SCIM list pages are small
            // (page=50 default); a future optimisation
            // could batch one LATERAL query, but the
            // simpler shape is easier to audit.
            let mut resources_rendered: Vec<Value> = Vec::with_capacity(result.resources.len());
            for g in &result.resources {
                let members = match store.members(tenant, g.id, &state.public_url).await {
                    Ok(m) => m,
                    Err(e) => return scim_error_response(e),
                };
                resources_rendered.push(group_to_scim_resource(g, &members));
            }
            Json(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": result.total_results,
                "startIndex": params.start_index.max(1),
                "itemsPerPage": resources_rendered.len(),
                "Resources": resources_rendered,
            }))
            .into_response()
        }
        Err(e) => scim_error_response(e),
    }
}

async fn get_group(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let tenant = principal.tenant.as_str();
    match store.get(tenant, id).await {
        Ok(Some(g)) => {
            let members = match store.members(tenant, g.id, &state.public_url).await {
                Ok(m) => m,
                Err(e) => return scim_error_response(e),
            };
            Json(group_to_scim_resource(&g, &members)).into_response()
        }
        Ok(None) => scim_error_response(ScimError::NotFound(format!("group {id}"))),
        Err(e) => scim_error_response(e),
    }
}

async fn create_group(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let parsed = match parse_group_request(&body) {
        Ok(p) => p,
        Err(e) => return scim_error_response(e),
    };
    let tenant_str = principal.tenant.as_str();
    let result = store
        .create(
            tenant_str,
            parsed.external_id.as_deref(),
            &parsed.display_name,
            parsed.attrs,
            &parsed.member_user_ids,
        )
        .await;
    match result {
        Ok(g) => {
            invalidate_group_authorization_caches(&state);
            // The group row already
            // committed; if members() fails we still record
            // both audit + provisioning entries (with
            // `member_count_unknown: true` in detail) so the
            // committed mutation isn't invisible. SCIM error
            // response still goes back so the client sees the
            // failure shape — but the gateway-side record
            // exists.
            let members_res = store.members(tenant_str, g.id, &state.public_url).await;
            let (member_count_for_record, detail_for_record): (usize, serde_json::Value) =
                match members_res.as_ref() {
                    Ok(m) => (m.len(), serde_json::json!({ "member_count": m.len() })),
                    Err(_) => (0, serde_json::json!({ "member_count_unknown": true })),
                };
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_groups",
                &g.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_groups.create",
                scim_group_reason(&g, member_count_for_record),
            )
            .await;
            crate::scim_provisioning::append(
                &state,
                tenant_str,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
                g.id,
                &g.display_name,
                g.external_id.as_deref(),
                "create",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                detail_for_record,
            )
            .await;
            match members_res {
                Ok(members) => (
                    StatusCode::CREATED,
                    Json(group_to_scim_resource(&g, &members)),
                )
                    .into_response(),
                Err(e) => scim_error_response(e),
            }
        }
        Err(e) => scim_error_response(e),
    }
}

async fn replace_group(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let parsed = match parse_group_request(&body) {
        Ok(p) => p,
        Err(e) => return scim_error_response(e),
    };
    // Same id-mismatch guard as scim_users: body.id (when present) MUST
    // match the URL id.
    if let Some(body_id) = parsed.body_id.as_deref() {
        if body_id != id.to_string() {
            return scim_error_response(ScimError::InvalidResource(format!(
                "body `id` ({body_id}) does not match URL id ({id})"
            )));
        }
    }
    let tenant_str = principal.tenant.as_str();
    let result = store
        .replace(
            tenant_str,
            id,
            parsed.external_id.as_deref(),
            &parsed.display_name,
            parsed.attrs,
            &parsed.member_user_ids,
        )
        .await;
    match result {
        Ok(Some(g)) => {
            invalidate_group_authorization_caches(&state);
            // Same members()-failure
            // shape as create_group. The replace already
            // committed; record both audit + provisioning
            // entries either way, then propagate the
            // members() error to the SCIM client.
            let members_res = store.members(tenant_str, g.id, &state.public_url).await;
            let (member_count_for_record, detail_for_record): (usize, serde_json::Value) =
                match members_res.as_ref() {
                    Ok(m) => (m.len(), serde_json::json!({ "member_count": m.len() })),
                    Err(_) => (0, serde_json::json!({ "member_count_unknown": true })),
                };
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_groups",
                &g.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_groups.replace",
                scim_group_reason(&g, member_count_for_record),
            )
            .await;
            crate::scim_provisioning::append(
                &state,
                tenant_str,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
                g.id,
                &g.display_name,
                g.external_id.as_deref(),
                "replace",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                detail_for_record,
            )
            .await;
            match members_res {
                Ok(members) => Json(group_to_scim_resource(&g, &members)).into_response(),
                Err(e) => scim_error_response(e),
            }
        }
        Ok(None) => scim_error_response(ScimError::NotFound(format!("group {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// Rich audit-reason line for a SCIM group row — what the shared recorder
/// stamps on the `AdminMutation` event (`admin_mutation` module; SCIM uses
/// the logged disposition). `member_count` is passed separately: the
/// patch/delete paths know the count without holding the full member list.
fn scim_group_reason(group: &ScimGroup, member_count: usize) -> String {
    format!(
        "scim group id={} display_name={} external_id={} members={}",
        group.id,
        group.display_name,
        group.external_id.as_deref().unwrap_or(""),
        member_count,
    )
}

/// RFC 7644 §3.5.2 PATCH for Groups — tightly scoped to the membership-delta
/// operations Authentik emits for group sync. PATCH is a *partial* update over
/// the current membership, so we read the current member set, apply the ops,
/// and write the resulting full set back through `replace` (which diffs).
///
/// Supported ops (path is the `members` attribute, case-insensitive):
/// `add` (value array → union), `remove` (value array → difference, or the
/// `members[value eq "<uuid>"]` filter-path form → remove one), and `replace`
/// (value array → set the full membership).
///
/// Group/display-name field edits and any other op/path are rejected
/// (400 `invalidValue`) — Authentik doesn't PATCH those, and a full field
/// replace goes through PUT. `value` must be non-empty: a membership op with an
/// empty/missing value is refused so a malformed body can't silently wipe the
/// group (a deliberate full clear uses PUT with empty `members`).
async fn patch_group(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let tenant_str = principal.tenant.as_str();
    // Fetch the group (for displayName/externalId/attrs) and its current members
    // — PATCH deltas apply on top of the existing membership.
    let group = match store.get(tenant_str, id).await {
        Ok(Some(g)) => g,
        Ok(None) => return scim_error_response(ScimError::NotFound(format!("group {id}"))),
        Err(e) => return scim_error_response(e),
    };
    let current = match store.members(tenant_str, id, &state.public_url).await {
        Ok(m) => m,
        Err(e) => return scim_error_response(e),
    };
    let mut member_ids: BTreeSet<Uuid> = BTreeSet::new();
    for m in &current {
        match Uuid::parse_str(&m.value) {
            Ok(u) => {
                member_ids.insert(u);
            }
            Err(e) => {
                return scim_error_response(ScimError::InvalidResource(format!(
                    "stored member id `{}` is not a UUID: {e}",
                    m.value
                )))
            }
        }
    }
    if let Err(e) = apply_group_member_patch(&body, &mut member_ids) {
        return scim_error_response(e);
    }
    let new_ids: Vec<Uuid> = member_ids.iter().copied().collect();
    let result = store
        .replace(
            tenant_str,
            id,
            group.external_id.as_deref(),
            &group.display_name,
            group.attrs.clone(),
            &new_ids,
        )
        .await;
    match result {
        Ok(Some(g)) => {
            invalidate_group_authorization_caches(&state);
            let members_res = store.members(tenant_str, g.id, &state.public_url).await;
            let (count, detail): (usize, Value) = match members_res.as_ref() {
                Ok(m) => (m.len(), json!({ "member_count": m.len() })),
                Err(_) => (0, json!({ "member_count_unknown": true })),
            };
            crate::admin_mutation::record_admin_mutation_logged(
                &state,
                "scim_groups",
                &g.id.to_string(),
                principal.tenant.as_str(),
                Some(&principal),
                "scim_groups.patch",
                scim_group_reason(&g, count),
            )
            .await;
            crate::scim_provisioning::append(
                &state,
                tenant_str,
                Some(&principal),
                waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
                g.id,
                &g.display_name,
                g.external_id.as_deref(),
                "patch",
                waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                None,
                detail,
            )
            .await;
            match members_res {
                Ok(members) => Json(group_to_scim_resource(&g, &members)).into_response(),
                Err(e) => scim_error_response(e),
            }
        }
        Ok(None) => scim_error_response(ScimError::NotFound(format!("group {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// Apply a SCIM PatchOp body's membership operations to `member_ids`. See
/// [`patch_group`] for the supported shapes. `add` is idempotent (set union);
/// `remove` of an absent member is a no-op (RFC 7644 §3.5.2 permits it).
fn apply_group_member_patch(
    body: &Value,
    member_ids: &mut BTreeSet<Uuid>,
) -> Result<(), ScimError> {
    let ops = body
        .get("Operations")
        .or_else(|| body.get("operations"))
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ScimError::InvalidResource("PATCH requires a non-empty `Operations` array".into())
        })?;
    for op in ops {
        let op_kind = op
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = op
            .get("path")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        let path_l = path.to_ascii_lowercase();
        // Filter-path remove: `members[value eq "<uuid>"]`.
        if op_kind == "remove" && path_l.starts_with("members[") {
            let raw = extract_filter_member_id(path).ok_or_else(|| {
                ScimError::InvalidResource(format!(
                    "unsupported PATCH path `{path}` (expected members[value eq \"<id>\"])"
                ))
            })?;
            let uuid = Uuid::parse_str(raw).map_err(|e| {
                ScimError::InvalidResource(format!("PATCH member id `{raw}` is not a UUID: {e}"))
            })?;
            member_ids.remove(&uuid);
            continue;
        }
        if path_l != "members" {
            return Err(ScimError::InvalidResource(format!(
                "unsupported PATCH path `{path}` (Groups PATCH supports only `members`)"
            )));
        }
        let ids = patch_member_value_ids(op.get("value"))?;
        match op_kind.as_str() {
            "add" => {
                for u in ids {
                    member_ids.insert(u);
                }
            }
            "remove" => {
                for u in ids {
                    member_ids.remove(&u);
                }
            }
            "replace" => {
                *member_ids = ids.into_iter().collect();
            }
            other => {
                return Err(ScimError::InvalidResource(format!(
                    "unsupported PATCH op `{other}` (Groups PATCH supports add/remove/replace on `members`)"
                )))
            }
        }
    }
    Ok(())
}

/// Parse a PatchOp `value` (array of `{value:<uuid>}`, or bare `"<uuid>"`
/// strings) into user ids. Requires a non-empty array — an empty/missing value
/// on a membership op is refused to avoid an accidental membership wipe.
fn patch_member_value_ids(value: Option<&Value>) -> Result<Vec<Uuid>, ScimError> {
    let arr = value
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            ScimError::InvalidResource(
                "PATCH `members` op requires a non-empty `value` array of {value:<id>}".into(),
            )
        })?;
    let mut ids = Vec::with_capacity(arr.len());
    for (i, m) in arr.iter().enumerate() {
        let raw = m
            .get("value")
            .and_then(Value::as_str)
            .or_else(|| m.as_str())
            .ok_or_else(|| {
                ScimError::InvalidResource(format!("members value[{i}] missing `value` (user id)"))
            })?;
        let uuid = Uuid::parse_str(raw).map_err(|e| {
            ScimError::InvalidResource(format!("members value[{i}] `{raw}` is not a UUID: {e}"))
        })?;
        ids.push(uuid);
    }
    Ok(ids)
}

/// Extract `<id>` from a SCIM value-path filter `members[value eq "<id>"]` — the
/// single-member remove form some IdPs emit. Strict: the bracket content must be
/// EXACTLY three whitespace-separated tokens `value eq "<id>"` (attribute and
/// operator case-insensitive). Anything else — a different attribute
/// (`valuex eq …`), a different operator, a compound filter (`… and …`), or a
/// quoted value containing a quote — returns `None` so the caller rejects it
/// with `400 invalidValue` rather than silently mutating membership.
/// UUID member ids contain no whitespace, so token-splitting is safe.
fn extract_filter_member_id(path: &str) -> Option<&str> {
    let open = path.find('[')?;
    let close = path.rfind(']')?;
    // The filter must be the ENTIRE path: `members[...]` with `]` as the final
    // char and `members` as the attribute before the bracket. Reject a trailing
    // sub-attribute selector like `members[value eq "<id>"].display` or a
    // different attribute — otherwise `rfind(']')` would ignore the suffix and
    // wrongly match.
    if close <= open || close != path.len() - 1 || !path[..open].eq_ignore_ascii_case("members") {
        return None;
    }
    let inner = &path[open + 1..close];
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 3
        || !parts[0].eq_ignore_ascii_case("value")
        || !parts[1].eq_ignore_ascii_case("eq")
    {
        return None;
    }
    let id = parts[2].strip_prefix('"')?.strip_suffix('"')?;
    if id.contains('"') {
        return None;
    }
    Some(id)
}

async fn delete_group(
    State(state): State<Arc<AdminState>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(store) = state.identity.scim_groups.get() else {
        return scim_503(state.identity.scim_groups.unavailable_msg());
    };
    let tenant_str = principal.tenant.as_str();
    // Capture pre-delete state so the audit row records
    // display_name + member_count.
    //
    // Distinguish "row was absent"
    // from "get errored" + distinguish "member count was
    // really zero" from "members read errored". Silently
    // collapsing either case would erase the record of a
    // successful delete if Postgres flaps transiently —
    // scim_users.rs applies the same guard on the user-delete path.
    let pre: Option<waygate_scim::ScimGroup> = match store.get(tenant_str, id).await {
        Ok(maybe) => maybe,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant = %tenant_str,
                group_id = %id,
                "scim_groups.delete: pre-delete get failed; proceeding with id-only record on success",
            );
            None
        }
    };
    // members_res is computed ONLY when pre is Some (no
    // point reading members of a row that doesn't exist).
    // Carries the Result so the success path can distinguish
    // "real zero" from "members errored".
    let pre_members_res: Option<Result<Vec<waygate_scim::GroupMember>, waygate_scim::ScimError>> =
        if pre.is_some() {
            Some(store.members(tenant_str, id, &state.public_url).await)
        } else {
            None
        };
    let result = store.delete(tenant_str, id).await;
    match result {
        Ok(true) => {
            invalidate_group_authorization_caches(&state);
            // Record the delete either way. When `pre` is
            // Some we get full target identifiers + member
            // count (or `member_count_unknown` marker when
            // the members read errored). When None (the
            // pre-delete get errored), fall back to the URL
            // id as the display string so the new timeline
            // still surfaces a row for the successful delete.
            match pre.as_ref() {
                Some(g) => {
                    let (count_for_record, detail_for_record): (usize, serde_json::Value) =
                        match pre_members_res.as_ref() {
                            Some(Ok(m)) => {
                                (m.len(), serde_json::json!({ "member_count": m.len() }))
                            }
                            Some(Err(_)) | None => {
                                (0, serde_json::json!({ "member_count_unknown": true }))
                            }
                        };
                    crate::admin_mutation::record_admin_mutation_logged(
                        &state,
                        "scim_groups",
                        &g.id.to_string(),
                        principal.tenant.as_str(),
                        Some(&principal),
                        "scim_groups.delete",
                        scim_group_reason(g, count_for_record),
                    )
                    .await;
                    crate::scim_provisioning::append(
                        &state,
                        tenant_str,
                        Some(&principal),
                        waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
                        g.id,
                        &g.display_name,
                        g.external_id.as_deref(),
                        "delete",
                        waygate_dashboard_stores::scim_provisioning_log::Outcome::Success,
                        None,
                        detail_for_record,
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
                        "scim_groups",
                        &id.to_string(),
                        principal.tenant.as_str(),
                        Some(&principal),
                        "scim_groups.delete",
                        format!("scim group id={id} (pre-delete get failed; id-only record)"),
                    )
                    .await;
                    crate::scim_provisioning::append(
                        &state,
                        tenant_str,
                        Some(&principal),
                        waygate_dashboard_stores::scim_provisioning_log::TargetKind::Group,
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
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => scim_error_response(ScimError::NotFound(format!("group {id}"))),
        Err(e) => scim_error_response(e),
    }
}

/// Group rows feed SCIM UUID membership and API-key Cedar labels. Invalidate
/// both process-local bearer caches immediately after a successful committed
/// mutation and before any follow-up audit or rendering read can fail. Group
/// mutations are low-rate and may affect many principals, so coarse
/// invalidation gives ordinary-role changes prompt local convergence;
/// control-plane role resolutions independently recheck Postgres and are never
/// cached.
fn invalidate_group_authorization_caches(state: &Arc<AdminState>) {
    crate::rbac::invalidate_rbac_cache(state);
    if let Some(enricher) = state.identity.scim_enricher.as_ref() {
        enricher.invalidate_all();
    }
}

// --- parse / render helpers ----------------------------

/// Human-friendly JSON type label for SCIM error messages.
/// Used by `parse_group_request` when rejecting a non-array
/// `members` value so the client gets `"got object"` instead of
/// the literal `serde_json` enum variant name.
fn describe_json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[derive(Debug)]
struct ParsedGroupRequest {
    display_name: String,
    external_id: Option<String>,
    body_id: Option<String>,
    member_user_ids: Vec<Uuid>,
    /// Everything other than the column-level fields +
    /// `members` (which lives in the join table). Stored
    /// verbatim so the round-trip preserves IdP-emitted
    /// extension attributes.
    attrs: Value,
}

fn parse_group_request(body: &Value) -> Result<ParsedGroupRequest, ScimError> {
    let obj = body
        .as_object()
        .ok_or_else(|| ScimError::InvalidResource("request body must be a JSON object".into()))?;
    if let Some(schemas) = obj.get("schemas") {
        let arr = schemas
            .as_array()
            .ok_or_else(|| ScimError::InvalidResource("`schemas` must be an array".into()))?;
        if !arr.is_empty()
            && !arr
                .iter()
                .any(|s| s.as_str() == Some(SCIM_SCHEMA_GROUP_URN))
        {
            return Err(ScimError::InvalidResource(format!(
                "`schemas` does not include `{SCIM_SCHEMA_GROUP_URN}`"
            )));
        }
    }
    let display_name = obj
        .get("displayName")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ScimError::InvalidResource("missing required `displayName` (RFC 7643 §4.2)".into())
        })?
        .to_owned();
    let external_id = obj
        .get("externalId")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let body_id = obj.get("id").and_then(|v| v.as_str()).map(str::to_owned);
    // SCIM `members` is OPTIONAL; when absent it means "leave
    // membership unchanged on the parsed representation" — the
    // store treats an empty member list as "no members" for PUT
    // (full-replace), which matches RFC 7643 §4.2.
    //
    // A present-but-non-array
    // `members` value (e.g. `{"members": {}}` or `{"members":
    // "alice"}`) must NOT collapse silently into the absent
    // branch — that would let a malformed PUT body wipe the
    // membership set instead of returning SCIM `invalidValue`.
    // Split the cases so non-array shapes surface as 400.
    let member_user_ids: Vec<Uuid> = match obj.get("members") {
        None => Vec::new(),
        Some(Value::Array(arr)) => {
            let mut ids = Vec::with_capacity(arr.len());
            for (i, m) in arr.iter().enumerate() {
                let value = m.get("value").and_then(|v| v.as_str()).ok_or_else(|| {
                    ScimError::InvalidResource(format!("members[{i}] missing `value` (user id)"))
                })?;
                let uuid = Uuid::parse_str(value).map_err(|e| {
                    ScimError::InvalidResource(format!(
                        "members[{i}].value `{value}` is not a UUID: {e}"
                    ))
                })?;
                ids.push(uuid);
            }
            ids
        }
        Some(other) => {
            return Err(ScimError::InvalidResource(format!(
                "`members` must be a JSON array per RFC 7643 §4.2; got {}",
                describe_json_type(other),
            )));
        }
    };
    let mut attrs = body.clone();
    if let Some(o) = attrs.as_object_mut() {
        o.remove("displayName");
        o.remove("externalId");
        o.remove("schemas");
        o.remove("id");
        o.remove("meta");
        // `members` lives in the join table, not attrs;
        // dropping here so a tampered attrs blob can't
        // smuggle a stale membership snapshot.
        o.remove("members");
    }
    Ok(ParsedGroupRequest {
        display_name,
        external_id,
        body_id,
        member_user_ids,
        attrs,
    })
}

fn group_to_scim_resource(g: &ScimGroup, members: &[waygate_scim::GroupMember]) -> Value {
    let mut resource = serde_json::Map::new();
    if let Some(o) = g.attrs.as_object() {
        for (k, v) in o {
            resource.insert(k.clone(), v.clone());
        }
    }
    resource.insert("schemas".into(), json!([SCIM_SCHEMA_GROUP_URN]));
    resource.insert("id".into(), json!(g.id.to_string()));
    resource.insert("displayName".into(), json!(g.display_name));
    if let Some(eid) = g.external_id.as_deref() {
        resource.insert("externalId".into(), json!(eid));
    }
    resource.insert("members".into(), json!(members));
    resource.insert(
        "meta".into(),
        json!({
            "resourceType": "Group",
            "created": g.created_at,
            "lastModified": g.updated_at,
            "location": format!("/scim/v2/Groups/{}", g.id),
        }),
    );
    Value::Object(resource)
}

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
    fn parse_group_request_minimum() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers"
        });
        let p = parse_group_request(&body).unwrap();
        assert_eq!(p.display_name, "engineers");
        assert!(p.member_user_ids.is_empty());
    }

    #[test]
    fn parse_group_request_strips_members_from_attrs() {
        let uid = "11111111-1111-1111-1111-111111111111";
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers",
            "members": [{ "value": uid, "type": "User" }],
            "x-okta-meta": "extension"
        });
        let p = parse_group_request(&body).unwrap();
        assert_eq!(p.member_user_ids.len(), 1);
        assert_eq!(p.member_user_ids[0].to_string(), uid);
        // Extension attribute survives in attrs.
        assert_eq!(p.attrs["x-okta-meta"], json!("extension"));
        // `members` MUST NOT live in attrs (would be a
        // stale snapshot the next time the IdP queries
        // membership via the join table).
        assert!(!p.attrs.as_object().unwrap().contains_key("members"));
    }

    #[test]
    fn parse_group_request_rejects_non_uuid_member() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers",
            "members": [{ "value": "not-a-uuid", "type": "User" }]
        });
        let err = parse_group_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    #[test]
    fn parse_group_request_rejects_missing_value_on_member() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers",
            "members": [{ "type": "User" }]
        });
        let err = parse_group_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    /// A present-but-non-array
    /// `members` value must surface as SCIM `invalidValue`, not
    /// silently parse as "no members specified." Otherwise a
    /// malformed PUT body would wipe an existing group's
    /// membership set instead of being rejected.
    #[test]
    fn parse_group_request_rejects_non_array_members_object() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers",
            "members": { "value": "not-an-array" }
        });
        let err = parse_group_request(&body).unwrap_err();
        match err {
            ScimError::InvalidResource(msg) => {
                assert!(
                    msg.contains("members") && msg.contains("array"),
                    "error message should name the field and the expected type; got `{msg}`",
                );
            }
            other => panic!("expected InvalidResource, got {other:?}"),
        }
    }

    /// Companion to the object case — covers the other common
    /// malformed shape (someone sending a single string instead
    /// of an array of member objects).
    #[test]
    fn parse_group_request_rejects_non_array_members_string() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers",
            "members": "alice"
        });
        let err = parse_group_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    /// Pin: absent `members` is still legitimate (Group with no
    /// members specified). This must NOT regress after splitting
    /// the present-vs-array branches.
    #[test]
    fn parse_group_request_treats_absent_members_as_empty() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "displayName": "engineers"
        });
        let parsed = parse_group_request(&body).expect("absent members must still parse");
        assert!(parsed.member_user_ids.is_empty());
    }

    #[test]
    fn parse_group_request_rejects_wrong_schema() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_USER_URN_FOR_TEST],
            "displayName": "engineers"
        });
        let err = parse_group_request(&body).unwrap_err();
        assert!(matches!(err, ScimError::InvalidResource(_)), "{err:?}");
    }

    const SCIM_SCHEMA_USER_URN_FOR_TEST: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

    #[test]
    fn parse_group_request_captures_body_id_for_put_mismatch_check() {
        let body = json!({
            "schemas": [SCIM_SCHEMA_GROUP_URN],
            "id": "22222222-2222-2222-2222-222222222222",
            "displayName": "engineers"
        });
        let p = parse_group_request(&body).unwrap();
        assert_eq!(
            p.body_id.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
    }

    /// Column-authoritative fields override `attrs` —
    /// same defence as scim_users.
    #[test]
    fn group_to_scim_resource_column_fields_win() {
        let g = ScimGroup {
            id: Uuid::from_u128(1),
            tenant_id: "default".into(),
            external_id: Some("ext-1".into()),
            display_name: "engineers".into(),
            attrs: json!({
                "displayName": "spoofed",
                "id": "00000000-0000-0000-0000-000000000000",
                "x-okta-extension": "value"
            }),
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let r = group_to_scim_resource(&g, &[]);
        assert_eq!(r["displayName"], json!("engineers"));
        assert_eq!(r["id"], json!(g.id.to_string()));
        assert_eq!(r["x-okta-extension"], json!("value"));
    }

    // --- PATCH membership-delta parsing ---

    const A: &str = "11111111-1111-1111-1111-111111111111";
    const B: &str = "22222222-2222-2222-2222-222222222222";
    const C: &str = "33333333-3333-3333-3333-333333333333";

    fn uid(s: &str) -> Uuid {
        Uuid::parse_str(s).unwrap()
    }

    fn set(ids: &[&str]) -> BTreeSet<Uuid> {
        ids.iter().map(|s| uid(s)).collect()
    }

    fn patch_op(ops: Value) -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": ops,
        })
    }

    #[test]
    fn patch_add_members_is_union_and_idempotent() {
        let mut m = set(&[A]);
        let body = patch_op(json!([{ "op": "add", "path": "members",
            "value": [{ "value": A }, { "value": B }] }]));
        apply_group_member_patch(&body, &mut m).unwrap();
        // A was already present (idempotent), B added.
        assert_eq!(m, set(&[A, B]));
    }

    #[test]
    fn patch_remove_members_value_array() {
        let mut m = set(&[A, B, C]);
        let body = patch_op(json!([{ "op": "remove", "path": "members",
            "value": [{ "value": B }] }]));
        apply_group_member_patch(&body, &mut m).unwrap();
        assert_eq!(m, set(&[A, C]));
    }

    #[test]
    fn patch_remove_members_filter_path() {
        // Azure/older-Authentik form: path = members[value eq "<id>"].
        let mut m = set(&[A, B]);
        let body = patch_op(json!([{ "op": "remove",
            "path": format!("members[value eq \"{B}\"]") }]));
        apply_group_member_patch(&body, &mut m).unwrap();
        assert_eq!(m, set(&[A]));
    }

    #[test]
    fn patch_remove_absent_member_is_noop() {
        let mut m = set(&[A]);
        let body = patch_op(json!([{ "op": "remove", "path": "members",
            "value": [{ "value": C }] }]));
        apply_group_member_patch(&body, &mut m).unwrap();
        assert_eq!(m, set(&[A]), "removing an absent member is a no-op");
    }

    #[test]
    fn patch_replace_members_sets_full_list() {
        let mut m = set(&[A, B]);
        let body = patch_op(json!([{ "op": "replace", "path": "members",
            "value": [{ "value": C }] }]));
        apply_group_member_patch(&body, &mut m).unwrap();
        assert_eq!(m, set(&[C]));
    }

    #[test]
    fn patch_multiple_ops_apply_in_order() {
        let mut m = set(&[A]);
        let body = patch_op(json!([
            { "op": "add",    "path": "members", "value": [{ "value": B }] },
            { "op": "remove", "path": "members", "value": [{ "value": A }] },
        ]));
        apply_group_member_patch(&body, &mut m).unwrap();
        assert_eq!(m, set(&[B]));
    }

    #[test]
    fn patch_rejects_empty_value_to_prevent_wipe() {
        let mut m = set(&[A, B]);
        let body = patch_op(json!([{ "op": "remove", "path": "members", "value": [] }]));
        assert!(
            apply_group_member_patch(&body, &mut m).is_err(),
            "an empty value array must be refused, not wipe the group",
        );
        assert_eq!(m, set(&[A, B]), "membership unchanged on rejection");
    }

    #[test]
    fn patch_rejects_unsupported_path_and_op() {
        let mut m = set(&[A]);
        let bad_path = patch_op(json!([{ "op": "add", "path": "displayName", "value": "x" }]));
        assert!(apply_group_member_patch(&bad_path, &mut m).is_err());
        let bad_op = patch_op(json!([{ "op": "frobnicate", "path": "members",
            "value": [{ "value": B }] }]));
        assert!(apply_group_member_patch(&bad_op, &mut m).is_err());
    }

    #[test]
    fn patch_rejects_non_uuid_member() {
        let mut m = set(&[A]);
        let body = patch_op(json!([{ "op": "add", "path": "members",
            "value": [{ "value": "not-a-uuid" }] }]));
        assert!(apply_group_member_patch(&body, &mut m).is_err());
    }

    #[test]
    fn extract_filter_member_id_parses_quoted_id() {
        assert_eq!(
            extract_filter_member_id(&format!("members[value eq \"{A}\"]")),
            Some(A)
        );
        // case-insensitive attribute/operator
        assert_eq!(
            extract_filter_member_id(&format!("Members[Value EQ \"{A}\"]")),
            Some(A)
        );
        // not a value-path filter
        assert_eq!(extract_filter_member_id("members"), None);
    }

    #[test]
    fn extract_filter_member_id_rejects_overbroad_filters() {
        // Must be EXACTLY `value eq "<id>"`, not a prefix match
        // or a compound filter.
        assert_eq!(
            extract_filter_member_id(&format!("members[valuex eq \"{A}\"]")),
            None,
            "a different attribute starting with `value` must not match"
        );
        assert_eq!(
            extract_filter_member_id(&format!("members[value ne \"{A}\"]")),
            None,
            "a different operator must not match"
        );
        assert_eq!(
            extract_filter_member_id(&format!("members[value eq \"{A}\" and value eq \"{B}\"]")),
            None,
            "a compound filter must not match"
        );
        // The `]` must terminate the path — a trailing
        // sub-attribute selector must not be ignored by rfind.
        assert_eq!(
            extract_filter_member_id(&format!("members[value eq \"{A}\"].display")),
            None,
            "a trailing sub-attribute selector must not match"
        );
        // a different attribute before the bracket must not match
        assert_eq!(
            extract_filter_member_id(&format!("groups[value eq \"{A}\"]")),
            None,
            "a non-`members` attribute must not match"
        );
    }

    #[test]
    fn patch_remove_overbroad_filter_path_is_rejected() {
        // The whole PATCH must fail (400) — not silently remove a member — when
        // the filter path isn't the exact supported shape.
        let mut m = set(&[A, B]);
        let body = patch_op(json!([{ "op": "remove",
            "path": format!("members[valuex eq \"{A}\"]") }]));
        assert!(
            apply_group_member_patch(&body, &mut m).is_err(),
            "an over-broad filter path must be rejected"
        );
        assert_eq!(m, set(&[A, B]), "membership unchanged on rejection");
    }
}
