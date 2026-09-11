//! Roles page — `/admin/t/{tenant}/rbac`.
//!
//! Nav tab + page title read "Roles"; the route and backend stay
//! RBAC (`waygate_rbac`), so the module keeps the RBAC name.
//!
//! Operator view of the per-tenant RBAC configuration
//! (`waygate_rbac`). Four sections — the first three (roles,
//! assignments, group mappings) carry inline create / delete; the
//! fourth is a read-only lookup:
//!
//! 1. **Roles** — `gateway_roles` for the tenant: name, the bundled
//!    scopes, and a count of direct subject assignments. Backed by
//!    `RbacStore::list_roles` (+ `list_assignments` for the count).
//! 2. **Assignments** — `role_assignments`: the role name, the
//!    subject (`sub` or `group:<id>`), created timestamp. Backed by
//!    `RbacStore::list_assignments`.
//! 3. **Group mappings** — `group_role_mappings`: SCIM group id →
//!    role name, created timestamp (the common config path). Backed
//!    by `RbacStore::list_group_mappings`.
//! 4. **Effective permissions for subject** — interactive
//!    `?subject=...` lookup. Resolves the subject via the same
//!    `ScimResolver` the bearer middleware uses (SCIM user + group
//!    list), then calls `RbacStore::resolve_for_subject` to render
//!    the union of roles + scopes the runtime would grant. Mirrors
//!    the resolver's fail-closed ambiguous-match path: a `sub` that
//!    matches more than one SCIM row renders an explicit "ambiguous"
//!    card, NOT a silent fall-through.
//!
//! The companion **"Who has scope X?"** reverse lookup (`?scope=...`)
//! moved to the Scopes page (`/scopes`) in the Identities revamp —
//! scopes are the natural home for a scope→holders query, and it sits
//! beside the scope registry there. See `dashboard_scopes`.
//!
//! Role ids are resolved to names in-process from the single
//! `list_roles` result (a `HashMap<Uuid, name>`), so the
//! Assignments and Group-mappings sections show human-readable role
//! names without a per-row fetch.
//!
//! Roles (create/edit/delete), assignments, and group-mappings
//! (create/delete) all have inline forms on this page, each
//! reusing the matching REST `*_core` function so the HTML and JSON
//! surfaces can't drift. The REST surface at `/api/v1/admin/rbac/*`
//! remains available in parallel.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`; all three `list_*` calls are
//! strictly per-tenant.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin`. A dashboard session
//! without `mcp:admin` (or a peer-asserted principal) sees the
//! insufficient-scope card; every store fetch is skipped so no role
//! names, scope bundles, or subject identifiers enter the rendered
//! HTML.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_rbac::{GroupRoleMapping, ResolvedRoles, Role, RoleAssignment};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::rbac::{
    create_assignment_core, create_group_mapping_core, create_role_core, delete_assignment_core,
    delete_group_mapping_core, delete_role_core, update_role_core,
};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "rbac.html")]
struct RbacPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the RBAC store is unwired (dev mode / no DB).
    store_configured: bool,
    /// `true` when the principal lacks `mcp:admin` (or is a peer
    /// assertion). Template renders the insufficient-scope card and
    /// SKIPS every fetch.
    insufficient_scope: bool,

    roles: Vec<RoleRow>,
    roles_load_error: bool,

    assignments: Vec<AssignmentRow>,
    assignments_load_error: bool,

    mappings: Vec<MappingRow>,
    mappings_load_error: bool,

    /// Current `?subject=` value so the form input
    /// re-populates after the page's GET round-trip (same
    /// re-fill posture as the activity page's plain-GET form).
    subject_input: Option<String>,
    /// Result of the "Effective permissions" lookup.
    effective: EffectivePanel,
    /// `true` when the SCIM resolver wasn't wired on
    /// `AdminState`. The Effective panel renders a "SCIM resolver
    /// not configured" empty state in that case.
    scim_resolver_configured: bool,
    /// `Some(msg)` when a role create / edit / delete submission failed,
    /// threaded back via the `?rbac_error=` PRG query param and rendered
    /// above the Roles section.
    rbac_error: Option<String>,
}

impl RbacPage {}

struct RoleRow {
    /// Bare role id (uuid string) — used as the `<option value>` in the
    /// assignment + group-mapping create `<select>`s.
    id: String,
    /// Relative URLs for the edit / delete form actions; the template
    /// wraps each with `self.nav_url(...)`. Precomputed because askama
    /// can't `format!` the id into the path inline.
    update_rel: String,
    delete_rel: String,
    name: String,
    /// Raw description for the edit form pre-fill; `None` renders blank.
    description: Option<String>,
    /// Comma-joined scope bundle; empty renders an em-dash. Doubles as
    /// the edit form's scopes input value (re-split on submit).
    scopes: String,
    /// Count of direct (`role_assignments`) grants to this role.
    /// Group-derived grants are shown in the Group mappings section.
    /// `None` when the assignments fetch failed — template renders
    /// `—` (unknown) rather than a misleading `0`.
    assignment_count: Option<usize>,
    created_at_abs: String,
}

struct AssignmentRow {
    /// Resolved role name; falls back to the raw id when the role
    /// row is missing (shouldn't happen — FK — but never panic).
    role: String,
    /// `sub` or `group:<group_id>`.
    subject: String,
    created_at_abs: String,
    /// Relative URL for the per-row delete form.
    delete_rel: String,
}

struct MappingRow {
    /// SCIM group id (uuid string). The SCIM page resolves these to
    /// display names; here we show the id to avoid a cross-store
    /// fetch.
    group_id: String,
    role: String,
    created_at_abs: String,
    /// Relative URL for the per-row delete form. Delete keys on
    /// (group_id, role_id) — the composite PK.
    delete_rel: String,
}

/// Query-string state for the page. The "Effective permissions
/// for subject" lookup (`?subject=`) lives here; the "Who has scope X?"
/// reverse lookup lives on the Scopes page (`/scopes?scope=`), so RBAC
/// no longer reads a `scope` param.
#[derive(Debug, Default, Deserialize)]
pub struct RbacQuery {
    /// "Effective permissions for subject" lookup input. Trimmed
    /// then emptied at `cleaned()`; an empty value renders the
    /// form with no result panel.
    #[serde(default)]
    subject: Option<String>,
    /// PRG channel: a role create / edit / delete failure is
    /// carried back here and rendered above the Roles section. Passed
    /// through verbatim (not trimmed-to-None) so the message renders.
    #[serde(default)]
    rbac_error: Option<String>,
}

impl RbacQuery {
    fn cleaned(self) -> Self {
        fn norm(v: Option<String>) -> Option<String> {
            v.and_then(|s| {
                let t = s.trim().to_owned();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            })
        }
        Self {
            subject: norm(self.subject),
            rbac_error: self.rbac_error,
        }
    }
}

/// Result of the "Effective permissions for subject"
/// lookup. Flat struct rather than an enum so askama can render
/// each branch with plain `{% if %}` against booleans; the
/// invariant is enforced by the constructor helpers below
/// (`not_queried`, `ambiguous`, `subject_missing`, `resolved`,
/// `error`) — one of `is_ambiguous` / `is_error` /
/// `is_resolved` / `is_subject_missing` / nothing-queried is
/// true at a time.
#[derive(Default)]
struct EffectivePanel {
    /// `true` when the operator submitted `?subject=`.
    queried: bool,
    /// The submitted value, for the result-panel header.
    subject: Option<String>,
    /// `true` when SCIM resolver returned `Ambiguous` (multiple
    /// `scim_users` rows match the sub via `external_id` or
    /// `user_name`). Fail-closed same as the bearer middleware.
    is_ambiguous: bool,
    /// `scim_users.id`s the operator needs to reconcile. Empty
    /// unless `is_ambiguous`.
    candidate_ids: Vec<String>,
    /// `true` when the SCIM or RBAC backend errored.
    is_error: bool,
    /// Human-readable error class string. `None` unless `is_error`.
    error_message: Option<String>,
    /// `true` when the SCIM lookup specifically returned no row
    /// (not ambiguous, not error — the subject just isn't
    /// SCIM-provisioned). The RBAC resolve still runs with an
    /// empty group list, so `roles` / `scopes` may still be
    /// non-empty (direct assignments).
    is_subject_missing: bool,
    /// SCIM identity panel populated on the canonical "found"
    /// path — the template renders the SCIM card when this is
    /// `Some` and falls back to a "no SCIM row" note when it's
    /// `None` AND `is_subject_missing`. The "resolved" state is
    /// derived by the template via elimination
    /// (`queried && !is_ambiguous && !is_error`).
    scim: Option<ScimResolvedView>,
    /// Roles the runtime would grant. Populated whenever the
    /// RBAC resolve succeeded (Resolved + SubjectMissing).
    roles: Vec<String>,
    /// Union of scopes from the granted roles. Same population
    /// as `roles`.
    scopes: Vec<String>,
}

impl EffectivePanel {
    fn not_queried() -> Self {
        Self::default()
    }
    fn ambiguous(subject: String, candidate_ids: Vec<String>) -> Self {
        Self {
            queried: true,
            subject: Some(subject),
            is_ambiguous: true,
            candidate_ids,
            ..Self::default()
        }
    }
    fn error(subject: String, message: String) -> Self {
        Self {
            queried: true,
            subject: Some(subject),
            is_error: true,
            error_message: Some(message),
            ..Self::default()
        }
    }
    fn subject_missing(subject: String, roles: Vec<String>, scopes: Vec<String>) -> Self {
        Self {
            queried: true,
            subject: Some(subject),
            is_subject_missing: true,
            roles,
            scopes,
            ..Self::default()
        }
    }
    fn resolved(
        subject: String,
        scim: ScimResolvedView,
        roles: Vec<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            queried: true,
            subject: Some(subject),
            scim: Some(scim),
            roles,
            scopes,
            ..Self::default()
        }
    }
}

/// Trimmed view of `waygate_scim::ResolvedPrincipal` for the
/// template (omits `attrs` JSON — it's IdP-confidential and not
/// useful inline; SCIM page renders the full resource).
struct ScimResolvedView {
    user_name: String,
    external_id: Option<String>,
    active: bool,
    /// Pre-formatted `display_name (uuid)` per group so the template
    /// renders one row per group without an extra match.
    groups: Vec<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/rbac", get(rbac_page))
        .route("/rbac/roles/create", post(create_role))
        .route("/rbac/roles/{id}/update", post(update_role))
        .route("/rbac/roles/{id}/delete", post(delete_role))
        .route("/rbac/assignments/create", post(create_assignment))
        .route("/rbac/assignments/{id}/delete", post(delete_assignment))
        .route("/rbac/group-mappings/create", post(create_group_mapping))
        .route(
            "/rbac/group-mappings/{group_id}/{role_id}/delete",
            post(delete_group_mapping),
        )
}

async fn rbac_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<RbacQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.identity.rbac.enabled();
    let scim_resolver_configured = state.identity.scim_resolver.enabled();

    let query = q.cleaned();

    let load = if insufficient_scope {
        LoadResult::default()
    } else {
        match state.identity.rbac.get() {
            Some(store) => load_rbac(store.as_ref(), &read_tenant).await,
            None => LoadResult::default(),
        }
    };

    // Run the "Effective permissions for subject" lookup when
    // `?subject=` is present. Skipped entirely on insufficient scope
    // (mirrors the list-section gate above; SCIM identifiers are
    // operator-confidential). The "Who has scope X?" reverse lookup
    // lives on the Scopes page.
    let effective = if insufficient_scope || !store_configured {
        EffectivePanel::not_queried()
    } else {
        let rbac = state
            .identity
            .rbac
            .get()
            .expect("guarded by store_configured");
        match query.subject.as_deref() {
            None => EffectivePanel::not_queried(),
            Some(subject) => {
                lookup_effective(state.as_ref(), rbac.as_ref(), &read_tenant, subject).await
            }
        }
    };

    let page = RbacPage {
        chrome: PageChrome::build(
            &state,
            "Roles",
            "/rbac",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        roles: load.roles,
        roles_load_error: load.roles_load_error,
        assignments: load.assignments,
        assignments_load_error: load.assignments_load_error,
        mappings: load.mappings,
        mappings_load_error: load.mappings_load_error,
        subject_input: query.subject,
        effective,
        scim_resolver_configured,
        rbac_error: query.rbac_error,
    };
    render(&page)
}

// --- Role create / edit / delete forms (admin-gated + CSRF) ----------------

/// Form body for role create + edit. `scopes` is free text (space- or
/// comma-separated); parsed in the handler. `id` is empty for create,
/// set for edit.
#[derive(Deserialize)]
struct RoleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    scopes: String,
}

/// Form body for the per-row role delete — only the CSRF token.
#[derive(Deserialize)]
struct RoleDeleteForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /rbac/roles/create` — admin-gated + CSRF, reuses
/// [`create_role_core`] and PRG-redirects with a `?rbac_error=` channel.
async fn create_role(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<RoleForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let scopes = split_scopes(&form.scopes);
    match create_role_core(
        &state,
        tenant,
        principal,
        form.name.trim(),
        non_empty(&form.description).as_deref(),
        &scopes,
    )
    .await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "create")),
    }
}

/// `POST /rbac/roles/{id}/update` — admin-gated + CSRF, reuses
/// [`update_role_core`]. The edit form submits all fields.
async fn update_role(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RoleForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name: mounted at both `/rbac/roles/{id}/update` and the
    // 2-capture `/t/{tenant}/...` nest; `Path<String>` 500s on the latter.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing role id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid role id.");
    };
    let scopes = split_scopes(&form.scopes);
    match update_role_core(
        &state,
        tenant,
        principal,
        uuid,
        form.name.trim(),
        non_empty(&form.description).as_deref(),
        &scopes,
    )
    .await
    {
        Ok(Some(_)) => redirect_ok(tenant_ctx),
        Ok(None) => redirect_with_error(tenant_ctx, "That role no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "update")),
    }
}

/// `POST /rbac/roles/{id}/delete` — admin-gated + CSRF, reuses
/// [`delete_role_core`] (assignments + mappings cascade by FK).
async fn delete_role(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RoleDeleteForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name — same dual-mount reason as `update` above.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing role id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid role id.");
    };
    match delete_role_core(&state, tenant, principal, uuid).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That role no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "delete")),
    }
}

// --- Assignment + group-mapping create / delete -----------------------------

/// Form body for the assignment composer: a role `<select>` + a free-text
/// subject (`sub` or `group:<id>`).
#[derive(Deserialize)]
struct AssignmentForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role_id: String,
    #[serde(default)]
    subject_sub: String,
}

/// Form body for the group-mapping composer: a SCIM group id + a role
/// `<select>`.
#[derive(Deserialize)]
struct GroupMappingForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    role_id: String,
}

/// `POST /rbac/assignments/create` — admin-gated + CSRF, reuses
/// [`create_assignment_core`]. The role `<select>` posts a role id; an
/// unknown role surfaces the core's 422 as a friendly `?rbac_error=`.
async fn create_assignment(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<AssignmentForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Ok(role_id) = Uuid::parse_str(form.role_id.trim()) else {
        return redirect_with_error(tenant_ctx, "Pick a role for the assignment.");
    };
    match create_assignment_core(&state, tenant, principal, role_id, form.subject_sub.trim()).await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "create")),
    }
}

/// `POST /rbac/assignments/{id}/delete` — admin-gated + CSRF, reuses
/// [`delete_assignment_core`].
async fn delete_assignment(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RoleDeleteForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read `id` by name — same dual-mount reason as `delete_role` above.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx, "Missing assignment id.");
    };
    let Ok(uuid) = Uuid::parse_str(id.trim()) else {
        return redirect_with_error(tenant_ctx, "Invalid assignment id.");
    };
    match delete_assignment_core(&state, tenant, principal, uuid).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That assignment no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "delete")),
    }
}

/// `POST /rbac/group-mappings/create` — admin-gated + CSRF, reuses
/// [`create_group_mapping_core`].
async fn create_group_mapping(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<GroupMappingForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Ok(group_id) = Uuid::parse_str(form.group_id.trim()) else {
        return redirect_with_error(tenant_ctx, "Group id must be a valid SCIM group UUID.");
    };
    let Ok(role_id) = Uuid::parse_str(form.role_id.trim()) else {
        return redirect_with_error(tenant_ctx, "Pick a role for the mapping.");
    };
    match create_group_mapping_core(&state, tenant, principal, group_id, role_id).await {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "create")),
    }
}

/// `POST /rbac/group-mappings/{group_id}/{role_id}/delete` — admin-gated
/// and CSRF-checked, reuses [`delete_group_mapping_core`]. Keys on the
/// composite (group_id, role_id) PK.
async fn delete_group_mapping(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RoleDeleteForm>,
) -> Response {
    let (principal, tenant_ctx, tenant) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // Read both captures by name: mounted at both
    // `/rbac/group-mappings/{group_id}/{role_id}/delete` and the
    // 3-capture `/t/{tenant}/...` nest; `Path<(String, String)>` 500s on
    // the latter.
    let (Some(group_id), Some(role_id)) = (params.get("group_id"), params.get("role_id")) else {
        return redirect_with_error(tenant_ctx, "Missing mapping id.");
    };
    let (Ok(gid), Ok(rid)) = (
        Uuid::parse_str(group_id.trim()),
        Uuid::parse_str(role_id.trim()),
    ) else {
        return redirect_with_error(tenant_ctx, "Invalid mapping id.");
    };
    match delete_group_mapping_core(&state, tenant, principal, gid, rid).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That mapping no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &rbac_err_message(&e, "delete")),
    }
}

/// Shared admin-gate + CSRF for the role mutation handlers. Uses the
/// page's stricter [`principal_has_dashboard_admin`] (refuses
/// peer-asserted principals). Returns `(principal, tenant_ctx, tenant)`
/// or the boxed error `Response`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(Option<&'a Principal>, Option<TenantContext>, &'a str), Box<Response>> {
    let principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(principal) {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "RBAC changes require mcp:admin").into_response(),
        ));
    }
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form_csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, form_csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "csrf mismatch").into_response(),
        ));
    }
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c), tenant))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/rbac")).into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?rbac_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/rbac"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Split a free-text scope field on commas / whitespace, dropping
/// empties (scopes never contain internal whitespace).
fn split_scopes(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_owned())
    }
}

/// Operator-safe role-mutation message, parameterized by verb. The
/// conflict / invalid-reference / validation detail is safe to surface;
/// anything else collapses to a generic line.
fn rbac_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::BadGateway(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} role — see gateway logs for details."),
    }
}

/// SCIM-resolve the subject (group ids + identity) and
/// flatten roles + scopes via the same `resolve_for_subject` the
/// bearer middleware uses. The SCIM lookup and the RBAC resolve
/// are intentionally independent — a non-SCIM-provisioned subject
/// (one only granted via direct `role_assignments`) still resolves
/// roles, just with an empty group list.
async fn lookup_effective(
    state: &AdminState,
    rbac: &dyn waygate_rbac::RbacStore,
    tenant: &str,
    subject: &str,
) -> EffectivePanel {
    // Step 1: SCIM resolve. None ⇒ no SCIM row but direct grants
    // may still hit. Ambiguous ⇒ fail-closed (same shape as bearer
    // middleware's `enrichment_blocked`).
    let scim_row: Option<waygate_scim::ResolvedPrincipal> = match state.identity.scim_resolver.get()
    {
        None => None, // resolver not wired; treat as no SCIM data
        Some(resolver) => match resolver.resolve(tenant, subject).await {
            Ok(resolved) => resolved,
            Err(waygate_scim::ScimResolveError::Ambiguous { rows, .. }) => {
                return EffectivePanel::ambiguous(
                    subject.to_owned(),
                    rows.into_iter().map(|u| u.to_string()).collect(),
                );
            }
            Err(e) => {
                return EffectivePanel::error(
                    subject.to_owned(),
                    format!("SCIM resolver error: {e}"),
                );
            }
        },
    };

    let group_ids: Vec<Uuid> = scim_row
        .as_ref()
        .map(|r| r.groups.iter().map(|(id, _)| *id).collect())
        .unwrap_or_default();

    let ResolvedRoles {
        role_names,
        granted_scopes,
    } = match rbac.resolve_for_subject(tenant, subject, &group_ids).await {
        Ok(r) => r,
        Err(e) => {
            return EffectivePanel::error(subject.to_owned(), format!("RBAC resolve error: {e}"));
        }
    };

    match scim_row {
        Some(r) => EffectivePanel::resolved(
            subject.to_owned(),
            ScimResolvedView {
                user_name: r.user_name,
                external_id: r.external_id,
                active: r.active,
                groups: r
                    .groups
                    .into_iter()
                    .map(|(id, display)| format!("{display} ({id})"))
                    .collect(),
            },
            role_names,
            granted_scopes,
        ),
        None => EffectivePanel::subject_missing(subject.to_owned(), role_names, granted_scopes),
    }
}

/// Authorization gate for the RBAC dashboard page. Same shape as
/// `dashboard_scim::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    roles: Vec<RoleRow>,
    roles_load_error: bool,
    assignments: Vec<AssignmentRow>,
    assignments_load_error: bool,
    mappings: Vec<MappingRow>,
    mappings_load_error: bool,
}

async fn load_rbac(store: &dyn waygate_rbac::RbacStore, tenant: &str) -> LoadResult {
    let mut out = LoadResult::default();

    // Roles + assignments are fetched first; the role-id→name map and
    // the per-role assignment counts are derived from them. Each
    // section still renders its own error card on a partial failure.
    let roles_res = store.list_roles(tenant).await;
    let assignments_res = store.list_assignments(tenant, None, None).await;

    // role_id -> name, for resolving names in the other sections.
    let mut role_names: HashMap<Uuid, String> = HashMap::new();
    if let Ok(roles) = roles_res.as_ref() {
        for r in roles {
            role_names.insert(r.id, r.name.clone());
        }
    }

    // Per-role direct-assignment counts. `None` when the assignments
    // fetch failed: a role row then shows `—` (unknown) instead of a
    // misleading `0`. Only build the map when assignments actually
    // loaded.
    let counts: Option<HashMap<Uuid, usize>> = assignments_res.as_ref().ok().map(|assignments| {
        let mut m: HashMap<Uuid, usize> = HashMap::new();
        for a in assignments {
            *m.entry(a.role_id).or_insert(0) += 1;
        }
        m
    });

    match roles_res {
        Ok(roles) => {
            out.roles = roles
                .into_iter()
                .map(|r| role_row(r, counts.as_ref()))
                .collect();
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "rbac page: list_roles failed");
            out.roles_load_error = true;
        }
    }

    match assignments_res {
        Ok(assignments) => {
            out.assignments = assignments
                .into_iter()
                .map(|a| assignment_row(a, &role_names))
                .collect();
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "rbac page: list_assignments failed");
            out.assignments_load_error = true;
        }
    }

    match store.list_group_mappings(tenant, None, None).await {
        Ok(mappings) => {
            out.mappings = mappings
                .into_iter()
                .map(|m| mapping_row(m, &role_names))
                .collect();
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "rbac page: list_group_mappings failed");
            out.mappings_load_error = true;
        }
    }

    out
}

fn role_row(r: Role, counts: Option<&HashMap<Uuid, usize>>) -> RoleRow {
    RoleRow {
        // `Some(n)` (incl. Some(0)) when assignments loaded; `None`
        // when the assignments fetch failed → template shows `—`.
        assignment_count: counts.map(|c| c.get(&r.id).copied().unwrap_or(0)),
        id: r.id.to_string(),
        update_rel: format!("/rbac/roles/{}/update", r.id),
        delete_rel: format!("/rbac/roles/{}/delete", r.id),
        scopes: r.scopes.join(", "),
        description: r.description,
        name: r.name,
        created_at_abs: format_ts_abs(r.created_at),
    }
}

fn assignment_row(a: RoleAssignment, role_names: &HashMap<Uuid, String>) -> AssignmentRow {
    AssignmentRow {
        role: role_names
            .get(&a.role_id)
            .cloned()
            .unwrap_or_else(|| a.role_id.to_string()),
        subject: a.subject_sub,
        created_at_abs: format_ts_abs(a.created_at),
        delete_rel: format!("/rbac/assignments/{}/delete", a.id),
    }
}

fn mapping_row(m: GroupRoleMapping, role_names: &HashMap<Uuid, String>) -> MappingRow {
    MappingRow {
        group_id: m.group_id.to_string(),
        role: role_names
            .get(&m.role_id)
            .cloned()
            .unwrap_or_else(|| m.role_id.to_string()),
        created_at_abs: format_ts_abs(m.created_at),
        delete_rel: format!("/rbac/group-mappings/{}/{}/delete", m.group_id, m.role_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn principal_with(scopes: Vec<&str>, method: AuthMethod) -> Principal {
        Principal {
            sub: "tester".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.into_iter().map(String::from).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: method,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn rbac_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rbac_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rbac_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn rbac_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn role_row_counts_direct_assignments() {
        let id: Uuid = "00000000-0000-0000-0000-0000000000a1".parse().unwrap();
        let mut counts = HashMap::new();
        counts.insert(id, 3usize);
        let role = Role {
            id,
            tenant_id: "default".into(),
            name: "ops".into(),
            description: None,
            scopes: vec!["mcp:read".into(), "mcp:invoke".into()],
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let row = role_row(role, Some(&counts));
        assert_eq!(row.assignment_count, Some(3));
        assert_eq!(row.scopes, "mcp:read, mcp:invoke");
        assert_eq!(row.name, "ops");
    }

    #[test]
    fn role_row_count_is_none_when_assignments_unavailable() {
        // When the assignments fetch fails, load_rbac passes `None`
        // so the row shows `—` (unknown), NOT a misleading `0` that
        // implies no direct grants.
        let id: Uuid = "00000000-0000-0000-0000-0000000000a1".parse().unwrap();
        let role = Role {
            id,
            tenant_id: "default".into(),
            name: "ops".into(),
            description: None,
            scopes: vec![],
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let row = role_row(role, None);
        assert_eq!(
            row.assignment_count, None,
            "count must be unknown (None), not a misleading 0, when assignments failed",
        );
    }

    #[test]
    fn assignment_row_resolves_role_name_falls_back_to_id() {
        let known: Uuid = "00000000-0000-0000-0000-0000000000a1".parse().unwrap();
        let unknown: Uuid = "00000000-0000-0000-0000-0000000000ff".parse().unwrap();
        let mut names = HashMap::new();
        names.insert(known, "ops".to_string());

        let resolved = assignment_row(
            RoleAssignment {
                id: Uuid::nil(),
                tenant_id: "default".into(),
                role_id: known,
                subject_sub: "alice".into(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            &names,
        );
        assert_eq!(resolved.role, "ops");

        let fallback = assignment_row(
            RoleAssignment {
                id: Uuid::nil(),
                tenant_id: "default".into(),
                role_id: unknown,
                subject_sub: "bob".into(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            &names,
        );
        assert_eq!(fallback.role, unknown.to_string());
    }
}
