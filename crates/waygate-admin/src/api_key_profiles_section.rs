//! API-key profiles section — the body of the
//! `/admin/t/{tenant}/profiles` page, split onto its own page from
//! the API-keys page as part of the identities revamp.
//!
//! Read-only operator view of the per-tenant `api_key_profiles`
//! registry from `waygate_apikeys`. A profile is the constraint
//! envelope a mint must satisfy: `max_ttl_seconds`,
//! `allowed_scopes`, optional `allowed_servers` /
//! `allowed_tools` allowlists, and `requires_reason` /
//! `requires_owner` mint-time gates. The REST CRUD and call-time
//! enforcement of the allowed_{servers,tools} fields both live in
//! `api_key_profiles.rs`.
//!
//! ## What's here / NOT here
//!
//! - **Inline create form** (this module's `create` handler) —
//!   an admin-gated, CSRF-protected `<form>` that posts to
//!   `/identities/api-key-profiles/create` and reuses the REST
//!   path's `create_profile_core` (validate → store.create →
//!   `AdminMutation` audit), so the HTML and JSON surfaces can't
//!   drift.
//! - **Mint-via-profile composer (still deferred).** A mint form
//!   that pre-fills from a selected profile (so an operator can't
//!   fat-finger a scope outside the allowlist). The free-form
//!   mint composer in the API-keys block stays for now.
//! - **Per-row delete** (this module's `delete` handler) — an
//!   admin-gated, CSRF-protected `<form>` per row that posts to
//!   `/identities/api-key-profiles/{id}/delete` and reuses the REST
//!   path's `delete_profile_core` (the migration-0027 BEFORE-DELETE
//!   trigger guard → validator-cache flush → `AdminMutation` audit),
//!   so the HTML and JSON surfaces can't drift. The trigger's
//!   live-reference 409 is surfaced beside the table via the same
//!   `?akp_error=` PRG channel the create form uses.
//! - **Inline edit (intentionally absent — not a TODO).** Profiles
//!   are immutable post-create (see the module doc on
//!   `api_key_profiles.rs`): mutating `allowed_scopes` would let
//!   already-minted keys keep now-disallowed scopes, since profile
//!   validation runs at mint time only. "Rotating" a profile is a
//!   conscious delete + recreate, never an in-place edit.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin` middleware
//! (`crates/waygate-admin/src/api_key_profiles.rs`). Section
//! renders an admin-required card when the parent page's
//! `is_admin` flag is false. Tenant comes from the
//! principal, never `tenant_ctx`.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use uuid::Uuid;
use waygate_apikeys::Profile;
use waygate_oidc::Principal;

use crate::api_key_profiles::{create_profile_core, delete_profile_core, CreateProfileRequest};
use crate::auth::CsrfToken;
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// One profile row rendered in the section.
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Pre-formatted "Nh" / "Nd" / "Ns" label so the template
    /// doesn't have to do unit math on the i32 seconds.
    pub max_ttl_label: String,
    pub allowed_scopes: Vec<String>,
    /// `None` when unset (profile permits ANY server); `Some`
    /// when restricted to an explicit allowlist. Template
    /// branches on `is_none()` to render "any" vs the chip
    /// row.
    pub allowed_servers: Option<Vec<String>>,
    pub allowed_tools: Option<Vec<String>>,
    pub requires_reason: bool,
    pub requires_owner: bool,
    pub created_at_abs: String,
    pub updated_at_abs: String,
    /// Relative URL for the per-row delete form `action`; the
    /// template wraps it with `self.nav_url(...)` to add the tenant
    /// prefix. Precomputed here because askama can't `format!` the
    /// id into the path in expression position.
    pub delete_rel: String,
}

#[derive(Template)]
#[template(path = "api_key_profiles_section.html")]
pub struct ProfilesSection {
    /// `true` when the api_key_profiles store is wired
    /// (gateway has a database). False → "feature disabled"
    /// card.
    pub enabled: bool,
    /// Caller has `mcp:admin`. The parent page (`api_keys.rs`)
    /// already computes this from the same principal; we
    /// re-apply here as defense-in-depth so a future change
    /// to the parent that forgot to gate the section still
    /// keeps the data hidden.
    pub is_admin: bool,
    /// `Some(msg)` when the store fetch failed; template
    /// renders an error card instead of the empty state.
    pub error: Option<String>,
    /// `Some(msg)` when a create-form submission failed
    /// (validation / duplicate name). Rendered next to the form
    /// without hiding the existing table — distinct from `error`,
    /// which is a list-load failure. Threaded via a PRG
    /// `?akp_error=` query param off the create handler.
    pub create_error: Option<String>,
    pub profiles: Vec<ProfileRow>,
    /// CSRF token for the create form.
    pub csrf_token: String,
    /// Known scope strings, offered as a hint beside the
    /// `allowed_scopes` field (the form takes free text so an
    /// operator can also enter a scope not in this list).
    pub known_scopes: Vec<String>,
    /// Configured upstream server names, offered as a hint beside
    /// the `allowed_servers` field.
    pub known_servers: Vec<String>,
    /// Same as the parent's `tenant_ctx` so the section's
    /// `nav_url` deep links match.
    pub tenant_ctx: Option<TenantContext>,
}

impl ProfilesSection {
    /// Tenant-aware in-page URL helper, called from the
    /// section template via `{{ self.nav_url("/...") }}`.
    pub fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// Build the section's view-model. Skipped (returns the
/// "disabled" shape) when either the profiles store is
/// unwired or the caller lacks `mcp:admin`.
///
/// `tenant` should already be the principal's tenant —
/// callers must not pass a URL-derived tenant slug. The
/// parent Profiles page enforces this rule.
pub async fn load_section(
    state: &Arc<AdminState>,
    user: Option<&Principal>,
    tenant: &str,
    tenant_ctx: Option<TenantContext>,
    csrf_token: String,
    create_error: Option<String>,
) -> ProfilesSection {
    let is_admin = user
        .map(|p| p.has_scope(waygate_oidc::Scope::McpAdmin.as_str()))
        .unwrap_or(false);
    // Hints for the create form. Cheap to compute; only rendered
    // on the admin path, but set uniformly to keep the struct
    // literals simple.
    let known_scopes = known_profile_scopes();
    let known_servers: Vec<String> = state
        .upstreams
        .manifests()
        .iter()
        .map(|m| m.name.clone())
        .collect();
    let Some(store) = state.identity.api_key_profiles.get() else {
        return ProfilesSection {
            enabled: false,
            is_admin,
            error: None,
            create_error: None,
            profiles: Vec::new(),
            csrf_token,
            known_scopes,
            known_servers,
            tenant_ctx,
        };
    };
    if !is_admin {
        // Don't read the store for non-admins — no profile data
        // (which can include allowed_servers / allowed_tools
        // operator-confidential lists) enters the HTML.
        return ProfilesSection {
            enabled: true,
            is_admin,
            error: None,
            create_error: None,
            profiles: Vec::new(),
            csrf_token,
            known_scopes,
            known_servers,
            tenant_ctx,
        };
    }

    match store.list(tenant).await {
        Ok(rows) => ProfilesSection {
            enabled: true,
            is_admin,
            error: None,
            create_error,
            profiles: rows.into_iter().map(profile_row).collect(),
            csrf_token,
            known_scopes,
            known_servers,
            tenant_ctx,
        },
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "api_key_profiles_section: list failed",
            );
            ProfilesSection {
                enabled: true,
                is_admin,
                error: Some(
                    "Failed to load API-key profiles — see gateway logs for details.".into(),
                ),
                create_error,
                profiles: Vec::new(),
                csrf_token,
                known_scopes,
                known_servers,
                tenant_ctx,
            }
        }
    }
}

/// Scope strings offered as a hint beside the create form's
/// `allowed_scopes` field — the invoke / read / admin scopes a
/// key minted under a profile would typically carry. The field
/// is free text, so an operator can enter a scope not listed
/// here; this is guidance, not a constraint.
fn known_profile_scopes() -> Vec<String> {
    ["mcp:invoke", "mcp:invoke:high", "mcp:read", "mcp:admin"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// Form body for the in-page create. Every list field is plain
/// text (comma / whitespace separated) — the same single-field
/// approach the API-key mint form uses — so `serde_urlencoded`
/// (which can't collect repeated keys into a `Vec`) deserializes
/// it cleanly. `requires_*` are checkboxes (present ⇒ `Some`).
#[derive(serde::Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    /// Parsed to `i32` in the handler so an empty / non-numeric
    /// value yields a friendly error rather than a 422 from the
    /// extractor.
    #[serde(default)]
    max_ttl_seconds: String,
    #[serde(default)]
    allowed_scopes: String,
    #[serde(default)]
    allowed_servers: String,
    #[serde(default)]
    allowed_tools: String,
    #[serde(default)]
    requires_reason: Option<String>,
    #[serde(default)]
    requires_owner: Option<String>,
}

/// `POST /identities/api-key-profiles/create` — the in-page
/// create form. Admin-gated + CSRF, then reuses
/// [`create_profile_core`] (the same validate → `store.create` →
/// `AdminMutation` audit path the REST handler runs), and
/// PRG-redirects back to the Profiles page. On error it
/// redirects with an `?akp_error=` message the page re-renders
/// beside the form.
pub async fn create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<ProfileForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    // Same CSRF contract as the activity/servers/tenant forms:
    // when a token is injected it must match; when none is
    // injected (CSRF middleware off, e.g. dev) the check passes.
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form.csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, &form.csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let principal = user.as_ref().map(|Extension(p)| p);
    // Tenant from the principal, never tenant_ctx — same rule as
    // the REST handler and every other profile path.
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);

    let max_ttl_seconds = match form.max_ttl_seconds.trim().parse::<i32>() {
        Ok(n) => n,
        Err(_) => {
            return redirect_with_error(
                tenant_ctx.as_ref(),
                "Max TTL (seconds) must be a whole number greater than 0.",
            );
        }
    };

    let req = CreateProfileRequest {
        name: form.name.trim().to_owned(),
        description: non_empty(&form.description),
        max_ttl_seconds,
        allowed_scopes: split_list(&form.allowed_scopes),
        allowed_servers: opt_list(&form.allowed_servers),
        allowed_tools: opt_list(&form.allowed_tools),
        requires_reason: form.requires_reason.is_some(),
        requires_owner: form.requires_owner.is_some(),
    };

    match create_profile_core(&state, tenant, principal, &req).await {
        Ok(_) => Redirect::to(&crate::tenant_ctx::nav_url(
            tenant_ctx.as_ref(),
            "/profiles",
        ))
        .into_response(),
        Err(e) => redirect_with_error(tenant_ctx.as_ref(), &err_message(&e)),
    }
}

/// Form body for the per-row delete. Only the CSRF token — the
/// profile id is a path param.
#[derive(serde::Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /identities/api-key-profiles/{id}/delete` — the in-page
/// per-row delete. Admin-gated + CSRF, then reuses
/// [`delete_profile_core`] (the same migration-0027 trigger guard →
/// validator-cache flush → `AdminMutation` audit path the REST
/// handler runs), and PRG-redirects back to the Profiles page. On
/// the trigger's live-reference 409 (or any other failure) it
/// redirects with an `?akp_error=` message the page re-renders
/// beside the form — the same channel the create form uses.
pub async fn delete(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DeleteForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    // Same CSRF contract as the create form: when a token is
    // injected it must match; when none is injected (CSRF middleware
    // off, e.g. dev) the check passes.
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => {
            !form.csrf.is_empty() && crate::dashboard::csrf_matches(&c.0, &form.csrf)
        }
        None => true,
    };
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let principal = user.as_ref().map(|Extension(p)| p);
    // Tenant from the principal, never tenant_ctx — same rule as the
    // create handler and every other profile path.
    let tenant = principal
        .map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT);

    // Read `id` by name: this dashboard route is nested under
    // `/t/{tenant}` (and merged at `/`), so a `Path<String>` extractor
    // 500s on the tenant-scoped mount's 2-capture match.
    let Some(id) = params.get("id") else {
        return redirect_with_error(tenant_ctx.as_ref(), "Missing profile id.");
    };
    let uuid = match Uuid::parse_str(id.trim()) {
        Ok(u) => u,
        Err(_) => return redirect_with_error(tenant_ctx.as_ref(), "Invalid profile id."),
    };

    match delete_profile_core(&state, tenant, principal, uuid).await {
        Ok(true) => Redirect::to(&crate::tenant_ctx::nav_url(
            tenant_ctx.as_ref(),
            "/profiles",
        ))
        .into_response(),
        Ok(false) => redirect_with_error(
            tenant_ctx.as_ref(),
            "That profile no longer exists — it may have already been deleted.",
        ),
        Err(e) => redirect_with_error(tenant_ctx.as_ref(), &err_message_for(&e, "delete")),
    }
}

/// PRG redirect back to the Profiles page with a create/delete error
/// carried in `?akp_error=` (URL-encoded). The page handler reads it and
/// renders it beside the form via `create_error`.
fn redirect_with_error(tenant_ctx: Option<&TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?akp_error={}",
        crate::tenant_ctx::nav_url(tenant_ctx, "/profiles"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Operator-safe message for a create failure. Thin wrapper over
/// [`err_message_for`] with the `"create"` verb.
fn err_message(e: &ApiError) -> String {
    err_message_for(e, "create")
}

/// Operator-safe message for a profile-mutation failure. Validation /
/// conflict / unavailable detail is safe to surface; anything else (e.g. an
/// audit-persistence failure) collapses to a generic line — parameterized by
/// `verb` ("create" / "delete") so the catch-all names the operation that
/// actually failed rather than always saying "create".
fn err_message_for(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::BadGateway(d)
        // `InternalOperatorVisible` is the audit-persistence-failed message
        // (`record_required` failed after the mutation committed) — it is
        // deliberately operator-actionable, so surface it.
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} profile — see gateway logs for details."),
    }
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_owned())
    }
}

/// Split a free-text list field on commas and any whitespace
/// (newlines included, for the `allowed_tools` textarea), dropping
/// empties. Scopes / server names / `<server>.<tool>` names never
/// contain internal whitespace, so this is unambiguous.
fn split_list(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `None` (no restriction) when the field is empty, else the
/// parsed list — matching the store's "absent ⇒ any" semantics.
fn opt_list(s: &str) -> Option<Vec<String>> {
    let v = split_list(s);
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn profile_row(p: Profile) -> ProfileRow {
    ProfileRow {
        id: p.id.to_string(),
        name: p.name,
        description: p.description,
        max_ttl_label: format_ttl_seconds(p.max_ttl_seconds),
        allowed_scopes: p.allowed_scopes,
        // The REST create validator
        // (crates/waygate-admin/src/api_key_profiles.rs:572-595)
        // accepts an empty Vec as "no restriction" — same
        // semantics the runtime gate enforces
        // (crates/waygate-apikeys/src/validator.rs:421-435).
        // Normalize Some(empty) → None HERE so the template's
        // match-arm "any" branch fires for both shapes; the
        // alternative (a chip-row that renders empty) would
        // surface as a confusing blank cell.
        allowed_servers: normalize_unrestricted(p.allowed_servers),
        allowed_tools: normalize_unrestricted(p.allowed_tools),
        requires_reason: p.requires_reason,
        requires_owner: p.requires_owner,
        created_at_abs: format_ts_abs(p.created_at),
        updated_at_abs: format_ts_abs(p.updated_at),
        // Uuid is Copy, so reusing `p.id` after the `to_string()`
        // above is fine.
        delete_rel: format!("/identities/api-key-profiles/{}/delete", p.id),
    }
}

/// Collapse `Some(empty Vec)` to `None` so the template's
/// "unrestricted" branch fires for both shapes. See call site
/// in [`profile_row`] for the rationale.
fn normalize_unrestricted(v: Option<Vec<String>>) -> Option<Vec<String>> {
    match v {
        Some(inner) if inner.is_empty() => None,
        other => other,
    }
}

/// Render a max-TTL in operator-friendly units. Uses the
/// largest unit that divides cleanly (24h → 1d, 168h → 7d),
/// falls back to hours / minutes / seconds. Negative or zero
/// is surfaced rather than silently rendered as "0s" — the
/// DB CHECK enforces > 0 but the dashboard shouldn't lie if a
/// future migration weakens the constraint.
fn format_ttl_seconds(s: i32) -> String {
    if s <= 0 {
        return format!("invalid ({s}s)");
    }
    let s = s as i64;
    if s % 86400 == 0 {
        format!("{}d", s / 86400)
    } else if s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ttl_uses_days_when_clean() {
        assert_eq!(format_ttl_seconds(86_400), "1d");
        assert_eq!(format_ttl_seconds(7 * 86_400), "7d");
        assert_eq!(format_ttl_seconds(30 * 86_400), "30d");
    }

    #[test]
    fn format_ttl_falls_back_to_hours_minutes_seconds() {
        assert_eq!(format_ttl_seconds(3_600), "1h");
        assert_eq!(format_ttl_seconds(7_200), "2h");
        assert_eq!(format_ttl_seconds(60), "1m");
        assert_eq!(format_ttl_seconds(90), "90s");
    }

    #[test]
    fn format_ttl_marks_invalid_rather_than_lying() {
        // The DB CHECK enforces > 0 today; if a future
        // migration weakens that, the dashboard should
        // surface the bad value loud rather than render "0s".
        let label = format_ttl_seconds(0);
        assert!(label.contains("invalid"), "{label}");
        let label = format_ttl_seconds(-30);
        assert!(label.contains("invalid"), "{label}");
    }

    #[test]
    fn format_ttl_picks_largest_clean_unit() {
        // 1h 30m → not clean in hours or days, falls to minutes.
        assert_eq!(format_ttl_seconds(90 * 60), "90m");
        // Exact 24h → days.
        assert_eq!(format_ttl_seconds(24 * 3_600), "1d");
    }

    #[test]
    fn normalize_unrestricted_collapses_some_empty_to_none() {
        // The REST validator + runtime gate treat Some([]) the
        // same as None ("no restriction"); normalize before
        // render so the template's "any" branch fires for both
        // shapes.
        assert!(normalize_unrestricted(Some(Vec::new())).is_none());
    }

    #[test]
    fn normalize_unrestricted_preserves_non_empty_some() {
        let v = vec!["example-messages".to_owned(), "example-mailbox".to_owned()];
        let out = normalize_unrestricted(Some(v.clone()));
        assert_eq!(out, Some(v));
    }

    #[test]
    fn normalize_unrestricted_preserves_none() {
        assert!(normalize_unrestricted(None).is_none());
    }

    #[test]
    fn split_list_handles_commas_spaces_and_newlines() {
        assert_eq!(
            split_list("mcp:invoke mcp:read"),
            vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()]
        );
        assert_eq!(
            split_list("mcp:invoke, mcp:read"),
            vec!["mcp:invoke".to_owned(), "mcp:read".to_owned()]
        );
        // The allowed_tools textarea separates entries by newline.
        assert_eq!(
            split_list("example-messages.send_msg\nexample-mailbox.list_threads\n"),
            vec![
                "example-messages.send_msg".to_owned(),
                "example-mailbox.list_threads".to_owned()
            ]
        );
        // Collapses runs of separators and trims, dropping empties.
        assert_eq!(
            split_list("  a ,, b ,\n c  "),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
        assert!(split_list("   ").is_empty());
        assert!(split_list("").is_empty());
    }

    #[test]
    fn opt_list_is_none_when_blank_some_when_present() {
        // Blank ⇒ None ("no restriction" / "any"), matching the store.
        assert!(opt_list("").is_none());
        assert!(opt_list("  ,  \n ").is_none());
        assert_eq!(
            opt_list("example-messages"),
            Some(vec!["example-messages".to_owned()])
        );
    }

    #[test]
    fn non_empty_trims_and_nones_blank() {
        assert_eq!(non_empty("  hi  "), Some("hi".to_owned()));
        assert!(non_empty("   ").is_none());
        assert!(non_empty("").is_none());
    }

    #[test]
    fn err_message_surfaces_safe_detail_and_hides_internal() {
        // Validation / conflict detail is operator-safe to show.
        assert_eq!(
            err_message(&ApiError::BadRequest("name too long".into())),
            "name too long"
        );
        assert_eq!(
            err_message(&ApiError::Conflict("duplicate name".into())),
            "duplicate name"
        );
        assert_eq!(
            err_message(&ApiError::ServiceUnavailable(
                "profile store not configured"
            )),
            "profile store not configured"
        );
        // Internal failures collapse to a generic line — no detail leaks.
        let msg = err_message(&ApiError::Internal(
            "sqlx: connection refused at db:5432".into(),
        ));
        assert!(!msg.contains("sqlx"), "{msg}");
        assert!(msg.contains("see gateway logs"), "{msg}");
        assert!(
            msg.contains("create"),
            "create-path fallback names the verb: {msg}"
        );
    }

    #[test]
    fn err_message_for_names_the_failing_verb() {
        // The delete handler must not borrow the create-path's
        // "Failed to create profile" fallback for an unclassified
        // delete failure.
        let msg = err_message_for(
            &ApiError::Internal("sqlx: connection refused".into()),
            "delete",
        );
        assert!(msg.contains("delete"), "{msg}");
        assert!(
            !msg.contains("create"),
            "delete fallback must not say create: {msg}"
        );
        assert!(!msg.contains("sqlx"), "no internal detail leaks: {msg}");
        // Operator-safe detail (conflict / bad-request) is surfaced verbatim
        // regardless of verb.
        assert_eq!(
            err_message_for(&ApiError::Conflict("still referenced".into()), "delete"),
            "still referenced"
        );
    }
}
