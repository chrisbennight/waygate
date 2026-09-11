//! Inspection-rules page — `/admin/t/{tenant}/inspection_rules`.
//!
//! Operator view of the per-tenant `inspection_rules` registry
//! (`waygate_dashboard_stores::inspection_rules`) with full inline CRUD. Each rule layers a
//! custom response-inspector override (PII / secrets / poisoning / custom)
//! on top of the built-in rulesets. Columns: inspector, name, enabled,
//! `config` (inspector-specific JSON body), `applies_to` (tool/principal
//! selector JSON), created.
//!
//! ## Inline actions
//!
//! A create composer plus per-row edit and delete, each admin-gated + CSRF,
//! PRG via `?ir_error=`, reusing the REST `*_rule_core` functions so the HTML
//! and JSON surfaces can't drift on validation, the (tenant, inspector, name)
//! uniqueness conflict, or the fail-closed `AdminMutation` audit. `config`
//! and `applies_to` are arbitrary JSON (their shape is validated by the
//! runtime consumer, not storage), so the forms take JSON textareas parsed
//! with `serde_json` on submit; invalid JSON is a friendly `?ir_error=`.
//!
//! All forms are admin-only by construction — the insufficient-scope gate
//! hides every byte of rule data, so a non-admin never sees the forms.
//!
//! ## Tenant scoping
//!
//! Reads + writes use `principal.tenant` (never the request), same posture as
//! every other dashboard page.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use waygate_dashboard_stores::inspection_rules::{InspectionRule, InspectorKind, RuleFilter};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::inspection_rules::{create_rule_core, delete_rule_core, update_rule_core};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

/// Row cap for the dashboard list. The store clamps to
/// `waygate_dashboard_stores::inspection_rules::MAX_LIST_LIMIT` (500); operators with more
/// rules than this should narrow via the REST surface.
const LIST_LIMIT: u32 = 200;

#[derive(Template)]
#[template(path = "inspection_rules.html")]
struct InspectionRulesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the inspection-rules store is unwired (dev mode / no DB).
    store_configured: bool,
    /// `true` when the principal lacks `mcp:admin` (or is a peer assertion).
    /// Template renders the insufficient-scope card and SKIPS the store read.
    insufficient_scope: bool,
    rules: Vec<RuleRow>,
    /// Store-error fallback for the single list fetch.
    error: Option<String>,
    /// `Some(msg)` when a create / edit / delete submission failed, threaded
    /// back via the `?ir_error=` PRG query param.
    ir_error: Option<String>,
}

struct RuleRow {
    /// Relative URLs for the per-row edit / delete form actions; the template
    /// wraps each with `self.nav_url(...)`. Precomputed (askama can't
    /// `format!` the id into the path inline).
    update_rel: String,
    delete_rel: String,
    inspector: &'static str,
    name: String,
    enabled: bool,
    /// Pretty-printed JSON for display + the edit form's textarea prefill.
    config_pretty: String,
    applies_to_pretty: String,
    created_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/inspection_rules", get(inspection_rules_page))
        .route("/inspection_rules/create", post(ir_create))
        .route("/inspection_rules/{id}/update", post(ir_update))
        .route("/inspection_rules/{id}/delete", post(ir_delete))
}

#[derive(Debug, Default, Deserialize)]
struct IrQuery {
    #[serde(default)]
    ir_error: Option<String>,
}

async fn inspection_rules_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<IrQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.policy.inspection_rules.enabled();
    let (rules, error) = if insufficient_scope {
        (Vec::new(), None)
    } else {
        match state.policy.inspection_rules.get() {
            Some(store) => {
                let filter = RuleFilter {
                    inspector: None,
                    name: None,
                    enabled: None,
                };
                match store.list(&read_tenant, filter, LIST_LIMIT, 0).await {
                    Ok(rows) => (rows.into_iter().map(rule_row).collect(), None),
                    Err(e) => {
                        tracing::error!(error = %e, tenant = %read_tenant, "inspection_rules page: list failed");
                        (
                            Vec::new(),
                            Some(
                                "Failed to load inspection rules — see gateway logs for details."
                                    .to_owned(),
                            ),
                        )
                    }
                }
            }
            None => (Vec::new(), None),
        }
    };

    let page = InspectionRulesPage {
        chrome: PageChrome::build(
            &state,
            "Inspection rules",
            "/inspection_rules",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        rules,
        error,
        ir_error: q.ir_error,
    };
    render(&page)
}

// --- create / edit / delete -------------------------------------------------

/// Form body for the create composer + per-row edit (the edit form submits
/// every mutable field — a full replace).
#[derive(Debug, Deserialize)]
struct RuleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    inspector: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    config: String,
    #[serde(default)]
    applies_to: String,
    /// Checkbox: present (`"on"`) ⇒ enabled, absent ⇒ disabled.
    #[serde(default)]
    enabled: Option<String>,
}

/// Form body for the per-row delete — only the CSRF token.
#[derive(Debug, Deserialize)]
struct DeleteForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /inspection_rules/create` — admin-gated + CSRF, parses the JSON
/// `config` / `applies_to` textareas and reuses [`create_rule_core`].
async fn ir_create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<RuleForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(inspector) = parse_inspector(form.inspector.trim()) else {
        return redirect_with_error(tenant_ctx, "Pick a valid inspector.");
    };
    let config = match parse_json_field(&form.config, "config") {
        Ok(v) => v,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    let applies_to = match parse_applies_to(&form.applies_to) {
        Ok(v) => v,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    let enabled = form.enabled.is_some();
    match create_rule_core(
        &state,
        principal,
        inspector,
        form.name.trim(),
        &config,
        &applies_to,
        enabled,
    )
    .await
    {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &ir_err_message(&e, "create")),
    }
}

/// `POST /inspection_rules/{id}/update` — admin-gated + CSRF. The edit form
/// is a full replace of the mutable fields (name, config, applies_to,
/// enabled); inspector is the rule's identity and is not editable.
async fn ir_update(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<RuleForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // By-name `id`: this route is nested under `/t/{tenant}` (and merged at
    // `/`), so a `Path<Uuid>` extractor 500s on the 2-capture tenant-scoped
    // mount.
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return redirect_with_error(tenant_ctx, "Invalid rule id.");
    };
    let config = match parse_json_field(&form.config, "config") {
        Ok(v) => v,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    let applies_to = match parse_applies_to(&form.applies_to) {
        Ok(v) => v,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    let enabled = form.enabled.is_some();
    match update_rule_core(
        &state,
        principal,
        id,
        Some(form.name.trim()),
        Some(&config),
        Some(&applies_to),
        Some(enabled),
    )
    .await
    {
        Ok(Some(_)) => redirect_ok(tenant_ctx),
        Ok(None) => redirect_with_error(tenant_ctx, "That rule no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &ir_err_message(&e, "update")),
    }
}

/// `POST /inspection_rules/{id}/delete` — admin-gated + CSRF, reuses
/// [`delete_rule_core`].
async fn ir_delete(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return redirect_with_error(tenant_ctx, "Invalid rule id.");
    };
    match delete_rule_core(&state, principal, id).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That rule no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &ir_err_message(&e, "delete")),
    }
}

/// Shared admin-gate + CSRF for the mutation handlers. Uses the page's
/// stricter [`principal_has_dashboard_admin`] (refuses peer-asserted
/// principals). Returns `(principal, tenant_ctx)` or the boxed error
/// `Response`.
#[allow(clippy::type_complexity)]
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<Extension<TenantContext>>,
    form_csrf: &str,
) -> Result<(&'a Principal, Option<TenantContext>), Box<Response>> {
    let principal_opt = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(principal_opt) {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "Inspection-rule changes require mcp:admin",
            )
                .into_response(),
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
    let Some(principal) = principal_opt else {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "admin scope required").into_response(),
        ));
    };
    Ok((principal, tenant_ctx.clone().map(|Extension(c)| c)))
}

fn redirect_ok(tenant_ctx: Option<TenantContext>) -> Response {
    Redirect::to(&tenant_ctx::nav_url(
        tenant_ctx.as_ref(),
        "/inspection_rules",
    ))
    .into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?ir_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/inspection_rules"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

/// Parse a required JSON textarea into a `Value`. Empty ⇒ a friendly error
/// (config is required); invalid JSON ⇒ a friendly error naming the field.
fn parse_json_field(raw: &str, field: &str) -> Result<Value, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(format!("{field} is required (JSON object)."));
    }
    serde_json::from_str(t).map_err(|e| format!("{field} must be valid JSON: {e}"))
}

/// Parse the optional `applies_to` textarea. Empty ⇒ `{}` (any tool / any
/// principal), matching the REST default; otherwise it must be valid JSON.
fn parse_applies_to(raw: &str) -> Result<Value, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    serde_json::from_str(t).map_err(|e| format!("applies_to must be valid JSON: {e}"))
}

/// Parse the inspector `<select>` value. Matches [`InspectorKind::parse`].
fn parse_inspector(s: &str) -> Option<InspectorKind> {
    InspectorKind::parse(s)
}

/// Operator-safe inspection-rule mutation message, parameterized by verb.
fn ir_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::NotFoundDyn(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) | ApiError::NotFound(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} inspection rule — see gateway logs for details."),
    }
}

/// Authorization gate for the inspection-rules dashboard page. Same shape as
/// the rate-limits / break-glass pages — refuses peer assertions even when
/// scopes appear to match, matching the REST `require_admin` posture.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

fn rule_row(r: InspectionRule) -> RuleRow {
    RuleRow {
        update_rel: format!("/inspection_rules/{}/update", r.id),
        delete_rel: format!("/inspection_rules/{}/delete", r.id),
        inspector: r.inspector.as_str(),
        name: r.name,
        enabled: r.enabled,
        config_pretty: pretty_json(&r.config),
        applies_to_pretty: pretty_json(&r.applies_to),
        created_at_abs: format_ts_abs(r.created_at),
    }
}

/// Pretty-print a JSON value for the textarea / display; falls back to the
/// compact form if (somehow) it can't serialize.
fn pretty_json(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn admin_gate_allows_oauth_admin_blocks_peer_and_non_admin() {
        assert!(principal_has_dashboard_admin(Some(&principal_with(
            vec!["mcp:admin"],
            AuthMethod::Oauth
        ))));
        assert!(!principal_has_dashboard_admin(Some(&principal_with(
            vec!["mcp:read"],
            AuthMethod::Oauth
        ))));
        assert!(!principal_has_dashboard_admin(Some(&principal_with(
            vec!["mcp:admin"],
            AuthMethod::PeerAssertion
        ))));
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn parse_json_field_requires_nonempty_valid_json() {
        assert!(parse_json_field("  ", "config").is_err());
        assert!(parse_json_field("not json", "config").is_err());
        assert_eq!(
            parse_json_field(r#"{"pattern":"x"}"#, "config").unwrap(),
            serde_json::json!({"pattern": "x"}),
        );
    }

    #[test]
    fn parse_applies_to_defaults_empty_to_object() {
        assert_eq!(parse_applies_to("   ").unwrap(), serde_json::json!({}));
        assert!(parse_applies_to("[bad").is_err());
        assert_eq!(
            parse_applies_to(r#"{"tools":["a.b"]}"#).unwrap(),
            serde_json::json!({"tools": ["a.b"]}),
        );
    }

    #[test]
    fn parse_inspector_matches_kinds() {
        assert_eq!(parse_inspector("pii"), Some(InspectorKind::Pii));
        assert_eq!(parse_inspector("secrets"), Some(InspectorKind::Secrets));
        assert_eq!(parse_inspector("poisoning"), Some(InspectorKind::Poisoning));
        assert_eq!(parse_inspector("custom"), Some(InspectorKind::Custom));
        assert_eq!(parse_inspector("nope"), None);
    }
}
