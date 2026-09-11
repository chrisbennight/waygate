//! Policy playground page — `/admin/t/{tenant}/playground`.
//!
//! Standalone interactive Cedar policy tester — a live "policy
//! playground". An operator fills in a
//! hypothetical principal + action + resource and gets back the
//! gateway's live Cedar verdict — `allow` / `deny` / `step_up` — plus
//! the human-readable `reasons` and the matched `policy_ids`.
//!
//! ## Why this is a thin page
//!
//! The evaluation surface already exists: the Policies page ships an
//! inline simulator that POSTs to `/policies/simulate`
//! (`dashboard::policies_simulate`), which builds a synthetic
//! `Principal`/`Action`/`ResourceSpec`, runs the live
//! `AuthzEngine::evaluate`, and renders the shared
//! `policy_result.html` fragment (decision + reasons + policy IDs +
//! step-up affordance), which carries Cedar `@reason` annotations
//! through to the rendered result.
//!
//! This page is a **dedicated, roomier home** for that same
//! capability — a full-page form instead of a sidebar panel on the
//! Policies page — so policy authors have a stable place to iterate.
//! It reuses the existing `/policies/simulate` endpoint verbatim (same
//! field names, same CSRF token, same htmx target), so there is **no
//! new evaluation surface**.
//!
//! ## Saved scenarios
//!
//! The stateless form is unhelpful once an operator has 4-5 canonical
//! "regression scenarios" they re-run after every policy edit, so a
//! small per-tenant `playground_scenarios` table backs Save / Load
//! / Delete affordances on this page. The saved-body is the form's
//! JSON snapshot; loading a scenario pre-fills the form via
//! `?load=<name>` and the operator clicks Simulate as before.
//!
//! - `GET /playground[?load=<name>]` — the page handler. With
//!   `?load=<name>` set, pulls the named scenario, JSON-decodes the
//!   body, and pre-fills every form field. Unknown name renders the
//!   form with defaults + a small "scenario `name` not found" notice.
//! - `POST /playground/scenarios` — Save the current form values
//!   under a name. Upsert-by-name; the operator's `sub` is recorded
//!   as `created_by` for attribution. CSRF-checked.
//! - `POST /playground/scenarios/{name}/delete` — Delete a named
//!   scenario. POST (not DELETE) so the no-JS form works via the
//!   standard CSRF middleware that gates `POST` on the dashboard
//!   surface today.
//!
//! ## Scope posture
//!
//! Mirrors `dashboard::policies_page` exactly: the page renders for
//! any authenticated dashboard session (no in-page `mcp:admin` gate),
//! same as the existing Policies-page simulator this reuses. The
//! evaluation itself is read-only; the saved-scenarios mutations are
//! dashboard-only (no runtime path reads the table) and live behind
//! the existing dashboard CSRF gate.

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
use waygate_dashboard_stores::playground_scenarios::{validate_name, Scenario};
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// `?load=<name>` on the GET handler. Empty / unknown ⇒
/// the form pre-fills with the canonical defaults.
#[derive(Debug, Default, Deserialize)]
pub struct PlaygroundQuery {
    #[serde(default)]
    load: Option<String>,
}

#[derive(Template)]
#[template(path = "playground.html")]
struct PlaygroundPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when a Cedar engine is wired. `false` (dev-mode
    /// auth-disabled, no engine) ⇒ the template renders a
    /// "simulator unavailable" card instead of the form, matching
    /// what `/policies/simulate` would return (503) if posted.
    cedar_configured: bool,
    /// `true` when the `PlaygroundScenarioStore` is wired
    /// on `AdminState`. `false` ⇒ the Saved scenarios sidebar +
    /// Save form + Delete buttons all hide; the page falls back
    /// to the stateless shape.
    scenarios_configured: bool,
    /// Saved scenarios for the active tenant, alphabetised
    /// by name. Empty until the operator saves the first one.
    scenarios: Vec<ScenarioRow>,
    /// `true` when an `?load=<name>` request named a
    /// scenario that doesn't exist in the active tenant. Form
    /// still renders with defaults; the template surfaces a
    /// small notice so the operator sees why their bookmark
    /// didn't restore.
    load_miss: bool,
    /// Form-field values used to pre-fill each input. When
    /// `?load=<name>` resolves to a stored scenario, these reflect
    /// the saved body; otherwise the canonical defaults.
    form: PlaygroundForm,
    /// Name of the scenario currently loaded, or `None`
    /// for a fresh form. Pre-fills the Save form's "name" input
    /// so the typical workflow (load, tweak, re-save) just
    /// requires a single Save click.
    loaded_name: Option<String>,
}

/// Pre-fill values for every playground form input. Defaults
/// preserve the canonical example (alice@example.com,
/// engineers group, send_message tool); any saved scenario
/// overrides per the body's JSON shape.
struct PlaygroundForm {
    sub: String,
    groups: String,
    scopes: String,
    auth_method: String,
    action: String,
    risk: String,
    resource_type: String,
    server: String,
    tool: String,
    tool_name: String,
    pii: bool,
}

impl Default for PlaygroundForm {
    fn default() -> Self {
        Self {
            sub: "alice@example.com".into(),
            groups: "engineers".into(),
            scopes: "mcp:read".into(),
            auth_method: "oauth".into(),
            action: "call_tool".into(),
            risk: "low".into(),
            resource_type: "tool".into(),
            server: "example-messages".into(),
            tool: "send_message".into(),
            tool_name: "send_message".into(),
            pii: false,
        }
    }
}

impl PlaygroundForm {
    /// Decode a stored scenario's JSON body into the form. Missing
    /// keys fall back to defaults; unknown keys are silently
    /// ignored (forward-compat with future form fields).
    fn from_body(body: &Value) -> Self {
        let mut out = Self::default();
        if let Some(s) = body.get("sub").and_then(Value::as_str) {
            out.sub = s.to_owned();
        }
        if let Some(s) = body.get("groups").and_then(Value::as_str) {
            out.groups = s.to_owned();
        }
        if let Some(s) = body.get("scopes").and_then(Value::as_str) {
            out.scopes = s.to_owned();
        }
        if let Some(s) = body.get("auth_method").and_then(Value::as_str) {
            out.auth_method = s.to_owned();
        }
        if let Some(s) = body.get("action").and_then(Value::as_str) {
            out.action = s.to_owned();
        }
        if let Some(s) = body.get("risk").and_then(Value::as_str) {
            out.risk = s.to_owned();
        }
        if let Some(s) = body.get("resource_type").and_then(Value::as_str) {
            out.resource_type = s.to_owned();
        }
        if let Some(s) = body.get("server").and_then(Value::as_str) {
            out.server = s.to_owned();
        }
        if let Some(s) = body.get("tool").and_then(Value::as_str) {
            out.tool = s.to_owned();
        }
        if let Some(s) = body.get("tool_name").and_then(Value::as_str) {
            out.tool_name = s.to_owned();
        }
        if let Some(b) = body.get("pii").and_then(Value::as_bool) {
            out.pii = b;
        }
        out
    }
}

/// A saved scenario as the sidebar renders it. Pre-
/// formatted timestamps and the relative
/// `/playground?load=<name>` and
/// `/playground/scenarios/<name>/delete` URLs the template
/// uses directly.
struct ScenarioRow {
    name: String,
    /// URL-encoded form of `name` for `?load=<URL>` + `.../{name}/delete` —
    /// `validate_name` constrains the input to URL-safe chars
    /// plus space, but space still needs `%20` encoding for the
    /// bookmarkable link.
    name_qs: String,
    created_by_display: String,
    updated_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/playground", get(playground_page))
        // Save + Delete are dashboard-only mutations gated
        // behind the existing dashboard CSRF middleware. Same
        // POST-with-form-body shape every other dashboard
        // mutation uses today.
        .route("/playground/scenarios", post(save_scenario))
        .route("/playground/scenarios/{name}/delete", post(delete_scenario))
}

async fn playground_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<PlaygroundQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let scenarios_configured = state.dashboard.playground_scenarios.enabled();

    // Load saved scenarios for the sidebar. Empty Vec when the
    // store isn't wired or the list errors — surface a log line
    // on error rather than 500-ing the page.
    let scenarios: Vec<ScenarioRow> = match state.dashboard.playground_scenarios.get() {
        None => Vec::new(),
        Some(store) => match store.list(&read_tenant).await {
            Ok(list) => list.into_iter().map(scenario_row).collect(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %read_tenant,
                    "playground page: scenarios.list failed",
                );
                Vec::new()
            }
        },
    };

    // If `?load=<name>` is set, fetch + decode the body. Unknown
    // name renders the form with defaults + the load_miss notice;
    // a load against an unwired store falls through to defaults
    // (the operator's bookmark was made before the store became
    // configured, or the store flap'd — either way, the form
    // still renders).
    let (form, loaded_name, load_miss) = match (
        q.load.as_deref(),
        state.dashboard.playground_scenarios.get(),
    ) {
        (Some(name), Some(store)) if !name.is_empty() => {
            // validate_name returns the same Err the store would
            // raise; check up-front so a bad name doesn't make
            // it past the dashboard layer (and so the error
            // message is clearly "name shape" vs "name missing").
            if validate_name(name).is_err() {
                (PlaygroundForm::default(), None, true)
            } else {
                match store.get(&read_tenant, name).await {
                    Ok(Some(s)) => (PlaygroundForm::from_body(&s.body), Some(s.name), false),
                    Ok(None) => (PlaygroundForm::default(), None, true),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            tenant = %read_tenant,
                            name = name,
                            "playground page: scenarios.get failed",
                        );
                        (PlaygroundForm::default(), None, true)
                    }
                }
            }
        }
        _ => (PlaygroundForm::default(), None, false),
    };

    render(&PlaygroundPage {
        chrome: PageChrome::build(
            &state,
            "Playground",
            "/playground",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        cedar_configured: state.policy.cedar.enabled(),
        scenarios_configured,
        scenarios,
        load_miss,
        form,
        loaded_name,
    })
}

fn scenario_row(s: Scenario) -> ScenarioRow {
    ScenarioRow {
        name_qs: urlencode(&s.name),
        created_by_display: s.created_by.unwrap_or_else(|| "—".into()),
        updated_at_abs: format_ts_abs(s.updated_at),
        name: s.name,
    }
}

/// Save POST handler. The form body carries every playground
/// field PLUS the operator-chosen `name`. Body validation is
/// double-checked here even though the template restricts the
/// name input to the allowed shape — operators can craft a
/// direct POST.
#[derive(Debug, Deserialize)]
pub struct SaveForm {
    #[serde(default)]
    csrf: String,
    name: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    groups: String,
    #[serde(default)]
    scopes: String,
    #[serde(default)]
    auth_method: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    risk: String,
    #[serde(default)]
    resource_type: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    tool_name: String,
    /// HTML form posts unchecked checkboxes as absent → serde
    /// default `None`; checked → `Some("on")`. We coerce to a
    /// bool at the boundary so the stored JSON shape stays
    /// stable.
    #[serde(default)]
    pii: Option<String>,
}

async fn save_scenario(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<SaveForm>,
) -> Response {
    // CSRF gate. Mirror the existing dashboard `policies_simulate`
    // pattern: compare against the per-session token. The
    // middleware injects the same CsrfToken extension the form's
    // hidden input was stamped with.
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.dashboard.playground_scenarios.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "playground scenarios store not configured",
        )
            .into_response();
    };
    if let Err(e) = validate_name(&body.name) {
        return (StatusCode::BAD_REQUEST, format!("{e}")).into_response();
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let created_by = user_principal.map(|p| p.sub.clone());

    // Forward-compat preservation of unknown JSON keys runs
    // inside the SQL upsert (`playground_scenarios.body ||
    // EXCLUDED.body`), so this handler hands over ONLY the known
    // form fields and lets the store atomically merge with any
    // existing row — same shape as the activity saved-views save
    // handler. A read → modify → write merge here would open a
    // race window where a concurrent same-name save could clobber
    // a freshly-written unknown key between the read and the
    // write, and would silently fall back to an empty base
    // (dropping those keys) if the pre-merge read errored.
    let mut body_map = serde_json::Map::new();
    body_map.insert("sub".into(), Value::String(body.sub));
    body_map.insert("groups".into(), Value::String(body.groups));
    body_map.insert("scopes".into(), Value::String(body.scopes));
    body_map.insert("auth_method".into(), Value::String(body.auth_method));
    body_map.insert("action".into(), Value::String(body.action));
    body_map.insert("risk".into(), Value::String(body.risk));
    body_map.insert("resource_type".into(), Value::String(body.resource_type));
    body_map.insert("server".into(), Value::String(body.server));
    body_map.insert("tool".into(), Value::String(body.tool));
    body_map.insert("tool_name".into(), Value::String(body.tool_name));
    body_map.insert("pii".into(), Value::Bool(body.pii.as_deref() == Some("on")));
    let body_json = Value::Object(body_map);

    match store
        .save(&tenant, &body.name, body_json, created_by.as_deref())
        .await
    {
        Ok(_) => {
            // PRG: redirect to the playground page with the
            // freshly-saved scenario loaded. Same pattern the
            // tenant-switch form uses — keeps the URL
            // bookmarkable and the next refresh re-fetches the
            // scenario instead of re-submitting the form.
            let url = format!(
                "{}?load={}",
                crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/playground"),
                urlencode(&body.name),
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "playground save_scenario failed");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf: String,
}

async fn delete_scenario(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(body): Form<DeleteForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.dashboard.playground_scenarios.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "playground scenarios store not configured",
        )
            .into_response();
    };
    // Read `name` by name: mounted at both `/playground/scenarios/{name}/delete`
    // and the 2-capture `/t/{tenant}/...` nest; `Path<String>` 500s on the
    // latter.
    let Some(name) = params.get("name") else {
        return (StatusCode::BAD_REQUEST, "missing scenario name").into_response();
    };
    if let Err(e) = validate_name(name) {
        return (StatusCode::BAD_REQUEST, format!("{e}")).into_response();
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    match store.delete(&tenant, name).await {
        Ok(_existed) => {
            // PRG back to the playground page with no scenario loaded.
            let url = crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/playground");
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "playground delete_scenario failed");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}

fn csrf_ok(injected: Option<&Extension<CsrfToken>>, form_value: &str) -> bool {
    match injected {
        Some(Extension(c)) => !form_value.is_empty() && form_value == c.0,
        None => true, // dev-mode auth-disabled has no CSRF token to compare
    }
}

/// Minimal URL encoder. `validate_name` constrains scenario
/// names to `[A-Za-z0-9 _-]`, so the only character requiring
/// encoding in practice is the space (` ` → `%20`). The encoder
/// stays general (percent-encodes anything outside the unreserved
/// set) so a future widening of `validate_name` doesn't silently
/// emit broken URLs.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_from_body_overrides_defaults() {
        let body = serde_json::json!({
            "sub": "bob@example.com",
            "groups": "ops,sre",
            "scopes": "mcp:admin",
            "action": "list_tools",
            "risk": "high",
            "pii": true,
        });
        let form = PlaygroundForm::from_body(&body);
        assert_eq!(form.sub, "bob@example.com");
        assert_eq!(form.groups, "ops,sre");
        assert_eq!(form.scopes, "mcp:admin");
        assert_eq!(form.action, "list_tools");
        assert_eq!(form.risk, "high");
        assert!(form.pii);
        // Unset keys keep defaults.
        assert_eq!(form.server, "example-messages");
    }

    #[test]
    fn form_from_body_silently_ignores_unknown_keys() {
        let body = serde_json::json!({
            "future_field": "ignore me",
            "sub": "carol@example.com",
        });
        let form = PlaygroundForm::from_body(&body);
        assert_eq!(form.sub, "carol@example.com");
        // No panic, no error — forward-compat.
    }

    #[test]
    fn urlencode_handles_space_and_special_chars() {
        assert_eq!(urlencode("alice deny"), "alice%20deny");
        assert_eq!(urlencode("ok-name_2"), "ok-name_2");
        // Validate_name forbids these but the encoder is robust.
        assert_eq!(urlencode("a?b&c=d"), "a%3Fb%26c%3Dd");
    }

    #[test]
    fn csrf_ok_requires_match_when_token_present() {
        let token = CsrfToken("good-token".into());
        let ext = Extension(token);
        assert!(csrf_ok(Some(&ext), "good-token"));
        assert!(!csrf_ok(Some(&ext), "wrong-token"));
        assert!(!csrf_ok(Some(&ext), ""));
    }

    #[test]
    fn csrf_ok_permits_dev_mode_with_no_extension() {
        // No CsrfToken injected ⇒ no comparison to do; pass
        // through so dev-mode (auth-disabled) doesn't get
        // 403-locked out of the Save/Delete flow.
        assert!(csrf_ok(None, ""));
        assert!(csrf_ok(None, "anything"));
    }
}
