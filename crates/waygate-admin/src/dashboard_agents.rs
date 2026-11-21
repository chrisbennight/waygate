//! Gateway Agents page — `/admin/t/{tenant}/agents`.
//!
//! Operator view + full inline CRUD of the per-tenant `agent_configs` registry
//! (`waygate_dashboard_stores::agent_config`): the in-app LLM agents (interactive chat today;
//! policy-review / classification task agents later). Each agent pins a model,
//! a tool allowlist (empty by default), loop caps, and an enabled flag.
//!
//! ## Inline actions
//!
//! A create composer plus per-row edit and delete, each admin-gated + CSRF,
//! PRG via `?ag_error=`, reusing the [`crate::agent_configs`] `*_core`
//! functions so validation, the `(tenant, name)` uniqueness conflict, and the
//! fail-closed `AdminMutation` audit live in one place. The edit form is a full
//! replace of every mutable field (so the nullable `instructions` /
//! `token_budget` can be cleared).
//!
//! ## Safety posture
//!
//! - All forms are admin-only by construction (the insufficient-scope gate
//!   hides every byte of agent data, matching the administrator-only policy pages).
//! - The tool allowlist defaults to EMPTY: a new agent can call nothing until
//!   an operator opts tools in.
//! - Reads + writes use `principal.tenant`, never the request.

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
use waygate_dashboard_stores::agent_config::{AgentConfig, AgentKind};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::agent_configs::{
    create_agent_core, delete_agent_core, update_agent_core, AgentConfigInput,
};
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::error::ApiError;
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

/// Row cap for the dashboard list. The store clamps to
/// `waygate_dashboard_stores::agent_config::MAX_LIST_LIMIT` (500).
const LIST_LIMIT: u32 = 200;

#[derive(Template)]
#[template(path = "agents.html")]
struct AgentsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the agent-config store is unwired (dev mode / no DB).
    store_configured: bool,
    /// `true` when the principal lacks `mcp:admin` (or is a peer assertion).
    insufficient_scope: bool,
    agents: Vec<AgentRow>,
    /// Model aliases the operator can pick for an agent (from the `llm_models`
    /// catalog when wired). Rendered as a `<datalist>` for the model field;
    /// empty ⇒ a plain text input with a hint.
    available_models: Vec<String>,
    /// Store-error fallback for the single list fetch.
    error: Option<String>,
    /// `Some(msg)` when a create / edit / delete submission failed, threaded
    /// back via the `?ag_error=` PRG query param.
    ag_error: Option<String>,
}

struct AgentRow {
    /// Relative URLs for the per-row edit / delete form actions; the template
    /// wraps each with `self.nav_url(...)`.
    update_rel: String,
    delete_rel: String,
    name: String,
    kind: &'static str,
    model_alias: String,
    enabled: bool,
    instructions: String,
    /// Newline-joined allowlist for the edit textarea prefill + display.
    allowed_tools_text: String,
    allowed_tools_count: usize,
    max_steps: i32,
    max_tool_calls: i32,
    /// Empty string when no per-run token budget is set.
    token_budget_str: String,
    created_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/agents", get(agents_page))
        .route("/agents/create", post(ag_create))
        .route("/agents/{id}/update", post(ag_update))
        .route("/agents/{id}/delete", post(ag_delete))
}

#[derive(Debug, Default, Deserialize)]
struct AgQuery {
    #[serde(default)]
    ag_error: Option<String>,
}

async fn agents_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<AgQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.agent.agent_configs.enabled();

    let (agents, error) = if insufficient_scope {
        (Vec::new(), None)
    } else {
        match state.agent.agent_configs.get() {
            Some(store) => match store.list(&read_tenant, LIST_LIMIT, 0).await {
                Ok(rows) => (rows.into_iter().map(agent_row).collect(), None),
                Err(e) => {
                    tracing::error!(error = %e, tenant = %read_tenant, "agents page: list failed");
                    (
                        Vec::new(),
                        Some("Failed to load agents — see gateway logs for details.".to_owned()),
                    )
                }
            },
            None => (Vec::new(), None),
        }
    };

    // Model picker suggestions from the LLM catalog (best-effort; a failure
    // just yields no suggestions, the field is still a free text input).
    let available_models = if insufficient_scope {
        Vec::new()
    } else if let Some(catalog) = state.llm.llm_models.get() {
        match catalog.list_models(&read_tenant).await {
            Ok(rows) => rows
                .into_iter()
                .filter(|m| {
                    matches!(
                        m.upstream_api.as_str(),
                        "chat_completions" | "responses" | "messages" | "generate_content"
                    )
                })
                .map(|m| m.alias)
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "agents page: model catalog list failed");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let page = AgentsPage {
        chrome: PageChrome::build(
            &state,
            "Gateway Agents",
            "/agents",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        store_configured,
        insufficient_scope,
        agents,
        available_models,
        error,
        ag_error: q.ag_error,
    };
    render(&page)
}

// --- create / edit / delete -------------------------------------------------

/// Form body for the create composer + per-row edit (full replace).
#[derive(Debug, Deserialize)]
struct AgentForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    model_alias: String,
    #[serde(default)]
    instructions: String,
    #[serde(default)]
    allowed_tools: String,
    #[serde(default)]
    max_steps: String,
    #[serde(default)]
    max_tool_calls: String,
    #[serde(default)]
    token_budget: String,
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

async fn ag_create(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<AgentForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let input = match parse_form(&form) {
        Ok(i) => i,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    match create_agent_core(&state, principal, &input).await {
        Ok(_) => redirect_ok(tenant_ctx),
        Err(e) => redirect_with_error(tenant_ctx, &ag_err_message(&e, "create")),
    }
}

async fn ag_update(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<AgentForm>,
) -> Response {
    let (principal, tenant_ctx) = match authorize(&user, &csrf, &tenant_ctx, &form.csrf) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // By-name `id`: nested under `/t/{tenant}` (and merged at `/`), so a
    // `Path<Uuid>` extractor 500s on the 2-capture mount — parse it manually.
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return redirect_with_error(tenant_ctx, "Invalid agent id.");
    };
    let input = match parse_form(&form) {
        Ok(i) => i,
        Err(msg) => return redirect_with_error(tenant_ctx, &msg),
    };
    match update_agent_core(&state, principal, id, &input).await {
        Ok(Some(_)) => redirect_ok(tenant_ctx),
        Ok(None) => redirect_with_error(tenant_ctx, "That agent no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &ag_err_message(&e, "update")),
    }
}

async fn ag_delete(
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
        return redirect_with_error(tenant_ctx, "Invalid agent id.");
    };
    match delete_agent_core(&state, principal, id).await {
        Ok(true) => redirect_ok(tenant_ctx),
        Ok(false) => redirect_with_error(tenant_ctx, "That agent no longer exists."),
        Err(e) => redirect_with_error(tenant_ctx, &ag_err_message(&e, "delete")),
    }
}

/// Parse the form into an [`AgentConfigInput`]. Field-shape errors (bad kind /
/// non-numeric cap) become friendly `?ag_error=` messages; semantic validation
/// (lengths, ranges) happens in the core's `validate`.
fn parse_form(form: &AgentForm) -> Result<AgentConfigInput, String> {
    let kind =
        AgentKind::parse(form.kind.trim()).ok_or_else(|| "Pick a valid agent kind.".to_owned())?;
    let max_steps = parse_int_field(&form.max_steps, "max steps")?;
    let max_tool_calls = parse_int_field(&form.max_tool_calls, "max tool calls")?;
    let token_budget = parse_opt_int_field(&form.token_budget, "token budget")?;
    let instructions = {
        let t = form.instructions.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        }
    };
    Ok(AgentConfigInput {
        name: form.name.trim().to_owned(),
        kind,
        model_alias: form.model_alias.trim().to_owned(),
        instructions,
        allowed_tools: parse_allowed_tools(&form.allowed_tools),
        max_steps,
        max_tool_calls,
        token_budget,
        enabled: form.enabled.is_some(),
    })
}

/// Split the allowlist textarea (one tool id per line, commas also accepted)
/// into a deduped, trimmed list, dropping empties. Order is preserved.
fn parse_allowed_tools(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tok in raw.split(['\n', ',']) {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.to_owned()) {
            out.push(t.to_owned());
        }
    }
    out
}

fn parse_int_field(raw: &str, field: &str) -> Result<i32, String> {
    raw.trim()
        .parse::<i32>()
        .map_err(|_| format!("{field} must be a whole number."))
}

fn parse_opt_int_field(raw: &str, field: &str) -> Result<Option<i32>, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<i32>()
        .map(Some)
        .map_err(|_| format!("{field} must be a whole number (or left blank)."))
}

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
            (StatusCode::FORBIDDEN, "Agent changes require mcp:admin").into_response(),
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
    Redirect::to(&tenant_ctx::nav_url(tenant_ctx.as_ref(), "/agents")).into_response()
}

fn redirect_with_error(tenant_ctx: Option<TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?ag_error={}",
        tenant_ctx::nav_url(tenant_ctx.as_ref(), "/agents"),
        crate::dashboard::urlencode(msg),
    );
    Redirect::to(&url).into_response()
}

fn ag_err_message(e: &ApiError, verb: &str) -> String {
    match e {
        ApiError::BadRequest(d)
        | ApiError::Conflict(d)
        | ApiError::UnprocessableEntity(d)
        | ApiError::NotFoundDyn(d)
        | ApiError::InternalOperatorVisible(d) => d.clone(),
        ApiError::ServiceUnavailable(d) | ApiError::NotFound(d) => (*d).to_owned(),
        _ => format!("Failed to {verb} agent — see gateway logs for details."),
    }
}

fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

fn agent_row(a: AgentConfig) -> AgentRow {
    AgentRow {
        update_rel: format!("/agents/{}/update", a.id),
        delete_rel: format!("/agents/{}/delete", a.id),
        name: a.name,
        kind: a.kind.as_str(),
        model_alias: a.model_alias,
        enabled: a.enabled,
        instructions: a.instructions.unwrap_or_default(),
        allowed_tools_count: a.allowed_tools.len(),
        allowed_tools_text: a.allowed_tools.join("\n"),
        max_steps: a.max_steps,
        max_tool_calls: a.max_tool_calls,
        token_budget_str: a.token_budget.map(|b| b.to_string()).unwrap_or_default(),
        created_at_abs: format_ts_abs(a.created_at),
    }
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
    fn parse_allowed_tools_splits_dedupes_and_drops_empties() {
        let parsed = parse_allowed_tools("gateway-observe.query_audit\n\n a.b , a.b\nc.d");
        assert_eq!(parsed, vec!["gateway-observe.query_audit", "a.b", "c.d"]);
        assert!(parse_allowed_tools("   \n , \n").is_empty());
    }

    #[test]
    fn parse_int_fields_validate() {
        assert_eq!(parse_int_field("8", "x").unwrap(), 8);
        assert!(parse_int_field("nope", "x").is_err());
        assert_eq!(parse_opt_int_field("  ", "x").unwrap(), None);
        assert_eq!(parse_opt_int_field("100", "x").unwrap(), Some(100));
        assert!(parse_opt_int_field("1.5", "x").is_err());
    }

    #[test]
    fn parse_form_builds_input() {
        let form = AgentForm {
            csrf: "x".into(),
            name: " chat ".into(),
            kind: "chat".into(),
            model_alias: " gpt-x ".into(),
            instructions: "  ".into(),
            allowed_tools: "a.b\nc.d".into(),
            max_steps: "8".into(),
            max_tool_calls: "16".into(),
            token_budget: "".into(),
            enabled: Some("on".into()),
        };
        let input = parse_form(&form).unwrap();
        assert_eq!(input.name, "chat");
        assert_eq!(input.model_alias, "gpt-x");
        assert_eq!(input.kind, AgentKind::Chat);
        assert!(input.instructions.is_none());
        assert_eq!(input.allowed_tools, vec!["a.b", "c.d"]);
        assert!(input.enabled);
        assert_eq!(input.token_budget, None);

        let bad_kind = AgentForm {
            kind: "nope".into(),
            ..form
        };
        assert!(parse_form(&bad_kind).is_err());
    }
}
