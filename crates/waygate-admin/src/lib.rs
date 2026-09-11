//! Admin REST API + htmx dashboard surface.
//!
//! The REST API is the scriptable shape of everything an operator does — list
//! upstreams, inspect Cedar policies, simulate authz decisions, scroll the
//! audit log. Gated by coarse OAuth scopes (`mcp:read`, `mcp:admin`) against
//! the [`waygate_oidc::Principal`] stashed in request extensions by the
//! bearer middleware.
//!
//! The dashboard is the HTML twin of that surface, gated by a session cookie
//! minted via PKCE against the same IdP (see [`auth`]). Both surfaces share
//! [`AdminState`] so changes stay in lock-step.
//!
//! Shape invariants:
//! - REST responses are JSON. Errors are `{"error": ..., "detail": ...}`.
//! - State is a single [`AdminState`] built at startup; handlers extract
//!   what they need from it.
//! - Scope enforcement lives in the router layer, not per handler — keeps
//!   individual handlers free of boilerplate and makes the policy diffable.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

pub(crate) mod admin_mutation;
pub mod agent_configs;
pub mod agent_review;
pub mod api_key_profiles;
pub mod api_key_profiles_section;
pub mod api_keys;
pub mod approval_grants;
pub(crate) mod approval_requirement;
pub mod assist;
pub mod audit;
pub mod audit_bundle;
pub mod audit_retention;
pub mod audit_routing;
pub mod audit_sweep;
pub mod audit_verify;
pub mod auth;
pub mod break_glass;
pub mod builtins;
pub mod capability;
pub mod catalog;
pub mod change_context;
pub mod change_effect_preview;
pub mod change_executor;
pub mod change_notify;
pub mod change_policy_preview;
pub mod change_requests;
pub mod chrome;
pub mod codemode_executions;
pub mod confidential_clients;
pub mod config_reload;
pub mod dashboard;
pub mod dashboard_activity_page;
pub mod dashboard_agent_chat;
pub mod dashboard_agents;
pub mod dashboard_approvals;
pub mod dashboard_break_glass;
pub mod dashboard_builtins;
pub mod dashboard_catalog;
pub mod dashboard_changes;
pub mod dashboard_chat;
pub mod dashboard_connect;
pub mod dashboard_decisions;
pub mod dashboard_decisions_log;
pub mod dashboard_embeddings;
pub mod dashboard_evidence;
pub mod dashboard_federation;
pub mod dashboard_groups;
pub mod dashboard_inspection_rules;
pub mod dashboard_llm_credentials;
pub mod dashboard_llm_models;
pub mod dashboard_oauth_consent;
pub mod dashboard_overview;
pub mod dashboard_playground;
pub mod dashboard_policies;
pub mod dashboard_policy_bundles;
pub mod dashboard_profiles;
pub mod dashboard_rate_limits;
pub mod dashboard_rbac;
pub mod dashboard_scim;
pub mod dashboard_scopes;
pub mod dashboard_server_manifests;
pub mod dashboard_servers;
pub mod dashboard_sessions;
pub mod dashboard_settings;
pub mod dashboard_skills;
pub mod dashboard_tenants;
pub mod dashboard_tools;
pub mod error;
pub mod federated_peers;
pub mod hitl_ws;
pub mod identity_catalog;
pub mod impact;
pub mod inspection_rules;
pub mod manifest_bundles;
pub mod manifest_change_preview;
pub mod manifest_effect;
pub mod manifest_impact;
pub mod oauth_clients;
pub mod oauth_consent;
pub mod openapi;
pub mod page_context;
pub mod palette;
pub mod param_files;
pub mod policies;
pub mod policy_bundles;
pub mod policy_tests;
pub mod rate_limit_policies;
pub mod rbac;
pub mod resource_catalog;
pub mod scim_groups;
pub mod scim_provisioning;
pub mod scim_users;
pub mod scope;
pub mod servers;
pub mod skill_reviews;
pub mod state;
pub mod tasks;
pub mod tenant_ctx;
pub mod tenants;
pub mod upstream_sessions;

pub use auth::{CsrfToken, DashboardAuth, DashboardOidcConfig};
pub use openapi::ApiDoc;
pub use state::{AdminState, SharedCatalogReconcile};

/// Build the `/api/v1` router with scope-gated sub-routers composed in.
///
/// `GET /api/v1/openapi.json` is mounted outside the scope middleware so
/// external tooling (Swagger UI, client codegen, CI schema lint) can fetch
/// the spec without a bearer. The spec only documents shapes; callers still
/// need the appropriate scope to hit the actual endpoints.
pub fn api_router(state: Arc<AdminState>) -> Router<()> {
    // Force the resource-catalog descriptor registry to initialize at router
    // construction (i.e. boot) so its duplicate-key assert fires here — a
    // misregistered resource refuses to start rather than panicking on the
    // first describe_resource/read_resource call.
    let _ = resource_catalog::resource_types();
    Router::new()
        .merge(openapi::router())
        .merge(servers::router(state.clone()))
        .merge(servers::admin_router(state.clone()))
        .merge(builtins::router(state.clone()))
        .merge(policies::router(state.clone()))
        .merge(audit::router(state.clone()))
        .merge(audit_verify::router(state.clone()))
        .merge(audit_routing::router(state.clone()))
        .merge(audit_retention::router(state.clone()))
        .merge(audit_sweep::router(state.clone()))
        .merge(audit_bundle::router(state.clone()))
        .merge(catalog::router(state.clone()))
        .merge(policy_bundles::router(state.clone()))
        .merge(manifest_bundles::router(state.clone()))
        .merge(approval_grants::router(state.clone()))
        .merge(upstream_sessions::router(state.clone()))
        .merge(oauth_consent::router(state.clone()))
        .merge(rbac::router(state.clone()))
        .merge(tenants::router(state.clone()))
        .merge(rate_limit_policies::router(state.clone()))
        .merge(api_key_profiles::router(state.clone()))
        .merge(break_glass::router(state.clone()))
        .merge(change_requests::router(state.clone()))
        .merge(change_requests::admin_router(state.clone()))
        .merge(tasks::router(state.clone()))
        .merge(codemode_executions::router(state.clone()))
        .merge(inspection_rules::router(state.clone()))
        .merge(federated_peers::router(state.clone()))
        .merge(confidential_clients::router(state.clone()))
        .merge(hitl_ws::router(state))
}

/// Build the `/scim/v2` router. SCIM lives at
/// its own URL prefix (NOT `/api/v1/*`) because SCIM clients
/// (Okta, Authentik, EntraID) probe the well-known
/// `/scim/v2/ServiceProviderConfig` path; nesting under
/// `/api/v1/` would force operators to override the IdP
/// SCIM base URL or run a reverse-proxy rewrite. Mounted by
/// the binary alongside `api_router`, behind the same
/// `BearerLayer` so SCIM clients authenticate with API keys
/// just like the admin API.
pub fn scim_router(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .merge(scim_users::router(state.clone()))
        .merge(scim_groups::router(state))
}

/// Build the `/admin` dashboard router (server-rendered, askama + htmx).
///
/// The router is self-contained: all handlers are `.with_state(admin_state)`,
/// so it can be nested under `/admin` at any level. The `auth` argument
/// installs the PKCE + session-cookie auth layer:
///
/// * [`DashboardAuth::Enforce`] — every non-public route requires a valid
///   session cookie; missing/expired cookie ⇒ 302 to `/admin/login`.
/// * [`DashboardAuth::Disabled`] — dev-only bypass. A synthetic `dev@local`
///   principal is injected on every request. The gateway logs a loud warning
///   at startup so this can't ride into production unnoticed.
pub fn dashboard_router(state: Arc<AdminState>, auth: DashboardAuth) -> Router<()> {
    // Login / callback / logout are mounted *before* the session-middleware
    // layer so they can run without a cookie. The middleware's own allow-list
    // still lets them through for defense-in-depth, but mounting order keeps
    // the route graph easy to reason about.
    let auth_routes: Router<()> = Router::new()
        .route("/login", get(auth::login_get))
        .route("/auth/callback", get(auth::callback_get))
        .route("/logout", post(auth::logout_post))
        .with_state(auth.clone());

    let dashboard = dashboard::router(state).layer(axum::middleware::from_fn_with_state(
        auth,
        auth::session_middleware,
    ));

    // `merge` is fine here — the auth routes don't overlap with the dashboard
    // routes, and both share the same `/admin` prefix when nested.
    auth_routes.merge(dashboard)
}
