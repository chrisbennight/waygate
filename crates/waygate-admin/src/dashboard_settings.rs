//! Settings page — `/admin/t/{tenant}/settings`.
//!
//! Editable gateway-wide response delivery defaults, plus read-only boot
//! configuration, identity summaries, and capability status.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin`. A dashboard
//! session without `mcp:admin` (or a peer-asserted principal)
//! sees the insufficient-scope card and the
//! introspection/JWKS panes are not rendered — the
//! `SystemInfo` snapshot is non-secret, but treating the
//! whole page as admin-only matches every other dashboard
//! page's posture and keeps the gate uniform.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::{AdminState, IntrospectionSummary, JwksSummary, SystemInfo};
use crate::tenant_ctx::TenantContext;

/// Mirror of the bearer-chain's `want_upstream` predicate
/// (`waygate-server::main` — search the same file for
/// `want_upstream`). Re-stated here as a free function so the
/// Settings-page contract test can pin the truth table for
/// the introspection `active` flag without depending on
/// `waygate-server`.
///
/// The boot path skips wiring the introspection validator when
/// AS mode is on AND the upstream-tokens passthrough flag is
/// off, but the env triple may still be set.
/// `IntrospectionSummary.active` must follow this same rule so
/// the Settings page doesn't claim introspection is enabled
/// when it isn't.
pub fn introspection_active(as_enabled: bool, accept_upstream_tokens: bool) -> bool {
    !as_enabled || accept_upstream_tokens
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,

    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). The template renders the
    /// insufficient-scope card and skips every settings
    /// section.
    insufficient_scope: bool,
    response: ResponseSettingsPanel,

    /// Frozen-at-boot snapshot — see [`SystemInfo`].
    system: Arc<SystemInfo>,
    /// Capability-flag grid (boolean per-substrate). Always
    /// rendered when the principal can see the page;
    /// derived from `AdminState` field presence at request
    /// time so a hot-rewired store (none exist today, but
    /// future operator changes might) is reflected.
    capabilities: Vec<CapabilityRow>,
    /// `state.public_url`, surfaced both standalone (as the
    /// gateway's external URL) and as the host of the JWKS
    /// URL in [`SystemInfo::jwks`].
    public_url: String,
    /// `state.hitl.require_two_approvals` from the boot env. Surfaced
    /// because it materially affects the Catalog approval
    /// workflow without being visible elsewhere on the
    /// dashboard.
    two_approver_mode: bool,
    /// `state.identity.api_keys_enabled` from the boot env. Distinct
    /// from "API keys store is wired" (which the capability
    /// grid covers) — this flag gates the mint/list admin
    /// surface.
    api_keys_enabled: bool,
    /// `state.dashboard.overview_change_feed_actions` — the allowlist of change-request
    /// actions the Overview "What changed" feed surfaces from the broad
    /// `admin_mutation` category. Set via `GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS`
    /// (comma-separated); shown read-only here so an operator can see the
    /// effective set without reading the env.
    overview_change_feed_actions: Vec<String>,
}

/// One row in the capability grid. `name` is the operator-
/// facing label, `env_hint` names the env var(s) that flip
/// the row from off to on (rendered as a hint when `enabled`
/// is false), and `enabled` is read live off `AdminState`.
struct CapabilityRow {
    name: &'static str,
    enabled: bool,
    env_hint: &'static str,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/settings", get(settings_page))
        .route("/settings/responses", post(response_settings_save))
}

async fn settings_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<crate::auth::CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);

    let capabilities = if insufficient_scope {
        Vec::new()
    } else {
        build_capabilities(&state)
    };

    let page = SettingsPage {
        response: response_settings_panel(
            &state,
            user_principal,
            tenant_ctx.as_ref(),
            csrf.as_ref().map(|Extension(c)| c.0.as_str()).unwrap_or(""),
            String::new(),
        )
        .await,
        chrome: PageChrome::build(
            &state,
            "Settings",
            "/settings",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        insufficient_scope,
        system: state.system.clone(),
        capabilities,
        public_url: state.public_url.clone(),
        two_approver_mode: state.hitl.require_two_approvals,
        api_keys_enabled: state.identity.api_keys_feature.enabled(),
        overview_change_feed_actions: state.dashboard.overview_change_feed_actions.clone(),
    };
    render(&page)
}

/// Gateway-wide edits require an administrator of the default tenant, viewed
/// in that tenant. A tenant-local administrator cannot change other tenants.
pub(crate) fn require_global_settings_admin(
    principal: Option<&Principal>,
    tenant: Option<&TenantContext>,
) -> Result<(), crate::error::ApiError> {
    crate::scope::require_admin_extension(principal)?;
    if principal.is_some_and(|p| p.tenant.as_str() != waygate_core::TenantId::DEFAULT)
        || tenant.is_some_and(|t| t.slug != waygate_core::TenantId::DEFAULT)
    {
        return Err(crate::error::ApiError::Forbidden(
            "gateway-wide settings require the default tenant administrator",
        ));
    }
    Ok(())
}

#[derive(Template)]
#[template(path = "response_settings.html")]
struct ResponseSettingsPanel {
    available: bool,
    form_url: String,
    csrf: String,
    threshold: usize,
    effective: usize,
    revision: i64,
    environment_override: bool,
    editable: bool,
    message: String,
}

async fn response_settings_panel(
    state: &AdminState,
    principal: Option<&Principal>,
    tenant: Option<&TenantContext>,
    csrf: &str,
    mut message: String,
) -> ResponseSettingsPanel {
    let result = state.response_settings.get().await;
    let available = result.is_ok();
    let settings = match result {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(%error, "response settings could not be loaded");
            message =
                "Response settings are unavailable. Reopen Settings after the database recovers."
                    .to_owned();
            Default::default()
        }
    };
    let environment_override = state.response_settings.environment_override();
    ResponseSettingsPanel {
        available,
        form_url: crate::tenant_ctx::nav_url(tenant, "/settings/responses"),
        csrf: csrf.to_owned(),
        threshold: settings.inline_response_threshold_bytes.get(),
        effective: environment_override
            .unwrap_or(settings.inline_response_threshold_bytes)
            .get(),
        revision: settings.revision,
        environment_override: environment_override.is_some(),
        editable: available
            && state.response_settings.writable()
            && require_global_settings_admin(principal, tenant).is_ok(),
        message,
    }
}

#[derive(serde::Deserialize)]
struct ResponseSettingsForm {
    csrf: String,
    revision: i64,
    inline_response_threshold_bytes: String,
}

async fn response_settings_save(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<crate::auth::CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Form(form): Form<ResponseSettingsForm>,
) -> Response {
    let principal = user.as_ref().map(|Extension(p)| p);
    let tenant = tenant.as_ref().map(|Extension(t)| t);
    if let Err(error) = require_global_settings_admin(principal, tenant) {
        return error.into_response();
    }
    if !crate::dashboard::activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let threshold = form
        .inline_response_threshold_bytes
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|value| i64::try_from(*value).is_ok())
        .and_then(std::num::NonZeroUsize::new);
    let message = match threshold {
        None => "Enter a positive whole byte count no larger than 9223372036854775807.".to_owned(),
        Some(threshold) => match state
            .response_settings
            .update(
                form.revision,
                threshold,
                principal
                    .expect("admin gate requires a principal")
                    .sub
                    .as_str(),
            )
            .await
        {
            Ok(_) => {
                if let Err(error) = crate::admin_mutation::record_admin_mutation(
                    &state,
                    "response_settings",
                    "Settings → Response delivery",
                    waygate_core::TenantId::DEFAULT,
                    principal,
                    "response_settings.update",
                    format!("inline_response_threshold_bytes={threshold}"),
                )
                .await
                {
                    return error.into_response();
                }
                "Saved. New tool calls use this default unless a server or environment override applies.".to_owned()
            }
            Err(error @ (waygate_dashboard_stores::response_settings::ResponseSettingsError::Conflict | waygate_dashboard_stores::response_settings::ResponseSettingsError::Unavailable)) => error.to_string(),
            Err(error) => {
                tracing::error!(%error, "response settings save failed");
                "Response settings could not be saved. Reopen Settings and try again.".to_owned()
            },
        },
    };
    render(&response_settings_panel(&state, principal, tenant, &form.csrf, message).await)
}

/// Authorization gate for the Settings dashboard page. Same
/// shape as the other dashboard pages — `mcp:admin` scope AND
/// not a federated-peer assertion. Peer principals reach the
/// dashboard via the same bearer middleware as humans but
/// must not see capability/config metadata that could shape
/// a follow-up attack.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Build the capability-flag grid from live `AdminState`
/// field presence. Each row's `enabled` reflects whether the
/// corresponding store / hub / flag was wired at boot; the
/// `env_hint` strings tell the operator which env var to set
/// to enable a missing capability (kept short — the rotation
/// runbooks live in `docs/agents/`).
fn build_capabilities(state: &AdminState) -> Vec<CapabilityRow> {
    vec![
        CapabilityRow {
            name: "Postgres audit reader",
            enabled: state.observability.audit.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Built-in OAuth AS",
            enabled: state.identity.oauth.enabled(),
            env_hint: "GATEWAY_AS_ENABLED=true",
        },
        CapabilityRow {
            name: "Tier-A upstream sessions",
            enabled: state.identity.upstream_sessions.enabled(),
            env_hint: "GATEWAY_AS_ENABLED + AUTHENTIK_ISSUER",
        },
        CapabilityRow {
            name: "OAuth consent store",
            enabled: state.identity.consent.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Governed catalog",
            enabled: state.servers.catalog.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Policy bundle store",
            enabled: state.policy.policy_store.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Evidence routing",
            enabled: state.observability.routing.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Evidence retention",
            enabled: state.observability.retention.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Evidence sweeper",
            enabled: state.observability.sweeper.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Evidence bundle signer",
            enabled: state.observability.bundle_signer.enabled(),
            env_hint: "GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM",
        },
        CapabilityRow {
            name: "SCIM Users",
            enabled: state.identity.scim_users.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "SCIM Groups",
            enabled: state.identity.scim_groups.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "RBAC store",
            enabled: state.identity.rbac.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Tenants registry",
            enabled: state.identity.tenants.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Rate-limit policies",
            enabled: state.policy.rate_limit_policies.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "API-key profiles",
            enabled: state.identity.api_key_profiles.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Break-glass override",
            enabled: state.policy.break_glass.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
        CapabilityRow {
            name: "Federated peers",
            enabled: state.federation.federated_peers.enabled(),
            env_hint: "GATEWAY_DATABASE_URL",
        },
    ]
}

/// Template helpers exposed via the page struct's fields.
/// Askama needs accessor methods to drive `{% if %}` branches
/// on `Option<&JwksSummary>` and `Option<&IntrospectionSummary>`;
/// kept here so the template stays markup-only.
impl SettingsPage {
    fn jwks(&self) -> Option<&JwksSummary> {
        self.system.jwks.as_ref()
    }
    fn introspection(&self) -> Option<&IntrospectionSummary> {
        self.system.introspection.as_ref()
    }
    fn identity_token_ttl_secs(&self) -> Option<u64> {
        self.system.identity_token_ttl_secs
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
    fn settings_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn settings_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn settings_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn settings_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn global_settings_refuse_tenant_local_administrators() {
        let mut principal = principal_with(vec!["mcp:admin"], AuthMethod::Oauth);
        assert!(require_global_settings_admin(Some(&principal), None).is_ok());
        principal.tenant = waygate_core::TenantId::parse("other").unwrap();
        assert!(require_global_settings_admin(Some(&principal), None).is_err());
        assert!(require_global_settings_admin(None, None).is_err());
        let peer = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(require_global_settings_admin(Some(&peer), None).is_err());
    }

    #[test]
    fn capabilities_grid_reflects_unwired_default_admin_state() {
        // A minimum AdminState wires only `upstreams` + the
        // default HITL hub; every Option<Store> field is None,
        // so every capability row except those that don't
        // appear in the grid should be `enabled = false`. This
        // also catches the case where a new field's row was
        // forgotten on the grid as we grow AdminState: the
        // length is a fixed contract test.
        let state = AdminState::new(
            std::sync::Arc::new(waygate_upstream::UpstreamPool::from_manifests_disconnected(
                std::collections::BTreeMap::new(),
            )),
            None,
            None,
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "https://example.test".into(),
        );
        let caps = build_capabilities(&state);
        assert!(
            !caps.is_empty(),
            "capability grid must surface at least one row",
        );
        assert!(
            caps.iter().all(|c| !c.enabled),
            "default AdminState wires no stores; every grid row should be disabled",
        );
    }

    #[test]
    fn unknown_system_info_has_no_jwks_or_introspection() {
        let info = SystemInfo::unknown();
        assert!(info.jwks.is_none());
        assert!(info.introspection.is_none());
        assert!(info.identity_token_ttl_secs.is_none());
    }

    /// Truth table for the introspection-active predicate.
    /// Pins the four-case behavior so a future env-surface
    /// refactor that drifts the rule away from
    /// `waygate-server::build_oidc_chain` breaks here loudly.
    #[test]
    fn introspection_active_matches_bearer_chain_truth_table() {
        // 1. legacy mode (AS off): validator wires whenever
        //    the env triple is set; the upstream-tokens flag
        //    is irrelevant because there's no AS to bypass.
        assert!(super::introspection_active(false, false));
        assert!(super::introspection_active(false, true));
        // 2. AS mode + upstream-tokens passthrough explicitly
        //    enabled: validator wires (operator opted in to
        //    the deprecated combo).
        assert!(super::introspection_active(true, true));
        // 3. AS mode + passthrough off: validator is GATED
        //    OFF at boot — the env vars are configured but
        //    the bearer chain skips wiring to avoid the
        //    OAuth token-passthrough anti-pattern. This is
        //    the case the Settings page must surface as
        //    `configured but inactive`.
        assert!(!super::introspection_active(true, false));
    }
}
