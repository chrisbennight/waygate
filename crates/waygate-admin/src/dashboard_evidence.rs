//! Tenant-scoped evidence routing, retention, bundle export, and chain verification.
//! Store reads require an administrator and remain independent so one failed
//! section does not hide the others.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_storage::retention::RetentionPolicy;
use waygate_storage::routing::RoutingRow;

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "evidence.html")]
struct EvidencePage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS every store fetch.
    insufficient_scope: bool,

    /// `true` when the routing store is wired. `false` ⇒ the
    /// Routing section renders the "not configured" card.
    routing_configured: bool,
    routing: Vec<RoutingRowView>,
    /// `true` when the routing fetch errored. Renders a per-section
    /// error card instead of the empty state, so a store failure
    /// isn't mistaken for "nothing configured".
    routing_load_error: bool,

    retention_configured: bool,
    retention: Vec<RetentionRowView>,
    retention_load_error: bool,

    /// `true` when the bundle signer is configured
    /// (`GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM` + optional
    /// `_ID`). Drives whether the Bundle section shows "export
    /// available" vs a "signer not configured" note.
    bundle_signer_configured: bool,
}

struct RoutingRowView {
    exporter_name: String,
    enabled: bool,
    updated_at_abs: String,
}

struct RetentionRowView {
    /// `'*'` wildcard or an `EvidenceCategory.as_str()` value.
    category: String,
    delete_after_days: i32,
    updated_at_abs: String,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/evidence", get(evidence_page))
}

async fn evidence_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);

    let load = if insufficient_scope {
        // Skip every store read — no evidence config leaks into
        // the rendered HTML.
        LoadResult::default()
    } else {
        load_evidence(&state, &read_tenant).await
    };

    let page = EvidencePage {
        chrome: PageChrome::build(
            &state,
            "Evidence pipeline",
            "/evidence",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        insufficient_scope,
        routing_configured: load.routing_configured,
        routing: load.routing,
        routing_load_error: load.routing_load_error,
        retention_configured: load.retention_configured,
        retention: load.retention,
        retention_load_error: load.retention_load_error,
        bundle_signer_configured: load.bundle_signer_configured,
    };
    render(&page)
}

/// Authorization gate for the evidence dashboard page. Same
/// shape as `dashboard_catalog::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    routing_configured: bool,
    routing: Vec<RoutingRowView>,
    routing_load_error: bool,
    retention_configured: bool,
    retention: Vec<RetentionRowView>,
    retention_load_error: bool,
    bundle_signer_configured: bool,
}

async fn load_evidence(state: &AdminState, tenant: &str) -> LoadResult {
    let mut out = LoadResult::default();

    // Independent per-section fetches. A failure on one
    // renders that section's error card; the others keep their
    // data. No section is load-bearing for the page.
    if let Some(store) = state.observability.routing.get() {
        out.routing_configured = true;
        match store.list(Some(tenant)).await {
            Ok(rows) => out.routing = rows.into_iter().map(routing_row).collect(),
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "evidence page: routing list failed");
                out.routing_load_error = true;
            }
        }
    }

    if let Some(store) = state.observability.retention.get() {
        out.retention_configured = true;
        match store.list(Some(tenant)).await {
            Ok(rows) => out.retention = rows.into_iter().map(retention_row).collect(),
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "evidence page: retention list failed");
                out.retention_load_error = true;
            }
        }
    }

    out.bundle_signer_configured = state.observability.bundle_signer.enabled();
    out
}

fn routing_row(r: RoutingRow) -> RoutingRowView {
    RoutingRowView {
        exporter_name: r.exporter_name,
        enabled: r.enabled,
        updated_at_abs: format_ts_abs(r.updated_at),
    }
}

fn retention_row(r: RetentionPolicy) -> RetentionRowView {
    RetentionRowView {
        category: r.category,
        delete_after_days: r.delete_after_days,
        updated_at_abs: format_ts_abs(r.updated_at),
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
    fn evidence_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn evidence_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn evidence_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn evidence_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }
}
