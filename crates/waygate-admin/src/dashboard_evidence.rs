//! Evidence page — `/admin/t/{tenant}/evidence`.
//!
//! Read-only operator view of the per-tenant evidence
//! configuration + posture. Five sections, mirroring the
//! compliance-grade evidence pipeline:
//!
//! 1. **Routing** (Configure) — per-tenant exporter fan-out
//!    rows from `tenant_evidence_routing`
//!    (`waygate_storage::routing::RoutingStore`). Each row:
//!    exporter name + enabled flag + last-updated.
//! 2. **Retention** (Configure) — per-tenant per-category
//!    `delete_after_days` from `evidence_retention_policy`
//!    (`waygate_storage::retention::RetentionStore`).
//! 3. **Inspection rules** (Configure) — DLP / redaction rules
//!    from `inspection_rules`
//!    (`waygate_dashboard_stores::inspection_rules::InspectionRulesStore`):
//!    inspector kind, name, enabled, applies-to summary.
//! 4. **Bundle** (Operate) — signed-`.jsonl` export. The page
//!    surfaces whether the bundle signer is configured and
//!    points at the REST endpoint; the actual time-range +
//!    scope-filter export form is a mutation surface and stays
//!    at `POST /api/v1/audit/bundle`.
//! 5. **Chain integrity** (Monitor) — the required-write
//!    tamper-evidence hash chain. Best-effort audit rows are
//!    unchained and outside the verifier's coverage. The verify
//!    is an on-demand (potentially expensive) walk via
//!    `GET /api/v1/audit/verify`; the page documents it and links
//!    out rather than running it on every page load. A live
//!    "Verify now" button + last-result panel is not yet
//!    implemented.
//!
//! ## What's NOT here (deferred, intentional)
//!
//! - **Mutations.** Routing/retention/inspection-rule CRUD,
//!   bundle export, and chain verification stay at the REST
//!   surface (`/api/v1/audit/*`, `/api/v1/admin/inspection_rules/*`).
//!   Same read-only posture every other dashboard page holds.
//! - **Live chain verify on load + per-marker breakdown** —
//!   deferred, alongside the "Verify now" button. A full chain
//!   walk on every page render would be an unbounded scan.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`. Routing, retention, and
//! inspection-rule fetches are all strictly per-tenant.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin`. A dashboard
//! session without `mcp:admin` (or a peer-asserted principal)
//! sees the insufficient-scope card; every store fetch is
//! skipped so no exporter destinations, retention windows, or
//! inspection-rule patterns enter the rendered HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_dashboard_stores::inspection_rules::{InspectionRule, RuleFilter};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_storage::retention::RetentionPolicy;
use waygate_storage::routing::RoutingRow;

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::format_ts_abs;

/// Per-fetch row cap for the inspection-rules table. The store
/// orders by `created_at DESC` so the slice is the most-recent
/// N. 200 is plenty for a tenant's DLP ruleset; the REST
/// surface gives the paginated list.
const INSPECTION_FETCH_LIMIT: u32 = 200;

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

    inspection_configured: bool,
    inspection_rules: Vec<InspectionRuleView>,
    /// `true` when the inspection slice hit
    /// [`INSPECTION_FETCH_LIMIT`]; template renders a
    /// "showing first N" hint nudging toward the REST surface.
    inspection_truncated: bool,
    inspection_load_error: bool,

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

struct InspectionRuleView {
    inspector: &'static str,
    name: String,
    enabled: bool,
    /// Compact one-line summary of the `applies_to` selector
    /// (`{}` ⇒ "any tool, any principal").
    applies_to_summary: String,
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
        inspection_configured: load.inspection_configured,
        inspection_rules: load.inspection_rules,
        inspection_truncated: load.inspection_truncated,
        inspection_load_error: load.inspection_load_error,
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
    inspection_configured: bool,
    inspection_rules: Vec<InspectionRuleView>,
    inspection_truncated: bool,
    inspection_load_error: bool,
    bundle_signer_configured: bool,
}

async fn load_evidence(state: &AdminState, tenant: &str) -> LoadResult {
    let mut out = LoadResult::default();

    // Three independent per-section fetches. A failure on one
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

    if let Some(store) = state.policy.inspection_rules.get() {
        out.inspection_configured = true;
        match store
            .list(tenant, RuleFilter::default(), INSPECTION_FETCH_LIMIT, 0)
            .await
        {
            Ok(rows) => {
                out.inspection_truncated = rows.len() as u32 >= INSPECTION_FETCH_LIMIT;
                out.inspection_rules = rows.into_iter().map(inspection_row).collect();
            }
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "evidence page: inspection list failed");
                out.inspection_load_error = true;
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

fn inspection_row(r: InspectionRule) -> InspectionRuleView {
    InspectionRuleView {
        inspector: r.inspector.as_str(),
        name: r.name,
        enabled: r.enabled,
        applies_to_summary: applies_to_summary(&r.applies_to),
    }
}

/// Compact one-line summary of an inspection rule's `applies_to`
/// selector. Empty object (`{}`) ⇒ "any tool, any principal".
fn applies_to_summary(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) if m.is_empty() => "any tool, any principal".to_owned(),
        serde_json::Value::Null => "any tool, any principal".to_owned(),
        other => {
            let s = other.to_string();
            // Char-safe truncation: `applies_to` is arbitrary
            // operator-supplied JSON (serde_json::Value from the
            // admin API), so a byte-index slice (`&s[..80]`) would
            // panic on a multi-byte UTF-8 code point straddling
            // byte 80. Take 80 *chars* instead.
            if s.chars().count() > 80 {
                let truncated: String = s.chars().take(80).collect();
                format!("{truncated}…")
            } else {
                s
            }
        }
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

    #[test]
    fn applies_to_summary_empty_object_is_any() {
        let v = serde_json::json!({});
        assert_eq!(applies_to_summary(&v), "any tool, any principal");
    }

    #[test]
    fn applies_to_summary_null_is_any() {
        assert_eq!(
            applies_to_summary(&serde_json::Value::Null),
            "any tool, any principal"
        );
    }

    #[test]
    fn applies_to_summary_renders_selector() {
        let v = serde_json::json!({"tools": ["example-messages.send"]});
        let s = applies_to_summary(&v);
        assert!(
            s.contains("example-messages.send"),
            "selector must surface: {s}"
        );
    }

    #[test]
    fn applies_to_summary_multibyte_truncation_does_not_panic() {
        // applies_to is arbitrary operator JSON, so the truncation
        // must be char-safe — a byte-index slice (`&s[..80]`) panics
        // when a multi-byte UTF-8 code point straddles byte 80.
        // Build a selector whose
        // serialized form is well over 80 chars and whose ~80th
        // char is multi-byte; the call must return a truncated
        // string with the ellipsis instead of panicking.
        let long_value = "é".repeat(200); // each char is 2 bytes
        let v = serde_json::json!({ "principals": [long_value] });
        let s = applies_to_summary(&v); // must not panic
        assert!(s.ends_with('…'), "long selector must be truncated: {s}");
        assert!(
            s.chars().count() <= 81,
            "truncated to 80 chars + ellipsis, got {} chars",
            s.chars().count(),
        );
    }
}
