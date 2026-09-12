//! Cmd-K command palette — server-side search endpoint.
//!
//! The dashboard has 17 nav destinations; a sidebar nav doesn't scale
//! past 7-8 visible items, so `Cmd-K` / `Ctrl-K` opens a command
//! palette that lets operators navigate by typing instead of clicking
//! through a tree. This module is the JSON backend the palette
//! fetches from; the UI lives in `static/js/palette.js` + an overlay
//! in `layout.html`.
//!
//! ## Endpoint
//!
//! `GET /search?q=<query>` (mounted under the same prefixes as the
//! rest of the dashboard — `/admin/search` legacy, `/admin/t/{tenant}/search`
//! tenant-scoped). Returns `application/json`:
//!
//! ```json
//! {
//!   "query": "act",
//!   "items": [
//!     {"label": "Activity",
//!      "href": "/admin/t/acme/activity",
//!      "category": "page",
//!      "icon": "activity",
//!      "hint": "Audit log browser"}
//!   ]
//! }
//! ```
//!
//! ## What's searchable today
//!
//! 1. **Pages** — the same nav items the sidebar exposes. URLs are
//!    tenant-prefixed when a [`TenantContext`] is in scope, else
//!    legacy `/admin/...`.
//! 2. **Tenant switches** — when `state.identity.tenants` is wired, every
//!    tenant gets a "Switch to: <name>" entry routed through the
//!    server-side `/admin/tenant-switch` endpoint.
//! 3. **Per-server Tools jumps** — one `Tools: <server>` row per
//!    upstream manifest, navigating to the Tools console pre-filtered
//!    to that upstream (`/tools?server=<name>`). Read-only GET nav, so
//!    it honours the palette "rows must not mutate" contract.
//!
//! Per-page palette items (e.g. "Revoke API key alice-deploy") can be
//! added incrementally — the `SearchItem` shape is forward-compatible,
//! just append more producers to `collect_items`.
//!
//! ## Matching
//!
//! Case-insensitive substring on `label`. Empty `q` returns every
//! item (the palette renders the "nothing typed yet" state by
//! showing the full catalogue, capped). Cap at [`SEARCH_RESULT_CAP`]
//! results so a wide query doesn't ship a megabyte of JSON.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};

use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};

/// Maximum number of results returned in one search response. The
/// palette renders results in a small overlay; more than ~30 rows is
/// "use a more specific query" territory, not "scroll the dropdown."
pub const SEARCH_RESULT_CAP: usize = 30;

/// Maximum length of the `q` query string we accept. Anything larger
/// is almost certainly a bug / attack and would waste CPU on the
/// substring match. Refuse with 400.
const QUERY_MAX_LEN: usize = 256;

/// Query shape for the search endpoint.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

/// One row in the palette dropdown.
#[derive(Debug, Serialize)]
pub struct SearchItem {
    /// Visible row text (what matches the query).
    pub label: String,
    /// Target URL — either a page to navigate to or a form-action
    /// endpoint. The palette uses `window.location.href = item.href`
    /// for GETs; POST-actions aren't supported by this shape
    /// (intentional — keeps the palette read-only; tool-specific
    /// actions may land as a future producer).
    pub href: String,
    /// Logical bucket the row renders under. Drives the small
    /// badge next to the row. Known values: `"page"`, `"tenant"`,
    /// `"action"` — extend as new producers ship.
    pub category: String,
    /// Lucide icon name (matches the spritesheet under
    /// `static/lucide.svg`). The palette renders `<use href="#{icon}">`.
    pub icon: String,
    /// Optional secondary line. Today: a short description for
    /// pages, the slug for tenant switches. Hidden when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Full search response. Wrapped in a struct (not a bare array) so
/// future additions (e.g. `total_unfiltered`, `truncated: bool`)
/// don't break clients.
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub query: String,
    pub items: Vec<SearchItem>,
    /// `true` when more candidate items existed than the cap allowed.
    /// The palette renders a "type to narrow" hint when this is set.
    pub truncated: bool,
}

/// Build the `/search` router. Mounted by [`crate::dashboard::page_routes`]
/// so it inherits the same legacy + tenant-prefixed mount points the
/// rest of the dashboard pages get.
pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/search", get(search))
}

async fn search(
    State(state): State<Arc<AdminState>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<SearchQuery>,
) -> Response {
    if q.q.len() > QUERY_MAX_LEN {
        // 400 with a tiny JSON body so the palette JS can render a
        // sensible "query too long" message instead of unwrapping
        // text/plain.
        return (
            StatusCode::BAD_REQUEST,
            Json(SearchResponse {
                query: String::new(),
                items: Vec::new(),
                truncated: false,
            }),
        )
            .into_response();
    }

    let ctx = tenant_ctx.as_ref().map(|Extension(c)| c);
    let candidates = collect_items(&state, ctx).await;
    let needle = q.q.to_ascii_lowercase();
    let needle = needle.trim();

    let (items, truncated) = filter_and_cap(candidates, needle, SEARCH_RESULT_CAP);

    Json(SearchResponse {
        query: q.q,
        items,
        truncated,
    })
    .into_response()
}

/// Collect every palette-searchable item the dashboard currently
/// knows about. Pure (no DB I/O) for the page set; consults
/// `state.identity.tenants.list()` for the tenant-switch items.
async fn collect_items(state: &Arc<AdminState>, ctx: Option<&TenantContext>) -> Vec<SearchItem> {
    let mut out = Vec::new();

    // Pages — same set the sidebar renders.
    for (label, suffix, icon, hint) in PAGES {
        out.push(SearchItem {
            label: (*label).to_owned(),
            href: tenant_ctx::nav_url(ctx, suffix),
            category: "page".to_owned(),
            icon: (*icon).to_owned(),
            hint: Some((*hint).to_owned()),
        });
    }

    // Tenant switches — when a registry is wired. Each row routes
    // through the server-side `/admin/tenant-switch` endpoint so
    // the no-JS form fallback and the palette take the same path.
    if let Some(store) = state.identity.tenants.get() {
        if let Ok(rows) = store.list().await {
            for t in rows {
                out.push(SearchItem {
                    label: format!("Switch to tenant: {}", t.display_name),
                    href: format!("/admin/tenant-switch?tenant_slug={}", t.id),
                    category: "tenant".to_owned(),
                    icon: "users".to_owned(),
                    hint: Some(t.id),
                });
            }
        }
    }

    // Per-server jumps into the filtered Tools console. Read-only GET
    // navigation (honours the palette "rows must not mutate" contract — the
    // destination page does any acting); the free-string server name is
    // URL-encoded the same way the Servers drill-down and Activity facets are.
    let tools_base = tenant_ctx::nav_url(ctx, "/tools");
    for m in state.upstreams.manifests() {
        out.push(SearchItem {
            label: format!("Tools: {}", m.name),
            href: format!(
                "{}?server={}",
                tools_base,
                crate::dashboard::urlencode(&m.name)
            ),
            category: "action".to_owned(),
            icon: "box".to_owned(),
            hint: Some(format!("Filter the tool catalog to {}", m.name)),
        });
    }

    out
}

/// The page catalogue. Same shape as `dashboard::nav` items plus a
/// `hint` second line.
const PAGES: &[(&str, &str, &str, &str)] = &[
    (
        "Skills",
        "/skills",
        "file-text",
        "Browse workflows and review changed content",
    ),
    ("Overview", "/", "home", "Gateway health + recent activity"),
    (
        "Connect",
        "/connect",
        "server",
        "Connect an MCP client to the gateway",
    ),
    (
        "Servers",
        "/servers",
        "server",
        "Upstream MCP server inventory",
    ),
    (
        "Tools",
        "/tools",
        "box",
        "Catalog of tools across upstreams",
    ),
    (
        "Policies",
        "/policies",
        "shield-check",
        "Active Cedar policies + simulator",
    ),
    (
        "Decision Log",
        "/decisions-log",
        "file-text",
        "Authorization decisions — filter by policy id (decisions that matched a policy)",
    ),
    (
        "API keys",
        "/identities",
        "users",
        "Static API keys — inventory + mint",
    ),
    (
        "Sessions",
        "/sessions",
        "users",
        "Live OAuth sessions — inventory + revoke",
    ),
    (
        "Profiles",
        "/profiles",
        "box",
        "API-key profiles — the constraint envelopes a mint must satisfy",
    ),
    (
        "Federation",
        "/federation",
        "server",
        "Tier-C peer registry + JWKS cache state",
    ),
    (
        "Tenants",
        "/tenants",
        "users",
        "Canonical tenants registry (active / suspended)",
    ),
    (
        "Decisions",
        "/decisions",
        "inbox",
        "Merged queue: pending change requests + active break-glass",
    ),
    (
        "Approvals",
        "/approvals",
        "shield-check",
        "HITL approval grants (active / expired / closed)",
    ),
    (
        "Break-glass",
        "/break_glass",
        "alert-triangle",
        "Emergency override tokens (active / expired / used)",
    ),
    (
        "Rate limits",
        "/rate_limits",
        "activity",
        "Per-tenant token-bucket policies (scope / action / capacity)",
    ),
    (
        "Gateway Agents",
        "/agents",
        "box",
        "In-app LLM agents — model, tool allowlist, loop caps, enable",
    ),
    (
        "Policy bundles",
        "/policy_bundles",
        "shield-check",
        "Cedar policy bundle versions (draft / published / rolled_back)",
    ),
    (
        "Server manifests",
        "/server_manifests",
        "server",
        "servers/*.yaml version ledger — editor, versions, publish/rollback, YAML export",
    ),
    (
        "Playground",
        "/playground",
        "shield-check",
        "Interactive Cedar policy simulator — dry-run a verdict + reasons",
    ),
    (
        "OAuth consent",
        "/oauth_consent",
        "shield-check",
        "Per-(principal, client) OAuth consent grants (active / expired / revoked)",
    ),
    (
        "Users",
        "/scim",
        "users",
        "SCIM-provisioned user directory (IdP-managed)",
    ),
    (
        "Roles",
        "/rbac",
        "shield-check",
        "Roles, assignments, and SCIM group → role mappings",
    ),
    (
        "Groups",
        "/groups",
        "users",
        "Unified group catalog — SCIM-provisioned + local (api-key label) groups",
    ),
    (
        "Scopes",
        "/scopes",
        "key",
        "Scope registry — built-in, policy-referenced, and local capability scopes",
    ),
    (
        "Catalog",
        "/catalog",
        "box",
        "Governed catalog — servers registry + recent drift events",
    ),
    (
        "LLM Models",
        "/llm_models",
        "box",
        "Configured inference models — provider, routing, pricing",
    ),
    (
        "LLM Credentials",
        "/llm_credentials",
        "shield-check",
        "LLM provider credential pool health",
    ),
    ("Activity", "/activity", "activity", "Audit log browser"),
    (
        "Evidence pipeline",
        "/evidence",
        "shield-check",
        "Evidence pipeline — routing / retention / bundle / chain integrity",
    ),
    (
        "Settings",
        "/settings",
        "settings",
        "Gateway runtime configuration",
    ),
];

/// Case-insensitive substring filter, capped at `cap` results.
/// Returns `(items, truncated)` where `truncated = true` when the
/// raw match count exceeded `cap`. Empty needle returns every
/// candidate up to the cap (palette renders this as the "nothing
/// typed yet" catalogue view).
fn filter_and_cap(
    candidates: Vec<SearchItem>,
    needle: &str,
    cap: usize,
) -> (Vec<SearchItem>, bool) {
    let matched: Vec<SearchItem> = if needle.is_empty() {
        candidates
    } else {
        candidates
            .into_iter()
            .filter(|i| i.label.to_ascii_lowercase().contains(needle))
            .collect()
    };
    let total = matched.len();
    let truncated = total > cap;
    let items: Vec<SearchItem> = matched.into_iter().take(cap).collect();
    (items, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_item(label: &str) -> SearchItem {
        SearchItem {
            label: label.to_owned(),
            href: format!("/admin{}", label.to_lowercase()),
            category: "page".to_owned(),
            icon: "home".to_owned(),
            hint: None,
        }
    }

    #[test]
    fn empty_query_returns_full_catalogue_up_to_cap() {
        let candidates = vec![page_item("Overview"), page_item("Activity")];
        let (items, truncated) = filter_and_cap(candidates, "", 10);
        assert_eq!(items.len(), 2);
        assert!(!truncated);
    }

    #[test]
    fn substring_match_is_case_insensitive() {
        let candidates = vec![page_item("Overview"), page_item("Activity")];
        let (items, truncated) = filter_and_cap(candidates, "act", 10);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "Activity");
        assert!(!truncated);
    }

    #[test]
    fn no_match_returns_empty_not_truncated() {
        let candidates = vec![page_item("Overview"), page_item("Activity")];
        let (items, truncated) = filter_and_cap(candidates, "zzz", 10);
        assert!(items.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn cap_truncates_and_signals_truncated_flag() {
        let candidates: Vec<SearchItem> =
            (0..50).map(|i| page_item(&format!("Page{i:02}"))).collect();
        let (items, truncated) = filter_and_cap(candidates, "page", 30);
        assert_eq!(items.len(), 30);
        assert!(truncated);
    }

    #[test]
    fn cap_at_exact_match_count_is_not_truncated() {
        let candidates: Vec<SearchItem> = (0..30).map(|i| page_item(&format!("P{i}"))).collect();
        let (items, truncated) = filter_and_cap(candidates, "p", 30);
        assert_eq!(items.len(), 30);
        assert!(
            !truncated,
            "truncated should be false when match count == cap",
        );
    }
}
