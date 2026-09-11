//! Decision Log pane — `/admin/t/{tenant}/decisions-log`.
//!
//! The server-rendered UI for the Decision Log: the tenant's recent
//! authorization DECISIONS (tool-call `invocation` + model `llm_completion`
//! rows), newest-first, with the `?policy_id=` reverse lookup as the signature
//! feature — "decisions that matched THIS policy", cross-linked from the
//! Policies pane.
//!
//! ## Why a server-rendered pane, not a REST consumer
//!
//! Like the Activity feed, this calls `state.observability.audit` **directly** and renders
//! askama, rather than fetching the `/api/v1/audit/decisions` JSON from the
//! browser. The page and the REST endpoint share the decision filter through
//! one constructor — [`crate::audit::decision_store_query`] — so "what is a
//! decision query" (the category set, the `pre_call` exclusion, and the tenant
//! scope) lives in exactly one place and can't drift between the two surfaces.
//! htmx is used only for the "Load more" cursor pagination, mirroring the
//! Activity `/activity/rows` fragment.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`, never `tenant_ctx.slug` — the same SECURITY
//! boundary the Activity feed and `list_decisions` enforce. A decision query
//! can never read another tenant's audit history; a gateway-admin operator on
//! `/admin/t/acme/decisions-log` sees their own tenant's decisions and the red
//! cross-tenant banner naming acme, the posture every dashboard page takes.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;

use waygate_oidc::Principal;
use waygate_storage::AuditRow;

use crate::audit::decision_store_query;
use crate::chrome::PageChrome;
use crate::dashboard::{
    format_ts_abs, format_ts_rel, principal_label, render, urlencode, user_display,
};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

/// Page size for the decision list and the "Load more" cursor — matches the
/// Activity feed's page so the two panes paginate at the same cadence.
const PAGE_LIMIT: i64 = 50;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/decisions-log", get(decisions_log_page))
        .route("/decisions-log/rows", get(decisions_log_rows))
}

/// Filter bar + cursor for the Decision Log. Mirrors the REST `DecisionQuery`
/// facets (policy_id / outcome / server / principal) so the page and the API
/// filter on the same dimensions; the page is a browser, not an API, so it
/// parses leniently and never 400s on a stray value.
#[derive(Debug, Default, Deserialize)]
struct DecisionLogFilters {
    /// Reverse lookup: only decisions whose fired-policy set includes this
    /// stable policy `@id` (powers "decisions that matched this policy"). This
    /// is what the Policies pane "View recent decisions" link sets.
    #[serde(default)]
    policy_id: Option<String>,
    /// Exact match on the stored `outcome` string (lower/snake-case:
    /// `success` / `denied` / `step_up_required` / `execution_error`).
    #[serde(default)]
    outcome: Option<String>,
    /// Exact match on `server`.
    #[serde(default)]
    server: Option<String>,
    /// Case-sensitive substring match on principal sub/email.
    #[serde(default)]
    principal: Option<String>,
    /// htmx "Load more" keyset cursor — the id of the last row already shown.
    #[serde(default)]
    after_id: Option<Uuid>,
}

impl DecisionLogFilters {
    /// Trim empties to `None` so a blank form field imposes no constraint and
    /// the active-filter rendering / query suffix never carry an empty value.
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
            policy_id: norm(self.policy_id),
            outcome: norm(self.outcome),
            server: norm(self.server),
            principal: norm(self.principal),
            after_id: self.after_id,
        }
    }

    /// URL-encoded query-string fragment (each clause starts with `&`) carrying
    /// only the active facet filters — appended to the "Load more" fragment URL
    /// so pagination preserves the operator's filter scope. `after_id` is NOT
    /// included; the load-more button supplies its own cursor.
    fn to_query_suffix(&self) -> String {
        let mut s = String::new();
        if let Some(v) = &self.policy_id {
            s.push_str(&format!("&policy_id={}", urlencode(v)));
        }
        if let Some(v) = &self.outcome {
            s.push_str(&format!("&outcome={}", urlencode(v)));
        }
        if let Some(v) = &self.server {
            s.push_str(&format!("&server={}", urlencode(v)));
        }
        if let Some(v) = &self.principal {
            s.push_str(&format!("&principal={}", urlencode(v)));
        }
        s
    }
}

/// One decision row, projected for the template. Mirrors the Activity feed's
/// `ActivityEventView` shape, trimmed to the decision columns plus the
/// `policy_ids` set (rendered as cross-link chips to the Policies pane).
struct DecisionRow {
    ts_abs: String,
    ts_rel: String,
    principal: String,
    server: Option<String>,
    tool: Option<String>,
    /// What the decision acted on when it was not a tool — a native resource
    /// decision names a URI and no tool. Without it such a row shows at most an
    /// upstream, and a read nothing served shows no subject at all, so the log
    /// would say a resource read was decided without saying which resource.
    target: Option<String>,
    /// The operation the call selected. Two decisions on the same executor are
    /// otherwise indistinguishable in this log even when they authorized
    /// differently.
    operation: Option<String>,
    outcome: String,
    risk: Option<String>,
    /// Fired-policy ids, each rendered as a chip that links to the Policies
    /// pane anchored at `#policy-<id>` (matching `templates/policies.html`'s
    /// `id="policy-{{ p.id }}"`). A Cedar policy `@id` is a slug
    /// (`permit-mcp-users`, `step-up-delete-dataset`), so the raw value is also a
    /// safe URL fragment — no separate encoding is needed for the anchor.
    policies: Vec<String>,
}

#[derive(Template)]
#[template(path = "decisions_log.html")]
struct DecisionsLogPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `false` when `state.observability.audit` is unwired (no DB) — the template renders the
    /// same "audit store not configured" empty state the Activity feed uses.
    audit_available: bool,
    /// Active reverse-lookup id, if any — drives the prominent banner.
    policy_id: Option<String>,
    /// Echoed filter values for the GET filter bar's sticky inputs.
    outcome: Option<String>,
    server: Option<String>,
    principal: Option<String>,
    rows: Vec<DecisionRow>,
    /// Keyset cursor for the htmx "Load more" button; `None` when the last
    /// page didn't fill the limit (nothing more to fetch).
    next_after_id: Option<Uuid>,
    /// Active-filter query suffix threaded into the load-more URL.
    filter_qs: String,
    /// Closing-time line for the financial-statement table foot ("as of …Z").
    as_of: String,
}

impl DecisionsLogPage {
    /// Include-context delegate: the shared partial this page includes calls
    /// `self.nav_url(...)`, which must resolve on the page struct too. Pure
    /// forward to [`crate::chrome::PageChrome::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        self.chrome.nav_url(path)
    }
}

#[derive(Template)]
#[template(path = "decisions_log_rows.html")]
struct DecisionsLogRows {
    /// Carried so the "Load more" link inside the fragment stays inside the
    /// active tenant prefix (mirrors `ActivityRows.tenant_ctx`).
    tenant_ctx: Option<TenantContext>,
    rows: Vec<DecisionRow>,
    next_after_id: Option<Uuid>,
    filter_qs: String,
}

impl DecisionsLogRows {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// `GET /decisions-log` — the Decision Log page (filter bar + table).
async fn decisions_log_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<DecisionLogFilters>,
) -> Response {
    let filters = q.cleaned();
    let user_principal = user.as_ref().map(|Extension(p)| p);
    // Tenant is the PRINCIPAL's, never tenant_ctx (the same security boundary
    // `list_decisions` / the Activity feed enforce).
    let tenant = principal_tenant(user_principal);

    let (rows, next_after_id) = fetch_decision_rows(&state, &filters, tenant).await;
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);

    render(&DecisionsLogPage {
        chrome: PageChrome::build(
            &state,
            "Decision Log",
            "/decisions-log",
            &headers,
            user_principal.map(user_display),
            tenant_ctx,
            String::new(),
        ),
        audit_available: state.observability.audit.enabled(),
        policy_id: filters.policy_id.clone(),
        outcome: filters.outcome.clone(),
        server: filters.server.clone(),
        principal: filters.principal.clone(),
        rows,
        next_after_id,
        filter_qs: filters.to_query_suffix(),
        as_of: format_ts_abs(time::OffsetDateTime::now_utc()),
    })
}

/// `GET /decisions-log/rows` — htmx "Load more" fragment. Same filters + the
/// `after_id` cursor; returns the next page of `<tr>` rows plus a fresh
/// load-more button, mirroring `/activity/rows`.
async fn decisions_log_rows(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<DecisionLogFilters>,
) -> Response {
    let filters = q.cleaned();
    // Tenant-scope the fragment too — it's reachable directly, not only via the
    // parent page (mirrors `activity_rows`).
    let tenant = principal_tenant(user.as_ref().map(|Extension(p)| p));
    let (rows, next_after_id) = fetch_decision_rows(&state, &filters, tenant).await;
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    render(&DecisionsLogRows {
        tenant_ctx,
        rows,
        next_after_id,
        filter_qs: filters.to_query_suffix(),
    })
}

/// Fetch one filtered, keyset-paginated page of decision rows for `tenant`.
/// Builds the query via the shared [`decision_store_query`] (so the page and
/// the REST endpoint apply an identical decision filter) and projects to the
/// template view. An unwired audit store yields an empty page (the template
/// renders the "not configured" state from `audit_available`).
async fn fetch_decision_rows(
    state: &AdminState,
    filters: &DecisionLogFilters,
    tenant: &str,
) -> (Vec<DecisionRow>, Option<Uuid>) {
    let Some(reader) = state.observability.audit.get() else {
        return (Vec::new(), None);
    };
    let query = decision_store_query(
        tenant,
        filters.policy_id.clone(),
        filters.outcome.clone(),
        filters.server.clone(),
        filters.principal.clone(),
    );
    let rows = reader
        .query_events(&query, PAGE_LIMIT, filters.after_id)
        .await
        .unwrap_or_default();
    // Hand back the next cursor only when we filled the page — otherwise there's
    // nothing more to fetch (mirrors `fetch_activity_rows` / `list_decisions`).
    let next_after_id = if rows.len() as i64 >= PAGE_LIMIT {
        rows.last().map(|r| r.id)
    } else {
        None
    };
    (rows.iter().map(project_decision).collect(), next_after_id)
}

/// Project one fetched `AuditRow` into the template's [`DecisionRow`] shape.
/// Rows arrive already filtered by `query_events`, so this is a pure map.
fn project_decision(r: &AuditRow) -> DecisionRow {
    DecisionRow {
        ts_abs: format_ts_abs(r.ts),
        ts_rel: format_ts_rel(r.ts),
        principal: principal_label(r),
        server: r.server.clone(),
        tool: r.tool.clone(),
        target: r.target.clone(),
        operation: r.operation.clone(),
        outcome: r.outcome.clone(),
        risk: r.risk_level.clone(),
        policies: r.policy_ids.clone(),
    }
}

/// The principal's tenant (the read-scope security key), falling back to the
/// default tenant for anonymous / auth-disabled dev requests — same rule the
/// Activity feed's `principal_tenant` applies.
fn principal_tenant(user: Option<&Principal>) -> &str {
    user.map(|p| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT)
}
