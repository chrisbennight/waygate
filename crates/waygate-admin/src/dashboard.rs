//! Server-rendered admin dashboard (`/admin/*`).
//!
//! The dashboard talks directly to [`AdminState`] rather than re-issuing REST
//! calls to `/api/v1`. Going through the REST layer would double the work
//! (JSON round-trip, scope middleware, error-mapping) for zero gain — both
//! layers share the same state and error model. The REST surface stays the
//! scriptable contract; the dashboard is its HTML twin.
//!
//! Templates live under `crates/waygate-admin/templates/`; static assets
//! (CSS, theme script, Lucide sprite, htmx) under `crates/waygate-admin/static/`,
//! served by tower-http's [`ServeDir`]. Asset references in templates use
//! absolute `/admin/static/...` paths so htmx partial swaps — which don't
//! re-render the layout — can't break them.
//!
//! Auth: this router is **not** wrapped in bearer middleware. Punch-list
//! item #51 adds PKCE + encrypted session cookie as an outer layer. Until
//! then the gateway logs a loud warning at startup and the route is
//! effectively dev-only.

use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use waygate_mcp::catalog::UpstreamCatalog;
use waygate_mcp::protocol::RiskTier;
use waygate_oidc::Principal;
use waygate_storage::AuditRow;
use waygate_upstream::Transport;

use crate::auth::CsrfToken;
use crate::state::AdminState;
use crate::tenant_ctx::{tenant_scope_middleware, tenant_switch_get, TenantContext};
pub(crate) use waygate_core::fmt::{format_ts_abs, format_ts_rel};

// The six legacy pages live in sibling routers, matching the
// dashboard_*.rs pattern. The routing block below is unchanged;
// these private globs keep the handler names resolving.
pub(crate) use crate::dashboard_activity_page::*;
pub(crate) use crate::dashboard_connect::*;
pub(crate) use crate::dashboard_overview::*;
pub(crate) use crate::dashboard_policies::*;
pub(crate) use crate::dashboard_servers::*;
pub(crate) use crate::dashboard_tools::*;

/// Display name for the top bar: `email` if present, else `sub`.
pub(crate) fn user_display(p: &Principal) -> String {
    p.email.clone().unwrap_or_else(|| p.sub.clone())
}

/// Default page size for audit-table fetches. 50 matches the REST API
/// default in [`crate::audit`] so the two surfaces stay in lock-step.
pub(crate) const PAGE_LIMIT: i64 = 50;

/// Cap on "recent notable events" shown on the overview tile table. Small on
/// purpose — the full list lives under `/admin/activity`.
pub(crate) const NOTABLE_LIMIT: usize = 10;

// ---- sidebar nav ----------------------------------------------------------

/// One second-level page (a tab) inside a destination, rendered as an
/// underline tab bar at the top of the destination's pages.
///
/// `href` is owned (`String`) rather than `&'static str` so the same nav
/// helper can return both the legacy un-prefixed paths (e.g. `/admin/`)
/// AND the tenant-scoped paths (e.g. `/admin/t/acme/`) by composing the
/// prefix at call time from a [`TenantContext`].
#[derive(Debug, Clone)]
pub struct NavItem {
    pub label: &'static str,
    pub href: String,
    pub icon: &'static str,
    pub active: bool,
}

/// A task-oriented sidebar destination with second-level page tabs.
/// Destinations are grouped under Common, MCP Gateway, and LLM Gateway through
/// [`Self::section_header`]. Each has a distinct icon; the command palette
/// indexes every page directly. [`crate::chrome::PageChrome`] owns the navigation.
#[derive(Debug, Clone)]
pub struct NavGroup {
    pub label: &'static str,
    /// The destination's default page (where the sidebar link goes).
    pub href: String,
    pub icon: &'static str,
    /// True when any member page is the active one — drives both the
    /// sidebar highlight and which destination's tab bar renders.
    pub active: bool,
    /// The member pages, in tab order. Single-page destinations carry
    /// one entry; the layout only renders a tab bar for 2+.
    pub items: Vec<NavItem>,
    /// `Some(url)` on the Decisions destination: the endpoint
    /// `static/js/badge.js` fetches the pending-count from (30s
    /// server-side TTL cache; renders nothing when 0 / on error).
    pub badge_href: Option<String>,
    /// `Some(label)` on the FIRST destination of each sidebar section
    /// (Common / MCP Gateway / LLM Gateway); `None` on every other
    /// destination. Drives the section-header row the layout renders
    /// above the group. Computed in [`nav`] as "first occurrence of this
    /// section in render order", so the bottom-pinned Settings entry
    /// (section Common, but not the first Common destination) gets `None`
    /// and never emits a duplicate header at the foot of the sidebar.
    pub section_header: Option<&'static str>,
}

/// A tab definition: `(label, suffix)`.
type TabDef = (&'static str, &'static str);

/// A destination definition: `(section, label, default suffix, icon, tabs)`.
/// `section` is the sidebar group header the destination sits under
/// (Common / MCP Gateway / LLM Gateway). An empty tab list means the
/// destination IS its single page.
type DestDef = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [TabDef],
);

/// The sidebar, in render order, grouped into three sections (Common /
/// MCP Gateway / LLM Gateway). Sections are rendered as muted header rows
/// above the first destination of each group; depth still lives in the
/// per-destination tab bar, so the sidebar stays a short, scannable list.
/// Use distinct icons for destinations and tabs for their second-level pages.
///
/// Bucketing: **Common** holds the cross-cutting governance that applies
/// to both backends (audit, access, policy/guardrails, HITL decisions);
/// **MCP Gateway** holds MCP-specific resources (upstream servers, the
/// tool catalog, Tier-C federation, MCP-client connect); **LLM Gateway**
/// holds the provider-facing resources (models, credential pool). Settings
/// stays section Common but is pinned to the foot (see `section_header`).
const DESTINATIONS: &[DestDef] = &[
    // --- Common: cross-cutting governance for both MCP and LLM traffic ---
    ("Common", "Overview", "/", "home", &[]),
    (
        "Common",
        "Activity",
        "/activity",
        "activity",
        &[
            ("Activity", "/activity"),
            ("Evidence pipeline", "/evidence"),
        ],
    ),
    // The old single "Access" destination (which piled principals AND
    // the authz catalog onto one tab bar) splits into two — "Identities"
    // (the principals + their credentials/consent) and
    // "Access Control" (the authz catalog: users, groups, roles, scopes).
    // Acronym tabs become nouns: SCIM → Users, RBAC → Roles. URLs are
    // unchanged so bookmarks and the dual tenant mounts still resolve.
    (
        "Common",
        "Identities",
        "/identities",
        "users",
        &[
            // Sessions + Profiles are split off the API Keys page into
            // their own tabs; "Identities" tab → "API Keys" now that the
            // page is keys + mint only.
            ("API Keys", "/identities"),
            ("Sessions", "/sessions"),
            ("Profiles", "/profiles"),
            ("OAuth consent", "/oauth_consent"),
            ("Tenants", "/tenants"),
        ],
    ),
    (
        "Common",
        "Access Control",
        "/scim",
        "lock",
        &[
            ("Users", "/scim"),
            ("Groups", "/groups"),
            ("Roles", "/rbac"),
            ("Scopes", "/scopes"),
        ],
    ),
    (
        "Common",
        "Policy",
        "/policies",
        "shield-check",
        &[
            ("Policies", "/policies"),
            ("Bundles", "/policy_bundles"),
            ("Playground", "/playground"),
            ("Rate limits", "/rate_limits"),
        ],
    ),
    // The Decision Log — a server-rendered browser over the
    // tenant's authorization decisions (the audit-decision surface), with
    // the `?policy_id=` reverse lookup cross-linked from the Policy pane.
    // Single-page; sits next to Policy since it answers "what did this policy
    // decide?".
    ("Common", "Decision Log", "/decisions-log", "file-text", &[]),
    (
        "Common",
        "Decisions",
        "/decisions",
        "inbox",
        &[
            ("Queue", "/decisions"),
            ("Approvals", "/approvals"),
            ("Change requests", "/changes"),
            ("Break-glass", "/break_glass"),
        ],
    ),
    // --- MCP Gateway: MCP-specific resources ---
    (
        "MCP Gateway",
        "Servers",
        "/servers",
        "server",
        &[
            ("Servers", "/servers"),
            ("Built-ins", "/builtins"),
            ("Manifests", "/server_manifests"),
        ],
    ),
    (
        "MCP Gateway",
        "Tools",
        "/tools",
        "box",
        &[("Tools", "/tools"), ("Catalog", "/catalog")],
    ),
    ("MCP Gateway", "Skills", "/skills", "file-text", &[]),
    ("MCP Gateway", "Federation", "/federation", "network", &[]),
    ("MCP Gateway", "Connect", "/connect", "plug", &[]),
    // --- LLM Gateway: provider-facing resources ---
    ("LLM Gateway", "Models", "/llm_models", "cpu", &[]),
    ("LLM Gateway", "Credentials", "/llm_credentials", "key", &[]),
    ("LLM Gateway", "Chat", "/chat", "message-square", &[]),
    ("LLM Gateway", "Agents", "/agents", "box", &[]),
    // Contextual Assistant: the standalone "Agent Chat", "Policy Review",
    // and "Classification Audit" destinations are retired from the sidebar — the
    // docked assistant panel (present on every page) is the entry point now, and
    // the one-shot reviews ride in as suggested-action chips. Their routes stay
    // registered (`dashboard_agent_chat::router` / `agent_review::router`), so the
    // panel's chips and any existing bookmarks still reach the full immersive
    // views as deep-links; they're just no longer their own nav rows.
    ("LLM Gateway", "Embeddings", "/embeddings", "box", &[]),
    // --- Pinned to the foot (section Common; never emits a header) ---
    ("Common", "Settings", "/settings", "settings", &[]),
];

/// The human labels for a page suffix, resolved from [`DESTINATIONS`].
/// `section` / `dest` / `tab` widen from "which sidebar group" to "which
/// page" — e.g. `/server_manifests` → (`MCP Gateway`, `Servers`, `Manifests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PageLabel {
    pub section: &'static str,
    pub dest: &'static str,
    pub tab: &'static str,
}

/// Resolve a nav suffix (the page key the contextual assistant uses) to its
/// `(section, destination, tab)` labels from the single-source-of-truth
/// [`DESTINATIONS`] table. Returns `None` for a path that isn't a registered
/// destination/tab — the assistant still grounds such pages, just from the
/// raw path. Keeping this lookup here (next to `DESTINATIONS`) means a new
/// page added to the table is automatically grounded with no extra wiring.
pub(crate) fn page_label(suffix: &str) -> Option<PageLabel> {
    for d in DESTINATIONS {
        let (section, dest, default_suffix, tabs) = (d.0, d.1, d.2, d.4);
        // A multi-tab destination names its pages; a single-page destination
        // IS its page, so the tab label falls back to the destination label.
        if let Some((label, _)) = tabs.iter().find(|(_, s)| *s == suffix) {
            return Some(PageLabel {
                section,
                dest,
                tab: label,
            });
        }
        if default_suffix == suffix {
            return Some(PageLabel {
                section,
                dest,
                tab: dest,
            });
        }
    }
    None
}

/// Build the sidebar nav, optionally prefixed with the active tenant slug.
///
/// `active_suffix` is the un-prefixed page identifier (`"/"` for overview,
/// `"/servers"`, `"/policies"`, …). Pass the same value the page handler
/// uses to render its own URL. The function compares it against each tab's
/// declared suffix to set `active` — the prefix cancels out, so the
/// comparison works the same on both the legacy and tenant-scoped paths.
///
/// When `ctx` is `Some`, each href becomes `/admin/t/<slug><suffix>` so
/// sidebar + tab navigation preserves the tenant context. When `ctx` is
/// `None` (legacy un-prefixed entry, e.g. an old bookmark), hrefs stay at
/// `/admin<suffix>`.
///
/// Each destination's suffix set is unique across the sidebar, so the
/// active destination is unambiguous; the `position` lookup below finds it
/// whether the active page is a destination's default page or one of its
/// tabs.
pub(crate) fn nav(active_suffix: &str, ctx: Option<&TenantContext>) -> Vec<NavGroup> {
    let href_for = |suffix: &str| match ctx {
        Some(c) => c.url(suffix),
        None => format!("/admin{suffix}"),
    };
    let active_dest_idx = DESTINATIONS
        .iter()
        .position(|(_, _, default_suffix, _, tabs)| {
            *default_suffix == active_suffix || tabs.iter().any(|(_, s)| *s == active_suffix)
        });
    DESTINATIONS
        .iter()
        .enumerate()
        .map(|(idx, (section, label, default_suffix, icon, tabs))| {
            let items: Vec<NavItem> = tabs
                .iter()
                .map(|(tab_label, suffix)| NavItem {
                    label: tab_label,
                    href: href_for(suffix),
                    icon,
                    active: *suffix == active_suffix,
                })
                .collect();
            let active = active_dest_idx == Some(idx);
            // Emit a section header only on the FIRST destination of each
            // section (in render order). The trailing Settings entry is
            // section Common but not the first Common destination, so it
            // gets `None` and never re-prints the "Common" header.
            let section_header =
                (!DESTINATIONS[..idx].iter().any(|(s, ..)| s == section)).then_some(*section);
            NavGroup {
                label,
                href: href_for(default_suffix),
                icon,
                active,
                items,
                badge_href: (*label == "Decisions").then(|| href_for("/badge/decisions")),
                section_header,
            }
        })
        .collect()
}

/// Read the theme cookie (set by `static/js/theme.js`) so the server can
/// render the right `data-theme` attribute on first paint. Returns `None`
/// when unset — the CSS then falls back to `prefers-color-scheme`.
pub(crate) fn theme_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("mcp-gw-theme=") {
            if v == "light" || v == "dark" {
                return Some(v.to_owned());
            }
        }
    }
    None
}

/// Render a template into an `Html` response, or a 500 plain-text on a
/// template error. Templates are compile-time checked so a failure here is a
/// real infra issue (OOM, serializer crash) — log it and serve a terse page.
pub(crate) fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "dashboard template render failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}

// ---- overview -------------------------------------------------------------

/// All page + htmx-fragment routes the dashboard exposes. Factored out of
/// [`router`] so the same handler set can be mounted twice:
///
/// 1. **Tenant-scoped** at `/t/{tenant}/...` with [`tenant_scope_middleware`]
///    layered on top — every page handler then sees a
///    [`TenantContext`] via `Extension`, which `nav()` consumes to keep
///    sidebar links inside the prefix.
/// 2. **Legacy** at the root (`/`, `/servers`, …) with no tenant middleware,
///    preserving every existing bookmark / docs link. Handlers extract
///    `Option<Extension<TenantContext>>` so they degrade cleanly when no
///    context is in scope.
///
/// The function takes `state` and pre-injects it so the returned
/// `Router<()>` can be `.merge`d into a stateless outer router without an
/// extra plumbing turn.
/// `GET /badge/decisions` — plain-text pending-decision count for the
/// sidebar badge (`static/js/badge.js`). Counts pending change requests
/// plus active break-glass tokens for the principal's tenant, behind the
/// same admin posture as the Overview banner (non-admin sessions read
/// "0" rather than learning counts exist). Results are cached per tenant
/// for 30s on `AdminState` so the per-page-view fetch never adds store
/// round-trips in steady state; absent stores contribute zero, and the
/// badge is a hint — every failure path degrades to "0".
async fn decisions_badge(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !overview_break_glass_admin(user_principal) {
        return ([(header::CACHE_CONTROL, "no-store")], "0").into_response();
    }
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    const TTL: std::time::Duration = std::time::Duration::from_secs(30);
    {
        let cache = state.hitl.decisions_badge_cache.lock().await;
        if let Some((at, label)) = cache.get(&tenant) {
            if at.elapsed() < TTL {
                return ([(header::CACHE_CONTROL, "no-store")], label.clone()).into_response();
            }
        }
    }

    // Both component counts are capped; when either hits its cap the badge
    // renders "{n}+" rather than silently undercounting. Change requests use
    // a count query so badge refreshes never decode captured proposal params.
    const PENDING_CR_FETCH_LIMIT: u32 = 100;
    let (break_glass, bg_saturated) = match crate::dashboard_break_glass::count_active_for_banner(
        state.policy.break_glass.get(),
        &tenant,
    )
    .await
    {
        Some(n) => crate::dashboard_break_glass::active_banner_label(n),
        None => (0, false),
    };
    let (pending_changes, cr_saturated) = match state.hitl.change_requests.get() {
        Some(store) => store
            .count_pending_up_to(&tenant, PENDING_CR_FETCH_LIMIT)
            .await
            .map(|count| (count as usize, count >= PENDING_CR_FETCH_LIMIT))
            .unwrap_or((0, false)),
        None => (0, false),
    };
    let pending_skills = if state.hitl.reviewed_skills.get().is_some() {
        crate::dashboard_skills::current_reviews(&state, &tenant)
            .await
            .map(|reviews| {
                reviews
                    .iter()
                    .filter(|review| {
                        review.candidate_status == waygate_skills::review::CandidateStatus::Pending
                    })
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };
    let total = break_glass + pending_changes + pending_skills;
    let label = if bg_saturated || cr_saturated {
        format!("{total}+")
    } else {
        total.to_string()
    };

    state
        .hitl
        .decisions_badge_cache
        .lock()
        .await
        .insert(tenant, (std::time::Instant::now(), label.clone()));
    ([(header::CACHE_CONTROL, "no-store")], label).into_response()
}

fn page_routes(state: Arc<AdminState>) -> Router<()> {
    Router::new()
        .route("/", get(overview))
        .route("/badge/decisions", get(decisions_badge))
        .route("/connect", get(connect_page))
        .route("/servers", get(servers_page))
        .route("/servers/config", get(server_config_fragment))
        .route(
            "/servers/config/classifications",
            post(server_classifications_save),
        )
        .route("/servers/config/session", post(server_session_save))
        .route("/servers/config/identity", post(server_identity_save))
        .route("/servers/reconnect", post(servers_reconnect))
        .route("/servers/catalog/refresh", post(servers_refresh_catalog))
        .route("/servers/clear-quarantine", post(servers_clear_quarantine))
        .route("/servers/reload", post(servers_reload))
        .route("/tools", get(tools_page))
        .route("/tools/drawer", get(tools_drawer))
        .route("/tools/try", post(tools_try))
        .route("/policies", get(policies_page))
        .route("/policies/simulate", post(policies_simulate))
        .route("/activity", get(activity_page))
        .route("/activity/rows", get(activity_rows))
        // Side-by-side compare page. Mounted BEFORE
        // the `/activity/{id}` drawer route so `compare` isn't
        // mis-matched as an id. axum 0.8's route ordering goes
        // most-specific first, but the static segment makes
        // this explicit + grep-able.
        .route("/activity/compare", get(activity_compare))
        .route("/activity/{id}", get(activity_drawer))
        // Dashboard-only saved-views mutation surface.
        // Same CSRF + tenant-scoping posture as the playground
        // scenarios endpoints.
        .route("/activity/saved_views", post(save_activity_view))
        .route(
            "/activity/saved_views/{name}/delete",
            post(delete_activity_view),
        )
        .merge(crate::api_keys::router())
        .merge(crate::oauth_clients::router())
        // Sessions + Profiles split off the API
        // Keys page into their own pages (the OAuth-session inventory and
        // the API-key profile registry, respectively).
        .merge(crate::dashboard_sessions::router())
        .merge(crate::dashboard_profiles::router())
        // Cmd-K palette search endpoint. Mounted here so it
        // inherits the same legacy + `/t/{tenant}` mount points; the
        // tenant scope middleware injects `TenantContext` when the
        // request came via the prefixed tree, which the search
        // handler uses to render tenant-prefixed page hrefs.
        .merge(crate::palette::router())
        // Federation page (read-only operator view of
        // federated-peer state).
        .merge(crate::dashboard_federation::router())
        // Tenants page (read-only operator view of the
        // canonical tenants registry).
        .merge(crate::dashboard_tenants::router())
        // Approvals page (read-only operator view of
        // HITL approval grants).
        .merge(crate::dashboard_approvals::router())
        // Break-glass page (read-only operator view of
        // single-use override tokens).
        .merge(crate::dashboard_break_glass::router())
        // Change-request review queue (operator approve/deny
        // of agent-proposed control-plane changes).
        .merge(crate::dashboard_changes::router())
        // The merged Decisions queue — pending change requests +
        // active break-glass in one inbox, inline actions reusing the
        // change-request / break-glass mutation cores.
        .merge(crate::dashboard_decisions::router())
        .merge(crate::dashboard_skills::router())
        .merge(crate::dashboard_tool_reviews::router())
        // The Decision Log — server-rendered audit-decision
        // browser (the `/api/v1/audit/decisions` surface as a pane), with
        // the `?policy_id=` reverse lookup cross-linked from the Policies pane.
        .merge(crate::dashboard_decisions_log::router())
        // Rate-limits page (read-only operator view of
        // the rate_limit_policies registry).
        .merge(crate::dashboard_rate_limits::router())
        // Inspection-rules page (full CRUD over the per-tenant
        // response-inspector rule overrides).
        // OAuth-consent page (read-only operator view of
        // consent grants).
        .merge(crate::dashboard_oauth_consent::router())
        // Catalog page (read-only operator view of
        // servers + drift events).
        .merge(crate::dashboard_builtins::router())
        .merge(crate::dashboard_catalog::router())
        // LLM models page (read-only operator view of
        // the inference-plane model catalog).
        .merge(crate::dashboard_llm_models::router())
        // LLM credentials page (read-only operator view of
        // the process-global credential-pool health).
        .merge(crate::dashboard_llm_credentials::router())
        // Chat tester: streaming chatbot to exercise a model as the session
        // principal (NOT mcp:admin-gated — testing is a model invocation).
        .merge(crate::dashboard_chat::router())
        // Gateway Agents config tab: per-tenant agent
        // definitions — model, tool allowlist, loop caps, enable.
        .merge(crate::dashboard_agents::router())
        // Agent chat: the interactive agentic chat —
        // runs a configured agent's bounded loop over its allowlisted tools as
        // the session principal, streaming step events as SSE.
        .merge(crate::dashboard_agent_chat::router())
        // Contextual Assistant context plane: GET /assist/context?page=…
        // returns the per-page suggested-action chips the docked panel renders.
        .merge(crate::assist::router())
        // Policy-review task agent: one-shot structured
        // Cedar-policy review by a `policy_review` agent, run as the operator.
        .merge(crate::agent_review::router())
        // Embeddings tester: unary form to exercise an embeddings model as the
        // session principal, with a cosine-similarity result (NOT mcp:admin-gated).
        .merge(crate::dashboard_embeddings::router())
        .merge(crate::dashboard_evidence::router())
        // Policy-bundles page (read-only Versions registry
        // of policy_bundles).
        .merge(crate::dashboard_policy_bundles::router(state.clone()))
        // Server-manifests page (editor + versions + export
        // over the manifest store).
        .merge(crate::dashboard_server_manifests::router())
        // Playground page (standalone Cedar policy simulator;
        // reuses the /policies/simulate POST endpoint).
        .merge(crate::dashboard_playground::router())
        // SCIM page (read-only Users directory + provisioning log;
        // groups moved to the unified /groups page).
        .merge(crate::dashboard_scim::router())
        // RBAC page (read-only roles / assignments / mappings).
        .merge(crate::dashboard_rbac::router())
        // Read-only Scopes registry page.
        .merge(crate::dashboard_scopes::router())
        // Read-only unified Groups page.
        .merge(crate::dashboard_groups::router())
        // Settings page (read-only deployment posture +
        // JWKS lifecycle + introspection summary +
        // capability-flag grid).
        .merge(crate::dashboard_settings::router())
        .with_state(state)
}

/// Build the `/admin` sub-router. Caller nests this under `/admin`.
///
/// The static asset directory is resolved at runtime from
/// `GATEWAY_STATIC_DIR`, falling back to `CARGO_MANIFEST_DIR/static` for
/// local `cargo run` / tests. The release Dockerfile sets the env var to
/// the baked-in path (`/etc/mcp-gateway/static`) and copies the directory
/// into the distroless runtime image.
///
/// Router layout:
/// - `/admin/t/{tenant}/...` — tenant-scoped pages (middleware validates
///   the slug + injects [`TenantContext`])
/// - `/admin/...` — legacy un-prefixed pages, mounting the same
///   `page_routes` router as the tenant-scoped tree so every page is
///   reachable both ways
/// - `/admin/static/...` — assets, public, no auth
pub fn router(state: Arc<AdminState>) -> Router<()> {
    let static_dir = std::env::var("GATEWAY_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"));

    let tenant_pages = page_routes(state.clone()).layer(axum::middleware::from_fn_with_state(
        state.clone(),
        tenant_scope_middleware,
    ));

    Router::new()
        .nest("/t/{tenant}", tenant_pages)
        .merge(page_routes(state))
        // Tenant-switch endpoint — server-side `<select>` form target so
        // the no-JS path works the same as the JS path. Mounted at the
        // outer level (not under `/t/{tenant}`) so it doesn't require
        // the tenant_scope middleware to run first.
        .route("/tenant-switch", get(tenant_switch_get))
        // Static assets revalidate on every load (`no-cache` = "store but
        // always check freshness"). The asset paths are stable across
        // deploys (no content-hashed filenames), so the previous
        // `max-age=86400` let a browser serve a *stale* stylesheet, JS, or
        // Lucide sprite for up to a day after a deploy — a changed icon
        // referenced by `<use href=…#name>` rendered blank, and restyled
        // pages kept the old CSS, until the cache expired. `no-cache` makes
        // that impossible while staying cheap: ServeDir emits Last-Modified,
        // so each revalidation is a conditional GET that 304s with no body
        // (the 91KB of self-hosted woff2 is not re-downloaded unless it
        // actually changed). Correctness over a few 304 round-trips is the
        // right trade for an internal ops console; immutable content-hashed
        // URLs would let us cache hard, but that needs a build step we don't
        // have.
        .nest_service(
            "/static",
            Router::new()
                .fallback_service(ServeDir::new(static_dir))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-cache"),
                )),
        )
}

/// Terse verb for the Activity table: `example-messages.send_msg`, `SearchTools`,
/// etc. Row schema flattens action to a string so we stitch the server/tool
/// back on for call-like rows.
pub(crate) fn action_label(r: &AuditRow) -> String {
    match (r.action.as_str(), &r.server, &r.tool) {
        ("CallTool", Some(s), Some(t)) => format!("{s}.{t}"),
        ("CallTool", Some(s), None) => s.clone(),
        _ => r.action.clone(),
    }
}

/// Local CSRF helper for the saved-view forms. Same shape as
/// `dashboard_playground::csrf_ok` — none-injected (dev mode)
/// passes, otherwise the form value must match the session token.
pub(crate) fn activity_csrf_ok(injected: Option<&Extension<CsrfToken>>, form_value: &str) -> bool {
    match injected {
        Some(Extension(c)) => !form_value.is_empty() && csrf_matches(&c.0, form_value),
        None => true,
    }
}

/// Constant-time equality for the CSRF token compare. Guards against a
/// byte-timing oracle on the form field — paranoid, but free.
pub(crate) fn csrf_matches(expected: &str, got: &str) -> bool {
    let a = expected.as_bytes();
    let b = got.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode a JSON string for safe embedding inside an HTML
/// `<script type="application/json">` element, read with `| safe` (HTML
/// escaping disabled). Inside a `<script>`, content is raw text and the
/// browser does NOT un-escape HTML entities, so Askama's default escaping
/// would corrupt the JSON (`"` → `&quot;`) and break `JSON.parse`. JSON
/// structure never contains a literal `<` (only string *values* can), and
/// `<` is representable as the JSON unicode escape `<`, so replacing
/// every `<` round-trips to identical parsed data while making it
/// impossible to emit a `</script>` (or `<!--`) sequence that would close
/// the element early — the standard JSON-in-`<script>` XSS guard.
pub(crate) fn json_for_script_tag(json: &str) -> String {
    json.replace('<', "\\u003c")
}

/// Same gate as `dashboard_break_glass::principal_has_dashboard_admin`
/// — inlined here so the banner check doesn't reach across modules
/// for a 4-line function. Returns `true` only for OAuth/API-key
/// principals carrying `mcp:admin`; refuses peer assertions even
/// when scopes appear to match.
pub(crate) fn overview_break_glass_admin(p: Option<&Principal>) -> bool {
    use waygate_oidc::{AuthMethod, Scope};
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Best label for a row's principal. Prefer email for humans; fall back to
/// `sub`, then `–` for service-less events (initialize, health probe).
/// `pub(crate)` so the Decision Log pane projects rows with the same principal
/// label the Activity feed uses.
pub(crate) fn principal_label(r: &AuditRow) -> String {
    r.principal_email
        .clone()
        .or_else(|| r.principal_sub.clone())
        .unwrap_or_else(|| "–".into())
}

/// The principal's tenant (the same key the invocation pipeline resolves
/// facts under), falling back to the default tenant for anonymous /
/// auth-disabled dev requests.
pub(crate) fn principal_tenant(user: Option<&Extension<Principal>>) -> &str {
    user.map(|Extension(p)| p.tenant.as_str())
        .unwrap_or(waygate_core::TenantId::DEFAULT)
}

/// Best-effort `AdminMutation` audit for a server operational action.
/// Best-effort (not `record_required`) on purpose: these are recovery
/// actions an operator reaches for *because* the gateway is degraded, and
/// the audit DB may be part of that degradation — failing the recovery on
/// an audit-write error would be the wrong trade-off.
pub(crate) async fn record_server_action(
    state: &Arc<AdminState>,
    actor: Option<&Principal>,
    action: &'static str,
    reason: String,
) {
    let mut ev = waygate_mcp::AuditEvent::new(action, waygate_mcp::AuditOutcome::Success)
        .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
        .with_principal(actor)
        .with_reason(reason);
    if let Some(p) = actor {
        ev = ev.with_tenant(p.tenant.clone());
    }
    state.evidence.record_best_effort(ev).await;
}

/// Resolve a tool's risk + side-effects the **same way the invocation
/// pipeline does**: the tenant-aware governed catalog with manifest
/// fallback (`UpstreamCatalog::resolve_invocation_tool`, keyed on the
/// principal's tenant — exactly what `DefaultInvocationService` calls).
///
/// The dashboard's high-risk confirmation guard MUST key off these facts,
/// not the synchronous manifest-only `tool_facts`. If the governed catalog
/// classifies a tool as high-risk / side-effecting while the manifest still
/// says low / no-side-effect, keying off the manifest would let the call
/// reach `invoke` *without* the confirmation the pipeline's own risk class
/// demands — a real divergence. Routing both the drawer's confirm hint
/// and the server-side guard through this one helper keeps them aligned
/// with the pipeline by construction.
///
/// A quarantined/retired server or unavailable authoritative catalog is
/// surfaced as High + side-effecting so the guard conservatively requires
/// confirmation and the UI warns; the subsequent `invoke` returns the
/// lifecycle or retryable outage refusal. This never *under*-confirms.
pub(crate) async fn resolve_pipeline_facts(
    state: &AdminState,
    tenant: &str,
    server: &str,
    tool: &str,
) -> (RiskTier, bool, bool) {
    match state
        .upstreams
        .resolve_invocation_tool(tenant, server, tool)
        .await
    {
        waygate_mcp::catalog::ResolvedInvocationTool::Ready(snapshot) => {
            let facts = snapshot.facts();
            (facts.risk, facts.side_effects, facts.pii)
        }
        waygate_mcp::catalog::ResolvedInvocationTool::Quarantined { .. }
        | waygate_mcp::catalog::ResolvedInvocationTool::Unavailable { .. } => (
            RiskTier::High,
            true,
            state.upstreams.tool_facts(server, tool).pii,
        ),
    }
}

pub(crate) fn risk_str(r: RiskTier) -> &'static str {
    match r {
        RiskTier::Low => "low",
        RiskTier::Medium => "medium",
        RiskTier::High => "high",
    }
}

pub(crate) fn transport_str(t: &Transport) -> &'static str {
    match t {
        Transport::Http => "http",
        Transport::Sse => "sse",
        Transport::Stdio => "stdio",
    }
}

/// Minimal URL encoder sufficient for form values in a query string. The
/// form controls only accept printable input, so we just percent-encode the
/// reserved-in-query-string set. `pub(crate)` so the palette can encode
/// free-string server names in its Tools deep-links too.
pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn nav_legacy(path: &str) -> String {
        format!("/admin{path}")
    }

    // ---- Tier-0 default time-window contract -------------------------------

    fn filters_with_since(since: Option<&str>) -> ActivityFilters {
        ActivityFilters {
            since: since.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn cleaned_defaults_absent_or_invalid_since_to_24h() {
        // Absent → the bounded default, NOT all-time. This is the whole point of
        // Tier-0: a default Activity load must never fall back to a table scan.
        assert_eq!(
            filters_with_since(None).cleaned().since.as_deref(),
            Some(DEFAULT_SINCE)
        );
        // An unrecognised value also collapses to the bounded default.
        assert_eq!(
            filters_with_since(Some("garbage"))
                .cleaned()
                .since
                .as_deref(),
            Some(DEFAULT_SINCE)
        );
        // A recognised window is preserved verbatim.
        assert_eq!(
            filters_with_since(Some("7d")).cleaned().since.as_deref(),
            Some("7d")
        );
        // The explicit all-time escape hatch survives cleaning.
        assert_eq!(
            filters_with_since(Some(ALL_TIME_SINCE))
                .cleaned()
                .since
                .as_deref(),
            Some(ALL_TIME_SINCE)
        );
    }

    #[test]
    fn since_lower_bound_maps_default_window_and_all_time() {
        // The all-time escape hatch is the ONLY value that yields no lower bound.
        assert!(filters_with_since(Some(ALL_TIME_SINCE))
            .since_lower_bound()
            .is_none());
        // The default window resolves to a bound ~24h in the past, never None.
        let lb = filters_with_since(Some(DEFAULT_SINCE))
            .since_lower_bound()
            .expect("the 24h window must be bounded");
        let elapsed = OffsetDateTime::now_utc() - lb;
        assert!(
            (elapsed - time::Duration::hours(24)).abs() < time::Duration::minutes(1),
            "24h window should resolve to ~24h ago, got {elapsed:?}"
        );
        // An absent (un-cleaned) `since` also defaults to a bound, not all-time.
        assert!(filters_with_since(None).since_lower_bound().is_some());
    }

    #[test]
    fn query_suffix_omits_default_window_keeps_explicit() {
        // The implicit 24h baseline never clutters a derived URL...
        assert!(!filters_with_since(Some(DEFAULT_SINCE))
            .to_query_suffix()
            .contains("since="));
        //...but explicit windows (and the all-time opt-in) are carried.
        assert!(filters_with_since(Some("7d"))
            .to_query_suffix()
            .contains("since=7d"));
        assert!(filters_with_since(Some(ALL_TIME_SINCE))
            .to_query_suffix()
            .contains("since=all"));
    }

    #[test]
    fn session_tab_step_up_link_gated_on_admin_required() {
        // The "Re-authorize with the admin scope" step-up link shows only when
        // the tab is read-only *because* the user lacks mcp:admin — not for the
        // no-store / stdio read-only reasons.
        let frag = |admin_required: bool| ServerSessionFragment {
            name: "example-messages".into(),
            config_url: "/admin/servers/config?server=example-messages".into(),
            csrf_token: String::new(),
            tenant_ctx: None,
            editable: false,
            readonly_note: "Read-only — mcp:admin is required to edit the session policy.",
            admin_required,
            base_hash: String::new(),
            concurrency: String::new(),
            isolation: "",
            scope: "",
            retry_on_setup_failure: "",
            setup_recovery_supported: true,
        };
        let with = frag(true).render().expect("render");
        assert!(
            with.contains("step_up_scope=mcp:admin"),
            "step-up link must show when admin is the read-only reason: {with}"
        );
        let without = frag(false).render().expect("render");
        assert!(
            !without.contains("step_up_scope"),
            "no step-up link for a non-admin read-only reason (no store / stdio): {without}"
        );
    }

    #[test]
    fn json_for_script_tag_neutralizes_script_close_and_round_trips() {
        // A tool description containing a literal `</script>` is the attack /
        // breakage case: embedded raw in a <script> it would close the
        // element early. After encoding, no literal `<` survives…
        let schema = r#"{"properties":{"x":{"description":"evil </script><b>"}}}"#;
        let encoded = json_for_script_tag(schema);
        assert!(
            !encoded.contains('<'),
            "every `<` must be escaped so `</script>` can't be emitted: {encoded}"
        );
        assert!(encoded.contains("\\u003c/script>"));
        // …and it still parses to the SAME data (the escape is a no-op on
        // the decoded value).
        let original: serde_json::Value = serde_json::from_str(schema).unwrap();
        let round_tripped: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn attention_queue_is_empty_when_no_signals() {
        let items = attention_items_for_overview(None, false, None, None, &nav_legacy);
        assert!(items.is_empty());
        let items = attention_items_for_overview(Some(0), false, Some(0), Some(0), &nav_legacy);
        assert!(items.is_empty(), "zero counts must not produce rows");
    }

    #[test]
    fn attention_queue_orders_critical_warn_info() {
        let items = attention_items_for_overview(Some(2), false, Some(3), Some(4), &nav_legacy);
        let severities: Vec<_> = items.iter().map(|i| i.severity).collect();
        assert_eq!(severities, vec!["critical", "warn", "info"]);
    }

    #[test]
    fn attention_queue_pluralizes_labels_correctly() {
        let one = attention_items_for_overview(Some(1), false, Some(1), Some(1), &nav_legacy);
        assert_eq!(one[0].label, "1 active break-glass token");
        assert_eq!(one[1].label, "1 HITL approval grant waiting");
        assert_eq!(one[2].label, "1 expired-unused HITL grant");

        let many = attention_items_for_overview(Some(2), false, Some(2), Some(2), &nav_legacy);
        assert_eq!(many[0].label, "2 active break-glass tokens");
        assert_eq!(many[1].label, "2 HITL approval grants waiting");
        assert_eq!(many[2].label, "2 expired-unused HITL grants");
    }

    #[test]
    fn attention_queue_uses_plus_suffix_when_break_glass_saturated() {
        let items = attention_items_for_overview(Some(200), true, None, None, &nav_legacy);
        assert!(
            items[0].label.contains("200+ active"),
            "saturated count must surface as '200+': {}",
            items[0].label,
        );
    }

    #[test]
    fn attention_queue_deep_links_use_provided_nav() {
        let items = attention_items_for_overview(Some(1), false, Some(1), Some(1), &nav_legacy);
        assert_eq!(items[0].href, "/admin/break_glass");
        assert_eq!(items[1].href, "/admin/approvals");
        assert_eq!(items[2].href, "/admin/approvals");
        // Tenant-prefix case: same shape with a different nav fn.
        let nav_tenant = |p: &str| format!("/admin/t/acme{p}");
        let items = attention_items_for_overview(Some(1), false, None, None, &nav_tenant);
        assert_eq!(items[0].href, "/admin/t/acme/break_glass");
    }

    #[test]
    fn attention_queue_skips_none_counts_independently() {
        // A site that exposes only break-glass (catalog store
        // unwired) still surfaces the break-glass row; the
        // missing approval signals don't suppress it.
        let items = attention_items_for_overview(Some(1), false, None, None, &nav_legacy);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].severity, "critical");
    }
}
