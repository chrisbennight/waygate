//! Layout chrome + Overview page — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;

// ---- layout + overview ----------------------------------------------------

#[tokio::test]
pub(crate) async fn overview_renders() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("<!doctype html>"), "no doctype at start");
    assert!(body.contains(r#"<a class="skip-link""#));
    assert!(body.contains(r#"href="/admin/""#));
    assert!(body.contains(r#"aria-current="page""#));
    // Empty state message should appear when no upstreams are configured.
    assert!(body.contains("No upstreams configured"));
}

#[tokio::test]
pub(crate) async fn embeddings_tester_renders() {
    // The embeddings tester mounts at /embeddings and renders. With no inference
    // wired (empty state has no resolver) it shows the not-configured note rather
    // than the form — but the page (and its Embeddings nav entry) still render.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/embeddings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("<!doctype html>"), "no doctype at start");
    assert!(
        body.contains("Embeddings"),
        "page title / nav entry present"
    );
    assert!(
        body.contains("Inference is not configured"),
        "empty state shows the not-configured note"
    );
}

/// Security: the Overview's notable-events feed must be tenant-scoped.
/// `DashboardAuth::Disabled` synthesizes a `dev@local` admin in the
/// default tenant; a denied event recorded under a DIFFERENT tenant must
/// not surface on this tenant's Overview (guards against an un-scoped
/// `recent_events` query leaking across tenants).
#[tokio::test]
pub(crate) async fn overview_notable_feed_is_tenant_scoped() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mut home = sample_row("denied", Some("example-messages"), Some("high"));
    home.principal_email = Some("home-tenant-user@example.com".into());
    home.principal_sub = home.principal_email.clone();
    let mut foreign = sample_row("denied", Some("example-messages"), Some("high"));
    foreign.tenant_id = "other-tenant".into();
    foreign.principal_email = Some("foreign-tenant-user@example.com".into());
    foreign.principal_sub = foreign.principal_email.clone();
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![home, foreign],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("home-tenant-user@example.com"),
        "home tenant's notable event should render",
    );
    assert!(
        !body.contains("foreign-tenant-user@example.com"),
        "another tenant's audit event must never appear on this Overview",
    );
}

#[tokio::test]
async fn overview_notable_feed_renders_newest_event_times_first() {
    let now = OffsetDateTime::now_utc();
    let rows = (1..=12)
        .rev()
        .map(|n| {
            let mut row = sample_row("denied", Some("example-messages"), None);
            row.id = Uuid::from_u128(n);
            row.ts = now - time::Duration::minutes(n as i64);
            row.principal_email = Some(format!("notable-{n:02}@example.com"));
            row
        })
        .collect();
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    let state = Arc::new(AdminState::new(
        Arc::new(UpstreamPool::connect(BTreeMap::new()).await),
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let (status, body) = body_of(dashboard_router(state, DashboardAuth::Disabled), "/").await;
    assert_eq!(status, StatusCode::OK);
    let positions: Vec<_> = (1..=10)
        .map(|n| {
            body.find(&format!("notable-{n:02}@example.com"))
                .expect("latest event should render")
        })
        .collect();
    assert!(
        positions.windows(2).all(|p| p[0] < p[1]),
        "newest timestamp first"
    );
    assert!(!body.contains("notable-11@example.com"));
    assert!(!body.contains("notable-12@example.com"));
}

/// Migration 0046 contract: two `ApiKeyMinted` events by the SAME operator
/// for DIFFERENT key subjects must render as DISTINGUISHABLE "What changed"
/// rows. Before the structured `target` column the feed rendered only
/// `<action> · <principal>`, so both mints collapsed to an identical line —
/// exactly the bug this column fixes. The subject is what disambiguates them,
/// so the contract is "each subject appears", not an exact-string match.
#[tokio::test]
pub(crate) async fn overview_changed_feed_renders_target_subject() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mint = |sub: &str| {
        let mut r = sample_row("success", None, None);
        r.category = Some("api_key_lifecycle".into());
        r.action = "ApiKeyMinted".into();
        // Lifecycle rows carry no server/tool; the subject lives in `target`.
        r.server = None;
        r.tool = None;
        r.principal_email = Some("operator@example.com".into());
        r.principal_sub = r.principal_email.clone();
        r.target = Some(sub.to_owned());
        r
    };
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![mint("svc:example-triage"), mint("workstation@example.test")],
    });
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("svc:example-triage"),
        "the first mint's subject must render in the What-changed feed",
    );
    assert!(
        body.contains("workstation@example.test"),
        "the second mint's subject must render in the What-changed feed — \
         without `target` both mints would be an identical \
         'ApiKeyMinted · operator@example.com' row",
    );
}

/// The Overview "What changed" feed surfaces the change-request
/// ceremony from the broad `admin_mutation` category, filtered to the
/// configurable allowlist (default: ChangeRequest{Propose,Approve,Execute,
/// Deny}). An allowlisted `ChangeRequestPropose` row must appear (with its
/// `action_type` target rendered); a non-allowlisted `admin_mutation` row
/// (`ChangeRequestSecretRetrieve`) must NOT — else the feed would drown in
/// unrelated admin mutations. Contract is "allowlisted in / non-allowlisted
/// out", not an exact-string match.
#[tokio::test]
pub(crate) async fn overview_changed_feed_filters_admin_mutation_to_allowlist() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let admin_row = |action: &str, target: &str| {
        let mut r = sample_row("success", None, None);
        r.category = Some("admin_mutation".into());
        r.action = action.into();
        r.server = None;
        r.tool = None;
        r.principal_email = Some("workstation@example.test".into());
        r.principal_sub = r.principal_email.clone();
        r.target = Some(target.into());
        r
    };
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![
            admin_row("ChangeRequestPropose", "api_key.mint"),
            admin_row("ChangeRequestSecretRetrieve", "api_key.mint"),
        ],
    });
    // AdminState::new defaults overview_change_feed_actions to the four
    // ChangeRequest* actions — Propose in, SecretRetrieve out.
    let state = Arc::new(AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("ChangeRequestPropose"),
        "an allowlisted change-request action must surface on the What-changed feed",
    );
    assert!(
        body.contains("api_key.mint"),
        "the propose row's action_type target must render in its summary",
    );
    assert!(
        !body.contains("ChangeRequestSecretRetrieve"),
        "a non-allowlisted admin_mutation action must be filtered out of the feed",
    );
}

/// The overview leads with status and omits an empty attention section.
/// Missing audit data renders a caption instead of unavailable figures.
#[tokio::test]
pub(crate) async fn overview_leads_with_status_sentence_and_skips_empty_attention() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"class="status-sentence""#),
        "status sentence missing",
    );
    assert!(
        body.contains("Nothing needs your attention."),
        "all-clear clause missing from the status sentence",
    );
    assert!(
        !body.contains("Needs attention"),
        "empty attention queue must not render a section",
    );
    assert!(
        !body.contains("Active approvals") && !body.contains("Expired-unused"),
        "the permanently-dash KPI tiles should be gone",
    );
    assert!(
        body.contains("Traffic figures appear once the audit store is wired"),
        "absent-store figures caption missing",
    );
}

#[tokio::test]
pub(crate) async fn overview_shows_getting_started_when_setup_incomplete() {
    // empty_state: 0 upstreams, no audit, API keys disabled, no Cedar — all
    // four setup milestones unmet, so the checklist renders.
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Getting started"), "checklist card missing");
    assert!(body.contains("Connect an upstream"), "step label missing");
    assert!(body.contains("Set up"), "todo CTA missing");
    assert!(body.contains("(0/4)"), "progress count missing");
}

#[tokio::test]
pub(crate) async fn overview_marks_completed_setup_step_done() {
    // state_with_manifests has an upstream, so "Connect an upstream" is done
    // (struck through) while the card still shows (audit/keys/cedar unset).
    let app = dashboard_router(state_with_manifests().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Getting started"), "checklist card missing");
    assert!(
        body.contains("1 down") && body.contains(r#"state-err">down</span>"#),
        "disconnected runtime must be visible in the overview summary and row: {body}",
    );
    assert!(
        body.contains("gs-label--done"),
        "completed step not marked done"
    );
    assert!(body.contains("(1/4)"), "progress count should be 1/4");
}

#[tokio::test]
pub(crate) async fn overview_cedar_step_done_with_loaded_policy() {
    // state_with_cedar loads one policy (DENY_ALL) and nothing else, so the
    // Cedar milestone is the only one met → 1/4.
    let app = dashboard_router(state_with_cedar().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Load a Cedar policy"), "cedar step missing");
    assert!(body.contains("(1/4)"), "cedar step should count as done");
}

#[tokio::test]
pub(crate) async fn overview_cedar_step_todo_when_policy_set_empty() {
    // A Cedar engine configured from an empty source is a valid but EMPTY
    // policy set; the "Load a Cedar policy" milestone must stay unmet
    // → 0/4 with no upstreams/audit/keys either.
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let engine = Arc::new(ReloadableCedar::new(CedarEngine::from_source("").unwrap()));
    let state = Arc::new(AdminState::new(
        pool,
        Some(engine),
        None,
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    ));
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Load a Cedar policy"), "cedar step missing");
    assert!(
        body.contains("(0/4)"),
        "empty Cedar policy set must not satisfy the milestone"
    );
}

#[tokio::test]
pub(crate) async fn connect_page_renders_endpoint_and_snippets() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/connect").await;
    assert_eq!(status, StatusCode::OK);
    // The MCP endpoint is derived from the gateway's public_url.
    assert!(body.contains("/mcp"), "mcp endpoint missing");
    assert!(
        body.contains("claude mcp add"),
        "quick-connect snippet missing"
    );
    assert!(body.contains("mcpServers"), ".mcp.json snippet missing");
    // empty_state has the AS off → the API-key path + OAuth-disabled state.
    assert!(
        body.contains("Mint an API key"),
        "api-key alternative missing"
    );
    assert!(body.contains("OAuth disabled"), "AS-disabled state missing");
}

/// Regression: axum 0.8's `.nest("/admin", …)` with a child `/` route matches
/// `/admin` but 404s on `/admin/` — which is exactly the canonical URL the
/// sidebar's Overview link uses. waygate-server wraps the final service with
/// `NormalizePathLayer::trim_trailing_slash()` to paper over this; mirror
/// that wrapping here so the next accidental removal fails loudly.
#[tokio::test]
pub(crate) async fn admin_trailing_slash_reaches_overview() {
    use tower::Layer;
    use tower_http::normalize_path::NormalizePathLayer;

    let dashboard = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let nested: axum::Router<()> = axum::Router::new().nest("/admin", dashboard);
    let app = NormalizePathLayer::trim_trailing_slash().layer(nested);

    for path in ["/admin", "/admin/"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unexpected status for {path}"
        );
    }
}

/// Regression: mirrors the full `main.rs` router composition (including the
/// catch-all `nest_service("/mcp", …)` alongside the `/api/v1/*` routes). The
/// dashboard must be reachable at both `/admin` and `/admin/` even when the
/// merged-in `protected` router carries a bearer-middleware layer that 401s
/// requests without an Authorization header. Otherwise a `/admin/` hit would
/// fall through to the bearer fallback and return the production error
/// `{"error":"unauthorized","detail":"missing Authorization header"}`.
#[tokio::test]
pub(crate) async fn admin_trailing_slash_bypasses_bearer_middleware() {
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::middleware::Next;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{any, get};
    use tower::Layer;
    use tower_http::normalize_path::NormalizePathLayer;
    use tower_http::trace::TraceLayer;

    async fn bearer_mw(State(_): State<()>, req: Request, next: Next) -> Response {
        if req.headers().get("authorization").is_none() {
            return (StatusCode::UNAUTHORIZED, "missing auth").into_response();
        }
        next.run(req).await
    }

    let mcp_service = any(|| async { "mcp-ok" });

    let protected: axum::Router<()> = axum::Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/api/v1/servers", get(|| async { "api-ok" }))
        .layer(axum::middleware::from_fn_with_state((), bearer_mw));

    let dashboard = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let stateful = axum::Router::new().route("/healthz", get(|| async { "ok" }));
    let app: axum::Router<()> = stateful
        .merge(protected)
        .nest("/admin", dashboard)
        .layer(TraceLayer::new_for_http());
    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    for path in ["/admin", "/admin/"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unexpected status for {path}"
        );
    }
}

#[tokio::test]
pub(crate) async fn theme_cookie_is_respected() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("cookie", "mcp-gw-theme=dark")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.contains(r#"data-theme="dark""#),
        "dark theme not rendered"
    );
}

/// Static assets must revalidate on every load (`Cache-Control: no-cache`)
/// rather than cache hard, so a deploy is never masked by a browser
/// serving a stale stylesheet / JS / sprite from the old build (asset
/// paths aren't content-hashed). ServeDir keeps revalidation cheap via
/// Last-Modified → 304.
#[tokio::test]
pub(crate) async fn static_assets_revalidate_not_cache_hard() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/css/tokens.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "static asset should serve");
    let cc = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        cc, "no-cache",
        "static assets must revalidate so a deploy is never masked by a stale cached asset",
    );
}
