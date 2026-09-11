//! Activity page, drawer, facets, pushdown — split from the monolithic
//! `dashboard_render.rs`; bodies verbatim, cut at the file's own
//! section markers.

use crate::common::*;

// ---- activity + drawer ----------------------------------------------------

#[tokio::test]
pub(crate) async fn activity_page_shows_audit_unavailable_banner() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("audit store not configured"));
}

#[tokio::test]
pub(crate) async fn activity_page_renders_rows() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    // All three outcomes should appear as chips.
    assert!(body.contains("DENY"));
    assert!(body.contains("ALLOW"));
    assert!(body.contains("STEP_UP"));
    // Every row carries its audit id for drawer click-through.
    assert!(body.contains("data-audit-id="));
}

/// The volume histogram carries a y-axis with the
/// peak-bucket label so full bar height has a number, plus a "View as
/// table" numeric alternative for legibility/screen readers. The three
/// seeded events share ONE pinned timestamp, so they always land in the
/// same hourly bucket and the peak is deterministically 3 — the rows must
/// NOT use `sample_row`'s `now_utc()`, which could straddle an hourly
/// bucket boundary mid-construction and flake the assertion.
#[tokio::test]
pub(crate) async fn activity_histogram_has_peak_axis_and_table() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // ONE instant captured once and shared by all three rows: in-window
    // (the histogram defaults to the last 24h) and guaranteed in a single
    // hourly bucket. Capturing per-row via sample_row's now_utc() is the
    // straddle risk this avoids.
    let pinned = OffsetDateTime::now_utc();
    let rows: Vec<AuditRow> = ["denied", "success", "step_up_required"]
        .into_iter()
        .map(|o| {
            let mut r = sample_row(o, Some("example-messages"), Some("high"));
            r.ts = pinned;
            r
        })
        .collect();
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"class="hist-axis__max">3<"#),
        "y-axis must label the peak bucket count",
    );
    assert!(
        body.contains(r#"class="hist-axis__zero">0<"#),
        "y-axis must label the zero baseline",
    );
    assert!(
        body.contains("View as table"),
        "histogram must offer a numeric table alternative",
    );
    assert!(body.contains(r#"class="hist-table-toggle""#));
    // The table's own structure: headings + per-outcome count cells. The
    // three seeded rows (one denied, one success, one step_up_required)
    // share a bucket, so each outcome renders a "<outcome> 1" chip.
    assert!(
        body.contains("<th>Bucket</th>"),
        "table heading Bucket missing"
    );
    assert!(
        body.contains("<th>Total</th>"),
        "table heading Total missing"
    );
    assert!(
        body.contains("<th>By outcome</th>"),
        "table heading By outcome missing",
    );
    assert!(
        body.contains(r#"<span class="chip chip--xs">denied 1</span>"#),
        "per-outcome count cell missing for denied",
    );
    assert!(
        body.contains(r#"<span class="chip chip--xs">step_up_required 1</span>"#),
        "per-outcome count cell missing for step_up_required",
    );
}

#[tokio::test]
pub(crate) async fn activity_rows_filter_by_outcome() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    // Filter value matches `AuditOutcome::as_str()` — the storage form
    // is the wire form for the filter dropdown.
    let (status, body) = body_of(app, "/activity/rows?outcome=denied").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("DENY"));
    // ALLOW row should be filtered out entirely.
    assert!(!body.contains(">ALLOW<"));
}

#[tokio::test]
pub(crate) async fn activity_drawer_returns_event_detail() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, &format!("/activity/{deny_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice@example.com"));
    assert!(body.contains("group not permitted"));
    assert!(body.contains("policy0"));
}

/// With `GATEWAY_TRACE_URL_TEMPLATE` configured (via the
/// `with_trace_url_template` builder), the drawer renders a "View trace"
/// link with the `{trace_id}` placeholder substituted by the row's trace_id.
#[tokio::test]
pub(crate) async fn activity_drawer_renders_view_trace_link_when_template_set() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let rows = vec![sample_row("denied", Some("example-messages"), Some("high"))];
    let id = rows[0].id;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
    let state = Arc::new(
        AdminState::new(
            pool,
            None,
            Some(audit),
            AdminState::null_evidence(),
            None,
            None,
            None,
            None,
            "http://127.0.0.1:0".into(),
        )
        .with_trace_url_template(Some(
            "https://observability.example.com/explore?traceID={trace_id}".into(),
        )),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, &format!("/activity/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("View trace"),
        "drawer should render the View trace link when a template is configured",
    );
    assert!(
        body.contains(
            "https://observability.example.com/explore?traceID=00000000000000000000000000000001"
        ),
        "the {{trace_id}} placeholder should be substituted with the row's trace_id",
    );
}

/// Without a template (the default — no `GATEWAY_TRACE_URL_TEMPLATE`),
/// the drawer still shows the bare trace-id but renders NO "View trace" link.
#[tokio::test]
pub(crate) async fn activity_drawer_omits_view_trace_link_without_template() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, &format!("/activity/{deny_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("00000000000000000000000000000001"),
        "the bare trace-id should still be shown",
    );
    assert!(
        !body.contains("View trace"),
        "no View trace link should render when no template is configured",
    );
}

// ---- Facet explorer additions ---------------------------------------------

/// Facet sidebar appears on the parent activity page and shows
/// per-value counts derived from the current fetched page.
/// `state_with_audit()` seeds one each of denied/success/step_up_required,
/// so the Outcome facet must surface all three values with count=1.
#[tokio::test]
pub(crate) async fn activity_page_renders_facet_sidebar_with_counts() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"aria-label="Filter facets""#),
        "facet sidebar missing",
    );
    // Facet group headings present
    assert!(body.contains(">Outcome<"), "Outcome facet group missing");
    assert!(body.contains(">Risk<"), "Risk facet group missing");
    assert!(body.contains(">Server<"), "Server facet group missing");
    // Outcome values from the seeded events show up with the
    // operator-friendly text + the count column.
    assert!(body.contains("denied"));
    assert!(body.contains("step_up_required"));
    assert!(
        body.contains(r#"<span class="count">1</span>"#),
        "facet count span missing",
    );
}

/// With `?group=trace`, rows sharing a trace_id cluster into a banded
/// group and the head row shows a fan-out count. `state_with_audit` seeds 3
/// rows that all share trace_id `…0001`, so they form one group of 3.
#[tokio::test]
pub(crate) async fn activity_group_by_trace_clusters_rows_sharing_trace_id() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?group=trace").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Group by trace: on"),
        "group toggle should render on",
    );
    // Assert on the rendered ROW attribute (not the bare class name, which
    // also appears in the page's <style> block).
    assert!(
        body.contains(r#"class="trace-grouped trace-band-0""#),
        "rows sharing a trace_id should get the trace-band class on the <tr>",
    );
    assert!(
        body.contains("3 calls share this trace_id"),
        "the head row should show a fan-out count of 3 (all seeded rows share one trace)",
    );
}

/// The default (ungrouped) feed renders flat — no trace bands or
/// fan-out badges — and the toggle reads off.
#[tokio::test]
pub(crate) async fn activity_ungrouped_feed_has_no_trace_bands() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Group by trace: off"));
    // Negative checks target the rendered forms, not the class names (which
    // are always present in the <style> block).
    assert!(
        !body.contains(r#"class="trace-grouped"#),
        "flat feed must not band any <tr> by trace",
    );
    assert!(
        !body.contains("calls share this trace_id"),
        "flat feed must not show fan-out badges",
    );
}

/// The live-tail fragment with `since_id` returns ONLY rows newer than
/// it, marked with the new-row highlight class and without a load-more row.
/// `state_with_audit` seeds 3 rows; `deny_id` is the oldest, so a delta from it
/// returns exactly the 2 newer rows.
#[tokio::test]
pub(crate) async fn activity_rows_live_tail_delta_returns_only_newer_rows() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, &format!("/activity/rows?since_id={deny_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.matches("data-audit-id=").count(),
        2,
        "delta should return exactly the 2 rows newer than the oldest (since_id)",
    );
    assert!(
        body.contains("activity-row--new"),
        "delta rows should carry the new-row highlight class",
    );
    assert!(
        !body.contains(&deny_id.to_string()),
        "the since_id row itself is not newer than itself and must be excluded",
    );
    assert!(
        !body.contains("Load 50 more"),
        "a prepend delta must not include the load-more row",
    );
}

/// An empty delta (no rows newer than `since_id`) returns nothing —
/// crucially NOT the "No events" empty-state row, which would otherwise be
/// prepended to a populated feed on every poll.
#[tokio::test]
pub(crate) async fn activity_rows_live_tail_empty_delta_has_no_empty_state() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    // A fresh v7 id is newer than every seeded row → zero newer rows.
    let future = Uuid::now_v7();
    let (status, body) = body_of(app, &format!("/activity/rows?since_id={future}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("No events match"),
        "an empty live-tail delta must not prepend the empty-state row",
    );
    assert!(
        !body.contains("data-audit-id="),
        "an empty delta has no rows",
    );
}

/// A live-tail poll with an EMPTY `since_id` (the feed had no top row to
/// read) populates from the recent page AND suppresses the empty-state
/// row — so an idle poll never prepends a stray "No events".
#[tokio::test]
pub(crate) async fn activity_rows_live_tail_empty_since_id_populates_without_empty_state() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity/rows?since_id=").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("activity-row--new"),
        "empty-since_id populate should highlight the rows",
    );
    assert_eq!(
        body.matches("data-audit-id=").count(),
        3,
        "all 3 seeded rows populate the empty feed",
    );
    assert!(
        !body.contains("No events match"),
        "a live-tail poll must never render/prepend the empty-state row",
    );
}

/// When more than one page of new rows arrives between polls, the
/// saturated delta keeps the load-more cursor so the older-new rows
/// beyond the 50-row window stay reachable instead of being silently
/// dropped.
#[tokio::test]
pub(crate) async fn activity_rows_live_tail_saturated_delta_keeps_load_more() {
    // 51 rows with increasing ids (now_v7 is monotonic) → rows[0] is the oldest.
    let mut rows: Vec<AuditRow> = (0..51)
        .map(|_| sample_row("success", Some("example-messages"), Some("low")))
        .collect();
    let oldest = rows[0].id;
    // The in-memory fake returns rows in insertion order; mirror the storage
    // newest-first ordering by inserting newest first.
    rows.reverse();
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    // since_id = the oldest row → every fetched row (the newest 50) is newer,
    // so the delta is saturated.
    let (status, body) = body_of(app, &format!("/activity/rows?since_id={oldest}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.matches("data-audit-id=").count(),
        50,
        "delta returns the newest full page (50)",
    );
    assert!(
        body.contains("Load 50 more"),
        "a saturated delta keeps the load-more cursor so older-new rows stay reachable",
    );
}

/// Active-filter chip row appears above the events table when a
/// filter is set, and links back to the unfiltered page when the
/// chip's `×` is clicked (single active filter → empty `clear_url`).
#[tokio::test]
pub(crate) async fn activity_page_renders_active_filter_chip_when_filter_set() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?risk=high").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"aria-label="Active filters""#),
        "active-filter chip row missing when risk=high set",
    );
    assert!(
        body.contains("risk: high"),
        "active-filter chip label missing the filter name+value",
    );
    // Single active filter → clear URL is the bare /activity page
    // (no `?` because to_query_suffix() returns empty).
    assert!(
        body.contains(r#"href="/admin/activity""#),
        "single-filter clear link should target the bare activity page",
    );
}

/// Facet click sets the corresponding URL param via a same-page link
/// (no JS, no htmx fetch — bookmarkable). Active values render with the
/// `active` class on the link.
#[tokio::test]
pub(crate) async fn activity_facet_active_value_marks_link_active() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?outcome=denied").await;
    assert_eq!(status, StatusCode::OK);
    // The active Outcome=denied facet renders with the active class
    // AND its clear-link sets outcome to empty.
    assert!(
        body.contains(r#"href="/admin/activity?outcome=" class="active""#),
        "active Outcome=denied facet link should toggle off via empty value",
    );
}

/// The new category / pii / since filters all apply via the
/// /activity/rows fragment. With state_with_audit() seeding only
/// generic invocation-style events, none of them carry the
/// `data_inspection` category — so filtering to that category
/// produces an empty result set.
#[tokio::test]
pub(crate) async fn activity_rows_filter_by_unmatched_category_returns_empty() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity/rows?category=data_inspection").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("No events match these filters"),
        "expected empty-state copy for unmatched category filter",
    );
}

/// Since filter normalises its env-driven menu values; an
/// unknown value is silently dropped (no 400) and the rows render
/// unfiltered.
#[tokio::test]
pub(crate) async fn activity_rows_filter_with_invalid_since_falls_through() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity/rows?since=garbage").await;
    assert_eq!(status, StatusCode::OK);
    // All three outcomes still surface — the bogus `since` was treated
    // as no-filter rather than zeroing the page.
    assert!(body.contains("DENY"));
    assert!(body.contains("ALLOW"));
    assert!(body.contains("STEP_UP"));
}

// ---- Filter + facet pushdown reaches the whole table ---------------------

/// A filter must reach the whole `audit_log`, not just the newest page.
/// Seed 59 `example-compute` rows then one `searxng` row, so searxng is the 60th —
/// beyond the 50-row page. Filtering `server=searxng` must return the
/// searxng row: fetching only the newest 50 rows and filtering them in
/// memory would leave a row beyond the page (searxng) unable to surface —
/// the exact "I only ever see example-compute" symptom.
#[tokio::test]
pub(crate) async fn activity_filter_reaches_rows_beyond_the_first_page() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mut rows = Vec::new();
    for _ in 0..59 {
        rows.push(sample_row("success", Some("example-compute"), Some("low")));
    }
    rows.push(sample_row("success", Some("searxng"), Some("low")));
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    let (status, body) = body_of(app, "/activity/rows?server=searxng").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("searxng"),
        "server=searxng must surface the searxng row even though it sits \
         beyond the newest 50 (guards against a page-scoped-filter bug)",
    );
    assert!(
        !body.contains("example-compute"),
        "filtered rows must exclude non-matching servers",
    );
}

/// The facet rail is a table-wide aggregate within the time window,
/// not a count over the fetched page. With 59 example-compute + 1 searxng (searxng
/// beyond the 50-row page, so it never appears in the table), the Server
/// facet must still list searxng, and example-compute's count must be 59 — not
/// capped at the 50-row page.
#[tokio::test]
pub(crate) async fn activity_facets_count_the_whole_table_not_just_the_page() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mut rows = Vec::new();
    for _ in 0..59 {
        rows.push(sample_row("success", Some("example-compute"), Some("low")));
    }
    rows.push(sample_row("success", Some("searxng"), Some("low")));
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    // Server facet lists searxng even though its row is beyond the page
    // (so the table never shows it) — facets are table-wide.
    assert!(
        body.contains("server=searxng"),
        "Server facet must list searxng (table-wide) even though its row is \
         beyond the displayed page",
    );
    // example-compute's facet count reflects the whole window (59), not the page.
    assert!(
        body.contains(r#"<span class="count">59</span>"#),
        "Server facet count must reflect the whole window (59), not the page (≤50)",
    );
}

/// `since` is a real predicate pushed into the query (via
/// `AuditQuery::matches` for the in-memory fake), not a post-fetch filter
/// on the page. A row older than the window is excluded; a recent one kept.
#[tokio::test]
pub(crate) async fn activity_since_filter_excludes_old_rows() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let recent = sample_row("success", Some("searxng"), Some("low"));
    let mut old = sample_row("denied", Some("example-compute"), Some("high"));
    old.ts = OffsetDateTime::now_utc() - time::Duration::hours(2);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![recent, old],
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
    let (status, body) = body_of(app, "/activity/rows?since=1h").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("searxng"),
        "a row within the 1h window must render",
    );
    assert!(
        !body.contains("example-compute"),
        "a row older than 1h must be excluded by the since predicate",
    );
}

/// The Activity feed AND its facet rail are tenant-scoped to the active
/// principal's tenant. The whole-table SQL pushdown must never let a
/// tenant-scoped page read another tenant's audit rows or facet counts —
/// including when an operator explicitly filters for another tenant's
/// server. Disabled-auth tests run as the DEFAULT tenant (no principal),
/// so an `other-tenant` row must be invisible.
#[tokio::test]
pub(crate) async fn activity_feed_is_tenant_scoped() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mine = sample_row("success", Some("mine-mcp"), Some("low")); // tenant = default
    let mut theirs = sample_row("denied", Some("theirs-mcp"), Some("high"));
    theirs.tenant_id = "other-tenant".to_owned();
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![theirs, mine],
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

    // Full page: own-tenant row + server facet present; the other tenant's
    // row and server facet must not leak (rows query AND facet aggregate).
    let (status, body) = body_of(app.clone(), "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("mine-mcp"),
        "own-tenant row/facet must render"
    );
    assert!(
        !body.contains("theirs-mcp"),
        "another tenant's row + facet must not leak into the feed",
    );

    // Explicitly filtering for the other tenant's server still returns nothing.
    let (status, body) = body_of(app, "/activity/rows?server=theirs-mcp").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("theirs-mcp"),
        "explicitly filtering for another tenant's server must not surface it",
    );
}

/// The activity detail drawer is tenant-scoped. `fetch_event` is keyed by
/// id only, so without a gate a known UUID from another tenant would
/// render its full audit detail. A cross-tenant id is treated as
/// not-found (mirrors the compare gate), while an own-tenant id renders.
#[tokio::test]
pub(crate) async fn activity_drawer_rejects_cross_tenant_id() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mine = sample_row("denied", Some("example-messages"), Some("high")); // tenant = default
    let mine_id = mine.id;
    let mut foreign = sample_row("success", Some("example-observability"), Some("low"));
    foreign.tenant_id = "other".into();
    let foreign_id = foreign.id;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![mine, foreign],
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

    // Own-tenant id renders the drawer.
    let (status, _body) = body_of(app.clone(), &format!("/t/default/activity/{mine_id}")).await;
    assert_eq!(status, StatusCode::OK, "own-tenant drawer should render");

    // Cross-tenant id is treated as not-found — no audit detail leak.
    let (status, _body) = body_of(app, &format!("/t/default/activity/{foreign_id}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a cross-tenant event id must not render another tenant's audit detail",
    );
}

/// The "Top tools" panel renders per-(server, tool) reliability —
/// volume, execution-error + denial counts, error rate, and p95 latency —
/// as a separate aggregate (with `outcome` cleared so the failure counts
/// see every outcome). Seed 4 example-compute/get_pods rows (2 success, 1
/// execution_error, 1 denied; all latency 100) → total 4, errors 1, denied
/// 1, error rate 25.0%, p95 100.
#[tokio::test]
pub(crate) async fn activity_top_tools_panel_shows_per_tool_reliability() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mk = |outcome: &str| {
        let mut r = sample_row(outcome, Some("example-compute"), Some("low"));
        r.tool = Some("get_pods".into());
        r.latency_ms = Some(100);
        r
    };
    let rows = vec![
        mk("success"),
        mk("success"),
        mk("execution_error"),
        mk("denied"),
    ];
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Top tools in this window"),
        "tool-stats panel heading missing",
    );
    assert!(body.contains("get_pods"), "per-tool row missing");
    // 1 execution_error / 4 total = 25.0% (denials are counted separately,
    // not as errors), proving outcome is cleared for the aggregate.
    assert!(
        body.contains("25.0%"),
        "error rate should be 25.0% (execution_error / total)",
    );
}

/// The "Top tools" aggregate must exclude fail-closed pre-dispatch intent
/// rows (`reason='pre_call'`), which pair with a later outcome row. A
/// high-risk `execution_error` under `GATEWAY_AUDIT_MODE=fail_closed`
/// writes a `pre_call` Success row + the `execution_error` row; counting
/// both would report total=2/errors=1 (50%) instead of the correct
/// total=1/errors=1 (100%).
#[tokio::test]
pub(crate) async fn activity_top_tools_excludes_fail_closed_pre_call_rows() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // The pre-dispatch intent row: a Success row carrying reason="pre_call".
    let mut pre_call = sample_row("success", Some("example-compute"), Some("high"));
    pre_call.tool = Some("post_pods".into());
    pre_call.reason = Some("pre_call".into());
    pre_call.latency_ms = None;
    // The real outcome row for the same call.
    let mut outcome = sample_row("execution_error", Some("example-compute"), Some("high"));
    outcome.tool = Some("post_pods".into());
    outcome.latency_ms = Some(200);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit {
        rows: vec![pre_call, outcome],
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("post_pods"), "tool row missing");
    // total=1 (pre_call excluded), errors=1 → 100.0%, NOT 50.0%.
    assert!(
        body.contains("100.0%"),
        "error rate must be 100.0% (pre_call intent row excluded from the count)",
    );
    assert!(
        !body.contains("50.0%"),
        "counting the pre_call row would wrongly halve the error rate to 50.0%",
    );
}

/// The activity volume histogram renders a stacked-by-outcome bar
/// for the active window — a server-side aggregate, not the paged rows.
/// Seed 3 success + 1 denied (all "now", so one bucket) → one bar with a
/// success band (count 3) + a denied band (count 1), total 4.
#[tokio::test]
pub(crate) async fn activity_histogram_renders_stacked_by_outcome() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let rows = vec![
        sample_row("success", Some("example-compute"), Some("low")),
        sample_row("success", Some("example-compute"), Some("low")),
        sample_row("success", Some("searxng"), Some("low")),
        sample_row("denied", Some("example-messages"), Some("high")),
    ];
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows });
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Activity volume"), "histogram panel missing");
    // One bucket (all rows are "now") with a success band (3) + denied (1).
    assert!(
        body.contains(r#"data-outcome="success" data-count="3""#),
        "success band should count 3",
    );
    assert!(
        body.contains(r#"data-outcome="denied" data-count="1""#),
        "denied band should count 1",
    );
    assert!(
        body.contains(r#"data-total="4""#),
        "the bucket bar total should be 4",
    );
}

// ---- Activity filter/facet edge cases -------------------------------------

/// Legacy NULL `category` rows count under `invocation` for both the
/// matcher AND the facet. A page whose only seeded rows have
/// `category: None` (the pre-`0006_audit_category.sql` shape) must
/// therefore render when filtered to `category=invocation`, AND the
/// Category facet must show `invocation N`, not be empty.
#[tokio::test]
pub(crate) async fn activity_legacy_null_category_counts_as_invocation() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let mut r0 = sample_row("denied", Some("example-messages"), Some("high"));
    let mut r1 = sample_row("success", Some("example-observability"), Some("low"));
    r0.category = None;
    r1.category = None;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![r0, r1] });
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

    // Matcher honours NULL → invocation.
    let (status, body) = body_of(app.clone(), "/activity/rows?category=invocation").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("DENY"));
    assert!(body.contains("ALLOW"));

    // Facet counts NULL rows under `invocation`.
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    // The Category section header always renders; the value
    // line for invocation is what was previously missing.
    assert!(body.contains(">Category<"));
    assert!(
        body.contains("invocation"),
        "Category facet should show `invocation` for legacy NULL rows",
    );
}

/// Invalid `since` values get dropped at the cleaner, so the
/// form / chip / matcher all stay consistent. A request with
/// `?since=garbage` should render NO active-filter chip row
/// (no real filter is in effect).
#[tokio::test]
pub(crate) async fn activity_invalid_since_does_not_render_active_chip() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?since=garbage").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"aria-label="Active filters""#),
        "bogus `since=garbage` must not produce an active-filter chip row \
         (would be a UI lie — the matcher silently drops the value)",
    );
    // The form's `<select id="f-since">` should also NOT carry
    // a selected="" on any value.
    assert!(
        !body.contains(r#"value="garbage""#),
        "bogus `since` should not survive into the form state either",
    );
}

/// The filter form submits as a plain GET against the parent
/// page (not an htmx fragment swap), so the facet sidebar +
/// active-chip row stay consistent with the URL after a filter
/// change. Verify the form has `method="GET"` +
/// `action="/admin/.../activity"` and does NOT carry the prior
/// `hx-get` / `hx-target` attributes — otherwise the staleness
/// bug would silently regress.
#[tokio::test]
pub(crate) async fn activity_filter_form_is_plain_get_not_htmx() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    // Locate the filter form in the body so we don't accidentally
    // confuse other forms (drawer, tenant-switch).
    assert!(
        body.contains(r#"class="filter-bar""#),
        "filter form .filter-bar missing entirely",
    );
    assert!(
        body.contains(r#"method="GET""#),
        "filter form should be plain GET (htmx fragment swap left \
         facets + chips stale)",
    );
    assert!(
        body.contains(r#"action="/admin/activity""#),
        "filter form action should be the parent /activity page",
    );
    // Defensive: the filter form must NOT carry hx-target — the
    // load-more pagination button still does, so a naive substring
    // check would false-positive. Scope by anchoring to the form's
    // unique opening `<form class="filter-bar"`.
    let form_start = body
        .find(r#"<form class="filter-bar""#)
        .expect("filter form not found");
    let form_end = body[form_start..]
        .find("</form>")
        .map(|i| form_start + i)
        .expect("filter form not closed");
    let form_block = &body[form_start..form_end];
    assert!(
        !form_block.contains("hx-get="),
        "filter form must not carry htmx attrs — would regress the \
         facets/chips/rows stale-state bug",
    );
    assert!(
        !form_block.contains("hx-target="),
        "filter form must not carry hx-target — same regression risk",
    );
    // Submit button is visible so the no-JS path works (matches the
    // tenant-switch posture elsewhere in the dashboard).
    assert!(
        form_block.contains(r#"type="submit""#),
        "filter form needs a visible submit button now that it's plain GET",
    );
}

/// Category `<select>` menu must cover every canonical
/// `EvidenceCategory` variant the writer emits, so a pre-fill
/// from a real audit URL (`?category=manifest_reload` etc.)
/// produces a matching `<option... selected>`. Without this,
/// the URL still matched the active filter at fetch time but
/// the form state silently dropped it on the next Filter
/// click — the same form-state-drop shape the Outcome/Risk
/// selects guard against below, just for variants whose
/// `<option>` didn't exist.
///
/// The truth table is `EvidenceCategory::as_str()` at
/// `crates/waygate-evidence/src/audit.rs`. Asserting every
/// variant here catches a future enum addition that
/// forgets to widen the dashboard menu.
#[tokio::test]
pub(crate) async fn activity_category_select_covers_every_evidence_category_variant() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);

    // The full canonical list as the writer stamps it. If
    // EvidenceCategory grows a variant, this test breaks
    // until the dashboard menu catches up.
    let variants = [
        "invocation",
        "discovery",
        "admin_mutation",
        "auth_attempt",
        "policy_reload",
        "manifest_reload",
        "api_key_lifecycle",
        "oauth_event",
        "upstream_health",
        "approval_lifecycle",
        "catalog_drift",
        "data_inspection",
        "file_transfer",
        "retention_sweep",
        "llm_completion",
    ];
    for v in variants {
        let (status, body) = body_of(app.clone(), &format!("/activity?category={v}")).await;
        assert_eq!(status, StatusCode::OK, "request failed for ?category={v}");
        assert!(
            body.contains(&format!(r#"<option value="{v}" selected>"#)),
            "Category `<select>` missing `selected` option for {v} — \
             menu has drifted from EvidenceCategory::as_str()",
        );
    }
}

/// Outcome and Risk `<select>` elements re-render with the
/// right `<option selected>` after the form's GET round-trip.
/// Without this binding, an active `outcome=` / `risk=` URL
/// renders in the rows and chip but the form still says
/// "any" — clicking Filter would silently drop the active
/// filter. The `category` / `pii` / `since` selects already
/// carry this binding; this guards Outcome and Risk the
/// same way.
#[tokio::test]
pub(crate) async fn activity_filter_outcome_and_risk_selects_repopulate_from_url() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?outcome=denied&risk=high").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"<option value="denied" selected>"#),
        "Outcome `<select>` should mark denied as selected after \
         /activity?outcome=denied",
    );
    assert!(
        body.contains(r#"<option value="high" selected>"#),
        "Risk `<select>` should mark high as selected after \
         /activity?risk=high",
    );
}

/// Text inputs (Server, Principal) re-populate from the
/// current filter state after the form's GET round-trip.
/// Without this the operator's typed value would disappear
/// on every Filter click.
#[tokio::test]
pub(crate) async fn activity_filter_text_inputs_repopulate_from_url() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?server=example-messages&principal=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"value="example-messages""#),
        "Server input should pre-fill from ?server=",
    );
    assert!(
        body.contains(r#"value="alice""#),
        "Principal input should pre-fill from ?principal=",
    );
}

/// Same `cleaned`-validation posture as the `since` filter
/// above. `pii=garbage` should NOT render an active-filter
/// chip or survive into the form state.
#[tokio::test]
pub(crate) async fn activity_invalid_pii_does_not_render_active_chip() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/activity?pii=garbage").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"aria-label="Active filters""#),
        "bogus `pii=garbage` must not produce an active-filter chip row",
    );
    assert!(
        !body.contains(r#"value="garbage""#),
        "bogus `pii` should not survive into the form state either",
    );
}

/// Server facet values are URL-encoded in the bookmarkable
/// facet href. Operator-authored `UpstreamManifest.name`
/// strings can contain `&` / `?` / space / `%`, which would
/// otherwise break the link.
#[tokio::test]
pub(crate) async fn activity_facet_url_encodes_server_names_with_reserved_chars() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Server name with a reserved query character. The
    // facet href should percent-encode the `%` into `%25` (and
    // the space into `%20`); the visible label still shows
    // the raw value so the operator sees the actual name.
    let row = sample_row("success", Some("weird%name 42"), Some("low"));
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![row] });
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
    let (status, body) = body_of(app, "/activity").await;
    assert_eq!(status, StatusCode::OK);
    // The href carries the URL-encoded form.
    assert!(
        body.contains("?server=weird%25name%2042"),
        "Server facet href must URL-encode reserved characters; \
         expected `?server=weird%25name%2042` in the rendered body",
    );
    // The visible label still shows the raw name so the
    // operator can read it.
    assert!(
        body.contains("weird%name 42"),
        "Server facet label should show the raw server name",
    );
}

#[tokio::test]
pub(crate) async fn activity_drawer_404s_for_unknown_id() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let unknown = Uuid::now_v7();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/activity/{unknown}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The Activity view is where an operator reads what happened, so a tool that
/// carries many operations has to be distinguishable there. Two rows through
/// one executor render identically without it, while their risk and PII
/// describe different operations.
#[tokio::test]
pub(crate) async fn activity_rows_show_the_operation_a_call_selected() {
    let mut row = sample_row("success", Some("example-secrets"), Some("high"));
    row.tool = Some("read".into());
    row.operation = Some("secrets.reveal".into());
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![row] });
    let state = state_with_audit_reader(audit).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);

    let (status, body) = body_of(app, "/activity/rows").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("secrets.reveal"),
        "the operation must appear beside the tool it qualifies"
    );
}

/// The drawer is the detail view an investigator opens from a row, so it has
/// to name the operation too.
#[tokio::test]
pub(crate) async fn activity_drawer_shows_the_operation() {
    let mut row = sample_row("denied", Some("example-secrets"), Some("high"));
    row.tool = Some("read".into());
    row.operation = Some("secrets.reveal".into());
    let id = row.id;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![row] });
    let state = state_with_audit_reader(audit).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);

    let (status, body) = body_of(app, &format!("/activity/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("secrets.reveal"),
        "the drawer must name the operation the row recorded"
    );
}

/// A tool classified by name alone renders exactly as it always did.
#[tokio::test]
pub(crate) async fn activity_rows_omit_an_absent_operation() {
    let mut row = sample_row("success", Some("example-messages"), Some("low"));
    row.tool = Some("send".into());
    row.operation = None;
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: vec![row] });
    let state = state_with_audit_reader(audit).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);

    let (status, body) = body_of(app, "/activity/rows").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("send"));
    assert!(
        !body.contains("Operation this call selected"),
        "an absent operation must render nothing at all"
    );
}
