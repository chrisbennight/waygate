//! Activity saved views, live tail, event compare — split from the
//! monolithic `dashboard_render.rs`; bodies verbatim, cut at the file's
//! own section markers.

use crate::common::*;

// ---- Activity saved views ---------------------------------------------

/// In-memory ActivitySavedViewStore stub mirroring the per-domain
/// shape the scenarios / policy-store stubs use. Holds a Vec of
/// `SavedView` rows behind a tokio Mutex. Mutating methods
/// (`save`, `delete`) are exercised through the dashboard render
/// path indirectly — the `body_of` helper follows redirects
/// without re-issuing GETs at the new URL, so the render tests
/// only need `list` + `get` to drive the page. Calling `save` /
/// `delete` here would only matter for handler-level tests; mark
/// them as implemented (not panic!) so a future test can use the
/// stub end-to-end without re-writing it.
#[derive(Default)]
pub(crate) struct InMemoryActivitySavedViewStore {
    rows: tokio::sync::Mutex<Vec<waygate_dashboard_stores::activity_saved_views::SavedView>>,
}

impl InMemoryActivitySavedViewStore {
    pub(crate) fn seeded(
        seed: Vec<waygate_dashboard_stores::activity_saved_views::SavedView>,
    ) -> Self {
        Self {
            rows: tokio::sync::Mutex::new(seed),
        }
    }
}

#[async_trait::async_trait]
impl waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore
    for InMemoryActivitySavedViewStore
{
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<
        Vec<waygate_dashboard_stores::activity_saved_views::SavedView>,
        waygate_dashboard_stores::activity_saved_views::SavedViewError,
    > {
        let guard = self.rows.lock().await;
        let mut out: Vec<_> = guard
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
    async fn get(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<
        Option<waygate_dashboard_stores::activity_saved_views::SavedView>,
        waygate_dashboard_stores::activity_saved_views::SavedViewError,
    > {
        let guard = self.rows.lock().await;
        Ok(guard
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.name == name)
            .cloned())
    }
    async fn save(
        &self,
        tenant_id: &str,
        name: &str,
        filters: serde_json::Value,
        created_by: Option<&str>,
    ) -> Result<
        waygate_dashboard_stores::activity_saved_views::SavedView,
        waygate_dashboard_stores::activity_saved_views::SavedViewError,
    > {
        // Mirror the Pg impl's SQL-side shallow JSONB merge
        // (`existing || excluded`). On conflict, keys in the
        // existing row survive unless the incoming `filters`
        // overrides them. Stays faithful to the trait contract
        // tests assert against (forward-compat unknown keys
        // preserved on re-save).
        let mut guard = self.rows.lock().await;
        if let Some(existing) = guard
            .iter_mut()
            .find(|r| r.tenant_id == tenant_id && r.name == name)
        {
            let merged_filters = match (&existing.filters, &filters) {
                (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
                    let mut m = left.clone();
                    for (k, v) in right {
                        m.insert(k.clone(), v.clone());
                    }
                    serde_json::Value::Object(m)
                }
                // Non-object existing (or non-object incoming)
                // → take incoming verbatim, matching `jsonb ||`
                // when one side isn't an object.
                _ => filters.clone(),
            };
            existing.filters = merged_filters;
            // COALESCE: created_by stays unless absent.
            if existing.created_by.is_none() {
                existing.created_by = created_by.map(str::to_owned);
            }
            return Ok(existing.clone());
        }
        let row = waygate_dashboard_stores::activity_saved_views::SavedView {
            tenant_id: tenant_id.into(),
            name: name.into(),
            filters,
            created_by: created_by.map(str::to_owned),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        guard.push(row.clone());
        Ok(row)
    }
    async fn delete(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<bool, waygate_dashboard_stores::activity_saved_views::SavedViewError> {
        let mut guard = self.rows.lock().await;
        let before = guard.len();
        guard.retain(|r| !(r.tenant_id == tenant_id && r.name == name));
        Ok(guard.len() < before)
    }
}

pub(crate) fn seeded_saved_view(
    name: &str,
    filters: serde_json::Value,
) -> waygate_dashboard_stores::activity_saved_views::SavedView {
    waygate_dashboard_stores::activity_saved_views::SavedView {
        tenant_id: "default".into(),
        name: name.into(),
        filters,
        created_by: Some("test".into()),
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

pub(crate) async fn state_with_saved_views(
    seed: Vec<waygate_dashboard_stores::activity_saved_views::SavedView>,
) -> Arc<AdminState> {
    // Wire an audit reader too — the activity page renders the
    // saved-views sidebar only when `audit_available`, which
    // reflects `state.observability.audit.enabled()`. An unwired audit reader
    // shows the "audit store not configured" empty state and
    // skips the whole shell.
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: Vec::new() });
    let store: Arc<dyn waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore> =
        Arc::new(InMemoryActivitySavedViewStore::seeded(seed));
    let state = AdminState::new(
        pool,
        None,
        Some(audit),
        AdminState::null_evidence(),
        None,
        None,
        None,
        None,
        "http://127.0.0.1:0".into(),
    );
    Arc::new(state.with_activity_saved_views(Some(store)))
}

/// Saved-views sidebar section renders when the store is wired,
/// even with zero rows (operator can save their first view).
/// Save form + CSRF input present.
#[tokio::test]
pub(crate) async fn activity_saved_views_section_renders_when_store_wired() {
    let state = state_with_saved_views(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Saved views"), "section heading missing");
    assert!(
        body.contains("No saved views yet"),
        "empty-state copy missing",
    );
    assert!(
        body.contains(r#"action="/admin/t/default/activity/saved_views""#),
        "Save form action missing or not tenant-prefixed",
    );
    assert!(
        body.contains(r#"name="csrf""#),
        "CSRF hidden input missing in Save form",
    );
}

/// Section hides entirely when the store is unwired (empty_state).
#[tokio::test]
pub(crate) async fn activity_saved_views_section_hidden_when_store_unwired() {
    let app = dashboard_router(empty_state().await, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Saved views"),
        "saved-views heading should NOT render without a store",
    );
}

/// Seeded views render in the sidebar with Delete forms.
#[tokio::test]
pub(crate) async fn activity_saved_views_section_renders_seeded_rows() {
    let view = seeded_saved_view(
        "high-risk-denials",
        serde_json::json!({"outcome":"denied","risk":"high"}),
    );
    let state = state_with_saved_views(vec![view]).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("high-risk-denials"),
        "seeded view name missing from sidebar",
    );
    assert!(
        body.contains(r#"action="/admin/t/default/activity/saved_views/high-risk-denials/delete""#),
        "Delete form action missing or not tenant-prefixed",
    );
}

/// `?load_view=<name>` against a wired store applies the saved
/// view's filters AND surfaces the Loaded-view badge.
#[tokio::test]
pub(crate) async fn activity_load_view_applies_saved_filters() {
    let view = seeded_saved_view(
        "high-risk-denials",
        serde_json::json!({"outcome":"denied","risk":"high"}),
    );
    let state = state_with_saved_views(vec![view]).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity?load_view=high-risk-denials").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Loaded view:"),
        "loaded-view badge missing on resolved load_view",
    );
    assert!(
        body.contains("<code>high-risk-denials</code>"),
        "loaded-view badge name missing",
    );
    // The form `<select>` for Outcome should have the "denied"
    // option selected (matches `from_saved_filters` decode of
    // the stored JSON).
    assert!(
        body.contains(r#"value="denied" selected"#),
        "loaded view's outcome=denied not reflected in form select",
    );
}

/// Regression: Save must preserve unknown JSON keys via
/// read-modify-write merge so a re-save by an older dashboard
/// version doesn't silently drop forward-compat fields. Seeds
/// a view with an unknown `future_facet` key, POSTs a
/// known-fields-only re-save, and asserts the unknown key
/// still sits in the row after.
#[tokio::test]
pub(crate) async fn activity_save_view_preserves_unknown_filter_keys_on_resave() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore;

    let seed = seeded_saved_view(
        "compat-test",
        serde_json::json!({
            "outcome": "denied",
            "future_facet": "something-only-newer-versions-recognise"
        }),
    );
    let stub = Arc::new(InMemoryActivitySavedViewStore::seeded(vec![seed]));
    let stub_for_check = stub.clone();
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    let audit: Arc<dyn AuditReader> = Arc::new(MemoryAudit { rows: Vec::new() });
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
        .with_activity_saved_views(Some(
            stub as Arc<dyn waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore>,
        )),
    );
    let app = dashboard_router(state, DashboardAuth::Disabled);

    let body = "csrf=dev-csrf&name=compat-test&outcome=success&risk=&server=&principal=&category=&pii=&since=";
    let req = Request::builder()
        .method("POST")
        .uri("/t/default/activity/saved_views")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_redirection(),
        "expected redirect after save, got {}",
        resp.status(),
    );

    let row = stub_for_check
        .get("default", "compat-test")
        .await
        .unwrap()
        .expect("seeded view should still exist after re-save");
    let obj = row.filters.as_object().expect("filters should be object");
    assert_eq!(
        obj.get("outcome").and_then(|v| v.as_str()),
        Some("success"),
        "known field should reflect the re-save",
    );
    assert_eq!(
        obj.get("future_facet").and_then(|v| v.as_str()),
        Some("something-only-newer-versions-recognise"),
        "unknown forward-compat key must survive read-modify-write",
    );
}

/// Unknown view name silently falls through to the no-loaded
/// state (no banner, no crash).
#[tokio::test]
pub(crate) async fn activity_load_view_unknown_name_falls_through_silently() {
    let state = state_with_saved_views(Vec::new()).await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity?load_view=nope").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Loaded view:"),
        "loaded-view badge should not render for an unknown name",
    );
}

// ---- Live tail --------------------------------------------------------

/// Without `?live=1`, the toggle reads "Live tail: off" and
/// the tbody carries NO htmx polling attributes.
#[tokio::test]
pub(crate) async fn activity_live_tail_off_by_default() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Live tail: off"),
        "off-state toggle label missing",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/activity?live=1""#),
        "off-state toggle link should activate live mode",
    );
    let tbody_slice = body
        .split("activity-tbody")
        .nth(1)
        .unwrap_or("")
        .split("</tbody>")
        .next()
        .unwrap_or("");
    assert!(
        !tbody_slice.contains("hx-trigger"),
        "tbody must not poll when live tail is off",
    );
}

/// With `?live=1`, the toggle reads "Live tail: on" and the
/// tbody gains `hx-get` + `hx-trigger="every Ns"` pointing at
/// `/activity/rows`.
#[tokio::test]
pub(crate) async fn activity_live_tail_on_wires_htmx_polling() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity?live=1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Live tail: on"),
        "on-state toggle label missing",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/activity""#),
        "on-state toggle link should clear live mode",
    );
    let tbody_slice = body
        .split("activity-tbody")
        .nth(1)
        .unwrap_or("")
        .split("</tbody>")
        .next()
        .unwrap_or("");
    assert!(
        tbody_slice.contains(r#"hx-get="/admin/t/default/activity/rows""#),
        "tbody should poll the /activity/rows fragment",
    );
    assert!(
        tbody_slice.contains(r#"hx-trigger="every 5s""#),
        "tbody should auto-refresh every 5s",
    );
    // The live tail PREPENDS a highlighted delta of only-newer rows
    // (afterbegin) instead of re-rendering the whole tbody (innerHTML), sending
    // the current top row id as `since_id` via hx-vals.
    assert!(
        tbody_slice.contains(r#"hx-swap="afterbegin show:none""#),
        "tbody should prepend the delta (afterbegin), not replace its contents",
    );
    assert!(
        tbody_slice.contains("hx-vals") && tbody_slice.contains("since_id:"),
        "tbody should send the top row id as since_id via hx-vals so the poll \
         returns only newer rows",
    );
}

/// Live tail preserves active filters through the toggle URL
/// AND through the polled rows endpoint, so a tailing operator
/// stays inside their filter scope.
#[tokio::test]
pub(crate) async fn activity_live_tail_preserves_filters_in_toggle_and_poll_urls() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity?outcome=denied&risk=high&live=1").await;
    assert_eq!(status, StatusCode::OK);
    // Facet links emit one param at a time, so the only place
    // a multi-param `outcome=denied&risk=high` appears in the
    // body is the toggle URL or the poll URL. Cheapest
    // assertion: that substring exists at all in some rendered
    // attribute (askama escapes `&` → `&amp;` in attrs).
    // Askama renders `&` in attributes as the numeric entity
    // `&#38;` (verified empirically on this codebase) rather
    // than `&amp;`. Accept both for robustness against a
    // future askama version that switches.
    assert!(
        body.contains("outcome=denied&#38;risk=high")
            || body.contains("outcome=denied&amp;risk=high")
            || body.contains("outcome=denied&risk=high"),
        "toggle/poll URL should carry the multi-filter combo",
    );
    let toggle_off_link_present = body.contains(
        r#"<a href="/admin/t/default/activity?outcome=denied&#38;risk=high" class="live-tail-toggle on""#,
    ) || body.contains(
        r#"<a href="/admin/t/default/activity?outcome=denied&amp;risk=high" class="live-tail-toggle on""#,
    );
    assert!(
        toggle_off_link_present,
        "toggle-off link should be the live-tail-toggle on link with filters preserved minus `live`",
    );
    assert!(
        body.contains(r#"hx-get="/admin/t/default/activity/rows?outcome=denied&#38;risk=high""#)
            || body.contains(
                r#"hx-get="/admin/t/default/activity/rows?outcome=denied&amp;risk=high""#
            ),
        "poll URL should include the filter suffix",
    );
}

/// Garbage `?live=garbage` does NOT enable live mode (cleaned
/// to None). Protects against a stale bookmark or a copy-paste
/// from a future version inadvertently starting an unwanted
/// poller.
#[tokio::test]
pub(crate) async fn activity_live_tail_garbage_value_falls_through_to_off() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity?live=yes-please").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Live tail: off"),
        "garbage live value should not enable live mode",
    );
}

// ---- Event compare ------------------------------------------------------

/// Normal mode (no `?compare=`): each row gets a Pick link
/// that pins THIS row id via `?compare=<id>`. No
/// cancel-banner, no pinned marker.
#[tokio::test]
pub(crate) async fn activity_compare_picker_renders_pick_links_when_not_pinning() {
    let (state, _id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let (status, body) = body_of(app, "/t/default/activity").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(">Pick</a>"),
        "Pick links should render in normal mode",
    );
    assert!(
        body.contains(r#"href="/admin/t/default/activity?compare="#),
        "Pick href should point at /activity?compare=<row_id>",
    );
    assert!(
        !body.contains("Compare picker active"),
        "cancel banner should not render without ?compare=",
    );
    assert!(
        !body.contains("Compare with pinned"),
        "compare-with-pinned link should not render without ?compare=",
    );
}

/// Compare-picking mode (`?compare=<pinned>`): cancel banner
/// renders, the pinned row shows a marker, every other row
/// renders a "Compare with pinned" link pointing at
/// /activity/compare?a=<pinned>&b=<row_id>.
#[tokio::test]
pub(crate) async fn activity_compare_picker_renders_pinned_state_when_pinning() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let url = format!("/t/default/activity?compare={deny_id}");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Compare picker active"),
        "cancel banner should render in compare-picking mode",
    );
    let deny_id_str = deny_id.to_string();
    assert!(
        body.contains(&format!("<code>{deny_id_str}</code>")),
        "cancel banner should name the pinned event id",
    );
    assert!(
        body.contains("Compare with pinned"),
        "compare-with-pinned links should render for non-pinned rows",
    );
    // Pinned row marker present.
    assert!(
        body.contains("pinned</span>"),
        "pinned row should render its marker",
    );
    // Compare link base contains the pinned id.
    assert!(
        body.contains(&format!(
            "/admin/t/default/activity/compare?a={deny_id_str}&amp;b="
        )) || body.contains(&format!(
            "/admin/t/default/activity/compare?a={deny_id_str}&#38;b="
        )) || body.contains(&format!(
            "/admin/t/default/activity/compare?a={deny_id_str}&b="
        )),
        "compare link href should embed the pinned id",
    );
}

/// `/activity/compare?a=<id>&b=<id>` renders the side-by-
/// side table when both events resolve. Differing fields
/// carry a `diff` class so an operator can scan changes.
#[tokio::test]
pub(crate) async fn activity_compare_page_renders_diff_rows_for_differing_events() {
    let (state, deny_id) = state_with_audit().await;
    // state_with_audit seeds three rows; pick the deny + step_up
    // pair (different outcome, different action).
    let app = dashboard_router(state, DashboardAuth::Disabled);
    // Find a second id by listing — re-use the audit reader
    // through the page first.
    let (_, list_body) = body_of(app.clone(), "/t/default/activity").await;
    // Pull one OTHER data-audit-id from the listing.
    let other_id: String = list_body
        .split(r#"data-audit-id=""#)
        .filter_map(|s| s.split('"').next())
        .find(|s| s.len() == 36 && *s != deny_id.to_string())
        .expect("test fixture should seed at least two events")
        .to_owned();
    let url = format!("/t/default/activity/compare?a={deny_id}&b={other_id}");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK, "compare page should 200");
    assert!(body.contains("Compare events"), "page title missing",);
    assert!(body.contains("Outcome"), "field label should render",);
    // The two seeded rows differ on at least one field, so the
    // diff class must appear at least once.
    assert!(
        body.contains(r#"<tr class="diff">"#),
        "diff highlight class should mark differing rows",
    );
}

/// Regression: compare state must thread through the htmx
/// live-tail poll URL so the polled rows fragment renders
/// "Compare with pinned" links instead of reverting to plain
/// "Pick". Exercises by requesting `?compare=<id>&live=1`
/// and asserting the poll URL includes `compare=<id>`.
#[tokio::test]
pub(crate) async fn activity_compare_picker_threads_through_live_tail_poll_url() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let url = format!("/t/default/activity?compare={deny_id}&live=1");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    // Poll URL is hx-get on the tbody; must carry `compare=<id>`
    // so the swapped fragment knows we're in compare mode.
    let deny_id_str = deny_id.to_string();
    let needle_amp = format!("compare={deny_id_str}");
    assert!(
        body.contains("hx-get=\"/admin/t/default/activity/rows?"),
        "polling tbody should include an hx-get URL",
    );
    assert!(
        body.contains(&needle_amp),
        "poll URL should carry compare=<id>",
    );
}

/// Regression: `/activity/compare` must not surface an event
/// whose `tenant_id` differs from the active tenant — a
/// hand-crafted URL pointing at another tenant's known UUID
/// should hit the empty-state, not leak the row's audit detail.
#[tokio::test]
pub(crate) async fn activity_compare_page_rejects_cross_tenant_id() {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // Seed two rows: one in tenant "default" (the dev synthetic
    // principal's tenant), one in tenant "other".
    let in_tenant = sample_row("denied", Some("example-messages"), Some("high"));
    let in_tenant_id = in_tenant.id;
    let mut foreign = sample_row("success", Some("example-observability"), Some("low"));
    foreign.tenant_id = "other".into();
    let foreign_id = foreign.id;
    let rows = vec![in_tenant, foreign];
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
    let url = format!("/t/default/activity/compare?a={in_tenant_id}&b={foreign_id}");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("couldn&#39;t be loaded") || body.contains("couldn't be loaded"),
        "cross-tenant id should fall through to the empty state",
    );
    // The foreign row's outcome ("success") would render in the
    // table if the tenant check were skipped. Assert it ISN'T
    // anywhere in the rendered compare table.
    assert!(
        !body.contains(r#"<tr class="diff">"#),
        "no diff table should render when a tenant check fails",
    );
}

/// Compare page falls through to a friendly empty state when
/// one or both ids don't resolve (handcrafted URL across tenants
/// or after retention prune).
#[tokio::test]
pub(crate) async fn activity_compare_page_renders_empty_state_when_ids_dont_resolve() {
    let (state, deny_id) = state_with_audit().await;
    let app = dashboard_router(state, DashboardAuth::Disabled);
    let url =
        format!("/t/default/activity/compare?a={deny_id}&b=00000000-0000-0000-0000-000000000000");
    let (status, body) = body_of(app, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("couldn&#39;t be loaded") || body.contains("couldn't be loaded"),
        "expected empty-state copy when an id doesn't resolve",
    );
    assert!(
        !body.contains(r#"<tr class="diff">"#),
        "no diff rows should render in the empty state",
    );
}
