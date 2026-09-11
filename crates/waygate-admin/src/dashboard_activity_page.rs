//! Activity page — split out of `dashboard.rs` into the sibling
//! router-per-domain pattern; bodies verbatim. Routes stay mounted
//! by `dashboard::page_routes`, unchanged.

use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Extension;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_oidc::Principal;
use waygate_storage::AuditRow;

use super::dashboard::*;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::{format_ts_abs, format_ts_rel};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ActivityFilters {
    #[serde(default)]
    pub(crate) outcome: Option<String>,
    #[serde(default)]
    pub(crate) risk: Option<String>,
    #[serde(default)]
    pub(crate) server: Option<String>,
    #[serde(default)]
    pub(crate) principal: Option<String>,
    /// Filter on the audit row's `category` column
    /// (migration `0006_audit_category.sql`). Empty/unknown ⇒
    /// no filter. Single-select (the audit row has one
    /// category per event).
    #[serde(default)]
    pub(crate) category: Option<String>,
    /// Filter on the `pii` flag. `"true"` / `"false"` /
    /// anything else (including empty) ⇒ no filter. Rows whose
    /// `pii` column is NULL (non-tool-call events or
    /// pre-`0005_audit_pii.sql` rows) are excluded by EITHER
    /// non-empty value.
    #[serde(default)]
    pub(crate) pii: Option<String>,
    /// Relative time-window. `15m | 1h | 24h | 7d | 30d`.
    /// Empty/unknown ⇒ no filter; the page is a browser, not
    /// an API, so unparseable values are silently dropped
    /// rather than 400-ing.
    #[serde(default)]
    pub(crate) since: Option<String>,
    #[serde(default)]
    pub(crate) after_id: Option<Uuid>,
    /// Live-tail prepend cursor. The polling tbody sends the id of its
    /// current top (newest) row via `hx-vals`; the `/activity/rows` fragment
    /// then returns ONLY rows newer than this (id > since_id), rendered as a
    /// highlighted prepend delta with no load-more row — instead of the old
    /// 5s full-`innerHTML` re-render. A `String` (not `Uuid`) so an empty /
    /// malformed value from an empty feed deserialises cleanly to "no delta"
    /// rather than 400-ing the poll; parsed leniently via `since_id_uuid`.
    #[serde(default)]
    pub(crate) since_id: Option<String>,
    /// Name of a saved view to load. When set AND the
    /// saved-views store is wired AND the view exists, the
    /// activity-page handler overrides every other filter field
    /// with the view's stored filters (matches the playground
    /// `?load=<name>` pattern). The operator sees a "Loaded
    /// view: X" badge and can tweak + re-save. Unknown name /
    /// store unwired ⇒ the field is ignored and the page renders
    /// from the other URL params; no load-miss banner (the
    /// activity sidebar's empty-state copy already explains it).
    #[serde(default)]
    pub(crate) load_view: Option<String>,
    /// Live-tail toggle. `"1"` ⇒ the activity page
    /// wires `hx-trigger="every Ns"` onto the rows tbody so an
    /// operator on-call can watch the audit feed update in
    /// place. Anything else (default) renders the page static
    /// (the prior always-static behaviour). Toggle is URL-driven so an
    /// operator can bookmark "always-on tail for this filter
    /// combo" or share it via Slack without a stateful
    /// session preference.
    #[serde(default)]
    pub(crate) live: Option<String>,
    /// Pinned event id for the compare picker. When set,
    /// each row on the activity page renders a "Compare with
    /// pinned" link → `/activity/compare?a=<pinned>&b=<row_id>`,
    /// and a banner offers a cancel link. URL-driven so the
    /// pinned state is bookmarkable + survives a refresh
    /// without client-side storage; the same selection model
    /// the live-tail toggle uses.
    #[serde(default)]
    pub(crate) compare: Option<Uuid>,
    /// Group-by-trace toggle. `"trace"` ⇒ the feed clusters rows
    /// sharing a `trace_id` (one agent action's fan-out) into banded groups
    /// with a fan-out count on the head row. Anything else (default) renders
    /// the flat chronological feed. URL-driven like the live-tail toggle so
    /// an operator can bookmark / share the grouped view.
    #[serde(default)]
    pub(crate) group: Option<String>,
}

impl ActivityFilters {
    /// True when the group-by-trace view is active.
    fn group_by_trace(&self) -> bool {
        self.group.as_deref() == Some("trace")
    }

    /// The live-tail prepend cursor parsed leniently — `Some(id)` only
    /// when `since_id` holds a valid UUID, else `None` (empty feed / garbage ⇒
    /// fall back to a normal page render rather than 400-ing the poll).
    fn since_id_uuid(&self) -> Option<Uuid> {
        self.since_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    pub(crate) fn cleaned(self) -> Self {
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
        // `since` stays canonical so the matcher / query-suffix / form
        // `<option selected>` / active chip never drift. An absent or
        // unrecognised value defaults to a bounded 24h window rather
        // than dropping to `None` (all-time — an unbounded table
        // scan). `ALL_TIME_SINCE` ("all") is the explicit opt-in to
        // the full retained history and is preserved verbatim.
        // `since` is therefore always `Some(...)` after cleaning.
        let since = Some(match norm(self.since) {
            Some(s) if s == ALL_TIME_SINCE || is_valid_since(&s) => s,
            _ => DEFAULT_SINCE.to_owned(),
        });
        // Same posture for `pii`. The matcher only acts on
        // `"true"` / `"false"` (anything else is silently no-op),
        // but the un-cleaned value still threaded through
        // `to_query_suffix`, the form `<option selected>`, and the
        // active chip row — letting `pii=garbage` render as a live
        // filter that wasn't actually filtering. Same root cause
        // as the `since` case above, fixed the same way.
        let pii = norm(self.pii).filter(|s| is_valid_pii(s));
        Self {
            outcome: norm(self.outcome),
            risk: norm(self.risk),
            server: norm(self.server),
            principal: norm(self.principal),
            category: norm(self.category),
            pii,
            since,
            after_id: self.after_id,
            since_id: norm(self.since_id),
            load_view: norm(self.load_view),
            // Cleaned to canonical `"1"` / `None`.
            // Anything else (including legacy/garbage values)
            // collapses to off, so a bookmarked `?live=garbage`
            // doesn't surprise an operator by starting a 5s
            // poller against their browser.
            live: norm(self.live).filter(|s| s == "1"),
            compare: self.compare,
            // Canonicalise to `"trace"` / None so a bookmarked
            // `?group=garbage` doesn't render a half-on grouped view.
            group: norm(self.group).filter(|s| s == "trace"),
        }
    }

    /// Rebuild from a saved view's stored `filters`
    /// JSON. Unknown / out-of-shape keys are silently dropped
    /// (forward-compat); empty strings become `None`. `after_id`
    /// is NOT carried — pagination cursors don't belong in a
    /// saved view (operator wants today's events, not the
    /// position they were at last time).
    fn from_saved_filters(j: &serde_json::Value) -> Self {
        fn str_field(j: &serde_json::Value, k: &str) -> Option<String> {
            j.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
        }
        Self {
            outcome: str_field(j, "outcome"),
            risk: str_field(j, "risk"),
            server: str_field(j, "server"),
            principal: str_field(j, "principal"),
            category: str_field(j, "category"),
            pii: str_field(j, "pii"),
            since: str_field(j, "since"),
            after_id: None,
            since_id: None,
            load_view: None,
            live: None,
            compare: None,
            // group-by-trace is a view mode, not a saved filter.
            group: None,
        }
        .cleaned()
    }

    /// Serialise the active filters into the shape
    /// `from_saved_filters` round-trips. `after_id` + `load_view`
    /// are intentionally excluded — the first is a cursor, the
    /// second is the load mechanism itself.
    fn to_saved_filters(&self) -> serde_json::Value {
        serde_json::json!({
            "outcome": self.outcome.clone().unwrap_or_default(),
            "risk": self.risk.clone().unwrap_or_default(),
            "server": self.server.clone().unwrap_or_default(),
            "principal": self.principal.clone().unwrap_or_default(),
            "category": self.category.clone().unwrap_or_default(),
            "pii": self.pii.clone().unwrap_or_default(),
            "since": self.since.clone().unwrap_or_default(),
        })
    }

    /// URL-encoded query string fragment (starts with `&...`) for active
    /// filters only. Used by the "load more" button to preserve the filter
    /// state across htmx pagination hops.
    pub(crate) fn to_query_suffix(&self) -> String {
        let mut s = String::new();
        if let Some(v) = &self.outcome {
            s.push_str(&format!("&outcome={}", urlencode(v)));
        }
        if let Some(v) = &self.risk {
            s.push_str(&format!("&risk={}", urlencode(v)));
        }
        if let Some(v) = &self.server {
            s.push_str(&format!("&server={}", urlencode(v)));
        }
        if let Some(v) = &self.principal {
            s.push_str(&format!("&principal={}", urlencode(v)));
        }
        if let Some(v) = &self.category {
            s.push_str(&format!("&category={}", urlencode(v)));
        }
        if let Some(v) = &self.pii {
            s.push_str(&format!("&pii={}", urlencode(v)));
        }
        // The default 24h window is the implicit baseline — omit it from
        // derived URLs (chips, live-tail / compare / pagination fragments) so
        // they stay clean and a param-free URL round-trips back to the default
        // via `cleaned()`. Non-default windows (including the explicit `all`
        // escape hatch) are carried verbatim.
        if let Some(v) = self.since.as_deref().filter(|s| *s != DEFAULT_SINCE) {
            s.push_str(&format!("&since={}", urlencode(v)));
        }
        // `compare` must thread through every htmx fragment URL
        // (live-tail polling + load-more pagination) so newly
        // swapped rows continue rendering "Compare with pinned"
        // links instead of reverting to plain "Pick".
        // `to_saved_filters` still omits compare (it's per-session
        // UI state, not a bookmarkable filter), so saved views
        // aren't polluted.
        if let Some(v) = &self.compare {
            s.push_str(&format!("&compare={v}"));
        }
        // Thread the group toggle through live-tail + load-more URLs so
        // paginated/refreshed fragments keep grouping.
        if let Some(v) = &self.group {
            s.push_str(&format!("&group={}", urlencode(v)));
        }
        s
    }

    /// Parse `since` into an absolute lower-bound
    /// timestamp. Returns `None` for empty values so
    /// `matches()` can short-circuit. The closed set is small
    /// on purpose — operators get a known menu of windows
    /// (matching the filter-bar `<select>`), not arbitrary
    /// duration strings the parser would have to police.
    ///
    /// The cleaner drops any `since` value that doesn't match the
    /// allowlist, so by the time this runs the value (if `Some`) is
    /// always parseable.
    pub(crate) fn since_lower_bound(&self) -> Option<OffsetDateTime> {
        match self.since.as_deref() {
            // Explicit opt-in to the full retained history (no lower bound).
            Some(s) if s == ALL_TIME_SINCE => None,
            // A recognised window from the allowlist.
            Some(s) => since_duration(s).map(|dur| OffsetDateTime::now_utc() - dur),
            // `cleaned()` always populates `since`, so `None` only reaches here
            // for an un-cleaned filter — default to the bounded window, never
            // all-time.
            None => since_duration(DEFAULT_SINCE).map(|dur| OffsetDateTime::now_utc() - dur),
        }
    }
}

/// The default Activity window applied when the request carries no
/// (or an unrecognised) `since`. Bounding the default load to 24h turns the
/// page's aggregate queries (facets / tool-stats) from all-time table scans
/// into index-served range scans — measured `tool_stats` 30.6s → 17ms. The
/// data is retained unbounded; only the default *view* is windowed.
pub(crate) const DEFAULT_SINCE: &str = "24h";

/// Explicit "no lower bound" escape hatch. Survives `cleaned()` and resolves to
/// `since = None` (unbounded) in [`ActivityFilters::since_lower_bound`], so an
/// operator can still ask for the full retained history on purpose.
pub(crate) const ALL_TIME_SINCE: &str = "all";

/// Single source of truth for the
/// `since` allowlist. Both [`ActivityFilters::cleaned`]
/// (drop-at-the-edge) and [`ActivityFilters::since_lower_bound`]
/// (parse-for-the-matcher) go through this so a future menu
/// addition / removal can't drift them apart.
fn since_duration(s: &str) -> Option<time::Duration> {
    match s {
        "15m" => Some(time::Duration::minutes(15)),
        "1h" => Some(time::Duration::hours(1)),
        "24h" => Some(time::Duration::hours(24)),
        "7d" => Some(time::Duration::days(7)),
        "30d" => Some(time::Duration::days(30)),
        _ => None,
    }
}

fn is_valid_since(s: &str) -> bool {
    since_duration(s).is_some()
}

/// The matcher reads `pii` as a
/// three-state {true, false, ignore}. The cleaner uses this
/// helper to drop anything outside `{"true", "false"}` so the
/// form / chip / matcher all see `None` together for bogus
/// values.
fn is_valid_pii(s: &str) -> bool {
    matches!(s, "true" | "false")
}

impl ActivityFilters {
    /// Build the storage-layer [`waygate_storage::AuditQuery`] pushed down
    /// into SQL. Maps the cleaned UI filter fields to predicate columns;
    /// `since` is resolved to an absolute lower bound via the same allowlist
    /// the form uses. The predicate lives in the query
    /// (`AuditReader::query_events`) rather than a page-local `matches`
    /// method, so the feed searches the whole table, not just the
    /// most-recent page. The semantics are preserved
    /// exactly — see [`waygate_storage::AuditQuery::matches`], the in-memory
    /// twin the test fake uses.
    fn to_audit_query(&self, tenant: &str) -> waygate_storage::AuditQuery {
        waygate_storage::AuditQuery {
            // Security scope: always the active principal's tenant (passed in
            // by the caller). A tenant-scoped Activity page and its facet
            // rail must never read another tenant's audit rows.
            tenant_id: Some(tenant.to_owned()),
            server: self.server.clone(),
            outcome: self.outcome.clone(),
            // The Activity filter bar has no "not this outcome" control.
            outcome_ne: None,
            risk_level: self.risk.clone(),
            category: self.category.clone(),
            principal_substr: self.principal.clone(),
            // `cleaned()` already constrains `pii` to "true"/"false"; the
            // catch-all is defensive.
            pii: self.pii.as_deref().and_then(|p| match p {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            }),
            since: self.since_lower_bound(),
            until: None,
            // The Activity filter bar has no policy-id control (that's the
            // Decision Log's `/api/v1/audit/decisions?policy_id=` surface).
            policy_id: None,
            // The Activity page filters by the single `category` facet above,
            // not the decision-class set (that's the Decision Log's surface),
            // so the multi-category constraint stays empty here.
            categories: Vec::new(),
            // The Activity feed shows all evidence rows, including the
            // fail-closed `pre_call` rows; only the Decision Log excludes them.
            reason_ne: None,
        }
    }
}

/// One row in the "Top tools" reliability panel — per-(server, tool)
/// call volume, execution-error + denial counts (with a precomputed error
/// rate), and p95 latency. A table-wide aggregate within the active filter
/// window, decoupled from the paged event list.
struct ToolStatView {
    server: String,
    tool: String,
    total: i64,
    errors: i64,
    denied: i64,
    error_rate_pct: String,
    p95_ms: Option<i64>,
}

/// The activity volume histogram — a row of time buckets stacked by
/// outcome, above the event table. A server-side aggregate (not the paged
/// rows), so it shows the whole window's volume at a glance — the "is
/// anything wrong, and when?" triage signal.
struct HistogramView {
    bars: Vec<HistogramBar>,
    /// e.g. "last 24h" — the bounded window the buckets cover.
    window_label: String,
    /// Total events across all bars (after pre_call exclusion).
    total: i64,
    /// Busiest bucket's event count — the value full bar height maps to.
    /// Rendered as the y-axis max label so "full height" has a number
    /// and a spike is readable against it.
    peak: i64,
}

/// One time bucket: a stacked bar whose segments are per-outcome counts.
struct HistogramBar {
    /// Bucket start time, formatted for the bar tooltip.
    label: String,
    total: i64,
    segments: Vec<HistSegment>,
}

/// One outcome band within a bar. `height_pct` is the band height as a
/// percentage of the tallest bucket, so bar heights compare across the row.
struct HistSegment {
    class: &'static str,
    outcome: String,
    count: i64,
    height_pct: i64,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    audit_available: bool,
    events: Vec<ActivityEventView>,
    next_after_id: Option<Uuid>,
    filter_qs: String,
    /// Per-facet value counts computed from the
    /// fetched page (pre-`matches()` filter). Each
    /// [`FacetGroup`] gets a sidebar section; values within a
    /// group sort by count desc then value asc. Counts
    /// represent only the rows on the current page —
    /// pagination shifts them, by design: facets are a
    /// scoping aid for the visible slice, not a global
    /// histogram (which would need a new SQL aggregate per
    /// click).
    facets: Vec<FacetGroup>,
    /// Per-tool reliability stats (top N by volume) for the active
    /// filter window — a separate aggregate, not the paged rows.
    tool_stats: Vec<ToolStatView>,
    /// The activity volume histogram for the active window. `None`
    /// when no audit store is configured or the window is empty.
    histogram: Option<HistogramView>,
    /// Active-filter chip row above the event table.
    /// Each chip names the filter dimension + selected value
    /// and links to the same page with that filter cleared,
    /// so an operator can drop a single facet without
    /// rebuilding the whole URL.
    active_filter_chips: Vec<ActiveFilterChip>,
    /// Selected `since` window so the filter `<select>` keeps
    /// its current value across full-page-reload form submits
    /// (the form GETs the parent page on every filter change;
    /// the `<option selected>` branches on this field).
    since: Option<String>,
    /// Selected `category` so the category `<select>` keeps
    /// its value across form submits.
    category: Option<String>,
    /// Selected `pii` so the PII `<select>` keeps its value.
    pii: Option<String>,
    /// Current Server text-input value so the field re-populates
    /// after the form's GET round-trip. Without this the input
    /// would render empty on every reload and the operator would
    /// have to retype the server name to keep filtering on it.
    server: Option<String>,
    /// Current Principal text-input value — same reasoning as
    /// `server`.
    principal: Option<String>,
    /// Current Outcome selection so the `<select>` re-renders
    /// with the right `<option selected>` after the form's GET
    /// round-trip. The filter form is a plain GET (not an
    /// htmx-on-change swap against rows only), so missing this
    /// field would cause a Filter submit to silently drop the
    /// active `outcome=...` filter. Mirror of the `category` /
    /// `pii` / `since` selects that already had the binding.
    outcome: Option<String>,
    /// Current Risk selection — same reasoning as `outcome`.
    risk: Option<String>,
    /// Rendered saved-views sidebar rows. Empty when
    /// the store is unwired or has no rows; the template hides
    /// the entire section in that case. Sort order is alpha by
    /// name (server-side, in `ActivitySavedViewStore::list`).
    saved_views: Vec<SavedViewRow>,
    /// `true` when the saved-views store is wired —
    /// drives whether the Save form + sidebar render at all.
    /// Independent of `saved_views.len()` so an empty store
    /// still shows the Save form (operator can save their first
    /// view).
    saved_views_configured: bool,
    /// Name of the currently-loaded view (from
    /// `?load_view=<name>`), when it resolved. The template
    /// surfaces "Loaded view: <name>" + makes Save default to
    /// the same name (overwrite-in-place is the common operator
    /// flow). `None` when no `?load_view=` was set or the name
    /// didn't resolve.
    loaded_view_name: Option<String>,
    /// `true` when `?live=1` is in the URL. Drives the
    /// htmx auto-refresh attributes on the rows tbody (poll
    /// every `live_tail_interval_secs` against `/activity/rows`).
    live_tail: bool,
    /// Relative href that toggles live tail mode.
    /// `/activity?<filters>&live=1` when off; `/activity?<filters>`
    /// (without `live`) when on. URL-driven toggle keeps the
    /// state bookmarkable + shareable; no client-side state.
    live_toggle_url: String,
    /// Poll cadence in seconds. Conservative 5s default
    /// — fast enough that an on-call operator sees new events
    /// within the same glance, slow enough that a tab left
    /// open all day doesn't hammer the audit_log SELECT path.
    /// Adjustable from the same template binding so a future
    /// per-tenant or env override doesn't require a template
    /// refactor.
    live_tail_interval_secs: u32,
    /// URL the polling tbody points at — the existing
    /// `/activity/rows` fragment endpoint with the active
    /// filter suffix appended (so the polled fragment honours
    /// the same filters the static page does). Pre-computed
    /// here so the template stays a thin renderer.
    live_tail_rows_url: String,
    /// `true` when `?group=trace` is active — rows are clustered by
    /// trace and the toggle renders "on".
    group_by_trace: bool,
    /// Relative href that toggles the group-by-trace view, preserving
    /// the active filter combo.
    group_toggle_url: String,
    /// Pinned event id when the operator is mid-pick
    /// for compare. Drives the row template's per-row Pick /
    /// "Compare with pinned" link branch + the cancel-compare
    /// banner. `None` ⇒ normal browsing mode.
    compare_pinned_id: Option<Uuid>,
    /// Cancel link that drops the `compare=` param.
    /// Pre-computed so the banner is a thin renderer.
    compare_cancel_url: String,
    /// Relative base for the compare page —
    /// `/admin/t/<tenant>/activity/compare?a=<pinned>&b=`.
    /// The row template appends `<row_id>` to get the final
    /// link. `None` when not in compare-picking mode (which
    /// avoids the template emitting half-built URLs).
    compare_link_base: Option<String>,
    /// Prefix for the row-level "Pick" link in normal
    /// mode. Same shape as the [`ActivityRows`] field —
    /// `/admin/t/<tenant>/activity?<filters>&compare=`. Row
    /// template appends `<row_id>`.
    compare_pick_base: String,
    /// Always `false` on the full page — the included rows template
    /// shares this flag with the live-tail fragment, which sets it true to
    /// highlight prepended delta rows.
    highlight_new: bool,
}

impl ActivityPage {
    /// Include-context delegate: the shared partial this page includes calls
    /// `self.nav_url(...)`, which must resolve on the page struct too. Pure
    /// forward to [`crate::chrome::PageChrome::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        self.chrome.nav_url(path)
    }
}

/// One row in the saved-views sidebar. Mirrors the playground's
/// `ScenarioRow` shape so the template idiom (link + delete form
/// pair) stays consistent across dashboard pages.
struct SavedViewRow {
    /// Operator-friendly name (already validated against
    /// `validate_name` at save time).
    name: String,
    /// URL-encoded form for the Load href + Delete form action.
    name_qs: String,
    /// "—" when the row predates principal capture, else the
    /// saving operator's `sub`.
    created_by_display: String,
    /// Absolute ISO-ish timestamp ("2026-05-31 17:42:01Z") for
    /// the row's `updated_at`.
    updated_at_abs: String,
}

/// A facet sidebar group: one dimension (Outcome, Risk,
/// Category, Server, PII) and its value counts.
struct FacetGroup {
    /// Operator-facing label rendered as the section heading.
    label: &'static str,
    /// URL query-string parameter name (`outcome` / `risk` /
    /// `category` / `server` / `pii`). The template uses this
    /// when constructing the toggle link's `?key=value` part.
    param: &'static str,
    /// Computed values in render order: most-frequent first,
    /// then ascending by value for stable ties.
    values: Vec<FacetValue>,
}

struct FacetValue {
    /// Raw value as stored in the row, used for the visible
    /// label (e.g. `"high"`, `"invocation"`, `"true"`).
    value: String,
    /// URL-encoded form of `value` used
    /// in the facet href's `?key=value` part. Outcome, risk,
    /// category, and PII are controlled enum-like values, but
    /// Server names come from operator-authored
    /// `UpstreamManifest.name` — a name containing `&`, `?`,
    /// `=`, or space would otherwise break the bookmarkable
    /// link. Precomputed in `build_facets` so the template
    /// stays a thin renderer.
    value_qs: String,
    /// Optional display label — used for the `pii=true|false`
    /// case where the raw value isn't operator-friendly.
    /// `None` ⇒ template renders `value` verbatim.
    display: Option<String>,
    /// How many rows in the active time window carry this value
    /// (a table-wide aggregate, not just the fetched page).
    count: usize,
    /// `true` when this value is currently in the filter set
    /// (`ActivityFilters.<param> == Some(value)`); the
    /// template renders the chip with a pressed/active style.
    is_active: bool,
}

/// One chip in the active-filter row. Clicking the chip's
/// `clear_url` reloads the page with that single dimension
/// removed from the query string.
struct ActiveFilterChip {
    label: String,
    /// Relative URL (already tenant-prefixed) carrying every
    /// active filter EXCEPT this one. Empty (`""`) when the
    /// chip is the only active filter — the template treats
    /// that as a link back to the base `/activity` page.
    clear_url: String,
}

#[derive(Template)]
#[template(path = "activity_rows.html")]
struct ActivityRows {
    /// The pagination "load more" link is
    /// rendered inside this fragment and must stay inside the active
    /// tenant prefix when the parent page was loaded under
    /// `/admin/t/<tenant>/activity`. Populated from the fragment
    /// handler's `Option<Extension<TenantContext>>`.
    tenant_ctx: Option<TenantContext>,
    events: Vec<ActivityEventView>,
    next_after_id: Option<Uuid>,
    filter_qs: String,
    /// Pinned event id from the parent page's compare
    /// picker. `None` ⇒ render row "Pick" links; `Some(id)` ⇒
    /// render "Compare with pinned" / pinned-row marker. Mirrors
    /// `ActivityPage.compare_pinned_id` so the row template
    /// branches identically whether rendered as the full page
    /// or as an htmx fragment swap.
    compare_pinned_id: Option<Uuid>,
    /// Same as `ActivityPage.compare_link_base` —
    /// `/admin/t/<tenant>/activity/compare?a=<pinned>&b=` when
    /// in compare mode; `None` otherwise. Row template appends
    /// the row id to build the final href.
    compare_link_base: Option<String>,
    /// Prefix for the row-level "Pick" link in normal
    /// (non-compare) mode. The row template appends `<row_id>`
    /// to get the final href. Always set so the row template
    /// doesn't have to branch on `Option<_>`; harmless when
    /// `compare_pinned_id` is Some (the row template renders
    /// the "Compare with pinned" link path instead).
    /// Shape: `/admin/t/<tenant>/activity?<filters>&compare=`
    /// or `/admin/t/<tenant>/activity?compare=` when no
    /// filters are active.
    compare_pick_base: String,
    /// When true (a live-tail prepend delta), rows render with the
    /// `activity-row--new` highlight class and the empty-state row is
    /// suppressed (an empty delta must not prepend a "No events" row).
    highlight_new: bool,
}

impl ActivityRows {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

struct ActivityEventView {
    id: Uuid,
    ts_abs: String,
    ts_rel: String,
    principal: String,
    server: Option<String>,
    tool: Option<String>,
    /// The operation the call selected, when the tool carries many behind one
    /// name. Without it two calls through the same executor render identically
    /// while their risk and PII may describe different operations.
    operation: Option<String>,
    outcome: String,
    risk: Option<String>,
    /// PII flag mirrored from the audit row's new `pii` column
    /// (migration `0005_audit_pii.sql`). `Some(true)` ⇒ render a PII
    /// chip on the activity row; `None` ⇒ field absent (non-tool-call
    /// event or a pre-migration row). Drawer shows the same on the
    /// detail view.
    pii: Option<bool>,
    /// Event category from the audit row's `category` column
    /// (migration `0006_audit_category.sql`). Renders as a small chip
    /// for non-`invocation` rows so policy reloads / api-key
    /// lifecycle / etc. events are visually distinct from the
    /// tool-call stream. `None` for pre-migration rows; readers
    /// treat that as `invocation`.
    category: Option<String>,
    action_label: String,
    /// Structured subject of the event (migration `0046_audit_target.sql`).
    /// For lifecycle/mutation rows this is the affected key's `sub` (or a
    /// change-request `action_type`), rendered next to the action so the
    /// row reads "ApiKeyMinted · <sub>" instead of leaving "what" only in
    /// `reason`. `None` for tool-call rows (the `server`/`tool` columns
    /// already carry the subject) and pre-migration rows.
    target: Option<String>,
    /// `audit_log.reason` value, exposed so the activity-row template
    /// can distinguish the fail-closed pre-call intent rows
    /// (`reason="pre_call"`, written by
    /// `waygate-mcp::invocation::DefaultInvocationService::record_pre_call`
    /// when `GATEWAY_AUDIT_MODE=fail_closed` and the call is side-effecting)
    /// from regular invocation success rows. Without this the chip
    /// renders as ALLOW and an operator scanning the feed can't tell
    /// the pre-dispatch intent row apart from the post-dispatch outcome
    /// row.
    reason: Option<String>,
    /// The row's `trace_id`, carried so the group-by-trace
    /// view can cluster rows sharing one agent action's fan-out.
    trace_id: Option<String>,
    /// `Some(n)` only on the HEAD row of a trace group with `n` rows in
    /// the current page (group-by-trace mode); renders a "fan-out ×n" badge.
    /// `None` for singletons, trace-less rows, and the ungrouped feed.
    fan_out_count: Option<usize>,
    /// Alternating band index (0/1) tagging which rows belong to the
    /// same multi-row trace group, so adjacent agent actions are visually
    /// distinct. `None` ⇒ render flat (ungrouped / singleton).
    group_band: Option<u8>,
}

pub(crate) async fn activity_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<ActivityFilters>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    // When `?load_view=<name>` resolves against the
    // saved-views store, override every other filter with the
    // saved view's stored filters. URL params lose to a loaded
    // view by design — operator opted in by clicking Load.
    let (filters, loaded_view_name) = match (
        q.load_view.clone(),
        state.dashboard.activity_saved_views.get(),
    ) {
        (Some(ref name), Some(store)) if !name.is_empty() => {
            if waygate_dashboard_stores::activity_saved_views::validate_name(name).is_err() {
                (q.cleaned(), None)
            } else {
                match store.get(&read_tenant, name).await {
                    Ok(Some(v)) => (
                        ActivityFilters::from_saved_filters(&v.filters),
                        Some(v.name),
                    ),
                    Ok(None) => (q.cleaned(), None),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            tenant = %read_tenant,
                            name = name,
                            "activity page: saved_views.get failed; ignoring load_view",
                        );
                        (q.cleaned(), None)
                    }
                }
            }
        }
        _ => (q.cleaned(), None),
    };

    // Run the page's independent reads concurrently. Each future takes its own
    // reader-pool connection, so the page costs one round-trip of the slowest
    // query rather than the serial sum (feed + facets + tool-stats + histogram
    // + saved-views). facets/tool-stats/histogram are table-wide
    // aggregates within the time window (separate queries), not the fetched
    // page — so the rail lists every server/outcome an operator can pivot to,
    // not just the current page's values.
    let saved_views_configured = state.dashboard.activity_saved_views.enabled();
    let saved_views_fut = async {
        let Some(store) = state.dashboard.activity_saved_views.get() else {
            return Vec::new();
        };
        // Hide the saved-views sidebar on a store hiccup (log + empty)
        // rather than 500-ing the whole page for an unrelated failure.
        match store.list(&read_tenant).await {
            Ok(list) => list
                .into_iter()
                .map(saved_view_row)
                .collect::<Vec<SavedViewRow>>(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant = %read_tenant,
                    "activity page: saved_views.list failed",
                );
                Vec::new()
            }
        }
    };
    let ((rows, next_after_id), facets, tool_stats, histogram, saved_views) = tokio::join!(
        fetch_activity_rows(&state, &filters, &read_tenant),
        fetch_activity_facets(&state, &filters, &read_tenant),
        fetch_tool_stats(&state, &filters, &read_tenant),
        fetch_histogram(&state, &filters, &read_tenant),
        saved_views_fut,
    );
    let events = project_events(&rows);
    // Cluster rows by trace_id when the group-by-trace view is active.
    let events = if filters.group_by_trace() {
        group_events_by_trace(events)
    } else {
        events
    };
    let filter_qs = filters.to_query_suffix();
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    // Live-tail URL builders need a borrow that
    // outlives the page-struct construction (which moves
    // `tenant_ctx`). Clone here so both can read the same
    // context.
    let tenant_ctx_for_live = tenant_ctx.clone();
    let active_filter_chips = build_active_filter_chips(&filters, tenant_ctx.as_ref());

    render(&ActivityPage {
        chrome: PageChrome::build(
            &state,
            "Activity",
            "/activity",
            &headers,
            user_principal.map(user_display),
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        audit_available: state.observability.audit.enabled(),
        events,
        next_after_id,
        filter_qs,
        facets,
        tool_stats,
        histogram,
        active_filter_chips,
        since: filters.since.clone(),
        category: filters.category.clone(),
        pii: filters.pii.clone(),
        server: filters.server.clone(),
        principal: filters.principal.clone(),
        outcome: filters.outcome.clone(),
        risk: filters.risk.clone(),
        saved_views,
        saved_views_configured,
        loaded_view_name,
        live_tail: filters.live.is_some(),
        live_toggle_url: build_live_toggle_url(tenant_ctx_for_live.as_ref(), &filters),
        live_tail_interval_secs: LIVE_TAIL_INTERVAL_SECS,
        live_tail_rows_url: build_live_tail_rows_url(tenant_ctx_for_live.as_ref(), &filters),
        group_by_trace: filters.group_by_trace(),
        group_toggle_url: build_group_toggle_url(tenant_ctx_for_live.as_ref(), &filters),
        compare_pinned_id: filters.compare,
        compare_cancel_url: build_compare_cancel_url(tenant_ctx_for_live.as_ref(), &filters),
        compare_link_base: filters
            .compare
            .map(|a| build_compare_link_base(tenant_ctx_for_live.as_ref(), a)),
        compare_pick_base: build_compare_pick_base(tenant_ctx_for_live.as_ref(), &filters),
        // The full page is never a prepend delta.
        highlight_new: false,
    })
}

/// Prefix for the row-level "Pick" link. Carries the
/// current filter combo + `live` toggle so picking a row for
/// compare doesn't tear down the operator's broader scope.
/// Always ends with `compare=` so the row template appends
/// the row id verbatim.
fn build_compare_pick_base(
    tenant_ctx: Option<&TenantContext>,
    filters: &ActivityFilters,
) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity");
    // Drop the existing `compare` from the suffix — the row
    // template appends its own `<row_id>` to the trailing
    // `compare=`, and we don't want two `&compare=` clauses
    // in the URL. (In normal mode `filters.compare` is None,
    // so this is a no-op; in compare mode the "Pick" link
    // technically isn't rendered for non-pinned rows, but
    // keep the URL well-formed defensively.)
    let mut filters_no_compare = filters.clone();
    filters_no_compare.compare = None;
    let qs = filters_no_compare.to_query_suffix();
    let live_part = if filters.live.is_some() {
        "&live=1"
    } else {
        ""
    };
    if qs.is_empty() && live_part.is_empty() {
        format!("{base}?compare=")
    } else if qs.is_empty() {
        format!("{base}?{}&compare=", &live_part[1..])
    } else {
        format!("{base}?{}{}&compare=", &qs[1..], live_part)
    }
}

/// Cancel link for compare-picking mode. Drops the
/// `compare=` param while keeping every other active filter
/// and the `live` toggle so cancelling a compare doesn't tear
/// down the operator's broader scope.
///
/// `to_query_suffix` includes
/// `compare` (so htmx poll + load-more URLs preserve the
/// picker), so we have to clear it on the filter we pass in
/// here — otherwise the cancel link would re-pin the same id
/// and never actually cancel.
fn build_compare_cancel_url(
    tenant_ctx: Option<&TenantContext>,
    filters: &ActivityFilters,
) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity");
    let mut filters_no_compare = filters.clone();
    filters_no_compare.compare = None;
    let qs = filters_no_compare.to_query_suffix();
    let live_part = if filters.live.is_some() {
        "&live=1"
    } else {
        ""
    };
    if qs.is_empty() && live_part.is_empty() {
        base
    } else if qs.is_empty() {
        // live=1 only.
        format!("{base}?{}", &live_part[1..])
    } else {
        // qs starts with `&`; turn into `?`.
        format!("{base}?{}{}", &qs[1..], live_part)
    }
}

/// Prefix for the per-row "Compare with pinned" link.
/// Row templates append `<row_id>` to get the final href:
/// `/admin/t/<tenant>/activity/compare?a=<pinned>&b=<row_id>`.
fn build_compare_link_base(tenant_ctx: Option<&TenantContext>, pinned: Uuid) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity/compare");
    format!("{base}?a={pinned}&b=")
}

/// Poll cadence. 5s is short enough that an on-call
/// operator sees a new event within the same glance, long
/// enough that an idle tab doesn't push needless `audit_log`
/// SELECTs. Constant rather than env so a future runtime knob
/// requires an explicit code change — accidental "every 500ms"
/// from a stale env var would melt the DB.
const LIVE_TAIL_INTERVAL_SECS: u32 = 5;

/// Build the `/activity` URL with the live toggle
/// flipped. Carries every active filter forward so toggling
/// doesn't drop the operator's filter combo. The hidden `live`
/// filter form input + this toggle URL are the only sites
/// where `live` rides URL params; facet links + active-chip
/// clears intentionally drop it (clicking a facet IS the user
/// expressing "new scope", live tail is per-scope and should
/// be re-opted-into on each filter change).
/// URL that toggles the group-by-trace view, preserving every other
/// active filter. `/activity?<filters>&group=trace` when off,
/// `/activity?<filters>` (without `group`) when on. URL-driven like the
/// live-tail toggle so the grouped view is bookmarkable + shareable.
fn build_group_toggle_url(tenant_ctx: Option<&TenantContext>, filters: &ActivityFilters) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity");
    // Suffix from every filter EXCEPT group, so we can flip it cleanly.
    let mut without_group = filters.clone();
    without_group.group = None;
    let qs = without_group.to_query_suffix();
    let qs_norm = if qs.is_empty() {
        String::new()
    } else {
        // qs begins with `&...`; turn into `?...`.
        format!("?{}", &qs[1..])
    };
    if filters.group_by_trace() {
        // ON → toggle OFF: drop group.
        if qs_norm.is_empty() {
            base
        } else {
            format!("{base}{qs_norm}")
        }
    } else if qs_norm.is_empty() {
        format!("{base}?group=trace")
    } else {
        format!("{base}{qs_norm}&group=trace")
    }
}

fn build_live_toggle_url(tenant_ctx: Option<&TenantContext>, filters: &ActivityFilters) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity");
    let qs = filters.to_query_suffix();
    // qs starts with `&...` for each populated filter; replace
    // the leading `&` with `?` so the URL is well-formed when
    // no other filter is set (qs empty ⇒ no leading char to
    // replace, just append `?live=1`).
    let toggle_value = if filters.live.is_none() { "1" } else { "" };
    let qs_normalized = if qs.is_empty() {
        String::new()
    } else {
        // qs always begins with `&...`; turn into `?...`.
        format!("?{}", &qs[1..])
    };
    if toggle_value.is_empty() {
        // Turning live OFF: drop `live` from the URL entirely.
        // qs never contained it (to_query_suffix doesn't include
        // `live`) so we can just emit base + qs.
        if qs_normalized.is_empty() {
            base
        } else {
            format!("{base}{qs_normalized}")
        }
    } else {
        // Turning live ON: append `live=1` to the existing qs.
        let joiner = if qs_normalized.is_empty() { "?" } else { "&" };
        format!("{base}{qs_normalized}{joiner}live=1")
    }
}

/// The rows fragment URL the polling tbody targets.
/// Same `/activity/rows` endpoint the load-more button uses,
/// with the active filter suffix appended so the polled
/// fragment honours the same filter scope as the static page.
/// `live` itself is NOT propagated to the fragment URL — the
/// fragment is identical whether or not live mode is on; it's
/// the page that wraps it in an htmx polling container.
fn build_live_tail_rows_url(
    tenant_ctx: Option<&TenantContext>,
    filters: &ActivityFilters,
) -> String {
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity/rows");
    let qs = filters.to_query_suffix();
    if qs.is_empty() {
        base
    } else {
        // qs starts with `&...`; replace with `?...`.
        format!("{base}?{}", &qs[1..])
    }
}

fn saved_view_row(v: waygate_dashboard_stores::activity_saved_views::SavedView) -> SavedViewRow {
    SavedViewRow {
        name_qs: urlencode(&v.name),
        created_by_display: v.created_by.unwrap_or_else(|| "—".into()),
        updated_at_abs: format_ts_abs(v.updated_at),
        name: v.name,
    }
}

pub(crate) async fn activity_rows(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<ActivityFilters>,
) -> Response {
    // The live-tail poll always sends `since_id` via hx-vals (possibly
    // empty when the feed has no rows yet). Its PRESENCE — not whether it
    // parses — marks a live-tail poll, so an empty feed still suppresses the
    // empty-state row instead of prepending it every idle tick.
    let is_live_poll = q.since_id.is_some();
    let filters = q.cleaned();
    // Tenant-scope the fetch to the active principal's tenant (mirrors the
    // compare/drawer handlers). The /activity/rows fragment is reachable
    // directly and via live-tail polling, so it must scope too — not just
    // the parent /activity page.
    let tenant = principal_tenant(user.as_ref());
    let (rows, page_next_after_id) = fetch_activity_rows(&state, &filters, tenant).await;
    let mut events = project_events(&rows);
    // Live-tail prepend delta. When the tbody polls with `since_id`,
    // return rows for htmx to PREPEND (highlighted, no grouping) instead of the
    // old full-`innerHTML` re-render. Otherwise render the normal page
    // (group-by-trace grouping applies there).
    let (events, next_after_id, highlight_new) = if is_live_poll {
        match filters.since_id_uuid() {
            Some(since) => {
                // Only rows newer than the cursor. If the page came back FULL
                // and EVERY row is newer than `since` (a burst of more than one
                // page of new rows since the last poll), keep the load-more
                // cursor so the older-new rows beyond this window stay reachable
                // instead of being silently dropped.
                let fetched = events.len();
                events.retain(|e| e.id > since);
                let next = if events.len() == fetched && page_next_after_id.is_some() {
                    page_next_after_id
                } else {
                    None
                };
                (events, next, true)
            }
            None => {
                // Empty / unparseable `since_id` — the feed has no rows yet.
                // Return the recent page so it populates as events arrive;
                // `highlight_new` suppresses the empty-state row while it's
                // still empty, so an idle poll of an empty feed prepends
                // nothing.
                (events, page_next_after_id, true)
            }
        }
    } else if filters.group_by_trace() {
        (group_events_by_trace(events), page_next_after_id, false)
    } else {
        (events, page_next_after_id, false)
    };
    let filter_qs = filters.to_query_suffix();
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let compare_link_base = filters
        .compare
        .map(|a| build_compare_link_base(tenant_ctx.as_ref(), a));
    let compare_pick_base = build_compare_pick_base(tenant_ctx.as_ref(), &filters);
    render(&ActivityRows {
        tenant_ctx,
        events,
        next_after_id,
        filter_qs,
        compare_pinned_id: filters.compare,
        compare_link_base,
        compare_pick_base,
        highlight_new,
    })
}

// ---- saved-views form handlers --------------------------------------

/// Dashboard-form payload for `POST /activity/saved_views`. The
/// view's filter shape rides along as the same flat fields the
/// activity-page URL uses, so the Save form can reuse the filter
/// state already in the page without an extra encoding step.
#[derive(Debug, Deserialize)]
pub(crate) struct SaveSavedViewForm {
    #[serde(default)]
    csrf: String,
    name: String,
    #[serde(default)]
    outcome: String,
    #[serde(default)]
    risk: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    principal: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    pii: String,
    #[serde(default)]
    since: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteSavedViewForm {
    #[serde(default)]
    csrf: String,
}

/// POST /activity/saved_views — upsert-by-name. Mirrors the
/// playground `save_scenario` handler shape: CSRF gate, store
/// gate, name validation, then a JSON filters payload assembled
/// from the form fields and PRG redirect back to the activity
/// page with the saved view loaded.
pub(crate) async fn save_activity_view(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<SaveSavedViewForm>,
) -> Response {
    if !activity_csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.dashboard.activity_saved_views.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "activity saved views store not configured",
        )
            .into_response();
    };
    if let Err(e) = waygate_dashboard_stores::activity_saved_views::validate_name(&body.name) {
        return (StatusCode::BAD_REQUEST, format!("{e}")).into_response();
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let created_by = user_principal.map(|p| p.sub.clone());

    // Build the filters JSON from the submitted form fields.
    // Run through `ActivityFilters::cleaned()` so an operator
    // who pastes `since=garbage` doesn't persist it — the saved
    // shape matches what the activity page would actually apply
    // for the same params.
    //
    // Forward-compat preservation of
    // unknown JSON keys runs inside the SQL upsert
    // (`activity_saved_views.filters || EXCLUDED.filters`), so
    // the dashboard handler hands over ONLY the known fields
    // and lets the store atomically merge with any existing
    // row. Merging in SQL (rather than a dashboard-layer
    // read → modify → write) avoids a race window where a
    // concurrent same-name save could clobber a freshly-written
    // unknown key between the read and the write, while still
    // keeping the forward-compat contract.
    let filters_obj = ActivityFilters {
        outcome: Some(body.outcome),
        risk: Some(body.risk),
        server: Some(body.server),
        principal: Some(body.principal),
        category: Some(body.category),
        pii: Some(body.pii),
        since: Some(body.since),
        after_id: None,
        since_id: None,
        load_view: None,
        live: None,
        compare: None,
        // group-by-trace is a view mode, never persisted in a saved view.
        group: None,
    }
    .cleaned()
    .to_saved_filters();

    match store
        .save(&tenant, &body.name, filters_obj, created_by.as_deref())
        .await
    {
        Ok(_) => {
            // PRG: redirect to the activity page with the saved
            // view loaded. Operator sees the filters applied +
            // the "Loaded view" badge — confirms the save round-
            // tripped without re-submitting the form.
            let url = format!(
                "{}?load_view={}",
                crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/activity"),
                urlencode(&body.name),
            );
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                name = %body.name,
                "activity save_view failed",
            );
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}

/// POST /activity/saved_views/{name}/delete. Mirrors the
/// playground `delete_scenario` handler shape.
pub(crate) async fn delete_activity_view(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    axum::extract::Path(params): axum::extract::Path<std::collections::HashMap<String, String>>,
    Form(body): Form<DeleteSavedViewForm>,
) -> Response {
    if !activity_csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.dashboard.activity_saved_views.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "activity saved views store not configured",
        )
            .into_response();
    };
    // Read `name` by key from the params map: nested under `/t/{tenant}`
    // (+ merged at `/`), so a `Path<String>` extractor 500s on the
    // tenant-scoped 2-capture match.
    let Some(name) = params.get("name") else {
        return (StatusCode::BAD_REQUEST, "missing saved-view name").into_response();
    };
    if let Err(e) = waygate_dashboard_stores::activity_saved_views::validate_name(name) {
        return (StatusCode::BAD_REQUEST, format!("{e}")).into_response();
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    match store.delete(&tenant, name).await {
        Ok(_) => {
            let url = crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/activity");
            Redirect::to(&url).into_response()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                name = %name,
                "activity delete_view failed",
            );
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
        }
    }
}

/// Fetch a filtered, keyset-paginated page of audit rows. Every
/// `ActivityFilters` predicate is pushed into the query, so the page holds up
/// to 50 *matching* rows from the whole table — not 50 raw rows the
/// handler then filters in memory (which would mean `server=searxng`
/// only searches the newest 50). The cursor is the last returned id, which
/// stays correct because filtering happens in the query.
///
/// Facets are a separate aggregate ([`fetch_activity_facets`]) — the page
/// is filtered, the facet rail is not — so they no longer ride on these
/// rows.
async fn fetch_activity_rows(
    state: &AdminState,
    filters: &ActivityFilters,
    tenant: &str,
) -> (Vec<AuditRow>, Option<Uuid>) {
    let Some(reader) = state.observability.audit.get() else {
        return (Vec::new(), None);
    };
    let rows = reader
        .query_events(
            &filters.to_audit_query(tenant),
            PAGE_LIMIT,
            filters.after_id,
        )
        .await
        .unwrap_or_default();
    let next_after_id = if rows.len() as i64 >= PAGE_LIMIT {
        rows.last().map(|r| r.id)
    } else {
        None
    };
    (rows, next_after_id)
}

/// Project the fetched rows into the template's [`ActivityEventView`]
/// shape. Rows arrive already filtered by [`waygate_storage::AuditReader::query_events`],
/// so this is a pure map with no in-memory `matches` filter.
fn project_events(rows: &[AuditRow]) -> Vec<ActivityEventView> {
    rows.iter()
        .map(|r| ActivityEventView {
            id: r.id,
            ts_abs: format_ts_abs(r.ts),
            ts_rel: format_ts_rel(r.ts),
            principal: principal_label(r),
            server: r.server.clone(),
            tool: r.tool.clone(),
            operation: r.operation.clone(),
            outcome: r.outcome.clone(),
            risk: r.risk_level.clone(),
            pii: r.pii,
            category: r.category.clone(),
            action_label: action_label(r),
            target: r.target.clone(),
            reason: r.reason.clone(),
            trace_id: r.trace_id.clone(),
            // Grouping annotations default to "flat"; `group_events_by_trace`
            // sets them when the group-by-trace view is active.
            fan_out_count: None,
            group_band: None,
        })
        .collect()
}

/// Group-by-trace: cluster the page's rows so events sharing a
/// `trace_id` (one agent action's fan-out) render contiguously, the head row
/// of each multi-row group carries a `fan_out_count`, and group membership is
/// tagged with an alternating `group_band` for a visual left-edge band.
///
/// Grouping is stable on first appearance (preserving the newest-first feed
/// order across groups) and operates on the fetched page only — a trace whose
/// rows straddle a pagination boundary groups within each page, not across
/// (UUIDv7 ids mean a fan-out's rows are almost always adjacent anyway).
/// Rows with no `trace_id`, and traces with a single row in the page, stay
/// flat (`group_band = None`).
fn group_events_by_trace(events: Vec<ActivityEventView>) -> Vec<ActivityEventView> {
    use std::collections::HashMap;
    // Count rows per trace_id within this page; only traces with >1 row form a
    // banded group.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in &events {
        if let Some(t) = e.trace_id.as_deref() {
            *counts.entry(t.to_owned()).or_insert(0) += 1;
        }
    }
    // Walk once, preserving newest-first order. Flat rows (no trace / singleton
    // trace) keep their position; multi-row-trace rows accumulate into their
    // group, emitted contiguously at the group's first-seen slot.
    enum Slot {
        Flat(Box<ActivityEventView>),
        Group(String),
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut groups: HashMap<String, Vec<ActivityEventView>> = HashMap::new();
    // Band parity assigned in first-appearance (output) order so adjacent
    // groups always alternate — HashMap iteration order would not.
    let mut bands: HashMap<String, u8> = HashMap::new();
    let mut next_band: u8 = 0;
    for e in events {
        let multi = e
            .trace_id
            .as_deref()
            .is_some_and(|t| counts.get(t).copied().unwrap_or(0) > 1);
        if multi {
            let t = e.trace_id.clone().expect("multi implies Some(trace_id)");
            if !groups.contains_key(&t) {
                slots.push(Slot::Group(t.clone()));
                bands.insert(t.clone(), next_band);
                next_band ^= 1;
            }
            groups.entry(t).or_default().push(e);
        } else {
            slots.push(Slot::Flat(Box::new(e)));
        }
    }
    // Annotate each group: its first-appearance band, fan_out_count on the head.
    for (t, rows) in groups.iter_mut() {
        let n = rows.len();
        let b = bands.get(t).copied().unwrap_or(0);
        for (i, r) in rows.iter_mut().enumerate() {
            r.group_band = Some(b);
            r.fan_out_count = if i == 0 { Some(n) } else { None };
        }
    }
    let mut out: Vec<ActivityEventView> = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            Slot::Flat(e) => out.push(*e),
            Slot::Group(t) => {
                if let Some(rows) = groups.remove(&t) {
                    out.extend(rows);
                }
            }
        }
    }
    out
}

/// Map the storage-layer [`waygate_storage::AuditFacets`] counts into
/// render-ready facet groups: sort each dimension by count desc then value
/// asc, mark the active value, attach a display label + URL-encoded query
/// value, and drop empty groups.
///
/// The counts come from a table-wide aggregate within the time window
/// ([`waygate_storage::AuditReader::facet_counts`]), NOT the fetched page.
/// So the rail lists every server/outcome/category/etc. in the window,
/// rather than only values present in the newest 50 rows (e.g. "only
/// example-compute" on a high-volume feed). The categorical filters do not
/// narrow the rail; the row query does, so an operator can always see
/// and pivot to other values.
fn build_facets(
    facets: &waygate_storage::AuditFacets,
    filters: &ActivityFilters,
) -> Vec<FacetGroup> {
    fn group(
        label: &'static str,
        param: &'static str,
        active: Option<&str>,
        counts: &[(String, i64)],
        display_for: fn(&str) -> Option<String>,
    ) -> FacetGroup {
        let mut values: Vec<FacetValue> = counts
            .iter()
            .map(|(value, count)| FacetValue {
                is_active: active == Some(value.as_str()),
                display: display_for(value),
                value_qs: urlencode(value),
                value: value.clone(),
                count: *count as usize,
            })
            .collect();
        // Count desc, then value asc for stable ordering.
        values.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
        FacetGroup {
            label,
            param,
            values,
        }
    }

    let groups = vec![
        group(
            "Outcome",
            "outcome",
            filters.outcome.as_deref(),
            &facets.outcome,
            |_| None,
        ),
        group(
            "Risk",
            "risk",
            filters.risk.as_deref(),
            &facets.risk,
            |_| None,
        ),
        group(
            "Category",
            "category",
            filters.category.as_deref(),
            &facets.category,
            |_| None,
        ),
        group(
            "PII",
            "pii",
            filters.pii.as_deref(),
            &facets.pii,
            |v| match v {
                "true" => Some("present".into()),
                "false" => Some("absent".into()),
                _ => None,
            },
        ),
        group(
            "Server",
            "server",
            filters.server.as_deref(),
            &facets.server,
            |_| None,
        ),
    ];

    groups
        .into_iter()
        .filter(|g| !g.values.is_empty())
        .collect()
}

/// Fetch the table-wide facet counts for the current filter's time window
/// and map them to render-ready groups. Returns an empty rail when no audit
/// store is configured. Separate from [`fetch_activity_rows`] because facets
/// are a distinct aggregate: the page is filtered, the rail is time-windowed
/// but not categorically filtered.
/// Tier-2: a window wide enough that scanning raw `audit_log` is slow, so the
/// dashboard reads the `audit_rollup_hourly` pre-aggregate instead. Narrow
/// windows (<= 24h) stay on the live reader — fast already, and the live reader
/// can give the sub-hour precision the hourly rollup can't. The reader itself
/// additionally falls back to live when a `principal` filter is active (the
/// rollup carries no principal dimension).
fn use_rollup_for_window(since: Option<&str>) -> bool {
    matches!(since, Some("7d") | Some("30d") | Some(ALL_TIME_SINCE))
}

async fn fetch_activity_facets(
    state: &AdminState,
    filters: &ActivityFilters,
    tenant: &str,
) -> Vec<FacetGroup> {
    let Some(reader) = state.observability.audit.get() else {
        return Vec::new();
    };
    let q = filters.to_audit_query(tenant);
    let counts = if use_rollup_for_window(filters.since.as_deref()) {
        reader.rollup_facets(&q).await
    } else {
        reader.facet_counts(&q).await
    }
    .unwrap_or_default();
    build_facets(&counts, filters)
}

/// Cap on the "Top tools" reliability panel.
const TOOL_STATS_LIMIT: i64 = 20;

/// Per-tool reliability stats for the active filter window. Like the
/// facet rail it is a separate aggregate (not the paged rows); unlike the
/// rail it applies the categorical filters — except `outcome`, which is
/// cleared so the error / denial counts see every outcome. Empty when no
/// audit store is configured.
async fn fetch_tool_stats(
    state: &AdminState,
    filters: &ActivityFilters,
    tenant: &str,
) -> Vec<ToolStatView> {
    let Some(reader) = state.observability.audit.get() else {
        return Vec::new();
    };
    let mut query = filters.to_audit_query(tenant);
    query.outcome = None;
    // Wide windows read the rollup (p95 comes back None — not additive — and
    // the panel renders it as "—" for those windows); narrow windows stay live.
    let stats = if use_rollup_for_window(filters.since.as_deref()) {
        reader.rollup_tool_stats(&query, TOOL_STATS_LIMIT).await
    } else {
        reader.tool_stats(&query, TOOL_STATS_LIMIT).await
    }
    .unwrap_or_default();
    stats
        .into_iter()
        .map(|s| {
            let error_rate = if s.total > 0 {
                (s.errors as f64 / s.total as f64) * 100.0
            } else {
                0.0
            };
            ToolStatView {
                server: s.server,
                tool: s.tool,
                total: s.total,
                errors: s.errors,
                denied: s.denied,
                error_rate_pct: format!("{error_rate:.1}"),
                p95_ms: s.p95_latency_ms.map(|v| v.round() as i64),
            }
        })
        .collect()
}

/// Default histogram window (hours) when no `since` filter is active.
const HISTOGRAM_DEFAULT_WINDOW_HOURS: i64 = 24;

/// Bucket width (seconds) for the volume histogram, chosen from the
/// active `since` window to keep the bar count in a readable ~24–30 range.
fn histogram_bucket_seconds(since: Option<&str>) -> i64 {
    match since {
        Some("15m") => 30,
        Some("1h") => 120,
        Some("7d") => 21_600,
        Some("30d") => 86_400,
        // 24h and the default (no `since`) window.
        _ => 3_600,
    }
}

/// Outcome → histogram band CSS class.
fn hist_outcome_class(outcome: &str) -> &'static str {
    match outcome {
        "success" => "hist-ok",
        "denied" => "hist-deny",
        "step_up_required" => "hist-stepup",
        "execution_error" => "hist-err",
        _ => "hist-other",
    }
}

/// Stack order (bottom → top): successes at the base, failures on top so a
/// red error band sits at the top of the bar and is easy to spot.
fn hist_outcome_order(outcome: &str) -> u8 {
    match outcome {
        "success" => 0,
        "step_up_required" => 1,
        "denied" => 2,
        "execution_error" => 3,
        _ => 4,
    }
}

/// Format a bucket-start epoch for the bar tooltip. ≥6h buckets span days,
/// so they carry the date; finer buckets show just the time.
fn hist_bucket_label(epoch: i64, bucket_seconds: i64) -> String {
    let ts = OffsetDateTime::from_unix_timestamp(epoch).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    if bucket_seconds >= 21_600 {
        format!(
            "{:02}-{:02} {:02}:{:02}",
            u8::from(ts.month()),
            ts.day(),
            ts.hour(),
            ts.minute()
        )
    } else {
        format!("{:02}:{:02}", ts.hour(), ts.minute())
    }
}

/// Build the activity volume histogram for the active window. A
/// server-side aggregate stacked by outcome (with `outcome` cleared and
/// `pre_call` rows excluded), tenant-scoped. Sparse — only buckets with
/// events get a bar; the bar's tooltip carries the bucket time. The window
/// defaults to the last 24h when no `since` is active. `None` when no audit
/// store is configured or the window is empty.
async fn fetch_histogram(
    state: &AdminState,
    filters: &ActivityFilters,
    tenant: &str,
) -> Option<HistogramView> {
    use std::collections::BTreeMap;
    let reader = state.observability.audit.get()?;
    let bucket_seconds = histogram_bucket_seconds(filters.since.as_deref());
    let mut query = filters.to_audit_query(tenant);
    // Stacked by outcome → don't filter on outcome.
    query.outcome = None;
    let window_label = match filters.since.as_deref() {
        // The feed can be all-time, but the histogram always bounds itself to
        // the default window below — so label it for what it actually shows.
        Some(s) if s == ALL_TIME_SINCE => format!("last {HISTOGRAM_DEFAULT_WINDOW_HOURS}h"),
        Some(s) => format!("last {s}"),
        None => format!("last {HISTOGRAM_DEFAULT_WINDOW_HOURS}h"),
    };
    // The histogram needs a bounded window; default to the last 24h when the
    // feed has no `since` (the feed itself is all-time + paged). This is why
    // the rollup is used only for 7d/30d below — "all" collapses to a 24h
    // histogram window here, which the live reader serves fast.
    if query.since.is_none() {
        query.since =
            Some(OffsetDateTime::now_utc() - time::Duration::hours(HISTOGRAM_DEFAULT_WINDOW_HOURS));
    }
    // 7d/30d histograms scan a lot of raw rows live; read the hourly rollup
    // instead (its 6h/1d bars are coarser than an hour, so no precision lost).
    let wide = matches!(filters.since.as_deref(), Some("7d") | Some("30d"));
    let buckets = if wide {
        reader.rollup_histogram(&query, bucket_seconds).await
    } else {
        reader.histogram(&query, bucket_seconds).await
    }
    .unwrap_or_default();
    if buckets.is_empty() {
        return None;
    }
    let mut by_bucket: BTreeMap<i64, Vec<(String, i64)>> = BTreeMap::new();
    for b in buckets {
        by_bucket
            .entry(b.bucket_epoch)
            .or_default()
            .push((b.outcome, b.count));
    }
    let max_total = by_bucket
        .values()
        .map(|segs| segs.iter().map(|(_, c)| c).sum::<i64>())
        .max()
        .unwrap_or(1)
        .max(1);
    let mut total = 0i64;
    let bars: Vec<HistogramBar> = by_bucket
        .into_iter()
        .map(|(epoch, mut segs)| {
            segs.sort_by_key(|(o, _)| hist_outcome_order(o));
            let bar_total: i64 = segs.iter().map(|(_, c)| c).sum();
            total += bar_total;
            let segments = segs
                .into_iter()
                .map(|(outcome, count)| HistSegment {
                    class: hist_outcome_class(&outcome),
                    // At least 2% so a non-zero band stays visible.
                    height_pct: (count * 100 / max_total).max(if count > 0 { 2 } else { 0 }),
                    outcome,
                    count,
                })
                .collect();
            HistogramBar {
                label: hist_bucket_label(epoch, bucket_seconds),
                total: bar_total,
                segments,
            }
        })
        .collect();
    Some(HistogramView {
        bars,
        window_label,
        total,
        peak: max_total,
    })
}

/// Build the active-filter chip row above the event
/// table. One chip per filter dimension currently set; each
/// chip's `clear_url` carries the OTHER active filters
/// (sans the chip's own) so a click drops just that
/// dimension. The `since` window is included on the principle
/// that an operator wanting to "see everything" should be
/// able to click a chip rather than wading through the
/// filter form.
fn build_active_filter_chips(
    filters: &ActivityFilters,
    tenant_ctx: Option<&TenantContext>,
) -> Vec<ActiveFilterChip> {
    let mut out = Vec::new();
    let base = crate::tenant_ctx::nav_url(tenant_ctx, "/activity");

    fn chip_url(base: &str, mut without: ActivityFilters, key: &str) -> String {
        match key {
            "outcome" => without.outcome = None,
            "risk" => without.risk = None,
            "server" => without.server = None,
            "principal" => without.principal = None,
            "category" => without.category = None,
            "pii" => without.pii = None,
            "since" => without.since = None,
            _ => {}
        }
        without.after_id = None;
        let qs = without.to_query_suffix();
        // `qs` starts with `&`; convert the FIRST `&` to `?`
        // so the URL is well-formed. Empty qs ⇒ base URL alone.
        if qs.is_empty() {
            base.to_owned()
        } else {
            format!("{base}?{}", &qs[1..])
        }
    }

    macro_rules! maybe_chip {
        ($key:literal, $label_fn:expr, $value:expr) => {
            if let Some(v) = $value {
                let label: String = $label_fn(v.as_str());
                out.push(ActiveFilterChip {
                    label,
                    clear_url: chip_url(&base, filters.clone(), $key),
                });
            }
        };
    }

    maybe_chip!(
        "outcome",
        |v: &str| format!("outcome: {v}"),
        &filters.outcome
    );
    maybe_chip!("risk", |v: &str| format!("risk: {v}"), &filters.risk);
    maybe_chip!(
        "category",
        |v: &str| format!("category: {v}"),
        &filters.category
    );
    maybe_chip!(
        "pii",
        |v: &str| match v {
            "true" => "PII: present".into(),
            "false" => "PII: absent".into(),
            other => format!("pii: {other}"),
        },
        &filters.pii
    );
    maybe_chip!("server", |v: &str| format!("server: {v}"), &filters.server);
    maybe_chip!(
        "principal",
        |v: &str| format!("principal contains: {v}"),
        &filters.principal
    );
    // The active time window renders as a chip only when it differs from the
    // default 24h view — the default isn't a user-applied filter, so a
    // permanent un-clearable "since: 24h" chip would be noise. Clearing drops
    // `since` from the URL, which `cleaned()` re-defaults back to 24h.
    if let Some(v) = filters.since.as_deref().filter(|s| *s != DEFAULT_SINCE) {
        out.push(ActiveFilterChip {
            label: format!("since: {v}"),
            clear_url: chip_url(&base, filters.clone(), "since"),
        });
    }

    out
}

#[derive(Template)]
#[template(path = "activity_drawer.html")]
struct ActivityDrawer {
    ts_abs: String,
    outcome: String,
    action_label_opt: Option<String>,
    principal_sub: String,
    email: Option<String>,
    issuer: Option<String>,
    groups: Vec<String>,
    action: String,
    server: Option<String>,
    tool: Option<String>,
    operation: Option<String>,
    risk: Option<String>,
    pii: Option<bool>,
    category: Option<String>,
    /// Migration 0046: the structured subject of the event (affected key
    /// `sub`, change-request `action_type`). Shown as a "Target" row in the
    /// drawer so the detail view names what the action acted on.
    target: Option<String>,
    reason: Option<String>,
    policy_ids: Vec<String>,
    trace_id: Option<String>,
    /// Pre-rendered Grafana Explore → Tempo URL (the configured
    /// `trace_url_template` with `{trace_id}` substituted). `None` when no
    /// template is configured or the row has no trace_id; the template then
    /// renders just the bare trace-id text without a link.
    trace_url: Option<String>,
    latency_ms: Option<i64>,
}

/// Side-by-side compare page. Fetches two audit
/// events by id, projects each into a column, and pairs
/// them up field-by-field so the template can mark
/// differing rows with a `diff` class. v1 compares the
/// flat top-level columns (timestamp / outcome / principal
/// / server / tool / risk / pii / category / reason /
/// trace_id / latency_ms / policy_ids). Field-level deep
/// diff of the `audit_log.details` JSONB is a follow-up.
#[derive(Template)]
#[template(path = "activity_compare.html")]
struct ActivityCompare {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the audit store is wired. Empty-state when
    /// not — same posture as the page itself.
    audit_available: bool,
    /// Both rows resolved? `false` ⇒ render the "one or both
    /// events not found in this tenant's audit chain" empty
    /// state; protects against hand-crafted URLs aimed at a
    /// different tenant's ids.
    both_resolved: bool,
    /// Brief two-line summaries for the column headers.
    a_summary: String,
    b_summary: String,
    /// Field pairs, in stable render order. Each `differs`
    /// drives a `tr.diff` class so an operator can scan
    /// what changed between the two events at a glance.
    fields: Vec<CompareField>,
    /// Cancel link back to the activity page. Carries no
    /// filter state — the compare page is reached from
    /// either a `?compare=` pin or a direct URL, neither of
    /// which round-trips through `to_query_suffix`.
    back_url: String,
}

struct CompareField {
    label: &'static str,
    a_val: String,
    b_val: String,
    differs: bool,
}

/// Query for `/activity/compare?a=<id>&b=<id>`. Both ids
/// required; absent or unparseable → 400 (the operator
/// almost certainly hand-edited the URL).
#[derive(Debug, Deserialize)]
pub(crate) struct CompareQuery {
    a: Uuid,
    b: Uuid,
}

pub(crate) async fn activity_compare(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<CompareQuery>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    // Tenant-scope the fetched rows against the active tenant.
    // `AuditReader::fetch_event` is keyed by id only (storage layer does
    // `WHERE id = $1`), so without this gate a hand-crafted
    // URL pointing at a known UUID from another tenant would
    // resolve + render that event's full audit detail. The
    // empty-state copy already exists for the "doesn't resolve"
    // case; treat a cross-tenant id the same way an absent id
    // is treated — render the empty state, don't 404 / 403
    // (no need to leak the existence of the id).
    let active_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);

    let audit_available = state.observability.audit.enabled();
    let mut both_resolved = false;
    let mut a_summary = format!("Event {}", q.a);
    let mut b_summary = format!("Event {}", q.b);
    let mut fields: Vec<CompareField> = Vec::new();

    if let Some(reader) = state.observability.audit.get() {
        let a_row = reader
            .fetch_event(q.a)
            .await
            .ok()
            .flatten()
            .filter(|r| r.tenant_id == active_tenant);
        let b_row = reader
            .fetch_event(q.b)
            .await
            .ok()
            .flatten()
            .filter(|r| r.tenant_id == active_tenant);
        if let (Some(a_row), Some(b_row)) = (a_row, b_row) {
            both_resolved = true;
            a_summary = format!("{} · {}", format_ts_abs(a_row.ts), action_label(&a_row),);
            b_summary = format!("{} · {}", format_ts_abs(b_row.ts), action_label(&b_row),);
            fields = build_compare_fields(&a_row, &b_row);
        }
    }

    render(&ActivityCompare {
        chrome: PageChrome::build(
            &state,
            "Compare events",
            "/activity",
            &headers,
            user_display_str,
            tenant_ctx.clone(),
            String::new(),
        ),
        audit_available,
        both_resolved,
        a_summary,
        b_summary,
        fields,
        back_url: crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/activity"),
    })
}

/// Pair two `AuditRow`s into ordered field rows for the
/// compare template. `differs` is true when the displayed
/// strings don't match — same comparison the visual diff
/// uses, so an operator never sees `differs=true` on rows
/// that look identical.
fn build_compare_fields(a: &AuditRow, b: &AuditRow) -> Vec<CompareField> {
    fn opt_str(v: Option<&String>) -> String {
        v.cloned().unwrap_or_else(|| "—".into())
    }
    fn opt_bool(v: Option<bool>) -> String {
        match v {
            Some(true) => "true".into(),
            Some(false) => "false".into(),
            None => "—".into(),
        }
    }
    fn opt_num(v: Option<i64>) -> String {
        v.map(|n| n.to_string()).unwrap_or_else(|| "—".into())
    }
    fn groups_or_dash(v: &[String]) -> String {
        if v.is_empty() {
            "—".into()
        } else {
            v.join(", ")
        }
    }
    let pairs: Vec<(&'static str, String, String)> = vec![
        ("Timestamp", format_ts_abs(a.ts), format_ts_abs(b.ts)),
        ("Outcome", a.outcome.clone(), b.outcome.clone()),
        ("Action", a.action.clone(), b.action.clone()),
        (
            "Operation",
            opt_str(a.operation.as_ref()),
            opt_str(b.operation.as_ref()),
        ),
        (
            "Target",
            opt_str(a.target.as_ref()),
            opt_str(b.target.as_ref()),
        ),
        (
            "Principal sub",
            opt_str(a.principal_sub.as_ref()),
            opt_str(b.principal_sub.as_ref()),
        ),
        (
            "Email",
            opt_str(a.principal_email.as_ref()),
            opt_str(b.principal_email.as_ref()),
        ),
        (
            "Issuer",
            opt_str(a.issuer.as_ref()),
            opt_str(b.issuer.as_ref()),
        ),
        (
            "Groups",
            groups_or_dash(&a.principal_groups),
            groups_or_dash(&b.principal_groups),
        ),
        (
            "Server",
            opt_str(a.server.as_ref()),
            opt_str(b.server.as_ref()),
        ),
        ("Tool", opt_str(a.tool.as_ref()), opt_str(b.tool.as_ref())),
        (
            "Risk",
            opt_str(a.risk_level.as_ref()),
            opt_str(b.risk_level.as_ref()),
        ),
        ("PII", opt_bool(a.pii), opt_bool(b.pii)),
        (
            "Category",
            opt_str(a.category.as_ref()),
            opt_str(b.category.as_ref()),
        ),
        (
            "Reason",
            opt_str(a.reason.as_ref()),
            opt_str(b.reason.as_ref()),
        ),
        (
            "Policy IDs",
            groups_or_dash(&a.policy_ids),
            groups_or_dash(&b.policy_ids),
        ),
        (
            "Trace id",
            opt_str(a.trace_id.as_ref()),
            opt_str(b.trace_id.as_ref()),
        ),
        ("Latency ms", opt_num(a.latency_ms), opt_num(b.latency_ms)),
    ];
    pairs
        .into_iter()
        .map(|(label, a_val, b_val)| {
            let differs = a_val != b_val;
            CompareField {
                label,
                a_val,
                b_val,
                differs,
            }
        })
        .collect()
}

pub(crate) async fn activity_drawer(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(reader) = state.observability.audit.get() else {
        return (StatusCode::NOT_FOUND, "audit not configured").into_response();
    };
    // Read `id` by name: this route is nested under `/t/{tenant}` (and
    // merged at `/`), so a `Path<Uuid>` extractor 500s on the
    // tenant-scoped mount's 2-capture match.
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return (StatusCode::NOT_FOUND, "event not found").into_response();
    };
    let Ok(Some(row)) = reader.fetch_event(id).await else {
        return (StatusCode::NOT_FOUND, "event not found").into_response();
    };
    // Tenant-scope: `fetch_event` is keyed by id only, so a known UUID from
    // another tenant would otherwise render its full audit detail. Treat a
    // cross-tenant row as not-found — the same gate the compare page applies —
    // and don't leak existence via a distinct status.
    if row.tenant_id != principal_tenant(user.as_ref()) {
        return (StatusCode::NOT_FOUND, "event not found").into_response();
    }
    // Substitute the row's trace_id into the configured Grafana Explore
    // → Tempo URL template. Render a link only when both the template and a
    // trace_id are present; otherwise the drawer shows the bare trace-id.
    let trace_url = state
        .observability
        .trace_url_template
        .as_deref()
        .zip(row.trace_id.as_deref())
        .map(|(tmpl, tid)| tmpl.replace("{trace_id}", tid));
    render(&ActivityDrawer {
        ts_abs: format_ts_abs(row.ts),
        outcome: row.outcome.clone(),
        action_label_opt: Some(action_label(&row)),
        principal_sub: row.principal_sub.clone().unwrap_or_else(|| "–".into()),
        email: row.principal_email.clone(),
        issuer: row.issuer.clone(),
        groups: row.principal_groups.clone(),
        action: row.action.clone(),
        server: row.server.clone(),
        tool: row.tool.clone(),
        operation: row.operation.clone(),
        risk: row.risk_level.clone(),
        pii: row.pii,
        category: row.category.clone(),
        target: row.target.clone(),
        reason: row.reason.clone(),
        policy_ids: row.policy_ids.clone(),
        trace_id: row.trace_id.clone(),
        trace_url,
        latency_ms: row.latency_ms,
    })
}

// ---- shared helpers -------------------------------------------------------

// ---- router ---------------------------------------------------------------
