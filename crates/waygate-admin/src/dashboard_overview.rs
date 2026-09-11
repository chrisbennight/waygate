//! Overview page — one of the router-per-domain modules `dashboard.rs`
//! delegates to. Routes stay mounted by `dashboard::page_routes`.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use time::OffsetDateTime;
use waygate_oidc::Principal;
use waygate_upstream::UpstreamPool;

use super::dashboard::*;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;
use waygate_core::fmt::{format_ts_abs, format_ts_rel};

#[derive(Template)]
#[template(path = "overview.html")]
struct OverviewPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    upstreams: Vec<UpstreamTile>,
    upstreams_total: usize,
    upstreams_degraded: usize,
    upstreams_down: usize,
    audit_available: bool,
    /// Figures-with-deltas (calls / deny rate / errors,
    /// today vs yesterday, with an hourly sparkline). `None` when the
    /// audit store is unwired or the aggregate failed — the template
    /// renders one caption line instead of dead tiles.
    figures: Option<OverviewFigures>,
    /// "What changed" feed: recent policy publishes, manifest reloads,
    /// and identity lifecycle events. Empty without an audit store.
    changed: Vec<ChangedEvent>,
    notable: Vec<NotableEvent>,
    /// Red banner. `Some(count)` when active break-glass
    /// tokens exist for the principal's tenant; `None` when the
    /// store is unwired, the fetch failed, or zero active rows
    /// (no banner in any of those cases). The template renders
    /// the banner with the count and a deep-link to
    /// `/break_glass`. Banner is admin-gated client-side: a
    /// non-admin SSO session sees `None` because we skip the
    /// store fetch entirely, mirroring the page's own gate.
    active_break_glass: Option<usize>,
    /// `true` when [`Self::active_break_glass`] saturated at
    /// the dashboard's fetch limit; the banner copy reads
    /// "{n}+ active". Operator on a runaway-mint tenant isn't
    /// lied to about the volume.
    active_break_glass_saturated: bool,
    /// Attention queue: zero-or-more rows the operator
    /// should look at. Each row has a severity, label,
    /// optional hint, and deep link. Empty when nothing is
    /// pending OR when the principal lacks the admin scope
    /// needed to compute the underlying counts — template
    /// renders an "all clear" placeholder in that case.
    attention_items: Vec<AttentionItem>,
    /// First-run "Getting started" checklist. `Some` only when setup is
    /// incomplete (at least one milestone unmet); `None` ⇒ the card is
    /// hidden once everything is wired. Built from cheap config signals,
    /// not row counts.
    getting_started: Option<GettingStarted>,
}

/// One row of the first-run setup checklist.
struct SetupStep {
    label: &'static str,
    hint: &'static str,
    done: bool,
    href: String,
}

/// First-run "Getting started" checklist view-model. Shown above the KPI
/// grid until every milestone is met.
struct GettingStarted {
    steps: Vec<SetupStep>,
    done_count: usize,
    total: usize,
    playground_href: String,
}

/// One row in the attention queue. The dashboard composes
/// these in `attention_items_for_overview` from break-glass
/// plus approval-grant counts; the template renders each row
/// with a severity chip and a deep link.
pub(crate) struct AttentionItem {
    /// Severity bucket — drives the chip color in the
    /// template: `"critical"` → red, `"warn"` → amber,
    /// `"info"` → muted. Keep the string values stable;
    /// the template branches on them by equality.
    pub(crate) severity: &'static str,
    /// Short label shown bold in the row.
    pub(crate) label: String,
    /// Optional secondary line (the "why this matters"
    /// summary). Hidden when empty.
    hint: &'static str,
    /// Where the operator clicks through to triage. Built
    /// from `nav_url` so the tenant prefix carries through.
    pub(crate) href: String,
}

impl OverviewPage {}

struct UpstreamTile {
    name: String,
    transport: &'static str,
    runtime_status: &'static str,
    tool_count: usize,
}

struct NotableEvent {
    ts_abs: String,
    ts_rel: String,
    principal: String,
    action_label: String,
    outcome: String,
}

/// The three Overview figures, each with a today-vs-yesterday delta
/// computed from one 48h hourly histogram (so all three agree on the
/// window). Deny rate counts `denied` only — denies are the policy
/// working; `execution_error` is the system failing and gets its own
/// figure.
struct OverviewFigures {
    calls_today: i64,
    calls_delta: String,
    deny_rate_pct: u32,
    deny_delta: String,
    errors_today: i64,
    errors_delta: String,
    // Each figure gets its own hourly sparkline: polyline
    // points for the 24 hourly totals, newest hour rightmost, scaled into
    // the 0 0 120 28 viewBox, plus the peak for the annotation/aria label.
    calls_spark_points: String,
    calls_spark_peak: i64,
    deny_spark_points: String,
    deny_spark_peak: i64,
    errors_spark_points: String,
    errors_spark_peak: i64,
}

/// One "what changed" feed row.
struct ChangedEvent {
    ts_abs: String,
    ts_rel: String,
    kind: &'static str,
    summary: String,
    href: String,
}

/// Format a today-vs-yesterday delta for a COUNT (calls, errors). The
/// reader wants "more or less than usual", so this is a percent change of
/// the count.
fn fmt_delta(today: i64, yesterday: i64) -> String {
    if yesterday == 0 {
        return if today == 0 {
            "quiet yesterday too".to_owned()
        } else {
            "none yesterday".to_owned()
        };
    }
    let pct = ((today - yesterday) * 100) / yesterday;
    match pct.cmp(&0) {
        std::cmp::Ordering::Greater => format!("+{pct}% vs yesterday"),
        std::cmp::Ordering::Less => format!("\u{2212}{}% vs yesterday", -pct),
        std::cmp::Ordering::Equal => "level with yesterday".to_owned(),
    }
}

/// Format a today-vs-yesterday delta for a RATE (deny rate). A rate's
/// change is best read in percentage *points* ("3% → 5%" is +2pp), not as
/// a percent-of-a-percent — and crucially NOT as the change in the raw
/// numerator, which a call-volume swing would distort.
/// `today`/`yesterday` are the rates in percent.
fn fmt_rate_delta(today_pct: u32, yesterday_pct: u32, had_yesterday_calls: bool) -> String {
    if !had_yesterday_calls {
        return "no calls yesterday".to_owned();
    }
    let pp = today_pct as i64 - yesterday_pct as i64;
    match pp.cmp(&0) {
        std::cmp::Ordering::Greater => format!("+{pp}pp vs yesterday"),
        std::cmp::Ordering::Less => format!("\u{2212}{}pp vs yesterday", -pp),
        std::cmp::Ordering::Equal => "level with yesterday".to_owned(),
    }
}

/// Scale 24 hourly totals into polyline points for a 120x28 viewBox
/// (5px per hour, 2px vertical padding). A flat-zero day draws a
/// baseline rather than nothing.
fn spark_points(hourly: &[i64]) -> String {
    let peak = hourly.iter().copied().max().unwrap_or(0).max(1);
    hourly
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = i as f64 * (120.0 / (hourly.len().max(2) - 1) as f64);
            let y = 26.0 - (*v as f64 / peak as f64) * 24.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Split a 48h hourly histogram into per-outcome (today, yesterday)
/// totals plus today's per-outcome hourly series (one sparkline each).
struct WindowTotals {
    calls: (i64, i64),
    denied: (i64, i64),
    errors: (i64, i64),
    hourly_calls: Vec<i64>,
    hourly_denied: Vec<i64>,
    hourly_errors: Vec<i64>,
}

fn split_histogram(
    buckets: &[waygate_storage::audit::HistogramBucket],
    now_epoch: i64,
) -> WindowTotals {
    // The store floors each event's ts to its hourly bucket start, so the
    // today/yesterday boundary must be bucket-aligned too — comparing a
    // floored bucket_epoch against the exact now-86400 instant would put
    // the current partial hour on the wrong side of the line. "Today" =
    // the 24 hourly buckets ending at the current one; "yesterday" = the
    // 24 before that.
    let current_hour = now_epoch.div_euclid(3600) * 3600;
    let today_start = current_hour - 23 * 3600;
    let yesterday_start = today_start - 24 * 3600;

    let mut calls = (0i64, 0i64);
    let mut denied = (0i64, 0i64);
    let mut errors = (0i64, 0i64);
    // 24 hourly slots, oldest first; slot 23 is the current hour.
    let mut hourly_calls = vec![0i64; 24];
    let mut hourly_denied = vec![0i64; 24];
    let mut hourly_errors = vec![0i64; 24];
    for b in buckets {
        let bucket = b.bucket_epoch.div_euclid(3600) * 3600;
        let side = if bucket >= today_start {
            Some(true)
        } else if bucket >= yesterday_start {
            Some(false)
        } else {
            None // older than the 48h window — ignore
        };
        let Some(today) = side else { continue };
        let slot = if today {
            Some(((bucket - today_start) / 3600).clamp(0, 23) as usize)
        } else {
            None
        };
        if today {
            calls.0 += b.count;
        } else {
            calls.1 += b.count;
        }
        if let Some(s) = slot {
            hourly_calls[s] += b.count;
        }
        match b.outcome.as_str() {
            "denied" => {
                if today {
                    denied.0 += b.count;
                } else {
                    denied.1 += b.count;
                }
                if let Some(s) = slot {
                    hourly_denied[s] += b.count;
                }
            }
            "execution_error" => {
                if today {
                    errors.0 += b.count;
                } else {
                    errors.1 += b.count;
                }
                if let Some(s) = slot {
                    hourly_errors[s] += b.count;
                }
            }
            _ => {}
        }
    }
    WindowTotals {
        calls,
        denied,
        errors,
        hourly_calls,
        hourly_denied,
        hourly_errors,
    }
}

pub(crate) async fn overview(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let upstreams = upstream_tiles(&state.upstreams).await;
    let upstreams_total = upstreams.len();
    let upstreams_degraded = upstreams
        .iter()
        .filter(|u| u.runtime_status == "degraded")
        .count();
    let upstreams_down = upstreams
        .iter()
        .filter(|u| u.runtime_status == "disconnected")
        .count();

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);

    // Red banner. Gated on mcp:admin + non-peer-assertion so
    // a non-admin SSO session can't infer that active overrides
    // exist by reading the banner copy (the page itself is
    // already gated; mirror the same posture here). Tenant comes
    // from the principal, NOT tenant_ctx — same rule the
    // /break_glass page enforces.
    let active_break_glass_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let (active_break_glass, active_break_glass_saturated) =
        if overview_break_glass_admin(user_principal) {
            let count = crate::dashboard_break_glass::count_active_for_banner(
                state.policy.break_glass.get(),
                &active_break_glass_tenant,
            )
            .await;
            match count {
                Some(0) => (None, false),
                Some(n) => {
                    let (n, sat) = crate::dashboard_break_glass::active_banner_label(n);
                    (Some(n), sat)
                }
                None => (None, false),
            }
        } else {
            (None, false)
        };

    // KPI tiles + attention queue. Same admin posture as the
    // break-glass banner: a non-admin SSO session sees `None` on
    // both tiles and an empty attention queue (the catalog reads
    // are skipped). Tenant is the principal's, never tenant_ctx.
    let approvals_tenant = active_break_glass_tenant.clone();
    let (active_approvals, expired_unused_approvals) = if overview_break_glass_admin(user_principal)
    {
        let store = state.servers.catalog.get();
        let active =
            crate::dashboard_approvals::count_active_for_attention(store, &approvals_tenant).await;
        let expired = crate::dashboard_approvals::count_expired_unused_for_attention(
            store,
            &approvals_tenant,
        )
        .await;
        (active, expired)
    } else {
        (None, None)
    };

    // Tenant-aware deep-link builder. Uses the same `nav_url`
    // helper the template's `self.nav_url` calls into, so a
    // tenant-prefixed URL ends up with the slug carried through.
    let ctx_ref = tenant_ctx.as_ref();
    let nav_for_attention = |path: &str| crate::tenant_ctx::nav_url(ctx_ref, path);
    let mut attention_items = attention_items_for_overview(
        active_break_glass,
        active_break_glass_saturated,
        active_approvals,
        expired_unused_approvals,
        &nav_for_attention,
    );

    if overview_break_glass_admin(user_principal) && state.hitl.reviewed_skills.get().is_some() {
        match crate::dashboard_skills::current_reviews(&state, &approvals_tenant).await {
            Ok(reviews) => {
                let pending = reviews
                    .iter()
                    .filter(|review| {
                        review.candidate_status == waygate_skills::review::CandidateStatus::Pending
                    })
                    .count();
                if pending > 0 {
                    attention_items.push(AttentionItem {
                        severity: "warn",
                        label: format!("{pending} skill candidates need review"),
                        hint: "Unapproved contents remain unavailable to clients.",
                        href: nav_for_attention("/skills"),
                    });
                }
            }
            Err(_) => attention_items.push(AttentionItem {
                severity: "warn",
                label: "Skill reviews are unavailable".into(),
                hint: "Review state could not be read; skill distribution fails closed.",
                href: nav_for_attention("/skills"),
            }),
        }
    }

    // Figures + "what changed" feed. One 48h hourly
    // histogram feeds all three deltas so they agree on the window;
    // the feed is three cheap category-filtered queries merged by
    // time. Tenant scope follows the same rule as the banner above
    // (the principal's tenant). Every failure path collapses to
    // None/empty — the template renders a caption line, never a
    // dead tile.
    let overview_tenant = active_break_glass_tenant.clone();
    // Compute the figures/"what changed" feed and the notable feed
    // concurrently — both are independent tenant-scoped audit reads, each on
    // its own reader-pool connection.
    let figures_changed_fut = async {
        match state.observability.audit.get() {
            None => (None, Vec::new()),
            Some(reader) => {
                let now = OffsetDateTime::now_utc();
                // category="invocation" scopes the figures to actual tool
                // calls — admin mutations, auth events, and reloads are NOT
                // calls and would inflate volume + dilute the deny/error
                // rates the labels promise.
                let q = waygate_storage::audit::AuditQuery {
                    tenant_id: Some(overview_tenant.clone()),
                    category: Some("invocation".to_owned()),
                    since: Some(now - time::Duration::hours(48)),
                    ..Default::default()
                };
                let figures = match reader.histogram(&q, 3600).await {
                    Err(e) => {
                        tracing::warn!(error = %e, "overview histogram failed");
                        None
                    }
                    Ok(buckets) => {
                        let t = split_histogram(&buckets, now.unix_timestamp());
                        let deny_rate_pct =
                            (t.denied.0 * 100).checked_div(t.calls.0).unwrap_or(0) as u32;
                        // The deny-rate delta tracks the RATE, not the raw
                        // denial count — a call-volume swing must not masquerade
                        // as a policy trend.
                        let deny_rate_yesterday =
                            (t.denied.1 * 100).checked_div(t.calls.1).unwrap_or(0) as u32;
                        let peak = |s: &[i64]| s.iter().copied().max().unwrap_or(0);
                        Some(OverviewFigures {
                            calls_today: t.calls.0,
                            calls_delta: fmt_delta(t.calls.0, t.calls.1),
                            deny_rate_pct,
                            deny_delta: fmt_rate_delta(
                                deny_rate_pct,
                                deny_rate_yesterday,
                                t.calls.1 > 0,
                            ),
                            errors_today: t.errors.0,
                            errors_delta: fmt_delta(t.errors.0, t.errors.1),
                            calls_spark_points: spark_points(&t.hourly_calls),
                            calls_spark_peak: peak(&t.hourly_calls),
                            deny_spark_points: spark_points(&t.hourly_denied),
                            deny_spark_peak: peak(&t.hourly_denied),
                            errors_spark_points: spark_points(&t.hourly_errors),
                            errors_spark_peak: peak(&t.hourly_errors),
                        })
                    }
                };

                let mut changed: Vec<(OffsetDateTime, ChangedEvent)> = Vec::new();
                for (category, kind, dest, limit) in [
                    ("policy_reload", "policy", "/policies", 5i64),
                    ("manifest_reload", "servers", "/servers", 5i64),
                    ("api_key_lifecycle", "identity", "/identities", 5i64),
                    // Surface the change-request ceremony. The broad
                    // `admin_mutation` category is filtered to the configurable
                    // allowlist below, so fetch a wider window (ceremony rows may
                    // sit behind unrelated mutations) before the global cap of 8.
                    ("admin_mutation", "control plane", "/changes", 20i64),
                ] {
                    // The tenant/category/ID index serves this bounded feed
                    // without scanning unrelated categories or sorting history.
                    if let Ok(rows) = reader
                        .recent_by_category(&overview_tenant, category, limit)
                        .await
                    {
                        for r in rows {
                            // `admin_mutation` is heterogeneous (secret-retrievals,
                            // oauth/session revokes, …); surface only the curated
                            // change-request ceremony actions (configurable via
                            // GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS) so the feed shows
                            // propose/approve/execute without the noise. Other
                            // categories pass through unfiltered.
                            if category == "admin_mutation"
                                && !state
                                    .dashboard
                                    .overview_change_feed_actions
                                    .iter()
                                    .any(|a| a == &r.action)
                            {
                                continue;
                            }
                            changed.push((
                                r.ts,
                                ChangedEvent {
                                    ts_abs: format_ts_abs(r.ts),
                                    ts_rel: format_ts_rel(r.ts),
                                    kind,
                                    // `<action> · <target> · <principal>` when
                                    // the row names a subject (migration 0046's
                                    // `target` column — e.g. the API key's sub),
                                    // else the legacy `<action> · <principal>`.
                                    // Without the target, two ApiKeyMinted rows
                                    // for different keys collapse to an identical
                                    // line; the subject is what disambiguates them.
                                    summary: match r.target.as_deref() {
                                        Some(t) if !t.is_empty() => format!(
                                            "{} · {} · {}",
                                            action_label(&r),
                                            t,
                                            principal_label(&r),
                                        ),
                                        _ => format!(
                                            "{} · {}",
                                            action_label(&r),
                                            principal_label(&r),
                                        ),
                                    },
                                    href: nav_for_attention(dest),
                                },
                            ));
                        }
                    }
                }
                changed.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
                let changed: Vec<ChangedEvent> =
                    changed.into_iter().take(8).map(|(_, e)| e).collect();
                (figures, changed)
            }
        }
    };

    // Recent non-success events, tenant-scoped. Computed
    // concurrently with the figures/changed feed above (separate connections).
    let ((figures, changed), notable) = tokio::join!(
        figures_changed_fut,
        overview_notable(&state, &overview_tenant),
    );

    // First-run "Getting started" checklist. Cheap config signals → setup
    // milestones; the card hides itself (None) once everything is wired.
    let setup_steps = vec![
        SetupStep {
            label: "Connect an upstream",
            hint: "Drop a manifest into servers/ and redeploy.",
            done: upstreams_total > 0,
            href: nav_for_attention("/servers"),
        },
        SetupStep {
            label: "Wire the audit store",
            hint: "Set GATEWAY_DATABASE_URL to persist evidence.",
            done: state.observability.audit.enabled(),
            href: nav_for_attention("/activity"),
        },
        SetupStep {
            label: "Enable API keys",
            hint: "Set GATEWAY_API_KEYS_ENABLED=true to mint client keys.",
            done: state.identity.api_keys_feature.enabled(),
            href: nav_for_attention("/identities"),
        },
        SetupStep {
            label: "Load a Cedar policy",
            hint: "Drop .cedar files into policies/ to govern tool access.",
            // Require a NON-EMPTY policy set: an empty / comments-only
            // policies dir still yields a valid *empty* Cedar engine, which
            // shouldn't satisfy this milestone.
            done: state
                .policy
                .cedar
                .get()
                .is_some_and(|c| !c.list_policies().is_empty()),
            href: nav_for_attention("/policies"),
        },
    ];
    let done_count = setup_steps.iter().filter(|s| s.done).count();
    let total = setup_steps.len();
    let getting_started = if done_count == total {
        None
    } else {
        Some(GettingStarted {
            steps: setup_steps,
            done_count,
            total,
            playground_href: nav_for_attention("/playground"),
        })
    };

    let user_display_str = user.map(|Extension(p)| user_display(&p));

    let page = OverviewPage {
        chrome: PageChrome::build(
            &state,
            "Overview",
            "/",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        upstreams,
        upstreams_total,
        upstreams_degraded,
        upstreams_down,
        figures,
        changed,
        audit_available: state.observability.audit.enabled(),
        notable,
        active_break_glass,
        active_break_glass_saturated,
        attention_items,
        getting_started,
    };
    render(&page)
}

/// Compose the attention-queue rows from the
/// already-computed counts. Pure function (no I/O) so the
/// ordering / severity assignment is easy to unit-test.
///
/// Ordering: critical first (break-glass — bypasses the
/// policy gate), then warn (active approvals — callers
/// blocked on operator action), then info (expired-unused —
/// signal, not urgent). Each input that's `None` or
/// `Some(0)` is skipped entirely. Empty result = "nothing
/// needs operator attention right now."
pub(crate) fn attention_items_for_overview(
    active_break_glass: Option<usize>,
    active_break_glass_saturated: bool,
    active_approvals: Option<usize>,
    expired_unused_approvals: Option<usize>,
    nav: &dyn Fn(&str) -> String,
) -> Vec<AttentionItem> {
    let mut items = Vec::new();
    if let Some(n) = active_break_glass.filter(|n| *n > 0) {
        let count_label = if active_break_glass_saturated {
            format!("{n}+")
        } else {
            n.to_string()
        };
        items.push(AttentionItem {
            severity: "critical",
            label: format!(
                "{count_label} active break-glass token{}",
                if n == 1 { "" } else { "s" }
            ),
            hint: "Single-use overrides currently bypassing the policy gate.",
            href: nav("/break_glass"),
        });
    }
    if let Some(n) = active_approvals.filter(|n| *n > 0) {
        items.push(AttentionItem {
            severity: "warn",
            label: format!(
                "{n} HITL approval grant{} waiting",
                if n == 1 { "" } else { "s" }
            ),
            hint: "Callers blocked until an admin claims or the grant expires.",
            href: nav("/approvals"),
        });
    }
    if let Some(n) = expired_unused_approvals.filter(|n| *n > 0) {
        items.push(AttentionItem {
            severity: "info",
            label: format!(
                "{n} expired-unused HITL grant{}",
                if n == 1 { "" } else { "s" }
            ),
            hint: "TTL-too-short signal — admins minted grants the caller never claimed.",
            href: nav("/approvals"),
        });
    }
    items
}

async fn upstream_tiles(pool: &UpstreamPool) -> Vec<UpstreamTile> {
    pool.status_snapshot()
        .await
        .into_iter()
        .map(|status| UpstreamTile {
            name: status.manifest.name,
            transport: transport_str(&status.manifest.transport),
            runtime_status: status.health.runtime_state.as_str(),
            tool_count: status.health.published_tool_count,
        })
        .collect()
}

/// Recent non-success events, selected by event timestamp within the tenant.
async fn overview_notable(state: &AdminState, tenant: &str) -> Vec<NotableEvent> {
    let Some(reader) = state.observability.audit.get() else {
        return Vec::new();
    };
    reader
        .recent_notable(
            tenant,
            OffsetDateTime::now_utc() - time::Duration::days(7),
            NOTABLE_LIMIT as i64,
        )
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| NotableEvent {
            ts_abs: format_ts_abs(r.ts),
            ts_rel: format_ts_rel(r.ts),
            principal: principal_label(r),
            action_label: action_label(r),
            outcome: r.outcome.clone(),
        })
        .collect()
}

// ---- servers --------------------------------------------------------------

#[cfg(test)]
mod overview_figure_tests {
    use super::*;
    use waygate_storage::audit::HistogramBucket;

    fn bucket(epoch: i64, outcome: &str, count: i64) -> HistogramBucket {
        HistogramBucket {
            bucket_epoch: epoch,
            outcome: outcome.to_owned(),
            count,
        }
    }

    #[test]
    fn split_histogram_separates_today_from_yesterday() {
        let now = 200_000;
        let buckets = [
            bucket(now - 1_000, "success", 10),
            bucket(now - 1_000, "denied", 2),
            bucket(now - 90_000, "success", 4),
            bucket(now - 90_000, "execution_error", 1),
        ];
        let t = split_histogram(&buckets, now);
        assert_eq!(t.calls, (12, 5));
        assert_eq!(t.denied, (2, 0));
        assert_eq!(t.errors, (0, 1));
        // Today's rows land in the newest hourly slot.
        assert_eq!(t.hourly_calls.iter().sum::<i64>(), 12);
        assert_eq!(t.hourly_calls[23], 12);
    }

    #[test]
    fn split_histogram_classifies_by_bucket_boundary_not_exact_now() {
        // now is mid-hour (1800s past). The store floors events to the
        // hour, so today/yesterday must be defined by whole buckets — the
        // window is "the last 24 hourly buckets ending at the current
        // hour", not "now minus 86400 seconds".
        let now = 50 * 3600 + 1800; // 13:30 in epoch-hours
        let current_hour = 50 * 3600;
        let today_start = current_hour - 23 * 3600;
        let buckets = [
            // Current partial hour — wholly today.
            bucket(current_hour + 600, "success", 7),
            // The oldest in-window bucket sits exactly on today_start.
            bucket(today_start, "success", 3),
            // One bucket older → yesterday, never bleeds into today.
            bucket(today_start - 3600, "denied", 5),
            // Outside the 48h window entirely → ignored.
            bucket(today_start - 30 * 3600, "success", 99),
        ];
        let t = split_histogram(&buckets, now);
        assert_eq!(
            t.calls,
            (10, 5),
            "boundary bucket counts as today, not split"
        );
        assert_eq!(t.denied, (0, 5));
        // The pre-window bucket is dropped, not summed into yesterday.
        assert_eq!(t.calls.0 + t.calls.1, 15);
        assert_eq!(t.hourly_calls[23], 7, "current hour is the newest slot");
        assert_eq!(t.hourly_calls[0], 3, "today_start is the oldest slot");
        // Per-outcome series populate too: the denied row lands yesterday
        // (slot N/A) so today's deny series is empty here.
        assert_eq!(t.hourly_denied.iter().sum::<i64>(), 0);
    }

    #[test]
    fn fmt_delta_covers_signs_and_zero_baselines() {
        assert_eq!(fmt_delta(150, 100), "+50% vs yesterday");
        assert_eq!(fmt_delta(50, 100), "−50% vs yesterday");
        assert_eq!(fmt_delta(100, 100), "level with yesterday");
        assert_eq!(fmt_delta(5, 0), "none yesterday");
        assert_eq!(fmt_delta(0, 0), "quiet yesterday too");
    }

    #[test]
    fn fmt_rate_delta_reports_percentage_points_not_volume() {
        // Deny rate 2% → 5% is +3pp regardless of how call volume moved.
        assert_eq!(fmt_rate_delta(5, 2, true), "+3pp vs yesterday");
        assert_eq!(fmt_rate_delta(2, 5, true), "−3pp vs yesterday");
        assert_eq!(fmt_rate_delta(4, 4, true), "level with yesterday");
        assert_eq!(fmt_rate_delta(5, 0, false), "no calls yesterday");
    }

    #[test]
    fn spark_points_scales_to_viewbox_and_survives_flat_zero() {
        let pts = spark_points(&[0, 5, 10]);
        let coords: Vec<&str> = pts.split(' ').collect();
        assert_eq!(coords.len(), 3);
        assert!(
            coords[0].ends_with(",26.0"),
            "zero sits on the baseline: {pts}"
        );
        assert!(
            coords[2].ends_with(",2.0"),
            "peak reaches the top pad: {pts}"
        );
        // All-zero input still draws a flat baseline, not NaN/empty.
        let flat = spark_points(&[0, 0, 0, 0]);
        assert!(flat.split(' ').all(|p| p.ends_with(",26.0")), "{flat}");
    }
}
