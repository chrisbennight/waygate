//! Servers page — one of the router-per-domain modules `dashboard.rs`
//! delegates to. Routes stay mounted by `dashboard::page_routes`.

use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use uuid::Uuid;
use waygate_core::fmt::format_ts_rfc3339;
use waygate_oidc::Principal;
use waygate_upstream::{CatalogRefreshOutcome, CatalogRefreshReport};

use super::dashboard::*;
use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "servers.html")]
struct ServersPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// When true, the operational action forms (reconnect / catalog refresh /
    /// clear quarantine) render. They POST to admin-gated handlers, so a
    /// non-admin would only get a 403 — hide them instead.
    is_admin: bool,
    /// When true, an on-disk `servers/*.yaml` set is configured to apply —
    /// the "Reload manifests" button renders (admins only). Mirrors
    /// `state.servers.servers_dir.is_some()`; reload reads disk (the source of
    /// truth), so it does NOT require a DB manifest store.
    reload_available: bool,
    /// True when a load/reload was refused and the gateway is serving
    /// a stale set — drives a prominent banner. `config_detail` is the human
    /// reason (incl. "stale Nm").
    config_degraded: bool,
    config_detail: String,
    servers: Vec<ServerRow>,
}

struct ServerRow {
    name: String,
    transport: &'static str,
    /// Authoritative runtime availability from the pool snapshot. Presentation
    /// must not re-derive health from lane and breaker fields independently.
    runtime_status: &'static str,
    breaker: &'static str,
    connected_lanes: usize,
    total_lanes: usize,
    last_success_at: String,
    last_error_class: String,
    next_retry_at: String,
    /// Joined negotiated protocol generations across connected lanes
    /// (`"2026-07-28"`, or `"2025-11-25 + 2026-07-28"` mid-migration);
    /// empty string when every lane is down.
    protocol: String,
    published_tool_count: usize,
    classified_tool_count: usize,
    url: Option<String>,
    /// Pre-built, URL-encoded drill-down into the filtered Tools console.
    /// Built server-side because `UpstreamManifest.name` is a free string
    /// that may contain reserved query characters — same fix the Activity
    /// facet hrefs use.
    tools_url: String,
    /// Pre-built, URL-encoded base for the per-server config accordion
    /// fragment (`/servers/config?server=<enc>`); the template appends
    /// `&tab=<tab>`. Query-param (not a path segment) so a free-string name
    /// with reserved chars stays safe — same reasoning as `tools_url`.
    config_url: String,
    /// Count of tools auto-quarantined by the drift detector. >0 ⇒ the
    /// "clear quarantine" action renders for admins.
    quarantined: usize,
    /// Count of tools published without the output schema this upstream
    /// advertised, because the schema's root was not `type: "object"`.
    /// A non-zero count means the upstream is emitting definitions a strict
    /// MCP client would discard the whole catalog over; the row flags it so
    /// an operator sees it without filtering the activity log.
    rejected_output_schemas: usize,
}

pub(crate) async fn servers_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let is_admin =
        crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)).is_ok();
    let tools_base =
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref().map(|Extension(c)| c), "/tools");
    let config_base =
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref().map(|Extension(c)| c), "/servers/config");
    let mut servers = Vec::new();
    for status in state.upstreams.status_snapshot().await {
        let m = status.manifest;
        let health = status.health;
        let enc = urlencode(&m.name);
        let tools_url = format!("{tools_base}?server={enc}");
        let config_url = format!("{config_base}?server={enc}");
        servers.push(ServerRow {
            name: m.name,
            transport: transport_str(&m.transport),
            runtime_status: health.runtime_state.as_str(),
            breaker: health.breaker.as_str(),
            connected_lanes: health.connected_lanes,
            total_lanes: health.total_lanes,
            last_success_at: health
                .last_success_at
                .map(format_ts_rfc3339)
                .unwrap_or_else(|| "never".to_owned()),
            last_error_class: health
                .last_error_class
                .map(|class| class.as_str().to_owned())
                .unwrap_or_else(|| "none".to_owned()),
            next_retry_at: health
                .next_retry_at
                .map(format_ts_rfc3339)
                .unwrap_or_else(|| "not scheduled".to_owned()),
            protocol: health.protocol_versions.join(" + "),
            published_tool_count: health.published_tool_count,
            classified_tool_count: m.tools.len(),
            url: m.url,
            tools_url,
            config_url,
            quarantined: health.quarantined_tool_count,
            rejected_output_schemas: health.rejected_output_schema_count,
        });
    }
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    // Surface a prominent banner when the config is degraded — a
    // load/reload was refused and the gateway is serving a stale set.
    let (config_degraded, config_detail) = match state
        .servers
        .config_health
        .as_ref()
        .and_then(|h| h.snapshot())
    {
        Some(s) if !s.healthy => (
            true,
            format!("{} (stale {})", s.detail, secs_ago(s.since_unix)),
        ),
        _ => (false, String::new()),
    };
    render(&ServersPage {
        chrome: PageChrome::build(
            &state,
            "Servers",
            "/servers",
            &headers,
            user.map(|Extension(p)| user_display(&p)),
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        is_admin,
        reload_available: state.servers.servers_dir.is_some(),
        config_degraded,
        config_detail,
        servers,
    })
}

/// Compact "Ns / Nm / Nh" age for a unix-seconds timestamp (config-degraded
/// banner). `pub(crate)` so the Policies page reuses it for its analogous
/// policy-health banner.
pub(crate) fn secs_ago(since_unix: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(since_unix);
    let s = (now - since_unix).max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

/// Form body for the Servers operational actions.
#[derive(Debug, Deserialize)]
pub(crate) struct ServerActionForm {
    /// Defaulted so a missing csrf field lands in the handler's own CSRF
    /// check (→ 403) rather than a 422 deserialize error — matches the
    /// `/policies/simulate` precedent.
    #[serde(default)]
    csrf: String,
    server: String,
}

#[derive(Template)]
#[template(path = "server_catalog_refresh_result.html")]
struct ServerCatalogRefreshResult {
    ok: bool,
    failed: bool,
    superseded: bool,
    server: String,
    outcome: &'static str,
    session_replaced: bool,
    before_tool_count: usize,
    after_tool_count: usize,
    added: Vec<String>,
    removed: Vec<String>,
    schema_changed: Vec<String>,
}

impl From<CatalogRefreshReport> for ServerCatalogRefreshResult {
    fn from(report: CatalogRefreshReport) -> Self {
        Self {
            ok: matches!(
                report.outcome,
                CatalogRefreshOutcome::Updated | CatalogRefreshOutcome::Unchanged
            ),
            failed: report.outcome == CatalogRefreshOutcome::Failed,
            superseded: report.outcome == CatalogRefreshOutcome::Superseded,
            server: report.server,
            outcome: report.outcome.as_str(),
            session_replaced: report.session_replaced,
            before_tool_count: report.before_tool_count,
            after_tool_count: report.after_tool_count,
            added: report.added,
            removed: report.removed,
            schema_changed: report.schema_changed,
        }
    }
}

/// Form body for the manifests-reload action — CSRF only (reload is a
/// whole-set operation, not per-server).
#[derive(Debug, Deserialize)]
pub(crate) struct ReloadForm {
    #[serde(default)]
    csrf: String,
}

/// htmx result fragment for the "Reload manifests" action: a status banner
/// swapped into `#reload-result`. Reports what the reload applied — including
/// hot add (dial + publish), hot remove (drain + drop), and connection-shape
/// changes re-dialed or rebuilt live (`redialed`). A shape change whose every
/// new-shape dial failed is reported as `redial_failed` (old shape kept). A
/// resource-ownership edit coupled to a shape edit is refused before mutation
/// and rendered through [`reload_err`] instead of this applied-result shape.
#[derive(Template)]
#[template(path = "servers_reload_result.html")]
struct ReloadResultFragment {
    ok: bool,
    message: String,
    version: i32,
    noop: bool,
    updated: usize,
    identity_updated: usize,
    session_policy_updated: usize,
    redialed: usize,
    redial_failed: usize,
    added: usize,
    removed: usize,
    /// This reload's set is NOT the one now live — a newer concurrent reload won,
    /// or a kept upstream was concurrently removed. The banner
    /// says "superseded" rather than "Applied", since the on-disk set the operator
    /// clicked Reload for is not what the live registry reflects.
    superseded: bool,
}

fn reload_err(message: impl Into<String>) -> Response {
    render(&ReloadResultFragment {
        ok: false,
        message: message.into(),
        version: 0,
        noop: false,
        updated: 0,
        identity_updated: 0,
        session_policy_updated: 0,
        redialed: 0,
        redial_failed: 0,
        added: 0,
        removed: 0,
        superseded: false,
    })
}

/// `POST /servers/reload` — re-apply the on-disk `servers/*.yaml` set (the
/// source of truth that boot/SIGHUP load) to the live pool in place.
/// Admin-gated + CSRF. Hot-reloads tool classifications, `exchange`, tier
/// flags, AND add/remove of upstreams (a newly-listed server is dialed and
/// published; a delisted one is drained and dropped) — all with no restart.
/// A re-dial that failed on every lane is **restart-required**. An existing
/// server edit that changes connection shape and resource ownership together is
/// refused before mutation and must be applied by restarting (same contract as
/// the SIGHUP path). No DB required; the reported version is the matching
/// ledger snapshot when the on-disk set corresponds to one, else 0 (out-of-band
/// / uncommitted).
pub(crate) async fn servers_reload(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<ReloadForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    if !activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    // Serialize with dashboard manifest writes AND concurrent dashboard
    // reloads: the pool-apply + catalog-reconcile pair below must not
    // interleave with another dashboard mutation of the same authorities.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Read the ON-DISK set — the source of truth that boot/SIGHUP load. No
    // DB required; Reload applies whatever is currently on disk, so an
    // out-of-band servers/*.yaml edit takes effect here too.
    let (manifests, disk_hash) = match state.read_manifest_set_from_disk() {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            // The on-disk set is broken: flip the global config-health
            // signal degraded so the whole Servers page renders the Config
            // STALE banner, not just this inline reload error — a reload
            // refusal must not leave the page reading healthy.
            if let Some(health) = state.servers.config_health.as_ref() {
                health.set_degraded(format!(
                    "dashboard reload: servers/*.yaml does not parse ({e}) — serving the previous set"
                ));
            }
            return reload_err(format!(
                "The on-disk manifest set (servers/*.yaml) does not parse: {e}"
            ));
        }
        None => return reload_err("No servers dir configured — nothing to reload."),
    };
    // Apply the same prod-profile safety gate as boot/SIGHUP *before*
    // mutating the live pool: in `prod`, refuse a set containing a
    // `transport: stdio` upstream (`reload_manifests` would otherwise still
    // copy tool classifications / exchange / tier for existing entries).
    // Fail-closed: keep the previous set, report the refusal.
    if let Err(msg) = waygate_upstream::enforce_no_prod_stdio(
        state.system.deployment_profile == "prod",
        &manifests,
    ) {
        // Prod safety refused the on-disk set: the live pool keeps the
        // previous (safe) set, so the running config no longer matches
        // what is on disk — signal degraded for the Config STALE banner.
        if let Some(health) = state.servers.config_health.as_ref() {
            health.set_degraded(format!(
                "dashboard reload refused (prod safety): {msg} — serving the previous set"
            ));
        }
        return reload_err(format!("On-disk set refused: {msg}"));
    }
    let report = state.upstreams.reload_manifests(&manifests).await;
    if !report.resource_shape_restart_required.is_empty() {
        let servers = report.resource_shape_restart_required.join(", ");
        if let Some(health) = state.servers.config_health.as_ref() {
            health.set_degraded(format!(
                "dashboard reload refused before mutation: resource ownership and connection \
                 shape changed together for {servers}; restart required"
            ));
        }
        return reload_err(format!(
            "Reload refused before mutation: resource ownership and connection shape changed \
             together for {servers}. Restart the gateway to apply the complete manifest set."
        ));
    }
    // Reconcile the governed catalog AFTER the pool applies the set. The pool
    // arms a per-tool generation fence before changed authorization inputs
    // become observable, so calls cannot combine the new manifest with the
    // preceding catalog while this import is pending or failed. The callback
    // also arms the reload task's latch so a concurrent dashboard/doorbell
    // interleaving converges again from current disk truth. A failure here
    // therefore degrades health and reports honestly — the applied pool reload
    // cannot be pretended away. Skipped when superseded: the winning reload
    // owns the control-plane side-effects.
    if !report.superseded {
        if let Some(reconcile) = state.servers.catalog_reconcile.as_ref() {
            match reconcile(manifests.clone()).await {
                Ok((servers, tools)) => {
                    state.upstreams.settle_catalog_reconcile(&report);
                    tracing::info!(
                        servers,
                        tools,
                        "catalog reconciled from dashboard manifest reload",
                    );
                }
                Err(e) => {
                    if let Some(health) = state.servers.config_health.as_ref() {
                        health.set_degraded(format!(
                            "dashboard reload applied, but the catalog reconcile \
                             failed ({e}) — the reload task retries until the \
                             catalog converges"
                        ));
                    }
                    return reload_err(format!(
                        "Reload applied to the live pool, but the catalog reconcile \
                         failed: {e}. The reload task retries automatically; config \
                         health stays degraded until it succeeds."
                    ));
                }
            }
        }
    }
    // Best-effort version label: the ledger snapshot whose hash matches the
    // on-disk set, else 0 (the on-disk set is uncommitted / out-of-band).
    // Compare the bundle's CANONICAL hash (what disk holds) to `disk_hash`, not
    // its raw stored `content_hash`: a non-canonical-but-valid published draft
    // hashes differently raw vs canonical, so the raw comparison would mislabel
    // a faithfully-published set as version 0.
    let version = match state.servers.manifest_store.get() {
        Some(store) => match store.active_bundle(waygate_core::TenantId::DEFAULT).await {
            Ok(b)
                if crate::dashboard_server_manifests::canonical_disk_hash(&b.content)
                    .map(|h| h == disk_hash)
                    .unwrap_or(false) =>
            {
                b.version
            }
            _ => 0,
        },
        None => 0,
    };
    // Reconcile the turnstile pointer to disk on a dashboard Reload too,
    // so clicking Reload after an out-of-band servers/*.yaml edit re-syncs the
    // pointer — otherwise the stale pointer CAS-fails the operator's next save
    // permanently. `disk_hash` is already the canonical on-disk hash
    // the write-path CAS compares against.
    // Skip the turnstile-pointer reconcile if a newer concurrent reload
    // superseded this one: `disk_hash` would be the losing set,
    // and reconciling could CAS the pointer backward. The winning reload owns it.
    if !report.superseded {
        if let Some(store) = state.servers.manifest_store.get() {
            match store
                .reconcile_pointer(
                    waygate_core::TenantId::DEFAULT,
                    &disk_hash,
                    "filesystem-dashboard",
                )
                .await
            {
                Ok(waygate_manifest_store::PointerReconcile::Advanced { from }) => {
                    tracing::warn!(
                        from = %from,
                        to = %disk_hash,
                        "dashboard reload reconciled the turnstile pointer (out-of-band edit detected)",
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "dashboard reload: turnstile pointer reconcile failed (non-fatal)",
                ),
            }
        }
    }
    record_server_action(
        &state,
        user.as_ref().map(|Extension(p)| p),
        "dashboard.server.reload",
        format!(
            "from servers/*.yaml; updated={}; identity_updated={}; session_policy_updated={}; redialed={}; redial_failed={}; added={}; removed={}",
            report.classifications_updated.len(),
            report.identity_updated.len(),
            report.session_policy_updated.len(),
            report.redialed.len(),
            report.redial_failed.len(),
            report.added.len(),
            report.removed.len(),
        ),
    )
    .await;
    // A clean on-disk reload applied: the live set now matches
    // servers/*.yaml, so clear any prior stale state (e.g. a degraded
    // signal left by a failed SIGHUP or an earlier broken-file reload) —
    // the Config STALE banner must drop here, without a restart.
    // Skipped if superseded: the winning reload owns the signal.
    if !report.superseded {
        if let Some(health) = state.servers.config_health.as_ref() {
            health.set_healthy(format!(
                "{} upstream(s) reloaded from servers/*.yaml via dashboard",
                manifests.len()
            ));
        }
    }
    render(&ReloadResultFragment {
        ok: true,
        message: String::new(),
        version,
        noop: report.is_noop(),
        updated: report.classifications_updated.len(),
        identity_updated: report.identity_updated.len(),
        session_policy_updated: report.session_policy_updated.len(),
        redialed: report.redialed.len(),
        redial_failed: report.redial_failed.len(),
        added: report.added.len(),
        removed: report.removed.len(),
        superseded: report.superseded,
    })
}

/// Query for the per-server config accordion fragment:
/// `GET /servers/config?server=<name>&tab=<tab>`. `server` is a query value
/// (not a path segment) so a free-string name with reserved chars is safe,
/// matching the `tools_url` drill-down.
#[derive(Debug, Deserialize)]
pub(crate) struct ServerConfigQuery {
    server: String,
    /// Selected tab: `overview` (read-only) or one of the editable
    /// Classifications / Session / Identity tabs. An omitted `tab`
    /// falls back to `overview`; an unrecognized value 404s.
    #[serde(default)]
    tab: Option<String>,
}

/// Read-only per-server config panel (the accordion body) — the Overview
/// tab. The Classifications / Session / Identity tabs render as separate
/// editable fragments against the same endpoint.
#[derive(Template)]
#[template(path = "server_config_fragment.html")]
struct ServerConfigFragment {
    /// Active tab key (`"overview"`); drives the tab-nav highlight.
    active_tab: &'static str,
    name: String,
    /// `?server=`-scoped base for the in-panel tab nav; each tab hx-gets
    /// `{config_url}&tab=<tab>`.
    config_url: String,
    /// Gates the Reconnect / Refresh-catalog / Clear-quarantine forms (admins
    /// only), mirroring the servers table's `is_admin` gate.
    is_admin: bool,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    // ---- Overview view model (all manifest-derived, read-only) ----
    runtime_status: &'static str,
    breaker: &'static str,
    connected_lanes: usize,
    total_lanes: usize,
    last_success_at: String,
    last_error_class: String,
    next_retry_at: String,
    transport: &'static str,
    endpoint: String,
    isolation: &'static str,
    isolation_note: &'static str,
    scope: &'static str,
    concurrency: String,
    identity_tier: &'static str,
    tier_a_required: bool,
    exchange_audience: Option<String>,
    auth_bearer_env: Option<String>,
    mtls_configured: bool,
    tool_count: usize,
    published_tool_count: usize,
    risk_high: usize,
    risk_medium: usize,
    risk_low: usize,
    quarantined: usize,
}

impl ServerConfigFragment {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// `GET /servers/config?server=<name>&tab=overview` — htmx-loaded body of the
/// servers-page accordion. Read-only: surfaces the resolved connection,
/// identity-chaining tier, dial-time auth, and tool-risk summary for one
/// upstream (never any secret — only the bearer env var *name*). Readable by
/// any dashboard user, same as the servers table; the relocated
/// Reconnect / Refresh-catalog / Clear-quarantine forms inside it stay
/// admin-gated.
pub(crate) async fn server_config_fragment(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Query(q): Query<ServerConfigQuery>,
) -> Response {
    let is_admin =
        crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)).is_ok();
    // Overview, Classifications, Session, and Identity & auth tabs.
    // An unknown tab is a 404, not a silent fall-through.
    let active_tab = match q.tab.as_deref() {
        None | Some("overview") => "overview",
        Some("classifications") => "classifications",
        Some("session") => "session",
        Some("identity") => "identity",
        Some(other) => {
            return (StatusCode::NOT_FOUND, format!("unknown tab: {other}")).into_response();
        }
    };
    let Some(manifest) = state
        .upstreams
        .manifests()
        .into_iter()
        .find(|m| m.name == q.server)
    else {
        return (StatusCode::NOT_FOUND, "no such server").into_response();
    };
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    // Query-param base for the in-panel tab nav (each tab hx-gets this with a
    // different &tab=, swapping the whole `.cfg-panel`). Free-string-name safe.
    let config_url = format!(
        "{}?server={}",
        crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/servers/config"),
        urlencode(&manifest.name)
    );

    if active_tab == "identity" {
        return render_identity_tab(
            &state, is_admin, csrf_token, tenant_ctx, config_url, &manifest,
        )
        .await;
    }
    if active_tab == "session" {
        return render_session_tab(
            &state, is_admin, csrf_token, tenant_ctx, config_url, &manifest,
        )
        .await;
    }
    if active_tab == "classifications" {
        return render_classifications_tab(
            &state, is_admin, csrf_token, tenant_ctx, config_url, &manifest,
        )
        .await;
    }

    let Some(status) = state
        .upstreams
        .status_snapshot()
        .await
        .into_iter()
        .find(|status| status.health.name == manifest.name)
    else {
        return (StatusCode::NOT_FOUND, "server was removed during snapshot").into_response();
    };
    let manifest = status.manifest;
    let health = status.health;

    // Identity-chaining tier. tier_c_peer and exchange are mutually exclusive
    // (manifest guardrail), so the order here is unambiguous.
    let (identity_tier, exchange_audience) = if manifest.tier_c_peer.is_some() {
        ("Tier C — peer assertion", None)
    } else if let Some(ex) = manifest.exchange.as_ref() {
        (
            "Tier A — RFC 8693 token exchange",
            Some(ex.audience.clone()),
        )
    } else {
        ("Tier B — gateway identity (X-MCP-Identity)", None)
    };

    let isolation = match waygate_upstream::pool::resolve_isolation(&manifest) {
        waygate_upstream::SessionIsolation::PerCall => "per_call",
        waygate_upstream::SessionIsolation::Reuse => "reuse",
    };
    let isolation_note = match manifest.transport {
        waygate_upstream::Transport::Stdio => "fixed for stdio",
        _ => {
            if manifest
                .session
                .as_ref()
                .and_then(|s| s.isolation)
                .is_some()
            {
                "manifest override"
            } else {
                "default (paranoid)"
            }
        }
    };
    let scope = match manifest.session.as_ref().and_then(|s| s.scope) {
        Some(waygate_upstream::SessionScope::Shared) => "shared",
        _ => "per_principal",
    };
    let concurrency = match manifest.transport {
        waygate_upstream::Transport::Stdio => "1 (stdio)".to_string(),
        _ => manifest
            .session
            .as_ref()
            .and_then(|s| s.concurrency)
            .map(|c| c.to_string())
            .unwrap_or_else(|| "default".to_string()),
    };
    let endpoint = match (&manifest.url, &manifest.command) {
        (Some(u), _) => u.clone(),
        (None, Some(cmd)) => cmd.join(" "),
        _ => "–".to_string(),
    };

    let (mut risk_high, mut risk_medium, mut risk_low) = (0usize, 0usize, 0usize);
    for t in &manifest.tools {
        match t.risk {
            waygate_mcp::protocol::RiskTier::High => risk_high += 1,
            waygate_mcp::protocol::RiskTier::Medium => risk_medium += 1,
            waygate_mcp::protocol::RiskTier::Low => risk_low += 1,
        }
    }

    render(&ServerConfigFragment {
        active_tab,
        name: manifest.name.clone(),
        config_url,
        is_admin,
        csrf_token,
        tenant_ctx,
        runtime_status: health.runtime_state.as_str(),
        breaker: health.breaker.as_str(),
        connected_lanes: health.connected_lanes,
        total_lanes: health.total_lanes,
        last_success_at: health
            .last_success_at
            .map(format_ts_rfc3339)
            .unwrap_or_else(|| "never".to_owned()),
        last_error_class: health
            .last_error_class
            .map(|class| class.as_str().to_owned())
            .unwrap_or_else(|| "none".to_owned()),
        next_retry_at: health
            .next_retry_at
            .map(format_ts_rfc3339)
            .unwrap_or_else(|| "not scheduled".to_owned()),
        transport: transport_str(&manifest.transport),
        endpoint,
        isolation,
        isolation_note,
        scope,
        concurrency,
        identity_tier,
        tier_a_required: manifest.tier_a_required,
        exchange_audience,
        auth_bearer_env: manifest.auth.as_ref().and_then(|a| a.bearer_env.clone()),
        mtls_configured: manifest.mtls.is_some(),
        tool_count: manifest.tools.len(),
        published_tool_count: health.published_tool_count,
        risk_high,
        risk_medium,
        risk_low,
        quarantined: health.quarantined_tool_count,
    })
}

/// One row of the Classifications tab — a tool's current classification.
struct ClassRow {
    name: String,
    /// `"low"`/`"medium"`/`"high"`, for the `<select>` selected state.
    risk: &'static str,
    side_effects: bool,
    pii: bool,
}

/// Classifications tab body (editable form, or read-only with a note).
#[derive(Template)]
#[template(path = "server_config_classifications.html")]
struct ServerClassificationsFragment {
    name: String,
    config_url: String,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    /// `true` ⇒ editable form (admin + manifest store + the server is present
    /// in the active bundle). `false` ⇒ read-only with `readonly_note`.
    editable: bool,
    readonly_note: &'static str,
    /// True only when read-only *because* the user lacks mcp:admin
    /// (vs no store / stdio) — drives the step-up re-authorize link.
    admin_required: bool,
    /// Active-bundle `content_hash` captured at render — the save refuses if
    /// the bundle changed since (stale-edit guard).
    base_hash: String,
    /// `mcp_annotations` governs this server: the legacy `side_effects`/`pii`
    /// manifest flags are required-false and the runtime conservatively
    /// forces BOTH facts true until claim enforcement lands — so the view
    /// shows that enforced posture and offers no legacy checkboxes (a save
    /// then correctly writes the required-false values).
    annotation_mode: bool,
    rows: Vec<ClassRow>,
}

impl ServerClassificationsFragment {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// Build + render the Classifications tab. Editable only when an admin has a
/// manifest store AND the server is in the active (default-tenant) bundle —
/// the same bundle the page's Reload button applies to, so an
/// edit→publish→reload is coherent. Otherwise read-only from the live
/// manifest, with a note pointing at the right path (publish a bundle / fix
/// it / use servers/*.yaml).
/// Resolve the editable on-disk base for a per-server config tab.
/// Editable requires:
/// admin, a wired `servers_dir` whose set parses, the server present in
/// that set, AND a manifest store (the ledger an edit records a snapshot
/// into). Returns the on-disk set + its canonical hash, or a static
/// read-only note plus whether the block is an admin gate (drives the
/// step-up link). Reading the on-disk set — not the DB active bundle — is
/// what makes the tab show, and edit from, the source of truth, so an
/// out-of-band `servers/*.yaml` edit is the base rather than something a
/// later publish silently clobbers.
type DiskBaseSet = std::collections::BTreeMap<String, waygate_upstream::UpstreamManifest>;
fn editable_disk_base(
    state: &AdminState,
    is_admin: bool,
    server_name: &str,
) -> Result<(DiskBaseSet, String), (&'static str, bool)> {
    if !is_admin {
        return Err(("Read-only — mcp:admin is required to edit.", true));
    }
    let Some(res) = state.read_manifest_set_from_disk() else {
        return Err((
            "No servers dir configured — edits go via servers/*.yaml and a redeploy.",
            false,
        ));
    };
    let (set, hash) = res.map_err(|_| {
        (
            "The on-disk manifest set (servers/*.yaml) does not parse — fix it before editing.",
            false,
        )
    })?;
    if !set.contains_key(server_name) {
        return Err((
            "This server isn't in the on-disk set (servers/*.yaml).",
            false,
        ));
    }
    if !state.servers.manifest_store.enabled() {
        return Err((
            "No manifest store configured — an edit records a ledger snapshot, which needs a DB.",
            false,
        ));
    }
    Ok((set, hash))
}

async fn render_classifications_tab(
    state: &Arc<AdminState>,
    is_admin: bool,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    config_url: String,
    manifest: &waygate_upstream::UpstreamManifest,
) -> Response {
    let mut editable = false;
    let mut readonly_note = "";
    let mut admin_required = false;
    let mut base_hash = String::new();
    let mut rows: Vec<ClassRow> = Vec::new();
    let mut annotation_mode = matches!(
        manifest.classification_mode,
        waygate_upstream::ClassificationMode::McpAnnotations
    );

    match editable_disk_base(state, is_admin, &manifest.name) {
        Ok((set, hash)) => {
            editable = true;
            base_hash = hash;
            let m = &set[&manifest.name];
            annotation_mode = matches!(
                m.classification_mode,
                waygate_upstream::ClassificationMode::McpAnnotations
            );
            rows = m
                .tools
                .iter()
                .map(|t| ClassRow {
                    name: t.name.clone(),
                    risk: risk_str(t.risk),
                    side_effects: t.side_effects,
                    pii: t.pii,
                })
                .collect();
        }
        Err((note, admin_req)) => {
            readonly_note = note;
            admin_required = admin_req;
        }
    }

    if !editable {
        rows = manifest
            .tools
            .iter()
            .map(|t| ClassRow {
                name: t.name.clone(),
                risk: risk_str(t.risk),
                side_effects: t.side_effects,
                pii: t.pii,
            })
            .collect();
    }

    render(&ServerClassificationsFragment {
        name: manifest.name.clone(),
        annotation_mode,
        config_url,
        csrf_token,
        tenant_ctx,
        editable,
        readonly_note,
        admin_required,
        base_hash,
        rows,
    })
}

/// htmx result banner shared by the editable config tabs (classifications,
/// session). `apply_hint` tells the operator how to make the published bundle
/// live: reload for hot-reloadable edits, restart for connection-shape ones.
#[derive(Template)]
#[template(path = "server_config_save_result.html")]
struct SaveResultBanner {
    ok: bool,
    message: String,
    version: i32,
    apply_hint: &'static str,
}

fn save_banner_err(message: impl Into<String>) -> Response {
    render(&SaveResultBanner {
        ok: false,
        message: message.into(),
        version: 0,
        apply_hint: "",
    })
}

fn save_banner_ok(version: i32, apply_hint: &'static str) -> Response {
    render(&SaveResultBanner {
        ok: true,
        message: String::new(),
        version,
        apply_hint,
    })
}

/// Shared save path for the editable config tabs. Reads the ON-DISK set
/// (the source of truth — so an out-of-band `servers/*.yaml` edit is the
/// base, not something this clobbers), guards on `base_hash` (stale-edit)
/// against the on-disk hash, applies `patch` to the named server's
/// manifest, validates the serialized set, writes it to disk FIRST (the
/// mirror applies the tenant guard + prod gate), then records a ledger
/// snapshot for history/rollback. Returns the new ledger version, or a
/// human-facing error. The disk write does not itself touch the live pool —
/// the caller's `apply_hint` says how to apply (reload for classifications,
/// restart for session/connection-shape). Validate + write-disk-before-
/// ledger keeps the irreversible step ahead of the bookkeeping.
pub(crate) async fn patch_and_publish(
    state: &Arc<AdminState>,
    store: &waygate_manifest_store::SharedManifestStore,
    user_principal: Option<&Principal>,
    server: &str,
    base_hash: &str,
    audit_action: &'static str,
    patch: impl FnOnce(&mut waygate_upstream::UpstreamManifest) -> Result<(), String>,
) -> Result<i32, String> {
    // Serialize manifest writes in-process so the DB publish and the
    // on-disk mirror stay atomic together: two concurrent edits can't
    // interleave and leave disk on an older version than the ledger's
    // newest (see AdminState.manifest_write_lock).
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Base the edit on the ON-DISK set (the source of truth), NOT the DB
    // ledger — so an out-of-band edit to servers/*.yaml is the base and a
    // dashboard edit can't silently clobber it.
    let (mut set, disk_hash) = match state.read_manifest_set_from_disk() {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(format!("The on-disk manifest set does not parse: {e}")),
        None => return Err("No servers dir configured — cannot edit.".to_owned()),
    };
    // Stale-edit guard against the on-disk hash: refuse if servers/*.yaml
    // changed since the form was rendered.
    if disk_hash != base_hash {
        return Err(
            "The on-disk config changed since you opened this — reopen the tab and re-apply."
                .to_owned(),
        );
    }
    let m = set
        .get_mut(server)
        .ok_or_else(|| "Server is not in the on-disk set.".to_owned())?;
    patch(m)?;
    let patched = waygate_upstream::serialize_manifest_set(&set)
        .map_err(|e| format!("Failed to serialize the patched set: {e}"))?;
    waygate_upstream::parse_manifest_set(&patched)
        .map_err(|e| format!("Patched set is invalid: {e}"))?;
    let author = user_principal.map(|p| p.sub.clone());
    let actor = user_principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned());
    // Cross-replica turnstile: CLAIM the right to write
    // before touching the file. The in-process lock above serializes THIS
    // replica; this PG compare-and-swap serializes ACROSS replicas sharing
    // the servers dir — there is no atomic CAS on NFS file content, so two
    // replicas could otherwise both rename over each other (lost update).
    // The CAS base is the on-disk hash the edit was rendered from (already
    // checked == base_hash); seeding first is idempotent and establishes the
    // pointer on a fresh deploy without clobbering a concurrent writer.
    // No-op guard: if `new_hash == disk_hash` the patch produced the
    // set already on disk, and a `cas_pointer(disk_hash, disk_hash)` would
    // "win" without advancing the pointer — the same lost-update shape the
    // whole-set `turnstile_cas` guards. In this per-server path it is not
    // reachable through the form (the patch re-serializes the whole set, so an
    // identity edit still differs from disk in serialization), but the guard is
    // cheap defense-in-depth for any future form that round-trips exactly.
    let new_hash = waygate_manifest_store::content_hash(&patched);
    if new_hash == disk_hash {
        return Err("That change matches the live on-disk set — nothing to apply.".to_owned());
    }
    store
        .seed_pointer(waygate_core::TenantId::DEFAULT, &disk_hash)
        .await
        .map_err(|e| format!("Turnstile seed failed: {e}. No change was made."))?;
    match store
        .cas_pointer(
            waygate_core::TenantId::DEFAULT,
            &disk_hash,
            &new_hash,
            &actor,
        )
        .await
        .map_err(|e| format!("Turnstile check failed: {e}. No change was made."))?
    {
        waygate_manifest_store::TurnstileOutcome::Won => {}
        waygate_manifest_store::TurnstileOutcome::Lost => {
            return Err(
                "Another replica changed the config since you opened this — \
                        reload the tab and re-apply."
                    .to_owned(),
            );
        }
    }
    // Turnstile won — this writer owns the slot. Write disk (the source of
    // truth; the mirror applies the tenant guard + prod-safety gate). On a
    // write failure (incl. a prod-safety refusal), best-effort roll the
    // pointer back to the base so it doesn't advertise a version that never
    // reached disk; the out-of-band reconciliation is the backstop if
    // the rollback itself fails.
    if let Err(e) = state.mirror_manifest_set_to_disk(waygate_core::TenantId::DEFAULT, &patched) {
        let _ = store
            .cas_pointer(
                waygate_core::TenantId::DEFAULT,
                &new_hash,
                &disk_hash,
                &actor,
            )
            .await;
        return Err(format!(
            "Writing the on-disk manifest dir failed: {e}. No change was made."
        ));
    }
    // Then record the snapshot in the ledger for history / rollback. The
    // disk write already took effect, so a ledger failure is surfaced but
    // the edit is live (out-of-band reconciliation backfills an unrecorded
    // change). Keeps the irreversible disk write ahead of the bookkeeping.
    let draft = store
        .create_draft(waygate_core::TenantId::DEFAULT, &patched, author.as_deref())
        .await
        .map_err(|e| {
            format!(
                "Applied to disk (live after Reload) but recording the ledger draft failed: {e}"
            )
        })?;
    let published = store
        .publish(waygate_core::TenantId::DEFAULT, draft.id, &actor)
        .await
        .map_err(|e| {
            format!("Applied to disk (live after Reload) but publishing the ledger snapshot failed: {e}")
        })?;
    // Doorbell: ping every replica — including this one
    // (read-your-writes: the self-NOTIFY reloads the live pool here too, so a
    // hot-reloadable edit applies without a manual Reload) — to re-read the
    // shared dir. Best-effort: a notify failure is ignored, the poll backstop
    // still converges.
    let _ = store.notify_reload(&new_hash).await;
    record_server_action(
        state,
        user_principal,
        audit_action,
        format!("server={server}; published v{}", published.version),
    )
    .await;
    Ok(published.version)
}

/// `POST /servers/config/classifications` — patch one server's tool
/// classifications in the active (default-tenant) bundle, then `create_draft`
/// plus `publish` a new version. Admin-gated and CSRF-checked.
/// Validate-before-publish; a stale-edit guard (active `content_hash` vs the
/// form's `base_hash`) narrows the read-then-publish race. Publish is durable
/// but does NOT touch the live pool: the operator clicks **Reload manifests**
/// to apply, exactly as the Server Manifests page works.
pub(crate) async fn server_classifications_save(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if let Err(e) = crate::scope::require_admin_extension(user_principal) {
        return e.into_response();
    }
    let csrf_form = form.get("csrf").map(String::as_str).unwrap_or("");
    if !activity_csrf_ok(csrf.as_ref(), csrf_form) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return save_banner_err(
            "No manifest store configured — classifications are edited via servers/*.yaml \
             and a redeploy.",
        );
    };
    let Some(server) = form.get("server").cloned() else {
        return save_banner_err("Missing server.");
    };
    let base_hash = form.get("base_hash").cloned().unwrap_or_default();

    let result = patch_and_publish(
        &state,
        store,
        user_principal,
        &server,
        &base_hash,
        "dashboard.server.classifications",
        |m| {
            let n: usize = form.get("n").and_then(|s| s.parse().ok()).unwrap_or(0);
            if n != m.tools.len() {
                return Err(
                    "Form is out of sync with the bundle — reopen the tab and re-apply.".to_owned(),
                );
            }
            for i in 0..n {
                let name = form.get(&format!("name_{i}")).cloned().unwrap_or_default();
                // base_hash matched, so the tool list is identical to render
                // time and index i must line up with m.tools[i]; verify the
                // name as a guard.
                if name != m.tools[i].name {
                    return Err(
                        "Form is out of sync with the bundle — reopen the tab and re-apply."
                            .to_owned(),
                    );
                }
                m.tools[i].risk = match form.get(&format!("risk_{i}")).map(String::as_str) {
                    Some("high") => waygate_mcp::protocol::RiskTier::High,
                    Some("medium") => waygate_mcp::protocol::RiskTier::Medium,
                    Some("low") => waygate_mcp::protocol::RiskTier::Low,
                    _ => return Err(format!("Invalid risk tier for tool '{name}'.")),
                };
                // Unchecked checkboxes are absent from the form body.
                m.tools[i].side_effects = form.contains_key(&format!("se_{i}"));
                m.tools[i].pii = form.contains_key(&format!("pii_{i}"));
            }
            Ok(())
        },
    )
    .await;

    match result {
        Ok(version) => save_banner_ok(
            version,
            "Classifications are hot-reloadable and apply to the live gateway automatically \
             within moments — or click \"Reload manifests\" (top of page) to apply immediately.",
        ),
        Err(msg) => save_banner_err(msg),
    }
}

/// Session tab body (editable form, or read-only with a note).
#[derive(Template)]
#[template(path = "server_config_session.html")]
pub(crate) struct ServerSessionFragment {
    pub(crate) name: String,
    pub(crate) config_url: String,
    pub(crate) csrf_token: String,
    pub(crate) tenant_ctx: Option<TenantContext>,
    /// `true` ⇒ editable (admin + store + the server is in the active bundle
    /// AND it's HTTP/SSE). stdio sessions are fixed, so they render read-only.
    pub(crate) editable: bool,
    pub(crate) readonly_note: &'static str,
    /// True only when read-only *because* the user lacks mcp:admin
    /// (vs no store / stdio) — drives the step-up re-authorize link.
    pub(crate) admin_required: bool,
    pub(crate) base_hash: String,
    /// Current `session.concurrency` ("" when inherited/default).
    pub(crate) concurrency: String,
    /// Current resolved/selected isolation: "" (inherit) / "per_call" / "reuse".
    pub(crate) isolation: &'static str,
    /// Current selected scope: "" (inherit) / "per_principal" / "shared".
    pub(crate) scope: &'static str,
    /// Current setup-recovery policy: "" (inherit) / "enabled" / "disabled".
    pub(crate) retry_on_setup_failure: &'static str,
    /// Whether this transport implements the safe setup-recovery path.
    pub(crate) setup_recovery_supported: bool,
}

impl ServerSessionFragment {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// Build + render the Session tab. Editable only for an admin with a manifest
/// store when the HTTP/SSE server is in the active bundle. stdio sessions are
/// fixed (one process, reuse), so they render read-only with a note. Session is
/// partly connection-shape: isolation/scope are re-dialed in place, and a
/// concurrency change is rebuilt live (restart-required only if every
/// new-shape dial fails). Setup-recovery policy hot-applies without a re-dial.
async fn render_session_tab(
    state: &Arc<AdminState>,
    is_admin: bool,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    config_url: String,
    manifest: &waygate_upstream::UpstreamManifest,
) -> Response {
    let is_stdio = matches!(manifest.transport, waygate_upstream::Transport::Stdio);
    let mut editable = false;
    let mut readonly_note = "";
    let mut admin_required = false;
    let mut base_hash = String::new();
    // Default the displayed values from the live manifest; overridden from the
    // active bundle when editable.
    let mut session = manifest.session.clone();

    if is_stdio {
        // stdio sessions are fixed regardless of admin, but a non-admin
        // still sees the admin gate first (matches the other tabs).
        if is_admin {
            readonly_note = "stdio sessions are fixed: one child process, reused across calls. \
                             Concurrency and isolation don't apply.";
        } else {
            readonly_note = "Read-only — mcp:admin is required to edit the session policy.";
            admin_required = true;
        }
    } else {
        match editable_disk_base(state, is_admin, &manifest.name) {
            Ok((set, hash)) => {
                editable = true;
                base_hash = hash;
                session = set[&manifest.name].session.clone();
            }
            Err((note, admin_req)) => {
                readonly_note = note;
                admin_required = admin_req;
            }
        }
    }

    let concurrency = session
        .as_ref()
        .and_then(|s| s.concurrency)
        .map(|c| c.to_string())
        .unwrap_or_default();
    let isolation = match session.as_ref().and_then(|s| s.isolation) {
        Some(waygate_upstream::SessionIsolation::PerCall) => "per_call",
        Some(waygate_upstream::SessionIsolation::Reuse) => "reuse",
        None => "",
    };
    let scope = match session.as_ref().and_then(|s| s.scope) {
        Some(waygate_upstream::SessionScope::PerPrincipal) => "per_principal",
        Some(waygate_upstream::SessionScope::Shared) => "shared",
        None => "",
    };
    let retry_on_setup_failure = match session.as_ref().and_then(|s| s.retry_on_setup_failure) {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "",
    };
    let setup_recovery_supported = matches!(manifest.transport, waygate_upstream::Transport::Http);

    render(&ServerSessionFragment {
        name: manifest.name.clone(),
        config_url,
        csrf_token,
        tenant_ctx,
        editable,
        readonly_note,
        admin_required,
        base_hash,
        concurrency,
        isolation,
        scope,
        retry_on_setup_failure,
        setup_recovery_supported,
    })
}

/// `POST /servers/config/session` — patch one server's `session` policy
/// (concurrency / isolation / scope / setup recovery) in the active bundle,
/// then `create_draft`
/// plus `publish`. Admin-gated and CSRF-checked. Setup recovery is request-path
/// policy and hot-applies without a re-dial. The validate-before-publish
/// step runs the manifest guardrail that refuses `isolation: reuse` on an
/// HTTP/SSE upstream without `scope: shared`, so the operator gets that error
/// instead of a silently unsafe bundle. Session is connection-shape, applied
/// live by Reload — isolation/scope re-dialed in place, a concurrency change
/// rebuilt live — so the banner says Reload (restart only if every new-shape
/// dial fails).
pub(crate) async fn server_session_save(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if let Err(e) = crate::scope::require_admin_extension(user_principal) {
        return e.into_response();
    }
    let csrf_form = form.get("csrf").map(String::as_str).unwrap_or("");
    if !activity_csrf_ok(csrf.as_ref(), csrf_form) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return save_banner_err(
            "No manifest store configured — the session policy is edited via servers/*.yaml \
             and a redeploy.",
        );
    };
    let Some(server) = form.get("server").cloned() else {
        return save_banner_err("Missing server.");
    };
    let base_hash = form.get("base_hash").cloned().unwrap_or_default();

    let result = patch_and_publish(
        &state,
        store,
        user_principal,
        &server,
        &base_hash,
        "dashboard.server.session",
        |m| {
            if matches!(m.transport, waygate_upstream::Transport::Stdio) {
                return Err("stdio sessions are fixed and can't be edited.".to_owned());
            }
            let concurrency = match form.get("concurrency").map(|s| s.trim()) {
                None | Some("") => None,
                Some(t) => match t.parse::<usize>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        return Err("Concurrency must be a positive integer or blank.".to_owned())
                    }
                },
            };
            let isolation = match form.get("isolation").map(String::as_str) {
                None | Some("") => None,
                Some("per_call") => Some(waygate_upstream::SessionIsolation::PerCall),
                Some("reuse") => Some(waygate_upstream::SessionIsolation::Reuse),
                Some(other) => return Err(format!("Invalid isolation: {other}.")),
            };
            let scope = match form.get("scope").map(String::as_str) {
                None | Some("") => None,
                Some("per_principal") => Some(waygate_upstream::SessionScope::PerPrincipal),
                Some("shared") => Some(waygate_upstream::SessionScope::Shared),
                Some(other) => return Err(format!("Invalid scope: {other}.")),
            };
            let retry_on_setup_failure =
                match form.get("retry_on_setup_failure").map(String::as_str) {
                    None | Some("") => None,
                    Some("enabled") => Some(true),
                    Some("disabled") => Some(false),
                    Some(other) => return Err(format!("Invalid setup recovery policy: {other}.")),
                };
            if retry_on_setup_failure.is_some()
                && !matches!(m.transport, waygate_upstream::Transport::Http)
            {
                return Err(
                    "Setup recovery policy applies only to streamable HTTP upstreams.".to_owned(),
                );
            }
            // All-inherit ⇒ drop the block entirely so the manifest falls back
            // to the gateway-wide defaults (vs an explicit empty SessionConfig).
            m.session = if concurrency.is_none()
                && isolation.is_none()
                && scope.is_none()
                && retry_on_setup_failure.is_none()
            {
                None
            } else {
                Some(waygate_upstream::SessionConfig {
                    concurrency,
                    isolation,
                    scope,
                    retry_on_setup_failure,
                })
            };
            Ok(())
        },
    )
    .await;

    match result {
        Ok(version) => save_banner_ok(
            version,
            "Setup recovery applies on Reload without replacing healthy sessions. \
             Session isolation/scope are connection-shape but re-dial live: \
             \"Reload manifests\" applies them with no restart. A \
             session.concurrency change resizes the slot pool and is rebuilt \
             live on Reload (no restart) — unless every new-shape dial fails, in \
             which case the old shape is kept and a restart is needed to retry.",
        ),
        Err(msg) => save_banner_err(msg),
    }
}

/// Identity & auth tab body (editable form, or read-only with a note).
#[derive(Template)]
#[template(path = "server_config_identity.html")]
struct ServerIdentityFragment {
    name: String,
    config_url: String,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    /// `true` ⇒ editable (admin + store + HTTP/SSE server in the active
    /// bundle). stdio upstreams use no network auth, so they render read-only.
    editable: bool,
    /// `true` ⇒ offer the `auth.bearer_env` row (HTTP + SSE, per
    /// `Transport::supports_static_bearer`). An SSE upstream keeps this `true`;
    /// hiding it would make Save drop the bearer.
    bearer_editable: bool,
    /// `true` ⇒ offer the mTLS rows (HTTP only, per `Transport::supports_mtls`).
    /// Hidden for SSE — the SSE client has no per-upstream cert wiring.
    mtls_editable: bool,
    readonly_note: &'static str,
    /// True only when read-only *because* the user lacks mcp:admin
    /// (vs no store / stdio) — drives the step-up re-authorize link.
    admin_required: bool,
    base_hash: String,
    // Current values for the form / read-only display.
    exchange_enabled: bool,
    exchange_audience: String,
    exchange_scope: String,
    tier_a_required: bool,
    tier_c_peer: String,
    bearer_env: String,
    mtls_cert: String,
    mtls_key: String,
    mtls_ca: String,
}

impl ServerIdentityFragment {
    /// Fragment delegate — fragments carry no full [`crate::chrome::PageChrome`];
    /// the URL logic lives in [`crate::tenant_ctx::nav_url`].
    fn nav_url(&self, path: &str) -> String {
        crate::tenant_ctx::nav_url(self.tenant_ctx.as_ref(), path)
    }
}

/// Identity-chaining + dial-time auth view model from a manifest. Never any
/// secret — `bearer_env` is the env var *name* and the mTLS fields are file
/// *paths*, not key material.
fn identity_view(m: &waygate_upstream::UpstreamManifest) -> ServerIdentityValues {
    ServerIdentityValues {
        exchange_enabled: m.exchange.is_some(),
        exchange_audience: m
            .exchange
            .as_ref()
            .map(|e| e.audience.clone())
            .unwrap_or_default(),
        exchange_scope: m
            .exchange
            .as_ref()
            .and_then(|e| e.scope.clone())
            .unwrap_or_default(),
        tier_a_required: m.tier_a_required,
        tier_c_peer: m.tier_c_peer.map(|u| u.to_string()).unwrap_or_default(),
        bearer_env: m
            .auth
            .as_ref()
            .and_then(|a| a.bearer_env.clone())
            .unwrap_or_default(),
        mtls_cert: m
            .mtls
            .as_ref()
            .and_then(|t| t.cert_path.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        mtls_key: m
            .mtls
            .as_ref()
            .and_then(|t| t.key_path.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        mtls_ca: m
            .mtls
            .as_ref()
            .and_then(|t| t.ca_path.as_ref())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
}

struct ServerIdentityValues {
    exchange_enabled: bool,
    exchange_audience: String,
    exchange_scope: String,
    tier_a_required: bool,
    tier_c_peer: String,
    bearer_env: String,
    mtls_cert: String,
    mtls_key: String,
    mtls_ca: String,
}

/// Build + render the Identity & auth tab. Editable for an admin with a
/// manifest store when the HTTP/SSE server is in the active bundle. stdio
/// upstreams forward no network identity (exchange / `auth.bearer_env` apply to
/// HTTP/SSE, mTLS to HTTP only), so they render read-only. These are applied
/// live by Reload:
/// `exchange` is a runtime-tunable identity field, while `auth.bearer_env` /
/// mTLS are connection-shape (re-dialed in place, or rebuilt live if the change
/// also resizes the slot pool; restart-required only if every new-shape dial
/// fails).
async fn render_identity_tab(
    state: &Arc<AdminState>,
    is_admin: bool,
    csrf_token: String,
    tenant_ctx: Option<TenantContext>,
    config_url: String,
    manifest: &waygate_upstream::UpstreamManifest,
) -> Response {
    let is_stdio = matches!(manifest.transport, waygate_upstream::Transport::Stdio);
    let mut editable = false;
    let mut readonly_note = "";
    let mut admin_required = false;
    let mut base_hash = String::new();
    let mut values = identity_view(manifest);
    // Track the auth-field capabilities from the SAME source as `values` — when
    // editing we read the on-disk set, which may already have a flipped
    // transport while the live pool is still the old one pending restart.
    // Deriving them from the live manifest there would hide the bearer/mTLS rows
    // and the save would then drop the on-disk auth/mtls. `Transport::supports_*`
    // is the single source of truth shared with `validate_manifest_invariants`.
    let mut bearer_supported = manifest.transport.supports_static_bearer();
    let mut mtls_supported = manifest.transport.supports_mtls();

    if is_stdio {
        if is_admin {
            readonly_note = "stdio upstreams forward no network identity — token exchange \
                             and bearer auth apply to HTTP/SSE upstreams, and mTLS to HTTP \
                             only.";
        } else {
            readonly_note = "Read-only — mcp:admin is required to edit identity & auth.";
            admin_required = true;
        }
    } else {
        match editable_disk_base(state, is_admin, &manifest.name) {
            Ok((set, hash)) => {
                editable = true;
                base_hash = hash;
                let m = &set[&manifest.name];
                values = identity_view(m);
                bearer_supported = m.transport.supports_static_bearer();
                mtls_supported = m.transport.supports_mtls();
            }
            Err((note, admin_req)) => {
                readonly_note = note;
                admin_required = admin_req;
            }
        }
    }

    render(&ServerIdentityFragment {
        name: manifest.name.clone(),
        config_url,
        csrf_token,
        tenant_ctx,
        editable,
        bearer_editable: editable && bearer_supported,
        mtls_editable: editable && mtls_supported,
        readonly_note,
        admin_required,
        base_hash,
        exchange_enabled: values.exchange_enabled,
        exchange_audience: values.exchange_audience,
        exchange_scope: values.exchange_scope,
        tier_a_required: values.tier_a_required,
        tier_c_peer: values.tier_c_peer,
        bearer_env: values.bearer_env,
        mtls_cert: values.mtls_cert,
        mtls_key: values.mtls_key,
        mtls_ca: values.mtls_ca,
    })
}

/// The `UPPER_SNAKE_CASE` environment-variable convention: non-empty, a
/// leading ASCII **uppercase** letter or underscore, then uppercase letters /
/// digits / underscores. Bearer secrets are referenced by an env var whose
/// name follows this convention (e.g. `MCP_GATEWAY_UPSTREAM_BEARER_*`), so
/// requiring it on the admin form rejects the common pasted-token shapes —
/// lowercase (`ghp_…`, base64, hex), mixed case, and anything with `-` / `.` /
/// `+` / `=` / PEM armor — before a value is stored as `auth.bearer_env` (and
/// rendered back as the "name"). An all-uppercase token can still pass, so
/// this is a strong heuristic on an admin-only field, not a proof.
fn is_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A plausible filesystem path (single line, no PEM armor). The gateway reads
/// the mTLS cert/key from disk at dial time, so the manifest stores a *path* —
/// this rejects a pasted certificate/key VALUE (multi-line, PEM-armored) so it
/// can't be serialized into the bundle masquerading as a path.
fn is_plausible_path(s: &str) -> bool {
    !s.contains('\n') && !s.contains('\r') && !s.contains("-----BEGIN")
}

/// `POST /servers/config/identity` — patch one server's identity-chaining +
/// dial-time auth (`exchange`, `tier_a_required`, `tier_c_peer`,
/// `auth.bearer_env`, `mtls`) in the active bundle, then `create_draft` +
/// `publish`. Admin-gated and CSRF-checked. The validate-before-publish step
/// runs the manifest guardrails (the Authorization-writer conflicts, the
/// per-transport auth rules — bearer on http/sse, mTLS on http — and the mTLS
/// https + cert/key requirement).
///
/// By design the gateway stores the bearer env var *name* and the mTLS file
/// *paths*, not secret values: `bearer_env` must follow the `UPPER_SNAKE_CASE`
/// env-var convention and the mTLS fields must look like paths (not PEM). This
/// rejects the common pasted-token shapes (lowercase `ghp_…` / base64 / hex,
/// mixed case, `+`/`=`/`-`/dotted tokens, PEM-armored key material) but cannot
/// prove an admin-entered all-uppercase string is a name and not a token — a
/// strong best-effort guard on an admin-only field, not a proof.
pub(crate) async fn server_identity_save(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if let Err(e) = crate::scope::require_admin_extension(user_principal) {
        return e.into_response();
    }
    let csrf_form = form.get("csrf").map(String::as_str).unwrap_or("");
    if !activity_csrf_ok(csrf.as_ref(), csrf_form) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return save_banner_err(
            "No manifest store configured — identity & auth are edited via servers/*.yaml \
             and a redeploy.",
        );
    };
    let Some(server) = form.get("server").cloned() else {
        return save_banner_err("Missing server.");
    };
    let base_hash = form.get("base_hash").cloned().unwrap_or_default();

    // Trim + drop-empty helper for the optional text fields.
    let opt = |key: &str| -> Option<String> {
        form.get(key)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let result = patch_and_publish(
        &state,
        store,
        user_principal,
        &server,
        &base_hash,
        "dashboard.server.identity",
        |m| {
            if matches!(m.transport, waygate_upstream::Transport::Stdio) {
                return Err(
                    "stdio upstreams forward no network identity — nothing to edit here."
                        .to_owned(),
                );
            }
            // Tier-A exchange (checkbox + audience + optional scope).
            m.exchange = if form.contains_key("exchange_enabled") {
                let Some(audience) = opt("exchange_audience") else {
                    return Err("Tier-A exchange needs an audience.".to_owned());
                };
                Some(waygate_upstream::ExchangeConfig {
                    audience,
                    scope: opt("exchange_scope"),
                })
            } else {
                None
            };
            m.tier_a_required = form.contains_key("tier_a_required");
            m.tier_c_peer = match opt("tier_c_peer") {
                None => None,
                Some(t) => match Uuid::parse_str(&t) {
                    Ok(u) => Some(u),
                    Err(_) => return Err("tier_c_peer must be a UUID or blank.".to_owned()),
                },
            };
            // Catalog-probe groups are governed through the raw manifest
            // change path, not this bearer-focused form. Preserve them across
            // both bearer edits and bearer removal so an unrelated dashboard
            // save cannot narrow a role-filtered upstream's indexed catalog.
            let catalog_probe_groups = m
                .auth
                .as_ref()
                .map(|auth| auth.catalog_probe_groups.clone())
                .unwrap_or_default();
            m.auth = match opt("bearer_env") {
                None if catalog_probe_groups.is_empty() => None,
                None => Some(waygate_upstream::UpstreamAuth {
                    catalog_probe_groups,
                    ..Default::default()
                }),
                Some(name) => {
                    // Require the UPPER_SNAKE_CASE env-var
                    // convention so a pasted token value (lowercase / base64 /
                    // hex / dotted) can't be stored — and then displayed — as
                    // the "name".
                    if !is_env_var_name(&name) {
                        return Err("Bearer env var must be an UPPER_SNAKE_CASE environment \
                                    variable name (e.g. UPSTREAM_TOKEN) — enter the variable \
                                    NAME, not the token value."
                            .to_owned());
                    }
                    Some(waygate_upstream::UpstreamAuth {
                        bearer_env: Some(name),
                        catalog_probe_groups,
                    })
                }
            };
            let cert = opt("mtls_cert");
            let key = opt("mtls_key");
            let ca = opt("mtls_ca");
            // Reject a pasted cert/key VALUE — these are file paths, read from
            // disk at dial. (Completeness — cert+key both required — is the
            // load-time manifest guardrail.)
            for v in [&cert, &key, &ca].into_iter().flatten() {
                if !is_plausible_path(v) {
                    return Err(
                        "mTLS fields must be file PATHS, not certificate/key contents — \
                                the gateway reads the cert and key from disk at dial time."
                            .to_owned(),
                    );
                }
            }
            m.mtls = if cert.is_some() || key.is_some() || ca.is_some() {
                Some(waygate_upstream::MtlsConfig {
                    cert_path: cert.map(PathBuf::from),
                    key_path: key.map(PathBuf::from),
                    ca_path: ca.map(PathBuf::from),
                })
            } else {
                None
            };
            Ok(())
        },
    )
    .await;

    match result {
        Ok(version) => save_banner_ok(
            version,
            "The exchange / tier_a_required / tier_c_peer changes are hot-reloadable and apply \
             automatically within moments (or click \"Reload manifests\"); bearer and mTLS are \
             connection-shape but re-dial live, so they also take effect on \"Reload manifests\" \
             with no restart.",
        ),
        Err(msg) => save_banner_err(msg),
    }
}

/// `POST /servers/reconnect` — re-dial one upstream. Admin-gated + CSRF.
pub(crate) async fn servers_reconnect(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<ServerActionForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    if !activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    // Validate the server exists BEFORE the external re-dial (side-effects
    // last). reconnect_one returns false for both "unknown" and "still
    // down", so the existence check has to be separate.
    if !state
        .upstreams
        .manifests()
        .iter()
        .any(|m| m.name == form.server)
    {
        return (StatusCode::NOT_FOUND, "no such server").into_response();
    }
    let connected = state.upstreams.reconnect_one(&form.server).await;
    record_server_action(
        &state,
        user.as_ref().map(|Extension(p)| p),
        "dashboard.server.reconnect",
        format!("server={}; connected={}", form.server, connected),
    )
    .await;
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    axum::response::Redirect::to(&crate::tenant_ctx::nav_url(tenant_ctx.as_ref(), "/servers"))
        .into_response()
}

/// `POST /servers/catalog/refresh` — replace one upstream's MCP session and
/// publish a fresh, classified tool inventory. Admin-gated + CSRF. The pool
/// records the actor-attributed evidence after its atomic session/index commit,
/// so this dashboard wrapper must not emit a duplicate action row.
pub(crate) async fn servers_refresh_catalog(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(form): Form<ServerActionForm>,
) -> Response {
    if let Err(error) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return error.into_response();
    }
    if !activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    // Validate every local precondition before the external dial. The pool
    // rechecks registry identity after dialing and returns None if a structural
    // reload removes this server in the meantime.
    if !state
        .upstreams
        .manifests()
        .iter()
        .any(|manifest| manifest.name == form.server)
    {
        return (StatusCode::NOT_FOUND, "no such server").into_response();
    }
    let actor = user
        .as_ref()
        .map(|Extension(principal)| principal)
        .expect("admin gate requires a principal");
    match state
        .upstreams
        .refresh_server_catalog(&form.server, actor)
        .await
    {
        Some(report) => render(&ServerCatalogRefreshResult::from(report)),
        None => (StatusCode::NOT_FOUND, "server was removed during refresh").into_response(),
    }
}

/// `POST /servers/clear-quarantine` — clear the drift quarantine for one
/// upstream. Admin-gated + CSRF.
pub(crate) async fn servers_clear_quarantine(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(form): Form<ServerActionForm>,
) -> Response {
    if let Err(e) = crate::scope::require_admin_extension(user.as_ref().map(|Extension(p)| p)) {
        return e.into_response();
    }
    if !activity_csrf_ok(csrf.as_ref(), &form.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    // clear_quarantine returns None for an unknown server, so it doubles as
    // the existence check.
    match state.upstreams.clear_quarantine(&form.server).await {
        Some(cleared) => {
            record_server_action(
                &state,
                user.as_ref().map(|Extension(p)| p),
                "dashboard.server.clear_quarantine",
                format!("server={}; cleared={}", form.server, cleared),
            )
            .await;
            let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
            axum::response::Redirect::to(&crate::tenant_ctx::nav_url(
                tenant_ctx.as_ref(),
                "/servers",
            ))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such server").into_response(),
    }
}

// ---- tools ----------------------------------------------------------------

#[cfg(test)]
mod catalog_refresh_result_tests {
    use super::*;
    use askama::Template;

    #[test]
    fn successful_refresh_result_renders_the_structured_diff() {
        let result = ServerCatalogRefreshResult::from(CatalogRefreshReport {
            server: "fetchlayer".to_owned(),
            outcome: CatalogRefreshOutcome::Updated,
            session_replaced: true,
            before_tool_count: 15,
            after_tool_count: 16,
            added: vec!["twitter_search".to_owned()],
            removed: vec!["legacy_search".to_owned()],
            schema_changed: vec!["reddit_search".to_owned()],
        });

        let html = result.render().expect("refresh result renders");

        assert!(html.contains("Catalog updated"));
        assert!(html.contains("15"));
        assert!(html.contains("16"));
        assert!(html.contains("twitter_search"));
        assert!(html.contains("legacy_search"));
        assert!(html.contains("reddit_search"));
    }

    fn render_non_success(outcome: CatalogRefreshOutcome) -> String {
        ServerCatalogRefreshResult::from(CatalogRefreshReport {
            server: "fetchlayer".to_owned(),
            outcome,
            session_replaced: false,
            before_tool_count: 15,
            after_tool_count: 7,
            added: vec!["new_tool".to_owned()],
            removed: vec!["old_tool".to_owned()],
            schema_changed: Vec::new(),
        })
        .render()
        .expect("refresh result renders")
    }

    #[test]
    fn failed_refresh_reports_the_preserved_inventory() {
        let html = render_non_success(CatalogRefreshOutcome::Failed);

        assert!(html.contains("Catalog refresh failed"));
        assert!(html.contains("still publishes 7 tools"));
        assert!(html.contains("previously published inventory remains unchanged"));
    }

    #[test]
    fn superseded_refresh_does_not_claim_current_inventory() {
        let html = render_non_success(CatalogRefreshOutcome::Superseded);

        assert!(html.contains("Catalog refresh superseded"));
        assert!(html.contains("newer server configuration won"));
        assert!(html.contains("Reload this overview for current status"));
        assert!(!html.contains("still publishes"));
        assert!(!html.contains("7 tools"));
    }

    #[test]
    fn removed_refresh_does_not_claim_current_inventory() {
        let html = render_non_success(CatalogRefreshOutcome::Removed);

        assert!(html.contains("Server removed during catalog refresh"));
        assert!(html.contains("may no longer be configured"));
        assert!(html.contains("Reload this overview for current status"));
        assert!(!html.contains("still publishes"));
        assert!(!html.contains("7 tools"));
    }
}

#[cfg(test)]
mod identity_capability_tests {
    use super::*;
    use askama::Template;

    fn identity_frag(bearer_editable: bool, mtls_editable: bool) -> ServerIdentityFragment {
        ServerIdentityFragment {
            name: "crawl4ai".into(),
            config_url: "/admin/servers?server=crawl4ai&tab=identity".into(),
            csrf_token: "tok".into(),
            tenant_ctx: None,
            editable: true,
            bearer_editable,
            mtls_editable,
            readonly_note: "",
            admin_required: false,
            base_hash: "h".into(),
            exchange_enabled: false,
            exchange_audience: String::new(),
            exchange_scope: String::new(),
            tier_a_required: false,
            tier_c_peer: String::new(),
            bearer_env: "MCP_GATEWAY_UPSTREAM_BEARER_CRAWL4AI".into(),
            mtls_cert: String::new(),
            mtls_key: String::new(),
            mtls_ca: String::new(),
        }
    }

    /// The identity form offers the bearer input on SSE (bearer is HTTP+SSE)
    /// but hides the mTLS rows (HTTP-only). Guard for the config-loss bug: a
    /// hidden bearer row would make Save drop an SSE upstream's `auth.bearer_env`.
    #[test]
    fn identity_form_offers_bearer_on_sse_hides_mtls() {
        // SSE: bearer editable, mTLS not.
        let html = identity_frag(true, false).render().expect("render sse");
        assert!(
            html.contains("name=\"bearer_env\""),
            "SSE must offer the bearer input (else Save drops the bearer)",
        );
        assert!(
            !html.contains("name=\"mtls_cert\""),
            "SSE must not offer mTLS inputs",
        );

        // HTTP: both editable.
        let html = identity_frag(true, true).render().expect("render http");
        assert!(html.contains("name=\"bearer_env\""), "HTTP offers bearer");
        assert!(html.contains("name=\"mtls_cert\""), "HTTP offers mTLS");
    }
}
