//! Server-manifest bundles page — `/admin/t/{tenant}/server_manifests`.
//! The dashboard editor for the durable upstream-manifest
//! overlay. A near-exact port of
//! `dashboard_policy_bundles.rs`, with Cedar parsing swapped for
//! `waygate_upstream::parse_manifest_set` and a YAML-export download
//! added.
//!
//! Surface:
//! - **Editor** — a textarea pre-fillable from any prior version (draft,
//!   published, rolled_back) via `?load=<bundle_id>` →
//!   `ManifestStore::get`. Plain monospace; no CodeMirror (the dashboard
//!   stack is askama + htmx + vanilla JS).
//! - **Validate** — POST running the same `parse_manifest_set` check as
//!   `create_draft` without persisting, re-rendering with an OK (+ upstream
//!   count) / error banner.
//! - **Save draft** — POST → `create_draft` → PRG redirect with the new
//!   draft loaded.
//! - **Publish** / **Rollback** — per-row POSTs → `publish` / `rollback_to`
//!   → PRG.
//! - **Export** — `GET /server_manifests/export` streams the active
//!   bundle's YAML as a `servers.yaml` download.
//!
//! Mutations delegate to the same `ManifestStore` the REST surface
//! uses, so audit + validation semantics stay identical across
//! the two surfaces.
//!
//! ## "Current" marker
//!
//! `ManifestStore::list_bundles` returns every version but doesn't flag
//! the active one. The active bundle is the **most recently published**
//! (`active_bundle` orders `published_at DESC, version DESC`). We
//! recompute that from the single `list_bundles` result — no second
//! fetch, no race — and stamp `is_current`.
//!
//! ## Admin gate
//!
//! Mirrors the REST `require_admin`. A dashboard session without
//! `mcp:admin` (or a peer-asserted principal) sees the insufficient-scope
//! card; both the store fetch and the mutation POSTs are skipped / 403'd.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;
use waygate_manifest_store::{ManifestBundleSummary, ManifestStatus, SharedManifestStore};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{csrf_matches, render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "server_manifests.html")]
struct ServerManifestsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the manifest store is unwired (dev mode / no DB).
    /// Template renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin` (or is a
    /// peer assertion). Template renders the insufficient-scope card and
    /// SKIPS both the store fetch and the editor section.
    insufficient_scope: bool,
    /// Bundle versions, newest first.
    bundles: Vec<BundleRow>,
    /// `true` when the bundle fetch failed.
    bundles_load_error: bool,
    /// Fleet roll-up: one row per replica, most-recent check-in
    /// first.
    fleet: Vec<FleetReplicaRow>,
    /// `true` when the fleet heartbeat fetch failed.
    fleet_load_error: bool,
    /// Editor textarea content — from `?load=<id>`, a Validate carryover,
    /// or empty.
    editor_content: String,
    /// Version of the `?load=<id>` bundle, for the editor heading.
    editor_loaded_version: Option<i32>,
    /// `?load=<id>` named an absent / wrong-tenant bundle.
    editor_load_miss: bool,
    /// Validate result: `Some(Ok(n))` ⇒ green banner with `n` upstreams;
    /// `Some(Err(m))` ⇒ red banner; `None` ⇒ no banner.
    editor_validate_result: Option<Result<usize, String>>,
    /// Blast-radius preview of the editor's content vs the live on-disk set —
    /// `Some` only after a Preview-impact submit (transient, like the validate
    /// banner). The report's own `error` carries a parse failure; a `None`-vs-set
    /// replay-dependency failure is surfaced as a report with `error` set.
    impact: Option<crate::manifest_impact::ManifestImpactReport>,
    /// Mutation flash from a PRG `?banner=...&banner_detail=...`.
    flash_kind: Option<&'static str>,
    flash_detail: Option<String>,
}

struct BundleRow {
    id: Uuid,
    /// URL-encoded `id` for form-action URLs.
    id_qs: String,
    version: i32,
    status: &'static str,
    /// `true` for the single active (most recently published) bundle.
    is_current: bool,
    /// `true` when eligible for the per-row Publish action (draft AND
    /// admin gate).
    can_publish: bool,
    /// `true` when eligible for Rollback (published/rolled_back AND not
    /// current AND admin gate).
    can_rollback: bool,
    /// First 12 hex chars + ellipsis; full hash on hover.
    content_hash_short: String,
    content_hash: String,
    author: Option<String>,
    created_at_abs: String,
    published_at_abs: Option<String>,
    published_by: Option<String>,
}

/// One replica in the fleet roll-up.
struct FleetReplicaRow {
    replica_id: String,
    /// `v<N>` for a committed config, or `uncommitted` for an out-of-band set.
    version_label: String,
    content_hash_short: String,
    content_hash: String,
    last_seen_abs: String,
    /// `true` when the replica hasn't checked in within the staleness window —
    /// it may be down or wedged.
    is_stale: bool,
}

/// Query params on the GET page: `load` pre-fills the editor; `banner` +
/// `banner_detail` carry the mutation flash through a PRG redirect.
#[derive(Debug, Default, Deserialize)]
struct PageQuery {
    #[serde(default)]
    load: Option<Uuid>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    banner_detail: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/server_manifests", get(server_manifests_page))
        .route("/server_manifests/export", get(export_active))
        .route("/server_manifests/validate", post(validate_form))
        .route(
            "/server_manifests/preview_impact",
            post(preview_impact_form),
        )
        .route("/server_manifests/save_draft", post(save_draft_form))
        .route("/server_manifests/{id}/publish", post(publish_form))
        .route("/server_manifests/{version}/rollback", post(rollback_form))
}

async fn server_manifests_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.servers.manifest_store.enabled();
    let admin_gate = !insufficient_scope;

    let load = if insufficient_scope {
        LoadResult::default()
    } else {
        match state.servers.manifest_store.get() {
            Some(store) => load_bundles(store.as_ref(), &read_tenant, admin_gate).await,
            None => LoadResult::default(),
        }
    };

    // Fleet roll-up (same admin gate as the bundle list).
    let fleet = if insufficient_scope {
        FleetResult::default()
    } else {
        match state.servers.manifest_store.get() {
            Some(store) => {
                load_fleet(store.as_ref(), &read_tenant, OffsetDateTime::now_utc()).await
            }
            None => FleetResult::default(),
        }
    };

    let (editor_content, editor_loaded_version, editor_load_miss) = editor_load(
        state.servers.manifest_store.get(),
        &read_tenant,
        q.load,
        insufficient_scope,
    )
    .await;

    let (flash_kind, flash_detail) = parse_flash(q.banner.as_deref(), q.banner_detail.as_deref());

    let page = ServerManifestsPage {
        chrome: PageChrome::build(
            &state,
            "Server manifests",
            "/server_manifests",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        fleet: fleet.replicas,
        fleet_load_error: fleet.fleet_load_error,
        editor_content,
        editor_loaded_version,
        editor_load_miss,
        editor_validate_result: None,
        impact: None,
        flash_kind,
        flash_detail,
    };
    render(&page)
}

/// Authorization gate for the dashboard page. Same shape as the policy
/// page: OAuth + `mcp:admin`; peer assertions and non-admins are denied.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    bundles: Vec<BundleRow>,
    bundles_load_error: bool,
}

async fn load_bundles(
    store: &dyn waygate_manifest_store::ManifestStore,
    tenant: &str,
    admin_gate: bool,
) -> LoadResult {
    match store.list_bundles(tenant).await {
        Ok(summaries) => {
            let current = active_bundle_id(&summaries);
            let bundles = summaries
                .into_iter()
                .map(|s| bundle_row(s, current, admin_gate))
                .collect();
            LoadResult {
                bundles,
                bundles_load_error: false,
            }
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "server manifests page: list_bundles failed");
            LoadResult {
                bundles: Vec::new(),
                bundles_load_error: true,
            }
        }
    }
}

/// Fetch the candidate bundle's YAML for editor pre-fill, or render
/// empty + `load_miss` on absent / wrong-tenant / unreachable store.
/// Returns `(content, loaded_version, load_miss)`. Skipped (returns
/// `("", None, false)`) when the gate is closed — the editor is hidden
/// in that branch anyway.
async fn editor_load(
    store: Option<&SharedManifestStore>,
    tenant: &str,
    load: Option<Uuid>,
    insufficient_scope: bool,
) -> (String, Option<i32>, bool) {
    if insufficient_scope {
        return (String::new(), None, false);
    }
    let Some(id) = load else {
        return (String::new(), None, false);
    };
    let Some(store) = store else {
        return (String::new(), None, true);
    };
    match store.get(tenant, id).await {
        Ok(b) => (b.content, Some(b.version), false),
        Err(waygate_manifest_store::ManifestError::NotFound(_)) => (String::new(), None, true),
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                bundle_id = %id,
                "server manifests editor: store.get failed",
            );
            (String::new(), None, true)
        }
    }
}

/// Map `?banner=...` to a typed flash kind + raw detail. Unknown banner
/// values render nothing.
fn parse_flash(
    banner: Option<&str>,
    detail: Option<&str>,
) -> (Option<&'static str>, Option<String>) {
    let kind: Option<&'static str> = match banner {
        Some("saved") => Some("saved"),
        Some("published") => Some("published"),
        Some("rolled_back") => Some("rolled_back"),
        Some("save_error") => Some("save_error"),
        Some("publish_error") => Some("publish_error"),
        Some("rollback_error") => Some("rollback_error"),
        _ => None,
    };
    (kind, detail.map(|s| s.to_owned()))
}

/// The active bundle's id — the most recently published
/// (`published_at DESC`, then `version DESC` as a same-instant
/// tie-break), matching `ManifestStore::active_bundle`. `None` when
/// nothing has ever been published.
fn active_bundle_id(summaries: &[ManifestBundleSummary]) -> Option<Uuid> {
    summaries
        .iter()
        .filter(|s| matches!(s.status, ManifestStatus::Published) && s.published_at.is_some())
        .max_by(|a, b| {
            let ord = a.published_at.cmp(&b.published_at);
            if ord == std::cmp::Ordering::Equal {
                a.version.cmp(&b.version)
            } else {
                ord
            }
        })
        .map(|s| s.id)
}

fn bundle_row(s: ManifestBundleSummary, current: Option<Uuid>, admin_gate: bool) -> BundleRow {
    let is_current = current == Some(s.id);
    let status = manifest_status_str(s.status);
    let can_publish = admin_gate && matches!(s.status, ManifestStatus::Draft);
    let can_rollback = admin_gate
        && !is_current
        && matches!(
            s.status,
            ManifestStatus::Published | ManifestStatus::RolledBack
        );
    BundleRow {
        id_qs: urlencode(&s.id.to_string()),
        is_current,
        version: s.version,
        status,
        can_publish,
        can_rollback,
        content_hash_short: short_hash(&s.content_hash),
        content_hash: s.content_hash,
        author: s.author,
        created_at_abs: format_ts_abs(s.created_at),
        published_at_abs: s.published_at.map(format_ts_abs),
        published_by: s.published_by,
        id: s.id,
    }
}

/// Display string for [`ManifestStatus`]. Matches the DB CHECK literal.
fn manifest_status_str(s: ManifestStatus) -> &'static str {
    match s {
        ManifestStatus::Draft => "draft",
        ManifestStatus::Published => "published",
        ManifestStatus::RolledBack => "rolled_back",
    }
}

/// First 12 hex chars + ellipsis; full hash on hover via the template.
fn short_hash(h: &str) -> String {
    if h.chars().count() <= 12 {
        return h.to_owned();
    }
    let prefix: String = h.chars().take(12).collect();
    format!("{prefix}…")
}

/// A replica is stale (possibly down/wedged) if it hasn't heartbeat within this
/// window. The reload loop heartbeats every poll tick (~20s), so a few missed
/// ticks is the signal.
const FLEET_STALE_AFTER: time::Duration = time::Duration::seconds(60);

/// Pure staleness check, so the threshold is unit-testable without a clock.
pub(crate) fn fleet_replica_is_stale(updated_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    now - updated_at > FLEET_STALE_AFTER
}

#[derive(Default)]
struct FleetResult {
    replicas: Vec<FleetReplicaRow>,
    fleet_load_error: bool,
}

async fn load_fleet(
    store: &dyn waygate_manifest_store::ManifestStore,
    tenant: &str,
    now: OffsetDateTime,
) -> FleetResult {
    match store.list_replica_heartbeats(tenant).await {
        Ok(heartbeats) => FleetResult {
            replicas: heartbeats.into_iter().map(|h| fleet_row(h, now)).collect(),
            fleet_load_error: false,
        },
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "server manifests page: list_replica_heartbeats failed");
            FleetResult {
                replicas: Vec::new(),
                fleet_load_error: true,
            }
        }
    }
}

fn fleet_row(h: waygate_manifest_store::ReplicaHeartbeat, now: OffsetDateTime) -> FleetReplicaRow {
    FleetReplicaRow {
        replica_id: h.replica_id,
        version_label: h
            .version
            .map(|v| format!("v{v}"))
            .unwrap_or_else(|| "uncommitted".to_owned()),
        content_hash_short: short_hash(&h.content_hash),
        content_hash: h.content_hash,
        last_seen_abs: format_ts_abs(h.updated_at),
        is_stale: fleet_replica_is_stale(h.updated_at, now),
    }
}

/// Minimal URL encoder — percent-encodes outside `[A-Za-z0-9-_.~]`.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn csrf_ok(injected: Option<&Extension<CsrfToken>>, form_value: &str) -> bool {
    match injected {
        Some(Extension(c)) => !form_value.is_empty() && csrf_matches(&c.0, form_value),
        None => true,
    }
}

// ---- form payloads ----

#[derive(Debug, Deserialize)]
pub struct ValidateForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    content: String,
}

/// POST body for the editor's Preview-impact button — the live textarea content
/// and CSRF, same shape as [`ValidateForm`]. Diffed against the on-disk active
/// set and replayed; never mutates.
#[derive(Debug, Deserialize)]
pub struct PreviewImpactForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
pub struct SaveDraftForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    content: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishForm {
    #[serde(default)]
    csrf: String,
}

#[derive(Debug, Deserialize)]
pub struct RollbackForm {
    #[serde(default)]
    csrf: String,
}

// ---- form handlers ----

/// POST /server_manifests/validate — non-mutating: re-renders the page
/// with the submitted `content` carried back and a typed validate banner
/// (parsed upstream count on success). No DB write, no audit row.
async fn validate_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Form(body): Form<ValidateForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }

    let result: Result<usize, String> = if body.content.trim().is_empty() {
        Err("manifest content is empty".into())
    } else {
        waygate_upstream::parse_manifest_set(&body.content)
            .map(|set| set.len())
            .map_err(|e| format!("manifest set is not valid: {e}"))
    };

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_display_str = user_principal.map(user_display);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let store_configured = state.servers.manifest_store.enabled();
    let load = match state.servers.manifest_store.get() {
        Some(store) => load_bundles(store.as_ref(), &read_tenant, true).await,
        None => LoadResult::default(),
    };
    let fleet = match state.servers.manifest_store.get() {
        Some(store) => load_fleet(store.as_ref(), &read_tenant, OffsetDateTime::now_utc()).await,
        None => FleetResult::default(),
    };

    let page = ServerManifestsPage {
        chrome: PageChrome::build(
            &state,
            "Server manifests",
            "/server_manifests",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope: false,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        fleet: fleet.replicas,
        fleet_load_error: fleet.fleet_load_error,
        editor_content: body.content,
        editor_loaded_version: None,
        editor_load_miss: false,
        editor_validate_result: Some(result),
        impact: None,
        flash_kind: None,
        flash_detail: None,
    };
    render(&page)
}

/// POST /server_manifests/preview_impact — non-mutating blast-radius preview of
/// the editor's content. Replays the tenant's recent recorded decisions for the
/// reclassified tools against the live policy + on-disk active set (via the
/// shared [`crate::manifest_impact::replay_manifest_impact`] core) and re-renders
/// the page with the impact panel, the editor content carried back. No DB write,
/// no audit row, no PRG — transient, like the Validate banner. The manifest
/// analogue of the policy editor's `preview_impact_form`, and the parity twin of
/// the `/changes` + `/decisions` approval-queue preview.
async fn preview_impact_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Form(body): Form<PreviewImpactForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }

    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_display_str = user_principal.map(user_display);
    let tenant = user_principal
        .map(|p| p.tenant.clone())
        .unwrap_or_else(waygate_core::TenantId::default_id);

    // Replay the editor content (READ-ONLY: reads the on-disk active set, the
    // recent decisions, and the live policy snapshot, evaluates in memory, never
    // writes). A replay-dependency failure (no engine / audit / unreadable disk)
    // becomes a panel report with `error` set, so the operator sees why there's
    // no blast radius rather than a blank panel.
    let impact = match crate::manifest_impact::replay_manifest_impact(
        &state,
        &tenant,
        &body.content,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => crate::manifest_impact::ManifestImpactReport::error(e.detail(), 0),
    };

    let read_tenant = tenant.as_str().to_owned();
    let store_configured = state.servers.manifest_store.enabled();
    let load = match state.servers.manifest_store.get() {
        Some(store) => load_bundles(store.as_ref(), &read_tenant, true).await,
        None => LoadResult::default(),
    };
    let fleet = match state.servers.manifest_store.get() {
        Some(store) => load_fleet(store.as_ref(), &read_tenant, OffsetDateTime::now_utc()).await,
        None => FleetResult::default(),
    };

    let page = ServerManifestsPage {
        chrome: PageChrome::build(
            &state,
            "Server manifests",
            "/server_manifests",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope: false,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        fleet: fleet.replicas,
        fleet_load_error: fleet.fleet_load_error,
        editor_content: body.content,
        editor_loaded_version: None,
        editor_load_miss: false,
        editor_validate_result: None,
        impact: Some(impact),
        flash_kind: None,
        flash_detail: None,
    };
    render(&page)
}

/// POST /server_manifests/save_draft — delegates to the REST
/// `create_draft` semantics. On success PRGs back with the new draft
/// loaded; on failure PRGs back with the error in `banner_detail`.
async fn save_draft_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<SaveDraftForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "manifest store not configured",
        )
            .into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let author = user_principal.map(|p| p.sub.clone());

    // Mirror the REST `create_draft` pre-store guards exactly so the
    // dashboard surface and the API surface validate identically.
    if body.content.trim().is_empty() {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "save_error",
            Some("manifest content is empty"),
        );
    }
    if let Err(e) = waygate_upstream::parse_manifest_set(&body.content) {
        let detail = format!("manifest set is not valid: {e}");
        return redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail));
    }

    match store
        .create_draft(&tenant, &body.content, author.as_deref())
        .await
    {
        Ok(bundle) => {
            state
                .evidence
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "server_manifest.create_draft",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                    .with_principal(user_principal)
                    .with_reason(format!(
                        "created manifest draft version={} hash={} (via dashboard)",
                        bundle.version, bundle.content_hash
                    )),
                )
                .await;
            let detail = format!("v{}", bundle.version);
            redirect_with_flash(tenant_ctx.as_ref(), Some(bundle.id), "saved", Some(&detail))
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "server_manifests save_draft failed");
            let detail = format!("{e}");
            redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail))
        }
    }
}

/// Mirror a published / rolled-back bundle's content onto the on-disk
/// source of truth (file-as-truth; see
/// `docs/server-config-source-of-truth.md`). The `server_manifests` row
/// is the history / recovery ledger; the dir is what boot / SIGHUP /
/// "Reload manifests" actually load, so the edit must reach disk to take
/// effect and survive a restart. Returns `Some(flash redirect)` on
/// failure so the caller early-returns with a loud banner — the mirror runs
/// BEFORE the ledger transition (see below), so on failure the ledger is still
/// untouched and nothing has been recorded. `None` when there is nothing to do
/// (no `servers_dir` wired) or the write succeeded.
///
/// The whole-set publish / rollback callers claim the cross-replica turnstile
/// (`turnstile_cas`) and run this mirror BEFORE their ledger transition,
/// rolling the turnstile back (`turnstile_rollback`) if this mirror fails — so
/// this helper stays a pure disk write and the lost-update guard lives at the
/// call site, matching the per-server editor. Because the mirror precedes the
/// ledger write, a failure here means nothing has been recorded yet.
fn mirror_bundle_to_disk(
    state: &AdminState,
    tenant: &str,
    content: &str,
    version: i32,
    tenant_ctx: Option<&TenantContext>,
    err_flash_kind: &'static str,
) -> Option<Response> {
    if let Err(e) = state.mirror_manifest_set_to_disk(tenant, content) {
        tracing::error!(error = %e, "server_manifests: on-disk mirror write failed");
        let detail = format!(
            "writing v{version} to disk failed: {e}. The change was not recorded \
             (ledger unchanged); if the write failed partway, the next reload \
             reconciles the on-disk set."
        );
        return Some(redirect_with_flash(
            tenant_ctx,
            None,
            err_flash_kind,
            Some(&detail),
        ));
    }
    None
}

/// Why a turnstile claim failed, so each surface maps it to the right outcome:
/// `Lost` is the *client's* to fix (reload and retry → HTTP 409), while `Store`
/// is an internal backing-store failure (DB/schema/connectivity → HTTP 500)
/// that a retry won't resolve. Collapsing both into one error reported a DB
/// outage to REST clients as 409 Conflict.
pub(crate) enum TurnstileError {
    /// Another replica advanced the on-disk config first — reload and retry.
    Lost(String),
    /// `seed_pointer` / `cas_pointer` failed against the backing store.
    Store(String),
}

impl TurnstileError {
    /// The human-readable reason, for the dashboard flash (which has no HTTP
    /// status to distinguish the two and shows the message either way).
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Lost(m) | Self::Store(m) => m,
        }
    }
}

/// The hash the on-disk set will have AFTER `content` is mirrored — the hash a
/// later [`AdminState::read_manifest_set_from_disk`] (and every other replica's
/// disk read) computes. The mirror writes `parse_manifest_set(content)` and a
/// disk read hashes `serialize_manifest_set(load_manifests(dir))`; the per-file
/// write/load round-trips the set faithfully (same `BTreeMap`, same
/// `serialize_manifest_set` output), so that equals
/// `content_hash(serialize_manifest_set(parse_manifest_set(content)))`.
///
/// The turnstile CAS, its rollback, and the doorbell hash MUST use this, NOT
/// `content_hash(raw bundle content)`: a draft whose submitted YAML differs from
/// the canonical serialization (key order, whitespace, comments, field order)
/// would otherwise advance `server_manifest_pointer` to a hash that never
/// matches disk, CAS-losing every later publish/rollback until reconciliation
/// re-syncs the pointer. Computing it up front also fails closed,
/// before the CAS, if the bundle content can't parse.
pub(crate) fn canonical_disk_hash(content: &str) -> Result<String, String> {
    let set = waygate_upstream::parse_manifest_set(content).map_err(|e| format!("{e}"))?;
    let canonical = waygate_upstream::serialize_manifest_set(&set).map_err(|e| format!("{e}"))?;
    Ok(waygate_manifest_store::content_hash(&canonical))
}

/// Outcome of a successful [`turnstile_cas`] claim — what the caller does next.
/// (Refusals are the `Err(TurnstileError)` arm.)
pub(crate) enum TurnstileClaim {
    /// Won: the pointer advanced `base -> new_hash`. The caller MUST mirror and,
    /// on a mirror failure, pass `base` to [`turnstile_rollback`] to undo it.
    Won(String),
    /// No turnstile ran — no `servers_dir`, an unreadable on-disk set being
    /// repaired, or a non-default tenant whose mirror is a no-op. The caller
    /// proceeds to mirror (a no-op or a repair); nothing to roll back.
    NoTurnstile,
    /// The on-disk set ALREADY equals the target (`new_hash == base`). The
    /// caller MUST NOT mirror: writing identical content does not advance the
    /// pointer, so a no-op CAS "wins" without actually claiming the slot, and a
    /// concurrent real write (`base -> other`) would then be clobbered by this
    /// mirror — the lost-update the turnstile exists to prevent.
    /// There is nothing to publish / roll back; the caller reports "no change".
    AlreadyCurrent,
}

/// Claim the cross-replica write turnstile for a whole-set publish / rollback
/// before the on-disk mirror, mirroring the per-server
/// editor's guard so two replicas can't clobber each other on the shared dir.
/// The CAS base is the current on-disk hash (the set being replaced). Returns a
/// typed [`TurnstileError`] on refusal so BOTH the dashboard (flash redirect)
/// and the REST API (`ApiError`) can map it to the right surface. Returns:
/// - `Ok(TurnstileClaim::NoTurnstile)` — no `servers_dir` / unreadable disk /
///   non-default tenant: the CAS is skipped (the mirror is a no-op or a repair);
/// - `Ok(TurnstileClaim::AlreadyCurrent)` — disk already equals the target
///   (`new_hash == base`): a no-op the caller must NOT mirror (see the variant
///   doc — a no-op CAS would falsely win and admit a lost update);
/// - `Ok(TurnstileClaim::Won(base))` — won; the caller mirrors and, on a mirror
///   failure, passes `base` to [`turnstile_rollback`] to undo the advance;
/// - `Err(TurnstileError::Lost)` — another replica wrote (→ 409 / retry);
/// - `Err(TurnstileError::Store)` — a backing-store failure (→ 500).
///
/// MUST be called BEFORE the caller's ledger transition (`publish` /
/// `rollback_to`), so a lost CAS leaves the ledger untouched (fail-closed).
pub(crate) async fn turnstile_cas(
    state: &AdminState,
    store: &waygate_manifest_store::SharedManifestStore,
    tenant: &str,
    new_hash: &str,
    actor: &str,
    // The on-disk hash the write is relative to. `None` (full-set publish /
    // rollback, which REPLACE the whole set) → re-read the current disk hash. For
    // a DERIVED write (upsert), the content was merged from a specific base the
    // caller read, so that base is passed in — CASing from it makes a concurrent
    // publish landing since that read LOSE the CAS instead of being silently
    // clobbered (a `manifest_write_lock` only serializes THIS replica).
    expected_base: Option<&str>,
) -> Result<TurnstileClaim, TurnstileError> {
    // Only the DEFAULT tenant's set is the global on-disk `servers/*.yaml` that
    // boot/reload load. A non-default tenant's publish/rollback stages in its DB
    // ledger only and does NOT mirror to disk (`mirror_manifest_set_to_disk` is
    // a no-op for a non-default tenant), so there is no disk write to guard —
    // and CASing the (shared, default) pointer to a non-default bundle's hash
    // would poison it. Skip the turnstile, matching the mirror's tenant gate.
    if tenant != waygate_core::TenantId::DEFAULT {
        return Ok(TurnstileClaim::NoTurnstile);
    }
    let base = match expected_base {
        // Derived write: CAS from the exact base the caller merged from.
        Some(b) => b.to_owned(),
        None => match state.read_manifest_set_from_disk() {
            Some(Ok((_, h))) => h,
            // An unreadable on-disk set has no usable CAS base, and a publish /
            // rollback is exactly how an operator REPAIRS a broken servers/*.yaml.
            // Skip the CAS (the mirror overwrites the broken set); the
            // out-of-band pointer reconciliation re-syncs afterward. The
            // cross-replica race here is negligible — two replicas repairing
            // a broken set both write a valid set, last wins.
            Some(Err(e)) => {
                tracing::warn!(error = %e, "turnstile: on-disk set unreadable; skipping CAS so the write can repair it");
                return Ok(TurnstileClaim::NoTurnstile);
            }
            // No servers_dir: nothing on disk to guard, skip the CAS.
            None => return Ok(TurnstileClaim::NoTurnstile),
        },
    };
    // No-op guard: the target already equals what is on disk. A
    // `cas_pointer(base, base)` UPDATE matches its own `WHERE current_hash=base`
    // and reports Won WITHOUT advancing the pointer — so it does not actually
    // claim the turnstile, and a concurrent `base -> other` write could be
    // clobbered when this request then mirrors the (identical) content. There is
    // nothing to write, so refuse the no-op here, before any CAS or mirror; the
    // turnstile then only ever admits writers that strictly advance the pointer.
    if new_hash == base {
        return Ok(TurnstileClaim::AlreadyCurrent);
    }
    let t = waygate_core::TenantId::DEFAULT;
    store
        .seed_pointer(t, &base)
        .await
        .map_err(|e| TurnstileError::Store(format!("turnstile seed failed: {e}")))?;
    match store
        .cas_pointer(t, &base, new_hash, actor)
        .await
        .map_err(|e| TurnstileError::Store(format!("turnstile check failed: {e}")))?
    {
        waygate_manifest_store::TurnstileOutcome::Won => Ok(TurnstileClaim::Won(base)),
        waygate_manifest_store::TurnstileOutcome::Lost => Err(TurnstileError::Lost(
            "another replica changed the config since this page loaded — reload and retry"
                .to_owned(),
        )),
    }
}

/// Best-effort undo of a turnstile advance when the subsequent mirror failed,
/// so the pointer never advertises a version that never reached disk.
/// `None` ⇒ the CAS was skipped, nothing to undo.
///
/// Caveat: `write_manifest_set_to_dir` has a mid-batch failure path where some
/// files are already renamed when it returns `Err`, leaving the dir a *mix* of
/// new and previous versions (each individually valid). Rolling the pointer
/// back to the old hash then disagrees with that mixed on-disk set. There is no
/// clean local undo for a partial rename; the out-of-band pointer
/// reconciliation detects disk≠pointer on the next reload and re-syncs to
/// the actual on-disk hash. The undo here still removes the common case (a
/// fully-failed write) cleanly.
pub(crate) async fn turnstile_rollback(
    store: &waygate_manifest_store::SharedManifestStore,
    won_from_base: Option<String>,
    new_hash: &str,
    actor: &str,
) {
    if let Some(base) = won_from_base {
        let _ = store
            .cas_pointer(waygate_core::TenantId::DEFAULT, new_hash, &base, actor)
            .await;
    }
}

/// POST /server_manifests/{id}/publish — delegates to the REST
/// `publish_bundle` semantics. PRGs back with a `published` /
/// `publish_error` banner.
async fn publish_form(
    State(state): State<Arc<AdminState>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<PublishForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "manifest store not configured",
        )
            .into_response();
    };
    // Read `id` by name: this route is nested under `/t/{tenant}` (and
    // merged at `/`), so an `AxumPath<Uuid>` extractor 500s on the
    // tenant-scoped mount's 2-capture match.
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return (StatusCode::BAD_REQUEST, "invalid manifest bundle id").into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let actor = user_principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned());

    // Serialize in-process with the per-server edit path so the DB
    // transition and the on-disk mirror stay atomic together.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Fetch the draft's content WITHOUT mutating the ledger: the turnstile +
    // mirror run BEFORE the publish transition, so a lost
    // CAS or a failed mirror leaves the ledger untouched (fail-closed). The
    // published bundle carries the same content the draft does.
    let draft = match store.get(&tenant, id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, bundle_id = %id, "server_manifests publish: draft fetch failed");
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "publish_error",
                Some(&format!("{e}")),
            );
        }
    };
    // Only a DRAFT may be published. `store.get` does NOT filter by status, and
    // the draft-only guard lives in `store.publish`'s UPDATE — so verify the
    // status HERE, before the CAS + mirror, or a non-draft id would write its
    // content to disk and notify before `publish` fails.
    if draft.status != waygate_manifest_store::ManifestStatus::Draft {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "publish_error",
            Some("that version is not a draft (already published?) — nothing to publish"),
        );
    }
    // The turnstile pointer tracks the on-disk hash, which is the CANONICAL
    // serialization the mirror writes — not the raw bundle content. Compute it
    // from the draft content (also fails closed here if it can't parse) and use
    // it for the CAS, its rollback, and the doorbell.
    let disk_hash = match canonical_disk_hash(&draft.content) {
        Ok(h) => h,
        Err(e) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "publish_error",
                Some(&format!("draft content is not a valid manifest set: {e}")),
            )
        }
    };
    let won_base = match turnstile_cas(&state, store, &tenant, &disk_hash, &actor, None).await {
        Ok(TurnstileClaim::Won(base)) => Some(base),
        Ok(TurnstileClaim::NoTurnstile) => None,
        Ok(TurnstileClaim::AlreadyCurrent) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "publish_error",
                Some("the draft already matches the live on-disk set — nothing to publish"),
            )
        }
        Err(e) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "publish_error",
                Some(e.message()),
            )
        }
    };
    // File-as-truth: mirror onto the on-disk source of truth so boot/SIGHUP/
    // Reload load it. On a mirror failure, roll the turnstile back.
    if let Some(flash) = mirror_bundle_to_disk(
        &state,
        &tenant,
        &draft.content,
        draft.version,
        tenant_ctx.as_ref(),
        "publish_error",
    ) {
        turnstile_rollback(store, won_base, &disk_hash, &actor).await;
        return flash;
    }
    // Ledger transition LAST — now that disk holds the content.
    let published = match store.publish(&tenant, id, &actor).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, bundle_id = %id, "server_manifests publish: ledger transition failed after disk write");
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "publish_error",
                Some(&format!(
                    "applied to disk but recording the publish in the ledger failed: {e}"
                )),
            );
        }
    };
    // Doorbell: notify replicas AFTER the ledger append, per
    // the doorbell contract — so a ledger failure (which returns an error here)
    // never tells the fleet to reload a change with no ledger/audit record. The
    // hash is the on-disk (canonical) hash, matching the pointer the fleet reads
    // back from disk — not the raw bundle hash.
    let _ = store.notify_reload(&disk_hash).await;
    state
        .evidence
        .record_best_effort(
            waygate_mcp::AuditEvent::new(
                "server_manifest.publish",
                waygate_mcp::AuditOutcome::Success,
            )
            .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
            .with_principal(user_principal)
            .with_reason(format!(
                "published manifest bundle version={} id={} hash={} (via dashboard)",
                published.version, published.id, published.content_hash
            )),
        )
        .await;
    let detail = format!("v{}", published.version);
    redirect_with_flash(tenant_ctx.as_ref(), None, "published", Some(&detail))
}

/// POST /server_manifests/{version}/rollback — delegates to the REST
/// `rollback_bundle` semantics. PRGs back with a `rolled_back` /
/// `rollback_error` banner.
async fn rollback_form(
    State(state): State<Arc<AdminState>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<RollbackForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.servers.manifest_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "manifest store not configured",
        )
            .into_response();
    };
    // Read `version` by name — same dual-mount reason as `publish_form`;
    // `AxumPath<i32>` 500s on the nested mount.
    let Some(version) = params
        .get("version")
        .and_then(|s| s.trim().parse::<i32>().ok())
    else {
        return (StatusCode::BAD_REQUEST, "invalid manifest bundle version").into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let actor = user_principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned());

    // Serialize in-process with the other manifest write paths so the DB
    // transition and the on-disk mirror stay atomic together.
    let _write_guard = state.servers.manifest_write_lock.lock().await;
    // Fetch version V's content WITHOUT mutating the ledger: the turnstile +
    // mirror run BEFORE the rollback_to transition, so a
    // lost CAS leaves the ledger untouched (fail-closed). `rollback_to` re-
    // publishes this same content as a new active version.
    let target = match store.get_by_version(&tenant, version).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, version, "server_manifests rollback: target fetch failed");
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "rollback_error",
                Some(&format!("{e}")),
            );
        }
    };
    // Canonical on-disk hash for the turnstile, same as publish_form.
    let disk_hash = match canonical_disk_hash(&target.content) {
        Ok(h) => h,
        Err(e) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "rollback_error",
                Some(&format!("target content is not a valid manifest set: {e}")),
            )
        }
    };
    let won_base = match turnstile_cas(&state, store, &tenant, &disk_hash, &actor, None).await {
        Ok(TurnstileClaim::Won(base)) => Some(base),
        Ok(TurnstileClaim::NoTurnstile) => None,
        Ok(TurnstileClaim::AlreadyCurrent) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "rollback_error",
                Some("that version already matches the live on-disk set — nothing to roll back"),
            )
        }
        Err(e) => {
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "rollback_error",
                Some(e.message()),
            )
        }
    };
    if let Some(flash) = mirror_bundle_to_disk(
        &state,
        &tenant,
        &target.content,
        target.version,
        tenant_ctx.as_ref(),
        "rollback_error",
    ) {
        turnstile_rollback(store, won_base, &disk_hash, &actor).await;
        return flash;
    }
    // Ledger transition LAST.
    let bundle = match store.rollback_to(&tenant, version, &actor).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, version, "server_manifests rollback: ledger transition failed after disk write");
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                None,
                "rollback_error",
                Some(&format!(
                    "applied to disk but recording the rollback in the ledger failed: {e}"
                )),
            );
        }
    };
    // Doorbell: notify AFTER the ledger append (see publish_form); the canonical
    // on-disk hash, not the raw bundle hash.
    let _ = store.notify_reload(&disk_hash).await;
    state
        .evidence
        .record_best_effort(
            waygate_mcp::AuditEvent::new("server_manifest.rollback", waygate_mcp::AuditOutcome::Success)
                .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                .with_principal(user_principal)
                .with_reason(format!(
                    "rolled back to manifest version={version}; new active version={} hash={} (via dashboard)",
                    bundle.version, bundle.content_hash
                )),
        )
        .await;
    let detail = format!("v{} → v{}", version, bundle.version);
    redirect_with_flash(tenant_ctx.as_ref(), None, "rolled_back", Some(&detail))
}

/// GET /server_manifests/export — stream the on-disk `servers/*.yaml` set
/// (the source of truth) as a `servers.yaml` attachment download.
/// Admin-gated; 503 without a servers dir. The content references
/// `auth.bearer_env` *names*, never token values, so it is safe to serve.
async fn export_active(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let content = match state.read_manifest_set_from_disk() {
        Some(Ok((set, _))) => match waygate_upstream::serialize_manifest_set(&set) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "server_manifests export: serialize failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "manifest export failed")
                    .into_response();
            }
        },
        Some(Err(e)) => {
            tracing::error!(error = %e, "server_manifests export: on-disk set does not parse");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the on-disk manifest set does not parse",
            )
                .into_response();
        }
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "no servers dir configured").into_response()
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"servers.yaml\"",
            ),
        ],
        content,
    )
        .into_response()
}

/// PRG redirect helper. Builds `/server_manifests[?load=...]?banner=...
/// [&banner_detail=...]`, URL-encoding both the load id and the detail.
fn redirect_with_flash(
    tenant_ctx: Option<&TenantContext>,
    load: Option<Uuid>,
    banner: &'static str,
    detail: Option<&str>,
) -> Response {
    let base = tenant_ctx::nav_url(tenant_ctx, "/server_manifests");
    let mut url = base;
    let mut first = true;
    if let Some(id) = load {
        url.push('?');
        url.push_str("load=");
        url.push_str(&urlencode(&id.to_string()));
        first = false;
    }
    url.push(if first { '?' } else { '&' });
    url.push_str("banner=");
    url.push_str(banner);
    if let Some(d) = detail {
        url.push_str("&banner_detail=");
        url.push_str(&urlencode(d));
    }
    Redirect::to(&url).into_response()
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

    fn summary(
        id: &str,
        version: i32,
        status: ManifestStatus,
        published_at: Option<OffsetDateTime>,
    ) -> ManifestBundleSummary {
        ManifestBundleSummary {
            id: id.parse().unwrap(),
            tenant_id: "default".into(),
            version,
            status,
            content_hash: "abcdef0123456789abcdef0123456789".into(),
            author: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            published_at,
            published_by: None,
        }
    }

    #[test]
    fn admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn fleet_replica_staleness_uses_the_grace_window() {
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        // A check-in just now is live.
        assert!(!fleet_replica_is_stale(now, now));
        // Within the window: still live.
        assert!(!fleet_replica_is_stale(
            now - super::FLEET_STALE_AFTER + time::Duration::seconds(1),
            now
        ));
        // Past the window: stale.
        assert!(fleet_replica_is_stale(
            now - super::FLEET_STALE_AFTER - time::Duration::seconds(1),
            now
        ));
    }

    #[test]
    fn fleet_row_labels_version_and_uncommitted() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let committed = super::fleet_row(
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "pod-a".into(),
                tenant_id: "default".into(),
                version: Some(7),
                content_hash: "abcdef0123456789".into(),
                updated_at: now,
            },
            now,
        );
        assert_eq!(committed.version_label, "v7");
        assert_eq!(committed.content_hash_short, "abcdef012345…");
        let uncommitted = super::fleet_row(
            waygate_manifest_store::ReplicaHeartbeat {
                replica_id: "pod-b".into(),
                tenant_id: "default".into(),
                version: None,
                content_hash: "x".into(),
                updated_at: now,
            },
            now,
        );
        assert_eq!(uncommitted.version_label, "uncommitted");
    }

    #[test]
    fn admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(vec!["openid", "mcp:read"], AuthMethod::Oauth);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn manifest_status_strings_match_db_constraints() {
        assert_eq!(manifest_status_str(ManifestStatus::Draft), "draft");
        assert_eq!(manifest_status_str(ManifestStatus::Published), "published");
        assert_eq!(
            manifest_status_str(ManifestStatus::RolledBack),
            "rolled_back"
        );
    }

    /// The turnstile pointer must end up at the hash DISK produces after the
    /// mirror, not `content_hash(raw bundle content)`. A draft whose YAML is
    /// valid but not in canonical serialized form (field order, comments,
    /// blank lines) would otherwise advance the pointer to a hash that never
    /// matches disk, CAS-losing every later publish/rollback.
    #[test]
    fn canonical_disk_hash_matches_post_mirror_disk_hash() {
        // Non-canonical: a leading comment, fields out of order, a blank line.
        let noncanonical = "# my upstreams\n- url: http://a/mcp\n  name: a\n  \
             transport: http\n\n- name: b\n  transport: http\n  url: http://b/mcp\n";

        // What the turnstile CASes the pointer to.
        let cas_hash = canonical_disk_hash(noncanonical).expect("valid manifest set");

        // What a disk read actually hashes to AFTER the mirror writes it — the
        // exact pipeline `AdminState::read_manifest_set_from_disk` uses.
        let dir = std::env::temp_dir().join(format!("smtest-canon-{}", Uuid::new_v4()));
        let set = waygate_upstream::parse_manifest_set(noncanonical).unwrap();
        waygate_upstream::write_manifest_set_to_dir(&dir, &set).unwrap();
        let loaded = waygate_upstream::load_manifests(&dir).unwrap();
        let disk_serialized = waygate_upstream::serialize_manifest_set(&loaded).unwrap();
        let disk_hash = waygate_manifest_store::content_hash(&disk_serialized);

        assert_eq!(
            cas_hash, disk_hash,
            "the CAS/notify hash must equal the post-mirror on-disk hash",
        );
        let replacement = waygate_upstream::parse_manifest_set(
            "- name: c\n  transport: http\n  url: http://c/mcp\n",
        )
        .unwrap();
        waygate_upstream::write_manifest_set_to_dir_from_base(&dir, &replacement, &cas_hash)
            .expect("the conditional writer must accept the admin context hash");
        let _ = std::fs::remove_dir_all(&dir);

        // And it must differ from the raw-content hash the buggy path used —
        // proving non-canonical input would have desynced the pointer from disk.
        let raw_hash = waygate_manifest_store::content_hash(noncanonical);
        assert_ne!(
            cas_hash, raw_hash,
            "non-canonical input hashes differently raw vs canonical — the bug this guards",
        );
    }

    /// `canonical_disk_hash` collapses cosmetic differences: two YAML strings
    /// that parse to the same set hash identically (so re-publishing an
    /// equivalent draft is a no-op CAS, not a spurious advance).
    #[test]
    fn canonical_disk_hash_is_serialization_invariant() {
        let a = "- name: x\n  transport: http\n  url: http://x/mcp\n";
        let b = "# comment\n- url: http://x/mcp\n  transport: http\n  name: x\n";
        assert_eq!(
            canonical_disk_hash(a).unwrap(),
            canonical_disk_hash(b).unwrap(),
            "equivalent sets must canonicalize to the same hash",
        );
    }

    #[test]
    fn short_hash_truncates_with_ellipsis_for_long_hashes() {
        let full = "abcdef0123456789abcdef0123456789";
        assert_eq!(short_hash(full), "abcdef012345…");
    }

    #[test]
    fn short_hash_passes_through_short_strings() {
        assert_eq!(short_hash("short"), "short");
        assert_eq!(short_hash("abcdef012345"), "abcdef012345");
    }

    #[test]
    fn active_bundle_id_picks_most_recently_published() {
        let t0 = OffsetDateTime::UNIX_EPOCH;
        let t1 = t0 + time::Duration::hours(1);
        let bundles = vec![
            summary(
                "00000000-0000-0000-0000-000000000003",
                3,
                ManifestStatus::Draft,
                None,
            ),
            summary(
                "00000000-0000-0000-0000-000000000002",
                2,
                ManifestStatus::Published,
                Some(t1),
            ),
            summary(
                "00000000-0000-0000-0000-000000000001",
                1,
                ManifestStatus::Published,
                Some(t0),
            ),
        ];
        assert_eq!(
            active_bundle_id(&bundles),
            Some("00000000-0000-0000-0000-000000000002".parse().unwrap()),
        );
    }

    #[test]
    fn active_bundle_id_none_when_only_drafts() {
        let bundles = vec![summary(
            "00000000-0000-0000-0000-000000000001",
            1,
            ManifestStatus::Draft,
            None,
        )];
        assert_eq!(active_bundle_id(&bundles), None);
    }

    #[test]
    fn active_bundle_id_tiebreaks_on_version() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let bundles = vec![
            summary(
                "00000000-0000-0000-0000-000000000001",
                1,
                ManifestStatus::Published,
                Some(t),
            ),
            summary(
                "00000000-0000-0000-0000-000000000005",
                5,
                ManifestStatus::Published,
                Some(t),
            ),
        ];
        assert_eq!(
            active_bundle_id(&bundles),
            Some("00000000-0000-0000-0000-000000000005".parse().unwrap()),
        );
    }

    #[test]
    fn bundle_row_publish_eligibility_matches_status() {
        let t = OffsetDateTime::UNIX_EPOCH;
        let draft = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000001",
                1,
                ManifestStatus::Draft,
                None,
            ),
            None,
            true,
        );
        assert!(draft.can_publish);
        assert!(!draft.can_rollback);

        let published = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000002",
                2,
                ManifestStatus::Published,
                Some(t),
            ),
            None,
            true,
        );
        assert!(!published.can_publish);
        assert!(published.can_rollback);

        let current = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000003",
                3,
                ManifestStatus::Published,
                Some(t),
            ),
            Some("00000000-0000-0000-0000-000000000003".parse().unwrap()),
            true,
        );
        assert!(!current.can_publish);
        assert!(!current.can_rollback);
    }

    #[test]
    fn bundle_row_action_eligibility_off_when_gate_closed() {
        let draft = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000001",
                1,
                ManifestStatus::Draft,
                None,
            ),
            None,
            false,
        );
        assert!(!draft.can_publish, "no publish without admin gate");
        assert!(!draft.can_rollback, "no rollback without admin gate");
    }

    #[test]
    fn parse_flash_maps_known_banners() {
        assert_eq!(parse_flash(Some("saved"), Some("v3")).0, Some("saved"));
        assert_eq!(
            parse_flash(Some("publish_error"), Some("oops")).0,
            Some("publish_error"),
        );
        assert_eq!(parse_flash(Some("not_a_thing"), None).0, None);
        assert_eq!(parse_flash(None, None).0, None);
    }

    #[test]
    fn urlencode_handles_special_chars() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            urlencode("00000000-0000-0000-0000-000000000001"),
            "00000000-0000-0000-0000-000000000001",
        );
    }

    #[test]
    fn csrf_ok_requires_match_when_token_present() {
        let token = CsrfToken("expected".into());
        let ext = Extension(token);
        assert!(csrf_ok(Some(&ext), "expected"));
        assert!(!csrf_ok(Some(&ext), "wrong"));
        assert!(!csrf_ok(Some(&ext), ""));
    }

    #[test]
    fn csrf_ok_permits_dev_mode_with_no_extension() {
        assert!(csrf_ok(None, ""));
    }
}
