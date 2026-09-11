//! Policy bundles page — `/admin/t/{tenant}/policy_bundles`.
//!
//! The read-only **Versions** registry is paired with an interactive
//! surface:
//!
//! - **Editor** — a textarea pre-fillable from any prior version (draft,
//!   published, or rolled_back) via `?load=<bundle_id>` →
//!   `PolicyStore::get`. The vendored CodeMirror 6 bundle
//!   (`static/js/codemirror.bundle.js`) mounts over the textarea as
//!   progressive enhancement — Cedar syntax highlighting + line numbers,
//!   syncing edits back to the textarea so htmx posts + no-JS still work.
//! - **Validate** — POST that runs the same `CedarEngine::from_source`
//!   parse check as `create_draft` without persisting, then re-renders
//!   the page with an OK / parse-error banner. Lets an operator
//!   confirm syntax before committing the audit row.
//! - **As-you-type diagnostics** — `POST /policy_bundles/diagnostics`
//!   is a stateless JSON endpoint (`waygate_authz::validate_diagnostics`)
//!   returning line/col diagnostics; the CM6 editor's lint gutter POSTs to it
//!   (debounced). It runs the SAME parse + duplicate-`@id` validation
//!   `CedarEngine::from_source` does (what Validate / Save Draft reject as
//!   unparseable) — so the gutter is an accurate "will this parse + re-key"
//!   signal. The full publish gate adds non-parse guards (non-empty content,
//!   the test gate, impact) that aren't surfaced here. No store, no
//!   tenant, no mutation; mcp:admin + CSRF.
//! - **Save draft** — POST → `POST /api/v1/policy_bundles` →
//!   PRG redirect to the page with the new draft loaded.
//! - **Publish** — per-row POST on draft rows →
//!   `POST /api/v1/policy_bundles/{id}/publish` → PRG redirect.
//! - **Rollback** — per-row POST on previously-published-but-not-current
//!   rows → `POST /api/v1/policy_bundles/{version}/rollback` → PRG.
//! - **Preview impact** — per-row POST →
//!   `POST /api/v1/policy_bundles/{id}/preview_impact` → re-renders the
//!   page with a read-only blast-radius panel: a replay of the tenant's
//!   recent recorded decisions against that bundle (which would flip
//!   allow→deny / deny→allow / →step-up). No PRG — the panel is transient,
//!   like the Validate banner. Delegates to the shared REST core
//!   `compute_impact_for_draft`.
//!
//! ## What's NOT here (deferred)
//!
//! - **Preview against draft (simulator)** — the
//!   `POST /api/v1/policy_bundles/preview_simulate` REST endpoint exists so a
//!   future single-request simulator Preview button can wire to it; that UI
//!   lands separately. Operators wanting candidate-bundle simulation today can
//!   call the endpoint directly. (Distinct from **Preview impact** above, which
//!   replays *recorded* decisions rather than simulating a hand-built request.)
//! - **Exact replay of SCIM-enriched decisions** — `preview_impact` excludes
//!   them today (the audit row captures only `scim_active` + `scim_groups`, not
//!   the full SCIM attr set the live entity exposes). Capturing the rest, like
//!   the other inputs, is a deferred follow-up.
//!
//! Same read-only-mutations-go-via-REST posture every other dashboard
//! page has held: the page submits dashboard-shaped POST forms that
//! delegate to the REST handlers under the hood, so the REST surface
//! stays the single source of truth for audit + CSRF semantics.
//!
//! ## "Current" marker
//!
//! `PolicyStore::list_bundles` returns every version but does not
//! flag which is active. The active bundle is the **most recently
//! published** one (`active_bundle` orders `published_at DESC, version
//! DESC`). We recompute that selection here from the single
//! `list_bundles` result — no second fetch, no race — and stamp
//! `is_current` on the matching row.
//!
//! ## Tenant scoping
//!
//! Reads + writes use `principal.tenant`; both `list_bundles` and
//! every mutation are strictly per-tenant via the underlying
//! `PolicyStore` API.
//!
//! ## Admin gate
//!
//! Mirrors the REST surface's `require_admin`. A dashboard session
//! without `mcp:admin` (or a peer-asserted principal) sees the
//! insufficient-scope card; both the store fetch AND the mutation
//! POST handlers are skipped / 403'd so no policy authorship metadata
//! or content hashes enter the rendered HTML or the audit log under
//! that principal's identity.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_policy::{PolicyBundle, PolicyBundleSummary, PolicyStatus, SharedPolicyStore};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{csrf_matches, render, user_display};
use crate::state::{AdminState, PolicyCommitError};
use crate::tenant_ctx::{self, TenantContext};
use waygate_core::fmt::format_ts_abs;

#[derive(Template)]
#[template(path = "policy_bundles.html")]
struct PolicyBundlesPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the policy-bundle store is unwired (dev mode /
    /// no DB / policy bundles not enabled). Template renders the
    /// "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS both the store fetch
    /// and the editor section.
    insufficient_scope: bool,
    /// Bundle versions, newest first. Ordered server-side by
    /// `version DESC`.
    bundles: Vec<BundleRow>,
    /// `true` when the bundle fetch failed. Template renders a
    /// section error card instead of the empty state.
    bundles_load_error: bool,
    /// Editor textarea content. Pre-filled from `?load=<id>`
    /// (the bundle's Cedar source), or from a Validate POST's
    /// carryover (the source the operator just submitted), or
    /// empty.
    editor_content: String,
    /// When pre-filled from `?load=<id>`, the version of the
    /// loaded bundle so the editor heading can read
    /// "Editor — loaded from v3".
    editor_loaded_version: Option<i32>,
    /// When `?load=<id>` named an absent / wrong-tenant bundle,
    /// the editor renders with empty content + a "not found"
    /// banner. Mirrors the playground's `load_miss` pattern.
    editor_load_miss: bool,
    /// The `@id` of a single policy to scroll to + highlight in the loaded
    /// content (the Policies pane "Edit" deep-link's `?focus=`). `None` on a
    /// normal load. Rendered as an HTML-escaped data attribute the editor's JS
    /// reads to position the cursor on that policy.
    editor_focus: Option<String>,
    /// Validate POST result: `Some(Ok)` ⇒ green banner; `Some(Err(m))`
    /// ⇒ red banner with the parse error; `None` ⇒ no banner.
    editor_validate_result: Option<Result<(), String>>,
    /// Mutation flash banner: rendered when a Save/Publish/Rollback
    /// POST redirected back with `?banner=...&banner_detail=...`.
    /// Each is its own field so the template doesn't have to parse
    /// a discriminator string.
    flash_kind: Option<&'static str>,
    flash_detail: Option<String>,
    /// `true` when the on-disk `policies/*.cedar` set is
    /// broken / ledger-recovered and the gateway is serving a stale policy set —
    /// the template renders a prominent "Policy config STALE" banner. Driven by
    /// the SEPARATE policy config-health signal (not the manifest one).
    config_degraded: bool,
    /// Detail line for the policy-config-stale banner (empty when healthy).
    config_detail: String,
    /// `Some(reason)` when policy editing is disabled for this deployment
    /// (`GATEWAY_POLICY_EDITING=off`, or the policies dir isn't writable). The
    /// template renders a prominent read-only banner and HIDES every mutation
    /// affordance (Save draft / per-row Publish / Rollback) so the editor page
    /// is purely a viewer — matching the `/policies` pane and the 403 the
    /// `gate_policy_editing` middleware returns if a hidden control is POSTed
    /// anyway. `None` ⇒ editing enabled, full affordances.
    editing_off_reason: Option<String>,
    /// The blast-radius panel, populated only by the "Preview impact" POST.
    /// `None` ⇒ the panel isn't rendered (the page GET, Validate, and the
    /// mutation PRGs all leave it unset).
    impact: Option<ImpactView>,
}

/// The blast-radius panel, projected from an
/// [`crate::impact::ImpactReport`] for the template. Carries the version the
/// replay ran against so the panel can name it ("Replaying … against v3").
struct ImpactView {
    /// The bundle version the replay ran against.
    version: i32,
    /// `Some(detail)` when the draft doesn't parse — the panel renders the error
    /// instead of the counts.
    error: Option<String>,
    /// Total recorded decisions considered (the rows fetched for the tenant).
    considered: usize,
    /// Of `considered`, how many were replayable and evaluated.
    replayed: usize,
    /// Of `replayed`, how many produced the SAME verdict.
    unchanged: usize,
    /// Of `replayed`, how many produced a DIFFERENT verdict.
    changed: usize,
    /// Of `considered`, how many couldn't be replayed (legacy rows without the
    /// captured inputs, model decisions, or non-decision outcomes).
    not_replayable: usize,
    /// Per-transition counts (allow→deny, deny→allow, →step_up, …).
    deltas: Vec<ImpactDeltaView>,
    /// A bounded set of changed-decision examples.
    samples: Vec<ImpactSampleView>,
}

/// One transition row in the blast-radius panel.
struct ImpactDeltaView {
    from: String,
    to: String,
    count: usize,
}

/// One changed-decision example row in the blast-radius panel.
struct ImpactSampleView {
    recorded: String,
    candidate: String,
    principal: String,
    server_tool: String,
    ts: String,
}

impl ImpactView {
    /// Project the REST-core [`crate::impact::ImpactReport`] into the template
    /// view, stamping the bundle version it ran against.
    fn from_report(version: i32, report: crate::impact::ImpactReport) -> Self {
        Self {
            version,
            error: report.error,
            considered: report.considered,
            replayed: report.replayed,
            unchanged: report.unchanged,
            changed: report.changed,
            not_replayable: report.not_replayable,
            deltas: report
                .deltas
                .into_iter()
                .map(|d| ImpactDeltaView {
                    from: d.from,
                    to: d.to,
                    count: d.count,
                })
                .collect(),
            samples: report
                .samples
                .into_iter()
                .map(|s| ImpactSampleView {
                    recorded: s.recorded,
                    candidate: s.candidate,
                    principal: s.principal,
                    server_tool: s.server_tool,
                    ts: s.ts,
                })
                .collect(),
        }
    }
}

struct BundleRow {
    id: Uuid,
    /// Encoded form of `id` for use in form action URLs. Same
    /// reasoning as the activity-page urlencode'd facet values —
    /// keep it self-contained even if Uuid::to_string is always
    /// URL-safe today.
    id_qs: String,
    version: i32,
    status: &'static str,
    /// `true` for the single active bundle (most recently
    /// published). Template renders a "current" chip.
    is_current: bool,
    /// `true` when this row is eligible for the per-row Publish
    /// action (status == draft AND admin gate passes). The
    /// template uses this to render or skip the button — keeps
    /// the row's action column visually consistent.
    can_publish: bool,
    /// `true` when this row is eligible for the per-row Rollback
    /// action (status is published OR rolled_back, AND not the
    /// current bundle, AND admin gate passes). The template hides
    /// the button when false.
    can_rollback: bool,
    /// First 12 hex chars + ellipsis; full hash on hover via the
    /// template's `title` attribute.
    content_hash_short: String,
    content_hash: String,
    /// `Some(author)` when set; `None` renders an em-dash.
    author: Option<String>,
    created_at_abs: String,
    /// `Some(ts)` for published / rolled-back bundles; `None`
    /// (em-dash) for a never-published draft.
    published_at_abs: Option<String>,
    /// `Some(publisher)` when published; `None` renders an em-dash.
    published_by: Option<String>,
}

/// Query-string parameters on the GET page. `load` pre-fills the
/// editor from an existing bundle's source; `banner` + `banner_detail`
/// carry the mutation-result flash through a PRG redirect.
#[derive(Debug, Default, Deserialize)]
struct PageQuery {
    /// Editor pre-fill source. A bundle UUID (a draft/published/rolled_back
    /// version), or the literal `active` to load the currently-published bundle
    /// — the latter is what the Policies pane's per-policy "Edit" link uses, so
    /// it can deep-link into the editor without knowing the active bundle's id.
    #[serde(default)]
    load: Option<String>,
    /// The `@id` of a single policy to scroll to + highlight in the loaded
    /// bundle (the Policies pane "Edit" deep-link). Operator-authored text; the
    /// template emits it as an HTML-escaped data attribute read by a small JS
    /// snippet, never interpolated into a script body.
    #[serde(default)]
    focus: Option<String>,
    /// Mutation banner discriminator: `saved`, `published`,
    /// `rolled_back`, `save_error`, `publish_error`, `rollback_error`.
    /// Anything else renders no banner.
    #[serde(default)]
    banner: Option<String>,
    /// Free-form supporting detail (version number, error message).
    /// Rendered verbatim through the template's `{{ ... }}` escape.
    #[serde(default)]
    banner_detail: Option<String>,
}

pub fn router(state: Arc<AdminState>) -> Router<Arc<AdminState>> {
    // The mutating routes are split into their own sub-router and
    // layered with `gate_policy_editing`, so a single switch
    // (`GATEWAY_POLICY_EDITING=off`, or a read-only policies dir) 403s every
    // write with the operator-facing reason. Each mutation delegates to the
    // REST handlers (via the shared PolicyStore) but accepts the dashboard's
    // form-encoded body + CSRF token, then PRGs back to the page so an
    // operator's refresh re-fetches state instead of re-submitting.
    //
    // The per-policy surface uses the segmenter
    // (waygate_authz::segment) to split a bundle into @id-addressed statements
    // so ONE policy can be edited / removed / added and the bundle recomposed
    // by exact concatenation — every other byte stays identical. Each mutation
    // produces a NEW DRAFT via the same `create_draft` plumbing as Save Draft
    // (never bypasses validate / the test gate / publish). On any
    // segmentation ambiguity the handlers fall back to whole-bundle editing
    // rather than splice blindly. The POSTs are CSRF + mcp:admin gated and PRG
    // back to the new draft.
    let mutations = Router::new()
        .route("/policy_bundles/save_draft", post(save_draft_form))
        .route("/policy_bundles/{id}/publish", post(publish_form))
        .route("/policy_bundles/{version}/rollback", post(rollback_form))
        .route("/policy_bundles/policy/edit", post(policy_edit_form))
        .route("/policy_bundles/policy/remove", post(policy_remove_form))
        .route("/policy_bundles/policy/add", post(policy_add_form))
        .layer(axum::middleware::from_fn_with_state(
            state,
            gate_policy_editing,
        ));

    // Read-only routes are NOT layered with the editing gate — an operator can
    // inspect, validate, and preview impact even on a read-only deployment.
    Router::new()
        .route("/policy_bundles", get(policy_bundles_page))
        .route("/policy_bundles/validate", post(validate_form))
        // Per-row "Preview impact" — replay the tenant's recent recorded
        // decisions against this bundle's content and re-render with a
        // blast-radius panel. Read-only (no publish, no audit mutation); routes
        // through the shared REST core `compute_impact_for_draft`.
        .route(
            "/policy_bundles/{id}/preview_impact",
            post(preview_impact_form),
        )
        // GET is a read (no CSRF) — the per-policy fragment loader.
        .route("/policy_bundles/policy", get(policy_fragment_get))
        // Stateless as-you-type Cedar validation for the
        // editor's lint gutter — parse the submitted text with the SAME parser
        // production uses and return line/col diagnostics as JSON. mcp:admin +
        // CSRF gated; no store, no tenant, no mutation.
        .route("/policy_bundles/diagnostics", post(policy_diagnostics))
        .merge(mutations)
}

/// The policy-config-stale banner inputs, read from the
/// SEPARATE policy config-health signal (mirrors the Servers page's manifest
/// banner). Returns `(degraded, detail)`; `(false, "")` when healthy or unwired.
fn policy_config_banner(state: &AdminState) -> (bool, String) {
    match state
        .policy
        .policy_config_health
        .as_ref()
        .and_then(|h| h.snapshot())
    {
        Some(s) if !s.healthy => (
            true,
            format!(
                "{} (stale {})",
                s.detail,
                crate::dashboard::secs_ago(s.since_unix)
            ),
        ),
        _ => (false, String::new()),
    }
}

async fn policy_bundles_page(
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
    let store_configured = state.policy.policy_store.enabled();
    let admin_gate = !insufficient_scope;

    let load = if insufficient_scope {
        LoadResult::default()
    } else {
        match state.policy.policy_store.get() {
            Some(store) => load_bundles(store.as_ref(), &read_tenant, admin_gate).await,
            None => LoadResult::default(),
        }
    };

    // Editor pre-fill: when `?load=<id>` is present AND the store is
    // wired AND the principal can read, fetch the bundle's source via
    // `editor_load` below.
    let (editor_content, editor_loaded_version, editor_load_miss) = editor_load(
        state.policy.policy_store.get(),
        &read_tenant,
        q.load,
        insufficient_scope,
    )
    .await;

    let (flash_kind, flash_detail) = parse_flash(q.banner.as_deref(), q.banner_detail.as_deref());
    let (config_degraded, config_detail) = policy_config_banner(&state);

    let page = PolicyBundlesPage {
        chrome: PageChrome::build(
            &state,
            "Policy bundles",
            "/policy_bundles",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        editor_content,
        editor_loaded_version,
        editor_load_miss,
        editor_focus: q.focus,
        editor_validate_result: None,
        flash_kind,
        flash_detail,
        config_degraded,
        config_detail,
        editing_off_reason: state.policy.policy_editing.off_reason().map(str::to_owned),
        impact: None,
    };
    render(&page)
}

/// Authorization gate for the policy-bundles dashboard page. Same
/// shape as `dashboard_evidence::principal_has_dashboard_admin`.
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
    store: &dyn waygate_policy::PolicyStore,
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
            tracing::error!(error = %e, tenant = %tenant, "policy bundles page: list_bundles failed");
            LoadResult {
                bundles: Vec::new(),
                bundles_load_error: true,
            }
        }
    }
}

/// Fetch the candidate bundle's Cedar source for editor pre-fill,
/// or render with empty + `load_miss` on absent / wrong-tenant /
/// unreachable store. Returns `(content, loaded_version, load_miss)`.
///
/// Skipped (returns `("", None, false)`) when the gate is closed —
/// the editor is hidden in that branch anyway, so don't churn the
/// store with reads that aren't going to render.
///
/// Uses `PolicyStore::get` (tenant-scoped get-by-id) so a draft,
/// published, or rolled_back bundle's source is reachable for the
/// editor — not just the active one. Without this, the Save Draft
/// PRG path's `?load=<new_draft_id>` would always land on
/// `load_miss=true` because a freshly-saved draft is never active.
async fn editor_load(
    store: Option<&SharedPolicyStore>,
    tenant: &str,
    load: Option<String>,
    insufficient_scope: bool,
) -> (String, Option<i32>, bool) {
    if insufficient_scope {
        return (String::new(), None, false);
    }
    let Some(spec) = load else {
        return (String::new(), None, false);
    };
    let Some(store) = store else {
        // Bookmarked `?load=...` against an unwired store — render
        // empty + the load_miss hint so the operator sees why the
        // textarea is empty.
        return (String::new(), None, true);
    };
    // `load=active` → the currently-published bundle (the Policies pane's
    // per-policy "Edit" deep-link, which doesn't know the active bundle's id);
    // otherwise a bundle UUID (the Save-Draft PRG / version "Load" path).
    let fetched = if spec == "active" {
        store.active_bundle(tenant).await
    } else {
        match Uuid::parse_str(spec.trim()) {
            Ok(id) => store.get(tenant, id).await,
            // A malformed `?load=` value renders empty + the load_miss hint
            // rather than 500ing the page.
            Err(_) => return (String::new(), None, true),
        }
    };
    match fetched {
        Ok(b) => (b.content, Some(b.version), false),
        Err(waygate_policy::PolicyError::NotFound(_)) => (String::new(), None, true),
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                load = %spec,
                "policy bundles editor: load failed",
            );
            (String::new(), None, true)
        }
    }
}

/// Map the `?banner=...` query param to a typed flash kind +
/// the raw detail. Unknown banner values render nothing.
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
    let detail_string = detail.map(|s| s.to_owned());
    (kind, detail_string)
}

/// The active bundle's id, computed from the full version list with
/// the SAME selection `PolicyStore::active_bundle` uses: the most
/// recently published bundle (`published_at DESC`, then `version
/// DESC` as a same-instant tie-break). Returns `None` when no bundle
/// has ever been published.
fn active_bundle_id(summaries: &[PolicyBundleSummary]) -> Option<Uuid> {
    summaries
        .iter()
        .filter(|s| matches!(s.status, PolicyStatus::Published) && s.published_at.is_some())
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

fn bundle_row(s: PolicyBundleSummary, current: Option<Uuid>, admin_gate: bool) -> BundleRow {
    let is_current = current == Some(s.id);
    let status = policy_status_str(s.status);
    let can_publish = admin_gate && matches!(s.status, PolicyStatus::Draft);
    let can_rollback = admin_gate
        && !is_current
        && matches!(s.status, PolicyStatus::Published | PolicyStatus::RolledBack);
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

/// Display string for [`PolicyStatus`]. Matches the DB CHECK literal;
/// a rename here without a migration would lie to operators about
/// what was stored.
fn policy_status_str(s: PolicyStatus) -> &'static str {
    match s {
        PolicyStatus::Draft => "draft",
        PolicyStatus::Published => "published",
        PolicyStatus::RolledBack => "rolled_back",
    }
}

/// First 12 hex chars + ellipsis. Content hashes are 64-char hex;
/// full hash is on hover via the template's `title` attribute.
fn short_hash(h: &str) -> String {
    if h.chars().count() <= 12 {
        return h.to_owned();
    }
    let prefix: String = h.chars().take(12).collect();
    format!("{prefix}…")
}

/// Minimal URL encoder matching the playground's helper — only
/// percent-encodes outside `[A-Za-z0-9-_.~]`. Used for action URLs
/// and the redirect-after-mutation query string.
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

/// Refuse a policy MUTATION when editing is disabled for the deployment
/// (`GATEWAY_POLICY_EDITING=off`, or the policies dir isn't writable). Layered
/// over the mutation sub-router in [`router`] so it gates every write in one
/// place; the read-only page / per-policy GET / validate / diagnostics /
/// preview-impact routes are NOT layered with it (they never persist, so an
/// operator can still inspect and lint in read-only mode). Pairs with the
/// dashboard hiding the editor affordances (see `dashboard.rs` /
/// `policies.html`) so the UI and the endpoint agree.
async fn gate_policy_editing(
    State(state): State<Arc<AdminState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Some(reason) = state.policy.policy_editing.off_reason() {
        return (
            StatusCode::FORBIDDEN,
            format!("policy editing is disabled — {reason}"),
        )
            .into_response();
    }
    next.run(req).await
}

// ---- form payloads ----

#[derive(Debug, Deserialize)]
pub struct ValidateForm {
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
pub struct PreviewImpactForm {
    #[serde(default)]
    csrf: String,
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

// ---- per-policy edit ----

/// `?base=<active|uuid>&id=<@id>` — read one policy's source for editor prefill.
#[derive(Debug, Deserialize)]
pub struct PolicyFragmentQuery {
    /// Which bundle to read from: `active` or a version UUID.
    #[serde(default = "default_base")]
    base: String,
    /// The `@id` of the policy to read.
    #[serde(default)]
    id: String,
}

/// JSON returned by `GET /policy_bundles/policy`.
#[derive(Debug, Serialize)]
struct PolicyFragmentResponse {
    ok: bool,
    /// The `@id` requested (echoed back).
    id: String,
    /// The policy statement's exact source text (present when `ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    statement: Option<String>,
    /// `true` when the bundle parses but couldn't be segmented per-policy, so
    /// the caller should edit the whole bundle instead. (`ok` is false.)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    fallback: bool,
    /// Human-readable error when `!ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Edit ONE policy (replace its statement), producing a new draft.
#[derive(Debug, Deserialize)]
pub struct PolicyEditForm {
    #[serde(default)]
    csrf: String,
    /// Base bundle to edit from: `active` or a version UUID.
    #[serde(default = "default_base")]
    base: String,
    /// The `@id` of the policy being replaced.
    #[serde(default)]
    id: String,
    /// The new statement source (a single Cedar policy).
    #[serde(default)]
    statement: String,
}

/// Remove ONE policy by `@id`, producing a new draft.
#[derive(Debug, Deserialize)]
pub struct PolicyRemoveForm {
    #[serde(default)]
    csrf: String,
    #[serde(default = "default_base")]
    base: String,
    #[serde(default)]
    id: String,
}

/// Append a new policy to the bundle, producing a new draft.
#[derive(Debug, Deserialize)]
pub struct PolicyAddForm {
    #[serde(default)]
    csrf: String,
    #[serde(default = "default_base")]
    base: String,
    /// The new policy statement source.
    #[serde(default)]
    statement: String,
}

fn default_base() -> String {
    "active".to_string()
}

/// Body for the as-you-type validation endpoint.
#[derive(Debug, Deserialize)]
pub struct DiagnosticsForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    content: String,
}

/// JSON returned by `POST /policy_bundles/diagnostics`.
#[derive(Debug, Serialize)]
struct DiagnosticsResponse {
    /// `true` when the content parses cleanly (no diagnostics).
    ok: bool,
    diagnostics: Vec<waygate_authz::CedarDiagnostic>,
}

// ---- form handlers ----

/// POST /policy_bundles/validate — non-mutating: re-renders the
/// page with the submitted `content` carried back into the editor
/// and a typed validate banner. No DB write, no audit row.
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

    let result: Result<(), String> = if body.content.trim().is_empty() {
        Err("policy content is empty".into())
    } else {
        waygate_authz::CedarEngine::from_source(&body.content)
            .map(|_| ())
            .map_err(|e| format!("policy does not parse as Cedar: {e}"))
    };

    // Re-render the full page with the submitted content carried
    // back. Same shape as the GET handler, minus the `?load=<id>`
    // pre-fill (the operator's draft is the authoritative content).
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_display_str = user_principal.map(user_display);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let store_configured = state.policy.policy_store.enabled();
    let load = match state.policy.policy_store.get() {
        Some(store) => load_bundles(store.as_ref(), &read_tenant, true).await,
        None => LoadResult::default(),
    };
    let (config_degraded, config_detail) = policy_config_banner(&state);

    let page = PolicyBundlesPage {
        chrome: PageChrome::build(
            &state,
            "Policy bundles",
            "/policy_bundles",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope: false,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        editor_content: body.content,
        editor_loaded_version: None,
        editor_load_miss: false,
        editor_focus: None,
        editor_validate_result: Some(result),
        flash_kind: None,
        flash_detail: None,
        config_degraded,
        config_detail,
        editing_off_reason: state.policy.policy_editing.off_reason().map(str::to_owned),
        impact: None,
    };
    render(&page)
}

/// POST /policy_bundles/{id}/preview_impact — blast-radius preview.
/// Non-mutating: replays the tenant's recent recorded decisions against this
/// bundle's content (via the shared REST core
/// [`crate::policy_bundles::compute_impact_for_draft`]) and re-renders the page
/// with the blast-radius panel. No DB write, no audit row, no PRG (the panel is
/// transient, like the Validate banner). Tenant-scoped to `principal.tenant`.
async fn preview_impact_form(
    State(state): State<Arc<AdminState>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
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
    // Read `id` by name: this route is nested under `/t/{tenant}` (and merged at
    // `/`), so an `AxumPath<Uuid>` extractor 500s on the tenant-scoped mount's
    // 2-capture match (same reason as `publish_form`).
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return (StatusCode::BAD_REQUEST, "invalid policy bundle id").into_response();
    };

    // Re-render the full page (same shape as the GET handler), then populate the
    // blast-radius panel from the shared REST core. The version the replay ran
    // against is resolved from the loaded bundle list for the panel heading.
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_display_str = user_principal.map(user_display);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let store_configured = state.policy.policy_store.enabled();
    let load = match state.policy.policy_store.get() {
        Some(store) => load_bundles(store.as_ref(), &read_tenant, true).await,
        None => LoadResult::default(),
    };
    let version = load
        .bundles
        .iter()
        .find(|b| b.id == id)
        .map(|b| b.version)
        .unwrap_or_default();

    // Compute the impact via the shared REST core (READ-ONLY: loads the bundle
    // + recent decisions, replays in memory, never writes). A store-not-wired /
    // not-found / audit-not-wired maps to a panel error so the operator sees why
    // there's no report, rather than a blank panel.
    let impact =
        match crate::policy_bundles::compute_impact_for_draft(&state, user_principal, id).await {
            Ok(report) => ImpactView::from_report(version, report),
            Err(e) => ImpactView {
                version,
                error: Some(e.detail()),
                considered: 0,
                replayed: 0,
                unchanged: 0,
                changed: 0,
                not_replayable: 0,
                deltas: Vec::new(),
                samples: Vec::new(),
            },
        };

    let (config_degraded, config_detail) = policy_config_banner(&state);
    let page = PolicyBundlesPage {
        chrome: PageChrome::build(
            &state,
            "Policy bundles",
            "/policy_bundles",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        store_configured,
        insufficient_scope: false,
        bundles: load.bundles,
        bundles_load_error: load.bundles_load_error,
        editor_content: String::new(),
        editor_loaded_version: None,
        editor_load_miss: false,
        editor_focus: None,
        editor_validate_result: None,
        flash_kind: None,
        flash_detail: None,
        config_degraded,
        config_detail,
        editing_off_reason: state.policy.policy_editing.off_reason().map(str::to_owned),
        impact: Some(impact),
    };
    render(&page)
}

/// POST /policy_bundles/save_draft — delegates to the REST
/// `create_draft` semantics. On success PRGs back with the new
/// draft loaded; on failure PRGs back with the error in the
/// `banner_detail` so the operator's textarea isn't lost (the
/// content sits in browser history one step back).
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
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
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
            Some("policy content is empty"),
        );
    }
    if let Err(e) = waygate_authz::CedarEngine::from_source(&body.content) {
        let detail = format!("policy does not parse as Cedar: {e}");
        return redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail));
    }

    match store
        .create_draft(&tenant, &body.content, None, author.as_deref())
        .await
    {
        Ok(bundle) => {
            // Best-effort AdminMutation evidence row, mirroring the
            // REST handler so the dashboard's save lands in the
            // audit chain too.
            state
                .evidence
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "policy_bundle.create_draft",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                    .with_principal(user_principal)
                    .with_reason(format!(
                        "created policy draft version={} hash={} (via dashboard)",
                        bundle.version, bundle.content_hash
                    )),
                )
                .await;
            let detail = format!("v{}", bundle.version);
            redirect_with_flash(tenant_ctx.as_ref(), Some(bundle.id), "saved", Some(&detail))
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, "policy_bundles save_draft failed");
            let detail = format!("{e}");
            redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail))
        }
    }
}

// ---- per-policy edit handlers ----

/// Resolve the base bundle to edit from: `active` (the published bundle) or a
/// version UUID. Returns an operator-facing error string on miss/malformed/
/// unreachable so the caller can flash it.
async fn load_base_bundle(
    store: &dyn waygate_policy::PolicyStore,
    tenant: &str,
    base: &str,
) -> Result<PolicyBundle, String> {
    let fetched = if base == "active" {
        store.active_bundle(tenant).await
    } else {
        match Uuid::parse_str(base.trim()) {
            Ok(id) => store.get(tenant, id).await,
            Err(_) => return Err(format!("malformed base bundle id \"{base}\"")),
        }
    };
    fetched.map_err(|e| match e {
        waygate_policy::PolicyError::NotFound(_) if base == "active" => {
            "no active (published) policy bundle to edit".to_string()
        }
        waygate_policy::PolicyError::NotFound(_) => format!("base bundle {base} not found"),
        other => format!("loading base bundle failed: {other}"),
    })
}

/// GET /policy_bundles/policy?base=<active|uuid>&id=<@id> — read ONE policy's
/// exact source for editor prefill. Read-only (no CSRF), `mcp:admin` + tenant
/// scoped. JSON so a future per-policy editor can populate a field;
/// a segmentation ambiguity returns `ok:false, fallback:true` (200) so the UI
/// routes the operator to whole-bundle editing instead.
async fn policy_fragment_get(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    Query(q): Query<PolicyFragmentQuery>,
) -> Response {
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    };
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    if q.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PolicyFragmentResponse {
                ok: false,
                id: q.id,
                statement: None,
                fallback: false,
                error: Some("missing policy id".into()),
            }),
        )
            .into_response();
    }

    let base = match load_base_bundle(store.as_ref(), &tenant, &q.base).await {
        Ok(b) => b,
        Err(detail) => {
            return (
                StatusCode::NOT_FOUND,
                Json(PolicyFragmentResponse {
                    ok: false,
                    id: q.id,
                    statement: None,
                    fallback: false,
                    error: Some(detail),
                }),
            )
                .into_response();
        }
    };

    match waygate_authz::policy_statement(&base.content, &q.id) {
        Ok(statement) => Json(PolicyFragmentResponse {
            ok: true,
            id: q.id,
            statement: Some(statement),
            fallback: false,
            error: None,
        })
        .into_response(),
        Err(waygate_authz::SegmentError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(PolicyFragmentResponse {
                ok: false,
                id: q.id,
                statement: None,
                fallback: false,
                error: Some("policy not found in this bundle".into()),
            }),
        )
            .into_response(),
        // Bundle parses but the tokenizer can't address it (or doesn't parse at
        // all): the per-policy editor isn't safe here → tell the UI to fall back.
        Err(
            e @ (waygate_authz::SegmentError::Ambiguous | waygate_authz::SegmentError::Parse(_)),
        ) => Json(PolicyFragmentResponse {
            ok: false,
            id: q.id,
            statement: None,
            fallback: true,
            error: Some(e.to_string()),
        })
        .into_response(),
    }
}

/// POST /policy_bundles/policy/edit — replace ONE policy's statement → new draft.
async fn policy_edit_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<PolicyEditForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    if body.id.trim().is_empty() {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "save_error",
            Some("missing policy id"),
        );
    }
    let base = match load_base_bundle(store.as_ref(), &tenant, &body.base).await {
        Ok(b) => b,
        Err(detail) => {
            return redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail))
        }
    };
    // Enforce the one-policy contract on the SUBMITTED text before splicing: the
    // payload must be exactly one policy whose @id stays the target's, so an
    // "edit" can't smuggle in extra policies or rename/drop the target (the
    // splice is verbatim and only the recomposed bundle is validated otherwise).
    if let Err(detail) = waygate_authz::ensure_single_policy(&body.statement, Some(&body.id)) {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            Some(base.id),
            "save_error",
            Some(&detail),
        );
    }
    let new_content = match waygate_authz::replace_policy(&base.content, &body.id, &body.statement)
    {
        Ok(c) => c,
        Err(waygate_authz::SegmentError::NotFound(_)) => {
            let detail = format!("policy @id \"{}\" not found in this bundle", body.id);
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                Some(base.id),
                "save_error",
                Some(&detail),
            );
        }
        Err(e) => return segment_fallback(tenant_ctx.as_ref(), base.id, &e),
    };
    finish_per_policy_draft(
        &state,
        store.as_ref(),
        tenant_ctx.as_ref(),
        user_principal,
        &tenant,
        &base,
        new_content,
        "edit",
        Some(&body.id),
    )
    .await
}

/// POST /policy_bundles/policy/remove — drop ONE policy by `@id` → new draft.
async fn policy_remove_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<PolicyRemoveForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    if body.id.trim().is_empty() {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "save_error",
            Some("missing policy id"),
        );
    }
    let base = match load_base_bundle(store.as_ref(), &tenant, &body.base).await {
        Ok(b) => b,
        Err(detail) => {
            return redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail))
        }
    };
    let new_content = match waygate_authz::remove_policy(&base.content, &body.id) {
        Ok(c) => c,
        Err(waygate_authz::SegmentError::NotFound(_)) => {
            let detail = format!("policy @id \"{}\" not found in this bundle", body.id);
            return redirect_with_flash(
                tenant_ctx.as_ref(),
                Some(base.id),
                "save_error",
                Some(&detail),
            );
        }
        Err(e) => return segment_fallback(tenant_ctx.as_ref(), base.id, &e),
    };
    finish_per_policy_draft(
        &state,
        store.as_ref(),
        tenant_ctx.as_ref(),
        user_principal,
        &tenant,
        &base,
        new_content,
        "remove",
        None,
    )
    .await
}

/// POST /policy_bundles/policy/add — append a new policy → new draft.
async fn policy_add_form(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Form(body): Form<PolicyAddForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    if body.statement.trim().is_empty() {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "save_error",
            Some("new policy is empty"),
        );
    }
    let base = match load_base_bundle(store.as_ref(), &tenant, &body.base).await {
        Ok(b) => b,
        Err(detail) => {
            return redirect_with_flash(tenant_ctx.as_ref(), None, "save_error", Some(&detail))
        }
    };
    // "Add" means exactly ONE new policy — reject a payload that carries several
    // (or none) so a single Add can't append a whole bundle's worth of policies.
    if let Err(detail) = waygate_authz::ensure_single_policy(&body.statement, None) {
        return redirect_with_flash(
            tenant_ctx.as_ref(),
            Some(base.id),
            "save_error",
            Some(&detail),
        );
    }
    let new_content = match waygate_authz::append_policy(&base.content, &body.statement) {
        Ok(c) => c,
        Err(e) => return segment_fallback(tenant_ctx.as_ref(), base.id, &e),
    };
    finish_per_policy_draft(
        &state,
        store.as_ref(),
        tenant_ctx.as_ref(),
        user_principal,
        &tenant,
        &base,
        new_content,
        "add",
        None,
    )
    .await
}

/// POST /policy_bundles/diagnostics — stateless as-you-type Cedar validation for
/// the editor's lint gutter. Returns `{ ok, diagnostics: [{line,col,end_line,
/// end_col,message}] }`. Runs the SAME parse + duplicate-`@id` validation as
/// `CedarEngine::from_source` (what Validate / Save Draft reject as
/// unparseable), so the gutter matches that bar — the full publish gate adds
/// non-parse guards (non-empty, the test gate, impact) beyond this. mcp:admin +
/// CSRF gated; no store, no tenant, no mutation.
async fn policy_diagnostics(
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(body): Form<DiagnosticsForm>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &body.csrf) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let user_principal = user.as_ref().map(|Extension(p)| p);
    if !principal_has_dashboard_admin(user_principal) {
        return (StatusCode::FORBIDDEN, "mcp:admin required").into_response();
    }
    let diagnostics = waygate_authz::validate_diagnostics(&body.content);
    Json(DiagnosticsResponse {
        ok: diagnostics.is_empty(),
        diagnostics,
    })
    .into_response()
}

/// Shared tail for the three per-policy mutations: validate the recomposed
/// bundle, create a new draft (carrying the base's `tests` forward so the
/// test gate isn't silently dropped), record audit evidence, and PRG to the new
/// draft scrolled to `focus`. Mirrors `save_draft_form`'s validate + audit +
/// PRG so the per-policy and whole-bundle surfaces behave identically.
#[allow(clippy::too_many_arguments)]
async fn finish_per_policy_draft(
    state: &AdminState,
    store: &dyn waygate_policy::PolicyStore,
    tenant_ctx: Option<&TenantContext>,
    user_principal: Option<&Principal>,
    tenant: &str,
    base: &PolicyBundle,
    new_content: String,
    op: &str,
    focus: Option<&str>,
) -> Response {
    // An empty result (e.g. removing the only policy) is deny-all — refuse it
    // the same way Save Draft refuses an empty textarea.
    if new_content.trim().is_empty() {
        return redirect_with_flash(
            tenant_ctx,
            Some(base.id),
            "save_error",
            Some("the edit would leave the policy set empty"),
        );
    }
    if let Err(e) = waygate_authz::CedarEngine::from_source(&new_content) {
        let detail = format!("edited policy does not parse as Cedar: {e}");
        return redirect_with_flash(tenant_ctx, Some(base.id), "save_error", Some(&detail));
    }
    let author = user_principal.map(|p| p.sub.clone());
    match store
        .create_draft(tenant, &new_content, base.tests.as_ref(), author.as_deref())
        .await
    {
        Ok(bundle) => {
            state
                .evidence
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "policy_bundle.create_draft",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                    .with_principal(user_principal)
                    .with_reason(format!(
                        "per-policy {op} → draft version={} hash={} (from v{}, via dashboard)",
                        bundle.version, bundle.content_hash, base.version
                    )),
                )
                .await;
            let detail = format!("v{}", bundle.version);
            redirect_to_draft(tenant_ctx, bundle.id, focus, "saved", Some(&detail))
        }
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, op = %op, "per-policy edit: create_draft failed");
            let detail = format!("{e}");
            redirect_with_flash(tenant_ctx, Some(base.id), "save_error", Some(&detail))
        }
    }
}

/// The segmenter refused to isolate the policy safely (ambiguous tokenization or
/// an unparseable base). Bounce the operator to the WHOLE-bundle editor with the
/// base loaded + an explanatory banner — never splice blindly.
fn segment_fallback(
    tenant_ctx: Option<&TenantContext>,
    base_id: Uuid,
    e: &waygate_authz::SegmentError,
) -> Response {
    let detail = format!("{e} — the whole bundle is loaded below for manual editing.");
    redirect_with_flash(tenant_ctx, Some(base_id), "save_error", Some(&detail))
}

/// PRG redirect onto a freshly-created draft, scrolled to `focus` (reusing the
/// page's `?focus=<@id>` jump-to-policy JS) and anchored at `#editor`.
fn redirect_to_draft(
    tenant_ctx: Option<&TenantContext>,
    draft_id: Uuid,
    focus: Option<&str>,
    banner: &'static str,
    detail: Option<&str>,
) -> Response {
    let mut url = tenant_ctx::nav_url(tenant_ctx, "/policy_bundles");
    url.push_str("?load=");
    url.push_str(&urlencode(&draft_id.to_string()));
    if let Some(f) = focus.filter(|f| !f.is_empty()) {
        url.push_str("&focus=");
        url.push_str(&urlencode(f));
    }
    url.push_str("&banner=");
    url.push_str(banner);
    if let Some(d) = detail {
        url.push_str("&banner_detail=");
        url.push_str(&urlencode(d));
    }
    url.push_str("#editor");
    Redirect::to(&url).into_response()
}

/// Map a failed atomic mirror-then-ledger commit ([`AdminState::mirror_then`])
/// to a flash redirect. The `policy_bundles` row is the history / recovery
/// ledger; `policies/*.cedar` is what boot / SIGHUP load (`resolve_policies`),
/// so publish/rollback mirror to disk AND record the ledger atomically — on a
/// `Mirror` or `Ledger` failure both are left consistent (nothing half-applied,
/// safe to retry); on the rare `DiskAhead` double fault the disk write could not
/// be rolled back, so the banner says so loudly. The policy analogue of
/// `dashboard_server_manifests::mirror_bundle_to_disk`.
fn commit_err_flash(
    e: &PolicyCommitError,
    tenant_ctx: Option<&TenantContext>,
    err_flash_kind: &'static str,
) -> Response {
    let detail = match e {
        PolicyCommitError::Mirror(m) => {
            tracing::error!(error = %m, "policy_bundles: on-disk mirror write failed");
            format!(
                "writing to policies/ failed: {m}. The change was not recorded (ledger unchanged)."
            )
        }
        PolicyCommitError::Ledger(pe) => {
            tracing::error!(error = %pe, "policy_bundles: ledger write failed (disk mirror rolled back)");
            format!("{pe}. The change was not recorded (on-disk set rolled back).")
        }
        PolicyCommitError::DiskAhead(m) => {
            tracing::error!(error = %m, "policy_bundles: disk may be ahead of ledger");
            m.clone()
        }
        PolicyCommitError::Conflict(m) => {
            // Turnstile LOST: another replica advanced the on-disk
            // policy set; nothing was written. Reload and retry.
            tracing::info!(reason = %m, "policy_bundles: turnstile lost (stale edit)");
            m.clone()
        }
        PolicyCommitError::NoChange(m) => {
            // The content already matches the live on-disk set — a no-op refusal.
            tracing::info!(reason = %m, "policy_bundles: no change (already current)");
            m.clone()
        }
    };
    redirect_with_flash(tenant_ctx, None, err_flash_kind, Some(&detail))
}

/// POST /policy_bundles/{id}/publish — mirrors the bundle onto disk (the
/// file-as-truth source `resolve_policies` loads) and then records the ledger
/// publish. PRGs back with a `published` or `publish_error` banner.
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
    if !state.policy.policy_store.enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    }
    // Read `id` by name: this route is nested under `/t/{tenant}` (and
    // merged at `/`), so an `AxumPath<Uuid>` extractor 500s on the
    // tenant-scoped mount's 2-capture match.
    let Some(id) = params
        .get("id")
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
    else {
        return (StatusCode::BAD_REQUEST, "invalid policy bundle id").into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);

    // Route through the SHARED gated publish core so the dashboard CANNOT
    // bypass the policy-test gate. `publish_bundle_core` takes the
    // `policy_write_lock`, deserializes + runs the draft's attached tests, and
    // rejects a failing/malformed set with a `Denied` audit BEFORE `mirror_then`
    // — then mirrors to `policies/*.cedar`, publishes the ledger row, and audits
    // `Success`. Calling it here (instead of a second copy of the
    // lock/get/mirror/publish/audit logic that skipped the gate) makes the
    // dashboard publish byte-identical to the REST/propose path; the gate is not
    // bypassable from this surface. The PRG flash maps
    // the shared `ApiResult`: a gate rejection surfaces its 422 detail as the
    // `publish_error` banner.
    match crate::policy_bundles::publish_bundle_core(&state, user_principal, id).await {
        Ok(bundle) => redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "published",
            Some(&format!("v{}", bundle.version)),
        ),
        Err(e) => redirect_with_flash(
            tenant_ctx.as_ref(),
            None,
            "publish_error",
            Some(&e.detail()),
        ),
    }
}

/// POST /policy_bundles/{version}/rollback — delegates to the REST
/// `rollback_bundle` semantics. PRGs back with a `rolled_back` or
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
    let Some(store) = state.policy.policy_store.get() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "policy bundle store not configured",
        )
            .into_response();
    };
    // Read `version` by name — same dual-mount reason as `publish_form`;
    // `AxumPath<i32>` 500s on the tenant-scoped mount.
    let Some(version) = params
        .get("version")
        .and_then(|s| s.trim().parse::<i32>().ok())
    else {
        return (StatusCode::BAD_REQUEST, "invalid policy bundle version").into_response();
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());
    let actor = user_principal
        .map(|p| p.sub.clone())
        .unwrap_or_else(|| "dev@local".to_owned());

    // Serialize the mirror + ledger transition within this replica (same
    // reasoning as `publish_form`).
    let _guard = state.policy.policy_write_lock.lock().await;

    // Resolve the target version's content BEFORE the ledger transition so we
    // mirror it onto `policies/*.cedar` (the boot/SIGHUP source) first. There is
    // no get-by-version, so find the (unique) bundle at `version` via the
    // summary list, then fetch its full content.
    let target = match store.list_bundles(&tenant).await {
        Ok(list) => list.into_iter().find(|b| b.version == version),
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, version = version, "policy_bundles rollback: list failed");
            let detail = format!("{e}");
            return redirect_with_flash(tenant_ctx.as_ref(), None, "rollback_error", Some(&detail));
        }
    };
    let Some(target) = target else {
        let detail = format!("no policy bundle at version {version}");
        return redirect_with_flash(tenant_ctx.as_ref(), None, "rollback_error", Some(&detail));
    };
    // rollback_to re-activates only vetted (previously-published) content; a
    // never-published draft is not a valid target. Pre-check here so we don't
    // mirror a draft to disk for a rollback the ledger would reject.
    if target.status == PolicyStatus::Draft {
        let detail = format!("version {version} was never published; cannot roll back to a draft");
        return redirect_with_flash(tenant_ctx.as_ref(), None, "rollback_error", Some(&detail));
    }
    let content = match store.get(&tenant, target.id).await {
        Ok(b) => b.content,
        Err(e) => {
            tracing::error!(error = %e, tenant = %tenant, version = version, bundle_id = %target.id, "policy_bundles rollback: load target failed");
            let detail = format!("{e}");
            return redirect_with_flash(tenant_ctx.as_ref(), None, "rollback_error", Some(&detail));
        }
    };
    // Turnstile + mirror + ledger, same disk-wins handling as publish (a ledger
    // failure leaves disk applied and reconciles to the ledger).
    match state
        .mirror_then(&tenant, &content, &actor, || {
            store.rollback_to(&tenant, version, &actor)
        })
        .await
    {
        Ok(bundle) => {
            state
                .evidence
                .record_best_effort(
                    waygate_mcp::AuditEvent::new(
                        "policy_bundle.rollback",
                        waygate_mcp::AuditOutcome::Success,
                    )
                    .with_category(waygate_mcp::EvidenceCategory::AdminMutation)
                    .with_principal(user_principal)
                    .with_reason(format!(
                        "rolled back to policy version={version}; new active version={} hash={} (via dashboard)",
                        bundle.version, bundle.content_hash
                    )),
                )
                .await;
            let detail = format!("v{} → v{}", version, bundle.version);
            redirect_with_flash(tenant_ctx.as_ref(), None, "rolled_back", Some(&detail))
        }
        Err(e) => commit_err_flash(&e, tenant_ctx.as_ref(), "rollback_error"),
    }
}

/// PRG redirect helper. Builds `/policy_bundles[?load=...]?banner=...
/// [&banner_detail=...]`, URL-encoding both the load id and the
/// detail so a parse-error message with `&` or `=` doesn't break
/// query parsing on the next render.
fn redirect_with_flash(
    tenant_ctx: Option<&TenantContext>,
    load: Option<Uuid>,
    banner: &'static str,
    detail: Option<&str>,
) -> Response {
    let base = tenant_ctx::nav_url(tenant_ctx, "/policy_bundles");
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
    use time::OffsetDateTime;

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
        status: PolicyStatus,
        published_at: Option<OffsetDateTime>,
    ) -> PolicyBundleSummary {
        PolicyBundleSummary {
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
    fn policy_bundles_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn policy_bundles_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn policy_bundles_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn policy_bundles_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn policy_status_strings_match_db_constraints() {
        assert_eq!(policy_status_str(PolicyStatus::Draft), "draft");
        assert_eq!(policy_status_str(PolicyStatus::Published), "published");
        assert_eq!(policy_status_str(PolicyStatus::RolledBack), "rolled_back");
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
                PolicyStatus::Draft,
                None,
            ),
            summary(
                "00000000-0000-0000-0000-000000000002",
                2,
                PolicyStatus::Published,
                Some(t1),
            ),
            summary(
                "00000000-0000-0000-0000-000000000001",
                1,
                PolicyStatus::Published,
                Some(t0),
            ),
        ];
        let current = active_bundle_id(&bundles);
        assert_eq!(
            current,
            Some("00000000-0000-0000-0000-000000000002".parse().unwrap()),
        );
    }

    #[test]
    fn active_bundle_id_none_when_only_drafts() {
        let bundles = vec![summary(
            "00000000-0000-0000-0000-000000000001",
            1,
            PolicyStatus::Draft,
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
                PolicyStatus::Published,
                Some(t),
            ),
            summary(
                "00000000-0000-0000-0000-000000000005",
                5,
                PolicyStatus::Published,
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
                PolicyStatus::Draft,
                None,
            ),
            None,
            /* admin_gate */ true,
        );
        assert!(draft.can_publish);
        assert!(!draft.can_rollback);

        let published = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000002",
                2,
                PolicyStatus::Published,
                Some(t),
            ),
            None, // not current
            true,
        );
        assert!(!published.can_publish);
        assert!(published.can_rollback);

        let current = bundle_row(
            summary(
                "00000000-0000-0000-0000-000000000003",
                3,
                PolicyStatus::Published,
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
                PolicyStatus::Draft,
                None,
            ),
            None,
            /* admin_gate */ false,
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
