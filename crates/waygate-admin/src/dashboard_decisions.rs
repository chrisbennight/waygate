//! Decisions queue — the merged "what needs you now" inbox.
//! Unifies the control surfaces that require an operator decision:
//!
//! - **Pending skill contents** — review the complete candidate before distribution.
//! - **Pending change requests** — a human must approve (and execute) or
//!   deny (with a reason). The decision action.
//! - **Active break-glass tokens** — overrides currently bypassing the
//!   policy gate; the operator reviews and revokes illegitimate ones.
//!
//! This is exactly the set the sidebar Decisions badge counts
//! (`dashboard::decisions_badge`). The inbox bounds its inline complete-params
//! render; when pending changes exceed that page, its saturation notice links
//! to the paginated `/changes` queue. Already-decided / informational items
//! (HITL approval-grant lifecycle) stay on their own Approvals tab; they are not
//! pending operator decisions.
//!
//! ## Inline actions, real cores
//!
//! Skill rows link to the complete review. Other rows carry the actual
//! approve / deny / revoke form. To keep the
//! operator on the queue (rather than the per-surface pages' own
//! redirects), the forms POST to queue-owned routes here that reuse the
//! shared mutation cores — [`change_requests::approve_and_execute_core`],
//! [`change_requests::deny_core`], [`break_glass::revoke_token_core`] —
//! and PRG-redirect back to `/decisions` with a flash. No mutation logic
//! is duplicated: these handlers are thin auth+CSRF+parse wrappers over
//! the same cores the per-surface dashboard forms and the REST API call.
//!
//! Security posture mirrors the badge and the three source pages:
//! `mcp:admin` + non-peer (`overview_break_glass_admin`), and the data is
//! always scoped to the **principal's** tenant, never `tenant_ctx` — an
//! operator-controlled value that must never leak another tenant's rows.

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::CsrfToken;
use crate::break_glass::revoke_token_core;
use crate::change_requests::{approve_and_execute_core, deny_core};
use crate::chrome::PageChrome;
use crate::dashboard::{
    csrf_matches, format_ts_abs, format_ts_rel, overview_break_glass_admin, render, urlencode,
    user_display,
};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_oidc::{Principal, Session};

/// Complete params are rendered inline, so the unified inbox shows at most the
/// same eight pending changes as one `/changes` page. The extra fetched row
/// drives the existing saturation link to the paginated full queue.
const PENDING_CR_FETCH_LIMIT: u32 = crate::dashboard_changes::PENDING_PARAMS_PAGE_SIZE + 1;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/decisions", get(decisions_page))
        .route("/decisions/changes/{id}/approve", post(approve_change))
        .route("/decisions/changes/{id}/deny", post(deny_change))
        .route(
            "/decisions/break_glass/{id}/revoke",
            post(revoke_break_glass),
        )
}

/// One queue row. `kind`/`severity` drive the chip; `summary` is the
/// plain-language line; the inline form fields (`approve_rel` etc.) are
/// queue-owned action paths so the post returns to the queue.
struct InboxItem {
    /// `"change request"` | `"break-glass"` | `"skill review"`.
    kind: &'static str,
    /// Decision-contract severity: `"warn"` (a pending change awaiting a
    /// decision) | `"critical"` (an active override bypassing policy).
    severity: &'static str,
    /// e.g. `example-agent · example-compute.jobs.delete` (CR) or
    /// `bgops@acme · mcp:invoke:high` (break-glass).
    summary: String,
    /// A short stable handle: CR binding code, or the short token id.
    handle: String,
    /// Pretty-rendered captured params for a change request — the maker's
    /// exact proposed intent, shown so the approver isn't deciding blind on
    /// `requested_by · action_type` alone. `None` for break-glass rows (an
    /// active override has no proposed params to review).
    params_pretty: Option<String>,
    /// Frozen approval conditions for a change request. `None` for a
    /// break-glass row, which is an already-active override rather than a
    /// proposed mutation.
    approval_requirement: Option<crate::dashboard_changes::ApprovalRequirementView>,
    age_rel: String,
    age_abs: String,
    /// Queue-owned action endpoints (relative; run through `nav_url`).
    /// `Some` for change requests (approve+deny), `None` for break-glass.
    cr_approve_rel: Option<String>,
    cr_deny_rel: Option<String>,
    /// `Some` for break-glass (revoke), `None` for change requests.
    bg_revoke_rel: Option<String>,
    /// Effect preview for a pending policy / manifest change — the blast-radius
    /// the approver reviews BEFORE approving, so this inbox is not a blind
    /// approval path for a change `/changes` would preview (the server-review
    /// gate must hold on EVERY approval surface). At most one is `Some`; both
    /// are `None` for break-glass rows and for non-previewable change actions.
    policy_preview: Option<crate::dashboard_changes::PolicyChangePreviewView>,
    manifest_preview: Option<crate::dashboard_changes::ManifestChangePreviewView>,
    /// The approver must explicitly confirm that they reviewed the computed
    /// effect before the approval form can be submitted.
    effect_preview_acknowledgement_required: bool,
    /// A missing or blocked mandatory preview makes approval fail closed;
    /// denial remains available so the queue can be cleared deliberately.
    approval_blocked: bool,
    /// Sort key — newest first.
    skill_review_rel: Option<String>,
    created_unix: i64,
}

#[derive(Template)]
#[template(path = "decisions.html")]
struct DecisionsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the principal lacks `mcp:admin` (or is a peer
    /// assertion). The template renders a scope card and NO queue data,
    /// matching the three source pages' posture.
    insufficient_scope: bool,
    items: Vec<InboxItem>,
    /// A source fetch hit its cap — the template nudges toward the owning
    /// tab for the remainder (mirrors the badge's `N+`).
    changes_saturated: bool,
    break_glass_saturated: bool,
    /// `true` when neither the change-request nor break-glass store is
    /// wired (dev / no DB): a distinct "not configured" line, not the
    /// benign "nothing pending" empty state.
    stores_unconfigured: bool,
    /// `true` when a configured store's read FAILED. The queue may be
    /// non-empty but incomplete, or empty only because the read errored —
    /// the template must NOT present that as "nothing to decide": a load
    /// error reading as empty would hide waiting decisions.
    load_error: bool,
    /// PRG flash channels (urlencoded on the way out).
    flash_ok: Option<String>,
    flash_err: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DecisionsQuery {
    #[serde(default)]
    ok: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

async fn decisions_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(q): Query<DecisionsQuery>,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let csrf_token = csrf.map(|Extension(c)| c.0).unwrap_or_default();

    // Tenant is the PRINCIPAL's, never tenant_ctx — tenant_ctx is
    // operator-controlled and must not leak cross-tenant data.
    let tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !overview_break_glass_admin(user_principal);

    let cr_store = state.hitl.change_requests.get();
    let bg_store = state.policy.break_glass.get();
    let stores_unconfigured =
        cr_store.is_none() && bg_store.is_none() && state.hitl.reviewed_skills.get().is_none();

    let mut items: Vec<InboxItem> = Vec::new();
    let mut changes_saturated = false;
    let mut break_glass_saturated = false;
    let mut load_error = false;
    // Per-load budget for the ≤500-row effect replays, shared across the pending
    // change rows (mirrors the /changes queue cap).
    let mut previews_left = crate::dashboard_changes::POLICY_PREVIEW_CAP;

    if !insufficient_scope {
        // Pending change requests — the decision queue proper.
        if let Some(store) = cr_store {
            match store
                .list(
                    &tenant,
                    Some(waygate_changeset::ChangeRequestLifecycle::Pending),
                    PENDING_CR_FETCH_LIMIT,
                    0,
                )
                .await
            {
                // A read FAILURE must not read as "nothing pending" — that
                // would tell the operator there's nothing to decide when a
                // decision may be waiting.
                Err(e) => {
                    tracing::warn!(error = %e, "decisions: change-request list failed");
                    load_error = true;
                }
                Ok(mut rows) => {
                    changes_saturated =
                        rows.len() > crate::dashboard_changes::PENDING_PARAMS_PAGE_SIZE as usize;
                    rows.truncate(crate::dashboard_changes::PENDING_PARAMS_PAGE_SIZE as usize);
                    for c in rows {
                        let approval_requirement =
                            crate::dashboard_changes::approval_requirement_view(&c);
                        // Same effect preview the /changes queue shows, drawing
                        // from a per-load budget, so the unified inbox is not a
                        // blind approval path for a previewable change.
                        let previews = crate::dashboard_changes::preview_pending_change(
                            &state,
                            &tenant,
                            &c.action_type,
                            &c.params,
                            c.target_etag.as_deref(),
                            &mut previews_left,
                        )
                        .await;
                        let effect_preview_acknowledgement_required =
                            crate::change_requests::requires_effect_preview_acknowledgement(
                                &c.action_type,
                            );
                        let preview_available =
                            previews.policy.is_some() || previews.manifest.is_some();
                        let approval_blocked = (effect_preview_acknowledgement_required
                            && !preview_available)
                            || previews
                                .policy
                                .as_ref()
                                .is_some_and(|preview| preview.blocked.is_some())
                            || previews
                                .manifest
                                .as_ref()
                                .is_some_and(|preview| preview.blocked.is_some());
                        items.push(InboxItem {
                            kind: "change request",
                            severity: "warn",
                            summary: format!("{} · {}", c.requested_by, c.action_type),
                            handle: c.binding_code.clone(),
                            params_pretty: Some(crate::dashboard_changes::render_params(&c.params)),
                            approval_requirement: Some(approval_requirement),
                            age_rel: format_ts_rel(c.created_at),
                            age_abs: format_ts_abs(c.created_at),
                            cr_approve_rel: Some(format!("/decisions/changes/{}/approve", c.id)),
                            cr_deny_rel: Some(format!("/decisions/changes/{}/deny", c.id)),
                            bg_revoke_rel: None,
                            policy_preview: previews.policy,
                            manifest_preview: previews.manifest,
                            effect_preview_acknowledgement_required,
                            approval_blocked,
                            skill_review_rel: None,
                            created_unix: c.created_at.unix_timestamp(),
                        });
                    }
                }
            }
        }
        // Active break-glass — overrides currently bypassing the gate.
        if let Some(store) = bg_store {
            match crate::dashboard_break_glass::list_active(store, &tenant).await {
                Err(e) => {
                    tracing::warn!(error = %e, "decisions: break-glass list failed");
                    load_error = true;
                }
                Ok(rows) => {
                    break_glass_saturated =
                        rows.len() >= crate::dashboard_break_glass::ACTIVE_FETCH_LIMIT as usize;
                    for t in rows {
                        items.push(InboxItem {
                            kind: "break-glass",
                            severity: "critical",
                            summary: format!("{} · {}", t.issued_to, t.scope_pattern),
                            handle: short(t.id),
                            // An active override has no proposed params to review;
                            // its subject/scope is already in `summary`.
                            params_pretty: None,
                            approval_requirement: None,
                            age_rel: format_ts_rel(t.created_at),
                            age_abs: format_ts_abs(t.created_at),
                            cr_approve_rel: None,
                            cr_deny_rel: None,
                            bg_revoke_rel: Some(format!("/decisions/break_glass/{}/revoke", t.id)),
                            // A break-glass override is not a proposed change — no
                            // effect preview.
                            policy_preview: None,
                            manifest_preview: None,
                            effect_preview_acknowledgement_required: false,
                            approval_blocked: false,
                            skill_review_rel: None,
                            created_unix: t.created_at.unix_timestamp(),
                        });
                    }
                }
            }
        }
        if state.hitl.reviewed_skills.get().is_some() {
            match crate::dashboard_skills::current_reviews(&state, &tenant).await {
                Ok(reviews) => {
                    for review in reviews.into_iter().filter(|review| {
                        review.candidate_status == waygate_skills::review::CandidateStatus::Pending
                    }) {
                        items.push(InboxItem {
                            kind: "skill",
                            severity: "warn",
                            summary: review.skill_uri.clone(),
                            handle: "Unapproved content".into(),
                            params_pretty: None,
                            approval_requirement: None,
                            age_rel: format_ts_rel(review.updated_at),
                            age_abs: format_ts_abs(review.updated_at),
                            cr_approve_rel: None,
                            cr_deny_rel: None,
                            bg_revoke_rel: None,
                            policy_preview: None,
                            manifest_preview: None,
                            effect_preview_acknowledgement_required: false,
                            approval_blocked: false,
                            skill_review_rel: Some(crate::dashboard_skills::review_url(
                                &review.skill_uri,
                            )),
                            created_unix: review.updated_at.unix_timestamp(),
                        });
                    }
                }
                Err(_) => load_error = true,
            }
        }
        // Newest first — consistent with the activity feed.
        items.sort_by_key(|i| std::cmp::Reverse(i.created_unix));
    }

    render(&DecisionsPage {
        chrome: PageChrome::build(
            &state,
            "Decisions",
            "/decisions",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf_token,
        ),
        insufficient_scope,
        items,
        changes_saturated,
        break_glass_saturated,
        stores_unconfigured,
        load_error,
        flash_ok: q.ok,
        flash_err: q.err,
    })
}

// ---- inline action handlers (reuse cores; PRG back to the queue) ----------

#[derive(Debug, Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: String,
    #[serde(default, alias = "policy_preview_acknowledged")]
    effect_preview_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
struct DenyForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    reason: String,
}

/// Admin-gate + CSRF, shared by the three action handlers. Returns the
/// principal + tenant_ctx, or a redirect-with-error back to the queue.
fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    csrf: &Option<Extension<CsrfToken>>,
    tenant_ctx: &Option<TenantContext>,
    form_csrf: &str,
) -> Result<&'a Principal, Box<Response>> {
    let principal = user.as_ref().map(|Extension(p)| p);
    let Some(principal) = principal else {
        return Err(Box::new(redirect_err(
            tenant_ctx.as_ref(),
            "Not authenticated.",
        )));
    };
    if !overview_break_glass_admin(Some(principal)) {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "decisions require mcp:admin").into_response(),
        ));
    }
    // CSRF: present session token must match; absent layer (test) ⇒ skip,
    // same convention as the per-surface dashboard forms.
    let csrf_ok = match csrf.as_ref() {
        Some(Extension(c)) => !form_csrf.is_empty() && csrf_matches(&c.0, form_csrf),
        None => true,
    };
    if !csrf_ok {
        return Err(Box::new(redirect_err(
            tenant_ctx.as_ref(),
            "Session expired. Refresh and try again.",
        )));
    }
    Ok(principal)
}

fn id_from(
    params: &HashMap<String, String>,
    tenant_ctx: Option<&TenantContext>,
) -> Result<Uuid, Box<Response>> {
    // Read by name (the `/t/{tenant}/...` nest is a 2-capture route;
    // `Path<String>` 500s on it — parse it manually instead).
    let Some(raw) = params.get("id") else {
        return Err(Box::new(redirect_err(tenant_ctx, "Missing id.")));
    };
    Uuid::parse_str(raw.trim()).map_err(|_| Box::new(redirect_err(tenant_ctx, "Invalid id.")))
}

async fn approve_change(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    session: Option<Extension<Session>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let tc = tenant_ctx.map(|Extension(c)| c);
    let principal = match authorize(&user, &csrf, &tc, &form.csrf) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match id_from(&params, tc.as_ref()) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    let session = session.as_ref().map(|Extension(s)| s);
    match approve_and_execute_core(
        &state,
        principal,
        id,
        session,
        form.effect_preview_acknowledged,
    )
    .await
    {
        Ok(cr) => redirect_ok(
            tc.as_ref(),
            &format!("Change {} is now {}.", short(id), cr.status.as_db_str()),
        ),
        Err(e) => redirect_err(
            tc.as_ref(),
            &crate::dashboard_changes::decision_err_message(&e),
        ),
    }
}

async fn deny_change(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DenyForm>,
) -> Response {
    let tc = tenant_ctx.map(|Extension(c)| c);
    let principal = match authorize(&user, &csrf, &tc, &form.csrf) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match id_from(&params, tc.as_ref()) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    if form.reason.trim().is_empty() {
        return redirect_err(tc.as_ref(), "A reason is required to deny a change.");
    }
    match deny_core(&state, principal, id, &form.reason).await {
        Ok(_) => redirect_ok(tc.as_ref(), &format!("Denied change {}.", short(id))),
        Err(e) => redirect_err(
            tc.as_ref(),
            &crate::dashboard_changes::decision_err_message(&e),
        ),
    }
}

async fn revoke_break_glass(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let tc = tenant_ctx.map(|Extension(c)| c);
    let principal = match authorize(&user, &csrf, &tc, &form.csrf) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let id = match id_from(&params, tc.as_ref()) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    // Tenant is the principal's (same rule as the read).
    let tenant = principal.tenant.as_str();
    match revoke_token_core(&state, tenant, Some(principal), id).await {
        Ok(_) => redirect_ok(
            tc.as_ref(),
            &format!("Revoked break-glass token {}.", short(id)),
        ),
        Err(e) => redirect_err(
            tc.as_ref(),
            &crate::dashboard_break_glass::bg_err_message(&e, "revoke"),
        ),
    }
}

fn redirect_ok(tenant_ctx: Option<&TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?ok={}",
        tenant_ctx::nav_url(tenant_ctx, "/decisions"),
        urlencode(msg)
    );
    Redirect::to(&url).into_response()
}

fn redirect_err(tenant_ctx: Option<&TenantContext>, msg: &str) -> Response {
    let url = format!(
        "{}?err={}",
        tenant_ctx::nav_url(tenant_ctx, "/decisions"),
        urlencode(msg)
    );
    Redirect::to(&url).into_response()
}

/// First 8 chars of a UUID — a stable handle for flashes / break-glass
/// rows, matching `dashboard_changes::short`.
fn short(id: Uuid) -> String {
    id.to_string().chars().take(8).collect()
}
