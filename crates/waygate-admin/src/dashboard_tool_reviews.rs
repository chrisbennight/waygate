//! A focused comparison of a quarantined tool and its accepted contract.

use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    contract_summary::{self, ContractSummary},
    dashboard::{csrf_matches, render, urlencode, user_display},
    error::ApiError,
    review_diff::{self, DiffSection, DiffView, SectionBody, ViewLink},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
    tool_reviews::{self, ToolReviewParams},
};
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use waygate_oidc::Principal;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/servers/tool-changes", get(page))
        .route("/servers/tool-changes/approve", post(approve))
        .route("/servers/tool-changes/events/{id}", get(event_page))
}

pub(crate) fn event_url(id: uuid::Uuid) -> String {
    format!("/servers/tool-changes/events/{id}")
}

/// What happened to the tool when the change was observed, and its chip class.
pub(crate) fn drift_outcome(
    severity: waygate_catalog::DriftSeverity,
) -> (&'static str, &'static str) {
    match severity {
        waygate_catalog::DriftSeverity::Info => ("Accepted automatically", "chip"),
        waygate_catalog::DriftSeverity::Warn => ("Flagged", "chip chip--warn"),
        waygate_catalog::DriftSeverity::Critical => ("Blocked for review", "chip chip--bad"),
    }
}

/// Display name of a top-level tool contract field.
pub(crate) fn field_label(key: &str) -> &str {
    match key {
        "description" => "Description",
        "inputSchema" => "Input schema",
        "outputSchema" => "Output schema",
        "annotations" => "Tool annotations",
        "_meta" => "Tool metadata",
        other => other,
    }
}

/// Changed top-level fields in reading order: the text the model reads, then
/// the shapes it fills and receives, then hints and metadata.
fn changed_fields(before: &serde_json::Value, after: &serde_json::Value) -> Vec<String> {
    const ORDER: [&str; 5] = [
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
        "_meta",
    ];
    let mut fields = waygate_catalog::tool_reviews::changed_fields(before, after);
    // A stable sort keeps any other fields in their existing name order.
    fields.sort_by_key(|field| {
        ORDER
            .iter()
            .position(|known| known == field)
            .unwrap_or(ORDER.len())
    });
    fields
}

pub(crate) fn review_url(server: &str, tool: &str) -> String {
    format!(
        "/servers/tool-changes?server={}&tool={}",
        urlencode(server),
        urlencode(tool)
    )
}

#[derive(Default, Deserialize)]
struct ReviewQuery {
    server: Option<String>,
    tool: Option<String>,
    after_server: Option<String>,
    after_tool: Option<String>,
    #[serde(default)]
    include_decided: bool,
    view: Option<DiffView>,
}
#[derive(Deserialize)]
struct ViewQuery {
    view: Option<DiffView>,
}
struct PendingRow {
    label: String,
    choice: Option<crate::dashboard_bulk_decisions::ToolChoice>,
    server: String,
    tool: String,
    url: String,
    trigger: String,
    status: &'static str,
}
#[derive(Template)]
#[template(path = "tool_review.html")]
struct ReviewPage {
    chrome: PageChrome,
    rows: Vec<PendingRow>,
    review: Option<waygate_catalog::tool_reviews::ToolReview>,
    /// What changed, when there is an accepted contract to compare with.
    summary: Option<ContractSummary>,
    sections: Vec<DiffSection>,
    /// Why whole definitions are shown instead of a comparison.
    baseline_note: Option<&'static str>,
    view: DiffView,
    view_links: Vec<ViewLink>,
    before_label: &'static str,
    after_label: &'static str,
    manifest_hash: String,
    observed_at: String,
    trigger: String,
    pending_count: i64,
    next: Option<String>,
    include_decided: bool,
    bulk_available: bool,
    receipts_available: bool,
}

pub(crate) fn trigger(review: &waygate_catalog::tool_reviews::ToolReview) -> String {
    if !review.quarantined {
        return "Approved definition".into();
    }
    if review.approved_hash.is_empty() {
        return "Initial approval required".into();
    }
    if review.approved_contract.is_null() {
        return "Definition differs from approval; previous definition unavailable".into();
    }
    if review.observed_contract.is_null() {
        return "Definition changed; comparison unavailable".into();
    }
    let fields = changed_fields(&review.approved_contract, &review.observed_contract)
        .into_iter()
        .map(|key| format!("{} changed", field_label(&key)))
        .collect::<Vec<_>>();
    let changed = if fields.is_empty() {
        "Definition differs from approval".into()
    } else {
        fields.join("; ")
    };
    match contract_summary::summarize(&review.approved_contract, &review.observed_contract).flagged
    {
        0 => changed,
        1 => format!("{changed} · 1 change flagged"),
        flagged => format!("{changed} · {flagged} changes flagged"),
    }
}

/// The summary of a change from one stored contract to another, when both
/// were retained.
pub(crate) fn summary(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Option<ContractSummary> {
    (!before.is_null() && !after.is_null()).then(|| contract_summary::summarize(before, after))
}

/// The review's changed fields, and why whole definitions are shown when
/// there is no accepted definition to compare with.
pub(crate) fn review_sections(
    review: &waygate_catalog::tool_reviews::ToolReview,
) -> (Vec<DiffSection>, Option<&'static str>) {
    review_sections_before(review, None)
}

pub(crate) fn review_sections_before(
    review: &waygate_catalog::tool_reviews::ToolReview,
    deadline: Option<std::time::Instant>,
) -> (Vec<DiffSection>, Option<&'static str>) {
    if review.observed_contract.is_null() {
        return (Vec::new(), None);
    }
    if !review.approved_contract.is_null() {
        return (
            field_sections_before(
                &review.approved_contract,
                &review.observed_contract,
                deadline,
            ),
            None,
        );
    }
    let note = if review.approved_hash.is_empty() {
        "No definition has been accepted for this tool yet, so the complete observed definition is shown."
    } else {
        "The previously accepted definition was not retained, so only the observed definition is shown."
    };
    let sections = changed_fields(&serde_json::Value::Null, &review.observed_contract)
        .into_iter()
        .map(|key| DiffSection {
            body: SectionBody::Definition(review_diff::text_segments(&field_text(
                &review.observed_contract[&key],
            ))),
            name: field_label(&key).to_owned(),
        })
        .collect();
    (sections, Some(note))
}

/// Descriptions read as prose; structured fields as formatted JSON.
fn field_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        value => serde_json::to_string_pretty(value).expect("JSON contract serializes"),
    }
}

/// Compare each changed top-level field. Both contracts are read from jsonb
/// columns, whose normalized key order keeps unchanged keys on matching lines.
fn field_sections(before: &serde_json::Value, after: &serde_json::Value) -> Vec<DiffSection> {
    field_sections_before(before, after, None)
}

fn field_sections_before(
    before: &serde_json::Value,
    after: &serde_json::Value,
    deadline: Option<std::time::Instant>,
) -> Vec<DiffSection> {
    changed_fields(before, after)
        .into_iter()
        .map(|key| {
            let old = before.get(&key).map(field_text);
            let new = after.get(&key).map(field_text);
            DiffSection {
                name: field_label(&key).to_owned(),
                body: SectionBody::Compared(match deadline {
                    Some(deadline) => {
                        review_diff::compare_before(old.as_deref(), new.as_deref(), deadline)
                    }
                    None => review_diff::compare(old.as_deref(), new.as_deref()),
                }),
            }
        })
        .collect()
}

/// The view switcher, shown only when a section has a comparison to switch.
fn view_links(sections: &[DiffSection], base: &str, view: DiffView) -> Vec<ViewLink> {
    if sections.iter().any(|s| s.comparison().is_some()) {
        review_diff::view_links(base, view, "Full definitions")
    } else {
        Vec::new()
    }
}

#[derive(Template)]
#[template(path = "tool_change_event.html")]
struct EventPage {
    chrome: PageChrome,
    event: waygate_catalog::DriftEvent,
    observed_at: String,
    outcome: (&'static str, &'static str),
    /// When the tool returned to a definition recorded earlier.
    earlier_recorded_at: Option<String>,
    /// Why no field comparison is shown, when it cannot be.
    unavailable: Option<&'static str>,
    summary: Option<ContractSummary>,
    sections: Vec<DiffSection>,
    view: DiffView,
    view_links: Vec<ViewLink>,
    before_label: &'static str,
    after_label: &'static str,
    quarantined: bool,
    review_url: String,
}

async fn event_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Path(params): Path<std::collections::HashMap<String, String>>,
    Query(query): Query<ViewQuery>,
) -> Result<Response, ApiError> {
    // Read `id` by key: the tenant-prefixed mount adds a second capture.
    let id = params
        .get("id")
        .and_then(|id| id.parse::<uuid::Uuid>().ok())
        .ok_or(ApiError::NotFound("Tool change not found"))?;
    let actor = user
        .as_ref()
        .map(|Extension(p)| p)
        .ok_or(ApiError::Forbidden("An administrator session is required"))?;
    tool_reviews::authorize(
        actor,
        tenant
            .as_ref()
            .map(|Extension(t)| t.slug.as_str())
            .unwrap_or(actor.tenant.as_str()),
    )?;
    let change = tool_reviews::store(&state)?
        .drift_change(actor.tenant.as_str(), id)
        .await
        .map_err(tool_reviews::unavailable)?
        .ok_or(ApiError::NotFound("Tool change not found"))?;
    let (unavailable, sections) = match (
        &change.event.previous_hash,
        &change.previous_contract,
        &change.observed_contract,
    ) {
        (None, _, _) => (
            Some("The earlier definition was not recorded for this change."),
            Vec::new(),
        ),
        (Some(_), None, _) => (
            Some("The earlier definition exceeded the review storage limit and was not kept."),
            Vec::new(),
        ),
        (Some(_), Some(_), None) => (
            Some("The new definition exceeded the review storage limit and was not kept."),
            Vec::new(),
        ),
        (Some(_), Some(before), Some(after)) => {
            let sections = field_sections(before, after);
            let unavailable = sections
                .is_empty()
                .then_some("The stored definitions do not differ.");
            (unavailable, sections)
        }
    };
    let view = DiffView::select(query.view, &headers);
    let summary = match (&change.previous_contract, &change.observed_contract) {
        (Some(before), Some(after)) if change.event.previous_hash.is_some() => {
            summary(before, after)
        }
        _ => None,
    };
    let page = EventPage {
        summary,
        view_links: view_links(&sections, &event_url(id), view),
        view,
        before_label: "Before",
        after_label: "After",
        observed_at: waygate_core::fmt::format_ts_abs(change.event.observed_at),
        outcome: drift_outcome(change.event.severity),
        earlier_recorded_at: change
            .event
            .earlier_recorded_at
            .map(waygate_core::fmt::format_ts_abs),
        unavailable,
        sections,
        quarantined: change.quarantined,
        review_url: review_url(&change.event.server, &change.event.tool),
        chrome: PageChrome::build(
            &state,
            "Tool change",
            "/servers",
            &headers,
            Some(user_display(actor)),
            tenant.map(|Extension(t)| t),
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        event: change.event,
    };
    let mut response = render(&page);
    DiffView::remember(query.view, response.headers_mut());
    Ok(response)
}

async fn page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<ReviewQuery>,
) -> Result<Response, ApiError> {
    let actor = user
        .as_ref()
        .map(|Extension(p)| p)
        .ok_or(ApiError::Forbidden("An administrator session is required"))?;
    tool_reviews::authorize(
        actor,
        tenant
            .as_ref()
            .map(|Extension(t)| t.slug.as_str())
            .unwrap_or(actor.tenant.as_str()),
    )?;
    let store = tool_reviews::store(&state)?;
    let review = match (&query.server, &query.tool) {
        (Some(server), Some(tool)) => Some(
            store
                .get(actor.tenant.as_str(), server, tool)
                .await
                .map_err(tool_reviews::unavailable)?
                .ok_or(ApiError::NotFound("Tool review not found"))?,
        ),
        _ => None,
    };
    let after = match (&query.after_server, &query.after_tool) {
        (Some(server), Some(tool)) => Some((server.as_str(), tool.as_str())),
        (None, None) => None,
        _ => {
            return Err(ApiError::BadRequest(
                "Both review page cursor fields are required".into(),
            ))
        }
    };
    let candidates = store
        .blocked_after(actor.tenant.as_str(), after, query.include_decided)
        .await
        .map_err(tool_reviews::unavailable)?;
    // The following page can be empty if another administrator decides its
    // candidates before navigation; no remaining review is silently omitted.
    let next = if candidates.len() == 50 {
        candidates.last().map(|r| {
            format!(
                "/servers/tool-changes?after_server={}&after_tool={}&include_decided={}",
                urlencode(&r.server),
                urlencode(&r.tool),
                query.include_decided
            )
        })
    } else {
        None
    };
    let manifests = state.upstreams.manifests();
    let rows = candidates
        .into_iter()
        .map(|r| PendingRow {
            label: format!("{} · {}", r.server, r.tool),
            choice: crate::dashboard_bulk_decisions::tool_choice(&r, &manifests),
            trigger: trigger(&r),
            status: if r.decided_at.is_some() {
                "Kept blocked"
            } else {
                "Needs review"
            },
            url: review_url(&r.server, &r.tool),
            server: r.server,
            tool: r.tool,
        })
        .collect();
    let (sections, baseline_note) = review.as_ref().map(review_sections).unwrap_or_default();
    let view = DiffView::select(query.view, &headers);
    let view_links = review
        .as_ref()
        .map(|r| view_links(&sections, &review_url(&r.server, &r.tool), view))
        .unwrap_or_default();
    let manifest_hash = state
        .read_manifest_set_from_disk()
        .and_then(Result::ok)
        .map(|(_, hash)| hash)
        .unwrap_or_default();
    let observed_at = review
        .as_ref()
        .map(|r| waygate_core::fmt::format_ts_abs(r.observed_at))
        .unwrap_or_default();
    let page = ReviewPage {
        receipts_available: state.hitl.decision_batches.get().is_some(),
        bulk_available: state.hitl.decision_batches.get().is_some() && !query.include_decided,
        next,
        include_decided: query.include_decided,
        trigger: review.as_ref().map(trigger).unwrap_or_default(),
        pending_count: store
            .pending_count(actor.tenant.as_str(), None)
            .await
            .map_err(tool_reviews::unavailable)?,
        observed_at,
        chrome: PageChrome::build(
            &state,
            "Tool changes",
            "/servers",
            &headers,
            Some(user_display(actor)),
            tenant.map(|Extension(t)| t),
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        rows,
        summary: review
            .as_ref()
            .and_then(|r| summary(&r.approved_contract, &r.observed_contract)),
        review,
        sections,
        baseline_note,
        view,
        view_links,
        before_label: "Previously accepted",
        after_label: "Observed replacement",
        manifest_hash,
    };
    let mut response = render(&page);
    DiffView::remember(query.view, response.headers_mut());
    Ok(response)
}

#[derive(Deserialize)]
struct ApprovalForm {
    csrf: String,
    server: String,
    tool: String,
    generation: i64,
    observed_hash: String,
    manifest_hash: String,
    action: Option<String>,
    risk: Option<String>,
}
async fn approve(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Form(form): Form<ApprovalForm>,
) -> Response {
    if !csrf_matches(
        csrf.as_ref()
            .map(|Extension(c)| c.0.as_str())
            .unwrap_or_default(),
        &form.csrf,
    ) {
        return (StatusCode::FORBIDDEN, "csrf mismatch").into_response();
    }
    let Some(Extension(actor)) = user else {
        return ApiError::Forbidden("An administrator session is required").into_response();
    };
    if let Err(error) = tool_reviews::authorize(
        &actor,
        tenant
            .as_ref()
            .map(|Extension(t)| t.slug.as_str())
            .unwrap_or(actor.tenant.as_str()),
    ) {
        return error.into_response();
    }
    let risk = match form.risk.as_deref().filter(|risk| !risk.is_empty()) {
        Some(risk) => match waygate_core::RiskTier::parse(risk) {
            Some(risk) => Some(risk),
            None => {
                return ApiError::BadRequest("Invalid gateway risk classification".into())
                    .into_response()
            }
        },
        None => None,
    };
    let params = ToolReviewParams {
        server: form.server,
        tool: form.tool,
        generation: form.generation,
        observed_hash: form.observed_hash,
        manifest_hash: form.manifest_hash,
        risk,
    };
    let result = match form.action.as_deref().unwrap_or("approve") {
        "approve" => {
            tool_reviews::approve_core(&state, actor.tenant.as_str(), &actor, &params).await
        }
        "reject" => tool_reviews::reject_core(&state, actor.tenant.as_str(), &actor, &params).await,
        _ => return ApiError::BadRequest("Unknown tool review decision".into()).into_response(),
    };
    match result {
        Ok(_) => Redirect::to(&tenant_ctx::nav_url(
            tenant.as_ref().map(|Extension(t)| t),
            &review_url(&params.server, &params.tool),
        ))
        .into_response(),
        Err(error) => error.into_response(),
    }
}
