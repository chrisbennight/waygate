//! Selection, explicit review, and recoverable results for administrator decisions.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use askama::Template;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use waygate_catalog::tool_reviews::ToolReview;
use waygate_dashboard_stores::decision_batches::{
    BatchError, BatchOwner, BatchRequest, DecisionBatch, DecisionBatchStore, ItemProgress,
};
use waygate_oidc::Principal;

use crate::{
    auth::CsrfToken,
    bulk_tool_reviews,
    chrome::PageChrome,
    contract_summary::ContractSummary,
    dashboard::{csrf_matches, overview_break_glass_admin, render, user_display},
    dashboard_tool_reviews,
    error::ApiError,
    review_diff::{DiffSection, DiffView},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
    tool_reviews::{self, ToolReviewParams},
};

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/decisions/bulk", get(recent))
        .route("/decisions/bulk/tools/review", post(prepare_tools))
        .route("/decisions/bulk/{id}", get(page))
        .route("/decisions/bulk/{id}/confirm", post(confirm))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedTool {
    pub tool_id: Uuid,
    pub params: ToolReviewParams,
}

pub(crate) struct ToolChoice {
    pub token: String,
    pub risk_name: String,
    pub initial: bool,
    pub approvable: bool,
}

fn initial_risk_required(
    review: &ToolReview,
    manifests: &[waygate_upstream::UpstreamManifest],
) -> bool {
    manifests
        .iter()
        .find(|manifest| manifest.name == review.server)
        .is_some_and(|manifest| {
            matches!(
                manifest.classification_mode,
                waygate_upstream::ClassificationMode::McpAnnotations
            ) && !manifest.tools.iter().any(|tool| tool.name == review.tool)
        })
}

pub(crate) fn tool_choice(
    review: &ToolReview,
    manifests: &[waygate_upstream::UpstreamManifest],
) -> Option<ToolChoice> {
    if !review.quarantined || review.decided_at.is_some() {
        return None;
    }
    Some(ToolChoice {
        token: serde_json::to_string(&SelectedTool {
            tool_id: review.tool_id,
            params: ToolReviewParams {
                server: review.server.clone(),
                tool: review.tool.clone(),
                generation: review.generation,
                observed_hash: review.observed_hash.clone(),
                manifest_hash: String::new(),
                risk: None,
            },
        })
        .expect("tool selection serializes"),
        risk_name: format!("risk_{}", review.tool_id.simple()),
        initial: initial_risk_required(review, manifests),
        approvable: !review.observed_contract.is_null(),
    })
}

pub(crate) fn manifest_hash(state: &AdminState) -> String {
    state
        .read_manifest_set_from_disk()
        .and_then(Result::ok)
        .map(|(_, hash)| hash)
        .unwrap_or_default()
}

pub(crate) fn owner(actor: &Principal) -> BatchOwner<'_> {
    BatchOwner {
        tenant: actor.tenant.as_str(),
        issuer: &actor.issuer,
        subject: &actor.sub,
    }
}

pub(crate) fn authorize<'a>(
    user: &'a Option<Extension<Principal>>,
    tenant: &Option<Extension<TenantContext>>,
) -> Result<&'a Principal, ApiError> {
    let actor = user
        .as_ref()
        .map(|Extension(p)| p)
        .ok_or(ApiError::Forbidden("An administrator session is required"))?;
    if !overview_break_glass_admin(Some(actor))
        || tenant
            .as_ref()
            .is_some_and(|Extension(t)| t.slug != actor.tenant.as_str())
    {
        return Err(ApiError::Forbidden(
            "Decisions require an administrator in this tenant",
        ));
    }
    Ok(actor)
}

pub(crate) fn csrf(csrf: &Option<Extension<CsrfToken>>, supplied: &str) -> Result<(), ApiError> {
    let Some(Extension(expected)) = csrf else {
        return Err(ApiError::Forbidden("csrf mismatch"));
    };
    if supplied.is_empty() || !csrf_matches(&expected.0, supplied) {
        return Err(ApiError::Forbidden("csrf mismatch"));
    }
    Ok(())
}

pub(crate) fn store_error(error: BatchError) -> ApiError {
    match error {
        BatchError::Invalid(message)=>ApiError::BadRequest(message.into()),
        BatchError::Conflict=>ApiError::Conflict("This submission identifies a different selection".into()),
        BatchError::Capacity=>ApiError::Conflict("The retained bulk-decision limit has been reached. Review recent submissions or wait for older receipts to expire.".into()),
        BatchError::Store(_) | BatchError::Encoding(_)=>ApiError::ServiceUnavailable("Decision receipts are unavailable"),
    }
}

pub(crate) fn field<'a>(
    fields: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    let mut values = fields
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str());
    let value = values.next();
    if values.next().is_some() {
        return Err(ApiError::BadRequest("Duplicate decision form field".into()));
    }
    Ok(value)
}

fn selections(batch: &DecisionBatch) -> Result<Vec<SelectedTool>, ApiError> {
    if batch.request.kind != "tool"
        || !matches!(batch.request.action.as_str(), "approve" | "reject")
    {
        return Err(ApiError::BadRequest("Unsupported bulk decision".into()));
    }
    batch
        .request
        .items
        .iter()
        .cloned()
        .map(|item| {
            serde_json::from_value(item)
                .map_err(|_| ApiError::Internal("Invalid stored tool selection".into()))
        })
        .collect()
}

async fn reviewed_tools(
    state: &AdminState,
    actor: &Principal,
    selected: &[SelectedTool],
    accepting: bool,
) -> Result<Vec<ToolReview>, ApiError> {
    tool_reviews::authorize(actor, actor.tenant.as_str())?;
    let store = tool_reviews::store(state)?;
    let mut reviews = Vec::new();
    let manifests = state.upstreams.manifests();
    let mut identities = HashSet::new();
    for selected in selected {
        if !identities.insert(selected.tool_id) {
            return Err(ApiError::BadRequest("Select each tool only once".into()));
        }
        let target = &selected.params;
        let review = store
            .get(actor.tenant.as_str(), &target.server, &target.tool)
            .await
            .map_err(tool_reviews::unavailable)?
            .ok_or(ApiError::NotFound("Tool review no longer exists"))?;
        if review.tool_id != selected.tool_id
            || review.generation != target.generation
            || review.observed_hash != target.observed_hash
            || !review.quarantined
            || review.decided_at.is_some()
        {
            return Err(ApiError::Conflict("A selected tool changed or was already decided. Select the current pending reviews again.".into()));
        }
        if accepting {
            if review.observed_contract.is_null() {
                return Err(ApiError::Conflict("An observed definition is unavailable. It can be kept blocked, but cannot be accepted.".into()));
            }
            let initial = initial_risk_required(&review, &manifests);
            if initial && target.risk.is_none() {
                return Err(ApiError::BadRequest(
                    "Select a gateway risk classification for every initial tool approval".into(),
                ));
            }
            if !initial && target.risk.is_some() {
                return Err(ApiError::BadRequest(
                    "A gateway risk choice is only valid for an unclassified annotation-based tool"
                        .into(),
                ));
            }
        }
        reviews.push(review);
    }
    bulk_tool_reviews::check_review_budget(&reviews)?;
    Ok(reviews)
}

async fn prepare_tools(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    token: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Redirect, ApiError> {
    let actor = authorize(&user, &tenant)?;
    tool_reviews::authorize(actor, actor.tenant.as_str())?;
    csrf(&token, field(&fields, "csrf")?.unwrap_or_default())?;
    let action = field(&fields, "action")?
        .filter(|a| matches!(*a, "approve" | "reject"))
        .ok_or(ApiError::BadRequest(
            "Choose Approve replacements or Keep blocked".into(),
        ))?;
    let base = field(&fields, "manifest_hash")?.unwrap_or_default();
    let mut selected = Vec::new();
    for (_, value) in fields.iter().filter(|(key, _)| key == "selected") {
        if selected.len() >= waygate_dashboard_stores::decision_batches::MAX_ITEMS {
            return Err(ApiError::BadRequest(
                "Select no more than fifty decisions".into(),
            ));
        }
        let mut item: SelectedTool = serde_json::from_str(value).map_err(|_| {
            ApiError::BadRequest("Invalid tool selection. Reload the review list.".into())
        })?;
        item.params.manifest_hash = base.into();
        item.params.risk = if action == "approve" {
            match field(&fields, &format!("risk_{}", item.tool_id.simple()))?
                .filter(|s| !s.is_empty())
            {
                Some(risk) => Some(waygate_core::RiskTier::parse(risk).ok_or(
                    ApiError::BadRequest("Invalid gateway risk classification".into()),
                )?),
                None => None,
            }
        } else {
            None
        };
        selected.push(item);
    }
    if selected.is_empty() {
        return Err(ApiError::BadRequest(
            "Select at least one pending tool review".into(),
        ));
    }
    reviewed_tools(&state, actor, &selected, action == "approve").await?;
    let request = BatchRequest {
        kind: "tool".into(),
        action: action.into(),
        items: selected
            .iter()
            .map(|item| serde_json::to_value(item).expect("tool selection serializes"))
            .collect(),
    };
    let id = Uuid::new_v4();
    state
        .hitl
        .decision_batches
        .require()?
        .prepare(owner(actor), id, &request)
        .await
        .map_err(store_error)?;
    Ok(Redirect::to(&tenant_ctx::nav_url(
        tenant.as_ref().map(|Extension(t)| t),
        &format!("/decisions/bulk/{id}"),
    )))
}

struct ReviewItem {
    name: String,
    url: String,
    trigger: String,
    sections: Vec<DiffSection>,
    summary: Option<ContractSummary>,
    baseline_note: Option<&'static str>,
    outcome: &'static str,
    guidance: &'static str,
    risk: String,
}

#[derive(Template)]
#[template(path = "bulk_tool_decisions.html")]
struct ReviewPage {
    chrome: PageChrome,
    items: Vec<ReviewItem>,
    approving: bool,
    started: bool,
    confirmable: bool,
    confirm_url: String,
    note: Option<String>,
    view: DiffView,
    before_label: &'static str,
    after_label: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionOutcome {
    Approved,
    KeptBlocked,
    Rejected,
    GrantIssued,
    InvocationDenied,
    AlreadyDecided,
    Changed,
    Unavailable,
    AppliedEvidenceAttention,
    Uncertain,
}

impl DecisionOutcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Approved => "Approved",
            Self::KeptBlocked => "Kept blocked",
            Self::Rejected => "Rejected",
            Self::GrantIssued => "Single-use grant issued",
            Self::InvocationDenied => "Invocation request denied",
            Self::AlreadyDecided => "Already decided",
            Self::Changed => "Changed since review",
            Self::Unavailable => "Unavailable",
            Self::AppliedEvidenceAttention => "Applied; evidence needs attention",
            Self::Uncertain => "Outcome needs reconciliation",
        }
    }
    fn guidance(&self) -> &'static str {
        match self {
            Self::Approved=>"Existing configuration and access policies still apply.",
            Self::GrantIssued=>"No execution was confirmed by this decision. The requester must retry only the reviewed call through the ordinary invocation boundary before the grant expires. Do not replay completed program effects.",
            Self::InvocationDenied=>"No permission was issued. A denied Code Mode execution cannot resume this request.",
            Self::KeptBlocked=>"The reviewed definition remains blocked.",
            Self::Rejected=>"The candidate was rejected. Any previously serving skill version retains its existing eligibility.",
            Self::AlreadyDecided=>"A completed decision already resolved this candidate. Inspect its current review before reconsidering it.",
            Self::Changed=>"Review the current candidate before making another decision.",
            Self::Unavailable=>"No decision was confirmed for this item. Inspect its current review.",
            Self::AppliedEvidenceAttention=>"The decision took effect, but required evidence recording failed. Verify the review and Activity before further action.",
            Self::Uncertain=>"Inspect the current review and Activity before starting a new decision. This submission will not be replayed.",
        }
    }
}

pub(crate) fn outcome(error: &ApiError) -> DecisionOutcome {
    match error {
        ApiError::Conflict(_)
        | ApiError::NotFound(_)
        | ApiError::NotFoundDyn(_)
        | ApiError::BadRequest(_) => DecisionOutcome::Changed,
        ApiError::ServiceUnavailable(_) => DecisionOutcome::Unavailable,
        ApiError::InternalOperatorVisible(_) => DecisionOutcome::AppliedEvidenceAttention,
        _ => DecisionOutcome::Uncertain,
    }
}

pub(crate) fn progress(
    progress: &ItemProgress,
    started: bool,
) -> Result<(&'static str, &'static str), ApiError> {
    if let Some(value) = &progress.result {
        let outcome: DecisionOutcome = serde_json::from_value(value["outcome"].clone())
            .map_err(|_| ApiError::Internal("Invalid stored decision outcome".into()))?;
        return Ok((outcome.label(), outcome.guidance()));
    }
    if progress.started_at.is_some() {
        return Ok((
            "Awaiting a confirmed outcome",
            DecisionOutcome::Uncertain.guidance(),
        ));
    }
    Ok((
        if started {
            "Not started"
        } else {
            "Awaiting confirmation"
        },
        "",
    ))
}

fn batch_id(params: &HashMap<String, String>) -> Result<Uuid, ApiError> {
    params
        .get("id")
        .and_then(|s| s.parse().ok())
        .ok_or(ApiError::NotFound("Decision receipt not found"))
}

pub(crate) async fn begin(
    receipts: &dyn DecisionBatchStore,
    owner: BatchOwner<'_>,
    id: Uuid,
    index: usize,
) -> Result<(), ApiError> {
    if !receipts
        .begin_item(owner, id, index as i32)
        .await
        .map_err(store_error)?
    {
        return Err(ApiError::Conflict(
            "The submission is already in progress".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn finish(
    receipts: &dyn DecisionBatchStore,
    owner: BatchOwner<'_>,
    id: Uuid,
    index: usize,
    observed: DecisionOutcome,
) -> Result<(), ApiError> {
    if !receipts
        .complete_item(
            owner,
            id,
            index as i32,
            &serde_json::json!({"outcome":observed}),
        )
        .await
        .map_err(store_error)?
    {
        return Err(ApiError::Conflict(
            "The decision result requires reconciliation".into(),
        ));
    }
    Ok(())
}

async fn tool_outcome(
    state: &AdminState,
    actor: &Principal,
    selected: &SelectedTool,
    result: Result<(), ApiError>,
    success: DecisionOutcome,
) -> DecisionOutcome {
    match result {
        Ok(()) => success,
        Err(ApiError::Conflict(_)) => match tool_reviews::store(state) {
            Ok(store) => match store
                .get(
                    actor.tenant.as_str(),
                    &selected.params.server,
                    &selected.params.tool,
                )
                .await
            {
                Ok(Some(review))
                    if review.tool_id == selected.tool_id
                        && review.generation == selected.params.generation
                        && review.observed_hash == selected.params.observed_hash
                        && (!review.quarantined || review.decided_at.is_some()) =>
                {
                    DecisionOutcome::AlreadyDecided
                }
                Ok(_) => DecisionOutcome::Changed,
                Err(_) => DecisionOutcome::Unavailable,
            },
            Err(_) => DecisionOutcome::Unavailable,
        },
        Err(error) => outcome(&error),
    }
}

async fn page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    token: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, ApiError> {
    let actor = authorize(&user, &tenant)?;
    let id = batch_id(&params)?;
    let batch = state
        .hitl
        .decision_batches
        .require()?
        .get(owner(actor), id)
        .await
        .map_err(store_error)?
        .ok_or(ApiError::NotFound(
            "Decision receipt expired or is unavailable",
        ))?;
    if batch.request.kind == "invocation" {
        return crate::dashboard_bulk_invocations::page(
            &state,
            actor,
            tenant.map(|Extension(t)| t),
            token.map(|Extension(t)| t.0).unwrap_or_default(),
            &headers,
            batch,
        )
        .await;
    }
    if batch.request.kind == "skill" {
        return crate::dashboard_bulk_skills::page(
            &state,
            actor,
            tenant.map(|Extension(t)| t),
            token.map(|Extension(t)| t.0).unwrap_or_default(),
            &headers,
            batch,
        )
        .await;
    }
    let selected = selections(&batch)?;
    tool_reviews::authorize(actor, actor.tenant.as_str())?;
    let started = batch.started_at.is_some();
    let approving = batch.request.action == "approve";
    let reviews = if !started {
        reviewed_tools(&state, actor, &selected, approving)
            .await
            .map(Some)
    } else {
        Ok(None)
    };
    let (reviews, note) = match reviews {
        Ok(reviews) => (reviews, None),
        Err(error) => (None, Some(error.detail())),
    };
    let mut items = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    for (index, selection) in selected.iter().enumerate() {
        let (sections, baseline_note, summary, trigger) =
            match reviews.as_ref().and_then(|rows| rows.get(index)) {
                Some(review) => {
                    let (sections, note) =
                        dashboard_tool_reviews::review_sections_before(review, Some(deadline));
                    (
                        sections,
                        note,
                        dashboard_tool_reviews::summary(
                            &review.approved_contract,
                            &review.observed_contract,
                        ),
                        dashboard_tool_reviews::trigger(review),
                    )
                }
                None => (Vec::new(), None, None, String::new()),
            };
        let item_progress = batch.items.get(index).ok_or(ApiError::Internal(
            "Decision receipt progress is incomplete".into(),
        ))?;
        let (outcome, guidance) = progress(item_progress, started)?;
        items.push(ReviewItem {
            name: format!("{} · {}", selection.params.server, selection.params.tool),
            url: dashboard_tool_reviews::review_url(
                &selection.params.server,
                &selection.params.tool,
            ),
            trigger,
            sections,
            summary,
            baseline_note,
            outcome,
            guidance,
            risk: selection
                .params
                .risk
                .map(|risk| risk.as_str().to_owned())
                .unwrap_or_default(),
        });
    }
    Ok(render(&ReviewPage {
        chrome: PageChrome::build(
            &state,
            "Bulk tool decisions",
            "/decisions",
            &headers,
            Some(user_display(actor)),
            tenant.map(|Extension(t)| t),
            token.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        items,
        approving,
        started,
        confirmable: !started && note.is_none(),
        confirm_url: format!("/decisions/bulk/{id}/confirm"),
        note,
        view: DiffView::Unified,
        before_label: "Previously accepted",
        after_label: "Observed replacement",
    }))
}

#[derive(Deserialize)]
struct Confirmation {
    csrf: String,
    #[serde(default)]
    reviewed: bool,
}

async fn confirm(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    token: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<Confirmation>,
) -> Result<Redirect, ApiError> {
    let actor = authorize(&user, &tenant)?;
    csrf(&token, &form.csrf)?;
    if !form.reviewed {
        return Err(ApiError::BadRequest(
            "Confirm that you reviewed the complete selection".into(),
        ));
    }
    let id = batch_id(&params)?;
    let receipts = state.hitl.decision_batches.require()?;
    let batch = receipts
        .get(owner(actor), id)
        .await
        .map_err(store_error)?
        .ok_or(ApiError::NotFound(
            "Decision receipt expired or is unavailable",
        ))?;
    if batch.request.kind == "skill" {
        crate::dashboard_bulk_skills::confirm(&state, actor, &batch).await?;
        return Ok(Redirect::to(&tenant_ctx::nav_url(
            tenant.as_ref().map(|Extension(t)| t),
            &format!("/decisions/bulk/{id}"),
        )));
    }
    if batch.request.kind == "invocation" {
        crate::dashboard_bulk_invocations::confirm(&state, actor, &batch).await?;
        return Ok(Redirect::to(&tenant_ctx::nav_url(
            tenant.as_ref().map(|Extension(t)| t),
            &format!("/decisions/bulk/{id}"),
        )));
    }
    tool_reviews::authorize(actor, actor.tenant.as_str())?;
    let selected = selections(&batch)?;
    if batch.started_at.is_none()
        && receipts
            .claim(owner(actor), id)
            .await
            .map_err(store_error)?
    {
        if batch.request.action == "approve" {
            for index in 0..selected.len() {
                begin(receipts.as_ref(), owner(actor), id, index).await?;
            }
            let params: Vec<_> = selected.iter().map(|s| s.params.clone()).collect();
            match bulk_tool_reviews::approve(&state, actor, &params, id).await {
                Ok(results) => {
                    for (index, result) in results.into_iter().enumerate() {
                        let observed = tool_outcome(
                            &state,
                            actor,
                            &selected[index],
                            result.map(|_| ()),
                            DecisionOutcome::Approved,
                        )
                        .await;
                        finish(receipts.as_ref(), owner(actor), id, index, observed).await?;
                    }
                }
                // A group failure can follow a committed publication. Retain
                // uncertain progress rather than presenting it as no effect.
                Err(_) => {
                    tracing::error!(batch_id=%id,"Bulk tool decisions need reconciliation; inspect receipt progress and server configuration");
                }
            }
        } else {
            for (index, item) in selected.iter().enumerate() {
                begin(receipts.as_ref(), owner(actor), id, index).await?;
                let result = tool_reviews::reject_for_batch(
                    &state,
                    actor.tenant.as_str(),
                    actor,
                    &item.params,
                    Some(id),
                )
                .await;
                let observed =
                    tool_outcome(&state, actor, item, result, DecisionOutcome::KeptBlocked).await;
                finish(receipts.as_ref(), owner(actor), id, index, observed).await?;
            }
        }
    }
    state
        .hitl
        .decisions_badge_cache
        .lock()
        .await
        .remove(actor.tenant.as_str());
    Ok(Redirect::to(&tenant_ctx::nav_url(
        tenant.as_ref().map(|Extension(t)| t),
        &format!("/decisions/bulk/{id}"),
    )))
}

struct RecentRow {
    url: String,
    kind: String,
    action: String,
    created: String,
    items: i64,
    completed: i64,
}
#[derive(Template)]
#[template(path = "bulk_decisions.html")]
struct RecentPage {
    chrome: PageChrome,
    rows: Vec<RecentRow>,
}

async fn recent(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    token: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let actor = authorize(&user, &tenant)?;
    let rows = state
        .hitl
        .decision_batches
        .require()?
        .recent(owner(actor))
        .await
        .map_err(store_error)?
        .into_iter()
        .map(|r| RecentRow {
            url: format!("/decisions/bulk/{}", r.id),
            kind: r.kind,
            action: r.action,
            created: waygate_core::fmt::format_ts_abs(r.created_at),
            items: r.item_count,
            completed: r.completed_count,
        })
        .collect();
    Ok(render(&RecentPage {
        chrome: PageChrome::build(
            &state,
            "Bulk decisions",
            "/decisions",
            &headers,
            Some(user_display(actor)),
            tenant.map(|Extension(t)| t),
            token.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        rows,
    }))
}
