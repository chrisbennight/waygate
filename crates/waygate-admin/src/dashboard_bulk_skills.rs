//! Selected distribution decisions retain the skill service's exact-content rules.

use std::{collections::HashSet, sync::Arc};

use askama::Template;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{Redirect, Response},
    routing::post,
    Extension, Form, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use waygate_dashboard_stores::decision_batches::{BatchRequest, DecisionBatch};
use waygate_oidc::Principal;
use waygate_skills::review::{CandidateStatus, ReviewDecision, SkillReview};

use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{render, user_display},
    dashboard_bulk_decisions::{self as batches, DecisionOutcome},
    error::ApiError,
    review_diff::{self, Segment},
    skill_reviews::{self, SkillDecisionParams},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
};

const MAX_SKILLS: usize = 10;
const MAX_REVIEW_BYTES: u64 = 2 * 1024 * 1024;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/decisions/bulk/skills/review", post(prepare))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedSkill {
    uri: String,
    generation: i64,
    digest: String,
    #[serde(default)]
    reason: String,
}

pub(crate) fn choice(review: &SkillReview) -> Option<String> {
    (review.candidate_status == CandidateStatus::Pending).then(|| {
        serde_json::to_string(&SelectedSkill {
            uri: review.skill_uri.clone(),
            generation: review.generation,
            digest: review.candidate.content_digest().into(),
            reason: String::new(),
        })
        .expect("skill identity serializes")
    })
}

fn selections(batch: &DecisionBatch) -> Result<Vec<SelectedSkill>, ApiError> {
    if batch.request.kind != "skill"
        || !matches!(batch.request.action.as_str(), "approve" | "reject")
    {
        return Err(ApiError::BadRequest("Unsupported skill decision".into()));
    }
    batch
        .request
        .items
        .iter()
        .cloned()
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|_| ApiError::Internal("Invalid stored skill selection".into()))
        })
        .collect()
}

async fn current(
    state: &AdminState,
    actor: &Principal,
    selected: &SelectedSkill,
) -> Result<SkillReview, ApiError> {
    let review = skill_reviews::current_review(state, actor.tenant.as_str(), &selected.uri).await?;
    if review.generation != selected.generation
        || review.candidate.content_digest() != selected.digest
        || review.candidate_status != CandidateStatus::Pending
    {
        return Err(ApiError::Conflict("A selected skill changed or was already decided. Select current pending candidates again.".into()));
    }
    Ok(review)
}

async fn reviews(
    state: &AdminState,
    actor: &Principal,
    selected: &[SelectedSkill],
) -> Result<Vec<SkillReview>, ApiError> {
    if selected.is_empty() || selected.len() > MAX_SKILLS {
        return Err(ApiError::BadRequest(
            "Select between one and ten pending skills".into(),
        ));
    }
    let mut identities = HashSet::new();
    let mut rows = Vec::new();
    let mut bytes = 0_u64;
    for item in selected {
        if !identities.insert(&item.uri) {
            return Err(ApiError::BadRequest("Select each skill only once".into()));
        }
        let row = current(state, actor, item).await?;
        bytes = bytes.saturating_add(
            serde_json::to_vec(&row.candidate)
                .expect("candidate serializes")
                .len() as u64,
        );
        for file in &row.candidate.skill().resources {
            bytes = bytes.saturating_add(file.size);
        }
        if bytes > MAX_REVIEW_BYTES {
            return Err(ApiError::PayloadTooLarge("The complete skill review exceeds two MiB. Select fewer skills or use individual review; no content was truncated.".into()));
        }
        rows.push(row);
    }
    Ok(rows)
}

async fn prepare(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    token: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Redirect, ApiError> {
    let actor = batches::authorize(&user, &tenant)?;
    batches::csrf(&token, batches::field(&fields, "csrf")?.unwrap_or_default())?;
    let action = batches::field(&fields, "action")?
        .filter(|value| matches!(*value, "approve" | "reject"))
        .ok_or(ApiError::BadRequest(
            "Choose Approve skills or Reject candidates".into(),
        ))?;
    let reason = batches::field(&fields, "reason")?
        .unwrap_or_default()
        .trim();
    if reason.is_empty() || reason.len() > 4096 {
        return Err(ApiError::BadRequest(
            "An operator reason of at most 4096 bytes is required".into(),
        ));
    }
    let mut selected = Vec::new();
    for (_, value) in fields.iter().filter(|(key, _)| key == "selected") {
        if selected.len() >= MAX_SKILLS {
            return Err(ApiError::BadRequest(
                "Select no more than ten skills".into(),
            ));
        }
        let mut item: SelectedSkill = serde_json::from_str(value).map_err(|_| {
            ApiError::BadRequest("Invalid skill selection; reload the queue".into())
        })?;
        item.reason = reason.into();
        selected.push(item);
    }
    reviews(&state, actor, &selected).await?;
    let request = BatchRequest {
        kind: "skill".into(),
        action: action.into(),
        items: selected
            .iter()
            .map(|item| serde_json::to_value(item).expect("skill selection serializes"))
            .collect(),
    };
    let id = Uuid::new_v4();
    state
        .hitl
        .decision_batches
        .require()?
        .prepare(batches::owner(actor), id, &request)
        .await
        .map_err(batches::store_error)?;
    Ok(Redirect::to(&tenant_ctx::nav_url(
        tenant.as_ref().map(|Extension(t)| t),
        &format!("/decisions/bulk/{id}"),
    )))
}

struct FileView {
    path: String,
    media: String,
    object: String,
    size: u64,
    text: Option<Vec<Segment>>,
    note: Option<&'static str>,
    unavailable: bool,
}
struct SkillView {
    uri: String,
    url: String,
    metadata: Vec<Segment>,
    source: String,
    reason: String,
    files: Vec<FileView>,
    outcome: &'static str,
    guidance: &'static str,
}
#[derive(Template)]
#[template(path = "bulk_skill_decisions.html")]
struct ReviewPage {
    chrome: PageChrome,
    items: Vec<SkillView>,
    approving: bool,
    started: bool,
    confirmable: bool,
    confirm_url: String,
    note: Option<String>,
}

async fn review_files(state: &AdminState, review: &SkillReview) -> Result<Vec<FileView>, ApiError> {
    let snapshot = state
        .hitl
        .reviewed_skills
        .require()?
        .review_snapshot(&review.candidate)
        .await
        .ok();
    let mut files = Vec::new();
    for file in &review.candidate.skill().resources {
        let mut row = FileView {
            path: file.source_path.clone(),
            media: file.media_type.clone(),
            object: file.source_object.clone(),
            size: file.size,
            text: None,
            note: None,
            unavailable: false,
        };
        if let Some(snapshot) = &snapshot {
            match snapshot.load_resource(&file.uri).await {
                Ok(Some(resource)) => match std::str::from_utf8(&resource.bytes) {
                    Ok(text) => row.text = Some(review_diff::text_segments(text)),
                    Err(_) => row.note = Some(
                        "Binary file: review its immutable object identity, size, and media type.",
                    ),
                },
                _ => {
                    row.unavailable = true;
                    row.note =
                        Some("Exact file unavailable. No replacement content was substituted.");
                }
            }
        } else {
            row.unavailable = true;
            row.note =
                Some("Exact source revision unavailable. No replacement content was substituted.");
        }
        files.push(row);
    }
    Ok(files)
}

pub(crate) async fn page(
    state: &Arc<AdminState>,
    actor: &Principal,
    tenant: Option<TenantContext>,
    csrf: String,
    headers: &HeaderMap,
    batch: DecisionBatch,
) -> Result<Response, ApiError> {
    let selected = selections(&batch)?;
    let started = batch.started_at.is_some();
    let approving = batch.request.action == "approve";
    let (rows, mut note) = if started {
        (None, None)
    } else {
        match reviews(state, actor, &selected).await {
            Ok(rows) => (Some(rows), None),
            Err(error) => (None, Some(error.detail())),
        }
    };
    let mut items = Vec::new();
    for (index, selection) in selected.iter().enumerate() {
        let (outcome, guidance) = batches::progress(
            batch.items.get(index).ok_or(ApiError::Internal(
                "Skill receipt progress is incomplete".into(),
            ))?,
            started,
        )?;
        let mut view = SkillView {
            uri: selection.uri.clone(),
            url: crate::dashboard_skills::review_url(&selection.uri),
            metadata: Vec::new(),
            source: String::new(),
            reason: selection.reason.clone(),
            files: Vec::new(),
            outcome,
            guidance,
        };
        if let Some(review) = rows.as_ref().and_then(|rows| rows.get(index)) {
            view.metadata = review_diff::text_segments(
                &serde_json::to_string_pretty(&review.candidate.skill().frontmatter)
                    .expect("metadata serializes"),
            );
            view.source = format!(
                "{} · {} · {}",
                review.candidate.source().origin,
                review.candidate.source().reference,
                review.candidate.source().resolved_digest
            );
            view.files = review_files(state, review).await?;
            if approving && view.files.iter().any(|file| file.unavailable) {
                note = Some("A selected candidate has unavailable source content. Use its individual review after restoring the exact revision.".into());
            }
        }
        items.push(view);
    }
    Ok(render(&ReviewPage {
        chrome: PageChrome::build(
            state,
            "Bulk skill decisions",
            "/decisions",
            headers,
            Some(user_display(actor)),
            tenant,
            csrf,
        ),
        items,
        approving,
        started,
        confirmable: !started && note.is_none(),
        confirm_url: format!("/decisions/bulk/{}/confirm", batch.id),
        note,
    }))
}

pub(crate) async fn confirm(
    state: &Arc<AdminState>,
    actor: &Principal,
    batch: &DecisionBatch,
) -> Result<(), ApiError> {
    let selected = selections(batch)?;
    let receipts = state.hitl.decision_batches.require()?;
    if batch.started_at.is_some()
        || !receipts
            .claim(batches::owner(actor), batch.id)
            .await
            .map_err(batches::store_error)?
    {
        return Ok(());
    }
    for (index, item) in selected.iter().enumerate() {
        batches::begin(receipts.as_ref(), batches::owner(actor), batch.id, index).await?;
        let decision = if batch.request.action == "approve" {
            ReviewDecision::Approve
        } else {
            ReviewDecision::Reject
        };
        let result = async {
            let review = current(state, actor, item).await?;
            if decision == ReviewDecision::Approve
                && review_files(state, &review)
                    .await?
                    .iter()
                    .any(|file| file.unavailable)
            {
                return Err(skill_reviews::unavailable_revision());
            }
            let params = SkillDecisionParams {
                skill_uri: item.uri.clone(),
                generation: item.generation,
                content_digest: item.digest.clone(),
                reason: item.reason.clone(),
            };
            skill_reviews::decide_for_batch(
                state,
                actor.tenant.as_str(),
                actor,
                &params,
                decision,
                Some(batch.id),
            )
            .await
        }
        .await;
        let observed = match result {
            Ok(_) => {
                if decision == ReviewDecision::Approve {
                    DecisionOutcome::Approved
                } else {
                    DecisionOutcome::Rejected
                }
            }
            Err(ApiError::Conflict(_)) => {
                match skill_reviews::current_review(state, actor.tenant.as_str(), &item.uri).await {
                    Ok(review)
                        if review.candidate.content_digest() == item.digest
                            && review.candidate_status != CandidateStatus::Pending =>
                    {
                        DecisionOutcome::AlreadyDecided
                    }
                    Ok(_) => DecisionOutcome::Changed,
                    Err(error) => batches::outcome(&error),
                }
            }
            Err(error) => batches::outcome(&error),
        };
        batches::finish(
            receipts.as_ref(),
            batches::owner(actor),
            batch.id,
            index,
            observed,
        )
        .await?;
    }
    Ok(())
}
