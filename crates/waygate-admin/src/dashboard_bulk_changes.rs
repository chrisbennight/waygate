//! Compatible administrator changes retain their captured approval conditions.
use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{render, user_display},
    dashboard_bulk_decisions::{self as batches, DecisionOutcome},
    error::ApiError,
    review_diff::{self, Segment},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
};
use askama::Template;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{Redirect, Response},
    routing::post,
    Extension, Form, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;
use waygate_changeset::{ChangeRequest, ChangeRequestStatus};
use waygate_dashboard_stores::decision_batches::{BatchRequest, DecisionBatch};
use waygate_oidc::{Principal, Session};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedChange {
    id: Uuid,
    digest: String,
    #[serde(default)]
    reason: String,
}
fn intent(change: &ChangeRequest) -> serde_json::Value {
    serde_json::json!({"tenant":change.tenant_id,"action":change.action_type,"params":change.params,"preview":change.preview,"target":change.target_etag,"requested_by":change.requested_by,"justification":change.justification,"binding_code":change.binding_code,"requirement":change.requirement(),"created":change.created_at.to_string(),"expires":change.expires_at.to_string()})
}
fn digest(change: &ChangeRequest) -> String {
    waygate_catalog::argument_hash(intent(change).as_object())
}
fn target(change: &ChangeRequest) -> Result<(String, String), ApiError> {
    if change.action_type != "rate_limit.create" {
        return Err(ApiError::BadRequest("Only creation of independent rate-limit policies supports selected approval. Other actions require individual review.".into()));
    }
    let params: crate::rate_limit_policies::CreatePolicyRequest =
        serde_json::from_value(change.params.clone()).map_err(|_| {
            ApiError::BadRequest("The captured rate-limit policy is invalid".into())
        })?;
    let group = format!("{}:{}", params.scope.as_str(), params.action.as_str());
    let key = params.scope_value.unwrap_or_default();
    Ok((group, key))
}
pub(crate) fn choice(change: &ChangeRequest) -> Option<String> {
    (change.effective_status(time::OffsetDateTime::now_utc()) == ChangeRequestStatus::Pending
        && target(change).is_ok())
    .then(|| {
        serde_json::to_string(&SelectedChange {
            id: change.id,
            digest: digest(change),
            reason: String::new(),
        })
        .expect("change selection serializes")
    })
}
pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/decisions/bulk/changes/review", post(prepare))
}
fn selections(batch: &DecisionBatch) -> Result<Vec<SelectedChange>, ApiError> {
    if batch.request.kind != "change" || batch.request.action != "approve" {
        return Err(ApiError::BadRequest(
            "Unsupported administrative decision".into(),
        ));
    }
    batch
        .request
        .items
        .iter()
        .cloned()
        .map(|item| {
            serde_json::from_value(item)
                .map_err(|_| ApiError::Internal("Invalid stored administrative selection".into()))
        })
        .collect()
}
async fn current(
    state: &AdminState,
    actor: &Principal,
    item: &SelectedChange,
) -> Result<ChangeRequest, ApiError> {
    let change = state
        .hitl
        .change_requests
        .require()?
        .get(actor.tenant.as_str(), item.id)
        .await
        .map_err(|_| ApiError::Internal("Administrative request read failed".into()))?
        .ok_or(ApiError::NotFound("Administrative change request"))?;
    if change.effective_status(time::OffsetDateTime::now_utc()) != ChangeRequestStatus::Pending
        || digest(&change) != item.digest
    {
        return Err(ApiError::Conflict(
            "The selected administrative change expired, changed, or was already decided".into(),
        ));
    }
    target(&change)?;
    Ok(change)
}
async fn reviews(
    state: &AdminState,
    actor: &Principal,
    selected: &[SelectedChange],
) -> Result<Vec<ChangeRequest>, ApiError> {
    if selected.is_empty() || selected.len() > 50 {
        return Err(ApiError::BadRequest(
            "Select between one and fifty supported changes".into(),
        ));
    }
    let mut ids = HashSet::new();
    let mut targets = HashSet::new();
    let mut group = None;
    let mut bytes = 0;
    let mut rows = Vec::new();
    for item in selected {
        let row = current(state, actor, item).await?;
        let (kind, key) = target(&row)?;
        if !ids.insert(item.id)
            || !targets.insert(key)
            || group.as_ref().is_some_and(|group| group != &kind)
        {
            return Err(ApiError::BadRequest("Select distinct policy targets with the same scope and action. Dependent or incompatible changes require individual review.".into()));
        }
        group = Some(kind);
        bytes += serde_json::to_vec(&intent(&row))
            .expect("intent serializes")
            .len();
        if bytes > 2 * 1024 * 1024 {
            return Err(ApiError::PayloadTooLarge("Complete administrative review exceeds two MiB. Select fewer changes; no intent was truncated.".into()));
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
        if selected.len() >= 50 {
            return Err(ApiError::BadRequest(
                "Select no more than fifty changes".into(),
            ));
        }
        let mut item: SelectedChange = serde_json::from_str(value)
            .map_err(|_| ApiError::BadRequest("Invalid administrative selection".into()))?;
        item.reason = reason.into();
        selected.push(item);
    }
    reviews(&state, actor, &selected).await?;
    let request = BatchRequest {
        kind: "change".into(),
        action: "approve".into(),
        items: selected
            .iter()
            .map(|item| serde_json::to_value(item).expect("selection serializes"))
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
struct ItemView {
    id: String,
    url: String,
    context: Vec<Segment>,
    reason: String,
    outcome: &'static str,
    guidance: &'static str,
}
#[derive(Template)]
#[template(path = "bulk_change_decisions.html")]
struct ReviewPage {
    chrome: PageChrome,
    items: Vec<ItemView>,
    started: bool,
    confirmable: bool,
    confirm_url: String,
    note: Option<String>,
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
    let (rows, note) = if started {
        (None, None)
    } else {
        match reviews(state, actor, &selected).await {
            Ok(rows) => (Some(rows), None),
            Err(error) => (None, Some(error.detail())),
        }
    };
    let mut items = Vec::new();
    for (index, item) in selected.iter().enumerate() {
        let (outcome, guidance) = batches::progress(
            batch.items.get(index).ok_or(ApiError::Internal(
                "Incomplete administrative receipt".into(),
            ))?,
            started,
        )?;
        let context = rows
            .as_ref()
            .and_then(|rows| rows.get(index))
            .map(|row| {
                review_diff::text_segments(
                    &serde_json::to_string_pretty(&intent(row)).expect("intent serializes"),
                )
            })
            .unwrap_or_default();
        items.push(ItemView {
            id: item.id.to_string(),
            url: format!("/changes?pending_id={}", item.id),
            context,
            reason: item.reason.clone(),
            outcome,
            guidance,
        });
    }
    Ok(render(&ReviewPage {
        chrome: PageChrome::build(
            state,
            "Bulk administrative decisions",
            "/changes",
            headers,
            Some(user_display(actor)),
            tenant,
            csrf,
        ),
        items,
        started,
        confirmable: !started && note.is_none(),
        confirm_url: format!("/decisions/bulk/{}/confirm", batch.id),
        note,
    }))
}
fn status_outcome(change: &ChangeRequest) -> DecisionOutcome {
    match change.effective_status(time::OffsetDateTime::now_utc()) {
        ChangeRequestStatus::Pending => DecisionOutcome::ApprovalRecorded,
        ChangeRequestStatus::Approved => DecisionOutcome::ApprovalCompleted,
        ChangeRequestStatus::Executed => DecisionOutcome::ChangeExecuted,
        ChangeRequestStatus::Failed => DecisionOutcome::ChangeFailed,
        ChangeRequestStatus::Executing => DecisionOutcome::Uncertain,
        _ => DecisionOutcome::Changed,
    }
}
pub(crate) async fn confirm(
    state: &Arc<AdminState>,
    actor: &Principal,
    session: Option<&Session>,
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
        let result = async {
            current(state, actor, item).await?;
            crate::change_requests::approve_and_execute_core(state, actor, item.id, session, true)
                .await
        }
        .await;
        let outcome = match result {
            Ok(change) => {
                let outcome = status_outcome(&change);
                match crate::admin_mutation::record_admin_mutation(
                    state,
                    "administrative decisions",
                    "the change request page",
                    actor.tenant.as_str(),
                    Some(actor),
                    "change.bulk_approve",
                    format!("change={} batch={}", item.id, batch.id),
                )
                .await
                {
                    Ok(()) => outcome,
                    Err(error) => batches::outcome(&error),
                }
            }
            Err(error) => {
                // Execution may have committed or recorded a failure before a
                // response error. Reconcile that owning state before labelling it.
                let observed = state
                    .hitl
                    .change_requests
                    .require()?
                    .get(actor.tenant.as_str(), item.id)
                    .await;
                match observed {
                    Ok(Some(change))
                        if digest(&change) == item.digest
                            && matches!(
                                change.status,
                                ChangeRequestStatus::Approved
                                    | ChangeRequestStatus::Executed
                                    | ChangeRequestStatus::Failed
                            ) =>
                    {
                        status_outcome(&change)
                    }
                    _ => match error {
                        ApiError::Forbidden(_) | ApiError::ForbiddenDyn(_) => {
                            DecisionOutcome::RequirementsNotMet
                        }
                        _ => batches::outcome(&error),
                    },
                }
            }
        };
        batches::finish(
            receipts.as_ref(),
            batches::owner(actor),
            batch.id,
            index,
            outcome,
        )
        .await?;
    }
    state
        .hitl
        .decisions_badge_cache
        .lock()
        .await
        .remove(actor.tenant.as_str());
    Ok(())
}
