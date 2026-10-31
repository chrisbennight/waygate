//! Selected invocation decisions reuse the owning direct-call and Code Mode rules.
use crate::{
    approval_grants::{self, CodeModeApprovalDecision},
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{render, user_display},
    dashboard_bulk_decisions::{self as batches, DecisionOutcome},
    dashboard_invocation_requests as direct,
    error::ApiError,
    review_diff::{self, Segment},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
};
use askama::Template;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{Redirect, Response},
    routing::post,
    Extension, Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;
use waygate_dashboard_stores::decision_batches::{BatchRequest, DecisionBatch};
use waygate_oidc::Principal;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SelectedInvocation {
    Direct { id: Uuid },
    CodeMode { id: Uuid, digest: String },
}
impl SelectedInvocation {
    fn id(&self) -> Uuid {
        match self {
            Self::Direct { id } | Self::CodeMode { id, .. } => *id,
        }
    }
    fn group(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::CodeMode { .. } => "codemode",
        }
    }
}
pub(crate) fn direct_choice(id: Uuid) -> String {
    serde_json::to_string(&SelectedInvocation::Direct { id })
        .expect("invocation identity serializes")
}
pub(crate) fn codemode_choice(id: Uuid, digest: String) -> String {
    serde_json::to_string(&SelectedInvocation::CodeMode { id, digest })
        .expect("invocation identity serializes")
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    request: SelectedInvocation,
    reason: String,
}
fn selections(batch: &DecisionBatch) -> Result<Vec<Selection>, ApiError> {
    if batch.request.kind != "invocation"
        || !matches!(batch.request.action.as_str(), "approve" | "deny")
    {
        return Err(ApiError::BadRequest(
            "Unsupported invocation decision".into(),
        ));
    }
    batch
        .request
        .items
        .iter()
        .cloned()
        .map(|item| {
            serde_json::from_value(item)
                .map_err(|_| ApiError::Internal("Invalid stored invocation selection".into()))
        })
        .collect()
}
pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/decisions/bulk/invocations/review", post(prepare))
}

pub(crate) struct RequestView {
    pub title: String,
    pub url: String,
    pub context: Vec<Segment>,
    bytes: usize,
}
pub(crate) async fn view(
    state: &AdminState,
    actor: &Principal,
    selected: &SelectedInvocation,
    approving: bool,
) -> Result<RequestView, ApiError> {
    let (title, url, context, can_approve) = match selected {
        SelectedInvocation::Direct { id } => {
            let row = direct::store(state)?
                .get(actor.tenant.as_str(), *id)
                .await
                .map_err(direct::request_error)?
                .ok_or(ApiError::NotFound("Pending invocation request"))?;
            if row.status != "pending" {
                return Err(ApiError::Conflict(
                    "The direct request expired or was already decided".into(),
                ));
            }
            let can_approve = row.summary.is_some()
                && (row.principal_issuer != actor.issuer || row.principal_sub != actor.sub);
            let context=serde_json::to_string_pretty(&serde_json::json!({"requester":{"issuer":row.principal_issuer,"subject":row.principal_sub},"behavior":row.behavior_hash,"argument_identity":row.argument_hash,"expires":row.expires_at.to_string(),"review_context":row.summary})).expect("request context serializes");
            (
                format!("{} · {}", row.server, row.tool),
                direct::review_url(*id),
                context,
                can_approve,
            )
        }
        SelectedInvocation::CodeMode { id, digest } => {
            if approving {
                return Err(ApiError::Conflict("Historical Code Mode approval waits cannot continue on this runtime. They may be denied; current Code Mode calls use the ordinary per-call request queue.".into()));
            }
            let execution = state
                .hitl
                .codemode_executions
                .require()?
                .get(actor.tenant.as_str(), *id)
                .await
                .map_err(|_| ApiError::Internal("Code Mode request read failed".into()))?
                .ok_or(ApiError::NotFound("Code Mode request"))?;
            if serde_json::to_vec(&execution.resume_context)
                .map(|value| value.len())
                .unwrap_or(usize::MAX)
                > 2 * 1024 * 1024
            {
                return Err(ApiError::PayloadTooLarge("Complete request context exceeds two MiB. Use the existing individual request API; no review context was truncated.".into()));
            }
            let (request, current) = approval_grants::codemode_request(&execution)?;
            if &current != digest || execution.retention_until <= time::OffsetDateTime::now_utc() {
                return Err(ApiError::Conflict(
                    "The Code Mode request changed or expired".into(),
                ));
            }
            let can_approve = false;
            let context=serde_json::to_string_pretty(&serde_json::json!({"execution":id,"requester":{"issuer":execution.principal_issuer,"subject":execution.principal_sub},"retained_until":execution.retention_until.to_string(),"request_digest":digest,"reviewed_request":request})).expect("request context serializes");
            (
                format!("{} · {}", request.connector, request.operation),
                format!("/invocation-requests?execution={id}"),
                context,
                can_approve,
            )
        }
    };
    if approving && !can_approve {
        return Err(ApiError::Conflict("Complete request context and a different requesting identity are required for approval".into()));
    }
    Ok(RequestView {
        title,
        url,
        bytes: context.len(),
        context: review_diff::text_segments(&context),
    })
}
async fn reviews(
    state: &AdminState,
    actor: &Principal,
    selected: &[Selection],
    approving: bool,
) -> Result<Vec<RequestView>, ApiError> {
    if selected.is_empty() || selected.len() > 50 {
        return Err(ApiError::BadRequest(
            "Select between one and fifty pending invocation requests".into(),
        ));
    }
    let mut ids = HashSet::new();
    let mut bytes = 0;
    let mut rows = Vec::new();
    for item in selected {
        if item.request.group() != selected[0].request.group() || !ids.insert(item.request.id()) {
            return Err(ApiError::BadRequest(
                "Select distinct requests from one invocation group".into(),
            ));
        }
        let row = view(state, actor, &item.request, approving).await?;
        // Bound the complete serialized request before rendering a selection.
        bytes += row.bytes;
        if bytes > 2 * 1024 * 1024 {
            return Err(ApiError::PayloadTooLarge("Complete invocation review exceeds two MiB. Select fewer requests; no context was truncated.".into()));
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
        .filter(|value| matches!(*value, "approve" | "deny"))
        .ok_or(ApiError::BadRequest("Choose approval or denial".into()))?;
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
                "Select no more than fifty requests".into(),
            ));
        }
        selected.push(Selection {
            request: serde_json::from_str(value)
                .map_err(|_| ApiError::BadRequest("Invalid invocation selection".into()))?,
            reason: reason.into(),
        });
    }
    for item in &mut selected {
        if let SelectedInvocation::CodeMode { id, digest } = &mut item.request {
            if digest.is_empty() {
                let execution = state
                    .hitl
                    .codemode_executions
                    .require()?
                    .get(actor.tenant.as_str(), *id)
                    .await
                    .map_err(|_| ApiError::Internal("Code Mode request read failed".into()))?
                    .ok_or(ApiError::NotFound("Code Mode request"))?;
                *digest = approval_grants::codemode_request(&execution)?.1;
            }
        }
    }
    reviews(&state, actor, &selected, action == "approve").await?;
    let request = BatchRequest {
        kind: "invocation".into(),
        action: action.into(),
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
    title: String,
    url: String,
    context: Vec<Segment>,
    reason: String,
    outcome: &'static str,
    guidance: &'static str,
}
#[derive(Template)]
#[template(path = "bulk_invocation_decisions.html")]
struct ReviewPage {
    chrome: PageChrome,
    items: Vec<ItemView>,
    started: bool,
    approving: bool,
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
    let approving = batch.request.action == "approve";
    let (rows, note) = if started {
        (None, None)
    } else {
        match reviews(state, actor, &selected, approving).await {
            Ok(rows) => (Some(rows), None),
            Err(error) => (None, Some(error.detail())),
        }
    };
    let mut items = Vec::new();
    for (index, item) in selected.iter().enumerate() {
        let (outcome, guidance) = batches::progress(
            batch
                .items
                .get(index)
                .ok_or(ApiError::Internal("Incomplete invocation receipt".into()))?,
            started,
        )?;
        let current = rows.as_ref().and_then(|rows| rows.get(index));
        items.push(ItemView {
            title: current
                .map(|row| row.title.clone())
                .unwrap_or_else(|| item.request.id().to_string()),
            url: current
                .map(|row| row.url.clone())
                .unwrap_or_else(|| match item.request {
                    SelectedInvocation::Direct { id } => direct::review_url(id),
                    SelectedInvocation::CodeMode { id, .. } => {
                        format!("/invocation-requests?execution={id}")
                    }
                }),
            context: current.map(|row| row.context.clone()).unwrap_or_default(),
            reason: item.reason.clone(),
            outcome,
            guidance,
        });
    }
    Ok(render(&ReviewPage {
        chrome: PageChrome::build(
            state,
            "Bulk invocation decisions",
            "/invocation-requests",
            headers,
            Some(user_display(actor)),
            tenant,
            csrf,
        ),
        items,
        started,
        approving,
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
    let approving = batch.request.action == "approve";
    for (index, item) in selected.iter().enumerate() {
        batches::begin(receipts.as_ref(), batches::owner(actor), batch.id, index).await?;
        let result = async {
            view(state, actor, &item.request, approving).await?;
            match &item.request {
                SelectedInvocation::Direct { id } => {
                    direct::decide_core(state, actor, *id, approving, &item.reason, Some(batch.id))
                        .await?;
                }
                SelectedInvocation::CodeMode { id, digest } => {
                    let body = CodeModeApprovalDecision {
                        reason: Some(item.reason.clone()),
                        request_digest: Some(digest.clone()),
                        ..Default::default()
                    };
                    approval_grants::deny_codemode_request(
                        State(state.clone()),
                        Some(Extension(actor.clone())),
                        Path(*id),
                        Json(body),
                    )
                    .await?;
                    crate::admin_mutation::record_admin_mutation(
                        state,
                        "Code Mode invocation requests",
                        "the pending invocation request page",
                        actor.tenant.as_str(),
                        Some(actor),
                        if approving {
                            "invocation.approve"
                        } else {
                            "invocation.deny"
                        },
                        format!("execution={id} batch={}", batch.id),
                    )
                    .await?;
                }
            }
            Ok::<_, ApiError>(())
        }
        .await;
        let observed = match result {
            Ok(()) => {
                if approving {
                    DecisionOutcome::GrantIssued
                } else {
                    DecisionOutcome::InvocationDenied
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
    state
        .hitl
        .decisions_badge_cache
        .lock()
        .await
        .remove(actor.tenant.as_str());
    Ok(())
}
