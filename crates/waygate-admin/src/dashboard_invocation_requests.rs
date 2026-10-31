//! Administrator review of retained direct-call requests. Approval issues a
//! single-use grant; the requester still retries through the invocation service.

use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{render, user_display},
    dashboard_bulk_decisions as batches,
    error::ApiError,
    review_diff::{self, Segment},
    state::AdminState,
    tenant_ctx::{self, TenantContext},
};
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;
use waygate_catalog::pending_invocations::{
    InvocationDecision, InvocationRequest, RequestError, SharedPendingInvocationStore,
};
use waygate_oidc::Principal;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/invocation-requests", get(page))
        .route("/invocation-requests/{id}/decide", post(decide))
}
pub(crate) fn store(state: &AdminState) -> Result<SharedPendingInvocationStore, ApiError> {
    state
        .servers
        .catalog
        .require()?
        .pending_invocations()
        .ok_or(ApiError::ServiceUnavailable(
            state.servers.catalog.unavailable_msg(),
        ))
}
pub(crate) fn request_error(error: RequestError) -> ApiError {
    match error {
        RequestError::Changed=>ApiError::Conflict("The invocation request expired, changed, or was already decided. Review current requests again.".into()),
        RequestError::SelfApproval=>ApiError::Conflict("An administrator cannot approve an invocation requested by their own identity.".into()),
        RequestError::Invalid(message)=>ApiError::BadRequest(message.into()),
        RequestError::Capacity=>ApiError::Conflict("The pending invocation queue is full. Review existing requests or wait for retained requests to expire.".into()),
        RequestError::Database(_)=>ApiError::Internal("Pending invocation request storage failed".into()),
    }
}
pub(crate) fn review_url(id: Uuid) -> String {
    format!("/invocation-requests?request={id}")
}

pub(crate) async fn decide_core(
    state: &AdminState,
    actor: &Principal,
    id: Uuid,
    approve: bool,
    reason: &str,
    batch: Option<Uuid>,
) -> Result<InvocationRequest, ApiError> {
    if !crate::dashboard::overview_break_glass_admin(Some(actor)) {
        return Err(ApiError::Forbidden(
            "Invocation decisions require an administrator session",
        ));
    }
    let request = store(state)?
        .decide(InvocationDecision {
            tenant: actor.tenant.as_str(),
            id,
            approver_issuer: &actor.issuer,
            approver_sub: &actor.sub,
            reason,
            approve,
        })
        .await
        .map_err(request_error)?;
    state
        .hitl
        .decisions_badge_cache
        .lock()
        .await
        .remove(actor.tenant.as_str());
    crate::admin_mutation::record_admin_mutation(
        state,
        "invocation requests",
        "the pending invocation request page",
        actor.tenant.as_str(),
        Some(actor),
        if approve {
            "invocation.approve"
        } else {
            "invocation.deny"
        },
        format!(
            "request={}{}",
            id,
            batch.map(|id| format!(" batch={id}")).unwrap_or_default()
        ),
    )
    .await?;
    Ok(request)
}

struct RequestRow {
    choice: String,
    decide_url: String,
    url: String,
    server: String,
    tool: String,
    requester: String,
    issuer: String,
    status: String,
    expires: String,
    behavior: String,
    arguments: String,
    description: Option<Vec<Segment>>,
    fields: Vec<Vec<Segment>>,
    context_available: bool,
    can_approve: bool,
    can_deny: bool,
    grant: Option<String>,
}
#[derive(Template)]
#[template(path = "invocation_requests.html")]
struct RequestsPage {
    chrome: PageChrome,
    rows: Vec<RequestRow>,
    detail: bool,
    bulk_available: bool,
    codemode: Vec<CodeModeRow>,
    note: Option<String>,
}
#[derive(Default, Deserialize)]
struct RequestQuery {
    request: Option<Uuid>,
    execution: Option<Uuid>,
    note: Option<String>,
}
struct CodeModeRow {
    choice: String,
    title: String,
    url: String,
    context: Vec<Segment>,
    can_approve: bool,
}

async fn page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    headers: HeaderMap,
    Query(query): Query<RequestQuery>,
) -> Result<Response, ApiError> {
    let actor = batches::authorize(&user, &tenant)?;
    let mut note = query.note;
    let direct_rows = if query.execution.is_some() {
        Vec::new()
    } else if let Ok(requests) = store(&state) {
        match query.request {
            Some(id) => vec![requests
                .get(actor.tenant.as_str(), id)
                .await
                .map_err(request_error)?
                .ok_or(ApiError::NotFound(
                    "Invocation request expired or is unavailable",
                ))?],
            None => requests
                .pending(actor.tenant.as_str())
                .await
                .map_err(request_error)?,
        }
    } else {
        note = Some("Direct invocation request storage is unavailable.".into());
        Vec::new()
    };
    let rows = direct_rows
        .into_iter()
        .map(|row| {
            let can_deny = row.status == "pending";
            let can_approve = can_deny
                && row.summary.is_some()
                && (row.principal_issuer != actor.issuer || row.principal_sub != actor.sub);
            let context_available = row.summary.is_some();
            let (description, fields) = row
                .summary
                .map(|summary| (summary.description, summary.affected_fields))
                .unwrap_or_default();
            RequestRow {
                choice: crate::dashboard_bulk_invocations::direct_choice(row.id),
                decide_url: format!("/invocation-requests/{}/decide", row.id),
                url: review_url(row.id),
                server: row.server,
                tool: row.tool,
                requester: row.principal_sub,
                issuer: row.principal_issuer,
                status: row.status,
                expires: waygate_core::fmt::format_ts_abs(row.expires_at),
                behavior: row.behavior_hash,
                arguments: row.argument_hash,
                description: description.map(|text| review_diff::text_segments(&text)),
                fields: fields
                    .into_iter()
                    .map(|text| review_diff::text_segments(&text))
                    .collect(),
                context_available,
                can_approve,
                can_deny,
                grant: row.grant_id.map(|id| id.to_string()),
            }
        })
        .collect();
    let mut codemode = Vec::new();
    if query.request.is_none() {
        if let Some(executions) = state.hitl.codemode_executions.get() {
            if let Some(id) = query.execution {
                match executions.get(actor.tenant.as_str(),id).await {
                    Ok(Some(execution))=>match crate::approval_grants::codemode_request(&execution) {
                        Ok((_,digest))=>{
                            let selected=crate::dashboard_bulk_invocations::SelectedInvocation::CodeMode{id,digest:digest.clone()};
                            match crate::dashboard_bulk_invocations::view(&state,actor,&selected,false).await {
                                Ok(row)=>codemode.push(CodeModeRow{choice:crate::dashboard_bulk_invocations::codemode_choice(id,digest),title:row.title,url:row.url,context:row.context,can_approve:false}),
                                Err(error)=>note=Some(error.detail()),
                            }
                        },
                        Err(_)=>note=Some(format!("Code Mode execution {id} is no longer awaiting a decision. Current state: {:?}. Inspect its execution history before further action.",execution.status)),
                    },
                    Ok(None)=>note=Some("Code Mode request is unavailable or expired.".into()),
                    Err(_)=>note=Some("Code Mode request could not be loaded.".into()),
                }
            } else {
                match executions.list_waiting_approval_summaries(actor.tenant.as_str(),50).await {
                    Ok(rows)=>for row in rows {codemode.push(CodeModeRow{choice:crate::dashboard_bulk_invocations::codemode_choice(row.id,String::new()),title:format!("{} · execution {}",row.principal_sub,row.id),url:format!("/invocation-requests?execution={}",row.id),context:Vec::new(),can_approve:false});},
                    Err(_)=>note=Some("Historical Code Mode requests could not be loaded. The queue may be incomplete.".into()),
                }
            }
        }
    }
    Ok(render(&RequestsPage {
        chrome: PageChrome::build(
            &state,
            "Pending invocation requests",
            "/invocation-requests",
            &headers,
            Some(user_display(actor)),
            tenant.map(|Extension(t)| t),
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        rows,
        detail: query.request.is_some(),
        bulk_available: state.hitl.decision_batches.get().is_some(),
        codemode,
        note,
    }))
}

#[derive(Deserialize)]
struct DecisionForm {
    csrf: String,
    reason: String,
    action: String,
    #[serde(default)]
    reviewed: bool,
}
async fn decide(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant: Option<Extension<TenantContext>>,
    Path(params): Path<HashMap<String, String>>,
    Form(form): Form<DecisionForm>,
) -> Result<Redirect, ApiError> {
    let actor = batches::authorize(&user, &tenant)?;
    batches::csrf(&csrf, &form.csrf)?;
    let id = params
        .get("id")
        .and_then(|id| id.parse().ok())
        .ok_or(ApiError::NotFound("Invocation request not found"))?;
    let approve = match form.action.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return Err(ApiError::BadRequest(
                "Choose Approve request or Deny request".into(),
            ))
        }
    };
    if !form.reviewed {
        return Err(ApiError::BadRequest(
            "Confirm that you reviewed the exact requested effects".into(),
        ));
    }
    let note = match decide_core(&state, actor, id, approve, form.reason.trim(), None).await {
        Ok(_) => {
            if approve {
                "The request was approved. The requester may retry this exact invocation before its grant expires.".into()
            } else {
                "The request was denied. No invocation permission was issued.".into()
            }
        }
        Err(error) => error.detail(),
    };
    Ok(Redirect::to(&tenant_ctx::nav_url(
        tenant.as_ref().map(|Extension(t)| t),
        &format!(
            "{}&note={}",
            review_url(id),
            crate::dashboard::urlencode(&note)
        ),
    )))
}
