//! A focused comparison of a quarantined tool and its accepted contract.

use crate::{
    auth::CsrfToken,
    chrome::PageChrome,
    dashboard::{csrf_matches, render, urlencode, user_display},
    error::ApiError,
    state::AdminState,
    tenant_ctx::{self, TenantContext},
    tool_reviews::{self, ToolReviewParams},
};
use askama::Template;
use axum::{
    extract::{Query, State},
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
}
struct PendingRow {
    server: String,
    tool: String,
    url: String,
    trigger: String,
    status: &'static str,
}
struct FieldChange {
    name: String,
    before: String,
    after: String,
}
#[derive(Template)]
#[template(path = "tool_review.html")]
struct ReviewPage {
    chrome: PageChrome,
    rows: Vec<PendingRow>,
    review: Option<waygate_catalog::tool_reviews::ToolReview>,
    changes: Vec<FieldChange>,
    manifest_hash: String,
    observed_at: String,
    trigger: String,
    pending_count: i64,
    next: Option<String>,
    include_decided: bool,
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
    let fields = changes(review)
        .into_iter()
        .map(|change| format!("{} changed", change.name))
        .collect::<Vec<_>>();
    if fields.is_empty() {
        "Definition differs from approval".into()
    } else {
        fields.join("; ")
    }
}

fn changes(review: &waygate_catalog::tool_reviews::ToolReview) -> Vec<FieldChange> {
    if review.observed_contract.is_null() {
        return Vec::new();
    }
    let mut keys = std::collections::BTreeSet::new();
    for value in [&review.approved_contract, &review.observed_contract] {
        if let Some(object) = value.as_object() {
            keys.extend(object.keys().cloned());
        }
    }
    let text = |value: Option<&serde_json::Value>| match value {
        None => "Not present".into(),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(value) => serde_json::to_string_pretty(value).expect("JSON contract serializes"),
    };
    keys.into_iter()
        .filter(|key| review.approved_contract.get(key) != review.observed_contract.get(key))
        .map(|key| FieldChange {
            before: if review.approved_contract.is_null() {
                "Previous definition unavailable".into()
            } else {
                text(review.approved_contract.get(&key))
            },
            after: text(review.observed_contract.get(&key)),
            name: match key.as_str() {
                "description" => "Description",
                "inputSchema" => "Input schema",
                "outputSchema" => "Output schema",
                "annotations" => "Tool annotations",
                "_meta" => "Tool metadata",
                other => other,
            }
            .to_owned(),
        })
        .collect()
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
    let rows = candidates
        .into_iter()
        .map(|r| PendingRow {
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
    let changes = review.as_ref().map(changes).unwrap_or_default();
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
        review,
        changes,
        manifest_hash,
    };
    Ok(render(&page))
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
    let params = ToolReviewParams {
        server: form.server,
        tool: form.tool,
        generation: form.generation,
        observed_hash: form.observed_hash,
        manifest_hash: form.manifest_hash,
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
