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
}
struct PendingRow {
    server: String,
    tool: String,
    url: String,
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
            before: text(review.approved_contract.get(&key)),
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
    let rows = store
        .pending(actor.tenant.as_str())
        .await
        .map_err(tool_reviews::unavailable)?
        .into_iter()
        .map(|r| PendingRow {
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
    match tool_reviews::approve_core(&state, actor.tenant.as_str(), &actor, &params).await {
        Ok(_) => Redirect::to(&tenant_ctx::nav_url(
            tenant.as_ref().map(|Extension(t)| t),
            &review_url(&params.server, &params.tool),
        ))
        .into_response(),
        Err(error) => error.into_response(),
    }
}
