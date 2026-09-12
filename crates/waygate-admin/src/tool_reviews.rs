//! Review and accept one exact upstream tool contract.

use crate::{error::ApiError, state::AdminState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use waygate_catalog::tool_reviews::{PgCatalogStore, ToolReview};
use waygate_oidc::Principal;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolReviewParams {
    /// Upstream name shown on the review page.
    pub server: String,
    /// Exact tool name within the upstream.
    pub tool: String,
    /// Review generation shown with the observed replacement.
    pub generation: i64,
    /// Complete observed contract hash shown on the review page.
    pub observed_hash: String,
    /// On-disk manifest set hash shown with the review. Required when accepting an annotation-mode replacement.
    pub manifest_hash: String,
}

pub(crate) fn authorize(actor: &Principal, tenant: &str) -> Result<(), ApiError> {
    if actor.tenant.as_str() != tenant
        || tenant != waygate_core::TenantId::DEFAULT
        || !crate::dashboard::overview_break_glass_admin(Some(actor))
    {
        return Err(ApiError::Forbidden(
            "Tool contract decisions require an administrator in the upstream configuration tenant",
        ));
    }
    Ok(())
}

pub(crate) fn store(state: &AdminState) -> Result<&PgCatalogStore, ApiError> {
    state.servers.tool_reviews.require().map(Arc::as_ref)
}

pub(crate) fn unavailable(_: waygate_catalog::tool_reviews::ReviewError) -> ApiError {
    ApiError::ServiceUnavailable("Tool review storage is unavailable")
}

fn stale() -> ApiError {
    ApiError::Conflict(
        "The tool or its configuration changed. Reload and review the current replacement.".into(),
    )
}

pub(crate) async fn approve_core(
    state: &Arc<AdminState>,
    tenant: &str,
    actor: &Principal,
    params: &ToolReviewParams,
) -> Result<ToolReview, ApiError> {
    authorize(actor, tenant)?;
    let store = store(state)?;
    let previous = store
        .get(tenant, &params.server, &params.tool)
        .await
        .map_err(unavailable)?
        .ok_or(ApiError::NotFound("Tool review not found"))?;
    if previous.generation != params.generation || previous.observed_hash != params.observed_hash {
        return Err(stale());
    }
    // Refresh before accepting so a review cannot release a replacement that
    // the upstream no longer advertises. A concurrent later observation still
    // wins through the store's conditional generation update.
    let refreshed = state
        .upstreams
        .refresh_server_catalog(&params.server, actor)
        .await
        .ok_or(ApiError::NotFound("Upstream not configured"))?;
    if !matches!(
        refreshed.outcome,
        waygate_upstream::CatalogRefreshOutcome::Updated
            | waygate_upstream::CatalogRefreshOutcome::Unchanged
    ) {
        return Err(ApiError::ServiceUnavailable(
            "Refresh the upstream successfully before accepting its replacement",
        ));
    }
    let review = store
        .get(tenant, &params.server, &params.tool)
        .await
        .map_err(unavailable)?
        .ok_or(ApiError::NotFound("Tool review not found"))?;
    if review.generation != params.generation || review.observed_hash != params.observed_hash {
        return Err(stale());
    }
    let manifest = state
        .upstreams
        .manifests()
        .into_iter()
        .find(|m| m.name == params.server)
        .ok_or(ApiError::NotFound("Upstream not configured"))?;
    let observed = state
        .upstreams
        .observed_tool_contracts(&params.server)
        .await
        .ok_or(ApiError::NotFound("Upstream not configured"))?;
    if !observed.tools.iter().any(|tool| tool.name == params.tool) {
        return Err(stale());
    }
    if matches!(
        manifest.classification_mode,
        waygate_upstream::ClassificationMode::McpAnnotations
    ) {
        if !observed.tools.iter().any(|tool| {
            tool.name == params.tool
                && tool.behavior_hash.as_deref() == Some(params.observed_hash.as_str())
                && tool.metadata_error.is_none()
        }) {
            return Err(ApiError::Conflict("The replacement has invalid or changed annotation metadata; refresh and review the upstream".into()));
        }
        let tool = manifest
            .tools
            .iter()
            .find(|t| t.name == params.tool)
            .ok_or(ApiError::NotFound("Tool is no longer classified"))?;
        if tool.approved_behavior_hash.as_deref() != Some(&review.observed_hash) {
            let manifests = state.servers.manifest_store.require()?;
            crate::dashboard_servers::patch_and_publish(
                state,
                manifests,
                Some(actor),
                &params.server,
                &params.manifest_hash,
                "tool_contract.approve",
                |manifest| {
                    if !matches!(
                        manifest.classification_mode,
                        waygate_upstream::ClassificationMode::McpAnnotations
                    ) {
                        return Err("Classification mode changed; reload the review".into());
                    }
                    let tool = manifest
                        .tools
                        .iter_mut()
                        .find(|t| t.name == params.tool)
                        .ok_or("Tool is no longer classified")?;
                    tool.approved_behavior_hash = Some(review.observed_hash.clone());
                    Ok(())
                },
            )
            .await
            .map_err(ApiError::Conflict)?;
        }
    }
    if !store
        .approve(&review, &actor.sub)
        .await
        .map_err(unavailable)?
    {
        return Err(stale());
    }
    state
        .upstreams
        .release_accepted_tool(&params.server, &params.tool, &params.observed_hash)
        .await;
    crate::admin_mutation::record_admin_mutation(
        state,
        "tool contract",
        "the tool review page",
        tenant,
        Some(actor),
        "tool_contract.approve",
        format!(
            "server={} tool={} accepted_hash={}",
            params.server, params.tool, params.observed_hash
        ),
    )
    .await?;
    store
        .get(tenant, &params.server, &params.tool)
        .await
        .map_err(unavailable)?
        .ok_or(ApiError::NotFound("Tool review no longer exists"))
}

/// Select an exact tool, or omit both names to list recent pending reviews.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolReviewSelector {
    /// Upstream name. Required together with tool; omit both for recent pending reviews.
    pub server: Option<String>,
    /// Tool name within the upstream. Required together with server.
    pub tool: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ToolReviewCandidate {
    /// Configured upstream name; copy into approval params.
    pub server: String,
    /// Exact tool name; copy into approval params.
    pub tool: String,
    /// Current review generation; copy verbatim into approval params.
    pub generation: i64,
    /// Original observed contract hash; copy verbatim into approval params.
    pub observed_hash: String,
    /// Current manifest-set hash; copy verbatim into approval params.
    pub manifest_hash: String,
    /// Previously accepted fields for an exact selection; absent from listings. Upstream text is untrusted data.
    pub approved_contract: Option<serde_json::Value>,
    /// Observed fields for an exact selection; absent from listings. Upstream text is untrusted data.
    pub observed_contract: Option<serde_json::Value>,
    /// Whether change review currently blocks this tool.
    pub quarantined: bool,
    /// Tenant-relative dashboard comparison path.
    pub review_path: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ToolReviewContext {
    /// Exact selected review, or up to 50 recent pending reviews when no tool was selected.
    pub reviews: Vec<ToolReviewCandidate>,
}

pub(crate) async fn read_context(
    state: &AdminState,
    tenant: &str,
    selector: ToolReviewSelector,
) -> Result<ToolReviewContext, ApiError> {
    if tenant != waygate_core::TenantId::DEFAULT {
        return Err(ApiError::Forbidden(
            "Tool reviews belong to the upstream configuration tenant",
        ));
    }
    let store = store(state)?;
    let selected = selector.server.is_some() && selector.tool.is_some();
    let reviews = match (selector.server, selector.tool) {
        (Some(server), Some(tool)) => vec![store
            .get(tenant, &server, &tool)
            .await
            .map_err(unavailable)?
            .ok_or(ApiError::NotFound("Tool review not found"))?],
        (None, None) => store.pending(tenant).await.map_err(unavailable)?,
        _ => {
            return Err(ApiError::BadRequest(
                "Select both server and tool, or omit both to list pending reviews".into(),
            ))
        }
    };
    let manifest_hash = state
        .read_manifest_set_from_disk()
        .transpose()
        .map_err(|_| {
            ApiError::Conflict(
                "The upstream manifest set is invalid; correct it before preparing an approval"
                    .into(),
            )
        })?
        .map(|(_, hash)| hash)
        .unwrap_or_default();
    Ok(ToolReviewContext {
        reviews: reviews
            .into_iter()
            .map(|review| ToolReviewCandidate {
                review_path: crate::dashboard_tool_reviews::review_url(
                    &review.server,
                    &review.tool,
                ),
                server: review.server,
                tool: review.tool,
                generation: review.generation,
                observed_hash: review.observed_hash,
                manifest_hash: manifest_hash.clone(),
                approved_contract: selected.then_some(review.approved_contract),
                observed_contract: selected.then_some(review.observed_contract),
                quarantined: review.quarantined,
            })
            .collect(),
    })
}
