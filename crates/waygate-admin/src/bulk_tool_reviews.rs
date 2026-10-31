//! Coordinated acceptance of explicitly reviewed tool replacements.

use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

use waygate_catalog::tool_reviews::ToolReview;
use waygate_oidc::Principal;
use waygate_upstream::ClassificationMode;

use crate::{
    error::ApiError,
    state::AdminState,
    tool_reviews::{self, PreparedToolApproval, ToolReviewParams},
};

pub(crate) const MAX_REVIEW_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn check_review_budget(reviews: &[ToolReview]) -> Result<(), ApiError> {
    let bytes: usize = reviews
        .iter()
        .map(|r| r.approved_contract.to_string().len() + r.observed_contract.to_string().len())
        .sum();
    if bytes > MAX_REVIEW_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "The complete review exceeds two MiB. Select fewer tools; no decision details were truncated.".into(),
        ));
    }
    Ok(())
}

fn annotation(prepared: &PreparedToolApproval) -> bool {
    matches!(
        prepared.manifest.classification_mode,
        ClassificationMode::McpAnnotations
    )
}

async fn publish_selected(
    state: &Arc<AdminState>,
    actor: &Principal,
    candidates: &[(usize, PreparedToolApproval)],
    params: &[ToolReviewParams],
    manifest_guard: &tokio::sync::MutexGuard<'_, ()>,
) -> Result<Option<String>, ApiError> {
    let selected: Vec<_> = candidates.iter().filter(|(_, p)| annotation(p)).collect();
    if selected.is_empty() {
        return Ok(None);
    }
    let (mut set, base) = state
        .read_manifest_set_from_disk()
        .ok_or(ApiError::ServiceUnavailable(
            crate::manifest_bundles::MANIFEST_SERVERS_DIR_UNAVAILABLE,
        ))?
        .map_err(|_| ApiError::Internal("Could not read the live server configuration".into()))?;
    let mut changed = false;
    for (index, prepared) in selected {
        let target = &params[*index];
        if target.manifest_hash != base {
            return Err(ApiError::Conflict(
                "Server configuration changed. Review the selection again.".into(),
            ));
        }
        let manifest = set
            .get_mut(&target.server)
            .ok_or(ApiError::NotFound("Server configuration no longer exists"))?;
        if !matches!(
            manifest.classification_mode,
            ClassificationMode::McpAnnotations
        ) {
            return Err(ApiError::Conflict(
                "Tool classification mode changed. Review again.".into(),
            ));
        }
        if let Some(tool) = manifest
            .tools
            .iter_mut()
            .find(|tool| tool.name == target.tool)
        {
            if prepared.initial_classification.is_some() {
                return Err(ApiError::Conflict(
                    "Initial classification changed. Review again.".into(),
                ));
            }
            if tool.approved_behavior_hash.as_deref() != Some(target.observed_hash.as_str()) {
                tool.approved_behavior_hash = Some(target.observed_hash.clone());
                changed = true;
            }
        } else {
            let classification =
                prepared
                    .initial_classification
                    .clone()
                    .ok_or(ApiError::Conflict(
                        "Tool classification changed. Review again.".into(),
                    ))?;
            manifest.tools.push(classification);
            changed = true;
        }
    }
    if changed {
        let content = waygate_upstream::serialize_manifest_set(&set).map_err(|_| {
            ApiError::Internal("Could not serialize reviewed tool approvals".into())
        })?;
        return crate::manifest_bundles::publish_tool_approval_set(
            state,
            actor,
            &content,
            &base,
            manifest_guard,
        )
        .await
        .map(Some);
    }
    Ok(None)
}

pub(crate) async fn approve(
    state: &Arc<AdminState>,
    actor: &Principal,
    params: &[ToolReviewParams],
    batch_id: uuid::Uuid,
) -> Result<Vec<Result<ToolReview, ApiError>>, ApiError> {
    let tenant = actor.tenant.as_str();
    tool_reviews::authorize(actor, tenant)?;
    if params.is_empty() || params.len() > waygate_dashboard_stores::decision_batches::MAX_ITEMS {
        return Err(ApiError::BadRequest(
            "Select between one and fifty tool decisions".into(),
        ));
    }
    let mut identities = HashSet::new();
    if params
        .iter()
        .any(|p| !identities.insert((&p.server, &p.tool)))
    {
        return Err(ApiError::BadRequest("Select each tool only once".into()));
    }
    let mut results: Vec<Option<Result<ToolReview, ApiError>>> =
        (0..params.len()).map(|_| None).collect();
    let mut unavailable = BTreeSet::new();
    let servers: BTreeSet<_> = params.iter().map(|p| p.server.as_str()).collect();
    for server in servers {
        let refreshed = state.upstreams.refresh_server_catalog(server, actor).await;
        if !refreshed.is_some_and(|r| {
            matches!(
                r.outcome,
                waygate_upstream::CatalogRefreshOutcome::Updated
                    | waygate_upstream::CatalogRefreshOutcome::Unchanged
            )
        }) {
            unavailable.insert(server);
        }
    }
    let mut candidates = Vec::new();
    for (index, target) in params.iter().enumerate() {
        if unavailable.contains(target.server.as_str()) {
            results[index] = Some(Err(ApiError::ServiceUnavailable(
                "Refresh the upstream before accepting its replacement",
            )));
            continue;
        }
        match tool_reviews::prepare_approval(state, tenant, actor, target, false).await {
            Ok(prepared) => candidates.push((index, prepared)),
            Err(error) => results[index] = Some(Err(error)),
        }
    }
    check_review_budget(
        &candidates
            .iter()
            .map(|(_, p)| p.review.clone())
            .collect::<Vec<_>>(),
    )?;
    let reviews: Vec<_> = candidates.iter().map(|(_, p)| p.review.clone()).collect();
    // Dashboard reload takes the manifest mutex before observing catalog
    // reviews. Preserve that order and finish all upstream work before locking.
    let manifest_guard = state.servers.manifest_write_lock.lock().await;
    let mut locked = tool_reviews::store(state)?
        .lock_pending_approvals(&reviews)
        .await
        .map_err(tool_reviews::unavailable)?;
    candidates.retain(|(index, prepared)| {
        if locked.contains(&prepared.review) {
            return true;
        }
        results[*index] = Some(Err(ApiError::Conflict(
            "The selected tool was already decided or changed. Review again.".into(),
        )));
        false
    });
    let publication = publish_selected(state, actor, &candidates, params, &manifest_guard).await;
    let mut accepted = Vec::new();
    for (index, prepared) in candidates {
        if annotation(&prepared) {
            if let Err(ref error) = publication {
                results[index] = Some(Err(match error {
                    ApiError::Conflict(_) | ApiError::NotFound(_) => ApiError::Conflict(
                        "Shared server configuration changed. Review again.".into(),
                    ),
                    ApiError::ServiceUnavailable(message) => ApiError::ServiceUnavailable(message),
                    _ => ApiError::Internal(
                        "Manifest publication outcome needs reconciliation".into(),
                    ),
                }));
                continue;
            }
        }
        if locked
            .approve(&prepared.review, &actor.sub)
            .await
            .map_err(tool_reviews::unavailable)?
        {
            accepted.push((index, prepared));
        } else {
            results[index] = Some(Err(ApiError::Conflict(
                "The tool review changed before acceptance".into(),
            )));
        }
    }
    locked.commit().await.map_err(tool_reviews::unavailable)?;
    drop(manifest_guard);
    if let Ok(Some(hash)) = publication {
        let _ = state
            .servers
            .manifest_store
            .require()?
            .notify_reload(&hash)
            .await;
    }
    for (index, prepared) in accepted {
        results[index] = Some(
            tool_reviews::record_acceptance(state, actor, &params[index], Some(batch_id))
                .await
                .map(|()| prepared.review),
        );
    }
    Ok(results
        .into_iter()
        .map(|result| result.expect("every selected tool receives an outcome"))
        .collect())
}
