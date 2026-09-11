//! Operator decisions for exact skill content. Git remains the authoring source.

use schemars::JsonSchema;
use serde::Deserialize;
use waygate_oidc::Principal;
use waygate_skills::review::{
    DecisionActor, ReviewCandidate, ReviewDecision, ReviewError, SkillReview,
};

use crate::{error::ApiError, state::AdminState};

/// New tenants can review the loaded catalog even when periodic refresh is off.
/// Only missing pending candidates are inserted; existing decisions are untouched.
pub(crate) async fn seed_tenant(
    state: &AdminState,
    tenant: &str,
) -> crate::tenants::SideEffectStatus {
    use crate::tenants::SideEffectStatus;
    let Some(snapshot) = state
        .hitl
        .skills
        .get()
        .and_then(|catalog| catalog.current())
    else {
        return SideEffectStatus {
            status: "skipped",
            detail: Some(
                "No skill catalog is loaded; source acquisition will create pending reviews".into(),
            ),
        };
    };
    let Some(reviewed) = state.hitl.reviewed_skills.get() else {
        return SideEffectStatus {
            status: "skipped",
            detail: Some("Skill review storage is not configured".into()),
        };
    };
    let result = async {
        let store = reviewed.store().map_err(|_| {
            ApiError::ServiceUnavailable(state.hitl.reviewed_skills.unavailable_msg())
        })?;
        for skill in snapshot.skills() {
            let candidate = ReviewCandidate::from_snapshot(&snapshot, &skill.uri)
                .expect("verified skill inventory");
            match store.observe(tenant, None, &candidate).await {
                Ok(_) | Err(ReviewError::Stale) => {}
                Err(error) => return Err(review_error(error)),
            }
        }
        Ok::<_, ApiError>(())
    }
    .await;
    state.hitl.decisions_badge_cache.lock().await.remove(tenant);
    match result {
        Ok(()) => SideEffectStatus {
            status: "seeded",
            detail: None,
        },
        Err(error) => {
            tracing::warn!(tenant, error = %error.detail(), "tenant onboarding: skill review seed failed");
            SideEffectStatus { status: "failed", detail: Some("Pending skill reviews could not be created; retry source refresh before using skills".into()) }
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillDecisionParams {
    /// Exact SKILL.md URI shown on the skill review page.
    pub skill_uri: String,
    /// Review generation displayed with the candidate. A changed review requires reloading.
    pub generation: i64,
    /// Complete content digest displayed with the candidate, including supporting files.
    pub content_digest: String,
    /// Operator explanation retained with the decision.
    #[schemars(length(min = 1, max = 4096))]
    pub reason: String,
}

pub(crate) fn review_error(error: ReviewError) -> ApiError {
    match error {
        ReviewError::Stale => ApiError::Conflict(
            "The skill review changed. Reload and review the current candidate.".into(),
        ),
        ReviewError::InvalidAttribution => ApiError::BadRequest(
            "A non-empty operator reason of at most 4096 bytes is required.".into(),
        ),
        ReviewError::Store(_) | ReviewError::Encoding(_) => {
            ApiError::ServiceUnavailable("Skill review storage is unavailable")
        }
    }
}

pub(crate) async fn current_review(
    state: &AdminState,
    tenant: &str,
    uri: &str,
) -> Result<SkillReview, ApiError> {
    let catalog = state.hitl.skills.require()?;
    let snapshot = catalog.current().ok_or(ApiError::ServiceUnavailable(
        state.hitl.skills.unavailable_msg(),
    ))?;
    let candidate = ReviewCandidate::from_snapshot(&snapshot, uri)
        .ok_or(ApiError::NotFound("Skill is not in the configured source"))?;
    state
        .hitl
        .reviewed_skills
        .require()?
        .store()
        .map_err(|_| ApiError::ServiceUnavailable(state.hitl.reviewed_skills.unavailable_msg()))?
        .get(tenant, &candidate.source_key(), uri)
        .await
        .map_err(review_error)?
        .ok_or(ApiError::ServiceUnavailable(
            "The skill has not yet been observed for this tenant",
        ))
}

pub(crate) async fn decide_core(
    state: &AdminState,
    tenant: &str,
    actor: &Principal,
    params: &SkillDecisionParams,
    decision: ReviewDecision,
) -> Result<SkillReview, ApiError> {
    if actor.tenant.as_str() != tenant || !crate::dashboard::overview_break_glass_admin(Some(actor))
    {
        return Err(ApiError::Forbidden(
            "Skill decisions require an administrator in this tenant",
        ));
    }
    let review = current_review(state, tenant, &params.skill_uri).await?;
    if review.generation != params.generation
        || review.candidate.content_digest() != params.content_digest
    {
        return Err(review_error(ReviewError::Stale));
    }
    let reviewed = state.hitl.reviewed_skills.require()?;
    if decision == ReviewDecision::Approve {
        reviewed
            .review_snapshot(&review.candidate)
            .await
            .map_err(|_| {
                ApiError::ServiceUnavailable(
                    "The exact candidate revision is unavailable; approval was not recorded",
                )
            })?;
    }
    let decided = reviewed
        .store()
        .map_err(|_| ApiError::ServiceUnavailable(state.hitl.reviewed_skills.unavailable_msg()))?
        .decide(
            &review,
            decision,
            DecisionActor {
                subject: &actor.sub,
                issuer: &actor.issuer,
                reason: &params.reason,
            },
        )
        .await
        .map_err(review_error)?;
    state.hitl.decisions_badge_cache.lock().await.remove(tenant);
    state.upstreams.tool_catalog_epoch().mark_changed();
    let action = match decision {
        ReviewDecision::Approve => "skill.approve",
        ReviewDecision::Reject => "skill.reject",
        ReviewDecision::Quarantine => "skill.quarantine",
    };
    crate::admin_mutation::record_admin_mutation(
        state,
        "skill reviews",
        "the Skills review page",
        tenant,
        Some(actor),
        action,
        format!(
            "skill={} content={} generation={}",
            decided.skill_uri,
            decided.candidate.content_digest(),
            decided.generation
        ),
    )
    .await?;
    Ok(decided)
}
