//! Explicit distribution approvals for tests of other policy boundaries.
//! Persistence and decision transitions are exercised against PostgreSQL.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};
use waygate_skills::{
    distribution::ReviewedSkillCatalog,
    review::{
        CandidateStatus, DecisionActor, ReviewCandidate, ReviewDecision, ReviewError,
        SkillDecisionRecord, SkillReview, SkillReviewStore,
    },
    ReloadableSkillCatalog, SkillCatalogSnapshot, SkillCatalogSource, SkillSourceError,
};

#[derive(Default)]
pub struct SkillReviewFixture {
    rows: RwLock<BTreeMap<(String, String, String), SkillReview>>,
}

impl SkillReviewFixture {
    pub fn approve(&self, tenant: &str, snapshot: &SkillCatalogSnapshot) {
        let mut rows = self.rows.write().unwrap();
        for skill in snapshot.skills() {
            let candidate = ReviewCandidate::from_snapshot(snapshot, &skill.uri).unwrap();
            let key = (tenant.to_owned(), candidate.source_key(), skill.uri.clone());
            rows.insert(
                key.clone(),
                SkillReview {
                    tenant_id: key.0,
                    source_key: key.1,
                    skill_uri: key.2,
                    generation: 1,
                    serving: Some(candidate.clone()),
                    candidate,
                    candidate_status: CandidateStatus::Approved,
                    quarantined: false,
                    updated_at: time::OffsetDateTime::UNIX_EPOCH,
                },
            );
        }
    }

    pub fn quarantine(&self, tenant: &str, source_key: &str, uri: &str) {
        if let Some(row) =
            self.rows
                .write()
                .unwrap()
                .get_mut(&(tenant.into(), source_key.into(), uri.into()))
        {
            row.quarantined = true;
        }
    }
}

#[async_trait::async_trait]
impl SkillReviewStore for SkillReviewFixture {
    async fn get(
        &self,
        tenant: &str,
        source_key: &str,
        uri: &str,
    ) -> Result<Option<SkillReview>, ReviewError> {
        Ok(self
            .rows
            .read()
            .unwrap()
            .get(&(tenant.into(), source_key.into(), uri.into()))
            .cloned())
    }
    async fn list(
        &self,
        tenant: &str,
        source_key: &str,
        after: &str,
        limit: u16,
    ) -> Result<Vec<SkillReview>, ReviewError> {
        Ok(self
            .rows
            .read()
            .unwrap()
            .values()
            .filter(|row| {
                row.tenant_id == tenant
                    && row.source_key == source_key
                    && row.skill_uri.as_str() > after
            })
            .take(usize::from(limit))
            .cloned()
            .collect())
    }
    async fn permits(
        &self,
        tenant: &str,
        candidate: &ReviewCandidate,
    ) -> Result<bool, ReviewError> {
        Ok(self
            .get(tenant, &candidate.source_key(), &candidate.skill().uri)
            .await?
            .is_some_and(|row| {
                !row.quarantined
                    && row.serving.as_ref().is_some_and(|serving| {
                        serving.content_digest() == candidate.content_digest()
                    })
            }))
    }
    async fn observe(
        &self,
        _: &str,
        _: Option<i64>,
        _: &ReviewCandidate,
    ) -> Result<SkillReview, ReviewError> {
        panic!("Use PostgreSQL to test review observation")
    }
    async fn decide(
        &self,
        _: &SkillReview,
        _: ReviewDecision,
        _: DecisionActor<'_>,
    ) -> Result<SkillReview, ReviewError> {
        panic!("Use PostgreSQL to test review decisions")
    }
    async fn history(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
        _: u16,
    ) -> Result<Vec<SkillDecisionRecord>, ReviewError> {
        Ok(Vec::new())
    }
}

struct FixtureSource(Arc<ReloadableSkillCatalog>);
#[async_trait::async_trait]
impl SkillCatalogSource for FixtureSource {
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        self.0
            .current()
            .map(|snapshot| (*snapshot).clone())
            .ok_or(SkillSourceError::Withdrawn)
    }
}

pub fn approved_catalog(
    catalog: Arc<ReloadableSkillCatalog>,
    tenant: &str,
) -> Arc<ReviewedSkillCatalog> {
    let reviews = Arc::new(SkillReviewFixture::default());
    if let Some(snapshot) = catalog.current() {
        reviews.approve(tenant, &snapshot);
    }
    reviewed_catalog(catalog, reviews)
}

pub fn reviewed_catalog(
    catalog: Arc<ReloadableSkillCatalog>,
    reviews: Arc<SkillReviewFixture>,
) -> Arc<ReviewedSkillCatalog> {
    Arc::new(ReviewedSkillCatalog::new(
        catalog.clone(),
        Arc::new(FixtureSource(catalog)),
        Some(reviews),
    ))
}
