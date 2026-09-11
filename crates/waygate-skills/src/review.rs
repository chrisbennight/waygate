//! Durable, tenant-scoped distribution decisions for verified skill contents.
//!
//! This store records approval of a file inventory, not script execution or
//! caller authorization. Observation requires a generation captured before
//! source acquisition; decisions require the generation displayed for review.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;

use crate::{CatalogSkill, CatalogSourceIdentity, SkillCatalogSnapshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewCandidate {
    source: CatalogSourceIdentity,
    skill: CatalogSkill,
    content_digest: String,
}

impl ReviewCandidate {
    /// Bind the complete verified inventory while leaving unrelated repository
    /// revisions outside the distribution-approval identity.
    pub fn from_snapshot(snapshot: &SkillCatalogSnapshot, uri: &str) -> Option<Self> {
        let entry = snapshot.skills().iter().find(|entry| entry.uri == uri)?;
        let mut resources = entry.resources.to_vec();
        resources.sort_by(|a, b| a.uri.cmp(&b.uri));
        let skill = CatalogSkill {
            uri: entry.uri.clone(),
            frontmatter: entry.frontmatter.clone(),
            resources,
        };
        let source = snapshot.source().clone();
        let content_digest = crate::sha256_digest(
            &serde_json::to_vec(&(
                "gateway-skill-distribution-v1",
                &source.origin,
                &source.reference,
                &skill,
            ))
            .expect("verified skill metadata is serializable"),
        );
        Some(Self {
            source,
            skill,
            content_digest,
        })
    }

    pub fn source(&self) -> &CatalogSourceIdentity {
        &self.source
    }
    pub fn skill(&self) -> &CatalogSkill {
        &self.skill
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
    pub fn source_key(&self) -> String {
        Self::source_key_for(&self.source.origin, &self.source.reference)
    }

    pub fn source_key_for(origin: &str, reference: &str) -> String {
        crate::sha256_digest(
            &serde_json::to_vec(&(origin, reference)).expect("source identity is serializable"),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillReview {
    pub tenant_id: String,
    pub source_key: String,
    pub skill_uri: String,
    pub generation: i64,
    pub candidate: ReviewCandidate,
    pub serving: Option<ReviewCandidate>,
    pub candidate_status: CandidateStatus,
    pub quarantined: bool,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approve,
    Reject,
    Quarantine,
}

impl ReviewDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
        }
    }
}

/// Authenticated attribution supplied by the authorized control-plane handler.
pub struct DecisionActor<'a> {
    pub subject: &'a str,
    pub issuer: &'a str,
    pub reason: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDecisionRecord {
    pub id: i64,
    pub generation: i64,
    pub decision: ReviewDecision,
    pub candidate: ReviewCandidate,
    pub actor: String,
    pub actor_issuer: String,
    pub reason: String,
    pub decided_at: OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("skill review changed; reload and review the current candidate")]
    Stale,
    #[error("decision attribution and reason must be nonempty and within their size limits")]
    InvalidAttribution,
    #[error(transparent)]
    Store(#[from] waygate_core::store::StoreError),
    #[error(transparent)]
    Encoding(#[from] serde_json::Error),
}

impl From<sqlx::Error> for ReviewError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

#[async_trait::async_trait]
pub trait SkillReviewStore: Send + Sync {
    async fn get(
        &self,
        tenant: &str,
        source_key: &str,
        uri: &str,
    ) -> Result<Option<SkillReview>, ReviewError>;
    async fn list(
        &self,
        tenant: &str,
        source_key: &str,
        after_uri: &str,
        limit: u16,
    ) -> Result<Vec<SkillReview>, ReviewError>;
    async fn observe(
        &self,
        tenant: &str,
        expected_generation: Option<i64>,
        candidate: &ReviewCandidate,
    ) -> Result<SkillReview, ReviewError>;
    async fn decide(
        &self,
        review: &SkillReview,
        decision: ReviewDecision,
        actor: DecisionActor<'_>,
    ) -> Result<SkillReview, ReviewError>;
    async fn permits(&self, tenant: &str, candidate: &ReviewCandidate)
        -> Result<bool, ReviewError>;
    /// Require every candidate to be currently approved.
    async fn permits_all(
        &self,
        tenant: &str,
        candidates: &[ReviewCandidate],
    ) -> Result<bool, ReviewError> {
        let permitted = self.permits_each(tenant, candidates).await?;
        Ok(permitted.len() == candidates.len() && permitted.into_iter().all(|value| value))
    }
    /// Return one eligibility result per candidate, in input order.
    async fn permits_each(
        &self,
        tenant: &str,
        candidates: &[ReviewCandidate],
    ) -> Result<Vec<bool>, ReviewError> {
        let mut permitted = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            permitted.push(self.permits(tenant, candidate).await?);
        }
        Ok(permitted)
    }
    async fn history(
        &self,
        tenant: &str,
        source_key: &str,
        uri: &str,
        before_id: i64,
        limit: u16,
    ) -> Result<Vec<SkillDecisionRecord>, ReviewError>;
}

#[derive(Debug, Clone)]
pub struct PgSkillReviewStore {
    pool: PgPool,
}

impl PgSkillReviewStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SkillReviewStore for PgSkillReviewStore {
    async fn get(
        &self,
        tenant: &str,
        source_key: &str,
        uri: &str,
    ) -> Result<Option<SkillReview>, ReviewError> {
        let row = sqlx::query(
            "SELECT r.* FROM skill_reviews r WHERE tenant_id=$1 AND source_key=$2 AND skill_uri=$3",
        )
        .bind(tenant)
        .bind(source_key)
        .bind(uri)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_review).transpose()
    }

    /// Bounded page ordered by stable identity; the caller passes the last URI
    /// as continuation within one source and tenant.
    async fn list(
        &self,
        tenant: &str,
        source_key: &str,
        after_uri: &str,
        limit: u16,
    ) -> Result<Vec<SkillReview>, ReviewError> {
        let rows = sqlx::query("SELECT r.* FROM skill_reviews r WHERE tenant_id=$1 AND source_key=$2 AND skill_uri>$3 ORDER BY skill_uri LIMIT $4")
            .bind(tenant).bind(source_key).bind(after_uri).bind(i64::from(limit.clamp(1, 200))).fetch_all(&self.pool).await?;
        rows.into_iter().map(decode_review).collect()
    }

    /// Publish a verified candidate only if the pre-acquisition witness still
    /// matches. Repeated observations of identical content preserve rejection,
    /// approval, quarantine, and the exact approved source provenance.
    async fn observe(
        &self,
        tenant: &str,
        expected_generation: Option<i64>,
        candidate: &ReviewCandidate,
    ) -> Result<SkillReview, ReviewError> {
        let source_key = candidate.source_key();
        let value = serde_json::to_value(candidate)?;
        let row = match expected_generation {
            None => sqlx::query("INSERT INTO skill_reviews (tenant_id,source_key,skill_uri,candidate,candidate_status) VALUES ($1,$2,$3,$4,'pending') ON CONFLICT DO NOTHING RETURNING skill_reviews.*")
                .bind(tenant).bind(&source_key).bind(&candidate.skill.uri).bind(value).fetch_optional(&self.pool).await?,
            Some(generation) => sqlx::query("UPDATE skill_reviews SET candidate=CASE WHEN candidate->>'content_digest'=$5 THEN candidate WHEN serving->>'content_digest'=$5 THEN serving ELSE $4 END, candidate_status=CASE WHEN candidate->>'content_digest'=$5 THEN candidate_status WHEN serving->>'content_digest'=$5 THEN 'approved' WHEN (SELECT d.decision FROM skill_review_decisions d WHERE d.tenant_id=$1 AND d.source_key=$2 AND d.skill_uri=$3 AND d.candidate->>'content_digest'=$5 AND d.decision IN ('approve','reject') ORDER BY d.id DESC LIMIT 1)='reject' THEN 'rejected' ELSE 'pending' END, generation=CASE WHEN candidate->>'content_digest'=$5 THEN generation ELSE generation+1 END, updated_at=CASE WHEN candidate->>'content_digest'=$5 THEN updated_at ELSE now() END WHERE tenant_id=$1 AND source_key=$2 AND skill_uri=$3 AND generation=$6 RETURNING skill_reviews.*")
                .bind(tenant).bind(&source_key).bind(&candidate.skill.uri).bind(value).bind(&candidate.content_digest).bind(generation).fetch_optional(&self.pool).await?,
        };
        decode_review(row.ok_or(ReviewError::Stale)?)
    }

    /// The row lock and generation check make the review decision and its
    /// durable attribution one transaction, including concurrent revocation.
    async fn decide(
        &self,
        review: &SkillReview,
        decision: ReviewDecision,
        actor: DecisionActor<'_>,
    ) -> Result<SkillReview, ReviewError> {
        if actor.subject.trim().is_empty()
            || actor.issuer.trim().is_empty()
            || actor.reason.trim().is_empty()
            || actor.subject.len() > 1024
            || actor.issuer.len() > 2048
            || actor.reason.len() > 4096
        {
            return Err(ReviewError::InvalidAttribution);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT r.* FROM skill_reviews r WHERE tenant_id=$1 AND source_key=$2 AND skill_uri=$3 FOR UPDATE")
            .bind(&review.tenant_id).bind(&review.source_key).bind(&review.skill_uri).fetch_optional(&mut *tx).await?;
        let current = decode_review(row.ok_or(ReviewError::Stale)?)?;
        if current.generation != review.generation
            || current.candidate != review.candidate
            || (decision == ReviewDecision::Reject
                && current.candidate_status != CandidateStatus::Pending)
            || (decision == ReviewDecision::Approve
                && current.candidate_status == CandidateStatus::Approved
                && !current.quarantined)
        {
            return Err(ReviewError::Stale);
        }
        let value = serde_json::to_value(&current.candidate)?;
        let row = sqlx::query("UPDATE skill_reviews SET generation=generation+1, updated_at=now(), serving=CASE WHEN $4='approve' THEN candidate ELSE serving END, candidate_status=CASE WHEN $4='approve' THEN 'approved' WHEN $4='reject' THEN 'rejected' ELSE candidate_status END, quarantined=CASE WHEN $4='approve' THEN false WHEN $4='quarantine' THEN true ELSE quarantined END WHERE tenant_id=$1 AND source_key=$2 AND skill_uri=$3 RETURNING skill_reviews.*")
            .bind(&review.tenant_id).bind(&review.source_key).bind(&review.skill_uri).bind(decision.as_str()).fetch_one(&mut *tx).await?;
        let decided = decode_review(row)?;
        sqlx::query("INSERT INTO skill_review_decisions (tenant_id,source_key,skill_uri,generation,decision,candidate,actor,actor_issuer,reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&review.tenant_id).bind(&review.source_key).bind(&review.skill_uri).bind(decided.generation).bind(decision.as_str()).bind(value).bind(actor.subject).bind(actor.issuer).bind(actor.reason).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(decided)
    }

    /// Consult authoritative state on every admission and again after slow
    /// content acquisition. Old approval records cannot override quarantine.
    async fn permits(
        &self,
        tenant: &str,
        candidate: &ReviewCandidate,
    ) -> Result<bool, ReviewError> {
        self.permits_all(tenant, std::slice::from_ref(candidate))
            .await
    }

    async fn permits_each(
        &self,
        tenant: &str,
        candidates: &[ReviewCandidate],
    ) -> Result<Vec<bool>, ReviewError> {
        let requested = candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                serde_json::json!({
                    "candidate_index": index,
                    "source_key": candidate.source_key(),
                    "skill_uri": candidate.skill.uri,
                    "content_digest": candidate.content_digest,
                })
            })
            .collect::<Vec<_>>();
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM skill_reviews r WHERE r.tenant_id=$1 AND r.source_key=requested.source_key AND r.skill_uri=requested.skill_uri AND NOT r.quarantined AND EXISTS (SELECT 1 FROM skill_review_decisions d WHERE d.tenant_id=r.tenant_id AND d.source_key=r.source_key AND d.skill_uri=r.skill_uri AND d.decision='approve' AND d.candidate->>'content_digest'=requested.content_digest AND d.id = (SELECT max(latest.id) FROM skill_review_decisions latest WHERE latest.tenant_id=r.tenant_id AND latest.source_key=r.source_key AND latest.skill_uri=r.skill_uri AND latest.candidate->>'content_digest'=requested.content_digest AND latest.decision IN ('approve','reject')) AND d.id > COALESCE((SELECT max(q.id) FROM skill_review_decisions q WHERE q.tenant_id=r.tenant_id AND q.source_key=r.source_key AND q.skill_uri=r.skill_uri AND q.decision='quarantine'),0))) FROM jsonb_to_recordset($2) AS requested(source_key text, skill_uri text, content_digest text, candidate_index bigint) ORDER BY requested.candidate_index")
            .bind(tenant).bind(serde_json::Value::Array(requested)).fetch_all(&self.pool).await?)
    }

    async fn history(
        &self,
        tenant: &str,
        source_key: &str,
        uri: &str,
        before_id: i64,
        limit: u16,
    ) -> Result<Vec<SkillDecisionRecord>, ReviewError> {
        let rows=sqlx::query("SELECT id,generation,decision,candidate,actor,actor_issuer,reason,decided_at FROM skill_review_decisions WHERE tenant_id=$1 AND source_key=$2 AND skill_uri=$3 AND id<$4 ORDER BY id DESC LIMIT $5")
            .bind(tenant).bind(source_key).bind(uri).bind(before_id).bind(i64::from(limit.clamp(1,200))).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(SkillDecisionRecord {
                    id: row.try_get("id")?,
                    generation: row.try_get("generation")?,
                    decision: serde_json::from_value(serde_json::Value::String(
                        row.try_get("decision")?,
                    ))?,
                    candidate: serde_json::from_value(row.try_get("candidate")?)?,
                    actor: row.try_get("actor")?,
                    actor_issuer: row.try_get("actor_issuer")?,
                    reason: row.try_get("reason")?,
                    decided_at: row.try_get("decided_at")?,
                })
            })
            .collect()
    }
}

fn decode_review(row: sqlx::postgres::PgRow) -> Result<SkillReview, ReviewError> {
    let serving: Option<serde_json::Value> = row.try_get("serving")?;
    Ok(SkillReview {
        tenant_id: row.try_get("tenant_id")?,
        source_key: row.try_get("source_key")?,
        skill_uri: row.try_get("skill_uri")?,
        generation: row.try_get("generation")?,
        candidate: serde_json::from_value(row.try_get("candidate")?)?,
        serving: serving.map(serde_json::from_value).transpose()?,
        candidate_status: serde_json::from_value(serde_json::Value::String(
            row.try_get("candidate_status")?,
        ))?,
        quarantined: row.try_get("quarantined")?,
        updated_at: row.try_get("updated_at")?,
    })
}
