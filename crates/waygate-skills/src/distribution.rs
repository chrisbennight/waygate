//! Approval-aware selection over verified source snapshots. Cached metadata
//! never grants permission: every selection and content release checks the store.

use std::sync::Arc;

use crate::review::{ReviewCandidate, ReviewError, SkillReviewStore};
use crate::{ReloadableSkillCatalog, SkillCatalogSnapshot, SkillCatalogSource};

#[derive(Debug, thiserror::Error)]
pub enum DistributionError {
    #[error("skill distribution approval is unavailable")]
    Unavailable,
    #[error("skill is not approved for distribution")]
    NotApproved,
    #[error("skill or requested revision is unavailable")]
    NotFound,
    #[error(transparent)]
    Store(#[from] ReviewError),
}

/// A discovery projection with its original complete-catalog provenance.
#[derive(Clone)]
pub struct ApprovedSkill {
    pub snapshot: Arc<SkillCatalogSnapshot>,
    pub uri: String,
}

/// Discovery keeps independent approved skills available when a historical
/// source cannot be restored. Callers can report these unavailable identities;
/// direct reads still fail explicitly instead of returning replacement bytes.
pub struct SkillListing {
    pub skills: Vec<ApprovedSkill>,
    pub unavailable: Vec<String>,
}

#[derive(Clone)]
pub struct ReviewedSkillCatalog {
    catalog: Arc<ReloadableSkillCatalog>,
    source: Arc<dyn SkillCatalogSource>,
    reviews: Option<Arc<dyn SkillReviewStore>>,
}

impl ReviewedSkillCatalog {
    pub fn new(
        catalog: Arc<ReloadableSkillCatalog>,
        source: Arc<dyn SkillCatalogSource>,
        reviews: Option<Arc<dyn SkillReviewStore>>,
    ) -> Self {
        Self {
            catalog,
            source,
            reviews,
        }
    }

    pub fn store(&self) -> Result<&dyn SkillReviewStore, DistributionError> {
        self.reviews
            .as_deref()
            .ok_or(DistributionError::Unavailable)
    }

    /// Only the currently configured source and its present skill identities
    /// participate in client delivery. Historical metadata cannot undo withdrawal.
    pub async fn check(
        &self,
        tenant: &str,
        snapshot: &SkillCatalogSnapshot,
        uri: &str,
    ) -> Result<(), DistributionError> {
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        let root = owning_skill(snapshot, uri).ok_or(DistributionError::NotFound)?;
        if snapshot.source().origin != current.source().origin
            || snapshot.source().reference != current.source().reference
            || !current.skills().iter().any(|skill| skill.uri == root)
        {
            return Err(DistributionError::NotApproved);
        }
        let candidate =
            ReviewCandidate::from_snapshot(snapshot, root).ok_or(DistributionError::NotFound)?;
        if !self.store()?.permits(tenant, &candidate).await? {
            return Err(DistributionError::NotApproved);
        }
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        if snapshot.source().origin != current.source().origin
            || snapshot.source().reference != current.source().reference
            || !current.skills().iter().any(|skill| skill.uri == root)
        {
            return Err(DistributionError::NotApproved);
        }
        Ok(())
    }

    /// Restore metadata for privileged review. This does not approve the content
    /// or grant a caller permission to receive it; the control plane owns that gate.
    pub async fn review_snapshot(
        &self,
        candidate: &ReviewCandidate,
    ) -> Result<Arc<SkillCatalogSnapshot>, DistributionError> {
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        if current.source().origin != candidate.source().origin
            || current.source().reference != candidate.source().reference
        {
            return Err(DistributionError::NotFound);
        }
        let snapshot = match self.catalog.at_source(candidate.source()) {
            Some(snapshot) => snapshot,
            None => {
                let snapshot = Arc::new(
                    self.source
                        .restore(candidate.source())
                        .await
                        .map_err(|_| DistributionError::NotFound)?,
                );
                if snapshot.source() != candidate.source()
                    || ReviewCandidate::from_snapshot(&snapshot, &candidate.skill().uri).as_ref()
                        != Some(candidate)
                    || !self.catalog.retain_restored(snapshot.clone())
                {
                    return Err(DistributionError::NotFound);
                }
                snapshot
            }
        };
        if ReviewCandidate::from_snapshot(&snapshot, &candidate.skill().uri).as_ref()
            != Some(candidate)
        {
            return Err(DistributionError::NotFound);
        }
        Ok(snapshot)
    }

    pub async fn resolve(
        &self,
        tenant: &str,
        uri: &str,
        revision: Option<&str>,
    ) -> Result<Arc<SkillCatalogSnapshot>, DistributionError> {
        self.store()?;
        if let Some(snapshot) = revision.and_then(|revision| self.catalog.at_revision(revision)) {
            if snapshot.resource(uri).is_none() {
                return Err(DistributionError::NotFound);
            }
            self.check(tenant, &snapshot, uri).await?;
            return Ok(snapshot);
        }
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        let root = current
            .skills()
            .iter()
            .find(|skill| {
                skill
                    .uri
                    .strip_suffix("SKILL.md")
                    .is_some_and(|prefix| uri.starts_with(prefix))
            })
            .ok_or(DistributionError::NotFound)?;
        let current_candidate = ReviewCandidate::from_snapshot(&current, &root.uri)
            .ok_or(DistributionError::NotFound)?;
        let review = self
            .store()?
            .get(tenant, &current_candidate.source_key(), &root.uri)
            .await?
            .ok_or(DistributionError::NotApproved)?;
        if review.quarantined {
            return Err(DistributionError::NotApproved);
        }
        let serving = review.serving.ok_or(DistributionError::NotApproved)?;
        let snapshot = if current_candidate.content_digest() == serving.content_digest()
            && revision.is_none()
        {
            self.catalog.at_source(serving.source()).unwrap_or(current)
        } else {
            self.review_snapshot(&serving).await?
        };
        if snapshot.resource(uri).is_none()
            || revision.is_some_and(|revision| revision != snapshot.revision())
        {
            return Err(DistributionError::NotFound);
        }
        self.check(tenant, &snapshot, uri).await?;
        Ok(snapshot)
    }

    /// Batch revocation checks avoid per-skill database round trips.
    pub async fn check_all(
        &self,
        tenant: &str,
        entries: &[ApprovedSkill],
    ) -> Result<(), DistributionError> {
        let candidates = self.current_candidates(entries)?;
        if !self.store()?.permits_all(tenant, &candidates).await? {
            return Err(DistributionError::NotApproved);
        }
        self.current_candidates(entries)?;
        Ok(())
    }

    fn current_candidates(
        &self,
        entries: &[ApprovedSkill],
    ) -> Result<Vec<ReviewCandidate>, DistributionError> {
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        let roots = current
            .skills()
            .iter()
            .map(|skill| skill.uri.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        entries
            .iter()
            .map(|entry| {
                if entry.snapshot.source().origin != current.source().origin
                    || entry.snapshot.source().reference != current.source().reference
                    || !roots.contains(entry.uri.as_str())
                {
                    return Err(DistributionError::NotApproved);
                }
                ReviewCandidate::from_snapshot(&entry.snapshot, &entry.uri)
                    .ok_or(DistributionError::NotFound)
            })
            .collect()
    }

    pub async fn list(
        &self,
        tenant: &str,
        revision: Option<&str>,
    ) -> Result<SkillListing, DistributionError> {
        self.store()?;
        let current = self
            .catalog
            .current()
            .ok_or(DistributionError::Unavailable)?;
        let mut result = SkillListing {
            skills: Vec::new(),
            unavailable: Vec::new(),
        };
        let key =
            ReviewCandidate::source_key_for(&current.source().origin, &current.source().reference);
        let cached_revision = revision.and_then(|revision| self.catalog.at_revision(revision));
        let reviews = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut after = String::new();
            let mut reviews = Vec::new();
            loop {
                let page = self.store()?.list(tenant, &key, &after, 200).await?;
                let Some(last) = page.last() else {
                    break;
                };
                after = last.skill_uri.clone();
                reviews.extend(page);
            }
            Ok::<_, DistributionError>(reviews)
        })
        .await
        .map_err(|_| DistributionError::Unavailable)??;
        let restore_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut pending = std::collections::VecDeque::new();
        for review in reviews {
            let Some(candidate) = ReviewCandidate::from_snapshot(&current, &review.skill_uri)
            else {
                continue;
            };
            if review.quarantined {
                continue;
            }
            let Some(serving) = review.serving else {
                continue;
            };
            let selected = if let Some(snapshot) = &cached_revision {
                Ok(snapshot.clone())
            } else if candidate.content_digest() == serving.content_digest() && revision.is_none() {
                Ok(self
                    .catalog
                    .at_source(serving.source())
                    .unwrap_or_else(|| current.clone()))
            } else {
                match self.catalog.at_source(serving.source()) {
                    Some(snapshot)
                        if ReviewCandidate::from_snapshot(&snapshot, &review.skill_uri)
                            .as_ref()
                            == Some(&serving) =>
                    {
                        Ok(snapshot)
                    }
                    Some(_) => Err(DistributionError::NotFound),
                    None => {
                        pending.push_back(serving);
                        continue;
                    }
                }
            };
            match selected {
                Ok(snapshot)
                    if snapshot.resource(&review.skill_uri).is_some()
                        && revision.is_none_or(|revision| revision == snapshot.revision()) =>
                {
                    result.skills.push(ApprovedSkill {
                        snapshot,
                        uri: review.skill_uri,
                    });
                }
                Ok(_) | Err(DistributionError::NotFound) => {
                    result.unavailable.push(review.skill_uri)
                }
                Err(error) => return Err(error),
            }
        }
        // Bound source concurrency while allowing independent revisions to make
        // progress. Dropping the listing also cancels its owned recovery tasks.
        let mut recovering = tokio::task::JoinSet::new();
        loop {
            while recovering.len() < 4 {
                let Some(candidate) = pending.pop_front() else {
                    break;
                };
                let uri = candidate.skill().uri.clone();
                if tokio::time::Instant::now() >= restore_deadline {
                    result.unavailable.push(uri);
                    continue;
                }
                let catalog = self.clone();
                recovering.spawn(async move {
                    let snapshot = tokio::time::timeout_at(
                        restore_deadline,
                        catalog.review_snapshot(&candidate),
                    )
                    .await
                    .unwrap_or(Err(DistributionError::NotFound));
                    (uri, snapshot)
                });
            }
            let Some(recovered) = recovering.join_next().await else {
                break;
            };
            let (uri, snapshot) = recovered.expect("skill metadata recovery task failed");
            match snapshot {
                Ok(snapshot)
                    if snapshot.resource(&uri).is_some()
                        && revision.is_none_or(|revision| revision == snapshot.revision()) =>
                {
                    result.skills.push(ApprovedSkill { snapshot, uri })
                }
                Ok(_) | Err(DistributionError::NotFound) => result.unavailable.push(uri),
                Err(error) => return Err(error),
            }
        }
        result
            .skills
            .sort_by(|left, right| left.uri.cmp(&right.uri));
        result.unavailable.sort();
        let permitted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let candidates = self.current_candidates(&result.skills)?;
            let permitted = self.store()?.permits_each(tenant, &candidates).await?;
            self.current_candidates(&result.skills)?;
            Ok::<_, DistributionError>(permitted)
        })
        .await
        .map_err(|_| DistributionError::Unavailable)??;
        result.skills = result
            .skills
            .into_iter()
            .zip(permitted)
            .filter_map(|(skill, permitted)| permitted.then_some(skill))
            .collect();
        Ok(result)
    }
}

fn owning_skill<'a>(snapshot: &'a SkillCatalogSnapshot, uri: &str) -> Option<&'a str> {
    snapshot
        .skills()
        .iter()
        .find(|skill| skill.resources.iter().any(|file| file.uri == uri))
        .map(|skill| skill.uri.as_str())
}
