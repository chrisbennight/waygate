use std::collections::BTreeMap;

use waygate_skills::review::{
    CandidateStatus, DecisionActor, PgSkillReviewStore, ReviewCandidate, ReviewDecision,
    ReviewError, SkillReviewStore,
};
use waygate_skills::{
    verify_in_memory_catalog, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
    SkillResourceDescriptor, CATALOG_SCHEMA_VERSION,
};

fn candidate(commit: &str, body: &str, helper: &str) -> ReviewCandidate {
    let uri = "skill://fixture/demo/SKILL.md";
    let helper_uri = "skill://fixture/demo/scripts/helper.js";
    let text = format!("---\nname: demo\ndescription: A test workflow\n---\n{body}\n");
    let bytes = BTreeMap::from([
        (uri.to_owned(), text.into_bytes()),
        (helper_uri.to_owned(), helper.as_bytes().to_vec()),
    ]);
    let resources = bytes
        .iter()
        .map(|(uri, bytes)| SkillResourceDescriptor {
            uri: uri.clone(),
            source_path: uri.strip_prefix("skill://fixture/").unwrap().into(),
            source_object: waygate_skills::sha256_digest(bytes),
            size: bytes.len() as u64,
            media_type: if uri.ends_with(".js") {
                "text/javascript"
            } else {
                "text/markdown"
            }
            .into(),
        })
        .collect();
    let snapshot = verify_in_memory_catalog(
        CatalogSourceIdentity {
            origin: "git+https://example.test/team/skills".into(),
            reference: "main".into(),
            resolved_digest: format!("git-sha1:{}", commit.repeat(40)),
            resolved_tree_digest: format!("git-sha1:{}", commit.repeat(40)),
        },
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills: vec![CatalogSkill {
                uri: uri.into(),
                frontmatter: serde_json::from_value(
                    serde_json::json!({"name":"demo","description":"A test workflow"}),
                )
                .unwrap(),
                resources,
            }],
        },
        bytes,
    )
    .unwrap();
    ReviewCandidate::from_snapshot(&snapshot, uri).unwrap()
}

fn actor() -> DecisionActor<'static> {
    DecisionActor {
        subject: "operator",
        issuer: "https://idp.test",
        reason: "Reviewed the complete skill changes",
    }
}

#[tokio::test]
async fn deleting_and_recreating_a_tenant_does_not_restore_its_approvals() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let other = waygate_test_support::pg::create_tenant(&pool).await;
    let candidate = candidate("a", "Reviewed", "return 1;");
    for id in [&tenant, &other] {
        let pending = store.observe(id, None, &candidate).await.unwrap();
        store
            .decide(&pending, ReviewDecision::Approve, actor())
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM tenants WHERE id=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!store.permits(&tenant, &candidate).await.unwrap());
    assert!(store
        .get(&tenant, &candidate.source_key(), &candidate.skill().uri)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .history(
            &tenant,
            &candidate.source_key(),
            &candidate.skill().uri,
            i64::MAX,
            10
        )
        .await
        .unwrap()
        .is_empty());
    sqlx::query(
        "INSERT INTO tenants (id, display_name, status) VALUES ($1, 'Recreated tenant', 'active')",
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .unwrap();
    assert!(!store.permits(&tenant, &candidate).await.unwrap());
    let pending = store.observe(&tenant, None, &candidate).await.unwrap();
    assert_eq!(pending.candidate_status, CandidateStatus::Pending);
    assert!(pending.serving.is_none());
    assert!(store.permits(&other, &candidate).await.unwrap());
}

#[test]
fn distribution_identity_tracks_skill_content_not_repository_revision() {
    let initial = candidate("a", "Initial", "return 1;");
    let unrelated = candidate("b", "Initial", "return 1;");
    assert_eq!(initial.content_digest(), unrelated.content_digest());
    assert_ne!(
        initial.source().resolved_digest,
        unrelated.source().resolved_digest
    );
    assert_ne!(
        initial.content_digest(),
        candidate("b", "Changed", "return 1;").content_digest()
    );
    assert_ne!(
        initial.content_digest(),
        candidate("b", "Initial", "return 2;").content_digest()
    );
}

#[tokio::test]
async fn pending_and_rejected_updates_preserve_only_approved_content() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let first = candidate("a", "Initial", "return 1;");
    assert!(!store.permits(&tenant, &first).await.unwrap());
    let pending = store.observe(&tenant, None, &first).await.unwrap();
    assert_eq!(pending.candidate_status, CandidateStatus::Pending);
    assert!(pending.serving.is_none());
    assert!(!store.permits(&tenant, &first).await.unwrap());
    let approved = store
        .decide(&pending, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    assert!(store.permits(&tenant, &first).await.unwrap());
    assert!(!store.permits("other-tenant", &first).await.unwrap());

    let unchanged = candidate("b", "Initial", "return 1;");
    let observed = store
        .observe(&tenant, Some(approved.generation), &unchanged)
        .await
        .unwrap();
    assert_eq!(observed.generation, approved.generation);
    assert_eq!(observed.serving.as_ref(), Some(&first));
    assert!(store.permits(&tenant, &unchanged).await.unwrap());

    let update = candidate("c", "Initial", "return 2;");
    let pending = store
        .observe(&tenant, Some(observed.generation), &update)
        .await
        .unwrap();
    assert_eq!(pending.candidate_status, CandidateStatus::Pending);
    assert!(store.permits(&tenant, &first).await.unwrap());
    assert!(!store.permits(&tenant, &update).await.unwrap());
    let rejected = store
        .decide(&pending, ReviewDecision::Reject, actor())
        .await
        .unwrap();
    let repeated = store
        .observe(&tenant, Some(rejected.generation), &update)
        .await
        .unwrap();
    assert_eq!(repeated.candidate_status, CandidateStatus::Rejected);
    assert!(store.permits(&tenant, &first).await.unwrap());
    assert!(!store.permits(&tenant, &update).await.unwrap());

    let restarted = PgSkillReviewStore::new(pool.clone());
    let restored = restarted
        .get(&tenant, &first.source_key(), &first.skill().uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored.serving, Some(first));
    assert_eq!(restored.candidate, update);
    let history = restarted
        .history(
            &tenant,
            &restored.source_key,
            &restored.skill_uri,
            i64::MAX,
            10,
        )
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].decision, ReviewDecision::Reject);
    assert_eq!(history[1].decision, ReviewDecision::Approve);
    assert_eq!(history[1].actor, "operator");
    assert_eq!(history[1].actor_issuer, "https://idp.test");
    assert_eq!(history[1].reason, actor().reason);

    let returned = restarted
        .observe(
            &tenant,
            Some(restored.generation),
            restored.serving.as_ref().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(returned.candidate_status, CandidateStatus::Approved);
    assert!(restarted
        .permits(&tenant, &returned.candidate)
        .await
        .unwrap());
    assert!(matches!(
        restarted
            .decide(&returned, ReviewDecision::Reject, actor())
            .await,
        Err(ReviewError::Stale)
    ));
}

#[tokio::test]
async fn stale_reviews_and_observations_cannot_overwrite_newer_decisions() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let first = candidate("a", "Initial", "return 1;");
    let review = store.observe(&tenant, None, &first).await.unwrap();
    let (left, right) = tokio::join!(
        store.decide(&review, ReviewDecision::Approve, actor()),
        store.decide(&review, ReviewDecision::Approve, actor())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        left.as_ref().err().or(right.as_ref().err()),
        Some(ReviewError::Stale)
    ));
    assert!(matches!(
        store
            .observe(
                &tenant,
                Some(review.generation),
                &candidate("b", "New", "return 1;")
            )
            .await,
        Err(ReviewError::Stale)
    ));
    assert!(matches!(
        store.observe(&tenant, None, &first).await,
        Err(ReviewError::Stale)
    ));
    let current = store
        .get(&tenant, &first.source_key(), &first.skill().uri)
        .await
        .unwrap()
        .unwrap();
    let newer = store
        .observe(
            &tenant,
            Some(current.generation),
            &candidate("b", "New", "return 1;"),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .decide(&current, ReviewDecision::Approve, actor())
            .await,
        Err(ReviewError::Stale)
    ));
    assert!(!store.permits(&tenant, &newer.candidate).await.unwrap());
}

#[tokio::test]
async fn quarantine_survives_refresh_and_later_approval_does_not_revive_old_content() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let old = candidate("a", "Initial", "return 1;");
    let initial = store.observe(&tenant, None, &old).await.unwrap();
    let approved = store
        .decide(&initial, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let quarantined = store
        .decide(&approved, ReviewDecision::Quarantine, actor())
        .await
        .unwrap();
    assert!(!store.permits(&tenant, &old).await.unwrap());
    assert!(matches!(
        store
            .decide(&approved, ReviewDecision::Approve, actor())
            .await,
        Err(ReviewError::Stale)
    ));
    let refreshed = store
        .observe(&tenant, Some(quarantined.generation), &old)
        .await
        .unwrap();
    assert!(refreshed.quarantined);
    let new = candidate("b", "Fixed", "return 2;");
    let update = store
        .observe(&tenant, Some(refreshed.generation), &new)
        .await
        .unwrap();
    assert!(update.quarantined);
    store
        .decide(&update, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let restarted = PgSkillReviewStore::new(pool.clone());
    assert!(restarted.permits(&tenant, &new).await.unwrap());
    assert!(!restarted.permits(&tenant, &old).await.unwrap());
}

#[tokio::test]
async fn invalid_attribution_has_no_effect_and_queue_is_tenant_scoped() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let initial = candidate("a", "Initial", "return 1;");
    let review = store.observe(&tenant, None, &initial).await.unwrap();
    assert!(matches!(
        store
            .decide(
                &review,
                ReviewDecision::Approve,
                DecisionActor {
                    reason: " ",
                    ..actor()
                }
            )
            .await,
        Err(ReviewError::InvalidAttribution)
    ));
    assert!(!store.permits(&tenant, &initial).await.unwrap());
    assert_eq!(
        store
            .list(&tenant, &initial.source_key(), "", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .list("other-tenant", &initial.source_key(), "", 10)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .history(
            &tenant,
            &initial.source_key(),
            &initial.skill().uri,
            i64::MAX,
            10
        )
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn rejecting_reintroduced_content_overrides_its_historical_approval() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let first = candidate("a", "Original", "return 1;");
    let pending = store.observe(&tenant, None, &first).await.unwrap();
    let approved = store
        .decide(&pending, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let second = candidate("b", "Replacement", "return 2;");
    let pending = store
        .observe(&tenant, Some(approved.generation), &second)
        .await
        .unwrap();
    let approved = store
        .decide(&pending, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let reverted = store
        .observe(&tenant, Some(approved.generation), &first)
        .await
        .unwrap();
    let rejected = store
        .decide(&reverted, ReviewDecision::Reject, actor())
        .await
        .unwrap();
    assert!(!store.permits(&tenant, &first).await.unwrap());
    assert!(store.permits(&tenant, &second).await.unwrap());
    store
        .observe(
            &tenant,
            Some(rejected.generation),
            &candidate("c", "Another candidate", "return 3;"),
        )
        .await
        .unwrap();
    assert!(!store.permits(&tenant, &first).await.unwrap());
    assert!(store.permits(&tenant, &second).await.unwrap());
}

#[tokio::test]
async fn rejected_content_stays_rejected_after_intervening_candidates() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let store = PgSkillReviewStore::new(pool.clone());
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let rejected_content = candidate("a", "Rejected", "return 1;");
    let pending = store
        .observe(&tenant, None, &rejected_content)
        .await
        .unwrap();
    let rejected = store
        .decide(&pending, ReviewDecision::Reject, actor())
        .await
        .unwrap();
    let other = store
        .observe(
            &tenant,
            Some(rejected.generation),
            &candidate("b", "Other", "return 2;"),
        )
        .await
        .unwrap();
    let returned = store
        .observe(
            &tenant,
            Some(other.generation),
            &candidate("c", "Rejected", "return 1;"),
        )
        .await
        .unwrap();
    assert_eq!(returned.candidate_status, CandidateStatus::Rejected);
    assert!(returned.serving.is_none());
    assert!(!store.permits(&tenant, &rejected_content).await.unwrap());
    let approved = store
        .decide(&returned, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    assert!(store.permits(&tenant, &rejected_content).await.unwrap());
    let other = store
        .observe(
            &tenant,
            Some(approved.generation),
            &candidate("d", "Other", "return 2;"),
        )
        .await
        .unwrap();
    let returned = store
        .observe(&tenant, Some(other.generation), &rejected_content)
        .await
        .unwrap();
    assert_eq!(returned.candidate_status, CandidateStatus::Approved);
}
