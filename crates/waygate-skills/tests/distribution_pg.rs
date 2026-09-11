use std::{collections::BTreeMap, sync::Arc};
use waygate_skills::{
    distribution::ReviewedSkillCatalog,
    review::{
        DecisionActor, PgSkillReviewStore, ReviewCandidate, ReviewDecision, SkillReviewStore,
    },
    verify_in_memory_catalog, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
    ReloadableSkillCatalog, SkillCatalogSnapshot, SkillCatalogSource, SkillResourceDescriptor,
    SkillSourceError, CATALOG_SCHEMA_VERSION,
};

const URI: &str = "skill://fixture/demo/SKILL.md";
const HELPER: &str = "skill://fixture/demo/helper.txt";

fn snapshot(commit: char, body: &str, helper: &str) -> SkillCatalogSnapshot {
    let text = format!("---\nname: demo\ndescription: Review fixture\n---\n{body}");
    let bytes = BTreeMap::from([
        (URI.into(), text.into_bytes()),
        (HELPER.into(), helper.as_bytes().to_vec()),
    ]);
    let resources = bytes
        .iter()
        .map(
            |(uri, bytes): (&String, &Vec<u8>)| SkillResourceDescriptor {
                uri: uri.clone(),
                source_path: uri.strip_prefix("skill://fixture/").unwrap().into(),
                source_object: waygate_skills::sha256_digest(bytes),
                size: bytes.len() as u64,
                media_type: if uri.ends_with(".md") {
                    "text/markdown"
                } else {
                    "text/plain"
                }
                .into(),
            },
        )
        .collect();
    verify_in_memory_catalog(
        CatalogSourceIdentity {
            origin: "git+https://fixture.test/skills".into(),
            reference: "main".into(),
            resolved_digest: format!("git-sha1:{}", commit.to_string().repeat(40)),
            resolved_tree_digest: format!("git-sha1:{}", commit.to_string().repeat(40)),
        },
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills: vec![CatalogSkill {
                uri: URI.into(),
                frontmatter: serde_json::from_value(
                    serde_json::json!({"name":"demo","description":"Review fixture"}),
                )
                .unwrap(),
                resources,
            }],
        },
        bytes,
    )
    .unwrap()
}

struct Source {
    current: SkillCatalogSnapshot,
    historical: Vec<SkillCatalogSnapshot>,
}
#[async_trait::async_trait]
impl SkillCatalogSource for Source {
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        Ok(self.current.clone())
    }
    async fn restore(
        &self,
        identity: &CatalogSourceIdentity,
    ) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        self.historical
            .iter()
            .find(|snapshot| snapshot.source() == identity)
            .cloned()
            .ok_or(SkillSourceError::Withdrawn)
    }
}
fn actor() -> DecisionActor<'static> {
    DecisionActor {
        subject: "operator",
        issuer: "test",
        reason: "Reviewed fixture contents",
    }
}

#[tokio::test]
async fn discovery_spans_review_pages_and_batch_checks_revocation() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let store = Arc::new(PgSkillReviewStore::new(pool));
    let mut contents = BTreeMap::new();
    let mut skills = Vec::new();
    for index in 0..201 {
        let name = format!("workflow-{index}");
        let uri = format!("skill://fixture/{name}/SKILL.md");
        let bytes = format!(
            "---\nname: {name}\ndescription: Batch review fixture\n---\nReviewed instructions"
        )
        .into_bytes();
        skills.push(CatalogSkill {
            uri: uri.clone(),
            frontmatter: serde_json::from_value(
                serde_json::json!({"name": name, "description": "Batch review fixture"}),
            )
            .unwrap(),
            resources: vec![SkillResourceDescriptor {
                uri: uri.clone(),
                source_path: format!("{name}/SKILL.md"),
                source_object: waygate_skills::sha256_digest(&bytes),
                size: bytes.len() as u64,
                media_type: "text/markdown".into(),
            }],
        });
        contents.insert(uri, bytes);
    }
    let snapshot = verify_in_memory_catalog(
        snapshot('a', "", "").source().clone(),
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills,
        },
        contents,
    )
    .unwrap();
    let source = Arc::new(Source {
        current: snapshot.clone(),
        historical: vec![],
    });
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(source.as_ref()).await.unwrap();
    let service = ReviewedSkillCatalog::new(catalog, source, Some(store.clone()));
    let mut candidates = Vec::new();
    for skill in snapshot.skills() {
        let candidate = ReviewCandidate::from_snapshot(&snapshot, &skill.uri).unwrap();
        let pending = store.observe(&tenant, None, &candidate).await.unwrap();
        store
            .decide(&pending, ReviewDecision::Approve, actor())
            .await
            .unwrap();
        candidates.push(candidate);
    }
    let listing = service.list(&tenant, None).await.unwrap();
    assert_eq!(listing.skills.len(), snapshot.skills().len());
    assert!(store.permits_all(&tenant, &candidates).await.unwrap());
    assert!(!store
        .permits_all("another-tenant", &candidates)
        .await
        .unwrap());
    let candidate = &candidates[100];
    let review = store
        .get(&tenant, &candidate.source_key(), &candidate.skill().uri)
        .await
        .unwrap()
        .unwrap();
    store
        .decide(&review, ReviewDecision::Quarantine, actor())
        .await
        .unwrap();
    assert!(!store.permits_all(&tenant, &candidates).await.unwrap());
    let eligibility = store.permits_each(&tenant, &candidates).await.unwrap();
    assert_eq!(eligibility.len(), candidates.len());
    assert!(eligibility
        .iter()
        .enumerate()
        .all(|(index, permitted)| *permitted == (index != 100)));
    assert!(service.check_all(&tenant, &listing.skills).await.is_err());
    let available = service.list(&tenant, None).await.unwrap();
    assert_eq!(available.skills.len(), snapshot.skills().len() - 1);
    assert!(available
        .skills
        .iter()
        .all(|entry| entry.uri != candidate.skill().uri));
}

#[tokio::test]
async fn restart_restores_approved_contents_and_quarantine_revokes_retained_reads() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let store = Arc::new(PgSkillReviewStore::new(pool.clone()));
    let old = snapshot('a', "Approved instructions", "approved helper");
    let candidate = ReviewCandidate::from_snapshot(&old, URI).unwrap();
    let pending = store.observe(&tenant, None, &candidate).await.unwrap();
    let approved = store
        .decide(&pending, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let new = snapshot('b', "Unreviewed instructions", "changed helper");
    let update = ReviewCandidate::from_snapshot(&new, URI).unwrap();
    let pending = store
        .observe(&tenant, Some(approved.generation), &update)
        .await
        .unwrap();
    let source = Arc::new(Source {
        current: new,
        historical: vec![old.clone()],
    });
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(source.as_ref()).await.unwrap();
    assert!(catalog.at_revision(&old.revision()).is_none());
    let reviewed = ReviewedSkillCatalog::new(catalog.clone(), source, Some(store.clone()));
    let served = reviewed.resolve(&tenant, HELPER, None).await.unwrap();
    assert_eq!(
        &*served.load_resource(HELPER).await.unwrap().unwrap().bytes,
        b"approved helper"
    );
    assert_eq!(
        reviewed.list(&tenant, None).await.unwrap().skills[0]
            .snapshot
            .revision(),
        old.revision()
    );
    assert!(reviewed
        .resolve("different-tenant", URI, None)
        .await
        .is_err());
    store
        .decide(&pending, ReviewDecision::Quarantine, actor())
        .await
        .unwrap();
    assert!(reviewed.check(&tenant, &served, HELPER).await.is_err());
    assert!(reviewed
        .resolve(&tenant, HELPER, Some(&served.revision()))
        .await
        .is_err());
    assert!(reviewed
        .list(&tenant, None)
        .await
        .unwrap()
        .skills
        .is_empty());
}

#[tokio::test]
async fn unavailable_approved_revision_never_substitutes_candidate_contents() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let store = Arc::new(PgSkillReviewStore::new(pool.clone()));
    let old = snapshot('a', "Approved", "approved helper");
    let candidate = ReviewCandidate::from_snapshot(&old, URI).unwrap();
    let pending = store.observe(&tenant, None, &candidate).await.unwrap();
    store
        .decide(&pending, ReviewDecision::Approve, actor())
        .await
        .unwrap();
    let source = Arc::new(Source {
        current: snapshot('b', "Changed", "changed helper"),
        historical: Vec::new(),
    });
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(source.as_ref()).await.unwrap();
    let reviewed = ReviewedSkillCatalog::new(catalog.clone(), source.clone(), Some(store));
    assert!(reviewed.resolve(&tenant, URI, None).await.is_err());
    let listed = reviewed.list(&tenant, None).await.unwrap();
    assert!(listed.skills.is_empty());
    assert_eq!(listed.unavailable, vec![URI]);
    let no_store = ReviewedSkillCatalog::new(catalog.clone(), source, None);
    assert!(no_store.list(&tenant, None).await.is_err());
    catalog.withdraw();
    assert!(reviewed
        .resolve(&tenant, URI, Some(&old.revision()))
        .await
        .is_err());
}

#[tokio::test]
async fn stalled_historical_restore_preserves_other_available_approved_skills() {
    async fn with_peers(snapshot: SkillCatalogSnapshot, historical: &str) -> SkillCatalogSnapshot {
        let mut skills = snapshot
            .skills()
            .iter()
            .map(|skill| CatalogSkill {
                uri: skill.uri.clone(),
                frontmatter: skill.frontmatter.clone(),
                resources: skill.resources.to_vec(),
            })
            .collect::<Vec<_>>();
        let mut bytes = BTreeMap::new();
        for skill in snapshot.skills() {
            for file in skill.resources.iter() {
                bytes.insert(
                    file.uri.clone(),
                    snapshot
                        .load_resource(&file.uri)
                        .await
                        .unwrap()
                        .unwrap()
                        .bytes
                        .to_vec(),
                );
            }
        }
        for (name, body) in [("z-peer", "Stable instructions"), ("y-history", historical)] {
            let uri = format!("skill://fixture/{name}/SKILL.md");
            let peer = format!("---\nname: {name}\ndescription: Independent skill\n---\n{body}\n")
                .into_bytes();
            skills.push(CatalogSkill {
                uri: uri.clone(),
                frontmatter: serde_json::from_value(
                    serde_json::json!({"name":name,"description":"Independent skill"}),
                )
                .unwrap(),
                resources: vec![SkillResourceDescriptor {
                    uri: uri.clone(),
                    source_path: format!("{name}/SKILL.md"),
                    source_object: waygate_skills::sha256_digest(&peer),
                    size: peer.len() as u64,
                    media_type: "text/markdown".into(),
                }],
            });
            bytes.insert(uri, peer);
        }
        verify_in_memory_catalog(
            snapshot.source().clone(),
            CatalogManifest {
                schema_version: CATALOG_SCHEMA_VERSION,
                skills,
            },
            bytes,
        )
        .unwrap()
    }
    struct StalledSource {
        current: SkillCatalogSnapshot,
        available: SkillCatalogSnapshot,
    }
    #[async_trait::async_trait]
    impl SkillCatalogSource for StalledSource {
        async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            Ok(self.current.clone())
        }
        async fn restore(
            &self,
            identity: &CatalogSourceIdentity,
        ) -> Result<SkillCatalogSnapshot, SkillSourceError> {
            if identity == self.available.source() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Ok(self.available.clone())
            } else {
                std::future::pending().await
            }
        }
    }
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = waygate_test_support::pg::create_tenant(&pool).await;
    let store = Arc::new(PgSkillReviewStore::new(pool));
    let old = with_peers(
        snapshot('a', "Approved", "approved helper"),
        "Old instructions",
    )
    .await;
    let available = with_peers(
        snapshot('c', "Approved", "approved helper"),
        "Approved historical instructions",
    )
    .await;
    let current = with_peers(
        snapshot('b', "Pending", "changed helper"),
        "Pending historical instructions",
    )
    .await;
    for skill in old.skills() {
        let approved_snapshot = if skill.uri == "skill://fixture/y-history/SKILL.md" {
            &available
        } else {
            &old
        };
        let candidate = ReviewCandidate::from_snapshot(approved_snapshot, &skill.uri).unwrap();
        let pending = store.observe(&tenant, None, &candidate).await.unwrap();
        let approved = store
            .decide(&pending, ReviewDecision::Approve, actor())
            .await
            .unwrap();
        let replacement = ReviewCandidate::from_snapshot(&current, &skill.uri).unwrap();
        store
            .observe(&tenant, Some(approved.generation), &replacement)
            .await
            .unwrap();
    }
    let revision = current.revision();
    let historical_revision = available.revision();
    let source = Arc::new(StalledSource { current, available });
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(source.as_ref()).await.unwrap();
    let reviewed = ReviewedSkillCatalog::new(catalog, source, Some(store));
    let selected = reviewed.list(&tenant, Some(&revision)).await.unwrap();
    assert_eq!(
        selected
            .skills
            .iter()
            .map(|skill| skill.uri.as_str())
            .collect::<Vec<_>>(),
        vec!["skill://fixture/z-peer/SKILL.md"]
    );
    let listing = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reviewed.list(&tenant, None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        listing
            .skills
            .iter()
            .map(|skill| skill.uri.as_str())
            .collect::<Vec<_>>(),
        vec![
            "skill://fixture/y-history/SKILL.md",
            "skill://fixture/z-peer/SKILL.md"
        ]
    );
    assert_eq!(listing.skills[0].snapshot.revision(), historical_revision);
    assert_eq!(listing.unavailable, vec![URI]);
}
