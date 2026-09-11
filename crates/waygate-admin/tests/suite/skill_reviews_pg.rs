use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;
use waygate_admin::{dashboard_router, DashboardAuth};
use waygate_skills::{
    distribution::ReviewedSkillCatalog,
    review::{PgSkillReviewStore, ReviewCandidate, SkillReviewStore},
    verify_in_memory_catalog, CatalogManifest, CatalogSkill, CatalogSourceIdentity,
    ReloadableSkillCatalog, SkillCatalogSnapshot, SkillCatalogSource, SkillResourceDescriptor,
    SkillSourceError, CATALOG_SCHEMA_VERSION,
};

struct Source(SkillCatalogSnapshot);
#[async_trait::async_trait]
impl SkillCatalogSource for Source {
    async fn load(&self) -> Result<SkillCatalogSnapshot, SkillSourceError> {
        Ok(self.0.clone())
    }
}

async fn request(app: axum::Router, path: &str, form: Option<String>) -> (StatusCode, String) {
    let mut request = Request::builder().uri(path);
    let body = match form {
        Some(form) => {
            request = request
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded");
            Body::from(form)
        }
        None => Body::empty(),
    };
    let response = app.oneshot(request.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn skill_review_pages_escape_source_and_bind_decisions_to_csrf_and_generation() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let name = format!("review-{}", uuid::Uuid::new_v4());
    let uri = format!("skill://fixture/{name}/SKILL.md");
    let bytes = format!(
        "---\nname: {name}\ndescription: Review fixture\n---\n<script>alert('source')</script>\n"
    )
    .into_bytes();
    let snapshot = verify_in_memory_catalog(
        CatalogSourceIdentity {
            origin: "git+https://fixture.test/api/v1/team/skills".into(),
            reference: "main".into(),
            resolved_digest: waygate_skills::sha256_digest(&bytes),
            resolved_tree_digest: waygate_skills::sha256_digest(&bytes),
        },
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills: vec![CatalogSkill {
                uri: uri.clone(),
                frontmatter: serde_json::from_value(
                    serde_json::json!({"name":name,"description":"Review fixture"}),
                )
                .unwrap(),
                resources: vec![SkillResourceDescriptor {
                    uri: uri.clone(),
                    source_path: format!("{name}/SKILL.md"),
                    source_object: waygate_skills::sha256_digest(&bytes),
                    size: bytes.len() as u64,
                    media_type: "text/markdown".into(),
                }],
            }],
        },
        BTreeMap::from([(uri.clone(), bytes)]),
    )
    .unwrap();
    let candidate = ReviewCandidate::from_snapshot(&snapshot, &uri).unwrap();
    let store = Arc::new(PgSkillReviewStore::new(pool.clone()));
    let tenant = waygate_core::TenantId::DEFAULT;
    let pending = store.observe(tenant, None, &candidate).await.unwrap();
    let source = Arc::new(Source(snapshot));
    let catalog = Arc::new(ReloadableSkillCatalog::default());
    catalog.refresh(source.as_ref()).await.unwrap();
    let reviewed = Arc::new(ReviewedSkillCatalog::new(
        catalog.clone(),
        source,
        Some(store.clone()),
    ));
    let mut state = waygate_test_support::admin::base_admin_state()
        .with_tenant_store(Some(Arc::new(waygate_tenants::PgTenantStore::new(pool))))
        .with_skill_catalog(Some(catalog))
        .with_skill_distribution(Some(reviewed));
    state.evidence = Arc::new(waygate_mcp::audit::InMemorySink::default());
    let page = waygate_admin::resource_catalog::read(
        &state,
        "skill_review",
        tenant,
        &serde_json::Map::new(),
        200,
        0,
    )
    .await
    .unwrap();
    let row = page
        .rows
        .iter()
        .find(|row| row["skill_uri"] == uri)
        .unwrap();
    assert_eq!(row["generation"], pending.generation);
    assert_eq!(row["content_digest"], candidate.content_digest());
    assert_eq!(row["candidate_status"], "pending");
    assert_eq!(
        row["candidate_status"],
        serde_json::to_value(pending.candidate_status).unwrap()
    );
    assert!(waygate_admin::resource_catalog::read(
        &state,
        "skill_review",
        "another-tenant",
        &serde_json::Map::new(),
        200,
        0,
    )
    .await
    .unwrap()
    .rows
    .is_empty());
    let app = dashboard_router(Arc::new(state), DashboardAuth::Disabled);
    let new_tenant = uuid::Uuid::new_v4().to_string();
    let (status, _) = request(
        app.clone(),
        "/tenants/create",
        Some(format!(
            "csrf=dev-csrf&id={new_tenant}&display_name=New+tenant"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let new_review = store
        .get(&new_tenant, &candidate.source_key(), &uri)
        .await
        .unwrap()
        .expect("tenant onboarding observes the already-loaded catalog");
    assert!(new_review.serving.is_none());
    assert_eq!(new_review.candidate, candidate);
    assert!(!store.permits(&new_tenant, &candidate).await.unwrap());
    for path in ["/skills", "/t/default/skills"] {
        let (status, body) = request(app.clone(), path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&name));
        assert!(body.contains("Needs review"));
        assert!(body.contains("aria-current=\"page\""));
        if path.starts_with("/t/") {
            assert!(body.contains("/admin/t/default/skills/review?uri="));
        }
    }
    let encoded_uri: String = url::form_urlencoded::byte_serialize(uri.as_bytes()).collect();
    let (status, body) = request(
        app.clone(),
        &format!("/t/default/skills/review?uri={encoded_uri}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("&#60;script&#62;") || body.contains("&lt;script&gt;"));
    assert!(!body.contains("<script>alert('source')</script>"));
    assert!(body.contains("/admin/t/default/skills/decision"));
    assert!(body.contains("href=\"https://fixture.test/team/skills\""));
    assert!(body.contains("Runtime compatibility:"));
    assert!(body.contains("Not applicable (skill instructions)"));
    assert!(body.contains("optional publisher-reported test information"));
    assert!(!body.contains("execution refused"));
    assert!(!body.contains("separate, expiring grants"));
    assert!(body.contains("id=\"skill-uri\""));
    let form = |csrf: &str, action: &str, generation: i64| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", csrf)
            .append_pair("action", action)
            .append_pair("skill_uri", &uri)
            .append_pair("generation", &generation.to_string())
            .append_pair("content_digest", candidate.content_digest())
            .append_pair("reason", "Reviewed exact fixture contents")
            .finish()
    };
    let (status, _) = request(
        app.clone(),
        "/t/default/skills/decision",
        Some(form("", "approve", pending.generation)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!store.permits(tenant, &candidate).await.unwrap());
    let (status, _) = request(
        app.clone(),
        "/t/default/skills/decision",
        Some(form("dev-csrf", "approve", pending.generation)),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(store.permits(tenant, &candidate).await.unwrap());
    assert!(!store.permits("another-tenant", &candidate).await.unwrap());
    let (status, body) = request(app.clone(), "/skills", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Approved metadata available"));
    // A restarted source has only the replacement metadata and cannot restore
    // the approved revision. The approval remains recorded, but delivery is unavailable.
    let replacement =
        format!("---\nname: {name}\ndescription: Review fixture\n---\nReplacement\n").into_bytes();
    let mut descriptor = candidate.skill().resources[0].clone();
    descriptor.source_object = waygate_skills::sha256_digest(&replacement);
    descriptor.size = replacement.len() as u64;
    let mut identity = candidate.source().clone();
    identity.resolved_digest = waygate_skills::sha256_digest(&replacement);
    identity.resolved_tree_digest = identity.resolved_digest.clone();
    let replacement = verify_in_memory_catalog(
        identity,
        CatalogManifest {
            schema_version: CATALOG_SCHEMA_VERSION,
            skills: vec![CatalogSkill {
                uri: uri.clone(),
                frontmatter: candidate.skill().frontmatter.clone(),
                resources: vec![descriptor],
            }],
        },
        BTreeMap::from([(uri.clone(), replacement)]),
    )
    .unwrap();
    let replacement_source = Arc::new(Source(replacement));
    let restarted = Arc::new(ReloadableSkillCatalog::default());
    restarted
        .refresh(replacement_source.as_ref())
        .await
        .unwrap();
    let restarted_reviews = Arc::new(ReviewedSkillCatalog::new(
        restarted.clone(),
        replacement_source,
        Some(store.clone()),
    ));
    let restarted_state = waygate_test_support::admin::base_admin_state()
        .with_skill_catalog(Some(restarted))
        .with_skill_distribution(Some(restarted_reviews));
    let (status, body) = request(
        dashboard_router(Arc::new(restarted_state), DashboardAuth::Disabled),
        "/skills",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Approved · source unavailable"));
    assert!(!body.contains("Approved metadata available"));
    let (status, _) = request(
        app.clone(),
        "/skills/decision",
        Some(form("dev-csrf", "approve", pending.generation)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let approved = store
        .get(tenant, &candidate.source_key(), &uri)
        .await
        .unwrap()
        .unwrap();
    let (status, _) = request(
        app.clone(),
        "/skills/decision",
        Some(form("dev-csrf", "quarantine", approved.generation)),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(!store.permits(tenant, &candidate).await.unwrap());
    let history = store
        .history(tenant, &candidate.source_key(), &uri, i64::MAX, 10)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert!(history
        .iter()
        .all(|row| !row.actor.is_empty() && !row.actor_issuer.is_empty()));
}
