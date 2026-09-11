//! PostgreSQL contract coverage for served catalog metadata invalidation.

use uuid::Uuid;
use waygate_catalog::{ImportServer, ImportTool, ManifestImporter};
use waygate_test_support::pg::audit_pool_or_skip;

fn server(tenant: &str) -> ImportServer {
    ImportServer {
        tenant_id: tenant.to_owned(),
        name: "served-metadata".into(),
        transport: "http".into(),
        runtime_target: serde_json::json!({ "url": "http://served-metadata.test/mcp" }),
        classification_mode: "mcp_annotations".into(),
        tools: vec![ImportTool {
            name: "search".into(),
            approved_behavior_hash: Some("a".repeat(64)),
            risk: "low".into(),
            side_effects: false,
            pii: false,
            discriminator: None,
            operations: Vec::new(),
        }],
    }
}

#[tokio::test]
async fn every_served_version_metadata_change_advances_discovery_generation() {
    let Some(pool) = audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("test-discovery-metadata-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant)], true)
        .await
        .expect("seed catalog tool");

    let tool_id: Uuid = sqlx::query_scalar(
        "SELECT t.id FROM mcp_tools t \
         JOIN mcp_servers s ON s.id = t.server_id \
         WHERE s.tenant_id = $1 AND s.name = 'served-metadata' AND t.name = 'search'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read seeded tool id");

    // Hold the singleton generation row in one transaction so concurrent PG
    // suites cannot interleave their own catalog triggers with these deltas.
    let mut tx = pool
        .begin()
        .await
        .expect("begin metadata update transaction");
    let mut expected: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation \
         WHERE singleton = TRUE FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("lock catalog generation");

    for statement in [
        "UPDATE mcp_tool_versions SET schema_hash = repeat('b', 64) WHERE tool_id = $1",
        "UPDATE mcp_tool_versions SET tool_annotations = '{\"readOnlyHint\":true}'::jsonb WHERE tool_id = $1",
        "UPDATE mcp_tool_versions SET action_metadata = '{\"kind\":\"read\"}'::jsonb WHERE tool_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tool_id)
            .execute(&mut *tx)
            .await
            .expect("update served tool metadata");
        expected += 1;
        let observed: i64 = sqlx::query_scalar(
            "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("read advanced catalog generation");
        assert_eq!(observed, expected);
    }

    sqlx::query(
        "UPDATE mcp_tool_versions SET action_metadata = action_metadata WHERE tool_id = $1",
    )
    .bind(tool_id)
    .execute(&mut *tx)
    .await
    .expect("repeat unchanged served metadata");
    let unchanged: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read unchanged catalog generation");
    assert_eq!(
        unchanged, expected,
        "a no-op update must not invalidate discovery"
    );

    tx.rollback()
        .await
        .expect("rollback isolated metadata fixture");
}

#[tokio::test]
async fn operation_review_activation_and_withdrawal_advance_discovery_generation() {
    let Some(pool) = audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("test-discovery-operation-review-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant)], true)
        .await
        .expect("seed catalog tool");

    let tool_id: Uuid = sqlx::query_scalar(
        "SELECT t.id FROM mcp_tools t \
         JOIN mcp_servers s ON s.id = t.server_id \
         WHERE s.tenant_id = $1 AND s.name = 'served-metadata' AND t.name = 'search'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("read seeded tool id");

    let mut tx = pool
        .begin()
        .await
        .expect("begin operation review transaction");
    sqlx::query(
        "INSERT INTO tool_operation_classifications \
             (tool_id, operation, risk, side_effects, pii, reviewed_at) \
         VALUES ($1, 'lookup', 'low', FALSE, FALSE, NULL)",
    )
    .bind(tool_id)
    .execute(&mut *tx)
    .await
    .expect("seed unreviewed operation classification");
    let before: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation \
         WHERE singleton = TRUE FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("lock catalog generation");

    sqlx::query(
        "UPDATE tool_operation_classifications SET reviewed_at = now() \
         WHERE tool_id = $1 AND operation = 'lookup'",
    )
    .bind(tool_id)
    .execute(&mut *tx)
    .await
    .expect("activate operation classification");
    let activated: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read activation generation");
    assert_eq!(activated, before + 1);

    sqlx::query(
        "UPDATE tool_operation_classifications SET reviewed_at = reviewed_at \
         WHERE tool_id = $1 AND operation = 'lookup'",
    )
    .bind(tool_id)
    .execute(&mut *tx)
    .await
    .expect("repeat unchanged review metadata");
    let unchanged: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read unchanged review generation");
    assert_eq!(unchanged, activated);

    sqlx::query(
        "UPDATE tool_operation_classifications SET reviewed_at = NULL \
         WHERE tool_id = $1 AND operation = 'lookup'",
    )
    .bind(tool_id)
    .execute(&mut *tx)
    .await
    .expect("withdraw operation classification review");
    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT generation FROM catalog_discovery_generation WHERE singleton = TRUE",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read withdrawal generation");
    assert_eq!(withdrawn, activated + 1);

    tx.rollback()
        .await
        .expect("rollback isolated operation review fixture");
}
