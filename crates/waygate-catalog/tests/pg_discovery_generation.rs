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
async fn batched_resolution_preserves_tenant_lifecycle_and_review_decisions_in_bounded_reads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use waygate_catalog::{CatalogStore, PgCatalogStore, ResolvedTool, TOOL_RESOLUTION_BATCH_SIZE};
    let Some(setup) = audit_pool_or_skip().await else {
        return;
    };
    let own = format!("batch-own-{}", Uuid::new_v4());
    let global = format!("batch-global-{}", Uuid::new_v4());
    let name = format!("batch-{}", Uuid::new_v4());
    let mut own_server = server(&own);
    own_server.name = name.clone();
    let prototype = own_server.tools[0].clone();
    own_server.tools = (0..TOOL_RESOLUTION_BATCH_SIZE)
        .map(|i| {
            let mut tool = prototype.clone();
            tool.name = format!("tool.{i}");
            tool
        })
        .collect();
    let names = own_server
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    let mut global_server = server(&global);
    global_server.name = name.clone();
    global_server.tools[0].name = names[0].clone();
    for fixture in [own_server, global_server] {
        ManifestImporter::new(setup.clone())
            .import_atomic(&fixture.tenant_id, std::slice::from_ref(&fixture), false)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE mcp_servers SET visibility='global' WHERE tenant_id=$1 AND name=$2")
        .bind(&global)
        .bind(&name)
        .execute(&setup)
        .await
        .unwrap();

    let reads = Arc::new(AtomicUsize::new(0));
    let on_connect = reads.clone();
    let on_acquire = reads.clone();
    let measured = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .test_before_acquire(false)
        .after_connect(move |_, _| {
            on_connect.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        })
        .before_acquire(move |_, _| {
            on_acquire.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        })
        .connect(&std::env::var("AUDIT_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let store = PgCatalogStore::new(measured.clone());
    reads.store(0, Ordering::Relaxed);
    let batch = store.resolve_tools(&own, &name, &names).await.unwrap();
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "a complete batch needs one database statement"
    );
    assert_eq!(batch.len(), names.len());
    for (tool, expected) in batch.iter().zip(&names) {
        let ResolvedTool::Live(tool) = tool else {
            panic!("expected approved tool");
        };
        assert_eq!(&tool.tool_name, expected);
    }
    let own_id = match &batch[0] {
        ResolvedTool::Live(tool) => tool.tool_id,
        _ => unreachable!(),
    };
    let other = store
        .resolve_tools("unrelated-tenant", &name, &[names[0].clone()])
        .await
        .unwrap();
    let ResolvedTool::Live(global_tool) = &other[0] else {
        panic!("global tool is visible");
    };
    assert_ne!(
        own_id, global_tool.tool_id,
        "the caller's tenant overrides the global server"
    );

    let requested = vec![
        "absent".to_owned(),
        names[1].clone(),
        names[0].clone(),
        names[1].clone(),
    ];
    let ordered = store.resolve_tools(&own, &name, &requested).await.unwrap();
    for (tool, expected) in ordered.iter().zip(&requested) {
        let single = store
            .resolve_tool(&own, &format!("{name}.{expected}"))
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(tool).unwrap(),
            serde_json::to_value(single).unwrap()
        );
    }
    reads.store(0, Ordering::Relaxed);
    assert!(store
        .resolve_tools(&own, &name, &[])
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .resolve_tools(
            &own,
            &name,
            &vec![names[0].clone(); TOOL_RESOLUTION_BATCH_SIZE + 1]
        )
        .await
        .is_err());
    assert_eq!(
        reads.load(Ordering::Relaxed),
        0,
        "empty and oversized requests do not query storage"
    );

    sqlx::query("UPDATE mcp_tool_versions SET approved_at=NULL WHERE tool_id=$1")
        .bind(own_id)
        .execute(&setup)
        .await
        .unwrap();
    let pending = store.resolve_tools(&own, &name, &names[..2]).await.unwrap();
    assert!(matches!(pending[0], ResolvedTool::PendingApproval { .. }));
    assert!(matches!(pending[1], ResolvedTool::Live(_)));

    let reviews = PgCatalogStore::new(setup.clone());
    reviews
        .observe(
            &own,
            &name,
            &names[1],
            "first",
            &serde_json::json!({}),
            true,
        )
        .await
        .unwrap();
    reviews
        .observe(
            &own,
            &name,
            &names[1],
            "changed",
            &serde_json::json!({}),
            true,
        )
        .await
        .unwrap();
    reads.store(0, Ordering::Relaxed);
    let states = store.review_states(&own, &name, &names).await.unwrap();
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "review decisions are read as one batch"
    );
    assert_eq!(states.get(&names[1]), Some(&("changed".to_owned(), true)));
    assert!(
        !states.contains_key(&names[0]),
        "unobserved names stay distinct from acceptance"
    );
    assert!(store
        .review_states(&global, &name, &names)
        .await
        .unwrap()
        .is_empty());

    sqlx::query("UPDATE mcp_servers SET status='quarantined' WHERE tenant_id=$1 AND name=$2")
        .bind(&own)
        .bind(&name)
        .execute(&setup)
        .await
        .unwrap();
    assert!(
        store
            .resolve_tools(&own, &name, &requested)
            .await
            .unwrap()
            .iter()
            .all(|tool| matches!(tool, ResolvedTool::Quarantined { .. })),
        "server quarantine also blocks missing tool rows and never revives the global fallback"
    );
    sqlx::query("DELETE FROM mcp_servers WHERE tenant_id=ANY($1)")
        .bind(&[own, global])
        .execute(&setup)
        .await
        .unwrap();
    measured.close().await;
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
