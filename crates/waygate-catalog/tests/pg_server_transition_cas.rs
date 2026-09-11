//! Postgres contract coverage for governed catalog-server recovery.
//!
//! The reviewed row witness must close the read/approval/write race: only the
//! exact quarantined row version captured by the proposal may transition to
//! live, and the lifecycle audit must commit with that transition.

use std::time::Duration;

use sqlx::postgres::PgListener;
use uuid::Uuid;
use waygate_catalog::{
    CatalogServerStatus, CatalogServerStatusChange, CatalogStore, ImportServer, ImportTool,
    ManifestImporter, PgCatalogStore, CATALOG_RELOAD_CHANNEL,
};
use waygate_test_support::pg::audit_pool_or_skip;

fn server(tenant: &str) -> ImportServer {
    ImportServer {
        tenant_id: tenant.to_owned(),
        name: "grounded-docs".into(),
        transport: "http".into(),
        runtime_target: serde_json::json!({ "url": "http://grounded-docs.test/mcp" }),
        classification_mode: "manifest".into(),
        tools: vec![ImportTool {
            name: "list_libraries".into(),
            approved_behavior_hash: None,
            risk: "low".into(),
            side_effects: false,
            pii: false,
            discriminator: None,
            operations: Vec::new(),
        }],
    }
}

#[tokio::test]
async fn unquarantine_is_bound_to_authorization_facts_and_audited_atomically() {
    let Some(pool) = audit_pool_or_skip().await else {
        return;
    };

    let tenant = format!("test-catalog-transition-{}", Uuid::new_v4());
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[server(&tenant)], true)
        .await
        .expect("seed catalog server");
    let server_id: Uuid =
        sqlx::query_scalar("SELECT id FROM mcp_servers WHERE tenant_id = $1 AND name = $2")
            .bind(&tenant)
            .bind("grounded-docs")
            .fetch_one(&pool)
            .await
            .expect("read seeded server id");
    sqlx::query(
        "UPDATE mcp_servers SET status = 'quarantined', updated_at = now() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(&tenant)
    .bind(server_id)
    .execute(&pool)
    .await
    .expect("quarantine seeded server");

    let store = PgCatalogStore::new(pool.clone());
    let stale = store
        .server_transition_target(&tenant, server_id)
        .await
        .expect("capture transition target")
        .expect("seeded server exists");

    let mut changed = server(&tenant);
    changed.tools[0].pii = true;
    ManifestImporter::new(pool.clone())
        .import_atomic(&tenant, &[changed], true)
        .await
        .expect("reconcile changed authorization facts");
    let stale_updated = store
        .transition_server_status_if_unchanged(CatalogServerStatusChange {
            target: &stale,
            new_status: CatalogServerStatus::Live,
            actor: "reviewer@example.com",
            reason: Some("validated catalog"),
        })
        .await
        .expect("stale transition is a clean conflict");
    assert!(
        !stale_updated,
        "a review of an older authorization generation must not unquarantine"
    );

    let current = store
        .server_transition_target(&tenant, server_id)
        .await
        .expect("recapture transition target")
        .expect("seeded server exists");
    let mut listener = PgListener::connect_with(&pool)
        .await
        .expect("connect catalog listener");
    listener
        .listen(CATALOG_RELOAD_CHANNEL)
        .await
        .expect("LISTEN catalog doorbell");
    let generation_before = store
        .discovery_generation()
        .await
        .expect("read catalog generation")
        .expect("catalog generation singleton exists");
    let updated = store
        .transition_server_status_if_unchanged(CatalogServerStatusChange {
            target: &current,
            new_status: CatalogServerStatus::Live,
            actor: "reviewer@example.com",
            reason: Some("validated catalog"),
        })
        .await
        .expect("current transition succeeds");
    assert!(updated);

    let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("catalog transition doorbell arrives within five seconds")
        .expect("receive catalog transition doorbell");
    assert_eq!(notification.channel(), CATALOG_RELOAD_CHANNEL);
    let generation_after = store
        .discovery_generation()
        .await
        .expect("read advanced catalog generation")
        .expect("catalog generation singleton exists");
    assert!(
        generation_after > generation_before,
        "the durable generation must advance with the committed transition"
    );

    sqlx::query(
        "UPDATE mcp_tool_versions v \
            SET description = 'updated discovery description' \
           FROM mcp_tools t \
          WHERE v.tool_id = t.id AND t.server_id = $1",
    )
    .bind(server_id)
    .execute(&pool)
    .await
    .expect("change a published tool definition");
    let definition_notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("tool-definition doorbell arrives within five seconds")
        .expect("receive tool-definition doorbell");
    assert_eq!(definition_notification.channel(), CATALOG_RELOAD_CHANNEL);
    let generation_after_definition = store
        .discovery_generation()
        .await
        .expect("read generation after tool definition change")
        .expect("catalog generation singleton exists");
    assert!(
        generation_after_definition > generation_after,
        "tool definition changes must share the fleet-wide invalidation contract"
    );

    sqlx::query("UPDATE mcp_servers SET classification_mode = 'mcp_annotations' WHERE id = $1")
        .bind(server_id)
        .execute(&pool)
        .await
        .expect("change the server classification mode");
    let mode_notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
        .await
        .expect("classification-mode doorbell arrives within five seconds")
        .expect("receive classification-mode doorbell");
    assert_eq!(mode_notification.channel(), CATALOG_RELOAD_CHANNEL);
    let generation_after_mode = store
        .discovery_generation()
        .await
        .expect("read generation after classification-mode change")
        .expect("catalog generation singleton exists");
    assert!(
        generation_after_mode > generation_after_definition,
        "classification-mode changes must share the fleet-wide invalidation contract"
    );

    let status: String = sqlx::query_scalar("SELECT status FROM mcp_servers WHERE id = $1")
        .bind(server_id)
        .fetch_one(&pool)
        .await
        .expect("read final server status");
    assert_eq!(status, "live");
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM catalog_approvals \
         WHERE tenant_id = $1 AND subject_id = $2 \
           AND action = 'approved' AND actor = 'reviewer@example.com'",
    )
    .bind(&tenant)
    .bind(server_id)
    .fetch_one(&pool)
    .await
    .expect("read lifecycle audit");
    assert_eq!(approvals, 1, "only the committed transition is audited");

    let _ = sqlx::query("DELETE FROM mcp_servers WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await;
}
