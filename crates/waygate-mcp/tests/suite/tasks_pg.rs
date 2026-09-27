//! Public persistence contract for upstream-owned task routing.
use waygate_core::store::StoreError;
use waygate_invocation::task_routes::{TaskRoute, TaskRouteStore};
use waygate_mcp::tasks::PgTaskRouteStore;

#[tokio::test]
async fn routes_survive_reconnection_and_expiry_precedes_cleanup() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = uuid::Uuid::new_v4().to_string();
    let route: TaskRoute = serde_json::from_value(serde_json::json!({
        "sub": "alice", "issuer": "test", "tenant": tenant,
        "profile": null, "auth_method": "oauth", "server": "service",
        "tool": "work", "upstream_id": "original-task", "binding": "original-manifest",
        "contract": {
            "authority": waygate_invocation::InvocationContractAuthority::SyntheticModel, "input_schema_hash": null,
            "output_schema_hash": null, "tool_annotations_hash": null,
            "action_metadata_hash": null, "operations_hash": null,
            "risk": "low", "side_effects": false, "pii": false,
            "requires_approval": false, "requires_approval_known": true
        },
        "operation_arguments": {}, "request_facts": waygate_core::RequestFacts::default(),
        "created_at": "2026-01-01T00:00:00Z", "ttl_ms": 129600000,
        "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 129600
    }))
    .unwrap();
    let id = uuid::Uuid::new_v4();
    let store = PgTaskRouteStore::new(pool.clone());
    store.insert(id, &route).await.unwrap();
    let mut replacement = route.clone();
    replacement.upstream_id = "different-task".into();
    assert!(matches!(
        store.insert(id, &replacement).await,
        Err(StoreError::Conflict)
    ));
    assert!(store.get(id, "other").await.unwrap().is_none());
    drop(store);
    pool.close().await;

    let pool = waygate_test_support::pg::audit_pool_or_skip()
        .await
        .unwrap();
    let store = PgTaskRouteStore::new(pool.clone());
    let restored = store.get(id, &tenant).await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&restored).unwrap(),
        serde_json::to_value(&route).unwrap()
    );
    let expired_id = uuid::Uuid::new_v4();
    let mut expired = route;
    expired.exp = 1;
    store.insert(expired_id, &expired).await.unwrap();
    assert!(store.get(expired_id, &tenant).await.unwrap().is_none());
    store.sweep_expired().await.unwrap();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM upstream_task_routes WHERE id = $1)")
            .bind(expired_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!exists);
    assert!(store.get(id, &tenant).await.unwrap().is_some());
    sqlx::query("DELETE FROM upstream_task_routes WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}
