use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use waygate_dashboard_stores::decision_batches::{
    BatchError, BatchOwner, BatchRequest, DecisionBatchStore, PgDecisionBatchStore, MAX_ITEMS,
    MAX_REQUEST_BYTES,
};

async fn connect() -> Option<sqlx::PgPool> {
    let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping: AUDIT_DATABASE_URL not set");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("isolated Postgres");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations");
    Some(pool)
}

fn request() -> BatchRequest {
    BatchRequest {
        kind: "tool".into(),
        action: "approve".into(),
        items: vec![
            json!({"tool":"one","generation":1}),
            json!({"tool":"two","generation":2}),
        ],
    }
}

#[test]
fn selection_is_bounded_and_references_are_unique() {
    let mut selection = request();
    assert!(selection.validate().is_ok());
    selection.items.push(selection.items[0].clone());
    assert!(matches!(selection.validate(), Err(BatchError::Invalid(_))));
    selection.items = vec![];
    assert!(selection.validate().is_err());
    selection.items = (0..=MAX_ITEMS).map(|i| json!({"id":i})).collect();
    assert!(selection.validate().is_err());
    selection.items = vec![json!({"id":"x".repeat(MAX_REQUEST_BYTES)})];
    assert!(selection.validate().is_err());
}

#[tokio::test]
async fn concurrent_submission_is_owned_immutable_and_replay_safe() {
    let Some(pool) = connect().await else { return };
    let tenant = format!("batch-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id,display_name,status) VALUES ($1,$1,'active')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    let store = PgDecisionBatchStore::new(pool.clone());
    let owner = BatchOwner {
        tenant: &tenant,
        issuer: "https://id.example",
        subject: "administrator",
    };
    let id = Uuid::new_v4();
    let selection = request();
    let (first, retry) = tokio::join!(
        store.prepare(owner, id, &selection),
        store.prepare(owner, id, &selection)
    );
    assert_eq!(first.unwrap().request, retry.unwrap().request);
    assert!(!store.begin_item(owner, id, 0).await.unwrap());
    let mut changed = selection.clone();
    changed.action = "reject".into();
    assert!(matches!(
        store.prepare(owner, id, &changed).await,
        Err(BatchError::Conflict)
    ));
    for stranger in [
        BatchOwner {
            subject: "another-administrator",
            ..owner
        },
        BatchOwner {
            issuer: "https://other.example",
            ..owner
        },
        BatchOwner {
            tenant: "default",
            ..owner
        },
    ] {
        assert!(store.get(stranger, id).await.unwrap().is_none());
        assert!(!store.claim(stranger, id).await.unwrap());
        assert!(!store.begin_item(stranger, id, 0).await.unwrap());
        assert!(!store
            .complete_item(stranger, id, 0, &json!({"outcome":"approved"}))
            .await
            .unwrap());
    }
    let (claim_one, claim_two) = tokio::join!(store.claim(owner, id), store.claim(owner, id));
    assert_ne!(claim_one.unwrap(), claim_two.unwrap());
    assert!(store.begin_item(owner, id, 0).await.unwrap());
    assert!(!store.begin_item(owner, id, 0).await.unwrap());
    assert!(store
        .complete_item(owner, id, 0, &json!({"outcome":"approved"}))
        .await
        .unwrap());
    assert!(!store
        .complete_item(owner, id, 0, &json!({"outcome":"rejected"}))
        .await
        .unwrap());
    assert!(store.begin_item(owner, id, 1).await.unwrap());

    // A new service instance can distinguish a completed effect from one that
    // started without a recorded outcome. It cannot reclaim the submission.
    let restarted = PgDecisionBatchStore::new(pool.clone());
    let batch = restarted.get(owner, id).await.unwrap().unwrap();
    assert_eq!(
        batch.items[0].result.as_ref().unwrap()["outcome"],
        "approved"
    );
    assert!(batch.items[1].started_at.is_some());
    assert!(batch.items[1].result.is_none());
    assert!(!restarted.claim(owner, id).await.unwrap());
    assert!(restarted
        .complete_item(owner, id, 1, &json!({"outcome":"changed"}))
        .await
        .unwrap());
    assert!(restarted
        .complete_item(owner, id, 0, &json!("invalid"))
        .await
        .is_err());
    sqlx::query("DELETE FROM tenants WHERE id=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    assert!(restarted.get(owner, id).await.unwrap().is_none());
}

#[tokio::test]
async fn expired_receipts_cannot_execute_and_capture_capacity_is_bounded() {
    let Some(pool) = connect().await else { return };
    let tenant = format!("batch-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO tenants (id,display_name,status) VALUES ($1,$1,'active')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
    let store = PgDecisionBatchStore::new(pool.clone());
    let owner = BatchOwner {
        tenant: &tenant,
        issuer: "https://id.example",
        subject: "administrator",
    };
    let id = Uuid::new_v4();
    store.prepare(owner, id, &request()).await.unwrap();
    sqlx::query("UPDATE admin_decision_batches SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE tenant_id=$1")
        .bind(&tenant).execute(&pool).await.unwrap();
    assert!(store.get(owner, id).await.unwrap().is_none());
    assert!(!store.claim(owner, id).await.unwrap());
    store
        .prepare(owner, Uuid::new_v4(), &request())
        .await
        .unwrap();
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_decision_batches WHERE tenant_id=$1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, 1);
    sqlx::query(
        "INSERT INTO admin_decision_batches (tenant_id,id,actor_issuer,actor_sub,request)
        SELECT $1,gen_random_uuid(),$2,$3,'{}'::jsonb FROM generate_series(1,99)",
    )
    .bind(&tenant)
    .bind(owner.issuer)
    .bind(owner.subject)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store.prepare(owner, Uuid::new_v4(), &request()).await,
        Err(BatchError::Capacity)
    ));
    sqlx::query("DELETE FROM tenants WHERE id=$1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}
