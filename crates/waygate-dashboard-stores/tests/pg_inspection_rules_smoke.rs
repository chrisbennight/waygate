//! Live Postgres smoke for `PgInspectionRulesStore`.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` without a DB passes. Pins six behaviours
//! a future runtime consumer + the admin REST handlers
//! depend on:
//!
//! 1. Insert → get round-trip; every field returned.
//! 2. Tenant scoping on `get` and `delete` (tenant_b
//!    cannot see / remove tenant_a's rules).
//! 3. `list` filter combinations (inspector / name /
//!    enabled).
//! 4. `update` mutates the row + the `updated_at` trigger
//!    fires.
//! 5. `MAX_LIST_LIMIT` clamp.
//! 6. UNIQUE (tenant_id, inspector, name) surfaces as
//!    `RuleError::DuplicateName`.

use std::env;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_dashboard_stores::inspection_rules::{
    InspectionRulesStore, InspectorKind, NewInspectionRule, PgInspectionRulesStore, RuleError,
    RuleFilter, RuleUpdate, MAX_LIST_LIMIT,
};

async fn connect() -> Option<sqlx::PgPool> {
    let url = env::var("AUDIT_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    Some(pool)
}

async fn seed_tenant(pool: &sqlx::PgPool, suffix: &str) -> String {
    let tenant_id = format!("pg-rules-{suffix}");
    sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&tenant_id)
    .execute(pool)
    .await
    .expect("seed tenant");
    tenant_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rules_lifecycle_and_isolation() {
    let Some(pool) = connect().await else {
        eprintln!("skipping inspection_rules Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant_a = seed_tenant(&pool, &suffix).await;
    let tenant_b = seed_tenant(&pool, &format!("b-{suffix}")).await;
    let store = PgInspectionRulesStore::new(pool.clone());

    // 1. Insert round-trip.
    let cfg = json!({"pattern": r"\bACME-\d{6}\b", "label": "ACME_ID"});
    let applies = json!({});
    let r1 = store
        .insert(NewInspectionRule {
            tenant_id: &tenant_a,
            inspector: InspectorKind::Pii,
            name: "acme-employee-id",
            config: &cfg,
            applies_to: &applies,
            enabled: true,
        })
        .await
        .expect("insert r1");
    assert_eq!(r1.tenant_id, tenant_a);
    assert_eq!(r1.inspector, InspectorKind::Pii);
    assert_eq!(r1.name, "acme-employee-id");
    assert!(r1.enabled);

    let fetched = store
        .get(&tenant_a, r1.id)
        .await
        .expect("get r1")
        .expect("r1 present");
    assert_eq!(fetched.id, r1.id);
    assert_eq!(fetched.config, cfg);

    // 2. Tenant isolation on get + delete.
    assert!(
        store
            .get(&tenant_b, r1.id)
            .await
            .expect("get cross")
            .is_none(),
        "tenant_b must not see tenant_a's rule"
    );
    assert!(
        !store.delete(&tenant_b, r1.id).await.expect("delete cross"),
        "tenant_b must not be able to delete tenant_a's rule"
    );

    // 3. List filter combinations. Seed a second rule under
    //    secrets + disabled.
    let r2 = store
        .insert(NewInspectionRule {
            tenant_id: &tenant_a,
            inspector: InspectorKind::Secrets,
            name: "company-internal-token",
            config: &json!({"pattern": r"\bACME_TOKEN_[A-Z0-9]{20}\b"}),
            applies_to: &json!({}),
            enabled: false,
        })
        .await
        .expect("insert r2");

    let all = store
        .list(&tenant_a, RuleFilter::default(), 50, 0)
        .await
        .expect("list all");
    assert!(all.iter().any(|r| r.id == r1.id));
    assert!(all.iter().any(|r| r.id == r2.id));

    let pii_only = store
        .list(
            &tenant_a,
            RuleFilter {
                inspector: Some(InspectorKind::Pii),
                name: None,
                enabled: None,
            },
            50,
            0,
        )
        .await
        .expect("list pii");
    assert!(pii_only.iter().any(|r| r.id == r1.id));
    assert!(!pii_only.iter().any(|r| r.id == r2.id));

    let enabled_only = store
        .list(
            &tenant_a,
            RuleFilter {
                inspector: None,
                name: None,
                enabled: Some(true),
            },
            50,
            0,
        )
        .await
        .expect("list enabled");
    assert!(enabled_only.iter().any(|r| r.id == r1.id));
    assert!(!enabled_only.iter().any(|r| r.id == r2.id));

    let by_name = store
        .list(
            &tenant_a,
            RuleFilter {
                inspector: Some(InspectorKind::Pii),
                name: Some("acme-employee-id"),
                enabled: None,
            },
            50,
            0,
        )
        .await
        .expect("list by name");
    assert_eq!(by_name.len(), 1);

    // 4. Update mutates + bumps updated_at trigger.
    let pre_update = r1.updated_at;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let new_cfg = json!({"pattern": r"\bACME-\d{7}\b", "label": "ACME_ID_V2"});
    let updated = store
        .update(
            &tenant_a,
            r1.id,
            RuleUpdate {
                name: None,
                config: Some(&new_cfg),
                applies_to: None,
                enabled: Some(false),
            },
        )
        .await
        .expect("update")
        .expect("row found in tenant");
    assert_eq!(updated.config, new_cfg);
    assert!(!updated.enabled);
    assert!(
        updated.updated_at > pre_update,
        "trigger must bump updated_at: pre={pre_update}, post={}",
        updated.updated_at,
    );

    // Cross-tenant update returns None.
    let cross_update = store
        .update(
            &tenant_b,
            r1.id,
            RuleUpdate {
                name: None,
                config: None,
                applies_to: None,
                enabled: Some(true),
            },
        )
        .await
        .expect("cross update");
    assert!(cross_update.is_none());

    // 5. MAX_LIST_LIMIT clamp.
    let clamped = store
        .list(&tenant_a, RuleFilter::default(), 1_000_000, 0)
        .await
        .expect("list clamped");
    assert!(
        clamped.len() <= MAX_LIST_LIMIT as usize,
        "list must clamp; got {} > {}",
        clamped.len(),
        MAX_LIST_LIMIT,
    );

    // 6. UNIQUE constraint surfaces DuplicateName.
    let dup_err = store
        .insert(NewInspectionRule {
            tenant_id: &tenant_a,
            inspector: InspectorKind::Pii,
            name: "acme-employee-id",
            config: &json!({}),
            applies_to: &json!({}),
            enabled: true,
        })
        .await
        .expect_err("dup insert must fail");
    assert!(
        matches!(dup_err, RuleError::DuplicateName),
        "expected DuplicateName, got {dup_err:?}",
    );

    // Delete cleanly.
    assert!(store.delete(&tenant_a, r1.id).await.expect("delete r1"));
    assert!(store.delete(&tenant_a, r2.id).await.expect("delete r2"));

    // Cleanup tenants.
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}
