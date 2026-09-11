use uuid::Uuid;
use waygate_admin::tenants::{PgTenantLifecycleStore, TenantLifecycleStore};

#[tokio::test]
async fn tenant_and_policy_bundles_commit_or_fail_together() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("test-tenant-atomic-delete-{}", Uuid::new_v4());
    let bundle_id = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants (id, display_name, status) VALUES ($1, $1, 'active')")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed tenant");
    sqlx::query(
        r#"INSERT INTO policy_bundles
           (id, tenant_id, version, status, content, content_hash)
           VALUES ($1, $2, 1, 'draft', 'forbid(principal, action, resource);', 'test')"#,
    )
    .bind(bundle_id)
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed tenant policy bundle");

    // A referencing fixture makes deletion fail deterministically. No second
    // transaction or server-speed deadline participates in the assertion.
    // The SQL identifier contains only this literal prefix and generated UUID
    // hex digits; tenant values remain bound parameters.
    let blocker = format!("tenant_delete_blocker_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE {blocker} (tenant_id TEXT REFERENCES tenants(id) ON DELETE RESTRICT)"
    )))
    .execute(&pool)
    .await
    .expect("create isolated deletion blocker");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {blocker} (tenant_id) VALUES ($1)"
    )))
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("block tenant deletion");
    let store = PgTenantLifecycleStore::new(pool.clone());
    let waygate_tenants::TenantError::Sqlx(error) = store
        .delete_with_policy_bundles(&tenant)
        .await
        .expect_err("referenced tenant cannot be deleted")
    else {
        panic!("expected the database constraint failure");
    };
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some(waygate_core::store::FOREIGN_KEY_VIOLATION),
    );

    let tenant_count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants WHERE id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count tenant after failed delete");
    let bundle_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM policy_bundles WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("count bundle after failed delete");
    assert_eq!((tenant_count, bundle_count), (1, 1));

    sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {blocker}")))
        .execute(&pool)
        .await
        .expect("remove deletion blocker");
    let outcome = store
        .delete_with_policy_bundles(&tenant)
        .await
        .expect("atomic tenant delete");
    assert!(outcome.tenant_deleted);
    assert_eq!(outcome.policy_bundles_deleted, 1);

    let tenant_count: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants WHERE id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count tenant after committed delete");
    let bundle_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM policy_bundles WHERE tenant_id = $1")
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("count bundle after committed delete");
    assert_eq!((tenant_count, bundle_count), (0, 0));

    let orphan_insert = sqlx::query(
        r#"INSERT INTO policy_bundles
           (id, tenant_id, version, status, content, content_hash)
           VALUES ($1, $2, 2, 'draft', 'forbid(principal, action, resource);', 'test')"#,
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect_err("policy bundle insert must require a current tenant");
    assert_eq!(
        orphan_insert
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some(waygate_core::store::FOREIGN_KEY_VIOLATION),
    );
}
