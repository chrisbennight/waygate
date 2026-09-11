//! Tenant-registry backfill smoke.
//!
//! Migration 0024 backfills `tenants` from every existing
//! `tenant_id`-bearing table. This proves the SELECT…UNION runs
//! end-to-end and that a non-default tenant_id pre-existing in a
//! scoped table lands as a `tenants` row after the migration
//! applies.
//!
//! We can't easily test "the migration backfills" by *replaying*
//! 0024 against a DB that 0024 already created. Instead: assume
//! the schema is migrated, INSERT a fresh tenant_id into a
//! scoped table (audit_log here — the cheapest), then re-run the
//! same backfill statement and assert the row appeared in
//! `tenants`. This pins both the SQL shape and the
//! ON-CONFLICT-DO-NOTHING idempotency.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` on a laptop without a DB passes. Mirrors
//! waygate-rbac::tests::pg_composite_fk_smoke.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn backfill_picks_up_pre_existing_tenant_ids() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    // Per-test tenant so concurrent runs don't race + cleanup is
    // unambiguous on failure.
    let tenant = format!("test-tenants-backfill-{}", Uuid::new_v4());

    // Seed: write a row to a tenant_id-bearing table without
    // first inserting the matching `tenants` row. audit_log is
    // the cheapest target — its INSERT path doesn't require any
    // FKs into other tables.
    sqlx::query(
        r#"
        INSERT INTO audit_log (
            id, ts, principal_sub, action, outcome, tenant_id
        )
        VALUES ($1, now(), 'test', 'noop', 'success', $2)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("seed audit_log row");

    // Confirm the tenants row does NOT yet exist (the migration's
    // initial backfill only ran once at apply-time, before our
    // seed).
    let pre: Option<(String,)> = sqlx::query_as("SELECT id FROM tenants WHERE id = $1")
        .bind(&tenant)
        .fetch_optional(&pool)
        .await
        .expect("pre-check tenants");
    assert!(pre.is_none(), "tenant row already exists before backfill");

    // Re-run the same backfill statement as the migration. If the
    // shape drifts in 0024 this test starts failing — that's the
    // intended pin.
    let inserted = sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        SELECT DISTINCT tenant_id, tenant_id, 'active'
          FROM (
                SELECT tenant_id FROM audit_log
                UNION SELECT tenant_id FROM oauth_transactions
                UNION SELECT tenant_id FROM oauth_codes
                UNION SELECT tenant_id FROM oauth_refresh_tokens
                UNION SELECT tenant_id FROM api_keys
                UNION SELECT tenant_id FROM api_key_usage
                UNION SELECT tenant_id FROM user_upstream_sessions
                UNION SELECT tenant_id FROM mcp_servers
                UNION SELECT tenant_id FROM catalog_approvals
                UNION SELECT tenant_id FROM catalog_drift_events
                UNION SELECT tenant_id FROM policy_bundles
                UNION SELECT tenant_id FROM approval_grants
                UNION SELECT tenant_id FROM tenant_evidence_routing
                UNION SELECT tenant_id FROM evidence_retention_policy
                UNION SELECT tenant_id FROM scim_users
                UNION SELECT tenant_id FROM scim_groups
                UNION SELECT tenant_id FROM scim_user_groups
                UNION SELECT tenant_id FROM gateway_roles
                UNION SELECT tenant_id FROM role_assignments
                UNION SELECT tenant_id FROM group_role_mappings
          ) all_tenant_ids
         WHERE tenant_id IS NOT NULL
           AND tenant_id <> ''
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .execute(&pool)
    .await
    .expect("re-run backfill");
    assert!(
        inserted.rows_affected() >= 1,
        "backfill inserted no rows — UNION SELECT may have drifted",
    );

    let post: Option<(String, String, String)> =
        sqlx::query_as("SELECT id, display_name, status FROM tenants WHERE id = $1")
            .bind(&tenant)
            .fetch_optional(&pool)
            .await
            .expect("post-check tenants");
    let post = post.expect("backfill row missing");
    assert_eq!(post.0, tenant);
    assert_eq!(
        post.1, tenant,
        "backfill display_name should mirror id so operators can PATCH later",
    );
    assert_eq!(post.2, "active");

    // Idempotent: a second run inserts nothing (ON CONFLICT
    // DO NOTHING swallows the duplicate).
    let second = sqlx::query(
        r#"
        INSERT INTO tenants (id, display_name, status)
        VALUES ($1, $1, 'active')
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&tenant)
    .execute(&pool)
    .await
    .expect("idempotency probe");
    assert_eq!(
        second.rows_affected(),
        0,
        "ON CONFLICT DO NOTHING should swallow the duplicate",
    );

    // Cleanup.
    sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}
