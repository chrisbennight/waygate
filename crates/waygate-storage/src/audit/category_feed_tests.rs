use super::{AuditReader, PgAuditSink, PgPoolOptions, RECENT_BY_CATEGORY_SQL};
use serde_json::Value;
use uuid::Uuid;

#[tokio::test]
async fn category_feed_uses_bounded_index_scans_and_preserves_results() {
    let Some(migrated) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    // A dedicated connection keeps the temporary table private to this test.
    // Copy the migrated indexes so removing the migration breaks the plan check.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*migrated.connect_options()).clone())
        .await
        .expect("connect isolated fixture");
    sqlx::raw_sql(
        r#"
        CREATE TEMP TABLE audit_log (LIKE public.audit_log INCLUDING ALL);
        INSERT INTO audit_log (id, ts, tenant_id, category, action, outcome)
        SELECT lpad(to_hex(n), 32, '0')::uuid,
               now() - n * interval '1 second',
               CASE WHEN n % 2 = 0 THEN 'home' ELSE 'foreign' END,
               CASE WHEN n <= 20 THEN 'manifest_reload' ELSE 'invocation' END,
               'fixture', 'success'
        FROM generate_series(1, 20000) AS n;
        ANALYZE audit_log;
        "#,
    )
    .execute(&pool)
    .await
    .expect("seed isolated audit history");

    let sink = PgAuditSink::with_pool(pool.clone());
    let rows = sink
        .recent_by_category("home", "manifest_reload", 5)
        .await
        .expect("read rare category");
    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        [20, 18, 16, 14, 12].map(Uuid::from_u128),
        "newest IDs in the requested tenant/category, regardless of timestamp order"
    );
    assert!(rows
        .iter()
        .all(|row| row.tenant_id == "home" && row.category.as_deref() == Some("manifest_reload")));
    assert!(sink
        .recent_by_category("home", "absent", 5)
        .await
        .expect("read absent category")
        .is_empty());
    assert_eq!(
        sink.recent_by_category("home", "manifest_reload", 0)
            .await
            .expect("minimum limit")
            .len(),
        1
    );
    assert_eq!(
        sink.recent_by_category("home", "invocation", i64::MAX)
            .await
            .expect("maximum limit")
            .len(),
        500
    );

    // A retained statement can switch to a generic plan based on the common
    // category and then scan unrelated history when asked for a rare one.
    for category in ["invocation", "manifest_reload", "absent"].repeat(3) {
        sink.recent_by_category("home", category, 5)
            .await
            .expect("repeat feed with skewed categories");
    }
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_prepared_statements WHERE statement = $1")
            .bind(RECENT_BY_CATEGORY_SQL)
            .fetch_one(&pool)
            .await
            .expect("inspect statement lifetime");
    assert_eq!(
        retained, 0,
        "feed must not accumulate a reusable generic plan"
    );

    // Explain the same SQL the reader executes. Only this compile-time constant
    // is composed into PREPARE; tenant/category values remain bound parameters.
    sqlx::QueryBuilder::<sqlx::Postgres>::new("PREPARE category_feed(text, text, bigint) AS ")
        .push(RECENT_BY_CATEGORY_SQL)
        .build()
        .execute(&pool)
        .await
        .expect("prepare production query");
    {
        let mode = "SET plan_cache_mode = force_custom_plan";
        sqlx::raw_sql(mode).execute(&pool).await.expect("plan mode");
        for query in [
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE category_feed('home', 'manifest_reload', 5)",
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE category_feed('home', 'absent', 5)",
        ] {
            let explain: Value = sqlx::query_scalar(query)
                .fetch_one(&pool)
                .await
                .expect("explain category feed");
            let limit = &explain[0]["Plan"];
            assert_eq!(limit["Node Type"], "Limit", "{mode}: {explain}");
            let child = &limit["Plans"][0];
            // With custom statistics PostgreSQL may prove an absent category
            // empty through the smaller category index and sort that empty set.
            // That is bounded work, not the unrelated-history scan we prevent.
            if child["Node Type"] == "Sort" {
                assert_eq!(child["Actual Rows"], 0, "{mode}: {explain}");
                let scan = &child["Plans"][0];
                assert_eq!(scan["Node Type"], "Index Scan", "{mode}: {explain}");
                assert_eq!(scan["Actual Rows"], 0, "{mode}: {explain}");
                assert_eq!(scan["Rows Removed by Filter"], 0, "{mode}: {explain}");
                assert!(scan["Index Cond"].as_str().expect("category seek").contains("category"));
                continue;
            }
            let scan = child;
            assert_eq!(scan["Node Type"], "Index Scan", "{mode}: {explain}");
            let condition = scan["Index Cond"]
                .as_str()
                .unwrap_or_else(|| panic!("index condition missing: {mode}: {explain}"));
            assert!(condition.contains("tenant_id") && condition.contains("category"));
            assert!(scan.get("Filter").is_none(), "{mode}: {explain}");
            assert!(scan["Actual Rows"].as_u64().expect("row count") <= 5);
            assert!(scan.get("Plans").is_none(), "no sorting or subsidiary scan");
        }
    }
    pool.close().await;
}
