use super::SQL;
use crate::audit::{AuditReader, PgAuditSink};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn notable_feed_selects_latest_timestamps_before_limiting_with_bounded_plans() {
    let Some(migrated) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*migrated.connect_options()).clone())
        .await
        .expect("isolated connection");
    // Copy actual migrated indexes into a connection-local fixture. IDs run in
    // the opposite direction to timestamps, and excluded rows outnumber a page.
    sqlx::raw_sql(
        r#"
        CREATE TEMP TABLE audit_log (LIKE public.audit_log INCLUDING ALL);
        INSERT INTO audit_log (id, ts, tenant_id, category, action, outcome, reason)
        SELECT lpad(to_hex(n), 32, '0')::uuid,
               to_timestamp(1700000000) - n * interval '1 second',
               CASE WHEN n % 2 = 0 THEN 'home' ELSE 'foreign' END,
               'invocation', 'fixture',
               CASE WHEN n > 5000 OR n % 5 = 0 THEN 'success' ELSE 'denied' END,
               CASE WHEN n % 7 = 0 THEN 'pre_call' ELSE NULL END
        FROM generate_series(1, 20000) AS n;
        INSERT INTO audit_log (id, ts, tenant_id, category, action, outcome)
        SELECT lpad(to_hex(n), 32, '0')::uuid, to_timestamp(1700000000),
               'home', 'invocation', 'fixture', 'execution_error'
        FROM unnest(ARRAY[0, 20001]) AS n;
        ANALYZE audit_log;
        "#,
    )
    .execute(&pool)
    .await
    .expect("seed history");
    let sink = PgAuditSink::with_pool(pool.clone());
    let newest = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let since = newest - Duration::seconds(100);
    let rows = sink.recent_notable("home", since, 5).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        [20001, 0, 2, 4, 6].map(Uuid::from_u128),
        "timestamp order selects the page; equal timestamps use descending ID"
    );
    let all = sink.recent_notable("home", since, 500).await.unwrap();
    assert!(all.len() > rows.len());
    assert!(all.iter().all(|r| r.tenant_id == "home"
        && r.ts >= since
        && r.outcome != "success"
        && r.reason.as_deref() != Some("pre_call")));
    assert!(all
        .windows(2)
        .all(|r| (r[0].ts, r[0].id) > (r[1].ts, r[1].id)));
    assert_eq!(
        sink.recent_notable("home", newest, 500)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(sink
        .recent_notable("absent", since, 5)
        .await
        .unwrap()
        .is_empty());
    assert!(sink
        .recent_notable("home", newest + Duration::seconds(1), 5)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        sink.recent_notable("home", since, 0).await.unwrap().len(),
        1
    );
    assert_eq!(
        sink.recent_notable("home", newest - Duration::days(1), i64::MAX)
            .await
            .unwrap()
            .len(),
        500
    );

    sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "PREPARE notable_feed(text, timestamptz, bigint) AS ",
    )
    .push(SQL)
    .build()
    .execute(&pool)
    .await
    .unwrap();
    for mode in [
        "SET plan_cache_mode = force_custom_plan",
        "SET plan_cache_mode = force_generic_plan",
    ] {
        sqlx::raw_sql(mode).execute(&pool).await.unwrap();
        for query in [
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE notable_feed('home', to_timestamp(1699999900), 5)",
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE notable_feed('absent', to_timestamp(1699999900), 5)",
        ] {
            let explain: Value = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
            let limit = &explain[0]["Plan"];
            assert_eq!(limit["Node Type"], "Limit", "{mode}: {explain}");
            let scan = &limit["Plans"][0];
            assert_eq!(scan["Node Type"], "Index Scan", "{mode}: {explain}");
            let condition = scan["Index Cond"].as_str().expect("bounded index condition");
            assert!(condition.contains("tenant_id") && condition.contains("ts"));
            assert!(scan.get("Filter").is_none(), "{mode}: {explain}");
            assert!(scan.get("Plans").is_none(), "no sort or subsidiary scan: {explain}");
            assert!(scan["Actual Rows"].as_u64().unwrap() <= 5, "{explain}");
        }
    }
    pool.close().await;
}
