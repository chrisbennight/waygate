use super::*;
use crate::audit::{AuditReader, PgAuditSink};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;

async fn fixture() -> Option<PgPool> {
    let migrated = waygate_test_support::pg::audit_pool_or_skip().await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*migrated.connect_options()).clone())
        .await
        .unwrap();
    sqlx::raw_sql(
        r#"
        CREATE TEMP TABLE audit_log (LIKE public.audit_log INCLUDING ALL);
        INSERT INTO audit_log
            (id, ts, tenant_id, category, action, outcome, principal_sub,
             principal_email, server, risk_level, pii, policy_ids, reason)
        SELECT lpad(to_hex(n), 32, '0')::uuid,
               to_timestamp(1700000000) - n * interval '1 second',
               CASE WHEN n % 2 = 0 THEN 'home' ELSE 'foreign' END,
               CASE WHEN n % 3 = 0 THEN NULL ELSE 'invocation' END,
               'fixture', 'denied',
               CASE WHEN n = 2 THEN 'service:rare%_suffix' ELSE 'service:common' END,
               CASE WHEN n = 4 THEN 'rare%_email@example.test' ELSE NULL END,
               'fixture', 'low', false, ARRAY['fixture-policy'], NULL
        FROM generate_series(1, 20000) AS n;
        ANALYZE audit_log;
        SET plan_cache_mode = force_generic_plan;
        SET statement_timeout = 0;
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    Some(pool)
}

fn query(principal: &str) -> AuditQuery {
    AuditQuery {
        tenant_id: Some("home".to_owned()),
        principal_substr: Some(principal.to_owned()),
        since: Some(OffsetDateTime::from_unix_timestamp(1_699_999_900).unwrap()),
        ..Default::default()
    }
}

#[tokio::test]
async fn bounded_rows_preserve_filters_cursors_and_connection_settings() {
    let Some(pool) = fixture().await else { return };
    let sink = PgAuditSink::with_pool(pool.clone());
    let mut q = query("rare%_");
    q.server = Some("fixture".to_owned());
    q.outcome = Some("denied".to_owned());
    q.outcome_ne = Some("success".to_owned());
    q.risk_level = Some("low".to_owned());
    q.category = Some("invocation".to_owned());
    q.categories = vec!["invocation".to_owned()];
    q.pii = Some(false);
    q.policy_id = Some("fixture-policy".to_owned());
    q.reason_ne = Some("pre_call".to_owned());
    q.until = Some(OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap());
    let before_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let rows = sink
        .query_events_bounded(&q, 60, None, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        [4, 2].map(Uuid::from_u128)
    );
    assert!(rows.iter().all(|r| q.matches(r)));
    // IDs increase while timestamps decrease in this fixture.
    assert!(rows[0].ts < rows[1].ts);
    let page = sink
        .query_events_bounded(&q, 1, Some(rows[0].id), Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(page[0].id, rows[1].id);
    for principal in ["absent", "rareXX", "RARE%_"] {
        assert!(sink
            .query_events_bounded(&query(principal), 60, None, Duration::from_secs(60))
            .await
            .unwrap()
            .is_empty());
    }
    q.principal_substr = Some("common".to_owned());
    let expected = sink.query_events(&q, 60, None).await.unwrap();
    let actual = sink
        .query_events_bounded(&q, 60, None, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        actual.iter().map(|r| r.id).collect::<Vec<_>>(),
        expected.iter().map(|r| r.id).collect::<Vec<_>>()
    );
    assert!(actual.iter().all(|r| q.matches(r)));
    // Exercise rejection by each categorical predicate against otherwise matching rows.
    let base = q.clone();
    let mut rejected = Vec::new();
    q.server = Some("absent".to_owned());
    rejected.push(q);
    q = base.clone();
    q.outcome = Some("success".to_owned());
    rejected.push(q);
    q = base.clone();
    q.outcome_ne = Some("denied".to_owned());
    rejected.push(q);
    q = base.clone();
    q.risk_level = Some("high".to_owned());
    rejected.push(q);
    q = base.clone();
    q.category = Some("admin_mutation".to_owned());
    rejected.push(q);
    q = base.clone();
    q.categories = vec!["admin_mutation".to_owned()];
    rejected.push(q);
    q = base.clone();
    q.pii = Some(true);
    rejected.push(q);
    q = base.clone();
    q.policy_id = Some("absent".to_owned());
    rejected.push(q);
    q = base.clone();
    q.tenant_id = Some("absent".to_owned());
    rejected.push(q);
    q = base.clone();
    q.tool = Some("absent".to_owned());
    rejected.push(q);
    q = base.clone();
    q.reason = Some("absent".to_owned());
    rejected.push(q);
    q = base.clone();
    q.trace_id = Some("absent".to_owned());
    rejected.push(q);
    for q in rejected {
        assert!(sink
            .query_events_bounded(&q, 60, None, Duration::from_secs(60))
            .await
            .unwrap()
            .is_empty());
    }
    let (pid, timeout, mode): (i32, String, String) = sqlx::query_as(
        "SELECT pg_backend_pid(), current_setting('statement_timeout'), current_setting('plan_cache_mode')"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(pid, before_pid, "successful reads reuse their connection");
    assert_eq!(timeout, "0");
    assert_eq!(mode, "force_generic_plan");
    pool.close().await;
}

fn inspect_plan(node: &Value, found_time_bound: &mut bool) {
    if node["Relation Name"] == "audit_log" {
        let condition = node["Index Cond"]
            .as_str()
            .expect("audit scan must use an index condition");
        assert!(
            condition.contains("tenant_id") && condition.contains("ts"),
            "{node}"
        );
        let visited = node["Actual Rows"].as_u64().unwrap_or(0)
            + node["Rows Removed by Filter"].as_u64().unwrap_or(0);
        assert!(visited <= 100, "out-of-window history was scanned: {node}");
        *found_time_bound = true;
    }
    if let Some(children) = node["Plans"].as_array() {
        for child in children {
            inspect_plan(child, found_time_bound);
        }
    }
}

#[tokio::test]
async fn bounded_principal_plan_does_not_scan_old_history() {
    let Some(pool) = fixture().await else { return };
    sqlx::raw_sql("SET plan_cache_mode=force_custom_plan; SET random_page_cost=1.1; SET jit=off")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::QueryBuilder::<Postgres>::new("PREPARE observer_rows AS ")
        .push(sql(&query("rare%_"), true))
        .build()
        .execute(&pool)
        .await
        .unwrap();
    for statement in [
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE observer_rows (NULL,NULL,NULL,NULL,'rare%_',NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,NULL,NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE observer_rows (NULL,NULL,NULL,NULL,'absent',NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,NULL,NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE observer_rows (NULL,NULL,NULL,NULL,'common',NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,NULL,NULL)",
    ] {
        let plan: Value = sqlx::query_scalar(statement).fetch_one(&pool).await.unwrap();
        let mut found_time_bound = false;
        inspect_plan(&plan[0]["Plan"], &mut found_time_bound);
        assert!(found_time_bound, "missing audit scan: {plan}");
    }
    pool.close().await;
}

/// Marks three in-window rows of the fixture tenant with a tool, refusal
/// reason, and trace id; every other row keeps NULL in those columns.
async fn mark_refusals(pool: &PgPool) {
    sqlx::raw_sql(
        r#"
        UPDATE audit_log
           SET tool = 'send', reason = 'refused:server_quarantined', trace_id = 'trace-a'
         WHERE id IN (lpad(to_hex(2), 32, '0')::uuid, lpad(to_hex(4), 32, '0')::uuid);
        UPDATE audit_log
           SET tool = 'send', reason = 'refused:drift_quarantined', trace_id = 'trace-b'
         WHERE id = lpad(to_hex(6), 32, '0')::uuid;
        ANALYZE audit_log;
        "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

fn window() -> AuditQuery {
    AuditQuery {
        tenant_id: Some("home".to_owned()),
        since: Some(OffsetDateTime::from_unix_timestamp(1_699_999_900).unwrap()),
        ..Default::default()
    }
}

#[tokio::test]
async fn exact_tool_reason_and_trace_filters_select_only_matching_rows() {
    let Some(pool) = fixture().await else { return };
    mark_refusals(&pool).await;
    let sink = PgAuditSink::with_pool(pool.clone());
    let ids = |rows: &[AuditRow]| rows.iter().map(|r| r.id).collect::<Vec<_>>();
    let cases = [
        (
            AuditQuery {
                tool: Some("send".to_owned()),
                ..window()
            },
            vec![6, 4, 2],
        ),
        (
            AuditQuery {
                reason: Some("refused:server_quarantined".to_owned()),
                ..window()
            },
            vec![4, 2],
        ),
        (
            AuditQuery {
                trace_id: Some("trace-b".to_owned()),
                ..window()
            },
            vec![6],
        ),
        (
            AuditQuery {
                tool: Some("send".to_owned()),
                reason: Some("refused:server_quarantined".to_owned()),
                trace_id: Some("trace-a".to_owned()),
                ..window()
            },
            vec![4, 2],
        ),
        (
            AuditQuery {
                reason: Some("refused:server".to_owned()),
                ..window()
            },
            vec![],
        ),
        (
            AuditQuery {
                trace_id: Some("trace-a".to_owned()),
                tenant_id: Some("foreign".to_owned()),
                ..window()
            },
            vec![],
        ),
    ];
    for (q, expected) in cases {
        let expected: Vec<Uuid> = expected.into_iter().map(Uuid::from_u128).collect();
        let bounded = sink
            .query_events_bounded(&q, 60, None, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(ids(&bounded), expected, "bounded read for {q:?}");
        assert!(bounded.iter().all(|r| q.matches(r)), "{q:?}");
        let unbounded = sink.query_events(&q, 60, None).await.unwrap();
        assert_eq!(ids(&unbounded), expected, "dashboard read for {q:?}");
    }

    // The Activity aggregates apply the same predicates as the rows.
    let refused = AuditQuery {
        reason: Some("refused:server_quarantined".to_owned()),
        ..window()
    };
    let stats = sink.tool_stats(&refused, 10).await.unwrap();
    assert_eq!(stats.len(), 1, "{stats:?}");
    assert_eq!(
        (
            stats[0].server.as_str(),
            stats[0].tool.as_str(),
            stats[0].total
        ),
        ("fixture", "send", 2)
    );
    let traced = AuditQuery {
        trace_id: Some("trace-b".to_owned()),
        ..window()
    };
    let buckets = sink.histogram(&traced, 3600).await.unwrap();
    assert_eq!(buckets.iter().map(|b| b.count).sum::<i64>(), 1);
    let rollup = sink.rollup_tool_stats(&refused, 10).await.unwrap();
    assert_eq!(
        rollup.iter().map(|s| s.total).sum::<i64>(),
        2,
        "a reason filter must not be dropped by the rollup reader"
    );
    pool.close().await;
}

/// The new exact-match filters have no index of their own. Within a time
/// window the tenant timestamp index must bound the rows examined, whether or
/// not any row matches.
#[tokio::test]
async fn bounded_exact_filter_plans_do_not_scan_old_history() {
    let Some(pool) = fixture().await else { return };
    mark_refusals(&pool).await;
    sqlx::raw_sql("SET plan_cache_mode=force_custom_plan; SET random_page_cost=1.1; SET jit=off")
        .execute(&pool)
        .await
        .unwrap();
    let mut q = window();
    q.trace_id = Some("trace-a".to_owned());
    sqlx::QueryBuilder::<Postgres>::new("PREPARE exact_rows AS ")
        .push(sql(&q, true))
        .build()
        .execute(&pool)
        .await
        .unwrap();
    // Parameters $16, $17, and $18 are the tool, reason, and trace id.
    for statement in [
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,'send',NULL,NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,'absent',NULL,NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,'refused:server_quarantined',NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,'absent',NULL)",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,NULL,'trace-a')",
        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE exact_rows (NULL,NULL,NULL,NULL,NULL,NULL,to_timestamp(1699999900),NULL,NULL,60,'home',NULL,NULL,'{}'::text[],NULL,NULL,NULL,'absent')",
    ] {
        let plan: Value = sqlx::query_scalar(statement)
            .fetch_one(&pool)
            .await
            .unwrap();
        let mut found_time_bound = false;
        inspect_plan(&plan[0]["Plan"], &mut found_time_bound);
        assert!(found_time_bound, "missing audit scan: {plan}");
    }
    pool.close().await;
}

#[tokio::test]
async fn bounded_read_limits_pool_wait_and_preserves_held_connection() {
    let Some(pool) = fixture().await else { return };
    let held = pool.acquire().await.unwrap();
    let error = fetch_bounded(&pool, &query("rare"), 60, None, Duration::from_millis(10))
        .await
        .unwrap_err();
    assert!(matches!(error, AuditReadError::DeadlineExceeded));
    drop(held);
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    pool.close().await;
}

#[tokio::test]
async fn interrupted_read_retires_connection_and_releases_database_work() {
    let Some(migrated) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let schema = format!("audit_read_{}", Uuid::new_v4().simple());
    // Identifiers are generated locally, never derived from request input.
    sqlx::QueryBuilder::<Postgres>::new("CREATE SCHEMA ")
        .push(&schema)
        .build()
        .execute(&migrated)
        .await
        .unwrap();
    sqlx::QueryBuilder::<Postgres>::new("CREATE TABLE ")
        .push(&schema)
        .push(".audit_log (LIKE public.audit_log INCLUDING ALL)")
        .build()
        .execute(&migrated)
        .await
        .unwrap();
    let options = (*migrated.connect_options())
        .clone()
        .options([("search_path", schema.as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut lock = migrated.begin().await.unwrap();
    sqlx::QueryBuilder::<Postgres>::new("LOCK TABLE ")
        .push(&schema)
        .push(".audit_log IN ACCESS EXCLUSIVE MODE")
        .build()
        .execute(&mut *lock)
        .await
        .unwrap();
    let error = fetch_bounded(&pool, &query("rare"), 60, None, Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AuditReadError::DeadlineExceeded)
            || matches!(&error, AuditReadError::Database(sqlx::Error::Database(db)) if db.code().as_deref() == Some("57014"))
    );
    // Keep the lock held: success here proves pool recovery does not wait for
    // the blocked read to finish normally.
    let replacement: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(pid, replacement);
    loop {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                .bind(pid)
                .fetch_one(&migrated)
                .await
                .unwrap();
        if !exists {
            break;
        }
        tokio::task::yield_now().await;
    }
    lock.rollback().await.unwrap();

    let mut lock = migrated.begin().await.unwrap();
    sqlx::QueryBuilder::<Postgres>::new("LOCK TABLE ")
        .push(&schema)
        .push(".audit_log IN ACCESS EXCLUSIVE MODE")
        .build()
        .execute(&mut *lock)
        .await
        .unwrap();
    let reading_pool = pool.clone();
    let reading = tokio::spawn(async move {
        fetch_bounded(
            &reading_pool,
            &query("rare"),
            60,
            None,
            Duration::from_secs(60),
        )
        .await
    });
    // Observe the actual database wait before dropping the caller's future.
    loop {
        assert!(
            !reading.is_finished(),
            "read must wait for the held table lock"
        );
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
        )
        .bind(replacement)
        .fetch_one(&migrated)
        .await
        .unwrap();
        if waiting {
            break;
        }
        tokio::task::yield_now().await;
    }
    reading.abort();
    assert!(reading.await.unwrap_err().is_cancelled());
    let after_cancellation: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(replacement, after_cancellation);
    lock.rollback().await.unwrap();
    loop {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                .bind(replacement)
                .fetch_one(&migrated)
                .await
                .unwrap();
        if !exists {
            break;
        }
        tokio::task::yield_now().await;
    }
    let rows = fetch_bounded(&pool, &query("rare"), 60, None, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(rows.is_empty());
    pool.close().await;
    sqlx::QueryBuilder::<Postgres>::new("DROP SCHEMA ")
        .push(&schema)
        .push(" CASCADE")
        .build()
        .execute(&migrated)
        .await
        .unwrap();
}
