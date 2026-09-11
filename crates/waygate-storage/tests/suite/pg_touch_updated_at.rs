//! Live Postgres pin for migration 0071: the fourteen
//! `updated_at` triggers all execute the one shared `touch_updated_at()`
//! function, the twelve per-table copies are gone, and the bump behavior
//! still works. Skips cleanly when `AUDIT_DATABASE_URL` is unset (CI
//! provisions it); rows created here are deleted before the test ends.

use sqlx::Row;

#[tokio::test]
async fn all_touch_updated_at_triggers_share_the_generic_function() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    // Every `*_touch_updated_at_trg` trigger points at touch_updated_at().
    // Asserting over the catalog (not a hardcoded table list) keeps the
    // test valid as tables are added — the tripwire is a trigger of this
    // naming family wired to anything else.
    let rows = sqlx::query(
        "SELECT t.tgname, p.proname
           FROM pg_trigger t
           JOIN pg_proc p ON p.oid = t.tgfoid
          WHERE NOT t.tgisinternal
            AND t.tgname LIKE '%touch_updated_at_trg'",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog query");

    assert!(
        rows.len() >= 14,
        "expected at least the 14 repointed triggers, found {}",
        rows.len()
    );
    for row in &rows {
        let tgname: String = row.get("tgname");
        let proname: String = row.get("proname");
        assert_eq!(
            proname, "touch_updated_at",
            "trigger {tgname} executes {proname}, not the shared touch_updated_at()"
        );
    }
}

#[tokio::test]
async fn per_table_touch_functions_are_gone() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    // The generic function exists…
    let generic: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_proc WHERE proname = 'touch_updated_at'")
            .fetch_one(&pool)
            .await
            .expect("pg_proc query");
    assert_eq!(
        generic, 1,
        "shared touch_updated_at() must exist exactly once"
    );

    // …and no per-table `<table>_touch_updated_at` copy survived 0071.
    let stragglers: Vec<String> = sqlx::query_scalar(
        "SELECT proname FROM pg_proc
          WHERE proname LIKE '%touch_updated_at'
            AND proname <> 'touch_updated_at'",
    )
    .fetch_all(&pool)
    .await
    .expect("pg_proc query");
    assert!(
        stragglers.is_empty(),
        "per-table touch functions still present: {stragglers:?}"
    );
}

#[tokio::test]
async fn updated_at_still_advances_on_update() {
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };

    // Representative behavioral check on `tenants` (simplest of the 14 —
    // no FKs to satisfy). Unique id so concurrent suites can't collide.
    let id = format!("ws10b-{}", uuid::Uuid::now_v7().simple());
    sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("insert test tenant");

    let before: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM tenants WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read initial updated_at");

    // Separate transaction + a real clock step so now() must differ.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    sqlx::query("UPDATE tenants SET display_name = 'ws10b-renamed' WHERE id = $1")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("update test tenant");

    let after: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM tenants WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("read bumped updated_at");

    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&id)
        .execute(&pool)
        .await
        .expect("clean up test tenant");

    assert!(
        after > before,
        "updated_at did not advance: before={before}, after={after}"
    );
}
