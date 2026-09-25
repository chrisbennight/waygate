//! Live Postgres tests for the per-principal completion cache
//! (`migrations/0050_llm_cache.sql` + `waygate_storage::llm_cache`).
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is unset. Uses a unique tenant and
//! cleans up its rows.

use std::env;
use std::time::Duration;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_storage::{
    cache_key, enforce_tenant_cap, get_cached, put_cached, sweep_expired_llm_cache, CacheEntry,
    PgAuditSink,
};

#[tokio::test]
async fn provider_cache_isolates_issuers_and_never_reuses_legacy_entries() {
    use waygate_evidence::cache::{CacheStoreRequest, LlmCache};
    let Some(pool) = waygate_test_support::pg::audit_pool_or_skip().await else {
        return;
    };
    let tenant = format!("cache-issuer-test-{}", Uuid::now_v7());
    let request = r#"{"model":"alias","messages":[]}"#;
    let cache = waygate_storage::PgLlmCache::new(pool.clone());
    let legacy_key = blake3::hash(&serde_json::to_vec(&(&tenant, Some("alice"), request)).unwrap())
        .to_hex()
        .to_string();
    put_cached(
        &pool,
        &CacheEntry {
            cache_key: legacy_key,
            tenant_id: tenant.clone(),
            principal_sub: Some("alice".into()),
            model_alias: "alias".into(),
            model_served: None,
            provider: "openrouter".into(),
            response_body: json!({"content": "ambiguous legacy owner"}),
            ttl: Duration::from_secs(3600),
        },
    )
    .await
    .unwrap();
    for issuer in ["issuer-a", "issuer-b"] {
        assert!(cache
            .get(request, &tenant, Some(issuer), Some("alice"))
            .await
            .is_none());
    }
    let body = json!({"content": "issuer-a response"});
    cache
        .put(CacheStoreRequest {
            canonical_request: request.into(),
            tenant_id: tenant.clone(),
            principal_issuer: Some("issuer-a".into()),
            principal_sub: Some("alice".into()),
            model_alias: "alias".into(),
            model_served: None,
            provider: "openrouter".into(),
            body: body.clone(),
            ttl: Duration::from_secs(3600),
        })
        .await;
    assert_eq!(
        cache
            .get(request, &tenant, Some("issuer-a"), Some("alice"))
            .await
            .unwrap()
            .body,
        body
    );
    assert!(cache
        .get(request, &tenant, Some("issuer-b"), Some("alice"))
        .await
        .is_none());
    assert!(cache.get(request, &tenant, None, None).await.is_none());
    sqlx::query("DELETE FROM llm_cache WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn cache_round_trips_is_per_principal_and_respects_ttl() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_cache test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    PgAuditSink::migrate(&pool).await.expect("migrate");
    let tenant = format!("cache-test-{}", Uuid::now_v7());

    let req = r#"{"model":"alias","messages":[{"role":"user","content":"hi"}]}"#;
    let alice_key = cache_key(req, &tenant, Some("issuer-a"), Some("alice"));
    let body = json!({
        "object": "chat.completion",
        "model": "served-x",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}]
    });

    // Miss before any put.
    assert!(get_cached(&pool, &alice_key).await.expect("get").is_none());

    // Put for alice → a hit returns the stored body + served model verbatim.
    put_cached(
        &pool,
        &CacheEntry {
            cache_key: alice_key.clone(),
            tenant_id: tenant.clone(),
            principal_sub: Some("alice".into()),
            model_alias: "alias".into(),
            model_served: Some("served-x".into()),
            provider: "openrouter".into(),
            response_body: body.clone(),
            ttl: Duration::from_secs(3600),
        },
    )
    .await
    .expect("put");

    let hit = get_cached(&pool, &alice_key)
        .await
        .expect("get")
        .expect("hit");
    assert_eq!(hit.model_served.as_deref(), Some("served-x"));
    assert_eq!(
        hit.provider.as_deref(),
        Some("openrouter"),
        "the serving provider round-trips for hit attribution"
    );
    assert_eq!(hit.response_body, body);

    // Bob's key for the SAME request differs → a cross-principal MISS. This is
    // the security guarantee: bob can never be served alice's completion.
    let bob_key = cache_key(req, &tenant, Some("issuer-a"), Some("bob"));
    assert_ne!(alice_key, bob_key);
    assert!(
        get_cached(&pool, &bob_key).await.expect("get").is_none(),
        "another principal's key must miss"
    );

    // A zero-TTL entry is already expired → never served (the read filters on
    // expires_at, so an expired-but-unswept row is invisible).
    let exp_key = cache_key(req, &tenant, Some("issuer-a"), Some("ephemeral"));
    put_cached(
        &pool,
        &CacheEntry {
            cache_key: exp_key.clone(),
            tenant_id: tenant.clone(),
            principal_sub: Some("ephemeral".into()),
            model_alias: "alias".into(),
            model_served: None,
            provider: "openrouter".into(),
            response_body: body.clone(),
            ttl: Duration::from_secs(0),
        },
    )
    .await
    .expect("put expired");
    assert!(
        get_cached(&pool, &exp_key).await.expect("get").is_none(),
        "an expired entry must not be served"
    );

    sqlx::query("DELETE FROM llm_cache WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn ttl_sweep_reclaims_expired_rows_and_spares_fresh_ones() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_cache sweep test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    PgAuditSink::migrate(&pool).await.expect("migrate");
    let tenant = format!("cache-sweep-{}", Uuid::now_v7());

    let body = json!({"object": "chat.completion", "choices": []});
    let mk = |sub: &str, ttl: Duration| CacheEntry {
        cache_key: cache_key(sub, &tenant, Some("issuer-a"), Some(sub)),
        tenant_id: tenant.clone(),
        principal_sub: Some(sub.to_string()),
        model_alias: "alias".into(),
        model_served: None,
        provider: "openrouter".into(),
        response_body: body.clone(),
        ttl,
    };

    // One already-expired row (ttl 0) and one fresh row (ttl 1h).
    let fresh_key = cache_key("fresh", &tenant, Some("issuer-a"), Some("fresh"));
    put_cached(&pool, &mk("expired", Duration::from_secs(0)))
        .await
        .expect("put expired");
    put_cached(&pool, &mk("fresh", Duration::from_secs(3600)))
        .await
        .expect("put fresh");

    // The sweep removes at least our expired row (the table is shared, so other
    // tenants' expired rows may be reclaimed too — assert on what we control).
    let deleted = sweep_expired_llm_cache(&pool, 1000).await.expect("sweep");
    assert!(deleted >= 1, "the sweep reclaimed the expired row");

    // The fresh row survives and is still served; ours is the durable check.
    let hit = get_cached(&pool, &fresh_key).await.expect("get");
    assert!(hit.is_some(), "a fresh row must survive the sweep");

    // A non-positive batch must terminate (clamped to 1), not loop forever —
    // the exported helper is hardened against a 0/negative batch. Returning at
    // all is the assertion; the COUNT is not one, because the sweep is
    // table-wide and a sibling test parked an already-expired row of its own in
    // the same table (each test runs in its own process, so they interleave).
    sweep_expired_llm_cache(&pool, 0)
        .await
        .expect("a zero batch must terminate, not hang");

    // What the sweep owes us, stated over rows we control: none of ours is
    // still reclaimable.
    let ours_expired: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM llm_cache WHERE tenant_id = $1 AND expires_at <= now()",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await
    .expect("count our unreclaimed rows");
    assert_eq!(
        ours_expired, 0,
        "every expired row of ours was reclaimed by the sweep"
    );

    sqlx::query("DELETE FROM llm_cache WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn tenant_cap_evicts_oldest_beyond_max() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping llm_cache cap test: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    PgAuditSink::migrate(&pool).await.expect("migrate");
    let tenant = format!("cache-cap-{}", Uuid::now_v7());

    let body = json!({"object": "chat.completion", "choices": []});
    let put = |sub: &'static str| {
        let pool = pool.clone();
        let tenant = tenant.clone();
        let body = body.clone();
        async move {
            put_cached(
                &pool,
                &CacheEntry {
                    cache_key: cache_key(sub, &tenant, Some("issuer-a"), Some(sub)),
                    tenant_id: tenant.clone(),
                    principal_sub: Some(sub.to_string()),
                    model_alias: "alias".into(),
                    model_served: None,
                    provider: "openrouter".into(),
                    response_body: body,
                    ttl: Duration::from_secs(3600),
                },
            )
            .await
            .expect("put");
        }
    };

    // Insert three entries in order; sequential statements get strictly
    // increasing `created_at`, so k1 is the oldest.
    put("k1").await;
    put("k2").await;
    put("k3").await;

    // Cap the tenant at 2 → the oldest (k1) is evicted; the newest two survive.
    let evicted = enforce_tenant_cap(&pool, &tenant, 2).await.expect("cap");
    assert_eq!(
        evicted, 1,
        "exactly the one over-cap (oldest) row is evicted"
    );

    let k1 = cache_key("k1", &tenant, Some("issuer-a"), Some("k1"));
    let k2 = cache_key("k2", &tenant, Some("issuer-a"), Some("k2"));
    let k3 = cache_key("k3", &tenant, Some("issuer-a"), Some("k3"));
    assert!(
        get_cached(&pool, &k1).await.expect("get").is_none(),
        "the oldest entry is evicted by the cap"
    );
    assert!(
        get_cached(&pool, &k2).await.expect("get").is_some(),
        "the second-newest survives"
    );
    assert!(
        get_cached(&pool, &k3).await.expect("get").is_some(),
        "the newest survives"
    );

    // Re-running at/under the live count is a no-op.
    let again = enforce_tenant_cap(&pool, &tenant, 2).await.expect("cap");
    assert_eq!(again, 0, "no eviction when already at the cap");

    sqlx::query("DELETE FROM llm_cache WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}
