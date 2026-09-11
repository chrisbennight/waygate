//! Live Postgres smoke for the SCIM soft-delete tombstone.
//!
//! Skips when `AUDIT_DATABASE_URL` is unset so a laptop `cargo test`
//! passes without a DB; CI provisions Postgres and runs it.
//!
//! Pins the deprovisioning-gap fix: a DELETE soft-deletes (tombstone),
//! the resolver's tombstone-fallback resolves it as `active = false`
//! (so the request is blocked), SCIM reads 404 the tombstone, the same
//! userName/externalId can be re-provisioned, and a never-provisioned
//! `sub` stays a clean miss. Also exercises the retention sweep.

use std::env;
use std::time::Duration;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_core::TenantId;
use waygate_oidc::{AuthMethod, Principal, PrincipalEnricher};
use waygate_scim::{
    sweep_scim_tombstones, PgScimEnricher, PgScimGroupStore, PgScimResolver, PgScimUserStore,
    ScimGroupStore, ScimResolver, ScimUserStore,
};

fn principal(tenant: &str, sub: &str) -> Principal {
    Principal {
        sub: sub.to_owned(),
        email: None,
        groups: vec![],
        issuer: "https://idp.test/".into(),
        scopes: vec![],
        tenant: TenantId::parse(tenant).expect("tenant parse"),
        auth_method: AuthMethod::Oauth,
        raw_token: None,
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
        roles: vec![],
    }
}

async fn pool_or_skip() -> Option<sqlx::PgPool> {
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

#[tokio::test]
async fn soft_delete_blocks_via_tombstone_and_hides_from_reads() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("skipping pg tombstone smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let store = PgScimUserStore::new(pool.clone());
    let resolver = PgScimResolver::new(pool.clone());

    let tenant = format!("test-tomb-{}", Uuid::new_v4());
    let sub = format!("ext-{}", Uuid::new_v4());
    let user_name = format!("u-{}", Uuid::new_v4());

    let created = store
        .create(&tenant, Some(&sub), &user_name, true, json!({}))
        .await
        .expect("create live user");

    // Live: resolves active=true.
    let live = resolver
        .resolve(&tenant, &sub)
        .await
        .expect("resolve live")
        .expect("live user must resolve");
    assert!(live.active, "freshly created user must resolve active");

    // Soft-delete.
    assert!(
        store.delete(&tenant, created.id).await.expect("delete"),
        "first delete must report a row affected",
    );

    // Tombstone: resolver now resolves active=false (blocks the request).
    // This is the deprovisioning gap the tombstone closes — a hard
    // DELETE would make the resolver return None (treated active).
    let tomb = resolver
        .resolve(&tenant, &sub)
        .await
        .expect("resolve tombstone")
        .expect("deprovisioned user must still RESOLVE (as inactive) so the request is blocked");
    assert!(
        !tomb.active,
        "tombstoned user must resolve active=false so scim_blocks_request() blocks",
    );

    // SCIM read hides the tombstone (404 to the IdP).
    assert!(
        store.get(&tenant, created.id).await.expect("get").is_none(),
        "GET on a soft-deleted user must return None (404 to the SCIM client)",
    );

    // Re-delete is a no-op → false (RFC 7644 delete-missing → 404).
    assert!(
        !store.delete(&tenant, created.id).await.expect("re-delete"),
        "deleting an already-tombstoned row must report no rows affected",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn reprovision_after_delete_succeeds() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let store = PgScimUserStore::new(pool.clone());
    let resolver = PgScimResolver::new(pool.clone());

    let tenant = format!("test-reprov-{}", Uuid::new_v4());
    let sub = format!("ext-{}", Uuid::new_v4());
    let user_name = format!("u-{}", Uuid::new_v4());

    let first = store
        .create(&tenant, Some(&sub), &user_name, true, json!({}))
        .await
        .expect("create first");
    assert!(store.delete(&tenant, first.id).await.expect("delete first"));

    // Same userName + externalId must re-provision into a fresh live
    // row — the partial unique indexes (live-only) make the tombstone
    // invisible to the uniqueness constraint. Pre-fix this 409'd.
    let second = store
        .create(&tenant, Some(&sub), &user_name, true, json!({}))
        .await
        .expect("re-provision same userName/externalId must succeed (partial unique index)");
    assert_ne!(first.id, second.id, "re-provision mints a new row id");

    let live = resolver
        .resolve(&tenant, &sub)
        .await
        .expect("resolve")
        .expect("re-provisioned user must resolve");
    assert!(live.active, "re-provisioned user resolves active");
    assert_eq!(
        live.user_id, second.id,
        "resolves to the LIVE row, not the tombstone",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn never_provisioned_sub_is_clean_miss() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let resolver = PgScimResolver::new(pool.clone());
    let tenant = format!("test-miss-{}", Uuid::new_v4());
    let sub = format!("never-{}", Uuid::new_v4());
    let res = resolver.resolve(&tenant, &sub).await.expect("resolve");
    assert!(
        res.is_none(),
        "a sub with no live row and no tombstone must be a clean miss (treated active)",
    );
}

#[tokio::test]
async fn sweep_reclaims_old_tombstones_only() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let store = PgScimUserStore::new(pool.clone());
    let tenant = format!("test-sweep-{}", Uuid::new_v4());

    // A tombstone we backdate past the retention window.
    let old = store
        .create(
            &tenant,
            Some(&format!("old-{}", Uuid::new_v4())),
            &format!("old-{}", Uuid::new_v4()),
            true,
            json!({}),
        )
        .await
        .expect("create old");
    store.delete(&tenant, old.id).await.expect("delete old");
    sqlx::query("UPDATE scim_users SET deleted_at = now() - interval '40 days' WHERE id = $1")
        .bind(old.id)
        .execute(&pool)
        .await
        .expect("backdate tombstone");

    // A recent tombstone inside the window — must survive.
    let recent = store
        .create(
            &tenant,
            Some(&format!("rec-{}", Uuid::new_v4())),
            &format!("rec-{}", Uuid::new_v4()),
            true,
            json!({}),
        )
        .await
        .expect("create recent");
    store
        .delete(&tenant, recent.id)
        .await
        .expect("delete recent");

    // A live row — must never be swept.
    let live = store
        .create(
            &tenant,
            Some(&format!("live-{}", Uuid::new_v4())),
            &format!("live-{}", Uuid::new_v4()),
            true,
            json!({}),
        )
        .await
        .expect("create live");

    let reclaimed = sweep_scim_tombstones(&pool, Duration::from_secs(30 * 86_400))
        .await
        .expect("sweep");
    assert!(reclaimed >= 1, "the 40-day-old tombstone must be reclaimed");

    // Tenant-scoped count: only recent tombstone + live row survive.
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        remaining, 2,
        "recent tombstone + live row survive; only the old tombstone is swept",
    );
    assert!(
        store
            .get(&tenant, live.id)
            .await
            .expect("get live")
            .is_some(),
        "the live row must survive the sweep",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn tombstoned_user_drops_out_of_group_members() {
    // Soft-delete doesn't cascade
    // scim_user_groups (that FK only cascades on physical DELETE), so
    // PgScimGroupStore::members must filter deleted_at IS NULL or a
    // SCIM Group GET/LIST would keep rendering a deprovisioned user as
    // a member even though /scim/v2/Users/{id} is hidden.
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let users = PgScimUserStore::new(pool.clone());
    let groups = PgScimGroupStore::new(pool.clone());

    let tenant = format!("test-grp-{}", Uuid::new_v4());
    let sub = format!("ext-{}", Uuid::new_v4());
    let user = users
        .create(
            &tenant,
            Some(&sub),
            &format!("u-{}", Uuid::new_v4()),
            true,
            json!({}),
        )
        .await
        .expect("create user");
    let group = groups
        .create(
            &tenant,
            None,
            &format!("g-{}", Uuid::new_v4()),
            json!({}),
            &[user.id],
        )
        .await
        .expect("create group with member");

    // Live: the user appears in the group's member list.
    let before = groups
        .members(&tenant, group.id, "https://gw.test")
        .await
        .expect("members before");
    assert!(
        before.iter().any(|m| m.value == user.id.to_string()),
        "live user must appear in group members",
    );

    // Soft-delete the user.
    assert!(users.delete(&tenant, user.id).await.expect("delete user"));

    // Tombstoned: the user must no longer render as a group member.
    let after = groups
        .members(&tenant, group.id, "https://gw.test")
        .await
        .expect("members after");
    assert!(
        !after.iter().any(|m| m.value == user.id.to_string()),
        "soft-deleted user must NOT appear in group members",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup users");
    sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup groups");
}

#[tokio::test]
async fn invalidate_evicts_cached_active_after_soft_delete() {
    // Security: the bearer enricher caches a Hit
    // for 60s, so without cache eviction a just-deprovisioned principal
    // keeps passing until the TTL expires. The DELETE handler calls
    // PgScimEnricher::invalidate; this pins that the cached active entry
    // masks the tombstone until invalidated, and that invalidation makes
    // the block take effect immediately.
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let users = PgScimUserStore::new(pool.clone());
    let enricher = PgScimEnricher::new(pool.clone()); // production 60s TTL

    let tenant = format!("test-inval-{}", Uuid::new_v4());
    let sub = format!("ext-{}", Uuid::new_v4());
    let user = users
        .create(
            &tenant,
            Some(&sub),
            &format!("u-{}", Uuid::new_v4()),
            true,
            json!({}),
        )
        .await
        .expect("create");

    // Prime the cache: enrich resolves active and caches a Hit.
    let primed = enricher.enrich(principal(&tenant, &sub)).await;
    assert!(
        !primed.scim_blocks_request(),
        "active user must not be blocked"
    );
    assert!(
        primed.scim.as_ref().map(|s| s.active).unwrap_or(false),
        "active SCIM enrichment must be cached",
    );

    // Soft-delete in the DB (tombstone).
    assert!(users.delete(&tenant, user.id).await.expect("delete"));

    // Without invalidation the cached Hit still passes — the ≤60s gap.
    let stale = enricher.enrich(principal(&tenant, &sub)).await;
    assert!(
        !stale.scim_blocks_request(),
        "cached active entry masks the tombstone until evicted (the gap the fix closes)",
    );

    // Invalidate (what the DELETE handler does) → re-resolve hits the
    // tombstone-fallback → blocked immediately.
    enricher.invalidate(&tenant, &sub).await;
    let fresh = enricher.enrich(principal(&tenant, &sub)).await;
    assert!(
        fresh.scim_blocks_request(),
        "after invalidate, the deprovisioned principal must be blocked on the next request",
    );

    sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup");
}
