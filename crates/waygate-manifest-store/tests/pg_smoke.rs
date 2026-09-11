//! Live Postgres smoke test for [`PgManifestStore`]. Skips cleanly when
//! `AUDIT_DATABASE_URL` is unset, so CI and local `cargo test` runs
//! without a DB pass without special-casing (same convention as the
//! policy / audit / oauth-session smoke tests). When the var *is* set we
//! connect, apply migrations, exercise the create_draft → publish →
//! active_bundle → list_bundles → rollback lifecycle on a throwaway
//! tenant, and clean up after ourselves.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_manifest_store::{
    ManifestHistoryFilter, ManifestStatus, ManifestStore, PgManifestStore,
};

/// A minimal but valid manifest-set YAML document. The store treats
/// `content` as opaque text, but using a real upstream-manifest set
/// (rather than `permit(...)`-style policy text) keeps the smoke test
/// honest about what S1 actually stores.
fn manifest_set(name: &str, url: &str) -> String {
    format!("- name: {name}\n  transport: http\n  url: {url}\n")
}

#[tokio::test]
async fn manifest_bundle_lifecycle_round_trips() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping manifest Pg smoke: AUDIT_DATABASE_URL not set");
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

    // Unique tenant per run so concurrent / repeated runs don't collide
    // and cleanup is scoped to exactly our rows.
    let tenant = format!("pg-smoke-manifest-{}", Uuid::now_v7());
    let store = PgManifestStore::new(pool.clone());

    // No published bundle yet ⇒ active_bundle is NotFound.
    assert!(
        store.active_bundle(&tenant).await.is_err(),
        "fresh tenant has no active bundle",
    );

    // First draft → version 1, status draft, no publish stamp.
    let v1 = store
        .create_draft(
            &tenant,
            &manifest_set("example-messages", "http://example-messages/mcp"),
            Some("alice"),
        )
        .await
        .expect("create draft v1");
    assert_eq!(v1.version, 1);
    assert_eq!(v1.status, ManifestStatus::Draft);
    assert!(v1.published_at.is_none());

    // Second and third drafts → versions 2 and 3 (monotonic).
    let v2 = store
        .create_draft(
            &tenant,
            &manifest_set("example-mailbox", "http://example-mailbox/mcp"),
            Some("bob"),
        )
        .await
        .expect("create draft v2");
    assert_eq!(v2.version, 2);
    let v3 = store
        .create_draft(
            &tenant,
            &manifest_set("example-observability", "http://example-observability/mcp"),
            None,
        )
        .await
        .expect("create draft v3");
    assert_eq!(v3.version, 3);

    // Tenant scoping at the write boundary: publishing v3's id under a
    // DIFFERENT tenant must not match (NotFound) and must leave v3 a
    // draft — the real-tenant publish below then succeeds, proving the
    // cross-tenant attempt was a no-op.
    assert!(
        store
            .publish("some-other-tenant", v3.id, "mallory")
            .await
            .is_err(),
        "cross-tenant publish must not match another tenant's draft",
    );

    // Publish the HIGHEST version (v3) first → active.
    let pub_v3 = store
        .publish(&tenant, v3.id, "carol")
        .await
        .expect("publish v3");
    assert_eq!(pub_v3.status, ManifestStatus::Published);
    assert!(pub_v3.published_at.is_some());
    assert_eq!(pub_v3.published_by.as_deref(), Some("carol"));
    assert_eq!(
        store.active_bundle(&tenant).await.expect("active").version,
        3,
    );

    // Republishing the same row is a no-op error (it's no longer a
    // draft) — pins the conditional-UPDATE guard against double-stamp.
    assert!(
        store.publish(&tenant, v3.id, "carol").await.is_err(),
        "re-publishing a non-draft row must fail",
    );

    // The discriminating case: publish a LOWER version (v2) AFTER the
    // higher v3. Most-recently-published wins, so v2 — not the higher
    // v3 — becomes active. If selection were by version number this
    // would still report 3 and the assert fails.
    store
        .publish(&tenant, v2.id, "carol")
        .await
        .expect("publish v2");
    let active = store.active_bundle(&tenant).await.expect("active");
    assert_eq!(
        active.version, 2,
        "most-recently-published (v2) must win over higher-version v3",
    );
    assert_eq!(active.content_hash, v2.content_hash);

    // get() returns the full content for any version, scoped to tenant.
    let fetched = store.get(&tenant, v1.id).await.expect("get v1");
    assert_eq!(fetched.content, v1.content);
    assert!(
        store.get("some-other-tenant", v1.id).await.is_err(),
        "get is tenant-scoped",
    );

    // list_bundles returns all three, newest version first.
    let bundles = store.list_bundles(&tenant).await.expect("list");
    let versions: Vec<i32> = bundles.iter().map(|b| b.version).collect();
    assert_eq!(versions, vec![3, 2, 1]);

    // Candidate paging filters and limits in Postgres rather than loading the
    // tenant's complete immutable history into the caller.
    let drafts = store
        .list_bundles_page(&tenant, ManifestHistoryFilter::Draft, 1, 0)
        .await
        .expect("page drafts");
    assert_eq!(drafts.total, 1);
    assert_eq!(drafts.bundles[0].version, 1);
    let history = store
        .list_bundles_page(&tenant, ManifestHistoryFilter::PreviouslyPublished, 1, 1)
        .await
        .expect("page published history");
    assert_eq!(history.total, 2);
    assert_eq!(history.bundles.len(), 1);
    assert_eq!(history.bundles[0].version, 2);

    // Rollback to v3's content: re-published as a NEW version (4),
    // which becomes active and carries v3's content/hash. Append-only:
    // the original rows are untouched.
    let rolled = store
        .rollback_to(&tenant, 3, "dave")
        .await
        .expect("rollback to v3");
    assert_eq!(rolled.version, 4, "rollback creates a new version");
    assert_eq!(
        rolled.content_hash, v3.content_hash,
        "rolled-back bundle carries the target version's content",
    );
    assert_eq!(rolled.published_by.as_deref(), Some("dave"));
    assert_eq!(
        store.active_bundle(&tenant).await.expect("active").version,
        4,
        "the rolled-back copy is now active",
    );

    // Rolling back to a nonexistent version is NotFound.
    assert!(
        store.rollback_to(&tenant, 999, "dave").await.is_err(),
        "rollback to a missing version must fail",
    );

    // delete_all_for_tenant removes every row and reports the count.
    let deleted = store
        .delete_all_for_tenant(&tenant)
        .await
        .expect("delete all");
    assert_eq!(deleted, 4, "v1..v3 + the rollback copy = 4 rows");
    assert!(
        store.active_bundle(&tenant).await.is_err(),
        "tenant has no bundles after delete",
    );
}
