//! Live Postgres smoke for `PgFederatedPeersStore`.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so
//! `cargo test` without a DB passes. Pins six behaviours
//! the JWKS refresher (a `list_all_for_refresh` consumer)
//! and the admin REST handlers depend on:
//!
//! 1. Insert → get round-trip; every field returned.
//! 2. Tenant scoping on get / update / delete.
//! 3. List filter combinations (peer_name / issuer /
//!    trust_tier).
//! 4. Update mutates + the `updated_at` trigger fires.
//! 5. `MAX_LIST_LIMIT` clamp.
//! 6. UNIQUE (tenant_id, peer_name) AND (tenant_id, issuer)
//!    each surface as `PeerError::DuplicateName`.

use std::env;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use waygate_federation::{
    FederatedPeersStore, NewFederatedPeer, PeerError, PeerFilter, PeerUpdate,
    PgFederatedPeersStore, TrustTier, MAX_LIST_LIMIT,
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
    let tenant_id = format!("pg-peers-{suffix}");
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
async fn peers_lifecycle_and_isolation() {
    let Some(pool) = connect().await else {
        eprintln!("skipping federated_peers Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let suffix = Uuid::new_v4().to_string();
    let tenant_a = seed_tenant(&pool, &suffix).await;
    let tenant_b = seed_tenant(&pool, &format!("b-{suffix}")).await;
    let store = PgFederatedPeersStore::new(pool.clone());

    // 1. Insert + get round-trip.
    let p1 = store
        .insert(NewFederatedPeer {
            tenant_id: &tenant_a,
            peer_name: "acme-prod",
            issuer: "https://gw.acme.example",
            jwks_url: "https://gw.acme.example/.well-known/jwks.json",
            trust_tier: TrustTier::Full,
        })
        .await
        .expect("insert p1");
    assert_eq!(p1.tenant_id, tenant_a);
    assert_eq!(p1.peer_name, "acme-prod");
    assert_eq!(p1.issuer, "https://gw.acme.example");
    assert_eq!(p1.trust_tier, TrustTier::Full);

    let fetched = store
        .get(&tenant_a, p1.id)
        .await
        .expect("get p1")
        .expect("p1 present");
    assert_eq!(fetched.id, p1.id);

    // 2. Tenant isolation.
    assert!(
        store
            .get(&tenant_b, p1.id)
            .await
            .expect("get cross")
            .is_none(),
        "tenant_b must not see tenant_a's peer"
    );
    assert!(
        !store.delete(&tenant_b, p1.id).await.expect("delete cross"),
        "tenant_b cannot delete tenant_a's peer"
    );
    let cross_update = store
        .update(
            &tenant_b,
            p1.id,
            PeerUpdate {
                peer_name: Some("hacked"),
                issuer: None,
                jwks_url: None,
                trust_tier: None,
            },
        )
        .await
        .expect("cross update");
    assert!(cross_update.is_none());

    // 3. List filter combinations. Seed a second peer
    //    (restricted trust tier, different issuer) in
    //    tenant_a so filters are meaningful.
    let p2 = store
        .insert(NewFederatedPeer {
            tenant_id: &tenant_a,
            peer_name: "globex-stg",
            issuer: "https://gw.globex.example",
            jwks_url: "https://gw.globex.example/.well-known/jwks.json",
            trust_tier: TrustTier::Restricted,
        })
        .await
        .expect("insert p2");

    let all = store
        .list(&tenant_a, PeerFilter::default(), 50, 0)
        .await
        .expect("list all");
    assert!(all.iter().any(|p| p.id == p1.id));
    assert!(all.iter().any(|p| p.id == p2.id));

    let by_name = store
        .list(
            &tenant_a,
            PeerFilter {
                peer_name: Some("acme-prod"),
                issuer: None,
                trust_tier: None,
            },
            50,
            0,
        )
        .await
        .expect("list by name");
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].id, p1.id);

    let by_issuer = store
        .list(
            &tenant_a,
            PeerFilter {
                peer_name: None,
                issuer: Some("https://gw.globex.example"),
                trust_tier: None,
            },
            50,
            0,
        )
        .await
        .expect("list by issuer");
    assert_eq!(by_issuer.len(), 1);
    assert_eq!(by_issuer[0].id, p2.id);

    let restricted_only = store
        .list(
            &tenant_a,
            PeerFilter {
                peer_name: None,
                issuer: None,
                trust_tier: Some(TrustTier::Restricted),
            },
            50,
            0,
        )
        .await
        .expect("list restricted");
    assert!(restricted_only.iter().any(|p| p.id == p2.id));
    assert!(!restricted_only.iter().any(|p| p.id == p1.id));

    // 4. Update mutates + bumps updated_at trigger.
    let pre_update = p1.updated_at;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let updated = store
        .update(
            &tenant_a,
            p1.id,
            PeerUpdate {
                peer_name: None,
                issuer: None,
                jwks_url: Some("https://gw.acme.example/v2/.well-known/jwks.json"),
                trust_tier: Some(TrustTier::Restricted),
            },
        )
        .await
        .expect("update")
        .expect("row found in tenant");
    assert_eq!(
        updated.jwks_url,
        "https://gw.acme.example/v2/.well-known/jwks.json"
    );
    assert_eq!(updated.trust_tier, TrustTier::Restricted);
    assert!(
        updated.updated_at > pre_update,
        "trigger must bump updated_at: pre={pre_update}, post={}",
        updated.updated_at,
    );

    // 5. MAX_LIST_LIMIT clamp.
    let clamped = store
        .list(&tenant_a, PeerFilter::default(), 1_000_000, 0)
        .await
        .expect("list clamped");
    assert!(
        clamped.len() <= MAX_LIST_LIMIT as usize,
        "list must clamp; got {} > {}",
        clamped.len(),
        MAX_LIST_LIMIT,
    );

    // 6. UNIQUE collisions on (tenant, peer_name) AND
    //    (tenant, issuer) each surface as DuplicateName.
    let dup_name = store
        .insert(NewFederatedPeer {
            tenant_id: &tenant_a,
            peer_name: "acme-prod", // collides with p1
            issuer: "https://gw.different.example",
            jwks_url: "https://gw.different.example/.well-known/jwks.json",
            trust_tier: TrustTier::Full,
        })
        .await
        .expect_err("dup name insert must fail");
    assert!(matches!(dup_name, PeerError::DuplicateName));

    let dup_issuer = store
        .insert(NewFederatedPeer {
            tenant_id: &tenant_a,
            peer_name: "different-name",
            issuer: "https://gw.globex.example", // collides with p2
            jwks_url: "https://gw.globex.example/.well-known/jwks.json",
            trust_tier: TrustTier::Full,
        })
        .await
        .expect_err("dup issuer insert must fail");
    assert!(matches!(dup_issuer, PeerError::DuplicateName));

    // 7. Cross-tenant scan used by the JWKS refresher:
    //    list_all_for_refresh returns peers
    //    from every tenant, ordered by id, clamped to
    //    MAX_LIST_LIMIT. Seed a peer in tenant_b first so
    //    we can observe at least one row outside tenant_a.
    let p_b = store
        .insert(NewFederatedPeer {
            tenant_id: &tenant_b,
            peer_name: "tenant-b-peer",
            issuer: "https://gw.tenant-b.example",
            jwks_url: "https://gw.tenant-b.example/jwks",
            trust_tier: TrustTier::Restricted,
        })
        .await
        .expect("insert tenant_b peer");
    let cross = store
        .list_all_for_refresh(100, 0)
        .await
        .expect("list_all_for_refresh");
    assert!(
        cross.iter().any(|p| p.id == p1.id),
        "p1 (tenant_a) must appear in cross-tenant scan",
    );
    assert!(
        cross.iter().any(|p| p.id == p2.id),
        "p2 (tenant_a) must appear in cross-tenant scan",
    );
    assert!(
        cross.iter().any(|p| p.id == p_b.id),
        "p_b (tenant_b) must appear in cross-tenant scan",
    );
    let clamped_all = store
        .list_all_for_refresh(1_000_000, 0)
        .await
        .expect("list_all_for_refresh clamped");
    assert!(
        clamped_all.len() <= MAX_LIST_LIMIT as usize,
        "list_all_for_refresh must clamp to MAX_LIST_LIMIT",
    );

    // Cleanup.
    assert!(store.delete(&tenant_a, p1.id).await.expect("delete p1"));
    assert!(store.delete(&tenant_a, p2.id).await.expect("delete p2"));
    assert!(store.delete(&tenant_b, p_b.id).await.expect("delete p_b"));
    sqlx::query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind(&tenant_a)
        .bind(&tenant_b)
        .execute(&pool)
        .await
        .expect("cleanup tenants");
}
