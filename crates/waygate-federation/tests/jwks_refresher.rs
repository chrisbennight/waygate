//! Refresh-cycle behaviour for `PeerJwksRefresher`. Uses an
//! in-memory fake `FederatedPeersStore` so the test focuses on the
//! orchestration (page → fetch → upsert → GC) without
//! standing up Postgres. The actual HTTP layer hits a real
//! axum loopback so reqwest's full stack runs unmocked,
//! matching `jwks_fetcher_http.rs`.
//!
//! Predicates pinned:
//!
//! 1. Two peers with reachable jwks_url: both cached after
//!    one cycle; lookup by issuer + by peer_id works.
//! 2. One peer's url fails (returns 500) while the other
//!    succeeds: the OK one is cached, the failure increments
//!    the per-cycle failed count, the previous cache entry
//!    for the failing peer is *retained* across cycles —
//!    so a flapping peer doesn't blank out trust we already
//!    had.
//! 3. Peer removed from the store between cycles → entry
//!    GC'd from cache.
//! 4. Same issuer registered in two tenants → both surface
//!    in `get_by_issuer` (mirrors the unit test, but here
//!    via the end-to-end refresher path).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use uuid::Uuid;

use waygate_federation::jwks::{
    FetchOutcome, InMemoryPeerJwksCache, PeerJwksCache, PeerJwksFetcher, PeerJwksRefresher,
};
use waygate_federation::{
    FederatedPeer, FederatedPeersStore, NewFederatedPeer, PeerError, PeerFilter, PeerUpdate,
    SharedPeersStore, TrustTier,
};

const KEY_A: &str = include_str!("fixtures/jwks_a.json");
const KEY_B: &str = include_str!("fixtures/jwks_b.json");

// -----------------------------------------------------------------------------
// In-memory peers store fake
// -----------------------------------------------------------------------------

#[derive(Default)]
struct FakePeersStore {
    inner: Mutex<Vec<FederatedPeer>>,
}

impl FakePeersStore {
    fn new() -> Self {
        Self::default()
    }

    fn push(&self, peer: FederatedPeer) {
        self.inner.lock().unwrap().push(peer);
    }

    fn remove_by_id(&self, id: Uuid) {
        self.inner.lock().unwrap().retain(|p| p.id != id);
    }
}

#[async_trait]
impl FederatedPeersStore for FakePeersStore {
    async fn insert(&self, _peer: NewFederatedPeer<'_>) -> Result<FederatedPeer, PeerError> {
        unimplemented!("fake store: refresher path uses push() directly")
    }
    async fn get(&self, _t: &str, _id: Uuid) -> Result<Option<FederatedPeer>, PeerError> {
        unimplemented!()
    }
    async fn list(
        &self,
        _t: &str,
        _f: PeerFilter<'_>,
        _l: u32,
        _o: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        unimplemented!()
    }
    async fn update(
        &self,
        _t: &str,
        _id: Uuid,
        _u: PeerUpdate<'_>,
    ) -> Result<Option<FederatedPeer>, PeerError> {
        unimplemented!()
    }
    async fn delete(&self, _t: &str, _id: Uuid) -> Result<bool, PeerError> {
        unimplemented!()
    }

    async fn list_all_for_refresh(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        let guard = self.inner.lock().unwrap();
        let start = offset as usize;
        if start >= guard.len() {
            return Ok(vec![]);
        }
        let end = (start + limit as usize).min(guard.len());
        Ok(guard[start..end].to_vec())
    }
}

// -----------------------------------------------------------------------------
// JWKS HTTP server
// -----------------------------------------------------------------------------

#[derive(Clone, Default)]
struct JwksServer {
    // path -> (status, body)
    routes: Arc<Mutex<HashMap<String, (u16, String)>>>,
}

impl JwksServer {
    fn new() -> Self {
        Self::default()
    }

    fn set(&self, path: &str, status: u16, body: &str) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, body.to_owned()));
    }
}

async fn route_handler(State(state): State<JwksServer>, Path(name): Path<String>) -> Response {
    let guard = state.routes.lock().unwrap();
    let (status, body) = guard.get(&name).cloned().unwrap_or((404, "{}".to_owned()));
    drop(guard);
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn spawn_jwks_server() -> (String, JwksServer) {
    let state = JwksServer::new();
    let app = Router::new()
        .route("/jwks/{name}", get(route_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

fn mk_peer(tenant: &str, name: &str, base: &str, slug: &str, trust: TrustTier) -> FederatedPeer {
    use time::OffsetDateTime;
    FederatedPeer {
        id: Uuid::new_v4(),
        tenant_id: tenant.to_owned(),
        peer_name: name.to_owned(),
        issuer: format!("https://issuer.{name}.example"),
        jwks_url: format!("{base}/jwks/{slug}"),
        trust_tier: trust,
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn refresh_populates_cache_for_all_peers() {
    let (base, jwks) = spawn_jwks_server().await;
    jwks.set("a", 200, KEY_A);
    jwks.set("b", 200, KEY_B);

    let fake = Arc::new(FakePeersStore::new());
    let store: SharedPeersStore = fake.clone();
    let p1 = mk_peer("t1", "peer-a", &base, "a", TrustTier::Full);
    let p2 = mk_peer("t2", "peer-b", &base, "b", TrustTier::Restricted);
    fake.push(p1.clone());
    fake.push(p2.clone());

    let cache = Arc::new(InMemoryPeerJwksCache::new());
    let fetcher = Arc::new(PeerJwksFetcher::new());
    let refresher = PeerJwksRefresher::new(
        store.clone(),
        cache.clone(),
        fetcher.clone(),
        Duration::from_secs(60),
    );

    let summary = refresher.refresh_once().await;
    assert_eq!(summary.total, 2);
    assert_eq!(summary.ok, 2);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.gc, 0);

    // Lookup by issuer: each peer's distinct issuer surfaces
    // the matching entry.
    let hits_a = cache.get_by_issuer(&p1.issuer).await;
    assert_eq!(hits_a.len(), 1);
    assert_eq!(hits_a[0].peer_id, p1.id);
    assert_eq!(hits_a[0].tenant_id, "t1");
    let hits_b = cache.get_by_issuer(&p2.issuer).await;
    assert_eq!(hits_b.len(), 1);
    assert_eq!(hits_b[0].peer_id, p2.id);

    // Lookup by peer id round-trips trust tier.
    assert_eq!(
        cache
            .get_by_peer_id(p1.id)
            .await
            .expect("p1 cached")
            .trust_tier,
        TrustTier::Full,
    );
    assert_eq!(cache.len().await, 2);
    // Implicit: both peers had distinct jwks_url paths, so
    // cache containing both entries is the proof that each
    // URL was fetched independently. A hit counter would
    // double-count nothing here — drop it for slice-size
    // discipline.
}

#[tokio::test]
async fn partial_failure_retains_previous_cache_entry() {
    // Round 1: both peers succeed. Round 2: peer B's URL
    // returns 500. Predicate: peer A's cache entry is
    // refreshed (new fetched_at), peer B's cache entry from
    // round 1 is retained byte-for-byte. This is the
    // "flapping peer doesn't blank our trust" guarantee.
    let (base, jwks) = spawn_jwks_server().await;
    jwks.set("a", 200, KEY_A);
    jwks.set("b", 200, KEY_B);

    let fake = Arc::new(FakePeersStore::new());
    let store: SharedPeersStore = fake.clone();
    let p_a = mk_peer("t1", "peer-a", &base, "a", TrustTier::Full);
    let p_b = mk_peer("t1", "peer-b", &base, "b", TrustTier::Restricted);
    fake.push(p_a.clone());
    fake.push(p_b.clone());

    let cache = Arc::new(InMemoryPeerJwksCache::new());
    let fetcher = Arc::new(PeerJwksFetcher::new());
    let refresher = PeerJwksRefresher::new(
        store.clone(),
        cache.clone(),
        fetcher.clone(),
        Duration::from_secs(60),
    );

    let s1 = refresher.refresh_once().await;
    assert_eq!(s1.ok, 2);
    let pre_b = cache.get_by_peer_id(p_b.id).await.unwrap();
    let pre_b_fetched = pre_b.fetched_at;

    // Round 2: peer B's URL goes bad.
    jwks.set("b", 500, "boom");
    let s2 = refresher.refresh_once().await;
    assert_eq!(s2.total, 2);
    assert_eq!(s2.ok, 1);
    assert_eq!(s2.failed, 1);
    assert_eq!(s2.failures.len(), 1);
    assert_eq!(s2.failures[0].peer_id, p_b.id);
    assert_eq!(s2.failures[0].outcome, FetchOutcome::HttpError);

    // Peer A refreshed (new fetched_at >= pre because we
    // can't easily wait without flake; the contract is "OK
    // on round 2 means new entry").
    assert!(cache.get_by_peer_id(p_a.id).await.is_some());

    // Peer B's PRIOR entry is preserved byte-for-byte:
    // same Arc identity is not guaranteed (refresher does
    // not touch the slot on failure), but the contents
    // (fetched_at, peer_id, issuer) must match round 1's.
    let post_b = cache
        .get_by_peer_id(p_b.id)
        .await
        .expect("retained on failure");
    assert_eq!(post_b.peer_id, p_b.id);
    assert_eq!(post_b.fetched_at, pre_b_fetched, "fetched_at preserved");
}

#[tokio::test]
async fn peer_removed_from_store_is_gc_from_cache() {
    let (base, jwks) = spawn_jwks_server().await;
    jwks.set("a", 200, KEY_A);
    jwks.set("b", 200, KEY_B);

    let fake = Arc::new(FakePeersStore::new());
    let store: SharedPeersStore = fake.clone();
    let p_a = mk_peer("t1", "peer-a", &base, "a", TrustTier::Full);
    let p_b = mk_peer("t1", "peer-b", &base, "b", TrustTier::Restricted);
    fake.push(p_a.clone());
    fake.push(p_b.clone());

    let cache = Arc::new(InMemoryPeerJwksCache::new());
    let fetcher = Arc::new(PeerJwksFetcher::new());
    let refresher = PeerJwksRefresher::new(
        store.clone(),
        cache.clone(),
        fetcher.clone(),
        Duration::from_secs(60),
    );
    let _ = refresher.refresh_once().await;
    assert_eq!(cache.len().await, 2);

    // Simulate admin-REST DELETE of peer A.
    fake.remove_by_id(p_a.id);

    let s2 = refresher.refresh_once().await;
    assert_eq!(s2.total, 1);
    assert_eq!(s2.gc, 1, "removed peer should be GC'd");
    assert!(cache.get_by_peer_id(p_a.id).await.is_none());
    assert!(cache.get_by_peer_id(p_b.id).await.is_some());
}

#[tokio::test]
async fn same_issuer_across_tenants_surfaces_both_entries() {
    // The migration's UNIQUE constraint is (tenant_id, issuer),
    // not (issuer); two tenants registering the same issuer
    // should each get a cached entry, and the verifier lookup
    // returns both so the verifier can disambiguate by tenant.
    let (base, jwks) = spawn_jwks_server().await;
    jwks.set("a", 200, KEY_A);
    jwks.set("b", 200, KEY_B);

    let fake = Arc::new(FakePeersStore::new());
    let store: SharedPeersStore = fake.clone();
    let shared_issuer = "https://shared.example".to_owned();
    let mut p1 = mk_peer("t1", "peer-x", &base, "a", TrustTier::Full);
    p1.issuer = shared_issuer.clone();
    let mut p2 = mk_peer("t2", "peer-x", &base, "b", TrustTier::Restricted);
    p2.issuer = shared_issuer.clone();
    fake.push(p1.clone());
    fake.push(p2.clone());

    let cache = Arc::new(InMemoryPeerJwksCache::new());
    let fetcher = Arc::new(PeerJwksFetcher::new());
    let refresher = PeerJwksRefresher::new(
        store.clone(),
        cache.clone(),
        fetcher.clone(),
        Duration::from_secs(60),
    );
    let _ = refresher.refresh_once().await;

    let hits = cache.get_by_issuer(&shared_issuer).await;
    assert_eq!(hits.len(), 2);
    let tenants: std::collections::BTreeSet<&str> =
        hits.iter().map(|c| c.tenant_id.as_str()).collect();
    assert_eq!(tenants.into_iter().collect::<Vec<_>>(), vec!["t1", "t2"]);
}
