//! `/api/v1/admin/upstream_sessions` route-level coverage. Uses an
//! in-memory `UpstreamSessionStore` fake so the test doesn't need a
//! live Postgres pool — the Pg impl is exercised by the
//! `waygate-as::sessions` integration suite that needs the DB
//! anyway.
//!
//! Three things this pins:
//! 1. `None` store ⇒ both endpoints 503 (matches the audit/cedar
//!    pattern).
//! 2. With a wired store: list returns ciphertext-free metadata;
//!    revoke removes the row and a subsequent list omits it.
//! 3. Scope-gating: `mcp:read` is insufficient; `mcp:admin` succeeds.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use time::OffsetDateTime;
use tower::util::ServiceExt;

use waygate_admin::{api_router, AdminState};
use waygate_as::sessions::{
    NewSessionRow, OffKeyRow, SessionMetadata, SessionStoreError, SharedUpstreamSessionStore,
    StoredSessionRow, UpstreamSessionStore, MAX_LIST_LIMIT,
};
use waygate_oidc::Principal;
use waygate_upstream::pool::UpstreamPool;

/// Single-process, lock-protected in-memory implementation of
/// [`UpstreamSessionStore`]. Cloneable (`Arc<Mutex<...>>`) so a
/// handle for the store can outlive the AdminState the test mounts.
#[derive(Default, Clone)]
struct MemoryStore {
    rows: Arc<Mutex<Vec<StoredRow>>>,
}

#[derive(Clone)]
struct StoredRow {
    sub: String,
    upstream_issuer: String,
    tokens_ciphertext: Vec<u8>,
    key_id: String,
    access_expires_at: OffsetDateTime,
    refreshed_at: OffsetDateTime,
    created_at: OffsetDateTime,
}

#[async_trait]
impl UpstreamSessionStore for MemoryStore {
    async fn upsert(&self, row: NewSessionRow<'_>) -> Result<(), SessionStoreError> {
        let mut g = self.rows.lock().unwrap();
        let now = OffsetDateTime::now_utc();
        if let Some(existing) = g
            .iter_mut()
            .find(|r| r.sub == row.sub && r.upstream_issuer == row.upstream_issuer)
        {
            existing.tokens_ciphertext = row.tokens_ciphertext.to_vec();
            existing.key_id = row.key_id.to_owned();
            existing.access_expires_at = row.access_expires_at;
            existing.refreshed_at = now;
        } else {
            g.push(StoredRow {
                sub: row.sub.into(),
                upstream_issuer: row.upstream_issuer.into(),
                tokens_ciphertext: row.tokens_ciphertext.to_vec(),
                key_id: row.key_id.to_owned(),
                access_expires_at: row.access_expires_at,
                refreshed_at: now,
                created_at: now,
            });
        }
        Ok(())
    }

    async fn get(
        &self,
        sub: &str,
        upstream_issuer: &str,
    ) -> Result<Option<StoredSessionRow>, SessionStoreError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .find(|r| r.sub == sub && r.upstream_issuer == upstream_issuer)
            .map(|r| StoredSessionRow {
                tokens_ciphertext: r.tokens_ciphertext.clone(),
                key_id: r.key_id.clone(),
                access_expires_at: r.access_expires_at,
                refreshed_at: r.refreshed_at,
            }))
    }

    async fn update_if_ciphertext_matches(
        &self,
        row: NewSessionRow<'_>,
        expected_old_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let mut g = self.rows.lock().unwrap();
        if let Some(existing) = g.iter_mut().find(|r| {
            r.sub == row.sub
                && r.upstream_issuer == row.upstream_issuer
                && r.tokens_ciphertext == expected_old_ciphertext
        }) {
            existing.tokens_ciphertext = row.tokens_ciphertext.to_vec();
            existing.key_id = row.key_id.to_owned();
            existing.access_expires_at = row.access_expires_at;
            existing.refreshed_at = OffsetDateTime::now_utc();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn revoke(&self, sub: &str, upstream_issuer: &str) -> Result<bool, SessionStoreError> {
        let mut g = self.rows.lock().unwrap();
        let before = g.len();
        g.retain(|r| !(r.sub == sub && r.upstream_issuer == upstream_issuer));
        Ok(g.len() < before)
    }

    async fn revoke_if_ciphertext_matches(
        &self,
        sub: &str,
        upstream_issuer: &str,
        expected_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        let mut g = self.rows.lock().unwrap();
        let before = g.len();
        g.retain(|r| {
            !(r.sub == sub
                && r.upstream_issuer == upstream_issuer
                && r.tokens_ciphertext == expected_ciphertext)
        });
        Ok(g.len() < before)
    }

    async fn list_all(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionMetadata>, SessionStoreError> {
        let g = self.rows.lock().unwrap();
        let mut copy: Vec<_> = g.clone();
        copy.sort_by(|a, b| {
            a.sub
                .cmp(&b.sub)
                .then_with(|| a.upstream_issuer.cmp(&b.upstream_issuer))
        });
        Ok(copy
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|r| SessionMetadata {
                sub: r.sub,
                upstream_issuer: r.upstream_issuer,
                key_id: r.key_id,
                access_expires_at: r.access_expires_at,
                refreshed_at: r.refreshed_at,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn list_off_active_key(
        &self,
        active_id: &str,
        decryptable_key_ids: &[String],
        limit: u32,
    ) -> Result<Vec<OffKeyRow>, SessionStoreError> {
        let g = self.rows.lock().unwrap();
        let mut copy: Vec<_> = g
            .iter()
            .filter(|r| {
                r.key_id != active_id && decryptable_key_ids.iter().any(|id| id == &r.key_id)
            })
            .cloned()
            .collect();
        copy.sort_by(|a, b| {
            a.sub
                .cmp(&b.sub)
                .then_with(|| a.upstream_issuer.cmp(&b.upstream_issuer))
        });
        Ok(copy
            .into_iter()
            .take(limit as usize)
            .map(|r| OffKeyRow {
                sub: r.sub,
                upstream_issuer: r.upstream_issuer,
                key_id: r.key_id,
                tokens_ciphertext: r.tokens_ciphertext,
                access_expires_at: r.access_expires_at,
            })
            .collect())
    }

    async fn sweep_expired(&self, _retain: Duration) -> Result<u64, SessionStoreError> {
        Ok(0)
    }
}

fn principal_with(scopes: &[&str]) -> Principal {
    Principal {
        sub: "admin@example.com".into(),
        email: None,
        groups: vec![],
        issuer: "test".into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        tenant: waygate_core::TenantId::default(),
        auth_method: waygate_oidc::AuthMethod::Oauth,
        raw_token: None,
        roles: vec![],
        scim: None,
        enrichment_blocked: None,
        api_key_profile_restrictions: None,
    }
}

async fn state_with_store(store: Option<SharedUpstreamSessionStore>) -> Arc<AdminState> {
    let pool = Arc::new(UpstreamPool::connect(BTreeMap::new()).await);
    // A real in-memory sink, not null_evidence(): the revoke path now records
    // a fail-closed `record_required` AdminMutation (it was best-effort before
    // revoke_session_core was extracted), and the NullSink fails record_required
    // by design — so the audited happy path needs a sink that actually persists.
    let evidence: waygate_mcp::audit::SharedEvidence =
        Arc::new(waygate_mcp::audit::InMemorySink::default());
    Arc::new(AdminState::new(
        pool,
        None,
        None,
        evidence,
        None,
        None,
        store,
        None,
        "http://127.0.0.1:0".into(),
    ))
}

#[tokio::test]
async fn list_503s_without_store() {
    let app = api_router(state_with_store(None).await);

    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn revoke_503s_without_store() {
    let app = api_router(state_with_store(None).await);

    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions/alice/https%3A%2F%2Fidp.test")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn list_requires_admin_scope() {
    let store: SharedUpstreamSessionStore = Arc::new(MemoryStore::default());
    let app = api_router(state_with_store(Some(store)).await);

    // No principal → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/upstream_sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // mcp:read is insufficient.
    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:read"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_returns_metadata_only_no_ciphertext() {
    let store = MemoryStore::default();
    // Seed two rows.
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"VERY_SECRET_CIPHERTEXT_xxx",
            access_expires_at: exp,
        })
        .await
        .unwrap();
    store
        .upsert(NewSessionRow {
            sub: "bob",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"different",
            access_expires_at: exp,
        })
        .await
        .unwrap();

    let shared: SharedUpstreamSessionStore = Arc::new(store);
    let app = api_router(state_with_store(Some(shared)).await);

    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions?limit=100&offset=0")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["sessions"].as_array().unwrap().len(), 2);
    // Critical security invariant: the ciphertext must NEVER appear in
    // the admin read surface. A buggy serializer that accidentally
    // re-exported `tokens_ciphertext` would leak decryptable bearer
    // material to anyone with `mcp:admin`.
    let serialized = String::from_utf8_lossy(&bytes);
    assert!(
        !serialized.contains("VERY_SECRET_CIPHERTEXT"),
        "list response must not include the encrypted bearer envelope: {serialized}",
    );
    assert!(
        !serialized.contains("tokens_ciphertext"),
        "list response must not include the ciphertext field name: {serialized}",
    );

    // Ordering: alice before bob (sub-then-issuer sort).
    assert_eq!(body["sessions"][0]["sub"], "alice");
    assert_eq!(body["sessions"][1]["sub"], "bob");
}

#[tokio::test]
async fn revoke_removes_row_and_subsequent_list_omits_it() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"cipher",
            access_expires_at: exp,
        })
        .await
        .unwrap();
    let shared: SharedUpstreamSessionStore = Arc::new(store.clone());
    let app = api_router(state_with_store(Some(shared)).await);

    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions/alice/https:%2F%2Fidp.test")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Row gone in the underlying store.
    assert!(store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .is_none());

    // And the second revoke is idempotent — still 204, no error.
    let mut req = Request::builder()
        .uri("/api/v1/admin/upstream_sessions/alice/https:%2F%2Fidp.test")
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// The durable boundary between
/// admin `revoke()` and the refresh-on-demand write. With a bare
/// `upsert` here, an in-flight refresh that completed *after*
/// admin DELETE would INSERT-resurrect the row. The new
/// `update_if_ciphertext_matches` only updates a row whose
/// current ciphertext byte-equals the pre-refresh ciphertext, so
/// a concurrent DELETE leaves 0 rows-affected; the refresher
/// returns `RevokedDuringRefresh` and the per-call Tier-A path
/// falls through to "no stored token" (refused under
/// `tier_a_required: true`).
///
/// Store-level contract — the refresher-against-fake-IdP path
/// isn't yet wired in this crate's integration tests.
#[tokio::test]
async fn update_if_ciphertext_matches_refuses_to_resurrect_after_revoke() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);

    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"original-c1",
            access_expires_at: exp,
        })
        .await
        .unwrap();

    // Simulated admin revoke between refresh read and refresh write.
    assert!(store.revoke("alice", "https://idp.test").await.unwrap());

    // Refresh path attempts to write the freshly-refreshed envelope.
    // The CAS witness is the pre-refresh C1. Row is gone, no match.
    let resurrected = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: b"refreshed-after-revoke",
                access_expires_at: exp,
            },
            b"original-c1",
        )
        .await
        .unwrap();
    assert!(
        !resurrected,
        "update_if_ciphertext_matches must not resurrect a deleted row",
    );
    assert!(store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .is_none());
}

/// The row-REPLACED race: after
/// admin DELETE, the user re-completes `/oauth/callback`, which
/// `upsert`-INSERTs a fresh envelope C3. The original in-flight
/// refresh (which decrypted pre-revoke C1) finally writes. A bare
/// UPDATE-on-(sub, issuer) would clobber C3 with the stale
/// envelope C2. CAS-on-ciphertext closes the window: the WHERE
/// adds `AND tokens_ciphertext = C1`, doesn't match C3, no-op.
#[tokio::test]
async fn update_if_ciphertext_matches_refuses_to_overwrite_replaced_row() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);

    // Pre-refresh ciphertext the refresher decrypted.
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"original-c1",
            access_expires_at: exp,
        })
        .await
        .unwrap();

    // Admin revoke followed by user re-auth produces fresh C3.
    assert!(store.revoke("alice", "https://idp.test").await.unwrap());
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"reauth-c3",
            access_expires_at: exp,
        })
        .await
        .unwrap();

    // Stale refresh writes back with C1 as the CAS witness — the
    // row is now C3, no match, the refresh's stale envelope is
    // dropped on the floor instead of clobbering C3.
    let updated = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: b"stale-c2",
                access_expires_at: exp,
            },
            b"original-c1",
        )
        .await
        .unwrap();
    assert!(
        !updated,
        "stale refresh must not overwrite re-auth row C3 with C2",
    );

    let row = store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.tokens_ciphertext, b"reauth-c3",
        "row must still hold the fresh re-auth envelope, not the stale refresh",
    );
}

/// A refresh-on-demand under a new active key
/// advances the row's `key_id` (from `v1` to the new active id)
/// alongside the new ciphertext. Pins the rotation-during-refresh
/// path: a row written under v1 that refreshes mid-rotation flips
/// to v2 without a separate sweeper pass.
#[tokio::test]
async fn refresh_path_advances_key_id_to_active() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"under-v1",
            access_expires_at: exp,
        })
        .await
        .unwrap();
    // Simulate refresh CAS-updating under the new active id `v2`.
    let updated = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v2",
                tokens_ciphertext: b"under-v2",
                access_expires_at: exp,
            },
            b"under-v1",
        )
        .await
        .unwrap();
    assert!(updated);
    let row = store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.tokens_ciphertext, b"under-v2");
    assert_eq!(
        row.key_id, "v2",
        "refresh must advance key_id alongside ciphertext"
    );
}

/// Happy path: when the row is unchanged since the refresher's
/// read, `update_if_ciphertext_matches` succeeds and persists the
/// new ciphertext.
#[tokio::test]
async fn update_if_ciphertext_matches_succeeds_on_unchanged_row() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
    store
        .upsert(NewSessionRow {
            sub: "bob",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"bob-original",
            access_expires_at: exp,
        })
        .await
        .unwrap();
    let updated = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "bob",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: b"bob-refreshed",
                access_expires_at: exp,
            },
            b"bob-original",
        )
        .await
        .unwrap();
    assert!(updated);
    let row = store.get("bob", "https://idp.test").await.unwrap().unwrap();
    assert_eq!(row.tokens_ciphertext, b"bob-refreshed");
}

/// A client asking for
/// `limit > MAX_LIST_LIMIT` must see the echoed `limit` reflect
/// the actually-applied cap, not the request value. Otherwise an
/// operator script paging by `offset += response.limit` skips
/// rows whenever the request exceeded the cap.
#[tokio::test]
async fn oversized_limit_echoes_the_cap_not_the_request() {
    let store: SharedUpstreamSessionStore = Arc::new(MemoryStore::default());
    let app = api_router(state_with_store(Some(store)).await);

    let oversized = MAX_LIST_LIMIT + 250;
    let mut req = Request::builder()
        .uri(format!(
            "/api/v1/admin/upstream_sessions?limit={oversized}&offset=0"
        ))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(principal_with(&["mcp:admin"]));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["limit"].as_u64(),
        Some(u64::from(MAX_LIST_LIMIT)),
        "oversized limit must echo the cap, not the request: {body}",
    );
}

/// The re-encrypt sweep's CAS
/// witness was symmetric with the refresh path's witness, so a
/// sweep-then-refresh interleave caused refresh to MISS its CAS
/// even though it held a freshly-IdP-rotated `refresh_token`.
/// The refresh path now distinguishes between "row replaced with
/// new plaintext" and "row re-encrypted under a new key with the
/// SAME plaintext" — the latter is a sweep race, and the refresh
/// retries the CAS using the sweep's ciphertext as the new
/// witness so rt-B lands in the row.
///
/// This test exercises the store-level contract the retry depends
/// on: when the row's ciphertext changes between read and write
/// but the row is still present and decryptable, the refresh path
/// can retry by using the current ciphertext as the new witness.
/// (The full refresher-against-fake-IdP path requires a wiremock
/// or axum harness we don't yet have in this crate.)
#[tokio::test]
async fn cas_witness_can_chain_through_a_sweep_race() {
    let store = MemoryStore::default();
    let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);

    // Initial row: under v1, ciphertext C1.
    store
        .upsert(NewSessionRow {
            sub: "alice",
            upstream_issuer: "https://idp.test",
            key_id: "v1",
            tokens_ciphertext: b"C1",
            access_expires_at: exp,
        })
        .await
        .unwrap();

    // Refresh path read C1; before refresh writes, sweep
    // re-encrypts the same plaintext under v2 ⇒ C2-sweep.
    let updated = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v2",
                tokens_ciphertext: b"C2-sweep",
                access_expires_at: exp,
            },
            b"C1",
        )
        .await
        .unwrap();
    assert!(
        updated,
        "sweep CAS must succeed when no one else has written"
    );

    // Refresh now tries to write rt-B's envelope (C2-refresh)
    // using C1 as the witness — CAS misses.
    let first_attempt = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v2",
                tokens_ciphertext: b"C2-refresh",
                access_expires_at: exp,
            },
            b"C1",
        )
        .await
        .unwrap();
    assert!(
        !first_attempt,
        "stale C1 witness must miss after sweep wrote C2-sweep"
    );

    // The refresh path's recovery: get current row, decrypt,
    // compare plaintext. In this fixture the plaintexts match
    // (same envelope re-encrypted), so refresh retries with
    // C2-sweep as the new witness.
    let current = store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.tokens_ciphertext, b"C2-sweep");
    let retry = store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v2",
                tokens_ciphertext: b"C2-refresh",
                access_expires_at: exp,
            },
            &current.tokens_ciphertext,
        )
        .await
        .unwrap();
    assert!(
        retry,
        "retry with sweep's ciphertext as new witness must succeed"
    );

    // Final state: row holds rt-B's envelope, NOT the sweep's
    // stale-relative-to-IdP envelope.
    let final_row = store
        .get("alice", "https://idp.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        final_row.tokens_ciphertext, b"C2-refresh",
        "refresh's rt-B envelope must end up in the row, not the sweep's stale copy",
    );
}
