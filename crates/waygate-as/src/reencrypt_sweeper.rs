//! Background sweeper that re-encrypts
//! `user_upstream_sessions` rows whose `key_id` is not the
//! current active id.
//!
//! ## Why this exists
//!
//! An `UpstreamCrypto` keyring holds a per-row
//! `key_id` column. Rotation no longer requires a deployment
//! outage — the operator adds a new key alongside the old, flips
//! `_ACTIVE_ID`, and old-key rows stay decryptable as long as
//! their key remains in the ring. Two natural advance points
//! already exist:
//!
//! - Refresh-on-demand: rows that refresh during the rotation
//!   window are re-encrypted under the active key as a side
//!   effect of `session_refresh::SessionRefresher::refresh`.
//! - User re-auth: rows written by `/oauth/callback` always stamp
//!   the active id.
//!
//! Neither catches sessions that simply *don't refresh* during
//! the rotation window — a user who logged in months ago, made no
//! upstream calls, and whose access token is still valid. Without
//! a sweeper their `key_id` stays at the old value indefinitely,
//! pinning the legacy key in the operator's env until every such
//! row eventually refreshes or expires. The sweeper closes that
//! gap so the operator can retire an old key in bounded time.
//!
//! ## Concurrency
//!
//! The write uses
//! [`UpstreamSessionStore::update_if_ciphertext_matches`] with
//! the row's pre-sweep ciphertext as the CAS witness — the same
//! discriminator the refresh path uses. So if any of the
//! following land between the sweeper's read and write, the CAS
//! fails and the sweeper safely no-ops:
//!
//! - An admin DELETE removed the row.
//! - A user re-auth via `/oauth/callback` produced a new row.
//! - A refresh-on-demand wrote a different envelope.
//!
//! The sweeper is best-effort and idempotent: missed-on-this-tick
//! rows get picked up next tick.
//!
//! ## Behaviour summary
//!
//! - `re_encrypt_batch`: pull at most `batch_size` off-key rows,
//!   migrate each, return [`SweepStats`].
//! - `run_reencrypt_sweeper`: periodic loop around
//!   `re_encrypt_batch`. Logs at INFO when rows are migrated,
//!   WARN on errors. Errors don't kill the loop; transient DB
//!   hiccups must not crash a long-running gateway.

use std::sync::Arc;
use std::time::Duration;

use tracing::Instrument;

use crate::crypto::{CryptoError, UpstreamCrypto};
use crate::sessions::{NewSessionRow, OffKeyRow, SessionStoreError, SharedUpstreamSessionStore};

/// Outcome counters reported by a single batch + by the periodic
/// driver after each tick. Aggregated across all rows in the
/// batch.
#[derive(Debug, Clone, Copy, Default)]
pub struct SweepStats {
    /// Rows successfully migrated to the active key.
    pub migrated: u64,
    /// Rows where the CAS missed (admin DELETE, user re-auth, or
    /// a refresh landed between read and write). Not an error;
    /// the row no longer needs sweeping or will be picked up next
    /// tick.
    pub skipped: u64,
    /// Rows where decrypt under the stored `key_id` failed
    /// (operator removed the old key from the keyring before
    /// re-encrypting). Surfaced so the operator knows there's a
    /// stuck row needing attention.
    pub decrypt_failures: u64,
    /// Rows where the re-encrypt under the active key failed.
    /// Should be impossible (active key is always present by
    /// construction), but tracked so an in-the-wild surprise
    /// gets visibility.
    pub encrypt_failures: u64,
    /// Rows where the CAS update returned a store error (DB
    /// transient). Logged + counted; the next tick retries.
    pub store_failures: u64,
}

impl SweepStats {
    pub fn total(&self) -> u64 {
        self.migrated
            + self.skipped
            + self.decrypt_failures
            + self.encrypt_failures
            + self.store_failures
    }
}

/// Top-level sweeper error. Only returned when the *initial*
/// `list_off_active_key` call itself fails — per-row failures are
/// counted inside [`SweepStats`] so a single poisoned row never
/// halts a batch.
#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error("list off-key rows: {0}")]
    List(#[source] SessionStoreError),
}

/// Process one batch of off-key rows.
///
/// Reads up to `batch_size` rows whose `key_id != crypto.active_id()`,
/// decrypts each under its stored key, re-encrypts under the
/// active key, and writes back via
/// [`UpstreamSessionStore::update_if_ciphertext_matches`] (CAS on
/// the pre-sweep ciphertext).
///
/// Returns aggregated counts. Per-row errors are counted into the
/// stats (decrypt / encrypt / store) and logged at WARN; only an
/// initial list failure short-circuits to `Err`.
pub async fn re_encrypt_batch(
    crypto: &UpstreamCrypto,
    store: &SharedUpstreamSessionStore,
    batch_size: u32,
) -> Result<SweepStats, SweepError> {
    let active = crypto.active_id().to_owned();
    // Scope the SQL filter to keys we can decrypt under. Without
    // this, a batch could be entirely occupied by rows stamped with
    // a decommissioned key id; the sweeper would re-fetch the same
    // failing rows every tick and never make progress on later
    // decryptable rows.
    let decryptable: Vec<String> = crypto.key_ids();
    let rows = store
        .list_off_active_key(&active, &decryptable, batch_size)
        .await
        .map_err(SweepError::List)?;
    let mut stats = SweepStats::default();
    for row in rows {
        process_row(crypto, store, &active, &row, &mut stats).await;
    }
    Ok(stats)
}

async fn process_row(
    crypto: &UpstreamCrypto,
    store: &SharedUpstreamSessionStore,
    active: &str,
    row: &OffKeyRow,
    stats: &mut SweepStats,
) {
    let plaintext = match crypto.decrypt(&row.key_id, &row.tokens_ciphertext) {
        Ok(p) => p,
        Err(CryptoError::UnknownKeyId(_)) | Err(CryptoError::Decrypt(_)) => {
            // The operator decommissioned the old key (or the row
            // is corrupted) — the sweeper can't migrate this one
            // and shouldn't keep retrying it on every tick. Logged
            // loud so an operator can investigate; the per-call
            // Tier-A read path also fails closed for this row.
            tracing::warn!(
                sub = %row.sub,
                upstream_issuer = %row.upstream_issuer,
                stored_key_id = %row.key_id,
                "tier-a re-encrypt sweep: decrypt failed under stored key id; \
                 row stuck until operator re-adds the key or removes the row",
            );
            stats.decrypt_failures += 1;
            return;
        }
        Err(e) => {
            tracing::warn!(
                sub = %row.sub,
                upstream_issuer = %row.upstream_issuer,
                stored_key_id = %row.key_id,
                error = %e,
                "tier-a re-encrypt sweep: unexpected decrypt error",
            );
            stats.decrypt_failures += 1;
            return;
        }
    };

    let fresh_ct = match crypto.encrypt(&plaintext) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::warn!(
                sub = %row.sub,
                upstream_issuer = %row.upstream_issuer,
                error = %e,
                "tier-a re-encrypt sweep: encrypt under active key failed",
            );
            stats.encrypt_failures += 1;
            return;
        }
    };

    match store
        .update_if_ciphertext_matches(
            NewSessionRow {
                sub: &row.sub,
                upstream_issuer: &row.upstream_issuer,
                key_id: active,
                tokens_ciphertext: &fresh_ct,
                access_expires_at: row.access_expires_at,
            },
            &row.tokens_ciphertext,
        )
        .await
    {
        Ok(true) => {
            stats.migrated += 1;
        }
        Ok(false) => {
            // CAS missed: an admin DELETE, /oauth/callback re-auth,
            // or refresh landed between our read and write. Not an
            // error — the row no longer needs sweeping (or will be
            // picked up by the next tick if it landed back under
            // the old key for some reason).
            stats.skipped += 1;
        }
        Err(e) => {
            tracing::warn!(
                sub = %row.sub,
                upstream_issuer = %row.upstream_issuer,
                error = %e,
                "tier-a re-encrypt sweep: CAS update failed",
            );
            stats.store_failures += 1;
        }
    }
}

/// Periodic driver around [`re_encrypt_batch`].
///
/// Wakes every `interval`, processes one batch of `batch_size`
/// rows, logs the outcome. Exits cleanly when `shutdown` resolves
/// (typically `CancellationToken::cancelled_owned()` from the
/// gateway's main shutdown signal).
///
/// Errors from `re_encrypt_batch` are logged at WARN and the loop
/// continues — a transient DB hiccup must not silently kill the
/// sweeper.
pub async fn run_reencrypt_sweeper(
    crypto: Arc<UpstreamCrypto>,
    store: SharedUpstreamSessionStore,
    interval: Duration,
    batch_size: u32,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Burn the immediate tick so a restart loop can't hammer the
    // DB if the process is flapping.
    ticker.tick().await;
    tokio::pin!(shutdown);
    let span = tracing::info_span!("tier_a_reencrypt_sweeper", active = %crypto.active_id());
    async move {
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::debug!("tier-a re-encrypt sweeper exiting");
                    return;
                }
                _ = ticker.tick() => {
                    match re_encrypt_batch(&crypto, &store, batch_size).await {
                        Ok(stats) if stats.total() > 0 => {
                            tracing::info!(
                                migrated = stats.migrated,
                                skipped = stats.skipped,
                                decrypt_failures = stats.decrypt_failures,
                                encrypt_failures = stats.encrypt_failures,
                                store_failures = stats.store_failures,
                                "tier-a re-encrypt sweep processed batch",
                            );
                        }
                        Ok(_) => {
                            tracing::debug!("tier-a re-encrypt sweep: nothing to migrate");
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "tier-a re-encrypt sweep failed; retrying on next tick",
                            );
                        }
                    }
                }
            }
        }
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{StoredSessionRow, UpstreamSessionStore};
    use async_trait::async_trait;
    use base64::Engine as _;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    /// In-memory store fake. Carries an explicit `key_id` per row
    /// so the sweeper's CAS + list-off-active-key paths exercise
    /// real state instead of always-zero defaults.
    #[derive(Default)]
    struct FakeStore {
        rows: Mutex<Vec<FakeRow>>,
    }

    #[derive(Clone, Debug)]
    struct FakeRow {
        sub: String,
        upstream_issuer: String,
        tokens_ciphertext: Vec<u8>,
        key_id: String,
        access_expires_at: OffsetDateTime,
    }

    #[async_trait]
    impl UpstreamSessionStore for FakeStore {
        async fn upsert(&self, row: NewSessionRow<'_>) -> Result<(), SessionStoreError> {
            let mut g = self.rows.lock().unwrap();
            if let Some(existing) = g
                .iter_mut()
                .find(|r| r.sub == row.sub && r.upstream_issuer == row.upstream_issuer)
            {
                existing.tokens_ciphertext = row.tokens_ciphertext.to_vec();
                existing.key_id = row.key_id.to_owned();
                existing.access_expires_at = row.access_expires_at;
            } else {
                g.push(FakeRow {
                    sub: row.sub.into(),
                    upstream_issuer: row.upstream_issuer.into(),
                    tokens_ciphertext: row.tokens_ciphertext.to_vec(),
                    key_id: row.key_id.to_owned(),
                    access_expires_at: row.access_expires_at,
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
                    refreshed_at: r.access_expires_at,
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
                Ok(true)
            } else {
                Ok(false)
            }
        }

        async fn revoke(
            &self,
            sub: &str,
            upstream_issuer: &str,
        ) -> Result<bool, SessionStoreError> {
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

        async fn list_off_active_key(
            &self,
            active_id: &str,
            decryptable_key_ids: &[String],
            limit: u32,
        ) -> Result<Vec<OffKeyRow>, SessionStoreError> {
            let g = self.rows.lock().unwrap();
            Ok(g.iter()
                .filter(|r| {
                    r.key_id != active_id && decryptable_key_ids.iter().any(|id| id == &r.key_id)
                })
                .take(limit as usize)
                .map(|r| OffKeyRow {
                    sub: r.sub.clone(),
                    upstream_issuer: r.upstream_issuer.clone(),
                    key_id: r.key_id.clone(),
                    tokens_ciphertext: r.tokens_ciphertext.clone(),
                    access_expires_at: r.access_expires_at,
                })
                .collect())
        }

        async fn list_all(
            &self,
            _limit: u32,
            _offset: u32,
        ) -> Result<Vec<crate::sessions::SessionMetadata>, SessionStoreError> {
            Ok(vec![])
        }

        async fn sweep_expired(&self, _retain: Duration) -> Result<u64, SessionStoreError> {
            Ok(0)
        }
    }

    fn two_key_crypto(active: &str) -> Arc<UpstreamCrypto> {
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        Arc::new(
            UpstreamCrypto::from_keyring(
                [
                    (
                        "v1".into(),
                        base64::engine::general_purpose::STANDARD.encode(v1),
                    ),
                    (
                        "v2".into(),
                        base64::engine::general_purpose::STANDARD.encode(v2),
                    ),
                ],
                active,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn batch_migrates_off_key_rows_to_active() {
        // Active is v2. Seed one row under v1; sweeper migrates it.
        let crypto = two_key_crypto("v2");
        let store: SharedUpstreamSessionStore = Arc::new(FakeStore::default());
        let plaintext = b"alice-envelope";
        // Encrypt under v1 directly so the row's ciphertext is
        // v1-only-decryptable (simulates a pre-rotation row).
        let one = UpstreamCrypto::from_key_bytes([1u8; 32]);
        let v1_ct = one.encrypt(plaintext).unwrap();
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: &v1_ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();

        let stats = re_encrypt_batch(&crypto, &store, 10).await.unwrap();
        assert_eq!(stats.migrated, 1, "off-key row must be migrated");
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.decrypt_failures, 0);

        // Row is now under v2.
        let row = store
            .get("alice", "https://idp.test")
            .await
            .unwrap()
            .expect("row still present");
        assert_eq!(row.key_id, "v2");
        assert_eq!(
            crypto.decrypt("v2", &row.tokens_ciphertext).unwrap(),
            plaintext,
            "re-encrypted envelope must decrypt to the same plaintext under v2",
        );
    }

    #[tokio::test]
    async fn batch_skips_when_cas_misses_concurrent_revoke() {
        let crypto = two_key_crypto("v2");
        let store: SharedUpstreamSessionStore = Arc::new(FakeStore::default());

        let v1_ct = UpstreamCrypto::from_key_bytes([1u8; 32])
            .encrypt(b"x")
            .unwrap();
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: &v1_ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();

        // Simulate the sweeper having already read the row, then
        // admin DELETE landing before the CAS write.
        let active = crypto.active_id().to_owned();
        let decryptable = crypto.key_ids();
        let off_rows = store
            .list_off_active_key(&active, &decryptable, 10)
            .await
            .unwrap();
        assert_eq!(off_rows.len(), 1);
        // Admin revoke between read and write.
        store.revoke("alice", "https://idp.test").await.unwrap();

        // Now process the row — CAS should miss.
        let mut stats = SweepStats::default();
        process_row(&crypto, &store, &active, &off_rows[0], &mut stats).await;
        assert_eq!(stats.migrated, 0);
        assert_eq!(stats.skipped, 1);
        // Row stays deleted; sweeper didn't resurrect.
        assert!(store
            .get("alice", "https://idp.test")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn batch_skips_when_cas_misses_concurrent_re_auth() {
        // Race shape: admin DELETE → user re-auth → stale write
        // would clobber. Here the "stale write" is the sweeper's,
        // not refresh's.
        let crypto = two_key_crypto("v2");
        let store: SharedUpstreamSessionStore = Arc::new(FakeStore::default());

        let v1_ct = UpstreamCrypto::from_key_bytes([1u8; 32])
            .encrypt(b"v1-env")
            .unwrap();
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: &v1_ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();

        let active = crypto.active_id().to_owned();
        let decryptable = crypto.key_ids();
        let off_rows = store
            .list_off_active_key(&active, &decryptable, 10)
            .await
            .unwrap();

        // Admin revoke + user re-auth between the sweeper's read
        // and its write.
        store.revoke("alice", "https://idp.test").await.unwrap();
        let reauth_ct = crypto.encrypt(b"reauth-fresh").unwrap();
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: &active,
                tokens_ciphertext: &reauth_ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();

        let mut stats = SweepStats::default();
        process_row(&crypto, &store, &active, &off_rows[0], &mut stats).await;
        assert_eq!(
            stats.skipped, 1,
            "stale sweep write must miss the re-auth row"
        );

        let row = store
            .get("alice", "https://idp.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.tokens_ciphertext, reauth_ct,
            "re-auth envelope must survive an in-flight sweeper write",
        );
    }

    #[tokio::test]
    async fn batch_filters_undecryptable_rows_to_avoid_starving_the_loop() {
        // A batch entirely occupied by rows stamped under a
        // decommissioned key id would starve the sweeper — every
        // tick would re-fetch the same failing rows and never reach
        // later decryptable rows. Fix: the SQL filter accepts a
        // `decryptable_key_ids` list and excludes rows outside it.
        //
        // Seed two rows: one under v99 (NOT in the keyring), one
        // under v1 (IS in the keyring, off-key). Active is v2.
        // The sweep must filter v99 out and migrate v1.
        let crypto = two_key_crypto("v2");
        let store: SharedUpstreamSessionStore = Arc::new(FakeStore::default());
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v99",
                tokens_ciphertext: b"opaque",
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let v1_ct = UpstreamCrypto::from_key_bytes([1u8; 32])
            .encrypt(b"bob-envelope")
            .unwrap();
        store
            .upsert(NewSessionRow {
                sub: "bob",
                upstream_issuer: "https://idp.test",
                key_id: "v1",
                tokens_ciphertext: &v1_ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let stats = re_encrypt_batch(&crypto, &store, 10).await.unwrap();
        assert_eq!(
            stats.migrated, 1,
            "decryptable v1 row must migrate even when an undecryptable v99 row exists",
        );
        assert_eq!(
            stats.decrypt_failures, 0,
            "v99 row is filtered at SQL level, never reaches process_row",
        );
        // Alice's v99 row is still in the store — surfaced via the
        // admin list endpoint, not via sweeper retries.
        let alice = store
            .get("alice", "https://idp.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.key_id, "v99");
    }

    #[tokio::test]
    async fn batch_noop_when_all_rows_on_active_key() {
        let crypto = two_key_crypto("v2");
        let store: SharedUpstreamSessionStore = Arc::new(FakeStore::default());
        let ct = crypto.encrypt(b"already-v2").unwrap();
        store
            .upsert(NewSessionRow {
                sub: "alice",
                upstream_issuer: "https://idp.test",
                key_id: "v2",
                tokens_ciphertext: &ct,
                access_expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let stats = re_encrypt_batch(&crypto, &store, 10).await.unwrap();
        assert_eq!(stats.total(), 0);
    }
}
