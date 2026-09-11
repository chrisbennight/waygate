//! `user_upstream_sessions` — durable per-user, per-upstream encrypted
//! token envelopes for Tier-A identity chaining. See
//! [`crate::session_refresh`] for refresh-on-demand, [`crate::reencrypt_sweeper`]
//! for the background key-rotation sweeper, and
//! `crates/waygate-admin/src/upstream_sessions.rs` for the admin
//! list + revoke endpoints.
//!
//! ## Capabilities
//!
//! - Schema + `upsert` write path at `/oauth/callback`.
//! - `get` read path consumed by `waygate-upstream::IdentityAugmenter`
//!   so Tier-A RFC 8693 token exchange uses the user's stored upstream
//!   access token as the subject (instead of the gateway's bearer).
//! - `revoke` and `sweep_expired` for cleanup, plus
//!   `revoke_if_ciphertext_matches` for the conditional revoke on
//!   concurrent refresh.
//! - Refresh-on-demand against the upstream IdP token endpoint when
//!   the stored access token is past `access_expires_at` —
//!   implemented in [`crate::session_refresh`].
//! - Manifest `tier_a_required` fail-closed flag — the per-call
//!   pipeline refuses to dispatch unless a durable session yields a
//!   stored upstream subject token.
//! - Admin `/api/v1/admin/upstream_sessions` list + revoke endpoints
//!   (behind `mcp:admin`). Ciphertext-free list, idempotent revoke;
//!   `update_if_ciphertext_matches` closes the admin-revoke-vs-refresh
//!   race by CAS-ing on ciphertext rather than just
//!   `(sub, upstream_issuer)`.
//! - `UpstreamCrypto` keyring + `GATEWAY_UPSTREAM_TOKEN_KEY_<id>`
//!   env-var family + per-row `key_id` column — rotation no longer
//!   requires an outage.
//! - Background re-encrypt sweeper migrates rows whose `key_id` lags
//!   the active id forward under the active key — implemented in
//!   [`crate::reencrypt_sweeper`]. Same CAS-on-ciphertext as the
//!   refresh path, so concurrent admin DELETE, user re-auth, and
//!   refresh writes all win against a stale sweep write.

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::PgPool;

use sqlx::Row;
use time::OffsetDateTime;
pub use waygate_oidc::upstream_session::{
    NewSessionRow, OffKeyRow, SessionMetadata, SessionStoreError, SharedUpstreamSessionStore,
    StoredSessionRow, UpstreamSessionStore, MAX_LIST_LIMIT,
};

/// Postgres-backed [`UpstreamSessionStore`].
#[derive(Clone)]
pub struct PgUpstreamSessionStore {
    pool: PgPool,
}

impl PgUpstreamSessionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UpstreamSessionStore for PgUpstreamSessionStore {
    async fn upsert(&self, row: NewSessionRow<'_>) -> Result<(), SessionStoreError> {
        // ON CONFLICT (sub, upstream_issuer) DO UPDATE so a refresh-on-
        // demand path can call the same method without first checking
        // for a row. `refreshed_at = now()` on every UPSERT — including
        // the first insert — so a future "stale sessions" sweeper has a
        // monotonic timestamp regardless of where the row originated.
        sqlx::query(
            r#"
            INSERT INTO user_upstream_sessions
                (sub, upstream_issuer, tokens_ciphertext, key_id, access_expires_at, refreshed_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (sub, upstream_issuer) DO UPDATE
                SET tokens_ciphertext = EXCLUDED.tokens_ciphertext,
                    key_id            = EXCLUDED.key_id,
                    access_expires_at = EXCLUDED.access_expires_at,
                    refreshed_at      = now()
            "#,
        )
        .bind(row.sub)
        .bind(row.upstream_issuer)
        .bind(row.tokens_ciphertext)
        .bind(row.key_id)
        .bind(row.access_expires_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(SessionStoreError::database)
    }

    async fn get(
        &self,
        sub: &str,
        upstream_issuer: &str,
    ) -> Result<Option<StoredSessionRow>, SessionStoreError> {
        let row = sqlx::query(
            r#"
            SELECT tokens_ciphertext, key_id, access_expires_at, refreshed_at
              FROM user_upstream_sessions
             WHERE sub = $1 AND upstream_issuer = $2
            "#,
        )
        .bind(sub)
        .bind(upstream_issuer)
        .fetch_optional(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(row.map(|r| StoredSessionRow {
            tokens_ciphertext: r.get("tokens_ciphertext"),
            key_id: r.get("key_id"),
            access_expires_at: r.get("access_expires_at"),
            refreshed_at: r.get("refreshed_at"),
        }))
    }

    async fn revoke(&self, sub: &str, upstream_issuer: &str) -> Result<bool, SessionStoreError> {
        let res = sqlx::query(
            r#"
            DELETE FROM user_upstream_sessions
             WHERE sub = $1 AND upstream_issuer = $2
            "#,
        )
        .bind(sub)
        .bind(upstream_issuer)
        .execute(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(res.rows_affected() > 0)
    }

    async fn revoke_if_ciphertext_matches(
        &self,
        sub: &str,
        upstream_issuer: &str,
        expected_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        // The ciphertext comparison is a byte-level equality check
        // against the BYTEA column. Postgres handles this in a single
        // round-trip — no need to fetch-then-compare-then-delete
        // (which would itself be racy). The CAS-style WHERE makes
        // the operation atomic: if a sibling UPDATE landed between
        // our caller's read and this DELETE, the column no longer
        // matches and the DELETE is a no-op.
        let res = sqlx::query(
            r#"
            DELETE FROM user_upstream_sessions
             WHERE sub = $1
               AND upstream_issuer = $2
               AND tokens_ciphertext = $3
            "#,
        )
        .bind(sub)
        .bind(upstream_issuer)
        .bind(expected_ciphertext)
        .execute(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(res.rows_affected() > 0)
    }

    async fn update_if_ciphertext_matches(
        &self,
        row: NewSessionRow<'_>,
        expected_old_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError> {
        // CAS on `tokens_ciphertext`: only update when the row's
        // current ciphertext is byte-equal to what the refresher
        // just decrypted. Closes two races:
        // (a) admin DELETE followed by in-flight refresh write
        //     would INSERT-resurrect via `upsert`; here the WHERE
        //     matches 0 rows (row absent) → no-op.
        // (b) admin DELETE → user re-auth via `/oauth/callback`
        //     (upsert-INSERT of fresh envelope C3) → in-flight
        //     refresh writes; a bare UPDATE-on-(sub,issuer) would
        //     clobber C3 with the pre-revoke C2. Here the WHERE
        //     adds `AND tokens_ciphertext = $5` (which is C1),
        //     doesn't match C3, no-op.
        let res = sqlx::query(
            r#"
            UPDATE user_upstream_sessions
               SET tokens_ciphertext = $3,
                   key_id            = $4,
                   access_expires_at = $5,
                   refreshed_at      = now()
             WHERE sub = $1
               AND upstream_issuer = $2
               AND tokens_ciphertext = $6
            "#,
        )
        .bind(row.sub)
        .bind(row.upstream_issuer)
        .bind(row.tokens_ciphertext)
        .bind(row.key_id)
        .bind(row.access_expires_at)
        .bind(expected_old_ciphertext)
        .execute(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_all(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionMetadata>, SessionStoreError> {
        // Hard cap: a buggy admin client paging through too aggressively
        // shouldn't be able to ask the gateway to serialize the whole
        // table in one shot. 500 is generous for human-driven UI use
        // and tight enough to bound worst-case JSON payload size.
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let rows = sqlx::query(
            r#"
            SELECT sub, upstream_issuer, key_id, access_expires_at, refreshed_at, created_at
              FROM user_upstream_sessions
             ORDER BY sub, upstream_issuer
             LIMIT $1 OFFSET $2
            "#,
        )
        .bind(effective_limit)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(rows
            .into_iter()
            .map(|r| SessionMetadata {
                sub: r.get("sub"),
                upstream_issuer: r.get("upstream_issuer"),
                key_id: r.get("key_id"),
                access_expires_at: r.get("access_expires_at"),
                refreshed_at: r.get("refreshed_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn list_off_active_key(
        &self,
        active_id: &str,
        decryptable_key_ids: &[String],
        limit: u32,
    ) -> Result<Vec<OffKeyRow>, SessionStoreError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        // `key_id = ANY($2)` filters at the SQL level so a batch full
        // of undecryptable rows doesn't starve the sweeper. The
        // `decryptable_key_ids` slice is
        // typically every entry in the operator's
        // `GATEWAY_UPSTREAM_TOKEN_KEY_<id>` family; rows stamped
        // with an id outside that set are operator-actionable
        // through the admin list endpoint.
        let rows = sqlx::query(
            r#"
            SELECT sub, upstream_issuer, key_id, tokens_ciphertext, access_expires_at
              FROM user_upstream_sessions
             WHERE key_id <> $1
               AND key_id = ANY($2)
             ORDER BY sub, upstream_issuer
             LIMIT $3
            "#,
        )
        .bind(active_id)
        .bind(decryptable_key_ids)
        .bind(effective_limit)
        .fetch_all(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(rows
            .into_iter()
            .map(|r| OffKeyRow {
                sub: r.get("sub"),
                upstream_issuer: r.get("upstream_issuer"),
                key_id: r.get("key_id"),
                tokens_ciphertext: r.get("tokens_ciphertext"),
                access_expires_at: r.get("access_expires_at"),
            })
            .collect())
    }

    async fn sweep_expired(&self, retain: Duration) -> Result<u64, SessionStoreError> {
        // `retain` ≥ 0 — saturating arithmetic against the system
        // clock so a wildly large retention doesn't underflow `now()`.
        let cutoff = OffsetDateTime::now_utc()
            - time::Duration::seconds(retain.as_secs().min(i64::MAX as u64) as i64);
        let res = sqlx::query(
            r#"
            DELETE FROM user_upstream_sessions
             WHERE access_expires_at < $1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .map_err(SessionStoreError::database)?;
        Ok(res.rows_affected())
    }
}
