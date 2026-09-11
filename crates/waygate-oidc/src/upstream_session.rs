//! The upstream-session seam for Tier-A identity chaining.
//!
//! The data-plane pool (`waygate-upstream`) needs three things to resolve
//! a Tier-A subject token: the durable session-row store, the sealed
//! token envelope's shape, and refresh-on-demand. Those used to live in
//! `waygate-as`, which made the pool link the whole OAuth
//! Authorization-Server crate for what are pure seam types. This module
//! owns the seam; `waygate-as` keeps the implementations
//! (`PgUpstreamSessionStore`, `SessionRefresher`) and re-exports these
//! items at their historical paths, and `waygate-server` injects the
//! impls into the pool.
//!
//! Layering: `waygate-oidc` already owns the AEAD envelope
//! ([`crate::aead`]), the keyring over it ([`crate::upstream_crypto`]),
//! and the IdP refresh HTTP call (`refresh_access_token`) — the session
//! seam completes the set. Nothing here touches `sqlx`; the store error's
//! backing source is type-erased ([`BoxedStoreError`]).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::upstream_crypto::CryptoError;

/// Decoupled store surface so callers don't reach for the Postgres pool
/// directly. Tests implement an in-memory variant; the production path
/// uses `waygate_as::sessions::PgUpstreamSessionStore`.
#[async_trait]
pub trait UpstreamSessionStore: Send + Sync + 'static {
    /// Insert-or-replace the ciphertext + expiry for the given
    /// `(sub, upstream_issuer)` pair. Atomic: a concurrent write that
    /// reaches the same pair while the first is in flight produces
    /// last-writer-wins semantics keyed on Postgres row locks, which
    /// is the right shape — both writers presented a fresh upstream
    /// access token, so either is correct to keep.
    async fn upsert(&self, row: NewSessionRow<'_>) -> Result<(), SessionStoreError>;

    /// Look up the current ciphertext + expiry for the given
    /// `(sub, upstream_issuer)` pair. Returns `None` when the row is
    /// absent (user has never authenticated against the upstream IdP,
    /// OR a `revoke` / `sweep_expired` removed it). The hot-path
    /// Tier-A read in `waygate-upstream::IdentityAugmenter` calls
    /// this once per tool dispatch — keep it lean.
    async fn get(
        &self,
        sub: &str,
        upstream_issuer: &str,
    ) -> Result<Option<StoredSessionRow>, SessionStoreError>;

    /// Drop the row for `(sub, upstream_issuer)`. Used by the admin
    /// revoke endpoint — the operator's
    /// intent is "burn the session" and there's no analogous race.
    /// The refresh-on-demand path uses
    /// [`Self::revoke_if_ciphertext_matches`] instead, which is the
    /// safe variant for concurrent refreshes.
    ///
    /// Returns `true` when a row was removed, `false` when there was
    /// nothing to remove. Callers can ignore the boolean for
    /// idempotent operations (admin revoke is happy either way).
    async fn revoke(&self, sub: &str, upstream_issuer: &str) -> Result<bool, SessionStoreError>;

    /// Conditional revoke: delete the row for `(sub, upstream_issuer)`
    /// **only if** its current `tokens_ciphertext` byte-for-byte
    /// matches `expected_ciphertext`. Returns `true` iff a row was
    /// deleted.
    ///
    /// Closes a concurrent-refresh race: two concurrent expired-session
    /// calls to *different* Tier-A upstreams both read the same row,
    /// both POST the IdP with the same refresh token. The IdP rotates,
    /// so the winner's UPSERT writes a fresh `rt-B` envelope and the
    /// loser receives `invalid_grant` on `rt-A`. An unconditional
    /// `revoke` from the loser would delete the fresh row the winner
    /// just wrote — user loses their session. Conditional revoke uses
    /// the loser's pre-refresh ciphertext as a discriminator: when
    /// the row's current ciphertext is the winner's fresh envelope,
    /// the WHERE doesn't match and the DELETE is a safe no-op.
    async fn revoke_if_ciphertext_matches(
        &self,
        sub: &str,
        upstream_issuer: &str,
        expected_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError>;

    /// Refresh-on-demand write path. Updates the row in place ONLY
    /// when its current `tokens_ciphertext` byte-for-byte matches
    /// `expected_old_ciphertext` (the bytes the refresher just
    /// decrypted before posting the IdP). Returns `Ok(true)` iff
    /// a row was updated; `Ok(false)` covers both "row gone" and
    /// "row replaced".
    ///
    /// Two race windows — row-gone resurrect and row-replaced
    /// overwrite — close with the same CAS:
    ///
    /// 1. Resurrect: admin `revoke()` deletes the row while a
    ///    refresh is in flight. A bare `upsert` here would
    ///    INSERT a fresh row and undo the operator's intent.
    /// 2. Overwrite: admin `revoke()` deletes the row, then the
    ///    user re-completes `/oauth/callback` (legitimate
    ///    `upsert`-INSERT of a fresh envelope C3), THEN the
    ///    original in-flight refresh writes its stale-relative-to-
    ///    revoke envelope C2. A bare `UPDATE WHERE (sub,issuer)`
    ///    would clobber the user's fresh C3 with C2.
    ///
    /// Distinct from [`Self::revoke_if_ciphertext_matches`]:
    /// that uses the CAS to DELETE; this uses it to UPDATE. Same
    /// discriminator (pre-refresh ciphertext as the row's
    /// "version" identifier), opposite operation.
    ///
    /// The first-write path (`/oauth/callback` after a user
    /// re-authenticates) keeps using `upsert` — that's a
    /// legitimate "create the row" event from a user action, not
    /// a background refresh trying to write under a replaced row.
    async fn update_if_ciphertext_matches(
        &self,
        row: NewSessionRow<'_>,
        expected_old_ciphertext: &[u8],
    ) -> Result<bool, SessionStoreError>;

    /// Enumerate rows whose `key_id` is not the
    /// active id, so the background re-encrypt sweeper can migrate
    /// them under the current key. Returns `(sub, upstream_issuer,
    /// key_id, tokens_ciphertext)` for each row — enough for the
    /// sweeper to decrypt under the stored key, re-encrypt under
    /// the active key, and CAS-update via
    /// [`Self::update_if_ciphertext_matches`].
    ///
    /// `limit` caps the page size so a deployment with millions of
    /// off-key rows doesn't pull the world into memory. The
    /// Postgres impl applies the same `MAX_LIST_LIMIT` hard cap as
    /// the admin list path.
    ///
    /// `decryptable_key_ids` is the set of keyring ids the current
    /// `UpstreamCrypto` can decrypt under — typically every entry
    /// in the operator's `GATEWAY_UPSTREAM_TOKEN_KEY_<id>` family.
    /// Rows stamped with an id outside this set (e.g. operator
    /// decommissioned an old key before every row migrated) are
    /// filtered out at the SQL level.
    /// Without the filter, a batch full of undecryptable
    /// rows could starve the sweeper indefinitely, blocking
    /// progress on later decryptable rows. Surfacing those rows
    /// stays the admin endpoint's job (the `key_id` field on the
    /// list response).
    async fn list_off_active_key(
        &self,
        active_id: &str,
        decryptable_key_ids: &[String],
        limit: u32,
    ) -> Result<Vec<OffKeyRow>, SessionStoreError>;

    /// Paginated metadata list for the admin
    /// `GET /api/v1/admin/upstream_sessions` endpoint. Returns
    /// `(sub, upstream_issuer, access_expires_at, refreshed_at,
    /// created_at)` ordered by `(sub, upstream_issuer)` so a
    /// long-poll operator workflow sees stable ordering across
    /// pages. Does NOT return `tokens_ciphertext` — the encrypted
    /// bearer envelope is for the gateway's per-call Tier-A path
    /// only, never the admin read surface.
    ///
    /// `limit` caps how many rows per page. The Postgres impl
    /// applies a hard upper bound (currently 500) regardless of
    /// what the caller passes, so a misconfigured admin client
    /// can't accidentally fetch the whole table.
    async fn list_all(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionMetadata>, SessionStoreError>;

    /// Bulk-delete rows whose `access_expires_at` is older than
    /// `now() - retain`. Intended for a periodic background sweeper
    /// (caller wiring lands alongside the refresh-on-demand slice) —
    /// a long-stale row is one whose access token has been expired
    /// for so long that even refresh-on-demand can't recover (the
    /// upstream's refresh-token TTL is up). Returns the number of
    /// rows removed for observability.
    ///
    /// The `access_expires_at` cutoff is conservative: this layer
    /// doesn't know the IdP's refresh-token TTL, so the caller
    /// supplies `retain` as a soft retention policy.
    async fn sweep_expired(&self, retain: Duration) -> Result<u64, SessionStoreError>;
}

/// New / refreshed row to be persisted. Borrowed where it makes sense
/// to keep the call site from cloning the ciphertext into a `Vec<u8>`
/// (the encrypted envelope can be up to a few KiB; cloning per-write
/// is wasteful when the buffer is already owned by the caller).
#[derive(Debug)]
pub struct NewSessionRow<'a> {
    pub sub: &'a str,
    pub upstream_issuer: &'a str,
    pub tokens_ciphertext: &'a [u8],
    /// Identifier of the `UpstreamCrypto` keyring entry that produced
    /// `tokens_ciphertext`. Persisted in the
    /// `user_upstream_sessions.key_id` column so a future decrypt
    /// can route to the correct key after the operator rotates the
    /// active key. Callers source this from
    /// `UpstreamCrypto::active_id` immediately before calling
    /// `encrypt`; the two are paired by construction so a write
    /// never stamps a stale id.
    pub key_id: &'a str,
    /// Absolute wall-clock time the upstream access token expires.
    /// Carrying this on the row (rather than recomputing from
    /// `expires_in` on read) means a refresh-on-demand caller can do
    /// a `WHERE access_expires_at < now()` filter cheaply.
    pub access_expires_at: OffsetDateTime,
}

/// Read-side view returned by [`UpstreamSessionStore::get`]. Carries
/// the encrypted envelope (caller decrypts with the gateway's
/// `UpstreamCrypto`) plus the access-token expiry so the caller can
/// decide whether to use the stored token directly, refresh first,
/// or fall back to the existing identity path.
#[derive(Debug, Clone)]
pub struct StoredSessionRow {
    pub tokens_ciphertext: Vec<u8>,
    /// Keyring id under which `tokens_ciphertext` was encrypted.
    /// The caller routes `UpstreamCrypto::decrypt`
    /// to the matching key. When the stored id isn't in the current
    /// keyring (operator removed a key without re-encrypting every
    /// row) the decrypt call returns
    /// [`crate::upstream_crypto::CryptoError::UnknownKeyId`] and the Tier-A
    /// path falls back per `tier_a_required`.
    pub key_id: String,
    pub access_expires_at: OffsetDateTime,
    pub refreshed_at: OffsetDateTime,
}

/// Type-erased handle for `AsState` and `UpstreamPool` — same
/// `Arc<dyn ...>` shape every other store in this crate uses.
pub type SharedUpstreamSessionStore = Arc<dyn UpstreamSessionStore>;

/// Hard ceiling on `UpstreamSessionStore::list_all` page size. A
/// misconfigured admin client asking for `limit=1000` is silently
/// capped to this value by the Postgres impl's `list_all`.
/// Exported so callers (the admin handler) can clamp BEFORE
/// calling `list_all` and echo the actually-applied limit to the
/// client — paging by an echoed-but-uncapped limit would otherwise
/// skip rows.
pub use waygate_core::page::MAX_LIST_LIMIT;

/// Per-row metadata returned by [`UpstreamSessionStore::list_all`].
/// Deliberately ciphertext-free so the admin read surface never
/// exposes decryptable bearer material.
/// A single row pulled by
/// [`UpstreamSessionStore::list_off_active_key`] for the
/// re-encrypt sweeper to process. Carries both `key_id` (for the
/// decrypt routing) and `tokens_ciphertext` (for the CAS witness
/// when the sweeper writes the new envelope back under the active
/// key).
#[derive(Debug, Clone)]
pub struct OffKeyRow {
    pub sub: String,
    pub upstream_issuer: String,
    pub key_id: String,
    pub tokens_ciphertext: Vec<u8>,
    pub access_expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub sub: String,
    pub upstream_issuer: String,
    /// Surfaced on the admin list endpoint so an operator can
    /// confirm a rotation has completed (every row's `key_id`
    /// equals the current active id).
    pub key_id: String,
    pub access_expires_at: OffsetDateTime,
    pub refreshed_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Type-erased backing-store error so this seam crate does not link
/// `sqlx` (the Postgres impl lives in `waygate-as`). `Display` output
/// is unchanged from the pre-split `sqlx::Error`-sourced variant.
pub type BoxedStoreError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("upstream session store: {0}")]
    Database(#[source] BoxedStoreError),
}

impl SessionStoreError {
    /// Point-free-friendly constructor for `map_err`.
    pub fn database(e: impl Into<BoxedStoreError>) -> Self {
        Self::Database(e.into())
    }
}

/// Stored envelope for the upstream token pair. Serialized with serde_json
/// before AES-GCM encryption — avoids hand-rolled framing.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpstreamTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("decrypt stored envelope: {0}")]
    Decrypt(#[source] CryptoError),
    #[error("re-encrypt fresh envelope: {0}")]
    Encrypt(#[source] CryptoError),
    #[error("envelope JSON shape: {0}")]
    EnvelopeParse(String),
    #[error("stored envelope has no refresh_token; falling back")]
    NoRefreshToken,
    #[error("refresh token revoked at IdP ({body}); row dropped")]
    RefreshTokenRevoked { body: String },
    /// Between this
    /// refresher's read of the stored row and its post-IdP write,
    /// the row's identity changed: either an admin
    /// `/api/v1/admin/upstream_sessions` DELETE removed it
    /// (the resurrect race), or admin DELETE plus a user
    /// re-auth via `/oauth/callback` produced a fresh envelope
    /// before this stale refresh could write (the overwrite
    /// race). `update_if_ciphertext_matches` matched 0 rows in
    /// either case; we refuse to write the stale refreshed
    /// envelope. Caller falls through to the standard
    /// no-stored-token path (under `tier_a_required: true` the
    /// upstream pool refuses dispatch; otherwise a subsequent
    /// call re-reads whatever row exists now).
    #[error("session row changed during refresh; refusing to write stale envelope")]
    RevokedDuringRefresh,
    #[error("IdP rejected refresh ({status}): {body}")]
    Idp {
        status: http::StatusCode,
        body: String,
    },
    #[error("IdP transport: {0}")]
    IdpTransport(String),
    #[error("session store: {0}")]
    Store(#[source] SessionStoreError),
}

/// Refresh-on-demand seam consumed by the upstream pool when a stored
/// access token is at/near expiry. Implemented by
/// `waygate_as::session_refresh::SessionRefresher` (decrypt current
/// envelope -> POST the IdP -> re-encrypt -> CAS-update the row);
/// the pool only ever calls this one method.
#[async_trait]
pub trait SessionRefresh: Send + Sync + 'static {
    async fn refresh(
        &self,
        sub: &str,
        upstream_issuer: &str,
        current_ciphertext: &[u8],
        current_key_id: &str,
    ) -> Result<UpstreamTokens, RefreshError>;
}

/// Type-erased handle. `UpstreamPool` carries it in the Tier-A bundle
/// alongside `SharedUpstreamSessionStore` + `Arc<UpstreamCrypto>`.
pub type SharedSessionRefresher = Arc<dyn SessionRefresh>;
