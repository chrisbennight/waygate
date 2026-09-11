//! `oauth_consent` — per-(tenant, principal, client) consent
//! grant persistence.
//!
//! ## What this is
//!
//! A row recording that a named CIMD client has been
//! authorized to act on behalf of a user with a particular
//! scope set. Written at `/oauth/callback` completion: the
//! upstream IdP has already proved the user's identity (id
//! token signature + iss + aud validated by
//! [`waygate_oidc::IdTokenValidator`]), the gateway is
//! about to mint its own authorization code into
//! `oauth_codes`, and the consent row lands between those
//! two steps so the audit trail captures the grant before
//! the code can be redeemed.
//!
//! ## How the gate uses it
//!
//! This is the data layer plus the admin surface (list /
//! revoke). When the gateway-wide `require_explicit_consent`
//! flag is off, or the user already has an active grant
//! covering the requested scopes, the callback path UPSERTs
//! the row unconditionally on every successful
//! authorize-then-callback flow. When the flag is on and no
//! covering grant exists, the same row becomes the lookup
//! the gate consults ("does this user already have a grant
//! covering this client + scopes?"), and its absence routes
//! the browser through the interactive consent screen (see
//! [`crate::consent_screen`], [`crate::consent_pending`])
//! before the code-mint write.
//!
//! ## Why a separate store (not just SQL in callback.rs)
//!
//! The admin surface needs the same surface — list grants,
//! revoke a grant — so a trait that both `callback.rs` and
//! the `waygate-admin` handler can use keeps the SQL
//! single-sourced. Same pattern as
//! [`crate::sessions::UpstreamSessionStore`].

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// Decoupled store surface used by `/oauth/callback` to
/// record a grant and by the admin handler to list /
/// revoke. Tests use an in-memory variant; production uses
/// [`PgConsentStore`].
#[async_trait]
pub trait ConsentStore: Send + Sync + 'static {
    /// Insert-or-refresh the grant for the given
    /// `(tenant_id, principal_sub, client_id)`. On
    /// conflict the existing row's `scopes` is replaced
    /// with the new value, `granted_at` bumps to `now()`,
    /// and any prior `revoked_at` is cleared — a user
    /// re-completing the authorize flow after revocation
    /// is unambiguously re-granting consent, and the
    /// gateway has just received fresh upstream tokens to
    /// honour it. `expires_at` is overwritten too (NULL
    /// from the caller means "no expiry").
    async fn upsert(&self, grant: NewConsentGrant<'_>) -> Result<ConsentGrant, ConsentStoreError>;

    /// Page through grants for a tenant. When
    /// `principal_sub` is `Some`, scope to that user;
    /// otherwise return every grant in the tenant.
    /// Ordered by `(principal_sub, client_id)` for stable
    /// pagination. `limit` is clamped to
    /// [`MAX_LIST_LIMIT`] inside the Postgres impl so a
    /// misconfigured admin client can't fetch the whole
    /// table in one shot.
    async fn list(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ConsentGrant>, ConsentStoreError>;

    /// Soft-delete the grant for the full triple by
    /// stamping `revoked_at = now()`. Returns `true` when
    /// a row transitioned from "active" to "revoked",
    /// `false` when there was nothing to revoke (row
    /// absent, or already revoked). Revoking an
    /// already-revoked grant is a no-op — admin intent is
    /// idempotent ("burn this grant").
    async fn revoke(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<bool, ConsentStoreError>;

    /// Hot-path lookup the consent gate consults in
    /// `/oauth/callback`. Returns the active grant for
    /// the triple, or `None` when:
    ///
    /// - no row exists (this is the first time the user
    ///   has hit this client),
    /// - the row is soft-revoked (`revoked_at IS NOT NULL`),
    /// - or the row has an `expires_at` in the past.
    ///
    /// Any of those three states triggers the consent
    /// screen via the callback gate. The caller then
    /// additionally checks whether the active grant's
    /// `scopes` cover the request — a covered grant
    /// skips the screen; a scope-mismatch routes through
    /// the screen so the user can approve the new
    /// scope set.
    async fn find_active(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, ConsentStoreError>;
}

/// Owned input row for [`ConsentStore::upsert`]. Borrowed
/// where it makes sense (callers already own the strings
/// from the OAuth transaction record); `expires_at` is
/// owned so the caller can pass `None` without juggling
/// reference lifetimes.
#[derive(Debug)]
pub struct NewConsentGrant<'a> {
    pub tenant_id: &'a str,
    pub principal_sub: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub expires_at: Option<OffsetDateTime>,
}

/// Read-side view of a row. Returned by `upsert` (so the
/// callback can log the canonical `id` it just minted /
/// refreshed) and by `list`.
#[derive(Debug, Clone)]
pub struct ConsentGrant {
    pub id: Uuid,
    pub tenant_id: String,
    pub principal_sub: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Type-erased handle for `AsState` and `AdminState` — same
/// `Arc<dyn …>` shape every other store in this crate uses.
pub type SharedConsentStore = Arc<dyn ConsentStore>;

/// Hard ceiling on [`ConsentStore::list`] page size.
/// Mirrors [`crate::sessions::MAX_LIST_LIMIT`] so an
/// operator paging the consent table sees the same shape
/// as paging the upstream-sessions table. Exported so the
/// admin handler can clamp BEFORE calling `list` and echo
/// the actually-applied limit (paging by an echoed-but-
/// uncapped limit would skip rows).
pub use waygate_core::page::MAX_LIST_LIMIT;

#[derive(Debug, thiserror::Error)]
pub enum ConsentStoreError {
    #[error("consent store: {0}")]
    Database(#[source] sqlx::Error),
}

/// Postgres-backed [`ConsentStore`].
#[derive(Clone)]
pub struct PgConsentStore {
    pool: PgPool,
}

impl PgConsentStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConsentStore for PgConsentStore {
    async fn upsert(&self, grant: NewConsentGrant<'_>) -> Result<ConsentGrant, ConsentStoreError> {
        // ON CONFLICT branch: replace scopes, bump
        // granted_at, clear revoked_at. A user
        // re-completing /oauth/authorize after a prior
        // revocation is unambiguously re-granting, and the
        // gateway has just received fresh upstream tokens
        // to back the grant.
        let row = sqlx::query(
            r#"
            INSERT INTO oauth_consent
                (tenant_id, principal_sub, client_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, principal_sub, client_id)
            DO UPDATE SET
                scopes      = EXCLUDED.scopes,
                expires_at  = EXCLUDED.expires_at,
                granted_at  = now(),
                revoked_at  = NULL
            RETURNING id, tenant_id, principal_sub, client_id,
                      scopes, granted_at, expires_at, revoked_at
            "#,
        )
        .bind(grant.tenant_id)
        .bind(grant.principal_sub)
        .bind(grant.client_id)
        .bind(grant.scopes)
        .bind(grant.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(ConsentStoreError::Database)?;

        Ok(row_to_grant(&row))
    }

    async fn list(
        &self,
        tenant_id: &str,
        principal_sub: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ConsentGrant>, ConsentStoreError> {
        // Same MAX_LIST_LIMIT discipline as
        // upstream_sessions: clamp here so a misconfigured
        // caller can't fetch the whole table.
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;

        let rows = match principal_sub {
            Some(sub) => {
                sqlx::query(
                    r#"
                    SELECT id, tenant_id, principal_sub, client_id,
                           scopes, granted_at, expires_at, revoked_at
                      FROM oauth_consent
                     WHERE tenant_id = $1 AND principal_sub = $2
                     ORDER BY principal_sub, client_id
                     LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(sub)
                .bind(effective_limit)
                .bind(offset_i)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(
                    r#"
                    SELECT id, tenant_id, principal_sub, client_id,
                           scopes, granted_at, expires_at, revoked_at
                      FROM oauth_consent
                     WHERE tenant_id = $1
                     ORDER BY principal_sub, client_id
                     LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(tenant_id)
                .bind(effective_limit)
                .bind(offset_i)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(ConsentStoreError::Database)?;

        Ok(rows.iter().map(row_to_grant).collect())
    }

    async fn revoke(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<bool, ConsentStoreError> {
        // Conditional UPDATE: only flip rows that aren't
        // already revoked. `rows_affected() == 1` ⇒ "we
        // moved a live grant to revoked"; `0` ⇒ "nothing
        // to do" (absent or already revoked). The admin
        // endpoint maps both to 204, but reporting the
        // distinction lets the audit reason field be
        // accurate.
        let result = sqlx::query(
            r#"
            UPDATE oauth_consent
               SET revoked_at = now()
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND client_id = $3
               AND revoked_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(ConsentStoreError::Database)?;

        Ok(result.rows_affected() == 1)
    }

    async fn find_active(
        &self,
        tenant_id: &str,
        principal_sub: &str,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, ConsentStoreError> {
        // The partial index `oauth_consent_active_by_principal`
        // covers `(tenant_id, principal_sub) WHERE
        // revoked_at IS NULL`; the additional
        // `client_id = $3 AND (expires_at IS NULL OR
        // expires_at > now())` filters happen in the
        // SELECT projection (~O(grants-per-user-in-this-
        // tenant) candidates, typically <10).
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, client_id,
                   scopes, granted_at, expires_at, revoked_at
              FROM oauth_consent
             WHERE tenant_id = $1
               AND principal_sub = $2
               AND client_id = $3
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > now())
             LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(principal_sub)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ConsentStoreError::Database)?;

        Ok(row.as_ref().map(row_to_grant))
    }
}

fn row_to_grant(row: &sqlx::postgres::PgRow) -> ConsentGrant {
    ConsentGrant {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        principal_sub: row.get("principal_sub"),
        client_id: row.get("client_id"),
        scopes: row.get("scopes"),
        granted_at: row.get("granted_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    }
}
