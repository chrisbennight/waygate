//! Post-callback pre-consent state.
//!
//! When the OAuth callback resolves the user's identity
//! and the gateway-wide `require_explicit_consent` flag is
//! on (and the user hasn't already granted), the AS
//! pauses BEFORE minting its own authorization code: it
//! persists the post-id-token state as a pending row,
//! 302s the user to `/oauth/consent?token=…`, and only
//! drains the row when the user clicks approve.
//!
//! ## Why a dedicated table
//!
//! `oauth_transactions` is the pre-authorize state and
//! gets DELETEd by `take_transaction` on the FIRST
//! callback hit. The pending state is what's left AFTER
//! that delete — different lifecycle, different
//! columns. A pending row preserves the validated identity and requested
//! authorization while the user decides whether to grant consent.
//!
//! ## CSRF posture
//!
//! `token` is a random 32-byte URL-safe identifier
//! created in [`Token::new`]. It functions as both the
//! lookup key AND the CSRF token: the POST handler
//! requires the token in the form body matching the
//! token in the URL; an attacker without the value
//! can't manufacture a successful approval. The token
//! is single-use (the POST handler DELETEs the row
//! atomically before the redirect).

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct PendingConsent {
    pub token: String,
    pub tenant_id: String,
    pub principal_sub: String,
    pub principal_email: Option<String>,
    pub principal_groups: Vec<String>,
    pub client_id: String,
    pub client_redirect_uri: String,
    pub client_state: Option<String>,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub upstream_tokens_ciphertext: Vec<u8>,
    pub key_id: String,
    /// Real upstream IdP access-token expiry (from
    /// `token_resp.expires_in`). Carried so the approve-path's
    /// `user_upstream_sessions` write records the REAL
    /// expiry rather than synthesising `now() + 1h`.
    pub access_expires_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct NewPendingConsent<'a> {
    pub token: &'a str,
    pub tenant_id: &'a str,
    pub principal_sub: &'a str,
    pub principal_email: Option<&'a str>,
    pub principal_groups: &'a [String],
    pub client_id: &'a str,
    pub client_redirect_uri: &'a str,
    pub client_state: Option<&'a str>,
    pub code_challenge: &'a str,
    pub scopes: &'a [String],
    pub upstream_tokens_ciphertext: &'a [u8],
    pub key_id: &'a str,
    pub access_expires_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[async_trait]
pub trait ConsentPendingStore: Send + Sync + 'static {
    /// Persist a pending row. Token is the caller's
    /// concern — produce via `waygate_oidc::pkce::new_random_token`
    /// to inherit the same RNG quality as PKCE
    /// verifiers.
    async fn insert(&self, pending: NewPendingConsent<'_>) -> Result<(), ConsentPendingError>;

    /// Look up a pending row by token. `Ok(None)` when
    /// the token is unknown OR the row is expired —
    /// the SQL filter does both at once so the GET
    /// /oauth/consent handler doesn't need to
    /// re-evaluate.
    async fn get(&self, token: &str) -> Result<Option<PendingConsent>, ConsentPendingError>;

    /// Single-use take: DELETE the row by token and
    /// return it if it WAS live (not expired). The
    /// POST handler calls this on approve so the row
    /// disappears atomically before the redirect.
    /// On deny, the POST handler also calls take
    /// (and discards the result) so the row doesn't
    /// linger.
    async fn take(&self, token: &str) -> Result<Option<PendingConsent>, ConsentPendingError>;

    /// Sweep expired rows. Returns the number deleted.
    /// Called by the existing OAuth-state periodic
    /// sweeper.
    async fn sweep_expired(&self) -> Result<u64, ConsentPendingError>;
}

pub type SharedConsentPendingStore = Arc<dyn ConsentPendingStore>;

#[derive(Debug, thiserror::Error)]
pub enum ConsentPendingError {
    #[error("consent pending store: {0}")]
    Database(#[source] sqlx::Error),
}

#[derive(Clone)]
pub struct PgConsentPendingStore {
    pool: PgPool,
}

impl PgConsentPendingStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConsentPendingStore for PgConsentPendingStore {
    async fn insert(&self, p: NewPendingConsent<'_>) -> Result<(), ConsentPendingError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_consent_pending
                (token, tenant_id, principal_sub, principal_email,
                 principal_groups, client_id, client_redirect_uri,
                 client_state, code_challenge, scopes,
                 upstream_tokens_ciphertext, key_id,
                 access_expires_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(p.token)
        .bind(p.tenant_id)
        .bind(p.principal_sub)
        .bind(p.principal_email)
        .bind(p.principal_groups)
        .bind(p.client_id)
        .bind(p.client_redirect_uri)
        .bind(p.client_state)
        .bind(p.code_challenge)
        .bind(p.scopes)
        .bind(p.upstream_tokens_ciphertext)
        .bind(p.key_id)
        .bind(p.access_expires_at)
        .bind(p.expires_at)
        .execute(&self.pool)
        .await
        .map_err(ConsentPendingError::Database)?;
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<PendingConsent>, ConsentPendingError> {
        let row = sqlx::query(
            r#"
            SELECT token, tenant_id, principal_sub, principal_email,
                   principal_groups, client_id, client_redirect_uri,
                   client_state, code_challenge, scopes,
                   upstream_tokens_ciphertext, key_id,
                   access_expires_at, expires_at
              FROM oauth_consent_pending
             WHERE token = $1 AND expires_at > now()
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(ConsentPendingError::Database)?;
        Ok(row.as_ref().map(row_to_pending))
    }

    async fn take(&self, token: &str) -> Result<Option<PendingConsent>, ConsentPendingError> {
        // DELETE … RETURNING is atomic per row; the
        // `expires_at > now()` filter means an expired
        // row neither returns nor deletes (the sweep
        // path catches it later). A live row is
        // returned exactly once across racing callers.
        let row = sqlx::query(
            r#"
            DELETE FROM oauth_consent_pending
             WHERE token = $1 AND expires_at > now()
            RETURNING token, tenant_id, principal_sub, principal_email,
                      principal_groups, client_id, client_redirect_uri,
                      client_state, code_challenge, scopes,
                      upstream_tokens_ciphertext, key_id,
                      access_expires_at, expires_at
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(ConsentPendingError::Database)?;
        Ok(row.as_ref().map(row_to_pending))
    }

    async fn sweep_expired(&self) -> Result<u64, ConsentPendingError> {
        let res = sqlx::query("DELETE FROM oauth_consent_pending WHERE expires_at <= now()")
            .execute(&self.pool)
            .await
            .map_err(ConsentPendingError::Database)?;
        Ok(res.rows_affected())
    }
}

fn row_to_pending(row: &sqlx::postgres::PgRow) -> PendingConsent {
    PendingConsent {
        token: row.get("token"),
        tenant_id: row.get("tenant_id"),
        principal_sub: row.get("principal_sub"),
        principal_email: row.get("principal_email"),
        principal_groups: row.get("principal_groups"),
        client_id: row.get("client_id"),
        client_redirect_uri: row.get("client_redirect_uri"),
        client_state: row.get("client_state"),
        code_challenge: row.get("code_challenge"),
        scopes: row.get("scopes"),
        upstream_tokens_ciphertext: row.get("upstream_tokens_ciphertext"),
        key_id: row.get("key_id"),
        access_expires_at: row.get("access_expires_at"),
        expires_at: row.get("expires_at"),
    }
}
