//! Confidential OAuth client registry for EMA ID-JAG redemption.
//!
//! The `jwt-bearer` redeem path requires the redeeming client to authenticate
//! with a registered credential (draft-ietf-oauth-identity-assertion-authz-grant
//! §4.4 / §9.1 — confidential clients only). CIMD clients are public, so
//! confidential clients are a separate, operator-registered set stored in
//! `oauth_confidential_clients` (migration 0061). A client authenticates by
//! `client_secret` (argon2id) and/or `private_key_jwt` (its public JWKS).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum ConfidentialClientError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// A registered confidential client. Carries the argon2id `secret_hash`
/// (never the plaintext) and/or the client's public `jwks` for
/// private_key_jwt verification.
#[derive(Debug, Clone)]
pub struct ConfidentialClient {
    pub client_id: String,
    pub secret_hash: Option<String>,
    pub jwks: Option<JsonValue>,
    pub created_at: OffsetDateTime,
}

impl ConfidentialClient {
    pub fn has_secret(&self) -> bool {
        self.secret_hash.is_some()
    }
    pub fn has_jwks(&self) -> bool {
        self.jwks.is_some()
    }
}

/// Store for confidential clients. Trait-backed (mirroring `SharedConsentStore`)
/// so `waygate-admin` and tests can share one handle / fake it.
#[async_trait]
pub trait ConfidentialClientStore: Send + Sync {
    /// Create or replace a confidential client. At least one of `secret_hash`
    /// / `jwks` must be `Some` (the DB CHECK also enforces this).
    async fn upsert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&JsonValue>,
    ) -> Result<(), ConfidentialClientError>;

    /// Insert a NEW client. Returns `true` iff a row was inserted; `false`
    /// when `client_id` already exists (no overwrite). Atomic — the conditional
    /// INSERT + rows-affected has no read-then-write window, so two concurrent
    /// registrations can't both "win" and silently clobber each other's
    /// credential. The admin create path uses this to return `409` on a
    /// duplicate rather than racing through `upsert`.
    async fn insert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&JsonValue>,
    ) -> Result<bool, ConfidentialClientError>;

    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<ConfidentialClient>, ConfidentialClientError>;

    /// List registered clients. `secret_hash` is included on the struct but
    /// callers (the admin list endpoint) MUST NOT serialize it.
    async fn list(&self) -> Result<Vec<ConfidentialClient>, ConfidentialClientError>;

    /// Delete a client. Returns `true` iff a row was removed.
    async fn delete(&self, client_id: &str) -> Result<bool, ConfidentialClientError>;
}

pub type SharedConfidentialClientStore = Arc<dyn ConfidentialClientStore>;

#[derive(Clone)]
pub struct PgConfidentialClientStore {
    pool: PgPool,
}

impl PgConfidentialClientStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConfidentialClientStore for PgConfidentialClientStore {
    async fn upsert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&JsonValue>,
    ) -> Result<(), ConfidentialClientError> {
        sqlx::query(
            r#"
            INSERT INTO oauth_confidential_clients (client_id, secret_hash, jwks)
            VALUES ($1, $2, $3)
            ON CONFLICT (client_id) DO UPDATE
              SET secret_hash = EXCLUDED.secret_hash,
                  jwks        = EXCLUDED.jwks
            "#,
        )
        .bind(client_id)
        .bind(secret_hash)
        .bind(jwks)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert(
        &self,
        client_id: &str,
        secret_hash: Option<&str>,
        jwks: Option<&JsonValue>,
    ) -> Result<bool, ConfidentialClientError> {
        let result = sqlx::query(
            r#"
            INSERT INTO oauth_confidential_clients (client_id, secret_hash, jwks)
            VALUES ($1, $2, $3)
            ON CONFLICT (client_id) DO NOTHING
            "#,
        )
        .bind(client_id)
        .bind(secret_hash)
        .bind(jwks)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get(
        &self,
        client_id: &str,
    ) -> Result<Option<ConfidentialClient>, ConfidentialClientError> {
        let row = sqlx::query_as::<_, ClientRow>(
            r#"
            SELECT client_id, secret_hash, jwks, created_at
            FROM oauth_confidential_clients
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(ConfidentialClient::from))
    }

    async fn list(&self) -> Result<Vec<ConfidentialClient>, ConfidentialClientError> {
        let rows = sqlx::query_as::<_, ClientRow>(
            r#"
            SELECT client_id, secret_hash, jwks, created_at
            FROM oauth_confidential_clients
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(ConfidentialClient::from).collect())
    }

    async fn delete(&self, client_id: &str) -> Result<bool, ConfidentialClientError> {
        let result = sqlx::query("DELETE FROM oauth_confidential_clients WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[derive(sqlx::FromRow)]
struct ClientRow {
    client_id: String,
    secret_hash: Option<String>,
    jwks: Option<JsonValue>,
    created_at: OffsetDateTime,
}

impl From<ClientRow> for ConfidentialClient {
    fn from(r: ClientRow) -> Self {
        Self {
            client_id: r.client_id,
            secret_hash: r.secret_hash,
            jwks: r.jwks,
            created_at: r.created_at,
        }
    }
}
