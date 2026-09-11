//! Federated gateway peer support.
//!
//! Owns the `federated_peers` table (migration 0033) — the
//! operator-approved list of remote MCP gateways this
//! gateway will federate with via Tier-C identity chaining
//! (gateway-to-gateway signed assertions).
//!
//! ## Why this crate
//!
//! Same per-feature shape as the `waygate-dashboard-stores`
//! modules / `waygate-quota`: dependency-
//! light, owns its own trait + types + Pg impl. The runtime
//! consumers (JWKS fetcher cache below, the peer-assertion
//! validator, and per-upstream `tier_c_peer:<id>` identity
//! selection) all live in this crate so the federation
//! surface stays cohesive.
//!
//! ## Module map
//!
//! - This file: `federated_peers` storage trait + Pg impl +
//!   types.
//! - [`jwks`]: periodic JWKS fetcher + in-memory cache so
//!   the peer-assertion validator has verified key material
//!   to check signatures against.
//!
//! ## Trust boundary
//!
//! Storage + admin CRUD and the JWKS supply pipeline are
//! necessary but not sufficient for trust: a row in
//! `federated_peers` becomes *materially* trusted only once
//! the bearer middleware consumes `peer_jwks_cache` to
//! verify signatures on peer-asserted JWTs (see
//! [`peer_jwt::PeerJwtValidator`]).

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod jwks;
pub mod peer_jwt;

/// How much identity the peer's assertion is allowed to
/// project into this gateway's authorization decisions.
/// Closed enum — typos at insert time fail fast; mirrors
/// the SQL CHECK in migration 0033.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Runtime semantics: the peer's principal is
    /// propagated as-is into this gateway's authz pipeline
    /// (the calling user reaches Cedar with their original
    /// identity, signed by the peer). Use when the two
    /// gateways are operationally a single trust domain
    /// (e.g. blue/green or active/active deployments under
    /// the same operator).
    Full,
    /// Runtime semantics: the peer's identity is
    /// wrapped under this gateway's tenant scope — Cedar
    /// sees `peer:<peer_id>` as the principal, not the
    /// original user. Use when the peer is a separately-
    /// operated gateway and the operator wants per-peer
    /// authz decisions rather than per-user.
    Restricted,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Restricted => "restricted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

/// Full read-side view of a `federated_peers` row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FederatedPeer {
    pub id: Uuid,
    pub tenant_id: String,
    pub peer_name: String,
    pub issuer: String,
    pub jwks_url: String,
    pub trust_tier: TrustTier,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct NewFederatedPeer<'a> {
    pub tenant_id: &'a str,
    pub peer_name: &'a str,
    pub issuer: &'a str,
    pub jwks_url: &'a str,
    pub trust_tier: TrustTier,
}

#[derive(Debug, Default)]
pub struct PeerFilter<'a> {
    /// Exact-name filter within the tenant scope.
    pub peer_name: Option<&'a str>,
    /// Exact-issuer filter — useful for the runtime per-
    /// JWT-validation lookup path.
    pub issuer: Option<&'a str>,
    pub trust_tier: Option<TrustTier>,
}

#[derive(Debug)]
pub struct PeerUpdate<'a> {
    /// Renames are allowed (operator-friendly label only)
    /// but UNIQUE per tenant.
    pub peer_name: Option<&'a str>,
    /// Issuer changes are unusual but allowed — when an
    /// upstream rotates issuer URLs. UNIQUE per tenant.
    pub issuer: Option<&'a str>,
    pub jwks_url: Option<&'a str>,
    pub trust_tier: Option<TrustTier>,
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peers store: {0}")]
    Database(#[source] sqlx::Error),
    #[error("peer with the same (tenant, peer_name) OR (tenant, issuer) already exists")]
    DuplicateName,
}

/// Hard ceiling on `list_peers` page size — mirrors the
/// other admin stores (`oauth_consent`, `break_glass_tokens`,
/// `task_states`, `inspection_rules`).
pub use waygate_core::page::MAX_LIST_LIMIT;

#[async_trait]
pub trait FederatedPeersStore: Send + Sync + 'static {
    /// Insert a new peer. `PeerError::DuplicateName` on a
    /// UNIQUE collision (either peer_name OR issuer).
    async fn insert(&self, peer: NewFederatedPeer<'_>) -> Result<FederatedPeer, PeerError>;

    /// Single fetch by id, tenant-scoped. `Ok(None)` covers
    /// both "no such id" and "exists but wrong tenant" —
    /// same existence-disclosure-collapsing rule as the
    /// other admin stores.
    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<FederatedPeer>, PeerError>;

    /// Paginated list, tenant-scoped. Filters AND together.
    /// Ordered by `created_at DESC` so newest land first.
    async fn list(
        &self,
        tenant_id: &str,
        filter: PeerFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError>;

    /// Partial update; `None` fields are left alone. Returns
    /// `Ok(Some(_))` with the post-update row when the peer
    /// existed in the caller's tenant; `Ok(None)` when it
    /// didn't.
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: PeerUpdate<'_>,
    ) -> Result<Option<FederatedPeer>, PeerError>;

    /// Hard delete. Returns `Ok(true)` when the row was
    /// removed; `Ok(false)` on no-such-id-or-wrong-tenant.
    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, PeerError>;

    /// Cross-tenant paginated scan used by the [`jwks`]
    /// refresher to keep every registered peer's JWKS warm.
    /// Intentionally *not* tenant-scoped: the refresher
    /// runs as an internal background task with no
    /// principal, and the cache it populates is keyed by
    /// `(peer_id, tenant_id)` so the per-call verifier
    /// re-applies tenancy at lookup time. Ordered by `id`
    /// so pagination is stable across calls within a single
    /// refresh cycle.
    async fn list_all_for_refresh(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError>;
}

pub type SharedPeersStore = Arc<dyn FederatedPeersStore>;

#[derive(Clone)]
pub struct PgFederatedPeersStore {
    pool: PgPool,
}

impl PgFederatedPeersStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FederatedPeersStore for PgFederatedPeersStore {
    async fn insert(&self, peer: NewFederatedPeer<'_>) -> Result<FederatedPeer, PeerError> {
        let row = sqlx::query(
            r#"
            INSERT INTO federated_peers
                (tenant_id, peer_name, issuer, jwks_url, trust_tier)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, tenant_id, peer_name, issuer, jwks_url,
                      trust_tier, created_at, updated_at
            "#,
        )
        .bind(peer.tenant_id)
        .bind(peer.peer_name)
        .bind(peer.issuer)
        .bind(peer.jwks_url)
        .bind(peer.trust_tier.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_insert_err)?;
        Ok(row_to_peer(&row))
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<FederatedPeer>, PeerError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, peer_name, issuer, jwks_url,
                   trust_tier, created_at, updated_at
              FROM federated_peers
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(PeerError::Database)?;
        Ok(row.as_ref().map(row_to_peer))
    }

    async fn list(
        &self,
        tenant_id: &str,
        filter: PeerFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let trust_str = filter.trust_tier.map(|t| t.as_str().to_owned());
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, peer_name, issuer, jwks_url,
                   trust_tier, created_at, updated_at
              FROM federated_peers
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR peer_name = $2)
               AND ($3::text IS NULL OR issuer    = $3)
               AND ($4::text IS NULL OR trust_tier = $4)
             ORDER BY created_at DESC, id
             LIMIT $5 OFFSET $6
            "#,
        )
        .bind(tenant_id)
        .bind(filter.peer_name)
        .bind(filter.issuer)
        .bind(trust_str.as_deref())
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await
        .map_err(PeerError::Database)?;
        Ok(rows.iter().map(row_to_peer).collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: PeerUpdate<'_>,
    ) -> Result<Option<FederatedPeer>, PeerError> {
        let trust_str = update.trust_tier.map(|t| t.as_str().to_owned());
        let row = sqlx::query(
            r#"
            UPDATE federated_peers
               SET peer_name  = COALESCE($3, peer_name),
                   issuer     = COALESCE($4, issuer),
                   jwks_url   = COALESCE($5, jwks_url),
                   trust_tier = COALESCE($6, trust_tier)
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, peer_name, issuer, jwks_url,
                      trust_tier, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(update.peer_name)
        .bind(update.issuer)
        .bind(update.jwks_url)
        .bind(trust_str.as_deref())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_insert_err)?;
        Ok(row.as_ref().map(row_to_peer))
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, PeerError> {
        let res = sqlx::query(
            r#"
            DELETE FROM federated_peers
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(PeerError::Database)?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_all_for_refresh(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<FederatedPeer>, PeerError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, peer_name, issuer, jwks_url,
                   trust_tier, created_at, updated_at
              FROM federated_peers
             ORDER BY id
             LIMIT $1 OFFSET $2
            "#,
        )
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await
        .map_err(PeerError::Database)?;
        Ok(rows.iter().map(row_to_peer).collect())
    }
}

fn map_insert_err(e: sqlx::Error) -> PeerError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) {
            return PeerError::DuplicateName;
        }
    }
    PeerError::Database(e)
}

fn row_to_peer(row: &PgRow) -> FederatedPeer {
    let trust_str: String = row.get("trust_tier");
    // Defensive: CHECK constraint guarantees one of the
    // canonical values, so this fallback is only reachable
    // if an operator pokes the row by hand bypassing CHECK.
    let trust_tier = TrustTier::parse(&trust_str).unwrap_or(TrustTier::Restricted);
    FederatedPeer {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        peer_name: row.get("peer_name"),
        issuer: row.get("issuer"),
        jwks_url: row.get("jwks_url"),
        trust_tier,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_tier_roundtrips_through_as_str_parse() {
        for t in [TrustTier::Full, TrustTier::Restricted] {
            assert_eq!(TrustTier::parse(t.as_str()), Some(t));
        }
        assert_eq!(TrustTier::parse("nope"), None);
    }
}
