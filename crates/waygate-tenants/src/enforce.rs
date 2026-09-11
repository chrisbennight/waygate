//! Bearer-validate-time tenant enforcement.
//!
//! Resolves `principal.tenant` against the canonical `tenants`
//! registry (migration 0024) at bearer-validate time and,
//! when the tenant is missing or `status='suspended'`, blocks
//! the request via the same `Principal.enrichment_blocked` channel
//! the SCIM resolver uses. Wired in by chaining a
//! [`PgTenantEnricher`] BEFORE the SCIM/RBAC enrichers, so a
//! blocked principal short-circuits the more expensive lookups
//! downstream (the SCIM/RBAC enrichers see
//! `enrichment_blocked.is_some()` and return early per their
//! contract).
//!
//! ## Why bearer-layer enforcement (vs Cedar policy)
//!
//! - Cedar policies only fire for actions the engine evaluates
//!   (tool calls). Admin / SCIM / dashboard surfaces are
//!   scope-gated, not Cedar-gated — a suspended tenant could
//!   still hit those surfaces if enforcement lived only in policy.
//! - The bearer middleware is the established
//!   single point for "this principal cannot proceed" decisions
//!   that must apply on every surface (`/mcp`, `/api/v1`,
//!   `/scim/v2`, dashboard). Tenant lifecycle is the same shape
//!   of decision.
//!
//! ## Caching
//!
//! Tenant lookups happen on every authenticated request. A
//! moka TTL cache keyed on `tenant_id` (60s default, 10k cap)
//! absorbs the steady-state load. Cache invalidation hooks fire
//! from the admin CRUD handlers (PATCH/DELETE) so an operator
//! suspension takes effect immediately rather than waiting on
//! TTL; if the admin path is bypassed (someone hand-edits the
//! tenants row in SQL) the change is visible within the TTL.
//!
//! ## Fail mode
//!
//! - DB error fetching the row → log WARN, return the principal
//!   unchanged. A Postgres outage must NOT lock every tenant out
//!   of the gateway. The SCIM enricher follows the same
//!   precedent for the same reason.
//! - Row missing → fail-CLOSED. `enrichment_blocked =
//!   "tenant_not_found"`. The token's `tenant` claim referenced a
//!   tenant the operator never provisioned (or that was deleted);
//!   forwarding to admin/SCIM/tool surfaces would let
//!   un-onboarded principals operate. Migration 0024
//!   backfills every distinct `tenant_id` seen in prior schema
//!   so the historic data path can't trigger this.
//! - Row present + `status = 'suspended'` → fail-CLOSED.
//!   `enrichment_blocked = "tenant_suspended"`. The operator-
//!   initiated lifecycle action gates every surface.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use sqlx::PgPool;

use waygate_oidc::{Principal, PrincipalEnricher};

/// Errors the tenant resolver can surface to the enricher. Two
/// kinds with different fail-mode semantics:
///
/// - [`Self::Store`] — best-effort. Enricher logs WARN and lets
///   the principal through so a Postgres outage doesn't take the
///   gateway down. Same precedent as `ScimResolveError::Store`.
#[derive(Debug, thiserror::Error)]
pub enum TenantResolveError {
    #[error("tenants store error: {0}")]
    Store(#[from] sqlx::Error),
}

/// Definitive resolution outcomes. The enum is the unit the
/// cache stores because all three are stable until either the
/// TTL elapses or an admin mutation invalidates the entry.
///
/// - [`Self::Active`] — row exists, status = 'active'. Principal
///   passes through unchanged.
/// - [`Self::Suspended`] — row exists, status = 'suspended'.
///   Enricher sets `enrichment_blocked = "tenant_suspended"`.
/// - [`Self::Missing`] — no row for this tenant_id. Enricher
///   sets `enrichment_blocked = "tenant_not_found"`.
///
/// A CHECK constraint at the SQL layer pins status to
/// active/suspended so the resolver doesn't need a third "unknown"
/// arm — a row with anything else can't exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantLookup {
    Active,
    Suspended,
    Missing,
}

/// Backing-store trait so the enricher can be unit-tested with a
/// fake resolver and so non-Postgres backends can plug in without
/// touching `waygate-oidc`.
#[async_trait]
pub trait TenantResolver: Send + Sync {
    async fn resolve(&self, tenant_id: &str) -> Result<TenantLookup, TenantResolveError>;
}

/// Postgres-backed [`TenantResolver`]. Single SELECT per cold
/// lookup; the enricher in front of it bounds the steady-state
/// rate at one DB read per `(tenant_id)` per TTL window.
pub struct PgTenantResolver {
    pool: PgPool,
}

impl PgTenantResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantResolver for PgTenantResolver {
    async fn resolve(&self, tenant_id: &str) -> Result<TenantLookup, TenantResolveError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(match row.as_ref().map(|r| r.0.as_str()) {
            None => TenantLookup::Missing,
            Some("active") => TenantLookup::Active,
            // Anything not 'active' is treated as suspended for
            // the enforcement path. The CHECK constraint at the
            // SQL layer pins this to 'suspended', so the only
            // other path is a future status the migration adds
            // explicitly; that PR will revisit this match.
            Some(_) => TenantLookup::Suspended,
        })
    }
}

/// [`PrincipalEnricher`] backed by a [`TenantResolver`] plus a
/// moka TTL cache. Build with [`PgTenantEnricher::new`] for
/// production wiring; `new_with_resolver` takes any
/// [`TenantResolver`] so tests can drive it with a fake.
pub struct PgTenantEnricher {
    resolver: Arc<dyn TenantResolver>,
    cache: Cache<String, TenantLookup>,
}

impl PgTenantEnricher {
    /// Production constructor: Postgres-backed resolver with the
    /// same 60-second TTL + 10_000-entry cap as the SCIM resolver,
    /// for symmetry on operator mental model.
    pub fn new(pool: PgPool) -> Self {
        let resolver = Arc::new(PgTenantResolver::new(pool));
        Self::new_with_resolver(resolver, Duration::from_secs(60), 10_000)
    }

    pub fn new_with_resolver(
        resolver: Arc<dyn TenantResolver>,
        ttl: Duration,
        max_entries: u64,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();
        Self { resolver, cache }
    }

    async fn lookup(&self, tenant: &str) -> TenantLookup {
        if let Some(hit) = self.cache.get(tenant).await {
            return hit;
        }
        match self.resolver.resolve(tenant).await {
            Ok(outcome) => {
                self.cache.insert(tenant.to_owned(), outcome).await;
                outcome
            }
            Err(TenantResolveError::Store(e)) => {
                tracing::warn!(
                    tenant = tenant,
                    error = %e,
                    "tenant resolver lookup failed; principal allowed through unchanged \
                     (best-effort — a DB outage must not lock every tenant out)",
                );
                // Don't cache infra failures — a transient outage
                // should not stick for 60s. Soft-fail: treat as
                // Active for this single request so we don't block
                // on flaky DB, but don't insert anything so the
                // next call retries.
                TenantLookup::Active
            }
        }
    }

    /// Drop a cached entry. Called by the admin tenant CRUD
    /// handler (PATCH / DELETE) so an operator suspension takes
    /// effect on the very next request instead of waiting up to
    /// the TTL window.
    pub async fn invalidate(&self, tenant: &str) {
        self.cache.invalidate(tenant).await;
    }
}

#[async_trait]
impl PrincipalEnricher for PgTenantEnricher {
    async fn enrich(&self, principal: Principal) -> Principal {
        // Honor upstream blocks: if a prior enricher already
        // refused this principal, don't overwrite or re-check.
        // Tenant enricher always runs FIRST in the chain today,
        // so this branch is defensive — it'd fire only if the
        // chain order is ever rearranged.
        if principal.enrichment_blocked.is_some() {
            return principal;
        }
        let tenant = principal.tenant.as_str();
        match self.lookup(tenant).await {
            TenantLookup::Active => principal,
            TenantLookup::Suspended => {
                tracing::warn!(
                    sub = %principal.sub,
                    tenant = tenant,
                    "principal blocked: tenant is suspended",
                );
                Principal {
                    enrichment_blocked: Some("tenant_suspended".into()),
                    ..principal
                }
            }
            TenantLookup::Missing => {
                tracing::warn!(
                    sub = %principal.sub,
                    tenant = tenant,
                    "principal blocked: tenant_id has no row in tenants registry (operator \
                     must provision via POST /api/v1/admin/tenants)",
                );
                Principal {
                    enrichment_blocked: Some("tenant_not_found".into()),
                    ..principal
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use waygate_core::TenantId;
    use waygate_oidc::AuthMethod;

    use super::*;

    struct FakeResolver {
        result: Mutex<Result<TenantLookup, ()>>,
        calls: Mutex<u32>,
    }

    impl FakeResolver {
        fn new(result: Result<TenantLookup, ()>) -> Self {
            Self {
                result: Mutex::new(result),
                calls: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl TenantResolver for FakeResolver {
        async fn resolve(&self, _tenant_id: &str) -> Result<TenantLookup, TenantResolveError> {
            *self.calls.lock().unwrap() += 1;
            match *self.result.lock().unwrap() {
                Ok(v) => Ok(v),
                Err(()) => Err(TenantResolveError::Store(sqlx::Error::PoolTimedOut)),
            }
        }
    }

    fn principal(tenant: &str) -> Principal {
        Principal {
            sub: "alice".into(),
            email: None,
            groups: vec![],
            issuer: "test".into(),
            scopes: vec![],
            tenant: TenantId::parse(tenant).unwrap_or_default(),
            auth_method: AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: vec![],
        }
    }

    #[tokio::test]
    async fn active_tenant_passes_through_unchanged() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Active)));
        let enricher =
            PgTenantEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("acme")).await;
        assert!(out.enrichment_blocked.is_none());
    }

    #[tokio::test]
    async fn suspended_tenant_marks_principal_blocked() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Suspended)));
        let enricher = PgTenantEnricher::new_with_resolver(resolver, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("acme")).await;
        assert_eq!(out.enrichment_blocked.as_deref(), Some("tenant_suspended"));
    }

    #[tokio::test]
    async fn missing_tenant_marks_principal_blocked() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Missing)));
        let enricher = PgTenantEnricher::new_with_resolver(resolver, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("ghost")).await;
        assert_eq!(out.enrichment_blocked.as_deref(), Some("tenant_not_found"));
    }

    #[tokio::test]
    async fn store_error_is_best_effort_allow() {
        let resolver = Arc::new(FakeResolver::new(Err(())));
        let enricher = PgTenantEnricher::new_with_resolver(resolver, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("acme")).await;
        assert!(
            out.enrichment_blocked.is_none(),
            "infra error must NOT block — that would let a DB blip lock every tenant out",
        );
    }

    #[tokio::test]
    async fn upstream_block_is_not_overwritten() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Active)));
        let enricher =
            PgTenantEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let mut p = principal("acme");
        p.enrichment_blocked = Some("scim_inactive".into());
        let out = enricher.enrich(p).await;
        assert_eq!(out.enrichment_blocked.as_deref(), Some("scim_inactive"));
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            0,
            "enricher should not even hit the resolver when upstream already blocked",
        );
    }

    #[tokio::test]
    async fn cache_absorbs_repeat_lookups() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Active)));
        let enricher =
            PgTenantEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        for _ in 0..5 {
            let _ = enricher.enrich(principal("acme")).await;
        }
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            1,
            "second through fifth enrich should hit cache",
        );
    }

    #[tokio::test]
    async fn invalidate_forces_refetch() {
        let resolver = Arc::new(FakeResolver::new(Ok(TenantLookup::Active)));
        let enricher =
            PgTenantEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let _ = enricher.enrich(principal("acme")).await;
        enricher.invalidate("acme").await;
        let _ = enricher.enrich(principal("acme")).await;
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            2,
            "invalidate should drop the cached entry — second enrich should hit resolver again",
        );
    }
}
