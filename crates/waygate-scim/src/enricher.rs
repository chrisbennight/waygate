//! Bearer-validate-time SCIM resolver.
//!
//! Looks up the principal in `scim_users` (by tenant + sub) and
//! joins `scim_user_groups` + `scim_groups` to assemble a
//! [`waygate_oidc::ScimPrincipalAttrs`] that the gateway carries on
//! the request for the rest of the call. Wired in via
//! [`waygate_oidc::BearerLayer::with_principal_enricher`].
//!
//! ## Lookup key
//!
//! JWTs and API keys both expose a `sub`. Different IdPs put
//! different things in it:
//!
//! - Authentik: opaque user UUID — typically also surfaces as
//!   `external_id` on the SCIM row (when Authentik provisions the
//!   gateway via SCIM, its external-id maps to its user UUID).
//! - Okta / EntraID: `sub` is the user's `userName` (their primary
//!   login) on JWT-emitted access tokens.
//!
//! To cover both shapes without operator-side configuration knobs,
//! the resolver tries `external_id` first and falls back to
//! `user_name` on miss. Both columns have a unique index per tenant,
//! so the lookup is index-bound either way.
//!
//! ## Caching
//!
//! Bearer validation runs on every authenticated request. A SCIM
//! lookup per request would put every authz hot path one synchronous
//! Postgres round-trip behind the principal. A `moka` future-aware
//! cache keyed on `(tenant, sub)` with a short TTL (default 60s)
//! absorbs the steady-state lookup load; invalidation is implicit —
//! when an operator deactivates a user via SCIM the change is visible
//! within the TTL window.
//!
//! The cache stores both hits AND misses — a token whose `sub` does
//! not match any SCIM row would otherwise hit Postgres on every
//! request from that caller. Negative TTL matches the positive TTL
//! by default.
//!
//! ## Best-effort
//!
//! Per the [`waygate_oidc::PrincipalEnricher`] contract, every error
//! path returns the original principal unchanged. A SCIM-store outage
//! must NOT take the gateway down — Cedar policies that don't
//! reference `principal.scim` continue to evaluate, and policies that
//! do simply see `principal.scim == null` which they're already
//! expected to handle (an active=false user is denied; an
//! attrs-missing user is denied per any default-deny rule).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use waygate_oidc::{Principal, PrincipalEnricher, ScimGroupRef, ScimPrincipalAttrs};

/// Resolved facts about a SCIM-provisioned principal: the user row
/// itself plus the groups they belong to (display name + id). Mirrors
/// what the enricher writes into [`waygate_oidc::ScimPrincipalAttrs`]
/// but in raw types so the resolver layer can be unit-tested in
/// isolation from the OIDC `Principal` plumbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    pub user_id: Uuid,
    pub user_name: String,
    pub external_id: Option<String>,
    pub active: bool,
    pub attrs: Value,
    pub groups: Vec<(Uuid, String)>,
}

/// Errors the resolver can surface to the enricher. Two kinds with
/// very different fail-mode semantics:
///
/// - [`Self::Store`] — best-effort. The enricher logs WARN and
///   passes the principal through unchanged so a Postgres outage
///   does NOT take the gateway down.
/// - [`Self::Ambiguous`] — fail-CLOSED. The
///   enricher marks the principal `enrichment_blocked` so the
///   bearer middleware 403s the request. Treating this as
///   best-effort would silently bypass the SCIM deactivation
///   check.
#[derive(Debug, thiserror::Error)]
pub enum ScimResolveError {
    #[error("scim store error: {0}")]
    Store(#[from] sqlx::Error),
    /// `sub` matches more than one `scim_users` row in this tenant
    /// — typically because one row's `external_id` equals another
    /// row's `user_name`. Carrying the row ids so the operator can
    /// reconcile them from the WARN log.
    #[error("ambiguous scim match in tenant `{tenant}` for sub `{sub}`: {rows:?}")]
    Ambiguous {
        tenant: String,
        sub: String,
        rows: Vec<Uuid>,
    },
}

/// Backing-store trait so the enricher can be unit-tested with a fake
/// resolver and so non-Postgres backends (in-memory tests, future
/// directory adapters) can plug in without touching `waygate-oidc`.
#[async_trait]
pub trait ScimResolver: Send + Sync {
    /// Look up the principal by `tenant + sub`. Returns `None` when
    /// no SCIM row matches (legitimate: not every authenticated
    /// caller is SCIM-provisioned). Returns
    /// [`ScimResolveError::Ambiguous`] when the sub matches multiple
    /// rows — the enricher escalates this to a fail-closed block.
    /// Other errors are best-effort: enricher logs and leaves the
    /// principal unchanged.
    async fn resolve(
        &self,
        tenant_id: &str,
        sub: &str,
    ) -> Result<Option<ResolvedPrincipal>, ScimResolveError>;
}

/// Postgres-backed [`ScimResolver`]. One live-row union lookup; on a
/// live miss a tombstone-fallback probe detects
/// deprovisioned users; on a hit one join for groups.
pub struct PgScimResolver {
    pool: PgPool,
}

impl PgScimResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Tombstone-fallback probe. Called when the primary
    /// (live-row) lookup matched nothing. A matching soft-deleted row
    /// means the user was DEPROVISIONED (scope-exit DELETE), so resolve
    /// it as `active = false` — the enricher's `Hit` branch turns that
    /// into a blocked request via `scim_blocks_request()`. A genuinely
    /// absent user (no live row, no tombstone) returns `None` → treated
    /// active, preserving the service-account / API-key semantics. The
    /// probe is scoped to `deleted_at IS NOT NULL`, so it can never
    /// collide with the live-row ambiguity guard.
    async fn resolve_tombstone(
        &self,
        tenant_id: &str,
        sub: &str,
    ) -> Result<Option<ResolvedPrincipal>, ScimResolveError> {
        let tomb: Option<UserRow> = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, external_id, user_name, active, attrs
              FROM scim_users
             WHERE tenant_id = $1
               AND (external_id = $2 OR user_name = $2)
               AND deleted_at IS NOT NULL
             ORDER BY deleted_at DESC
             LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;
        Ok(tomb.map(|row| ResolvedPrincipal {
            user_id: row.id,
            user_name: row.user_name,
            external_id: row.external_id,
            // Force inactive: a tombstone is a deprovisioned user
            // regardless of the stored flag.
            active: false,
            attrs: serde_json::json!({}),
            groups: vec![],
        }))
    }
}

#[async_trait]
impl ScimResolver for PgScimResolver {
    async fn resolve(
        &self,
        tenant_id: &str,
        sub: &str,
    ) -> Result<Option<ResolvedPrincipal>, ScimResolveError> {
        // Security: the schema only
        // enforces separate uniqueness on `(tenant_id, user_name)`
        // and `(tenant_id, external_id)`. A token `sub` could
        // therefore legitimately match row X via external_id AND
        // row Y via user_name (two distinct rows). The original
        // "external_id first, then user_name" fallback silently
        // resolved to X and Y's attrs/groups would never be seen
        // — a confused-deputy-style leak where row X inherits
        // row Y's privileges (or vice versa, depending on which
        // side an attacker controls).
        //
        // Fix: union both predicates in a single query, fail-
        // closed on ambiguity. LIMIT 2 caps the read; the
        // resolver treats 2 distinct rows as "no match" and logs
        // WARN with both row ids. The legitimate cases (only one
        // column matches; or both columns match the same row
        // because the IdP set external_id == user_name) still
        // resolve cleanly.
        let candidates: Vec<UserRow> = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, external_id, user_name, active, attrs
              FROM scim_users
             WHERE tenant_id = $1
               AND (external_id = $2 OR user_name = $2)
               AND deleted_at IS NULL
             LIMIT 2
            "#,
        )
        .bind(tenant_id)
        .bind(sub)
        .fetch_all(&self.pool)
        .await?;

        let row = match candidates.len() {
            // No LIVE row. Probe for a tombstone before
            // concluding "not provisioned" — a deprovisioned user
            // (scope-exit DELETE) must be blocked, not treated active.
            0 => return self.resolve_tombstone(tenant_id, sub).await,
            1 => candidates.into_iter().next().unwrap(),
            _ => {
                // Ambiguity is fail-CLOSED, not
                // fail-open. A `return Ok(None)` here would
                // silently bypass SCIM enforcement because the
                // enricher would set `principal.scim = None`, and
                // the active-check only fires when SCIM is present.
                // Instead we propagate `ScimResolveError::Ambiguous`
                // and the enricher marks `enrichment_blocked` so
                // the bearer middleware 403s the request.
                let rows: Vec<Uuid> = candidates.iter().map(|r| r.id).collect();
                tracing::warn!(
                    tenant = tenant_id,
                    sub = sub,
                    candidates = ?rows,
                    "SCIM resolver: tenant `{tenant_id}` has multiple rows whose external_id \
                     or user_name equals `{sub}`; blocking enrichment (ambiguous). Fix by \
                     reconciling the conflicting scim_users rows.",
                );
                return Err(ScimResolveError::Ambiguous {
                    tenant: tenant_id.to_owned(),
                    sub: sub.to_owned(),
                    rows,
                });
            }
        };

        let groups: Vec<(Uuid, String)> = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT g.id, g.display_name
              FROM scim_user_groups m
              JOIN scim_groups g ON g.id = m.group_id
             WHERE m.tenant_id = $1 AND m.user_id = $2
             ORDER BY g.display_name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(row.id)
        .fetch_all(&self.pool)
        .await?;

        Ok(Some(ResolvedPrincipal {
            user_id: row.id,
            user_name: row.user_name,
            external_id: row.external_id,
            active: row.active,
            attrs: row.attrs,
            groups,
        }))
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    external_id: Option<String>,
    user_name: String,
    active: bool,
    attrs: Value,
}

/// Three distinct outcomes the cache stores. All three are cached
/// so the steady-state cost is one moka `Arc` clone:
///
/// - `Hit` — sub matched a single SCIM row, enricher attaches it.
/// - `Miss` — sub matched no SCIM row, enricher leaves
///   `Principal.scim = None`.
/// - `Blocked` — sub matched multiple rows (ambiguous); fail-closed.
///   Enricher sets
///   `Principal.enrichment_blocked = Some(reason)` so the bearer
///   middleware 403s the request. Caching ambiguity is safe — it
///   stays ambiguous until the operator reconciles the rows, and
///   the TTL bounds how long the block sticks after that.
///
/// Infra errors (`ScimResolveError::Store`) are NOT cached — they
/// must clear on the next call after recovery, so transient outages
/// don't pin a stale "scim=None" result.
#[derive(Debug)]
enum CachedResolution {
    Hit(ResolvedPrincipal),
    Miss,
    Blocked(String),
}

type CacheEntry = Arc<CachedResolution>;

/// [`PrincipalEnricher`] backed by a [`ScimResolver`] plus a moka TTL
/// cache. Build with [`PgScimEnricher::new`] for production wiring;
/// the `new_with_resolver` constructor takes any [`ScimResolver`]
/// implementation so tests can drive it with an in-memory fake.
pub struct PgScimEnricher {
    resolver: Arc<dyn ScimResolver>,
    cache: Cache<(String, String), CacheEntry>,
}

impl PgScimEnricher {
    /// Production constructor: Postgres-backed resolver with the
    /// default 60-second TTL and 10_000-entry cap. The cap bounds
    /// memory for pathological cases (millions of distinct API keys
    /// rotating per minute) without slowing the common case where
    /// the working set is well below it.
    pub fn new(pool: PgPool) -> Self {
        let resolver = Arc::new(PgScimResolver::new(pool));
        Self::new_with_resolver(resolver, Duration::from_secs(60), 10_000)
    }

    /// Test/extension constructor that takes a custom resolver +
    /// cache parameters. Production code should prefer [`new`].
    pub fn new_with_resolver(
        resolver: Arc<dyn ScimResolver>,
        ttl: Duration,
        max_entries: u64,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();
        Self { resolver, cache }
    }

    async fn lookup(&self, tenant: &str, sub: &str) -> CacheEntry {
        let key = (tenant.to_owned(), sub.to_owned());
        if let Some(hit) = self.cache.get(&key).await {
            return hit;
        }
        // Race window note: two concurrent enrichments for the same
        // (tenant, sub) may both miss the cache and both query the
        // store. moka coalesces neither (this isn't `get_with`); the
        // cost is a duplicate DB read on a cold key, never a wrong
        // result. Switching to `get_with` would serialise concurrent
        // misses but introduces a future-pinning constraint that's
        // overkill for this path's QPS profile.
        let entry: CacheEntry = match self.resolver.resolve(tenant, sub).await {
            Ok(Some(r)) => Arc::new(CachedResolution::Hit(r)),
            Ok(None) => Arc::new(CachedResolution::Miss),
            Err(ScimResolveError::Ambiguous { rows, .. }) => {
                // Fail-closed: cache the block so
                // the next call from the same caller stays blocked
                // within the TTL window without re-querying the
                // store. Operator reconciliation invalidates via
                // TTL.
                let reason = format!("scim_ambiguous_match:{}", rows.len());
                Arc::new(CachedResolution::Blocked(reason))
            }
            Err(ScimResolveError::Store(e)) => {
                tracing::warn!(
                    tenant = tenant,
                    sub = sub,
                    error = %e,
                    "SCIM resolver lookup failed; principal will be enriched as if absent",
                );
                // Don't cache infra failures — a transient outage
                // should not stick for 60s. Return Miss without
                // inserting so the next call retries.
                return Arc::new(CachedResolution::Miss);
            }
        };
        self.cache.insert(key, entry.clone()).await;
        entry
    }

    /// Drop a cached entry for `(tenant, sub)`. Hook for future SCIM
    /// mutation handlers to call when they know a row changed — keeps
    /// the cache TTL short for security-relevant updates (e.g.
    /// `active=false`) instead of waiting up to TTL.
    pub async fn invalidate(&self, tenant: &str, sub: &str) {
        self.cache
            .invalidate(&(tenant.to_owned(), sub.to_owned()))
            .await;
    }

    /// Drop every cached SCIM resolution after a group-catalog mutation.
    /// Group create/replace/delete can affect many subjects at once, and a
    /// coarse invalidation avoids retaining removed membership facts when the
    /// mutation's prior member set is unavailable.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}

#[async_trait]
impl PrincipalEnricher for PgScimEnricher {
    async fn enrich(&self, principal: Principal) -> Principal {
        if principal.scim.is_some() || principal.enrichment_blocked.is_some() {
            // Already enriched (e.g. a hydrated session principal)
            // OR already blocked by an upstream enricher. Don't
            // re-query and don't unblock.
            return principal;
        }
        let tenant = principal.tenant.as_str();
        let sub = principal.sub.as_str();
        let entry = self.lookup(tenant, sub).await;
        match entry.as_ref() {
            CachedResolution::Hit(resolved) => {
                let scim = ScimPrincipalAttrs {
                    user_id: resolved.user_id.to_string(),
                    user_name: resolved.user_name.clone(),
                    external_id: resolved.external_id.clone(),
                    active: resolved.active,
                    attrs: resolved.attrs.clone(),
                    groups: resolved
                        .groups
                        .iter()
                        .map(|(id, name)| ScimGroupRef {
                            id: id.to_string(),
                            display_name: name.clone(),
                        })
                        .collect(),
                };
                Principal {
                    scim: Some(scim),
                    ..principal
                }
            }
            CachedResolution::Miss => principal,
            CachedResolution::Blocked(reason) => {
                // Ambiguous SCIM matches must
                // surface as a fail-closed block, not as "no SCIM
                // data." `scim_blocks_request()` consults
                // `enrichment_blocked` so the bearer middleware
                // returns 403 with this reason.
                Principal {
                    enrichment_blocked: Some(reason.clone()),
                    ..principal
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Fake resolver for unit testing the enricher without Postgres.
    /// Tracks call count so cache-hit tests can prove they didn't
    /// re-hit the store.
    struct FakeResolver {
        result: Mutex<Result<Option<ResolvedPrincipal>, ()>>,
        calls: Mutex<u32>,
    }

    impl FakeResolver {
        fn new(result: Result<Option<ResolvedPrincipal>, ()>) -> Self {
            Self {
                result: Mutex::new(result),
                calls: Mutex::new(0),
            }
        }

        fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl ScimResolver for FakeResolver {
        async fn resolve(
            &self,
            _tenant_id: &str,
            _sub: &str,
        ) -> Result<Option<ResolvedPrincipal>, ScimResolveError> {
            *self.calls.lock().unwrap() += 1;
            match self.result.lock().unwrap().clone() {
                Ok(opt) => Ok(opt),
                Err(()) => Err(ScimResolveError::Store(sqlx::Error::PoolTimedOut)),
            }
        }
    }

    fn principal(sub: &str) -> Principal {
        Principal {
            sub: sub.into(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test/".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn resolved() -> ResolvedPrincipal {
        ResolvedPrincipal {
            user_id: Uuid::new_v4(),
            user_name: "alice".into(),
            external_id: Some("alice-ext".into()),
            active: true,
            attrs: serde_json::json!({"department": "finance"}),
            groups: vec![
                (Uuid::new_v4(), "admins".into()),
                (Uuid::new_v4(), "finance".into()),
            ],
        }
    }

    #[tokio::test]
    async fn enricher_attaches_scim_attrs_on_hit() {
        let r = resolved();
        let resolver = Arc::new(FakeResolver::new(Ok(Some(r.clone()))));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("alice")).await;
        let scim = out.scim.expect("scim should be populated on hit");
        assert_eq!(scim.user_name, "alice");
        assert_eq!(scim.external_id.as_deref(), Some("alice-ext"));
        assert!(scim.active);
        assert_eq!(scim.groups.len(), 2);
        assert_eq!(scim.groups[0].display_name, "admins");
        assert_eq!(scim.attrs, serde_json::json!({"department": "finance"}));
    }

    #[tokio::test]
    async fn enricher_returns_unchanged_principal_on_miss() {
        let resolver = Arc::new(FakeResolver::new(Ok(None)));
        let enricher = PgScimEnricher::new_with_resolver(resolver, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("bob")).await;
        assert!(
            out.scim.is_none(),
            "missing SCIM row must leave principal.scim == None",
        );
    }

    #[tokio::test]
    async fn enricher_returns_unchanged_principal_on_resolver_error() {
        // Infra error must NOT block the request — principal flows
        // through with scim=None, request continues.
        let resolver = Arc::new(FakeResolver::new(Err(())));
        let enricher = PgScimEnricher::new_with_resolver(resolver, Duration::from_secs(60), 100);
        let out = enricher.enrich(principal("alice")).await;
        assert!(out.scim.is_none());
    }

    #[tokio::test]
    async fn enricher_caches_hits_within_ttl() {
        let resolver = Arc::new(FakeResolver::new(Ok(Some(resolved()))));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        // Three calls for the same (tenant, sub) must hit the store
        // exactly once — the rest come from cache.
        for _ in 0..3 {
            let _ = enricher.enrich(principal("alice")).await;
        }
        assert_eq!(resolver.call_count(), 1);
    }

    #[tokio::test]
    async fn enricher_caches_misses_within_ttl() {
        // Cache-the-miss is important: an authenticated caller whose
        // `sub` doesn't map to any SCIM row should not pay a DB
        // round-trip on every request.
        let resolver = Arc::new(FakeResolver::new(Ok(None)));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        for _ in 0..3 {
            let _ = enricher.enrich(principal("nobody")).await;
        }
        assert_eq!(resolver.call_count(), 1);
    }

    #[tokio::test]
    async fn enricher_skips_lookup_when_principal_already_has_scim() {
        let resolver = Arc::new(FakeResolver::new(Ok(Some(resolved()))));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let mut p = principal("alice");
        p.scim = Some(ScimPrincipalAttrs {
            user_id: "preset".into(),
            user_name: "preset".into(),
            external_id: None,
            active: true,
            attrs: Value::Null,
            groups: vec![],
        });
        let out = enricher.enrich(p).await;
        assert_eq!(out.scim.expect("preset").user_id, "preset");
        // Critically: the resolver was NOT called. A hydrated
        // session principal must not pay a SCIM lookup it already
        // resolved at login.
        assert_eq!(resolver.call_count(), 0);
    }

    #[tokio::test]
    async fn enricher_does_not_cache_resolver_errors() {
        // Transient outage must not stick for 60s. After an error,
        // a recovery (resolver flipped to Ok) should be visible on
        // the next call.
        let resolver = Arc::new(FakeResolver::new(Err(())));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let _ = enricher.enrich(principal("alice")).await;
        *resolver.result.lock().unwrap() = Ok(Some(resolved()));
        let out = enricher.enrich(principal("alice")).await;
        assert!(
            out.scim.is_some(),
            "after recovery, the next call must reflect the now-Ok resolver",
        );
        assert_eq!(resolver.call_count(), 2);
    }

    #[tokio::test]
    async fn invalidate_drops_cached_entry() {
        let resolver = Arc::new(FakeResolver::new(Ok(Some(resolved()))));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let _ = enricher.enrich(principal("alice")).await;
        enricher
            .invalidate(waygate_core::TenantId::default().as_str(), "alice")
            .await;
        let _ = enricher.enrich(principal("alice")).await;
        assert_eq!(
            resolver.call_count(),
            2,
            "invalidate() must drop the entry so the next enrich() re-queries",
        );
    }

    #[tokio::test]
    async fn invalidate_all_drops_every_cached_subject() {
        let resolver = Arc::new(FakeResolver::new(Ok(Some(resolved()))));
        let enricher =
            PgScimEnricher::new_with_resolver(resolver.clone(), Duration::from_secs(60), 100);
        let _ = enricher.enrich(principal("alice")).await;
        let _ = enricher.enrich(principal("bob")).await;
        assert_eq!(resolver.call_count(), 2);

        enricher.invalidate_all();
        let _ = enricher.enrich(principal("alice")).await;
        let _ = enricher.enrich(principal("bob")).await;
        assert_eq!(
            resolver.call_count(),
            4,
            "group mutation invalidation must evict every affected subject",
        );
    }
}
