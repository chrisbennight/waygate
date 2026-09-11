//! [`waygate_oidc::HeaderValidator`] impl backed by the `api_keys` table.
//!
//! Hot path:
//! 1. Parse `Authorization: Bearer mcpgw_<43>` into prefix + remainder.
//! 2. Check the moka cache. On hit, re-check `expires_at` against
//!    wall-clock now (the cache stores it alongside the principal so this
//!    is in-memory, no DB hop); spawn a fire-and-forget `touch_usage`;
//!    return the cached principal. The in-memory expiry check fixes a
//!    window where a key cached just before `expires_at` would keep
//!    validating for up to `cache_ttl` past its actual expiry. The
//!    cache-hit `touch_usage` fixes the dashboard sparkline undercounting
//!    repeated hits inside the cache window.
//! 3. On miss, look up live rows by prefix. Always run argon2id verify —
//!    even on "no rows" (against a fixed dummy hash) — so a timing
//!    attacker can't distinguish "unknown prefix" from "wrong secret".
//! 4. On verified match: build the [`Principal`], cache it with the row's
//!    `expires_at`, and spawn a fire-and-forget `touch_usage`.
//!
//! Errors:
//! * All failures map to [`ValidationError`] variants tagged as client
//!   errors so the middleware's validator chain falls through to the next
//!   one and ultimately produces a 401 — not a 503 — when no validator
//!   accepts the token.
//! * Genuine DB outages surface as [`ValidationError::Infra`]: those
//!   are *infra* errors and the middleware surfaces them as 503.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_oidc::{AuthMethod, HeaderValidator, Principal, ValidationError};

use crate::store::{ApiKeyStore, StoreError};
use crate::token::{self, ParsedToken, TokenError};

/// Runtime configuration for the validator.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// How long a successful validation stays cached. Bounds the lag between
    /// a dashboard revoke and the next 401. Default 60s.
    pub cache_ttl: Duration,
    /// Maximum number of cached principals. Keeps the cache bounded under a
    /// burst of distinct tokens.
    pub cache_capacity: u64,
    /// `Principal.issuer` value for API-key principals. Distinct from any
    /// real OIDC issuer URL so audit-log queries can filter by issuer.
    pub issuer_label: String,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(60),
            cache_capacity: 4096,
            issuer_label: "api-key".to_owned(),
        }
    }
}

/// Cached principal + the row metadata the validator needs to re-check
/// per-hit invariants (expiry, usage attribution) without round-tripping
/// to the DB.
///
/// Storing the row's `expires_at` alongside the principal lets us check
/// expiration in-memory on every cache hit — without this, a key cached
/// just before its `expires_at` would keep validating for up to
/// `cache_ttl` past its actual expiry. Revocation still relies on cache
/// eviction (revoke flips the row out of the `lookup_by_prefix` live-set,
/// so the cache entry just times out and a fresh validation misses).
#[derive(Clone)]
struct CachedEntry {
    principal: Principal,
    expires_at: Option<OffsetDateTime>,
    key_id: Uuid,
}

/// Record one request against `key` and report whether the caller must start a
/// flush task.
///
/// Returns `true` only when this call created the entry. The entry then exists
/// for as long as a flush task is alive for that key — including while its
/// write is in flight, when the entry sits at `count == 0` purely as the
/// writer-alive marker. That is what bounds concurrency to **one writer per
/// active key regardless of database latency**: removing the entry before the
/// write finished would let every subsequent window start another writer, so a
/// stalled pool would accumulate them exactly when it could least afford to.
///
/// Split out from the spawn so the coalescing contract is testable without a
/// database or a runtime.
fn accrue_usage(
    pending: &Mutex<HashMap<(Uuid, OffsetDateTime), UsageDelta>>,
    key: (Uuid, OffsetDateTime),
    now: OffsetDateTime,
) -> bool {
    let mut pending = pending.lock().expect("api-key usage map poisoned");
    match pending.get_mut(&key) {
        Some(delta) => {
            delta.count += 1;
            delta.last_used_at = delta.last_used_at.max(now);
            false
        }
        None => {
            pending.insert(
                key,
                UsageDelta {
                    count: 1,
                    last_used_at: now,
                },
            );
            true
        }
    }
}

/// Take what has accrued for `key` so it can be written.
///
/// Returns `None` when nothing accrued since the last take, which also **ends**
/// the writer: the entry is removed, so the next request starts a fresh flush
/// task. Otherwise the counts are taken and the entry is left in place at zero,
/// keeping the writer-alive marker until the window that finds it idle.
fn take_for_flush(
    pending: &Mutex<HashMap<(Uuid, OffsetDateTime), UsageDelta>>,
    key: &(Uuid, OffsetDateTime),
) -> Option<(i64, OffsetDateTime)> {
    let mut pending = pending.lock().expect("api-key usage map poisoned");
    let delta = pending.get_mut(key)?;
    if delta.count == 0 {
        pending.remove(key);
        return None;
    }
    let taken = (delta.count, delta.last_used_at);
    delta.count = 0;
    Some(taken)
}

/// Requests accrued for one `(key, hour bucket)` since the last flush.
#[derive(Debug)]
struct UsageDelta {
    count: i64,
    /// Newest observation in the window — what `last_used_at` should become.
    last_used_at: OffsetDateTime,
}

/// How long an accrued bucket waits before it is written. Sized to collapse a
/// burst from one hot key into a single transaction while keeping the
/// dashboard's usage view fresh to within a few seconds. The data is only
/// hour-bucketed, so nothing downstream needs per-request write latency.
const USAGE_FLUSH_DEBOUNCE: Duration = Duration::from_secs(5);

pub struct ApiKeyValidator {
    store: ApiKeyStore,
    cache: Cache<String, CachedEntry>,
    config: ValidatorConfig,
    /// When set, the validator resolves the matched api_keys
    /// row's profile and stamps the
    /// invocation-time restrictions on the Principal. `None` ⇒
    /// no profile resolution (cheaper boot for deployments
    /// that don't use profiles, and the existing
    /// validate-then-call path keeps working). Wired in by
    /// `waygate-server::main` when a Postgres pool exists.
    profile_store: Option<Arc<dyn crate::profiles::ProfileStore>>,
    /// Usage accrued in memory, keyed by `(key id, hour bucket)`.
    ///
    /// Every authenticated request used to detach its own transaction. At the
    /// RPS the validator's cache exists to serve, those unbounded tasks queue on
    /// the shared pool and starve the genuine cache-miss lookups, which then
    /// fail as infrastructure errors — the fast path turning into a 503 source
    /// for valid tokens. Accruing here and flushing on a debounce bounds the
    /// writes by the number of active keys rather than by request rate, and it
    /// is also more accurate: counts are summed rather than raced.
    ///
    /// Held behind its own `Arc` so a flush task can own a handle without
    /// needing `Arc<Self>`, which `new` cannot hand out from inside itself.
    usage: Arc<Mutex<HashMap<(Uuid, OffsetDateTime), UsageDelta>>>,
}

impl ApiKeyValidator {
    pub fn new(store: ApiKeyStore, config: ValidatorConfig) -> Arc<Self> {
        let cache: Cache<String, CachedEntry> = Cache::builder()
            .max_capacity(config.cache_capacity)
            .time_to_live(config.cache_ttl)
            .build();
        Arc::new(Self {
            store,
            cache,
            config,
            profile_store: None,
            usage: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Attach the api_key_profiles store so the validator can
    /// resolve profile restrictions onto
    /// `Principal.api_key_profile_restrictions`. Without this
    /// hook the profile restrictions are not enforced (the
    /// invocation gate's check is a no-op when the field is
    /// `None`).
    pub fn with_profile_store(
        self: Arc<Self>,
        store: Option<Arc<dyn crate::profiles::ProfileStore>>,
    ) -> Arc<Self> {
        let inner = Arc::try_unwrap(self).unwrap_or_else(|arc| Self {
            store: arc.store.clone(),
            cache: arc.cache.clone(),
            config: arc.config.clone(),
            profile_store: arc.profile_store.clone(),
            // Share the accrual map rather than starting a fresh one, so any
            // usage already pending a flush survives the rebuild.
            usage: Arc::clone(&arc.usage),
        });
        Arc::new(Self {
            store: inner.store,
            cache: inner.cache,
            config: inner.config,
            profile_store: store,
            usage: inner.usage,
        })
    }

    /// Drop every cached principal. Called from the tenant
    /// DELETE cleanup path
    /// (`waygate-admin::tenants::cleanup_onboarding_residue`) so
    /// freshly-revoked keys can't still authenticate against the
    /// in-memory cache for the remainder of its TTL window. Cheap
    /// on moka: single `invalidate_all` is a segment-marker bump,
    /// not a per-entry walk. The next call for any still-valid
    /// key incurs one DB lookup + argon2 verify and re-warms.
    /// We invalidate the whole cache (not just entries for the
    /// deleted tenant) because the cache key is the opaque token
    /// — we cannot enumerate which cached tokens belonged to the
    /// deleted tenant without iterating, and the operator-rare
    /// tenant DELETE path can absorb the cold-cache cost.
    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Bump `last_used_at` + the current-hour bucket. Always fire-and-forget;
    /// callers must never await this on the request hot path. Pulled out so
    /// both the cache-hit and cache-miss paths share identical accounting.
    fn spawn_touch_usage(&self, id: Uuid) {
        let now = OffsetDateTime::now_utc();
        let key = (id, crate::store::hour_bucket(now));
        // Accrue first, and only schedule a flush when this bucket had none
        // pending. A bucket already awaiting its flush absorbs the request for
        // free, so a hot key costs one transaction per debounce window instead
        // of one per request.
        if !accrue_usage(&self.usage, key, now) {
            return;
        }
        let store = self.store.clone();
        let usage = Arc::clone(&self.usage);
        let (id, bucket) = key;
        // One task per active key, living until a window finds nothing
        // accrued. Looping rather than respawning is what keeps a slow or
        // stalled database from multiplying writers: while this task is alive
        // its entry exists, so `accrue_usage` never starts a second one.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(USAGE_FLUSH_DEBOUNCE).await;
                // Take under the lock, write outside it, so a slow database
                // never blocks the request path.
                let Some((count, last_used_at)) = take_for_flush(&usage, &key) else {
                    break;
                };
                if let Err(e) = store.add_usage(id, bucket, count, last_used_at).await {
                    // Usage accounting is telemetry: a failed write drops that
                    // window's counts rather than requeuing them. Requests that
                    // arrived during the write are still in the entry and are
                    // picked up by the next iteration, so the retry cadence
                    // stays one write per key per window even while the
                    // database is unhealthy.
                    tracing::warn!(
                        api_key.id = %id,
                        dropped_requests = count,
                        error = %e,
                        "api_keys: usage flush failed",
                    );
                }
            }
        });
    }

    async fn lookup_and_verify(
        &self,
        parsed: ParsedToken<'_>,
    ) -> Result<Option<CachedEntry>, ValidationError> {
        let rows = self
            .store
            .lookup_by_prefix(parsed.prefix)
            .await
            .map_err(infra_error)?;

        if rows.is_empty() {
            // No rows: still run an argon2 verify against a fixed dummy
            // hash so timing analysis can't distinguish "unknown prefix"
            // from "wrong secret". Discard the result.
            let _ = token::verify_secret(parsed.secret_remainder, dummy_hash());
            return Ok(None);
        }

        for row in rows {
            match token::verify_secret(parsed.secret_remainder, &row.key_hash) {
                Ok(true) => {
                    // Route the row's `tenant_id` into
                    // `Principal.tenant`. Falls back to
                    // `TenantId::default()` if the stored value
                    // doesn't parse (operator-injected garbage
                    // in the DB; should never happen in practice
                    // since the mint path validates). The fallback
                    // logs at WARN so a corrupt row gets noticed
                    // without rejecting the entire request — the
                    // default-tenant landing is at least no worse
                    // than a single-tenant deployment.
                    let tenant = waygate_core::TenantId::parse(&row.tenant_id).unwrap_or_else(
                        |e| {
                            tracing::warn!(
                                row_id = %row.id,
                                tenant_id = %row.tenant_id,
                                error = %e,
                                "api_keys row carries an invalid tenant_id; routing principal to default tenant",
                            );
                            waygate_core::TenantId::default()
                        },
                    );
                    // Resolve profile restrictions onto
                    // the principal so the invocation gate
                    // doesn't need a per-call store lookup.
                    // Returns Ok(None) when:
                    //   - the row has no profile_id (legacy
                    //     mint path)
                    //   - the profile store isn't wired
                    //   - the profile no longer exists (FK
                    //     SET NULL on delete should make this
                    //     unreachable, but defensively the
                    //     missing-profile case is treated as
                    //     "no restrictions" rather than fail-
                    //     closed; the operator who deleted the
                    //     profile already had the chance to
                    //     revoke affected keys, and profile
                    //     DELETE flushes the validator cache so
                    //     cached entries can't keep enforcing
                    //     the deleted restrictions)
                    //
                    // A resolved profile is always carried, even when it has
                    // no server/tool allowlist. The identity still matters to
                    // downstream authorization records because the profile
                    // may constrain scopes, TTL, owner, or reason at mint
                    // time.
                    //
                    // Returns Err on a transient store failure
                    // (DB connection drop, query error). Those
                    // MUST fail closed — mapping them to None
                    // would let a transient profile_store hiccup
                    // turn a profiled key into an unrestricted
                    // principal cached for the full cache_ttl
                    // window (default 60s), bypassing
                    // allowed_servers/allowed_tools. Surface
                    // as ValidationError::Infra so the bearer
                    // middleware returns 503 and the cache
                    // stays uninfected.
                    let restrictions = resolve_profile_restrictions(
                        self.profile_store.as_deref(),
                        &row.tenant_id,
                        row.profile_id,
                    )
                    .await
                    .map_err(|e| {
                        ValidationError::Infra(format!(
                            "api_keys profile resolution failed (failing closed to avoid \
                             routing profiled key as unrestricted): {e}"
                        ))
                    })?;
                    let principal = Principal {
                        sub: row.sub,
                        email: row.email,
                        groups: row.groups,
                        issuer: self.config.issuer_label.clone(),
                        scopes: row.scopes,
                        tenant,
                        auth_method: AuthMethod::ApiKey,
                        // API keys are not OAuth tokens — never offer them
                        // to RFC 8693 exchange paths.
                        raw_token: None,
                        // SCIM attrs are filled by the optional
                        // PrincipalEnricher in BearerLayer after
                        // this validator returns (when configured).
                        roles: vec![],
                        scim: None,
                        enrichment_blocked: None,
                        api_key_profile_restrictions: restrictions,
                    };
                    return Ok(Some(CachedEntry {
                        principal,
                        expires_at: row.expires_at,
                        key_id: row.id,
                    }));
                }
                Ok(false) => continue,
                Err(e) => {
                    // Corrupt hash in the DB — log and treat as "no match"
                    // so other rows with the same prefix still get checked.
                    tracing::error!(
                        api_key.id = %row.id,
                        error = %e,
                        "api_keys: stored hash is unparseable",
                    );
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl HeaderValidator for ApiKeyValidator {
    async fn validate_header(&self, header: &str) -> Result<Principal, ValidationError> {
        // Cache lookup before parsing avoids touching the cache on
        // garbage headers (e.g. real JWTs that another validator owns).
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(ValidationError::Malformed)?;

        // Fast path: only attempt full validation for things that look
        // like our tokens. Anything else falls through to the next
        // validator in the chain via `Malformed`.
        if !token.starts_with(token::TOKEN_LITERAL) {
            return Err(ValidationError::Malformed);
        }

        if let Some(entry) = self.cache.get(token).await {
            // Re-check wall-clock expiry on every hit. The row's
            // `expires_at` is captured at cache-insert time and never
            // changes, so this is a cheap in-memory comparison — no
            // DB hop. Evict on expiry so the next request goes through
            // the miss path and rebuilds the cache cleanly (if the key
            // was rolled forward) or hits the unknown-prefix branch (if
            // it really is expired).
            if entry_expired(&entry) {
                self.cache.invalidate(token).await;
                return Err(ValidationError::Malformed);
            }
            // Account for the hit before returning — without this, the
            // dashboard sparkline reports one bump per `cache_ttl` even
            // under hot-key traffic. Fire-and-forget keeps the hot path
            // free.
            self.spawn_touch_usage(entry.key_id);
            return Ok(entry.principal);
        }

        let parsed = ParsedToken::parse(token).map_err(|e| match e {
            // Bad shape: fall through to the next validator. The
            // middleware will surface a 401 if no validator accepts.
            TokenError::BadLiteral | TokenError::BadLength(_) | TokenError::BadChars => {
                ValidationError::Malformed
            }
            // Argon2 hashing failure on the parse path is genuinely
            // unexpected (parse never hashes), but mapping it here keeps
            // the match exhaustive without an `_` arm.
            TokenError::Hash(msg) => ValidationError::Infra(format!("api_keys hash: {msg}")),
        })?;

        match self.lookup_and_verify(parsed).await? {
            Some(entry) => {
                self.spawn_touch_usage(entry.key_id);
                let principal = entry.principal.clone();
                self.cache.insert(token.to_owned(), entry).await;
                Ok(principal)
            }
            None => Err(ValidationError::Malformed),
        }
    }
}

fn entry_expired(e: &CachedEntry) -> bool {
    matches!(e.expires_at, Some(exp) if exp <= OffsetDateTime::now_utc())
}

/// A fixed argon2id hash we verify against when the prefix lookup found
/// nothing. The plaintext is irrelevant — we throw the result away — but
/// running the verify keeps timing characteristics roughly equal between
/// "unknown prefix" and "wrong secret" paths.
///
/// Computed once per process on first use.
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        token::hash_secret("api-keys-dummy-secret-for-timing-equalisation")
            .expect("argon2 hash of constant must succeed")
    })
}

/// Map a [`StoreError`] to a [`ValidationError`] the middleware
/// classifies as infra (→ 503).
fn infra_error(e: StoreError) -> ValidationError {
    ValidationError::Infra(format!("api_keys store: {e}"))
}

/// Resolve the api_key_profile_restrictions for a matched
/// api_keys row.
///
/// Returns `Ok(None)` whenever the principal shouldn't carry
/// restrictions for non-error reasons:
/// - profile store unconfigured,
/// - row predates profile support (profile_id NULL),
/// - profile no longer exists (FK SET NULL race or hand-
///   edit — best-effort: the legitimate DELETE path already
///   flushes the validator cache),
///
/// Returns `Err` on a transient store failure (DB connection
/// drop, query error). Callers MUST propagate this as
/// `ValidationError::Infra` rather than mapping it back to
/// `Ok(None)` — otherwise a
/// transient profile_store hiccup turns a profiled key
/// into an unrestricted principal that gets cached for the
/// full cache_ttl window (default 60s), silently bypassing
/// allowed_servers/allowed_tools. Fail closed at the
/// validator boundary so the bearer middleware returns 503
/// and the cache stays uninfected.
///
/// Hot path: one extra SELECT per cold-cache mint. Once the
/// principal lands in `CachedEntry`, repeated requests skip
/// this entirely. Operators who don't use profiles pay zero
/// cost (profile_id NULL short-circuits before the store
/// call).
async fn resolve_profile_restrictions(
    store: Option<&dyn crate::profiles::ProfileStore>,
    tenant_id: &str,
    profile_id: Option<Uuid>,
) -> Result<Option<waygate_oidc::ApiKeyProfileRestrictions>, crate::profiles::ProfileStoreError> {
    let Some(store) = store else {
        return Ok(None);
    };
    let Some(id) = profile_id else {
        return Ok(None);
    };
    match store.get(tenant_id, id).await {
        Ok(Some(p)) => Ok(Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: p.id.to_string(),
            profile_name: p.name,
            allowed_servers: p.allowed_servers,
            allowed_tools: p.allowed_tools,
        })),
        Ok(None) => {
            // Profile vanished (FK SET NULL race or hand-edit).
            // Treat as no-restrictions; the operator who
            // deleted the profile already had the chance to
            // revoke keys, and profile DELETE flushes the
            // validator cache so cached entries can't keep
            // stale restrictions.
            tracing::warn!(
                tenant = tenant_id,
                profile_id = %id,
                "api_keys: row references a profile that no longer exists; routing as unrestricted",
            );
            Ok(None)
        }
        Err(e) => {
            // Transient store failure — fail closed. Bubbling
            // the error up to the validator boundary turns the
            // request into a 503 (ValidationError::Infra) so
            // the unrestricted principal never enters the
            // cache. Logging at warn (not error) because the
            // bearer middleware will already log the 503 at
            // its own severity.
            tracing::warn!(
                tenant = tenant_id,
                profile_id = %id,
                error = %e,
                "api_keys: profile_store lookup failed; failing closed to avoid routing profiled key as unrestricted",
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod resolve_profile_restrictions_tests {
    //! Pin the fail-closed contract of
    //! `resolve_profile_restrictions`. The
    //! callsite in `lookup_and_verify` propagates via `?`
    //! into `ValidationError::Infra`, so this also covers
    //! the validator-boundary fail-closed posture (an
    //! infrastructure error → 503 from bearer middleware,
    //! no infected cache entry).

    use super::*;
    use crate::profiles::{Profile, ProfileStore, ProfileStoreError};
    use async_trait::async_trait;
    use time::OffsetDateTime;
    use uuid::Uuid;

    struct FakeStore {
        outcome: FakeOutcome,
    }

    enum FakeOutcome {
        Err,
        Missing,
        WithBoth(Vec<String>, Vec<String>),
        Empty,
    }

    #[async_trait]
    impl ProfileStore for FakeStore {
        async fn create(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: i32,
            _: &[String],
            _: Option<&[String]>,
            _: Option<&[String]>,
            _: bool,
            _: bool,
        ) -> Result<Profile, ProfileStoreError> {
            unimplemented!("create not exercised by resolve tests")
        }
        async fn get(&self, _: &str, id: Uuid) -> Result<Option<Profile>, ProfileStoreError> {
            match &self.outcome {
                FakeOutcome::Err => Err(ProfileStoreError::InvalidShape("simulated".into())),
                FakeOutcome::Missing => Ok(None),
                FakeOutcome::WithBoth(servers, tools) => Ok(Some(Profile {
                    id,
                    tenant_id: "t".into(),
                    name: "n".into(),
                    description: None,
                    max_ttl_seconds: 3600,
                    allowed_scopes: vec!["mcp:read".into()],
                    allowed_servers: Some(servers.clone()),
                    allowed_tools: Some(tools.clone()),
                    requires_reason: true,
                    requires_owner: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                })),
                FakeOutcome::Empty => Ok(Some(Profile {
                    id,
                    tenant_id: "t".into(),
                    name: "empty".into(),
                    description: None,
                    max_ttl_seconds: 3600,
                    allowed_scopes: vec!["mcp:read".into()],
                    allowed_servers: Some(vec![]),
                    allowed_tools: Some(vec![]),
                    requires_reason: true,
                    requires_owner: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                })),
            }
        }
        async fn list(&self, _: &str) -> Result<Vec<Profile>, ProfileStoreError> {
            unimplemented!()
        }
        async fn delete(&self, _: &str, _: Uuid) -> Result<bool, ProfileStoreError> {
            unimplemented!()
        }
        async fn delete_if_updated_at(
            &self,
            _: &str,
            _: Uuid,
            _: OffsetDateTime,
        ) -> Result<bool, ProfileStoreError> {
            unimplemented!()
        }
        async fn delete_all_for_tenant(&self, _: &str) -> Result<u64, ProfileStoreError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn store_error_propagates_so_caller_can_fail_closed() {
        let store = FakeStore {
            outcome: FakeOutcome::Err,
        };
        let result = resolve_profile_restrictions(Some(&store), "t", Some(Uuid::new_v4())).await;
        assert!(
            result.is_err(),
            "transient store error must propagate as Err so the validator boundary can map \
             it to ValidationError::Infra; mapping it to Ok(None) would let a profiled key \
             validate as unrestricted for the cache TTL window"
        );
    }

    #[tokio::test]
    async fn missing_profile_is_documented_ok_none_not_err() {
        let store = FakeStore {
            outcome: FakeOutcome::Missing,
        };
        let result = resolve_profile_restrictions(Some(&store), "t", Some(Uuid::new_v4())).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn no_store_is_ok_none() {
        let result = resolve_profile_restrictions(None, "t", Some(Uuid::new_v4())).await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn no_profile_id_is_ok_none() {
        let store = FakeStore {
            outcome: FakeOutcome::Err,
        };
        let result = resolve_profile_restrictions(Some(&store), "t", None).await;
        assert!(
            matches!(result, Ok(None)),
            "store must not be called when profile_id is None"
        );
    }

    #[tokio::test]
    async fn empty_lists_preserve_profile_identity() {
        let store = FakeStore {
            outcome: FakeOutcome::Empty,
        };
        let id = Uuid::new_v4();
        let result = resolve_profile_restrictions(Some(&store), "t", Some(id)).await;
        let profile = result.expect("ok").expect("resolved profile");
        assert_eq!(profile.profile_id, id.to_string());
        assert_eq!(profile.allowed_servers.as_deref(), Some([].as_slice()));
        assert_eq!(profile.allowed_tools.as_deref(), Some([].as_slice()));
    }

    #[tokio::test]
    async fn populated_lists_yield_restrictions() {
        let store = FakeStore {
            outcome: FakeOutcome::WithBoth(vec!["email".into()], vec!["email.send".into()]),
        };
        let result = resolve_profile_restrictions(Some(&store), "t", Some(Uuid::new_v4())).await;
        let r = result.expect("ok").expect("some");
        assert_eq!(
            r.allowed_servers.as_deref(),
            Some(&["email".to_string()][..])
        );
        assert_eq!(
            r.allowed_tools.as_deref(),
            Some(&["email.send".to_string()][..])
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(hour_offset: i64) -> OffsetDateTime {
        crate::store::hour_bucket(
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp")
                + time::Duration::hours(hour_offset),
        )
    }

    /// The property the whole change rests on: a burst against one key
    /// schedules exactly one flush and the requests are summed, rather than
    /// each request detaching its own transaction.
    #[test]
    fn a_burst_schedules_one_flush_and_sums_the_requests() {
        let pending = Mutex::new(HashMap::new());
        let key = (Uuid::new_v4(), bucket(0));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");

        assert!(
            accrue_usage(&pending, key, now),
            "the first request must schedule the flush",
        );
        for i in 1..500 {
            assert!(
                !accrue_usage(&pending, key, now + time::Duration::milliseconds(i)),
                "request {i} must be absorbed by the pending flush, not schedule another",
            );
        }

        let map = pending.lock().expect("lock");
        let delta = map.get(&key).expect("bucket still pending");
        assert_eq!(
            delta.count, 500,
            "every request must be counted, not dropped"
        );
        assert_eq!(
            delta.last_used_at,
            now + time::Duration::milliseconds(499),
            "last_used_at must advance to the newest observation in the window",
        );
    }

    /// The bound that survives a slow database: while a write is in flight the
    /// entry stays put at zero, so no further request can start a second
    /// writer for the same key. Draining the entry before the write completed
    /// would let every subsequent window spawn another one, and outstanding
    /// writers would grow with the stall — the pile-up this change removes.
    #[test]
    fn a_writer_in_flight_blocks_a_second_one_for_the_same_key() {
        let pending = Mutex::new(HashMap::new());
        let key = (Uuid::new_v4(), bucket(0));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");

        assert!(accrue_usage(&pending, key, now));
        assert!(!accrue_usage(&pending, key, now));

        // The writer takes the counts; its transaction has not returned yet.
        assert_eq!(
            take_for_flush(&pending, &key),
            Some((2, now)),
            "the writer takes everything accrued so far",
        );
        assert!(
            pending.lock().expect("lock").contains_key(&key),
            "the entry must remain as the writer-alive marker",
        );
        for _ in 0..100 {
            assert!(
                !accrue_usage(&pending, key, now),
                "no request may start a second writer while one is in flight",
            );
        }
        // Those 100 are not lost — the same writer picks them up next window.
        assert_eq!(take_for_flush(&pending, &key), Some((100, now)));
    }

    /// The writer ends only when a window finds nothing accrued, and the next
    /// request then starts a fresh one — otherwise usage would stop being
    /// recorded after the key went briefly idle.
    #[test]
    fn an_idle_window_ends_the_writer_and_the_next_request_starts_another() {
        let pending = Mutex::new(HashMap::new());
        let key = (Uuid::new_v4(), bucket(0));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");

        assert!(accrue_usage(&pending, key, now));
        assert_eq!(take_for_flush(&pending, &key), Some((1, now)));
        assert_eq!(
            take_for_flush(&pending, &key),
            None,
            "an idle window ends the writer",
        );
        assert!(
            pending.lock().expect("lock").is_empty(),
            "ending the writer must drop the entry, or the key would never flush again",
        );
        assert!(
            accrue_usage(&pending, key, now),
            "the next request starts a fresh writer",
        );
    }

    /// Accrual is keyed by hour bucket, so a burst spanning an hour boundary
    /// is attributed to both hours rather than folded into whichever one the
    /// flush happened to observe.
    #[test]
    fn separate_hour_buckets_accrue_independently() {
        let pending = Mutex::new(HashMap::new());
        let id = Uuid::new_v4();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("timestamp");

        assert!(accrue_usage(&pending, (id, bucket(0)), now));
        assert!(
            accrue_usage(&pending, (id, bucket(1)), now + time::Duration::hours(1)),
            "a new hour is a new bucket and needs its own flush",
        );
        let map = pending.lock().expect("lock");
        assert_eq!(map.len(), 2);
        assert!(map.values().all(|d| d.count == 1));
    }
}
