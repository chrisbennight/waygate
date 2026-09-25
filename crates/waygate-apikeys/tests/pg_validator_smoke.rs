//! End-to-end smoke test for the API-key validator against a real Postgres.
//!
//! Skips cleanly when `AUDIT_DATABASE_URL` is not set so `cargo test` on a
//! laptop without a DB passes without special-casing. When the env var IS
//! set we apply migrations idempotently, mint → validate → revoke → wait
//! out the cache TTL → validate again, asserting the post-revocation
//! validation fails.
//!
//! The unit tests cover the token-format / argon2 / cache plumbing in
//! isolation; this one exercises the validator's contract end-to-end so a
//! regression in any of the moving parts (schema, store query, validator
//! wiring) trips the test rather than going unnoticed until production.

use std::env;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_apikeys::{token, ApiKeyRow, ApiKeyStore, ApiKeyValidator, ValidatorConfig};
use waygate_oidc::{AuthMethod, HeaderValidator};

const CACHE_TTL_MS: u64 = 200;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mint_validate_revoke_roundtrip() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping api-keys Pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");

    // Migrations are idempotent — `IF NOT EXISTS` everywhere. The migration
    // path lives in the waygate-storage crate's `PgAuditSink::migrate`, but
    // pointing sqlx at the same on-disk folder here keeps this test
    // self-contained (no inter-crate test ordering).
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = ApiKeyStore::new(pool.clone());
    let validator = ApiKeyValidator::new(
        store.clone(),
        ValidatorConfig {
            cache_ttl: Duration::from_millis(CACHE_TTL_MS),
            cache_capacity: 16,
            issuer_label: "api-key-smoke".into(),
        },
    );

    // 1. Mint outside the dashboard form path so this test stays independent
    //    of `waygate-admin`. The token helpers are the same code the dashboard
    //    handler runs.
    let minted = token::mint().expect("mint");
    let row = ApiKeyRow {
        id: Uuid::new_v4(),
        key_prefix: minted.key_prefix.clone(),
        key_hash: minted.key_hash.clone(),
        name: format!("pg-smoke-{}", Uuid::new_v4()),
        sub: "pg-smoke@example.test".into(),
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        email: Some("pg-smoke@example.test".into()),
        groups: vec!["mcp-users".into()],
        scopes: vec!["mcp:invoke".into(), "mcp:read".into()],
        created_by: "test".into(),
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
        expires_at: None,
        revoked_at: None,
        profile_id: None,
        owner: None,
        reason: None,
        rotation_due_at: None,
    };
    store.insert(&row).await.expect("insert");

    // 2. Validate happy path — the validator should accept the just-minted
    //    secret and return a Principal tagged ApiKey.
    let header = format!("Bearer {}", minted.display);
    let principal = validator
        .validate_header(&header)
        .await
        .expect("validate accepts minted key");
    assert_eq!(principal.sub, row.sub);
    assert_eq!(
        principal.email.as_deref(),
        Some(row.email.as_deref().unwrap())
    );
    assert_eq!(principal.groups, row.groups);
    assert_eq!(principal.scopes, row.scopes);
    assert_eq!(principal.auth_method, AuthMethod::ApiKey);
    assert_eq!(principal.issuer, "api-key-smoke");
    assert!(
        principal.raw_token.is_none(),
        "API-key principals must not expose raw_token (no RFC8693 exchange path)",
    );

    // 3. Revoke and wait out the cache TTL. The validator may serve a cached
    //    Principal for up to `cache_ttl` after revocation — that's the
    //    documented contract. Add a small fudge factor over the TTL so the
    //    test isn't racing the cache expiry.
    let revoked = store.revoke(row.id).await.expect("revoke");
    assert!(revoked, "revoke flips revoked_at");
    tokio::time::sleep(Duration::from_millis(CACHE_TTL_MS * 2)).await;

    // 4. Validate must now fail — the row no longer matches the live-only
    //    `lookup_by_prefix` filter, so the validator falls through to the
    //    "unknown prefix" path and returns Malformed.
    let err = validator
        .validate_header(&header)
        .await
        .expect_err("revoked key must not validate");
    assert!(
        err.is_client_error(),
        "post-revoke validation should be a client error, got {err:?}",
    );

    // 5. Cleanup: leave the table tidy so repeated runs don't bloat the
    //    smoke-test DB.
    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(row.id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

/// Pin that `ApiKeyValidator::invalidate_all` actually evicts cached
/// principals. The tenant DELETE cleanup path relies on this
/// to make freshly-revoked keys fail immediately rather than
/// after the validator's cache TTL window — without it, a
/// re-created tenant id could briefly resurrect a prior
/// bearer.
///
/// Sequence: mint → validate (caches) → soft-revoke the row
/// via `revoke_all_for_tenant` → validate again WITHOUT
/// invalidating; this should still pass (proving the cache
/// gap exists) → call `invalidate_all` → validate; this
/// MUST now fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidate_all_drops_cached_principal_so_post_revoke_validation_fails() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping invalidate_all pg smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let store = ApiKeyStore::new(pool.clone());
    // Use a LONG TTL here so the test doesn't accidentally rely
    // on the TTL expiry — we want to prove invalidate_all is
    // what flushes, not the clock.
    let validator = ApiKeyValidator::new(
        store.clone(),
        ValidatorConfig {
            cache_ttl: Duration::from_secs(600),
            cache_capacity: 16,
            issuer_label: "api-key-invalidate-smoke".into(),
        },
    );

    let tenant = format!("test-validator-invalidate-{}", Uuid::new_v4());
    let minted = token::mint().expect("mint");
    let row = ApiKeyRow {
        id: Uuid::new_v4(),
        key_prefix: minted.key_prefix.clone(),
        key_hash: minted.key_hash.clone(),
        name: format!("invalidate-smoke-{}", Uuid::new_v4()),
        sub: format!("system:scim-provisioner:{tenant}"),
        tenant_id: tenant.clone(),
        email: None,
        groups: vec![],
        scopes: vec!["scim:write".into()],
        created_by: "test".into(),
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
        expires_at: None,
        revoked_at: None,
        profile_id: None,
        owner: None,
        reason: None,
        rotation_due_at: None,
    };
    store.insert(&row).await.expect("insert");

    let header = format!("Bearer {}", minted.display);
    let _ = validator
        .validate_header(&header)
        .await
        .expect("first validate caches the principal");

    // Soft-revoke via the new bulk-tenant method (what the
    // tenant DELETE cleanup actually calls).
    let n = store
        .revoke_all_for_tenant(&tenant)
        .await
        .expect("revoke_all_for_tenant");
    assert_eq!(n, 1);

    // Without invalidation, the cache serves the prior
    // principal — this is the cache-gap this test guards against.
    let cached_ok = validator.validate_header(&header).await;
    assert!(
        cached_ok.is_ok(),
        "pre-invalidate validation must still pass — proves the cache gap exists",
    );

    // Now flush.
    validator.invalidate_all().await;

    let after = validator.validate_header(&header).await;
    assert!(
        after.is_err(),
        "post-invalidate validation must fail — revoked row should no longer match",
    );

    sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
        .bind(&tenant)
        .execute(&pool)
        .await
        .ok();
}

/// The write half of usage coalescing: `add_usage` must ADD its accrued count
/// to the bucket rather than overwrite it, or a second flush in the same hour
/// would discard the first one's requests.
///
/// This is the only coverage of the `count` binding and the additive UPSERT.
/// The roundtrip smoke above cannot reach it — it waits out a 200 ms cache TTL
/// and deletes its key well before the validator's multi-second flush debounce
/// elapses, and it never reads `api_key_usage`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_usage_accumulates_within_a_bucket() {
    let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
        eprintln!("skipping api-keys usage smoke: AUDIT_DATABASE_URL not set");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to AUDIT_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");

    let store = ApiKeyStore::new(pool.clone());
    let minted = token::mint().expect("mint");
    let id = Uuid::new_v4();
    let row = ApiKeyRow {
        id,
        key_prefix: minted.key_prefix.clone(),
        key_hash: minted.key_hash.clone(),
        name: format!("usage-smoke-{}", Uuid::new_v4()),
        sub: format!("usage-smoke-{id}@example.test"),
        tenant_id: waygate_core::TenantId::DEFAULT.to_owned(),
        email: None,
        groups: vec![],
        scopes: vec!["mcp:read".into()],
        created_by: "test".into(),
        created_at: OffsetDateTime::now_utc(),
        last_used_at: None,
        expires_at: None,
        revoked_at: None,
        profile_id: None,
        owner: None,
        reason: None,
        rotation_due_at: None,
    };
    store.insert(&row).await.expect("insert");

    // Two flushes landing in the same hour, as a burst spanning a debounce
    // boundary would produce.
    let now = OffsetDateTime::now_utc();
    let bucket = now
        - time::Duration::seconds(i64::from(now.minute()) * 60 + i64::from(now.second()))
        - time::Duration::nanoseconds(i64::from(now.nanosecond()));
    store
        .add_usage(id, bucket, 7, now)
        .await
        .expect("first flush");
    store
        .add_usage(id, bucket, 5, now + time::Duration::seconds(1))
        .await
        .expect("second flush");

    let count: i64 =
        sqlx::query_scalar("SELECT request_count FROM api_key_usage WHERE api_key_id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("usage row exists");
    assert_eq!(
        count, 12,
        "the second flush must add to the bucket, not replace it",
    );

    let last_used: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("key row exists");
    assert!(
        last_used.is_some_and(|t| t >= now),
        "last_used_at must advance to the flushed observation",
    );

    sqlx::query("DELETE FROM api_key_usage WHERE api_key_id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .ok();
}

mod profile_capacity {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use waygate_apikeys::{PgProfileStore, Profile, ProfileStore, ProfileStoreError};

    struct PausedProfileRead {
        profile: Profile,
        entered: Semaphore,
        resume: Semaphore,
    }

    #[async_trait::async_trait]
    impl ProfileStore for PausedProfileRead {
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
            unreachable!("authentication does not create profiles")
        }

        async fn get(&self, tenant: &str, id: Uuid) -> Result<Option<Profile>, ProfileStoreError> {
            assert_eq!(tenant, self.profile.tenant_id);
            assert_eq!(id, self.profile.id);
            self.entered.add_permits(1);
            self.resume.acquire().await.unwrap().forget();
            Ok(Some(self.profile.clone()))
        }

        async fn list(&self, _: &str) -> Result<Vec<Profile>, ProfileStoreError> {
            unreachable!()
        }
        async fn delete(&self, _: &str, _: Uuid) -> Result<bool, ProfileStoreError> {
            unreachable!()
        }
        async fn delete_if_updated_at(
            &self,
            _: &str,
            _: Uuid,
            _: OffsetDateTime,
        ) -> Result<bool, ProfileStoreError> {
            unreachable!()
        }
        async fn delete_all_for_tenant(&self, _: &str) -> Result<u64, ProfileStoreError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn slow_profile_reads_keep_admission_until_completion_or_cancellation() {
        let Ok(url) = env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping profile capacity Pg smoke: AUDIT_DATABASE_URL not set");
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
        let tenant = format!("test-profile-capacity-{}", Uuid::new_v4());
        sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
        let profiles = PgProfileStore::new(pool.clone());
        let profile = profiles
            .create(
                &tenant,
                "capacity",
                None,
                3600,
                &["mcp:read".to_owned()],
                None,
                None,
                false,
                false,
            )
            .await
            .unwrap();
        let paused = Arc::new(PausedProfileRead {
            profile: profile.clone(),
            entered: Semaphore::new(0),
            resume: Semaphore::new(0),
        });
        let store = ApiKeyStore::new(pool.clone());
        let validator = ApiKeyValidator::new(store.clone(), ValidatorConfig::default())
            .with_profile_store(Some(paused.clone()));
        let minted = token::mint().unwrap();
        let row = ApiKeyRow {
            id: Uuid::new_v4(),
            key_prefix: minted.key_prefix,
            key_hash: minted.key_hash,
            name: "profile capacity".into(),
            sub: "profile-capacity-user".into(),
            tenant_id: tenant.clone(),
            email: None,
            groups: vec![],
            scopes: vec!["mcp:read".into()],
            created_by: "test".into(),
            created_at: OffsetDateTime::now_utc(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            profile_id: Some(profile.id),
            owner: None,
            reason: None,
            rotation_due_at: None,
        };
        store.insert(&row).await.unwrap();
        let header = format!("Bearer {}", minted.display);
        let mut callers = Vec::new();
        // The documented capacity remains occupied after hashing, while each
        // caller is waiting for its authenticated profile restrictions.
        for _ in 0..4 {
            let validator = validator.clone();
            let header = header.clone();
            callers.push(tokio::spawn(async move {
                validator.validate_header(&header).await
            }));
            paused.entered.acquire().await.unwrap().forget();
        }
        let unknown = format!("Bearer mcpgw_{}", "Z".repeat(token::SECRET_LEN));
        let overloaded = validator.validate_header(&unknown).await.unwrap_err();
        assert!(
            matches!(overloaded, waygate_oidc::ValidationError::Infra(message) if message.contains("capacity exhausted"))
        );

        let cancelled = callers.pop().unwrap();
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert!(
            validator
                .validate_header(&unknown)
                .await
                .unwrap_err()
                .is_client_error(),
            "cancelling a profile lookup restores admission for another authentication"
        );

        paused.resume.add_permits(callers.len());
        for caller in callers {
            let principal = caller.await.unwrap().unwrap();
            assert_eq!(
                principal.api_key_profile_restrictions.unwrap().profile_id,
                profile.id.to_string()
            );
        }
        assert_eq!(
            validator.validate_header(&header).await.unwrap().sub,
            row.sub
        );
        sqlx::query("DELETE FROM api_keys WHERE id=$1")
            .bind(row.id)
            .execute(&pool)
            .await
            .unwrap();
        profiles.delete(&tenant, profile.id).await.unwrap();
        sqlx::query("DELETE FROM tenants WHERE id=$1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }
}
