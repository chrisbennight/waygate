//! sqlx-backed store for `api_keys` + `api_key_usage` tables.
//!
//! The validator's hot path uses [`ApiKeyStore::lookup_by_prefix`] (live
//! rows only) and [`ApiKeyStore::touch_usage`] (fire-and-forget update of
//! `last_used_at` + the current hour's usage bucket). Mint / list / revoke
//! land on top of [`ApiKeyStore::insert`] and [`ApiKeyStore::revoke`] in
//! the dashboard PR.

use std::time::Duration;

use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown catalog scopes: {0:?}")]
    UnknownScopes(Vec<String>),
    #[error("unknown catalog groups: {0:?}")]
    UnknownGroups(Vec<String>),
}

/// One hourly bucket from `api_key_usage`. Caller-facing shape used by
/// the dashboard's sparkline.
#[derive(Debug, Clone)]
pub struct UsageBucket {
    pub bucket_start: OffsetDateTime,
    pub request_count: i64,
}

#[derive(sqlx::FromRow)]
struct UsageBucketRow {
    bucket_start: OffsetDateTime,
    request_count: i64,
}

/// One row of `api_keys` minus the `key_hash` (which we always extract
/// separately to avoid copying it around the hot path).
#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub key_prefix: String,
    pub key_hash: String,
    pub name: String,
    pub sub: String,
    /// Tenant this key belongs to. Stamped at mint time from the
    /// minting principal's tenant (admin via the dashboard form,
    /// or programmatic via the admin API). Defaults to
    /// [`waygate_core::TenantId::DEFAULT`] for keys minted before
    /// migration 0010 (via the column's NOT NULL DEFAULT
    /// 'default'), so single-tenant deployments see no behaviour
    /// change.
    pub tenant_id: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub created_by: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    /// Nullable so keys minted before profile support, and the
    /// transitional "legacy" mint path (no `profile_id` form
    /// field), keep working. When `Some`, the key was minted
    /// via a profile + carries the profile id for dashboard
    /// surfacing and rotation tracking.
    pub profile_id: Option<Uuid>,
    /// Operator-attributed owner. Set by the mint handler when
    /// the profile says `requires_owner`.
    pub owner: Option<String>,
    /// Operator-stated reason at mint time.
    pub reason: Option<String>,
    /// Deadline hint for rotation nudges in the dashboard.
    pub rotation_due_at: Option<OffsetDateTime>,
}

#[derive(Clone)]
pub struct ApiKeyStore {
    pool: PgPool,
}

impl ApiKeyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Live rows matching `prefix`. "Live" = not revoked, and either
    /// non-expiring or not yet expired. We expect a single row in practice
    /// (48 bits of prefix entropy → collision probability negligible up to
    /// ~16M live keys), but return a `Vec` so the validator can verify each
    /// hash on the cosmically-unlikely chance of a prefix collision.
    pub async fn lookup_by_prefix(&self, prefix: &str) -> Result<Vec<ApiKeyRow>, StoreError> {
        let rows = sqlx::query_as::<_, ApiKeyRowRaw>(
            r#"
            SELECT id, key_prefix, key_hash, name, sub, tenant_id, email, groups, scopes,
                   created_by, created_at, last_used_at, expires_at, revoked_at,
                   profile_id, owner, reason, rotation_due_at
            FROM api_keys
            WHERE key_prefix = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            "#,
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(ApiKeyRow::try_from).collect()
    }

    /// Low-level insert for callers that intentionally do not enforce a
    /// catalog (tests and tenant bootstrap). Admin minting uses
    /// [`Self::insert_catalog_checked`]. `key_hash` is the PHC string from
    /// `token::hash_secret`.
    pub async fn insert(&self, row: &ApiKeyRow) -> Result<(), StoreError> {
        self.insert_catalog_checked(row, false, false).await
    }

    /// Insert a freshly minted key after atomically locking and validating the
    /// configured catalog dimensions. The row locks serialize catalog-backed
    /// grants with guarded local group/scope deletion: either the grant lands
    /// first and deletion observes it, or deletion lands first and validation
    /// rejects the now-unknown name.
    pub async fn insert_catalog_checked(
        &self,
        row: &ApiKeyRow,
        enforce_scopes: bool,
        enforce_groups: bool,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        lock_and_validate_catalog(
            &mut tx,
            &row.tenant_id,
            &row.scopes,
            &row.groups,
            enforce_scopes,
            enforce_groups,
        )
        .await?;
        sqlx::query(
            r#"
            INSERT INTO api_keys (
                id, key_prefix, key_hash, name, sub, tenant_id, email, groups, scopes,
                created_by, created_at, last_used_at, expires_at, revoked_at,
                   profile_id, owner, reason, rotation_due_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                    $15, $16, $17, $18)
            "#,
        )
        .bind(row.id)
        .bind(&row.key_prefix)
        .bind(&row.key_hash)
        .bind(&row.name)
        .bind(&row.sub)
        .bind(&row.tenant_id)
        .bind(&row.email)
        .bind(JsonValue::from(
            row.groups
                .iter()
                .map(|g| JsonValue::from(g.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(JsonValue::from(
            row.scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(&row.created_by)
        .bind(row.created_at)
        .bind(row.last_used_at)
        .bind(row.expires_at)
        .bind(row.revoked_at)
        .bind(row.profile_id)
        .bind(&row.owner)
        .bind(&row.reason)
        .bind(row.rotation_due_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// All rows for the dashboard table — newest first, includes revoked
    /// and expired so operators can see "recently revoked" without a
    /// separate query. Bounded by `limit` to keep the page render cheap.
    pub async fn list(&self, limit: i64) -> Result<Vec<ApiKeyRow>, StoreError> {
        let rows = sqlx::query_as::<_, ApiKeyRowRaw>(
            r#"
            SELECT id, key_prefix, key_hash, name, sub, tenant_id, email, groups, scopes,
                   created_by, created_at, last_used_at, expires_at, revoked_at,
                   profile_id, owner, reason, rotation_due_at
            FROM api_keys
            ORDER BY created_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(ApiKeyRow::try_from).collect()
    }

    /// Tenant-scoped page of keys, newest first (includes revoked/expired,
    /// like [`Self::list`]). Used by the MCP `read_resource` surface so a
    /// tenant's keys paginate correctly: the global [`Self::list`] caps the
    /// pre-filter scan and hides a tenant's rows beyond the cap at scale,
    /// whereas this filters in SQL and pages within the tenant.
    pub async fn list_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApiKeyRow>, StoreError> {
        let rows = sqlx::query_as::<_, ApiKeyRowRaw>(
            r#"
            SELECT id, key_prefix, key_hash, name, sub, tenant_id, email, groups, scopes,
                   created_by, created_at, last_used_at, expires_at, revoked_at,
                   profile_id, owner, reason, rotation_due_at
            FROM api_keys
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(ApiKeyRow::try_from).collect()
    }

    /// Fetch a single row by id (any state — including revoked and
    /// expired). Used by the dashboard handlers to enrich audit logs
    /// with the row's identity fields before mutating.
    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKeyRow>, StoreError> {
        let row = sqlx::query_as::<_, ApiKeyRowRaw>(
            r#"
            SELECT id, key_prefix, key_hash, name, sub, tenant_id, email, groups, scopes,
                   created_by, created_at, last_used_at, expires_at, revoked_at,
                   profile_id, owner, reason, rotation_due_at
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(ApiKeyRow::try_from).transpose()
    }

    /// Update only the human-readable name. The secret + every other
    /// field stays put — rename never invalidates a key.
    pub async fn rename(&self, id: Uuid, name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys SET name = $2 WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Hourly request counts for a single key since `since`, newest first.
    /// Empty vec ⇒ no usage in window (key never touched, or all activity
    /// outside the window). The dashboard renders this as a sparkline.
    pub async fn usage_since(
        &self,
        id: Uuid,
        since: OffsetDateTime,
    ) -> Result<Vec<UsageBucket>, StoreError> {
        let rows = sqlx::query_as::<_, UsageBucketRow>(
            r#"
            SELECT bucket_start, request_count
            FROM api_key_usage
            WHERE api_key_id = $1 AND bucket_start >= $2
            ORDER BY bucket_start DESC
            "#,
        )
        .bind(id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| UsageBucket {
                bucket_start: r.bucket_start,
                request_count: r.request_count,
            })
            .collect())
    }

    /// Bulk soft-revoke every live key for a tenant. Called from the
    /// tenant DELETE path so a tenant that's later re-created with
    /// the same id cannot resurrect previously-issued keys (which
    /// would still pass tenant-gate enforcement because the new row
    /// exists and the lookup is keyed on `tenant_id` text).
    /// Soft-revoke `revoked_at = now()` rather than hard-DELETE so
    /// the audit trail of "key id X existed, was revoked at Y by
    /// tenant-delete cascade" stays intact for compliance. Returns
    /// the number of rows revoked so the handler can audit + log it.
    pub async fn revoke_all_for_tenant(&self, tenant_id: &str) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = now()
            WHERE tenant_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Atomically set `revoked_at = now()`. Returns `true` iff this call
    /// was the one that flipped the field. Cache TTL bounds the gap before
    /// in-flight callers see the rejection.
    pub async fn revoke(&self, id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = now()
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Low-level replacement of the grant set (`scopes` + `groups`) without a
    /// catalog check. Admin grant editing uses
    /// [`Self::update_grants_catalog_checked`]. The write is scoped to
    /// its tenant. Conditional on `revoked_at IS NULL` so an edit can never
    /// resurrect a revoked key (mirrors [`Self::revoke`]'s guard): returns
    /// `true` iff a live row owned by `tenant_id` was updated. The secret,
    /// sub, profile binding, and expiry are untouched — editing grants
    /// re-scopes a key in place; it never re-issues or rotates it. The
    /// validator's cache TTL bounds the gap before in-flight callers observe
    /// the new grants (same propagation envelope as revoke).
    pub async fn update_grants(
        &self,
        id: Uuid,
        tenant_id: &str,
        scopes: &[String],
        groups: &[String],
    ) -> Result<bool, StoreError> {
        self.update_grants_catalog_checked(id, tenant_id, scopes, groups, false, false)
            .await
    }

    /// Replace a live key's grants after locking and validating configured
    /// catalog dimensions in the same transaction as the update.
    // The key identity, two grant sets, and two independently configurable
    // catalog gates are separate invariants at this transaction boundary.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_grants_catalog_checked(
        &self,
        id: Uuid,
        tenant_id: &str,
        scopes: &[String],
        groups: &[String],
        enforce_scopes: bool,
        enforce_groups: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        lock_and_validate_catalog(
            &mut tx,
            tenant_id,
            scopes,
            groups,
            enforce_scopes,
            enforce_groups,
        )
        .await?;
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET scopes = $3, groups = $4
            WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(JsonValue::from(
            scopes
                .iter()
                .map(|s| JsonValue::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .bind(JsonValue::from(
            groups
                .iter()
                .map(|g| JsonValue::from(g.as_str()))
                .collect::<Vec<_>>(),
        ))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

    /// Record one successful use: bump `last_used_at` and increment the
    /// current hour's bucket in `api_key_usage`. Idempotent under
    /// concurrent callers via `ON CONFLICT DO UPDATE`.
    ///
    /// Designed to be `tokio::spawn`-ed off the hot path — callers ignore
    /// the result on the request side, but the test suite wants the
    /// `Result` to assert correctness.
    pub async fn touch_usage(&self, id: Uuid, now: OffsetDateTime) -> Result<(), StoreError> {
        self.add_usage(id, hour_bucket(now), 1, now).await
    }

    /// Apply `count` accrued requests for one `(key, hour bucket)` in a single
    /// transaction. The validator coalesces requests in memory and calls this
    /// once per debounce window instead of once per request, so a hot key costs
    /// one transaction every few seconds rather than one per hit.
    ///
    /// `count` is added rather than assigned, so concurrent flushes for the
    /// same bucket accumulate instead of clobbering each other.
    pub async fn add_usage(
        &self,
        id: Uuid,
        bucket: OffsetDateTime,
        count: i64,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            UPDATE api_keys SET last_used_at = $2 WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        // Stamp the usage row's `tenant_id` from the parent
        // api_keys row so per-tenant usage reporting doesn't
        // silently land at 'default' for keys minted under a
        // non-default tenant. The INSERT reads the parent's
        // tenant_id via subquery so the contract is "usage tenant
        // always matches parent key tenant" by construction —
        // callers don't have to pass it.
        sqlx::query(
            r#"
            INSERT INTO api_key_usage (api_key_id, bucket_start, request_count, tenant_id)
            SELECT $1, $2, $3, ak.tenant_id FROM api_keys ak WHERE ak.id = $1
            ON CONFLICT (api_key_id, bucket_start)
            DO UPDATE SET request_count = api_key_usage.request_count + EXCLUDED.request_count
            "#,
        )
        .bind(id)
        .bind(bucket)
        .bind(count)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Sweep revoked-or-expired rows older than `retain`. NULL `expires_at`
    /// rows are never swept by this query — operator chose "unlimited", we
    /// honour it. Revoked rows are kept for `retain` past their revocation
    /// so the dashboard can still surface "recently revoked" history.
    ///
    /// Returns the number of rows deleted (cascades into `api_key_usage`).
    pub async fn sweep_expired(&self, retain: Duration) -> Result<u64, StoreError> {
        let cutoff_secs: i64 = retain.as_secs().min(i64::MAX as u64) as i64;
        let result = sqlx::query(
            r#"
            DELETE FROM api_keys
            WHERE (revoked_at IS NOT NULL AND revoked_at < now() - make_interval(secs => $1))
               OR (expires_at IS NOT NULL AND expires_at < now() - make_interval(secs => $1))
            "#,
        )
        .bind(cutoff_secs)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

async fn lock_and_validate_catalog(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    scopes: &[String],
    groups: &[String],
    enforce_scopes: bool,
    enforce_groups: bool,
) -> Result<(), StoreError> {
    if enforce_scopes && !scopes.is_empty() {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
              FROM scopes
             WHERE name = ANY($2)
               AND (tenant_id IS NULL OR tenant_id = $1)
             ORDER BY id
             FOR KEY SHARE
            "#,
        )
        .bind(tenant_id)
        .bind(scopes)
        .fetch_all(&mut **tx)
        .await?;
        let unknown = sqlx::query_scalar::<_, String>(
            r#"
            SELECT n FROM unnest($2::text[]) AS n
             WHERE NOT EXISTS (
                 SELECT 1 FROM scopes s
                  WHERE s.name = n
                    AND (s.tenant_id IS NULL OR s.tenant_id = $1)
             )
            "#,
        )
        .bind(tenant_id)
        .bind(scopes)
        .fetch_all(&mut **tx)
        .await?;
        if !unknown.is_empty() {
            return Err(StoreError::UnknownScopes(unknown));
        }
    }

    if enforce_groups && !groups.is_empty() {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
              FROM scim_groups
             WHERE tenant_id = $1 AND display_name = ANY($2)
             ORDER BY id
             FOR KEY SHARE
            "#,
        )
        .bind(tenant_id)
        .bind(groups)
        .fetch_all(&mut **tx)
        .await?;
        let unknown = sqlx::query_scalar::<_, String>(
            r#"
            SELECT n FROM unnest($2::text[]) AS n
             WHERE NOT EXISTS (
                 SELECT 1 FROM scim_groups g
                  WHERE g.tenant_id = $1 AND g.display_name = n
             )
            "#,
        )
        .bind(tenant_id)
        .bind(groups)
        .fetch_all(&mut **tx)
        .await?;
        if !unknown.is_empty() {
            return Err(StoreError::UnknownGroups(unknown));
        }
    }
    Ok(())
}

/// Round `t` down to the start of its UTC hour.
pub(crate) fn hour_bucket(t: OffsetDateTime) -> OffsetDateTime {
    let m = t.minute();
    let s = t.second();
    let n = t.nanosecond();
    t - time::Duration::seconds(i64::from(m) * 60 + i64::from(s))
        - time::Duration::nanoseconds(i64::from(n))
}

#[derive(sqlx::FromRow)]
struct ApiKeyRowRaw {
    id: Uuid,
    key_prefix: String,
    key_hash: String,
    name: String,
    sub: String,
    tenant_id: String,
    email: Option<String>,
    groups: JsonValue,
    scopes: JsonValue,
    created_by: String,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    // Nullable so keys minted before profile support (and the
    // transitional "legacy" mint path) keep working.
    profile_id: Option<Uuid>,
    owner: Option<String>,
    reason: Option<String>,
    rotation_due_at: Option<OffsetDateTime>,
}

impl TryFrom<ApiKeyRowRaw> for ApiKeyRow {
    type Error = StoreError;
    fn try_from(r: ApiKeyRowRaw) -> Result<Self, StoreError> {
        Ok(Self {
            id: r.id,
            key_prefix: r.key_prefix,
            key_hash: r.key_hash,
            name: r.name,
            sub: r.sub,
            tenant_id: r.tenant_id,
            email: r.email,
            groups: json_to_str_vec(r.groups),
            scopes: json_to_str_vec(r.scopes),
            created_by: r.created_by,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
            profile_id: r.profile_id,
            owner: r.owner,
            reason: r.reason,
            rotation_due_at: r.rotation_due_at,
        })
    }
}

fn json_to_str_vec(v: JsonValue) -> Vec<String> {
    match v {
        JsonValue::Array(items) => items
            .into_iter()
            .filter_map(|i| match i {
                JsonValue::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hour_bucket_truncates() {
        let t = OffsetDateTime::from_unix_timestamp(1_700_000_123).unwrap()
            + time::Duration::microseconds(456);
        let b = hour_bucket(t);
        assert_eq!(b.minute(), 0);
        assert_eq!(b.second(), 0);
        assert_eq!(b.nanosecond(), 0);
        assert_eq!(b.hour(), t.hour());
    }
}
