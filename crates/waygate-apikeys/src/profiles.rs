//! API-key mint profiles.
//!
//! A profile is a per-tenant template that bounds what an
//! operator can pick when minting an api_keys row. The mint
//! handler validates the requested fields against the
//! profile's allowed_scopes / max_ttl_seconds / etc. and
//! refuses on overflow.
//!
//! See migration `0026_api_key_profiles.sql` for the storage
//! shape + rationale. This module is the store + validation
//! surface the admin handler consumes; the handler itself
//! lives in `waygate-admin::api_key_profiles`.
//!
//! ## Validation
//!
//! [`Profile::validate_mint`] takes the operator's requested
//! mint inputs (scopes, ttl, owner, reason) and returns
//! [`Ok`] if every constraint passes, [`Err(MintViolation)`]
//! with the specific failure otherwise. The admin handler
//! maps the variant to an HTTP 400 / 422 with operator-
//! visible detail.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// One `api_key_profiles` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct Profile {
    pub id: Uuid,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub max_ttl_seconds: i32,
    pub allowed_scopes: Vec<String>,
    /// `None` ⇒ any server allowed. `Some([])` is treated
    /// the same as `None` (unrestricted) by the call-time
    /// gate at `waygate_mcp::invocation::evaluate_profile_
    /// restrictions` and by the validator's resolver, which
    /// returns `None` for both-empty profiles so the
    /// `Principal` carries no inert restrictions struct.
    /// The CHECK at the SQL layer doesn't bar empty arrays.
    pub allowed_servers: Option<Vec<String>>,
    /// `None` ⇒ any tool allowed (within allowed_servers).
    /// `Some([])` is treated the same as `None` — see the
    /// `allowed_servers` doc above for the unified empty-
    /// equals-unrestricted semantics.
    pub allowed_tools: Option<Vec<String>>,
    pub requires_reason: bool,
    pub requires_owner: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum MintViolation {
    /// Requested scope is not in `allowed_scopes`.
    #[error("scope `{scope}` is not allowed by profile `{profile}`")]
    ScopeNotAllowed { profile: String, scope: String },
    /// Requested TTL exceeds the profile's `max_ttl_seconds`,
    /// OR TTL is None when the profile requires expiry.
    #[error("requested TTL exceeds profile `{profile}` max of {max_seconds}s")]
    TtlExceedsMax { profile: String, max_seconds: i32 },
    /// Profile requires `owner` to be set and the request
    /// didn't include one (or supplied empty).
    #[error("profile `{profile}` requires an `owner`")]
    OwnerRequired { profile: String },
    /// Profile requires `reason` to be set.
    #[error("profile `{profile}` requires a `reason`")]
    ReasonRequired { profile: String },
}

impl Profile {
    /// Validate a mint request against this profile. The
    /// admin handler builds the inputs from the dashboard form
    /// (or the JSON POST body) and maps each `MintViolation`
    /// variant to an HTTP 422 with operator-visible detail.
    ///
    /// `requested_ttl` of `None` means "no expiry" — the
    /// profile rejects this because profiles always require
    /// a bounded TTL (see migration 0026 doc comment).
    pub fn validate_mint(
        &self,
        scopes: &[String],
        requested_ttl: Option<Duration>,
        owner: Option<&str>,
        reason: Option<&str>,
    ) -> Result<(), MintViolation> {
        for s in scopes {
            if !self.allowed_scopes.iter().any(|a| a == s) {
                return Err(MintViolation::ScopeNotAllowed {
                    profile: self.name.clone(),
                    scope: s.clone(),
                });
            }
        }
        let max = Duration::from_secs(self.max_ttl_seconds as u64);
        match requested_ttl {
            None => {
                return Err(MintViolation::TtlExceedsMax {
                    profile: self.name.clone(),
                    max_seconds: self.max_ttl_seconds,
                })
            }
            Some(ttl) if ttl > max => {
                return Err(MintViolation::TtlExceedsMax {
                    profile: self.name.clone(),
                    max_seconds: self.max_ttl_seconds,
                })
            }
            _ => {}
        }
        if self.requires_owner && owner.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err(MintViolation::OwnerRequired {
                profile: self.name.clone(),
            });
        }
        if self.requires_reason && reason.map(|s| s.trim().is_empty()).unwrap_or(true) {
            return Err(MintViolation::ReasonRequired {
                profile: self.name.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileStoreError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// `(tenant_id, name)` uniqueness — admin returns 409.
    #[error("conflict: a profile already exists for this name")]
    Conflict,
    /// CHECK constraint failure — usually empty
    /// `allowed_scopes` or non-positive `max_ttl_seconds`.
    /// Admin returns 400 with the message verbatim.
    #[error("invalid profile shape: {0}")]
    InvalidShape(String),
    /// The `api_key_profiles_block_delete_if_referenced` trigger
    /// (migration 0027) raises because deleting the profile would
    /// strip `allowed_servers`/`allowed_tools` enforcement from
    /// `live_refs` still-active api_keys rows. The admin handler
    /// maps this to HTTP 409 and tells the operator to revoke or
    /// rotate the dependent keys first.
    #[error("blocked: {live_refs} live api_keys still reference this profile")]
    Blocked { live_refs: i64 },
}

#[async_trait]
pub trait ProfileStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        max_ttl_seconds: i32,
        allowed_scopes: &[String],
        allowed_servers: Option<&[String]>,
        allowed_tools: Option<&[String]>,
        requires_reason: bool,
        requires_owner: bool,
    ) -> Result<Profile, ProfileStoreError>;

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Profile>, ProfileStoreError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<Profile>, ProfileStoreError>;

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ProfileStoreError>;

    /// Delete only if the row still has the version captured for human review.
    /// The version predicate is part of the DELETE statement so an update in
    /// the final validation-to-write window causes zero affected rows.
    async fn delete_if_updated_at(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, ProfileStoreError>;

    /// Bulk-delete every profile for a tenant on tenant DELETE.
    /// The `api_keys.profile_id` FK is `ON DELETE SET NULL`, so
    /// existing api_keys rows stay intact (they get cascade-revoked
    /// separately by the tenant-deletion `revoke_all_for_tenant`
    /// arm). Returns the number of profile rows deleted.
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ProfileStoreError>;
}

/// Postgres-backed [`ProfileStore`].
pub struct PgProfileStore {
    pool: PgPool,
}

impl PgProfileStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ProfileStore for PgProfileStore {
    async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        max_ttl_seconds: i32,
        allowed_scopes: &[String],
        allowed_servers: Option<&[String]>,
        allowed_tools: Option<&[String]>,
        requires_reason: bool,
        requires_owner: bool,
    ) -> Result<Profile, ProfileStoreError> {
        let id = Uuid::now_v7();
        match sqlx::query(
            r#"
            INSERT INTO api_key_profiles (
                id, tenant_id, name, description, max_ttl_seconds,
                allowed_scopes, allowed_servers, allowed_tools,
                requires_reason, requires_owner
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, tenant_id, name, description, max_ttl_seconds,
                      allowed_scopes, allowed_servers, allowed_tools,
                      requires_reason, requires_owner, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(max_ttl_seconds)
        .bind(allowed_scopes)
        .bind(allowed_servers)
        .bind(allowed_tools)
        .bind(requires_reason)
        .bind(requires_owner)
        .fetch_one(&self.pool)
        .await
        {
            Ok(r) => Ok(row_to_profile(&r)),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(ProfileStoreError::Conflict)
            }
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::CHECK_VIOLATION) =>
            {
                Err(ProfileStoreError::InvalidShape(db.message().to_owned()))
            }
            Err(e) => Err(ProfileStoreError::Sqlx(e)),
        }
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<Profile>, ProfileStoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, name, description, max_ttl_seconds,
                   allowed_scopes, allowed_servers, allowed_tools,
                   requires_reason, requires_owner, created_at, updated_at
              FROM api_key_profiles
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_profile))
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<Profile>, ProfileStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, name, description, max_ttl_seconds,
                   allowed_scopes, allowed_servers, allowed_tools,
                   requires_reason, requires_owner, created_at, updated_at
              FROM api_key_profiles
             WHERE tenant_id = $1
             ORDER BY name ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_profile).collect())
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ProfileStoreError> {
        // The `api_key_profiles_block_delete_if_referenced` trigger
        // (migration 0027) raises with the message "blocked: N live
        // api_keys still reference this profile" when at least one
        // live api_keys row points at the profile_id. Catch the
        // trigger's RAISE EXCEPTION (SQLSTATE P0001 = raise_exception)
        // and map to the typed Blocked variant so the admin handler
        // can return HTTP 409 with the count. The trigger guarantees
        // atomicity vs. concurrent mints — the count is evaluated
        // inside the EXCLUSIVE row lock the DELETE acquires.
        map_delete_result(
            sqlx::query("DELETE FROM api_key_profiles WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&self.pool)
                .await,
        )
    }

    async fn delete_if_updated_at(
        &self,
        tenant_id: &str,
        id: Uuid,
        expected_updated_at: OffsetDateTime,
    ) -> Result<bool, ProfileStoreError> {
        map_delete_result(
            sqlx::query(
                "DELETE FROM api_key_profiles \
                 WHERE tenant_id = $1 AND id = $2 AND updated_at = $3",
            )
            .bind(tenant_id)
            .bind(id)
            .bind(expected_updated_at)
            .execute(&self.pool)
            .await,
        )
    }

    async fn delete_all_for_tenant(&self, tenant_id: &str) -> Result<u64, ProfileStoreError> {
        let n = sqlx::query("DELETE FROM api_key_profiles WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }
}

fn map_delete_result(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
) -> Result<bool, ProfileStoreError> {
    match result {
        Ok(result) => Ok(result.rows_affected() > 0),
        Err(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("P0001") && db.message().starts_with("blocked: ") =>
        {
            let live_refs = parse_blocked_count(db.message());
            Err(ProfileStoreError::Blocked { live_refs })
        }
        Err(error) => Err(ProfileStoreError::Sqlx(error)),
    }
}

/// Extract the live-reference count from the trigger's
/// "blocked: N live api_keys still reference this profile"
/// RAISE message. Returns `0` if parsing fails — the
/// operator-facing 409 message degrades to "blocked by some
/// live keys" but the request still gets correctly refused,
/// which is the safety-critical behavior.
fn parse_blocked_count(msg: &str) -> i64 {
    msg.strip_prefix("blocked: ")
        .and_then(|tail| tail.split(' ').next())
        .and_then(|n| n.parse::<i64>().ok())
        .unwrap_or(0)
}

fn row_to_profile(r: &sqlx::postgres::PgRow) -> Profile {
    Profile {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        description: r.get("description"),
        max_ttl_seconds: r.get("max_ttl_seconds"),
        allowed_scopes: r.get("allowed_scopes"),
        allowed_servers: r.get("allowed_servers"),
        allowed_tools: r.get("allowed_tools"),
        requires_reason: r.get("requires_reason"),
        requires_owner: r.get("requires_owner"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pin the parse contract for the trigger's "blocked: N..."
    // RAISE message. If the trigger text ever changes, these
    // tests catch the drift before the admin handler starts
    // returning "blocked by 0 keys" 409s in production.
    #[test]
    fn parse_blocked_count_extracts_the_number() {
        assert_eq!(
            parse_blocked_count("blocked: 3 live api_keys still reference this profile"),
            3
        );
        assert_eq!(
            parse_blocked_count("blocked: 1 live api_keys still reference this profile"),
            1
        );
    }

    #[test]
    fn parse_blocked_count_degrades_safely_on_format_drift() {
        // Safety contract: a malformed message must not lose
        // the 409 — the handler still refuses, just with a
        // less helpful count. Returning a non-zero parsed
        // value would be the unsafe failure mode.
        assert_eq!(parse_blocked_count(""), 0);
        assert_eq!(parse_blocked_count("blocked"), 0);
        assert_eq!(parse_blocked_count("blocked: abc rows"), 0);
        assert_eq!(parse_blocked_count("some other error"), 0);
    }

    fn profile(allowed_scopes: &[&str], requires_owner: bool, requires_reason: bool) -> Profile {
        Profile {
            id: Uuid::nil(),
            tenant_id: "default".into(),
            name: "test".into(),
            description: None,
            max_ttl_seconds: 3600,
            allowed_scopes: allowed_scopes.iter().map(|s| (*s).to_owned()).collect(),
            allowed_servers: None,
            allowed_tools: None,
            requires_reason,
            requires_owner,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn validate_mint_passes_on_subset_of_allowed_scopes() {
        let p = profile(&["mcp:invoke", "mcp:read"], false, false);
        assert!(p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                None,
                None
            )
            .is_ok());
        assert!(p
            .validate_mint(
                &["mcp:invoke".into(), "mcp:read".into()],
                Some(Duration::from_secs(60)),
                None,
                None
            )
            .is_ok());
    }

    #[test]
    fn validate_mint_rejects_scope_not_in_allowed_list() {
        let p = profile(&["mcp:read"], false, false);
        let err = p
            .validate_mint(
                &["mcp:admin".into()],
                Some(Duration::from_secs(60)),
                None,
                None,
            )
            .unwrap_err();
        match err {
            MintViolation::ScopeNotAllowed { scope, profile } => {
                assert_eq!(scope, "mcp:admin");
                assert_eq!(profile, "test");
            }
            other => panic!("expected ScopeNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn validate_mint_rejects_ttl_above_max() {
        let p = profile(&["mcp:read"], false, false);
        let err = p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(7200)),
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, MintViolation::TtlExceedsMax { .. }));
    }

    #[test]
    fn validate_mint_rejects_no_expiry_when_profile_set() {
        let p = profile(&["mcp:read"], false, false);
        let err = p
            .validate_mint(&["mcp:read".into()], None, None, None)
            .unwrap_err();
        assert!(matches!(err, MintViolation::TtlExceedsMax { .. }));
    }

    #[test]
    fn validate_mint_requires_owner_when_profile_says() {
        let p = profile(&["mcp:read"], true, false);
        let err = p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, MintViolation::OwnerRequired { .. }));
        // Empty owner also rejected.
        let err = p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                Some("   "),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, MintViolation::OwnerRequired { .. }));
        // Non-empty owner passes.
        assert!(p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                Some("alice@example.com"),
                None,
            )
            .is_ok());
    }

    #[test]
    fn validate_mint_requires_reason_when_profile_says() {
        let p = profile(&["mcp:read"], false, true);
        let err = p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, MintViolation::ReasonRequired { .. }));
        assert!(p
            .validate_mint(
                &["mcp:read".into()],
                Some(Duration::from_secs(60)),
                None,
                Some("rotating service account"),
            )
            .is_ok());
    }
}
