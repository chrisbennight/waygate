//! SCIM 2.0 (RFC 7643 / RFC 7644) Users
//! ingestion store.
//!
//! Minimal subset of the SCIM Core schema needed for Okta /
//! Authentik / EntraID to provision the gateway with its
//! tenant's users. Groups are implemented; PATCH (RFC 7644
//! §3.5.2) is handled at the `waygate-admin` handler layer
//! over the existing `get`/`replace` store ops,
//! so this store gained no PATCH-specific method. The full
//! filter grammar remains a follow-up.
//!
//! ## Surface
//!
//! - [`ScimUser`]: the SCIM User resource shape.
//! - [`ScimUserStore`] trait + [`PgScimUserStore`] impl.
//! - [`SCIM_SCHEMA_USER_URN`]: the canonical urn the
//!   handler stamps into emitted resources and validates
//!   on incoming POST/PUT bodies.
//!
//! ## What we keep on the SCIM resource vs in storage
//!
//! The SCIM Core User schema has many optional attributes
//! (name.*, emails[], phones[], addresses[], roles[],
//! enterprise-extension fields, ...). Storing each as a
//! dedicated column would force a column-per-IdP-attribute
//! migration treadmill. Instead the store keeps the fixed
//! attributes that appear in unique constraints + filters
//! as typed columns (`user_name`, `external_id`, `active`)
//! and the rest as a single `attrs` JSON blob preserving
//! the IdP-emitted shape verbatim. The handler validates
//! the inbound JSON shape; this crate's
//! [`PgScimUserStore`] is shape-agnostic.
//!
//! ## Tenancy
//!
//! Every read and write is tenant-scoped at the SQL level
//! via `WHERE tenant_id = $tenant`. Cross-tenant access is
//! structurally impossible — a tenant-A SCIM client (its
//! API key carries `tenant_id = "A"`) cannot see or mutate
//! tenant-B rows.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

pub mod enricher;

pub use enricher::{
    PgScimEnricher, PgScimResolver, ResolvedPrincipal, ScimResolveError, ScimResolver,
};

/// Canonical SCIM Core User schema URN per RFC 7643 §8.7.
/// Handler validates inbound resource bodies carry this in
/// their `schemas` array; emitted resources stamp it in.
pub const SCIM_SCHEMA_USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// SCIM error shape per RFC 7644 §3.12. Wrapped in
/// [`ScimError::to_json`] so admin handlers render
/// SCIM-spec-compliant error bodies (a SCIM client like
/// Okta validates that the error JSON has the expected
/// `schemas` + `status` + `detail` shape).
#[derive(Debug, thiserror::Error)]
pub enum ScimError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("uniqueness: {0}")]
    Uniqueness(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid filter: {0}")]
    InvalidFilter(String),
    #[error("invalid resource: {0}")]
    InvalidResource(String),
}

impl ScimError {
    /// HTTP status the SCIM spec assigns to each error
    /// shape (per RFC 7644 §3.12 Table 9). The handler
    /// renders this as the response status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Sqlx(_) => 500,
            Self::Uniqueness(_) => 409,
            Self::NotFound(_) => 404,
            Self::InvalidFilter(_) => 400,
            Self::InvalidResource(_) => 400,
        }
    }

    /// RFC 7644 §3.12 `scimType` string. Only some statuses
    /// have one; `None` falls back to no `scimType` field
    /// in the response body.
    pub fn scim_type(&self) -> Option<&'static str> {
        match self {
            Self::Uniqueness(_) => Some("uniqueness"),
            Self::InvalidFilter(_) => Some("invalidFilter"),
            Self::InvalidResource(_) => Some("invalidValue"),
            _ => None,
        }
    }
}

/// One SCIM-provisioned user. The handler converts between
/// this and the on-wire SCIM resource JSON; the store
/// reads/writes this exact shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    pub id: Uuid,
    pub tenant_id: String,
    /// IdP-assigned external id. Nullable because some
    /// IdPs (custom / homegrown) don't emit it.
    pub external_id: Option<String>,
    /// SCIM `userName` — unique per tenant per RFC 7643 §4.1.1.
    pub user_name: String,
    /// SCIM `active`. `false` ⇒ user is deactivated.
    pub active: bool,
    /// Everything else SCIM puts on the User resource
    /// (`name.*`, `emails[]`, `groups[]`, `roles[]`, ...).
    /// Stored verbatim so we don't lose IdP-specific fields
    /// across the round-trip.
    pub attrs: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ScimUser {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            external_id: row.try_get("external_id")?,
            user_name: row.try_get("user_name")?,
            active: row.try_get("active")?,
            attrs: row.try_get("attrs")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Pagination request shape per RFC 7644 §3.4.2.4.
/// SCIM uses 1-based `startIndex`; the store translates
/// to SQL OFFSET internally.
#[derive(Debug, Clone, Copy)]
pub struct ListParams {
    /// 1-based index of the first row to return per RFC
    /// 7644 §3.4.2.4. `1` = first row; values < 1 clamp
    /// to 1 at the store boundary.
    pub start_index: i64,
    /// Page size cap. Clamped to `[1, 200]` at the store
    /// boundary so a pathological `?count=999999` can't
    /// pull the whole table into memory.
    pub count: i64,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            start_index: 1,
            count: 50,
        }
    }
}

/// Result of a list call. SCIM `ListResponse` wraps this
/// with `schemas`, `totalResults`, `Resources`, etc. —
/// the handler does the wrapping; the store returns the
/// raw rows plus the count.
#[derive(Debug)]
pub struct ListResult {
    pub total_results: i64,
    pub resources: Vec<ScimUser>,
}

/// Minimal SCIM filter the store can answer. RFC 7644
/// §3.4.2.2 defines a richer grammar (`and`, `or`, complex
/// attribute paths, ...) — Round 1 supports just the
/// `userName eq "x"` and `externalId eq "x"` cases because
/// they cover every Okta + Authentik bootstrap probe.
/// Richer filters are tracked as a follow-up. (PATCH is
/// implemented in `waygate-admin` over `get`/`replace`.)
#[derive(Debug, Clone)]
pub enum ScimFilter {
    None,
    UserNameEq(String),
    /// SCIM `displayName eq "X"` per RFC 7644 §3.4.2.2.
    /// Used for both User (display_name attribute) and
    /// Group (displayName attribute) filters — same SQL
    /// column `display_name` in both stores.
    DisplayNameEq(String),
    ExternalIdEq(String),
}

/// Storage trait. Tenancy is a per-call parameter so a
/// single store wires every tenant.
#[async_trait]
pub trait ScimUserStore: Send + Sync + 'static {
    /// SCIM CREATE per RFC 7644 §3.3. Returns the persisted
    /// resource (including the server-assigned `id`). Fails
    /// with [`ScimError::Uniqueness`] when `(tenant_id,
    /// user_name)` or `(tenant_id, external_id)` collides
    /// with an existing row.
    async fn create(
        &self,
        tenant_id: &str,
        external_id: Option<&str>,
        user_name: &str,
        active: bool,
        attrs: Value,
    ) -> Result<ScimUser, ScimError>;

    /// SCIM GET per RFC 7644 §3.4.1. `None` ⇒ 404.
    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<ScimUser>, ScimError>;

    /// SCIM LIST per RFC 7644 §3.4.2. Filter + pagination.
    async fn list(
        &self,
        tenant_id: &str,
        filter: ScimFilter,
        params: ListParams,
    ) -> Result<ListResult, ScimError>;

    /// SCIM PUT per RFC 7644 §3.5.1: full replace of the
    /// resource. The handler ensures the `id` in the body
    /// matches the URL and passes the parsed fields.
    /// Returns the updated row; `None` ⇒ 404.
    async fn replace(
        &self,
        tenant_id: &str,
        id: Uuid,
        external_id: Option<&str>,
        user_name: &str,
        active: bool,
        attrs: Value,
    ) -> Result<Option<ScimUser>, ScimError>;

    /// SCIM DELETE per RFC 7644 §3.6. Returns `true` if a
    /// row was deleted; `false` ⇒ 404. The handler maps
    /// SCIM's preferred `204 No Content` on success.
    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ScimError>;
}

/// Postgres-backed [`ScimUserStore`].
pub struct PgScimUserStore {
    pool: sqlx::PgPool,
}

impl PgScimUserStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScimUserStore for PgScimUserStore {
    async fn create(
        &self,
        tenant_id: &str,
        external_id: Option<&str>,
        user_name: &str,
        active: bool,
        attrs: Value,
    ) -> Result<ScimUser, ScimError> {
        let row = sqlx::query_as::<_, ScimUser>(
            r#"
            INSERT INTO scim_users (tenant_id, external_id, user_name, active, attrs)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, tenant_id, external_id, user_name, active, attrs,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(external_id)
        .bind(user_name)
        .bind(active)
        .bind(&attrs)
        .fetch_one(&self.pool)
        .await;
        match row {
            Ok(u) => Ok(u),
            // Per-tenant uniqueness violation surfaces as
            // SQLSTATE 23505 (unique_violation). RFC 7644
            // §3.3 maps this to SCIM `uniqueness` error
            // (HTTP 409).
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(ScimError::Uniqueness(format!(
                    "user_name `{user_name}` or external_id already exists for tenant `{tenant_id}`"
                )))
            }
            Err(e) => Err(ScimError::Sqlx(e)),
        }
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<ScimUser>, ScimError> {
        sqlx::query_as::<_, ScimUser>(
            r#"
            SELECT id, tenant_id, external_id, user_name, active, attrs,
                   created_at, updated_at
              FROM scim_users
             WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ScimError::Sqlx)
    }

    async fn list(
        &self,
        tenant_id: &str,
        filter: ScimFilter,
        params: ListParams,
    ) -> Result<ListResult, ScimError> {
        // RFC 7644 §3.4.2.4: SCIM `startIndex` is 1-based;
        // SQL OFFSET is 0-based. Clamp both bounds to a
        // safe range so a pathological caller can't trip
        // an arithmetic overflow or pull the whole table.
        let start_index = params.start_index.max(1);
        let count = params.count.clamp(1, 200);
        let offset = start_index - 1;

        // Separate filter
        // fragments per query because positional binds
        // differ. The resources SELECT binds
        // (tenant, count, offset, filter) so the filter
        // is `$4`; the count SELECT binds (tenant, filter)
        // so the filter is `$2`. Reusing the same
        // fragment with `$4` in both would leave `$4`
        // unbound on the count query → Postgres errors
        // on every filtered list.
        // The filter variants include
        // DisplayNameEq for Groups. The User store
        // rejects DisplayNameEq here — the
        // resource-specific `parse_user_filter` shouldn't
        // emit it, but defending in the store catches a
        // future caller that bypasses the parser.
        if let ScimFilter::DisplayNameEq(_) = &filter {
            return Err(ScimError::InvalidFilter(
                "`displayName` is a Group attribute; User filters accept userName / externalId"
                    .into(),
            ));
        }
        let bind_value: Option<&str> = match &filter {
            ScimFilter::None => None,
            ScimFilter::UserNameEq(v) | ScimFilter::ExternalIdEq(v) => Some(v.as_str()),
            ScimFilter::DisplayNameEq(_) => unreachable!(),
        };
        let (resources_filter_sql, count_filter_sql) = match &filter {
            ScimFilter::None => ("", ""),
            ScimFilter::UserNameEq(_) => (" AND user_name = $4", " AND user_name = $2"),
            ScimFilter::ExternalIdEq(_) => (" AND external_id = $4", " AND external_id = $2"),
            ScimFilter::DisplayNameEq(_) => unreachable!(),
        };
        let resources_sql = format!(
            r#"
            SELECT id, tenant_id, external_id, user_name, active, attrs,
                   created_at, updated_at
              FROM scim_users
             WHERE tenant_id = $1{resources_filter_sql} AND deleted_at IS NULL
             ORDER BY created_at ASC, id ASC
             LIMIT $2 OFFSET $3
            "#
        );
        let count_sql = format!(
            r#"
            SELECT COUNT(*) FROM scim_users
             WHERE tenant_id = $1{count_filter_sql} AND deleted_at IS NULL
            "#
        );

        let mut q = sqlx::query_as::<_, ScimUser>(sqlx::AssertSqlSafe(resources_sql))
            .bind(tenant_id)
            .bind(count)
            .bind(offset);
        if let Some(v) = bind_value {
            q = q.bind(v);
        }
        let resources = q.fetch_all(&self.pool).await.map_err(ScimError::Sqlx)?;

        let mut cq = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql)).bind(tenant_id);
        if let Some(v) = bind_value {
            cq = cq.bind(v);
        }
        let total_results = cq.fetch_one(&self.pool).await.map_err(ScimError::Sqlx)?;
        Ok(ListResult {
            total_results,
            resources,
        })
    }

    async fn replace(
        &self,
        tenant_id: &str,
        id: Uuid,
        external_id: Option<&str>,
        user_name: &str,
        active: bool,
        attrs: Value,
    ) -> Result<Option<ScimUser>, ScimError> {
        let row = sqlx::query_as::<_, ScimUser>(
            r#"
            UPDATE scim_users
               SET external_id = $3,
                   user_name   = $4,
                   active      = $5,
                   attrs       = $6
             WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
            RETURNING id, tenant_id, external_id, user_name, active, attrs,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(external_id)
        .bind(user_name)
        .bind(active)
        .bind(&attrs)
        .fetch_optional(&self.pool)
        .await;
        match row {
            Ok(opt) => Ok(opt),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                Err(ScimError::Uniqueness(format!(
                    "user_name `{user_name}` or external_id already exists for tenant `{tenant_id}`"
                )))
            }
            Err(e) => Err(ScimError::Sqlx(e)),
        }
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ScimError> {
        // Soft-delete. Retain the row as a tombstone
        // (`active = false, deleted_at = now()`) instead of removing it,
        // so the enricher's tombstone-fallback blocks the deprovisioned
        // user. SCIM reads filter `deleted_at IS NULL`, so the resource
        // still 404s to the IdP (RFC 7644 — DELETE removes it from the
        // client's view); the retained row is an internal block signal.
        // The `deleted_at IS NULL` predicate makes a repeated DELETE of
        // an already-tombstoned row affect 0 rows → `false` → 404,
        // matching RFC 7644's "delete a missing resource" semantics.
        let n = sqlx::query(
            r#"
            UPDATE scim_users
               SET active = false, deleted_at = now()
             WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(ScimError::Sqlx)?
        .rows_affected();
        Ok(n > 0)
    }
}

/// Reclaim SCIM user tombstones older than `retention`.
///
/// Soft-deleted rows (`deleted_at IS NOT NULL`) are retained so the
/// enricher's tombstone-fallback keeps blocking a deprovisioned user.
/// They only accrue on deprovision events, but an unbounded tombstone
/// set is still housekeeping debt — this drops the ones past the
/// operator's retention window. Pure GC: never touches a live row, and
/// a tombstone still inside the window keeps blocking. Returns the
/// number of rows reclaimed.
pub async fn sweep_scim_tombstones(
    pool: &sqlx::PgPool,
    retention: std::time::Duration,
) -> Result<u64, sqlx::Error> {
    let n = sqlx::query(
        r#"
        DELETE FROM scim_users
         WHERE deleted_at IS NOT NULL
           AND deleted_at < now() - make_interval(secs => $1)
        "#,
    )
    .bind(retention.as_secs() as f64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// RFC 7644 §3.4.2.2 simple-filter parser. Accepts the
/// subset needed for Okta/Authentik bootstrap probes:
///
///   userName eq "value"
///   externalId eq "value"
///
/// Both single-quoted and double-quoted values are accepted
/// because some IdPs emit single quotes despite the spec.
/// Anything else returns `InvalidFilter`.
///
/// Named `parse_user_filter` (not a generic `parse_filter`)
/// to make the resource-type-specific allowlist explicit;
/// the Groups equivalent lives at [`parse_group_filter`].
pub fn parse_user_filter(raw: &str) -> Result<ScimFilter, ScimError> {
    parse_filter_with_allowed(raw, &["userName", "externalId"])
}

/// Group-resource equivalent of [`parse_user_filter`].
/// Accepts `displayName eq "X"` and `externalId eq "X"`.
pub fn parse_group_filter(raw: &str) -> Result<ScimFilter, ScimError> {
    parse_filter_with_allowed(raw, &["displayName", "externalId"])
}

/// Shared tokenizer for the minimal SCIM filter grammar.
/// Accepts `<attr> eq "<value>"` (single or double
/// quotes); restricts `<attr>` to the supplied
/// `allowed_attrs` set so each resource type only matches
/// its own column slots.
fn parse_filter_with_allowed(raw: &str, allowed_attrs: &[&str]) -> Result<ScimFilter, ScimError> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(ScimFilter::None);
    }
    // Tokenize permissively: split on whitespace, allow
    // quoted last segment.
    let mut chars = s.chars().peekable();
    let mut attr = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            break;
        }
        attr.push(c);
        chars.next();
    }
    skip_whitespace(&mut chars);
    let mut op = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            break;
        }
        op.push(c);
        chars.next();
    }
    skip_whitespace(&mut chars);
    let value = match chars.next() {
        Some('"') => read_until(&mut chars, '"')?,
        Some('\'') => read_until(&mut chars, '\'')?,
        _ => {
            return Err(ScimError::InvalidFilter(format!(
                "expected quoted value in filter `{raw}`"
            )))
        }
    };
    // Trailing must be empty/whitespace.
    let trailing: String = chars.collect();
    if !trailing.trim().is_empty() {
        return Err(ScimError::InvalidFilter(format!(
            "unexpected trailing content in filter `{raw}`"
        )));
    }
    if !op.eq_ignore_ascii_case("eq") {
        return Err(ScimError::InvalidFilter(format!(
            "unsupported operator `{op}` in filter `{raw}` (only `eq` is supported)"
        )));
    }
    if !allowed_attrs.contains(&attr.as_str()) {
        return Err(ScimError::InvalidFilter(format!(
            "unsupported attribute `{attr}` in filter (this resource only supports: {})",
            allowed_attrs.join(", ")
        )));
    }
    match attr.as_str() {
        "userName" => Ok(ScimFilter::UserNameEq(value)),
        "displayName" => Ok(ScimFilter::DisplayNameEq(value)),
        "externalId" => Ok(ScimFilter::ExternalIdEq(value)),
        // unreachable — allowed_attrs check above gates
        // the inputs that reach this match.
        other => Err(ScimError::InvalidFilter(format!(
            "internal: unhandled attribute `{other}` (allowed_attrs accepted it but match didn't)"
        ))),
    }
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn read_until(
    chars: &mut std::iter::Peekable<std::str::Chars>,
    terminator: char,
) -> Result<String, ScimError> {
    let mut out = String::new();
    for c in chars.by_ref() {
        if c == terminator {
            return Ok(out);
        }
        out.push(c);
    }
    Err(ScimError::InvalidFilter(format!(
        "filter value missing closing `{terminator}`"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_parses_username_eq() {
        match parse_user_filter(r#"userName eq "alice""#).unwrap() {
            ScimFilter::UserNameEq(v) => assert_eq!(v, "alice"),
            other => panic!("expected UserNameEq, got {other:?}"),
        }
    }

    #[test]
    fn filter_parses_external_id_eq() {
        match parse_user_filter(r#"externalId eq "abc-123""#).unwrap() {
            ScimFilter::ExternalIdEq(v) => assert_eq!(v, "abc-123"),
            other => panic!("expected ExternalIdEq, got {other:?}"),
        }
    }

    /// Some IdPs emit single quotes despite the spec. We
    /// accept both. Pinning this so a future tightening
    /// doesn't accidentally break Authentik.
    #[test]
    fn filter_accepts_single_quotes() {
        match parse_user_filter(r#"userName eq 'alice'"#).unwrap() {
            ScimFilter::UserNameEq(v) => assert_eq!(v, "alice"),
            other => panic!("expected UserNameEq, got {other:?}"),
        }
    }

    /// Empty filter ⇒ ScimFilter::None (list-all).
    #[test]
    fn empty_filter_returns_none() {
        assert!(matches!(parse_user_filter("").unwrap(), ScimFilter::None));
        assert!(matches!(
            parse_user_filter("   ").unwrap(),
            ScimFilter::None
        ));
    }

    /// Unsupported operator → InvalidFilter so the
    /// SCIM handler returns 400 `invalidFilter` instead
    /// of silently mismatching every row.
    #[test]
    fn unsupported_operator_rejected() {
        let err = parse_user_filter(r#"userName co "ali""#).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter(_)), "{err:?}");
    }

    /// Unsupported attribute → InvalidFilter. Round 1
    /// only handles userName + externalId; richer filter
    /// support is a follow-up.
    #[test]
    fn unsupported_attribute_rejected() {
        let err = parse_user_filter(r#"emails eq "alice@x""#).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter(_)), "{err:?}");
    }

    /// Missing closing quote → InvalidFilter.
    #[test]
    fn unterminated_quoted_value_rejected() {
        let err = parse_user_filter(r#"userName eq "alice"#).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter(_)), "{err:?}");
    }

    /// HTTP-status mapping matches RFC 7644 §3.12.
    #[test]
    fn http_status_mapping_matches_spec() {
        assert_eq!(ScimError::NotFound("x".into()).http_status(), 404);
        assert_eq!(ScimError::Uniqueness("x".into()).http_status(), 409);
        assert_eq!(ScimError::InvalidFilter("x".into()).http_status(), 400);
        assert_eq!(ScimError::InvalidResource("x".into()).http_status(), 400);
    }

    /// Group filter parses displayName + externalId, rejects
    /// userName (User-only attribute).
    #[test]
    fn group_filter_parses_display_name_and_external_id() {
        match parse_group_filter(r#"displayName eq "engineers""#).unwrap() {
            ScimFilter::DisplayNameEq(v) => assert_eq!(v, "engineers"),
            other => panic!("expected DisplayNameEq, got {other:?}"),
        }
        match parse_group_filter(r#"externalId eq "okta-grp-1""#).unwrap() {
            ScimFilter::ExternalIdEq(v) => assert_eq!(v, "okta-grp-1"),
            other => panic!("expected ExternalIdEq, got {other:?}"),
        }
    }

    #[test]
    fn group_filter_rejects_user_only_attribute() {
        let err = parse_group_filter(r#"userName eq "alice""#).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter(_)), "{err:?}");
    }

    /// User filter symmetric: rejects displayName (Group
    /// attribute). Defends against a SCIM client filtering
    /// /Users with a Group-shaped expression that would
    /// otherwise silently match no users.
    #[test]
    fn user_filter_rejects_group_only_attribute() {
        let err = parse_user_filter(r#"displayName eq "engineers""#).unwrap_err();
        assert!(matches!(err, ScimError::InvalidFilter(_)), "{err:?}");
    }
}

// ---------------------------------------------------------
// SCIM Groups
// ---------------------------------------------------------

/// Canonical SCIM Core Group schema URN per RFC 7643 §8.7.
pub const SCIM_SCHEMA_GROUP_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// One SCIM-provisioned group. Membership is stored
/// separately in `scim_user_groups` (see migration 0020)
/// so add/remove operations don't have to rewrite the
/// whole `attrs` blob, and the future RBAC layer can join
/// `group_role_mappings ↔ scim_user_groups ↔ scim_users`
/// without un-nesting a JSON array per request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    pub id: Uuid,
    pub tenant_id: String,
    pub external_id: Option<String>,
    /// SCIM `displayName` — unique per tenant.
    pub display_name: String,
    /// Verbatim SCIM extension attributes. `members[]`
    /// does NOT live here; the handler reassembles
    /// members from `scim_user_groups` at GET time.
    pub attrs: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ScimGroup {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            external_id: row.try_get("external_id")?,
            display_name: row.try_get("display_name")?,
            attrs: row.try_get("attrs")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Group-list result. Same shape as [`ListResult`] but
/// carries `ScimGroup` rows.
#[derive(Debug)]
pub struct GroupListResult {
    pub total_results: i64,
    pub resources: Vec<ScimGroup>,
}

/// One membership reference rendered into the SCIM
/// Group resource's `members[]` array. RFC 7643 §4.2:
/// each member has `value` (the user id), `$ref` (a
/// resolvable URL back to the user), `display`
/// (human-readable), and `type` (constant `"User"`
/// here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub value: String,
    #[serde(rename = "$ref")]
    pub r#ref: String,
    pub display: String,
    #[serde(rename = "type")]
    pub member_type: String,
}

/// Storage trait for SCIM Groups + membership operations.
#[async_trait]
pub trait ScimGroupStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        external_id: Option<&str>,
        display_name: &str,
        attrs: Value,
        member_user_ids: &[Uuid],
    ) -> Result<ScimGroup, ScimError>;

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<ScimGroup>, ScimError>;

    async fn list(
        &self,
        tenant_id: &str,
        filter: ScimFilter,
        params: ListParams,
    ) -> Result<GroupListResult, ScimError>;

    /// Full replace per RFC 7644 §3.5.1. Replaces every
    /// group field AND the membership set (members not in
    /// `member_user_ids` are removed; new ones added).
    async fn replace(
        &self,
        tenant_id: &str,
        id: Uuid,
        external_id: Option<&str>,
        display_name: &str,
        attrs: Value,
        member_user_ids: &[Uuid],
    ) -> Result<Option<ScimGroup>, ScimError>;

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ScimError>;

    /// Fetch the members rendered for inclusion in the
    /// Group resource's `members[]` array. The handler
    /// passes `gateway_base_url` so `$ref` URLs resolve
    /// to the caller's gateway. Returns members sorted by
    /// user_name for stable list output.
    async fn members(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        gateway_base_url: &str,
    ) -> Result<Vec<GroupMember>, ScimError>;
}

/// Postgres-backed [`ScimGroupStore`].
pub struct PgScimGroupStore {
    pool: sqlx::PgPool,
}

impl PgScimGroupStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScimGroupStore for PgScimGroupStore {
    async fn create(
        &self,
        tenant_id: &str,
        external_id: Option<&str>,
        display_name: &str,
        attrs: Value,
        member_user_ids: &[Uuid],
    ) -> Result<ScimGroup, ScimError> {
        // Group insert + membership inserts must be one
        // transaction so a partial create can't leave a
        // group without its declared members.
        let mut tx = self.pool.begin().await.map_err(ScimError::Sqlx)?;
        let group: ScimGroup = match sqlx::query_as::<_, ScimGroup>(
            r#"
            -- SCIM-provisioned groups are always
            -- source='scim' (explicit, not just the column default, so the
            -- boundary survives a future default change). On a display_name
            -- conflict with an existing LOCAL group — an api-key label
            -- backfilled by migration 0066 — PROMOTE that row to 'scim' and
            -- adopt the IdP's external_id/attrs. This is the unification: an
            -- IdP provisioning a name that first appeared as a local label
            -- takes ownership of it rather than getting a spurious 409.
            -- A conflict with an existing 'scim' group is
            -- a real collision: the WHERE makes the DO UPDATE a no-op,
            -- RETURNING yields no row, and we 409 below.
            INSERT INTO scim_groups (tenant_id, external_id, display_name, attrs, source)
            VALUES ($1, $2, $3, $4, 'scim')
            ON CONFLICT (tenant_id, display_name) DO UPDATE
               SET external_id = EXCLUDED.external_id,
                   attrs       = EXCLUDED.attrs,
                   source      = 'scim'
             WHERE scim_groups.source = 'local'
            RETURNING id, tenant_id, external_id, display_name, attrs,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(external_id)
        .bind(display_name)
        .bind(&attrs)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(Some(g)) => g,
            // No row back from the upsert ⇒ the conflicting row is an
            // existing source='scim' group (the DO UPDATE WHERE was false):
            // a genuine display_name collision between two SCIM groups.
            Ok(None) => {
                return Err(ScimError::Uniqueness(format!(
                    "display_name `{display_name}` already exists for tenant `{tenant_id}`"
                )));
            }
            // A 23505 here is the (tenant_id, external_id) unique index — a
            // different constraint than the ON CONFLICT target — colliding.
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                return Err(ScimError::Uniqueness(format!(
                    "external_id already exists for tenant `{tenant_id}`"
                )));
            }
            Err(e) => return Err(ScimError::Sqlx(e)),
        };
        insert_memberships(&mut tx, tenant_id, group.id, member_user_ids).await?;
        tx.commit().await.map_err(ScimError::Sqlx)?;
        Ok(group)
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<ScimGroup>, ScimError> {
        sqlx::query_as::<_, ScimGroup>(
            r#"
            SELECT id, tenant_id, external_id, display_name, attrs,
                   created_at, updated_at
              FROM scim_groups
             WHERE tenant_id = $1 AND id = $2 AND source = 'scim'
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(ScimError::Sqlx)
    }

    async fn list(
        &self,
        tenant_id: &str,
        filter: ScimFilter,
        params: ListParams,
    ) -> Result<GroupListResult, ScimError> {
        let start_index = params.start_index.max(1);
        let count = params.count.clamp(1, 200);
        let offset = start_index - 1;
        // Same per-query bind-fragment pattern as the User
        // store — separate `$4` vs `$2` placeholders for
        // resources vs count so the bind counts match.
        // Defence-in-depth: reject UserName filter on
        // the Group store. parse_group_filter doesn't
        // emit it, but a future caller that constructs a
        // ScimFilter directly should fail cleanly.
        if let ScimFilter::UserNameEq(_) = &filter {
            return Err(ScimError::InvalidFilter(
                "`userName` is a User attribute; Group filters accept displayName / externalId"
                    .into(),
            ));
        }
        let bind_value: Option<&str> = match &filter {
            ScimFilter::None => None,
            ScimFilter::DisplayNameEq(v) | ScimFilter::ExternalIdEq(v) => Some(v.as_str()),
            ScimFilter::UserNameEq(_) => unreachable!(),
        };
        let (resources_filter_sql, count_filter_sql) = match &filter {
            ScimFilter::None => ("", ""),
            ScimFilter::DisplayNameEq(_) => (" AND display_name = $4", " AND display_name = $2"),
            ScimFilter::ExternalIdEq(_) => (" AND external_id = $4", " AND external_id = $2"),
            ScimFilter::UserNameEq(_) => unreachable!(),
        };
        // `AND source = 'scim'` scopes the SCIM
        // 2.0 surface to IdP-provisioned groups only. After migration
        // 0066 backfills api-key labels as source='local' rows into the
        // same table, this filter keeps a SCIM client from enumerating
        // those local catalog rows (the admin Groups page shows both).
        let resources_sql = format!(
            r#"
            SELECT id, tenant_id, external_id, display_name, attrs,
                   created_at, updated_at
              FROM scim_groups
             WHERE tenant_id = $1 AND source = 'scim'{resources_filter_sql}
             ORDER BY created_at ASC, id ASC
             LIMIT $2 OFFSET $3
            "#
        );
        let count_sql = format!(
            r#"
            SELECT COUNT(*) FROM scim_groups
             WHERE tenant_id = $1 AND source = 'scim'{count_filter_sql}
            "#
        );
        let mut q = sqlx::query_as::<_, ScimGroup>(sqlx::AssertSqlSafe(resources_sql))
            .bind(tenant_id)
            .bind(count)
            .bind(offset);
        if let Some(v) = bind_value {
            q = q.bind(v);
        }
        let resources = q.fetch_all(&self.pool).await.map_err(ScimError::Sqlx)?;
        let mut cq = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql)).bind(tenant_id);
        if let Some(v) = bind_value {
            cq = cq.bind(v);
        }
        let total_results = cq.fetch_one(&self.pool).await.map_err(ScimError::Sqlx)?;
        Ok(GroupListResult {
            total_results,
            resources,
        })
    }

    async fn replace(
        &self,
        tenant_id: &str,
        id: Uuid,
        external_id: Option<&str>,
        display_name: &str,
        attrs: Value,
        member_user_ids: &[Uuid],
    ) -> Result<Option<ScimGroup>, ScimError> {
        let mut tx = self.pool.begin().await.map_err(ScimError::Sqlx)?;
        let group: Option<ScimGroup> = match sqlx::query_as::<_, ScimGroup>(
            r#"
            UPDATE scim_groups
               SET external_id = $3,
                   display_name = $4,
                   attrs = $5
             WHERE tenant_id = $1 AND id = $2 AND source = 'scim'
            RETURNING id, tenant_id, external_id, display_name, attrs,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(external_id)
        .bind(display_name)
        .bind(&attrs)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(opt) => opt,
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) =>
            {
                return Err(ScimError::Uniqueness(format!(
                    "display_name `{display_name}` or external_id already exists for tenant `{tenant_id}`"
                )));
            }
            Err(e) => return Err(ScimError::Sqlx(e)),
        };
        let Some(g) = group else {
            tx.rollback().await.map_err(ScimError::Sqlx)?;
            return Ok(None);
        };
        // Full replace = drop all existing memberships then
        // re-insert the declared set. Atomic per the
        // transaction; partial state never visible.
        sqlx::query(r#"DELETE FROM scim_user_groups WHERE group_id = $1"#)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(ScimError::Sqlx)?;
        insert_memberships(&mut tx, tenant_id, id, member_user_ids).await?;
        tx.commit().await.map_err(ScimError::Sqlx)?;
        Ok(Some(g))
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, ScimError> {
        // `AND source = 'scim'` so a SCIM write
        // client cannot delete a local (api-key-label) group through the
        // SCIM surface — those are admin-catalog rows, not IdP-managed.
        let n = sqlx::query(
            r#"DELETE FROM scim_groups WHERE tenant_id = $1 AND id = $2 AND source = 'scim'"#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(ScimError::Sqlx)?
        .rows_affected();
        Ok(n > 0)
    }

    async fn members(
        &self,
        tenant_id: &str,
        group_id: Uuid,
        gateway_base_url: &str,
    ) -> Result<Vec<GroupMember>, ScimError> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT u.id, u.user_name
              FROM scim_user_groups m
              JOIN scim_users u ON u.id = m.user_id
             WHERE m.tenant_id = $1 AND m.group_id = $2
               AND u.deleted_at IS NULL
             ORDER BY u.user_name ASC
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(ScimError::Sqlx)?;
        Ok(rows
            .into_iter()
            .map(|(uid, user_name)| GroupMember {
                value: uid.to_string(),
                r#ref: format!(
                    "{}/scim/v2/Users/{}",
                    gateway_base_url.trim_end_matches('/'),
                    uid
                ),
                display: user_name,
                member_type: "User".to_owned(),
            })
            .collect())
    }
}

/// Shared INSERT-membership helper used by `create` and
/// `replace`. The migration's tenant-match trigger
/// enforces that every membership row's user + group are
/// in the same tenant as the row itself; we still pass
/// `tenant_id` explicitly so the trigger has it on
/// INSERT.
async fn insert_memberships(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    group_id: Uuid,
    member_user_ids: &[Uuid],
) -> Result<(), ScimError> {
    for user_id in member_user_ids {
        match sqlx::query(
            r#"
            INSERT INTO scim_user_groups (user_id, group_id, tenant_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, group_id) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(group_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        {
            Ok(_) => {}
            // The tenant-match trigger raises a generic
            // exception (SQLSTATE P0001) when a member is
            // cross-tenant. Map to InvalidResource so the
            // SCIM client sees a 400 ("you sent a
            // tenant-foreign user id") rather than 500.
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("P0001") => {
                return Err(ScimError::InvalidResource(format!(
                    "membership: user {user_id} not in tenant `{tenant_id}` (per scim_user_groups tenant-match trigger)"
                )));
            }
            // Missing-user / missing-group references
            // surface as 23503 foreign-key violations.
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some(waygate_core::store::FOREIGN_KEY_VIOLATION) =>
            {
                return Err(ScimError::InvalidResource(format!(
                    "membership: user {user_id} does not exist in tenant `{tenant_id}`"
                )));
            }
            Err(e) => return Err(ScimError::Sqlx(e)),
        }
    }
    Ok(())
}
