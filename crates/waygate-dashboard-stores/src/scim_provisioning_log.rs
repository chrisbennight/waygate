//! SCIM provisioning-log timeline store.
//!
//! The existing `audit_log` already captures every SCIM
//! mutation as a generic `AdminMutation` event with a
//! free-form `reason` string. That's fine for compliance
//! sweeps, but operator-facing "what did Okta push for
//! alice@example.com on Friday?" / "why did the last PATCH on
//! the `ops` group fail?" questions answer faster against a
//! purpose-shaped table: this one indexes
//! `(tenant_id, target_kind, target_id, ts DESC)` so the
//! per-target drawer on the dashboard SCIM page is one
//! index-bound query instead of a regex over the audit log.
//!
//! ## Why a separate crate
//!
//! Same per-domain crate pattern as `waygate-rbac` /
//! `waygate-scim` / `waygate-tenants` / `gateway-playground-
//! scenarios`: keeps `waygate-admin`'s main deps free of
//! direct `sqlx` for one read/write surface.
//!
//! ## Writer + reader split
//!
//! `append` is the only write entry — best-effort by
//! contract (the SCIM mutation that triggered it already
//! committed; logging it must not roll back the mutation),
//! so callers `await` the result + log the error rather than
//! propagating. `list` is the per-tenant timeline; `list_for_target`
//! is the per-row drawer.
//!
//! ## Schema-free `detail`
//!
//! The `detail` column is JSONB and schema-free at the SQL
//! layer. Writers choose the keys (`before` / `after` for
//! replace, `added_member_ids` / `removed_member_ids` for
//! membership patches, etc.); readers render whatever's
//! present. A future writer that adds a key doesn't need a
//! migration, matching the `playground_scenarios.body`
//! posture.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// What kind of SCIM resource the event targeted. Mirrors
/// the SQL CHECK on the same column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    User,
    Group,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }
}

/// Outcome of the mutation. Mirrors the SQL CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Error,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

/// One stored row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub tenant_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub target_kind: TargetKind,
    pub target_id: Uuid,
    pub target_display: String,
    pub target_external_id: Option<String>,
    pub action: String,
    pub outcome: Outcome,
    pub actor_sub: Option<String>,
    pub actor_email: Option<String>,
    pub error_message: Option<String>,
    pub detail: Value,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for Entry {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        let target_kind_s: String = row.try_get("target_kind")?;
        let target_kind = match target_kind_s.as_str() {
            "user" => TargetKind::User,
            "group" => TargetKind::Group,
            other => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "target_kind".into(),
                    source: format!("unknown target_kind {other:?}").into(),
                });
            }
        };
        let outcome_s: String = row.try_get("outcome")?;
        let outcome = match outcome_s.as_str() {
            "success" => Outcome::Success,
            "error" => Outcome::Error,
            other => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "outcome".into(),
                    source: format!("unknown outcome {other:?}").into(),
                });
            }
        };
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            ts: row.try_get("ts")?,
            target_kind,
            target_id: row.try_get("target_id")?,
            target_display: row.try_get("target_display")?,
            target_external_id: row.try_get("target_external_id")?,
            action: row.try_get("action")?,
            outcome,
            actor_sub: row.try_get("actor_sub")?,
            actor_email: row.try_get("actor_email")?,
            error_message: row.try_get("error_message")?,
            detail: row.try_get("detail")?,
        })
    }
}

/// Write-side payload. Callers build one of these per SCIM
/// mutation; the writer copies it into the row.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub tenant_id: String,
    pub target_kind: TargetKind,
    pub target_id: Uuid,
    pub target_display: String,
    pub target_external_id: Option<String>,
    pub action: String,
    pub outcome: Outcome,
    pub actor_sub: Option<String>,
    pub actor_email: Option<String>,
    pub error_message: Option<String>,
    pub detail: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Page-size cap for per-tenant + per-target reads. Both
/// surfaces page the same way: ordered by `ts DESC`,
/// optionally bounded by `before=<ts>` for pagination.
// Deliberate divergence from waygate_core::page (limit/offset, u32):
// this log pages by `before=<timestamp>` cursor with an i64 limit.
pub const DEFAULT_PAGE_LIMIT: i64 = 100;

#[async_trait]
pub trait ScimProvisioningLogStore: Send + Sync + 'static {
    /// Best-effort write. The caller's SCIM mutation has
    /// already committed by the time we get here — failing
    /// the append must not roll back the mutation. The
    /// dashboard handler logs the error and continues.
    async fn append(&self, entry: NewEntry) -> Result<Entry, LogError>;
    /// Per-tenant timeline (newest first). `before` lets the
    /// dashboard paginate without a cursor token — just pass
    /// the oldest `ts` from the previous page.
    async fn list(
        &self,
        tenant_id: &str,
        limit: i64,
        before: Option<OffsetDateTime>,
    ) -> Result<Vec<Entry>, LogError>;
    /// Per-target drawer. Same page shape, scoped to one
    /// `(target_kind, target_id)` pair.
    async fn list_for_target(
        &self,
        tenant_id: &str,
        target_kind: TargetKind,
        target_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Entry>, LogError>;
}

pub struct PgScimProvisioningLogStore {
    pool: PgPool,
}

impl PgScimProvisioningLogStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScimProvisioningLogStore for PgScimProvisioningLogStore {
    async fn append(&self, entry: NewEntry) -> Result<Entry, LogError> {
        let row = sqlx::query_as::<_, Entry>(
            r#"
            INSERT INTO scim_provisioning_log
                (tenant_id, target_kind, target_id, target_display,
                 target_external_id, action, outcome, actor_sub,
                 actor_email, error_message, detail)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, tenant_id, ts, target_kind, target_id,
                      target_display, target_external_id, action,
                      outcome, actor_sub, actor_email, error_message,
                      detail
            "#,
        )
        .bind(&entry.tenant_id)
        .bind(entry.target_kind.as_str())
        .bind(entry.target_id)
        .bind(&entry.target_display)
        .bind(&entry.target_external_id)
        .bind(&entry.action)
        .bind(entry.outcome.as_str())
        .bind(&entry.actor_sub)
        .bind(&entry.actor_email)
        .bind(&entry.error_message)
        .bind(&entry.detail)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list(
        &self,
        tenant_id: &str,
        limit: i64,
        before: Option<OffsetDateTime>,
    ) -> Result<Vec<Entry>, LogError> {
        let clamped = limit.clamp(1, DEFAULT_PAGE_LIMIT);
        let rows = match before {
            None => {
                sqlx::query_as::<_, Entry>(
                    r#"
                    SELECT id, tenant_id, ts, target_kind, target_id,
                           target_display, target_external_id, action,
                           outcome, actor_sub, actor_email, error_message,
                           detail
                      FROM scim_provisioning_log
                     WHERE tenant_id = $1
                     ORDER BY ts DESC
                     LIMIT $2
                    "#,
                )
                .bind(tenant_id)
                .bind(clamped)
                .fetch_all(&self.pool)
                .await?
            }
            Some(b) => {
                sqlx::query_as::<_, Entry>(
                    r#"
                    SELECT id, tenant_id, ts, target_kind, target_id,
                           target_display, target_external_id, action,
                           outcome, actor_sub, actor_email, error_message,
                           detail
                      FROM scim_provisioning_log
                     WHERE tenant_id = $1 AND ts < $2
                     ORDER BY ts DESC
                     LIMIT $3
                    "#,
                )
                .bind(tenant_id)
                .bind(b)
                .bind(clamped)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    async fn list_for_target(
        &self,
        tenant_id: &str,
        target_kind: TargetKind,
        target_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Entry>, LogError> {
        let clamped = limit.clamp(1, DEFAULT_PAGE_LIMIT);
        let rows = sqlx::query_as::<_, Entry>(
            r#"
            SELECT id, tenant_id, ts, target_kind, target_id,
                   target_display, target_external_id, action,
                   outcome, actor_sub, actor_email, error_message,
                   detail
              FROM scim_provisioning_log
             WHERE tenant_id = $1
               AND target_kind = $2
               AND target_id = $3
             ORDER BY ts DESC
             LIMIT $4
            "#,
        )
        .bind(tenant_id)
        .bind(target_kind.as_str())
        .bind(target_id)
        .bind(clamped)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kind_round_trips_as_str() {
        assert_eq!(TargetKind::User.as_str(), "user");
        assert_eq!(TargetKind::Group.as_str(), "group");
    }

    #[test]
    fn outcome_round_trips_as_str() {
        assert_eq!(Outcome::Success.as_str(), "success");
        assert_eq!(Outcome::Error.as_str(), "error");
    }

    #[test]
    fn default_page_limit_matches_typical_dashboard_render() {
        // The dashboard timeline section sizes its table at ~50
        // rows before "Load more"; 100 leaves headroom for filter
        // refinement without hitting a page boundary on every
        // click.
        assert_eq!(DEFAULT_PAGE_LIMIT, 100);
    }
}
