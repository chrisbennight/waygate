//! Per-tenant response-inspector rule storage.
//!
//! Owns the `inspection_rules` table (migration 0032) — the
//! per-tenant custom rules meant to layer on top of the
//! hard-coded built-in inspector rulesets.
//!
//! ## Why this crate
//!
//! Same shape as `tasks` / `waygate-quota` /
//! `waygate-rbac`: per-feature crate owning its own trait +
//! types + Pg impl, kept dependency-light so a future runtime
//! consumer (the inspector loading rows on each invoke / via a
//! cached refresh worker) can hold the trait by handle without
//! pulling in admin-only baggage.
//!
//! ## What this crate provides
//!
//! Storage + trait + Pg impl only. No runtime inspector reads
//! these rules and enforces them yet — rows in
//! `inspection_rules` are inert (visible via the admin REST
//! surface in `waygate-admin::inspection_rules` but not
//! enforced on tool calls).

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

/// Built-in inspector this rule layers onto. Closed enum so
/// typos at insert time fail fast; mirrors the SQL CHECK
/// constraint in `migrations/0032_inspection_rules.sql`.
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
pub enum InspectorKind {
    Pii,
    Secrets,
    Poisoning,
    /// Reserved label for inspector kinds a future runtime
    /// will introduce when per-tenant rules unlock new
    /// inspector shapes (e.g. tenant-defined regex inspector
    /// not tied to a built-in).
    Custom,
}

impl InspectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pii => "pii",
            Self::Secrets => "secrets",
            Self::Poisoning => "poisoning",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pii" => Some(Self::Pii),
            "secrets" => Some(Self::Secrets),
            "poisoning" => Some(Self::Poisoning),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Full read-side view of an `inspection_rules` row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InspectionRule {
    pub id: Uuid,
    pub tenant_id: String,
    pub inspector: InspectorKind,
    pub name: String,
    /// Inspector-specific rule body (pattern, replacement
    /// token, label, etc.). Shape validated by the future
    /// runtime consumer; the storage layer is opaque so
    /// future inspector kinds can store richer data without
    /// a schema rev.
    pub config: serde_json::Value,
    /// Operator-authored selector for which tools/principals
    /// this rule applies to (e.g.
    /// `{"tools": ["example-messages.send"], "principals": ["*"]}`).
    /// `{}` ⇒ "any tool, any principal".
    pub applies_to: serde_json::Value,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug)]
pub struct NewInspectionRule<'a> {
    pub tenant_id: &'a str,
    pub inspector: InspectorKind,
    pub name: &'a str,
    pub config: &'a serde_json::Value,
    pub applies_to: &'a serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Default)]
pub struct RuleFilter<'a> {
    pub inspector: Option<InspectorKind>,
    /// Match by exact name within the (tenant, inspector)
    /// scope. Useful for the admin UI's "find by label" path.
    pub name: Option<&'a str>,
    /// Defaults to `true` ⇒ only enabled rows surface.
    /// `Some(false)` returns disabled-only, `None` returns
    /// both.
    pub enabled: Option<bool>,
}

#[derive(Debug)]
pub struct RuleUpdate<'a> {
    pub name: Option<&'a str>,
    pub config: Option<&'a serde_json::Value>,
    pub applies_to: Option<&'a serde_json::Value>,
    pub enabled: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("rule store: {0}")]
    Database(#[source] sqlx::Error),
    #[error("rule with the same (tenant, inspector, name) already exists")]
    DuplicateName,
}

/// Hard ceiling on `list_rules` page size — mirrors the other
/// admin stores (`oauth_consent`, `break_glass_tokens`,
/// `task_states`).
pub use waygate_core::page::MAX_LIST_LIMIT;

#[async_trait]
pub trait InspectionRulesStore: Send + Sync + 'static {
    /// Insert a new rule. Returns the created row.
    /// `RuleError::DuplicateName` on UNIQUE collision.
    async fn insert(&self, rule: NewInspectionRule<'_>) -> Result<InspectionRule, RuleError>;

    /// Single fetch by id, tenant-scoped. `Ok(None)` covers
    /// both "no such id" and "exists but wrong tenant" — same
    /// existence-disclosure-collapsing rule as `task_states`.
    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<InspectionRule>, RuleError>;

    /// Paginated list, tenant-scoped. Filters AND together.
    /// Ordered by `created_at DESC` so newest land first.
    async fn list(
        &self,
        tenant_id: &str,
        filter: RuleFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<InspectionRule>, RuleError>;

    /// Partial update of name / config / applies_to / enabled
    /// — `None` fields are left alone. Returns `Ok(Some(_))`
    /// with the post-update row when the rule existed in the
    /// caller's tenant; `Ok(None)` when it didn't.
    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: RuleUpdate<'_>,
    ) -> Result<Option<InspectionRule>, RuleError>;

    /// Hard delete. Returns `Ok(true)` when the row was
    /// removed; `Ok(false)` on no-such-id-or-wrong-tenant.
    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RuleError>;
}

pub type SharedRulesStore = Arc<dyn InspectionRulesStore>;

#[derive(Clone)]
pub struct PgInspectionRulesStore {
    pool: PgPool,
}

impl PgInspectionRulesStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InspectionRulesStore for PgInspectionRulesStore {
    async fn insert(&self, rule: NewInspectionRule<'_>) -> Result<InspectionRule, RuleError> {
        let row = sqlx::query(
            r#"
            INSERT INTO inspection_rules
                (tenant_id, inspector, name, config, applies_to, enabled)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, tenant_id, inspector, name, config, applies_to,
                      enabled, created_at, updated_at
            "#,
        )
        .bind(rule.tenant_id)
        .bind(rule.inspector.as_str())
        .bind(rule.name)
        .bind(rule.config)
        .bind(rule.applies_to)
        .bind(rule.enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(map_insert_err)?;
        Ok(row_to_rule(&row))
    }

    async fn get(&self, tenant_id: &str, id: Uuid) -> Result<Option<InspectionRule>, RuleError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, inspector, name, config, applies_to,
                   enabled, created_at, updated_at
              FROM inspection_rules
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(RuleError::Database)?;
        Ok(row.as_ref().map(row_to_rule))
    }

    async fn list(
        &self,
        tenant_id: &str,
        filter: RuleFilter<'_>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<InspectionRule>, RuleError> {
        let effective_limit = limit.min(MAX_LIST_LIMIT) as i64;
        let offset_i = offset as i64;
        let inspector_str = filter.inspector.map(|k| k.as_str().to_owned());
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, inspector, name, config, applies_to,
                   enabled, created_at, updated_at
              FROM inspection_rules
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR inspector = $2)
               AND ($3::text IS NULL OR name      = $3)
               AND ($4::bool IS NULL OR enabled   = $4)
             ORDER BY created_at DESC, id
             LIMIT $5 OFFSET $6
            "#,
        )
        .bind(tenant_id)
        .bind(inspector_str.as_deref())
        .bind(filter.name)
        .bind(filter.enabled)
        .bind(effective_limit)
        .bind(offset_i)
        .fetch_all(&self.pool)
        .await
        .map_err(RuleError::Database)?;
        Ok(rows.iter().map(row_to_rule).collect())
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: Uuid,
        update: RuleUpdate<'_>,
    ) -> Result<Option<InspectionRule>, RuleError> {
        // COALESCE preserves the existing value when the caller
        // passes None. `updated_at` is auto-bumped by the trigger
        // so it's deliberately NOT in the SET list.
        let row = sqlx::query(
            r#"
            UPDATE inspection_rules
               SET name       = COALESCE($3, name),
                   config     = COALESCE($4, config),
                   applies_to = COALESCE($5, applies_to),
                   enabled    = COALESCE($6, enabled)
             WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, inspector, name, config, applies_to,
                      enabled, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(update.name)
        .bind(update.config)
        .bind(update.applies_to)
        .bind(update.enabled)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_insert_err)?;
        Ok(row.as_ref().map(row_to_rule))
    }

    async fn delete(&self, tenant_id: &str, id: Uuid) -> Result<bool, RuleError> {
        let res = sqlx::query(
            r#"
            DELETE FROM inspection_rules
             WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(RuleError::Database)?;
        Ok(res.rows_affected() > 0)
    }
}

/// Map a sqlx error from INSERT / UPDATE into either a
/// `DuplicateName` (the operator-actionable UNIQUE collision)
/// or generic `Database`.
fn map_insert_err(e: sqlx::Error) -> RuleError {
    if let sqlx::Error::Database(ref db_err) = e {
        // Postgres unique_violation = 23505. The constraint
        // we care about is `inspection_rules_tenant_id_inspector_name_key`
        // but any unique violation on this table is the same
        // user-error class.
        if db_err.code().as_deref() == Some(waygate_core::store::UNIQUE_VIOLATION) {
            return RuleError::DuplicateName;
        }
    }
    RuleError::Database(e)
}

fn row_to_rule(row: &PgRow) -> InspectionRule {
    let inspector_str: String = row.get("inspector");
    let inspector = InspectorKind::parse(&inspector_str).unwrap_or(InspectorKind::Custom);
    InspectionRule {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        inspector,
        name: row.get("name"),
        config: row.get("config"),
        applies_to: row.get("applies_to"),
        enabled: row.get("enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspector_kind_roundtrips_through_as_str_parse() {
        for k in [
            InspectorKind::Pii,
            InspectorKind::Secrets,
            InspectorKind::Poisoning,
            InspectorKind::Custom,
        ] {
            assert_eq!(InspectorKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(InspectorKind::parse("nope"), None);
    }
}
