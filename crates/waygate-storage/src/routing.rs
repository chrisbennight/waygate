//! Per-tenant evidence routing.
//!
//! Read-side counterpart to `migrations/0016_tenant_evidence_routing.sql`.
//! The recorder calls [`fetch_tenant_routing`] inside its
//! `record_required` transaction; the pure resolver
//! [`resolve_outbox_targets`] then decides which exporter
//! names to enqueue outbox rows for. The admin API
//! (`crates/waygate-admin/src/audit_routing.rs`) calls the
//! upsert / list / delete helpers below.
//!
//! ## Resolution semantics
//!
//! The recorder owns three inputs:
//!
//! - `configured`: the gateway's `GATEWAY_EVIDENCE_OUTBOX_TARGETS`
//!   list (whatever the operator wired at boot). An exporter not
//!   in this list won't be enqueued regardless of routing rows —
//!   the table can't route to a sink the gateway doesn't know
//!   about.
//! - `routing`: `None` when zero rows exist for the event's tenant;
//!   `Some(vec)` when one-or-more rows exist, containing the
//!   enabled subset.
//!
//! Decision: `None` → fall back to `configured` (the
//! no-routing-rows default; preserves every existing
//! deployment). `Some(vec)`
//! → intersection with `configured`. `Some(empty)` (every row
//! disabled) → enqueue NOTHING for this tenant. The last case
//! is the operator's explicit per-tenant suppression switch:
//! flip every row to `enabled=false` to drop a tenant's
//! events without taking the gateway pipeline offline.

use serde_json::Value as JsonValue;
use time::OffsetDateTime;

/// One routing row, projected with the columns the admin
/// API serves and the recorder consumes.
#[derive(Debug, Clone)]
pub struct RoutingRow {
    pub tenant_id: String,
    pub exporter_name: String,
    pub enabled: bool,
    pub config: JsonValue,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for RoutingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            exporter_name: row.try_get("exporter_name")?,
            enabled: row.try_get("enabled")?,
            config: row.try_get("config")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Recorder-side lookup: return the routing decision for a
/// tenant. `None` distinguishes "no rows in the table for
/// this tenant" (fall back) from `Some(vec![])` ("rows
/// exist but all disabled"; enqueue nothing). See module
/// docstring.
///
/// The two cases would collide if we returned a plain
/// `Vec<String>` from the SELECT — they look identical
/// (zero enabled rows). Distinguishing them at the storage
/// boundary is the only place we have the information.
pub async fn fetch_tenant_routing<'e, E>(
    executor: E,
    tenant_id: &str,
) -> Result<Option<Vec<String>>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let rows: Vec<(String, bool)> = sqlx::query_as(
        r#"
        SELECT exporter_name, enabled
          FROM tenant_evidence_routing
         WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_all(executor)
    .await?;
    if rows.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            rows.into_iter()
                .filter(|(_, enabled)| *enabled)
                .map(|(name, _)| name)
                .collect(),
        ))
    }
}

/// Pure resolver: combine the gateway's configured targets
/// with the per-tenant routing decision. See module
/// docstring for the three cases.
///
/// `routing` is whatever [`fetch_tenant_routing`] returned;
/// the recorder hands it through unchanged so the storage
/// boundary owns the "no rows vs all-disabled" distinction.
pub fn resolve_outbox_targets(configured: &[String], routing: Option<&[String]>) -> Vec<String> {
    match routing {
        // No per-tenant routing rows — fall back to the
        // configured targets. Every existing deployment
        // lands here.
        None => configured.to_vec(),
        // Routing rows exist; keep only the (enabled, configured)
        // intersection. Order follows `configured` so the
        // recorder's enqueue order is stable across calls
        // (avoids spurious diffs in tests that inspect
        // enqueue ordering).
        Some(enabled_names) => configured
            .iter()
            .filter(|c| enabled_names.iter().any(|e| e == *c))
            .cloned()
            .collect(),
    }
}

/// Admin-side routing CRUD trait. Kept separate from
/// [`crate::AuditReader`] (which is the read view over
/// `audit_log`) so the admin state can wire routing
/// independently — operators can run the gateway with
/// audit reads enabled but no routing table writes, or
/// vice versa. The Postgres impl is [`PgRoutingStore`].
#[async_trait::async_trait]
pub trait RoutingStore: Send + Sync + 'static {
    async fn list(&self, tenant_id: Option<&str>) -> Result<Vec<RoutingRow>, sqlx::Error>;
    async fn upsert(
        &self,
        tenant_id: &str,
        exporter_name: &str,
        enabled: bool,
        config: &JsonValue,
    ) -> Result<RoutingRow, sqlx::Error>;
    /// Returns `true` when a row was actually removed (handlers
    /// map this to 204 vs 404).
    async fn delete(&self, tenant_id: &str, exporter_name: &str) -> Result<bool, sqlx::Error>;
}

/// Postgres-backed [`RoutingStore`]. Thin wrapper around the
/// free-function helpers in this module so production code
/// and tests share the same SQL.
pub struct PgRoutingStore {
    pool: sqlx::PgPool,
}

impl PgRoutingStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl RoutingStore for PgRoutingStore {
    async fn list(&self, tenant_id: Option<&str>) -> Result<Vec<RoutingRow>, sqlx::Error> {
        list_routing_rows(&self.pool, tenant_id).await
    }
    async fn upsert(
        &self,
        tenant_id: &str,
        exporter_name: &str,
        enabled: bool,
        config: &JsonValue,
    ) -> Result<RoutingRow, sqlx::Error> {
        upsert_routing_row(&self.pool, tenant_id, exporter_name, enabled, config).await
    }
    async fn delete(&self, tenant_id: &str, exporter_name: &str) -> Result<bool, sqlx::Error> {
        delete_routing_row(&self.pool, tenant_id, exporter_name).await
    }
}

/// Admin: list every routing row, optionally scoped to a
/// single tenant. Used by the admin UI's routing panel.
pub async fn list_routing_rows(
    pool: &sqlx::PgPool,
    tenant_id: Option<&str>,
) -> Result<Vec<RoutingRow>, sqlx::Error> {
    match tenant_id {
        Some(t) => {
            sqlx::query_as::<_, RoutingRow>(
                r#"
                SELECT tenant_id, exporter_name, enabled, config,
                       created_at, updated_at
                  FROM tenant_evidence_routing
                 WHERE tenant_id = $1
                 ORDER BY exporter_name ASC
                "#,
            )
            .bind(t)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, RoutingRow>(
                r#"
                SELECT tenant_id, exporter_name, enabled, config,
                       created_at, updated_at
                  FROM tenant_evidence_routing
                 ORDER BY tenant_id ASC, exporter_name ASC
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}

/// Admin: upsert a routing row by `(tenant_id, exporter_name)`
/// PK. `updated_at` is bumped automatically on every call;
/// `created_at` keeps the original value via the
/// `ON CONFLICT … DO UPDATE` clause that only writes the
/// mutable columns.
pub async fn upsert_routing_row(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    exporter_name: &str,
    enabled: bool,
    config: &JsonValue,
) -> Result<RoutingRow, sqlx::Error> {
    sqlx::query_as::<_, RoutingRow>(
        r#"
        INSERT INTO tenant_evidence_routing
            (tenant_id, exporter_name, enabled, config, updated_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (tenant_id, exporter_name) DO UPDATE
            SET enabled    = EXCLUDED.enabled,
                config     = EXCLUDED.config,
                updated_at = now()
        RETURNING tenant_id, exporter_name, enabled, config,
                  created_at, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(exporter_name)
    .bind(enabled)
    .bind(config)
    .fetch_one(pool)
    .await
}

/// Admin: delete a routing row. Returns `true` if a row was
/// removed (so the handler can map "no such row" to a 404).
pub async fn delete_routing_row(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    exporter_name: &str,
) -> Result<bool, sqlx::Error> {
    let rows_affected = sqlx::query(
        r#"
        DELETE FROM tenant_evidence_routing
         WHERE tenant_id = $1 AND exporter_name = $2
        "#,
    )
    .bind(tenant_id)
    .bind(exporter_name)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(rows_affected > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(s: &str) -> String {
        s.to_owned()
    }

    /// No routing rows for this tenant → recorder uses the
    /// gateway's configured targets verbatim. Every existing
    /// deployment lands on this branch.
    #[test]
    fn resolve_no_routing_falls_back_to_configured() {
        let configured = vec![s("ocsf"), s("webhook")];
        let out = resolve_outbox_targets(&configured, None);
        assert_eq!(out, vec![s("ocsf"), s("webhook")]);
    }

    /// Operator routes tenant ACME to OCSF only; the
    /// gateway's configured targets are [ocsf, webhook].
    /// Recorder must enqueue ONLY ocsf — webhook is in
    /// `configured` but not in routing.
    #[test]
    fn resolve_intersects_routing_with_configured() {
        let configured = vec![s("ocsf"), s("webhook")];
        let routed = vec![s("ocsf")];
        let out = resolve_outbox_targets(&configured, Some(&routed));
        assert_eq!(out, vec![s("ocsf")]);
    }

    /// Operator routing references an exporter the gateway
    /// doesn't have configured (typo, removed from env var,
    /// stale row). That target is dropped — the table can't
    /// route to a sink the gateway doesn't know about. The
    /// remaining routed targets still apply.
    #[test]
    fn resolve_drops_unknown_routed_exporters() {
        let configured = vec![s("ocsf")];
        let routed = vec![s("ocsf"), s("typo_target")];
        let out = resolve_outbox_targets(&configured, Some(&routed));
        assert_eq!(out, vec![s("ocsf")]);
    }

    /// Every routing row for this tenant is disabled, so
    /// `fetch_tenant_routing` returns `Some(vec![])`.
    /// Recorder must enqueue NOTHING — the operator
    /// explicitly turned off all exports for this tenant.
    /// This is the case that absolutely must NOT collapse
    /// to the `None` fallback (which would resurrect every
    /// configured target and silently overrule the
    /// suppression).
    #[test]
    fn resolve_all_disabled_yields_empty_targets() {
        let configured = vec![s("ocsf"), s("webhook")];
        let routed: Vec<String> = vec![];
        let out = resolve_outbox_targets(&configured, Some(&routed));
        assert!(
            out.is_empty(),
            "all-disabled must enqueue nothing; got {out:?}",
        );
    }

    /// Order: the resolver follows `configured` ordering so
    /// the recorder's enqueue order is stable. Tests that
    /// snapshot `evidence_outbox` rows by ordinal benefit
    /// from a deterministic order; this also keeps any
    /// downstream "first target wins" semantics
    /// reproducible.
    #[test]
    fn resolve_preserves_configured_order() {
        let configured = vec![s("a"), s("b"), s("c"), s("d")];
        let routed = vec![s("d"), s("a"), s("c")];
        let out = resolve_outbox_targets(&configured, Some(&routed));
        assert_eq!(out, vec![s("a"), s("c"), s("d")]);
    }
}
