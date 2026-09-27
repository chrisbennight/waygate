//! Durable, immutable routing records; upstream execution state is never stored here.

use super::{TaskRoute, TaskRouteStore};
use sqlx::{types::Json, PgPool};
use uuid::Uuid;
use waygate_core::store::StoreError;

pub struct PgTaskRouteStore {
    pool: PgPool,
}

impl PgTaskRouteStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Remove a bounded batch of expired mappings without touching upstream work.
    pub async fn sweep_expired(&self) -> Result<u64, StoreError> {
        Ok(sqlx::query(
            "DELETE FROM upstream_task_routes WHERE id IN (
                SELECT id FROM upstream_task_routes
                WHERE expires_at <= floor(extract(epoch FROM now()))::bigint
                ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
            )",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
}

#[async_trait::async_trait]
impl TaskRouteStore for PgTaskRouteStore {
    async fn insert(&self, id: Uuid, route: &TaskRoute) -> Result<(), StoreError> {
        // No upsert: neither retries nor collisions may overwrite an admitted association.
        sqlx::query(
            "INSERT INTO upstream_task_routes (id, tenant_id, expires_at, route)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(&route.tenant)
        .bind(route.exp)
        .bind(Json(route))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid, tenant: &str) -> Result<Option<TaskRoute>, StoreError> {
        Ok(sqlx::query_scalar::<_, Json<TaskRoute>>(
            "SELECT route FROM upstream_task_routes
             WHERE id = $1 AND tenant_id = $2
               AND expires_at > floor(extract(epoch FROM now()))::bigint",
        )
        .bind(id)
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await?
        .map(|route| route.0))
    }
}
