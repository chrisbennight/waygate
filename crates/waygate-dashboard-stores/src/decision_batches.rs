//! Administrator-scoped receipts for bounded dashboard decisions.
//!
//! A durable claim prevents submission replay. Item progress distinguishes
//! unstarted work from an interrupted effect whose outcome needs reconciliation.
//! This store never executes decisions or takes over domain authorization.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

pub const MAX_ITEMS: usize = 50;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESULT_BYTES: usize = 2048;
const MAX_RECEIPTS_PER_OWNER: i64 = 100;

/// Identity comes from the authenticated administrator, never submitted fields.
#[derive(Clone, Copy)]
pub struct BatchOwner<'a> {
    pub tenant: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
}

/// Only bounded decision references and reviewed versions belong in `items`.
/// The administrator service owns and validates the domain-specific shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub kind: String,
    pub action: String,
    pub items: Vec<Value>,
}

impl BatchRequest {
    pub fn validate(&self) -> Result<(), BatchError> {
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || matches!(c, b'_' | b'-'))
        };
        if !identifier(&self.kind) || !identifier(&self.action) {
            return Err(BatchError::Invalid("Unsupported decision identifier"));
        }
        if self.items.is_empty() || self.items.len() > MAX_ITEMS {
            return Err(BatchError::Invalid(
                "Select between one and fifty decisions",
            ));
        }
        if self.items.iter().any(|item| !item.is_object()) {
            return Err(BatchError::Invalid("Decision references must be objects"));
        }
        if self
            .items
            .iter()
            .enumerate()
            .any(|(index, item)| self.items[..index].contains(item))
        {
            return Err(BatchError::Invalid("Select each decision only once"));
        }
        if serde_json::to_vec(self)?.len() > MAX_REQUEST_BYTES {
            return Err(BatchError::Invalid(
                "The selection exceeds the receipt size limit",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemProgress {
    pub item_index: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    pub result: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct DecisionBatch {
    pub id: Uuid,
    pub request: BatchRequest,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub started_at: Option<OffsetDateTime>,
    pub items: Vec<ItemProgress>,
}

#[derive(Debug)]
pub struct BatchSummary {
    pub id: Uuid,
    pub kind: String,
    pub action: String,
    pub created_at: OffsetDateTime,
    pub item_count: i64,
    pub completed_count: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("postgres: {0}")]
    Store(#[from] sqlx::Error),
    #[error("receipt encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("The submission identity already belongs to another selection")]
    Conflict,
    #[error("The administrator has too many retained submissions")]
    Capacity,
}

pub type SharedDecisionBatchStore = Arc<dyn DecisionBatchStore>;

#[async_trait]
pub trait DecisionBatchStore: Send + Sync {
    /// All retained receipts for this owner fit within the capture quota.
    async fn recent(&self, owner: BatchOwner<'_>) -> Result<Vec<BatchSummary>, BatchError>;
    /// Capture a reviewed selection before confirmation. An identical capture
    /// is idempotent; a retained identifier cannot be reused for another owner or intent.
    async fn prepare(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        request: &BatchRequest,
    ) -> Result<DecisionBatch, BatchError>;

    async fn get(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
    ) -> Result<Option<DecisionBatch>, BatchError>;

    /// Exactly one caller can execute a captured submission. A crashed claim
    /// is never automatically reclaimed: its effects must first be reconciled.
    async fn claim(&self, owner: BatchOwner<'_>, id: Uuid) -> Result<bool, BatchError>;

    async fn begin_item(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        item_index: i32,
    ) -> Result<bool, BatchError>;

    /// Record an observed result once. Callers supply a bounded, value-free
    /// outcome object, not raw invocation inputs or upstream diagnostics.
    async fn complete_item(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        item_index: i32,
        result: &Value,
    ) -> Result<bool, BatchError>;
}

pub struct PgDecisionBatchStore {
    pool: PgPool,
}

impl PgDecisionBatchStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn receipt(row: sqlx::postgres::PgRow) -> Result<DecisionBatch, BatchError> {
    Ok(DecisionBatch {
        id: row.try_get("id")?,
        request: serde_json::from_value(row.try_get("request")?)?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        started_at: row.try_get("started_at")?,
        items: serde_json::from_value(row.try_get("progress")?)?,
    })
}

const SELECT_RECEIPT: &str = "SELECT b.id,b.request,b.created_at,b.expires_at,b.started_at,
    (SELECT jsonb_agg(jsonb_build_object(
        'item_index',i.item_index,'started_at',i.started_at,'result',i.result)
        ORDER BY i.item_index)
     FROM admin_decision_batch_items i WHERE i.tenant_id=b.tenant_id AND i.batch_id=b.id)
    AS progress
    FROM admin_decision_batches b
    WHERE b.tenant_id=$1 AND b.id=$2 AND b.actor_issuer=$3 AND b.actor_sub=$4
    AND b.expires_at>clock_timestamp()";

#[async_trait]
impl DecisionBatchStore for PgDecisionBatchStore {
    async fn recent(&self, owner: BatchOwner<'_>) -> Result<Vec<BatchSummary>, BatchError> {
        let rows=sqlx::query("SELECT b.id,b.request->>'kind' AS kind,b.request->>'action' AS action,b.created_at,
            (SELECT count(*) FROM admin_decision_batch_items i WHERE i.tenant_id=b.tenant_id AND i.batch_id=b.id) AS item_count,
            (SELECT count(*) FROM admin_decision_batch_items i WHERE i.tenant_id=b.tenant_id AND i.batch_id=b.id AND i.result IS NOT NULL) AS completed_count
            FROM admin_decision_batches b WHERE b.tenant_id=$1 AND b.actor_issuer=$2 AND b.actor_sub=$3
            AND b.expires_at>clock_timestamp() ORDER BY b.created_at DESC LIMIT 100")
            .bind(owner.tenant).bind(owner.issuer).bind(owner.subject).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(BatchSummary {
                    id: row.try_get("id")?,
                    kind: row.try_get("kind")?,
                    action: row.try_get("action")?,
                    created_at: row.try_get("created_at")?,
                    item_count: row.try_get("item_count")?,
                    completed_count: row.try_get("completed_count")?,
                })
            })
            .collect()
    }
    async fn prepare(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        request: &BatchRequest,
    ) -> Result<DecisionBatch, BatchError> {
        request.validate()?;
        if owner.issuer.is_empty() || owner.subject.is_empty() {
            return Err(BatchError::Invalid("An administrator identity is required"));
        }
        let mut tx = self.pool.begin().await?;
        // The tenant lock bounds concurrent captures and retention cleanup.
        // It is held only for local store work, never while executing decisions.
        if sqlx::query("SELECT id FROM tenants WHERE id=$1 AND status='active' FOR UPDATE")
            .bind(owner.tenant)
            .fetch_optional(&mut *tx)
            .await?
            .is_none()
        {
            return Err(BatchError::Invalid("An active tenant is required"));
        }
        sqlx::query("DELETE FROM admin_decision_batches WHERE tenant_id=$1 AND expires_at<=clock_timestamp()")
            .bind(owner.tenant).execute(&mut *tx).await?;
        let existing = sqlx::query(
            "SELECT actor_issuer,actor_sub,request FROM admin_decision_batches WHERE tenant_id=$1 AND id=$2",
        ).bind(owner.tenant).bind(id).fetch_optional(&mut *tx).await?;
        let request_value = serde_json::to_value(request)?;
        if let Some(row) = existing {
            if row.try_get::<String, _>("actor_issuer")? != owner.issuer
                || row.try_get::<String, _>("actor_sub")? != owner.subject
                || row.try_get::<Value, _>("request")? != request_value
            {
                return Err(BatchError::Conflict);
            }
        } else {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM admin_decision_batches WHERE tenant_id=$1 AND actor_issuer=$2 AND actor_sub=$3",
            ).bind(owner.tenant).bind(owner.issuer).bind(owner.subject).fetch_one(&mut *tx).await?;
            if count >= MAX_RECEIPTS_PER_OWNER {
                return Err(BatchError::Capacity);
            }
            sqlx::query("INSERT INTO admin_decision_batches (tenant_id,id,actor_issuer,actor_sub,request) VALUES ($1,$2,$3,$4,$5)")
                .bind(owner.tenant).bind(id).bind(owner.issuer).bind(owner.subject).bind(request_value)
                .execute(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO admin_decision_batch_items (tenant_id,batch_id,item_index)
                SELECT $1,$2,generate_series(0,$3)",
            )
            .bind(owner.tenant)
            .bind(id)
            .bind(request.items.len() as i32 - 1)
            .execute(&mut *tx)
            .await?;
        }
        let row = sqlx::query(SELECT_RECEIPT)
            .bind(owner.tenant)
            .bind(id)
            .bind(owner.issuer)
            .bind(owner.subject)
            .fetch_one(&mut *tx)
            .await?;
        let batch = receipt(row)?;
        tx.commit().await?;
        Ok(batch)
    }

    async fn get(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
    ) -> Result<Option<DecisionBatch>, BatchError> {
        sqlx::query(SELECT_RECEIPT)
            .bind(owner.tenant)
            .bind(id)
            .bind(owner.issuer)
            .bind(owner.subject)
            .fetch_optional(&self.pool)
            .await?
            .map(receipt)
            .transpose()
    }

    async fn claim(&self, owner: BatchOwner<'_>, id: Uuid) -> Result<bool, BatchError> {
        Ok(sqlx::query(
            "UPDATE admin_decision_batches SET started_at=clock_timestamp()
            WHERE tenant_id=$1 AND id=$2 AND actor_issuer=$3 AND actor_sub=$4
            AND started_at IS NULL AND expires_at>clock_timestamp()",
        )
        .bind(owner.tenant)
        .bind(id)
        .bind(owner.issuer)
        .bind(owner.subject)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }

    async fn begin_item(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        item_index: i32,
    ) -> Result<bool, BatchError> {
        Ok(sqlx::query(
            "UPDATE admin_decision_batch_items i SET started_at=clock_timestamp()
            FROM admin_decision_batches b WHERE i.tenant_id=b.tenant_id AND i.batch_id=b.id
            AND b.tenant_id=$1 AND b.id=$2 AND b.actor_issuer=$3 AND b.actor_sub=$4
            AND b.started_at IS NOT NULL AND b.expires_at>clock_timestamp()
            AND i.item_index=$5 AND i.started_at IS NULL",
        )
        .bind(owner.tenant)
        .bind(id)
        .bind(owner.issuer)
        .bind(owner.subject)
        .bind(item_index)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }

    async fn complete_item(
        &self,
        owner: BatchOwner<'_>,
        id: Uuid,
        item_index: i32,
        result: &Value,
    ) -> Result<bool, BatchError> {
        if !result.is_object() || serde_json::to_vec(result)?.len() > MAX_RESULT_BYTES {
            return Err(BatchError::Invalid(
                "The decision result must be a bounded outcome object",
            ));
        }
        Ok(sqlx::query(
            "UPDATE admin_decision_batch_items i SET result=$6
            FROM admin_decision_batches b WHERE i.tenant_id=b.tenant_id AND i.batch_id=b.id
            AND b.tenant_id=$1 AND b.id=$2 AND b.actor_issuer=$3 AND b.actor_sub=$4
            AND i.item_index=$5 AND i.started_at IS NOT NULL AND i.result IS NULL",
        )
        .bind(owner.tenant)
        .bind(id)
        .bind(owner.issuer)
        .bind(owner.subject)
        .bind(item_index)
        .bind(result)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }
}
