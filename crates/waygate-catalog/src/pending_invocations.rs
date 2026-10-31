//! Durable references to denied direct calls. No arguments or executable work
//! are retained; callers retry through the ordinary invocation boundary.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::approval_binding_hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationSummary {
    pub description: Option<String>,
    pub affected_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NewInvocationRequest {
    pub tenant: String,
    pub principal_issuer: String,
    pub principal_sub: String,
    pub tool_id: Uuid,
    pub server: String,
    pub tool: String,
    pub behavior_hash: String,
    pub argument_hash: String,
    pub summary: InvocationSummary,
}

#[derive(Debug, Clone)]
pub struct InvocationRequest {
    pub id: Uuid,
    pub tenant: String,
    pub principal_issuer: String,
    pub principal_sub: String,
    pub tool_id: Uuid,
    pub server: String,
    pub tool: String,
    pub behavior_hash: String,
    pub argument_hash: String,
    pub summary: Option<InvocationSummary>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub status: String,
    pub grant_id: Option<Uuid>,
}

pub struct InvocationDecision<'a> {
    pub tenant: &'a str,
    pub id: Uuid,
    pub approver_issuer: &'a str,
    pub approver_sub: &'a str,
    pub reason: &'a str,
    pub approve: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("catalog database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid invocation review: {0}")]
    Invalid(&'static str),
    #[error("request changed, expired, or was already decided")]
    Changed,
    #[error("requester cannot approve their own invocation")]
    SelfApproval,
    #[error("pending invocation queue capacity reached")]
    Capacity,
}

pub type SharedPendingInvocationStore = Arc<dyn PendingInvocationStore>;

#[async_trait]
pub trait PendingInvocationStore: Send + Sync {
    async fn retain(&self, request: &NewInvocationRequest) -> Result<Uuid, RequestError>;
    async fn get(&self, tenant: &str, id: Uuid) -> Result<Option<InvocationRequest>, RequestError>;
    async fn pending(&self, tenant: &str) -> Result<Vec<InvocationRequest>, RequestError>;
    /// Decide once and, for approval, commit a single-use grant in the same
    /// transaction. A second decision cannot mint another usable grant.
    async fn decide(
        &self,
        decision: InvocationDecision<'_>,
    ) -> Result<InvocationRequest, RequestError>;
}

pub struct PgPendingInvocationStore {
    pool: PgPool,
}
impl PgPendingInvocationStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn from_row(row: sqlx::postgres::PgRow) -> Result<InvocationRequest, RequestError> {
    let summary: Option<serde_json::Value> = row.try_get("summary")?;
    Ok(InvocationRequest {
        id: row.try_get("id")?,
        tenant: row.try_get("tenant_id")?,
        principal_issuer: row.try_get("principal_issuer")?,
        principal_sub: row.try_get("principal_sub")?,
        tool_id: row.try_get("tool_id")?,
        server: row.try_get("server_name")?,
        tool: row.try_get("tool_name")?,
        behavior_hash: row.try_get("behavior_hash")?,
        argument_hash: row.try_get("argument_hash")?,
        summary: summary
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| RequestError::Invalid("stored summary is invalid"))?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        status: row.try_get("effective_status")?,
        grant_id: row.try_get("grant_id")?,
    })
}
macro_rules! request_columns {
    () => { "SELECT r.*,CASE WHEN r.status='pending' AND r.expires_at<=clock_timestamp() THEN 'expired' ELSE r.status END AS effective_status FROM pending_invocation_requests r" };
}

#[async_trait]
impl PendingInvocationStore for PgPendingInvocationStore {
    async fn retain(&self, request: &NewInvocationRequest) -> Result<Uuid, RequestError> {
        if [
            &request.principal_issuer,
            &request.principal_sub,
            &request.server,
            &request.tool,
            &request.behavior_hash,
            &request.argument_hash,
        ]
        .iter()
        .any(|value| value.is_empty() || value.len() > 4096)
        {
            return Err(RequestError::Invalid(
                "request identity is missing or too large",
            ));
        }
        // Preserve complete review context or explicitly mark it unavailable;
        // never turn a truncated description into an apparently complete review.
        let summary = serde_json::to_value(&request.summary)
            .map_err(|_| RequestError::Invalid("summary encoding failed"))?;
        let summary = (summary.to_string().len() <= 64 * 1024).then_some(summary);
        let mut tx = self.pool.begin().await?;
        let tenant =
            sqlx::query("SELECT id FROM tenants WHERE id=$1 AND status='active' FOR UPDATE")
                .bind(&request.tenant)
                .fetch_optional(&mut *tx)
                .await?;
        if tenant.is_none() {
            return Err(RequestError::Invalid("an active tenant is required"));
        }
        sqlx::query("DELETE FROM pending_invocation_requests WHERE tenant_id=$1 AND created_at<clock_timestamp()-INTERVAL '7 days'").bind(&request.tenant).execute(&mut *tx).await?;
        sqlx::query("UPDATE pending_invocation_requests SET status='expired' WHERE tenant_id=$1 AND status='pending' AND expires_at<=clock_timestamp()")
            .bind(&request.tenant).execute(&mut *tx).await?;
        if let Some(id)=sqlx::query_scalar("SELECT id FROM pending_invocation_requests WHERE tenant_id=$1 AND principal_issuer=$2 AND principal_sub=$3 AND tool_id=$4 AND behavior_hash=$5 AND argument_hash=$6 AND status='pending'")
            .bind(&request.tenant).bind(&request.principal_issuer).bind(&request.principal_sub).bind(request.tool_id).bind(&request.behavior_hash).bind(&request.argument_hash).fetch_optional(&mut *tx).await? {
            tx.commit().await?;
            return Ok(id);
        }
        let (total,pending,owned):(i64,i64,i64)=sqlx::query_as("SELECT count(*),count(*) FILTER(WHERE status='pending'),count(*) FILTER(WHERE status='pending' AND principal_issuer=$2 AND principal_sub=$3) FROM pending_invocation_requests WHERE tenant_id=$1")
            .bind(&request.tenant).bind(&request.principal_issuer).bind(&request.principal_sub).fetch_one(&mut *tx).await?;
        if total >= 10000 || pending >= 1000 || owned >= 100 {
            return Err(RequestError::Capacity);
        }
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO pending_invocation_requests(tenant_id,id,principal_issuer,principal_sub,tool_id,server_name,tool_name,behavior_hash,argument_hash,summary) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&request.tenant).bind(id).bind(&request.principal_issuer).bind(&request.principal_sub).bind(request.tool_id).bind(&request.server).bind(&request.tool).bind(&request.behavior_hash).bind(&request.argument_hash).bind(summary).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
    async fn get(&self, tenant: &str, id: Uuid) -> Result<Option<InvocationRequest>, RequestError> {
        sqlx::query(concat!(request_columns!()," WHERE r.tenant_id=$1 AND r.id=$2 AND r.created_at>=clock_timestamp()-INTERVAL '7 days'"))
            .bind(tenant).bind(id).fetch_optional(&self.pool).await?.map(from_row).transpose()
    }
    async fn pending(&self, tenant: &str) -> Result<Vec<InvocationRequest>, RequestError> {
        sqlx::query(concat!(request_columns!()," WHERE r.tenant_id=$1 AND r.status='pending' AND r.expires_at>clock_timestamp() ORDER BY r.created_at,r.id LIMIT 50"))
            .bind(tenant).fetch_all(&self.pool).await?.into_iter().map(from_row).collect()
    }
    async fn decide(
        &self,
        decision: InvocationDecision<'_>,
    ) -> Result<InvocationRequest, RequestError> {
        if decision.approver_issuer.is_empty()
            || decision.approver_sub.is_empty()
            || decision.reason.trim().is_empty()
            || decision.reason.len() > 4096
        {
            return Err(RequestError::Invalid(
                "an administrator identity and reason of at most 4096 bytes are required",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query(concat!(request_columns!()," WHERE r.tenant_id=$1 AND r.id=$2 AND r.status='pending' AND r.expires_at>clock_timestamp() FOR UPDATE OF r"))
            .bind(decision.tenant).bind(decision.id).fetch_optional(&mut *tx).await?.ok_or(RequestError::Changed)?;
        let request = from_row(row)?;
        let grant_id = if decision.approve {
            if request.principal_issuer == decision.approver_issuer
                && request.principal_sub == decision.approver_sub
            {
                return Err(RequestError::SelfApproval);
            }
            if request.summary.is_none() {
                return Err(RequestError::Invalid(
                    "complete review context is unavailable; use individual request evidence",
                ));
            }
            let binding = approval_binding_hash(&request.behavior_hash, &request.argument_hash);
            let id = Uuid::now_v7();
            // The allocation checks the current visible catalog identity at
            // the write. Dispatch independently checks and consumes this exact
            // behavior-and-arguments grant before performing any tool effect.
            let inserted=sqlx::query("INSERT INTO approval_grants(id,tenant_id,principal_sub,principal_issuer,server_id,tool_id,argument_hash,expires_at,approver,reason)
                SELECT $1,$2,$3,$4,t.server_id,t.id,$5,LEAST($6,clock_timestamp()+INTERVAL '5 minutes'),$7,$8
                FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id
                WHERE t.id=$9 AND t.name=$10 AND s.name=$11 AND s.status='live'
                AND (s.visibility='global' OR s.tenant_id=$2)
                AND (SELECT v.schema_hash FROM mcp_tool_versions v WHERE v.tool_id=t.id AND v.approved_at IS NOT NULL ORDER BY v.approved_at DESC LIMIT 1)=$12")
                .bind(id).bind(decision.tenant).bind(&request.principal_sub).bind(&request.principal_issuer).bind(binding).bind(request.expires_at)
                .bind(decision.approver_sub).bind(decision.reason).bind(request.tool_id).bind(&request.tool).bind(&request.server).bind(&request.behavior_hash).execute(&mut *tx).await?;
            if inserted.rows_affected() != 1 {
                return Err(RequestError::Changed);
            }
            Some(id)
        } else {
            None
        };
        let row=sqlx::query("UPDATE pending_invocation_requests SET status=$3,decided_at=clock_timestamp(),decided_by_issuer=$4,decided_by_sub=$5,reason=$6,grant_id=$7
            WHERE tenant_id=$1 AND id=$2 AND status='pending' AND expires_at>clock_timestamp() RETURNING *,status AS effective_status")
            .bind(decision.tenant).bind(decision.id).bind(if decision.approve {"approved"} else {"denied"}).bind(decision.approver_issuer).bind(decision.approver_sub).bind(decision.reason).bind(grant_id)
            .fetch_optional(&mut *tx).await?.ok_or(RequestError::Changed)?;
        let result = from_row(row)?;
        tx.commit().await?;
        Ok(result)
    }
}
