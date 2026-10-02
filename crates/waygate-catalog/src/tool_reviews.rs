//! Durable review of an upstream tool's observed contract. One current
//! candidate and one accepted baseline are retained per catalog tool.

pub use crate::PgCatalogStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

pub use crate::CatalogError as ReviewError;
use ReviewError as CatalogError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolReview {
    pub tool_id: Uuid,
    pub tenant_id: String,
    pub server: String,
    pub tool: String,
    pub approved_hash: String,
    pub approved_contract: Value,
    pub observed_hash: String,
    /// JSON null means the observed contract exceeds the comparison storage limit.
    pub observed_contract: Value,
    pub generation: i64,
    pub quarantined: bool,
    pub observed_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
}

impl PgCatalogStore {
    /// Admission reads only the decision, never the stored comparison payloads.
    pub async fn review_state(
        &self,
        tenant: &str,
        server: &str,
        tool: &str,
    ) -> Result<Option<(String, bool)>, CatalogError> {
        Ok(sqlx::query_as("SELECT r.observed_hash,r.quarantined FROM tool_contract_reviews r JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id WHERE s.tenant_id=$1 AND s.name=$2 AND t.name=$3")
            .bind(tenant).bind(server).bind(tool).fetch_optional(&self.pool).await?)
    }
    /// Read only admission decisions for a bounded discovery batch. Missing
    /// names have no recorded observation; comparison payloads stay in storage.
    pub async fn review_states(
        &self,
        tenant: &str,
        server: &str,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, (String, bool)>, CatalogError> {
        if names.len() > crate::TOOL_RESOLUTION_BATCH_SIZE {
            return Err(CatalogError::InvalidInput(
                "tool review batch exceeds 256 names".into(),
            ));
        }
        if names.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT t.name,r.observed_hash,r.quarantined FROM tool_contract_reviews r
             JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id
             WHERE s.tenant_id=$1 AND s.name=$2 AND t.name=ANY($3)",
        )
        .bind(tenant)
        .bind(server)
        .bind(names)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(name, hash, quarantined)| (name, (hash, quarantined)))
            .collect())
    }

    pub async fn quarantined_names(
        &self,
        tenant: &str,
        server: &str,
    ) -> Result<Vec<String>, CatalogError> {
        Ok(sqlx::query_scalar("SELECT t.name FROM tool_contract_reviews r JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id WHERE s.tenant_id=$1 AND s.name=$2 AND r.quarantined ORDER BY t.name")
            .bind(tenant).bind(server).fetch_all(&self.pool).await?)
    }
    pub async fn pending(&self, tenant: &str) -> Result<Vec<ToolReview>, CatalogError> {
        self.pending_page(tenant, 50, 0).await
    }

    pub async fn pending_page(
        &self,
        tenant: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ToolReview>, CatalogError> {
        let rows = sqlx::query(
            "SELECT r.*,s.tenant_id,s.name AS server,t.name AS tool FROM tool_contract_reviews r
             JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id
             WHERE s.tenant_id=$1 AND r.quarantined AND r.decided_at IS NULL
             ORDER BY r.observed_at DESC,r.tool_id LIMIT $2 OFFSET $3",
        )
        .bind(tenant)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(review_from_row).collect())
    }

    pub async fn pending_after(
        &self,
        tenant: &str,
        after: Option<(&str, &str)>,
    ) -> Result<Vec<ToolReview>, CatalogError> {
        self.blocked_after(tenant, after, false).await
    }
    /// Browse retained refusal decisions as well as pending candidates.
    pub async fn blocked_after(
        &self,
        tenant: &str,
        after: Option<(&str, &str)>,
        include_decided: bool,
    ) -> Result<Vec<ToolReview>, CatalogError> {
        let rows = sqlx::query(
            "SELECT r.*,s.tenant_id,s.name AS server,t.name AS tool FROM tool_contract_reviews r
             JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id
             WHERE s.tenant_id=$1 AND r.quarantined AND ($4 OR r.decided_at IS NULL)
             AND ($2::text IS NULL OR (s.name,t.name) > ($2,$3))
             ORDER BY s.name,t.name LIMIT 50",
        )
        .bind(tenant)
        .bind(after.map(|pair| pair.0))
        .bind(after.map(|pair| pair.1))
        .bind(include_decided)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(review_from_row).collect())
    }

    /// Count pending decisions without loading contract bodies or imposing a page cap.
    pub async fn pending_count(
        &self,
        tenant: &str,
        server: Option<&str>,
    ) -> Result<i64, CatalogError> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM tool_contract_reviews r
            JOIN mcp_tools t ON t.id=r.tool_id JOIN mcp_servers s ON s.id=t.server_id
            WHERE s.tenant_id=$1 AND ($2::text IS NULL OR s.name=$2)
            AND r.quarantined AND r.decided_at IS NULL",
        )
        .bind(tenant)
        .bind(server)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Observe a bounded contract before publishing its session. The row lock
    /// serializes observations and decisions. A later change retains the last
    /// accepted baseline while replacing only the candidate; repeated listings
    /// cannot clear quarantine. First observation seeds the baseline.
    pub async fn observe(
        &self,
        tenant: &str,
        server: &str,
        tool: &str,
        hash: &str,
        contract: &Value,
        block_changes: bool,
    ) -> Result<bool, CatalogError> {
        self.observe_against_approval(tenant, server, tool, hash, contract, block_changes, None)
            .await
    }

    /// Annotation admission seeds the approval for a first observation. Later
    /// observations use durable catalog activation and exact review decisions;
    /// a live session's manifest can lag either source of accepted changes.
    /// A mismatched observation is a candidate, never an accepted baseline.
    /// Missing historical content is kept as null rather than reconstructed.
    #[allow(clippy::too_many_arguments)]
    pub async fn observe_against_approval(
        &self,
        tenant: &str,
        server: &str,
        tool: &str,
        hash: &str,
        contract: &Value,
        block_changes: bool,
        approved_hash: Option<&str>,
    ) -> Result<bool, CatalogError> {
        let mut tx = self.pool.begin().await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT t.id FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id
             WHERE s.tenant_id=$1 AND s.name=$2 AND t.name=$3 FOR UPDATE OF t",
        )
        .bind(tenant)
        .bind(server)
        .bind(tool)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(id) = id else {
            // Newly configured tools are not authoritative until catalog
            // reconciliation creates their identity. Admission refuses absence.
            return Ok(false);
        };
        let previous = sqlx::query(
            "SELECT observed_hash, approved_hash, quarantined FROM tool_contract_reviews WHERE tool_id=$1 FOR UPDATE",
        ).bind(id).fetch_optional(&mut *tx).await?;
        // Catalog activation records deliberate manifest changes, including
        // rollback. Exact review approvals remain durable when a new observed
        // candidate clears its decision marker. Read both after taking the row
        // locks shared with import and review writes, so session lag cannot
        // replace a newer acceptance or erase its retained comparison.
        let durable_approval = if approved_hash.is_some() {
            sqlx::query_scalar::<_, String>(
                "SELECT approval_hash FROM (
                    (SELECT schema_hash AS approval_hash, approved_at AS accepted_at, 0 AS priority
                     FROM mcp_tool_versions WHERE tool_id=$1 AND approved_at IS NOT NULL
                     ORDER BY approved_at DESC LIMIT 1)
                    UNION ALL
                    (SELECT subject_version_hash AS approval_hash, created_at AS accepted_at, 1 AS priority
                     FROM catalog_approvals WHERE tenant_id=$2 AND subject_type='tool_version'
                     AND subject_id=$1 AND action='approved' AND reason='Accepted observed tool contract'
                     ORDER BY created_at DESC, id DESC LIMIT 1)
                 ) approvals ORDER BY accepted_at DESC, priority DESC LIMIT 1",
            ).bind(id).bind(tenant).fetch_optional(&mut *tx).await?
        } else {
            None
        };
        let approved_hash = durable_approval.as_deref().or(approved_hash);
        // Use PostgreSQL's representation so the bound matches the table's
        // constraint, including JSONB whitespace. Retain identity and refusal
        // even when the comparison itself cannot be stored.
        let contract: Value = sqlx::query_scalar(
            "SELECT CASE WHEN octet_length($1::jsonb::text) <= 262144
             THEN $1::jsonb ELSE 'null'::jsonb END",
        )
        .bind(contract)
        .fetch_one(&mut *tx)
        .await?;
        let unavailable = contract.is_null();
        // A missing optional comparison cannot override an exact annotation approval.
        let storage_requires_review = unavailable && approved_hash.is_none();
        let approval_mismatch = approved_hash.is_some_and(|approved| approved != hash);
        let baseline_hash = approved_hash.unwrap_or(hash);
        let baseline = if approval_mismatch {
            Value::Null
        } else {
            contract.clone()
        };
        sqlx::query(
            "INSERT INTO tool_contract_reviews
             (tool_id, approved_hash, approved_contract, observed_hash, observed_contract, quarantined)
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tool_id) DO NOTHING",
        )
        .bind(id)
        .bind(baseline_hash)
        .bind(&baseline)
        .bind(hash)
        .bind(&contract)
        .bind(storage_requires_review || approval_mismatch)
        .execute(&mut *tx)
        .await?;
        let previous = match previous {
            Some(previous) => previous,
            None => sqlx::query(
                "SELECT observed_hash, approved_hash, quarantined FROM tool_contract_reviews WHERE tool_id=$1 FOR UPDATE",
            ).bind(id).fetch_one(&mut *tx).await?,
        };
        let old: String = previous.get("observed_hash");
        let repair_baseline = approval_mismatch
            && (previous.get::<String, _>("approved_hash") != baseline_hash
                || !previous.get::<bool, _>("quarantined"));
        if repair_baseline {
            sqlx::query("UPDATE tool_contract_reviews SET
                approved_contract=CASE WHEN approved_hash=$2 THEN approved_contract ELSE 'null'::jsonb END,
                approved_hash=$2,quarantined=true,generation=generation+1,
                decided_at=NULL,decided_by=NULL,observed_at=now() WHERE tool_id=$1")
                .bind(id).bind(baseline_hash).execute(&mut *tx).await?;
        }
        if old != hash {
            let blocked = previous.get::<bool, _>("quarantined")
                || block_changes
                || storage_requires_review
                || approval_mismatch;
            sqlx::query(
                "UPDATE tool_contract_reviews SET observed_hash=$2, observed_contract=$3,
                 approved_hash=CASE WHEN $4 THEN approved_hash ELSE $2 END,
                 approved_contract=CASE WHEN $4 THEN approved_contract ELSE $3 END,
                 quarantined=$4, generation=generation+1, observed_at=now(),
                 decided_at=NULL, decided_by=NULL WHERE tool_id=$1",
            )
            .bind(id)
            .bind(hash)
            .bind(contract)
            .bind(blocked)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO catalog_drift_events
                 (id,tenant_id,tool_id,observed_hash,approved_hash,severity)
                 SELECT $1,$2,tool_id,observed_hash,approved_hash,$3
                 FROM tool_contract_reviews WHERE tool_id=$4",
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(if blocked { "critical" } else { "info" })
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(old != hash || repair_baseline)
    }

    pub async fn get(
        &self,
        tenant: &str,
        server: &str,
        tool: &str,
    ) -> Result<Option<ToolReview>, CatalogError> {
        let row = sqlx::query(
            "SELECT r.*,s.tenant_id,s.name AS server,t.name AS tool
             FROM tool_contract_reviews r JOIN mcp_tools t ON t.id=r.tool_id
             JOIN mcp_servers s ON s.id=t.server_id
             WHERE s.tenant_id=$1 AND s.name=$2 AND t.name=$3",
        )
        .bind(tenant)
        .bind(server)
        .bind(tool)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(review_from_row))
    }

    /// Acknowledge the exact candidate while retaining its refusal state.
    /// A later observation reopens review; a stale form cannot revoke approval.
    pub async fn reject(&self, review: &ToolReview, actor: &str) -> Result<bool, CatalogError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE tool_contract_reviews r SET decided_at=now(),decided_by=$4
            FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id
            WHERE r.tool_id=t.id AND r.tool_id=$1 AND r.generation=$2
            AND r.observed_hash=$3 AND s.tenant_id=$5 AND r.quarantined AND r.decided_at IS NULL",
        )
        .bind(review.tool_id)
        .bind(review.generation)
        .bind(&review.observed_hash)
        .bind(actor)
        .bind(&review.tenant_id)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            sqlx::query("INSERT INTO catalog_approvals
                (id,tenant_id,subject_type,subject_id,subject_version_hash,action,actor,reason)
                VALUES ($1,$2,'tool_version',$3,$4,'rejected',$5,'Kept observed tool contract blocked')")
                .bind(Uuid::new_v4()).bind(&review.tenant_id).bind(review.tool_id)
                .bind(&review.observed_hash).bind(actor).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    /// Accept only the candidate the operator saw. The generation prevents an
    /// A → B → A change from reviving an old form. An already accepted identical
    /// submission is harmless.
    pub async fn approve(&self, review: &ToolReview, actor: &str) -> Result<bool, CatalogError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE tool_contract_reviews r SET approved_hash=observed_hash,
             approved_contract=observed_contract,quarantined=false,decided_at=now(),decided_by=$4
             FROM mcp_tools t JOIN mcp_servers s ON s.id=t.server_id
             WHERE r.tool_id=t.id AND r.tool_id=$1 AND r.generation=$2
             AND r.observed_hash=$3 AND s.tenant_id=$5
             AND r.observed_contract <> 'null'::jsonb",
        )
        .bind(review.tool_id)
        .bind(review.generation)
        .bind(&review.observed_hash)
        .bind(actor)
        .bind(&review.tenant_id)
        .execute(&mut *tx)
        .await?;
        let changed = result.rows_affected() == 1;
        if changed {
            sqlx::query("INSERT INTO catalog_approvals
                (id,tenant_id,subject_type,subject_id,subject_version_hash,action,actor,reason,created_at)
                VALUES ($1,$2,'tool_version',$3,$4,'approved',$5,'Accepted observed tool contract',clock_timestamp())")
                .bind(Uuid::new_v4()).bind(&review.tenant_id).bind(review.tool_id)
                .bind(&review.observed_hash).bind(actor).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(changed)
    }
}

fn review_from_row(r: sqlx::postgres::PgRow) -> ToolReview {
    ToolReview {
        tool_id: r.get("tool_id"),
        tenant_id: r.get("tenant_id"),
        server: r.get("server"),
        tool: r.get("tool"),
        approved_hash: r.get("approved_hash"),
        approved_contract: r.get("approved_contract"),
        observed_hash: r.get("observed_hash"),
        observed_contract: r.get("observed_contract"),
        generation: r.get("generation"),
        quarantined: r.get("quarantined"),
        observed_at: r.get("observed_at"),
        decided_at: r.get("decided_at"),
    }
}
