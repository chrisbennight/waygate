use super::{FileStorageError, GatewayFileOwner, GatewayFileStorage};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct NewFileDelivery<'a> {
    pub id: Uuid,
    pub owner: &'a GatewayFileOwner,
    pub file_id: Uuid,
    pub invocation_id: &'a str,
    pub server: &'a str,
    pub tool: &'a str,
    pub source_server: &'a str,
    pub source_tool: &'a str,
    pub upstream_uri: &'a str,
    pub lifecycle_supported: bool,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct GatewayFileDelivery {
    pub id: Uuid,
    pub file_id: Uuid,
    pub server: String,
    pub tool: String,
    pub source_server: String,
    pub source_tool: String,
    pub upstream_uri: String,
    pub lifecycle_supported: bool,
    pub stage: String,
}

fn decode(row: sqlx::postgres::PgRow) -> Result<GatewayFileDelivery, sqlx::Error> {
    Ok(GatewayFileDelivery {
        id: row.try_get("id")?,
        file_id: row.try_get("file_id")?,
        server: row.try_get("upstream_server")?,
        tool: row.try_get("upstream_tool")?,
        source_server: row.try_get("source_server")?,
        source_tool: row.try_get("source_tool")?,
        upstream_uri: row.try_get("upstream_uri")?,
        lifecycle_supported: row.try_get("lifecycle_supported")?,
        stage: row.try_get("stage")?,
    })
}

impl GatewayFileStorage {
    pub async fn record_delivery(&self, new: NewFileDelivery<'_>) -> Result<(), FileStorageError> {
        sqlx::query("INSERT INTO gateway_file_deliveries (id,tenant_id,principal_sub,principal_issuer,file_id,invocation_id,upstream_server,upstream_tool,source_server,source_tool,upstream_uri,lifecycle_supported,stage,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'prepared',$13)")
            .bind(new.id).bind(new.owner.tenant_id.as_str()).bind(&new.owner.principal_sub).bind(&new.owner.principal_issuer)
            .bind(new.file_id).bind(new.invocation_id).bind(new.server).bind(new.tool).bind(new.source_server).bind(new.source_tool)
            .bind(new.upstream_uri).bind(new.lifecycle_supported).bind(new.expires_at).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn owned_delivery(
        &self,
        owner: &GatewayFileOwner,
        id: Uuid,
    ) -> Result<Option<GatewayFileDelivery>, FileStorageError> {
        let row = sqlx::query("SELECT * FROM gateway_file_deliveries WHERE id=$1 AND tenant_id=$2 AND principal_sub=$3 AND principal_issuer=$4 AND expires_at>now()")
            .bind(id).bind(owner.tenant_id.as_str()).bind(&owner.principal_sub).bind(&owner.principal_issuer).fetch_optional(&self.pool).await?;
        Ok(row.map(decode).transpose()?)
    }

    pub async fn deliveries_for_file(
        &self,
        owner: &GatewayFileOwner,
        file: Uuid,
        cursor: Option<Uuid>,
    ) -> Result<Vec<GatewayFileDelivery>, FileStorageError> {
        let rows = sqlx::query("SELECT * FROM gateway_file_deliveries WHERE file_id=$1 AND tenant_id=$2 AND principal_sub=$3 AND principal_issuer=$4 AND expires_at>now() AND ($5::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM gateway_file_deliveries WHERE id=$5 AND tenant_id=$2 AND principal_sub=$3 AND principal_issuer=$4 AND file_id=$1)) ORDER BY created_at DESC,id DESC LIMIT 21")
            .bind(file).bind(owner.tenant_id.as_str()).bind(&owner.principal_sub).bind(&owner.principal_issuer).bind(cursor).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(decode).collect::<Result<_, _>>()?)
    }

    pub async fn deliveries_for_invocation(
        &self,
        owner: &GatewayFileOwner,
        invocation: &str,
    ) -> Result<Vec<GatewayFileDelivery>, FileStorageError> {
        let rows = sqlx::query("SELECT * FROM gateway_file_deliveries WHERE invocation_id=$1 AND tenant_id=$2 AND principal_sub=$3 AND principal_issuer=$4 AND expires_at>now()")
            .bind(invocation).bind(owner.tenant_id.as_str()).bind(&owner.principal_sub).bind(&owner.principal_issuer).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(decode).collect::<Result<_, _>>()?)
    }

    pub async fn set_delivery_stage(
        &self,
        owner: &GatewayFileOwner,
        id: Uuid,
        stage: &str,
    ) -> Result<bool, FileStorageError> {
        let result=sqlx::query("UPDATE gateway_file_deliveries SET stage=$1 WHERE id=$2 AND tenant_id=$3 AND principal_sub=$4 AND principal_issuer=$5 AND (stage NOT IN ('cancelled','cancelling') OR $1 IN ('cancelled','cancelling')) AND NOT (stage='cancelled' AND $1='cancelling') AND ($1<>'dispatched' OR stage='ready')")
            .bind(stage).bind(id).bind(owner.tenant_id.as_str()).bind(&owner.principal_sub).bind(&owner.principal_issuer).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
}
