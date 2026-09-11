use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use waygate_core::store::StoreError;

use crate::{
    AuthorizedTransferRequest, NewGrantRow, TransferDigest, TransferDirection, TransferEndpoint,
    TransferGrant, TransferOwner, TransferStatus, TransferStore,
};

macro_rules! grant_query {
    ($before:literal, $after:literal) => {
        sqlx::query(concat!(
            $before,
            " id, tenant_id, handle_hash, principal_sub, principal_issuer,
              credential_profile_id, invocation_id, file_uri, direction,
              source_kind, source_ref, destination_kind, destination_ref, helper_jkt,
              max_bytes, expected_size, media_type, digest_algorithm, expected_digest,
              max_requests, requests_used, credential_ttl_seconds, status,
              credential_expires_at, expires_at, created_at ",
            $after
        ))
    };
}

#[derive(Clone)]
pub struct PgTransferStore {
    pool: PgPool,
}

impl PgTransferStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl TransferStore for PgTransferStore {
    async fn insert(&self, row: NewGrantRow) -> Result<TransferGrant, StoreError> {
        let expected_size = row.spec.expected_size.map(u64_to_i64).transpose()?;
        let max_bytes = u64_to_i64(row.spec.max_bytes)?;
        let max_requests = u64_to_i64(row.spec.max_requests)?;
        let credential_ttl_seconds = row.spec.credential_ttl.whole_seconds();
        let source_ref = row.spec.source.encode_reference();
        let destination_ref = row.spec.destination.encode_reference();
        let digest_algorithm = row
            .spec
            .expected_digest
            .as_ref()
            .map(|digest| digest.algorithm.as_str());
        let expected_digest = row
            .spec
            .expected_digest
            .as_ref()
            .map(|digest| digest.value.as_slice());
        let result = grant_query!(
            r#"
            INSERT INTO file_transfer_grants (
                id, tenant_id, handle_hash, principal_sub, principal_issuer,
                credential_profile_id, invocation_id, file_uri, direction,
                source_kind, source_ref, destination_kind, destination_ref,
                helper_jkt, max_bytes, expected_size, media_type,
                digest_algorithm, expected_digest, max_requests,
                credential_ttl_seconds, expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
            )
            RETURNING
            "#,
            ""
        )
        .bind(row.id)
        .bind(row.owner.tenant_id.as_str())
        .bind(&row.handle_hash)
        .bind(&row.owner.principal_sub)
        .bind(&row.owner.principal_issuer)
        .bind(&row.owner.credential_profile_id)
        .bind(&row.spec.invocation_id)
        .bind(&row.spec.file_uri)
        .bind(row.spec.direction.as_str())
        .bind(row.spec.source.kind())
        .bind(source_ref)
        .bind(row.spec.destination.kind())
        .bind(destination_ref)
        .bind(&row.spec.helper_jkt)
        .bind(max_bytes)
        .bind(expected_size)
        .bind(&row.spec.media_type)
        .bind(digest_algorithm)
        .bind(expected_digest)
        .bind(max_requests)
        .bind(credential_ttl_seconds)
        .bind(row.spec.expires_at)
        .fetch_one(&self.pool)
        .await?;
        row_to_grant(&result)
    }

    async fn find_by_handle(
        &self,
        handle_hash: &[u8],
    ) -> Result<Option<TransferGrant>, StoreError> {
        let row = grant_query!("SELECT", "FROM file_transfer_grants WHERE handle_hash = $1")
            .bind(handle_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| row_to_grant(&row)).transpose()
    }

    async fn find_by_credential_hash(
        &self,
        credential_hash: &[u8],
    ) -> Result<Option<TransferGrant>, StoreError> {
        let row = grant_query!(
            "SELECT",
            "FROM file_transfer_grants WHERE credential_hash = $1"
        )
        .bind(credential_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_grant(&row)).transpose()
    }

    async fn find_upload_by_owner(
        &self,
        owner: &TransferOwner,
        file_uri: &str,
    ) -> Result<Option<TransferGrant>, StoreError> {
        let row = grant_query!(
            "SELECT",
            r#"
            FROM file_transfer_grants
            WHERE tenant_id = $1
              AND principal_sub = $2
              AND principal_issuer = $3
              AND credential_profile_id IS NOT DISTINCT FROM $4
              AND file_uri = $5
              AND direction = 'upload'
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            "#
        )
        .bind(owner.tenant_id.as_str())
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .bind(&owner.credential_profile_id)
        .bind(file_uri)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_grant(&row)).transpose()
    }

    async fn activate(
        &self,
        handle_hash: &[u8],
        helper_jkt: &str,
        credential_hash: &[u8],
        credential_expires_at: OffsetDateTime,
    ) -> Result<Option<TransferGrant>, StoreError> {
        grant_query!(
            r#"
            UPDATE file_transfer_grants
               SET status = 'active', credential_hash = $3,
                   credential_expires_at = $4, activated_at = now()
             WHERE handle_hash = $1
               AND helper_jkt = $2
               AND status = 'pending'
               AND expires_at > now()
               AND $4 > now()
               AND $4 <= expires_at
            RETURNING
            "#,
            ""
        )
        .bind(handle_hash)
        .bind(helper_jkt)
        .bind(credential_hash)
        .bind(credential_expires_at)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row_to_grant(&row))
        .transpose()
    }

    async fn authorize_request(
        &self,
        credential_hash: &[u8],
        helper_jkt: &str,
        authorization_id: Uuid,
    ) -> Result<Option<AuthorizedTransferRequest>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = grant_query!(
            r#"
            UPDATE file_transfer_grants
               SET requests_used = requests_used + 1,
                   active_heartbeat_at = now()
             WHERE credential_hash = $1
               AND helper_jkt = $2
               AND status = 'active'
               AND expires_at > now()
               AND credential_expires_at > now()
               AND requests_used < max_requests
            RETURNING
            "#,
            ""
        )
        .bind(credential_hash)
        .bind(helper_jkt)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let grant = row_to_grant(&row)?;
        sqlx::query(
            r#"
            INSERT INTO file_transfer_requests (id, grant_id, request_number)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(authorization_id)
        .bind(grant.id)
        .bind(u64_to_i64(grant.requests_used)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(AuthorizedTransferRequest {
            authorization_id,
            request_number: grant.requests_used,
            grant,
        }))
    }

    async fn complete(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        observed_size: u64,
        observed_digest: Option<&[u8]>,
    ) -> Result<Option<TransferGrant>, StoreError> {
        let observed_size = u64_to_i64(observed_size)?;
        let mut transaction = self.pool.begin().await?;
        let grant_row = grant_query!(
            "SELECT",
            "FROM file_transfer_grants WHERE id = $1 AND status = 'active' FOR UPDATE"
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(grant_row) = grant_row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let grant = row_to_grant(&grant_row)?;
        if observed_size > u64_to_i64(grant.max_bytes)?
            || grant
                .expected_size
                .is_some_and(|expected| expected != observed_size as u64)
            || !crate::digest_matches(&grant.expected_digest, observed_digest)
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        let request_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
              FROM file_transfer_requests
             WHERE id = $1 AND grant_id = $2 AND status = 'authorized'
             FOR UPDATE
            "#,
        )
        .bind(authorization_id)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if request_id.is_none() {
            transaction.rollback().await?;
            return Ok(None);
        }
        let updated = sqlx::query(
            r#"
            UPDATE file_transfer_requests
               SET status = 'completed', observed_size = $2,
                   observed_digest = $3, completed_at = now()
             WHERE id = $1 AND status = 'authorized'
            "#,
        )
        .bind(authorization_id)
        .bind(observed_size)
        .bind(observed_digest)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        settle_grant_if_finished(&mut transaction, id).await?;
        let row = grant_query!("SELECT", "FROM file_transfer_grants WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *transaction)
            .await?;
        transaction.commit().await?;
        row_to_grant(&row).map(Some)
    }

    async fn complete_upload(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        file_id: Uuid,
        observed_size: u64,
        observed_digest: &[u8],
        retention: Duration,
    ) -> Result<Option<TransferGrant>, crate::UploadCompletionError> {
        let observed_size = u64_to_i64(observed_size)?;
        let mut transaction = self.pool.begin().await?;
        let grant_row = grant_query!(
            "SELECT",
            "FROM file_transfer_grants WHERE id = $1 AND status = 'active' FOR UPDATE"
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(grant_row) = grant_row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        let grant = row_to_grant(&grant_row)?;
        if grant.direction != TransferDirection::Upload
            || grant.file_uri != format!("mcp-file://gateway/{file_id}")
            || observed_size > u64_to_i64(grant.max_bytes)?
            || grant
                .expected_size
                .is_some_and(|expected| expected != observed_size as u64)
            || !crate::digest_matches(&grant.expected_digest, Some(observed_digest))
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        let request_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
              FROM file_transfer_requests
             WHERE id = $1 AND grant_id = $2 AND status = 'authorized'
             FOR UPDATE
            "#,
        )
        .bind(authorization_id)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if request_id.is_none() {
            transaction.rollback().await?;
            return Ok(None);
        }
        let expires_at = OffsetDateTime::now_utc() + retention;
        let published = sqlx::query(
            r#"
            UPDATE gateway_files
               SET state = 'ready', expires_at = $2, updated_at = now()
             WHERE id = $1
               AND batch_id = $1
               AND state = 'pending'
               AND tenant_id = $3
               AND principal_sub = $4
               AND principal_issuer = $5
               AND size_bytes = $6
               AND sha256_digest = $7
               AND invocation_id = $8
               AND upstream_uri = $9
            "#,
        )
        .bind(file_id)
        .bind(expires_at)
        .bind(grant.owner.tenant_id.as_str())
        .bind(&grant.owner.principal_sub)
        .bind(&grant.owner.principal_issuer)
        .bind(observed_size)
        .bind(observed_digest)
        .bind(&grant.invocation_id)
        .bind(grant.source.reference())
        .execute(&mut *transaction)
        .await?;
        if published.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        let completed = sqlx::query(
            r#"
            UPDATE file_transfer_requests
               SET status = 'completed', observed_size = $2,
                   observed_digest = $3, completed_at = now()
             WHERE id = $1 AND status = 'authorized'
            "#,
        )
        .bind(authorization_id)
        .bind(observed_size)
        .bind(observed_digest)
        .execute(&mut *transaction)
        .await?;
        if completed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        settle_grant_if_finished(&mut transaction, id).await?;
        let row = grant_query!("SELECT", "FROM file_transfer_grants WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *transaction)
            .await?;
        let committed_grant = row_to_grant(&row)?;
        if let Err(commit_error) = transaction.commit().await {
            let commit_error = StoreError::from(commit_error);
            let converged = grant_query!(
                "SELECT",
                r#"
                FROM file_transfer_grants AS transfer_grant
                WHERE transfer_grant.id = $1
                  AND transfer_grant.status = 'completed'
                  AND EXISTS (
                      SELECT 1 FROM file_transfer_requests AS transfer_request
                       WHERE transfer_request.id = $2
                         AND transfer_request.grant_id = transfer_grant.id
                         AND transfer_request.status = 'completed'
                         AND transfer_request.observed_size = $3
                         AND transfer_request.observed_digest = $4
                  )
                  AND EXISTS (
                      SELECT 1 FROM gateway_files AS gateway_file
                       WHERE gateway_file.id = $5
                         AND gateway_file.state = 'ready'
                         AND gateway_file.tenant_id = transfer_grant.tenant_id
                         AND gateway_file.principal_sub = transfer_grant.principal_sub
                         AND gateway_file.principal_issuer = transfer_grant.principal_issuer
                         AND gateway_file.size_bytes = $3
                         AND gateway_file.sha256_digest = $4
                  )
                "#
            )
            .bind(id)
            .bind(authorization_id)
            .bind(observed_size)
            .bind(observed_digest)
            .bind(file_id)
            .fetch_optional(&self.pool)
            .await;
            return match converged {
                Ok(Some(row)) => row_to_grant(&row).map(Some).map_err(Into::into),
                Ok(None) => Err(crate::UploadCompletionError::OutcomeUnknown {
                    commit: commit_error,
                    verification: crate::UploadCompletionVerification::NotVisible,
                }),
                Err(verification) => Err(crate::UploadCompletionError::OutcomeUnknown {
                    commit: commit_error,
                    verification: crate::UploadCompletionVerification::Store(verification.into()),
                }),
            };
        }
        Ok(Some(committed_grant))
    }

    async fn heartbeat_request(
        &self,
        id: Uuid,
        authorization_id: Uuid,
    ) -> Result<bool, StoreError> {
        let renewed = sqlx::query(
            r#"
            UPDATE file_transfer_grants AS transfer_grant
               SET active_heartbeat_at = now()
             WHERE transfer_grant.id = $1
               AND transfer_grant.status = 'active'
               AND EXISTS (
                    SELECT 1
                      FROM file_transfer_requests AS transfer_request
                     WHERE transfer_request.id = $2
                       AND transfer_request.grant_id = transfer_grant.id
                       AND transfer_request.status = 'authorized'
               )
            "#,
        )
        .bind(id)
        .bind(authorization_id)
        .execute(&self.pool)
        .await?;
        Ok(renewed.rows_affected() == 1)
    }

    async fn fail_request(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        failure_code: &str,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let grant_exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM file_transfer_grants WHERE id = $1 AND status = 'active' FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if grant_exists.is_none() {
            transaction.rollback().await?;
            return Ok(false);
        }
        let request_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
              FROM file_transfer_requests
             WHERE id = $1 AND grant_id = $2 AND status = 'authorized'
             FOR UPDATE
            "#,
        )
        .bind(authorization_id)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
        if request_id.is_none() {
            transaction.rollback().await?;
            return Ok(false);
        }
        let updated = sqlx::query(
            r#"
            UPDATE file_transfer_requests
               SET status = 'failed', failure_code = $2, failed_at = now()
             WHERE id = $1 AND status = 'authorized'
            "#,
        )
        .bind(authorization_id)
        .bind(failure_code)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(false);
        }
        settle_grant_if_finished(&mut transaction, id).await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn revoke(&self, id: Uuid, reason: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE file_transfer_grants
               SET status = 'revoked', revoked_at = now(), failure_code = $2
             WHERE id = $1 AND status IN ('pending', 'active')
            "#,
        )
        .bind(id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn claim_dpop_jti(
        &self,
        helper_jkt: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let inserted = sqlx::query(
            r#"
            INSERT INTO file_transfer_dpop_replays (helper_jkt, jti, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(helper_jkt)
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1;
        Ok(inserted)
    }

    async fn sweep_expired(&self, limit: u32) -> Result<u64, StoreError> {
        sqlx::query("DELETE FROM file_transfer_dpop_replays WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        let terminal = sqlx::query(
            r#"
            DELETE FROM file_transfer_grants
             WHERE id IN (
                SELECT transfer_grant.id
                  FROM file_transfer_grants AS transfer_grant
                 WHERE transfer_grant.status IN ('completed', 'revoked', 'failed')
                   AND transfer_grant.expires_at <= now()
                   AND NOT EXISTS (
                        SELECT 1
                          FROM gateway_files AS gateway_file
                         WHERE transfer_grant.direction = 'upload'
                           AND transfer_grant.status = 'completed'
                           AND transfer_grant.file_uri =
                               'mcp-file://gateway/' || gateway_file.id::text
                           AND gateway_file.state = 'ready'
                           AND gateway_file.expires_at > now()
                   )
                 ORDER BY transfer_grant.expires_at, transfer_grant.id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $1
             )
            "#,
        )
        .bind(i64::from(limit))
        .execute(&self.pool)
        .await?;
        let expired = sqlx::query(
            r#"
            WITH expired AS (
                SELECT id
                  FROM file_transfer_grants
                 WHERE (status = 'pending'
                        OR (status = 'active'
                            AND (requests_used = 0
                                 OR active_heartbeat_at <= now() - INTERVAL '5 minutes')))
                   AND expires_at <= now()
                 ORDER BY expires_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $1
            )
            UPDATE file_transfer_grants AS target
               SET status = 'failed', failure_code = 'expired'
              FROM expired
             WHERE target.id = expired.id
            "#,
        )
        .bind(i64::from(limit))
        .execute(&self.pool)
        .await?;
        Ok(terminal.rows_affected() + expired.rows_affected())
    }
}

async fn settle_grant_if_finished(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        WITH request_state AS (
            SELECT COUNT(*) FILTER (WHERE status = 'authorized') AS open_requests,
                   COUNT(*) FILTER (WHERE status = 'failed') AS failed_requests,
                   MAX(failure_code) FILTER (WHERE status = 'failed') AS failure_code
              FROM file_transfer_requests
             WHERE grant_id = $1
        )
        UPDATE file_transfer_grants AS transfer_grant
           SET status = CASE
                   WHEN request_state.failed_requests > 0 THEN 'failed'
                   ELSE 'completed'
               END,
               failure_code = CASE
                   WHEN request_state.failed_requests > 0 THEN request_state.failure_code
                   ELSE NULL
               END,
               completed_at = CASE
                   WHEN request_state.failed_requests = 0 THEN now()
                   ELSE NULL
               END
          FROM request_state
         WHERE transfer_grant.id = $1
           AND transfer_grant.status = 'active'
           AND transfer_grant.requests_used = transfer_grant.max_requests
           AND request_state.open_requests = 0
        "#,
    )
    .bind(id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn row_to_grant(row: &PgRow) -> Result<TransferGrant, StoreError> {
    let direction_raw: String = row.try_get("direction")?;
    let direction = TransferDirection::parse(&direction_raw)
        .ok_or_else(|| invalid_data("stored transfer direction is invalid"))?;
    let status_raw: String = row.try_get("status")?;
    let status = TransferStatus::parse(&status_raw)
        .ok_or_else(|| invalid_data("stored transfer status is invalid"))?;
    let source_kind: String = row.try_get("source_kind")?;
    let source_ref: String = row.try_get("source_ref")?;
    let destination_kind: String = row.try_get("destination_kind")?;
    let destination_ref: String = row.try_get("destination_ref")?;
    let digest_algorithm: Option<String> = row.try_get("digest_algorithm")?;
    let expected_digest: Option<Vec<u8>> = row.try_get("expected_digest")?;
    let expected_digest = match (digest_algorithm, expected_digest) {
        (Some(algorithm), Some(value)) => Some(TransferDigest { algorithm, value }),
        (None, None) => None,
        _ => return Err(invalid_data("stored transfer digest columns disagree")),
    };

    Ok(TransferGrant {
        id: row.try_get("id")?,
        owner: TransferOwner {
            tenant_id: waygate_core::TenantId::parse(row.try_get::<String, _>("tenant_id")?)
                .map_err(|error| invalid_data(error.to_string()))?,
            principal_sub: row.try_get("principal_sub")?,
            principal_issuer: row.try_get("principal_issuer")?,
            credential_profile_id: row.try_get("credential_profile_id")?,
        },
        invocation_id: row.try_get("invocation_id")?,
        file_uri: row.try_get("file_uri")?,
        direction,
        source: TransferEndpoint::decode(&source_kind, &source_ref)?,
        destination: TransferEndpoint::decode(&destination_kind, &destination_ref)?,
        helper_jkt: row.try_get("helper_jkt")?,
        max_bytes: i64_to_u64(row.try_get("max_bytes")?)?,
        expected_size: row
            .try_get::<Option<i64>, _>("expected_size")?
            .map(i64_to_u64)
            .transpose()?,
        media_type: row.try_get("media_type")?,
        expected_digest,
        max_requests: i64_to_u64(row.try_get("max_requests")?)?,
        requests_used: i64_to_u64(row.try_get("requests_used")?)?,
        credential_ttl: Duration::seconds(row.try_get("credential_ttl_seconds")?),
        status,
        credential_expires_at: row.try_get("credential_expires_at")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn u64_to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(int_decode_error)
}

fn i64_to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(int_decode_error)
}

fn int_decode_error(error: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(Box::new(error)))
}

fn invalid_data(message: impl Into<String>) -> StoreError {
    int_decode_error(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}
