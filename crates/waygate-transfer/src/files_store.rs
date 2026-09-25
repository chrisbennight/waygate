use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use waygate_core::TenantId;

pub const PENDING_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const PENDING_UPLOAD_RETENTION: time::Duration = time::Duration::minutes(5);
pub const UPLOAD_PROGRESS_WINDOW: Duration = Duration::from_secs(30);
pub const UPLOAD_PROGRESS_BYTES: usize = 64 * 1024;

struct UploadProgress {
    deadline: tokio::time::Instant,
    remaining: usize,
}

impl UploadProgress {
    fn new() -> Self {
        Self {
            deadline: tokio::time::Instant::now() + UPLOAD_PROGRESS_WINDOW,
            remaining: UPLOAD_PROGRESS_BYTES,
        }
    }

    fn record(&mut self, bytes: usize) {
        if bytes >= self.remaining {
            self.deadline = tokio::time::Instant::now() + UPLOAD_PROGRESS_WINDOW;
            self.remaining = UPLOAD_PROGRESS_BYTES;
        } else {
            self.remaining -= bytes;
        }
    }
}

async fn within_upload_progress<T>(
    progress: &Option<UploadProgress>,
    operation: impl std::future::Future<Output = Result<T, FileStorageError>>,
) -> Result<T, FileStorageError> {
    match progress {
        Some(progress) => tokio::time::timeout_at(progress.deadline, operation)
            .await
            .map_err(|_| FileStorageError::UploadStalled)?,
        None => operation.await,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayFileOwner {
    pub tenant_id: TenantId,
    pub principal_sub: String,
    pub principal_issuer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileInspectionStatus {
    Checked,
    Uninspectable,
}

impl FileInspectionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checked => "checked",
            Self::Uninspectable => "uninspectable",
        }
    }

    fn parse(value: &str) -> Result<Self, FileStorageError> {
        match value {
            "checked" => Ok(Self::Checked),
            "uninspectable" => Ok(Self::Uninspectable),
            _ => Err(FileStorageError::StoredData(
                "unknown file inspection status".to_owned(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct NewGatewayFile {
    pub batch_id: Uuid,
    pub owner: GatewayFileOwner,
    pub invocation_id: String,
    pub upstream_server: String,
    pub upstream_tool: String,
    pub upstream_uri: String,
    pub display_name: Option<String>,
    pub media_type: Option<String>,
    pub expected_size: Option<u64>,
    pub expected_sha256: Option<Vec<u8>>,
    pub max_bytes: Option<u64>,
    pub inspection_status: FileInspectionStatus,
    pub retention: time::Duration,
}

#[derive(Clone)]
pub struct StoredGatewayFile {
    pub id: Uuid,
    pub owner: GatewayFileOwner,
    pub invocation_id: String,
    pub upstream_server: String,
    pub upstream_tool: String,
    pub upstream_uri: String,
    pub storage_key: String,
    pub display_name: Option<String>,
    pub media_type: Option<String>,
    pub size: u64,
    pub sha256: Vec<u8>,
    pub inspection_status: FileInspectionStatus,
    pub expires_at: OffsetDateTime,
}

impl StoredGatewayFile {
    pub fn uri(&self) -> String {
        format!("{}{}", waygate_core::GATEWAY_FILE_URI_PREFIX, self.id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileStorageError {
    #[error("file storage path: {0}")]
    Io(#[from] std::io::Error),
    #[error("file metadata store: {0}")]
    Database(#[from] sqlx::Error),
    #[error("upstream file download: {0}")]
    Download(#[from] reqwest::Error),
    #[error("upstream file is larger than the allowed byte count")]
    TooLarge,
    #[error("upstream file size does not match its FileValue")]
    SizeMismatch,
    #[error("upstream file digest does not match its FileValue")]
    DigestMismatch,
    #[error("stored file metadata is invalid: {0}")]
    StoredData(String),
    #[error("staged file batch is no longer available")]
    BatchUnavailable,
    #[error("staged file is no longer available")]
    FileUnavailable,
    #[error("upload made insufficient progress; send at least 64 KiB or finish within 30 seconds")]
    UploadStalled,
}

#[derive(Clone)]
pub struct GatewayFileStorage {
    pool: PgPool,
    root: PathBuf,
}

impl GatewayFileStorage {
    pub async fn new(pool: PgPool, root: impl AsRef<Path>) -> Result<Self, FileStorageError> {
        let mut builder = tokio::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(root.as_ref()).await?;
        let root = tokio::fs::canonicalize(root.as_ref()).await?;
        Ok(Self { pool, root })
    }

    pub async fn stage_response(
        &self,
        new_file: NewGatewayFile,
        response: reqwest::Response,
    ) -> Result<StoredGatewayFile, FileStorageError> {
        let pending_retention = new_file.retention;
        // Strip the request URL before a body-stream error is retained: it
        // would otherwise carry the signed transfer URL into whatever logs
        // the wrapped error.
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|error| error.without_url()));
        self.stage_stream(Uuid::new_v4(), new_file, body, pending_retention, false)
            .await
    }

    /// Import an already recovered body through the same private staging lifecycle.
    pub async fn stage_bytes(
        &self,
        new_file: NewGatewayFile,
        bytes: Vec<u8>,
    ) -> Result<StoredGatewayFile, FileStorageError> {
        let retention = new_file.retention;
        let body = futures::stream::iter([Ok::<_, FileStorageError>(bytes::Bytes::from(bytes))]);
        self.stage_stream(Uuid::new_v4(), new_file, body, retention, false)
            .await
    }

    /// Stage a caller upload under the gateway file identifier minted before
    /// the body arrived. The row remains pending until the transfer authority
    /// confirms completion and the HTTP handler publishes its one-file batch.
    pub async fn stage_upload<S, E>(
        &self,
        id: Uuid,
        new_file: NewGatewayFile,
        stream: S,
    ) -> Result<StoredGatewayFile, FileStorageError>
    where
        S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
        E: Into<FileStorageError>,
    {
        self.stage_stream(id, new_file, stream, PENDING_UPLOAD_RETENTION, true)
            .await
    }

    async fn stage_stream<S, E>(
        &self,
        id: Uuid,
        new_file: NewGatewayFile,
        mut stream: S,
        pending_retention: time::Duration,
        check_upload_progress: bool,
    ) -> Result<StoredGatewayFile, FileStorageError>
    where
        S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
        E: Into<FileStorageError>,
    {
        let storage_key = id.to_string();
        let pending_path = self.root.join(format!(".{storage_key}.part"));
        let final_path = self.root.join(&storage_key);
        // A pending row must outlive the gap to its first batch renewal even
        // when its class window equals the heartbeat interval; the sweeper may
        // otherwise remove a completed short-class sibling mid-batch. Pending
        // rows are not downloadable and publication starts the class window
        // fresh, so the floor never lengthens published availability.
        let pending_floor =
            time::Duration::seconds((2 * PENDING_HEARTBEAT_INTERVAL).as_secs() as i64);
        let pending_retention = pending_retention.max(pending_floor);
        let initial_expires_at = OffsetDateTime::now_utc() + pending_retention;
        sqlx::query(
            r#"
            INSERT INTO gateway_files (
                id, batch_id, tenant_id, principal_sub, principal_issuer, invocation_id,
                upstream_server, upstream_tool, upstream_uri, storage_key, display_name,
                media_type, inspection_status, expires_at, retention_seconds
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(id)
        .bind(new_file.batch_id)
        .bind(new_file.owner.tenant_id.as_str())
        .bind(&new_file.owner.principal_sub)
        .bind(&new_file.owner.principal_issuer)
        .bind(&new_file.invocation_id)
        .bind(&new_file.upstream_server)
        .bind(&new_file.upstream_tool)
        .bind(&new_file.upstream_uri)
        .bind(&storage_key)
        .bind(&new_file.display_name)
        .bind(&new_file.media_type)
        .bind(new_file.inspection_status.as_str())
        .bind(initial_expires_at)
        .bind(new_file.retention.whole_seconds().max(1))
        .execute(&self.pool)
        .await?;
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let output = options.open(&pending_path).await;
        let mut output = match output {
            Ok(output) => output,
            Err(error) => {
                self.cleanup_failed_file(id).await;
                return Err(error.into());
            }
        };
        let mut size = 0_u64;
        let mut digest = Sha256::new();
        let mut heartbeat = tokio::time::interval(PENDING_HEARTBEAT_INTERVAL);
        heartbeat.tick().await;
        let mut progress = check_upload_progress.then(UploadProgress::new);
        let write_result: Result<(), FileStorageError> = async {
            loop {
                let deadline = progress.as_ref().map(|progress| progress.deadline);
                tokio::select! {
                    biased;
                    _ = async {
                        match deadline {
                            Some(deadline) => tokio::time::sleep_until(deadline).await,
                            None => std::future::pending().await,
                        }
                    } => return Err(FileStorageError::UploadStalled),
                    _ = heartbeat.tick() => {
                        within_upload_progress(&progress, self.heartbeat_pending_batch(new_file.batch_id, id)).await?;
                    }
                    chunk = stream.next() => {
                        let Some(chunk) = chunk else {
                            break;
                        };
                        let chunk = chunk.map_err(Into::into)?;
                        size = size
                            .checked_add(chunk.len() as u64)
                            .ok_or(FileStorageError::TooLarge)?;
                        // A declared-size overrun is an integrity outcome;
                        // exceeding the configured byte budget is a limit
                        // refusal. The two must stay distinguishable.
                        if new_file
                            .expected_size
                            .is_some_and(|expected| size > expected)
                        {
                            return Err(FileStorageError::SizeMismatch);
                        }
                        if new_file.max_bytes.is_some_and(|limit| size > limit) {
                            return Err(FileStorageError::TooLarge);
                        }
                        if let Some(progress) = progress.as_mut() {
                            progress.record(chunk.len());
                        }
                        digest.update(&chunk);
                        within_upload_progress(&progress, async {
                            output.write_all(&chunk).await.map_err(FileStorageError::Io)
                        }).await?;
                    }
                }
            }
            within_upload_progress(&progress, async {
                output.flush().await.map_err(FileStorageError::Io)
            }).await?;
            Ok(())
        }
        .await;
        if let Err(error) = write_result {
            drop(output);
            self.cleanup_failed_file(id).await;
            return Err(error);
        }
        if new_file
            .expected_size
            .is_some_and(|expected| expected != size)
        {
            drop(output);
            self.cleanup_failed_file(id).await;
            return Err(FileStorageError::SizeMismatch);
        }
        let sha256 = digest.finalize().to_vec();
        if new_file
            .expected_sha256
            .as_deref()
            .is_some_and(|expected| expected != sha256.as_slice())
        {
            drop(output);
            self.cleanup_failed_file(id).await;
            return Err(FileStorageError::DigestMismatch);
        }
        if let Err(error) = output.sync_all().await {
            drop(output);
            self.cleanup_failed_file(id).await;
            return Err(error.into());
        }
        drop(output);
        if let Err(error) = tokio::fs::rename(&pending_path, &final_path).await {
            self.cleanup_failed_file(id).await;
            return Err(error.into());
        }
        if let Err(error) = sync_directory(&self.root).await {
            self.cleanup_failed_file(id).await;
            return Err(error.into());
        }

        let size_i64 = match i64::try_from(size) {
            Ok(size) => size,
            Err(_) => {
                self.cleanup_failed_file(id).await;
                return Err(FileStorageError::TooLarge);
            }
        };
        let expires_at = OffsetDateTime::now_utc() + pending_retention;
        let update = sqlx::query(
            "UPDATE gateway_files SET size_bytes = $2, sha256_digest = $3, expires_at = $4 \
             WHERE id = $1 AND state = 'pending'",
        )
        .bind(id)
        .bind(size_i64)
        .bind(&sha256)
        .bind(expires_at)
        .execute(&self.pool)
        .await;
        let updated = match update {
            Ok(updated) => updated,
            Err(error) => {
                self.cleanup_failed_file(id).await;
                return Err(FileStorageError::Database(error));
            }
        };
        if updated.rows_affected() != 1 {
            self.cleanup_failed_file(id).await;
            return Err(FileStorageError::FileUnavailable);
        }

        Ok(StoredGatewayFile {
            id,
            owner: new_file.owner,
            invocation_id: new_file.invocation_id,
            upstream_server: new_file.upstream_server,
            upstream_tool: new_file.upstream_tool,
            upstream_uri: new_file.upstream_uri,
            storage_key,
            display_name: new_file.display_name,
            media_type: new_file.media_type,
            size,
            sha256,
            inspection_status: new_file.inspection_status,
            expires_at,
        })
    }

    pub async fn publish_batch(
        &self,
        batch_id: Uuid,
        expected_files: usize,
    ) -> Result<(), FileStorageError> {
        if expected_files == 0 {
            return Err(FileStorageError::BatchUnavailable);
        }
        let expected_rows =
            u64::try_from(expected_files).map_err(|_| FileStorageError::BatchUnavailable)?;
        let mut transaction = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT state, size_bytes, sha256_digest FROM gateway_files \
             WHERE batch_id = $1 FOR UPDATE",
        )
        .bind(batch_id)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.len() != expected_files
            || rows.iter().any(|row| {
                !matches!(row.try_get::<String, _>("state"), Ok(state) if state == "pending")
                    || row
                        .try_get::<Option<i64>, _>("size_bytes")
                        .ok()
                        .flatten()
                        .is_none()
                    || row
                        .try_get::<Option<Vec<u8>>, _>("sha256_digest")
                        .ok()
                        .flatten()
                        .is_none()
            })
        {
            return Err(FileStorageError::BatchUnavailable);
        }
        // Retention starts at publication (the documented contract), measured
        // per row from its own staged class: an ordinary file gets its full
        // general window regardless of how long the batch staged, and a
        // secret-class file cannot be moved onto the general window because
        // its class travels with the row.
        let published = sqlx::query(
            "UPDATE gateway_files SET state = 'ready', \
             expires_at = now() + make_interval(secs => retention_seconds::double precision), \
             updated_at = now() \
             WHERE batch_id = $1 AND state = 'pending'",
        )
        .bind(batch_id)
        .execute(&mut *transaction)
        .await?;
        if published.rows_affected() != expected_rows {
            return Err(FileStorageError::BatchUnavailable);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Keep completed siblings available while another member of the same
    /// unpublished batch is still arriving.
    pub async fn heartbeat_pending_batch(
        &self,
        batch_id: Uuid,
        active_file_id: Uuid,
    ) -> Result<(), FileStorageError> {
        // Completed siblings are renewed by their own staged retention class so
        // a batch-wide value cannot erase a per-file promise. The floor keeps a
        // short-class row alive across beat intervals; pending rows are not
        // downloadable, so the floor never extends published availability —
        // publication clamps each row back to its class.
        let keepalive_floor_seconds = (2 * PENDING_HEARTBEAT_INTERVAL).as_secs() as i64;
        let active_file_renewed: bool = sqlx::query_scalar(
            r#"
            WITH renewed AS (
                UPDATE gateway_files
                   SET updated_at = now(),
                       expires_at = CASE
                           WHEN size_bytes IS NULL THEN expires_at
                           ELSE GREATEST(expires_at,
                               now() + make_interval(secs =>
                                   GREATEST(retention_seconds, $2)::double precision))
                       END
                 WHERE batch_id = $1
                   AND state = 'pending'
                RETURNING id
            )
            SELECT EXISTS (SELECT 1 FROM renewed WHERE id = $3)
            "#,
        )
        .bind(batch_id)
        .bind(keepalive_floor_seconds)
        .bind(active_file_id)
        .fetch_one(&self.pool)
        .await?;
        if !active_file_renewed {
            return Err(FileStorageError::FileUnavailable);
        }
        Ok(())
    }

    pub async fn discard_batch(&self, batch_id: Uuid) -> Result<(), FileStorageError> {
        sqlx::query(
            "UPDATE gateway_files SET state = 'deleting' WHERE batch_id = $1 AND state = 'pending'",
        )
        .bind(batch_id)
        .execute(&self.pool)
        .await?;
        self.remove_marked(1_000).await?;
        Ok(())
    }

    pub async fn find_ready(
        &self,
        owner: &GatewayFileOwner,
        id: Uuid,
    ) -> Result<Option<StoredGatewayFile>, FileStorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, tenant_id, principal_sub, principal_issuer, invocation_id,
                   upstream_server, upstream_tool, upstream_uri, storage_key, display_name,
                   media_type, size_bytes, sha256_digest, inspection_status,
                   expires_at
              FROM gateway_files
             WHERE id = $1
               AND tenant_id = $2
               AND principal_sub = $3
               AND principal_issuer = $4
               AND state = 'ready'
               AND expires_at > now()
            "#,
        )
        .bind(id)
        .bind(owner.tenant_id.as_str())
        .bind(&owner.principal_sub)
        .bind(&owner.principal_issuer)
        .fetch_optional(&self.pool)
        .await?;
        row.map(decode_file_row).transpose()
    }

    pub fn path_for(&self, file: &StoredGatewayFile) -> PathBuf {
        self.root.join(&file.storage_key)
    }

    pub async fn sweep_expired(&self, limit: i64) -> Result<u64, FileStorageError> {
        sqlx::query(
            r#"
            WITH expired AS (
                SELECT id
                 FROM gateway_files
                 WHERE (state = 'ready' AND expires_at <= now())
                    OR (state = 'pending' AND size_bytes IS NULL
                        AND updated_at <= now() - INTERVAL '5 minutes')
                    OR (state = 'pending' AND size_bytes IS NOT NULL
                        AND expires_at <= now())
                 ORDER BY expires_at, id
                 LIMIT $1
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE gateway_files AS target
               SET state = 'deleting'
              FROM expired
             WHERE target.id = expired.id
            "#,
        )
        .bind(limit)
        .execute(&self.pool)
        .await?;
        self.remove_marked(limit).await
    }

    async fn cleanup_failed_file(&self, id: Uuid) {
        if let Err(error) = sqlx::query(
            "UPDATE gateway_files SET state = 'deleting' WHERE id = $1 AND state = 'pending'",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        {
            tracing::warn!(file_id = %id, error = %error, "failed file could not be marked for cleanup");
            return;
        }
        if let Err(error) = self.remove_file_row(id).await {
            tracing::warn!(file_id = %id, error = %error, "failed file cleanup will be retried");
        }
    }

    async fn remove_marked(&self, limit: i64) -> Result<u64, FileStorageError> {
        let rows = sqlx::query(
            "SELECT id, storage_key FROM gateway_files WHERE state = 'deleting' ORDER BY id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut removed = 0_u64;
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            match self.remove_file_row(id).await {
                Ok(true) => removed += 1,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(file_id = %id, error = %error, "file cleanup failed");
                }
            }
        }
        Ok(removed)
    }

    async fn remove_file_row(&self, id: Uuid) -> Result<bool, FileStorageError> {
        let row = sqlx::query(
            "SELECT storage_key FROM gateway_files WHERE id = $1 AND state = 'deleting'",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let storage_key: String = row.try_get("storage_key")?;
        validate_storage_key(id, &storage_key)?;
        remove_if_present(&self.root.join(&storage_key)).await?;
        remove_if_present(&self.root.join(format!(".{storage_key}.part"))).await?;
        let deleted = sqlx::query("DELETE FROM gateway_files WHERE id = $1 AND state = 'deleting'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(deleted.rows_affected() == 1)
    }
}

async fn remove_if_present(path: &Path) -> Result<(), std::io::Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
async fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::File::open(path).await?.sync_all().await
}

#[cfg(not(unix))]
async fn sync_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn decode_file_row(row: sqlx::postgres::PgRow) -> Result<StoredGatewayFile, FileStorageError> {
    let id: Uuid = row.try_get("id")?;
    let storage_key: String = row.try_get("storage_key")?;
    validate_storage_key(id, &storage_key)?;
    let size: i64 = row.try_get("size_bytes")?;
    Ok(StoredGatewayFile {
        id,
        owner: GatewayFileOwner {
            tenant_id: TenantId::parse(row.try_get::<String, _>("tenant_id")?)
                .map_err(|error| FileStorageError::StoredData(error.to_string()))?,
            principal_sub: row.try_get("principal_sub")?,
            principal_issuer: row.try_get("principal_issuer")?,
        },
        invocation_id: row.try_get("invocation_id")?,
        upstream_server: row.try_get("upstream_server")?,
        upstream_tool: row.try_get("upstream_tool")?,
        upstream_uri: row.try_get("upstream_uri")?,
        storage_key,
        display_name: row.try_get("display_name")?,
        media_type: row.try_get("media_type")?,
        size: u64::try_from(size)
            .map_err(|_| FileStorageError::StoredData("negative file size".to_owned()))?,
        sha256: row.try_get("sha256_digest")?,
        inspection_status: FileInspectionStatus::parse(
            &row.try_get::<String, _>("inspection_status")?,
        )?,
        expires_at: row.try_get("expires_at")?,
    })
}

fn validate_storage_key(id: Uuid, storage_key: &str) -> Result<(), FileStorageError> {
    if storage_key == id.to_string() {
        Ok(())
    } else {
        Err(FileStorageError::StoredData(
            "file storage key does not match its identifier".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_must_be_the_files_own_uuid() {
        let id = Uuid::new_v4();
        validate_storage_key(id, &id.to_string()).expect("matching key");
        assert!(validate_storage_key(id, "../outside").is_err());
        assert!(validate_storage_key(id, &Uuid::new_v4().to_string()).is_err());
    }
}

#[cfg(test)]
mod upload_progress_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn empty_and_small_chunks_do_not_extend_the_progress_deadline() {
        let mut progress = UploadProgress::new();
        let first_deadline = progress.deadline;
        tokio::time::advance(Duration::from_secs(20)).await;
        progress.record(0);
        progress.record(UPLOAD_PROGRESS_BYTES - 1);
        assert_eq!(progress.deadline, first_deadline);
        progress.record(1);
        assert_eq!(
            progress.deadline,
            tokio::time::Instant::now() + UPLOAD_PROGRESS_WINDOW
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_storage_or_heartbeat_work_obeys_the_same_deadline() {
        let progress = Some(UploadProgress::new());
        let result: Result<(), FileStorageError> =
            within_upload_progress(&progress, std::future::pending()).await;
        assert!(matches!(result, Err(FileStorageError::UploadStalled)));
    }

    #[tokio::test(start_paused = true)]
    async fn progressing_uploads_have_no_total_duration_limit() {
        let mut progress = UploadProgress::new();
        for _ in 0..100 {
            tokio::time::advance(Duration::from_secs(20)).await;
            assert!(tokio::time::Instant::now() < progress.deadline);
            progress.record(UPLOAD_PROGRESS_BYTES);
        }
    }
}
