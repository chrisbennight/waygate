use crate::codemode_limits::limits;
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, str::FromStr};

use anyhow::Context;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use rmcp::model::{CallToolResult, ReadResourceResult, ResourceContents};
use rmcp::ErrorData as McpError;
use serde_json::{Map, Value};
use sqlx::postgres::PgPool;
use std::collections::{BTreeMap, HashSet};
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use waygate_core::fmt::format_ts_rfc3339;
use waygate_mcp::audit::{AuditEvent, AuditOutcome, EvidenceCategory, SharedEvidence};
use waygate_mcp::files::{
    file_transfer_failure, invalid_file_request, AuthorizeDownloadParams, AuthorizeDownloadResult,
    AuthorizeUploadParams, AuthorizeUploadResult, FileDigest, FileDownloadAuthorizer,
    FileInputContext, FileInputDescriptor, FileInputProcessor, FileOutputContext,
    FileOutputProcessor, FileTransferDescriptor, FileTransferMode, FileTransferReason,
    FileTransport, FileUploadAuthorizer, FileValue, PreparedFileOutput, PreparedResourceOutput,
    TransferMethod,
};
use waygate_mcp::SharedCatalog;
use waygate_oidc::Principal;
use waygate_transfer::{
    FileInspectionStatus, FileTransferAdmission, GatewayFileOwner, GatewayFileStorage,
    NewGatewayFile, StoredGatewayFile,
};
use waygate_transfer::{SharedTransferStore, TransferAuthority};

pub(crate) struct TransferRuntime {
    pub(crate) authority: Arc<TransferAuthority>,
    store: SharedTransferStore,
    file_storage: Option<Arc<GatewayFileStorage>>,
    exchange_concurrency: usize,
    audit: SharedEvidence,
}

const NATIVE_RESOURCE_FILE_ORIGIN: &str = "resources/read";

/// Re-check the profile boundary of the operation that produced a stored
/// file. Native resource files remain resource-confined even though storage
/// records their producing operation in the legacy `upstream_tool` column.
pub(crate) fn profile_blocks_file_origin(
    principal: &Principal,
    server: &str,
    origin: &str,
) -> bool {
    if origin == NATIVE_RESOURCE_FILE_ORIGIN {
        waygate_mcp::authz::profile_blocks_resources(principal, server)
    } else {
        waygate_mcp::authz::profile_blocks_server(principal, server)
            || waygate_mcp::authz::profile_blocks_tool(principal, server, origin)
    }
}

pub(crate) struct FileServices {
    pub(crate) input_processor: Option<waygate_mcp::files::SharedFileInputProcessor>,
    pub(crate) output_processor: Option<waygate_mcp::files::SharedFileOutputProcessor>,
    pub(crate) tools: Option<waygate_mcp::builtin::SharedBuiltinTools>,
    pub(crate) native_download_authorizer: Option<waygate_mcp::files::SharedFileDownloadAuthorizer>,
    pub(crate) native_upload_authorizer: Option<waygate_mcp::files::SharedFileUploadAuthorizer>,
    pub(crate) admission: Option<FileTransferAdmission>,
}

pub(crate) use crate::file_transfer_config::FileRetention;

pub(crate) fn build_file_services(
    runtime: Option<&TransferRuntime>,
    catalog: SharedCatalog,
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    public_url: &str,
    retention: FileRetention,
    max_bytes: Option<u64>,
    max_concurrent_transfers: usize,
) -> anyhow::Result<FileServices> {
    // Transfer-mode and inline-constraint admission is schema policy, not
    // storage behavior: a gateway without file storage must still refuse a
    // value that uses a transport the tool did not admit, so the input
    // processor is present in every configuration.
    let storage_disabled = FileServices {
        input_processor: Some(Arc::new(AdmissionOnlyFileInputProcessor)),
        output_processor: None,
        tools: None,
        native_download_authorizer: None,
        native_upload_authorizer: None,
        admission: None,
    };
    let Some(runtime) = runtime else {
        return Ok(storage_disabled);
    };
    let Some(storage) = runtime.file_storage() else {
        return Ok(storage_disabled);
    };
    let public_transport = validate_file_public_url(public_url)?;
    let native_https = public_transport == "https";
    let admission = FileTransferAdmission::new(max_concurrent_transfers);
    let processor = Arc::new(OutboundFileProcessor::new(
        catalog,
        storage.clone(),
        runtime.audit.clone(),
        retention,
        max_bytes,
        admission.clone(),
        native_https,
    )?);
    Ok(FileServices {
        input_processor: Some(processor.clone()),
        output_processor: Some(processor),
        tools: Some(Arc::new(
            crate::mcp_files::GatewayFileTools::new(
                runtime.authority.clone(),
                storage.clone(),
                admission.clone(),
                quota.clone(),
                runtime.audit.clone(),
                public_url.to_owned(),
                public_transport.to_owned(),
            )
            .with_max_bytes(max_bytes),
        )),
        native_download_authorizer: Some(Arc::new(
            NativeFileAuthorizer::new(
                runtime.authority.clone(),
                storage.clone(),
                admission.clone(),
                quota.clone(),
                runtime.audit.clone(),
                public_url.to_owned(),
                native_https,
            )
            .with_max_bytes(max_bytes),
        )),
        native_upload_authorizer: Some(Arc::new(
            NativeFileAuthorizer::new(
                runtime.authority.clone(),
                storage,
                admission.clone(),
                quota,
                runtime.audit.clone(),
                public_url.to_owned(),
                native_https,
            )
            .with_max_bytes(max_bytes),
        )),
        admission: Some(admission),
    })
}

/// Canonical message for "this gateway's file storage could not serve the read
/// right now". Distinct from an unwired capability: reaching any of these sites
/// means storage IS configured and the call against it failed.
const FILE_STORAGE_UNAVAILABLE: &str = "gateway file storage is unavailable";

/// The control plane's reader for documents a maker uploaded, or `None` when
/// this deployment has no file storage — in which case a submission that names
/// a file is refused and inline submission is unaffected.
///
/// Deliberately not part of [`FileServices`]: those are the MCP wire adapters
/// for file transfer, and this serves the change-request submission path.
pub(crate) fn document_reader(
    runtime: Option<&TransferRuntime>,
) -> Option<Arc<dyn waygate_admin::param_files::ProposalFileReader>> {
    let storage = runtime?.file_storage()?;
    Some(Arc::new(StoredTextFileReader { storage }))
}

/// Owner-scoped bounded text reader shared by built-ins that consume an
/// already-uploaded gateway file themselves.
pub(crate) fn source_file_reader(
    runtime: Option<&TransferRuntime>,
) -> Option<SharedStoredTextReader> {
    let storage = runtime?.file_storage()?;
    Some(Arc::new(StoredTextFileReader { storage }))
}

/// Reads a stored gateway file as the text of a proposed change's document
/// param (`waygate_admin::param_files`).
///
/// The file plane's admission rules apply unchanged: the lookup is owner-scoped
/// and the caller's credential profile must still permit whatever produced the
/// file, so a maker can only submit a document it uploaded and is allowed to
/// use. A file that exists but is not the caller's is reported exactly like one
/// that does not exist.
///
/// It deliberately takes no [`FileTransferAdmission`] permit. That limit bounds
/// simultaneous file *streams*; this is a single bounded read of a local file
/// already resident in gateway storage, and spending a stream slot on it would
/// let data-plane transfer load refuse a control-plane proposal for reasons
/// that have nothing to do with it.
pub(crate) struct StoredTextFileReader {
    storage: Arc<GatewayFileStorage>,
}

pub(crate) struct StoredTextFile {
    pub(crate) text: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
}

pub(crate) enum StoredTextFileError {
    InvalidUri,
    NotFound,
    TooLarge { size: u64, max_bytes: usize },
    InvalidUtf8,
    Unavailable,
}

pub(crate) type SharedStoredTextReader = Arc<dyn StoredTextReader>;

#[async_trait]
pub(crate) trait StoredTextReader: Send + Sync + 'static {
    async fn read_text(
        &self,
        principal: &Principal,
        uri: &str,
        max_bytes: usize,
    ) -> Result<StoredTextFile, StoredTextFileError>;
}

/// Lowercase hex, for the non-secret digest recorded on the propose audit
/// entry.
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
        out
    })
}

#[async_trait]
impl StoredTextReader for StoredTextFileReader {
    async fn read_text(
        &self,
        principal: &Principal,
        uri: &str,
        max_bytes: usize,
    ) -> Result<StoredTextFile, StoredTextFileError> {
        let file_id = parse_gateway_file_uri(uri).map_err(|_| StoredTextFileError::InvalidUri)?;
        let file = self
            .storage
            .find_ready(&owner_from_principal(principal), file_id)
            .await
            .map_err(|error| {
                tracing::warn!(%file_id, error = %error, "gateway file lookup failed");
                StoredTextFileError::Unavailable
            })?
            .ok_or(StoredTextFileError::NotFound)?;
        // Same restriction the download path applies: holding the URI is not
        // authority to read the file if the caller's credential profile no
        // longer permits the tool that produced it. Indistinguishable from
        // absent, so this cannot be used to probe for a file's existence.
        if profile_blocks_file_origin(principal, &file.upstream_server, &file.upstream_tool) {
            return Err(StoredTextFileError::NotFound);
        }
        if file.size > max_bytes as u64 {
            return Err(StoredTextFileError::TooLarge {
                size: file.size,
                max_bytes,
            });
        }
        // Bound the read at the same ceiling rather than trusting the recorded
        // size: the check above uses stored metadata, and a read that ignored
        // the ceiling would turn a storage inconsistency into unbounded memory.
        let path = self.storage.path_for(&file);
        let mut bytes = Vec::with_capacity(file.size as usize);
        tokio::fs::File::open(&path)
            .await
            .map_err(|error| {
                tracing::warn!(%file_id, error = %error, "stored document could not be opened");
                StoredTextFileError::Unavailable
            })?
            .take(max_bytes as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| {
                tracing::warn!(%file_id, error = %error, "stored document could not be read");
                StoredTextFileError::Unavailable
            })?;
        // The propose audit entry states that the reviewed text came from this
        // file with this digest, and that entry is the only durable link back
        // to the upload. Re-verify rather than assume it: a short or altered
        // read would otherwise put a truncated manifest set or instruction in
        // front of an approver under a digest that describes something else.
        {
            use sha2::{Digest, Sha256};
            if Sha256::digest(&bytes).as_slice() != file.sha256.as_slice() {
                tracing::error!(
                    %file_id,
                    stored_size = file.size,
                    read_size = bytes.len(),
                    "stored document does not match its recorded digest",
                );
                return Err(StoredTextFileError::Unavailable);
            }
        }
        let text = String::from_utf8(bytes).map_err(|_| StoredTextFileError::InvalidUtf8)?;
        Ok(StoredTextFile {
            text,
            sha256: hex_digest(&file.sha256),
            size: file.size,
        })
    }
}

#[async_trait]
impl waygate_admin::param_files::ProposalFileReader for StoredTextFileReader {
    async fn read_text(
        &self,
        principal: &Principal,
        uri: &str,
        max_bytes: usize,
    ) -> Result<waygate_admin::param_files::ProposalFileContent, waygate_admin::error::ApiError>
    {
        use waygate_admin::error::ApiError;

        let file = StoredTextReader::read_text(self, principal, uri, max_bytes)
            .await
            .map_err(|error| match error {
                StoredTextFileError::InvalidUri => ApiError::BadRequest(format!(
                    "not a gateway file URI; expected `{}<id>` as returned by \
                     `gateway-files.prepare_upload`",
                    waygate_core::GATEWAY_FILE_URI_PREFIX,
                )),
                StoredTextFileError::NotFound => ApiError::BadRequest(
                    "the uploaded file is unavailable or expired; upload it again with \
                     `gateway-files.prepare_upload` and submit the fresh URI"
                        .to_owned(),
                ),
                StoredTextFileError::TooLarge { size, max_bytes } => ApiError::BadRequest(format!(
                    "the uploaded file is {size} bytes; this action accepts at most \
                         {max_bytes} bytes because the review queue renders the complete \
                         document for the approver"
                )),
                StoredTextFileError::InvalidUtf8 => ApiError::BadRequest(
                    "the uploaded file is not valid UTF-8 text; this field takes a text document"
                        .to_owned(),
                ),
                StoredTextFileError::Unavailable => {
                    ApiError::ServiceUnavailable(FILE_STORAGE_UNAVAILABLE)
                }
            })?;
        Ok(waygate_admin::param_files::ProposalFileContent {
            text: file.text,
            sha256: file.sha256,
            size: file.size,
        })
    }
}

#[derive(Clone)]
pub(crate) struct OutboundFileProcessor {
    catalog: SharedCatalog,
    storage: Arc<GatewayFileStorage>,
    audit: SharedEvidence,
    http: reqwest::Client,
    #[cfg(test)]
    additional_root_certificates: Vec<reqwest::Certificate>,
    retention: FileRetention,
    /// Retention for files whose authorization declared them secret-class.
    max_bytes: Option<u64>,
    admission: FileTransferAdmission,
    native_https: bool,
    resource_preparation_timeout: Duration,
}

struct PreparedFileDelivery {
    file: StoredGatewayFile,
    upload_name: Option<String>,
    upstream_file: FileValue,
    descriptor: FileTransferDescriptor,
    headers: HeaderMap,
    url: url::Url,
    network: waygate_mcp::files::FileTransferNetwork,
    delivery_target: String,
}

impl OutboundFileProcessor {
    pub(crate) fn new(
        catalog: SharedCatalog,
        storage: Arc<GatewayFileStorage>,
        audit: SharedEvidence,
        retention: FileRetention,
        max_bytes: Option<u64>,
        admission: FileTransferAdmission,
        native_https: bool,
    ) -> anyhow::Result<Self> {
        let http =
            waygate_core::http_client::builder(waygate_core::http_client::Profile::NoTotalTimeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build outbound file client")?;
        Ok(Self {
            catalog,
            storage,
            audit,
            http,
            #[cfg(test)]
            additional_root_certificates: Vec::new(),
            retention,
            max_bytes,
            admission,
            native_https,
            resource_preparation_timeout: resource_file_preparation_timeout(),
        })
    }

    async fn discard_resource_batch_bounded(&self, batch_id: uuid::Uuid) {
        match tokio::time::timeout(
            RESOURCE_FILE_CLEANUP_TIMEOUT,
            self.storage.discard_batch(batch_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%batch_id, %error, "file batch cleanup failed");
            }
            Err(_) => {
                tracing::warn!(%batch_id, "file batch cleanup exceeded its deadline");
            }
        }
    }

    /// `budget` is what remains of the CALL's byte allowance, not the
    /// per-file cap. One tool result can carry many files, so capping each one
    /// individually leaves the call itself unbounded — a compromised upstream
    /// returning enough references still exhausts the volume. Passing the
    /// remaining allowance makes the per-file guard enforce the cumulative
    /// bound too, and the consumed size comes back so the caller can decrement.
    async fn stage_file(
        &self,
        context: &FileOutputContext,
        principal: &Principal,
        batch_id: uuid::Uuid,
        budget: Option<u64>,
        upstream_file: FileValue,
    ) -> Result<(FileValue, uuid::Uuid, u64), McpError> {
        let _permit = self.admission.try_enter().map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TemporarilyUnavailable,
                "file transfer capacity is currently full; retry later",
            )
        })?;
        let authorized = self
            .catalog
            .authorize_file_download(
                &context.server,
                AuthorizeDownloadParams {
                    meta: waygate_mcp::files::stateless_client_capability_meta(
                        waygate_mcp::files::FileOperation::Download,
                    ),
                    uri: upstream_file.uri.clone(),
                },
                Some(principal),
            )
            .await?;
        let claims = authorized_file_claims(&upstream_file, &authorized.response.file)?;
        let cleartext = authorized.network.admits_cleartext_transfer();
        if authorized.response.download.method != TransferMethod::GET
            || !transport_admitted(&authorized.response.download.transport, cleartext)
        {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file download descriptor is not an admissible GET for this destination",
            ));
        }
        verify_descriptor_expiry(authorized.response.download.expires_at.as_deref())?;
        let url = url::Url::parse(&authorized.response.download.url).map_err(|_| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream returned an invalid file URL",
            )
        })?;
        if !scheme_admitted(
            url.scheme(),
            &authorized.response.download.transport,
            cleartext,
        ) || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file transfer URL is not admissible for this destination, does not \
                 match its declared transport, or carries userinfo",
            ));
        }
        let headers = descriptor_headers(&authorized.response.download.headers)?;
        let expected_sha256 = decode_sha256(claims.digest.as_ref())?;
        // A secret-class file's delivery copy lives about as long as its handoff:
        // the staged row's own expiry carries the short window, and publication
        // never extends it past what staging promised.
        let selected_retention = match authorized.response.sensitivity {
            Some(waygate_mcp::files::FileSensitivity::Secret) => self.retention.secret,
            None => self.retention.general,
        };
        let retention = time::Duration::try_from(selected_retention).map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TransferFailed,
                "file retention is too large",
            )
        })?;
        let http = self.client_for_transfer(&url, &authorized.network).await?;
        let response = http
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(server = %context.server, error = %error.without_url(), "upstream file request failed");
                file_transfer_failure(FileTransferReason::TransferFailed, "upstream file request failed")
            })?;
        if let Err(error) = verify_complete_response_status(response.status()) {
            tracing::warn!(server = %context.server, status = %response.status(), "upstream file request was refused");
            return Err(error);
        }
        verify_response_media_type(claims.mime_type.as_deref(), response.headers())?;
        let stored = self
            .storage
            .stage_response(
                NewGatewayFile {
                    batch_id,
                    owner: owner_from_principal(principal),
                    invocation_id: context.invocation_id.clone(),
                    upstream_server: context.server.clone(),
                    upstream_tool: context.tool.clone(),
                    upstream_uri: upstream_file.uri,
                    display_name: upstream_file.name,
                    media_type: upstream_file.mime_type,
                    expected_size: claims.size,
                    expected_sha256,
                    max_bytes: budget,
                    // A file is only marked checked when an installed scanner
                    // actually inspected it. Missing scanner coverage remains
                    // visible without blocking an otherwise valid transfer.
                    inspection_status: FileInspectionStatus::Uninspectable,
                    retention,
                },
                response,
            )
            .await
            .map_err(|error| {
                tracing::warn!(server = %context.server, error = %error, "upstream file could not be saved");
                // Integrity outcomes are their own category: a corrupted or
                // inconsistent transfer must not route as a retryable
                // movement failure.
                match error {
                    waygate_transfer::FileStorageError::SizeMismatch
                    | waygate_transfer::FileStorageError::DigestMismatch => invalid_file_request(
                        FileTransferReason::IntegrityMismatch,
                        "upstream file did not match its declared size or digest",
                    ),
                    waygate_transfer::FileStorageError::TooLarge => invalid_file_request(
                        FileTransferReason::QuotaExhausted,
                        "upstream file exceeded the configured size limit",
                    ),
                    _ => file_transfer_failure(
                        FileTransferReason::TransferFailed,
                        "upstream file could not be saved or verified",
                    ),
                }
            })?;

        let file_uri = stored.uri();
        let evidence_target = serde_json::json!({
            "file_uri": file_uri,
            "inspection_status": stored.inspection_status.as_str(),
            "invocation_id": stored.invocation_id,
        })
        .to_string();
        for action in [
            "file_transfer.bytes.received",
            "file_transfer.file.verified",
        ] {
            let event = AuditEvent::new(action, AuditOutcome::Success)
                .with_category(EvidenceCategory::FileTransfer)
                .with_tenant(principal.tenant.clone())
                .with_principal(Some(principal))
                .with_tool(&context.server, &context.tool)
                .with_target(evidence_target.clone());
            self.audit.record_required(event).await.map_err(|error| {
                tracing::warn!(server = %context.server, error = %error, "file transfer evidence could not be recorded");
                file_transfer_failure(FileTransferReason::TransferFailed, "file transfer evidence could not be recorded")
            })?;
        }

        Ok((
            FileValue {
                uri: file_uri,
                name: stored.display_name,
                mime_type: stored.media_type,
                size: Some(stored.size),
                digest: Some(FileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: URL_SAFE_NO_PAD.encode(&stored.sha256),
                }),
            },
            stored.id,
            stored.size,
        ))
    }

    async fn stage_file_with_batch_heartbeat(
        &self,
        context: &FileOutputContext,
        principal: &Principal,
        batch_id: uuid::Uuid,
        active_file_id: Option<uuid::Uuid>,
        budget: Option<u64>,
        upstream_file: FileValue,
    ) -> Result<(FileValue, uuid::Uuid, u64), McpError> {
        let Some(active_file_id) = active_file_id else {
            return self
                .stage_file(context, principal, batch_id, budget, upstream_file)
                .await;
        };
        let mut heartbeat = tokio::time::interval(waygate_transfer::PENDING_HEARTBEAT_INTERVAL);
        heartbeat.tick().await;
        let stage = self.stage_file(context, principal, batch_id, budget, upstream_file);
        tokio::pin!(stage);
        loop {
            tokio::select! {
                result = &mut stage => return result,
                _ = heartbeat.tick() => {
                    self.storage
                        .heartbeat_pending_batch(batch_id, active_file_id)
                        .await
                        .map_err(|error| {
                            tracing::warn!(%batch_id, error = %error, "pending file batch could not be renewed");
                            file_transfer_failure(FileTransferReason::TransferFailed, "gateway file batch expired during preparation")
                        })?;
                }
            }
        }
    }

    async fn prepare_file_delivery(
        &self,
        context: &FileInputContext,
        principal: &Principal,
        supplied: &FileValue,
        constraints: &[FileInputDescriptor],
    ) -> Result<PreparedFileDelivery, McpError> {
        let file_id = parse_gateway_file_uri(&supplied.uri)?;
        let file = self
            .storage
            .find_ready(&owner_from_principal(principal), file_id)
            .await
            .map_err(|error| {
                tracing::warn!(%file_id, error = %error, "gateway file lookup failed");
                file_transfer_failure(
                    FileTransferReason::TemporarilyUnavailable,
                    "gateway file storage is unavailable",
                )
            })?
            .ok_or_else(|| {
                invalid_file_request(
                    FileTransferReason::FileUnavailable,
                    "file is unavailable or expired",
                )
            })?;
        enforce_file_input_constraints(
            constraints,
            file.media_type.as_deref(),
            file.display_name.as_deref(),
            file.size,
        )?;
        if profile_blocks_file_origin(principal, &file.upstream_server, &file.upstream_tool) {
            return Err(invalid_file_request(
                FileTransferReason::FileUnavailable,
                "file is unavailable or expired",
            ));
        }
        let digest = FileDigest {
            algorithm: "sha-256".to_owned(),
            value: URL_SAFE_NO_PAD.encode(&file.sha256),
        };
        let authorized = self
            .catalog
            .authorize_file_upload(
                &context.server,
                &context.tool,
                AuthorizeUploadParams {
                    meta: waygate_mcp::files::stateless_client_capability_meta(
                        waygate_mcp::files::FileOperation::Upload,
                    ),
                    name: supplied.name.clone().or(file.display_name.clone()),
                    mime_type: file.media_type.clone(),
                    size: Some(file.size),
                    digest: Some(digest.clone()),
                },
                Some(principal),
                &context.admitted_contract,
            )
            .await?;
        let mut upstream_file = validate_authorized_upload(
            &authorized.response.file,
            file.media_type.as_deref(),
            file.size,
            &digest,
        )?;
        let descriptor = &authorized.response.upload;
        let cleartext = authorized.network.admits_cleartext_transfer();
        if !matches!(
            descriptor.method,
            TransferMethod::PUT | TransferMethod::POST
        ) || !transport_admitted(&descriptor.transport, cleartext)
        {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file upload descriptor is not an admissible PUT or POST for this destination",
            ));
        }
        verify_descriptor_expiry(descriptor.expires_at.as_deref())?;
        let url = url::Url::parse(&descriptor.url).map_err(|_| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream returned an invalid file URL",
            )
        })?;
        if !scheme_admitted(url.scheme(), &descriptor.transport, cleartext)
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file upload URL is not admissible for this destination, does not \
                 match its declared transport, or carries userinfo",
            ));
        }
        let headers = descriptor_headers(&descriptor.headers)?;
        let delivery_target = serde_json::json!({
            "file_uri": file.uri(),
            "preparation_invocation_id": file.invocation_id,
            "consuming_invocation_id": context.invocation_id,
            "destination_server": context.server,
            "destination_tool": context.tool,
        })
        .to_string();
        upstream_file.name = upstream_file.name.or(supplied.name.clone());
        upstream_file.mime_type = file.media_type.clone();
        upstream_file.size = Some(file.size);
        upstream_file.digest = Some(digest);
        Ok(PreparedFileDelivery {
            upload_name: supplied.name.clone().or(file.display_name.clone()),
            file,
            upstream_file,
            descriptor: descriptor.clone(),
            headers,
            url,
            network: authorized.network,
            delivery_target,
        })
    }

    async fn execute_file_delivery(
        &self,
        context: &FileInputContext,
        principal: &Principal,
        delivery: PreparedFileDelivery,
    ) -> Result<(), McpError> {
        let _permit = self.admission.try_enter().map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TemporarilyUnavailable,
                "file transfer capacity is currently full; retry later",
            )
        })?;
        let http = self
            .client_for_transfer(&delivery.url, &delivery.network)
            .await?;
        let body = file_body(self.storage.path_for(&delivery.file)).await?;
        let mut request = match delivery.descriptor.method {
            TransferMethod::PUT => http.put(delivery.url),
            TransferMethod::POST => http.post(delivery.url),
            TransferMethod::GET => unreachable!("upload method checked during preparation"),
        }
        .headers(delivery.headers.clone());
        if let Some(multipart) = delivery.descriptor.multipart.as_ref() {
            let mut part = reqwest::multipart::Part::stream_with_length(body, delivery.file.size);
            if let Some(name) = delivery.upload_name.as_ref() {
                part = part.file_name(name.clone());
            }
            if let Some(media_type) = delivery.file.media_type.as_ref() {
                part = part.mime_str(media_type).map_err(|_| {
                    invalid_file_request(
                        FileTransferReason::IntegrityMismatch,
                        "stored file media type is invalid",
                    )
                })?;
            }
            let mut form = reqwest::multipart::Form::new();
            for (name, value) in &multipart.fields {
                form = form.text(name.clone(), value.clone());
            }
            request = request.multipart(form.part(multipart.file_field.clone(), part));
        } else {
            request = request
                .header(CONTENT_LENGTH, delivery.file.size)
                .body(body);
            if !delivery.headers.contains_key(CONTENT_TYPE) {
                if let Some(media_type) = delivery.file.media_type.as_ref() {
                    request = request.header(CONTENT_TYPE, media_type);
                }
            }
        }
        self.audit
            .record_required(
                AuditEvent::new(
                    "file_transfer.file.delivery_started",
                    AuditOutcome::Success,
                )
                .with_category(EvidenceCategory::FileTransfer)
                .with_tenant(principal.tenant.clone())
                .with_principal(Some(principal))
                .with_tool(&context.server, &context.tool)
                .with_target(delivery.delivery_target.clone()),
            )
            .await
            .map_err(|error| {
                tracing::warn!(server = %context.server, error = %error, "file delivery evidence could not be started");
                file_transfer_failure(FileTransferReason::TransferFailed, "file delivery evidence could not be recorded")
            })?;
        let response = request.send().await.map_err(|error| {
            tracing::warn!(server = %context.server, error = %error.without_url(), "upstream file upload failed");
            file_transfer_failure(FileTransferReason::TransferFailed, "upstream file upload failed")
        })?;
        if let Err(error) = verify_upload_response_status(response.status()) {
            tracing::warn!(server = %context.server, status = %response.status(), "upstream file upload was refused");
            return Err(error);
        }
        self.audit
            .record_required(
                AuditEvent::new("file_transfer.file.delivered", AuditOutcome::Success)
                    .with_category(EvidenceCategory::FileTransfer)
                    .with_tenant(principal.tenant.clone())
                    .with_principal(Some(principal))
                    .with_tool(&context.server, &context.tool)
                    .with_target(delivery.delivery_target),
            )
            .await
            .map_err(|error| {
                tracing::warn!(server = %context.server, error = %error, "file delivery evidence could not be recorded");
                file_transfer_failure(FileTransferReason::TransferFailed, "file delivery evidence could not be recorded")
            })?;
        Ok(())
    }

    async fn client_for_transfer(
        &self,
        url: &url::Url,
        network: &waygate_mcp::files::FileTransferNetwork,
    ) -> Result<reqwest::Client, McpError> {
        let host = url.host_str().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file transfer URL has no host",
            )
        })?;
        let port = url.port_or_known_default().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file transfer URL has no port",
            )
        })?;
        let pinned = match network {
            waygate_mcp::files::FileTransferNetwork::Public => {
                resolve_public_file_destination(host, port).await?
            }
            waygate_mcp::files::FileTransferNetwork::Pinned { addresses, .. } => addresses.clone(),
            waygate_mcp::files::FileTransferNetwork::Local => return Ok(self.http.clone()),
        };
        let mut builder =
            waygate_core::http_client::builder(waygate_core::http_client::Profile::NoTotalTimeout)
                .redirect(reqwest::redirect::Policy::none());
        #[cfg(test)]
        {
            for certificate in &self.additional_root_certificates {
                builder = builder.add_root_certificate(certificate.clone());
            }
        }
        let pinned = pinned
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        builder = builder.resolve_to_addrs(host, &pinned);
        builder.build().map_err(|error| {
            tracing::warn!(error = %error.without_url(), "upstream file client could not be built");
            file_transfer_failure(
                FileTransferReason::TransferFailed,
                "upstream file request could not be prepared",
            )
        })
    }
}

fn collect_resource_file_values(
    result: &ReadResourceResult,
) -> Result<Vec<(usize, FileValue)>, McpError> {
    let mut files = Vec::new();
    for (index, contents) in result.contents.iter().enumerate() {
        let meta = match contents {
            ResourceContents::TextResourceContents { meta, .. }
            | ResourceContents::BlobResourceContents { meta, .. } => meta.as_ref(),
            _ => None,
        };
        let Some(value) =
            meta.and_then(|meta| meta.get(waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY))
        else {
            continue;
        };
        if files.len() == limits().file_count {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                format!(
                    "file-backed resource output exceeds the {}-file limit",
                    limits().file_count
                ),
            ));
        }
        let file = serde_json::from_value::<FileValue>(value.clone()).map_err(|_| {
            invalid_file_request(
                FileTransferReason::InvalidFileInput,
                "file-backed resource metadata is malformed",
            )
        })?;
        files.push((index, file));
    }
    Ok(files)
}

async fn file_body(path: std::path::PathBuf) -> Result<reqwest::Body, McpError> {
    let file = tokio::fs::File::open(path).await.map_err(|error| {
        tracing::warn!(error = %error, "stored gateway file could not be opened");
        file_transfer_failure(
            FileTransferReason::TemporarilyUnavailable,
            "gateway file storage is unavailable",
        )
    })?;
    let stream = futures::stream::try_unfold(file, |mut file| async move {
        let mut chunk = vec![0_u8; 64 * 1024];
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        chunk.truncate(read);
        Ok(Some((bytes::Bytes::from(chunk), file)))
    });
    Ok(reqwest::Body::wrap_stream(stream))
}

async fn resolve_public_file_destination(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::IpAddr>, McpError> {
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "upstream file destination could not be resolved");
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file destination could not be resolved",
            )
        })?;
    let mut pinned = Vec::new();
    for address in addresses {
        if !waygate_core::net::is_public_ip(&address.ip()) {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file destination is not allowed",
            ));
        }
        if !pinned.contains(&address.ip()) {
            pinned.push(address.ip());
        }
    }
    if pinned.is_empty() {
        return Err(invalid_file_request(
            FileTransferReason::PolicyViolation,
            "upstream file destination could not be resolved",
        ));
    }
    Ok(pinned)
}

fn verify_complete_response_status(status: reqwest::StatusCode) -> Result<(), McpError> {
    if status == reqwest::StatusCode::OK {
        Ok(())
    } else {
        Err(file_transfer_failure(
            FileTransferReason::TransferFailed,
            "upstream file request did not return a complete representation",
        ))
    }
}

fn verify_upload_response_status(status: reqwest::StatusCode) -> Result<(), McpError> {
    if matches!(
        status,
        reqwest::StatusCode::OK | reqwest::StatusCode::CREATED | reqwest::StatusCode::NO_CONTENT
    ) {
        Ok(())
    } else {
        Err(file_transfer_failure(
            FileTransferReason::TransferFailed,
            "upstream file upload did not confirm complete storage",
        ))
    }
}

#[async_trait]
impl FileInputProcessor for OutboundFileProcessor {
    fn admit(
        &self,
        input_schema: Option<&Value>,
        compiled: Option<&jsonschema::Validator>,
        arguments: &mut Option<Map<String, Value>>,
        input_responses: Option<&BTreeMap<String, Value>>,
        deliverable_keys: &[String],
    ) -> Result<(), McpError> {
        // A gateway file reference the retry will not deliver must never
        // reach the upstream unresolved: `deliverable_keys` is empty when no
        // verified continuation authorized delivery here (no seal key, an
        // unverified retry, or a pause that asked for no file), so any
        // reference present is refused before quota rather than forwarded.
        refuse_undeliverable_continuation_files(input_responses, deliverable_keys)?;
        admit_file_arguments(input_schema, compiled, arguments).map(|_| ())
    }

    async fn prepare(
        &self,
        context: FileInputContext,
        input_schema: Option<&Value>,
        arguments: &mut Option<Map<String, Value>>,
    ) -> Result<bool, McpError> {
        let (Some(schema), Some(arguments)) = (input_schema, arguments.as_mut()) else {
            return Ok(false);
        };
        let mut root = Value::Object(arguments.clone());
        let files = collect_file_inputs(schema, context.compiled_input_schema.as_deref(), &root)?;
        if files.is_empty() {
            *arguments = root
                .as_object_mut()
                .map(std::mem::take)
                .expect("invocation arguments remain an object");
            return Ok(false);
        }
        let principal = context.principal.as_ref().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file input requires an authenticated caller",
            )
        })?;
        let mut replacements = Vec::with_capacity(files.len());
        let mut deliveries = Vec::with_capacity(files.len());
        for input in files {
            let delivery = self
                .prepare_file_delivery(&context, principal, &input.file, &input.constraints)
                .await?;
            let value = replacement_file_value(&input, delivery.upstream_file.clone())?;
            replacements.push((input.path, value));
            deliveries.push(delivery);
        }
        for (path, replacement) in replacements {
            replace_value_at_path(&mut root, &path, replacement)?;
        }
        let local;
        let validator = match context.compiled_input_schema.as_deref() {
            Some(validator) => validator,
            None => {
                local = jsonschema::validator_for(schema).map_err(|_| {
                    file_transfer_failure(
                        FileTransferReason::InvalidToolContract,
                        "tool has an invalid file input schema",
                    )
                })?;
                &local
            }
        };
        if !validator.is_valid(&root) {
            return Err(invalid_file_request(
                FileTransferReason::InvalidToolContract,
                "prepared file input does not satisfy the tool schema",
            ));
        }
        for delivery in deliveries {
            self.execute_file_delivery(&context, principal, delivery)
                .await?;
        }
        *arguments = root
            .as_object_mut()
            .map(std::mem::take)
            .expect("invocation arguments remain an object");
        Ok(true)
    }

    async fn prepare_continuation(
        &self,
        context: FileInputContext,
        input_responses: &mut BTreeMap<String, Value>,
        file_keys: &[String],
    ) -> Result<bool, McpError> {
        // Gather every reference first: one quota-charged call must not turn
        // into unbounded upstream allocations and outbound transfers. A file
        // repeated across the continuation is delivered once and its
        // upstream reference reused, and the number of distinct files is
        // bounded — a caller with a legitimate elicitation answer needs a
        // handful, not thousands. Two ceilings apply: collection stops once
        // it has accumulated more locations than an answer may mention, and
        // the distinct-file bound is enforced as the walk finds each new
        // file rather than after it finishes. Membership is a set lookup.
        // What a caller can force is therefore bounded in both allocation
        // and comparisons, instead of growing with the square of however
        // many distinct references it chose to send.
        let mut locations: Vec<(String, Vec<JsonPathPart>, String)> = Vec::new();
        let mut distinct: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (key, value) in input_responses.iter() {
            let mut found = Vec::new();
            let mut path = Vec::new();
            collect_gateway_file_uris(value, &mut path, &mut found);
            // A file may travel only where the sealed pause asked for one.
            if !found.is_empty() && !file_keys.iter().any(|allowed| allowed == key) {
                return Err(invalid_file_request(
                    FileTransferReason::PolicyViolation,
                    "the elicitation this retry answers did not request a file here",
                ));
            }
            // The ceiling is on the whole continuation, not on each answer
            // within it: a pause with several elicitation keys must not be
            // able to multiply what one retry may accumulate.
            if found.len() > limits().file_locations
                || locations.len() + found.len() > limits().file_locations
            {
                return Err(invalid_file_request(
                    FileTransferReason::QuotaExhausted,
                    format!(
                        "an elicitation response may mention at most \
                         {} file references",
                        limits().file_locations
                    ),
                ));
            }
            for (location, uri) in found {
                if seen.insert(uri.clone()) {
                    if distinct.len() == limits().file_count {
                        return Err(invalid_file_request(
                            FileTransferReason::QuotaExhausted,
                            format!(
                                "an elicitation response may carry at most \
                                 {} distinct files",
                                limits().file_count
                            ),
                        ));
                    }
                    distinct.push(uri.clone());
                }
                locations.push((key.clone(), location, uri));
            }
        }
        if locations.is_empty() {
            return Ok(false);
        }
        let principal = context.principal.as_ref().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file input requires an authenticated caller",
            )
        })?;

        // Deliver each distinct file exactly once. Each follows the ordinary
        // delivery path: ownership, credential-profile, and invocation
        // binding are checked, a fresh upstream authorization is obtained,
        // and the bytes stream before the retry is dispatched. There is no
        // gateway-trusted elicitation schema, so no declared constraint list
        // applies here; the asking upstream validates its own elicited
        // values on receipt.
        let mut delivered: BTreeMap<String, String> = BTreeMap::new();
        for uri in distinct {
            let supplied = FileValue {
                uri: uri.clone(),
                name: None,
                mime_type: None,
                size: None,
                digest: None,
            };
            let delivery = self
                .prepare_file_delivery(&context, principal, &supplied, &[])
                .await?;
            let upstream_uri = delivery.upstream_file.uri.clone();
            self.execute_file_delivery(&context, principal, delivery)
                .await?;
            delivered.insert(uri, upstream_uri);
        }
        for (key, location, uri) in locations {
            let replacement = Value::String(
                delivered
                    .get(&uri)
                    .expect("every collected reference was delivered")
                    .clone(),
            );
            let value = input_responses
                .get_mut(&key)
                .expect("continuation keys are stable across delivery");
            replace_value_at_path(value, &location, replacement)?;
        }
        Ok(true)
    }
}

/// Refuse gateway file references in a continuation that this retry will not
/// deliver. Without this they would travel to the upstream as opaque
/// `mcp-file://gateway/…` strings it cannot resolve.
fn refuse_undeliverable_continuation_files(
    input_responses: Option<&BTreeMap<String, Value>>,
    deliverable_keys: &[String],
) -> Result<(), McpError> {
    let Some(responses) = input_responses else {
        return Ok(());
    };
    for (key, value) in responses {
        if deliverable_keys.iter().any(|allowed| allowed == key) {
            continue;
        }
        let mut found = Vec::new();
        let mut path = Vec::new();
        collect_gateway_file_uris(value, &mut path, &mut found);
        if !found.is_empty() {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "this retry cannot deliver a file here; the elicitation it answers did not \
                 request one, or this gateway is not configured to authorize elicited files",
            ));
        }
    }
    Ok(())
}

/// One deadline spans every file marker in a resource response. Per-request
/// HTTP timeouts are insufficient because a server can return many fast files
/// whose cumulative staging work still monopolizes the read.
fn resource_file_preparation_timeout() -> Duration {
    Duration::from_secs(limits().file_preparation_seconds)
}
const RESOURCE_FILE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Collect the locations of caller-owned gateway file references inside a
/// caller-authored continuation value. Only the self-describing
/// `mcp-file://gateway/` namespace is collected: continuation values have no
/// gateway-trusted schema, and nothing else may be treated as a file.
///
/// Collection stops after one more than the configured file-reference location limit.
/// Callers treat that extra entry as a refusal rather than a truncation: a
/// response that mentions more references than that is over the bound
/// whatever the remainder holds, so there is nothing left to learn by
/// walking it.
fn collect_gateway_file_uris(
    value: &Value,
    path: &mut Vec<JsonPathPart>,
    found: &mut Vec<(Vec<JsonPathPart>, String)>,
) {
    if found.len() > limits().file_locations {
        return;
    }
    match value {
        Value::String(text) => {
            if is_gateway_file_uri(text) {
                found.push((path.clone(), text.clone()));
            }
        }
        Value::Object(object) => {
            for (key, member) in object {
                path.push(JsonPathPart::Key(key.clone()));
                collect_gateway_file_uris(member, path, found);
                path.pop();
                if found.len() > limits().file_locations {
                    return;
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(JsonPathPart::Index(index));
                collect_gateway_file_uris(item, path, found);
                path.pop();
                if found.len() > limits().file_locations {
                    return;
                }
            }
        }
        _ => {}
    }
}

#[async_trait]
impl FileOutputProcessor for OutboundFileProcessor {
    fn retained_response_max_bytes(&self) -> Option<usize> {
        self.max_bytes.and_then(|bytes| usize::try_from(bytes).ok())
    }

    async fn prepare_retained(
        &self,
        context: FileOutputContext,
        body: waygate_mcp::files::RetainedFileBody,
    ) -> Result<waygate_mcp::files::PreparedRetainedFile, McpError> {
        let principal = context.principal.as_ref().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "retained response files require an authenticated caller",
            )
        })?;
        let _permit = self.admission.try_enter().map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TemporarilyUnavailable,
                "file transfer capacity is currently full",
            )
        })?;
        let batch_id = uuid::Uuid::new_v4();
        let retention = if body.sensitive {
            self.retention.secret
        } else {
            self.retention.general
        };
        let retention = time::Duration::try_from(retention).map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TransferFailed,
                "file retention is too large",
            )
        })?;
        let staged = self
            .storage
            .stage_bytes(
                NewGatewayFile {
                    batch_id,
                    owner: owner_from_principal(principal),
                    invocation_id: context.invocation_id.clone(),
                    upstream_server: context.server.clone(),
                    upstream_tool: NATIVE_RESOURCE_FILE_ORIGIN.to_owned(),
                    upstream_uri: body.upstream_uri,
                    display_name: None,
                    media_type: Some(body.media_type),
                    expected_size: Some(body.bytes.len() as u64),
                    expected_sha256: None,
                    max_bytes: self.max_bytes,
                    inspection_status: FileInspectionStatus::Uninspectable,
                    retention,
                },
                body.bytes,
            )
            .await;
        let stored = match staged {
            Ok(stored) => stored,
            Err(error) => {
                self.discard_resource_batch_bounded(batch_id).await;
                tracing::warn!(server = %context.server, %error, "retained response staging failed");
                return Err(file_transfer_failure(
                    FileTransferReason::TransferFailed,
                    "retained response could not be staged",
                ));
            }
        };
        let evidence = AuditEvent::new("file_transfer.file.verified", AuditOutcome::Success)
            .with_category(EvidenceCategory::FileTransfer)
            .with_tenant(principal.tenant.clone())
            .with_principal(Some(principal))
            .with_tool(&context.server, &context.tool)
            .with_target(
                serde_json::json!({"file_uri": stored.uri(),
                "invocation_id": context.invocation_id,
                "inspection_status": stored.inspection_status.as_str()})
                .to_string(),
            );
        if let Err(error) = self.audit.record_required(evidence).await {
            self.discard_resource_batch_bounded(batch_id).await;
            tracing::warn!(%error, "retained response evidence could not be recorded");
            return Err(file_transfer_failure(
                FileTransferReason::TransferFailed,
                "retained response evidence could not be recorded",
            ));
        }
        Ok(waygate_mcp::files::PreparedRetainedFile {
            file: FileValue {
                uri: stored.uri(),
                name: stored.display_name,
                mime_type: stored.media_type,
                size: Some(stored.size),
                digest: Some(FileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: URL_SAFE_NO_PAD.encode(&stored.sha256),
                }),
            },
            batch_id: batch_id.to_string(),
        })
    }

    fn native_https_available(&self) -> bool {
        self.native_https
    }

    async fn prepare(
        &self,
        context: FileOutputContext,
        mut result: CallToolResult,
    ) -> Result<PreparedFileOutput, McpError> {
        let Some(structured) = result.structured_content.as_mut() else {
            return Ok(PreparedFileOutput {
                result,
                batch_id: None,
                file_count: 0,
            });
        };
        let files = collect_file_values(structured)?;
        if files.is_empty() {
            return Ok(PreparedFileOutput {
                result,
                batch_id: None,
                file_count: 0,
            });
        }
        let principal = context.principal.as_ref().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file output requires an authenticated caller",
            )
        })?;
        let batch_id = uuid::Uuid::new_v4();
        let mut replacements = Vec::with_capacity(files.len());
        let mut active_file_id = None;
        // The size cap bounds the CALL, not just each file in it. A result
        // carrying many references would otherwise pass a per-file check while
        // its total still filled the volume, so each file is admitted against
        // what the earlier ones left rather than against the full limit.
        let mut budget = self.max_bytes;
        for (path, file) in files {
            match self
                .stage_file_with_batch_heartbeat(
                    &context,
                    principal,
                    batch_id,
                    active_file_id,
                    budget,
                    file,
                )
                .await
            {
                Ok((replacement, stored_file_id, staged_bytes)) => {
                    budget = budget.map(|left| left.saturating_sub(staged_bytes));
                    replacements.push((path, replacement));
                    active_file_id = Some(stored_file_id);
                }
                Err(error) => {
                    if let Err(cleanup_error) = self.storage.discard_batch(batch_id).await {
                        tracing::warn!(%batch_id, error = %cleanup_error, "file batch cleanup failed");
                    }
                    return Err(error);
                }
            }
        }
        let file_count = replacements.len();
        for (path, replacement) in replacements {
            if let Err(error) = replace_file_at_path(structured, &path, replacement) {
                if let Err(cleanup_error) = self.storage.discard_batch(batch_id).await {
                    tracing::warn!(%batch_id, error = %cleanup_error, "file batch cleanup failed");
                }
                return Err(error);
            }
        }
        Ok(PreparedFileOutput {
            result,
            batch_id: Some(batch_id.to_string()),
            file_count,
        })
    }

    async fn prepare_resource(
        &self,
        context: FileOutputContext,
        mut result: ReadResourceResult,
    ) -> Result<PreparedResourceOutput, McpError> {
        let files = collect_resource_file_values(&result)?;
        if files.is_empty() {
            return Ok(PreparedResourceOutput {
                result,
                batch_id: None,
                file_count: 0,
            });
        }
        let principal = context.principal.as_ref().ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file-backed resource output requires an authenticated caller",
            )
        })?;
        let batch_id = uuid::Uuid::new_v4();
        let mut replacements = Vec::with_capacity(files.len());
        let mut active_file_id = None;
        let mut budget = self.max_bytes;
        let deadline = tokio::time::Instant::now() + self.resource_preparation_timeout;
        for (index, file) in files {
            let staged = tokio::time::timeout_at(
                deadline,
                self.stage_file_with_batch_heartbeat(
                    &context,
                    principal,
                    batch_id,
                    active_file_id,
                    budget,
                    file,
                ),
            )
            .await;
            match staged {
                Ok(Ok((replacement, stored_file_id, staged_bytes))) => {
                    budget = budget.map(|left| left.saturating_sub(staged_bytes));
                    replacements.push((index, replacement));
                    active_file_id = Some(stored_file_id);
                }
                Ok(Err(error)) => {
                    self.discard_resource_batch_bounded(batch_id).await;
                    return Err(error);
                }
                Err(_) => {
                    self.discard_resource_batch_bounded(batch_id).await;
                    return Err(file_transfer_failure(
                        FileTransferReason::TransferFailed,
                        "file-backed resource preparation exceeded its overall deadline",
                    ));
                }
            }
        }
        let mut rewrite_error = None;
        for (index, replacement) in &replacements {
            let meta = match &mut result.contents[*index] {
                ResourceContents::TextResourceContents { meta, .. }
                | ResourceContents::BlobResourceContents { meta, .. } => meta.as_mut(),
                _ => None,
            };
            let Some(meta) = meta else {
                rewrite_error = Some(file_transfer_failure(
                    FileTransferReason::TransferFailed,
                    "file-backed resource metadata disappeared during transfer",
                ));
                break;
            };
            match serde_json::to_value(replacement) {
                Ok(replacement) => {
                    meta.insert(
                        waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY.to_owned(),
                        replacement,
                    );
                }
                Err(_) => {
                    rewrite_error = Some(file_transfer_failure(
                        FileTransferReason::TransferFailed,
                        "gateway file metadata could not be encoded",
                    ));
                    break;
                }
            }
        }
        if let Some(error) = rewrite_error {
            self.discard_resource_batch_bounded(batch_id).await;
            return Err(error);
        }
        Ok(PreparedResourceOutput {
            result,
            batch_id: Some(batch_id.to_string()),
            file_count: replacements.len(),
        })
    }

    async fn publish(&self, batch_id: &str, file_count: usize) -> Result<(), McpError> {
        let batch_id = parse_batch_id(batch_id)?;
        self.storage
            .publish_batch(batch_id, file_count)
            .await
            .map_err(|error| {
                tracing::warn!(%batch_id, error = %error, "file batch could not be published");
                file_transfer_failure(
                    FileTransferReason::TransferFailed,
                    "gateway file could not be published",
                )
            })
    }

    async fn discard(&self, batch_id: &str) {
        let Ok(batch_id) = uuid::Uuid::parse_str(batch_id) else {
            tracing::error!("invalid private file batch identifier");
            return;
        };
        if let Err(error) = self.storage.discard_batch(batch_id).await {
            tracing::warn!(%batch_id, error = %error, "file batch cleanup failed");
        }
    }
}

#[derive(Clone)]
pub(crate) struct NativeFileAuthorizer {
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    admission: FileTransferAdmission,
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    audit: SharedEvidence,
    public_url: String,
    native_https: bool,
    max_bytes: Option<u64>,
}

impl NativeFileAuthorizer {
    pub(crate) fn new(
        authority: Arc<TransferAuthority>,
        storage: Arc<GatewayFileStorage>,
        admission: FileTransferAdmission,
        quota: Option<Arc<dyn waygate_quota::QuotaService>>,
        audit: SharedEvidence,
        public_url: String,
        native_https: bool,
    ) -> Self {
        Self {
            authority,
            storage,
            admission,
            quota,
            audit,
            public_url,
            native_https,
            max_bytes: None,
        }
    }

    pub(crate) fn with_max_bytes(mut self, max_bytes: Option<u64>) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

#[async_trait]
impl FileUploadAuthorizer for NativeFileAuthorizer {
    async fn authorize_upload(
        &self,
        principal: Option<&Principal>,
        params: AuthorizeUploadParams,
    ) -> Result<AuthorizeUploadResult, McpError> {
        if !self.native_https {
            return Err(invalid_file_request(
                FileTransferReason::NotEnabled,
                "native file uploads require an HTTPS gateway public URL; use the helper path \
                 for loopback HTTP",
            ));
        }
        let principal = principal.ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file upload authorization requires authentication",
            )
        })?;
        crate::mcp_files::enforce_upload_preparation_profile(principal)?;
        let max_bytes = self.max_bytes.unwrap_or(i64::MAX as u64);
        if params.size.is_some_and(|size| size > max_bytes) {
            return Err(invalid_file_request(
                FileTransferReason::QuotaExhausted,
                "declared file size exceeds the configured upload limit",
            ));
        }
        let expected_digest = params
            .digest
            .as_ref()
            .map(|digest| {
                if digest.algorithm != "sha-256" {
                    return Err(invalid_file_request(
                        FileTransferReason::InvalidFileInput,
                        "gateway uploads currently verify sha-256 digests",
                    ));
                }
                let value = URL_SAFE_NO_PAD
                    .decode(digest.value.as_bytes())
                    .map_err(|_| {
                        invalid_file_request(
                            FileTransferReason::InvalidFileInput,
                            "upload digest is not valid base64url",
                        )
                    })?;
                if value.len() != 32 {
                    return Err(invalid_file_request(
                        FileTransferReason::InvalidFileInput,
                        "upload sha-256 digest must contain 32 bytes",
                    ));
                }
                Ok(waygate_transfer::TransferDigest {
                    algorithm: digest.algorithm.clone(),
                    value,
                })
            })
            .transpose()?;
        crate::mcp_files::check_upload_preparation_quota(
            self.quota.as_ref(),
            &self.audit,
            principal,
        )
        .await?;
        let file_uri = format!("mcp-file://gateway/{}", uuid::Uuid::new_v4());
        let now = OffsetDateTime::now_utc();
        let issued = self
            .authority
            .issue_native_upload_credential(
                principal,
                waygate_transfer::NewTransferGrant {
                    invocation_id: uuid::Uuid::now_v7().to_string(),
                    file_uri: file_uri.clone(),
                    direction: waygate_transfer::TransferDirection::Upload,
                    source: waygate_transfer::TransferEndpoint::client(
                        waygate_transfer::NATIVE_MCP_CLIENT_REFERENCE,
                    )
                    .map_err(transfer_authority_error)?,
                    destination: waygate_transfer::TransferEndpoint::upstream(
                        "gateway",
                        file_uri.clone(),
                    )
                    .map_err(transfer_authority_error)?,
                    helper_jkt: String::new(),
                    max_bytes,
                    expected_size: params.size,
                    media_type: params.mime_type.clone(),
                    expected_digest,
                    max_requests: 1,
                    expires_at: now + time::Duration::minutes(15),
                    credential_ttl: time::Duration::minutes(5),
                },
                now,
            )
            .await
            .map_err(transfer_authority_error)?;
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_owned(),
            format!("Bearer {}", issued.credential.expose()),
        );
        if let Some(media_type) = params.mime_type.as_ref() {
            headers.insert("Content-Type".to_owned(), media_type.clone());
        }
        Ok(AuthorizeUploadResult {
            file: FileValue {
                uri: file_uri,
                name: params.name,
                mime_type: params.mime_type,
                size: params.size,
                digest: params.digest,
            },
            upload: FileTransferDescriptor {
                transport: FileTransport::https(),
                method: TransferMethod::PUT,
                url: format!(
                    "{}{}",
                    self.public_url.trim_end_matches('/'),
                    waygate_transfer::FILE_UPLOAD_PATH,
                ),
                headers,
                multipart: None,
                expires_at: Some(format_ts_rfc3339(issued.expires_at)),
            },
            download: None,
        })
    }
}

#[async_trait]
impl FileDownloadAuthorizer for NativeFileAuthorizer {
    async fn authorize_download(
        &self,
        principal: Option<&Principal>,
        params: AuthorizeDownloadParams,
    ) -> Result<AuthorizeDownloadResult, McpError> {
        if !self.native_https {
            return Err(invalid_file_request(
                FileTransferReason::NotEnabled,
                "native file downloads require an HTTPS gateway public URL; use the helper path \
                 for loopback HTTP",
            ));
        }
        let principal = principal.ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "file download authorization requires authentication",
            )
        })?;
        let file_id = parse_gateway_file_uri(&params.uri)?;
        let _permit = self.admission.try_enter().map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TemporarilyUnavailable,
                "file transfer capacity is currently full; retry later",
            )
        })?;
        let owner = owner_from_principal(principal);
        let file = self
            .storage
            .find_ready(&owner, file_id)
            .await
            .map_err(|error| {
                tracing::warn!(%file_id, error = %error, "gateway file lookup failed");
                file_transfer_failure(
                    FileTransferReason::TemporarilyUnavailable,
                    "gateway file storage is unavailable",
                )
            })?
            .ok_or_else(|| {
                invalid_file_request(
                    FileTransferReason::FileUnavailable,
                    "file is unavailable or expired",
                )
            })?;
        if profile_blocks_file_origin(principal, &file.upstream_server, &file.upstream_tool) {
            return Err(invalid_file_request(
                FileTransferReason::FileUnavailable,
                "file is unavailable or expired",
            ));
        }
        crate::mcp_files::check_download_preparation_quota(
            self.quota.as_ref(),
            &self.audit,
            principal,
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let issued = self
            .authority
            .issue_native_download_credential(
                principal,
                waygate_transfer::NewTransferGrant {
                    invocation_id: file.invocation_id.clone(),
                    file_uri: file.uri(),
                    direction: waygate_transfer::TransferDirection::Download,
                    source: waygate_transfer::TransferEndpoint::upstream(
                        file.upstream_server.clone(),
                        file.upstream_uri.clone(),
                    )
                    .map_err(transfer_authority_error)?,
                    destination: waygate_transfer::TransferEndpoint::client(
                        waygate_transfer::NATIVE_MCP_CLIENT_REFERENCE,
                    )
                    .map_err(transfer_authority_error)?,
                    helper_jkt: String::new(),
                    max_bytes: file.size.max(1),
                    expected_size: Some(file.size),
                    media_type: file.media_type.clone(),
                    expected_digest: Some(waygate_transfer::TransferDigest {
                        algorithm: "sha-256".to_owned(),
                        value: file.sha256.clone(),
                    }),
                    max_requests: 1,
                    expires_at: std::cmp::min(file.expires_at, now + time::Duration::minutes(15)),
                    credential_ttl: time::Duration::minutes(5),
                },
                now,
            )
            .await
            .map_err(transfer_authority_error)?;
        let expires_at = format_ts_rfc3339(issued.expires_at);
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_owned(),
            format!("Bearer {}", issued.credential.expose()),
        );
        Ok(AuthorizeDownloadResult {
            sensitivity: None,
            file: FileValue {
                uri: file.uri(),
                name: file.display_name,
                mime_type: file.media_type,
                size: Some(file.size),
                digest: Some(FileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: URL_SAFE_NO_PAD.encode(file.sha256),
                }),
            },
            download: FileTransferDescriptor {
                transport: FileTransport::https(),
                method: TransferMethod::GET,
                url: format!(
                    "{}{}",
                    self.public_url.trim_end_matches('/'),
                    waygate_transfer::FILE_DOWNLOAD_PATH,
                ),
                headers,
                multipart: None,
                expires_at: Some(expires_at),
            },
        })
    }
}

fn validate_file_public_url(public_url: &str) -> anyhow::Result<&str> {
    let url = url::Url::parse(public_url).context("parse gateway public URL for file transfer")?;
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("file transfer public URL must not contain userinfo");
    }
    match url.scheme() {
        "https" => Ok("https"),
        "http"
            if url.host().is_some_and(|host| match host {
                url::Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            }) =>
        {
            Ok("http")
        }
        _ => anyhow::bail!(
            "file transfer requires an HTTPS public URL; HTTP is allowed only on loopback"
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonPathPart {
    Key(String),
    Index(usize),
}

#[derive(Debug)]
struct FileInput {
    path: Vec<JsonPathPart>,
    file: FileValue,
    /// Present only for the object-valued gateway compatibility extension:
    /// the caller's annotated object, preserved so schema-owned vendor
    /// fields survive the rewrite. The strict SEP URI-string form leaves
    /// this `None` and is replaced by a plain string.
    object_template: Option<Map<String, Value>>,
    constraints: Vec<FileInputDescriptor>,
}

/// Admit every evaluated `x-mcp-file` location and return the gateway-owned
/// file references that need governed delivery.
///
/// `transferModes` names which trust and data path the tool admitted, so a
/// value using a disallowed mode is rejected rather than forwarded: an inline
/// `data:` value must not bypass the governed upload path, and a
/// gateway-private URI must not reach a field that only admits inline bytes.
/// Inline values are checked against the same declared constraints as stored
/// files (decoded size, media type) and then left in place — the value is the
/// payload the tool admitted. The same rules apply however a location was
/// reached: direct properties, arrays, references, and composed or
/// conditional branches all funnel through this one evaluation.
fn collect_file_inputs(
    schema: &Value,
    compiled: Option<&jsonschema::Validator>,
    value: &Value,
) -> Result<Vec<FileInput>, McpError> {
    let mut files: Vec<FileInput> = Vec::new();
    admit_annotated_file_locations(
        schema,
        compiled,
        value,
        |annotated_value, uri, path, descriptors| {
            let (file, object_template) = match annotated_value {
                Value::Object(object) => (
                    serde_json::from_value(annotated_value.clone()).map_err(|_| {
                        invalid_file_request(
                            FileTransferReason::InvalidFileInput,
                            "annotated file input is not a valid FileValue",
                        )
                    })?,
                    Some(object.clone()),
                ),
                _ => (
                    FileValue {
                        uri: uri.to_owned(),
                        name: None,
                        mime_type: None,
                        size: None,
                        digest: None,
                    },
                    None,
                ),
            };
            files.push(FileInput {
                path,
                file,
                object_template,
                constraints: descriptors,
            });
            Ok(())
        },
    )?;
    Ok(files)
}

/// Count the deliverable gateway references among the admitted file values.
/// Pre-quota admission uses this sink: every mode and inline-constraint check
/// still runs, but nothing payload-sized is materialized for a call that may
/// be refused before the rate limit is debited.
fn count_deliverable_file_inputs(
    schema: &Value,
    compiled: Option<&jsonschema::Validator>,
    value: &Value,
) -> Result<usize, McpError> {
    let mut deliverable = 0usize;
    admit_annotated_file_locations(schema, compiled, value, |_, _, _, _| {
        deliverable += 1;
        Ok(())
    })?;
    Ok(deliverable)
}

/// Walk every evaluated `x-mcp-file` location once, enforce transfer-mode and
/// inline-content admission, and hand each deliverable gateway reference to
/// `deliverable` with its borrowed value, path, and gathered descriptors.
fn admit_annotated_file_locations(
    schema: &Value,
    compiled: Option<&jsonschema::Validator>,
    value: &Value,
    mut deliverable: impl FnMut(
        &Value,
        &str,
        Vec<JsonPathPart>,
        Vec<FileInputDescriptor>,
    ) -> Result<(), McpError>,
) -> Result<(), McpError> {
    // The pipeline supplies its cached compiled validator; compiling here is
    // the fallback for callers outside the invocation path.
    let local;
    let validator = match compiled {
        Some(validator) => validator,
        None => {
            local = jsonschema::validator_for(schema).map_err(|_| {
                file_transfer_failure(
                    FileTransferReason::InvalidToolContract,
                    "tool has an invalid file input schema",
                )
            })?;
            &local
        }
    };
    let evaluation = validator.evaluate(value);
    if !evaluation.flag().valid {
        return Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "tool arguments do not match its input schema",
        ));
    }

    // Gather every descriptor per instance location first: composed schemas
    // may annotate one location from several branches, and all of those
    // constraints apply to the admitted value. Locations are keyed by their
    // instance pointer — this runs before quota is consumed, so grouping must
    // stay near-linear even when an annotation lands on every element of a
    // caller-controlled array.
    let mut locations: Vec<(Vec<JsonPathPart>, String, Vec<FileInputDescriptor>)> = Vec::new();
    let mut index_by_pointer: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for entry in evaluation.iter_annotations() {
        let Some(annotation) = entry.annotations.value().get("x-mcp-file") else {
            continue;
        };
        let descriptor: FileInputDescriptor =
            serde_json::from_value(annotation.clone()).map_err(|_| {
                file_transfer_failure(
                    FileTransferReason::InvalidToolContract,
                    "tool has an invalid file annotation",
                )
            })?;
        let pointer = entry.instance_location.as_str();
        if let Some(&index) = index_by_pointer.get(pointer) {
            let descriptors = &mut locations[index].2;
            if !descriptors.contains(&descriptor) {
                descriptors.push(descriptor);
            }
            continue;
        }
        let path = json_pointer_path(value, pointer)?;
        index_by_pointer.insert(pointer.to_owned(), locations.len());
        locations.push((path, pointer.to_owned(), vec![descriptor]));
    }

    for (path, instance_location, descriptors) in locations {
        let annotated_value = value
            .pointer(&instance_location)
            .expect("an evaluation annotation points into its evaluated instance");
        // Classification borrows from the arguments: an inline value is the
        // payload itself, so admission must not duplicate it into an owned
        // FileValue. Materialization is the sink's decision — the pre-quota
        // counting sink never copies anything.
        let (uri, name) = match annotated_value {
            Value::String(uri) => (uri.as_str(), None),
            Value::Object(object) => {
                validate_file_object_shape(object)?;
                let uri = object
                    .get("uri")
                    .and_then(Value::as_str)
                    .expect("shape validation admitted a string uri");
                (uri, object.get("name").and_then(Value::as_str))
            }
            _ => continue,
        };
        if is_inline_data_uri(uri) {
            admit_inline_file_value(&descriptors, uri, name)?;
            continue;
        }
        if is_gateway_file_uri(uri) {
            require_transfer_mode(
                &descriptors,
                FileTransferMode::Upload,
                "tool input does not admit uploaded files here; supply an inline data: value",
            )?;
            deliverable(annotated_value, uri, path, descriptors)?;
        }
    }
    Ok(())
}

/// Borrow-based shape check for an annotated object-valued file input: the
/// standard members must have their `FileValue` types. This runs during
/// admission, so it must not clone a payload-sized `uri` the way a full
/// deserialization would.
fn validate_file_object_shape(object: &Map<String, Value>) -> Result<(), McpError> {
    let shape_error = || {
        invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "annotated file input is not a valid FileValue",
        )
    };
    if !object.get("uri").is_some_and(Value::is_string) {
        return Err(shape_error());
    }
    // Optional members are `Option` values in the model, so an explicit null
    // means absent, exactly as deserialization treats it.
    for member in ["name", "mimeType"] {
        if object
            .get(member)
            .is_some_and(|value| !value.is_string() && !value.is_null())
        {
            return Err(shape_error());
        }
    }
    if object
        .get("size")
        .is_some_and(|value| !value.is_u64() && !value.is_null())
    {
        return Err(shape_error());
    }
    if let Some(digest) = object.get("digest") {
        let valid = digest.is_null()
            || digest.as_object().is_some_and(|digest| {
                digest.get("algorithm").is_some_and(Value::is_string)
                    && digest.get("value").is_some_and(Value::is_string)
            });
        if !valid {
            return Err(shape_error());
        }
    }
    Ok(())
}

/// Enforces `x-mcp-file` admission on a gateway that has no file storage.
///
/// Admitted inline `data:` values need no gateway byte path — they travel to
/// the upstream inside the arguments — so mode and constraint checks still
/// apply. A gateway-owned file reference cannot be delivered without storage
/// (no such file can even exist), so it is refused explicitly instead of
/// being forwarded as an unresolvable private URI.
struct AdmissionOnlyFileInputProcessor;

#[async_trait]
impl FileInputProcessor for AdmissionOnlyFileInputProcessor {
    fn admit(
        &self,
        input_schema: Option<&Value>,
        compiled: Option<&jsonschema::Validator>,
        arguments: &mut Option<Map<String, Value>>,
        input_responses: Option<&BTreeMap<String, Value>>,
        _deliverable_keys: &[String],
    ) -> Result<(), McpError> {
        let mut deliverable = admit_file_arguments(input_schema, compiled, arguments)?;
        if let Some(responses) = input_responses {
            for value in responses.values() {
                let mut found = Vec::new();
                let mut path = Vec::new();
                collect_gateway_file_uris(value, &mut path, &mut found);
                deliverable += found.len();
            }
        }
        if deliverable == 0 {
            return Ok(());
        }
        Err(invalid_file_request(
            FileTransferReason::NotEnabled,
            "file transfer is not enabled on this gateway; the referenced file cannot be \
             delivered",
        ))
    }

    async fn prepare(
        &self,
        context: FileInputContext,
        input_schema: Option<&Value>,
        arguments: &mut Option<Map<String, Value>>,
    ) -> Result<bool, McpError> {
        // The pipeline already admitted before quota and approval; repeating
        // the deterministic check keeps this surface safe for callers that
        // reach `prepare` directly.
        self.admit(
            input_schema,
            context.compiled_input_schema.as_deref(),
            arguments,
            None,
            &[],
        )?;
        Ok(false)
    }

    async fn prepare_continuation(
        &self,
        _context: FileInputContext,
        input_responses: &mut BTreeMap<String, Value>,
        _file_keys: &[String],
    ) -> Result<bool, McpError> {
        for value in input_responses.values() {
            let mut found = Vec::new();
            let mut path = Vec::new();
            collect_gateway_file_uris(value, &mut path, &mut found);
            if !found.is_empty() {
                return Err(invalid_file_request(
                    FileTransferReason::NotEnabled,
                    "file transfer is not enabled on this gateway; the referenced file cannot \
                     be delivered",
                ));
            }
        }
        Ok(false)
    }
}

/// Deterministic admission shared by every processor configuration: mode and
/// inline-constraint checks for each evaluated `x-mcp-file` location, with a
/// cheap pre-scan so tools without file inputs skip schema evaluation.
/// Returns the number of deliverable gateway file references; delivery-time
/// checks (ownership, stored metadata, authority) stay with delivery. The
/// argument map is moved through evaluation and restored, never copied, and
/// nothing payload-sized is materialized — admission runs before quota.
fn admit_file_arguments(
    input_schema: Option<&Value>,
    compiled: Option<&jsonschema::Validator>,
    arguments: &mut Option<Map<String, Value>>,
) -> Result<usize, McpError> {
    let Some(schema) = input_schema else {
        return Ok(0);
    };
    if !waygate_mcp::files::schema_declares_file_inputs(schema) {
        return Ok(0);
    }
    let Some(map) = arguments.as_mut() else {
        return Ok(0);
    };
    let root = Value::Object(std::mem::take(map));
    let outcome = count_deliverable_file_inputs(schema, compiled, &root);
    let Value::Object(restored) = root else {
        unreachable!("the admission root remains the argument object")
    };
    *map = restored;
    outcome
}

/// Reject a value whose transfer mode is not admitted by every descriptor
/// that annotated its location.
fn require_transfer_mode(
    descriptors: &[FileInputDescriptor],
    mode: FileTransferMode,
    refusal: &str,
) -> Result<(), McpError> {
    let admitted = descriptors.iter().all(|descriptor| {
        descriptor
            .transfer_modes
            .as_ref()
            .is_none_or(|modes| modes.contains(&mode))
    });
    if admitted {
        Ok(())
    } else {
        Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            refusal.to_owned(),
        ))
    }
}

fn is_inline_data_uri(uri: &str) -> bool {
    // Byte-wise comparison: the caller-controlled value may end a multibyte
    // character anywhere, so no string slice may be taken before this check
    // proves the prefix is ASCII.
    uri.as_bytes()
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"data:"))
}

/// Enforce mode, decoded size, and media type for an inline `data:` value.
/// The payload itself stays in place: when inline transfer is admitted, the
/// value is exactly what the tool asked for and is not rewritten. An
/// object-valued inline file keeps its declared name so extension hints can
/// evaluate it. Everything is borrowed — admission never copies the payload.
fn admit_inline_file_value(
    descriptors: &[FileInputDescriptor],
    data_uri: &str,
    name: Option<&str>,
) -> Result<(), McpError> {
    require_transfer_mode(
        descriptors,
        FileTransferMode::Inline,
        "tool input does not admit inline data: values here; upload the file instead",
    )?;
    let claims = inline_file_claims(data_uri)?;
    for descriptor in descriptors {
        enforce_file_input_constraint(
            descriptor,
            Some(&claims.media_type),
            name,
            claims.decoded_size,
        )?;
    }
    Ok(())
}

struct InlineFileClaims {
    media_type: String,
    decoded_size: u64,
}

/// Read the RFC 2397 claims of an inline `data:` URI: its declared media type
/// (defaulting to `text/plain`) and the decoded payload size. The payload is
/// decoded only to count it; the value on the wire is left untouched.
fn inline_file_claims(data_uri: &str) -> Result<InlineFileClaims, McpError> {
    let malformed = || {
        invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "inline data: value is malformed",
        )
    };
    // `is_inline_data_uri` proved the first five bytes are ASCII `data:`, so
    // byte offset 5 is a character boundary.
    let rest = &data_uri[5..];
    // A literal `#` begins the URI fragment — inside RFC 2397 data it must be
    // percent-encoded — so the fragment is excluded from the payload count.
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (header, payload) = rest.split_once(',').ok_or_else(malformed)?;
    // The `;base64` marker is case-insensitive like the rest of the media
    // type grammar. The suffix comparison is byte-wise, and a matched ASCII
    // suffix makes the boundary at `len - 7` valid.
    let marker = b";base64";
    let (mediatype, base64_encoded) = match header.len().checked_sub(marker.len()) {
        Some(split)
            if header.as_bytes()[split..].eq_ignore_ascii_case(marker)
                && header.is_char_boundary(split) =>
        {
            (&header[..split], true)
        }
        _ => (header, false),
    };
    let declared = mediatype
        .split(';')
        .next()
        .map(str::trim)
        .filter(|essence| !essence.is_empty());
    let media_type = match declared {
        None => "text/plain".to_owned(),
        Some(essence) => {
            // A registered type and subtype name are each at most 127
            // characters, so the bounded essence copy stays small however
            // large the caller made the pre-comma header. RFC 2397 permits
            // percent-encoding in the mediatype, so escapes are decoded
            // first — validation and `accept` matching must see the same
            // text a conforming parser would, or equivalent spellings would
            // pass and fail the same filter.
            const MEDIA_TYPE_ESSENCE_LIMIT: usize = 255;
            // The decoded length is what the bound governs; the encoded
            // spelling may legally be up to three bytes per decoded byte.
            if essence.len() > MEDIA_TYPE_ESSENCE_LIMIT * 3 {
                return Err(malformed());
            }
            let mut decoded_bytes = Vec::with_capacity(essence.len());
            for byte in percent_decoded_bytes(essence) {
                decoded_bytes.push(byte.ok_or_else(malformed)?);
            }
            if decoded_bytes.len() > MEDIA_TYPE_ESSENCE_LIMIT {
                return Err(malformed());
            }
            let decoded = String::from_utf8(decoded_bytes).map_err(|_| malformed())?;
            let mut halves = decoded.split('/');
            let well_formed = matches!(
                (halves.next(), halves.next(), halves.next()),
                (Some(kind), Some(subtype), None)
                    if is_media_type_token(kind) && is_media_type_token(subtype)
            );
            if !well_formed {
                return Err(malformed());
            }
            decoded
        }
    };
    // The decoded size is counted in one streaming pass. Admission runs
    // before quota is consumed, so a rejected value must not cost a
    // payload-proportional allocation: neither the percent-decoded bytes nor
    // the base64 plaintext is ever materialized.
    let mut decoded = percent_decoded_bytes(payload);
    let decoded_size = if base64_encoded {
        let mut units: u64 = 0;
        let mut padding: u32 = 0;
        let mut last_unit: u8 = 0;
        for byte in &mut decoded {
            let byte = byte.ok_or_else(malformed)?;
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                    if padding > 0 {
                        return Err(malformed());
                    }
                    units += 1;
                    last_unit = base64_symbol_value(byte);
                }
                b'=' => {
                    padding += 1;
                    if padding > 2 {
                        return Err(malformed());
                    }
                }
                _ => return Err(malformed()),
            }
        }
        // Padding must complete the final quartet: `abc==` has five symbols
        // in total and is malformed even though its unit count alone maps to
        // a decoded length. Omitted padding is accepted deliberately — it is
        // the widely produced unpadded form browsers accept — while
        // whitespace and non-canonical encodings stay rejected: the value is
        // forwarded verbatim, so a strict upstream decoder must never
        // receive a payload the gateway measured differently.
        if padding > 0 && !(units + u64::from(padding)).is_multiple_of(4) {
            return Err(malformed());
        }
        let (remainder, unused_bits) = match units % 4 {
            0 => (0, 0),
            2 => (1, 4),
            3 => (2, 2),
            _ => return Err(malformed()),
        };
        // A canonical encoding leaves the unused low bits of the final data
        // symbol zero; `YR==` decodes to one byte only under lenient
        // decoders and strict ones reject it.
        if unused_bits > 0 && last_unit & ((1 << unused_bits) - 1) != 0 {
            return Err(malformed());
        }
        units / 4 * 3 + remainder
    } else {
        let mut count: u64 = 0;
        for byte in &mut decoded {
            byte.ok_or_else(malformed)?;
            count += 1;
        }
        count
    };
    Ok(InlineFileClaims {
        media_type,
        decoded_size,
    })
}

/// Whether the (already percent-decoded) string is a media-type token:
/// restricted token characters only, so names with spaces or delimiters
/// cannot pose as a type or subtype. A literal `%` is itself a token
/// character.
fn is_media_type_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// The 6-bit value of one standard-alphabet base64 symbol. Callers pass only
/// bytes already matched against the alphabet.
fn base64_symbol_value(symbol: u8) -> u8 {
    match symbol {
        b'A'..=b'Z' => symbol - b'A',
        b'a'..=b'z' => symbol - b'a' + 26,
        b'0'..=b'9' => symbol - b'0' + 52,
        b'+' => 62,
        _ => 63,
    }
}

/// Streaming percent-decoder: yields each decoded byte, or `None` for an
/// invalid escape, without materializing the decoded payload.
fn percent_decoded_bytes(payload: &str) -> impl Iterator<Item = Option<u8>> + '_ {
    let mut input = payload.bytes();
    std::iter::from_fn(move || {
        let byte = input.next()?;
        if byte != b'%' {
            return Some(Some(byte));
        }
        let high = input.next().and_then(|byte| char::from(byte).to_digit(16));
        let low = input.next().and_then(|byte| char::from(byte).to_digit(16));
        match (high, low) {
            (Some(high), Some(low)) => Some(Some((high * 16 + low) as u8)),
            _ => Some(None),
        }
    })
}

fn json_pointer_path(root: &Value, pointer: &str) -> Result<Vec<JsonPathPart>, McpError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let tokens = pointer.strip_prefix('/').ok_or_else(|| {
        file_transfer_failure(
            FileTransferReason::InvalidToolContract,
            "schema evaluation returned an invalid argument path",
        )
    })?;
    let mut current = root;
    let mut path = Vec::new();
    for token in tokens.split('/') {
        let token = token.replace("~1", "/").replace("~0", "~");
        match current {
            Value::Object(object) => {
                current = object.get(&token).ok_or_else(|| {
                    file_transfer_failure(
                        FileTransferReason::InvalidToolContract,
                        "schema evaluation returned an unknown argument path",
                    )
                })?;
                path.push(JsonPathPart::Key(token));
            }
            Value::Array(array) => {
                let index = token.parse::<usize>().map_err(|_| {
                    file_transfer_failure(
                        FileTransferReason::InvalidToolContract,
                        "schema evaluation returned an invalid array path",
                    )
                })?;
                current = array.get(index).ok_or_else(|| {
                    file_transfer_failure(
                        FileTransferReason::InvalidToolContract,
                        "schema evaluation returned an unknown array path",
                    )
                })?;
                path.push(JsonPathPart::Index(index));
            }
            _ => {
                return Err(file_transfer_failure(
                    FileTransferReason::InvalidToolContract,
                    "schema evaluation returned a path through a scalar value",
                ));
            }
        }
    }
    Ok(path)
}

/// Build the wire value that replaces an admitted file reference.
///
/// The strict SEP contract is the first arm: a URI-string input becomes a
/// plain string. The object arm is the gateway compatibility extension for
/// tools whose own schema models an attachment as an object — schema-owned
/// fields are preserved while the standard members present are rewritten
/// from the delivered file: identity and integrity (URI, size, digest,
/// media type) come from stored state and the authorization exchange, so
/// caller-supplied identity never survives into dispatch, while the display
/// name is the deliberate presentation-hint exception the caller may have
/// chosen upstream of this rewrite.
fn replacement_file_value(input: &FileInput, replacement: FileValue) -> Result<Value, McpError> {
    let Some(mut template) = input.object_template.clone() else {
        return Ok(Value::String(replacement.uri));
    };
    let replacement = serde_json::to_value(replacement).map_err(|_| {
        file_transfer_failure(
            FileTransferReason::TransferFailed,
            "upstream file metadata could not be serialized",
        )
    })?;
    let replacement = replacement
        .as_object()
        .expect("serialized FileValue is an object");
    for key in ["uri", "name", "mimeType", "size", "digest"] {
        if template.contains_key(key) {
            if let Some(value) = replacement.get(key) {
                template.insert(key.to_owned(), value.clone());
            }
        }
    }
    Ok(Value::Object(template))
}

fn enforce_file_input_constraints(
    constraints: &[FileInputDescriptor],
    media_type: Option<&str>,
    file_name: Option<&str>,
    size: u64,
) -> Result<(), McpError> {
    for constraint in constraints {
        enforce_file_input_constraint(constraint, media_type, file_name, size)?;
    }
    Ok(())
}

/// Enforce one descriptor's declared constraints against a file's claims.
///
/// `accept` mixes two vocabularies, mirroring the HTML file-picker attribute:
/// MIME patterns (`image/*`, `application/pdf`) and dot-prefixed filename
/// extension hints (`.pdf`). A file is accepted when its media type matches
/// any MIME pattern or its name matches any extension hint. An extension hint
/// is a picker hint, not a MIME pattern: it must never be compared against a
/// media type, and a hints-only list cannot deny a file whose name is
/// unknown — the server-side content policy stays with media type and size.
fn enforce_file_input_constraint(
    constraints: &FileInputDescriptor,
    media_type: Option<&str>,
    file_name: Option<&str>,
    size: u64,
) -> Result<(), McpError> {
    if constraints.max_size.is_some_and(|limit| size > limit) {
        return Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "file exceeds the tool input size limit",
        ));
    }
    let Some(accepted) = constraints.accept.as_deref() else {
        return Ok(());
    };
    let (extension_hints, mime_patterns): (Vec<&str>, Vec<&str>) = accepted
        .iter()
        .map(|entry| entry.trim())
        .partition(|entry| entry.starts_with('.'));
    if let Some(name) = file_name {
        // Byte-wise suffix comparison: the caller-controlled name may contain
        // multibyte characters, so no length-derived string slice is safe.
        let name = name.as_bytes();
        let hinted = extension_hints.iter().any(|hint| {
            let hint = hint.as_bytes();
            name.len() > hint.len() && name[name.len() - hint.len()..].eq_ignore_ascii_case(hint)
        });
        if hinted {
            return Ok(());
        }
    }
    if mime_patterns.is_empty() {
        // Only extension hints were declared. A named file that matched none
        // of them was refused above the picker line; a nameless file has
        // nothing for a hint to inspect and passes.
        return match file_name {
            Some(_) => Err(invalid_file_request(
                FileTransferReason::InvalidFileInput,
                "file name does not match an extension accepted by the tool input",
            )),
            None => Ok(()),
        };
    }
    let Some(media_type) = media_type.map(|value| {
        value
            .split_once(';')
            .map_or(value, |(essence, _)| essence)
            .trim()
    }) else {
        return Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "file has no media type accepted by the tool input",
        ));
    };
    let matches = mime_patterns.iter().any(|pattern| {
        pattern.eq_ignore_ascii_case("*/*")
            || pattern.eq_ignore_ascii_case(media_type)
            || pattern
                .strip_suffix("/*")
                .and_then(|prefix| media_type.split_once('/').map(|(kind, _)| (prefix, kind)))
                .is_some_and(|(prefix, kind)| prefix.eq_ignore_ascii_case(kind))
    });
    if matches {
        Ok(())
    } else {
        Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "file media type is not accepted by the tool input",
        ))
    }
}

fn is_gateway_file_uri(uri: &str) -> bool {
    url::Url::parse(uri)
        .is_ok_and(|uri| uri.scheme() == "mcp-file" && uri.host_str() == Some("gateway"))
}

fn collect_file_values(root: &Value) -> Result<Vec<(Vec<JsonPathPart>, FileValue)>, McpError> {
    fn walk(
        value: &Value,
        path: &mut Vec<JsonPathPart>,
        files: &mut Vec<(Vec<JsonPathPart>, FileValue)>,
    ) -> Result<(), McpError> {
        if let Some(uri) = value.get("uri").and_then(Value::as_str) {
            if url::Url::parse(uri).is_ok_and(|uri| uri.scheme() == "mcp-file") {
                let file = serde_json::from_value(value.clone()).map_err(|_| {
                    invalid_file_request(
                        FileTransferReason::TransferFailed,
                        "upstream returned an invalid FileValue",
                    )
                })?;
                files.push((path.clone(), file));
                return Ok(());
            }
        }
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    path.push(JsonPathPart::Key(key.clone()));
                    walk(child, path, files)?;
                    path.pop();
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate() {
                    path.push(JsonPathPart::Index(index));
                    walk(child, path, files)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(root, &mut Vec::new(), &mut files)?;
    Ok(files)
}

fn replace_file_at_path(
    root: &mut Value,
    path: &[JsonPathPart],
    replacement: FileValue,
) -> Result<(), McpError> {
    let mut current = root;
    for part in path {
        current = match part {
            JsonPathPart::Key(key) => current.get_mut(key),
            JsonPathPart::Index(index) => current.get_mut(*index),
        }
        .ok_or_else(|| {
            file_transfer_failure(
                FileTransferReason::TransferFailed,
                "file result changed during processing",
            )
        })?;
    }
    let replacement = serde_json::to_value(replacement).map_err(|_| {
        file_transfer_failure(
            FileTransferReason::TransferFailed,
            "gateway file metadata could not be serialized",
        )
    })?;
    *current = replacement;
    Ok(())
}

fn replace_value_at_path(
    root: &mut Value,
    path: &[JsonPathPart],
    replacement: Value,
) -> Result<(), McpError> {
    let mut current = root;
    for part in path {
        current = match part {
            JsonPathPart::Key(key) => current.get_mut(key),
            JsonPathPart::Index(index) => current.get_mut(*index),
        }
        .ok_or_else(|| {
            file_transfer_failure(
                FileTransferReason::TransferFailed,
                "file input changed during processing",
            )
        })?;
    }
    *current = replacement;
    Ok(())
}

fn validate_authorized_upload(
    authorized: &FileValue,
    media_type: Option<&str>,
    size: u64,
    digest: &FileDigest,
) -> Result<FileValue, McpError> {
    if is_gateway_file_uri(&authorized.uri) || url::Url::parse(&authorized.uri).is_err() {
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "upstream upload authorization did not return a private file URI",
        ));
    }
    if authorized.size.is_some_and(|authorized| authorized != size)
        || authorized
            .mime_type
            .as_deref()
            .zip(media_type)
            .is_some_and(|(authorized, stored)| authorized != stored)
        || authorized
            .digest
            .as_ref()
            .is_some_and(|value| value != digest)
    {
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "upstream upload authorization changed authoritative file metadata",
        ));
    }
    Ok(authorized.clone())
}

fn verify_response_media_type(expected: Option<&str>, headers: &HeaderMap) -> Result<(), McpError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let Some(actual) = headers.get(CONTENT_TYPE) else {
        return Ok(());
    };
    let actual = actual
        .to_str()
        .map_err(|_| {
            invalid_file_request(
                FileTransferReason::IntegrityMismatch,
                "upstream returned an invalid Content-Type",
            )
        })?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if !expected.trim().eq_ignore_ascii_case(actual) {
        return Err(invalid_file_request(
            FileTransferReason::IntegrityMismatch,
            "upstream file media type does not match its FileValue",
        ));
    }
    Ok(())
}

/// Whether a descriptor's declared transport may be executed.
///
/// HTTPS always. Plaintext only where `cleartext` says the gateway already
/// reaches this upstream's control plane that way — see
/// [`waygate_mcp::files::FileTransferNetwork::admits_cleartext_transfer`] for
/// what establishes that and why it cannot be a downgrade. Unknown future
/// transports stay parseable and unexecuted, as before.
fn transport_admitted(transport: &waygate_mcp::files::FileTransport, cleartext: bool) -> bool {
    transport.is_https() || (cleartext && transport.as_str() == "http")
}

/// Whether a descriptor's URL may be executed, given the transport it declared.
///
/// The scheme must *be* the declared transport, not merely be separately
/// admissible. Judging them independently would accept `https` declared with an
/// `http://` URL — the transfer then runs in cleartext while the descriptor
/// claims TLS — and `http` declared with an `https://` URL, which is incoherent
/// in the other direction. Neither is the exception this admits, which is exactly
/// `http` with `http://`, and only on a qualifying leg.
///
/// While both halves had to be `https` they could not disagree; admitting a
/// second pair is what makes stating the agreement necessary.
fn scheme_admitted(
    scheme: &str,
    transport: &waygate_mcp::files::FileTransport,
    cleartext: bool,
) -> bool {
    scheme == transport.as_str() && transport_admitted(transport, cleartext)
}

fn verify_descriptor_expiry(expires_at: Option<&str>) -> Result<(), McpError> {
    let Some(expires_at) = expires_at else {
        return Ok(());
    };
    let expires_at =
        OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339).map_err(
            |_| {
                invalid_file_request(
                    FileTransferReason::PolicyViolation,
                    "upstream returned an invalid file expiry",
                )
            },
        )?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "upstream file transfer instructions have expired",
        ));
    }
    Ok(())
}

struct AuthorizedFileClaims {
    mime_type: Option<String>,
    size: Option<u64>,
    digest: Option<FileDigest>,
}

fn authorized_file_claims(
    original: &FileValue,
    authorized: &FileValue,
) -> Result<AuthorizedFileClaims, McpError> {
    let same_uri = match (
        url::Url::parse(&original.uri),
        url::Url::parse(&authorized.uri),
    ) {
        (Ok(original), Ok(authorized)) => original == authorized,
        _ => original.uri == authorized.uri,
    };
    if !same_uri {
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "upstream authorized a different file than the tool returned",
        ));
    }
    merge_claim(&original.name, &authorized.name, "name")?;
    Ok(AuthorizedFileClaims {
        mime_type: merge_claim(&original.mime_type, &authorized.mime_type, "media type")?,
        size: merge_claim(&original.size, &authorized.size, "size")?,
        digest: merge_claim(&original.digest, &authorized.digest, "digest")?,
    })
}

fn merge_claim<T: Clone + PartialEq>(
    first: &Option<T>,
    second: &Option<T>,
    field: &'static str,
) -> Result<Option<T>, McpError> {
    match (first, second) {
        (Some(first), Some(second)) if first != second => Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            format!("upstream file {field} changed during authorization"),
        )),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value.clone())),
        (None, None) => Ok(None),
    }
}

fn decode_sha256(digest: Option<&FileDigest>) -> Result<Option<Vec<u8>>, McpError> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    if digest.algorithm != "sha-256" {
        // This validates a digest the upstream declared, so the failure is
        // the transfer's, not the caller's argument.
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "gateway currently verifies sha-256 file digests",
        ));
    }
    let value = URL_SAFE_NO_PAD
        .decode(digest.value.as_bytes())
        .map_err(|_| {
            invalid_file_request(
                FileTransferReason::TransferFailed,
                "upstream file digest is not valid base64url",
            )
        })?;
    if value.len() != 32 {
        return Err(invalid_file_request(
            FileTransferReason::TransferFailed,
            "upstream sha-256 digest must contain 32 bytes",
        ));
    }
    Ok(Some(value))
}

fn descriptor_headers(
    headers: &std::collections::BTreeMap<String, String>,
) -> Result<HeaderMap, McpError> {
    let mut result = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let name = HeaderName::from_str(name).map_err(|_| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file descriptor has an invalid header name",
            )
        })?;
        if matches!(name.as_str(), "range" | "if-range") {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file descriptor requests a partial representation",
            ));
        }
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "content-length"
                | "forwarded"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
        ) {
            return Err(invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file descriptor contains a destination-changing header",
            ));
        }
        let value = HeaderValue::try_from(value).map_err(|_| {
            invalid_file_request(
                FileTransferReason::PolicyViolation,
                "upstream file descriptor has an invalid header value",
            )
        })?;
        result.insert(name, value);
    }
    Ok(result)
}

fn owner_from_principal(principal: &Principal) -> GatewayFileOwner {
    GatewayFileOwner {
        tenant_id: principal.tenant.clone(),
        principal_sub: principal.sub.clone(),
        principal_issuer: principal.issuer.clone(),
    }
}

fn parse_batch_id(value: &str) -> Result<uuid::Uuid, McpError> {
    uuid::Uuid::parse_str(value).map_err(|_| {
        file_transfer_failure(
            FileTransferReason::TransferFailed,
            "invalid private file batch identifier",
        )
    })
}

fn parse_gateway_file_uri(value: &str) -> Result<uuid::Uuid, McpError> {
    let uri = url::Url::parse(value).map_err(|_| {
        invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "uri must be a gateway mcp-file URI",
        )
    })?;
    if uri.scheme() != "mcp-file" || uri.host_str() != Some("gateway") {
        return Err(invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "uri must be a gateway mcp-file URI",
        ));
    }
    uuid::Uuid::parse_str(uri.path().trim_start_matches('/')).map_err(|_| {
        invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "uri must be a gateway mcp-file URI",
        )
    })
}

fn transfer_authority_error(error: waygate_transfer::AuthorityError) -> McpError {
    match error {
        waygate_transfer::AuthorityError::Store(_)
        | waygate_transfer::AuthorityError::Evidence(_) => file_transfer_failure(
            FileTransferReason::TemporarilyUnavailable,
            "file transfer service is unavailable",
        ),
        // GrantUnavailable and CredentialUnavailable arise after a valid
        // request when internal lookup or activation fails; they are gateway
        // failures, not caller input defects.
        waygate_transfer::AuthorityError::GrantUnavailable
        | waygate_transfer::AuthorityError::CredentialUnavailable => file_transfer_failure(
            FileTransferReason::TransferFailed,
            "file transfer authority is unavailable",
        ),
        waygate_transfer::AuthorityError::IntegrityMismatch => invalid_file_request(
            FileTransferReason::IntegrityMismatch,
            "transfer integrity constraints were not satisfied",
        ),
        waygate_transfer::AuthorityError::CompletionUnknown { .. } => file_transfer_failure(
            FileTransferReason::CompletionUnknown,
            "upload completion outcome is unknown",
        ),
        _ => invalid_file_request(FileTransferReason::InvalidFileInput, error.to_string()),
    }
}

impl TransferRuntime {
    pub(crate) fn mount_routes(
        &self,
        mut app: axum::Router<()>,
        public_url: String,
        admission: Option<FileTransferAdmission>,
        retention: Duration,
    ) -> anyhow::Result<axum::Router<()>> {
        app = app.merge(waygate_transfer::credential_exchange_router(
            self.authority.clone(),
            public_url.clone(),
            self.exchange_concurrency(),
        ));
        if let (Some(storage), Some(admission)) = (self.file_storage(), admission) {
            app = app.merge(waygate_transfer::file_transfer_router(
                self.authority.clone(),
                storage,
                public_url,
                admission,
                time::Duration::try_from(retention).context("file retention is too large")?,
            ));
        }
        Ok(app)
    }

    /// Build durable authority shared by MCP grant creation and direct helper requests.
    pub(crate) async fn from_pool(
        pool: Option<PgPool>,
        audit: SharedEvidence,
        file_storage_dir: Option<&std::path::Path>,
    ) -> anyhow::Result<Option<Self>> {
        let Some(pool) = pool else {
            return Ok(None);
        };
        // Keep one control-pool connection available for unrelated gateway
        // operations while bounding the bearer-free exchange surface. The
        // exchange is short-lived authorization work; transfer bytes never
        // pass through this admission gate.
        let exchange_concurrency = usize::try_from(
            pool.options()
                .get_max_connections()
                .saturating_sub(1)
                .max(1),
        )
        .context("file-transfer exchange concurrency is not representable")?;
        let store: SharedTransferStore =
            Arc::new(waygate_transfer::PgTransferStore::new(pool.clone()));
        let dpop = waygate_transfer::DpopVerifier::new(
            time::Duration::minutes(5),
            time::Duration::seconds(30),
        )
        .context("file-transfer DPoP verifier configuration")?;
        let authority = Arc::new(TransferAuthority::new(store.clone(), audit.clone(), dpop));
        let file_storage = match file_storage_dir {
            Some(root) => Some(Arc::new(
                GatewayFileStorage::new(pool, root)
                    .await
                    .context("initialize gateway file storage")?,
            )),
            None => None,
        };
        Ok(Some(Self {
            authority,
            store,
            file_storage,
            exchange_concurrency,
            audit,
        }))
    }

    pub(crate) fn exchange_concurrency(&self) -> usize {
        self.exchange_concurrency
    }

    pub(crate) fn file_storage(&self) -> Option<Arc<GatewayFileStorage>> {
        self.file_storage.clone()
    }

    /// Sweep short-lived authorization state away from active transfer request paths.
    pub(crate) fn spawn_sweeper(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        let store = self.store.clone();
        let file_storage = self.file_storage.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => match store.sweep_expired(1_000).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(count, "expired file-transfer grants swept");
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(error = %error, "file-transfer authority sweep failed");
                        }
                    },
                }
                if let Some(storage) = file_storage.as_ref() {
                    match storage.sweep_expired(1_000).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(count, "expired gateway files removed");
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(error = %error, "gateway file cleanup failed");
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_principal(
        allowed_servers: Option<Vec<String>>,
        allowed_tools: Option<Vec<String>>,
    ) -> Principal {
        Principal {
            sub: "file-profile-test".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "gateway-test".to_owned(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::ApiKey,
            raw_token: None,
            roles: Vec::new(),
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "file-profile-test".to_owned(),
                profile_name: "file-profile-test".to_owned(),
                allowed_servers,
                allowed_tools,
            }),
        }
    }

    #[test]
    fn resource_file_origin_keeps_native_resource_profile_confinement() {
        let tool_confined = profile_principal(
            Some(vec!["printable".to_owned()]),
            Some(vec!["printable.resources/read".to_owned()]),
        );
        assert!(
            profile_blocks_file_origin(&tool_confined, "printable", "resources/read"),
            "spelling the storage origin as an allowed tool must not grant native resources",
        );

        let resource_capable = profile_principal(Some(vec!["printable".to_owned()]), None);
        assert!(!profile_blocks_file_origin(
            &resource_capable,
            "printable",
            "resources/read",
        ));
        let ordinary_tool = profile_principal(
            Some(vec!["printable".to_owned()]),
            Some(vec!["printable.export".to_owned()]),
        );
        assert!(!profile_blocks_file_origin(
            &ordinary_tool,
            "printable",
            "export",
        ));
        assert!(profile_blocks_file_origin(
            &ordinary_tool,
            "printable",
            NATIVE_RESOURCE_FILE_ORIGIN,
        ));
    }

    fn file_backed_resource_with_markers(count: usize) -> ReadResourceResult {
        let contents = (0..count)
            .map(|index| {
                let mut contents = ResourceContents::text(
                    format!("file {index}"),
                    format!("browser://screenshot/handle/{index}.png"),
                );
                let ResourceContents::TextResourceContents { meta, .. } = &mut contents else {
                    unreachable!("text constructor must return text resource contents")
                };
                meta.get_or_insert_with(Default::default).insert(
                    waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY.to_owned(),
                    serde_json::to_value(FileValue {
                        uri: format!("mcp-file://browser/{index}"),
                        name: Some(format!("{index}.png")),
                        mime_type: Some("image/png".to_owned()),
                        size: Some(0),
                        digest: None,
                    })
                    .expect("encode file marker"),
                );
                contents
            })
            .collect();
        ReadResourceResult::new(contents)
    }

    #[test]
    fn file_backed_resource_marker_count_is_bounded_before_staging() {
        assert_eq!(
            collect_resource_file_values(&file_backed_resource_with_markers(limits().file_count))
                .expect("the maximum legitimate bundle")
                .len(),
            limits().file_count,
        );

        let error = collect_resource_file_values(&file_backed_resource_with_markers(
            limits().file_count + 1,
        ))
        .expect_err("one marker over the response limit must be refused");
        assert!(error
            .message
            .contains(&format!("{}-file limit", limits().file_count)));
    }

    /// The whole admission rule, both halves, in the four cases that matter.
    ///
    /// A plaintext file leg is admissible only where the gateway has already
    /// accepted plaintext for the same upstream's control plane, on the same
    /// pinned addresses. Everywhere else the HTTPS requirement is exactly what
    /// it was.
    #[test]
    fn plaintext_is_admitted_only_where_the_control_plane_is_already_plaintext() {
        use waygate_mcp::files::{FileTransferNetwork, FileTransport};

        let pinned_cleartext = FileTransferNetwork::Pinned {
            addresses: vec!["10.0.0.8".parse().unwrap()],
            cleartext_control_plane: true,
        };
        let pinned_tls = FileTransferNetwork::Pinned {
            addresses: vec!["10.0.0.8".parse().unwrap()],
            cleartext_control_plane: false,
        };

        assert!(pinned_cleartext.admits_cleartext_transfer());
        assert!(
            !pinned_tls.admits_cleartext_transfer(),
            "a TLS control plane must not admit a plaintext file leg — the \
             exception cannot become a downgrade"
        );
        assert!(
            !FileTransferNetwork::Public.admits_cleartext_transfer(),
            "a public destination is a host the gateway never agreed to reach in the clear"
        );
        assert!(
            !FileTransferNetwork::Local.admits_cleartext_transfer(),
            "stdio has no pinned segment to reason about"
        );

        // Constructed the way one actually arrives — off the wire — rather than
        // by widening the type's API for a test.
        let transport = |declared: &str| {
            serde_json::from_value::<FileTransport>(serde_json::json!(declared))
                .expect("a transport is a bare string")
        };
        let https = FileTransport::https();
        let http = transport("http");
        let future = transport("future-transport");

        // HTTPS is admitted everywhere, unconditionally, as before.
        for admits in [true, false] {
            assert!(transport_admitted(&https, admits));
            assert!(scheme_admitted("https", &https, admits));
        }

        // Plaintext only under the exception.
        assert!(transport_admitted(&http, true));
        assert!(scheme_admitted("http", &http, true));
        assert!(!transport_admitted(&http, false));
        assert!(!scheme_admitted("http", &http, false));

        // The URL must be the transport that was declared. A descriptor claiming
        // TLS while naming an http:// URL would otherwise run in cleartext under
        // a claim that it does not, and the reverse is incoherent the other way.
        assert!(
            !scheme_admitted("http", &https, true),
            "https declared with an http:// URL must be refused even on a qualifying leg"
        );
        assert!(
            !scheme_admitted("https", &http, true),
            "http declared with an https:// URL must be refused"
        );

        // An unknown transport stays parseable and unexecuted either way.
        assert!(!transport_admitted(&future, true));
        assert!(!transport_admitted(&future, false));
        assert!(!scheme_admitted("future-transport", &future, true));
        assert!(!scheme_admitted("ftp", &https, true));
        assert!(!scheme_admitted("file", &http, true));
    }

    use rmcp::model::{
        CallToolRequestParams, CallToolResponse, ClientCapabilities, ClientInfo, ClientRequest,
        ContentBlock, CustomRequest, CustomResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, ResourceContents, ServerCapabilities, ServerInfo, ServerResult, Tool,
    };
    use rmcp::service::RequestContext;
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    };
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use rmcp::{RoleClient, RoleServer, ServerHandler, ServiceExt};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tower::ServiceExt as _;
    use waygate_mcp::files::CLIENT_CAPABILITIES_META_KEY;
    use waygate_mcp::protocol::RiskTier;
    use waygate_mcp::{DefaultInvocationService, GatewayServer};
    use waygate_upstream::{ToolClassification, Transport, UpstreamManifest, UpstreamPool};

    struct FilePolicyGate {
        allow_native_download: Arc<AtomicBool>,
        observed_native_download: Arc<AtomicBool>,
    }

    struct RecordingQuota {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl waygate_quota::QuotaService for RecordingQuota {
        async fn check_and_consume(
            &self,
            context: &waygate_quota::QuotaContext,
            actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            assert!(matches!(
                context.fq_tool.as_str(),
                "gateway-files.prepare_download" | "gateway-files.prepare_upload"
            ));
            assert_eq!(
                actions,
                [
                    waygate_quota::QuotaAction::Call,
                    waygate_quota::QuotaAction::SideEffectingCall,
                ]
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl waygate_mcp::AuthzGate for FilePolicyGate {
        async fn may_discover_server(&self, _principal: &Principal, _server: &str) -> bool {
            true
        }

        async fn authorize_tool_call(
            &self,
            _facts: &waygate_core::Facts,
        ) -> waygate_mcp::AuthzVerdict {
            waygate_mcp::AuthzVerdict::Allow {
                policy_ids: Vec::new(),
            }
        }

        async fn authorize_builtin_call(
            &self,
            _principal: &Principal,
            facts: &waygate_mcp::ToolFacts,
        ) -> waygate_mcp::BuiltinAuthz {
            if facts.server == waygate_core::FILES_BUILTIN_NAMESPACE
                && facts.name == "prepare_download"
            {
                self.observed_native_download.store(true, Ordering::SeqCst);
                if !self.allow_native_download.load(Ordering::SeqCst) {
                    return waygate_mcp::BuiltinAuthz::Forbidden {
                        reason: "file download blocked by test policy".to_owned(),
                        policy_ids: vec!["test-file-download-forbid".to_owned()],
                        reasons: Vec::new(),
                    };
                }
            }
            waygate_mcp::BuiltinAuthz::Proceed
        }
    }

    /// Request `_meta` exactly as it arrives, paired with the file-authorization
    /// method that carried it. An upstream reads the merged metadata, not the
    /// params copy the gateway wrote, so this is the only place the emitted
    /// declaration can be checked against what the wire carries.
    type ObservedAuthorizationMeta = Arc<tokio::sync::Mutex<Vec<(String, Map<String, Value>)>>>;

    #[derive(Clone)]
    struct PrintableFileUpstream {
        authorized: Arc<AtomicUsize>,
        results: Arc<Vec<AuthorizeDownloadResult>>,
        upload: Option<AuthorizeUploadResult>,
        imported_arguments: Arc<tokio::sync::Mutex<Option<Map<String, Value>>>>,
        authorization_meta: ObservedAuthorizationMeta,
    }

    impl ServerHandler for PrintableFileUpstream {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("printable-file-test", "0.0.0"))
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, McpError> {
            let mut file_schema = json!({
                "type": "object",
                "properties": {"uri": {"type": "string", "format": "uri"}},
                "required": ["uri"],
                "additionalProperties": false
            });
            waygate_mcp::files::annotate_file_input(
                &mut file_schema,
                &waygate_mcp::files::FileInputDescriptor {
                    accept: Some(vec!["application/octet-stream".to_owned()]),
                    max_size: None,
                    transfer_modes: Some(vec![FileTransferMode::Upload]),
                },
            )
            .expect("annotate import file");
            Ok(ListToolsResult::with_all_items(vec![
                Tool::new(
                    "render".to_owned(),
                    "produce a test file".to_owned(),
                    Arc::new(
                        json!({"type": "object", "properties": {}})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                ),
                Tool::new(
                    "import".to_owned(),
                    "consume a test file".to_owned(),
                    Arc::new(
                        json!({
                            "type": "object",
                            "properties": {"file": file_schema},
                            "required": ["file"]
                        })
                        .as_object()
                        .unwrap()
                        .clone(),
                    ),
                ),
            ]))
        }

        async fn call_tool(
            &self,
            request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResponse, McpError> {
            if request.name.as_ref() == "import" {
                *self.imported_arguments.lock().await = request.arguments;
                return Ok(
                    CallToolResult::success(vec![ContentBlock::text("file imported")]).into(),
                );
            }
            let mut result = CallToolResult::success(vec![ContentBlock::text("output is ready")]);
            let files = self
                .results
                .iter()
                .map(|result| &result.file)
                .collect::<Vec<_>>();
            result.structured_content = Some(json!({"files": files}));
            Ok(result.into())
        }

        async fn on_custom_request(
            &self,
            request: CustomRequest,
            context: RequestContext<RoleServer>,
        ) -> Result<CustomResult, McpError> {
            self.authorization_meta
                .lock()
                .await
                .push((request.method.to_string(), context.meta.0 .0.clone()));
            let result = match request.method.as_str() {
                waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD => {
                    let params: AuthorizeDownloadParams =
                        serde_json::from_value(request.params.unwrap_or(Value::Null))
                            .map_err(|_| McpError::invalid_params("invalid file request", None))?;
                    serde_json::to_value(
                        self.results
                            .iter()
                            .find(|result| result.file.uri == params.uri)
                            .ok_or_else(|| McpError::invalid_params("unknown file URI", None))?,
                    )
                }
                waygate_mcp::files::AUTHORIZE_UPLOAD_METHOD => {
                    serde_json::to_value(self.upload.as_ref().ok_or_else(|| {
                        McpError::invalid_params("file upload is unavailable", None)
                    })?)
                }
                _ => {
                    return Err(McpError::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        request.method,
                        None,
                    ));
                }
            };
            self.authorized.fetch_add(1, Ordering::SeqCst);
            result
                .map(CustomResult::new)
                .map_err(|error| McpError::internal_error(error.to_string(), None))
        }
    }

    async fn spawn_printable_upstream(
        results: Vec<AuthorizeDownloadResult>,
        upload: Option<AuthorizeUploadResult>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<tokio::sync::Mutex<Option<Map<String, Value>>>>,
        ObservedAuthorizationMeta,
    ) {
        let authorized = Arc::new(AtomicUsize::new(0));
        let imported_arguments = Arc::new(tokio::sync::Mutex::new(None));
        let authorization_meta = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let handler = PrintableFileUpstream {
            authorized: authorized.clone(),
            results: Arc::new(results),
            upload,
            imported_arguments: imported_arguments.clone(),
            authorization_meta: authorization_meta.clone(),
        };
        let factory = handler.clone();
        let service = StreamableHttpService::new(
            move || Ok(factory.clone()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default().with_legacy_session_mode(true),
        );
        let app: axum::Router<()> = axum::Router::new().nest_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind printable MCP server");
        let address = listener.local_addr().expect("printable MCP address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve printable MCP server");
        });
        (address, authorized, imported_arguments, authorization_meta)
    }

    async fn connect_printable(address: std::net::SocketAddr) -> Arc<UpstreamPool> {
        let manifest = UpstreamManifest {
            classification_mode: Default::default(),
            approval_mode: Default::default(),
            name: "printable".to_owned(),
            transport: Transport::Http,
            protocol: Default::default(),
            url: Some(format!("http://{address}/mcp")),
            command: None,
            tools: vec![
                ToolClassification::new("render", RiskTier::Low, false, false),
                ToolClassification::new("import", RiskTier::Low, true, false),
            ],
            resources: Vec::new(),
            exchange: None,
            auth: None,
            mtls: None,
            tier_a_required: false,
            tier_c_peer: None,
            session: None,
        };
        Arc::new(UpstreamPool::connect(BTreeMap::from([("printable".to_owned(), manifest)])).await)
    }

    #[tokio::test]
    async fn upstream_file_authorization_declares_file_support_on_the_wire() {
        // The declaration only matters as the upstream reads it. A leg that
        // negotiates the stateless protocol stamps the client capability key
        // onto every request from the connection's declared capabilities, and
        // that stamp replaces the same key in the request params, so a
        // declaration carried only in the params never arrives.
        let file = FileValue {
            uri: "mcp-file://printable/output-a".to_owned(),
            name: None,
            mime_type: None,
            size: None,
            digest: None,
        };
        let (address, _authorized, _imported, authorization_meta) = spawn_printable_upstream(
            vec![AuthorizeDownloadResult {
                file: file.clone(),
                sensitivity: None,
                download: FileTransferDescriptor {
                    transport: FileTransport::https(),
                    method: TransferMethod::GET,
                    url: "https://printable.invalid/file-a".to_owned(),
                    headers: BTreeMap::new(),
                    multipart: None,
                    expires_at: None,
                },
            }],
            None,
        )
        .await;
        let pool = connect_printable(address).await;

        use waygate_mcp::UpstreamCatalog as _;
        pool.authorize_file_download(
            "printable",
            AuthorizeDownloadParams {
                meta: waygate_mcp::files::stateless_client_capability_meta(
                    waygate_mcp::files::FileOperation::Download,
                ),
                uri: file.uri.clone(),
            },
            None,
        )
        .await
        .expect("authorize an upstream download");

        let observed = authorization_meta.lock().await.clone();
        let (method, meta) = observed.first().expect("upstream saw one authorization");
        assert_eq!(method, waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD);
        assert!(
            meta.contains_key("io.modelcontextprotocol/protocolVersion"),
            "the leg did not negotiate the stateless protocol, so this asserts nothing"
        );
        assert_eq!(
            meta.get(CLIENT_CAPABILITIES_META_KEY).and_then(
                |capabilities| capabilities.get(waygate_mcp::files::FILES_CAPABILITY_MEMBER)
            ),
            Some(&serde_json::json!({
                "download": true,
                "transports": ["https", "http"]
            }))
        );
    }

    #[derive(Clone)]
    struct ResourceCapabilityUpstream {
        observed_meta: Arc<tokio::sync::Mutex<Option<Map<String, Value>>>>,
    }

    impl ServerHandler for ResourceCapabilityUpstream {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_resources()
                    .build(),
            )
            .with_server_info(Implementation::new("resource-file-test", "0.0.0"))
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, McpError> {
            Ok(ListToolsResult::with_all_items(Vec::new()))
        }

        async fn read_resource(
            &self,
            request: ReadResourceRequestParams,
            context: RequestContext<RoleServer>,
        ) -> Result<ReadResourceResponse, McpError> {
            *self.observed_meta.lock().await = Some(context.meta.0 .0.clone());
            Ok(ReadResourceResult::new(vec![ResourceContents::text(
                "inline fallback",
                request.uri,
            )])
            .into())
        }
    }

    #[tokio::test]
    async fn resource_read_preserves_the_request_local_file_capability_on_the_wire() {
        let observed_meta = Arc::new(tokio::sync::Mutex::new(None));
        let handler = ResourceCapabilityUpstream {
            observed_meta: observed_meta.clone(),
        };
        let factory = handler.clone();
        let service = StreamableHttpService::new(
            move || Ok(factory.clone()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default().with_legacy_session_mode(true),
        );
        let app: axum::Router<()> = axum::Router::new().nest_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind resource MCP server");
        let address = listener.local_addr().expect("resource MCP address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve resource MCP server");
        });
        let pool = connect_printable(address).await;
        let capability_meta = waygate_mcp::files::stateless_client_capability_meta(
            waygate_mcp::files::FileOperation::Download,
        );
        let request = ReadResourceRequestParams::new("browser://screenshot/handle/capture.png")
            .with_meta(rmcp::model::RequestMetaObject(rmcp::model::MetaObject(
                capability_meta.into_iter().collect(),
            )));

        use waygate_mcp::UpstreamCatalog as _;
        pool.read_resource("printable", request, None)
            .await
            .expect("read resource through the upstream pool");

        let meta = observed_meta
            .lock()
            .await
            .clone()
            .expect("upstream observed resource request metadata");
        assert_eq!(
            meta.get(CLIENT_CAPABILITIES_META_KEY)
                .and_then(|capabilities| {
                    capabilities.get(waygate_mcp::files::FILES_CAPABILITY_MEMBER)
                }),
            Some(&waygate_mcp::files::stateless_client_file_capability(
                waygate_mcp::files::FileOperation::Download,
            ))
        );
    }

    #[test]
    fn replacing_a_file_removes_non_file_fields_from_the_upstream() {
        let mut value = json!({
            "result": {
                "uri": "MCP-FILE://upstream/report",
                "name": "report.pdf",
                "data": "embedded bytes",
                "headers": {"Authorization": "Bearer upstream-secret"},
                "vendorField": {"notPartOfFileValue": true}
            }
        });
        let files = collect_file_values(&value).expect("collect file");
        assert_eq!(files.len(), 1);
        replace_file_at_path(
            &mut value,
            &files[0].0,
            FileValue {
                uri: "mcp-file://gateway/01999999-9999-7999-8999-999999999999".to_owned(),
                name: Some("report.pdf".to_owned()),
                mime_type: Some("application/pdf".to_owned()),
                size: Some(42),
                digest: None,
            },
        )
        .expect("replace file");

        assert!(value["result"].get("data").is_none());
        assert!(value["result"].get("headers").is_none());
        assert!(value["result"].get("vendorField").is_none());
        assert_eq!(value["result"]["size"], 42);
        assert_eq!(value["result"]["mimeType"], "application/pdf");
    }

    #[test]
    fn only_annotated_gateway_file_inputs_are_selected_for_delivery() {
        let schema = json!({
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "x-mcp-file": {"transferModes": ["upload"]}
                },
                "ordinary_url": {"type": "string", "format": "uri"}
            }
        });
        let arguments = json!({
            "file": "mcp-file://gateway/01999999-9999-7999-8999-999999999999",
            "ordinary_url": "https://caller.example/private-file"
        });

        let files =
            collect_file_inputs(&schema, None, &arguments).expect("collect annotated inputs");

        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].file.uri,
            "mcp-file://gateway/01999999-9999-7999-8999-999999999999"
        );
    }

    #[test]
    fn file_annotations_follow_the_validated_schema_path() {
        let annotation = json!({
            "type": "string",
            "x-mcp-file": {"transferModes": ["upload"]}
        });
        let schema = json!({
            "type": "object",
            "properties": {
                "mode": {"const": "with-file"},
                "conditional": {"type": "string"},
                "dependent_trigger": true,
                "dependent_file": {"type": "string"},
                "composed": {
                    "allOf": [
                        {
                            "type": "string",
                            "x-mcp-file": {
                                "accept": ["image/*"],
                                "transferModes": ["upload"]
                            }
                        },
                        {
                            "x-mcp-file": {
                                "maxSize": 7,
                                "transferModes": ["upload"]
                            }
                        }
                    ]
                },
                "tuple": {
                    "type": "array",
                    "prefixItems": [annotation.clone()],
                    "items": false
                },
                "matching_item": {
                    "type": "array",
                    "contains": annotation.clone()
                },
                "open_object": {
                    "type": "object",
                    "properties": {"ordinary": {"type": "string"}},
                    "unevaluatedProperties": annotation.clone()
                },
                "open_tuple": {
                    "type": "array",
                    "prefixItems": [{"type": "string"}],
                    "unevaluatedItems": annotation.clone()
                }
            },
            "if": {
                "properties": {"mode": {"const": "with-file"}},
                "required": ["mode"]
            },
            "then": {
                "properties": {"conditional": annotation.clone()}
            },
            "dependentSchemas": {
                "dependent_trigger": {
                    "properties": {"dependent_file": annotation.clone()}
                }
            },
            "patternProperties": {
                "^(?=image_)": annotation.clone(),
                "^(?=ordinary_)": {"type": "string"}
            },
            "additionalProperties": annotation
        });
        let arguments = json!({
            "mode": "with-file",
            "conditional": "mcp-file://gateway/01999999-9999-7999-8999-999999999990",
            "dependent_trigger": true,
            "dependent_file": "mcp-file://gateway/01999999-9999-7999-8999-999999999994",
            "composed": "mcp-file://gateway/01999999-9999-7999-8999-999999999998",
            "tuple": ["mcp-file://gateway/01999999-9999-7999-8999-999999999991"],
            "matching_item": ["mcp-file://gateway/01999999-9999-7999-8999-999999999995"],
            "open_object": {
                "ordinary": "not a file",
                "attachment": "mcp-file://gateway/01999999-9999-7999-8999-999999999996"
            },
            "open_tuple": [
                "not a file",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999997"
            ],
            "image_cover": "mcp-file://gateway/01999999-9999-7999-8999-999999999992",
            "attachment": "mcp-file://gateway/01999999-9999-7999-8999-999999999993",
            "ordinary_link": "https://caller.example/file"
        });

        let files =
            collect_file_inputs(&schema, None, &arguments).expect("collect annotated inputs");
        let mut uris = files
            .iter()
            .map(|input| input.file.uri.as_str())
            .collect::<Vec<_>>();
        uris.sort_unstable();

        assert_eq!(
            uris,
            vec![
                "mcp-file://gateway/01999999-9999-7999-8999-999999999990",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999991",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999992",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999993",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999994",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999995",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999996",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999997",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999998",
            ]
        );
        let composed = files
            .iter()
            .find(|input| input.file.uri.ends_with("999998"))
            .expect("composed file input");
        assert_eq!(composed.constraints.len(), 2);
        assert!(
            enforce_file_input_constraints(&composed.constraints, Some("image/png"), None, 7)
                .is_ok()
        );
        assert!(
            enforce_file_input_constraints(&composed.constraints, Some("text/plain"), None, 7)
                .is_err()
        );
        assert!(
            enforce_file_input_constraints(&composed.constraints, Some("image/png"), None, 8)
                .is_err()
        );
    }

    #[test]
    fn file_annotations_apply_only_from_matching_schema_alternatives() {
        let schema = json!({
            "type": "object",
            "properties": {
                "source": {
                    "anyOf": [
                        {
                            "type": "object",
                            "x-mcp-file": {"transferModes": ["upload"]}
                        },
                        {"type": "string"}
                    ]
                }
            }
        });
        let arguments = json!({
            "source": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"
        });

        let files =
            collect_file_inputs(&schema, None, &arguments).expect("collect annotated inputs");

        assert!(files.is_empty());

        let annotated_arguments = json!({
            "source": {
                "uri": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"
            }
        });
        let files = collect_file_inputs(&schema, None, &annotated_arguments)
            .expect("collect matching annotated alternative");
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn file_input_constraints_apply_before_delivery() {
        let accepted = FileInputDescriptor {
            accept: Some(vec!["image/*".to_owned()]),
            max_size: Some(10),
            transfer_modes: Some(vec![FileTransferMode::Upload]),
        };
        assert!(enforce_file_input_constraints(
            std::slice::from_ref(&accepted),
            Some("image/png"),
            None,
            10
        )
        .is_ok());
        assert!(enforce_file_input_constraints(
            std::slice::from_ref(&accepted),
            Some("text/plain"),
            None,
            10
        )
        .is_err());
        assert!(enforce_file_input_constraints(
            std::slice::from_ref(&accepted),
            Some("image/png"),
            None,
            11
        )
        .is_err());
        assert!(
            enforce_file_input_constraints(std::slice::from_ref(&accepted), None, None, 1).is_err()
        );
    }

    #[test]
    fn transfer_modes_reject_values_using_a_disallowed_path() {
        let schema = json!({
            "type": "object",
            "properties": {
                "upload_only": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}},
                "inline_only": {"type": "string", "x-mcp-file": {"transferModes": ["inline"]}}
            }
        });

        // An upload-only field must not carry the payload inside JSON-RPC.
        let inline_at_upload_only = json!({"upload_only": "data:text/plain;base64,aGVsbG8="});
        let error = collect_file_inputs(&schema, None, &inline_at_upload_only)
            .expect_err("inline value at an upload-only field must be rejected");
        assert!(error.to_string().contains("does not admit inline"));
        // Refusals carry the bounded machine-readable recovery category so
        // clients route on it rather than parsing prose.
        assert_eq!(
            // Assert the literal wire key: it is the external contract.
            error.data.expect("refusal carries data")["error"],
            "invalid_file_input"
        );

        // An inline-only field must not receive an opaque gateway-private URI
        // the upstream cannot resolve.
        let gateway_at_inline_only = json!({
            "inline_only": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"
        });
        let error = collect_file_inputs(&schema, None, &gateway_at_inline_only)
            .expect_err("gateway file reference at an inline-only field must be rejected");
        assert!(error.to_string().contains("does not admit uploaded"));

        // A field with no declared modes admits both paths: the inline value
        // stays in place and the gateway reference is selected for delivery.
        let open_schema = json!({
            "type": "object",
            "properties": {
                "either_a": {"type": "string", "x-mcp-file": {}},
                "either_b": {"type": "string", "x-mcp-file": {}}
            }
        });
        let both = json!({
            "either_a": "data:text/plain,hello",
            "either_b": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"
        });
        let files = collect_file_inputs(&open_schema, None, &both).expect("both modes admitted");
        assert_eq!(files.len(), 1);
        assert!(files[0].file.uri.starts_with("mcp-file://gateway/"));
    }

    #[test]
    fn inline_values_obey_declared_size_and_media_constraints() {
        let schema = json!({
            "type": "object",
            "properties": {
                "note": {
                    "type": "string",
                    "x-mcp-file": {
                        "accept": ["text/plain"],
                        "maxSize": 5,
                        "transferModes": ["inline"]
                    }
                }
            }
        });

        // Decoded size is what counts, for percent-encoded and base64 payloads
        // alike; the base64 wire form is longer than five bytes.
        for admitted in [
            json!({"note": "data:,hello"}),
            json!({"note": "data:text/plain;base64,aGVsbG8="}),
            json!({"note": "data:text/plain;base64,YQ=="}),
            // Omitted padding is valid forgiving base64 (the form browsers
            // accept for data: URLs); the decoded size is still exact.
            json!({"note": "data:text/plain;base64,YQ"}),
            // Header parameters are not consumed by any gateway policy and
            // pass through for the upstream's own parser.
            json!({"note": "data:text/plain;bogus,x"}),
            // Escaped and literal spellings of one media type are the same
            // type: the decoded essence matches the accept filter.
            json!({"note": "data:text/pl%61in,x"}),
            // A URI fragment is not payload: five data bytes plus a fragment
            // stay within the five-byte limit.
            json!({"note": "data:,hello#preview"}),
            json!({"note": "data:text/plain;base64,aGVsbG8=#preview"}),
        ] {
            assert!(collect_file_inputs(&schema, None, &admitted)
                .expect("admitted inline value")
                .is_empty());
        }

        let oversized = json!({"note": "data:,hello%20world"});
        let error = collect_file_inputs(&schema, None, &oversized)
            .expect_err("oversized inline value must be rejected");
        assert!(error.to_string().contains("size limit"));

        let oversized_base64 = json!({"note": "data:text/plain;base64,aGVsbG8gd29ybGQ="});
        assert!(collect_file_inputs(&schema, None, &oversized_base64).is_err());

        let wrong_media = json!({"note": "data:image/png;base64,aGVsbG8="});
        let error = collect_file_inputs(&schema, None, &wrong_media)
            .expect_err("inline media type must satisfy accept");
        assert!(error.to_string().contains("not accepted"));

        for malformed in [
            json!({"note": "data:text/plain;base64"}),
            json!({"note": "data:text/plain;base64,a!b="}),
            json!({"note": "data:text/plain;base64,abcde"}),
            json!({"note": "data:text/plain;base64,aGVsbG8==="}),
            json!({"note": "data:text/plain;base64,abc=="}),
            json!({"note": "data:text/plain;base64,ab="}),
            // Non-canonical: the unused low bits of the final symbol are set.
            json!({"note": "data:text/plain;base64,YR=="}),
            json!({"note": "data:,%zz"}),
            // The media-type essence is bounded; an oversized token is
            // refused instead of copied.
            json!({"note": format!("data:text/{},x", "y".repeat(300))}),
            // A declared essence must be two media-type tokens; a `%` in a
            // token needs its two-hex-digit escape.
            json!({"note": "data:not-a-media-type,hello"}),
            json!({"note": "data:a/b/c,hello"}),
            json!({"note": "data:text pl/plain,hello"}),
            json!({"note": "data:image/(png),hello"}),
            json!({"note": "data:text/%zz,hello"}),
            json!({"note": "data:text%20plain/plain,hello"}),
        ] {
            let error = collect_file_inputs(&schema, None, &malformed)
                .expect_err("malformed data: value is rejected");
            assert!(error.to_string().contains("malformed"));
        }
    }

    #[tokio::test]
    async fn storage_disabled_gateway_still_enforces_transfer_modes() {
        let context = || FileInputContext {
            principal: None,
            server: "printable".to_owned(),
            tool: "import".to_owned(),
            invocation_id: "admission-only".to_owned(),
            admitted_contract: waygate_mcp::catalog::InvocationContractIdentity {
                authority: waygate_mcp::catalog::InvocationContractAuthority::Catalog {
                    tool_id: "import".to_owned(),
                    catalog_schema_hash: "h".to_owned(),
                },
                input_schema_hash: None,
                output_schema_hash: None,
                tool_annotations_hash: None,
                action_metadata_hash: None,
                operations_hash: None,
                risk: waygate_mcp::catalog::InvocationRisk::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            compiled_input_schema: None,
        };
        let schema = json!({
            "type": "object",
            "properties": {
                "upload_only": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}},
                "note": {
                    "type": "string",
                    "x-mcp-file": {"maxSize": 5, "transferModes": ["inline"]}
                }
            }
        });
        let processor = AdmissionOnlyFileInputProcessor;

        // The mode contract holds without storage: inline bytes at an
        // upload-only field are refused, not forwarded.
        let mut smuggled = Some(
            json!({"upload_only": "data:text/plain,hello"})
                .as_object()
                .unwrap()
                .clone(),
        );
        let error =
            FileInputProcessor::prepare(&processor, context(), Some(&schema), &mut smuggled)
                .await
                .expect_err("inline value at an upload-only field is refused without storage");
        assert!(error.to_string().contains("does not admit inline"));

        // Admitted inline values pass their declared constraints and stay in
        // place; nothing is rewritten.
        let admitted = json!({"note": "data:,hello"}).as_object().unwrap().clone();
        let mut arguments = Some(admitted.clone());
        let rewritten =
            FileInputProcessor::prepare(&processor, context(), Some(&schema), &mut arguments)
                .await
                .expect("admitted inline value");
        assert!(!rewritten);
        assert_eq!(arguments, Some(admitted));
        let mut oversized = Some(
            json!({"note": "data:,hello%20world"})
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(
            FileInputProcessor::prepare(&processor, context(), Some(&schema), &mut oversized)
                .await
                .is_err()
        );

        // A gateway file reference cannot be delivered without storage and is
        // refused explicitly rather than forwarded as an unresolvable URI.
        let mut undeliverable = Some(
            json!({"upload_only": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"})
                .as_object()
                .unwrap()
                .clone(),
        );
        let error =
            FileInputProcessor::prepare(&processor, context(), Some(&schema), &mut undeliverable)
                .await
                .expect_err("gateway file reference is refused without storage");
        assert!(error.to_string().contains("not enabled"));

        // Tools without file inputs skip evaluation entirely.
        let plain_schema = json!({"type": "object", "properties": {"q": {"type": "string"}}});
        let mut plain = Some(json!({"q": 7}).as_object().unwrap().clone());
        assert!(!FileInputProcessor::prepare(
            &processor,
            context(),
            Some(&plain_schema),
            &mut plain
        )
        .await
        .expect("non-file tool is untouched"));
    }

    #[test]
    fn continuation_walker_collects_only_gateway_file_uris() {
        let value = json!({
            "answer": {
                "file": "mcp-file://gateway/01999999-9999-7999-8999-999999999999",
                "note": "not a file",
                "inline": "data:text/plain,hello",
                "other": "mcp-file://printable/private",
                "nested": [
                    {"more": "mcp-file://gateway/01999999-9999-7999-8999-999999999998"},
                    42
                ]
            }
        });
        let mut found = Vec::new();
        let mut path = Vec::new();
        collect_gateway_file_uris(&value, &mut path, &mut found);

        let mut uris: Vec<&str> = found.iter().map(|(_, uri)| uri.as_str()).collect();
        uris.sort_unstable();
        assert_eq!(
            uris,
            vec![
                "mcp-file://gateway/01999999-9999-7999-8999-999999999998",
                "mcp-file://gateway/01999999-9999-7999-8999-999999999999",
            ]
        );
    }

    #[tokio::test]
    async fn storage_disabled_gateway_refuses_continuation_file_references() {
        let processor = AdmissionOnlyFileInputProcessor;
        let context = FileInputContext {
            principal: None,
            server: "printable".to_owned(),
            tool: "import".to_owned(),
            invocation_id: "continuation-refusal".to_owned(),
            admitted_contract: waygate_mcp::catalog::InvocationContractIdentity {
                authority: waygate_mcp::catalog::InvocationContractAuthority::Catalog {
                    tool_id: "import".to_owned(),
                    catalog_schema_hash: "h".to_owned(),
                },
                input_schema_hash: None,
                output_schema_hash: None,
                tool_annotations_hash: None,
                action_metadata_hash: None,
                operations_hash: None,
                risk: waygate_mcp::catalog::InvocationRisk::Low,
                side_effects: false,
                pii: false,
                requires_approval: false,
                requires_approval_known: true,
            },
            compiled_input_schema: None,
        };

        let mut with_file = std::collections::BTreeMap::from([(
            "attachment".to_owned(),
            json!({"file": "mcp-file://gateway/01999999-9999-7999-8999-999999999999"}),
        )]);
        let error = FileInputProcessor::prepare_continuation(
            &processor,
            context.clone(),
            &mut with_file,
            &["attachment".to_owned()],
        )
        .await
        .expect_err("continuation file reference is refused without storage");
        assert!(error.to_string().contains("not enabled"));
        // The same refusal runs pre-quota through admission.
        assert!(FileInputProcessor::admit(
            &processor,
            None,
            None,
            &mut None,
            Some(&with_file),
            &[]
        )
        .is_err());

        let mut plain = std::collections::BTreeMap::from([("confirm".to_owned(), json!(true))]);
        assert!(
            !FileInputProcessor::prepare_continuation(&processor, context, &mut plain, &[])
                .await
                .expect("file-free continuation passes")
        );
    }

    #[test]
    fn multibyte_values_and_names_are_admitted_without_panicking() {
        // A schema-valid annotated string of multibyte characters has five or
        // more bytes without a character boundary at byte five; classifying
        // it must not slice mid-character.
        let schema = json!({
            "type": "object",
            "properties": {
                "file": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}}
            }
        });
        let multibyte = json!({"file": "ééé"});
        assert!(collect_file_inputs(&schema, None, &multibyte)
            .expect("non-file multibyte value passes through")
            .is_empty());

        // A hint whose byte length lands inside a multibyte character of the
        // name must evaluate as a non-match, not a panic.
        let hints_only = FileInputDescriptor {
            accept: Some(vec![".png".to_owned()]),
            max_size: None,
            transfer_modes: None,
        };
        assert!(
            enforce_file_input_constraint(&hints_only, Some("image/png"), Some("épng"), 1).is_err()
        );
        assert!(enforce_file_input_constraint(
            &hints_only,
            Some("image/png"),
            Some("naïve.png"),
            1
        )
        .is_ok());
    }

    #[test]
    fn inline_object_values_keep_their_declared_name_for_extension_hints() {
        let schema = json!({
            "type": "object",
            "properties": {
                "attachment": {
                    "type": "object",
                    "x-mcp-file": {"accept": [".png"], "transferModes": ["inline"]}
                }
            }
        });

        let mismatched = json!({
            "attachment": {"uri": "data:image/png;base64,aGVsbG8=", "name": "cover.jpg"}
        });
        let error = collect_file_inputs(&schema, None, &mismatched)
            .expect_err("named inline object must honor the declared extension filter");
        assert!(error.to_string().contains("extension"));

        let matched = json!({
            "attachment": {"uri": "data:image/png;base64,aGVsbG8=", "name": "cover.png"}
        });
        assert!(collect_file_inputs(&schema, None, &matched)
            .expect("matching inline object is admitted")
            .is_empty());

        // Explicit null for an optional member means absent, exactly as the
        // FileValue model deserializes it: a nameless file against a
        // hints-only list is admitted.
        let null_metadata = json!({
            "attachment": {"uri": "data:image/png;base64,aGVsbG8=", "name": null, "size": null}
        });
        assert!(collect_file_inputs(&schema, None, &null_metadata)
            .expect("null optional metadata is absent, not malformed")
            .is_empty());
    }

    #[test]
    fn base64_marker_is_case_insensitive_for_decoded_size() {
        // `;BASE64` is the same RFC 2397 marker; the decoded payload is five
        // bytes even though the encoded form is longer than the limit.
        let schema = json!({
            "type": "object",
            "properties": {
                "note": {
                    "type": "string",
                    "x-mcp-file": {"maxSize": 5, "transferModes": ["inline"]}
                }
            }
        });
        let upper = json!({"note": "data:text/plain;BASE64,aGVsbG8="});
        assert!(collect_file_inputs(&schema, None, &upper)
            .expect("case-variant base64 marker is measured by decoded size")
            .is_empty());
    }

    #[test]
    fn accept_extension_hints_are_picker_hints_not_mime_patterns() {
        let mixed = FileInputDescriptor {
            accept: Some(vec![".png".to_owned(), "application/pdf".to_owned()]),
            max_size: None,
            transfer_modes: None,
        };
        // Either vocabulary admits the file: a matching media type or a
        // matching (case-insensitive) filename extension.
        assert!(enforce_file_input_constraint(&mixed, Some("application/pdf"), None, 1).is_ok());
        assert!(
            enforce_file_input_constraint(&mixed, Some("image/png"), Some("cover.PNG"), 1).is_ok()
        );
        assert!(
            enforce_file_input_constraint(&mixed, Some("image/png"), Some("cover.jpg"), 1).is_err()
        );
        assert!(enforce_file_input_constraint(&mixed, Some("image/png"), None, 1).is_err());

        // A hints-only list never becomes a MIME-type denial: a nameless file
        // has nothing for the hint to inspect and passes, while a named file
        // still honors the declared filter.
        let hints_only = FileInputDescriptor {
            accept: Some(vec![".png".to_owned()]),
            max_size: None,
            transfer_modes: None,
        };
        assert!(enforce_file_input_constraint(&hints_only, Some("image/png"), None, 1).is_ok());
        assert!(enforce_file_input_constraint(
            &hints_only,
            Some("image/png"),
            Some("cover.png"),
            1
        )
        .is_ok());
        assert!(enforce_file_input_constraint(
            &hints_only,
            Some("image/png"),
            Some("cover.jpg"),
            1
        )
        .is_err());
    }

    #[test]
    fn strict_uri_string_inputs_round_trip_as_strings() {
        // The URI-string form is the SEP input contract: its replacement is
        // a plain string carrying only the authoritative URI, and it never
        // widens into the object-valued compatibility extension.
        let input = FileInput {
            path: Vec::new(),
            file: FileValue {
                uri: "mcp-file://gateway/01999999-9999-7999-8999-999999999999".to_owned(),
                name: None,
                mime_type: None,
                size: None,
                digest: None,
            },
            object_template: None,
            constraints: Vec::new(),
        };
        let replaced = replacement_file_value(
            &input,
            FileValue {
                uri: "https://upstream.example/private-file".to_owned(),
                name: Some("report.pdf".to_owned()),
                mime_type: Some("application/pdf".to_owned()),
                size: Some(42),
                digest: None,
            },
        )
        .expect("replace strict file input");

        assert_eq!(
            replaced,
            Value::String("https://upstream.example/private-file".to_owned())
        );
    }

    #[test]
    fn file_rewrite_preserves_fields_declared_by_the_tool_contract() {
        let input = FileInput {
            path: Vec::new(),
            file: FileValue {
                uri: "mcp-file://gateway/01999999-9999-7999-8999-999999999999".to_owned(),
                name: None,
                mime_type: Some("text/plain".to_owned()),
                size: Some(5),
                digest: None,
            },
            object_template: Some(
                json!({
                    "uri": "mcp-file://gateway/01999999-9999-7999-8999-999999999999",
                    "mimeType": "text/plain",
                    "purpose": "source-document"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            constraints: vec![FileInputDescriptor {
                accept: None,
                max_size: None,
                transfer_modes: Some(vec![FileTransferMode::Upload]),
            }],
        };
        let rewritten = replacement_file_value(
            &input,
            FileValue {
                uri: "mcp-file://upstream/private".to_owned(),
                name: None,
                mime_type: Some("text/plain".to_owned()),
                size: Some(5),
                digest: None,
            },
        )
        .expect("rewrite file value");

        assert_eq!(rewritten["uri"], "mcp-file://upstream/private");
        assert_eq!(rewritten["purpose"], "source-document");
    }

    #[test]
    fn file_authorization_accepts_equivalent_uri_scheme_casing() {
        let original = FileValue {
            uri: "MCP-FILE://upstream/report".to_owned(),
            name: None,
            mime_type: None,
            size: None,
            digest: None,
        };
        let authorized = FileValue {
            uri: "mcp-file://upstream/report".to_owned(),
            ..original.clone()
        };
        assert!(authorized_file_claims(&original, &authorized).is_ok());
    }

    #[test]
    fn authorization_only_display_text_stays_out_of_the_visible_file() {
        let original = FileValue {
            uri: "mcp-file://upstream/report".to_owned(),
            name: None,
            mime_type: None,
            size: None,
            digest: None,
        };
        let authorized = FileValue {
            uri: original.uri.clone(),
            name: Some("authorization-only name".to_owned()),
            mime_type: Some("application/pdf".to_owned()),
            size: Some(42),
            digest: None,
        };

        let claims = authorized_file_claims(&original, &authorized).expect("matching file");

        assert_eq!(claims.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(claims.size, Some(42));
        assert!(original.name.is_none());
        assert!(original.mime_type.is_none());
    }

    #[test]
    fn only_a_complete_http_representation_can_be_staged() {
        assert!(verify_complete_response_status(reqwest::StatusCode::OK).is_ok());
        assert!(verify_complete_response_status(reqwest::StatusCode::PARTIAL_CONTENT).is_err());
        assert!(verify_complete_response_status(reqwest::StatusCode::NO_CONTENT).is_err());
    }

    #[test]
    fn upload_requires_a_response_that_confirms_complete_storage() {
        for status in [
            reqwest::StatusCode::OK,
            reqwest::StatusCode::CREATED,
            reqwest::StatusCode::NO_CONTENT,
        ] {
            assert!(verify_upload_response_status(status).is_ok());
        }
        for status in [
            reqwest::StatusCode::ACCEPTED,
            reqwest::StatusCode::PARTIAL_CONTENT,
        ] {
            assert!(verify_upload_response_status(status).is_err());
        }
    }

    #[test]
    fn response_media_type_may_add_parameters_but_not_change_type() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/pdf; charset=binary"),
        );
        verify_response_media_type(Some("application/pdf"), &headers).expect("matching media type");
        assert!(verify_response_media_type(Some("image/png"), &headers).is_err());
    }

    #[test]
    fn expired_upstream_transfer_instructions_are_rejected_before_the_request() {
        assert!(verify_descriptor_expiry(Some("2000-01-01T00:00:00Z")).is_err());
        assert!(verify_descriptor_expiry(Some("not-a-time")).is_err());
        verify_descriptor_expiry(None).expect("descriptor may omit expiry");
    }

    #[test]
    fn file_public_url_requires_https_except_on_loopback() {
        assert_eq!(
            validate_file_public_url("https://gateway.example").unwrap(),
            "https"
        );
        assert_eq!(
            validate_file_public_url("http://127.0.0.1:8080").unwrap(),
            "http"
        );
        assert!(validate_file_public_url("http://0.0.0.0:8080").is_err());
        assert!(validate_file_public_url("http://gateway.example").is_err());
    }

    #[test]
    fn file_descriptor_cannot_override_the_request_destination() {
        assert!(descriptor_headers(&BTreeMap::from([(
            "Host".to_owned(),
            "metadata.internal".to_owned(),
        )]))
        .is_err());
        assert!(descriptor_headers(&BTreeMap::from([(
            "Authorization".to_owned(),
            "Bearer upstream-file-token".to_owned(),
        )]))
        .is_ok());
        assert!(descriptor_headers(&BTreeMap::from([(
            "Range".to_owned(),
            "bytes=0-99".to_owned(),
        )]))
        .is_err());
    }

    #[tokio::test]
    async fn untrusted_file_destination_cannot_resolve_to_loopback() {
        assert!(resolve_public_file_destination("127.0.0.1", 443)
            .await
            .is_err());
    }

    /// The round trip over TLS, which is every upstream that is not on a private
    /// cleartext segment.
    #[tokio::test]
    async fn real_mcp_upstream_file_becomes_a_gateway_reference_without_embedding_bytes() {
        upstream_file_round_trip(TransferScheme::Https).await;
    }

    /// The same round trip with plaintext descriptors, which is what the pinned
    /// cleartext-control-plane exception admits.
    ///
    /// This is the wiring the unit tests cannot reach: it proves the predicate is
    /// actually consulted by both production paths — the gateway uploads into the
    /// upstream's tool and downloads the files that tool returns — rather than
    /// merely being correct in isolation. The fake upstream's MCP endpoint is
    /// already `http://`, so the classification reaches `Pinned` with a cleartext
    /// control plane exactly as a private sidecar would.
    #[tokio::test]
    async fn a_pinned_cleartext_upstream_completes_a_plaintext_round_trip() {
        upstream_file_round_trip(TransferScheme::Http).await;
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TransferScheme {
        Http,
        Https,
    }

    impl TransferScheme {
        fn as_str(self) -> &'static str {
            match self {
                Self::Http => "http",
                Self::Https => "https",
            }
        }

        fn transport(self) -> FileTransport {
            serde_json::from_value(serde_json::json!(self.as_str()))
                .expect("a transport is a bare string")
        }
    }

    async fn upstream_file_round_trip(scheme: TransferScheme) {
        use sqlx::{migrate::MigrateDatabase, ConnectOptions};
        let Some(parent) = waygate_test_support::pg::audit_pool_or_skip().await else {
            return;
        };
        // The sweeper scans the entire database. Each independent byte root
        // therefore needs its own database, including concurrent round trips.
        let database_name = format!("waygate_round_trip_{}", uuid::Uuid::new_v4().simple());
        let options = parent
            .connect_options()
            .as_ref()
            .clone()
            .database(&database_name);
        let database_url = options.to_url_lossy().to_string();
        sqlx::Postgres::create_database(&database_url)
            .await
            .expect("create round-trip database");
        parent.close().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .expect("connect round-trip database");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrate round-trip database");
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tenant = format!("file-output-{}", uuid::Uuid::new_v4().simple());
        sqlx::query("INSERT INTO tenants (id, display_name) VALUES ($1, $1)")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed file-output tenant");

        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("test certificate");
        let certificate_der = certificate.cert.der().to_vec();
        let tls = axum_server::tls_rustls::RustlsConfig::from_der(
            vec![certificate_der.clone()],
            certificate.signing_key.serialize_der(),
        )
        .await
        .expect("TLS config");
        let uploaded_bytes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let upload_capture = uploaded_bytes.clone();
        let app = axum::Router::new()
            .route(
                "/file-a",
                axum::routing::get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        "hello",
                    )
                }),
            )
            .route(
                "/file-b",
                axum::routing::get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        "world",
                    )
                }),
            )
            .route(
                "/upload",
                axum::routing::put(move |body: axum::body::Bytes| {
                    let upload_capture = upload_capture.clone();
                    async move {
                        *upload_capture.lock().await = body.to_vec();
                        axum::http::StatusCode::NO_CONTENT
                    }
                }),
            );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind file endpoint");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("file endpoint address");
        let file_server = tokio::spawn(async move {
            match scheme {
                TransferScheme::Https => axum_server::from_tcp_rustls(listener, tls)
                    .expect("TLS listener")
                    .serve(app.into_make_service())
                    .await
                    .expect("serve file endpoint"),
                TransferScheme::Http => axum_server::from_tcp(listener)
                    .expect("plaintext listener")
                    .serve(app.into_make_service())
                    .await
                    .expect("serve file endpoint"),
            }
        });
        let upstream_file_a = FileValue {
            uri: "mcp-file://printable/output-a".to_owned(),
            name: Some("output-a.bin".to_owned()),
            mime_type: Some("application/octet-stream".to_owned()),
            size: Some(5),
            digest: Some(FileDigest {
                algorithm: "sha-256".to_owned(),
                value: URL_SAFE_NO_PAD.encode(Sha256::digest(b"hello")),
            }),
        };
        let upstream_file_b = FileValue {
            uri: "mcp-file://printable/output-b".to_owned(),
            name: Some("output-b.bin".to_owned()),
            mime_type: Some("application/octet-stream".to_owned()),
            size: Some(5),
            digest: Some(FileDigest {
                algorithm: "sha-256".to_owned(),
                value: URL_SAFE_NO_PAD.encode(Sha256::digest(b"world")),
            }),
        };
        let descriptor = |path: &str| FileTransferDescriptor {
            transport: scheme.transport(),
            method: TransferMethod::GET,
            url: format!("{}://{address}/{path}", scheme.as_str()),
            headers: BTreeMap::new(),
            multipart: None,
            expires_at: Some(format_ts_rfc3339(
                OffsetDateTime::now_utc() + time::Duration::minutes(5),
            )),
        };
        let (upstream_address, authorized, imported_arguments, upstream_authorization_meta) =
            spawn_printable_upstream(
                vec![
                    AuthorizeDownloadResult {
                        file: upstream_file_a.clone(),
                        sensitivity: Some(waygate_mcp::files::FileSensitivity::Secret),
                        download: descriptor("file-a"),
                    },
                    AuthorizeDownloadResult {
                        file: upstream_file_b,
                        sensitivity: None,
                        download: descriptor("file-b"),
                    },
                ],
                Some(AuthorizeUploadResult {
                    file: FileValue {
                        uri: "mcp-file://printable/imported".to_owned(),
                        name: None,
                        mime_type: Some("application/octet-stream".to_owned()),
                        size: Some(5),
                        digest: Some(FileDigest {
                            algorithm: "sha-256".to_owned(),
                            value: URL_SAFE_NO_PAD.encode(Sha256::digest(b"hello")),
                        }),
                    },
                    upload: FileTransferDescriptor {
                        transport: scheme.transport(),
                        method: TransferMethod::PUT,
                        url: format!("{}://{address}/upload", scheme.as_str()),
                        headers: BTreeMap::new(),
                        multipart: None,
                        expires_at: Some(format_ts_rfc3339(
                            OffsetDateTime::now_utc() + time::Duration::minutes(5),
                        )),
                    },
                    download: None,
                }),
            )
            .await;
        let catalog = connect_printable(upstream_address).await;
        let root = tempfile::tempdir().expect("file storage root");
        let storage = Arc::new(
            GatewayFileStorage::new(pool.clone(), root.path())
                .await
                .expect("file storage"),
        );
        let test_certificate =
            reqwest::Certificate::from_der(&certificate_der).expect("trusted test certificate");
        // A plaintext run trusts no extra root: if the exception were wired wrong
        // and the transfer fell back to TLS, there would be nothing to verify
        // against and the test would fail rather than quietly pass.
        let roots = match scheme {
            TransferScheme::Https => vec![test_certificate.clone()],
            TransferScheme::Http => Vec::new(),
        };
        let mut builder =
            waygate_core::http_client::builder(waygate_core::http_client::Profile::NoTotalTimeout)
                .redirect(reqwest::redirect::Policy::none());
        for root in &roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let http = builder.build().expect("file client");
        let evidence = Arc::new(waygate_mcp::audit::InMemorySink::new());
        let admission = FileTransferAdmission::new(8);
        let processor = Arc::new(OutboundFileProcessor {
            catalog: catalog.clone(),
            storage: storage.clone(),
            audit: evidence.clone(),
            http,
            native_https: scheme == TransferScheme::Https,
            additional_root_certificates: roots,
            retention: FileRetention {
                general: Duration::from_secs(3600),
                secret: Duration::from_secs(120),
            },
            max_bytes: None,
            admission: admission.clone(),
            resource_preparation_timeout: resource_file_preparation_timeout(),
        });
        let actor = Principal {
            sub: "file-user".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "test-issuer".to_owned(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::parse(&tenant).expect("tenant"),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: Vec::new(),
        };
        let transfer_authority = Arc::new(TransferAuthority::new(
            Arc::new(waygate_transfer::PgTransferStore::new(pool.clone())),
            evidence.clone(),
            waygate_transfer::DpopVerifier::new(
                time::Duration::minutes(5),
                time::Duration::seconds(30),
            )
            .expect("DPoP verifier"),
        ));
        let public_url = "https://gateway.example";
        let native_quota = Arc::new(RecordingQuota {
            calls: AtomicUsize::new(0),
        });
        let native_authorizer = Arc::new(NativeFileAuthorizer::new(
            transfer_authority.clone(),
            storage.clone(),
            admission.clone(),
            Some(native_quota.clone()),
            evidence.clone(),
            public_url.to_owned(),
            true,
        ));
        let file_tools = Arc::new(crate::mcp_files::GatewayFileTools::new(
            transfer_authority.clone(),
            storage.clone(),
            admission.clone(),
            None,
            evidence.clone(),
            public_url.to_owned(),
            "https".to_owned(),
        ));
        let shared_catalog: SharedCatalog = catalog.clone();
        let allow_native_download = Arc::new(AtomicBool::new(false));
        let observed_native_download = Arc::new(AtomicBool::new(false));
        let authz: waygate_mcp::SharedAuthz = Arc::new(FilePolicyGate {
            allow_native_download: allow_native_download.clone(),
            observed_native_download: observed_native_download.clone(),
        });
        let invocation = Arc::new(
            DefaultInvocationService::new(shared_catalog.clone(), authz.clone(), evidence.clone())
                .with_file_input_processor(Some(processor.clone()))
                .with_file_output_processor(Some(processor.clone())),
        );
        let handler = GatewayServer::with_deps(shared_catalog, authz, evidence.clone())
            .with_invocation_service(invocation)
            .with_builtin_tools(file_tools)
            .with_file_download_authorizer(Some(native_authorizer));
        let factory = handler.clone();
        let service = StreamableHttpService::new(
            move || Ok(factory.clone()),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default().with_legacy_session_mode(true),
        );
        let gateway_app: axum::Router<()> = axum::Router::new()
            .nest_service("/mcp", service)
            .layer(axum::Extension(actor.clone()));
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway MCP server");
        let gateway_address = gateway_listener.local_addr().expect("gateway address");
        let waygate_server = tokio::spawn(async move {
            axum::serve(gateway_listener, gateway_app)
                .await
                .expect("serve gateway MCP server");
        });
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(Arc::from(format!(
                "http://{gateway_address}/mcp"
            ))),
        );
        let client: rmcp::service::RunningService<RoleClient, ClientInfo> = ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("file-aware-test-client", "0.0.0"),
        )
        .serve(transport)
        .await
        .expect("connect to gateway MCP server");

        let result = client
            .call_tool(CallToolRequestParams::new("printable.render"))
            .await
            .expect("call printable through production invocation path");
        assert_eq!(authorized.load(Ordering::SeqCst), 2);
        let visible = serde_json::to_string(&result).expect("serialize tool result");
        assert_eq!(visible.matches("mcp-file://gateway/").count(), 2);
        assert!(!visible.contains("hello"));
        assert!(!visible.contains("world"));
        assert!(!visible.contains("mcp-file://printable/output-a"));
        assert!(!visible.contains("mcp-file://printable/output-b"));
        let gateway_uris = result.structured_content.as_ref().unwrap()["files"]
            .as_array()
            .expect("gateway file array")
            .iter()
            .map(|file| file["uri"].as_str().expect("gateway file URI").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(gateway_uris.len(), 2);
        // The upstream marked output-a secret: through the whole production
        // invocation path its published copy must carry the short window while
        // the unhinted sibling keeps the general one.
        let expiry_of = |uri: &str| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            let uri = uri.to_owned();
            async move {
                sqlx::query_scalar::<_, OffsetDateTime>(
                    "SELECT expires_at FROM gateway_files \
                     WHERE upstream_uri = $1 AND tenant_id = $2",
                )
                .bind(uri)
                .bind(tenant)
                .fetch_one(&pool)
                .await
                .expect("read published expiry")
            }
        };
        let now = OffsetDateTime::now_utc();
        assert!(
            expiry_of("mcp-file://printable/output-a").await <= now + time::Duration::minutes(3),
            "the secret-marked file keeps the short window end to end"
        );
        assert!(
            expiry_of("mcp-file://printable/output-b").await > now + time::Duration::minutes(30),
            "the unhinted sibling keeps the general window"
        );
        let owner = owner_from_principal(&actor);
        let mut ready_files = Vec::new();
        for uri in &gateway_uris {
            let file_id = parse_gateway_file_uri(uri).expect("gateway file id");
            ready_files.push(
                storage
                    .find_ready(&owner, file_id)
                    .await
                    .expect("ready lookup")
                    .expect("ready file"),
            );
        }
        let ready_id = ready_files[0].id;
        let ready_invocation_id = ready_files[0].invocation_id.clone();
        let batch_id: uuid::Uuid =
            sqlx::query_scalar("SELECT batch_id FROM gateway_files WHERE id = $1")
                .bind(ready_id)
                .fetch_one(&pool)
                .await
                .expect("file batch id");
        let published_files: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM gateway_files WHERE batch_id = $1 AND state = 'ready'",
        )
        .bind(batch_id)
        .fetch_one(&pool)
        .await
        .expect("published file count");
        assert_eq!(published_files, 2);
        let gateway_uri = gateway_uris[0].clone();

        let mut source_confined_actor = actor.clone();
        source_confined_actor.api_key_profile_restrictions =
            Some(waygate_oidc::ApiKeyProfileRestrictions {
                profile_id: "import-only".to_owned(),
                profile_name: "import-only".to_owned(),
                allowed_servers: Some(vec!["printable".to_owned()]),
                allowed_tools: Some(vec!["printable.import".to_owned()]),
            });
        let import_schema = json!({
            "type": "object",
            "properties": {
                "file": {
                    "type": "object",
                    "properties": {"uri": {"type": "string", "format": "uri"}},
                    "required": ["uri"],
                    "additionalProperties": false,
                    "x-mcp-file": {"transferModes": ["upload"]}
                }
            },
            "required": ["file"]
        });
        let mut confined_arguments = Some(
            json!({"file": {"uri": gateway_uri.clone()}})
                .as_object()
                .expect("confined import arguments")
                .clone(),
        );
        let authorization_count = authorized.load(Ordering::SeqCst);
        let admitted_contract =
            match waygate_mcp::catalog::UpstreamCatalog::resolve_invocation_tool(
                catalog.as_ref(),
                &tenant,
                "printable",
                "import",
            )
            .await
            {
                waygate_mcp::catalog::ResolvedInvocationTool::Ready(snapshot) => {
                    snapshot.contract_identity()
                }
                waygate_mcp::catalog::ResolvedInvocationTool::Quarantined { .. } => {
                    panic!("test import tool is admitted")
                }
                waygate_mcp::catalog::ResolvedInvocationTool::Unavailable { .. } => {
                    panic!("test catalog is available")
                }
            };
        let mut stale_contract = admitted_contract.clone();
        stale_contract.side_effects = !stale_contract.side_effects;
        let refused = waygate_mcp::catalog::UpstreamCatalog::authorize_file_upload(
            catalog.as_ref(),
            "printable",
            "import",
            AuthorizeUploadParams {
                meta: BTreeMap::new(),
                name: Some("stale.txt".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                size: Some(5),
                digest: None,
            },
            Some(&actor),
            &stale_contract,
        )
        .await
        .expect_err("stale tool contract must be refused before file authorization");
        assert!(
            refused.to_string().contains("changed during call setup"),
            "unexpected refusal: {refused}"
        );
        assert_eq!(authorized.load(Ordering::SeqCst), authorization_count);
        let rejecting_schema = json!({
            "type": "object",
            "properties": {
                "file": {
                    "type": "object",
                    "properties": {
                        "uri": {
                            "type": "string",
                            "pattern": "^mcp-file://gateway/"
                        }
                    },
                    "required": ["uri"],
                    "additionalProperties": false,
                    "x-mcp-file": {"transferModes": ["upload"]}
                }
            },
            "required": ["file"]
        });
        let mut rejecting_arguments = Some(
            json!({"file": {"uri": gateway_uri.clone()}})
                .as_object()
                .unwrap()
                .clone(),
        );
        FileInputProcessor::prepare(
            processor.as_ref(),
            FileInputContext {
                principal: Some(actor.clone()),
                server: "printable".to_owned(),
                tool: "import".to_owned(),
                invocation_id: "schema-refusal".to_owned(),
                admitted_contract: admitted_contract.clone(),
                compiled_input_schema: None,
            },
            Some(&rejecting_schema),
            &mut rejecting_arguments,
        )
        .await
        .expect_err("rewritten arguments must validate before bytes move");
        let authorization_count = authorized.load(Ordering::SeqCst);
        assert_eq!(authorization_count, 3);
        assert!(uploaded_bytes.lock().await.is_empty());
        let confined = FileInputProcessor::prepare(
            processor.as_ref(),
            FileInputContext {
                principal: Some(source_confined_actor),
                server: "printable".to_owned(),
                tool: "import".to_owned(),
                invocation_id: "confined-import".to_owned(),
                admitted_contract: admitted_contract.clone(),
                compiled_input_schema: None,
            },
            Some(&import_schema),
            &mut confined_arguments,
        )
        .await
        .expect_err("a destination-only profile must not export a source-confined file");
        assert!(confined.to_string().contains("unavailable or expired"));
        assert_eq!(authorized.load(Ordering::SeqCst), authorization_count);

        let import_arguments = json!({"file": {"uri": gateway_uri.clone()}})
            .as_object()
            .expect("import arguments")
            .clone();
        let import_result = client
            .call_tool(
                CallToolRequestParams::new("printable.import").with_arguments(import_arguments),
            )
            .await
            .expect("import gateway file through production invocation path");
        assert!(!import_result.is_error.unwrap_or(false));
        assert_eq!(authorized.load(Ordering::SeqCst), 4);
        assert_eq!(uploaded_bytes.lock().await.as_slice(), b"hello");
        let imported = imported_arguments
            .lock()
            .await
            .clone()
            .expect("upstream import arguments");
        assert_eq!(imported["file"]["uri"], "mcp-file://printable/imported");
        assert_eq!(imported["file"].as_object().unwrap().len(), 1);
        assert!(!serde_json::to_string(&imported)
            .expect("serialize imported arguments")
            .contains("mcp-file://gateway/"));
        // Every file authorization the upstream received must carry the
        // gateway's own capability declaration for that transfer direction.
        // A stateless leg stamps the same metadata key onto every request from
        // the connection's declared capabilities, which cannot express file
        // support, so an emission that only rides in the request params is
        // replaced before it leaves the gateway.
        let observed_authorizations = upstream_authorization_meta.lock().await.clone();
        assert!(!observed_authorizations.is_empty());
        for (method, meta) in &observed_authorizations {
            assert!(
                meta.contains_key("io.modelcontextprotocol/protocolVersion"),
                "{method} did not travel on a stateless leg, so this asserts nothing"
            );
            let direction = if method == waygate_mcp::files::AUTHORIZE_UPLOAD_METHOD {
                waygate_mcp::files::FileOperation::Upload
            } else {
                waygate_mcp::files::FileOperation::Download
            };
            let declared = meta
                .get(CLIENT_CAPABILITIES_META_KEY)
                .and_then(|capabilities| {
                    capabilities.get(waygate_mcp::files::FILES_CAPABILITY_MEMBER)
                })
                .unwrap_or_else(|| panic!("{method} carried no file capability declaration"));
            let mut expected = waygate_mcp::files::stateless_client_file_capability(direction);
            expected["transports"]
                .as_array_mut()
                .expect("the gateway file capability declares transports")
                .push(Value::String("http".to_owned()));
            assert_eq!(declared, &expected);
        }
        let delivery_evidence = evidence.snapshot_with_posture().await;
        let started = delivery_evidence
            .iter()
            .find(|record| record.event.action == "file_transfer.file.delivery_started")
            .expect("durable file-delivery start evidence");
        assert_eq!(
            started.posture,
            waygate_mcp::audit::EvidencePosture::Required
        );
        let delivery = delivery_evidence
            .iter()
            .find(|record| record.event.action == "file_transfer.file.delivered")
            .expect("durable file-delivery evidence");
        assert_eq!(
            delivery.posture,
            waygate_mcp::audit::EvidencePosture::Required
        );
        let delivery_target: Value = serde_json::from_str(
            delivery
                .event
                .target
                .as_deref()
                .expect("delivery evidence target"),
        )
        .expect("delivery evidence JSON");
        assert_eq!(
            delivery_target["preparation_invocation_id"],
            ready_invocation_id
        );
        assert!(delivery_target["consuming_invocation_id"].is_string());
        assert!(delivery_target.get("upstream_file_uri").is_none());
        assert_eq!(delivery_target["destination_server"], "printable");
        assert_eq!(delivery_target["destination_tool"], "import");

        // An elicited file inside an MRTR continuation follows the same
        // delivery path: the caller-owned gateway reference nested in the
        // caller-authored response is delivered to the upstream and replaced
        // with the upstream-private URI before the retry dispatches, and the
        // gateway reference never reaches the wire value.
        // The same file mentioned twice is one delivery: both locations are
        // rewritten, and only one upstream authorization is taken.
        let before_continuation = authorized.load(Ordering::SeqCst);
        let mut continuation = std::collections::BTreeMap::from([(
            "attachment".to_owned(),
            json!({"answer": {"file": gateway_uri.clone()}, "again": gateway_uri.clone()}),
        )]);
        let continuation_rewritten = FileInputProcessor::prepare_continuation(
            processor.as_ref(),
            FileInputContext {
                principal: Some(actor.clone()),
                server: "printable".to_owned(),
                tool: "import".to_owned(),
                invocation_id: "elicited-import".to_owned(),
                admitted_contract: admitted_contract.clone(),
                compiled_input_schema: None,
            },
            &mut continuation,
            &["attachment".to_owned()],
        )
        .await
        .expect("deliver elicited continuation file");
        assert!(continuation_rewritten);
        assert_eq!(
            continuation["attachment"]["answer"]["file"],
            "mcp-file://printable/imported"
        );
        assert_eq!(
            continuation["attachment"]["again"], "mcp-file://printable/imported",
            "every location of one file is rewritten"
        );
        assert_eq!(
            authorized.load(Ordering::SeqCst),
            before_continuation + 1,
            "a file repeated in the continuation is delivered once"
        );
        assert!(!serde_json::to_string(&continuation)
            .expect("serialize continuation")
            .contains("mcp-file://gateway/"));

        // More distinct files than one elicitation answer may carry is
        // refused by the production processor, and the refusal comes from
        // the walk rather than after it: the caller cannot force unbounded
        // work by sending more references than the limit allows.
        let mut oversized = std::collections::BTreeMap::from([(
            "attachment".to_owned(),
            json!((0..=limits().file_count)
                .map(|index| json!(format!(
                    "mcp-file://gateway/01999999-9999-7999-8999-9999999999{index:02}"
                )))
                .collect::<Vec<_>>()),
        )]);
        let over_limit = FileInputProcessor::prepare_continuation(
            processor.as_ref(),
            FileInputContext {
                principal: Some(actor.clone()),
                server: "printable".to_owned(),
                tool: "import".to_owned(),
                invocation_id: "elicited-oversized".to_owned(),
                admitted_contract: admitted_contract.clone(),
                compiled_input_schema: None,
            },
            &mut oversized,
            &["attachment".to_owned()],
        )
        .await
        .expect_err("an over-limit continuation is refused");
        assert!(
            over_limit.message.contains("at most"),
            "unexpected refusal: {}",
            over_limit.message
        );

        // One file named at more locations than collection will accumulate
        // is refused on the ceiling rather than walked to the end, so the
        // work is bounded even when every reference is the same file.
        let mut repetitive = std::collections::BTreeMap::from([(
            "attachment".to_owned(),
            json!((0..=limits().file_locations)
                .map(|_| json!(gateway_uri.clone()))
                .collect::<Vec<_>>()),
        )]);
        let over_locations = FileInputProcessor::prepare_continuation(
            processor.as_ref(),
            FileInputContext {
                principal: Some(actor.clone()),
                server: "printable".to_owned(),
                tool: "import".to_owned(),
                invocation_id: "elicited-repetitive".to_owned(),
                admitted_contract: admitted_contract.clone(),
                compiled_input_schema: None,
            },
            &mut repetitive,
            &["attachment".to_owned()],
        )
        .await
        .expect_err("a continuation over the location ceiling is refused");
        assert!(
            over_locations.message.contains("file references"),
            "unexpected refusal: {}",
            over_locations.message
        );
        assert_eq!(authorized.load(Ordering::SeqCst), 5);
        assert_eq!(uploaded_bytes.lock().await.as_slice(), b"hello");

        let missing_capability = client
            .peer()
            .send_request(ClientRequest::CustomRequest(CustomRequest::new(
                waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD,
                Some(json!({"uri": gateway_uri})),
            )))
            .await
            .expect_err("native request without the file capability must fail");
        assert!(missing_capability
            .to_string()
            .contains("requires declared download support"));
        assert!(!observed_native_download.load(Ordering::SeqCst));

        let native_params = json!({
            "uri": gateway_uri,
            "_meta": {
                CLIENT_CAPABILITIES_META_KEY: {
                    "files": {"download": true, "transports": ["https"]}
                }
            }
        });
        let blocked = client
            .peer()
            .send_request(ClientRequest::CustomRequest(CustomRequest::new(
                waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD,
                Some(native_params.clone()),
            )))
            .await
            .expect_err("Cedar overlay must block native download authorization");
        assert!(blocked
            .to_string()
            .contains("file download blocked by test policy"));
        assert!(observed_native_download.load(Ordering::SeqCst));
        assert_eq!(native_quota.calls.load(Ordering::SeqCst), 0);
        allow_native_download.store(true, Ordering::SeqCst);

        let authorization = client
            .peer()
            .send_request(ClientRequest::CustomRequest(CustomRequest::new(
                waygate_mcp::files::AUTHORIZE_DOWNLOAD_METHOD,
                Some(native_params),
            )))
            .await
            .expect("authorize native file download");
        assert_eq!(native_quota.calls.load(Ordering::SeqCst), 1);
        let ServerResult::CustomResult(authorization) = authorization else {
            panic!("file authorization returned the wrong MCP result kind");
        };
        let authorization = authorization
            .result_as::<AuthorizeDownloadResult>()
            .expect("decode file authorization");
        assert_eq!(
            authorization.download.url,
            format!("{public_url}{}", waygate_transfer::FILE_DOWNLOAD_PATH)
        );
        let bearer = authorization
            .download
            .headers
            .get("Authorization")
            .expect("native bearer header");
        let download_app = waygate_transfer::file_download_router(
            transfer_authority,
            storage.clone(),
            public_url,
            admission,
        );
        let response = download_app
            .oneshot(
                axum::http::Request::builder()
                    .uri(waygate_transfer::FILE_DOWNLOAD_PATH)
                    .header(axum::http::header::AUTHORIZATION, bearer)
                    .body(axum::body::Body::empty())
                    .expect("download request"),
            )
            .await
            .expect("download response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("download body");
        assert_eq!(body.as_ref(), b"hello");

        let mut file_backed_resource = ReadResourceResult::new(vec![ResourceContents::text(
            "file-backed resource",
            "browser://screenshot/handle/capture.png",
        )]);
        let ResourceContents::TextResourceContents { meta, .. } =
            &mut file_backed_resource.contents[0]
        else {
            panic!("test resource must be text-backed");
        };
        meta.get_or_insert_with(Default::default).insert(
            waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY.to_owned(),
            serde_json::to_value(&upstream_file_a).expect("encode upstream resource file"),
        );
        let resource_invocation_id = uuid::Uuid::new_v4().to_string();
        let prepared_resource = FileOutputProcessor::prepare_resource(
            processor.as_ref(),
            FileOutputContext {
                principal: Some(actor.clone()),
                server: "printable".to_owned(),
                tool: "resources/read".to_owned(),
                invocation_id: resource_invocation_id.clone(),
            },
            file_backed_resource,
        )
        .await
        .expect("stage a file-backed resource through the production processor");
        assert_eq!(prepared_resource.file_count, 1);
        let resource_batch = prepared_resource
            .batch_id
            .as_deref()
            .expect("file-backed resource has a private batch");
        FileOutputProcessor::publish(processor.as_ref(), resource_batch, 1)
            .await
            .expect("publish file-backed resource batch");
        let resource_visible = serde_json::to_value(&prepared_resource.result)
            .expect("serialize governed file-backed resource");
        let resource_uri = resource_visible["contents"][0]["_meta"]
            [waygate_mcp::files::FILE_RESOURCE_CONTENT_META_KEY]["uri"]
            .as_str()
            .expect("governed resource file URI");
        assert!(resource_uri.starts_with("mcp-file://gateway/"));
        assert!(!resource_visible.to_string().contains(&upstream_file_a.uri));
        let resource_file_id = parse_gateway_file_uri(resource_uri).expect("resource file id");
        ready_files.push(
            storage
                .find_ready(&owner, resource_file_id)
                .await
                .expect("resource ready lookup")
                .expect("published resource file"),
        );
        assert_eq!(authorized.load(Ordering::SeqCst), 6);

        let evidence = evidence.snapshot().await;
        for action in [
            "file_transfer.bytes.received",
            "file_transfer.file.verified",
        ] {
            let matching = evidence
                .iter()
                .filter(|event| event.action == action)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 3);
            for event in matching {
                let target: serde_json::Value =
                    serde_json::from_str(event.target.as_deref().expect("file evidence target"))
                        .expect("structured file evidence target");
                assert_eq!(target["inspection_status"], "uninspectable");
                assert!(
                    target["invocation_id"] == ready_invocation_id
                        || target["invocation_id"] == resource_invocation_id
                );
                assert!(ready_files
                    .iter()
                    .any(|file| target["file_uri"] == file.uri()));
            }
        }
        assert!(evidence.iter().any(|event| {
            event.action == "CallTool" && event.id.to_string() == ready_invocation_id
        }));

        client.cancel().await.expect("stop gateway MCP client");
        waygate_server.abort();
        file_server.abort();
        let stored_paths = ready_files
            .iter()
            .map(|file| storage.path_for(file))
            .collect::<Vec<_>>();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("delete test tenant");
        let deletion: (String, Option<String>) =
            sqlx::query_as("SELECT state, tenant_id FROM gateway_files WHERE id = $1")
                .bind(ready_id)
                .fetch_one(&pool)
                .await
                .expect("tenant delete keeps a file cleanup record");
        assert_eq!(deletion, ("deleting".to_owned(), None));
        assert!(stored_paths.iter().all(|path| path.exists()));
        assert!(storage.sweep_expired(10).await.expect("sweep files") >= 2);
        assert!(stored_paths.iter().all(|path| !path.exists()));
        let retained_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM gateway_files WHERE batch_id = $1")
                .bind(batch_id)
                .fetch_one(&pool)
                .await
                .expect("count deleted file row");
        assert_eq!(retained_rows, 0);
        pool.close().await;
        sqlx::Postgres::drop_database(&database_url)
            .await
            .expect("remove round-trip database");
    }
}
