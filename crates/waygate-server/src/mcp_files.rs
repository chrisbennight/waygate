//! File download preparation for MCP clients that do not implement the draft
//! `files/authorizeDownload` method.

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use waygate_core::fmt::format_ts_rfc3339;
use waygate_core::RiskTier;
use waygate_mcp::audit::{AuditEvent, AuditOutcome, EvidenceCategory, SharedEvidence};
use waygate_mcp::authz::{profile_blocks_server, profile_blocks_tool};
use waygate_mcp::builtin::BuiltinProfileScope;
use waygate_mcp::files::{file_transfer_failure, invalid_file_request, FileTransferReason};
use waygate_mcp::{BuiltinCatalog, BuiltinSurfaceDescriptor, BuiltinTools, CatalogTool};
use waygate_oidc::Principal;
use waygate_transfer::{
    FileInspectionStatus, GatewayFileOwner, GatewayFileStorage, NewTransferGrant,
    TransferAuthority, TransferDigest, TransferDirection, TransferEndpoint, UploadState,
};

use crate::mcp_builtin::{schema_obj, structured};

pub const NAMESPACE: &str = waygate_core::FILES_BUILTIN_NAMESPACE;
const PREPARE_DOWNLOAD: &str = "prepare_download";
const PREPARE_UPLOAD: &str = "prepare_upload";
const UPLOAD_STATUS: &str = "upload_status";

pub struct GatewayFileTools {
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    admission: waygate_transfer::FileTransferAdmission,
    quota: Option<Arc<dyn waygate_quota::QuotaService>>,
    audit: SharedEvidence,
    public_url: String,
    public_transport: String,
    max_bytes: Option<u64>,
}

impl GatewayFileTools {
    pub fn new(
        authority: Arc<TransferAuthority>,
        storage: Arc<GatewayFileStorage>,
        admission: waygate_transfer::FileTransferAdmission,
        quota: Option<Arc<dyn waygate_quota::QuotaService>>,
        audit: SharedEvidence,
        public_url: String,
        public_transport: String,
    ) -> Self {
        Self {
            authority,
            storage,
            admission,
            quota,
            audit,
            public_url,
            public_transport,
            max_bytes: None,
        }
    }

    pub fn with_max_bytes(mut self, max_bytes: Option<u64>) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    async fn prepare_upload(
        &self,
        principal: &Principal,
        input: PrepareUploadInput,
    ) -> Result<CallToolResult, McpError> {
        enforce_upload_preparation_profile(principal)?;
        let _permit = self
            .admission
            .try_enter_for(&crate::file_transfer::owner_from_principal(principal))
            .map_err(|_| {
                file_transfer_failure(
                    FileTransferReason::TemporarilyUnavailable,
                    "file transfer capacity is currently full; retry later",
                )
            })?;
        let max_bytes = self.max_bytes.unwrap_or(i64::MAX as u64);
        if input.size.is_some_and(|size| size > max_bytes) {
            return Err(invalid_file_request(
                FileTransferReason::QuotaExhausted,
                "declared file size exceeds the configured upload limit",
            ));
        }
        let expected_digest = input
            .digest
            .as_ref()
            .map(decode_upload_digest)
            .transpose()?;
        self.check_quota(principal, PREPARE_UPLOAD).await?;
        let file_id = Uuid::new_v4();
        let file_uri = format!("mcp-file://gateway/{file_id}");
        let now = OffsetDateTime::now_utc();
        let grant = self
            .authority
            .create_grant(
                principal,
                NewTransferGrant {
                    invocation_id: Uuid::now_v7().to_string(),
                    file_uri: file_uri.clone(),
                    direction: TransferDirection::Upload,
                    source: TransferEndpoint::client(waygate_transfer::GENERIC_HELPER_REFERENCE)
                        .map_err(authority_error)?,
                    destination: TransferEndpoint::upstream("gateway", file_uri.clone())
                        .map_err(authority_error)?,
                    helper_jkt: input.helper_jkt,
                    max_bytes,
                    expected_size: input.size,
                    media_type: input.mime_type.clone(),
                    expected_digest,
                    max_requests: 1,
                    expires_at: now + Duration::minutes(15),
                    credential_ttl: Duration::minutes(5),
                },
                now,
            )
            .await
            .map_err(authority_error)?;
        let expires_at = format_ts_rfc3339(grant.expires_at);
        Ok(structured(&PrepareUploadOutput {
            file: GatewayFileValue {
                uri: file_uri,
                name: input.name,
                mime_type: input.mime_type.clone(),
                size: input.size,
                digest: input.digest.map(Into::into),
            },
            inspection_status: "uninspectable",
            grant_handle: grant.handle.as_str(),
            credential_exchange: self.credential_exchange(),
            upload: UploadDescriptor {
                transport: self.public_transport.clone(),
                method: "PUT",
                url: format!(
                    "{}{}",
                    self.public_url.trim_end_matches('/'),
                    waygate_transfer::FILE_UPLOAD_PATH,
                ),
                authorization_scheme: "DPoP",
                proof_header: "DPoP",
                content_type: input.mime_type,
                expires_at,
            },
        }))
    }

    async fn prepare_download(
        &self,
        principal: &Principal,
        input: PrepareDownloadInput,
    ) -> Result<CallToolResult, McpError> {
        let file_id = parse_file_uri(&input.uri)?;
        let owner = crate::file_transfer::owner_from_principal(principal);
        let _permit = self.admission.try_enter_for(&owner).map_err(|_| {
            file_transfer_failure(
                FileTransferReason::TemporarilyUnavailable,
                "file transfer capacity is currently full; retry later",
            )
        })?;
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
        if crate::file_transfer::profile_blocks_file_origin(
            principal,
            &file.upstream_server,
            &file.upstream_tool,
        ) {
            return Err(invalid_file_request(
                FileTransferReason::FileUnavailable,
                "file is unavailable or expired",
            ));
        }
        self.check_quota(principal, PREPARE_DOWNLOAD).await?;

        let now = OffsetDateTime::now_utc();
        let grant_expiry = std::cmp::min(file.expires_at, now + Duration::minutes(15));
        let grant = self
            .authority
            .create_grant(
                principal,
                NewTransferGrant {
                    invocation_id: file.invocation_id.clone(),
                    file_uri: file.uri(),
                    direction: TransferDirection::Download,
                    source: TransferEndpoint::upstream(
                        file.upstream_server.clone(),
                        file.upstream_uri.clone(),
                    )
                    .map_err(authority_error)?,
                    destination: TransferEndpoint::client(
                        waygate_transfer::GENERIC_HELPER_REFERENCE,
                    )
                    .map_err(authority_error)?,
                    helper_jkt: input.helper_jkt,
                    max_bytes: file.size.max(1),
                    expected_size: Some(file.size),
                    media_type: file.media_type.clone(),
                    expected_digest: Some(TransferDigest {
                        algorithm: "sha-256".to_owned(),
                        value: file.sha256.clone(),
                    }),
                    max_requests: 1,
                    expires_at: grant_expiry,
                    credential_ttl: Duration::minutes(5),
                },
                now,
            )
            .await
            .map_err(authority_error)?;

        let expires_at = format_ts_rfc3339(grant.expires_at);
        Ok(structured(&PrepareDownloadOutput {
            file: GatewayFileValue {
                uri: file.uri(),
                name: file.display_name,
                mime_type: file.media_type,
                size: Some(file.size),
                digest: Some(GatewayFileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: URL_SAFE_NO_PAD.encode(file.sha256),
                }),
            },
            inspection_status: match file.inspection_status {
                FileInspectionStatus::Checked => "checked",
                FileInspectionStatus::Uninspectable => "uninspectable",
            },
            grant_handle: grant.handle.as_str(),
            credential_exchange: self.credential_exchange(),
            download: DownloadDescriptor {
                transport: self.public_transport.clone(),
                method: "GET",
                url: format!(
                    "{}{}",
                    self.public_url.trim_end_matches('/'),
                    waygate_transfer::FILE_DOWNLOAD_PATH,
                ),
                authorization_scheme: "DPoP",
                proof_header: "DPoP",
                expires_at,
            },
        }))
    }

    async fn upload_status(
        &self,
        principal: &Principal,
        input: UploadStatusInput,
    ) -> Result<CallToolResult, McpError> {
        enforce_upload_status_profile(principal)?;
        let file_id = parse_file_uri(&input.uri)?;
        let status = self
            .authority
            .upload_status(principal, &input.uri, OffsetDateTime::now_utc())
            .await
            .map_err(authority_error)?
            .ok_or_else(|| {
                invalid_file_request(
                    FileTransferReason::FileUnavailable,
                    "upload is unavailable or expired",
                )
            })?;

        if status.state == UploadState::Ready {
            let owner = GatewayFileOwner {
                tenant_id: principal.tenant.clone(),
                principal_sub: principal.sub.clone(),
                principal_issuer: principal.issuer.clone(),
            };
            let file = self
                .storage
                .find_ready(&owner, file_id)
                .await
                .map_err(|error| {
                    tracing::warn!(%file_id, error = %error, "gateway upload status lookup failed");
                    file_transfer_failure(
                        FileTransferReason::TemporarilyUnavailable,
                        "gateway file storage is unavailable",
                    )
                })?;
            if let Some(file) = file {
                return Ok(structured(&UploadStatusOutput {
                    file: GatewayFileValue {
                        uri: file.uri(),
                        name: file.display_name,
                        mime_type: file.media_type,
                        size: Some(file.size),
                        digest: Some(GatewayFileDigest {
                            algorithm: "sha-256".to_owned(),
                            value: URL_SAFE_NO_PAD.encode(file.sha256),
                        }),
                    },
                    status: UploadState::Ready.as_str(),
                    expires_at: format_ts_rfc3339(file.expires_at),
                }));
            }
        }

        let state = if status.state == UploadState::Ready {
            UploadState::Expired
        } else {
            status.state
        };
        Ok(structured(&UploadStatusOutput {
            file: GatewayFileValue {
                uri: input.uri,
                name: None,
                mime_type: status.media_type,
                size: status.expected_size,
                digest: status.expected_digest.map(|digest| GatewayFileDigest {
                    algorithm: digest.algorithm,
                    value: URL_SAFE_NO_PAD.encode(digest.value),
                }),
            },
            status: state.as_str(),
            expires_at: format_ts_rfc3339(status.expires_at),
        }))
    }

    fn credential_exchange(&self) -> CredentialExchangeDescriptor {
        CredentialExchangeDescriptor {
            method: "POST",
            url: format!(
                "{}{}",
                self.public_url.trim_end_matches('/'),
                waygate_transfer::CREDENTIAL_EXCHANGE_PATH,
            ),
            grant_handle_field: "grant_handle",
            proof_header: "DPoP",
            proof_standard: "RFC 9449",
            access_token_field: "access_token",
            expires_in_field: "expires_in",
            token_type: "DPoP",
        }
    }

    async fn check_quota(&self, principal: &Principal, tool: &str) -> Result<(), McpError> {
        check_file_preparation_quota(self.quota.as_ref(), &self.audit, principal, tool).await
    }
}

pub(crate) async fn check_download_preparation_quota(
    quota: Option<&Arc<dyn waygate_quota::QuotaService>>,
    audit: &SharedEvidence,
    principal: &Principal,
) -> Result<(), McpError> {
    check_file_preparation_quota(quota, audit, principal, PREPARE_DOWNLOAD).await
}

pub(crate) async fn check_upload_preparation_quota(
    quota: Option<&Arc<dyn waygate_quota::QuotaService>>,
    audit: &SharedEvidence,
    principal: &Principal,
) -> Result<(), McpError> {
    check_file_preparation_quota(quota, audit, principal, PREPARE_UPLOAD).await
}

pub(crate) fn enforce_upload_preparation_profile(principal: &Principal) -> Result<(), McpError> {
    if profile_blocks_server(principal, NAMESPACE)
        || profile_blocks_tool(principal, NAMESPACE, PREPARE_UPLOAD)
    {
        Err(invalid_file_request(
            FileTransferReason::PolicyViolation,
            "file upload preparation is not available to this credential",
        ))
    } else {
        Ok(())
    }
}

fn enforce_upload_status_profile(principal: &Principal) -> Result<(), McpError> {
    if profile_blocks_server(principal, NAMESPACE)
        || profile_blocks_tool(principal, NAMESPACE, UPLOAD_STATUS)
    {
        Err(invalid_file_request(
            FileTransferReason::PolicyViolation,
            "file upload status is not available to this credential",
        ))
    } else {
        Ok(())
    }
}

async fn check_file_preparation_quota(
    quota: Option<&Arc<dyn waygate_quota::QuotaService>>,
    audit: &SharedEvidence,
    principal: &Principal,
    tool: &str,
) -> Result<(), McpError> {
    let Some(quota) = quota else {
        return Ok(());
    };
    let fq_tool = format!("{NAMESPACE}.{tool}");
    let context = waygate_quota::QuotaContext {
        tenant_id: principal.tenant.as_str().to_owned(),
        principal_sub: Some(principal.sub.clone()),
        client_id: None,
        server: NAMESPACE.to_owned(),
        fq_tool,
    };
    match quota
        .check_and_consume(
            &context,
            &[
                waygate_quota::QuotaAction::Call,
                waygate_quota::QuotaAction::SideEffectingCall,
            ],
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(waygate_quota::QuotaError::RateLimited {
            policy_id,
            name,
            retry_after_seconds,
        }) => {
            audit
                .record_chained_best_effort(
                    AuditEvent::new("CallTool", AuditOutcome::Denied)
                        .with_category(EvidenceCategory::Invocation)
                        .with_principal(Some(principal))
                        .with_tool(NAMESPACE, tool)
                        .with_risk(RiskTier::Low)
                        .with_reason(format!(
                            "rate_limited by policy `{name}` ({policy_id}); \
                             retry_after_seconds={retry_after_seconds}"
                        )),
                )
                .await;
            Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("rate-limited by policy `{name}`; retry after {retry_after_seconds}s"),
                Some(serde_json::json!({
                    "error": "rate_limited",
                    "policy_id": policy_id.to_string(),
                    "policy_name": name,
                    "retry_after_seconds": retry_after_seconds,
                })),
            ))
        }
        Err(waygate_quota::QuotaError::Sqlx(error)) => {
            tracing::warn!(
                tenant = %principal.tenant.as_str(),
                error = %error,
                "file download quota store failed; allowing the request"
            );
            Ok(())
        }
    }
}

#[async_trait]
impl BuiltinTools for GatewayFileTools {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn profile_scope(&self) -> BuiltinProfileScope {
        BuiltinProfileScope::DelegatedDataPlane
    }

    fn catalog(&self) -> BuiltinCatalog {
        surface_catalog()
    }

    async fn list_tools(&self, principal: Option<&Principal>) -> Vec<Tool> {
        if principal.is_some() {
            self.catalog().definitions()
        } else {
            Vec::new()
        }
    }

    async fn call(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        principal: Option<&Principal>,
    ) -> Result<CallToolResult, McpError> {
        let principal = principal.ok_or_else(|| {
            invalid_file_request(
                FileTransferReason::AuthenticationRequired,
                "gateway file tools require authentication",
            )
        })?;
        match tool {
            PREPARE_UPLOAD => {
                let input = serde_json::from_value(serde_json::Value::Object(
                    arguments.unwrap_or_default(),
                ))
                .map_err(|error| {
                    invalid_file_request(
                        FileTransferReason::InvalidFileInput,
                        format!("invalid prepare_upload input: {error}"),
                    )
                })?;
                self.prepare_upload(principal, input).await
            }
            PREPARE_DOWNLOAD => {
                let input = serde_json::from_value(serde_json::Value::Object(
                    arguments.unwrap_or_default(),
                ))
                .map_err(|error| {
                    invalid_file_request(
                        FileTransferReason::InvalidFileInput,
                        format!("invalid prepare_download input: {error}"),
                    )
                })?;
                self.prepare_download(principal, input).await
            }
            UPLOAD_STATUS => {
                let input = serde_json::from_value(serde_json::Value::Object(
                    arguments.unwrap_or_default(),
                ))
                .map_err(|error| {
                    invalid_file_request(
                        FileTransferReason::InvalidFileInput,
                        format!("invalid upload_status input: {error}"),
                    )
                })?;
                self.upload_status(principal, input).await
            }
            other => Err(McpError::invalid_params(
                format!("unknown {NAMESPACE} tool: {other}"),
                None,
            )),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PrepareDownloadInput {
    /// Gateway-owned `mcp-file:` URI returned by an earlier tool call.
    uri: String,
    /// RFC 7638 SHA-256 thumbprint of the public key the helper will sign
    /// with. Obtain it from `mcp-files thumbprint`; the grant is bound to
    /// this key, so a thumbprint from any other key cannot be redeemed.
    helper_jkt: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PrepareUploadInput {
    /// RFC 7638 SHA-256 thumbprint of the public key the helper will sign
    /// with. Obtain it from `mcp-files thumbprint`; the grant is bound to
    /// this key, so a thumbprint from any other key cannot be redeemed.
    helper_jkt: String,
    /// Optional display name retained by the host; it is never used as a path.
    #[serde(default)]
    name: Option<String>,
    /// Optional media type that the upload request must carry.
    #[serde(default)]
    mime_type: Option<String>,
    /// Optional exact byte count. The streaming endpoint rejects a mismatch.
    #[serde(default)]
    size: Option<u64>,
    /// Optional exact SHA-256 digest encoded as base64url without padding.
    #[serde(default)]
    digest: Option<PrepareFileDigest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UploadStatusInput {
    /// Gateway-owned `mcp-file:` URI printed by `mcp-files upload` or returned
    /// by `prepare_upload`. The caller must own the corresponding upload.
    uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct PrepareFileDigest {
    /// Digest algorithm. The current byte endpoint accepts `sha-256`.
    algorithm: String,
    /// Base64url-encoded digest bytes without padding.
    value: String,
}

impl From<PrepareFileDigest> for GatewayFileDigest {
    fn from(value: PrepareFileDigest) -> Self {
        Self {
            algorithm: value.algorithm,
            value: value.value,
        }
    }
}

#[derive(Serialize, JsonSchema)]
struct PrepareDownloadOutput<'a> {
    /// Stable file metadata. This contains no access credential.
    file: GatewayFileValue,
    /// `checked` or `uninspectable`; an unsupported scanner is never reported as clean.
    inspection_status: &'a str,
    /// Opaque identifier the `mcp-files` helper exchanges for a credential. It
    /// is not a bearer credential and is useless without the helper's key, so
    /// relaying it through a tool result is safe.
    grant_handle: &'a str,
    /// Exact exchange request and response fields. The `mcp-files` helper
    /// consumes these; assembling the exchange by hand is only for someone
    /// writing their own helper.
    credential_exchange: CredentialExchangeDescriptor,
    /// Fixed HTTPS byte endpoint and grant expiry.
    download: DownloadDescriptor,
}

#[derive(Serialize, JsonSchema)]
struct PrepareUploadOutput<'a> {
    /// Stable metadata to retain after the helper completes the upload.
    file: GatewayFileValue,
    /// Uploads remain `uninspectable` until a configured scanner checks them.
    inspection_status: &'a str,
    /// Opaque identifier the `mcp-files` helper exchanges for a credential. It
    /// is not a bearer credential and is useless without the helper's key, so
    /// relaying it through a tool result is safe.
    grant_handle: &'a str,
    /// Exact exchange request and response fields. The `mcp-files` helper
    /// consumes these; assembling the exchange by hand is only for someone
    /// writing their own helper.
    credential_exchange: CredentialExchangeDescriptor,
    /// Fixed streaming upload endpoint and grant expiry.
    upload: UploadDescriptor,
}

#[derive(Serialize, JsonSchema)]
struct UploadStatusOutput<'a> {
    /// Safe file metadata. Before completion, size and digest are the declared
    /// expectations; once ready, they are the observed values.
    file: GatewayFileValue,
    /// `prepared`, `in_progress`, `ready`, `failed`, or `expired`.
    status: &'a str,
    /// Expiry of the transfer grant, or of the retained file once ready.
    expires_at: String,
}

#[derive(Serialize, JsonSchema)]
struct GatewayFileValue {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<GatewayFileDigest>,
}

#[derive(Serialize, JsonSchema)]
struct GatewayFileDigest {
    algorithm: String,
    value: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CredentialExchangeDescriptor {
    /// HTTP method. The DPoP proof's `htm` claim must match this value.
    method: &'static str,
    /// Fixed endpoint. The DPoP proof's `htu` claim must match this URL.
    url: String,
    /// JSON request field that carries the opaque grant handle.
    grant_handle_field: &'static str,
    /// HTTP header carrying the RFC 9449 proof JWT.
    proof_header: &'static str,
    /// Standard used to create the proof and RFC 7638 public-key thumbprint.
    proof_standard: &'static str,
    /// JSON response field containing the short-lived credential.
    access_token_field: &'static str,
    /// JSON response field containing the remaining credential lifetime in seconds.
    expires_in_field: &'static str,
    /// Authorization scheme used with the returned credential.
    token_type: &'static str,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DownloadDescriptor {
    transport: String,
    method: &'static str,
    url: String,
    /// Put the short-lived credential in `Authorization: DPoP <credential>`.
    authorization_scheme: &'static str,
    /// Send a fresh RFC 9449 proof here; its `ath` claim hashes the credential.
    proof_header: &'static str,
    expires_at: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct UploadDescriptor {
    transport: String,
    method: &'static str,
    url: String,
    /// Put the short-lived credential in `Authorization: DPoP <credential>`.
    authorization_scheme: &'static str,
    /// Send a fresh RFC 9449 proof here; its `ath` claim hashes the credential.
    proof_header: &'static str,
    /// Send this value as the request Content-Type when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    expires_at: String,
}

pub(crate) fn tool_defs() -> Vec<Tool> {
    vec![
        Tool::new(
            format!("{NAMESPACE}.{PREPARE_UPLOAD}"),
            "Prepare a local file for a streaming upload to gateway storage, so its bytes never enter a tool argument. Completing the upload requires signing and is the job of the `mcp-files` helper: run `mcp-files thumbprint` to get the helper_jkt this call needs, then pipe this result into `mcp-files upload --file <path>`, which prints the file URI. The helper starts after the first complete JSON value and does not require EOF; when a process host can write only through a PTY, disable terminal echo and send structuredContent followed by a newline. Carry only the file URI and safe metadata into later tool arguments — never the bytes, local path, or transfer credential. Capture structuredContent before using another result channel. Without the helper the upload cannot be completed by hand from an agent loop; obtain it rather than putting file contents in an argument. Writing your own helper instead: this result carries no file bytes or bearer credential, so follow credential_exchange for the short-lived access_token, then PUT the file stream to upload.url with Authorization: DPoP <access_token>, a fresh RFC 9449 proof containing ath, and upload.contentType when present.",
            schema_obj(
                serde_json::to_value(schemars::schema_for!(PrepareUploadInput))
                    .expect("prepare_upload input schema serializes"),
            ),
        )
        .with_title("Prepare a file upload")
        .with_output_schema::<PrepareUploadOutput<'static>>()
        .annotate(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(false),
        ),
        Tool::new(
            format!("{NAMESPACE}.{UPLOAD_STATUS}"),
            "Reconcile an upload after `mcp-files` could not determine whether its HTTP request completed. Pass the safe mcp-file URI from prepare_upload. A `ready` result means the file was atomically published and its observed size and digest are returned; `prepared` or `in_progress` means do not create a duplicate upload yet; `failed` or `expired` means a new prepare_upload may be started. This read does not consume or revive a grant.",
            schema_obj(
                serde_json::to_value(schemars::schema_for!(UploadStatusInput))
                    .expect("upload_status input schema serializes"),
            ),
        )
        .with_title("Check file upload status")
        .with_output_schema::<UploadStatusOutput<'static>>()
        .annotate(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true),
        ),
        Tool::new(
            format!("{NAMESPACE}.{PREPARE_DOWNLOAD}"),
            "Prepare a gateway-owned file for download to local disk, so its bytes never enter a tool result. Pass the file URI from an earlier tool result. Completing the download requires signing and is the job of the `mcp-files` helper: run `mcp-files thumbprint` to get the helper_jkt this call needs, then pipe this result into `mcp-files download --dest <path>`, which writes the file and verifies it against any declared size and digest. The helper starts after the first complete JSON value and does not require EOF; when a process host can write only through a PTY, disable terminal echo and send structuredContent followed by a newline. Without the helper the download cannot be completed by hand from an agent loop; obtain it rather than asking for the contents another way. Writing your own helper instead: this result carries no file bytes or bearer credential, so POST the handle to credential_exchange with an RFC 9449 proof, read the short-lived access_token, then send Authorization: DPoP <access_token> and a fresh proof carrying ath (the base64url SHA-256 of that token) to the download URL. Stream the response; do not read it into memory.",
            schema_obj(
                serde_json::to_value(schemars::schema_for!(PrepareDownloadInput))
                    .expect("prepare_download input schema serializes"),
            ),
        )
        .with_title("Prepare a file download")
        .with_output_schema::<PrepareDownloadOutput<'static>>()
        .annotate(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(false)
                .idempotent(false),
        ),
    ]
}

pub(crate) fn surface_descriptor() -> BuiltinSurfaceDescriptor {
    surface_catalog().descriptor()
}

pub(crate) fn surface_catalog() -> BuiltinCatalog {
    let tools = tool_defs()
        .into_iter()
        .map(|tool| {
            let side_effects = !tool.name.as_ref().ends_with(".upload_status");
            CatalogTool::builtin(NAMESPACE, tool, RiskTier::Low, side_effects, false)
        })
        .collect();
    BuiltinCatalog::new(
        NAMESPACE,
        "authenticated",
        "Prepare short-lived uploads and downloads without putting file bytes or broad MCP \
         credentials in model context, and reconcile an uncertain upload outcome. Transfers are \
         completed by the `mcp-files` helper, which holds the signing key.",
        tools,
    )
}

fn parse_file_uri(uri: &str) -> Result<Uuid, McpError> {
    let uri = url::Url::parse(uri).map_err(|_| {
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
    Uuid::parse_str(uri.path().trim_start_matches('/')).map_err(|_| {
        invalid_file_request(
            FileTransferReason::InvalidFileInput,
            "uri must be a gateway mcp-file URI",
        )
    })
}

fn decode_upload_digest(digest: &PrepareFileDigest) -> Result<TransferDigest, McpError> {
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
    Ok(TransferDigest {
        algorithm: digest.algorithm.clone(),
        value,
    })
}

fn authority_error(error: waygate_transfer::AuthorityError) -> McpError {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct DenyQuota;

    #[async_trait]
    impl waygate_quota::QuotaService for DenyQuota {
        async fn check_and_consume(
            &self,
            context: &waygate_quota::QuotaContext,
            actions: &[waygate_quota::QuotaAction],
        ) -> Result<(), waygate_quota::QuotaError> {
            assert_eq!(context.server, NAMESPACE);
            assert_eq!(context.fq_tool, "gateway-files.prepare_download");
            assert_eq!(
                actions,
                [
                    waygate_quota::QuotaAction::Call,
                    waygate_quota::QuotaAction::SideEffectingCall,
                ]
            );
            Err(waygate_quota::QuotaError::RateLimited {
                policy_id: Uuid::nil(),
                name: "file helper".to_owned(),
                retry_after_seconds: 7,
            })
        }
    }

    fn principal() -> Principal {
        Principal {
            sub: "file-user".to_owned(),
            email: None,
            groups: Vec::new(),
            issuer: "test-issuer".to_owned(),
            scopes: Vec::new(),
            tenant: waygate_core::TenantId::parse("test-tenant").expect("tenant"),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
            roles: Vec::new(),
        }
    }

    #[test]
    fn upload_preparation_honors_api_key_profile_confinement() {
        let mut actor = principal();
        actor.api_key_profile_restrictions = Some(waygate_oidc::ApiKeyProfileRestrictions {
            profile_id: "restricted".to_owned(),
            profile_name: "restricted".to_owned(),
            allowed_servers: None,
            allowed_tools: Some(vec!["printable.import".to_owned()]),
        });
        assert!(enforce_upload_preparation_profile(&actor).is_err());

        actor
            .api_key_profile_restrictions
            .as_mut()
            .unwrap()
            .allowed_tools = Some(vec!["gateway-files.prepare_upload".to_owned()]);
        assert!(enforce_upload_preparation_profile(&actor).is_ok());
    }

    #[test]
    fn file_helpers_are_fully_described_on_the_wire() {
        let tools = tool_defs();
        assert_eq!(tools.len(), 3);
        let tool = tools
            .iter()
            .find(|tool| tool.name.as_ref() == "gateway-files.prepare_download")
            .expect("download helper");
        assert!(tool.title.as_deref().is_some_and(|title| !title.is_empty()));
        assert!(tool.output_schema.is_some());
        assert_eq!(
            tool.annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint),
            Some(false)
        );
        assert!(surface_descriptor()
            .tools
            .iter()
            .filter(|tool| tool.name != UPLOAD_STATUS)
            .all(|tool| tool.side_effects));
        for field in ["uri", "helper_jkt"] {
            assert!(
                tool.input_schema["properties"][field]["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty()),
                "{field} needs a description"
            );
        }
        let upload = tools
            .iter()
            .find(|tool| tool.name.as_ref() == "gateway-files.prepare_upload")
            .expect("upload helper");
        assert!(upload
            .title
            .as_deref()
            .is_some_and(|title| !title.is_empty()));
        assert!(upload.output_schema.is_some());
        for field in ["helper_jkt", "name", "mime_type", "size", "digest"] {
            assert!(
                upload.input_schema["properties"][field]["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty()),
                "{field} needs a description"
            );
        }
        let status = tools
            .iter()
            .find(|tool| tool.name.as_ref() == "gateway-files.upload_status")
            .expect("upload status helper");
        assert!(status
            .title
            .as_deref()
            .is_some_and(|title| !title.is_empty()));
        assert!(status.output_schema.is_some());
        assert_eq!(
            status
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint),
            Some(true)
        );
        assert!(status.input_schema["properties"]["uri"]["description"]
            .as_str()
            .is_some_and(|description| !description.is_empty()));
    }

    #[test]
    fn prepare_download_output_matches_its_schema() {
        let sample = PrepareDownloadOutput {
            file: GatewayFileValue {
                uri: "mcp-file://gateway/01999999-9999-7999-8999-999999999999".to_owned(),
                name: Some("report.pdf".to_owned()),
                mime_type: Some("application/pdf".to_owned()),
                size: Some(42),
                digest: Some(GatewayFileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                }),
            },
            inspection_status: "uninspectable",
            grant_handle: "opaque-handle",
            credential_exchange: CredentialExchangeDescriptor {
                method: "POST",
                url: "https://gateway.example/file-transfers/credentials".to_owned(),
                grant_handle_field: "grant_handle",
                proof_header: "DPoP",
                proof_standard: "RFC 9449",
                access_token_field: "access_token",
                expires_in_field: "expires_in",
                token_type: "DPoP",
            },
            download: DownloadDescriptor {
                transport: "https".to_owned(),
                method: "GET",
                url: "https://gateway.example/file-transfers/content".to_owned(),
                authorization_scheme: "DPoP",
                proof_header: "DPoP",
                expires_at: "2026-08-10T12:00:00Z".to_owned(),
            },
        };
        let schema = serde_json::to_value(schemars::schema_for!(PrepareDownloadOutput<'static>))
            .expect("output schema");
        let value = serde_json::to_value(sample).expect("sample output");
        let validator = jsonschema::validator_for(&schema).expect("compile output schema");
        let errors: Vec<_> = validator.iter_errors(&value).collect();
        assert!(
            errors.is_empty(),
            "output does not match schema: {errors:?}"
        );
        assert_eq!(value["inspection_status"], json!("uninspectable"));
    }

    #[test]
    fn upload_status_output_matches_its_schema() {
        let sample = UploadStatusOutput {
            file: GatewayFileValue {
                uri: "mcp-file://gateway/01999999-9999-7999-8999-999999999999".to_owned(),
                name: None,
                mime_type: Some("application/pdf".to_owned()),
                size: Some(42),
                digest: Some(GatewayFileDigest {
                    algorithm: "sha-256".to_owned(),
                    value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                }),
            },
            status: UploadState::Ready.as_str(),
            expires_at: "2026-08-10T12:00:00Z".to_owned(),
        };
        let schema = serde_json::to_value(schemars::schema_for!(UploadStatusOutput<'static>))
            .expect("output schema");
        let value = serde_json::to_value(sample).expect("sample output");
        let validator = jsonschema::validator_for(&schema).expect("compile output schema");
        let errors: Vec<_> = validator.iter_errors(&value).collect();
        assert!(
            errors.is_empty(),
            "output does not match schema: {errors:?}"
        );
        assert_eq!(value["status"], json!("ready"));
    }

    #[tokio::test]
    async fn prepare_download_uses_call_and_side_effect_quota() {
        let quota: Arc<dyn waygate_quota::QuotaService> = Arc::new(DenyQuota);
        let sink = Arc::new(waygate_mcp::audit::InMemorySink::new());
        let audit: SharedEvidence = sink.clone();

        let error = check_download_preparation_quota(Some(&quota), &audit, &principal())
            .await
            .expect_err("quota must refuse the helper call");

        assert_eq!(error.data.as_ref().unwrap()["error"], "rate_limited");
        let events = sink.snapshot().await;
        assert!(events.iter().any(|event| {
            event.action == "CallTool"
                && event.server.as_deref() == Some(NAMESPACE)
                && event.tool.as_deref() == Some(PREPARE_DOWNLOAD)
                && event.outcome == AuditOutcome::Denied
        }));
    }

    #[test]
    fn file_uri_parser_rejects_other_authorities_and_extra_path_parts() {
        assert!(parse_file_uri("mcp-file://upstream/id").is_err());
        assert!(parse_file_uri("https://gateway/id").is_err());
        assert!(parse_file_uri("mcp-file://gateway/id/extra").is_err());
    }

    #[test]
    fn surface_descriptor_matches_served_tools() {
        let prefix = format!("{NAMESPACE}.");
        let served: Vec<String> = tool_defs()
            .into_iter()
            .map(|t| t.name.as_ref().strip_prefix(&prefix).unwrap().to_owned())
            .collect();
        let d = surface_descriptor();
        let described: Vec<String> = d.tools.iter().map(|t| t.name.clone()).collect();
        assert_eq!(described, served);
        assert_eq!(d.namespace, NAMESPACE);
        assert!(d
            .tools
            .iter()
            .filter(|tool| tool.name != UPLOAD_STATUS)
            .all(|tool| tool.side_effects));
        assert!(d
            .tools
            .iter()
            .find(|tool| tool.name == UPLOAD_STATUS)
            .is_some_and(|tool| !tool.side_effects));
    }

    /// A caller that cannot sign has to learn from the wire that a helper does
    /// it, before being told how the signing works. Getting that order wrong is
    /// what left this path unusable in practice: the protocol detail read as the
    /// only route, and a caller without a JOSE library concluded it was stuck.
    #[test]
    fn tool_descriptions_name_the_helper_before_the_protocol() {
        for tool in tool_defs() {
            let description = tool.description.as_deref().unwrap_or_default();
            let helper = description
                .find("mcp-files")
                .unwrap_or_else(|| panic!("{} never names the helper", tool.name));
            // Everything a caller would have to implement itself. Listing only
            // the exchange vocabulary would let a description regress to
            // "create a signing key and take its RFC 7638 thumbprint" first and
            // still pass, which is the shape that caused the original problem.
            for protocol_detail in [
                "DPoP",
                "RFC 9449",
                "RFC 7638",
                "credential_exchange",
                "access_token",
                "signing key",
                "thumbprint",
                "proof",
            ] {
                if let Some(at) = description.find(protocol_detail) {
                    assert!(
                        helper < at,
                        "{} explains {protocol_detail} before naming the helper",
                        tool.name
                    );
                }
            }
        }
    }
}
