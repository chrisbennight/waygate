//! Draft SEP-2631 file-transfer wire vocabulary.
//!
//! These types carry file identity, optional metadata, client capabilities,
//! and HTTPS transfer instructions. File bytes and production authorization
//! do not belong in this module. The SEP remains a draft, so translation from
//! raw MCP JSON stays here rather than leaking draft field locations into the
//! transfer authority or byte executor.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use rmcp::model::{CallToolResult, ReadResourceResult};
use rmcp::ErrorData as McpError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use waygate_oidc::Principal;

use crate::catalog::InvocationContractIdentity;

/// Draft request that prepares an out-of-band upload.
pub const AUTHORIZE_UPLOAD_METHOD: &str = "files/authorizeUpload";
/// Draft request that resolves an out-of-band download.
pub const AUTHORIZE_DOWNLOAD_METHOD: &str = "files/authorizeDownload";
/// Per-request MCP metadata key containing the caller's capabilities.
pub const CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
/// Member of the client capability object that declares file-transfer support.
pub const FILES_CAPABILITY_MEMBER: &str = "files";
/// Draft file-backed resource contents carried in `_meta` until the pinned
/// SDK can model SEP-2631's third `ResourceContents` union member directly.
/// Only callers that declared file-download support receive this shape.
pub const FILE_RESOURCE_CONTENT_META_KEY: &str = "io.modelcontextprotocol/fileResourceContents";
/// Generic helper operation whose Cedar policy also governs native downloads.
pub const PREPARE_DOWNLOAD_TOOL: &str = "gateway-files.prepare_download";
/// Generic helper operation whose Cedar policy also governs native uploads.
pub const PREPARE_UPLOAD_TOOL: &str = "gateway-files.prepare_upload";

/// Whether a URI belongs to the gateway-owned file-transfer plane rather than
/// to an upstream's native MCP resource namespace.
pub(crate) fn is_reserved_file_uri(uri: &str) -> bool {
    uri.split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("mcp-file"))
}

/// Facts needed to replace gateway file references before a tool call.
#[derive(Clone)]
pub struct FileInputContext {
    pub principal: Option<Principal>,
    pub server: String,
    pub tool: String,
    pub invocation_id: String,
    pub admitted_contract: InvocationContractIdentity,
    /// The cached compiled validator for the admitted input schema, when the
    /// pipeline already compiled it. Reusing it keeps delivery-time schema
    /// evaluation off the per-request compile path.
    pub compiled_input_schema: Option<Arc<jsonschema::Validator>>,
}

/// Delivers caller-owned gateway files to the selected upstream and replaces
/// their public gateway references with upstream-private file references.
/// Returns `true` only when arguments were rewritten, so the invocation
/// pipeline can revalidate the final wire value without taxing ordinary calls.
#[async_trait]
pub trait FileInputProcessor: Send + Sync + 'static {
    /// Deterministic admission of file-valued arguments: transfer-mode and
    /// inline-content constraints only. The pipeline runs this before quota
    /// and the one-time approval claim so a refusal consumes no irreversible
    /// resource; it must not move bytes or take authority. The mutable borrow
    /// exists only so an implementation can move the map through schema
    /// evaluation without duplicating a payload-sized value — the arguments
    /// must be left exactly as they were received.
    /// `compiled` carries the pipeline's cached validator for the same
    /// schema; implementations must use it instead of recompiling when
    /// present. `input_responses` is the caller's MRTR continuation payload,
    /// admitted alongside the arguments so a deliverability refusal still
    /// precedes the quota and approval gates.
    fn admit(
        &self,
        input_schema: Option<&Value>,
        compiled: Option<&jsonschema::Validator>,
        arguments: &mut Option<Map<String, Value>>,
        input_responses: Option<&BTreeMap<String, Value>>,
        deliverable_keys: &[String],
    ) -> Result<(), McpError>;

    async fn prepare(
        &self,
        context: FileInputContext,
        input_schema: Option<&Value>,
        arguments: &mut Option<Map<String, Value>>,
    ) -> Result<bool, McpError>;

    /// Deliver caller-owned gateway file references found inside an MRTR
    /// continuation's input responses and replace them with upstream-private
    /// references before the retry is dispatched.
    ///
    /// Elicitation responses are caller-authored values relayed to the
    /// upstream that asked for them; the gateway trusts no client-echoed
    /// schema and mints no continuation state. Only the self-describing
    /// gateway file URI namespace is delivered — ownership, credential
    /// profile, and invocation binding are enforced by the same delivery
    /// path as ordinary file arguments, and declared elicitation
    /// constraints remain the asking upstream's to enforce on receipt.
    /// `file_keys` are the response keys the verified continuation says the
    /// relayed pause asked a file for, taken from the upstream's own sealed
    /// elicitation shape — never from the caller. A gateway file reference
    /// under any other key is refused.
    async fn prepare_continuation(
        &self,
        context: FileInputContext,
        input_responses: &mut BTreeMap<String, Value>,
        file_keys: &[String],
    ) -> Result<bool, McpError>;
}

pub type SharedFileInputProcessor = Arc<dyn FileInputProcessor>;

/// Facts needed to replace upstream file references after a tool call.
#[derive(Debug, Clone)]
pub struct FileOutputContext {
    pub principal: Option<Principal>,
    pub server: String,
    pub tool: String,
    pub invocation_id: String,
}

/// A rewritten result that has not yet been released to the caller.
pub struct PreparedFileOutput {
    pub result: CallToolResult,
    /// Private batch identifier used only to publish or discard saved files.
    pub batch_id: Option<String>,
    /// Exact number of saved files that must be present before publication.
    pub file_count: usize,
}

/// A rewritten resource result whose staged file batch is still private.
pub struct PreparedResourceOutput {
    pub result: ReadResourceResult,
    pub batch_id: Option<String>,
    pub file_count: usize,
}

/// Recovered upstream bytes that have crossed the invocation's response controls.
pub struct RetainedFileBody {
    pub upstream_uri: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub sensitive: bool,
}

pub struct PreparedRetainedFile {
    pub file: FileValue,
    pub batch_id: String,
}

/// Trusted delivery metadata is mirrored in the structured gateway delivery envelope.
pub const RETAINED_DELIVERY_META_KEY: &str = "io.cacahuate.mcp-gateway/retained-delivery";

/// Saves upstream-produced files and replaces their private references before
/// a tool result is returned to the caller. Saved files stay private until the
/// final output-schema check succeeds.
#[async_trait]
pub trait FileOutputProcessor: Send + Sync + 'static {
    /// Opt in to retaining larger successful structured results instead of
    /// putting their complete wire envelope in direct-client model context.
    fn inline_response_threshold_bytes(&self) -> Option<usize> {
        None
    }

    fn retained_response_max_bytes(&self) -> Option<usize> {
        None
    }

    async fn prepare_retained(
        &self,
        _context: FileOutputContext,
        _body: RetainedFileBody,
    ) -> Result<PreparedRetainedFile, McpError> {
        Err(McpError::internal_error(
            "retained response file storage is unavailable",
            None,
        ))
    }
    /// Whether this processor can publish native HTTPS descriptors that a
    /// downstream resource client can actually consume.
    fn native_https_available(&self) -> bool {
        false
    }

    async fn prepare(
        &self,
        context: FileOutputContext,
        result: CallToolResult,
    ) -> Result<PreparedFileOutput, McpError>;

    async fn prepare_resource(
        &self,
        _context: FileOutputContext,
        result: ReadResourceResult,
    ) -> Result<PreparedResourceOutput, McpError> {
        Ok(PreparedResourceOutput {
            result,
            batch_id: None,
            file_count: 0,
        })
    }

    async fn publish(&self, batch_id: &str, file_count: usize) -> Result<(), McpError>;

    async fn discard(&self, batch_id: &str);
}

pub type SharedFileOutputProcessor = Arc<dyn FileOutputProcessor>;

#[async_trait]
pub trait FileDownloadAuthorizer: Send + Sync + 'static {
    async fn authorize_download(
        &self,
        principal: Option<&Principal>,
        params: AuthorizeDownloadParams,
    ) -> Result<AuthorizeDownloadResult, McpError>;
}

pub type SharedFileDownloadAuthorizer = Arc<dyn FileDownloadAuthorizer>;

#[async_trait]
pub trait FileUploadAuthorizer: Send + Sync + 'static {
    async fn authorize_upload(
        &self,
        principal: Option<&Principal>,
        params: AuthorizeUploadParams,
    ) -> Result<AuthorizeUploadResult, McpError>;
}

pub type SharedFileUploadAuthorizer = Arc<dyn FileUploadAuthorizer>;

/// The admitted file-transfer wire profile of one MCP caller or connection.
///
/// Three compatibility surfaces exist and each has its own negotiation shape:
/// the profile names which shape admitted the caller. Every profile converges
/// on the same canonical transfer authority, storage, integrity, retention,
/// and audit lifecycle — a profile selects a wire adapter, never an alternate
/// transfer implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWireProfile {
    /// MCP `2026-07-28` self-contained requests: file capabilities are
    /// declared in each request's `_meta` and are never remembered between
    /// requests, so any replica can serve any request.
    StatelessNative,
    /// Initialization/session-era draft: capabilities were negotiated by
    /// `initialize` and hold only for that negotiated session.
    LegacyDraft,
    /// No native negotiation surface: the caller reaches file transfer only
    /// through the ordinary `tools/list` / `tools/call` fallback tools.
    ToolFallback,
}

impl FileWireProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StatelessNative => "stateless-native",
            Self::LegacyDraft => "legacy-draft",
            Self::ToolFallback => "tool-fallback",
        }
    }
}

/// How the downstream connection negotiated, as observed at the MCP edge.
#[derive(Debug, Clone, Default)]
pub enum DownstreamNegotiation {
    /// Self-contained request; no initialization handshake on this connection.
    #[default]
    Stateless,
    /// The connection performed a legacy `initialize` handshake. The carried
    /// value is that handshake's `files` capability when the protocol layer
    /// exposes it; `None` means the handshake happened but its file
    /// capabilities are not observable through the pinned MCP library, which
    /// drops unknown members of the typed capability object.
    LegacySession(Option<FileCapabilities>),
}

/// One classified caller: the wire profile plus the capability declaration
/// that governs it. Produced once at the MCP edge so later stages route on an
/// explicit profile instead of re-inferring it from field locations.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifiedFileCaller {
    pub profile: FileWireProfile,
    pub capabilities: Option<FileCapabilities>,
}

impl ClassifiedFileCaller {
    pub fn supports(&self, operation: FileOperation) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.supports(operation))
    }
}

/// Classify a downstream caller from its request-local declaration and the
/// connection's negotiation history.
///
/// A request-local `_meta` declaration is authoritative and never merges with
/// remembered session state: a stateless request may land on any replica, so
/// it must carry its own authority-relevant context. Session capability state
/// applies only to callers that negotiated a legacy session and declared
/// nothing on the request itself.
pub fn classify_downstream_caller(
    request_local: Option<FileCapabilities>,
    negotiation: DownstreamNegotiation,
) -> ClassifiedFileCaller {
    if let Some(capabilities) = request_local {
        return ClassifiedFileCaller {
            profile: FileWireProfile::StatelessNative,
            capabilities: Some(capabilities),
        };
    }
    match negotiation {
        DownstreamNegotiation::LegacySession(capabilities) => ClassifiedFileCaller {
            profile: FileWireProfile::LegacyDraft,
            capabilities,
        },
        DownstreamNegotiation::Stateless => ClassifiedFileCaller {
            profile: FileWireProfile::ToolFallback,
            capabilities: None,
        },
    }
}

/// The request `_meta` capability declaration the gateway itself emits when it
/// acts as the stateless-native file-transfer client toward an upstream.
///
/// This is the single constructor for that declaration: both output staging
/// (gateway downloads from an upstream) and input delivery (gateway uploads to
/// an upstream) must emit the same shape, so a draft revision changes one
/// place. A legacy upstream negotiates at `initialize` instead and is handled
/// at the connection layer, not through request metadata.
pub fn stateless_client_capability_meta(operation: FileOperation) -> BTreeMap<String, Value> {
    BTreeMap::from([(
        CLIENT_CAPABILITIES_META_KEY.to_owned(),
        serde_json::json!({
            FILES_CAPABILITY_MEMBER: stateless_client_file_capability(operation)
        }),
    )])
}

/// The `files` member of that declaration on its own, for a caller that has to
/// compose it into a capability object the MCP SDK builds.
pub fn stateless_client_file_capability(operation: FileOperation) -> Value {
    match operation {
        FileOperation::Upload => serde_json::json!({"upload": true, "transports": ["https"]}),
        FileOperation::Download => serde_json::json!({"download": true, "transports": ["https"]}),
    }
}

/// The optional `files` member of the draft client capability object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<FileTransport>>,
}

impl FileCapabilities {
    pub fn supports(&self, operation: FileOperation) -> bool {
        let operation_supported = match operation {
            FileOperation::Upload => self.upload == Some(true),
            FileOperation::Download => self.download == Some(true),
        };
        operation_supported
            && self
                .transports
                .as_deref()
                .is_some_and(|transports| transports.iter().any(FileTransport::is_https))
    }
}

/// An open transport identifier. Unknown future transports remain parseable.
///
/// This implementation executes `https`, and `http` only on a leg whose control
/// plane the gateway already reaches in cleartext — see
/// [`FileTransferNetwork::admits_cleartext_transfer`]. Nothing else is executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileTransport(String);

impl FileTransport {
    pub fn https() -> Self {
        Self("https".to_owned())
    }

    pub fn is_https(&self) -> bool {
        self.0 == "https"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    Upload,
    Download,
}

/// SEP-2356 schema annotation reused by the file-transfer draft.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInputDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_modes: Option<Vec<FileTransferMode>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileTransferMode {
    Inline,
    Upload,
}

/// Integrity metadata for one immutable complete byte sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileDigest {
    pub algorithm: String,
    /// Base64url without padding.
    pub value: String,
}

/// Stable file reference and optional display/integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileValue {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<FileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipartUpload {
    pub file_field: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferMethod {
    GET,
    PUT,
    POST,
}

/// Host-consumed HTTPS transfer instructions. Header values and URLs may be
/// sensitive, so diagnostic output exposes neither.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransferDescriptor {
    pub transport: FileTransport,
    pub method: TransferMethod,
    pub url: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multipart: Option<MultipartUpload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for FileTransferDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTransferDescriptor")
            .field("transport", &self.transport)
            .field("method", &self.method)
            .field("url", &"[redacted]")
            .field("header_count", &self.headers.len())
            .field("multipart", &self.multipart.is_some())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeUploadParams {
    #[serde(rename = "_meta", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<FileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeDownloadParams {
    #[serde(rename = "_meta", default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, Value>,
    pub uri: String,
}

/// Upload authorization has one required upload descriptor and may include an
/// eager download descriptor beside the stable file value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeUploadResult {
    pub file: FileValue,
    pub upload: FileTransferDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<FileTransferDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeDownloadResult {
    pub file: FileValue,
    pub download: FileTransferDescriptor,
    /// Optional upstream hint that the file is secret-class: consumed within its
    /// handoff, so the gateway applies its short secret retention instead of the
    /// default window. Tolerant-reader: an unrecognized value reads as no hint,
    /// so an upstream speaking a newer vocabulary still transfers.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_sensitivity"
    )]
    pub sensitivity: Option<FileSensitivity>,
}

/// Sensitivity classes an authorization may declare for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileSensitivity {
    /// Credential-class content whose delivery copy should live about as long
    /// as its delivery.
    Secret,
}

/// Unknown sensitivity values are no hint, not an error: the member is an
/// extension, and refusing a transfer over an unrecognized label would turn a
/// forward-compatible hint into a compatibility break.
fn lenient_sensitivity<'de, D>(deserializer: D) -> Result<Option<FileSensitivity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| serde_json::from_value::<FileSensitivity>(value).ok()))
}

/// An upstream download response plus the gateway's network decision for its
/// destination. These fields are private gateway state and are never
/// serialized onto the MCP wire.
#[derive(Debug, Clone)]
pub struct AuthorizedFileDownload {
    pub response: AuthorizeDownloadResult,
    pub network: FileTransferNetwork,
}

#[derive(Debug, Clone)]
pub struct AuthorizedFileUpload {
    pub response: AuthorizeUploadResult,
    pub network: FileTransferNetwork,
}

#[derive(Debug, Clone)]
pub enum FileTransferNetwork {
    Public,
    Local,
    Pinned {
        addresses: Vec<std::net::IpAddr>,
        /// Whether the gateway already reaches this upstream's *control* plane
        /// over plaintext, on these same pinned addresses.
        ///
        /// Carried because it decides whether a plaintext transfer descriptor is
        /// admissible. When the MCP endpoint is `http`, the tool arguments, any
        /// inline `data:` payload, and the file reference that authorizes the
        /// transfer have all already crossed this segment in the clear —
        /// demanding TLS for the bytes alone protects nothing that has not
        /// already been given up on the same wire. When the MCP endpoint is
        /// `https` this is false and the file leg must match it, so the
        /// exception can never become a downgrade.
        cleartext_control_plane: bool,
    },
}

impl FileTransferNetwork {
    /// Whether a plaintext transfer descriptor is admissible for this destination.
    ///
    /// True only for a pinned destination whose control plane is already
    /// plaintext. `Public` is a host the gateway never agreed to reach in the
    /// clear, and `Local` has no pinned segment to reason about.
    pub fn admits_cleartext_transfer(&self) -> bool {
        matches!(
            self,
            Self::Pinned {
                cleartext_control_plane: true,
                ..
            }
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FileCapabilityError {
    #[error("invalid client file-capability declaration")]
    Malformed,
    #[error("MCP host does not declare file {0} support over HTTPS")]
    Unsupported(&'static str),
}

/// Read the current protocol's per-request client file capability.
pub fn request_file_capabilities(
    request_params: &Value,
) -> Result<Option<FileCapabilities>, FileCapabilityError> {
    parse_optional_capability(
        request_params
            .get("_meta")
            .and_then(|meta| meta.get(CLIENT_CAPABILITIES_META_KEY))
            .and_then(|capabilities| capabilities.get(FILES_CAPABILITY_MEMBER)),
    )
}

pub fn require_file_capability(
    capabilities: Option<&FileCapabilities>,
    operation: FileOperation,
) -> Result<(), FileCapabilityError> {
    if capabilities.is_some_and(|capabilities| capabilities.supports(operation)) {
        return Ok(());
    }
    let name = match operation {
        FileOperation::Upload => "upload",
        FileOperation::Download => "download",
    };
    Err(FileCapabilityError::Unsupported(name))
}

/// Machine-readable field carried in a file-transfer error's JSON-RPC
/// `error.data`, naming the bounded recovery category. The name matches the
/// bounded `error` field the gateway's other machine-readable envelopes
/// already use (authorization denials, quota refusals, and the HTTPS
/// transfer endpoints); `reason` stays human prose everywhere it appears.
pub const FILE_TRANSFER_REASON_KEY: &str = "error";

/// The bounded recovery category of a file-transfer refusal or failure.
///
/// A message string is unstable machine input; this category is the stable
/// contract a caller routes on: retry, obtain fresh authority, choose a
/// different file, wait for capacity, select the tool fallback, or stop.
/// JSON-RPC methods and fallback tools carry it in `error.data.error`; the
/// HTTPS transfer endpoints use the same vocabulary in their `error` body
/// field where the concept exists there. Deliberately absent detail: file
/// existence is never distinguished from ownership, and no category exposes
/// storage, provider, or credential specifics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferReason {
    /// The caller did not declare the native capability this method needs.
    UnsupportedCapability,
    /// The operation needs an authenticated principal.
    AuthenticationRequired,
    /// A file-valued argument violates its declared mode or content
    /// constraints, or is malformed.
    InvalidFileInput,
    /// The tool's own published file contract is unusable (schema or
    /// annotation), which the operator must fix.
    InvalidToolContract,
    /// The file is unavailable to this caller: unknown, expired, not ready,
    /// or not owned — deliberately indistinguishable.
    FileUnavailable,
    /// File transfer is not enabled on this gateway.
    NotEnabled,
    /// A configured quota refused the operation; retrying immediately will
    /// not succeed.
    QuotaExhausted,
    /// Transfer capacity is momentarily exhausted; retrying later may
    /// succeed.
    TemporarilyUnavailable,
    /// A descriptor, address, redirect, or credential violated transfer
    /// policy.
    PolicyViolation,
    /// Declared size, digest, or media type did not match observed bytes.
    IntegrityMismatch,
    /// Byte movement or storage failed; the transfer did not complete.
    TransferFailed,
    /// The final commit outcome could not be confirmed; the file may or may
    /// not exist.
    CompletionUnknown,
}

impl FileTransferReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedCapability => "unsupported_capability",
            Self::AuthenticationRequired => "authentication_required",
            Self::InvalidFileInput => "invalid_file_input",
            Self::InvalidToolContract => "invalid_tool_contract",
            Self::FileUnavailable => "file_unavailable",
            Self::NotEnabled => "not_enabled",
            Self::QuotaExhausted => "quota_exhausted",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::PolicyViolation => "policy_violation",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::TransferFailed => "transfer_failed",
            Self::CompletionUnknown => "completion_unknown",
        }
    }

    fn data(self) -> Option<Value> {
        Some(serde_json::json!({ FILE_TRANSFER_REASON_KEY: self.as_str() }))
    }
}

/// An invalid-params refusal carrying the machine-readable recovery category.
pub fn invalid_file_request(
    reason: FileTransferReason,
    message: impl Into<std::borrow::Cow<'static, str>>,
) -> McpError {
    McpError::invalid_params(message, reason.data())
}

/// An internal-error failure carrying the machine-readable recovery category.
pub fn file_transfer_failure(
    reason: FileTransferReason,
    message: impl Into<std::borrow::Cow<'static, str>>,
) -> McpError {
    McpError::internal_error(message, reason.data())
}

/// Whether any location in the schema carries the `x-mcp-file` annotation.
/// A cheap pre-scan so tools without file inputs never pay for a full schema
/// evaluation on the admission path.
pub fn schema_declares_file_inputs(schema: &Value) -> bool {
    match schema {
        Value::Object(object) => {
            object.contains_key("x-mcp-file") || object.values().any(schema_declares_file_inputs)
        }
        Value::Array(items) => items.iter().any(schema_declares_file_inputs),
        _ => false,
    }
}

/// Add the draft `x-mcp-file` annotation to a URI-string JSON Schema.
pub fn annotate_file_input(
    property_schema: &mut Value,
    descriptor: &FileInputDescriptor,
) -> Result<(), &'static str> {
    let property = property_schema
        .as_object_mut()
        .ok_or("file input schema must be a JSON object")?;
    let value =
        serde_json::to_value(descriptor).map_err(|_| "file input descriptor must serialize")?;
    property.insert("x-mcp-file".to_owned(), value);
    Ok(())
}

fn parse_optional_capability(
    value: Option<&Value>,
) -> Result<Option<FileCapabilities>, FileCapabilityError> {
    value
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| FileCapabilityError::Malformed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sensitivity_reads_leniently_and_round_trips() {
        let hinted: AuthorizeDownloadResult = serde_json::from_value(json!({
            "file": { "uri": "mcp-file://example-secrets/x" },
            "download": { "transport": "http", "method": "GET", "url": "http://u/d" },
            "sensitivity": "secret"
        }))
        .expect("hinted result parses");
        assert_eq!(hinted.sensitivity, Some(FileSensitivity::Secret));

        // Unknown vocabulary is no hint, not a transfer-breaking error.
        let unknown: AuthorizeDownloadResult = serde_json::from_value(json!({
            "file": { "uri": "mcp-file://example-secrets/x" },
            "download": { "transport": "http", "method": "GET", "url": "http://u/d" },
            "sensitivity": "paranoid"
        }))
        .expect("unknown sensitivity still parses");
        assert_eq!(unknown.sensitivity, None);

        let absent: AuthorizeDownloadResult = serde_json::from_value(json!({
            "file": { "uri": "mcp-file://example-secrets/x" },
            "download": { "transport": "http", "method": "GET", "url": "http://u/d" }
        }))
        .expect("absent sensitivity parses");
        assert_eq!(absent.sensitivity, None);
    }

    #[test]
    fn optional_capability_members_round_trip_without_defaults() {
        let capabilities: FileCapabilities = serde_json::from_value(json!({
            "upload": true,
            "transports": ["https", "future-transport"]
        }))
        .unwrap();

        assert_eq!(capabilities.upload, Some(true));
        assert_eq!(capabilities.download, None);
        assert!(capabilities.supports(FileOperation::Upload));
        assert!(!capabilities.supports(FileOperation::Download));
        assert_eq!(
            serde_json::to_value(capabilities).unwrap(),
            json!({"upload": true, "transports": ["https", "future-transport"]})
        );
    }

    #[test]
    fn current_request_metadata_is_the_primary_adapter_boundary() {
        let request = json!({
            "_meta": {
                CLIENT_CAPABILITIES_META_KEY: {
                    "files": {"download": true, "transports": ["https"]}
                }
            }
        });
        let capabilities = request_file_capabilities(&request).unwrap().unwrap();

        require_file_capability(Some(&capabilities), FileOperation::Download).unwrap();
        assert_eq!(
            require_file_capability(Some(&capabilities), FileOperation::Upload),
            Err(FileCapabilityError::Unsupported("upload"))
        );
    }

    #[test]
    fn upload_metadata_is_optional_but_result_descriptor_is_not() {
        let params: AuthorizeUploadParams = serde_json::from_value(json!({})).unwrap();
        assert_eq!(params, AuthorizeUploadParams::default());

        let missing_upload = serde_json::from_value::<AuthorizeUploadResult>(json!({
            "file": {"uri": "mcp-file://gateway/example"}
        }));
        assert!(missing_upload.is_err());
    }

    fn https_download_capabilities() -> FileCapabilities {
        FileCapabilities {
            upload: None,
            download: Some(true),
            transports: Some(vec![FileTransport::https()]),
        }
    }

    #[test]
    fn request_local_declaration_is_authoritative_over_session_state() {
        // A stateless declaration must stand alone on any replica: even when
        // the connection also negotiated a legacy session, the request-local
        // declaration wins and session state is not merged in.
        let session_only_upload = FileCapabilities {
            upload: Some(true),
            download: Some(true),
            transports: Some(vec![FileTransport::https()]),
        };
        let caller = classify_downstream_caller(
            Some(https_download_capabilities()),
            DownstreamNegotiation::LegacySession(Some(session_only_upload)),
        );

        assert_eq!(caller.profile, FileWireProfile::StatelessNative);
        assert!(caller.supports(FileOperation::Download));
        assert!(!caller.supports(FileOperation::Upload));
    }

    #[test]
    fn legacy_session_without_request_declaration_is_legacy_draft() {
        let unobservable =
            classify_downstream_caller(None, DownstreamNegotiation::LegacySession(None));
        assert_eq!(unobservable.profile, FileWireProfile::LegacyDraft);
        assert!(require_file_capability(
            unobservable.capabilities.as_ref(),
            FileOperation::Download
        )
        .is_err());

        // When the protocol layer can carry the initialize-time capability,
        // the same classification admits it without a request declaration.
        let negotiated = classify_downstream_caller(
            None,
            DownstreamNegotiation::LegacySession(Some(https_download_capabilities())),
        );
        assert_eq!(negotiated.profile, FileWireProfile::LegacyDraft);
        assert!(negotiated.supports(FileOperation::Download));
    }

    #[test]
    fn undeclared_stateless_caller_is_tool_fallback() {
        let caller = classify_downstream_caller(None, DownstreamNegotiation::Stateless);
        assert_eq!(caller.profile, FileWireProfile::ToolFallback);
        assert_eq!(caller.capabilities, None);
        assert!(!caller.supports(FileOperation::Upload));
        assert!(!caller.supports(FileOperation::Download));
    }

    #[test]
    fn gateway_upstream_declaration_matches_the_stateless_wire_shape() {
        // Both transfer directions must emit the exact capability shape the
        // gateway's own downstream edge would admit, so a gateway-to-gateway
        // hop negotiates cleanly.
        for (operation, expected) in [
            (
                FileOperation::Upload,
                json!({"files": {"upload": true, "transports": ["https"]}}),
            ),
            (
                FileOperation::Download,
                json!({"files": {"download": true, "transports": ["https"]}}),
            ),
        ] {
            let meta = stateless_client_capability_meta(operation);
            assert_eq!(meta.get(CLIENT_CAPABILITIES_META_KEY), Some(&expected));

            let request = json!({"_meta": meta});
            let parsed = request_file_capabilities(&request).unwrap().unwrap();
            require_file_capability(Some(&parsed), operation).unwrap();
        }
    }

    #[test]
    fn file_transfer_errors_carry_a_bounded_machine_readable_reason() {
        let refusal = invalid_file_request(
            FileTransferReason::FileUnavailable,
            "file is unavailable or expired",
        );
        assert_eq!(refusal.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(
            // The literal wire key is the external contract; renaming the
            // constant must fail this assertion.
            refusal.data.unwrap()["error"],
            "file_unavailable"
        );

        let failure = file_transfer_failure(
            FileTransferReason::CompletionUnknown,
            "file upload completion could not be confirmed",
        );
        assert_eq!(failure.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert_eq!(failure.data.unwrap()["error"], "completion_unknown");

        // The category names are wire contract: stable snake_case values a
        // client can route on.
        for (reason, name) in [
            (
                FileTransferReason::UnsupportedCapability,
                "unsupported_capability",
            ),
            (
                FileTransferReason::AuthenticationRequired,
                "authentication_required",
            ),
            (FileTransferReason::InvalidFileInput, "invalid_file_input"),
            (
                FileTransferReason::InvalidToolContract,
                "invalid_tool_contract",
            ),
            (FileTransferReason::FileUnavailable, "file_unavailable"),
            (FileTransferReason::NotEnabled, "not_enabled"),
            (FileTransferReason::QuotaExhausted, "quota_exhausted"),
            (
                FileTransferReason::TemporarilyUnavailable,
                "temporarily_unavailable",
            ),
            (FileTransferReason::PolicyViolation, "policy_violation"),
            (FileTransferReason::IntegrityMismatch, "integrity_mismatch"),
            (FileTransferReason::TransferFailed, "transfer_failed"),
            (FileTransferReason::CompletionUnknown, "completion_unknown"),
        ] {
            assert_eq!(reason.as_str(), name);
        }
    }

    #[test]
    fn file_input_annotation_preserves_absent_and_present_constraints() {
        let mut schema = json!({"type": "string", "format": "uri"});
        annotate_file_input(
            &mut schema,
            &FileInputDescriptor {
                accept: Some(vec!["application/pdf".to_owned()]),
                max_size: None,
                transfer_modes: Some(vec![FileTransferMode::Upload]),
            },
        )
        .unwrap();

        assert_eq!(
            schema["x-mcp-file"],
            json!({"accept": ["application/pdf"], "transferModes": ["upload"]})
        );
    }
}
