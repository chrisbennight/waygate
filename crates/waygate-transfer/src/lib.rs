//! Direction-neutral authority for out-of-context file transfer.
//!
//! MCP/SEP adapters create grants here; direct HTTPS requests redeem them.
//! A public grant handle identifies immutable movement authority but is not a
//! bearer credential. The separate credential adapter proves possession of the
//! helper key bound to the grant and returns only a narrow, short-lived token.

mod dpop;
mod files_store;
mod http;
mod store;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use waygate_core::store::StoreError;
use waygate_evidence::{
    AuditEvent, AuditOutcome, AuditPrincipal, EvidenceCategory, EvidenceError, SharedEvidence,
};
use waygate_oidc::Principal;
use zeroize::Zeroize;

pub use dpop::{DpopError, DpopVerifier, UnclaimedDpopProof, VerifiedDpopProof};
pub use files_store::{
    FileInspectionStatus, FileStorageError, GatewayFileOwner, GatewayFileStorage, NewGatewayFile,
    StoredGatewayFile, PENDING_HEARTBEAT_INTERVAL,
};
pub use http::{
    credential_exchange_router, file_download_router, file_transfer_router, FileTransferAdmission,
    CREDENTIAL_EXCHANGE_PATH, FILE_DOWNLOAD_PATH, FILE_UPLOAD_PATH,
};
pub use store::PgTransferStore;

const GRANT_HANDLE_PREFIX: &str = "ftg_";
const CREDENTIAL_PREFIX: &str = "ftc_";
pub const NATIVE_MCP_CLIENT_REFERENCE: &str = "native-mcp-host";
pub const GENERIC_HELPER_REFERENCE: &str = "generic-helper";

pub type SharedTransferStore = Arc<dyn TransferStore>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

impl TransferDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "upload" => Some(Self::Upload),
            "download" => Some(Self::Download),
            _ => None,
        }
    }
}

/// A typed side of a transfer. The reference is internal authority state and
/// is never included in the public handoff returned to an MCP client.
#[derive(Clone, PartialEq, Eq)]
pub enum TransferEndpoint {
    Client { reference: String },
    Upstream { server: String, reference: String },
}

impl TransferEndpoint {
    pub fn client(reference: impl Into<String>) -> Result<Self, AuthorityError> {
        let reference = nonempty(reference.into(), "client reference")?;
        Ok(Self::Client { reference })
    }

    pub fn upstream(
        server: impl Into<String>,
        reference: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let server = nonempty(server.into(), "upstream server")?;
        let reference = nonempty(reference.into(), "upstream reference")?;
        Ok(Self::Upstream { server, reference })
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Client { .. } => "client",
            Self::Upstream { .. } => "upstream",
        }
    }

    fn encode_reference(&self) -> String {
        let stored = match self {
            Self::Client { reference } => StoredTransferEndpoint::Client {
                reference: reference.clone(),
            },
            Self::Upstream { server, reference } => StoredTransferEndpoint::Upstream {
                server: server.clone(),
                reference: reference.clone(),
            },
        };
        serde_json::to_string(&stored).expect("private transfer endpoint enum serializes")
    }

    fn reference(&self) -> &str {
        match self {
            Self::Client { reference } | Self::Upstream { reference, .. } => reference,
        }
    }

    fn decode(kind: &str, encoded: &str) -> Result<Self, StoreError> {
        let stored: StoredTransferEndpoint =
            serde_json::from_str(encoded).map_err(store_decode_error)?;
        let endpoint = match stored {
            StoredTransferEndpoint::Client { reference } => Self::Client { reference },
            StoredTransferEndpoint::Upstream { server, reference } => {
                Self::Upstream { server, reference }
            }
        };
        if endpoint.kind() != kind {
            return Err(store_decode_error(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer endpoint kind does not match stored value",
            )));
        }
        Ok(endpoint)
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        match self {
            Self::Client { reference } => {
                nonempty(reference.clone(), "client reference")?;
            }
            Self::Upstream { server, reference } => {
                nonempty(server.clone(), "upstream server")?;
                nonempty(reference.clone(), "upstream reference")?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredTransferEndpoint {
    Client { reference: String },
    Upstream { server: String, reference: String },
}

impl fmt::Debug for TransferEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client { .. } => formatter
                .debug_struct("Client")
                .field("reference", &"[redacted]")
                .finish(),
            Self::Upstream { server, .. } => formatter
                .debug_struct("Upstream")
                .field("server", server)
                .field("reference", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferDigest {
    pub algorithm: String,
    /// Raw digest bytes. Wire adapters choose the external encoding.
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOwner {
    pub tenant_id: waygate_core::TenantId,
    pub principal_sub: String,
    pub principal_issuer: String,
    pub credential_profile_id: Option<String>,
}

impl TransferOwner {
    pub fn from_principal(principal: &Principal) -> Self {
        Self {
            tenant_id: principal.tenant.clone(),
            principal_sub: principal.sub.clone(),
            principal_issuer: principal.issuer.clone(),
            credential_profile_id: principal
                .api_key_profile_restrictions
                .as_ref()
                .map(|profile| profile.profile_id.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewTransferGrant {
    pub invocation_id: String,
    pub file_uri: String,
    pub direction: TransferDirection,
    pub source: TransferEndpoint,
    pub destination: TransferEndpoint,
    /// RFC 7638 JWK SHA-256 thumbprint for the helper's ephemeral key.
    pub helper_jkt: String,
    /// Explicit policy/provider limit for this movement. There is no default.
    pub max_bytes: u64,
    pub expected_size: Option<u64>,
    pub media_type: Option<String>,
    pub expected_digest: Option<TransferDigest>,
    /// Maximum separately authorized HTTP requests for this grant. This is not
    /// assumed to be one so future range/resume profiles remain representable.
    pub max_requests: u64,
    pub expires_at: OffsetDateTime,
    pub credential_ttl: Duration,
}

impl NewTransferGrant {
    fn validate(&self, now: OffsetDateTime) -> Result<(), AuthorityError> {
        nonempty(self.invocation_id.clone(), "invocation id")?;
        let file_uri = nonempty(self.file_uri.clone(), "file URI")?;
        let file_uri = url::Url::parse(&file_uri).map_err(|_| {
            AuthorityError::InvalidGrant("file URI must be an absolute mcp-file URI".to_owned())
        })?;
        if file_uri.scheme() != "mcp-file"
            || file_uri.host_str().is_none()
            || !file_uri.username().is_empty()
            || file_uri.password().is_some()
        {
            return Err(AuthorityError::InvalidGrant(
                "file URI must be an absolute mcp-file URI without userinfo".to_owned(),
            ));
        }
        nonempty(self.helper_jkt.clone(), "helper key thumbprint")?;
        let helper_jkt = URL_SAFE_NO_PAD
            .decode(self.helper_jkt.as_bytes())
            .map_err(|_| {
                AuthorityError::InvalidGrant(
                    "helper key thumbprint must be base64url-encoded SHA-256".to_owned(),
                )
            })?;
        if helper_jkt.len() != 32 {
            return Err(AuthorityError::InvalidGrant(
                "helper key thumbprint must be base64url-encoded SHA-256".to_owned(),
            ));
        }
        self.source.validate()?;
        self.destination.validate()?;
        if self.max_bytes == 0 || self.max_bytes > i64::MAX as u64 {
            return Err(AuthorityError::InvalidGrant(
                "max_bytes must be between 1 and i64::MAX".to_owned(),
            ));
        }
        if self
            .expected_size
            .is_some_and(|size| size > self.max_bytes || size > i64::MAX as u64)
        {
            return Err(AuthorityError::InvalidGrant(
                "expected size exceeds the authorized byte limit".to_owned(),
            ));
        }
        if self.max_requests == 0 || self.max_requests > i64::MAX as u64 {
            return Err(AuthorityError::InvalidGrant(
                "max_requests must be between 1 and i64::MAX".to_owned(),
            ));
        }
        if self.expires_at <= now || self.credential_ttl.whole_seconds() <= 0 {
            return Err(AuthorityError::InvalidGrant(
                "grant expiry and credential TTL must be in the future".to_owned(),
            ));
        }
        match (&self.direction, &self.source, &self.destination) {
            (
                TransferDirection::Upload,
                TransferEndpoint::Client { .. },
                TransferEndpoint::Upstream { .. },
            )
            | (
                TransferDirection::Download,
                TransferEndpoint::Upstream { .. },
                TransferEndpoint::Client { .. },
            ) => {}
            _ => {
                return Err(AuthorityError::InvalidGrant(
                    "upload must move client to upstream and download upstream to client"
                        .to_owned(),
                ));
            }
        }
        if let Some(digest) = &self.expected_digest {
            nonempty(digest.algorithm.clone(), "digest algorithm")?;
            if digest.value.is_empty() {
                return Err(AuthorityError::InvalidGrant(
                    "expected digest cannot be empty".to_owned(),
                ));
            }
        }
        if let Some(media_type) = &self.media_type {
            nonempty(media_type.clone(), "media type")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Pending,
    Active,
    Completed,
    Revoked,
    Failed,
}

impl TransferStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "completed" => Some(Self::Completed),
            "revoked" => Some(Self::Revoked),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantHandle(String);

impl GrantHandle {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        validate_secret_shape(&value, GRANT_HANDLE_PREFIX)?;
        Ok(Self(value))
    }

    fn mint() -> Self {
        Self(mint_secret(GRANT_HANDLE_PREFIX))
    }

    fn digest(&self) -> Vec<u8> {
        secret_digest(self.0.as_bytes())
    }
}

impl fmt::Debug for GrantHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GrantHandle([opaque])")
    }
}

/// A narrow credential returned once to the direct helper. It deliberately
/// has no Serialize or Clone implementation and redacts Debug output.
pub struct TransferCredential(String);

impl TransferCredential {
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        validate_secret_shape(&value, CREDENTIAL_PREFIX)?;
        Ok(Self(value))
    }

    fn mint() -> Self {
        Self(mint_secret(CREDENTIAL_PREFIX))
    }

    fn digest(&self) -> Vec<u8> {
        secret_digest(self.0.as_bytes())
    }
}

impl fmt::Debug for TransferCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransferCredential([redacted])")
    }
}

impl Drop for TransferCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct TransferGrant {
    pub id: Uuid,
    pub owner: TransferOwner,
    pub invocation_id: String,
    pub file_uri: String,
    pub direction: TransferDirection,
    pub source: TransferEndpoint,
    pub destination: TransferEndpoint,
    pub helper_jkt: String,
    pub max_bytes: u64,
    pub expected_size: Option<u64>,
    pub media_type: Option<String>,
    pub expected_digest: Option<TransferDigest>,
    pub max_requests: u64,
    pub requests_used: u64,
    pub credential_ttl: Duration,
    pub status: TransferStatus,
    pub credential_expires_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct PublicTransferGrant {
    pub handle: GrantHandle,
    pub file_uri: String,
    pub direction: TransferDirection,
    pub max_bytes: u64,
    pub expected_size: Option<u64>,
    pub media_type: Option<String>,
    pub expected_digest: Option<TransferDigest>,
    pub expires_at: OffsetDateTime,
}

/// Model-safe state for reconciling a direct upload whose HTTP response was
/// lost. It contains no grant handle, credential, helper key, or endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicUploadStatus {
    pub state: UploadState,
    pub expected_size: Option<u64>,
    pub media_type: Option<String>,
    pub expected_digest: Option<TransferDigest>,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    Prepared,
    InProgress,
    Ready,
    Failed,
    Expired,
}

impl UploadState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::InProgress => "in_progress",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

pub struct IssuedTransferCredential {
    pub credential: TransferCredential,
    pub expires_at: OffsetDateTime,
    pub grant: TransferGrant,
}

/// Narrow bearer returned only in a native MCP file-authorization response.
/// It is scoped to one file, one direction, one client destination, and one
/// request. It never appears in a URL or a model-visible tool result.
pub struct IssuedNativeCredential {
    pub credential: TransferCredential,
    pub expires_at: OffsetDateTime,
    pub grant: TransferGrant,
}

impl fmt::Debug for IssuedTransferCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTransferCredential")
            .field("credential", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("grant_id", &self.grant.id)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedTransferRequest {
    pub authorization_id: Uuid,
    pub grant: TransferGrant,
    pub request_number: u64,
}

#[derive(Debug, Clone)]
pub struct NewGrantRow {
    pub id: Uuid,
    pub handle_hash: Vec<u8>,
    pub owner: TransferOwner,
    pub spec: NewTransferGrant,
}

#[async_trait]
pub trait TransferStore: Send + Sync + 'static {
    async fn insert(&self, row: NewGrantRow) -> Result<TransferGrant, StoreError>;

    async fn find_by_handle(&self, handle_hash: &[u8])
        -> Result<Option<TransferGrant>, StoreError>;

    async fn find_by_credential_hash(
        &self,
        credential_hash: &[u8],
    ) -> Result<Option<TransferGrant>, StoreError>;

    async fn find_upload_by_owner(
        &self,
        owner: &TransferOwner,
        file_uri: &str,
    ) -> Result<Option<TransferGrant>, StoreError>;

    async fn activate(
        &self,
        handle_hash: &[u8],
        helper_jkt: &str,
        credential_hash: &[u8],
        credential_expires_at: OffsetDateTime,
    ) -> Result<Option<TransferGrant>, StoreError>;

    async fn authorize_request(
        &self,
        credential_hash: &[u8],
        helper_jkt: &str,
        authorization_id: Uuid,
    ) -> Result<Option<AuthorizedTransferRequest>, StoreError>;

    async fn heartbeat_request(&self, id: Uuid, authorization_id: Uuid)
        -> Result<bool, StoreError>;

    async fn complete(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        observed_size: u64,
        observed_digest: Option<&[u8]>,
    ) -> Result<Option<TransferGrant>, StoreError>;

    /// Complete one inbound upload and publish its gateway file in the same
    /// database transaction. The file must remain unavailable unless the
    /// transfer request also reaches its completed state.
    async fn complete_upload(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        file_id: Uuid,
        observed_size: u64,
        observed_digest: &[u8],
        retention: Duration,
    ) -> Result<Option<TransferGrant>, UploadCompletionError>;

    async fn fail_request(
        &self,
        id: Uuid,
        authorization_id: Uuid,
        failure_code: &str,
    ) -> Result<bool, StoreError>;

    async fn revoke(&self, id: Uuid, reason: &str) -> Result<bool, StoreError>;

    async fn claim_dpop_jti(
        &self,
        helper_jkt: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<bool, StoreError>;

    async fn sweep_expired(&self, limit: u32) -> Result<u64, StoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum UploadCompletionError {
    #[error("upload completion store failed: {0}")]
    Store(#[from] StoreError),
    #[error("upload completion outcome is unknown after the commit acknowledgement was lost")]
    OutcomeUnknown {
        commit: StoreError,
        verification: UploadCompletionVerification,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum UploadCompletionVerification {
    #[error("the completed state was not yet visible")]
    NotVisible,
    #[error("the completed-state read failed: {0}")]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for UploadCompletionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("invalid transfer grant: {0}")]
    InvalidGrant(String),
    #[error("transfer grant is unavailable")]
    GrantUnavailable,
    #[error("transfer credential is unavailable")]
    CredentialUnavailable,
    #[error("transfer integrity constraints were not satisfied")]
    IntegrityMismatch,
    #[error(
        "upload completion outcome is unknown: commit acknowledgement failed ({commit}); state verification failed ({verification})"
    )]
    CompletionUnknown {
        commit: StoreError,
        verification: UploadCompletionVerification,
    },
    #[error("invalid DPoP proof: {0}")]
    Dpop(#[from] DpopError),
    #[error("transfer store failed: {0}")]
    Store(#[from] StoreError),
    #[error("required transfer evidence failed: {0}")]
    Evidence(#[from] EvidenceError),
}

/// One semantic authority shared by native SEP and compatibility adapters.
pub struct TransferAuthority {
    store: SharedTransferStore,
    evidence: SharedEvidence,
    dpop: DpopVerifier,
}

impl TransferAuthority {
    pub fn new(store: SharedTransferStore, evidence: SharedEvidence, dpop: DpopVerifier) -> Self {
        Self {
            store,
            evidence,
            dpop,
        }
    }

    pub async fn create_grant(
        &self,
        principal: &Principal,
        spec: NewTransferGrant,
        now: OffsetDateTime,
    ) -> Result<PublicTransferGrant, AuthorityError> {
        spec.validate(now)?;
        let handle = GrantHandle::mint();
        let id = Uuid::now_v7();
        let grant = self
            .store
            .insert(NewGrantRow {
                id,
                handle_hash: handle.digest(),
                owner: TransferOwner::from_principal(principal),
                spec,
            })
            .await?;

        if let Err(error) = self
            .record_for_principal(
                &grant,
                Some(principal),
                "file_transfer.grant.created",
                AuditOutcome::Success,
                None,
            )
            .await
        {
            self.revoke_unreturned_grant(grant.id).await;
            return Err(error.into());
        }

        Ok(PublicTransferGrant {
            handle,
            file_uri: grant.file_uri,
            direction: grant.direction,
            max_bytes: grant.max_bytes,
            expected_size: grant.expected_size,
            media_type: grant.media_type,
            expected_digest: grant.expected_digest,
            expires_at: grant.expires_at,
        })
    }

    /// Return the current state of one upload without consuming or reviving
    /// any transfer authority. Ownership includes the credential profile so a
    /// less-confined credential cannot inspect a grant minted by another one.
    pub async fn upload_status(
        &self,
        principal: &Principal,
        file_uri: &str,
        now: OffsetDateTime,
    ) -> Result<Option<PublicUploadStatus>, AuthorityError> {
        let Some(grant) = self
            .store
            .find_upload_by_owner(&TransferOwner::from_principal(principal), file_uri)
            .await?
        else {
            return Ok(None);
        };
        let state = upload_state(grant.status, grant.requests_used, grant.expires_at, now);
        Ok(Some(PublicUploadStatus {
            state,
            expected_size: grant.expected_size,
            media_type: grant.media_type,
            expected_digest: grant.expected_digest,
            expires_at: grant.expires_at,
        }))
    }

    pub async fn issue_native_download_credential(
        &self,
        principal: &Principal,
        spec: NewTransferGrant,
        now: OffsetDateTime,
    ) -> Result<IssuedNativeCredential, AuthorityError> {
        if spec.direction != TransferDirection::Download
            || spec.destination != TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)?
        {
            return Err(AuthorityError::InvalidGrant(
                "native credential requires a download to a native MCP host".to_owned(),
            ));
        }
        self.issue_native_credential(principal, spec, now).await
    }

    pub async fn issue_native_upload_credential(
        &self,
        principal: &Principal,
        spec: NewTransferGrant,
        now: OffsetDateTime,
    ) -> Result<IssuedNativeCredential, AuthorityError> {
        if spec.direction != TransferDirection::Upload
            || spec.source != TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)?
        {
            return Err(AuthorityError::InvalidGrant(
                "native credential requires an upload from a native MCP host".to_owned(),
            ));
        }
        self.issue_native_credential(principal, spec, now).await
    }

    async fn issue_native_credential(
        &self,
        principal: &Principal,
        mut spec: NewTransferGrant,
        now: OffsetDateTime,
    ) -> Result<IssuedNativeCredential, AuthorityError> {
        let mut key_marker = [0_u8; 32];
        rand::rng().fill_bytes(&mut key_marker);
        spec.helper_jkt = URL_SAFE_NO_PAD.encode(key_marker);
        let helper_jkt = spec.helper_jkt.clone();
        let public = self.create_grant(principal, spec, now).await?;
        let handle_hash = public.handle.digest();
        let credential = TransferCredential::mint();
        let Some(stored) = self.store.find_by_handle(&handle_hash).await? else {
            return Err(AuthorityError::GrantUnavailable);
        };
        let expires_at = std::cmp::min(stored.expires_at, now + stored.credential_ttl);
        let Some(grant) = self
            .store
            .activate(&handle_hash, &helper_jkt, &credential.digest(), expires_at)
            .await?
        else {
            return Err(AuthorityError::GrantUnavailable);
        };
        if let Err(error) = self
            .record_for_owner(
                &grant,
                "file_transfer.credential.issued",
                AuditOutcome::Success,
                None,
            )
            .await
        {
            self.revoke_unreturned_grant(grant.id).await;
            return Err(error.into());
        }
        Ok(IssuedNativeCredential {
            credential,
            expires_at,
            grant,
        })
    }

    /// Validate the proof before claiming its jti. Callers can reject malformed
    /// HTTP input without consuming replay state, then claim immediately before
    /// the credential transition.
    pub async fn exchange_credential(
        &self,
        handle: &GrantHandle,
        proof_jwt: &str,
        request_method: &str,
        request_uri: &str,
        now: OffsetDateTime,
    ) -> Result<IssuedTransferCredential, AuthorityError> {
        let handle_hash = handle.digest();
        let Some(stored) = self.store.find_by_handle(&handle_hash).await? else {
            return Err(AuthorityError::GrantUnavailable);
        };
        let unclaimed = match self
            .dpop
            .verify(proof_jwt, request_method, request_uri, None, now)
        {
            Ok(proof) => proof,
            Err(error) => {
                self.record_for_grant_without_actor(
                    &stored,
                    "file_transfer.credential.exchange_refused",
                    AuditOutcome::Denied,
                    Some("invalid_dpop_proof"),
                )
                .await?;
                return Err(error.into());
            }
        };
        if unclaimed.jkt != stored.helper_jkt {
            self.record_for_grant_without_actor(
                &stored,
                "file_transfer.credential.exchange_refused",
                AuditOutcome::Denied,
                Some("helper_key_mismatch"),
            )
            .await?;
            return Err(AuthorityError::GrantUnavailable);
        }
        let proof = match self.claim_proof(unclaimed).await {
            Ok(proof) => proof,
            Err(error) => {
                let reason = proof_claim_failure_reason(&error);
                self.record_for_owner(
                    &stored,
                    "file_transfer.credential.exchange_refused",
                    AuditOutcome::Denied,
                    Some(reason),
                )
                .await?;
                return Err(error);
            }
        };
        let credential = TransferCredential::mint();
        let expires_at = std::cmp::min(stored.expires_at, now + stored.credential_ttl);
        let Some(grant) = self
            .store
            .activate(&handle_hash, &proof.jkt, &credential.digest(), expires_at)
            .await?
        else {
            self.record_for_owner(
                &stored,
                "file_transfer.credential.exchange_refused",
                AuditOutcome::Denied,
                Some("grant_not_pending"),
            )
            .await?;
            return Err(AuthorityError::GrantUnavailable);
        };

        if let Err(error) = self
            .record_for_owner(
                &grant,
                "file_transfer.credential.exchanged",
                AuditOutcome::Success,
                None,
            )
            .await
        {
            self.revoke_unreturned_grant(grant.id).await;
            return Err(error.into());
        }

        Ok(IssuedTransferCredential {
            credential,
            expires_at,
            grant,
        })
    }

    pub async fn authorize_request(
        &self,
        credential: &TransferCredential,
        proof_jwt: &str,
        request_method: &str,
        request_uri: &str,
        now: OffsetDateTime,
    ) -> Result<AuthorizedTransferRequest, AuthorityError> {
        let credential_hash = credential.digest();
        let Some(stored) = self.store.find_by_credential_hash(&credential_hash).await? else {
            return Err(AuthorityError::CredentialUnavailable);
        };
        let unclaimed = match self.dpop.verify(
            proof_jwt,
            request_method,
            request_uri,
            Some(credential.expose()),
            now,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                self.record_for_grant_without_actor(
                    &stored,
                    "file_transfer.request.refused",
                    AuditOutcome::Denied,
                    Some("invalid_dpop_proof"),
                )
                .await?;
                return Err(error.into());
            }
        };
        if unclaimed.jkt != stored.helper_jkt {
            self.record_for_grant_without_actor(
                &stored,
                "file_transfer.request.refused",
                AuditOutcome::Denied,
                Some("helper_key_mismatch"),
            )
            .await?;
            return Err(AuthorityError::CredentialUnavailable);
        }
        let proof = match self.claim_proof(unclaimed).await {
            Ok(proof) => proof,
            Err(error) => {
                let reason = proof_claim_failure_reason(&error);
                self.record_for_owner(
                    &stored,
                    "file_transfer.request.refused",
                    AuditOutcome::Denied,
                    Some(reason),
                )
                .await?;
                return Err(error);
            }
        };
        let authorization_id = Uuid::now_v7();
        let Some(authorized) = self
            .store
            .authorize_request(&credential_hash, &proof.jkt, authorization_id)
            .await?
        else {
            self.record_for_owner(
                &stored,
                "file_transfer.request.refused",
                AuditOutcome::Denied,
                Some("credential_unavailable"),
            )
            .await?;
            return Err(AuthorityError::CredentialUnavailable);
        };

        if let Err(error) = self
            .record_for_owner(
                &authorized.grant,
                "file_transfer.request.authorized",
                AuditOutcome::Success,
                None,
            )
            .await
        {
            self.revoke_unreturned_grant(authorized.grant.id).await;
            return Err(error.into());
        }
        Ok(authorized)
    }

    pub async fn authorize_native_request(
        &self,
        credential: &TransferCredential,
    ) -> Result<AuthorizedTransferRequest, AuthorityError> {
        let credential_hash = credential.digest();
        let Some(stored) = self.store.find_by_credential_hash(&credential_hash).await? else {
            return Err(AuthorityError::CredentialUnavailable);
        };
        let native_download = stored.direction == TransferDirection::Download
            && stored.destination == TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)?;
        let native_upload = stored.direction == TransferDirection::Upload
            && stored.source == TransferEndpoint::client(NATIVE_MCP_CLIENT_REFERENCE)?;
        if !native_download && !native_upload {
            return Err(AuthorityError::CredentialUnavailable);
        }
        let authorization_id = Uuid::now_v7();
        let Some(authorized) = self
            .store
            .authorize_request(&credential_hash, &stored.helper_jkt, authorization_id)
            .await?
        else {
            self.record_for_owner(
                &stored,
                "file_transfer.request.refused",
                AuditOutcome::Denied,
                Some("credential_unavailable"),
            )
            .await?;
            return Err(AuthorityError::CredentialUnavailable);
        };
        if let Err(error) = self
            .record_for_owner(
                &authorized.grant,
                "file_transfer.request.authorized",
                AuditOutcome::Success,
                None,
            )
            .await
        {
            self.revoke_unreturned_grant(authorized.grant.id).await;
            return Err(error.into());
        }
        Ok(authorized)
    }

    pub async fn heartbeat(
        &self,
        authorized: &AuthorizedTransferRequest,
    ) -> Result<(), AuthorityError> {
        if self
            .store
            .heartbeat_request(authorized.grant.id, authorized.authorization_id)
            .await?
        {
            Ok(())
        } else {
            Err(AuthorityError::GrantUnavailable)
        }
    }

    pub async fn complete(
        &self,
        authorized: &AuthorizedTransferRequest,
        observed_size: u64,
        observed_digest: Option<&[u8]>,
    ) -> Result<TransferGrant, AuthorityError> {
        self.authorize_completion(authorized, observed_size, observed_digest)
            .await?;
        let grant = self
            .store
            .complete(
                authorized.grant.id,
                authorized.authorization_id,
                observed_size,
                observed_digest,
            )
            .await?;
        self.require_completed_grant(authorized, grant, "grant_unavailable")
            .await
    }

    /// Complete an inbound upload and make its stored file visible as one
    /// durable state transition.
    pub async fn complete_upload(
        &self,
        authorized: &AuthorizedTransferRequest,
        file_id: Uuid,
        observed_size: u64,
        observed_digest: &[u8],
        retention: Duration,
    ) -> Result<TransferGrant, AuthorityError> {
        if authorized.grant.direction != TransferDirection::Upload {
            return Err(AuthorityError::InvalidGrant(
                "atomic file publication requires an upload grant".to_owned(),
            ));
        }
        self.authorize_completion(authorized, observed_size, Some(observed_digest))
            .await?;
        self.record_upload_observation(authorized, observed_size, observed_digest)
            .await?;
        let grant = match self
            .store
            .complete_upload(
                authorized.grant.id,
                authorized.authorization_id,
                file_id,
                observed_size,
                observed_digest,
                retention,
            )
            .await
        {
            Ok(grant) => grant,
            Err(UploadCompletionError::Store(error)) => {
                return Err(AuthorityError::Store(error));
            }
            Err(UploadCompletionError::OutcomeUnknown {
                commit,
                verification,
            }) => {
                return Err(AuthorityError::CompletionUnknown {
                    commit,
                    verification,
                });
            }
        };
        self.require_completed_grant(authorized, grant, "grant_or_file_unavailable")
            .await
    }

    /// Settle an authorized request that reached a definite local failure.
    ///
    /// The restrictive state is durable before its audit write, matching
    /// revocation: an unavailable evidence sink must not leave a request active
    /// after its staged bytes have been discarded.
    pub async fn fail_authorized_request(
        &self,
        authorized: &AuthorizedTransferRequest,
        failure_code: &str,
    ) -> Result<bool, AuthorityError> {
        let changed = self
            .store
            .fail_request(
                authorized.grant.id,
                authorized.authorization_id,
                failure_code,
            )
            .await?;
        if let Err(error) = self
            .record_for_owner(
                &authorized.grant,
                "file_transfer.completion.refused",
                AuditOutcome::Denied,
                Some(if changed {
                    failure_code
                } else {
                    "request_not_active"
                }),
            )
            .await
        {
            tracing::error!(
                grant_id = %authorized.grant.id,
                changed,
                error = %error,
                "file-transfer failure audit-of-record failed after the store decision; verify the durable request state",
            );
            return Err(error.into());
        }
        Ok(changed)
    }

    async fn record_upload_observation(
        &self,
        authorized: &AuthorizedTransferRequest,
        observed_size: u64,
        observed_digest: &[u8],
    ) -> Result<(), EvidenceError> {
        let grant = &authorized.grant;
        let target = serde_json::json!({
            "file_uri": grant.file_uri,
            "grant_id": grant.id,
            "invocation_id": grant.invocation_id,
            "size_bytes": observed_size,
            "sha256_digest": URL_SAFE_NO_PAD.encode(observed_digest),
            "media_type": grant.media_type,
        })
        .to_string();
        for action in [
            "file_transfer.bytes.received",
            "file_transfer.file.verified",
        ] {
            let mut event = AuditEvent::new(action, AuditOutcome::Success)
                .with_category(EvidenceCategory::FileTransfer)
                .with_tenant(grant.owner.tenant_id.clone())
                .with_target(target.clone());
            event.principal = Some(audit_principal(&grant.owner));
            self.evidence.record_required(event).await?;
        }
        Ok(())
    }

    async fn authorize_completion(
        &self,
        authorized: &AuthorizedTransferRequest,
        observed_size: u64,
        observed_digest: Option<&[u8]>,
    ) -> Result<(), AuthorityError> {
        if observed_size > authorized.grant.max_bytes
            || authorized
                .grant
                .expected_size
                .is_some_and(|expected| expected != observed_size)
            || !digest_matches(&authorized.grant.expected_digest, observed_digest)
        {
            self.record_for_owner(
                &authorized.grant,
                "file_transfer.completion.refused",
                AuditOutcome::Denied,
                Some("integrity_mismatch"),
            )
            .await?;
            let failed = self
                .store
                .fail_request(
                    authorized.grant.id,
                    authorized.authorization_id,
                    "integrity_mismatch",
                )
                .await?;
            return Err(if failed {
                AuthorityError::IntegrityMismatch
            } else {
                AuthorityError::GrantUnavailable
            });
        }
        self.record_for_owner(
            &authorized.grant,
            "file_transfer.completion.authorized",
            AuditOutcome::Success,
            None,
        )
        .await?;
        Ok(())
    }

    async fn require_completed_grant(
        &self,
        authorized: &AuthorizedTransferRequest,
        grant: Option<TransferGrant>,
        refusal_reason: &str,
    ) -> Result<TransferGrant, AuthorityError> {
        match grant {
            Some(grant) => Ok(grant),
            None => {
                self.record_for_owner(
                    &authorized.grant,
                    "file_transfer.completion.refused",
                    AuditOutcome::Denied,
                    Some(refusal_reason),
                )
                .await?;
                Err(AuthorityError::GrantUnavailable)
            }
        }
    }

    pub async fn revoke(
        &self,
        grant: &TransferGrant,
        reason: &str,
    ) -> Result<bool, AuthorityError> {
        let changed = self.store.revoke(grant.id, reason).await?;
        if let Err(error) = self
            .record_for_owner(
                grant,
                "file_transfer.revoked",
                if changed {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Denied
                },
                Some(if changed { reason } else { "not_revocable" }),
            )
            .await
        {
            tracing::error!(
                grant_id = %grant.id,
                changed,
                error = %error,
                "file-transfer revocation audit-of-record failed after the store decision; verify the durable grant state",
            );
            return Err(error.into());
        }
        Ok(changed)
    }

    async fn claim_proof(
        &self,
        proof: UnclaimedDpopProof,
    ) -> Result<VerifiedDpopProof, AuthorityError> {
        if !self
            .store
            .claim_dpop_jti(&proof.jkt, &proof.jti, proof.replay_expires_at)
            .await?
        {
            return Err(DpopError::Replay.into());
        }
        Ok(proof.claimed())
    }

    async fn revoke_unreturned_grant(&self, grant_id: Uuid) {
        match self.store.revoke(grant_id, "evidence_unavailable").await {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!(
                    %grant_id,
                    "file-transfer cleanup could not revoke the unreturned grant because its state changed; verify the durable grant state",
                );
            }
            Err(error) => {
                tracing::error!(
                    %grant_id,
                    %error,
                    "file-transfer cleanup could not revoke the unreturned grant; verify the durable grant state",
                );
            }
        }
    }

    async fn record_for_principal(
        &self,
        grant: &TransferGrant,
        principal: Option<&Principal>,
        action: &str,
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) -> Result<(), EvidenceError> {
        let mut event = AuditEvent::new(action, outcome)
            .with_category(EvidenceCategory::FileTransfer)
            .with_tenant(grant.owner.tenant_id.clone())
            .with_target(grant_audit_target(grant));
        if let Some(principal) = principal {
            event = event.with_principal(Some(principal));
        } else {
            event.principal = Some(audit_principal(&grant.owner));
        }
        if let Some(reason) = reason {
            event = event.with_reason(reason);
        }
        self.evidence.record_required(event).await.map(|_| ())
    }

    async fn record_for_owner(
        &self,
        grant: &TransferGrant,
        action: &str,
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) -> Result<(), EvidenceError> {
        self.record_for_principal(grant, None, action, outcome, reason)
            .await
    }

    async fn record_for_grant_without_actor(
        &self,
        grant: &TransferGrant,
        action: &str,
        outcome: AuditOutcome,
        reason: Option<&str>,
    ) -> Result<(), EvidenceError> {
        let mut event = AuditEvent::new(action, outcome)
            .with_category(EvidenceCategory::FileTransfer)
            .with_tenant(grant.owner.tenant_id.clone())
            .with_target(grant_audit_target(grant));
        if let Some(reason) = reason {
            event = event.with_reason(reason);
        }
        self.evidence.record_required(event).await.map(|_| ())
    }
}

fn audit_principal(owner: &TransferOwner) -> AuditPrincipal {
    AuditPrincipal {
        sub: owner.principal_sub.clone(),
        email: None,
        groups: Vec::new(),
        issuer: owner.principal_issuer.clone(),
        scim_active: None,
        scim_groups: Vec::new(),
    }
}

fn grant_audit_target(grant: &TransferGrant) -> String {
    serde_json::json!({
        "file_uri": grant.file_uri,
        "grant_id": grant.id,
        "invocation_id": grant.invocation_id,
    })
    .to_string()
}

fn nonempty(value: String, field: &str) -> Result<String, AuthorityError> {
    if value.trim().is_empty() {
        Err(AuthorityError::InvalidGrant(format!(
            "{field} cannot be empty"
        )))
    } else {
        Ok(value)
    }
}

fn mint_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn validate_secret_shape(value: &str, prefix: &str) -> Result<(), AuthorityError> {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return Err(AuthorityError::InvalidGrant(
            "opaque transfer value has an invalid prefix".to_owned(),
        ));
    };
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        AuthorityError::InvalidGrant("opaque transfer value is malformed".to_owned())
    })?;
    if decoded.len() != 32 {
        return Err(AuthorityError::InvalidGrant(
            "opaque transfer value has an invalid length".to_owned(),
        ));
    }
    Ok(())
}

fn secret_digest(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

fn store_decode_error(error: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Database(sqlx::Error::Decode(Box::new(error)))
}

fn digest_matches(expected: &Option<TransferDigest>, observed: Option<&[u8]>) -> bool {
    match (expected, observed) {
        (None, _) => true,
        (Some(expected), Some(observed)) => expected.value == observed,
        (Some(_), None) => false,
    }
}

fn proof_claim_failure_reason(error: &AuthorityError) -> &'static str {
    if matches!(error, AuthorityError::Dpop(DpopError::Replay)) {
        "dpop_replay"
    } else {
        "replay_state_unavailable"
    }
}

fn upload_state(
    status: TransferStatus,
    requests_used: u64,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> UploadState {
    let not_started = if expires_at <= now {
        UploadState::Expired
    } else {
        UploadState::Prepared
    };
    match status {
        TransferStatus::Pending => not_started,
        TransferStatus::Active if requests_used == 0 => not_started,
        TransferStatus::Active => UploadState::InProgress,
        TransferStatus::Completed => UploadState::Ready,
        TransferStatus::Revoked | TransferStatus::Failed => UploadState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_values_are_redacted_and_round_trip() {
        let handle = GrantHandle::mint();
        let parsed = GrantHandle::parse(handle.as_str()).unwrap();
        assert_eq!(parsed, handle);
        assert!(!format!("{handle:?}").contains(handle.as_str()));

        let credential = TransferCredential::mint();
        assert!(!format!("{credential:?}").contains(credential.expose()));
        assert_eq!(credential.digest().len(), 32);
    }

    #[test]
    fn endpoint_debug_never_exposes_private_reference() {
        let endpoint = TransferEndpoint::upstream("printable", "private-artifact-42").unwrap();
        let rendered = format!("{endpoint:?}");
        assert!(rendered.contains("printable"));
        assert!(!rendered.contains("private-artifact-42"));
    }

    #[test]
    fn direction_is_part_of_grant_validity() {
        let now = OffsetDateTime::now_utc();
        let mut grant = NewTransferGrant {
            invocation_id: "call-1".to_owned(),
            file_uri: "mcp-file://gateway/file-1".to_owned(),
            direction: TransferDirection::Upload,
            source: TransferEndpoint::upstream("printable", "artifact").unwrap(),
            destination: TransferEndpoint::client("helper").unwrap(),
            helper_jkt: URL_SAFE_NO_PAD.encode([1_u8; 32]),
            max_bytes: u64::MAX,
            expected_size: None,
            media_type: None,
            expected_digest: None,
            max_requests: 2,
            expires_at: now + Duration::minutes(5),
            credential_ttl: Duration::minutes(1),
        };
        assert!(grant.validate(now).is_err());
        grant.source = TransferEndpoint::client("helper").unwrap();
        grant.destination = TransferEndpoint::upstream("printable", "input").unwrap();
        grant.max_bytes = i64::MAX as u64;
        assert!(grant.validate(now).is_ok());

        grant.source = TransferEndpoint::Client {
            reference: " ".to_owned(),
        };
        assert!(grant.validate(now).is_err());
    }

    #[test]
    fn proof_claim_failures_distinguish_replay_from_store_outage() {
        assert_eq!(
            proof_claim_failure_reason(&AuthorityError::Dpop(DpopError::Replay)),
            "dpop_replay"
        );
        assert_eq!(
            proof_claim_failure_reason(&AuthorityError::Store(StoreError::Database(
                sqlx::Error::RowNotFound,
            ))),
            "replay_state_unavailable"
        );
    }

    #[test]
    fn upload_reconciliation_distinguishes_not_started_active_and_terminal_states() {
        let now = OffsetDateTime::now_utc();
        let future = now + Duration::minutes(1);
        assert_eq!(
            upload_state(TransferStatus::Pending, 0, future, now),
            UploadState::Prepared
        );
        assert_eq!(
            upload_state(TransferStatus::Active, 0, future, now),
            UploadState::Prepared
        );
        assert_eq!(
            upload_state(TransferStatus::Active, 1, future, now),
            UploadState::InProgress
        );
        assert_eq!(
            upload_state(TransferStatus::Completed, 1, now, now),
            UploadState::Ready
        );
        assert_eq!(
            upload_state(TransferStatus::Failed, 1, future, now),
            UploadState::Failed
        );
        assert_eq!(
            upload_state(TransferStatus::Active, 1, now, now),
            UploadState::InProgress
        );
        assert_eq!(
            upload_state(TransferStatus::Pending, 0, now, now),
            UploadState::Expired
        );
        assert_eq!(
            upload_state(TransferStatus::Active, 0, now, now),
            UploadState::Expired
        );
    }
}
