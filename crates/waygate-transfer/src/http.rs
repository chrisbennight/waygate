//! Direct helper credential exchange and file byte transfer.
//!
//! MCP may carry the opaque grant handle. The narrower transfer credential is
//! returned only over this direct HTTPS exchange after the helper proves it
//! owns the temporary key bound to the grant.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Json, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, PRAGMA};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_util::io::ReaderStream;

use crate::{
    AuthorityError, AuthorizedTransferRequest, GatewayFileOwner, GatewayFileStorage, GrantHandle,
    TransferAuthority, TransferCredential, TransferDirection, TransferEndpoint,
};

pub const CREDENTIAL_EXCHANGE_PATH: &str = "/file-transfers/credentials";
pub const FILE_DOWNLOAD_PATH: &str = "/file-transfers/content";
pub const FILE_UPLOAD_PATH: &str = "/file-transfers/content";
const EXCHANGE_BODY_LIMIT: usize = 1_024;
const ACTIVE_TRANSFER_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const CLIENT_UPLOAD_SOURCE_TOOL: &str = "prepare_upload";

#[derive(Clone)]
struct ExchangeState {
    authority: Arc<TransferAuthority>,
    public_url: Arc<str>,
    admission: ExchangeAdmission,
}

#[derive(Clone)]
struct DownloadState {
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    public_url: Arc<str>,
    admission: FileTransferAdmission,
}

#[derive(Clone)]
struct UploadState {
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    public_url: Arc<str>,
    admission: FileTransferAdmission,
    retention: time::Duration,
}

/// One shared limit for file byte streams in either direction. Acquiring is
/// non-blocking so a full transfer pool does not turn ordinary requests into
/// an unbounded queue.
#[derive(Clone)]
pub struct FileTransferAdmission(Arc<Semaphore>);

impl FileTransferAdmission {
    pub fn new(max_concurrent_transfers: usize) -> Self {
        Self(Arc::new(Semaphore::new(max_concurrent_transfers.max(1))))
    }

    pub fn try_enter(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.0.clone().try_acquire_owned()
    }
}

pub fn file_download_router(
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    public_url: impl Into<Arc<str>>,
    admission: FileTransferAdmission,
) -> Router<()> {
    Router::new()
        .route(FILE_DOWNLOAD_PATH, axum::routing::get(download))
        .with_state(DownloadState {
            authority,
            storage,
            public_url: public_url.into(),
            admission,
        })
}

pub fn file_transfer_router(
    authority: Arc<TransferAuthority>,
    storage: Arc<GatewayFileStorage>,
    public_url: impl Into<Arc<str>>,
    admission: FileTransferAdmission,
    retention: time::Duration,
) -> Router<()> {
    let public_url = public_url.into();
    file_download_router(
        authority.clone(),
        storage.clone(),
        public_url.clone(),
        admission.clone(),
    )
    .merge(
        Router::new()
            .route(FILE_UPLOAD_PATH, axum::routing::put(upload).post(upload))
            .layer(DefaultBodyLimit::disable())
            .with_state(UploadState {
                authority,
                storage,
                public_url,
                admission,
                retention,
            }),
    )
}

async fn upload(
    State(state): State<UploadState>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Ok(_permit) = state.admission.try_enter() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Some(credential) = transfer_credential(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let request_uri = format!(
        "{}{}",
        state.public_url.trim_end_matches('/'),
        FILE_UPLOAD_PATH,
    );
    let (authorization, expected_source) = match credential {
        PresentedCredential::Dpop { credential, proof } => (
            state
                .authority
                .authorize_request(
                    &credential,
                    &proof,
                    method.as_str(),
                    &request_uri,
                    OffsetDateTime::now_utc(),
                )
                .await,
            crate::GENERIC_HELPER_REFERENCE,
        ),
        PresentedCredential::Native(credential) => (
            state.authority.authorize_native_request(&credential).await,
            crate::NATIVE_MCP_CLIENT_REFERENCE,
        ),
    };
    let authorized = match authorization {
        Ok(authorized) => authorized,
        Err(AuthorityError::Store(_) | AuthorityError::Evidence(_)) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
        Err(_) => return error_response(StatusCode::UNAUTHORIZED, "invalid_token"),
    };
    if authorized.grant.direction != TransferDirection::Upload
        || !matches!(
            &authorized.grant.source,
            TransferEndpoint::Client { reference } if reference == expected_source
        )
        || !matches!(
            &authorized.grant.destination,
            TransferEndpoint::Upstream { server, reference }
                if server == "gateway" && reference == &authorized.grant.file_uri
        )
    {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::FORBIDDEN, "invalid_grant");
    }
    if !matches!(method, Method::PUT | Method::POST)
        || !request_media_type_matches(authorized.grant.media_type.as_deref(), &headers)
    {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::BAD_REQUEST, "invalid_upload");
    }
    let Some(file_id) = gateway_file_id(&authorized.grant.file_uri) else {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let owner = GatewayFileOwner {
        tenant_id: authorized.grant.owner.tenant_id.clone(),
        principal_sub: authorized.grant.owner.principal_sub.clone(),
        principal_issuer: authorized.grant.owner.principal_issuer.clone(),
    };
    let expected_sha256 = authorized
        .grant
        .expected_digest
        .as_ref()
        .filter(|digest| digest.algorithm == "sha-256")
        .map(|digest| digest.value.clone());
    if authorized.grant.expected_digest.is_some() && expected_sha256.is_none() {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::BAD_REQUEST, "invalid_upload");
    }
    let heartbeat = ActiveTransferHeartbeat(spawn_transfer_heartbeat(
        state.authority.clone(),
        authorized.clone(),
    ));
    let stream = body.into_data_stream().map(|chunk| {
        chunk.map_err(|error| std::io::Error::other(format!("upload body stream failed: {error}")))
    });
    let staged = state
        .storage
        .stage_upload(
            file_id,
            crate::NewGatewayFile {
                batch_id: file_id,
                owner,
                invocation_id: authorized.grant.invocation_id.clone(),
                upstream_server: waygate_core::FILES_BUILTIN_NAMESPACE.to_owned(),
                upstream_tool: CLIENT_UPLOAD_SOURCE_TOOL.to_owned(),
                upstream_uri: expected_source.to_owned(),
                display_name: None,
                media_type: authorized.grant.media_type.clone(),
                expected_size: authorized.grant.expected_size,
                expected_sha256,
                max_bytes: Some(authorized.grant.max_bytes),
                inspection_status: crate::FileInspectionStatus::Uninspectable,
                retention: state.retention,
            },
            stream,
        )
        .await;
    let staged = match staged {
        Ok(staged) => staged,
        Err(error) => {
            tracing::warn!(%file_id, error = %error, "file upload could not be staged");
            fail_authorized_request(&state.authority, &authorized).await;
            return error_response(StatusCode::BAD_REQUEST, "invalid_upload");
        }
    };
    heartbeat.abort();
    if let Err(error) = state
        .authority
        .complete_upload(
            &authorized,
            file_id,
            staged.size,
            &staged.sha256,
            state.retention,
        )
        .await
    {
        tracing::warn!(%file_id, error = %error, "file upload completion and publication were refused");
        if !matches!(&error, AuthorityError::CompletionUnknown { .. }) {
            if finalize_authorized_failure(&state.authority, &authorized).await {
                if let Err(cleanup_error) = state.storage.discard_batch(file_id).await {
                    tracing::warn!(%file_id, error = %cleanup_error, "refused file upload cleanup will be retried");
                }
            } else {
                tracing::warn!(%file_id, "staged upload retained because its durable failure state could not be confirmed");
            }
        }
        return match error {
            AuthorityError::CompletionUnknown { .. } => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "completion_unknown")
            }
            AuthorityError::Store(_) | AuthorityError::Evidence(_) => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
            }
            _ => error_response(StatusCode::BAD_REQUEST, "invalid_upload"),
        };
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn request_media_type_matches(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|actual| {
            media_type_essence(expected).eq_ignore_ascii_case(media_type_essence(actual))
        })
}

fn media_type_essence(value: &str) -> &str {
    value
        .split_once(';')
        .map_or(value, |(essence, _)| essence)
        .trim()
}

async fn download(State(state): State<DownloadState>, headers: HeaderMap) -> Response {
    let Ok(permit) = state.admission.try_enter() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Some(credential) = transfer_credential(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let request_uri = format!(
        "{}{}",
        state.public_url.trim_end_matches('/'),
        FILE_DOWNLOAD_PATH,
    );
    let (authorization, expected_destination) = match credential {
        PresentedCredential::Dpop { credential, proof } => (
            state
                .authority
                .authorize_request(
                    &credential,
                    &proof,
                    "GET",
                    &request_uri,
                    OffsetDateTime::now_utc(),
                )
                .await,
            crate::GENERIC_HELPER_REFERENCE,
        ),
        PresentedCredential::Native(credential) => (
            state.authority.authorize_native_request(&credential).await,
            crate::NATIVE_MCP_CLIENT_REFERENCE,
        ),
    };
    let authorized = match authorization {
        Ok(authorized) => authorized,
        Err(AuthorityError::Store(_) | AuthorityError::Evidence(_)) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
        Err(_) => return error_response(StatusCode::UNAUTHORIZED, "invalid_token"),
    };
    if authorized.grant.direction != TransferDirection::Download
        || !matches!(
            &authorized.grant.destination,
            TransferEndpoint::Client { reference } if reference == expected_destination
        )
    {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::FORBIDDEN, "invalid_grant");
    }
    let Some(file_id) = gateway_file_id(&authorized.grant.file_uri) else {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::NOT_FOUND, "file_unavailable");
    };
    let owner = GatewayFileOwner {
        tenant_id: authorized.grant.owner.tenant_id.clone(),
        principal_sub: authorized.grant.owner.principal_sub.clone(),
        principal_issuer: authorized.grant.owner.principal_issuer.clone(),
    };
    let file = match state.storage.find_ready(&owner, file_id).await {
        Ok(Some(file)) => file,
        Ok(None) => {
            fail_authorized_request(&state.authority, &authorized).await;
            return error_response(StatusCode::NOT_FOUND, "file_unavailable");
        }
        Err(error) => {
            tracing::warn!(file_id = %file_id, error = %error, "gateway file lookup failed");
            fail_authorized_request(&state.authority, &authorized).await;
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };
    if !grant_matches_file(&authorized, &file) {
        fail_authorized_request(&state.authority, &authorized).await;
        return error_response(StatusCode::FORBIDDEN, "invalid_grant");
    }
    let handle = match tokio::fs::File::open(state.storage.path_for(&file)).await {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(file_id = %file_id, error = %error, "gateway file open failed");
            fail_authorized_request(&state.authority, &authorized).await;
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };

    let stream = download_stream(
        ReaderStream::new(handle),
        state.authority,
        authorized,
        permit,
    );
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&file.size.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    if let Some(media_type) = file.media_type.as_deref() {
        if let Ok(value) = HeaderValue::from_str(media_type) {
            response.headers_mut().insert(CONTENT_TYPE, value);
        }
    }
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

fn grant_matches_file(
    authorized: &AuthorizedTransferRequest,
    file: &crate::StoredGatewayFile,
) -> bool {
    let grant = &authorized.grant;
    if file.size > grant.max_bytes
        || grant
            .expected_size
            .is_some_and(|expected| expected != file.size)
        || grant
            .media_type
            .as_ref()
            .is_some_and(|expected| file.media_type.as_ref() != Some(expected))
    {
        return false;
    }
    if !matches!(
        &grant.source,
        TransferEndpoint::Upstream { server, reference }
            if server == &file.upstream_server && reference == &file.upstream_uri
    ) {
        return false;
    }
    match &grant.expected_digest {
        Some(expected) => expected.algorithm == "sha-256" && expected.value == file.sha256,
        None => true,
    }
}

fn download_stream(
    reader: ReaderStream<tokio::fs::File>,
    authority: Arc<TransferAuthority>,
    authorized: AuthorizedTransferRequest,
    permit: OwnedSemaphorePermit,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    let heartbeat_task = spawn_transfer_heartbeat(authority.clone(), authorized.clone());
    futures::stream::unfold(
        Some(ActiveDownload {
            reader,
            authority,
            authorized,
            size: 0,
            digest: Sha256::new(),
            heartbeat_task,
            _permit: permit,
            finished: false,
        }),
        |state| async move {
            let mut state = state?;
            match state.reader.next().await {
                Some(Ok(chunk)) => {
                    state.size = match state.size.checked_add(chunk.len() as u64) {
                        Some(size) => size,
                        None => {
                            fail_authorized_request(&state.authority, &state.authorized).await;
                            state.finished = true;
                            return Some((Err(std::io::Error::other("file size overflow")), None));
                        }
                    };
                    state.digest.update(&chunk);
                    Some((Ok(chunk), Some(state)))
                }
                Some(Err(error)) => {
                    fail_authorized_request(&state.authority, &state.authorized).await;
                    state.finished = true;
                    Some((Err(error), None))
                }
                None => {
                    state.finished = true;
                    state.heartbeat_task.abort();
                    let digest = state.digest.clone().finalize();
                    match state
                        .authority
                        .complete(&state.authorized, state.size, Some(digest.as_slice()))
                        .await
                    {
                        Ok(_) => None,
                        Err(error) => {
                            tracing::warn!(grant_id = %state.authorized.grant.id, error = %error, "file download completion failed");
                            Some((
                                Err(std::io::Error::other("file integrity check failed")),
                                None,
                            ))
                        }
                    }
                }
            }
        },
    )
}

fn spawn_transfer_heartbeat(
    authority: Arc<TransferAuthority>,
    authorized: AuthorizedTransferRequest,
) -> tokio::task::JoinHandle<()> {
    let direction = authorized.grant.direction.as_str();
    tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + ACTIVE_TRANSFER_HEARTBEAT_INTERVAL,
            ACTIVE_TRANSFER_HEARTBEAT_INTERVAL,
        );
        loop {
            heartbeat.tick().await;
            match authority.heartbeat(&authorized).await {
                Ok(()) => {}
                Err(AuthorityError::GrantUnavailable) => {
                    tracing::warn!(grant_id = %authorized.grant.id, direction, "file transfer authority is no longer available");
                    return;
                }
                Err(error) => {
                    tracing::warn!(grant_id = %authorized.grant.id, direction, error = %error, "file transfer heartbeat failed; retrying");
                }
            }
        }
    })
}

struct ActiveTransferHeartbeat(tokio::task::JoinHandle<()>);

impl ActiveTransferHeartbeat {
    fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for ActiveTransferHeartbeat {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ActiveDownload {
    reader: ReaderStream<tokio::fs::File>,
    authority: Arc<TransferAuthority>,
    authorized: AuthorizedTransferRequest,
    size: u64,
    digest: Sha256,
    heartbeat_task: tokio::task::JoinHandle<()>,
    _permit: OwnedSemaphorePermit,
    finished: bool,
}

impl Drop for ActiveDownload {
    fn drop(&mut self) {
        self.heartbeat_task.abort();
        if self.finished {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(grant_id = %self.authorized.grant.id, "dropped file download could not be finalized outside a Tokio runtime");
            return;
        };
        let authority = self.authority.clone();
        let authorized = self.authorized.clone();
        runtime.spawn(async move {
            fail_authorized_request(&authority, &authorized).await;
        });
    }
}

enum PresentedCredential {
    Dpop {
        credential: TransferCredential,
        proof: String,
    },
    Native(TransferCredential),
}

fn transfer_credential(headers: &HeaderMap) -> Option<PresentedCredential> {
    let value = headers.get("authorization")?.to_str().ok()?;
    if let Some(credential) = value.strip_prefix("DPoP ") {
        let credential = TransferCredential::parse(credential.to_owned()).ok()?;
        let proof = headers.get("dpop")?.to_str().ok()?.to_owned();
        return Some(PresentedCredential::Dpop { credential, proof });
    }
    let credential = value.strip_prefix("Bearer ")?;
    TransferCredential::parse(credential.to_owned())
        .ok()
        .map(PresentedCredential::Native)
}

fn gateway_file_id(uri: &str) -> Option<uuid::Uuid> {
    let uri = url::Url::parse(uri).ok()?;
    if uri.scheme() != "mcp-file" || uri.host_str() != Some("gateway") {
        return None;
    }
    uuid::Uuid::parse_str(uri.path().trim_start_matches('/')).ok()
}

async fn fail_authorized_request(
    authority: &TransferAuthority,
    authorized: &AuthorizedTransferRequest,
) {
    let _ = finalize_authorized_failure(authority, authorized).await;
}

async fn finalize_authorized_failure(
    authority: &TransferAuthority,
    authorized: &AuthorizedTransferRequest,
) -> bool {
    match authority
        .fail_authorized_request(authorized, "transfer_refused")
        .await
    {
        Ok(_) => true,
        Err(AuthorityError::Evidence(error)) => {
            tracing::warn!(grant_id = %authorized.grant.id, error = %error, "file transfer refusal was finalized but its audit record failed");
            true
        }
        Err(error) => {
            tracing::warn!(grant_id = %authorized.grant.id, error = %error, "file transfer refusal could not be finalized");
            false
        }
    }
}

#[derive(Clone)]
struct ExchangeAdmission(Arc<Semaphore>);

impl ExchangeAdmission {
    fn new(max_concurrent_exchanges: usize) -> Self {
        Self(Arc::new(Semaphore::new(max_concurrent_exchanges.max(1))))
    }

    fn try_enter(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        self.0.clone().try_acquire_owned()
    }
}

/// Build the helper exchange route without OAuth bearer middleware.
///
/// Access is controlled by the opaque pending grant and an RFC 9449 DPoP proof
/// from the ephemeral helper key. This lets an ordinary script participate
/// without access to the MCP client's OAuth or CIMD cache.
pub fn credential_exchange_router(
    authority: Arc<TransferAuthority>,
    public_url: impl Into<Arc<str>>,
    max_concurrent_exchanges: usize,
) -> Router<()> {
    Router::new()
        .route(
            CREDENTIAL_EXCHANGE_PATH,
            post(exchange).layer(DefaultBodyLimit::max(EXCHANGE_BODY_LIMIT)),
        )
        .with_state(ExchangeState {
            authority,
            public_url: public_url.into(),
            admission: ExchangeAdmission::new(max_concurrent_exchanges),
        })
}

async fn exchange(
    State(state): State<ExchangeState>,
    headers: HeaderMap,
    payload: Result<Json<CredentialRequest>, JsonRejection>,
) -> Response {
    let Ok(_permit) = state.admission.try_enter() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let Ok(Json(payload)) = payload else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let proof = headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let handle = match GrantHandle::parse(payload.grant_handle) {
        Ok(handle) => handle,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    let request_uri = format!(
        "{}/file-transfers/credentials",
        state.public_url.trim_end_matches('/'),
    );

    match state
        .authority
        .exchange_credential(
            &handle,
            proof,
            "POST",
            &request_uri,
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(issued) => {
            let expires_in = (issued.expires_at - OffsetDateTime::now_utc())
                .whole_seconds()
                .max(0);
            let payload = CredentialResponse {
                access_token: issued.credential.expose(),
                token_type: "DPoP",
                expires_in,
            };
            match serde_json::to_vec(&payload) {
                Ok(body) => json_response(StatusCode::OK, body),
                Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            }
        }
        Err(AuthorityError::Store(_) | AuthorityError::Evidence(_)) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        Err(_) => error_response(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    grant_handle: String,
}

#[derive(Serialize)]
struct CredentialResponse<'a> {
    access_token: &'a str,
    token_type: &'static str,
    expires_in: i64,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

fn error_response(status: StatusCode, error: &'static str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse { error })
        .unwrap_or_else(|_| br#"{"error":"server_error"}"#.to_vec());
    json_response(status, body)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FileInspectionStatus, StoredGatewayFile, TransferDigest, TransferOwner, TransferStatus,
    };

    fn matching_file_and_request() -> (StoredGatewayFile, AuthorizedTransferRequest) {
        let tenant_id = waygate_core::TenantId::parse("file-test").unwrap();
        let file_id = uuid::Uuid::new_v4();
        let digest = vec![7; 32];
        let file = StoredGatewayFile {
            id: file_id,
            owner: GatewayFileOwner {
                tenant_id: tenant_id.clone(),
                principal_sub: "alice".to_owned(),
                principal_issuer: "test".to_owned(),
            },
            invocation_id: "call-1".to_owned(),
            upstream_server: "printable".to_owned(),
            upstream_tool: "render".to_owned(),
            upstream_uri: "mcp-file://printable/output".to_owned(),
            storage_key: file_id.to_string(),
            display_name: Some("output.bin".to_owned()),
            media_type: Some("application/octet-stream".to_owned()),
            size: 12,
            sha256: digest.clone(),
            inspection_status: FileInspectionStatus::Uninspectable,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        };
        let request = AuthorizedTransferRequest {
            authorization_id: uuid::Uuid::new_v4(),
            request_number: 1,
            grant: crate::TransferGrant {
                id: uuid::Uuid::new_v4(),
                owner: TransferOwner {
                    tenant_id,
                    principal_sub: "alice".to_owned(),
                    principal_issuer: "test".to_owned(),
                    credential_profile_id: None,
                },
                invocation_id: "call-1".to_owned(),
                file_uri: file.uri(),
                direction: TransferDirection::Download,
                source: TransferEndpoint::upstream("printable", "mcp-file://printable/output")
                    .unwrap(),
                destination: TransferEndpoint::client(crate::GENERIC_HELPER_REFERENCE).unwrap(),
                helper_jkt: "test-thumbprint".to_owned(),
                max_bytes: 12,
                expected_size: Some(12),
                media_type: Some("application/octet-stream".to_owned()),
                expected_digest: Some(TransferDigest {
                    algorithm: "sha-256".to_owned(),
                    value: digest,
                }),
                max_requests: 1,
                requests_used: 1,
                credential_ttl: time::Duration::minutes(1),
                status: TransferStatus::Active,
                credential_expires_at: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
                created_at: OffsetDateTime::now_utc(),
            },
        };
        (file, request)
    }

    #[test]
    fn all_responses_disable_caching() {
        let response = error_response(StatusCode::BAD_REQUEST, "invalid_grant");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[PRAGMA], "no-cache");
    }

    #[test]
    fn exchange_route_never_places_the_grant_handle_in_the_uri() {
        assert_eq!(CREDENTIAL_EXCHANGE_PATH, "/file-transfers/credentials");
        let payload: CredentialRequest =
            serde_json::from_str(r#"{"grant_handle":"ftg_value"}"#).unwrap();
        assert_eq!(payload.grant_handle, "ftg_value");
    }

    #[test]
    fn admission_is_fail_fast_when_database_work_is_at_capacity() {
        let admission = ExchangeAdmission::new(1);
        let _first = admission.try_enter().unwrap();
        assert!(admission.try_enter().is_err());
    }

    #[test]
    fn file_stream_admission_is_shared_and_fail_fast() {
        let admission = FileTransferAdmission::new(1);
        let first = admission.try_enter().unwrap();
        assert!(admission.clone().try_enter().is_err());
        drop(first);
        assert!(admission.try_enter().is_ok());
    }

    #[test]
    fn upload_media_type_compares_the_declared_and_received_essence() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );

        assert!(request_media_type_matches(
            Some("text/plain; charset=utf-8"),
            &headers
        ));
        assert!(!request_media_type_matches(Some("image/png"), &headers));
    }

    #[test]
    fn download_refuses_a_grant_whose_file_facts_changed() {
        let (file, request) = matching_file_and_request();
        assert!(grant_matches_file(&request, &file));

        let mut changed = file.clone();
        changed.size += 1;
        assert!(!grant_matches_file(&request, &changed));

        let mut changed = file.clone();
        changed.media_type = Some("text/plain".to_owned());
        assert!(!grant_matches_file(&request, &changed));

        let mut changed = file.clone();
        changed.sha256[0] ^= 1;
        assert!(!grant_matches_file(&request, &changed));

        let mut changed = file;
        changed.upstream_uri = "mcp-file://printable/other".to_owned();
        assert!(!grant_matches_file(&request, &changed));
    }
}
