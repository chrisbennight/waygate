//! Independent reference host for draft SEP-2631 HTTPS file descriptors.
//!
//! The wire shapes intentionally do not depend on `waygate-mcp`: serialized
//! agreement is tested across independent representations. The executor moves
//! bytes in bounded chunks and exposes only file references and measurements to
//! its caller.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use futures::stream;
use rand::Rng as _;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::oneshot;
use url::Url;

const TRANSFER_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDigest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTransferDescriptor {
    pub transport: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferMeasurements {
    pub size: u64,
    pub digest: FileDigest,
}

/// Supplies transfer-only credentials obtained outside the model-facing
/// projection. Production exchange and envelope semantics are intentionally
/// left to the gateway authority.
pub trait TransferCredentialProvider: Send + Sync {
    fn apply(&self, headers: &mut HeaderMap) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct TransferClientConfig {
    /// A total request timeout. `None` permits long-running streams while the
    /// caller retains cancellation control.
    pub total_timeout: Option<Duration>,
    pub max_download_redirects: usize,
}

impl Default for TransferClientConfig {
    fn default() -> Self {
        Self {
            total_timeout: None,
            max_download_redirects: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileDurability {
    /// Flush userspace buffers before publication.
    Flush,
    /// Ask the filesystem to synchronize file data before publication.
    SyncData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadOptions {
    pub overwrite_existing: bool,
    pub durability: FileDurability,
}

pub struct ReferenceFileHost {
    client: reqwest::Client,
    max_download_redirects: usize,
}

impl ReferenceFileHost {
    pub fn new(config: TransferClientConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(timeout) = config.total_timeout {
            builder = builder.timeout(timeout);
        }
        Ok(Self {
            client: builder.build().context("build file transfer client")?,
            max_download_redirects: config.max_download_redirects,
        })
    }

    #[cfg(test)]
    fn with_test_client(client: reqwest::Client, max_download_redirects: usize) -> Self {
        Self {
            client,
            max_download_redirects,
        }
    }

    pub async fn upload_path(
        &self,
        authorized: &AuthorizeUploadResult,
        source: &Path,
        credential: Option<&dyn TransferCredentialProvider>,
    ) -> Result<TransferMeasurements> {
        let file = tokio::fs::File::open(source)
            .await
            .with_context(|| format!("open upload source {}", source.display()))?;
        let display_name = authorized.file.name.clone().or_else(|| {
            source
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        });
        self.upload_reader(authorized, file, display_name, credential)
            .await
    }

    /// Upload an arbitrary reader without requiring a known length. The reader
    /// is consumed once and never accumulated into a whole-file buffer.
    pub async fn upload_reader<R>(
        &self,
        authorized: &AuthorizeUploadResult,
        reader: R,
        display_name: Option<String>,
        credential: Option<&dyn TransferCredentialProvider>,
    ) -> Result<TransferMeasurements>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        validate_expected_digest(authorized.file.digest.as_ref())?;
        let descriptor = &authorized.upload;
        let (url, mut headers) = validate_descriptor(descriptor)?;
        apply_credential(&mut headers, credential)?;
        let method = match descriptor.method {
            TransferMethod::PUT => Method::PUT,
            TransferMethod::POST => Method::POST,
            TransferMethod::GET => bail!("upload descriptor must use PUT or POST"),
        };
        if descriptor.multipart.is_some() && method != Method::POST {
            bail!("multipart upload descriptor must use POST");
        }

        let (body, completion) = upload_body(reader, &authorized.file);
        let request = if let Some(multipart) = &descriptor.multipart {
            // reqwest supplies the actual boundary; a generic descriptor value
            // cannot know it before the streaming form is constructed.
            headers.remove(reqwest::header::CONTENT_TYPE);
            headers.remove(reqwest::header::CONTENT_LENGTH);
            let mut part = reqwest::multipart::Part::stream(body);
            if let Some(name) = display_name {
                part = part.file_name(name);
            }
            if let Some(mime_type) = &authorized.file.mime_type {
                part = part
                    .mime_str(mime_type)
                    .context("invalid upload MIME type")?;
            }
            let mut form = reqwest::multipart::Form::new();
            for (name, value) in &multipart.fields {
                form = form.text(name.clone(), value.clone());
            }
            form = form.part(multipart.file_field.clone(), part);
            self.client
                .request(method, url)
                .headers(headers)
                .multipart(form)
        } else {
            self.client.request(method, url).headers(headers).body(body)
        };

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                let request_error = transfer_error("upload request", &error);
                if let Ok(Err(message)) = completion.await {
                    bail!(message);
                }
                return Err(request_error);
            }
        };
        if response.status().is_redirection() {
            bail!("upload endpoint redirected; obtain a fresh transfer descriptor");
        }
        if !response.status().is_success() {
            bail!("upload endpoint returned {}", response.status());
        }
        receive_upload_measurements(completion).await
    }

    pub async fn download_to(
        &self,
        authorized: &AuthorizeDownloadResult,
        destination: &Path,
        options: DownloadOptions,
        credential: Option<&dyn TransferCredentialProvider>,
    ) -> Result<TransferMeasurements> {
        validate_expected_digest(authorized.file.digest.as_ref())?;
        if authorized.download.method != TransferMethod::GET {
            bail!("download descriptor must use GET");
        }
        if authorized.download.multipart.is_some() {
            bail!("download descriptor must not contain multipart instructions");
        }
        let (url, mut headers) = validate_descriptor(&authorized.download)?;
        apply_credential(&mut headers, credential)?;
        let mut response = self.send_download(url, headers).await?;
        if !response.status().is_success() {
            bail!("download endpoint returned {}", response.status());
        }

        let parent = destination.parent().context("destination has no parent")?;
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create destination directory {}", parent.display()))?;
        let temporary = temporary_path(destination);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .with_context(|| format!("create staged download {}", temporary.display()))?;

        let transfer = async {
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| transfer_error("download body", &error))?
            {
                size = size
                    .checked_add(chunk.len() as u64)
                    .context("download size overflow")?;
                if authorized.file.size.is_some_and(|expected| size > expected) {
                    bail!("download exceeds declared file size");
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .context("write download chunk")?;
            }
            file.flush().await.context("flush staged download")?;
            if options.durability == FileDurability::SyncData {
                file.sync_data()
                    .await
                    .context("sync staged download data")?;
            }
            measurements_for(&authorized.file, size, hasher.finalize().as_slice())
        }
        .await;
        drop(file);

        let measurements = match transfer {
            Ok(measurements) => measurements,
            Err(error) => return cleanup_staged_error(&temporary, error).await,
        };
        let publication = if options.overwrite_existing {
            tokio::fs::rename(&temporary, destination).await
        } else {
            publish_noreplace(temporary.clone(), destination.to_owned()).await
        };
        if let Err(error) = publication {
            return cleanup_staged_error(
                &temporary,
                anyhow::Error::new(error).context(format!(
                    "publish verified download to {}",
                    destination.display()
                )),
            )
            .await;
        }
        Ok(measurements)
    }

    async fn send_download(
        &self,
        mut url: Url,
        mut headers: HeaderMap,
    ) -> Result<reqwest::Response> {
        for redirect_count in 0..=self.max_download_redirects {
            let response = self
                .client
                .get(url.clone())
                .headers(headers.clone())
                .send()
                .await
                .map_err(|error| transfer_error("download request", &error))?;
            if !is_redirect(response.status()) {
                return Ok(response);
            }
            if redirect_count == self.max_download_redirects {
                bail!("download exceeded configured redirect limit");
            }
            let location = response
                .headers()
                .get(LOCATION)
                .context("download redirect omitted Location")?
                .to_str()
                .context("download redirect Location is not valid text")?;
            let next = url.join(location).context("resolve download redirect")?;
            validate_transfer_url(&next)?;
            if !same_origin(&url, &next) {
                // Descriptor and helper credentials are scoped to the original
                // authority. A signed redirect URL can carry its own authority;
                // no caller-supplied header crosses that boundary.
                headers.clear();
            }
            url = next;
        }
        unreachable!("bounded redirect loop returns on every terminal branch")
    }
}

fn upload_body<R>(
    reader: R,
    expected: &FileValue,
) -> (
    reqwest::Body,
    oneshot::Receiver<std::result::Result<TransferMeasurements, String>>,
)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (completion_tx, completion_rx) = oneshot::channel();
    let state = UploadStreamState {
        reader,
        hasher: Sha256::new(),
        size: 0,
        expected_size: expected.size,
        expected_digest: expected.digest.clone(),
        completion: Some(completion_tx),
    };
    let stream = stream::try_unfold(state, |mut state| async move {
        let mut buffer = vec![0_u8; TRANSFER_CHUNK_BYTES];
        let read = match state.reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(error) => {
                send_upload_failure(&mut state.completion, error.to_string());
                return Err(error);
            }
        };
        if read == 0 {
            let digest = state.hasher.finalize();
            let result = measurements_for_parts(
                state.expected_size,
                state.expected_digest.as_ref(),
                state.size,
                digest.as_slice(),
            );
            match result {
                Ok(measurements) => {
                    if let Some(completion) = state.completion.take() {
                        let _ = completion.send(Ok(measurements));
                    }
                    Ok(None)
                }
                Err(error) => {
                    let message = error.to_string();
                    send_upload_failure(&mut state.completion, message.clone());
                    Err(io::Error::other(message))
                }
            }
        } else {
            buffer.truncate(read);
            state.size = state
                .size
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("upload size overflow"))?;
            if state
                .expected_size
                .is_some_and(|expected| state.size > expected)
            {
                let message = "upload exceeds declared file size".to_owned();
                send_upload_failure(&mut state.completion, message.clone());
                return Err(io::Error::other(message));
            }
            state.hasher.update(&buffer);
            Ok(Some((bytes::Bytes::from(buffer), state)))
        }
    });
    (reqwest::Body::wrap_stream(stream), completion_rx)
}

struct UploadStreamState<R> {
    reader: R,
    hasher: Sha256,
    size: u64,
    expected_size: Option<u64>,
    expected_digest: Option<FileDigest>,
    completion: Option<oneshot::Sender<std::result::Result<TransferMeasurements, String>>>,
}

async fn receive_upload_measurements(
    completion: oneshot::Receiver<std::result::Result<TransferMeasurements, String>>,
) -> Result<TransferMeasurements> {
    match completion.await.context("upload body did not complete")? {
        Ok(measurements) => Ok(measurements),
        Err(message) => bail!(message),
    }
}

fn send_upload_failure(
    completion: &mut Option<oneshot::Sender<std::result::Result<TransferMeasurements, String>>>,
    message: String,
) {
    if let Some(completion) = completion.take() {
        let _ = completion.send(Err(message));
    }
}

fn measurements_for(file: &FileValue, size: u64, digest: &[u8]) -> Result<TransferMeasurements> {
    measurements_for_parts(file.size, file.digest.as_ref(), size, digest)
}

fn measurements_for_parts(
    expected_size: Option<u64>,
    expected_digest: Option<&FileDigest>,
    size: u64,
    digest: &[u8],
) -> Result<TransferMeasurements> {
    if expected_size.is_some_and(|expected| expected != size) {
        bail!("file size mismatch");
    }
    let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    if expected_digest.is_some_and(|expected| expected.value != value) {
        bail!("file digest mismatch");
    }
    Ok(TransferMeasurements {
        size,
        digest: FileDigest {
            algorithm: "sha-256".to_owned(),
            value,
        },
    })
}

fn validate_expected_digest(digest: Option<&FileDigest>) -> Result<()> {
    if let Some(digest) = digest {
        if digest.algorithm != "sha-256" {
            bail!("unsupported digest algorithm {}", digest.algorithm);
        }
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&digest.value)
            .context("file digest is not base64url without padding")?;
        if decoded.len() != 32 {
            bail!("SHA-256 digest must contain 32 bytes");
        }
    }
    Ok(())
}

fn validate_descriptor(descriptor: &FileTransferDescriptor) -> Result<(Url, HeaderMap)> {
    if descriptor.transport != "https" {
        bail!("unsupported file transport {}", descriptor.transport);
    }
    if let Some(expires_at) = &descriptor.expires_at {
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .context("parse transfer descriptor expiry")?;
    }
    let url = Url::parse(&descriptor.url).context("parse transfer URL")?;
    validate_transfer_url(&url)?;
    let mut headers = HeaderMap::new();
    for (name, value) in &descriptor.headers {
        let name =
            HeaderName::from_bytes(name.as_bytes()).context("invalid transfer header name")?;
        let value = HeaderValue::from_str(value).context("invalid transfer header value")?;
        headers.insert(name, value);
    }
    Ok((url, headers))
}

fn validate_transfer_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("file transfer URL must use https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("file transfer URL must not contain userinfo");
    }
    Ok(())
}

fn apply_credential(
    headers: &mut HeaderMap,
    credential: Option<&dyn TransferCredentialProvider>,
) -> Result<()> {
    if let Some(credential) = credential {
        credential.apply(headers)?;
    }
    Ok(())
}

fn transfer_error(action: &str, error: &reqwest::Error) -> anyhow::Error {
    let category = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() {
        "body transfer failed"
    } else if error.is_request() {
        "request construction failed"
    } else {
        "request failed"
    };
    anyhow::anyhow!("{action} {category}")
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn temporary_path(destination: &Path) -> PathBuf {
    let mut entropy = [0_u8; 16];
    rand::rng().fill_bytes(&mut entropy);
    let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entropy);
    let mut name = std::ffi::OsString::from(".");
    name.push(
        destination
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("download")),
    );
    name.push(format!(".{suffix}.part"));
    destination.with_file_name(name)
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
async fn publish_noreplace(source: PathBuf, destination: PathBuf) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &source,
            rustix::fs::CWD,
            &destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "redox")))]
async fn publish_noreplace(source: PathBuf, destination: PathBuf) -> io::Result<()> {
    tokio::fs::hard_link(&source, &destination).await?;
    tokio::fs::remove_file(source).await
}

async fn cleanup_staged_error<T>(temporary: &Path, error: anyhow::Error) -> Result<T> {
    match tokio::fs::remove_file(temporary).await {
        Ok(()) => Err(error),
        Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => Err(error),
        Err(cleanup_error) => Err(error).context(format!(
            "remove staged download {} after failure: {cleanup_error}",
            temporary.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum::body::{Body, Bytes};
    use axum::extract::{DefaultBodyLimit, Multipart, State};
    use axum::http::{HeaderMap as AxumHeaders, HeaderValue as AxumHeaderValue};
    use axum::response::Response;
    use axum::routing::{get, post, put};
    use axum::Router;
    use axum_server::tls_rustls::RustlsConfig;
    use futures::StreamExt as _;
    use rmcp::model::{
        ClientCapabilities, ClientInfo, ClientRequest, CustomRequest, CustomResult, Implementation,
        ServerInfo, ServerResult,
    };
    use rmcp::{ServerHandler, ServiceExt};
    use serde_json::json;
    use tokio::sync::{Mutex, Notify};

    use super::*;

    const FIRST: &[u8] = b"streamed-first-chunk-";
    const SECOND: &[u8] = b"streamed-second-chunk";
    const SENTINEL: &[u8] = b"streamed-first-chunk-streamed-second-chunk";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct UploadRecord {
        size: u64,
        digest: String,
        chunks: usize,
        multipart_fields: BTreeMap<String, String>,
        credential: Option<String>,
    }

    struct TestState {
        upload: Mutex<Option<UploadRecord>>,
        first_chunk: Notify,
    }

    struct TlsServer {
        base_url: String,
        cert_der: Vec<u8>,
        state: Arc<TestState>,
        _directory: tempfile::TempDir,
    }

    struct AuthorizationServer {
        upload: AuthorizeUploadResult,
        download: AuthorizeDownloadResult,
        requests: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    }

    impl ServerHandler for AuthorizationServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::default()
        }

        async fn on_custom_request(
            &self,
            request: CustomRequest,
            _context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> Result<CustomResult, rmcp::ErrorData> {
            let params = request.params.unwrap_or(serde_json::Value::Null);
            self.requests
                .lock()
                .await
                .push((request.method.clone(), params));
            let value = match request.method.as_str() {
                "files/authorizeUpload" => serde_json::to_value(&self.upload),
                "files/authorizeDownload" => serde_json::to_value(&self.download),
                _ => {
                    return Err(rmcp::ErrorData::new(
                        rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                        request.method,
                        None,
                    ))
                }
            }
            .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))?;
            Ok(CustomResult::new(value))
        }
    }

    async fn raw_upload(
        State(state): State<Arc<TestState>>,
        headers: AxumHeaders,
        body: Body,
    ) -> StatusCode {
        let mut stream = body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut chunks = 0_usize;
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                return StatusCode::BAD_REQUEST;
            };
            chunks += 1;
            size += chunk.len() as u64;
            hasher.update(&chunk);
            if chunks == 1 {
                state.first_chunk.notify_one();
            }
        }
        *state.upload.lock().await = Some(UploadRecord {
            size,
            digest: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()),
            chunks,
            multipart_fields: BTreeMap::new(),
            credential: headers
                .get("x-transfer-credential")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
        StatusCode::NO_CONTENT
    }

    async fn multipart_upload(
        State(state): State<Arc<TestState>>,
        headers: AxumHeaders,
        mut multipart: Multipart,
    ) -> StatusCode {
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut chunks = 0_usize;
        let mut fields = BTreeMap::new();
        loop {
            let field = match multipart.next_field().await {
                Ok(Some(field)) => field,
                Ok(None) => break,
                Err(_) => return StatusCode::BAD_REQUEST,
            };
            let name = field.name().unwrap_or_default().to_owned();
            if name == "payload" {
                let mut field = field;
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            chunks += 1;
                            size += chunk.len() as u64;
                            hasher.update(&chunk);
                        }
                        Ok(None) => break,
                        Err(_) => return StatusCode::BAD_REQUEST,
                    }
                }
            } else {
                let value = match field.text().await {
                    Ok(value) => value,
                    Err(_) => return StatusCode::BAD_REQUEST,
                };
                fields.insert(name, value);
            }
        }
        *state.upload.lock().await = Some(UploadRecord {
            size,
            digest: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()),
            chunks,
            multipart_fields: fields,
            credential: headers
                .get("x-transfer-credential")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
        StatusCode::NO_CONTENT
    }

    async fn download() -> Response {
        let chunks = vec![
            Ok::<_, Infallible>(Bytes::from_static(FIRST)),
            Ok(Bytes::from_static(SECOND)),
        ];
        Response::new(Body::from_stream(stream::iter(chunks)))
    }

    async fn download_redirect() -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        response
            .headers_mut()
            .insert(LOCATION, AxumHeaderValue::from_static("/download"));
        response
    }

    async fn upload_redirect() -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
        response
            .headers_mut()
            .insert(LOCATION, AxumHeaderValue::from_static("/upload-put"));
        response
    }

    async fn spawn_https_server() -> TlsServer {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("self-signed certificate");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let tls = RustlsConfig::from_der(vec![cert_der.clone()], key_der)
            .await
            .expect("TLS configuration");
        let directory = tempfile::tempdir().expect("transfer directory");
        let state = Arc::new(TestState {
            upload: Mutex::new(None),
            first_chunk: Notify::new(),
        });
        let app = Router::new()
            .route("/upload-put", put(raw_upload))
            .route("/upload-post", post(raw_upload))
            .route("/upload-multipart", post(multipart_upload))
            .route("/upload-redirect", put(upload_redirect))
            .route("/download", get(download))
            .route("/download-redirect", get(download_redirect))
            .layer(DefaultBodyLimit::disable())
            .with_state(state.clone());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("listener address");
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .expect("TLS listener")
                .serve(app.into_make_service())
                .await
                .expect("serve reference transfer endpoint");
        });
        TlsServer {
            base_url: format!("https://127.0.0.1:{}", address.port()),
            cert_der,
            state,
            _directory: directory,
        }
    }

    fn client_trusting(cert_der: &[u8]) -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(cert_der).expect("certificate"))
            .build()
            .expect("reference client")
    }

    async fn wait_for_server(client: &reqwest::Client, base_url: &str) {
        for _ in 0..10 {
            if client
                .get(format!("{base_url}/download"))
                .send()
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("reference HTTPS server did not accept connections");
    }

    fn file_value_with_integrity() -> FileValue {
        FileValue {
            uri: "mcp-file://gateway/proof-file".to_owned(),
            name: Some("proof.bin".to_owned()),
            mime_type: Some("application/octet-stream".to_owned()),
            size: Some(SENTINEL.len() as u64),
            digest: Some(FileDigest {
                algorithm: "sha-256".to_owned(),
                value: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(Sha256::digest(SENTINEL)),
            }),
        }
    }

    fn descriptor(base_url: &str, method: TransferMethod, path: &str) -> FileTransferDescriptor {
        FileTransferDescriptor {
            transport: "https".to_owned(),
            method,
            url: format!("{base_url}{path}"),
            headers: BTreeMap::new(),
            multipart: None,
            // An old timestamp is accepted locally: the endpoint remains the
            // authority on descriptor lifetime and client clocks may differ.
            expires_at: Some("2000-01-01T00:00:00Z".to_owned()),
        }
    }

    async fn authorize<T: for<'de> Deserialize<'de>>(
        client: &rmcp::service::Peer<rmcp::RoleClient>,
        method: &'static str,
        params: serde_json::Value,
    ) -> T {
        let response = client
            .send_request(ClientRequest::CustomRequest(CustomRequest::new(
                method,
                Some(params),
            )))
            .await
            .unwrap();
        let ServerResult::CustomResult(result) = response else {
            panic!("unexpected response type");
        };
        serde_json::from_value(result.0).unwrap()
    }

    fn test_client_info() -> ClientInfo {
        ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("file-transfer-reference-host", env!("CARGO_PKG_VERSION")),
        )
    }

    #[tokio::test]
    async fn control_plane_carries_no_bytes_while_unknown_length_upload_streams() {
        let server = spawn_https_server().await;
        let transfer_client = client_trusting(&server.cert_der);
        wait_for_server(&transfer_client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(transfer_client, 5);

        let upload_result = AuthorizeUploadResult {
            file: FileValue {
                uri: "mcp-file://gateway/proof-file".to_owned(),
                name: None,
                mime_type: None,
                size: None,
                digest: None,
            },
            upload: descriptor(&server.base_url, TransferMethod::PUT, "/upload-put"),
            download: None,
        };
        let download_result = AuthorizeDownloadResult {
            file: file_value_with_integrity(),
            download: descriptor(&server.base_url, TransferMethod::GET, "/download-redirect"),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
        let authorization_server = AuthorizationServer {
            upload: upload_result,
            download: download_result,
            requests: requests.clone(),
        };
        let mcp_server = tokio::spawn(async move {
            authorization_server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let mcp_client = test_client_info().serve(client_transport).await.unwrap();

        let upload: AuthorizeUploadResult =
            authorize(mcp_client.peer(), "files/authorizeUpload", json!({})).await;
        let (mut writer, reader) = tokio::io::duplex(8);
        let upload_state = server.state.clone();
        let writer_task = tokio::spawn(async move {
            writer.write_all(FIRST).await.unwrap();
            upload_state.first_chunk.notified().await;
            writer.write_all(SECOND).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let uploaded = tokio::time::timeout(
            Duration::from_secs(5),
            host.upload_reader(&upload, reader, None, None),
        )
        .await
        .expect("streaming upload must make progress")
        .unwrap();
        writer_task.await.unwrap();
        assert_eq!(uploaded.size, SENTINEL.len() as u64);
        let received = server.state.upload.lock().await.clone().unwrap();
        assert_eq!(received.size, SENTINEL.len() as u64);
        assert_eq!(received.digest, uploaded.digest.value);
        assert!(received.chunks >= 2);

        let download: AuthorizeDownloadResult = authorize(
            mcp_client.peer(),
            "files/authorizeDownload",
            json!({"uri": "mcp-file://gateway/proof-file"}),
        )
        .await;
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("received.bin");
        let downloaded = host
            .download_to(
                &download,
                &destination,
                DownloadOptions {
                    overwrite_existing: false,
                    durability: FileDurability::Flush,
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(downloaded.size, SENTINEL.len() as u64);
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), SENTINEL);

        let model_visible = serde_json::to_string(&(&upload.file, &download.file)).unwrap();
        let control_plane =
            serde_json::to_string(&(requests.lock().await.clone(), &upload, &download)).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(SENTINEL);
        for serialized in [&model_visible, &control_plane] {
            assert!(!serialized
                .as_bytes()
                .windows(SENTINEL.len())
                .any(|window| window == SENTINEL));
            assert!(!serialized.contains(&encoded));
        }
        assert_eq!(requests.lock().await[0].1, json!({}));

        mcp_client.cancel().await.unwrap();
        mcp_server.await.unwrap();
    }

    #[tokio::test]
    async fn multipart_post_streams_file_and_additional_fields() {
        let server = spawn_https_server().await;
        let client = client_trusting(&server.cert_der);
        wait_for_server(&client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(client, 5);
        let mut fields = BTreeMap::new();
        fields.insert("purpose".to_owned(), "analysis".to_owned());
        let authorized = AuthorizeUploadResult {
            file: file_value_with_integrity(),
            upload: FileTransferDescriptor {
                multipart: Some(MultipartUpload {
                    file_field: "payload".to_owned(),
                    fields,
                }),
                ..descriptor(&server.base_url, TransferMethod::POST, "/upload-multipart")
            },
            download: None,
        };

        let measurements = host
            .upload_reader(&authorized, SENTINEL, Some("proof.bin".to_owned()), None)
            .await
            .unwrap();

        assert_eq!(measurements.size, SENTINEL.len() as u64);
        let received = server.state.upload.lock().await.clone().unwrap();
        assert_eq!(received.size, SENTINEL.len() as u64);
        assert_eq!(received.digest, measurements.digest.value);
        assert_eq!(received.multipart_fields["purpose"], "analysis");
    }

    struct TestCredential(String);

    impl TransferCredentialProvider for TestCredential {
        fn apply(&self, headers: &mut HeaderMap) -> Result<()> {
            headers.insert(
                HeaderName::from_static("x-transfer-credential"),
                HeaderValue::from_str(&self.0)?,
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn credential_provider_is_separate_from_serializable_descriptor() {
        let server = spawn_https_server().await;
        let client = client_trusting(&server.cert_der);
        wait_for_server(&client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(client, 5);
        let authorized = AuthorizeUploadResult {
            file: file_value_with_integrity(),
            upload: descriptor(&server.base_url, TransferMethod::POST, "/upload-post"),
            download: None,
        };
        let credential = TestCredential("narrow-short-lived-value".to_owned());

        host.upload_reader(&authorized, SENTINEL, None, Some(&credential))
            .await
            .unwrap();

        let serialized = serde_json::to_string(&authorized).unwrap();
        assert!(!serialized.contains("narrow-short-lived-value"));
        assert_eq!(
            server
                .state
                .upload
                .lock()
                .await
                .as_ref()
                .unwrap()
                .credential
                .as_deref(),
            Some("narrow-short-lived-value")
        );
    }

    #[tokio::test]
    async fn upload_redirect_is_not_replayed_or_buffered() {
        let server = spawn_https_server().await;
        let client = client_trusting(&server.cert_der);
        wait_for_server(&client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(client, 5);
        let authorized = AuthorizeUploadResult {
            file: file_value_with_integrity(),
            upload: descriptor(&server.base_url, TransferMethod::PUT, "/upload-redirect"),
            download: None,
        };

        let error = host
            .upload_reader(&authorized, SENTINEL, None, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("obtain a fresh"));
        assert!(server.state.upload.lock().await.is_none());
    }

    #[tokio::test]
    async fn digest_mismatch_never_publishes_download() {
        let server = spawn_https_server().await;
        let client = client_trusting(&server.cert_der);
        wait_for_server(&client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(client, 5);
        let mut file = file_value_with_integrity();
        file.digest.as_mut().unwrap().value =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"different"));
        let authorized = AuthorizeDownloadResult {
            file,
            download: descriptor(&server.base_url, TransferMethod::GET, "/download"),
        };
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("must-not-exist.bin");

        let error = host
            .download_to(
                &authorized,
                &destination,
                DownloadOptions {
                    overwrite_existing: false,
                    durability: FileDurability::SyncData,
                },
                None,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("digest mismatch"));
        assert!(!destination.exists());
        assert_eq!(directory.path().read_dir().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn verified_download_does_not_overwrite_without_explicit_permission() {
        let server = spawn_https_server().await;
        let client = client_trusting(&server.cert_der);
        wait_for_server(&client, &server.base_url).await;
        let host = ReferenceFileHost::with_test_client(client, 5);
        let authorized = AuthorizeDownloadResult {
            file: file_value_with_integrity(),
            download: descriptor(&server.base_url, TransferMethod::GET, "/download"),
        };
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("existing.bin");
        tokio::fs::write(&destination, b"existing").await.unwrap();

        host.download_to(
            &authorized,
            &destination,
            DownloadOptions {
                overwrite_existing: false,
                durability: FileDurability::Flush,
            },
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(tokio::fs::read(destination).await.unwrap(), b"existing");
    }

    #[test]
    fn independent_wire_shapes_match_the_draft_contract() {
        let capabilities = json!({
            "upload": true,
            "transports": ["https"]
        });
        assert!(capabilities.get("download").is_none());

        let result = AuthorizeUploadResult {
            file: FileValue {
                uri: "mcp-file://gateway/new".to_owned(),
                name: None,
                mime_type: None,
                size: None,
                digest: None,
            },
            upload: FileTransferDescriptor {
                transport: "https".to_owned(),
                method: TransferMethod::POST,
                url: "https://gateway.example/upload".to_owned(),
                headers: BTreeMap::new(),
                multipart: Some(MultipartUpload {
                    file_field: "file".to_owned(),
                    fields: BTreeMap::new(),
                }),
                expires_at: None,
            },
            download: None,
        };
        let serialized = serde_json::to_value(result).unwrap();
        assert_eq!(serialized["upload"]["method"], "POST");
        assert_eq!(serialized["upload"]["multipart"]["fileField"], "file");
        assert!(serialized["file"].get("size").is_none());
    }
}
