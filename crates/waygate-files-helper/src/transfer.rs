//! Redeeming a grant and moving the bytes.
//!
//! Two signed requests, in this order: trade the opaque handle for a short-lived
//! credential, then carry the bytes under it. Keeping them separate means a
//! rejected grant costs nothing — it is refused before the file is opened —
//! and it keeps both legs on shapes an off-the-shelf client library already
//! understands.

use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use reqwest::blocking::{Body, Client, Response};
use reqwest::StatusCode;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use url::{Origin, Url};

use crate::key::HelperKey;
use crate::wire::{
    self, CredentialExchange, FileValue, PrepareDownload, PrepareUpload, TransferDescriptor,
};

const CREDENTIAL_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Requests set their own deadlines so credential exchange stays short while
/// a bounded large-file transfer is not constrained by the library default.
fn client() -> Result<Client> {
    Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(None)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client")
}

pub fn upload(
    prepared: PrepareUpload,
    source: &Path,
    origin: &Origin,
    key: &HelperKey,
) -> Result<String> {
    let exchange_url = wire::check_address(
        &prepared.credential_exchange.url,
        origin,
        "credential_exchange.url",
    )?;
    let upload_url = wire::check_address(&prepared.upload.url, origin, "upload.url")?;

    let client = client()?;
    let credential = redeem(
        &client,
        &prepared.credential_exchange,
        &exchange_url,
        &prepared.grant_handle,
        key,
    )?;

    // Opened only once the grant is known good, so an expired or already-spent
    // handle costs a small refused request rather than a started transfer.
    let file = std::fs::File::open(source).with_context(|| format!("open {}", source.display()))?;
    let length = file
        .metadata()
        .with_context(|| format!("stat {}", source.display()))?
        .len();

    let descriptor = &prepared.upload;
    let mut request = client
        .request(method(&descriptor.method)?, upload_url.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("{} {credential}", descriptor.authorization_scheme),
        )
        .header(
            descriptor.proof_header.as_str(),
            key.proof(
                &descriptor.method,
                upload_url.as_str(),
                Some(&credential),
                OffsetDateTime::now_utc(),
            )?,
        );
    if let Some(content_type) = &descriptor.content_type {
        request = request.header(reqwest::header::CONTENT_TYPE, content_type.as_str());
    }

    let response = request
        .body(Body::sized(file, length))
        .timeout(TRANSFER_TIMEOUT)
        .send()
        .map_err(|error| upload_send_error(error, &prepared.file.uri))?;
    check_status(response, "upload", Some(&prepared.file.uri))?;

    Ok(prepared.file.uri)
}

fn upload_send_error(error: reqwest::Error, file_uri: &str) -> anyhow::Error {
    let failed_before_delivery = error.is_builder() || error.is_connect();
    let error = error.without_url();
    if failed_before_delivery {
        anyhow::Error::new(error)
            .context("upload request failed before the gateway could receive file bytes")
    } else {
        anyhow::Error::new(error).context(format!(
            "upload outcome is unknown for {file_uri}; call `gateway-files.upload_status` with \
             this URI before preparing another upload"
        ))
    }
}

pub fn download(
    prepared: PrepareDownload,
    destination: &Path,
    origin: &Origin,
    key: &HelperKey,
) -> Result<String> {
    let exchange_url = wire::check_address(
        &prepared.credential_exchange.url,
        origin,
        "credential_exchange.url",
    )?;
    let download_url = wire::check_address(&prepared.download.url, origin, "download.url")?;

    let client = client()?;
    let credential = redeem(
        &client,
        &prepared.credential_exchange,
        &exchange_url,
        &prepared.grant_handle,
        key,
    )?;

    let descriptor: &TransferDescriptor = &prepared.download;
    let response = client
        .request(method(&descriptor.method)?, download_url.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("{} {credential}", descriptor.authorization_scheme),
        )
        .header(
            descriptor.proof_header.as_str(),
            key.proof(
                &descriptor.method,
                download_url.as_str(),
                Some(&credential),
                OffsetDateTime::now_utc(),
            )?,
        )
        .timeout(TRANSFER_TIMEOUT)
        .send()
        .context("request the file from the gateway")?;
    let mut response = check_status(response, "download", None)?;

    // Stage beside the destination so a failed or mismatched transfer never
    // leaves a partial file where a caller would read it as complete.
    let staged = staging_path(destination);
    let outcome = (|| -> Result<()> {
        let mut file = std::fs::File::create(&staged)
            .with_context(|| format!("create {}", staged.display()))?;
        let measured = copy_measured(&mut response, &mut file, prepared.file.size)?;
        file.sync_all().context("flush the downloaded file")?;
        verify(&prepared.file, &measured)
    })();
    if let Err(e) = outcome {
        return Err(discard_staged(e, &staged));
    }

    publish(&staged, destination)?;

    Ok(prepared.file.uri)
}

/// Trade the opaque handle for a short-lived credential bound to our key.
fn redeem(
    client: &Client,
    exchange: &CredentialExchange,
    url: &Url,
    handle: &str,
    key: &HelperKey,
) -> Result<String> {
    let proof = key.proof(
        &exchange.method,
        url.as_str(),
        None,
        OffsetDateTime::now_utc(),
    )?;
    let body = serde_json::json!({ exchange.grant_handle_field.as_str(): handle });

    let response = client
        .request(method(&exchange.method)?, url.clone())
        .header(exchange.proof_header.as_str(), proof)
        .json(&body)
        .timeout(CREDENTIAL_EXCHANGE_TIMEOUT)
        .send()
        .context("exchange the grant handle for a transfer credential")?;
    let response = check_status(response, "credential exchange", None)?;

    let payload: serde_json::Value = response
        .json()
        .context("credential exchange response is not JSON")?;
    payload
        .get(&exchange.access_token_field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "credential exchange response has no `{}` field",
                exchange.access_token_field
            )
        })
}

/// Move a verified download onto its destination, owning the staged file
/// either way.
///
/// A failed move still leaves that file behind, and it holds a complete copy of
/// the payload under a name the caller was never told about. Keeping it would
/// hide the payload beside the destination and let every retry add another.
fn publish(staged: &Path, destination: &Path) -> Result<()> {
    if let Err(e) = std::fs::rename(staged, destination) {
        let move_failed = anyhow::Error::new(e).context(format!(
            "move {} into place at {}",
            staged.display(),
            destination.display()
        ));
        return Err(discard_staged(move_failed, staged));
    }
    Ok(())
}

/// Drop the staged file, folding a failed removal into `error` rather than
/// replacing it.
///
/// The transfer failure is what the caller has to act on, so cleanup must not
/// displace it. But a silently swallowed removal leaves transferred bytes on
/// disk with nothing said about them, so when cleanup fails the path is named
/// and the original failure is kept as the cause.
fn discard_staged(error: anyhow::Error, staged: &Path) -> anyhow::Error {
    match std::fs::remove_file(staged) {
        Ok(()) => error,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error,
        Err(e) => error.context(format!(
            "the staged file {} still holds the transferred bytes and could not be removed ({e}); \
             delete it once the cause is resolved",
            staged.display()
        )),
    }
}

/// What a completed download actually contained.
#[derive(Debug)]
struct Measured {
    bytes: u64,
    sha256: [u8; 32],
}

/// Copy while counting and hashing, so the result can be checked against what
/// the gateway said it was sending without a second pass over the file.
/// When the gateway declared a size, `limit` stops the copy as soon as the
/// response exceeds it. Waiting for the end to compare totals would mean
/// writing an unbounded response to disk before rejecting it.
fn copy_measured(
    reader: &mut impl Read,
    writer: &mut impl std::io::Write,
    limit: Option<u64>,
) -> Result<Measured> {
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = reader.read(&mut buffer).context("read the response body")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes += read as u64;
        if let Some(limit) = limit {
            if bytes > limit {
                bail!("the response is longer than the {limit} bytes the gateway declared");
            }
        }
        writer
            .write_all(&buffer[..read])
            .context("write the downloaded file")?;
    }

    Ok(Measured {
        bytes,
        sha256: hasher.finalize().into(),
    })
}

/// Refuse a file that is not what was described.
///
/// Silence here would hand the caller a truncated or altered file that looks
/// complete, so an unverifiable digest is treated as a failure rather than
/// waved through as "checked".
fn verify(declared: &FileValue, measured: &Measured) -> Result<()> {
    if let Some(size) = declared.size {
        if size != measured.bytes {
            bail!(
                "downloaded {} bytes but the gateway declared {size}",
                measured.bytes
            );
        }
    }

    if let Some(digest) = &declared.digest {
        if !digest.algorithm.eq_ignore_ascii_case("sha-256") {
            bail!(
                "cannot verify a `{}` digest; this helper implements sha-256",
                digest.algorithm
            );
        }
        let actual = URL_SAFE_NO_PAD.encode(measured.sha256);
        if actual != digest.value {
            bail!("downloaded file does not match the digest the gateway declared");
        }
    }

    Ok(())
}

fn method(raw: &str) -> Result<reqwest::Method> {
    raw.parse::<reqwest::Method>()
        .with_context(|| format!("`{raw}` is not an HTTP method"))
}

/// Turn a refusal into something a caller can act on.
///
/// The transfer endpoints answer with a bounded machine-readable `error` code;
/// surfacing it beats printing a status number on its own.
fn check_status(
    response: Response,
    stage: &str,
    ambiguous_upload_uri: Option<&str>,
) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let detail = response
        .json::<serde_json::Value>()
        .ok()
        .and_then(|body| {
            body.get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "no machine-readable reason supplied".to_owned());

    if let Some(uri) = ambiguous_upload_uri {
        if upload_response_requires_reconciliation(status, &detail) {
            return Err(unknown_upload_outcome(uri));
        }
    }

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        bail!(
            "{stage} refused ({status}): {detail}. The grant may have expired, already been used, \
             or been issued for a different key than this machine holds."
        );
    }
    bail!("{stage} failed ({status}): {detail}")
}

fn upload_response_requires_reconciliation(status: StatusCode, detail: &str) -> bool {
    detail == "completion_unknown"
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
}

fn unknown_upload_outcome(uri: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "upload outcome is unknown for {uri}; call `gateway-files.upload_status` with this URI \
         before preparing another upload"
    )
}

fn staging_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.partial", uuid::Uuid::now_v7()));
    destination.with_file_name(name)
}

/// The prepared result is a small JSON object: a handle, two URLs, some field
/// names and file metadata. A megabyte is far more than that shape ever needs
/// and small enough that a runaway or non-terminating pipe cannot grow this
/// process without bound.
const MAX_PREPARED_RESULT_BYTES: u64 = 1024 * 1024;

/// Read the prepared tool result from `reader`, refusing an implausible one.
pub fn read_to_end(reader: impl Read) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut bounded = reader.take(MAX_PREPARED_RESULT_BYTES + 1);
    bounded.read_to_end(&mut buffer).context("read stdin")?;
    if buffer.len() as u64 > MAX_PREPARED_RESULT_BYTES {
        bail!(
            "the input on stdin exceeds {MAX_PREPARED_RESULT_BYTES} bytes; \
             pipe in the prepare result, not the file"
        );
    }
    Ok(buffer)
}

/// Read the first complete JSON value without waiting for the writer to close
/// stdin. JSON values are self-delimiting, so this accepts both compact and
/// formatted prepare results without requiring launcher-specific EOF handling.
pub fn read_first_json_value_with_timeout<R>(reader: R, timeout: Duration) -> Result<Vec<u8>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(read_first_json_value(reader));
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            bail!("timed out waiting for a complete JSON prepare result on stdin")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            bail!("the stdin reader stopped before returning a prepare result")
        }
    }
}

fn read_first_json_value(reader: impl Read) -> Result<Vec<u8>> {
    let mut bounded = reader.take(MAX_PREPARED_RESULT_BYTES + 1);
    let parsed = {
        let mut values =
            serde_json::Deserializer::from_reader(&mut bounded).into_iter::<serde_json::Value>();
        match values.next() {
            Some(result) => result.context("input is not valid JSON"),
            None => bail!("stdin did not contain a prepare result"),
        }
    };
    let consumed = MAX_PREPARED_RESULT_BYTES + 1 - bounded.limit();
    if consumed > MAX_PREPARED_RESULT_BYTES {
        bail!(
            "the input on stdin exceeds {MAX_PREPARED_RESULT_BYTES} bytes; \
             pipe in the prepare result, not the file"
        );
    }
    serde_json::to_vec(&parsed?).context("serialize the prepared JSON value")
}

/// Read one compact JSON value terminated by a newline, without requiring the
/// writer to close stdin. A deadline prevents a partial frame from leaving a
/// detached helper waiting forever.
pub fn read_json_line_with_timeout<R>(reader: R, timeout: Duration) -> Result<Vec<u8>>
where
    R: BufRead + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(read_json_line(reader));
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => bail!(
            "timed out waiting for a newline-delimited prepare result; send one compact JSON \
             value followed by a newline"
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            bail!("the stdin reader stopped before returning a prepare result")
        }
    }
}

fn read_json_line(mut reader: impl BufRead) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut bounded = (&mut reader).take(MAX_PREPARED_RESULT_BYTES + 2);
    bounded
        .read_until(b'\n', &mut buffer)
        .context("read newline-delimited stdin")?;
    if buffer.len() as u64 > MAX_PREPARED_RESULT_BYTES + 1 {
        bail!(
            "the input on stdin exceeds {MAX_PREPARED_RESULT_BYTES} bytes; \
             pipe in the prepare result, not the file"
        );
    }
    if buffer.last() != Some(&b'\n') {
        bail!(
            "newline-delimited input ended before its delimiter; send one compact JSON value \
             followed by a newline"
        );
    }
    buffer.pop();
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    if buffer.is_empty() {
        bail!("newline-delimited input did not contain a prepare result");
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;

    #[test]
    fn staging_path_sits_beside_the_destination() {
        let destination = Path::new("/tmp/downloads/report.pdf");
        let staged = staging_path(destination);

        assert_eq!(staged.parent(), destination.parent());
        assert_ne!(staged, destination);
        assert!(
            staged
                .file_name()
                .and_then(|n| n.to_str())
                .expect("name")
                .ends_with(".partial"),
            "a partial download should be recognisable as one"
        );
    }

    #[test]
    fn publishing_moves_the_staged_file_onto_the_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged");
        let destination = dir.path().join("report.pdf");
        std::fs::write(&staged, b"contents").expect("stage");

        publish(&staged, &destination).expect("publish");

        assert_eq!(std::fs::read(&destination).expect("read"), b"contents");
        assert!(!staged.exists());
    }

    #[test]
    fn a_failed_publish_does_not_leave_the_payload_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"contents").expect("stage");
        // A non-empty directory cannot be replaced by a file, which is the
        // portable way to make the move fail with the staged file intact.
        let destination = dir.path().join("occupied");
        std::fs::create_dir(&destination).expect("dir");
        std::fs::write(destination.join("resident"), b"x").expect("resident");

        publish(&staged, &destination).expect_err("a blocked move must not report success");

        assert!(
            !staged.exists(),
            "a complete payload must not survive beside the destination"
        );
    }

    #[test]
    fn a_removable_staged_file_leaves_the_original_error_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"contents").expect("stage");

        let error = discard_staged(anyhow::anyhow!("digest mismatch"), &staged);

        assert!(!staged.exists());
        assert_eq!(error.to_string(), "digest mismatch");
    }

    #[test]
    fn an_unremovable_staged_file_is_named_without_hiding_the_cause() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A non-empty directory cannot be unlinked by `remove_file`, which
        // forces the failure regardless of who the test runs as.
        let staged = dir.path().join("staged");
        std::fs::create_dir(&staged).expect("dir");
        std::fs::write(staged.join("resident"), b"x").expect("resident");

        let error = discard_staged(anyhow::anyhow!("digest mismatch"), &staged);

        assert!(
            error
                .to_string()
                .contains("still holds the transferred bytes"),
            "abandoned bytes must be reported: {error}"
        );
        assert_eq!(
            error.root_cause().to_string(),
            "digest mismatch",
            "cleanup trouble must not displace what the caller has to act on"
        );
    }

    #[test]
    fn staging_paths_do_not_collide() {
        let destination = Path::new("report.pdf");
        assert_ne!(staging_path(destination), staging_path(destination));
    }

    #[test]
    fn rejects_a_nonsense_method() {
        method("not a method").expect_err("descriptor methods are validated before dialling");
    }

    #[test]
    fn connection_refusal_is_a_definite_pre_delivery_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind refusal address");
        let address = listener.local_addr().expect("refusal address");
        drop(listener);
        let error = Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .put(format!("http://{address}/upload"))
            .body("payload")
            .timeout(Duration::from_secs(1))
            .send()
            .expect_err("closed listener must refuse the connection");
        assert!(error.is_connect());

        let error = upload_send_error(error, "mcp-file://gateway/file-id");
        assert!(error
            .to_string()
            .contains("before the gateway could receive file bytes"));
        assert!(!error.to_string().contains("outcome is unknown"));
    }

    #[test]
    fn timeout_after_connect_is_an_unknown_upload_outcome() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind timeout address");
        let address = listener.local_addr().expect("timeout address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("read upload request");
            std::thread::sleep(Duration::from_millis(200));
        });
        let error = Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .put(format!("http://{address}/upload"))
            .body("payload")
            .timeout(Duration::from_millis(50))
            .send()
            .expect_err("server withholding a response must time out");
        assert!(error.is_timeout());
        assert!(!error.is_connect());

        let error = upload_send_error(error, "mcp-file://gateway/file-id");
        assert!(error.to_string().contains("upload outcome is unknown"));
        server.join().expect("timeout server");
    }

    #[test]
    fn intermediary_upload_failures_preserve_status_recovery() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(upload_response_requires_reconciliation(
                status,
                "proxy error"
            ));
        }
        assert!(!upload_response_requires_reconciliation(
            StatusCode::BAD_REQUEST,
            "invalid_upload"
        ));
        let uri = "mcp-file://gateway/file-id";
        let error = unknown_upload_outcome(uri);
        assert!(error.to_string().contains(uri));
        assert!(error.to_string().contains("gateway-files.upload_status"));
    }

    #[test]
    fn intermediary_upload_response_keeps_the_file_uri_actionable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind response address");
        let address = listener.local_addr().expect("response address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("read upload request");
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: 23\r\nConnection: close\r\n\r\n{\"error\":\"proxy_error\"}",
                )
                .expect("write proxy response");
        });
        let response = Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .put(format!("http://{address}/upload"))
            .body("payload")
            .send()
            .expect("receive proxy response");
        let uri = "mcp-file://gateway/file-id";

        let error = check_status(response, "upload", Some(uri))
            .expect_err("an intermediary failure cannot prove whether upload completed");

        assert!(error.to_string().contains(uri));
        assert!(error.to_string().contains("gateway-files.upload_status"));
        server.join().expect("proxy response server");
    }

    fn measured(body: &[u8]) -> Measured {
        Measured {
            bytes: body.len() as u64,
            sha256: Sha256::digest(body).into(),
        }
    }

    fn declared(size: Option<u64>, digest: Option<(&str, &str)>) -> FileValue {
        FileValue {
            uri: "mcp-file://gateway/abc".to_owned(),
            size,
            digest: digest.map(|(algorithm, value)| crate::wire::Digest {
                algorithm: algorithm.to_owned(),
                value: value.to_owned(),
            }),
        }
    }

    #[test]
    fn copy_measured_reports_what_it_wrote() {
        let body = b"the quick brown fox";
        let mut sink = Vec::new();

        let result = copy_measured(&mut body.as_slice(), &mut sink, None).expect("copy");

        assert_eq!(sink, body);
        assert_eq!(result.bytes, body.len() as u64);
        assert_eq!(result.sha256, <[u8; 32]>::from(Sha256::digest(body)));
    }

    /// Comparing totals only at the end would mean an oversized response is
    /// fully written to disk before it is rejected. The declared size is known
    /// up front, so the copy stops at it.
    #[test]
    fn a_response_longer_than_declared_stops_before_it_is_all_written() {
        let body = vec![b'x'; 64 * 1024 * 3];
        let mut sink = Vec::new();

        let error = copy_measured(&mut body.as_slice(), &mut sink, Some(1024))
            .expect_err("an over-long response must not be written out in full");

        assert!(
            error.to_string().contains("1024"),
            "the refusal should name the declared size: {error}"
        );
        assert!(
            (sink.len() as u64) < body.len() as u64,
            "the copy should have stopped early, wrote {} of {}",
            sink.len(),
            body.len()
        );
    }

    #[test]
    fn a_response_within_the_declared_size_is_copied_whole() {
        let body = b"exactly right";
        let mut sink = Vec::new();

        let measured = copy_measured(&mut body.as_slice(), &mut sink, Some(body.len() as u64))
            .expect("a response matching its declaration is accepted");

        assert_eq!(sink, body);
        assert_eq!(measured.bytes, body.len() as u64);
    }

    #[test]
    fn stdin_larger_than_a_prepared_result_is_refused() {
        let oversized = vec![b'{'; (MAX_PREPARED_RESULT_BYTES + 1) as usize];

        let error = read_to_end(oversized.as_slice())
            .expect_err("an implausible stdin payload must not be buffered whole");

        assert!(
            error.to_string().contains("prepare result"),
            "the refusal should say what was expected: {error}"
        );
    }

    #[test]
    fn an_ordinary_prepared_result_is_read_intact() {
        let body = b"{\"grant_handle\":\"h\"}";
        assert_eq!(read_to_end(body.as_slice()).expect("read"), body);
    }

    #[test]
    fn automatic_framing_returns_when_a_formatted_value_is_complete() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let client =
            std::net::TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .write_all(b"{\n  \"grant_handle\": \"h\"\n}")
                .expect("write value");
            release_receiver.recv().expect("release writer");
        });

        let result = read_first_json_value_with_timeout(client, Duration::from_secs(1))
            .expect("a complete JSON value must not need EOF");
        assert_eq!(result, br#"{"grant_handle":"h"}"#);
        release_sender.send(()).expect("release");
        writer.join().expect("writer");
    }

    #[test]
    fn automatic_framing_is_bounded() {
        let oversized = serde_json::json!({
            "padding": "x".repeat(MAX_PREPARED_RESULT_BYTES as usize)
        })
        .to_string();

        let error = read_first_json_value(oversized.as_bytes())
            .expect_err("an oversized JSON value must be refused");
        assert!(error.to_string().contains("prepare result"));
    }

    #[test]
    fn newline_framing_returns_without_waiting_for_the_writer_to_close() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let client =
            std::net::TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .write_all(b"{\"grant_handle\":\"h\"}\n")
                .expect("write frame");
            release_receiver.recv().expect("release writer");
        });

        let result =
            read_json_line_with_timeout(std::io::BufReader::new(client), Duration::from_secs(1))
                .expect("a complete frame must not need EOF");
        assert_eq!(result, b"{\"grant_handle\":\"h\"}");
        release_sender.send(()).expect("release");
        writer.join().expect("writer");
    }

    #[test]
    fn newline_framing_accepts_crlf() {
        assert_eq!(
            read_json_line(std::io::Cursor::new(b"{}\r\n")).expect("frame"),
            b"{}"
        );
    }

    #[test]
    fn newline_framing_requires_the_delimiter() {
        let error =
            read_json_line(std::io::Cursor::new(b"{}")).expect_err("EOF is not a JSONL delimiter");
        assert!(error.to_string().contains("before its delimiter"));
    }

    #[test]
    fn newline_framing_is_bounded() {
        let mut oversized = vec![b'{'; (MAX_PREPARED_RESULT_BYTES + 1) as usize];
        oversized.push(b'\n');

        let error = read_json_line(std::io::Cursor::new(oversized))
            .expect_err("an oversized frame must be refused");
        assert!(error.to_string().contains("prepare result"));
    }

    #[test]
    fn accepts_a_file_matching_its_declaration() {
        let body = b"contents";
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(body));

        verify(
            &declared(Some(body.len() as u64), Some(("sha-256", &digest))),
            &measured(body),
        )
        .expect("a faithful download is accepted");
    }

    #[test]
    fn refuses_a_truncated_file() {
        let error = verify(&declared(Some(4096), None), &measured(b"short"))
            .expect_err("a short read must not be published");
        assert!(
            error.to_string().contains("4096"),
            "the refusal should say what was expected: {error}"
        );
    }

    #[test]
    fn refuses_a_file_whose_digest_disagrees() {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(b"what was promised"));

        verify(
            &declared(None, Some(("sha-256", &digest))),
            &measured(b"what actually arrived"),
        )
        .expect_err("altered contents must not be published");
    }

    #[test]
    fn refuses_a_digest_it_cannot_check() {
        let error = verify(
            &declared(None, Some(("sha-512", "unused"))),
            &measured(b"x"),
        )
        .expect_err("an unverifiable digest is not a passed check");
        assert!(
            error.to_string().contains("sha-512"),
            "the refusal should name the algorithm it could not handle: {error}"
        );
    }

    #[test]
    fn accepts_a_file_with_nothing_declared() {
        verify(&declared(None, None), &measured(b"anything"))
            .expect("the gateway may authorize before it knows size or digest");
    }
}
