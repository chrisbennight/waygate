//! Legacy two-endpoint MCP SSE client transport.
//!
//! Crawl4AI and any MCP server still using the pre-streamable-HTTP transport
//! speak this protocol:
//!
//! 1. The client opens a long-lived `GET /sse-url` with
//!    `Accept: text/event-stream`.
//! 2. The first event the server emits is `event: endpoint` with the
//!    session-bound POST URL in `data:` (relative or absolute against the SSE
//!    URL). All subsequent server-to-client traffic is `event: message` with
//!    a JSON-RPC payload.
//! 3. The client POSTs JSON-RPC requests to the messages URL with
//!    `Content-Type: application/json`. The server replies `202 Accepted`
//!    with no body and delivers the real JSON-RPC response back over the
//!    open SSE stream, correlated by `id`.
//!
//! rmcp ships only the streamable-HTTP client transport, so this module
//! adapts the legacy protocol to a `(Sink<ClientJsonRpcMessage>,
//! Stream<ServerJsonRpcMessage>)` pair that rmcp's `IntoTransport` accepts
//! for `RoleClient` (see `rmcp::transport::sink_stream`).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use futures::Sink;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use sse_stream::{Sse, SseStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::{CancellationToken, PollSendError, PollSender};
use url::Url;

use crate::identity_client::IdentityAugmenter;

/// Buffer size for both inbound and outbound JSON-RPC channels. rmcp pumps
/// messages serially per peer so a small fixed buffer is fine; tune up only
/// if a real upstream starts blocking on backpressure.
const CHANNEL_BUFFER: usize = 64;

/// `(Sink, Stream)` pair handed to `info.serve(...)` via `IntoTransport`.
pub type SseClientTransport = (SseClientSink, ReceiverStream<ServerJsonRpcMessage>);

pub(crate) struct ConnectedSse {
    pub(crate) transport: SseClientTransport,
    pub(crate) cleartext_control_plane: bool,
}

/// Outbound half of the legacy SSE transport. Dropping or closing the sink
/// cancels the shared transport token immediately, including while the writer
/// is generating headers or waiting for a POST response.
#[derive(Debug)]
pub struct SseClientSink {
    inner: PollSender<ClientJsonRpcMessage>,
    cancel: CancellationToken,
}

impl SseClientSink {
    fn new(inner: PollSender<ClientJsonRpcMessage>, cancel: CancellationToken) -> Self {
        Self { inner, cancel }
    }
}

impl Drop for SseClientSink {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Sink<ClientJsonRpcMessage> for SseClientSink {
    type Error = PollSendError<ClientJsonRpcMessage>;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ClientJsonRpcMessage) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.cancel.cancel();
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SseConnectError {
    #[error("invalid sse url: {0}")]
    Url(#[from] url::ParseError),
    #[error("http transport: {0}")]
    Http(#[from] reqwest::Error),
    #[error("upstream returned status {0}")]
    Status(http::StatusCode),
    #[error("missing endpoint event before timeout ({0:?})")]
    EndpointTimeout(Duration),
    #[error("first sse event was `{got}`, expected `endpoint`")]
    UnexpectedFirstEvent { got: String },
    #[error("endpoint event missing data line")]
    EndpointMissingData,
    #[error("sse stream error: {0}")]
    Sse(#[from] sse_stream::Error),
    #[error("sse stream ended before endpoint event")]
    StreamEndedEarly,
}

/// Open an SSE-transport connection to `base_url`.
///
/// Returns once the endpoint handshake has completed, so the caller can pass
/// the resulting `(Sink, Stream)` straight to `info.serve(...)` without
/// risking a `serve()` that hangs on initialize. Reader and writer tasks run
/// in the background and shut down automatically when either side of the
/// channel pair is dropped.
///
/// `augmenter` is consulted on every POST (to keep per-caller identity
/// headers live across the SSE session) and once on the initial GET. The
/// pool stamps the initial GET with its catalog-probe identity (group-less by
/// default, optionally carrying manifest-bounded catalog groups); later caller
/// dispatches replace that bounded discovery context with the authenticated
/// principal.
///
/// `static_bearer` (from a manifest's `auth.bearer_env`) is stamped as
/// `Authorization: Bearer <token>` on the initial GET *and* every message
/// POST — the upstream's auth gate (e.g. crawl4ai 0.9.0) rejects any
/// unauthenticated path, so a GET-only bearer would 401 on the first call.
pub async fn connect(
    base_url: &str,
    http: reqwest::Client,
    augmenter: Option<IdentityAugmenter>,
    static_bearer: Option<String>,
    endpoint_timeout: Duration,
    write_timeout: Duration,
) -> Result<SseClientTransport, SseConnectError> {
    Ok(connect_with_control_plane(
        base_url,
        http,
        augmenter,
        static_bearer,
        endpoint_timeout,
        write_timeout,
    )
    .await?
    .transport)
}

pub(crate) async fn connect_with_control_plane(
    base_url: &str,
    http: reqwest::Client,
    augmenter: Option<IdentityAugmenter>,
    static_bearer: Option<String>,
    endpoint_timeout: Duration,
    write_timeout: Duration,
) -> Result<ConnectedSse, SseConnectError> {
    let base = Url::parse(base_url)?;

    let mut req = http.get(base.clone()).header(ACCEPT, "text/event-stream");
    // Static per-upstream bearer (`auth.bearer_env`) on the SSE GET. The
    // augmenter below adds per-caller identity (`X-MCP-Identity`), a distinct
    // header — `validate_manifest_invariants` makes `auth.bearer_env` mutually
    // exclusive with the augmenter's Authorization-writing variants
    // (`exchange` / `tier_c_peer`), so the two never collide on `Authorization`.
    if let Some(token) = static_bearer.as_ref() {
        req = req.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(aug) = augmenter.as_ref() {
        for (k, v) in aug.headers().await {
            req = req.header(k, v);
        }
    }
    // One deadline owns the complete handshake: the initial GET, response
    // headers, and first non-ping endpoint event. A peer that accepts TCP but
    // never returns headers must not escape the endpoint-event bound.
    let (sse, endpoint_event) = tokio::time::timeout(endpoint_timeout, async {
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(SseConnectError::Status(resp.status()));
        }

        // Box the SSE stream early so the background reader has a single
        // nameable type; the inner reqwest body type is `impl Stream`.
        let mut sse: BoxStream<'static, Result<Sse, sse_stream::Error>> =
            SseStream::from_bytes_stream(resp.bytes_stream()).boxed();
        loop {
            match sse.next().await {
                // Skip control frames that carry only SSE id/retry metadata;
                // they do not replace the MCP endpoint event.
                Some(Ok(event)) if event.event.is_none() && event.data.is_none() => continue,
                Some(Ok(event)) => return Ok::<_, SseConnectError>((sse, event)),
                Some(Err(e)) => return Err(e.into()),
                None => return Err(SseConnectError::StreamEndedEarly),
            }
        }
    })
    .await
    .map_err(|_| SseConnectError::EndpointTimeout(endpoint_timeout))??;

    if endpoint_event.event.as_deref() != Some("endpoint") {
        return Err(SseConnectError::UnexpectedFirstEvent {
            got: endpoint_event.event.unwrap_or_default(),
        });
    }
    let endpoint_data = endpoint_event
        .data
        .ok_or(SseConnectError::EndpointMissingData)?;
    let messages_url = base.join(&endpoint_data)?;
    let cleartext_control_plane = wholly_cleartext_control_plane(&base, &messages_url);

    let (inbound_tx, inbound_rx) = mpsc::channel::<ServerJsonRpcMessage>(CHANNEL_BUFFER);
    let (outbound_tx, outbound_rx) = mpsc::channel::<ClientJsonRpcMessage>(CHANNEL_BUFFER);
    let cancel = CancellationToken::new();
    let sink = SseClientSink::new(PollSender::new(outbound_tx), cancel.clone());

    tokio::spawn(reader_task(sse, inbound_tx, cancel.clone()));
    tokio::spawn(writer_task(
        http,
        messages_url,
        augmenter,
        static_bearer,
        write_timeout,
        outbound_rx,
        cancel,
    ));

    Ok(ConnectedSse {
        transport: (sink, ReceiverStream::new(inbound_rx)),
        cleartext_control_plane,
    })
}

fn wholly_cleartext_control_plane(receive_url: &Url, messages_url: &Url) -> bool {
    receive_url.scheme() == "http"
        && messages_url.scheme() == "http"
        && receive_url
            .host()
            .zip(messages_url.host())
            .is_some_and(|(receive, messages)| receive == messages)
}

async fn reader_task(
    mut sse: BoxStream<'static, Result<Sse, sse_stream::Error>>,
    tx: mpsc::Sender<ServerJsonRpcMessage>,
    cancel: CancellationToken,
) {
    loop {
        let item = tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tx.closed() => {
                cancel.cancel();
                return;
            }
            item = sse.next() => item,
        };
        let Some(item) = item else { break };
        match item {
            Ok(event) => {
                let Some(data) = event.data else { continue };
                // Per the legacy MCP SSE spec the event name is "message".
                // A handful of servers omit it; treat that as default and
                // accept the payload. Anything else (e.g. "ping") is dropped.
                if let Some(name) = event.event.as_deref() {
                    if name != "message" {
                        tracing::debug!(event = %name, "ignoring non-message sse event");
                        continue;
                    }
                }
                match serde_json::from_str::<ServerJsonRpcMessage>(&data) {
                    Ok(msg) => {
                        let sent = tokio::select! {
                            _ = cancel.cancelled() => return,
                            sent = tx.send(msg) => sent,
                        };
                        if sent.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "sse upstream sent malformed jsonrpc — dropped",
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "sse stream error — closing reader");
                break;
            }
        }
    }
    cancel.cancel();
    tracing::debug!("sse upstream closed inbound stream");
}

async fn writer_task(
    http: reqwest::Client,
    messages_url: Url,
    augmenter: Option<IdentityAugmenter>,
    static_bearer: Option<String>,
    write_timeout: Duration,
    mut rx: mpsc::Receiver<ClientJsonRpcMessage>,
    cancel: CancellationToken,
) {
    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => return,
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else { break };
        let body: Bytes = match serde_json::to_vec(&msg) {
            Ok(b) => b.into(),
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize outbound jsonrpc message");
                continue;
            }
        };
        let mut req = http
            .post(messages_url.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        // Same static bearer as the GET, on *every* outbound message
        // (initialize / ping / tools/list / call) — the upstream authorizes each
        // POST independently, so it must ride all of them, not just tool calls.
        if let Some(token) = static_bearer.as_ref() {
            req = req.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(aug) = augmenter.as_ref() {
            let headers = tokio::select! {
                _ = cancel.cancelled() => return,
                headers = aug.headers() => headers,
            };
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }
        let result = tokio::select! {
            _ = cancel.cancelled() => return,
            result = req.timeout(write_timeout).send() => result,
        };
        match result {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    "sse upstream rejected outbound jsonrpc post",
                );
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, "sse upstream post failed");
                break;
            }
        }
    }
    cancel.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleartext_control_plane_requires_both_sse_legs_on_the_same_host() {
        let receive = Url::parse("http://upstream.example/sse").unwrap();
        let relative_messages = receive.join("/messages").unwrap();
        let protected_messages = Url::parse("https://upstream.example/messages").unwrap();
        let other_host = Url::parse("http://messages.example/messages").unwrap();
        let protected_receive = Url::parse("https://upstream.example/sse").unwrap();
        let cleartext_messages = Url::parse("http://upstream.example/messages").unwrap();

        assert!(wholly_cleartext_control_plane(&receive, &relative_messages));
        assert!(!wholly_cleartext_control_plane(
            &receive,
            &protected_messages
        ));
        assert!(!wholly_cleartext_control_plane(&receive, &other_host));
        assert!(!wholly_cleartext_control_plane(
            &protected_receive,
            &cleartext_messages
        ));
    }
}
