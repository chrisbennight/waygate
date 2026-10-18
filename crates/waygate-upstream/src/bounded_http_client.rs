//! Per-request response bounds for gateway-internal MCP reads.
//!
//! Ordinary MCP traffic delegates unchanged to rmcp's reqwest client. A native
//! resource read or call-scoped retained-response read carries its serialized
//! materialization budget as a [`ResponseByteLimit`] request extension. For
//! that request only, this wrapper consumes one JSON-RPC response under the
//! raw-byte ceiling before rmcp can decode an untrusted body into the shared
//! gateway process.
//!
//! Every request also reports its outcome to the dial's exchange recorder,
//! which records only while the dial that built this client is in progress.

use std::collections::HashMap;
use std::io;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, OnceLock,
};

use futures::{stream::BoxStream, StreamExt, TryStreamExt};
use http::{HeaderName, HeaderValue};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rmcp::model::{ClientJsonRpcMessage, GetExtensions, JsonRpcMessage, ServerJsonRpcMessage};
use rmcp::service::ServiceError;
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use sse_stream::{Sse, SseStream};
use tokio_util::sync::CancellationToken;

use waygate_core::http_client::{read_body_capped, ReadBodyError};

use crate::dial_trace::ExchangeRecorder;
use crate::http_policy::RedirectRefused;
use crate::transport::QuerySecret;

const JSON_MIME_TYPE: &str = "application/json";
const EVENT_STREAM_MIME_TYPE: &str = "text/event-stream";
const SESSION_HEADER: &str = "mcp-session-id";

/// The raw-byte budget for the response to one outgoing request.
///
/// It rides in the request's in-process extensions rather than its `_meta`:
/// rmcp serializes only metadata objects from extensions, so the budget stays
/// inside the gateway while the message passes through the SDK to this client.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResponseByteLimit(pub(crate) usize);

#[derive(Debug, thiserror::Error)]
#[error("upstream response exceeded the {limit_bytes}-byte materialization limit")]
struct ResponseMaterializationLimit {
    limit_bytes: usize,
}

fn streamable_response_materialization_limit(
    error: &StreamableHttpError<reqwest::Error>,
) -> Option<usize> {
    let StreamableHttpError::Io(error) = error else {
        return None;
    };
    error
        .get_ref()?
        .downcast_ref::<ResponseMaterializationLimit>()
        .map(|error| error.limit_bytes)
}

/// Recover the gateway's typed raw-response refusal after rmcp erases the
/// concrete streamable-HTTP transport behind [`ServiceError::TransportSend`].
/// An upstream JSON-RPC error never enters this transport-error branch and
/// therefore cannot impersonate the refusal with matching wire data.
pub(crate) fn response_materialization_limit(error: &ServiceError) -> Option<usize> {
    let ServiceError::TransportSend(error) = error else {
        return None;
    };
    error
        .error
        .downcast_ref::<StreamableHttpError<reqwest::Error>>()
        .and_then(streamable_response_materialization_limit)
}

#[derive(Clone)]
pub(crate) struct BoundedResponseClient {
    inner: reqwest::Client,
    connection_failed: Arc<AtomicBool>,
    refused_redirect: Arc<OnceLock<RedirectRefused>>,
    open_requests: CancellationToken,
    exchanges: ExchangeRecorder,
    /// A secret query parameter added to every request URI here, at the last
    /// gateway layer, so the SDK and every error see only the configured URI.
    query_secret: Option<Arc<QuerySecret>>,
}

impl BoundedResponseClient {
    pub(crate) fn new(inner: reqwest::Client, exchanges: ExchangeRecorder) -> Self {
        Self {
            inner,
            connection_failed: Arc::new(AtomicBool::new(false)),
            refused_redirect: Arc::default(),
            open_requests: CancellationToken::new(),
            exchanges,
            query_secret: None,
        }
    }

    pub(crate) fn with_query_secret(mut self, query_secret: Option<Arc<QuerySecret>>) -> Self {
        self.query_secret = query_secret;
        self
    }

    /// `uri` as the request leaves the gateway.
    fn request_uri(&self, uri: Arc<str>) -> Arc<str> {
        match self.query_secret.as_ref() {
            Some(query) => query.apply_str(&uri).into(),
            None => uri,
        }
    }

    /// Cancelling the returned token ends every message POST still waiting on
    /// this connection, and any later one. The SDK's HTTP worker awaits a POST
    /// until its response headers arrive, and a 2026-07-28 upstream sends none
    /// until it has a result, so without this a closed session would leave the
    /// upstream working. Ending the POST closes its stream, which a
    /// 2026-07-28 upstream treats as cancellation.
    pub(crate) fn open_requests(&self) -> CancellationToken {
        self.open_requests.clone()
    }

    async fn until_closed(
        &self,
        request: impl std::future::Future<
            Output = Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>>,
        >,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
        tokio::select! {
            biased;
            () = self.open_requests.cancelled() => Err(StreamableHttpError::TransportChannelClosed),
            result = request => result,
        }
    }

    pub(crate) fn connection_failed(&self) -> bool {
        self.connection_failed.load(Ordering::Relaxed)
    }

    /// The first redirect this client refused. The SDK reports the failed
    /// request only as a transport error, so a dial reads this to say why.
    pub(crate) fn refused_redirect(&self) -> Option<RedirectRefused> {
        self.refused_redirect.get().copied()
    }

    /// The slot recording that refusal, shared by every clone of this client,
    /// so a connection can report it after the dial's handshake.
    pub(crate) fn refused_redirect_slot(&self) -> Arc<OnceLock<RedirectRefused>> {
        Arc::clone(&self.refused_redirect)
    }

    /// Record what a failure means for the dial, then drop the URL from an
    /// HTTP error: it can carry the secret query parameter, and the dial error
    /// names the server anyway.
    fn settle<T>(
        &self,
        result: Result<T, StreamableHttpError<reqwest::Error>>,
    ) -> Result<T, StreamableHttpError<reqwest::Error>> {
        self.observe_failure(&result);
        result.map_err(|error| match error {
            StreamableHttpError::Client(error) => StreamableHttpError::Client(error.without_url()),
            other => other,
        })
    }

    fn observe_failure<T>(&self, result: &Result<T, StreamableHttpError<reqwest::Error>>) {
        let Err(StreamableHttpError::Client(error)) = result else {
            return;
        };
        if error.is_connect() {
            self.connection_failed.store(true, Ordering::Relaxed);
        }
        if let Some(refused) = RedirectRefused::from_reqwest(error) {
            let _ = self.refused_redirect.set(refused);
        }
    }

    fn response_limit(message: &ClientJsonRpcMessage) -> Option<usize> {
        let JsonRpcMessage::Request(request) = message else {
            return None;
        };
        request
            .request
            .extensions()
            .get::<ResponseByteLimit>()
            .map(|limit| limit.0)
            .filter(|value| *value > 0)
    }

    fn limit_error(limit_bytes: usize) -> StreamableHttpError<reqwest::Error> {
        StreamableHttpError::Io(io::Error::other(ResponseMaterializationLimit {
            limit_bytes,
        }))
    }

    fn is_response_for(request: &ClientJsonRpcMessage, response: &ServerJsonRpcMessage) -> bool {
        let JsonRpcMessage::Request(request) = request else {
            return false;
        };
        match response {
            JsonRpcMessage::Response(response) => response.id == request.id,
            JsonRpcMessage::Error(error) => error.id.as_ref() == Some(&request.id),
            _ => false,
        }
    }

    async fn post_bounded(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        limit: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
        let mut request = self
            .inner
            .post(uri.as_ref())
            .header(ACCEPT, [EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE].join(", "));
        if let Some(auth_header) = auth_header {
            request = request.bearer_auth(auth_header);
        }
        for (name, value) in custom_headers {
            request = request.header(name, value);
        }
        let had_session = session_id.is_some();
        if let Some(session_id) = session_id {
            request = request.header(SESSION_HEADER, session_id.as_ref());
        }
        let response = request
            .json(&message)
            .send()
            .await
            .map_err(StreamableHttpError::Client)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND && had_session {
            return Err(StreamableHttpError::SessionExpired);
        }
        if matches!(
            response.status(),
            reqwest::StatusCode::ACCEPTED | reqwest::StatusCode::NO_CONTENT
        ) {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if !response.status().is_success() {
            return Err(StreamableHttpError::UnexpectedServerResponse(
                format!("HTTP {} during bounded resource read", response.status()).into(),
            ));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let returned_session = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|bytes| bytes > limit as u64)
        {
            return Err(Self::limit_error(limit));
        }

        match content_type.as_deref() {
            Some(value) if value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
                let body = match read_body_capped(response, limit).await {
                    Ok(body) => body,
                    Err(ReadBodyError::TooLarge(_)) => return Err(Self::limit_error(limit)),
                    Err(ReadBodyError::Http(error)) => {
                        return Err(StreamableHttpError::Client(error))
                    }
                };
                let decoded = serde_json::from_slice::<ServerJsonRpcMessage>(&body)?;
                Ok(StreamableHttpPostResponse::Json(decoded, returned_session))
            }
            Some(value)
                if value
                    .as_bytes()
                    .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) =>
            {
                let seen = Arc::new(AtomicUsize::new(0));
                let exceeded = Arc::new(AtomicBool::new(false));
                let count = Arc::clone(&seen);
                let tripped = Arc::clone(&exceeded);
                let bounded = response
                    .bytes_stream()
                    .map_err(|_| io::Error::other("bounded upstream response transport failed"))
                    .and_then(move |chunk| {
                        let next = count
                            .fetch_add(chunk.len(), Ordering::Relaxed)
                            .saturating_add(chunk.len());
                        let tripped = Arc::clone(&tripped);
                        async move {
                            if next > limit {
                                tripped.store(true, Ordering::Relaxed);
                                Err(io::Error::other(
                                    "bounded upstream response exceeded its limit",
                                ))
                            } else {
                                Ok(chunk)
                            }
                        }
                    });
                let events = SseStream::from_bytes_stream(bounded);
                futures::pin_mut!(events);
                while let Some(event) = events.next().await {
                    match event {
                        Ok(event) => {
                            let Some(data) = event.data.filter(|data| !data.trim().is_empty())
                            else {
                                continue;
                            };
                            let decoded = serde_json::from_str::<ServerJsonRpcMessage>(&data)?;
                            if Self::is_response_for(&message, &decoded) {
                                return Ok(StreamableHttpPostResponse::Json(
                                    decoded,
                                    returned_session,
                                ));
                            }
                        }
                        Err(_error) if exceeded.load(Ordering::Relaxed) => {
                            return Err(Self::limit_error(limit));
                        }
                        Err(error) => return Err(StreamableHttpError::Sse(error)),
                    }
                }
                Err(StreamableHttpError::UnexpectedEndOfStream)
            }
            _ => Err(StreamableHttpError::UnexpectedContentType(content_type)),
        }
    }
}

impl StreamableHttpClient for BoundedResponseClient {
    type Error = reqwest::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.post(&message);
        let uri = self.request_uri(uri);
        let result = self
            .until_closed(self.inner.post_message(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
            ))
            .await;
        exchange.post_result(self.settle(result))
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.post(&message);
        let uri = self.request_uri(uri);
        let result = if let Some(limit) = Self::response_limit(&message) {
            self.until_closed(self.post_bounded(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                limit,
            ))
            .await
        } else {
            self.until_closed(self.inner.post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            ))
            .await
        };
        exchange.post_result(self.settle(result))
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.delete();
        let uri = self.request_uri(uri);
        let result = self
            .inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await;
        exchange.unit_result(self.settle(result))
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.get();
        let uri = self.request_uri(uri);
        let result = self
            .inner
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await;
        exchange.stream_result(self.settle(result))
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.get();
        let uri = self.request_uri(uri);
        let result = self
            .inner
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await;
        exchange.stream_result(self.settle(result))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::{body::Body, response::Response, routing::post, Router};
    use bytes::Bytes;
    use futures::stream;
    use serde_json::json;

    use super::*;

    fn read_request(limit: Option<usize>) -> ClientJsonRpcMessage {
        let mut message: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {"uri": "connector-response:/large/0"},
        }))
        .expect("valid resources/read request");
        if let (Some(limit), JsonRpcMessage::Request(request)) = (limit, &mut message) {
            request
                .request
                .extensions_mut()
                .insert(ResponseByteLimit(limit));
        }
        message
    }

    #[test]
    fn only_the_in_process_budget_selects_a_response_limit() {
        let bounded = read_request(Some(73));
        assert_eq!(BoundedResponseClient::response_limit(&bounded), Some(73));
        assert!(
            serde_json::to_value(&bounded).unwrap()["params"]
                .get("_meta")
                .is_none(),
            "the budget must not serialize onto the upstream request"
        );
        assert_eq!(
            BoundedResponseClient::response_limit(&read_request(None)),
            None
        );

        let wire_shaped: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {
                "uri": "connector-response:/large/0",
                "_meta": {
                    waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY: 73
                },
            },
        }))
        .expect("valid resources/read request");
        assert_eq!(
            BoundedResponseClient::response_limit(&wire_shaped),
            None,
            "request metadata is not the budget's carrier"
        );
    }

    #[test]
    fn bounded_sse_waits_for_the_correlated_response() {
        let request = read_request(Some(73));
        let unrelated = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 8,
            "result": {"contents": []}
        }))
        .unwrap();
        let correlated = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"contents": []}
        }))
        .unwrap();

        assert!(!BoundedResponseClient::is_response_for(
            &request, &unrelated
        ));
        assert!(BoundedResponseClient::is_response_for(
            &request,
            &correlated
        ));
    }

    #[tokio::test]
    async fn chunked_json_is_refused_before_rmcp_decodes_beyond_the_budget() {
        let response_body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "contents": [{
                    "uri": "connector-response:/large/0",
                    "text": "x".repeat(1024)
                }]
            }
        }))
        .unwrap();
        let body = Arc::new(response_body);
        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = Arc::clone(&body);
                async move {
                    let chunks = stream::iter(vec![
                        Ok::<_, Infallible>(Bytes::copy_from_slice(&body[..64])),
                        Ok(Bytes::copy_from_slice(&body[64..])),
                    ]);
                    Response::builder()
                        .header(CONTENT_TYPE, JSON_MIME_TYPE)
                        .body(Body::from_stream(chunks))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = BoundedResponseClient::new(
            waygate_core::http_client::client(waygate_core::http_client::Profile::NoTotalTimeout)
                .unwrap(),
            ExchangeRecorder::default(),
        );

        let error = client
            .post_message_with_max_sse_event_size(
                format!("http://{address}/mcp").into(),
                read_request(Some(128)),
                None,
                None,
                HashMap::new(),
                usize::MAX,
            )
            .await
            .expect_err("local limit is a typed transport refusal");

        assert_eq!(streamable_response_materialization_limit(&error), Some(128));
        server.abort();
    }

    #[tokio::test]
    async fn chunked_sse_is_refused_before_rmcp_decodes_beyond_the_budget() {
        let event = format!(
            "event: message\ndata: {}\n\n",
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {
                    "contents": [{
                        "uri": "connector-response:/large/0",
                        "text": "x".repeat(1024)
                    }]
                }
            })
        );
        let body = Arc::new(event.into_bytes());
        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = Arc::clone(&body);
                async move {
                    let chunks = stream::iter(vec![
                        Ok::<_, Infallible>(Bytes::copy_from_slice(&body[..64])),
                        Ok(Bytes::copy_from_slice(&body[64..])),
                    ]);
                    Response::builder()
                        .header(CONTENT_TYPE, EVENT_STREAM_MIME_TYPE)
                        .body(Body::from_stream(chunks))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = BoundedResponseClient::new(
            waygate_core::http_client::client(waygate_core::http_client::Profile::NoTotalTimeout)
                .unwrap(),
            ExchangeRecorder::default(),
        );

        let error = client
            .post_message_with_max_sse_event_size(
                format!("http://{address}/mcp").into(),
                read_request(Some(128)),
                None,
                None,
                HashMap::new(),
                usize::MAX,
            )
            .await
            .expect_err("local SSE limit is a typed transport refusal");

        assert_eq!(streamable_response_materialization_limit(&error), Some(128));
        server.abort();
    }
}
