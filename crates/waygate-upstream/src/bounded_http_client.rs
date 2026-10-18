//! Per-request response bounds for gateway-originated MCP requests.
//!
//! Ordinary MCP traffic delegates unchanged to rmcp's reqwest client. A
//! request whose response budget rides in a [`ResponseByteLimit`] request
//! extension is read under that raw-byte ceiling before rmcp can decode an
//! untrusted body into the shared gateway process. A native resource read or
//! call-scoped retained-response read is consumed here up to its one JSON-RPC
//! response. Any other bounded request, such as a tool call, keeps its event
//! stream: rmcp still receives the upstream's notifications, requests and
//! resumable event IDs, and only the byte count is enforced here.
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
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, GetExtensions, JsonRpcMessage, RequestId,
    ServerJsonRpcMessage,
};
use rmcp::service::ServiceError;
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use sse_stream::{Sse, SseStream};
use tokio_util::sync::CancellationToken;

use waygate_core::http_client::{read_body_capped, ReadBodyError};

use crate::dial_trace::ExchangeRecorder;
use crate::http_policy::RedirectRefused;

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

/// `data` member of the JSON-RPC error that ends an event stream cut off at
/// its limit. Its value is [`local_limit_marker`].
const LIMIT_MARKER_KEY: &str = "io.bennight.gateway/responseLimitMarker";

/// Random value generated once per gateway process. Only this transport
/// writes it, into the refusals it hands to rmcp, and the pool replaces those
/// refusals before any caller sees them, so an upstream cannot produce a
/// JSON-RPC error that passes for the gateway's own refusal.
fn local_limit_marker() -> &'static str {
    static MARKER: OnceLock<String> = OnceLock::new();
    MARKER.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}

/// Limit named by an event-stream refusal this transport synthesized.
fn streamed_response_materialization_limit(error: &ErrorData) -> Option<usize> {
    let data = error.data.as_ref()?;
    if data.get(LIMIT_MARKER_KEY)?.as_str()? != local_limit_marker() {
        return None;
    }
    data.get("limit_bytes")?
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
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

/// Recover the gateway's raw-response refusal from the error rmcp returns for
/// the request.
///
/// A refusal made before rmcp has the response arrives as a typed transport
/// error behind [`ServiceError::TransportSend`], which an upstream JSON-RPC
/// error never enters. A refusal on an event stream already handed to rmcp
/// can only end the request as its JSON-RPC error, so that error carries the
/// process-local marker; an upstream error without it is never recognized,
/// whatever its wire data.
pub(crate) fn response_materialization_limit(error: &ServiceError) -> Option<usize> {
    match error {
        ServiceError::TransportSend(error) => error
            .error
            .downcast_ref::<StreamableHttpError<reqwest::Error>>()
            .and_then(streamable_response_materialization_limit),
        ServiceError::McpError(error) => streamed_response_materialization_limit(error),
        _ => None,
    }
}

#[derive(Clone)]
pub(crate) struct BoundedResponseClient {
    inner: reqwest::Client,
    connection_failed: Arc<AtomicBool>,
    refused_redirect: Arc<OnceLock<RedirectRefused>>,
    open_requests: CancellationToken,
    exchanges: ExchangeRecorder,
}

impl BoundedResponseClient {
    pub(crate) fn new(inner: reqwest::Client, exchanges: ExchangeRecorder) -> Self {
        Self {
            inner,
            connection_failed: Arc::new(AtomicBool::new(false)),
            refused_redirect: Arc::default(),
            open_requests: CancellationToken::new(),
            exchanges,
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

    /// Whether the bounded request is consumed here up to its one response.
    /// Resource reads are; every other request keeps its event stream so rmcp
    /// still sees what the upstream sends while it works.
    fn materializes_reply(message: &ClientJsonRpcMessage) -> bool {
        matches!(
            message,
            JsonRpcMessage::Request(request)
                if matches!(request.request, ClientRequest::ReadResourceRequest(_))
        )
    }

    async fn read_capped(
        response: reqwest::Response,
        limit: usize,
    ) -> Result<Vec<u8>, StreamableHttpError<reqwest::Error>> {
        match read_body_capped(response, limit).await {
            Ok(body) => Ok(body),
            Err(ReadBodyError::TooLarge(_)) => Err(Self::limit_error(limit)),
            Err(ReadBodyError::Http(error)) => Err(StreamableHttpError::Client(error)),
        }
    }

    /// The response body as a byte stream that fails once more than `limit`
    /// bytes have arrived, and the flag recording that it did.
    fn capped_bytes(
        response: reqwest::Response,
        limit: usize,
    ) -> (
        impl futures::Stream<Item = Result<bytes::Bytes, io::Error>> + Send + 'static,
        Arc<AtomicBool>,
    ) {
        let seen = Arc::new(AtomicUsize::new(0));
        let exceeded = Arc::new(AtomicBool::new(false));
        let tripped = Arc::clone(&exceeded);
        let bytes = response
            .bytes_stream()
            .map_err(|_| io::Error::other("bounded upstream response transport failed"))
            .and_then(move |chunk| {
                let next = seen
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
        (bytes, exceeded)
    }

    /// The request's event stream, ended by a marked JSON-RPC error for the
    /// request once it exceeds `limit`. The count covers every event, so it
    /// also bounds any single event. rmcp would resume a stream that merely
    /// failed after an event ID and could then read the rest uncounted; a
    /// final response for the request is what ends it for good.
    fn bounded_event_stream(
        response: reqwest::Response,
        request_id: Option<RequestId>,
        limit: usize,
    ) -> BoxStream<'static, Result<Sse, SseError>> {
        let refusal = request_id.map(|id| {
            let error = ErrorData::internal_error(
                format!("upstream response exceeded the {limit}-byte materialization limit"),
                Some(serde_json::json!({
                    LIMIT_MARKER_KEY: local_limit_marker(),
                    "limit_bytes": limit,
                })),
            );
            Sse {
                data: Some(
                    serde_json::to_string(&ServerJsonRpcMessage::error(error, Some(id)))
                        .expect("a JSON-RPC error serializes"),
                ),
                ..Sse::default()
            }
        });
        let (bytes, exceeded) = Self::capped_bytes(response, limit);
        let events = SseStream::from_bytes_stream(bytes).boxed();
        futures::stream::unfold(Some(events), move |events| {
            let refusal = refusal.clone();
            let exceeded = Arc::clone(&exceeded);
            async move {
                let mut events = events?;
                let event = events.next().await?;
                if event.is_err() && exceeded.load(Ordering::Relaxed) {
                    return Some((refusal.map_or(event, Ok), None));
                }
                Some((event, Some(events)))
            }
        })
        .boxed()
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
        let materialize = Self::materializes_reply(&message);
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

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        let is_json = content_type
            .as_deref()
            .is_some_and(|value| value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()));
        let returned_session = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let status = response.status();
        if !status.is_success() {
            if materialize {
                return Err(StreamableHttpError::UnexpectedServerResponse(
                    format!("HTTP {status} during bounded resource read").into(),
                ));
            }
            // Like rmcp, deliver a JSON-RPC error sent with an error status
            // as the request's typed error. The body never enters error text.
            if is_json {
                let body = Self::read_capped(response, limit).await?;
                if let Ok(error @ JsonRpcMessage::Error(_)) =
                    serde_json::from_slice::<ServerJsonRpcMessage>(&body)
                {
                    return Ok(StreamableHttpPostResponse::Json(error, returned_session));
                }
            }
            return Err(StreamableHttpError::UnexpectedServerResponse(
                format!("HTTP {status} during a bounded request").into(),
            ));
        }
        if response
            .content_length()
            .is_some_and(|bytes| bytes > limit as u64)
        {
            return Err(Self::limit_error(limit));
        }

        if is_json {
            let body = Self::read_capped(response, limit).await?;
            let decoded = serde_json::from_slice::<ServerJsonRpcMessage>(&body)?;
            return Ok(StreamableHttpPostResponse::Json(decoded, returned_session));
        }
        let is_event_stream = content_type.as_deref().is_some_and(|value| {
            value
                .as_bytes()
                .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes())
        });
        if !is_event_stream {
            return Err(StreamableHttpError::UnexpectedContentType(content_type));
        }
        if !materialize {
            let request_id = match &message {
                JsonRpcMessage::Request(request) => Some(request.id.clone()),
                _ => None,
            };
            return Ok(StreamableHttpPostResponse::Sse(
                Self::bounded_event_stream(response, request_id, limit),
                returned_session,
            ));
        }

        let (bounded, exceeded) = Self::capped_bytes(response, limit);
        let events = SseStream::from_bytes_stream(bounded);
        futures::pin_mut!(events);
        while let Some(event) = events.next().await {
            match event {
                Ok(event) => {
                    let Some(data) = event.data.filter(|data| !data.trim().is_empty()) else {
                        continue;
                    };
                    let decoded = serde_json::from_str::<ServerJsonRpcMessage>(&data)?;
                    if Self::is_response_for(&message, &decoded) {
                        return Ok(StreamableHttpPostResponse::Json(decoded, returned_session));
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
        let result = self
            .until_closed(self.inner.post_message(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
            ))
            .await;
        self.observe_failure(&result);
        exchange.post_result(result)
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
        self.observe_failure(&result);
        exchange.post_result(result)
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let exchange = self.exchanges.delete();
        let result = self
            .inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await;
        self.observe_failure(&result);
        exchange.unit_result(result)
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
        let result = self
            .inner
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await;
        self.observe_failure(&result);
        exchange.stream_result(result)
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
        self.observe_failure(&result);
        exchange.stream_result(result)
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

    fn tool_call_request(limit: usize) -> ClientJsonRpcMessage {
        let mut request = ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(
            rmcp::model::CallToolRequestParams::new("large"),
        ));
        request.extensions_mut().insert(ResponseByteLimit(limit));
        ClientJsonRpcMessage::request(request, RequestId::Number(7))
    }

    #[test]
    fn a_bounded_tool_call_keeps_its_budget_off_the_wire() {
        let bounded = tool_call_request(73);
        assert_eq!(BoundedResponseClient::response_limit(&bounded), Some(73));
        let wire = serde_json::to_value(&bounded).unwrap();
        assert_eq!(wire["method"], "tools/call");
        assert!(
            wire["params"].get("_meta").is_none(),
            "the budget must not serialize onto the upstream request: {wire}"
        );

        let wire_shaped: ClientJsonRpcMessage = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "large",
                "_meta": {
                    waygate_mcp::catalog::RESPONSE_MATERIALIZATION_LIMIT_META_KEY: 73
                },
            },
        }))
        .expect("valid tools/call request");
        assert_eq!(
            BoundedResponseClient::response_limit(&wire_shaped),
            None,
            "request metadata is not the budget's carrier"
        );
    }

    /// Serve `body` as two chunks split at `split`, with the given status and
    /// content type, so a limit falls inside the body rather than on its
    /// declared length. The limit is checked as each chunk arrives.
    async fn serve_chunked(
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
        split: usize,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let body = Arc::new(body);
        let app = Router::new().route(
            "/mcp",
            post(move || {
                let body = Arc::clone(&body);
                async move {
                    let chunks = stream::iter(vec![
                        Ok::<_, Infallible>(Bytes::copy_from_slice(&body[..split])),
                        Ok(Bytes::copy_from_slice(&body[split..])),
                    ]);
                    Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, content_type)
                        .body(Body::from_stream(chunks))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}/mcp"), server)
    }

    fn client() -> BoundedResponseClient {
        BoundedResponseClient::new(
            waygate_core::http_client::client(waygate_core::http_client::Profile::NoTotalTimeout)
                .unwrap(),
            ExchangeRecorder::default(),
        )
    }

    async fn post_tool_call(
        uri: String,
        limit: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
        client()
            .post_message_with_max_sse_event_size(
                uri.into(),
                tool_call_request(limit),
                None,
                None,
                HashMap::new(),
                usize::MAX,
            )
            .await
    }

    fn large_result_event() -> String {
        format!(
            "event: message\ndata: {}\n\n",
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": {"content": [{"type": "text", "text": "x".repeat(1024)}]}
            })
        )
    }

    fn progress_event() -> String {
        format!(
            "event: message\ndata: {}\n\n",
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": 1, "progress": 1}
            })
        )
    }

    #[test]
    fn only_resource_reads_are_consumed_up_to_their_response() {
        assert!(BoundedResponseClient::materializes_reply(&read_request(
            Some(73)
        )));
        assert!(!BoundedResponseClient::materializes_reply(
            &tool_call_request(73)
        ));
    }

    #[test]
    fn only_this_process_marker_identifies_a_streamed_refusal() {
        let refusal = |marker: &str| {
            ErrorData::internal_error(
                "upstream response exceeded the 128-byte materialization limit",
                Some(json!({LIMIT_MARKER_KEY: marker, "limit_bytes": 128})),
            )
        };
        assert_eq!(
            response_materialization_limit(&ServiceError::McpError(refusal(local_limit_marker()))),
            Some(128)
        );
        for spoofed in ["", "00000000000000000000000000000000"] {
            assert_eq!(
                response_materialization_limit(&ServiceError::McpError(refusal(spoofed))),
                None,
                "an upstream cannot name the gateway's marker"
            );
        }
    }

    #[tokio::test]
    async fn chunked_json_tool_result_is_refused_before_rmcp_decodes_it() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"content": [{"type": "text", "text": "x".repeat(1024)}]}
        }))
        .unwrap();
        let (uri, server) = serve_chunked(200, JSON_MIME_TYPE, body, 64).await;

        let error = post_tool_call(uri, 128)
            .await
            .expect_err("local limit is a typed transport refusal");

        assert_eq!(streamable_response_materialization_limit(&error), Some(128));
        server.abort();
    }

    #[tokio::test]
    async fn tool_call_event_stream_keeps_its_messages_until_the_limit_ends_it() {
        let progress = progress_event();
        let limit = progress.len() + 64;
        let body = format!("{progress}{}", large_result_event()).into_bytes();
        let (uri, server) = serve_chunked(200, EVENT_STREAM_MIME_TYPE, body, progress.len()).await;

        let response = post_tool_call(uri, limit)
            .await
            .expect("an event stream is handed to rmcp, not consumed here");
        let StreamableHttpPostResponse::Sse(mut events, _) = response else {
            panic!("a bounded tool call keeps its event stream")
        };
        let first = events.next().await.expect("first event").expect("readable");
        assert!(
            first
                .data
                .as_deref()
                .is_some_and(|data| data.contains("notifications/progress")),
            "messages within the limit reach rmcp unchanged: {first:?}"
        );
        let last = events
            .next()
            .await
            .expect("refusal event")
            .expect("readable");
        let message: ServerJsonRpcMessage =
            serde_json::from_str(last.data.as_deref().expect("refusal data")).unwrap();
        let JsonRpcMessage::Error(error) = message else {
            panic!("the stream ends with an error for the request")
        };
        assert_eq!(error.id, Some(RequestId::Number(7)));
        assert_eq!(
            response_materialization_limit(&ServiceError::McpError(error.error)),
            Some(limit)
        );
        assert!(
            events.next().await.is_none(),
            "nothing past the limit is read"
        );
        server.abort();
    }

    #[tokio::test]
    async fn tool_call_event_stream_within_its_limit_is_unchanged() {
        let progress = progress_event();
        let body = format!("{progress}{}", large_result_event()).into_bytes();
        let limit = body.len();
        let (uri, server) = serve_chunked(200, EVENT_STREAM_MIME_TYPE, body, progress.len()).await;

        let StreamableHttpPostResponse::Sse(events, _) =
            post_tool_call(uri, limit).await.expect("stream")
        else {
            panic!("a bounded tool call keeps its event stream")
        };
        let events: Vec<_> = events.collect().await;
        assert_eq!(events.len(), 2, "{events:?}");
        let result: ServerJsonRpcMessage = serde_json::from_str(
            events[1]
                .as_ref()
                .expect("readable")
                .data
                .as_deref()
                .expect("data"),
        )
        .unwrap();
        assert!(matches!(result, JsonRpcMessage::Response(_)));
        server.abort();
    }

    #[tokio::test]
    async fn tool_call_error_status_keeps_its_json_rpc_error() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "error": {"code": -32602, "message": "unknown tool"}
        }))
        .unwrap();
        let (uri, server) = serve_chunked(400, JSON_MIME_TYPE, body, 16).await;

        let response = post_tool_call(uri, 1024)
            .await
            .expect("a JSON-RPC error body is the request's typed error");
        let StreamableHttpPostResponse::Json(JsonRpcMessage::Error(error), _) = response else {
            panic!("the upstream's JSON-RPC error is delivered")
        };
        assert_eq!(error.error.message, "unknown tool");
        server.abort();
    }
}
