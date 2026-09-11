//! End-to-end test for `waygate-upstream::sse_client`.
//!
//! Spins up a tiny axum app that speaks the legacy MCP SSE transport, then
//! drives the resulting `(Sink, Stream)` pair directly to verify the
//! handshake, request/response round-trip, and identity-header forwarding.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;

use waygate_oidc::{IdentityIssuer, Principal};
use waygate_upstream::identity_client::{
    IdentityAugmenter, IdentityCell, IdentityContext, IDENTITY_HEADER,
};
use waygate_upstream::{http_policy, sse_client};

type EventSender = mpsc::Sender<Result<Event, Infallible>>;

struct NotifyOnDrop(Arc<Notify>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

fn streaming_client() -> reqwest::Client {
    http_policy::streaming_client().expect("production streaming client policy")
}

#[derive(Clone, Default)]
struct ServerState {
    /// Outbound SSE channel for the most recent connected client. Test only
    /// drives a single session, so a single Option suffices.
    inbox: Arc<tokio::sync::Mutex<Option<EventSender>>>,
    /// Headers from the most recent message POST.
    last_post_headers: Arc<tokio::sync::Mutex<Option<HeaderMap>>>,
    /// Headers from the most recent SSE GET (stream open).
    last_get_headers: Arc<tokio::sync::Mutex<Option<HeaderMap>>>,
    /// Bodies from every message POST in arrival order.
    posts: Arc<tokio::sync::Mutex<Vec<Value>>>,
}

async fn sse_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Sse<ReceiverStream<Result<Event, Infallible>>> {
    *state.last_get_headers.lock().await = Some(headers);
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(16);
    // The MCP legacy SSE handshake: announce the messages POST URL via
    // `event: endpoint`. Use a relative URL to also exercise base-URL joining
    // in `sse_client::connect`.
    let endpoint = Event::default()
        .event("endpoint")
        .data("/mcp/messages?session_id=test");
    tx.send(Ok(endpoint)).await.expect("send endpoint event");
    *state.inbox.lock().await = Some(tx);
    Sse::new(ReceiverStream::new(rx))
}

async fn message_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> &'static str {
    *state.last_post_headers.lock().await = Some(headers);
    state.posts.lock().await.push(body.clone());

    // Echo the request id back as an empty-result Response. EmptyResult
    // deserializes as `{}` so the rmcp `ServerJsonRpcMessage::Response`
    // variant accepts it.
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {},
    });
    let event = Event::default().event("message").data(response.to_string());
    if let Some(tx) = state.inbox.lock().await.as_ref() {
        let _ = tx.send(Ok(event)).await;
    }
    ""
}

async fn spawn_server() -> (std::net::SocketAddr, ServerState) {
    let state = ServerState::default();
    let app = Router::new()
        .route("/mcp/sse", get(sse_handler))
        .route("/mcp/messages", post(message_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, state)
}

fn ping_request(id: i64) -> rmcp::model::ClientJsonRpcMessage {
    rmcp::model::ClientJsonRpcMessage::Request(rmcp::model::JsonRpcRequest {
        jsonrpc: rmcp::model::JsonRpcVersion2_0,
        id: rmcp::model::NumberOrString::Number(id),
        request: rmcp::model::ClientRequest::PingRequest(rmcp::model::PingRequest::default()),
    })
}

#[tokio::test]
async fn handshake_post_response_round_trip() {
    let (addr, _state) = spawn_server().await;
    let url = format!("http://{addr}/mcp/sse");

    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");

    sink.send(ping_request(7)).await.expect("send ping");

    let resp = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("response timed out")
        .expect("stream closed");

    match resp {
        rmcp::model::ServerJsonRpcMessage::Response(r) => {
            assert_eq!(r.id, rmcp::model::NumberOrString::Number(7));
        }
        other => panic!("expected Response, got {other:?}"),
    }

    sink.send(ping_request(8))
        .await
        .expect("successful POST keeps writer open");
    let second = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("second response timed out")
        .expect("stream closed after successful POST");
    match second {
        rmcp::model::ServerJsonRpcMessage::Response(r) => {
            assert_eq!(r.id, rmcp::model::NumberOrString::Number(8));
        }
        other => panic!("expected second Response, got {other:?}"),
    }
}

#[tokio::test]
async fn receive_stream_outlives_ordinary_total_request_deadlines() {
    let (addr, state) = spawn_server().await;
    let url = format!("http://{addr}/mcp/sse");
    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");
    let get_headers = state
        .last_get_headers
        .lock()
        .await
        .clone()
        .expect("SSE GET recorded");
    assert_eq!(
        get_headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
        Some(waygate_core::http_client::USER_AGENT),
        "streaming client must come from the shared gateway factory"
    );

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    sink.send(ping_request(8))
        .await
        .expect("stream remains writable after 31 seconds");
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("long-lived stream response timed out");
    assert!(
        response.is_some(),
        "receive stream closed at an ordinary deadline"
    );
}

#[tokio::test]
async fn stalled_writer_post_closes_transport_at_operation_deadline() {
    let state = ServerState::default();
    let app = Router::new()
        .route("/mcp/sse", get(sse_handler))
        .route(
            "/mcp/messages",
            post(|| async { std::future::pending::<&'static str>().await }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let url = format!("http://{addr}/mcp/sse");
    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_millis(50),
    )
    .await
    .expect("connect");
    sink.send(ping_request(9)).await.expect("enqueue ping");

    let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("writer timeout must close the transport");
    assert!(next.is_none(), "timed-out writer left the transport open");
}

#[tokio::test]
async fn rejected_writer_post_closes_transport() {
    let state = ServerState::default();
    let app = Router::new()
        .route("/mcp/sse", get(sse_handler))
        .route(
            "/mcp/messages",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let url = format!("http://{addr}/mcp/sse");
    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");
    sink.send(ping_request(10)).await.expect("enqueue ping");

    let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("rejected writer POST must close the transport");
    assert!(
        next.is_none(),
        "rejected writer POST left the transport open"
    );
}

#[tokio::test]
async fn dropping_transport_closes_streaming_response_body() {
    let (addr, state) = spawn_server().await;
    let url = format!("http://{addr}/mcp/sse");
    let (sink, stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");
    let server_events = state
        .inbox
        .lock()
        .await
        .as_ref()
        .expect("server event channel")
        .clone();

    drop(sink);
    drop(stream);

    tokio::time::timeout(Duration::from_secs(1), server_events.closed())
        .await
        .expect("dropping the transport must close the SSE response body");
}

enum DroppedHalf {
    Sink,
    Stream,
}

async fn assert_dropping_half_cancels_active_write(dropped_half: DroppedHalf) {
    let state = ServerState::default();
    let post_started = Arc::new(Notify::new());
    let post_cancelled = Arc::new(Notify::new());
    let app = Router::new()
        .route("/mcp/sse", get(sse_handler))
        .route(
            "/mcp/messages",
            post({
                let post_started = post_started.clone();
                let post_cancelled = post_cancelled.clone();
                move || {
                    let post_started = post_started.clone();
                    let post_cancelled = post_cancelled.clone();
                    async move {
                        let _cancelled = NotifyOnDrop(post_cancelled);
                        post_started.notify_one();
                        std::future::pending::<&'static str>().await
                    }
                }
            }),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let url = format!("http://{addr}/mcp/sse");
    let (sink, stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(10),
    )
    .await
    .expect("connect");
    let mut sink = Some(sink);
    let mut stream = Some(stream);
    let server_events = state
        .inbox
        .lock()
        .await
        .as_ref()
        .expect("server event channel")
        .clone();
    sink.as_mut()
        .expect("sink present")
        .send(ping_request(11))
        .await
        .expect("enqueue ping");
    tokio::time::timeout(Duration::from_secs(1), post_started.notified())
        .await
        .expect("writer must start the stalled POST");

    match dropped_half {
        DroppedHalf::Sink => drop(sink.take()),
        DroppedHalf::Stream => drop(stream.take()),
    }

    tokio::time::timeout(Duration::from_secs(1), post_cancelled.notified())
        .await
        .expect("dropping either half must cancel the in-flight POST future");
    if let Some(stream) = stream.as_mut() {
        let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("sink drop must interrupt the active write");
        assert!(next.is_none(), "sink drop left the peer reader open");
    }
    tokio::time::timeout(Duration::from_secs(1), server_events.closed())
        .await
        .expect("dropping either half must release the SSE response body");
}

#[tokio::test]
async fn dropping_sink_cancels_an_active_write_and_closes_response_body() {
    assert_dropping_half_cancels_active_write(DroppedHalf::Sink).await;
}

#[tokio::test]
async fn dropping_stream_cancels_an_active_write_and_closes_response_body() {
    assert_dropping_half_cancels_active_write(DroppedHalf::Stream).await;
}

#[tokio::test]
async fn rejects_first_event_that_is_not_endpoint() {
    let state = ServerState::default();
    // Hand-roll a server whose first event is `event: message` instead of
    // `endpoint`, so we can prove the handshake guards that contract.
    let app = Router::new().route(
        "/mcp/sse",
        get({
            let state = state.clone();
            move || async move {
                let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(8);
                let bad = Event::default().event("message").data("{}");
                tx.send(Ok(bad)).await.unwrap();
                *state.inbox.lock().await = Some(tx);
                Sse::new(ReceiverStream::new(rx))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("http://{addr}/mcp/sse");
    let err = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect_err("connect must fail");
    assert!(
        matches!(
            err,
            sse_client::SseConnectError::UnexpectedFirstEvent { .. }
        ),
        "got {err:?}",
    );
}

#[tokio::test]
async fn handshake_skips_id_only_control_event_before_endpoint() {
    let app = Router::new().route(
        "/mcp/sse",
        get(|| async {
            let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(8);
            tx.send(Ok(Event::default().id("ping"))).await.unwrap();
            tx.send(Ok(Event::default().event("endpoint").data("/messages")))
                .await
                .unwrap();
            Sse::new(ReceiverStream::new(rx))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    sse_client::connect(
        &format!("http://{addr}/mcp/sse"),
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("id-only control event before endpoint is valid");
}

#[tokio::test]
async fn endpoint_event_without_data_is_rejected() {
    let app = Router::new().route(
        "/mcp/sse",
        get(|| async {
            let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(8);
            tx.send(Ok(Event::default().event("endpoint")))
                .await
                .unwrap();
            Sse::new(ReceiverStream::new(rx))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let error = sse_client::connect(
        &format!("http://{addr}/mcp/sse"),
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect_err("endpoint data is required");
    assert!(
        matches!(error, sse_client::SseConnectError::EndpointMissingData),
        "got {error:?}"
    );
}

/// Build an `IdentityAugmenter` with a live gateway-minted identity set on its
/// cell (Tier-B), mirroring how `pool/mod.rs` wires it. The augmenter stamps
/// `X-MCP-Identity` — a header distinct from the static `Authorization` bearer.
fn identity_augmenter_with_context() -> IdentityAugmenter {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
    let issuer = Arc::new(
        IdentityIssuer::from_ed25519_pkcs8_pem(
            &pem,
            "gw-test",
            "https://mcp.test",
            "gateway-main",
            Duration::from_secs(60),
        )
        .unwrap(),
    );
    let cell = IdentityCell::new();
    let augmenter = IdentityAugmenter::new(issuer, cell.clone());
    cell.set(IdentityContext {
        principal: Principal {
            sub: "user-a".into(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test/".into(),
            scopes: vec![],
            tenant: waygate_core::TenantId::default(),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        },
        audience: "crawl4ai".into(),
        exchange: None,
        stored_upstream_subject_token: None,
        exchanged_bearer: None,
        tier_c_audience: None,
    });
    augmenter
}

#[tokio::test]
async fn stamps_identity_header_on_post() {
    let (addr, state) = spawn_server().await;
    let augmenter = identity_augmenter_with_context();

    let url = format!("http://{addr}/mcp/sse");
    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        Some(augmenter),
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");

    sink.send(ping_request(11)).await.expect("send ping");

    // Drain one inbound response so we know the round-trip completed before
    // asserting on the recorded headers.
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("response timed out");

    let headers = state
        .last_post_headers
        .lock()
        .await
        .clone()
        .expect("post recorded");
    let identity = headers
        .get(IDENTITY_HEADER)
        .expect("X-MCP-Identity stamped on POST");
    assert!(
        !identity.is_empty(),
        "identity header should hold the gateway-minted JWT",
    );
}

/// A manifest `auth.bearer_env` bearer must ride BOTH the SSE GET (stream open)
/// and every message POST — the upstream auth gate (crawl4ai 0.9.0) 401s any
/// unauthenticated path. The `ping` is a non-tool JSON-RPC message, so this also
/// proves the bearer rides every outbound message, not just tool calls.
#[tokio::test]
async fn stamps_static_bearer_on_get_and_post() {
    let (addr, state) = spawn_server().await;
    let url = format!("http://{addr}/mcp/sse");

    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        Some("secret-bearer".to_string()),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");

    sink.send(ping_request(21)).await.expect("send ping");
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("response timed out");

    let get_headers = state
        .last_get_headers
        .lock()
        .await
        .clone()
        .expect("GET recorded");
    assert_eq!(
        get_headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer secret-bearer"),
        "SSE GET must carry the static bearer",
    );

    let post_headers = state
        .last_post_headers
        .lock()
        .await
        .clone()
        .expect("POST recorded");
    assert_eq!(
        post_headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer secret-bearer"),
        "SSE message POST must carry the static bearer",
    );
}

/// The static bearer (`Authorization`) and per-caller identity
/// (`X-MCP-Identity`) are distinct headers, so a Tier-B augmenter and a static
/// bearer coexist without clobbering each other on an SSE upstream.
#[tokio::test]
async fn static_bearer_coexists_with_identity_header() {
    let (addr, state) = spawn_server().await;
    let augmenter = identity_augmenter_with_context();
    let url = format!("http://{addr}/mcp/sse");

    let (mut sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        Some(augmenter),
        Some("secret-bearer".to_string()),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("connect");

    sink.send(ping_request(31)).await.expect("send ping");
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("response timed out");

    let post_headers = state
        .last_post_headers
        .lock()
        .await
        .clone()
        .expect("POST recorded");
    assert_eq!(
        post_headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer secret-bearer"),
        "static bearer present alongside identity",
    );
    assert!(
        post_headers.get(IDENTITY_HEADER).is_some(),
        "X-MCP-Identity present alongside the static bearer",
    );
}
