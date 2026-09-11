//! Coverage for the reqwest GET → `sse-stream` parse → reader-task path
//! against a server that ends the SSE stream cleanly. Exists alongside
//! `sse_transport.rs` (which tests the happy round-trip) so the
//! test → reqwest::Client::get + sse_stream::SseStream chain on the
//! waygate-upstream crate stays walkable. Both reqwest and sse-stream are
//! dependency-bump-prone, so we want one test that exercises both at
//! once and surfaces a regression in either.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use waygate_upstream::{http_policy, sse_client};

fn streaming_client() -> reqwest::Client {
    http_policy::streaming_client().expect("production streaming client policy")
}

#[derive(Default, Clone)]
struct State502;

async fn always_502(State(_): State<State502>) -> Response {
    Response::builder()
        .status(502)
        .body(axum::body::Body::from("upstream down"))
        .unwrap()
}

#[tokio::test]
async fn connect_to_5xx_surfaces_status_error() {
    let app = Router::new()
        .route("/mcp/sse", get(always_502))
        .with_state(State502);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    .expect_err("502 must abort connect");
    match err {
        sse_client::SseConnectError::Status(s) => assert_eq!(s.as_u16(), 502),
        other => panic!("expected Status(502), got {other:?}"),
    }
}

#[tokio::test]
async fn handshake_deadline_includes_initial_response_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });

    let url = format!("http://{addr}/mcp/sse");
    let err = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_millis(50),
        Duration::from_secs(2),
    )
    .await
    .expect_err("a peer that withholds headers must hit the handshake deadline");
    assert!(
        matches!(err, sse_client::SseConnectError::EndpointTimeout(_)),
        "got {err:?}",
    );
}

#[tokio::test]
#[ignore = "wall-clock connection-refusal race; manual diagnostic only"]
async fn connect_to_unreachable_host_surfaces_http_error() {
    // Bind a listener to grab a free port, then drop it so the port is
    // (very likely, briefly) unbound. Connection refusal still races the
    // client deadline and other users of the port, so this is a manual diagnostic.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let url = format!("http://{addr}/mcp/sse");
    let err = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_millis(500),
        Duration::from_secs(2),
    )
    .await
    .expect_err("connect must fail");
    // The exact reqwest::Error kind on a refused TCP connection has shifted
    // between minor versions before. Pinning the SseConnectError variant
    // (rather than the underlying error kind) is the contract we care about.
    assert!(
        matches!(err, sse_client::SseConnectError::Http(_)),
        "got {err:?}",
    );
}

// An unsupported scheme fails inside reqwest without a socket or scheduler race.
#[tokio::test(start_paused = true)]
async fn request_construction_failure_surfaces_http_error() {
    let err = sse_client::connect(
        "file:///synthetic-sse-endpoint",
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect_err("reqwest cannot send a file URL");
    assert!(
        matches!(err, sse_client::SseConnectError::Http(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn server_drops_stream_after_endpoint_yields_clean_close() {
    // The handler emits the `endpoint` event — completing the handshake —
    // and then drops the sender, ending the SSE stream cleanly. The reader
    // task in `sse_client` must observe the EOF and close the inbound
    // channel rather than hang forever.
    let app = Router::new().route(
        "/mcp/sse",
        get(|| async {
            let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(4);
            tx.send(Ok(Event::default()
                .event("endpoint")
                .data("/mcp/messages?session_id=test")))
                .await
                .unwrap();
            // Drop sender → stream ends.
            drop(tx);
            Sse::new(ReceiverStream::new(rx))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = format!("http://{addr}/mcp/sse");
    let (_sink, mut stream) = sse_client::connect(
        &url,
        streaming_client(),
        None,
        None,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .await
    .expect("handshake must succeed before close");

    // The inbound stream must terminate (yield None) within a bounded
    // window — no hang. This is the regression the reqwest + sse-stream
    // bumps could plausibly cause: a streaming-body change that loses the
    // final EOF and leaves the reader task pinned.
    let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("stream did not close in time");
    assert!(
        next.is_none(),
        "expected stream end after server drop, got {next:?}",
    );
}
