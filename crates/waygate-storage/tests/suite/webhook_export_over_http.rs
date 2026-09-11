//! Live-socket coverage for [`waygate_storage::WebhookExporter`]'s real POST
//! path (`crates/waygate-storage/src/exporter.rs`).
//!
//! The in-crate unit tests cover construction (URL validation, scheme
//! rejection), URL sanitisation, and the pure status classifier — but none
//! drives an actual `reqwest` POST over a socket. So a regression in the
//! `reqwest`/`hyper`/`http`/`serde_json` stack (the request never built, the
//! `.json()` body serialised wrong, the per-event headers dropped, or the
//! response status mis-read back into Ok/Transient/Permanent) would not trip
//! CI. This file stands up a tiny axum app on `127.0.0.1:0` — mirroring the
//! loopback harness in `crates/waygate-oidc/tests/suite/jwks_over_http.rs` and
//! `crates/waygate-upstream/tests/suite/token_exchange_over_http.rs` — and walks
//! `Exporter::export` → `Client::post → .json → .send` unmocked.
//!
//! Side-effect rules: loopback only (`127.0.0.1:0`), no real network, no DB,
//! no credentials. The server captures each request into `Arc<Mutex<…>>`
//! state the assertions read back.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use uuid::Uuid;

use waygate_storage::{ExportError, Exporter, WebhookExporter};

/// What the loopback sink recorded about the most recent POST.
#[derive(Default)]
struct Captured {
    hits: u32,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
struct SinkState {
    captured: Arc<Mutex<Captured>>,
    /// Status code the handler replies with. Lets one server exercise the
    /// 2xx / 4xx / 5xx classification arms without re-binding a socket.
    reply_status: Arc<AtomicU16>,
}

impl SinkState {
    fn new() -> Self {
        Self {
            captured: Arc::new(Mutex::new(Captured::default())),
            reply_status: Arc::new(AtomicU16::new(204)),
        }
    }
}

async fn sink_handler(State(state): State<SinkState>, headers: HeaderMap, body: Bytes) -> Response {
    {
        let mut cap = state.captured.lock().unwrap();
        cap.hits += 1;
        // The router matched `/evidence/webhook`, so the request line path is
        // implied; record it explicitly from the route for an exact assert.
        cap.path = "/evidence/webhook".to_owned();
        cap.headers = headers;
        cap.body = body.to_vec();
    }
    let status = state.reply_status.load(Ordering::SeqCst);
    Response::builder()
        .status(status)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn spawn_sink() -> (SocketAddr, SinkState) {
    let state = SinkState::new();
    let app = Router::new()
        .route("/evidence/webhook", post(sink_handler))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}

fn sample_payload() -> Value {
    json!({
        "category": "ToolInvocation",
        "tool": "example-messages.send_message",
        "principal_sub": "alice",
    })
}

/// Happy path: a real POST reaches the sink with the configured URL's path,
/// `Content-Type: application/json`, the per-event `x-evidence-event-id`
/// dedupe header carrying the exporter's `event_id`, and the exact JSON body
/// the exporter was handed. A 2xx reply classifies as `Ok(())`.
#[tokio::test]
async fn export_posts_payload_with_headers_and_succeeds_on_2xx() {
    let (addr, sink) = spawn_sink().await;
    sink.reply_status.store(204, Ordering::SeqCst);

    let exporter = WebhookExporter::new(format!("http://{addr}/evidence/webhook"))
        .expect("construct webhook exporter");
    let event_id = Uuid::now_v7();
    let payload = sample_payload();

    exporter
        .export("webhook", event_id, &payload)
        .await
        .expect("2xx reply must classify as Ok");

    let cap = sink.captured.lock().unwrap();
    assert_eq!(cap.hits, 1, "sink must receive exactly one POST");
    assert_eq!(
        cap.path, "/evidence/webhook",
        "POST must hit the configured path"
    );

    let content_type = cap
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/json"),
        "exporter must send application/json, got {content_type:?}",
    );

    let event_hdr = cap
        .headers
        .get("x-evidence-event-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(
        event_hdr,
        event_id.to_string(),
        "x-evidence-event-id must carry the event_id so the remote can dedupe retries",
    );

    // Body must round-trip back to the exact payload the exporter was given —
    // proves `.json(payload)` serialised the value, not some other shape.
    let received: Value =
        serde_json::from_slice(&cap.body).expect("request body must be valid JSON");
    assert_eq!(
        received, payload,
        "POST body must be the JSON payload handed to export()",
    );
}

/// A 4xx (other than 408/429) on a well-formed payload is a genuine
/// client-rejection: the exporter must classify it `Permanent` so the drain
/// dead-letters the row instead of retrying forever. Exercises the real
/// `resp.status()` read-back over the socket, not the pure classifier.
#[tokio::test]
async fn export_maps_4xx_to_permanent() {
    let (addr, sink) = spawn_sink().await;
    sink.reply_status.store(400, Ordering::SeqCst);

    let exporter = WebhookExporter::new(format!("http://{addr}/evidence/webhook"))
        .expect("construct webhook exporter");
    let err = exporter
        .export("webhook", Uuid::now_v7(), &sample_payload())
        .await
        .expect_err("400 must error");
    assert!(
        matches!(err, ExportError::Permanent(_)),
        "400 on a well-formed payload must be Permanent, got {err:?}",
    );
}

/// A 5xx is a server-side hiccup: the exporter must classify it `Transient`
/// so the drain retries after backoff.
#[tokio::test]
async fn export_maps_5xx_to_transient() {
    let (addr, sink) = spawn_sink().await;
    sink.reply_status.store(503, Ordering::SeqCst);

    let exporter = WebhookExporter::new(format!("http://{addr}/evidence/webhook"))
        .expect("construct webhook exporter");
    let err = exporter
        .export("webhook", Uuid::now_v7(), &sample_payload())
        .await
        .expect_err("503 must error");
    assert!(
        matches!(err, ExportError::Transient(_)),
        "503 must be Transient (retry after backoff), got {err:?}",
    );
}

/// 429 (rate limit) is the documented retryable 4xx: it must be `Transient`,
/// not `Permanent`. Pins the carve-out end-to-end over the socket — a
/// regression that reverted to a blanket `is_client_error → Permanent`
/// mapping would dead-letter the first rate-limited row.
#[tokio::test]
async fn export_maps_429_to_transient() {
    let (addr, sink) = spawn_sink().await;
    sink.reply_status.store(429, Ordering::SeqCst);

    let exporter = WebhookExporter::new(format!("http://{addr}/evidence/webhook"))
        .expect("construct webhook exporter");
    let err = exporter
        .export("webhook", Uuid::now_v7(), &sample_payload())
        .await
        .expect_err("429 must error");
    assert!(
        matches!(err, ExportError::Transient(_)),
        "429 Too Many Requests must retry (Transient), got {err:?}",
    );
}

/// Connection refused (no listener at the target) must surface as
/// `Transient` — a network blip, retryable. Uses a port we never bound so
/// the connect fails fast without any real-network egress.
#[tokio::test]
async fn export_maps_connection_failure_to_transient() {
    // Bind then immediately drop the listener so the port is (almost
    // certainly) closed; the exporter's connect attempt fails locally.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let exporter = WebhookExporter::new(format!("http://{addr}/evidence/webhook"))
        .expect("construct webhook exporter");
    let err = exporter
        .export("webhook", Uuid::now_v7(), &sample_payload())
        .await
        .expect_err("connect to a closed port must error");
    assert!(
        matches!(err, ExportError::Transient(_)),
        "connection failure must be Transient, got {err:?}",
    );
}
