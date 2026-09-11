//! End-to-end sanity test: a span emitted through `tracing` while
//! `waygate_telemetry::init` is configured with an OTLP endpoint reaches a
//! mock tonic/gRPC collector. Exercises the full pipeline: tracing subscriber
//! → OTel tracer provider → batch exporter → tonic export RPC.
//!
//! `init` touches process-global tracing/otel state, so the test lives in its
//! own integration binary (one process per `tests/*.rs` file).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Clone, Default)]
struct MockCollector {
    received: Arc<Mutex<Vec<ExportTraceServiceRequest>>>,
}

#[tonic::async_trait]
impl TraceService for MockCollector {
    async fn export(
        &self,
        req: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        self.received.lock().unwrap().push(req.into_inner());
        Ok(Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn span_reaches_mock_otlp_collector() {
    // Bind a tokio listener on a random port, hand it to tonic as an incoming
    // stream so we avoid the two-bind race that comes with `serve(addr)`.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock collector");
    let addr = listener.local_addr().expect("listener local_addr");

    let collector = MockCollector::default();
    let received = collector.received.clone();

    let server_handle = tokio::spawn(
        Server::builder()
            .add_service(TraceServiceServer::new(collector))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    let cfg = waygate_telemetry::TelemetryConfig {
        service_name: "gateway-telemetry-test".into(),
        service_version: Some("0.0.0-test".into()),
        otlp_endpoint: Some(format!("http://{addr}")),
        deployment_env: Some("test".into()),
        log_filter: Some("info".into()),
    };

    let guard = waygate_telemetry::init(cfg).expect("init telemetry");

    // Emit a span that should travel through the batch exporter. The
    // tracing→OTel bridge exports only when the tracing span is *closed*
    // (dropped), so scope it tightly.
    {
        let _span = tracing::info_span!("probe_span", probe = "otlp-roundtrip").entered();
        tracing::info!("inside probe span");
    }

    // Force-flush through the batch exporter. We explicitly do NOT rely on
    // Drop-time shutdown here: shutdown is synchronous and blocks the current
    // tokio task, which can starve the batch worker on a small runtime and
    // deadlock. Production is unaffected — the gateway drops the guard after
    // `axum::serve` returns, by which point the runtime is winding down.
    guard.force_flush();

    // The export RPC lands on the mock server asynchronously after flush; poll
    // for it so we aren't racing a slow runtime.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            panic!("mock collector received no spans within 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let requests = received.lock().unwrap();
    let rs = requests
        .iter()
        .flat_map(|r| r.resource_spans.iter())
        .next()
        .expect("at least one ResourceSpans");

    // service.name resource attribute must match what we configured.
    let resource = rs.resource.as_ref().expect("resource present");
    let service_name = resource
        .attributes
        .iter()
        .find(|kv| kv.key == "service.name")
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| v.value.as_ref())
        .and_then(|v| match v {
            opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s) => {
                Some(s.clone())
            }
            _ => None,
        })
        .expect("service.name attribute");
    assert_eq!(service_name, "gateway-telemetry-test");

    // And at least one span named `probe_span` came through.
    let names: Vec<String> = rs
        .scope_spans
        .iter()
        .flat_map(|ss| ss.spans.iter())
        .map(|s| s.name.clone())
        .collect();
    assert!(
        names.iter().any(|n| n == "probe_span"),
        "expected span named `probe_span` in {names:?}"
    );

    server_handle.abort();
}
