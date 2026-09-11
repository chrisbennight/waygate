//! `current_trace_id()` returns the active span's trace id once an
//! OpenTelemetry layer is installed by `init()`. Lives in its own integration
//! binary because `init()` touches process-global tracing/otel state (one
//! global subscriber per process).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn current_trace_id_reflects_active_span() {
    let cfg = waygate_telemetry::TelemetryConfig {
        service_name: "trace-correlation-test".into(),
        service_version: Some("0.0.0-test".into()),
        // A `Some(endpoint)` installs the OpenTelemetry layer, which is what we
        // exercise here. The batch exporter is never flushed in this test (we
        // only read the span context), so nothing is actually sent to it.
        otlp_endpoint: Some("http://127.0.0.1:4317".into()),
        deployment_env: Some("test".into()),
        log_filter: Some("info".into()),
    };
    let _guard = waygate_telemetry::init(cfg).expect("init telemetry");

    // Within an instrumented span the current trace id is a valid 32-hex id.
    let span = tracing::info_span!("correlation_probe");
    let trace_id = {
        let _entered = span.enter();
        waygate_telemetry::correlation::current_trace_id()
    };
    let trace_id = trace_id.expect("trace id present within an active span");

    assert_eq!(
        trace_id.len(),
        32,
        "W3C trace id is 32 hex chars: {trace_id}"
    );
    assert!(
        trace_id.chars().all(|c| c.is_ascii_hexdigit()),
        "trace id must be hex: {trace_id}"
    );
    assert_ne!(trace_id, "0".repeat(32), "trace id must be non-zero");

    // Regression guard for asynchronous evidence handoff: queue workers do not
    // carry the request span, so the outer recorder must capture the id before
    // submission instead of reading it in the worker. A bare spawned task
    // models that context boundary and proves both halves of the invariant.
    let captured = {
        let probe = tracing::info_span!("detached_probe");
        let _entered = probe.enter();
        waygate_telemetry::correlation::current_trace_id()
    };
    assert!(
        captured.is_some(),
        "id captured on the request task (before spawn) must be present"
    );
    let read_inside_bare_spawn =
        tokio::spawn(async { waygate_telemetry::correlation::current_trace_id() })
            .await
            .unwrap();
    assert!(
        read_inside_bare_spawn.is_none(),
        "a bare spawned task has no active span; reading the id inside it must be None"
    );
}
