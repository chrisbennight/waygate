//! End-to-end `_meta` propagation through a real span: baggage extracted on
//! the inbound leg (`adopt_parent`) must reappear on the outbound leg
//! (`inject_span`), because tracing-opentelemetry keeps the adopted parent
//! context — baggage included — on the span. Lives in its own integration
//! binary because `init()` touches process-global tracing/otel state (one
//! global subscriber per process).

use serde_json::{Map, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_baggage_reappears_on_outbound_meta() {
    let cfg = waygate_telemetry::TelemetryConfig {
        service_name: "baggage-propagation-test".into(),
        service_version: Some("0.0.0-test".into()),
        // A `Some(endpoint)` installs the OpenTelemetry layer, which is what
        // this test exercises. The batch exporter is never flushed (only the
        // span's context is read), so nothing is actually sent to it.
        otlp_endpoint: Some("http://127.0.0.1:4317".into()),
        deployment_env: Some("test".into()),
        log_filter: Some("info".into()),
    };
    let _guard = waygate_telemetry::init(cfg).expect("init telemetry");

    // Inbound `_meta` as an agent would send it: W3C trace context plus one
    // baggage entry.
    let mut inbound = Map::new();
    inbound.insert(
        "traceparent".into(),
        Value::String("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
    );
    inbound.insert("baggage".into(), Value::String("tenant.hint=acme".into()));

    let span = tracing::info_span!("inbound_request");
    let adopted = {
        let _entered = span.enter();
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &inbound)
    };
    assert!(adopted, "traceparent present, layer installed → adoption");

    // Outbound `_meta` built the way the upstream pool builds it: fresh map,
    // populated only by injection from the current span.
    let mut outbound = Map::new();
    {
        let _entered = span.enter();
        waygate_telemetry::propagation::inject_span(&tracing::Span::current(), &mut outbound);
    }

    let traceparent = outbound
        .get("traceparent")
        .and_then(Value::as_str)
        .expect("outbound carries trace context");
    assert!(
        traceparent.contains("4bf92f3577b34da6a3ce929d0e0e4736"),
        "outbound continues the inbound trace: {traceparent}"
    );
    assert_eq!(
        outbound.get("baggage").and_then(Value::as_str),
        Some("tenant.hint=acme"),
        "inbound baggage relayed verbatim: {outbound:?}"
    );

    // A request without baggage must not grow a baggage key on the way out.
    let mut inbound_no_bag = Map::new();
    inbound_no_bag.insert(
        "traceparent".into(),
        Value::String("00-11111111111111111111111111111111-2222222222222222-01".into()),
    );
    let span2 = tracing::info_span!("inbound_request_no_baggage");
    let mut outbound2 = Map::new();
    {
        let _entered = span2.enter();
        waygate_telemetry::propagation::adopt_parent(&tracing::Span::current(), &inbound_no_bag);
        waygate_telemetry::propagation::inject_span(&tracing::Span::current(), &mut outbound2);
    }
    assert!(outbound2.contains_key("traceparent"));
    assert!(
        !outbound2.contains_key("baggage"),
        "no baggage in → no baggage out: {outbound2:?}"
    );
}
