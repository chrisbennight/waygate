//! W3C trace-context and baggage propagation over the MCP `_meta` property
//! bag.
//!
//! MCP is transport-independent: stdio has no HTTP headers, and a single
//! Streamable-HTTP request multiplexes many JSON-RPC messages, so MCP
//! 2026-07-28 reserves the `_meta` keys `traceparent`, `tracestate`, and
//! `baggage` for OpenTelemetry context propagation (their values follow the
//! W3C Trace Context and W3C Baggage formats), matching the OTel MCP
//! semantic conventions
//! (<https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/>). This module
//! bridges that body-carried context to and from the active OpenTelemetry
//! context using the globally-installed text-map propagator (set in
//! [`crate::init`] from [`text_map_propagator`]).
//!
//! Kept rmcp-free: callers pass the `_meta` bag as a plain
//! [`serde_json::Map`] (rmcp's `Meta` is a newtype over exactly that), so this
//! crate takes no rmcp dependency. The gateway is both an MCP *server* (it
//! adopts the agent's parent on inbound `tools/call`) and an MCP *client* (it
//! injects its own span into the outbound upstream call), so both directions
//! live here.
//!
//! Baggage rides with trace context: entries extracted alongside a
//! `traceparent` live on the adopted parent [`Context`], survive on the
//! span (tracing-opentelemetry keeps the full parent context), and are
//! re-injected on the outbound leg. The gateway never originates baggage —
//! it only relays what the caller sent — and a `baggage` key with no
//! `traceparent` is not adopted: adoption works by re-parenting the span,
//! and there is no parent to adopt from a baggage-only carrier. The SDK's
//! extractor enforces the W3C limits (64 entries, 8 KiB total), which bounds
//! what an untrusted caller can make the gateway forward upstream.

use opentelemetry::propagation::{Extractor, Injector, TextMapCompositePropagator};
use opentelemetry::trace::TraceContextExt;
use opentelemetry::Context;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use serde_json::{Map, Value};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// W3C key written/read by the text-map propagator. Its presence is what
/// distinguishes a `_meta` carrying trace context from one that only carries,
/// e.g., a `progressToken`.
const TRACEPARENT: &str = "traceparent";

/// The propagator set the gateway speaks over `_meta`: W3C trace context
/// (`traceparent` / `tracestate`) plus W3C baggage (`baggage`) — exactly the
/// three keys MCP 2026-07-28 reserves for OpenTelemetry propagation.
/// [`crate::init`] installs this globally; it is constructed here so tests
/// exercise the same propagator production runs with.
pub fn text_map_propagator() -> TextMapCompositePropagator {
    TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ])
}

/// Read-side adapter exposing the string-valued entries of a `_meta` map to
/// the propagator. Non-string values (`progressToken`, structured payloads)
/// are simply invisible to extraction.
struct MetaExtractor<'a>(&'a Map<String, Value>);

impl Extractor for MetaExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Write-side adapter letting the propagator set string fields
/// (`traceparent`, `tracestate`) on a `_meta` map.
struct MetaInjector<'a>(&'a mut Map<String, Value>);

impl Injector for MetaInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_owned(), Value::String(value));
    }
}

/// Extract a remote parent [`Context`] from an MCP `_meta` map, or `None` when
/// the map carries no W3C `traceparent` — or carries one that does not parse
/// to a valid span context. Returning `None` (rather than a context with an
/// invalid remote span) lets callers leave the span's natural parent intact
/// when there is nothing to adopt, and the validity check keeps baggage from
/// outliving the trace context it rode in on: with a garbled `traceparent`,
/// the composite extraction would still parse `baggage` separately, and
/// adopting that context would detach the span AND relay baggage with no
/// trace context — exactly the baggage-only posture the module docs rule
/// out. When a valid `traceparent` is accompanied by a `baggage` key, the
/// entries are carried on the returned context.
pub fn extract_parent(meta: &Map<String, Value>) -> Option<Context> {
    if !meta.contains_key(TRACEPARENT) {
        return None;
    }
    let cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&MetaExtractor(meta)));
    cx.span().span_context().is_valid().then_some(cx)
}

/// Adopt a remote parent for `span` from an MCP `_meta` carrier when it holds
/// a `traceparent`. Returns `true` if a parent was adopted; `false` when there
/// was no `traceparent` to adopt or the span is not attached to an
/// OpenTelemetry subscriber (e.g. dev mode with no tracer provider). Telemetry
/// is best-effort, so a failed adoption is logged at debug and never surfaced
/// to the request path. Safe to call unconditionally on every request.
pub fn adopt_parent(span: &Span, meta: &Map<String, Value>) -> bool {
    match extract_parent(meta) {
        Some(parent) => match span.set_parent(parent) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(error = %e, "failed to adopt remote parent from _meta");
                false
            }
        },
        None => false,
    }
}

/// Inject `span`'s OpenTelemetry context into an MCP `_meta` map so a
/// downstream MCP server can continue the trace. Baggage entries on the
/// span's context (adopted from the inbound `_meta`) are re-injected under
/// the `baggage` key; an empty baggage writes no key at all. When no tracer
/// provider is installed (e.g. local dev with `OTEL_EXPORTER_OTLP_ENDPOINT`
/// unset) the span has no valid span context and the trace-context
/// propagator writes nothing.
pub fn inject_span(span: &Span, meta: &mut Map<String, Value>) {
    let cx = span.context();
    opentelemetry::global::get_text_map_propagator(|p| {
        p.inject_context(&cx, &mut MetaInjector(meta))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::baggage::{Baggage, BaggageExt};
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };

    // The propagator is process-global; install the production set so these
    // tests exercise exactly what init() installs (trace context + baggage)
    // without depending on init() having run in another test binary.
    fn ensure_propagator() {
        opentelemetry::global::set_text_map_propagator(text_map_propagator());
    }

    fn known_remote_context() -> (Context, TraceId, SpanId) {
        let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let span_id = SpanId::from_hex("00f067aa0ba902b7").unwrap();
        let sc = SpanContext::new(
            trace_id,
            span_id,
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        );
        (
            Context::new().with_remote_span_context(sc),
            trace_id,
            span_id,
        )
    }

    #[test]
    fn extract_parent_none_without_traceparent() {
        ensure_propagator();
        let mut meta = Map::new();
        meta.insert("progressToken".into(), Value::String("p1".into()));
        assert!(extract_parent(&meta).is_none());
    }

    #[test]
    fn context_round_trips_through_meta() {
        ensure_propagator();
        let (cx, trace_id, span_id) = known_remote_context();

        // Inject the known context into a fresh `_meta` map.
        let mut meta = Map::new();
        opentelemetry::global::get_text_map_propagator(|p| {
            p.inject_context(&cx, &mut MetaInjector(&mut meta))
        });
        assert!(
            meta.contains_key(TRACEPARENT),
            "traceparent must be written: {meta:?}"
        );

        // Extract it back; the remote parent must carry the same ids.
        let extracted = extract_parent(&meta).expect("traceparent present");
        assert_eq!(extracted.span().span_context().trace_id(), trace_id);
        assert_eq!(extracted.span().span_context().span_id(), span_id);
    }

    #[test]
    fn adopt_parent_false_on_empty() {
        ensure_propagator();
        // No traceparent → no adoption, and set_parent is never called.
        assert!(!adopt_parent(&Span::none(), &Map::new()));
    }

    #[test]
    fn baggage_rides_with_trace_context() {
        ensure_propagator();
        let (cx, trace_id, _) = known_remote_context();
        let mut bag = Baggage::new();
        // `insert` returns the *previous* value — None on a first insert.
        let _ = bag.insert("tenant.hint", "acme");
        let _ = bag.insert("session.tier", "gold");
        let cx = cx.with_baggage(bag);

        let mut meta = Map::new();
        opentelemetry::global::get_text_map_propagator(|p| {
            p.inject_context(&cx, &mut MetaInjector(&mut meta))
        });
        assert!(meta.contains_key("baggage"), "baggage written: {meta:?}");

        let extracted = extract_parent(&meta).expect("traceparent present");
        assert_eq!(extracted.span().span_context().trace_id(), trace_id);
        let baggage = extracted.baggage();
        assert_eq!(
            baggage.get("tenant.hint").map(|v| v.as_str().to_owned()),
            Some("acme".to_owned())
        );
        assert_eq!(
            baggage.get("session.tier").map(|v| v.as_str().to_owned()),
            Some("gold".to_owned())
        );
    }

    #[test]
    fn invalid_traceparent_is_not_adopted_even_with_baggage() {
        ensure_propagator();
        // A present-but-garbled traceparent must behave like an absent one:
        // no adoption, and no baggage relayed on its own — otherwise the
        // composite extraction would hand back a context with parsed baggage
        // but no valid remote span, detaching the span from its natural
        // parent while violating the baggage-rides-with-trace-context rule.
        let mut meta = Map::new();
        meta.insert(
            "traceparent".into(),
            Value::String("not-a-w3c-value".into()),
        );
        meta.insert("baggage".into(), Value::String("k=v".into()));
        assert!(extract_parent(&meta).is_none());
        assert!(!adopt_parent(&Span::none(), &meta));

        // Non-string values are invisible to extraction and equally invalid.
        let mut meta = Map::new();
        meta.insert("traceparent".into(), Value::Bool(true));
        assert!(extract_parent(&meta).is_none());
    }

    #[test]
    fn baggage_without_traceparent_is_not_adopted() {
        ensure_propagator();
        // The module contract: baggage rides with trace context, never alone —
        // there is no parent to adopt from a baggage-only carrier.
        let mut meta = Map::new();
        meta.insert("baggage".into(), Value::String("k=v".into()));
        assert!(extract_parent(&meta).is_none());
        assert!(!adopt_parent(&Span::none(), &meta));
    }

    #[test]
    fn empty_baggage_writes_no_key() {
        ensure_propagator();
        // A context with trace context but no baggage entries must not emit
        // an empty `baggage` key on the wire.
        let (cx, _, _) = known_remote_context();
        let mut meta = Map::new();
        opentelemetry::global::get_text_map_propagator(|p| {
            p.inject_context(&cx, &mut MetaInjector(&mut meta))
        });
        assert!(meta.contains_key(TRACEPARENT));
        assert!(!meta.contains_key("baggage"), "no empty baggage: {meta:?}");
    }
}
