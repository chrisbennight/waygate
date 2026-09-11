//! Correlating audit and log records with the active trace.
//!
//! [`current_trace_id`] lifts the W3C trace id off the current `tracing`
//! span's OpenTelemetry context so an `AuditEvent` can be stamped with it —
//! letting a Grafana/Tempo trace pivot to its audit rows and back. It returns
//! `None` when no OpenTelemetry layer is installed (dev mode,
//! `OTEL_EXPORTER_OTLP_ENDPOINT` unset) or the current span has no valid
//! context, so callers stay a no-op in those modes.

use opentelemetry::trace::TraceContextExt;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The 32-hex-character W3C trace id of the current span's OpenTelemetry
/// context, or `None` when there is no valid context to read.
pub fn current_trace_id() -> Option<String> {
    let span_context = Span::current().context().span().span_context().clone();
    span_context
        .is_valid()
        .then(|| span_context.trace_id().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_trace_id_is_none_without_provider() {
        // No OpenTelemetry layer is installed in the lib unit-test binary, so
        // the current span yields an invalid context. The valid path (a real
        // tracer provider returning a non-zero id) is covered by
        // `tests/trace_correlation.rs`.
        assert!(current_trace_id().is_none());
    }
}
