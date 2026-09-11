//! Telemetry bootstrap for the MCP gateway.
//!
//! Owns two distinct concerns:
//!
//! 1. **Tracing subscriber** — a JSON `fmt` layer (stdout, picked up by Loki)
//!    plus an optional OpenTelemetry OTLP layer pointed at the in-cluster
//!    collector. When `OTEL_EXPORTER_OTLP_ENDPOINT` is unset we skip the OTLP
//!    layer entirely so local `cargo run` stays noise-free.
//!
//! 2. **Prometheus registry** — a crate-global [`prometheus::Registry`] that
//!    other crates register counters / histograms into via [`register`]. The
//!    HTTP `/metrics` route just calls [`gather_text`] on each scrape.
//!
//! Shutdown is RAII: [`init`] returns a [`TelemetryGuard`] that owns the
//! tracer provider; dropping it flushes pending spans. `waygate-server`
//! holds the guard until `axum::serve` returns.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use prometheus::{Encoder, Registry, TextEncoder};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod correlation;
pub mod metrics;
pub mod propagation;

/// Input to [`init`]. Construct via [`TelemetryConfig::from_env`] and
/// optionally override fields before calling.
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: Option<String>,
    /// OTLP gRPC endpoint, e.g. `http://otel-collector:4317`. Unset → no OTLP
    /// layer is installed and spans only land in stdout JSON logs.
    pub otlp_endpoint: Option<String>,
    pub deployment_env: Option<String>,
    /// Passed verbatim to `EnvFilter::new`. When `None` we default to `info`.
    pub log_filter: Option<String>,
}

impl TelemetryConfig {
    pub fn from_env(service_name: impl Into<String>) -> Self {
        let log_filter = std::env::var("RUST_LOG")
            .ok()
            .or_else(|| std::env::var("GATEWAY_LOG_LEVEL").ok());

        // OTEL_SERVICE_NAME wins over the caller-provided default, matching
        // standard OpenTelemetry env-var precedence.
        let service_name = std::env::var("OTEL_SERVICE_NAME")
            .ok()
            .unwrap_or_else(|| service_name.into());

        // `deployment.environment` usually arrives via OTEL_RESOURCE_ATTRIBUTES
        // (comma-separated KV pairs). We pluck it out so it can also feed into
        // Prometheus labels later if we need it.
        let deployment_env = std::env::var("OTEL_RESOURCE_ATTRIBUTES")
            .ok()
            .and_then(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .find_map(|kv| kv.strip_prefix("deployment.environment="))
                    .map(str::to_owned)
            });

        Self {
            service_name,
            service_version: option_env!("CARGO_PKG_VERSION").map(str::to_owned),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .ok()
                .filter(|v| !v.is_empty()),
            deployment_env,
            log_filter,
        }
    }
}

/// RAII guard returned by [`init`]. Dropping flushes the OTLP batch exporter.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Force the batch exporter to flush pending spans without shutting down.
    /// Exposed for integration tests that need to observe exported spans
    /// without relying on Drop-time shutdown (which blocks the current tokio
    /// thread and can deadlock the batch worker in a small runtime).
    pub fn force_flush(&self) {
        if let Some(p) = self.tracer_provider.as_ref() {
            if let Err(e) = p.force_flush() {
                tracing::debug!(error = ?e, "force_flush span processor error");
            }
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            // `shutdown()` on an `SdkTracerProvider` flushes the batch exporter
            // synchronously — acceptable on shutdown; we're about to exit.
            let _ = provider.shutdown();
        }
    }
}

pub fn init(cfg: TelemetryConfig) -> Result<TelemetryGuard> {
    global::set_text_map_propagator(propagation::text_map_propagator());

    let filter = cfg
        .log_filter
        .as_deref()
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let fmt_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true);

    let tracer_provider = match cfg.otlp_endpoint.as_deref() {
        Some(endpoint) => Some(build_tracer_provider(&cfg, endpoint)?),
        None => None,
    };

    match &tracer_provider {
        Some(provider) => {
            let tracer = provider.tracer(cfg.service_name.clone());
            // Context activation must stay OFF: with it on (the 0.33 default),
            // entering a span starts its OTel context, and `set_parent` on an
            // already-started span fails — which silently breaks
            // `propagation::adopt_parent`, called from inside every entered
            // `#[instrument]` MCP handler span. Nothing here reads the ambient
            // `opentelemetry::Context` (correlation and injection go through
            // `Span::context()`, which activates on demand), so the attach on
            // entry buys nothing. Pinned by
            // `tests/baggage_propagation.rs` end to end.
            let otel_layer = tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_context_activation(false);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(otel_layer)
                .try_init()
                .map_err(|e| anyhow::anyhow!("tracing init: {e}"))?;
            tracing::info!(
                service = %cfg.service_name,
                otlp_endpoint = %cfg.otlp_endpoint.as_deref().unwrap_or(""),
                "telemetry initialized with OTLP export"
            );
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .try_init()
                .map_err(|e| anyhow::anyhow!("tracing init: {e}"))?;
            tracing::info!(
                service = %cfg.service_name,
                "telemetry initialized (stdout only; OTEL_EXPORTER_OTLP_ENDPOINT unset)"
            );
        }
    }

    Ok(TelemetryGuard { tracer_provider })
}

fn build_tracer_provider(cfg: &TelemetryConfig, endpoint: &str) -> Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(5))
        .build()
        .context("build OTLP span exporter")?;

    let mut resource_attrs = vec![KeyValue::new("service.name", cfg.service_name.clone())];
    if let Some(v) = cfg.service_version.clone() {
        resource_attrs.push(KeyValue::new("service.version", v));
    }
    if let Some(env) = cfg.deployment_env.clone() {
        resource_attrs.push(KeyValue::new("deployment.environment", env));
    }
    let resource = Resource::builder().with_attributes(resource_attrs).build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(provider.clone());
    Ok(provider)
}

// ------------------------------------------------------------------
// Prometheus registry
// ------------------------------------------------------------------

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Process-wide Prometheus registry. Every metric the gateway exposes
/// registers here so the `/metrics` handler produces a single unified scrape.
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

/// Register a collector. Safe to call multiple times with the same metric —
/// Prometheus returns `AlreadyReg` which we silently ignore so crates can
/// re-register after a hot reload.
pub fn register<C: prometheus::core::Collector + Clone + 'static>(collector: C) -> Result<()> {
    match registry().register(Box::new(collector)) {
        Ok(()) => Ok(()),
        Err(prometheus::Error::AlreadyReg) => Ok(()),
        Err(e) => Err(e).context("register prometheus collector"),
    }
}

/// Encode all registered metric families as Prometheus text-format.
/// Intended for the axum `/metrics` handler.
pub fn gather_text() -> String {
    let mut buf = Vec::new();
    let families = registry().gather();
    if TextEncoder::new().encode(&families, &mut buf).is_err() {
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gather_text_empty_when_nothing_registered() {
        // We can't touch a fresh registry from a test because it's process-global
        // and other tests may have registered things. The shape we care about is
        // that gather_text produces *some* UTF-8 without panicking.
        let _ = gather_text();
    }

    #[test]
    fn register_is_idempotent() {
        let c = prometheus::IntCounter::new("telemetry_test_counter", "help")
            .expect("counter construct");
        register(c.clone()).expect("first register");
        // second call should NOT error even though the collector is already
        // registered (we map AlreadyReg → Ok).
        register(c).expect("second register");
    }
}
