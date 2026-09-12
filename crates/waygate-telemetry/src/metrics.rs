//! Named Prometheus metrics for the gateway, registered lazily on first touch.
//!
//! All metrics live in [`crate::registry`]. The `record_*` helpers are the
//! public entry points; they hide the `prometheus` crate's typed builders so
//! callers don't need to depend on `prometheus` directly.
//!
//! **Cardinality policy** — dashboards must stay cheap, so label sets are
//! bounded at registration time:
//! - `server` is bounded by the upstream manifest count (~handful).
//! - `decision`, `outcome`, `risk` are closed enums.
//! - We do **not** label by `tool` or `user.sub` — per-call detail lives in
//!   OTLP spans and the audit log, not in metric series.
//!
//! If a call site needs a new label, add it in a PR that also grows the
//! Grafana dashboard — those two should evolve together.
//!
//! All `record_*` helpers silently no-op if metric construction failed at
//! registration time (`prometheus::Error::AlreadyReg` is folded to `Ok` and
//! anything else gets logged). A broken metric must never take down a request.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use prometheus::{
    register_counter_vec_with_registry, register_counter_with_registry,
    register_gauge_vec_with_registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, Counter, CounterVec, GaugeVec, Histogram, HistogramVec,
    IntGauge, IntGaugeVec,
};

use crate::registry;

// -----------------------------------------------------------------------------
// Handles (lazy, registered on first use)
// -----------------------------------------------------------------------------

fn authz_decisions() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_authz_decisions_total",
            "Cedar authorization decisions keyed by outcome and risk tier.",
            &["decision", "risk"],
            registry()
        )
        .expect("register mcp_authz_decisions_total")
    })
}

fn authz_latency() -> &'static Histogram {
    static M: OnceLock<Histogram> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_with_registry!(
            "mcp_authz_latency_seconds",
            "Cedar evaluation latency in seconds.",
            // Authz should be sub-millisecond; skew buckets tight.
            vec![0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1],
            registry()
        )
        .expect("register mcp_authz_latency_seconds")
    })
}

fn upstream_calls() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_upstream_calls_total",
            "Calls dispatched to an upstream MCP server, keyed by server name and outcome.",
            &["server", "outcome"],
            registry()
        )
        .expect("register mcp_upstream_calls_total")
    })
}

fn upstream_latency() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_upstream_latency_seconds",
            "End-to-end upstream call latency (includes identity cell serialization + rmcp dispatch).",
            &["server"],
            // Upstream MCPs span a wide range — from local HTTP (< 10ms) to
            // remote network calls (100ms–5s).
            vec![0.005, 0.025, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry()
        )
        .expect("register mcp_upstream_latency_seconds")
    })
}

fn upstream_call_failures() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_upstream_call_failures_total",
            "Upstream call failures by configured server and closed lifecycle phase. Raw error details remain in protected logs.",
            &["server", "phase"],
            registry()
        )
        .expect("register mcp_upstream_call_failures_total")
    })
}

fn upstream_safe_retries() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_upstream_safe_retries_total",
            "Gateway-owned retries whose original tool dispatch was proven absent, keyed by configured server and closed outcome.",
            &["server", "outcome"],
            registry()
        )
        .expect("register mcp_upstream_safe_retries_total")
    })
}

fn server_operation_duration() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_server_operation_duration_seconds",
            "Gateway-as-MCP-server request handling duration (OTel semconv `mcp.server.operation.duration`), keyed by MCP method and outcome.",
            &["method", "outcome"],
            // semconv-recommended bucket boundaries for MCP operation duration.
            vec![0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
            registry()
        )
        .expect("register mcp_server_operation_duration_seconds")
    })
}

fn discovery_operation_duration() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_discovery_operation_duration_seconds",
            "Authorization-scoped discovery operation duration, keyed only by closed operation and outcome vocabularies.",
            &["operation", "outcome"],
            vec![
                0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                5.0,
            ],
            registry()
        )
        .expect("register mcp_discovery_operation_duration_seconds")
    })
}

fn discovery_cursor_outcomes() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_discovery_cursor_total",
            "Discovery continuation attempts keyed by closed surface and outcome vocabularies; cursor values and queries are never labels.",
            &["surface", "outcome"],
            registry()
        )
        .expect("register mcp_discovery_cursor_total")
    })
}

fn discovery_index_publications() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_discovery_index_publications_total",
            "Legacy retrieval-index publications keyed by bounded publication mode and outcome.",
            &["mode", "outcome"],
            registry()
        )
        .expect("register mcp_discovery_index_publications_total")
    })
}

fn discovery_index_fallbacks() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_discovery_index_fallback_total",
            "Legacy searchTools requests that scanned the authoritative catalog instead of using the retrieval index, keyed by a closed reason.",
            &["reason"],
            registry()
        )
        .expect("register mcp_discovery_index_fallback_total")
    })
}

fn discovery_catalog_sources() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_discovery_catalog_sources",
            "Current source count in each bounded discovery plane. The legacy index plane covers upstream compatibility search only.",
            &["plane"],
            registry()
        )
        .expect("register mcp_discovery_catalog_sources")
    })
}

fn discovery_catalog_tools() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_discovery_catalog_tools",
            "Current tool count in each bounded discovery plane. The legacy index plane covers upstream compatibility search only.",
            &["plane"],
            registry()
        )
        .expect("register mcp_discovery_catalog_tools")
    })
}

fn discovery_retrieval_index_state() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_discovery_retrieval_index_state",
            "One-hot legacy retrieval-index state using the closed healthy, unhealthy, and unavailable vocabulary.",
            &["state"],
            registry()
        )
        .expect("register mcp_discovery_retrieval_index_state")
    })
}

fn discovery_retrieval_index_generation() -> &'static IntGauge {
    static M: OnceLock<IntGauge> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_with_registry!(
            "mcp_discovery_retrieval_index_generation",
            "Current legacy retrieval-index publication generation; odd values identify an in-progress publication.",
            registry()
        )
        .expect("register mcp_discovery_retrieval_index_generation")
    })
}

fn discovery_retrieval_index_skew_tools() -> &'static IntGauge {
    static M: OnceLock<IntGauge> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_with_registry!(
            "mcp_discovery_retrieval_index_skew_tools",
            "Authoritative upstream tool count minus legacy retrieval-index tool count. Gateway-local tools are outside both sides of this comparison.",
            registry()
        )
        .expect("register mcp_discovery_retrieval_index_skew_tools")
    })
}

fn catalog_reconciliation_duration() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_discovery_catalog_reconciliation_duration_seconds",
            "Atomic manifest-to-catalog reconciliation duration keyed by the closed success or error outcome.",
            &["outcome"],
            vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            ],
            registry()
        )
        .expect("register mcp_discovery_catalog_reconciliation_duration_seconds")
    })
}

fn identity_cell_wait() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_identity_cell_wait_seconds",
            "Time a call_tool waited to acquire a server's per-upstream call \
             serializer (the IdentityCell mutex). High values quantify the \
             per-upstream serialization bottleneck.",
            &["server"],
            // Contention should be ~0 when uncontended; widen up to a few
            // seconds to catch a wedged call holding the lock.
            vec![0.0001, 0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 2.5, 5.0],
            registry()
        )
        .expect("register mcp_identity_cell_wait_seconds")
    })
}

fn identity_cell_depth() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_identity_cell_queue_depth",
            "Calls currently waiting on or holding a server's per-upstream call \
             serializer. A depth > 1 means calls to that upstream are serializing.",
            &["server"],
            registry()
        )
        .expect("register mcp_identity_cell_queue_depth")
    })
}

fn database_pool_connections() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_database_pool_connections",
            "Postgres connections by isolated workload role and state. `in_use` plus \
             `idle` is the current pool size; `max` is the configured ceiling.",
            &["role", "state"],
            registry()
        )
        .expect("register mcp_database_pool_connections")
    })
}

fn tool_drift() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_tool_drift_total",
            "Per-upstream count of tool behavior drift events observed at \
             dial / reconnect / reload — i.e. a previously-seen tool now \
             advertises a different schema-or-security-metadata hash from the gateway's last \
             in-process observation. Bumped once per drifted tool per \
             observation pass. Tool identity intentionally omitted from \
             labels (cardinality policy); per-tool detail lives in the \
             tracing event and CatalogDrift audit events.",
            &["server"],
            registry()
        )
        .expect("register mcp_tool_drift_total")
    })
}

fn tool_quarantined() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_tool_quarantined",
            "Per-upstream count of tools currently quarantined by the gateway \
             (e.g. observed behavior drift on a tool whose catalog risk meets the \
             GATEWAY_QUARANTINE_ON_DRIFT_RISK threshold). Non-zero means calls to \
             those tools are being refused at resolve_invocation_tool. Cleared on \
             gateway restart — there is no persistence yet.",
            &["server"],
            registry()
        )
        .expect("register mcp_tool_quarantined")
    })
}

fn evidence_drain() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_evidence_drain_total",
            "Outcomes from the evidence outbox drain. \
             `outcome=delivered` shipped successfully via the registered \
             exporter; `outcome=failed` will be retried after backoff; \
             `outcome=dead_letter` exceeded retries OR exporter declared \
             unrecoverable OR no exporter is registered for the target \
             (operator config error).",
            &["target", "outcome"],
            registry()
        )
        .expect("register mcp_evidence_drain_total")
    })
}

fn evidence_drain_errors() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_evidence_drain_errors_total",
            "Count of drain ticks where the dequeue query itself \
             failed (not the same as a per-row delivery failure, which \
             is `mcp_evidence_drain_total{outcome=failed|dead_letter}`).",
            &["kind"],
            registry()
        )
        .expect("register mcp_evidence_drain_errors_total")
    })
}

fn evidence_chained_best_effort() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_evidence_chained_best_effort_total",
            "Chained best-effort evidence writes keyed by the closed outcome set: \
             attempted, inserted, dropped, or unknown. Unknown means commit \
             started but the caller did not observe whether PostgreSQL committed. \
             Attempted increments before the asynchronous write; task cancellation \
             can leave it unmatched by a terminal outcome.",
            &["outcome"],
            registry()
        )
        .expect("register mcp_evidence_chained_best_effort_total")
    })
}

fn evidence_chained_best_effort_failures() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_evidence_chained_best_effort_failures_total",
            "Failed chained best-effort evidence writes keyed by the closed write-stage set. \
             Every failure also increments the dropped or unknown series in \
             mcp_evidence_chained_best_effort_total.",
            &["stage"],
            registry()
        )
        .expect("register mcp_evidence_chained_best_effort_failures_total")
    })
}

fn evidence_chained_best_effort_duration() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_evidence_chained_best_effort_duration_seconds",
            "End-to-end chained best-effort evidence-write latency keyed by the closed terminal-outcome set.",
            &["outcome"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry()
        )
        .expect("register mcp_evidence_chained_best_effort_duration_seconds")
    })
}

fn evidence_submission() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_evidence_submission_total",
            "Bounded asynchronous evidence-submission transitions keyed by the closed posture \
             and outcome sets. Queued events are accepted into process memory; processed means \
             the backing recorder completed its attempt, not that best-effort persistence \
             necessarily succeeded.",
            &["posture", "outcome"],
            registry()
        )
        .expect("register mcp_evidence_submission_total")
    })
}

fn evidence_submission_pending() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_evidence_submission_pending",
            "Evidence events accepted by the bounded asynchronous recorder but not yet \
             completed by its backing recorder, including queued and currently processing \
             events.",
            &["posture"],
            registry()
        )
        .expect("register mcp_evidence_submission_pending")
    })
}

fn evidence_reason_truncations() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_evidence_reason_truncations_total",
            "Evidence events whose free-form reason exceeded the recorder's byte bound and \
             was truncated before persistence or asynchronous queueing.",
            registry()
        )
        .expect("register mcp_evidence_reason_truncations_total")
    })
}

fn grant_sweep() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_grant_sweep_total",
            "Background-sweep outcomes for the \
             `approval_grants` table. `outcome=deleted` is the cumulative \
             number of dead grant rows pruned (incremented by N each \
             successful tick that deleted N rows); `outcome=error` is the \
             count of ticks where the sweep query itself failed.",
            &["outcome"],
            registry()
        )
        .expect("register mcp_grant_sweep_total")
    })
}

fn bearer_validations() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_bearer_validations_total",
            "Bearer-token validation outcomes at the axum middleware.",
            &["outcome"],
            registry()
        )
        .expect("register mcp_bearer_validations_total")
    })
}

fn break_glass_uses() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_break_glass_total",
            "Break-glass override outcomes. \
             `outcome=claimed` ⇒ a Deny was overridden by a \
             successful single-use token claim. `lookup_error` / \
             `amr_unmet` / `claim_raced` / `claim_error` are the \
             various reasons an override DID NOT fire and the call \
             fell through to its original Deny. `audit_failed` is \
             the rare case where a token \
             was successfully claimed but the required audit row \
             insert failed — the gateway then refuses to dispatch \
             (token is burned without dispatching; operator must \
             mint another). Operators page on `claimed > 0` AND \
             `audit_failed > 0`; investigate `lookup_error > 0`.",
            &["outcome"],
            registry()
        )
        .expect("register mcp_break_glass_total")
    })
}

// Inference-plane (gen_ai.*) metrics. Names track the OpenTelemetry
// GenAI semantic conventions (`gen_ai.client.token.usage`, ...) with dots
// rendered as underscores for Prometheus. Recorded as counters — the gateway
// only learns final token/cost figures at completion ([DONE] / unary return),
// so a histogram of per-call values would not buy us more than the ledger
// already holds. Label cardinality is bounded: `provider` and `model` come from
// the configured catalog (a closed set), `type` is the fixed token-class set,
// and `finish_reason` is clamped to a known enum (see `normalize_finish_reason`).

fn llm_duration() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "gen_ai_client_duration_seconds",
            "Model request duration by provider account and outcome.",
            &["provider", "model", "user_account_id", "outcome"],
            vec![0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0],
            registry()
        )
        .expect("register gen_ai_client_duration_seconds")
    })
}

/// Count failed provider dispatches without credentials or provider error bodies.
#[derive(Clone, Copy)]
pub enum LlmFailurePhase {
    Dispatch,
    Stream,
    Abandoned,
}

impl LlmFailurePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::Stream => "stream",
            Self::Abandoned => "abandoned",
        }
    }
}

pub fn record_llm_request_failure(
    provider: &str,
    model: &str,
    account: Option<&str>,
    duration: f64,
    phase: LlmFailurePhase,
) {
    static M: OnceLock<CounterVec> = OnceLock::new();
    let counter = M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "gen_ai_client_request_failures_total",
            "Model requests without a terminal provider completion, by failure phase.",
            &["provider", "model", "user_account_id", "phase"],
            registry()
        )
        .expect("register gen_ai_client_request_failures_total")
    });
    let account = account.unwrap_or("unknown");
    counter
        .with_label_values(&[provider, model, account, phase.as_str()])
        .inc();
    if duration.is_finite() && duration >= 0.0 {
        llm_duration()
            .with_label_values(&[provider, model, account, "failed"])
            .observe(duration);
    }
}

fn llm_tokens() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "gen_ai_client_token_usage_total",
            "LLM tokens consumed, keyed by provider, model (request alias), and \
             token type (input/output/cached_read/cache_write/reasoning).",
            &["provider", "model", "type", "user_account_id"],
            registry()
        )
        .expect("register gen_ai_client_token_usage_total")
    })
}

fn llm_cost() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "gen_ai_client_cost_total",
            "LLM call cost (catalog-computed, best-effort), keyed by provider, \
             model (request alias), and currency. Only priced calls increment it.",
            &["provider", "model", "currency", "user_account_id"],
            registry()
        )
        .expect("register gen_ai_client_cost_total")
    })
}

fn llm_calls() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "gen_ai_client_calls_total",
            "Completed LLM calls, keyed by provider, model (request alias), and \
             finish reason (clamped to a known enum).",
            &["provider", "model", "finish_reason", "user_account_id"],
            registry()
        )
        .expect("register gen_ai_client_calls_total")
    })
}

// -----------------------------------------------------------------------------
// Public recorders
// -----------------------------------------------------------------------------

/// Record one Cedar authorization decision.
///
/// `decision` is one of `"allow"`, `"deny"`, `"step_up"`. `risk` is the
/// tool's risk tier (`"low"`, `"medium"`, `"high"`).
pub fn record_authz_decision(decision: &str, risk: &str) {
    authz_decisions().with_label_values(&[decision, risk]).inc();
}

pub fn record_authz_latency(seconds: f64) {
    authz_latency().observe(seconds);
}

/// Record one break-glass override outcome.
/// `outcome` ∈ `{"claimed", "lookup_error",
/// "amr_unmet", "claim_raced", "claim_error",
/// "audit_failed"}`. Closed set so dashboards stay
/// bounded. `audit_failed` is
/// the "token claimed but record_required failed; we
/// refused to dispatch" outcome — page on it too.
pub fn record_break_glass_use(outcome: &str) {
    break_glass_uses().with_label_values(&[outcome]).inc();
}

fn output_schema_violations() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_output_schema_violations_total",
            "Cumulative count of upstream \
             responses the `InvocationService::validate_output` \
             stage refused because the structured payload \
             didn't match the approved `mcp_tool_versions.\
             output_schema`. Labels: `(server, tool)`. A non-\
             zero value on a previously-clean tool usually \
             means the upstream rolled out a schema-breaking \
             change and the catalog approval is stale — page \
             the catalog operator.",
            &["server", "tool"],
            registry()
        )
        .expect("register mcp_output_schema_violations_total")
    })
}

/// Record one output-schema validation failure.
/// `server` + `tool` are the qualified pair operators page on.
pub fn record_output_schema_violation(server: &str, tool: &str) {
    output_schema_violations()
        .with_label_values(&[server, tool])
        .inc();
}

fn rejected_output_schemas() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_upstream_rejected_output_schemas",
            "Per-upstream count of tools the gateway is CURRENTLY \
             publishing without the `outputSchema` that upstream \
             advertised, because the schema's root was not \
             `type: \"object\"` and so could not describe a \
             `structuredContent` object. The tools stay callable; \
             non-zero means the upstream is emitting spec-violating \
             definitions, and a strict client would discard its ENTIRE \
             catalog over them — so alert on `> 0` and fix the \
             upstream. `Set`-style so it returns to zero once the \
             upstream is fixed and re-dialed, rather than latching \
             forever the way a cumulative counter would. Labelled by \
             `server` only: tool names are upstream-controlled and \
             unbounded, so a label per name would grow series for the \
             process lifetime; the offending tool is named in the \
             `UpstreamHealth` audit row and the dial-time warn log, \
             both retention-bounded. Distinct from \
             `mcp_output_schema_violations_total`, which counts \
             responses refused at invocation time; this reports \
             contracts refused at advertisement time. Cleared on \
             gateway restart until the first dial repopulates it.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_rejected_output_schemas")
    })
}

/// Set the current count of refused output schemas for `server`.
///
/// Computed from the same across-lane union the admin health snapshot
/// reports, but published only when a connection is installed (dial,
/// auto-recovery, re-dial, structural commit) and zeroed when the
/// upstream is removed. The health snapshot recomputes on every read, so
/// between installs the two can differ: a lane dropping after a transport
/// error shrinks the union the snapshot sees while the gauge still holds
/// the pre-drop count.
///
/// The skew is not bounded to one direction. The publisher checks that its
/// entry is still current and then writes, and those are separate
/// operations on a process-global gauge, so a replacement landing between
/// them can have its newer count overwritten by the retired publisher —
/// including with a lower value. Treat this as a best-effort alerting
/// signal that self-corrects at the next install; the AUTHORITATIVE count
/// is the one the admin health snapshot computes from the live registry on
/// every read.
pub fn set_rejected_output_schemas(server: &str, count: i64) {
    rejected_output_schemas()
        .with_label_values(&[server])
        .set(count);
}

fn unregisterable_input_schemas() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "mcp_upstream_unregisterable_input_schemas",
            "Per-upstream count of tools the gateway is CURRENTLY \
             publishing whose `inputSchema` applies a composition \
             keyword (`anyOf`, `oneOf`, `allOf`) at its root. Such a \
             schema is valid JSON Schema and valid MCP, so the gateway \
             publishes it verbatim, but the tool-calling APIs that \
             consume `tools/list` refuse the definition — the client \
             either drops that tool or fails every request carrying it. \
             Non-zero means those tools are unreachable for such \
             clients; the fix belongs in the upstream, which should \
             declare mutually exclusive arguments as independent \
             optional properties and enforce the exclusion when the \
             call is handled. `Set`-style so it returns to zero once \
             the upstream is fixed and re-dialed. Labelled by `server` \
             only: tool names are upstream-controlled and unbounded, so \
             a label per name would grow series for the process \
             lifetime; the offending tool is named in the dial-time \
             warn log. Distinct from \
             `mcp_upstream_rejected_output_schemas`, which reports \
             refused OUTPUT contracts the gateway strips; nothing is \
             stripped here, because removing a root union would rewrite \
             the upstream's input contract. Cleared on gateway restart \
             until the first dial repopulates it.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_unregisterable_input_schemas")
    })
}

/// Set the current count of unregisterable input schemas for `server`.
///
/// Published on the same schedule, from the same across-lane union, and
/// with the same best-effort skew as [`set_rejected_output_schemas`] —
/// see its documentation for why the value can lag a replacement.
pub fn set_unregisterable_input_schemas(server: &str, count: i64) {
    unregisterable_input_schemas()
        .with_label_values(&[server])
        .set(count);
}

/// Connected upstream lanes by negotiated MCP protocol generation —
/// the fleet-migration input for the legacy-removal decision. `generation`
/// is a closed label set (the served protocol revisions plus `other`),
/// bounded at the recording site so an upstream cannot mint label
/// cardinality by returning arbitrary version strings.
fn upstream_protocol_generation() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "gateway_upstream_protocol_generation",
            "Connected upstream lanes by negotiated MCP protocol \
             generation. The per-server input to the legacy-removal \
             decision: a fleet fully on `2026-07-28` has zeroes on every \
             other generation series.",
            &["server", "generation"],
            registry()
        )
        .expect("register gateway_upstream_protocol_generation")
    })
}

fn upstream_runtime_state() -> &'static IntGaugeVec {
    static M: OnceLock<IntGaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_int_gauge_vec_with_registry!(
            "gateway_upstream_runtime_state",
            "Authoritative upstream runtime availability as a one-hot gauge. \
             Exactly one of connected, degraded, or disconnected is 1 for \
             each configured server; all are 0 after removal.",
            &["server", "state"],
            registry()
        )
        .expect("register gateway_upstream_runtime_state")
    })
}

fn upstream_reconnect_attempts() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_upstream_reconnect_attempts_total",
            "Reconnect attempts by configured upstream.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_reconnect_attempts_total")
    })
}

fn upstream_reconnect_failure_episodes() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_upstream_reconnect_failure_episodes_total",
            "Distinct reconnect failure episodes by configured upstream.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_reconnect_failure_episodes_total")
    })
}

fn upstream_reconnect_backoff() -> &'static GaugeVec {
    static M: OnceLock<GaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_gauge_vec_with_registry!(
            "mcp_upstream_reconnect_backoff_seconds",
            "Current full-jitter reconnect delay by configured upstream; zero when idle.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_reconnect_backoff_seconds")
    })
}

fn upstream_reconnect_next_retry() -> &'static GaugeVec {
    static M: OnceLock<GaugeVec> = OnceLock::new();
    M.get_or_init(|| {
        register_gauge_vec_with_registry!(
            "mcp_upstream_reconnect_next_retry_timestamp_seconds",
            "Unix timestamp of the next reconnect attempt by configured upstream; zero when idle.",
            &["server"],
            registry()
        )
        .expect("register mcp_upstream_reconnect_next_retry_timestamp_seconds")
    })
}

/// Record every reconnect attempt when its first dial is launched. This also
/// counts attempts later cancelled or superseded.
pub fn record_upstream_reconnect_attempt(server: &str) {
    upstream_reconnect_attempts()
        .with_label_values(&[server])
        .inc();
}

/// Mark the beginning of one aggregated failure episode.
pub fn record_upstream_reconnect_failure_episode(server: &str) {
    upstream_reconnect_failure_episodes()
        .with_label_values(&[server])
        .inc();
}

/// Publish the selected full-jitter delay and deadline. Both gauges return to
/// zero after recovery or removal.
pub fn set_upstream_reconnect_schedule(
    server: &str,
    backoff: Option<std::time::Duration>,
    next_retry_unix: Option<i64>,
) {
    upstream_reconnect_backoff()
        .with_label_values(&[server])
        .set(backoff.map_or(0.0, |value| value.as_secs_f64()));
    upstream_reconnect_next_retry()
        .with_label_values(&[server])
        .set(next_retry_unix.map_or(0.0, |value| value as f64));
}

pub const UPSTREAM_RUNTIME_STATES: &[&str] = &["connected", "degraded", "disconnected"];

fn known_runtime_state_servers() -> &'static Mutex<HashSet<String>> {
    static SERVERS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SERVERS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn write_upstream_runtime_state(server: &str, state: Option<&str>) {
    for candidate in UPSTREAM_RUNTIME_STATES {
        upstream_runtime_state()
            .with_label_values(&[server, candidate])
            .set(i64::from(state == Some(*candidate)));
    }
}

/// Publish one upstream's authoritative runtime state. Unknown labels are
/// deliberately represented as all-zero rather than creating unbounded label
/// cardinality; passing `None` clears every state when a server is removed.
pub fn set_upstream_runtime_state(server: &str, state: Option<&str>) {
    let mut known = known_runtime_state_servers()
        .lock()
        .expect("upstream runtime-state server registry lock poisoned");
    if state.is_some() {
        known.insert(server.to_owned());
    } else {
        known.remove(server);
    }
    // Keep the registry lock through the gauge write. This gives explicit
    // removal, stale snapshot publication, and scrape reconciliation one
    // total order; otherwise a stale publisher could insert before removal
    // but write its `1` after removal, escaping later reconciliation.
    write_upstream_runtime_state(server, state);
}

/// Clear runtime-state series for servers absent from the authoritative pool
/// snapshot. The metric vector retains label series after a hot removal, so
/// this reconciliation makes a later scrape self-heal even when a racing,
/// older snapshot republished the removed server after its explicit clear.
pub fn reconcile_upstream_runtime_states<'a>(active_servers: impl IntoIterator<Item = &'a str>) {
    let active: HashSet<&str> = active_servers.into_iter().collect();
    let mut known = known_runtime_state_servers()
        .lock()
        .expect("upstream runtime-state server registry lock poisoned");
    known.retain(|server| {
        let remains_active = active.contains(server.as_str());
        if !remains_active {
            write_upstream_runtime_state(server, None);
        }
        remains_active
    });
}

/// The closed generation label set for
/// [`set_upstream_protocol_generations`]. Server-supplied version strings
/// outside the served set collapse to `other`.
pub const UPSTREAM_PROTOCOL_GENERATIONS: &[&str] = &["2025-11-25", "2026-07-28", "other"];

/// Publish the per-generation connected-lane counts for one upstream.
/// `counts` pairs each entry of [`UPSTREAM_PROTOCOL_GENERATIONS`] with its
/// lane count; every label in the closed set is written on every call so a
/// migration zeroes the departed generation's series.
pub fn set_upstream_protocol_generations(server: &str, counts: &[(&str, i64)]) {
    for (generation, lanes) in counts {
        upstream_protocol_generation()
            .with_label_values(&[server, generation])
            .set(*lanes);
    }
}

fn schema_validator_cache_hits() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_schema_validator_cache_hits_total",
            "Approved output-schema validator cache hits.",
            registry()
        )
        .expect("register mcp_schema_validator_cache_hits_total")
    })
}

pub fn record_schema_validator_cache_hit() {
    schema_validator_cache_hits().inc();
}

fn schema_validator_cache_misses() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_schema_validator_cache_misses_total",
            "Approved output-schema validator cache misses.",
            registry()
        )
        .expect("register mcp_schema_validator_cache_misses_total")
    })
}

pub fn record_schema_validator_cache_miss() {
    schema_validator_cache_misses().inc();
}

fn schema_validator_cache_evictions() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_schema_validator_cache_evictions_total",
            "Approved output-schema validators evicted from the bounded cache.",
            registry()
        )
        .expect("register mcp_schema_validator_cache_evictions_total")
    })
}

pub fn record_schema_validator_cache_eviction() {
    schema_validator_cache_evictions().inc();
}

fn schema_validator_compile_failures() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_schema_validator_compile_failures_total",
            "Approved output schemas refused at admission because compilation failed.",
            registry()
        )
        .expect("register mcp_schema_validator_compile_failures_total")
    })
}

pub fn record_schema_validator_compile_failure() {
    schema_validator_compile_failures().inc();
}

fn invocation_manifest_fallbacks() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_invocation_manifest_fallback_total",
            "Invocation admissions using manifest facts instead of a live catalog definition.",
            &["approval_authority"],
            registry()
        )
        .expect("register mcp_invocation_manifest_fallback_total")
    })
}

pub fn record_invocation_manifest_fallback(approval_requirements_known: bool) {
    invocation_manifest_fallbacks()
        .with_label_values(&[if approval_requirements_known {
            "known"
        } else {
            "unknown"
        }])
        .inc();
}

fn invocation_approval_unknown_refusals() -> &'static Counter {
    static M: OnceLock<Counter> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_with_registry!(
            "mcp_invocation_approval_unknown_refusals_total",
            "Invocations refused because fallback facts could not authoritatively state approval requirements.",
            registry()
        )
        .expect("register mcp_invocation_approval_unknown_refusals_total")
    })
}

pub fn record_invocation_approval_unknown_refusal() {
    invocation_approval_unknown_refusals().inc();
}

fn response_inspector_blocks() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_response_inspector_blocks_total",
            "Cumulative count of upstream \
             responses the `InvocationService::inspect_response` \
             stage refused because at least one configured \
             inspector returned `Decision::Block`. Labels: \
             `(server, tool, inspector)` — operators page on a \
             specific inspector to find tools that keep tripping \
             a rule.",
            &["server", "tool", "inspector"],
            registry()
        )
        .expect("register mcp_response_inspector_blocks_total")
    })
}

/// Record one response-inspector block. The
/// `inspector` value is `Inspector::name()` — a closed set
/// drawn from the registered inspectors.
pub fn record_response_inspector_block(server: &str, tool: &str, inspector: &str) {
    response_inspector_blocks()
        .with_label_values(&[server, tool, inspector])
        .inc();
}

fn response_inspector_redactions() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_response_inspector_redactions_total",
            "Cumulative count of upstream \
             response payloads the `InvocationService::inspect_response` \
             stage forwarded with at least one redaction. Labels: \
             `(server, tool, inspector)` — counts INSPECTIONS \
             that redacted, NOT individual findings (each \
             inspection emits a single +1 regardless of how \
             many matches it replaced). Pair with \
             `mcp_response_inspector_blocks_total` to see the \
             ratio of redact vs block decisions per inspector.",
            &["server", "tool", "inspector"],
            registry()
        )
        .expect("register mcp_response_inspector_redactions_total")
    })
}

/// Record one response-inspector redaction
/// pass. Bumps the counter by 1 (the inspection event), not
/// by `findings_count` — that detail is captured in the
/// summary audit row + tracing log so the metric stays
/// dashboard-friendly.
pub fn record_response_inspector_redaction(
    server: &str,
    tool: &str,
    inspector: &str,
    _findings_count: u32,
) {
    response_inspector_redactions()
        .with_label_values(&[server, tool, inspector])
        .inc();
}

/// Upstream call outcome — kept closed so dashboards don't grow unbounded.
#[derive(Copy, Clone, Debug)]
pub enum UpstreamOutcome {
    Ok,
    Error,
    NotConnected,
}

impl UpstreamOutcome {
    fn as_str(self) -> &'static str {
        match self {
            UpstreamOutcome::Ok => "ok",
            UpstreamOutcome::Error => "error",
            UpstreamOutcome::NotConnected => "not_connected",
        }
    }
}

pub fn record_upstream_call(server: &str, outcome: UpstreamOutcome, latency_seconds: f64) {
    upstream_calls()
        .with_label_values(&[server, outcome.as_str()])
        .inc();
    upstream_latency()
        .with_label_values(&[server])
        .observe(latency_seconds);
}

/// Record a stable lifecycle phase rather than an unbounded transport error.
pub fn record_upstream_call_failure(server: &str, phase: &str) {
    debug_assert!(matches!(
        phase,
        "dial"
            | "initialize"
            | "pre_dispatch"
            | "dispatched_known_refusal"
            | "dispatched_unknown_outcome"
    ));
    upstream_call_failures()
        .with_label_values(&[server, phase])
        .inc();
}

/// Record the bounded result vocabulary for a gateway-owned safe retry.
pub fn record_upstream_safe_retry(server: &str, outcome: &str) {
    debug_assert!(matches!(outcome, "attempted" | "recovered" | "exhausted"));
    upstream_safe_retries()
        .with_label_values(&[server, outcome])
        .inc();
}

/// Record one server-side MCP operation duration — the gateway acting as the
/// MCP *server*, i.e. total handling time for a `tools/call` / `tools/list`.
/// This is the OTel semconv `mcp.server.operation.duration`; the client-side
/// equivalent (`mcp.client.operation.duration`) is already covered by
/// `mcp_upstream_latency_seconds`.
///
/// `method` is the MCP method name — bounded, since the gateway only
/// instruments the closed set of methods it serves. `ok` maps to the closed
/// `outcome` label (`ok` / `error`), keeping cardinality fixed per the policy
/// at the top of this module (no per-tool / per-user labels).
pub fn record_server_operation(method: &str, ok: bool, seconds: f64) {
    server_operation_duration()
        .with_label_values(&[method, if ok { "ok" } else { "error" }])
        .observe(seconds);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryOperation {
    GatewaySearch,
    GatewayInspect,
    CodeModeSearch,
    CodeModeDescribe,
}

impl DiscoveryOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GatewaySearch => "gateway_search",
            Self::GatewayInspect => "gateway_inspect",
            Self::CodeModeSearch => "codemode_search",
            Self::CodeModeDescribe => "codemode_describe",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    Ok,
    Invalid,
    Unavailable,
    Error,
}

impl DiscoveryOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}

pub fn record_discovery_operation(
    operation: DiscoveryOperation,
    outcome: DiscoveryOutcome,
    seconds: f64,
) {
    discovery_operation_duration()
        .with_label_values(&[operation.as_str(), outcome.as_str()])
        .observe(seconds);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverySurface {
    Gateway,
    CodeMode,
}

impl DiscoverySurface {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::CodeMode => "codemode",
        }
    }
}

pub fn record_discovery_cursor(surface: DiscoverySurface, accepted: bool) {
    discovery_cursor_outcomes()
        .with_label_values(&[
            surface.as_str(),
            if accepted { "accepted" } else { "rejected" },
        ])
        .inc();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryIndexPublication {
    Slice,
    Full,
    Recovery,
}

impl DiscoveryIndexPublication {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Slice => "slice",
            Self::Full => "full",
            Self::Recovery => "recovery",
        }
    }
}

pub fn record_discovery_index_publication(mode: DiscoveryIndexPublication, ok: bool) {
    discovery_index_publications()
        .with_label_values(&[mode.as_str(), if ok { "success" } else { "error" }])
        .inc();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryIndexFallback {
    Unavailable,
    NoOpinion,
    QueryError,
    GenerationChurn,
}

impl DiscoveryIndexFallback {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NoOpinion => "no_opinion",
            Self::QueryError => "query_error",
            Self::GenerationChurn => "generation_churn",
        }
    }
}

pub fn record_discovery_index_fallback(reason: DiscoveryIndexFallback) {
    discovery_index_fallbacks()
        .with_label_values(&[reason.as_str()])
        .inc();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryIndexState {
    Healthy,
    Unhealthy,
    Unavailable,
}

impl DiscoveryIndexState {
    const ALL: [Self; 3] = [Self::Healthy, Self::Unhealthy, Self::Unavailable];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
            Self::Unavailable => "unavailable",
        }
    }
}

pub fn set_discovery_catalog_state(
    authoritative_sources: usize,
    authoritative_tools: usize,
    retrieval_sources: usize,
    retrieval_tools: usize,
    index_state: DiscoveryIndexState,
    index_generation: u64,
) {
    discovery_catalog_sources()
        .with_label_values(&["authoritative_upstream"])
        .set(i64::try_from(authoritative_sources).unwrap_or(i64::MAX));
    discovery_catalog_sources()
        .with_label_values(&["legacy_index"])
        .set(i64::try_from(retrieval_sources).unwrap_or(i64::MAX));
    discovery_catalog_tools()
        .with_label_values(&["authoritative_upstream"])
        .set(i64::try_from(authoritative_tools).unwrap_or(i64::MAX));
    discovery_catalog_tools()
        .with_label_values(&["legacy_index"])
        .set(i64::try_from(retrieval_tools).unwrap_or(i64::MAX));
    set_discovery_index_state(index_state);
    discovery_retrieval_index_generation().set(i64::try_from(index_generation).unwrap_or(i64::MAX));
    let authoritative = i64::try_from(authoritative_tools).unwrap_or(i64::MAX);
    let retrieval = i64::try_from(retrieval_tools).unwrap_or(i64::MAX);
    discovery_retrieval_index_skew_tools().set(authoritative.saturating_sub(retrieval));
}

/// Update only the retrieval-index health state while retaining the last
/// coherent inventory, generation, and skew observations.
pub fn set_discovery_index_state(index_state: DiscoveryIndexState) {
    for state in DiscoveryIndexState::ALL {
        discovery_retrieval_index_state()
            .with_label_values(&[state.as_str()])
            .set(i64::from(state == index_state));
    }
}

pub fn record_catalog_reconciliation(ok: bool, seconds: f64) {
    catalog_reconciliation_duration()
        .with_label_values(&[if ok { "success" } else { "error" }])
        .observe(seconds);
}

/// Observe how long a call waited to acquire `server`'s per-upstream call
/// serializer (the IdentityCell mutex).
pub fn record_identity_cell_wait(server: &str, seconds: f64) {
    identity_cell_wait()
        .with_label_values(&[server])
        .observe(seconds);
}

/// A call is now waiting on / holding `server`'s call serializer.
pub fn identity_cell_queue_inc(server: &str) {
    identity_cell_depth().with_label_values(&[server]).inc();
}

/// A call released `server`'s call serializer (or abandoned the wait).
pub fn identity_cell_queue_dec(server: &str) {
    identity_cell_depth().with_label_values(&[server]).dec();
}

/// Closed set of isolated database workloads. Keeping the mapping here avoids
/// accepting arbitrary metric labels from callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabasePoolRole {
    Audit,
    Control,
    Reader,
}

impl DatabasePoolRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Control => "control",
            Self::Reader => "reader",
        }
    }
}

/// Publish one instantaneous pool snapshot. `size` is the number of
/// established connections and `idle` is the available subset.
pub fn record_database_pool_connections(role: DatabasePoolRole, size: u32, idle: u32, max: u32) {
    let idle = idle.min(size);
    let in_use = size.saturating_sub(idle);
    let role = role.as_str();
    for (state, value) in [("in_use", in_use), ("idle", idle), ("max", max)] {
        database_pool_connections()
            .with_label_values(&[role, state])
            .set(i64::from(value));
    }
}

/// Record one observed tool behavior drift event for `server`.
///
/// Called by [`UpstreamPool`](../../waygate_upstream/) when a live
/// `tools/list` re-observation differs from the previous mode-specific
/// in-process contract: the legacy schema hash in manifest mode, or schemas
/// plus security metadata in annotation-native mode.
/// Operators alert on a non-zero rate.
pub fn record_tool_drift(server: &str) {
    tool_drift().with_label_values(&[server]).inc();
}

/// Record one drain-pass outcome for `target`.
/// `outcome` is one of `"delivered"`, `"failed"`, `"dead_letter"`.
pub fn record_evidence_drain(target: &str, outcome: &str) {
    evidence_drain().with_label_values(&[target, outcome]).inc();
}

/// Record one drain tick where the dequeue
/// itself failed (DB unavailable etc.). Distinct from per-row
/// delivery failures.
pub fn record_evidence_drain_error() {
    evidence_drain_errors()
        .with_label_values(&["dequeue"])
        .inc();
}

/// Closed outcome set for chained best-effort evidence-write metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainedBestEffortOutcome {
    Attempted,
    Inserted,
    Dropped,
    Unknown,
}

impl ChainedBestEffortOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Inserted => "inserted",
            Self::Dropped => "dropped",
            Self::Unknown => "unknown",
        }
    }
}

/// Record one chained best-effort evidence-write transition.
pub fn record_evidence_chained_best_effort(outcome: ChainedBestEffortOutcome) {
    evidence_chained_best_effort()
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// Closed write-stage set for chained best-effort failure metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainedBestEffortFailureStage {
    TxBegin,
    ChainLock,
    ChainLockRollback,
    ChainLockContended,
    ChainSelectPrev,
    AuditInsert,
    RoutingLookup,
    PayloadSerialize,
    OutboxEnqueue,
    TxCommit,
}

impl ChainedBestEffortFailureStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::TxBegin => "tx_begin",
            Self::ChainLock => "chain_lock",
            Self::ChainLockRollback => "chain_lock_rollback",
            Self::ChainLockContended => "chain_lock_contended",
            Self::ChainSelectPrev => "chain_select_prev",
            Self::AuditInsert => "audit_insert",
            Self::RoutingLookup => "routing_lookup",
            Self::PayloadSerialize => "payload_serialize",
            Self::OutboxEnqueue => "outbox_enqueue",
            Self::TxCommit => "tx_commit",
        }
    }
}

/// Record the exact stage of one failed chained best-effort evidence write.
pub fn record_evidence_chained_best_effort_failure(stage: ChainedBestEffortFailureStage) {
    evidence_chained_best_effort_failures()
        .with_label_values(&[stage.as_str()])
        .inc();
}

/// Closed terminal-outcome set for chained best-effort latency metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainedBestEffortTerminalOutcome {
    Inserted,
    Dropped,
    Unknown,
}

impl ChainedBestEffortTerminalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::Dropped => "dropped",
            Self::Unknown => "unknown",
        }
    }
}

/// Observe the end-to-end duration of one terminal chained best-effort write.
pub fn record_evidence_chained_best_effort_duration(
    outcome: ChainedBestEffortTerminalOutcome,
    seconds: f64,
) {
    evidence_chained_best_effort_duration()
        .with_label_values(&[outcome.as_str()])
        .observe(seconds);
}

/// Closed posture set for the bounded asynchronous evidence recorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceSubmissionPosture {
    ChainedBestEffort,
    BestEffort,
}

impl EvidenceSubmissionPosture {
    fn as_str(self) -> &'static str {
        match self {
            Self::ChainedBestEffort => "chained_best_effort",
            Self::BestEffort => "best_effort",
        }
    }
}

/// Closed outcome set for bounded asynchronous evidence submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceSubmissionOutcome {
    Queued,
    Processed,
    DroppedFull,
    DroppedClosed,
    DroppedShutdown,
    DroppedWorkerPanic,
}

impl EvidenceSubmissionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Processed => "processed",
            Self::DroppedFull => "dropped_full",
            Self::DroppedClosed => "dropped_closed",
            Self::DroppedShutdown => "dropped_shutdown",
            Self::DroppedWorkerPanic => "dropped_worker_panic",
        }
    }
}

/// Record `count` transitions in the bounded asynchronous evidence recorder.
pub fn record_evidence_submission(
    posture: EvidenceSubmissionPosture,
    outcome: EvidenceSubmissionOutcome,
    count: u64,
) {
    evidence_submission()
        .with_label_values(&[posture.as_str(), outcome.as_str()])
        .inc_by(count as f64);
}

/// Increment one posture's accepted-but-not-completed event count.
pub fn evidence_submission_pending_inc(posture: EvidenceSubmissionPosture) {
    evidence_submission_pending()
        .with_label_values(&[posture.as_str()])
        .inc();
}

/// Decrement one posture's accepted-but-not-completed event count.
pub fn evidence_submission_pending_dec(posture: EvidenceSubmissionPosture) {
    evidence_submission_pending()
        .with_label_values(&[posture.as_str()])
        .dec();
}

/// Remove events abandoned when the bounded shutdown deadline expires.
pub fn evidence_submission_pending_sub(posture: EvidenceSubmissionPosture, count: u64) {
    evidence_submission_pending()
        .with_label_values(&[posture.as_str()])
        .sub(i64::try_from(count).unwrap_or(i64::MAX));
}

/// Record one free-form evidence reason truncated at the recorder boundary.
pub fn record_evidence_reason_truncation() {
    evidence_reason_truncations().inc();
}

/// Record `n` grants pruned by one successful
/// sweep-tick. Called by `waygate_catalog::grant_sweeper`
/// after a non-zero-count DELETE; the counter is cumulative.
pub fn record_grant_sweep_deleted(n: u64) {
    grant_sweep()
        .with_label_values(&["deleted"])
        .inc_by(n as f64);
}

/// Record that one sweep-tick failed (the catalog
/// store returned an error). Doesn't take the error type because
/// the value of this counter is "is the sweeper healthy?" — the
/// detailed error stays in `tracing::warn!`.
pub fn record_grant_sweep_error() {
    grant_sweep().with_label_values(&["error"]).inc();
}

/// Set the current count of quarantined tools for `server`.
///
/// Called by [`UpstreamPool`](../../waygate_upstream/) whenever the
/// per-entry quarantine set changes (an observed drift event added a
/// tool, or an operator action cleared one — the second path doesn't
/// exist yet). The gauge is `Set`-style rather than counter-style so
/// dashboards show the *current* attack-surface reduction, not the
/// cumulative count of events.
pub fn set_tool_quarantined(server: &str, count: i64) {
    tool_quarantined().with_label_values(&[server]).set(count);
}

/// Bearer-middleware outcomes. Closed enum to keep cardinality predictable.
#[derive(Copy, Clone, Debug)]
pub enum BearerOutcome {
    Ok,
    Disabled,
    Missing,
    Invalid,
}

impl BearerOutcome {
    fn as_str(self) -> &'static str {
        match self {
            BearerOutcome::Ok => "ok",
            BearerOutcome::Disabled => "disabled",
            BearerOutcome::Missing => "missing",
            BearerOutcome::Invalid => "invalid",
        }
    }
}

pub fn record_bearer_validation(outcome: BearerOutcome) {
    bearer_validations()
        .with_label_values(&[outcome.as_str()])
        .inc();
}

/// One completed LLM call's observable usage, passed to [`record_llm_usage`].
/// Primitives only so the telemetry crate stays decoupled from storage's row
/// and cost types. Token fields are `None` when the provider did not report
/// that class; `cost` is `None` when the call could not be priced.
#[derive(Debug, Clone, Default)]
pub struct LlmUsageMetric<'a> {
    pub provider: &'a str,
    pub provider_account_id: Option<&'a str>,
    pub duration_seconds: Option<f64>,
    pub gateway_cache_hit: bool,
    /// The request alias (catalog `model.alias`), not the provider-reported
    /// served model — keeps the label set bounded to the configured catalog.
    pub model: &'a str,
    pub finish_reason: Option<&'a str>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    /// Total catalog-computed cost in `currency`. `None` ⇒ unpriced (no
    /// `gen_ai_client_cost_total` increment).
    pub cost: Option<f64>,
    pub currency: &'a str,
}

/// Clamp a provider finish reason to the known OpenAI-shape enum the translate
/// layer normalizes to, so a misbehaving upstream cannot blow up label
/// cardinality. `None` ⇒ `"unknown"`; anything off the known set ⇒ `"other"`.
fn normalize_finish_reason(reason: Option<&str>) -> &'static str {
    match reason {
        None => "unknown",
        Some(r) => match r {
            "stop" => "stop",
            "length" => "length",
            "tool_use" => "tool_use",
            "error" => "error",
            "tool_calls" => "tool_calls",
            "content_filter" => "content_filter",
            "function_call" => "function_call",
            _ => "other",
        },
    }
}

/// Record one completed LLM call's tokens, cost, and finish reason
/// into the `gen_ai.*` counters. Called from the usage sink after the cost is
/// computed — best-effort observability alongside the durable usage ledger, so
/// it runs regardless of whether the ledger insert later succeeds. Token
/// classes with no count are skipped (no zero-series churn).
pub fn record_llm_usage(m: LlmUsageMetric<'_>) {
    if m.gateway_cache_hit {
        return;
    }
    let account = m.provider_account_id.unwrap_or("unknown");
    if let Some(duration) = m
        .duration_seconds
        .filter(|value| value.is_finite() && *value >= 0.0)
    {
        llm_duration()
            .with_label_values(&[m.provider, m.model, account, "completed"])
            .observe(duration);
    }
    let tokens = llm_tokens();
    for (kind, count) in [
        ("input", m.input_tokens),
        ("output", m.output_tokens),
        ("cached_read", m.cached_read_tokens),
        ("cache_write", m.cache_write_tokens),
        ("reasoning", m.reasoning_tokens),
    ] {
        if let Some(n) = count {
            if n > 0 {
                tokens
                    .with_label_values(&[m.provider, m.model, kind, account])
                    .inc_by(n as f64);
            }
        }
    }

    if let Some(cost) = m.cost {
        // Guard against NaN/negative (a counter can only advance); skip rather
        // than poison the series.
        if cost.is_finite() && cost > 0.0 {
            llm_cost()
                .with_label_values(&[m.provider, m.model, m.currency, account])
                .inc_by(cost);
        }
    }

    llm_calls()
        .with_label_values(&[
            m.provider,
            m.model,
            normalize_finish_reason(m.finish_reason),
            account,
        ])
        .inc();
}

fn client_pings() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_client_pings_total",
            "Server-initiated MCP ping requests to connected streamable-HTTP \
             clients, keyed by outcome: `ok` (pong received), `timeout` (no \
             pong within the wait window), `session_closed` (the loop's \
             normal exit — the session ended), `stopped` (the loop gave up \
             after consecutive timeouts; the session idle timeout resumes \
             control). A rising `timeout`/`stopped` rate means clients are \
             holding sessions whose transport can no longer deliver \
             server-to-client traffic.",
            &["outcome"],
            registry()
        )
        .expect("register mcp_client_pings_total")
    })
}

/// Record one server-initiated client ping outcome. Called from the
/// per-session ping loop in `waygate-mcp`.
pub fn record_client_ping(outcome: &str) {
    client_pings().with_label_values(&[outcome]).inc();
}

fn requests_by_generation() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_requests_total",
            "MCP requests served, keyed by negotiated protocol generation: \
             `legacy` (2025-11-25-and-earlier sessions) or `2026-07-28` \
             (stateless per-request negotiation). The legacy series going \
             flat for the deprecation window is the evidence the \
             legacy-path removal decision requires.",
            &["protocol_generation"],
            registry()
        )
        .expect("register mcp_requests_total")
    })
}

/// Record one served MCP request under its negotiated protocol generation.
/// Called wherever `waygate-mcp` resolves the per-request client context.
pub fn record_protocol_generation(generation: &str) {
    requests_by_generation()
        .with_label_values(&[generation])
        .inc();
}

/// Closed set of downstream `tools/list` projections. Keeping all labels
/// behind one enum prevents client names or other unbounded request metadata
/// from becoming Prometheus cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolListProjection {
    LegacyProgressive,
    LegacyEagerGlobal,
    LegacyEagerClient,
    LegacyCodeModeOnly,
    Stateless2026,
    StatelessCodeModeOnly,
}

impl ToolListProjection {
    fn labels(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::LegacyProgressive => ("legacy", "progressive", "legacy_other"),
            Self::LegacyEagerGlobal => ("legacy", "eager_global", "global_override"),
            Self::LegacyEagerClient => ("legacy", "eager_client", "legacy_allowlisted"),
            Self::LegacyCodeModeOnly => ("legacy", "codemode_only", "compact_allowlisted"),
            Self::Stateless2026 => ("2026-07-28", "stable_full", "stateless"),
            Self::StatelessCodeModeOnly => ("2026-07-28", "codemode_only", "compact_allowlisted"),
        }
    }
}

fn tool_list_requests() -> &'static CounterVec {
    static M: OnceLock<CounterVec> = OnceLock::new();
    M.get_or_init(|| {
        register_counter_vec_with_registry!(
            "mcp_tools_list_requests_total",
            "MCP tools/list requests by negotiated protocol generation and \
             discovery mode. Labels are a closed product vocabulary: legacy \
             progressive disclosure, process-wide eager fallback, per-client \
             eager fallback, client-scoped Code Mode-only projection, or the \
             stable MCP 2026 full projection. \
             `client_class` is a closed projection class rather than the \
             self-asserted client name. No credential, tool name, or payload \
             is recorded.",
            &["protocol_generation", "discovery_mode", "client_class"],
            registry()
        )
        .expect("register mcp_tools_list_requests_total")
    })
}

fn tool_list_returned_tools() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_tools_list_returned_tools",
            "Number of tool declarations returned by one downstream \
             tools/list response, keyed only by the closed projection labels.",
            &["protocol_generation", "discovery_mode", "client_class"],
            vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_000.0],
            registry()
        )
        .expect("register mcp_tools_list_returned_tools")
    })
}

fn tool_list_serialized_bytes() -> &'static HistogramVec {
    static M: OnceLock<HistogramVec> = OnceLock::new();
    M.get_or_init(|| {
        register_histogram_vec_with_registry!(
            "mcp_tools_list_serialized_bytes",
            "Serialized ListToolsResult JSON bytes before the JSON-RPC envelope, \
             keyed only by the closed projection labels.",
            &["protocol_generation", "discovery_mode", "client_class"],
            vec![
                1_024.0,
                4_096.0,
                16_384.0,
                65_536.0,
                262_144.0,
                1_048_576.0,
                2_097_152.0,
                4_194_304.0,
            ],
            registry()
        )
        .expect("register mcp_tools_list_serialized_bytes")
    })
}

/// Record one completed downstream `tools/list` projection and its bounded
/// response-shape measurements. `serialized_bytes` covers the MCP result but
/// deliberately excludes transport framing and the request-specific JSON-RPC
/// envelope.
pub fn record_tool_list_response(
    projection: ToolListProjection,
    returned_tools: usize,
    serialized_bytes: Option<usize>,
) {
    let (generation, mode, client_class) = projection.labels();
    let labels = &[generation, mode, client_class];
    tool_list_requests().with_label_values(labels).inc();
    tool_list_returned_tools()
        .with_label_values(labels)
        .observe(returned_tools as f64);
    if let Some(serialized_bytes) = serialized_bytes {
        tool_list_serialized_bytes()
            .with_label_values(labels)
            .observe(serialized_bytes as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorders_do_not_panic_and_register_idempotently() {
        // Call each recorder twice — the second call hits the already-cached
        // `OnceLock` branch and must not error.
        record_authz_decision("allow", "low");
        record_authz_decision("deny", "high");
        record_authz_latency(0.0005);
        record_upstream_call("example-messages", UpstreamOutcome::Ok, 0.042);
        record_upstream_call("example-observability", UpstreamOutcome::Error, 1.5);
        record_upstream_call_failure("example-messages", "initialize");
        record_upstream_call_failure("example-messages", "dispatched_unknown_outcome");
        record_upstream_safe_retry("example-messages", "attempted");
        record_upstream_safe_retry("example-messages", "recovered");
        set_upstream_runtime_state("example-messages", Some("degraded"));
        set_upstream_runtime_state("example-messages", Some("connected"));
        set_upstream_runtime_state("example-observability", None);
        record_upstream_reconnect_attempt("example-messages");
        record_upstream_reconnect_attempt("example-messages");
        record_upstream_reconnect_failure_episode("example-messages");
        set_upstream_reconnect_schedule(
            "example-messages",
            Some(std::time::Duration::from_secs(7)),
            Some(11),
        );
        record_bearer_validation(BearerOutcome::Ok);
        record_bearer_validation(BearerOutcome::Invalid);
        record_tool_drift("example-messages");
        record_tool_drift("example-messages");
        record_tool_drift("example-observability");
        set_tool_quarantined("example-messages", 2);
        set_tool_quarantined("example-messages", 1);
        set_tool_quarantined("example-observability", 0);
        record_grant_sweep_deleted(5);
        record_grant_sweep_deleted(3);
        record_grant_sweep_error();
        record_evidence_chained_best_effort(ChainedBestEffortOutcome::Attempted);
        record_evidence_chained_best_effort(ChainedBestEffortOutcome::Inserted);
        record_evidence_chained_best_effort(ChainedBestEffortOutcome::Dropped);
        record_evidence_chained_best_effort(ChainedBestEffortOutcome::Unknown);
        record_evidence_chained_best_effort_failure(
            ChainedBestEffortFailureStage::ChainLockContended,
        );
        record_evidence_chained_best_effort_duration(
            ChainedBestEffortTerminalOutcome::Inserted,
            0.005,
        );
        record_evidence_chained_best_effort_duration(
            ChainedBestEffortTerminalOutcome::Dropped,
            0.02,
        );
        record_evidence_chained_best_effort_duration(
            ChainedBestEffortTerminalOutcome::Unknown,
            1.0,
        );
        for posture in [
            EvidenceSubmissionPosture::ChainedBestEffort,
            EvidenceSubmissionPosture::BestEffort,
        ] {
            for outcome in [
                EvidenceSubmissionOutcome::Queued,
                EvidenceSubmissionOutcome::Processed,
                EvidenceSubmissionOutcome::DroppedFull,
                EvidenceSubmissionOutcome::DroppedClosed,
                EvidenceSubmissionOutcome::DroppedShutdown,
                EvidenceSubmissionOutcome::DroppedWorkerPanic,
            ] {
                record_evidence_submission(posture, outcome, 1);
            }
            evidence_submission_pending_inc(posture);
            evidence_submission_pending_dec(posture);
        }
        record_evidence_reason_truncation();
        // Identity-cell instrumentation: inc/dec must balance and the
        // wait histogram must register.
        identity_cell_queue_inc("example-messages");
        identity_cell_queue_inc("example-messages");
        record_identity_cell_wait("example-messages", 0.003);
        identity_cell_queue_dec("example-messages");
        identity_cell_queue_dec("example-messages");
        record_database_pool_connections(DatabasePoolRole::Audit, 8, 2, 8);
        record_database_pool_connections(DatabasePoolRole::Audit, 4, 3, 8);
        record_database_pool_connections(DatabasePoolRole::Control, 2, 2, 8);
        record_database_pool_connections(DatabasePoolRole::Reader, 1, 0, 8);

        let text = crate::gather_text();
        assert!(
            text.contains("mcp_authz_decisions_total"),
            "authz counter missing from gather output:\n{text}"
        );
        assert!(
            text.contains("mcp_upstream_calls_total"),
            "upstream counter missing from gather output:\n{text}"
        );
        assert!(text.contains(
            "mcp_upstream_call_failures_total{phase=\"initialize\",server=\"example-messages\"} 1"
        ));
        assert!(text.contains(
            "mcp_upstream_call_failures_total{phase=\"dispatched_unknown_outcome\",server=\"example-messages\"} 1"
        ));
        assert!(text.contains(
            "mcp_upstream_safe_retries_total{outcome=\"attempted\",server=\"example-messages\"} 1"
        ));
        assert!(text.contains(
            "mcp_upstream_safe_retries_total{outcome=\"recovered\",server=\"example-messages\"} 1"
        ));
        assert!(text.contains(
            "gateway_upstream_runtime_state{server=\"example-messages\",state=\"connected\"} 1"
        ));
        assert!(text.contains(
            "gateway_upstream_runtime_state{server=\"example-messages\",state=\"degraded\"} 0"
        ));
        assert!(text.contains(
            "gateway_upstream_runtime_state{server=\"example-messages\",state=\"disconnected\"} 0"
        ));
        assert!(
            text.contains("mcp_upstream_reconnect_attempts_total{server=\"example-messages\"} 2")
        );
        assert!(text.contains(
            "mcp_upstream_reconnect_failure_episodes_total{server=\"example-messages\"} 1"
        ));
        assert!(
            text.contains("mcp_upstream_reconnect_backoff_seconds{server=\"example-messages\"} 7")
        );
        assert!(text.contains(
            "mcp_upstream_reconnect_next_retry_timestamp_seconds{server=\"example-messages\"} 11"
        ));
        assert!(
            text.contains("mcp_identity_cell_wait_seconds"),
            "identity-cell wait histogram missing from gather output:\n{text}"
        );
        assert!(
            text.contains("mcp_identity_cell_queue_depth"),
            "identity-cell depth gauge missing from gather output:\n{text}"
        );
        assert!(
            text.lines()
                .any(|line| line.contains("mcp_database_pool_connections")
                    && line.contains("role=\"audit\"")
                    && line.contains("state=\"in_use\"")
                    && line.trim_end().ends_with(" 1")),
            "audit in-use pool gauge should reflect the latest snapshot:\n{text}"
        );
        assert!(
            text.lines()
                .any(|line| line.contains("mcp_database_pool_connections")
                    && line.contains("role=\"reader\"")
                    && line.contains("state=\"max\"")
                    && line.trim_end().ends_with(" 8")),
            "reader pool maximum gauge missing:\n{text}"
        );
        assert!(
            text.contains("mcp_tool_drift_total"),
            "tool drift counter missing from gather output:\n{text}"
        );
        // Counter increments accumulate per label.
        assert!(
            text.lines().any(|l| l.contains("mcp_tool_drift_total")
                && l.contains("server=\"example-messages\"")
                && l.trim_end().ends_with(" 2")),
            "example-messages drift counter should be 2 (incremented twice):\n{text}"
        );
        assert!(
            text.contains("mcp_tool_quarantined"),
            "tool quarantined gauge missing from gather output:\n{text}"
        );
        // Set-style: last set wins. example-messages was set to 2 then 1 → 1.
        assert!(
            text.lines().any(|l| l.contains("mcp_tool_quarantined")
                && l.contains("server=\"example-messages\"")
                && l.trim_end().ends_with(" 1")),
            "example-messages quarantined gauge should be 1 (last set wins):\n{text}"
        );
        assert!(
            text.contains("mcp_grant_sweep_total"),
            "grant sweep counter missing:\n{text}"
        );
        // deleted = 5 + 3 = 8 (inc_by, cumulative).
        assert!(
            text.lines().any(|l| l.contains("mcp_grant_sweep_total")
                && l.contains("outcome=\"deleted\"")
                && l.trim_end().ends_with(" 8")),
            "deleted counter should be 8 (5 + 3):\n{text}"
        );
        // error = 1 (single inc).
        assert!(
            text.lines().any(|l| l.contains("mcp_grant_sweep_total")
                && l.contains("outcome=\"error\"")
                && l.trim_end().ends_with(" 1")),
            "error counter should be 1:\n{text}"
        );
        for outcome in ["attempted", "inserted", "dropped", "unknown"] {
            assert!(
                text.lines().any(|line| {
                    line.contains("mcp_evidence_chained_best_effort_total")
                        && line.contains(&format!("outcome=\"{outcome}\""))
                }),
                "chained best-effort {outcome} counter missing:\n{text}",
            );
        }
        assert!(
            text.lines().any(|line| {
                line.contains("mcp_evidence_chained_best_effort_failures_total")
                    && line.contains("stage=\"chain_lock_contended\"")
            }),
            "chained best-effort failure-stage counter missing:\n{text}",
        );
        for outcome in ["inserted", "dropped", "unknown"] {
            assert!(
                text.lines().any(|line| {
                    line.contains("mcp_evidence_chained_best_effort_duration_seconds_count")
                        && line.contains(&format!("outcome=\"{outcome}\""))
                }),
                "chained best-effort {outcome} duration histogram missing:\n{text}",
            );
        }
        for posture in ["chained_best_effort", "best_effort"] {
            for outcome in [
                "queued",
                "processed",
                "dropped_full",
                "dropped_closed",
                "dropped_shutdown",
                "dropped_worker_panic",
            ] {
                assert!(
                    text.lines().any(|line| {
                        line.contains("mcp_evidence_submission_total")
                            && line.contains(&format!("posture=\"{posture}\""))
                            && line.contains(&format!("outcome=\"{outcome}\""))
                    }),
                    "evidence submission {posture}/{outcome} counter missing:\n{text}",
                );
            }
            assert!(
                text.lines().any(|line| {
                    line.contains("mcp_evidence_submission_pending")
                        && line.contains(&format!("posture=\"{posture}\""))
                }),
                "evidence submission {posture} pending gauge missing:\n{text}",
            );
        }
        assert!(
            text.contains("mcp_evidence_reason_truncations_total"),
            "evidence reason truncation counter missing:\n{text}",
        );
    }

    #[test]
    fn server_operation_duration_records_with_bounded_labels() {
        record_server_operation("tools/call", true, 0.123);
        record_server_operation("tools/list", false, 1.5);
        let text = crate::gather_text();
        assert!(
            text.contains("mcp_server_operation_duration_seconds"),
            "metric family must be exported:\n{text}"
        );
        // Closed-cardinality labels: method + outcome only.
        assert!(
            text.contains("method=\"tools/call\"") && text.contains("outcome=\"ok\""),
            "tools/call ok series must be present:\n{text}"
        );
        assert!(
            text.contains("method=\"tools/list\"") && text.contains("outcome=\"error\""),
            "tools/list error series must be present:\n{text}"
        );
    }

    #[test]
    fn tool_list_projection_metrics_export_only_closed_rollout_labels() {
        for projection in [
            ToolListProjection::LegacyProgressive,
            ToolListProjection::LegacyEagerGlobal,
            ToolListProjection::LegacyEagerClient,
            ToolListProjection::LegacyCodeModeOnly,
            ToolListProjection::Stateless2026,
            ToolListProjection::StatelessCodeModeOnly,
        ] {
            record_tool_list_response(projection, 42, Some(65_536));
        }

        let text = crate::gather_text();
        for (generation, mode, client_class) in [
            ("legacy", "progressive", "legacy_other"),
            ("legacy", "eager_global", "global_override"),
            ("legacy", "eager_client", "legacy_allowlisted"),
            ("legacy", "codemode_only", "compact_allowlisted"),
            ("2026-07-28", "stable_full", "stateless"),
            ("2026-07-28", "codemode_only", "compact_allowlisted"),
        ] {
            assert!(text.lines().any(|line| {
                line.contains("mcp_tools_list_requests_total")
                    && line.contains(&format!("protocol_generation=\"{generation}\""))
                    && line.contains(&format!("discovery_mode=\"{mode}\""))
                    && line.contains(&format!("client_class=\"{client_class}\""))
            }));
        }
        assert!(text.contains("mcp_tools_list_returned_tools_bucket"));
        assert!(text.contains("mcp_tools_list_serialized_bytes_bucket"));
        assert!(!text.contains("client_name="));
    }

    #[test]
    fn discovery_metrics_export_only_closed_operational_labels() {
        for operation in [
            DiscoveryOperation::GatewaySearch,
            DiscoveryOperation::GatewayInspect,
            DiscoveryOperation::CodeModeSearch,
            DiscoveryOperation::CodeModeDescribe,
        ] {
            for outcome in [
                DiscoveryOutcome::Ok,
                DiscoveryOutcome::Invalid,
                DiscoveryOutcome::Unavailable,
                DiscoveryOutcome::Error,
            ] {
                record_discovery_operation(operation, outcome, 0.012);
            }
        }
        record_discovery_cursor(DiscoverySurface::Gateway, true);
        record_discovery_cursor(DiscoverySurface::Gateway, false);
        record_discovery_cursor(DiscoverySurface::CodeMode, true);
        for mode in [
            DiscoveryIndexPublication::Slice,
            DiscoveryIndexPublication::Full,
            DiscoveryIndexPublication::Recovery,
        ] {
            record_discovery_index_publication(mode, true);
            record_discovery_index_publication(mode, false);
        }
        for reason in [
            DiscoveryIndexFallback::Unavailable,
            DiscoveryIndexFallback::NoOpinion,
            DiscoveryIndexFallback::QueryError,
            DiscoveryIndexFallback::GenerationChurn,
        ] {
            record_discovery_index_fallback(reason);
        }
        set_discovery_catalog_state(3, 17, 2, 15, DiscoveryIndexState::Unhealthy, 8);
        record_catalog_reconciliation(true, 0.25);
        record_catalog_reconciliation(false, 0.5);

        let text = crate::gather_text();
        for metric in [
            "mcp_discovery_operation_duration_seconds",
            "mcp_discovery_cursor_total",
            "mcp_discovery_index_publications_total",
            "mcp_discovery_index_fallback_total",
            "mcp_discovery_catalog_sources",
            "mcp_discovery_catalog_tools",
            "mcp_discovery_retrieval_index_state",
            "mcp_discovery_retrieval_index_generation",
            "mcp_discovery_retrieval_index_skew_tools",
            "mcp_discovery_catalog_reconciliation_duration_seconds",
        ] {
            assert!(text.contains(metric), "metric {metric} missing:\n{text}");
        }
        assert!(text.contains("mcp_discovery_retrieval_index_state{state=\"unhealthy\"} 1"));
        assert!(text.contains("mcp_discovery_retrieval_index_skew_tools 2"));
        for line in text
            .lines()
            .filter(|line| line.starts_with("mcp_discovery_"))
        {
            for forbidden in ["query=", "cursor=", "tenant=", "tool=", "server="] {
                assert!(
                    !line.contains(forbidden),
                    "discovery metric exposed a forbidden label: {line}"
                );
            }
        }
    }

    #[test]
    fn invocation_admission_metrics_are_exported_with_finite_labels() {
        record_schema_validator_cache_hit();
        record_schema_validator_cache_miss();
        record_schema_validator_cache_eviction();
        record_schema_validator_compile_failure();
        record_invocation_manifest_fallback(true);
        record_invocation_manifest_fallback(false);
        record_invocation_approval_unknown_refusal();

        let text = crate::gather_text();
        for metric in [
            "mcp_schema_validator_cache_hits_total",
            "mcp_schema_validator_cache_misses_total",
            "mcp_schema_validator_cache_evictions_total",
            "mcp_schema_validator_compile_failures_total",
            "mcp_invocation_approval_unknown_refusals_total",
        ] {
            assert!(text.contains(metric), "metric {metric} missing:\n{text}");
        }
        assert!(text.lines().any(|line| {
            line.contains("mcp_invocation_manifest_fallback_total")
                && line.contains("approval_authority=\"known\"")
        }));
        assert!(text.lines().any(|line| {
            line.contains("mcp_invocation_manifest_fallback_total")
                && line.contains("approval_authority=\"unknown\"")
        }));
    }

    #[test]
    fn llm_usage_metrics_record_tokens_cost_and_calls() {
        record_llm_usage(LlmUsageMetric {
            provider: "openrouter",
            provider_account_id: None,
            duration_seconds: Some(1.0),
            gateway_cache_hit: false,
            model: "gpt-x",
            finish_reason: Some("stop"),
            input_tokens: Some(1000),
            output_tokens: Some(500),
            cached_read_tokens: None,
            // A zero-count class must NOT emit a series.
            cache_write_tokens: Some(0),
            reasoning_tokens: None,
            cost: Some(0.0125),
            currency: "USD",
        });

        let text = crate::gather_text();
        assert!(
            text.contains("gen_ai_client_token_usage_total"),
            "token counter missing:\n{text}"
        );
        // Input tokens series carries the count.
        assert!(
            text.lines()
                .any(|l| l.contains("gen_ai_client_token_usage_total")
                    && l.contains("type=\"input\"")
                    && l.contains("model=\"gpt-x\"")
                    && l.trim_end().ends_with(" 1000")),
            "input token series should be 1000:\n{text}"
        );
        // Zero-count cache_write class is skipped — no series.
        assert!(
            !text.contains("type=\"cache_write\""),
            "zero-count token class must not emit a series:\n{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.contains("gen_ai_client_cost_total") && l.contains("currency=\"USD\"")),
            "cost counter series missing:\n{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.contains("gen_ai_client_calls_total")
                    && l.contains("finish_reason=\"stop\"")),
            "calls counter series missing:\n{text}"
        );
    }

    #[test]
    fn account_usage_excludes_cache_replays_and_records_failures() {
        for cached in [false, true] {
            record_llm_usage(LlmUsageMetric {
                provider: "openai",
                model: "account-contract",
                provider_account_id: Some("test-account"),
                input_tokens: Some(7),
                output_tokens: Some(3),
                cached_read_tokens: Some(2),
                reasoning_tokens: Some(1),
                finish_reason: Some("tool_use"),
                duration_seconds: Some(2.0),
                gateway_cache_hit: cached,
                ..Default::default()
            });
        }
        record_llm_request_failure(
            "openai",
            "account-contract",
            Some("test-account"),
            1.0,
            LlmFailurePhase::Dispatch,
        );
        let text = crate::gather_text();
        let lines: Vec<_> = text
            .lines()
            .filter(|line| line.contains("model=\"account-contract\""))
            .collect();
        assert!(lines
            .iter()
            .all(|line| line.contains("user_account_id=\"test-account\"")));
        assert!(lines
            .iter()
            .any(|line| line.starts_with("gen_ai_client_token_usage_total")
                && line.contains("type=\"input\"")
                && line.ends_with(" 7")));
        assert!(lines
            .iter()
            .any(|line| line.starts_with("gen_ai_client_calls_total")
                && line.contains("finish_reason=\"tool_use\"")
                && line.ends_with(" 1")));
        assert!(lines.iter().any(
            |line| line.starts_with("gen_ai_client_request_failures_total") && line.ends_with(" 1")
        ));
        assert!(lines.iter().any(
            |line| line.starts_with("gen_ai_client_duration_seconds_count")
                && line.contains("outcome=\"completed\"")
                && line.ends_with(" 1")
        ));
        assert_eq!(normalize_finish_reason(Some("error")), "error");
    }

    #[test]
    fn finish_reason_is_clamped_to_known_enum() {
        assert_eq!(normalize_finish_reason(None), "unknown");
        assert_eq!(normalize_finish_reason(Some("stop")), "stop");
        assert_eq!(normalize_finish_reason(Some("tool_calls")), "tool_calls");
        // An unknown / novel provider value collapses to "other" so a
        // misbehaving upstream cannot blow up label cardinality.
        assert_eq!(
            normalize_finish_reason(Some("some_novel_reason_xyz")),
            "other"
        );
    }
}
