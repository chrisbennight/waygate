# Explain calls, refusals, and incidents

The gateway connects operational metrics, request traces, and durable evidence.
An operator can investigate which principal called a tool, which policy refused
it, how an upstream behaved, and which nested Code Mode step produced an event.
These signals answer different questions and have different persistence guarantees.

## Investigate a failed call

1. Keep the bounded error code and trace ID returned to the client. Do not copy
   bearer tokens, file contents, or provider credentials into an incident report.
2. Inspect **Activity** in the authenticated dashboard, or use the scoped
   `gateway-observe.query_audit` and `activity_summary` tools. Filter by the
   relevant time window, tool, and outcome using the live schemas.
3. Follow the trace ID into your configured trace backend to inspect request
   stages and upstream latency. Code Mode evidence also carries execution,
   step, call, and attempt identities.
4. Check upstream runtime health and catalog state. `triage_digest` combines
   durable signals for an observation-capable caller; an admin can choose the
   appropriate recovery action after diagnosis.

Authorization simulation is useful for explaining a candidate policy decision.
It does not execute the tool or grant future access; the actual invocation
still checks current authority and state.

Audit queries default to 20 rows and activity summaries to 10 top tools.
Positive explicit counts are honored. Responses report the requested count and
the applied SQL limit; counts beyond the database integer range saturate to that
range. Tenant scope, filters, and audit retention still determine available rows.

## Inspect rejected output schemas

On **Servers**, expand the **Output schemas** rejection count to see each
affected tool, the root type the upstream declared, and the recovery steps.
`absent` means the schema omitted its root `type` field. These diagnostics cover
published tools whose output schema lacks the required `type: "object"` root;
the tools remain callable with that optional schema omitted. Fix the upstream
definition and refresh its catalog from the server's Overview panel.

Over MCP, call `gateway-observe.describe_resource` with
`{"resource_type":"server"}`, then `gateway-observe.read_resource` with the
same argument. Each visible server row includes `rejected_output_schema_count`
and `rejected_output_schemas`, containing the unqualified tool name,
`observed_type`, and `reason`. These are current observations on the replica
serving the request, collected across its connected lanes. When lanes disagree,
the first rejecting lane's root type is shown. Both fields are null when the
catalog row has no loaded runtime entry; an empty list means no current refusals.

Historical events are available through `gateway-observe.query_audit` with
`{"server":"example","category":"upstream_health","since":"2w"}`.
Look for `UpstreamOutputSchemaRejected`. Audit retention and best-effort delivery
can limit that history. `gateway-control.refresh_server_catalog` is the
admin-authorized recovery action after the upstream definition is corrected.

## Configure the signals

For a reproducible starting point, run the [quickstart checker](../../examples/quickstart/README.md).
It calls `demo.greet` and attempts the forbidden `demo.restricted` tool. Note
the run's time window, then inspect Activity for those tool names. The
successful greeting and authorization refusal should be distinguishable; the
refused operation should not appear as a successful upstream dispatch.

With a Prometheus scraper attached to this isolated gateway, these queries
use the same metrics as the supplied dashboard:

```promql
sum(increase(mcp_authz_decisions_total{decision="deny"}[5m]))
sum(increase(mcp_upstream_calls_total[5m]))
```

Allow at least two scrapes around the exercise. These counters summarize all
calls in the selected scrape targets and window; they are not per-request
receipts. Use audit records and trace correlation for attribution. The
quickstart does not install a Prometheus or trace backend for you.

| Signal | Setup | Use |
| --- | --- | --- |
| Durable audit | Configure Postgres and choose invocation audit mode | Attributed activity, policy outcomes, governance events, and execution hierarchy. |
| Distributed traces | Set `OTEL_EXPORTER_OTLP_ENDPOINT` for OTLP/gRPC export | Follow timing and failures across request stages and services. |
| Prometheus metrics | Scrape `/metrics` through an appropriately restricted deployment route | Request rates, latency, upstream health, queue pressure, and resource utilization. |
| Dashboard panels | Import [the supplied Grafana dashboard](../../dashboards/mcp-gateway.json) and configure its datasource | Explore the metrics without a dependency on a particular home monitoring stack. |

The [OpenTelemetry MCP conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/)
ground the trace attributes. The [telemetry reference](../agents/telemetry.md)
lists metric names and correlation behavior. Collector addresses, datasource
credentials, log routing, and retention are operator configuration.

## Know what the evidence proves

The Postgres audit table is append-only. Required and chained-best-effort
recording paths also hash-chain successful rows; informational best-effort rows
are not chain-covered. The [producer classification](../evidence-caller-classification.md)
states which path each event uses.

Required recording fails a dependent operation when persistence fails.
Best-effort channels use bounded queues and can drop evidence under pressure;
commit uncertainty is reported separately from a known drop. Monitor queue,
drop, and unknown-outcome metrics instead of assuming every call has a durable
receipt. Invocation audit mode controls the pre-call posture; it does not make
all final outcomes synchronously durable.

Hash verification can expose alteration of chain-covered records, but does not
by itself prove completeness. A signed export protects the exported bytes;
version 1 does not attest complete database coverage. Missing database
configuration uses a warning-producing null sink in development, and therefore
does not provide a durable audit trail.

The [compliance mapping](../compliance.md) connects implementation evidence to
control concepts. It is engineering documentation, not a certification or an
independent audit of your deployment.
