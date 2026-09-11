# Telemetry

OTel traces (OTLP/gRPC), Prometheus metrics, and the evidence/audit trail,
plus how they correlate. The `EvidenceRecorder` and event-category sections
are authoritative for the audit surface; the spans / propagation / metrics /
correlation / dashboard / collector sections describe the OTel surface.

## EvidenceRecorder

`waygate_mcp::audit::EvidenceRecorder` is the trait every persisted
event flows through. It exposes three write methods so callers can
opt into the right reliability posture per event. The checked-in producer
classification is [`docs/evidence-caller-classification.md`](../evidence-caller-classification.md).

| Method | Delivery semantics | Failure mode |
|--------|--------------------|--------------|
| `record_required(event) -> Result<Uuid, EvidenceError>` | One inline required persistence attempt; the Postgres sink hash-chains a successful row. This is fail-closed, not an at-least-once retry guarantee. | Returns `EvidenceError::Persistence` (write failed) or `Unavailable` (no durable backing, e.g. `NullSink`). Fail-closed callers surface as 5xx. |
| `record_chained_best_effort(event)` | Non-blocking submission to one of four tenant-sharded queues (256 events each). Workers take up to 32 events per receive pass and make one hash-chained persistence attempt per event using the same per-tenant lock and hash transaction as required recording. The PostgreSQL attempt uses non-blocking lock acquisition and a one-second total write deadline. Hierarchy-bearing events enqueue configured external outbox targets inside that same bounded transaction; direct events do not. | Returns `()` after `try_send`. A full/closed queue is a measured drop. During the backing attempt, lock contention and any failure or deadline before commit count as dropped; a commit error or commit deadline counts as unknown because the worker cannot prove whether PostgreSQL committed. Neither outcome fails the originating request. |
| `record_best_effort(event)` | Non-blocking submission to a separate 256-event informational queue; its worker takes up to 32 events per receive pass and uses the Postgres independent-insert fast path, leaving successful rows outside the hash chain. | Returns `()` after `try_send`. Full/closed queue and persistence failures log-and-drop and never surface. The separate queue prevents informational load from consuming chained-evidence capacity. |

The append-only database trigger applies to all three paths. A non-null
`row_hash` marks a chain-covered row; `prev_hash` is null only for a valid
tenant chain root and names the predecessor on later rows. The Postgres
required and chained-best-effort paths supply those values. A signed evidence
bundle protects the bytes exported in that bundle but version 1 does not attest
chain coverage or database completeness.

The production decorator rebuilds any oversized `AuditEvent.reason` into a
fresh allocation of at most 8 KiB at a UTF-8 boundary before inline required
persistence or queue admission. Rebuilding is required: truncating the string's
length alone would retain its original untrusted allocation in the queue. This
makes the fixed event counts a useful memory bound without logging the
discarded text.
At shutdown, HTTP handlers drain first; the recorder then closes admission and
gets up to five seconds within the process-wide cleanup budget to drain
accepted events before any remaining worker is aborted and the database pool
closes. A cancelled shutdown future or a queue handle dropped without shutdown
also closes admission, aborts workers, removes all outstanding events from the
pending gauge, and counts them as `dropped_shutdown` exactly once.

Each channel has 256 buffered slots and its worker can hold one 32-event batch
outside the channel while processing it. The maximum accepted-but-unfinished
set is therefore 1,152 chained events across four shards and 288 informational
events. The pending gauge measures both buffered and worker-held events.

`GATEWAY_AUDIT_MODE` selects the invocation-path posture for the
`InvocationService` pipeline's `record_pre_call` stage. Final governed
invocation outcomes and security refusals use chained best effort regardless
of this mode. Operational reload, discovery, and health events remain
unchained best effort. The complete producer assignment lives in the caller
classification linked above.

- `best_effort` (default) — `record_pre_call` is a no-op. Invocation-path
  final outcomes use `record_chained_best_effort`; a DB outage is measured and
  logged but does not break the request path. Independently fail-closed admin
  mutations continue to use `record_required`.
- `fail_closed` — `record_pre_call` calls `record_required` for
  side-effecting tool calls (`facts.side_effects`). A persistence failure
  returns `InvocationError::AuditUnavailable`, which the adapter
  maps to an HTTP 5xx — the upstream dispatch never happens without a
  durable evidence-of-attempt row. Read-only (`!side_effects`) tools have no
  pre-call row and retain their chained-best-effort final outcome; the operator opts in to
  "evidence for the mutating surface," not "evidence for every
  call." Pre-call rows
  carry `reason = "pre_call"` so SELECTs can distinguish them from the
  post-dispatch outcome row written by `record_outcome`.

The wiring lives in `waygate-mcp::invocation::DefaultInvocationService`
under `record_pre_call`; the recorder fakes used by
`crates/waygate-mcp/tests/suite/fail_closed.rs` pin the matrix (cells:
`{BestEffort, FailClosed} × {!side_effects, side_effects} × {Ok, Err}` —
only `(FailClosed, side_effecting, Err)` blocks dispatch).

### Event categories

Every `AuditEvent` carries an `EvidenceCategory` discriminator
(persisted to `audit_log.category` via migration `0006_audit_category.sql`).
Categories defined today; some are recorded now, others are wiring
in incrementally:

| Category | Recorded today? | Notes |
|----------|-----------------|-------|
| `Invocation` | ✅ tool-call dispatch (Allow / Deny / StepUpRequired / ExecutionError) | Governed final outcomes and security refusals use chained best effort. Fail-closed mode also adds required pre-call evidence for side-effecting tools. |
| `PolicyReload` | ✅ on every SIGHUP that touches the Cedar engine | Success and failure both recorded. |
| `ManifestReload` | ✅ on every SIGHUP that loads `servers/*.yaml` | Success (with a compact added / removed / redialed / redial_failed / classifications_updated / identity_updated summary in `reason`) and parse failure both recorded; no-op reloads still record so operators can see "SIGHUP fired, nothing changed." |
| `ApiKeyLifecycle` | ✅ on `/admin/identities` mint / rename / revoke | `action` carries `ApiKeyMinted` / `ApiKeyRenamed` / `ApiKeyRevoked`; `reason` carries a compact key-identity summary (sub, name, scopes, actor, id). Revokes against an already-revoked row still record so the activity feed shows the operator's intent. Tracing → OTel and DB row → activity feed are written together. |
| `OAuthEvent` | ✅ on `/oauth/token`, `/oauth/callback`, and `/admin/identities` OAuth-session revoke | `action` discriminates the lifecycle point: `OAuthTokenIssued` / `OAuthTokenRefreshed` on success; `OAuthInvalidCode` / `OAuthPkceFailed` / `OAuthRedirectUriMismatch` / `OAuthClientIdMismatch` / `OAuthInvalidRefresh` / `OAuthUnsupportedGrant` / `OAuthMissingParameter` / `OAuthInternal` on token-endpoint rejections; on the EMA token-exchange (ID-JAG mint) grant `OAuthIdJagIssued` on success and `OAuthUnsupportedTokenType` / `OAuthInvalidSubjectToken` / `OAuthUntrustedAudience` / `OAuthUnknownResource` / `OAuthAccessDenied` on its rejections (it also reuses `OAuthClientIdMismatch` / `OAuthMissingParameter` / `OAuthUnsupportedGrant`); `OAuthCallbackCompleted` on success + `OAuthCallback{MissingCode,MissingState,UnknownTransaction,MissingIdToken,InvalidIdToken,UpstreamRejected,Internal}` on callback rejections; `OAuthSessionRevoked` on admin-driven chain revoke. `reason` carries `client_id=… sub=… grant=… detail=…`. `/oauth/authorize` is deliberately not recorded — too early in the flow to know `sub`. |
| `UpstreamHealth` | ✅ once per reconnect failure episode, plus recovery/admin refresh outcomes | `action` is `UpstreamReconnected` (outcome=success) or `UpstreamReconnectFailed` (outcome=execution_error). The first failed attempt opens one evidence episode with the raw dial error and selected retry delay; repeats are represented by the every-attempt metric and sampled power-of-two WARN summaries rather than one audit row per retry. Recovery reports the episode's aggregate failed-attempt count. **Boot-time dial failures are NOT recorded here** — `UpstreamPool::connect_inner` runs before the `.with_evidence()` builder chain can attach a recorder. The first failed scheduled retry opens the episode. Discrete connection-loss events likewise become visible through the recovery episode rather than an unbounded event stream. Correlates with the Grafana upstream-recovery panels. |
| `AdminMutation` | ✅ on operator-driven CRUD across `/admin` REST surfaces | Security-impacting mutations require durable evidence. Producers include catalog approval / quarantine, policy bundle publish / rollback, inspection-rules CRUD, federated_peers CRUD, break-glass mint / revoke, tenant CRUD, rate-limit policy CRUD, api-key profile CRUD, OAuth consent revoke. `action` discriminates the specific mutation; `reason` carries the sanitized identifiers + the actor's sub. |
| `AuthAttempt` | ✅ on every rejected bearer validation in `waygate-oidc::middleware` | `action` discriminates the failure class: `AuthAttemptMissingHeader` (no `Authorization` header), `AuthAttemptRejected` (header malformed OR every validator returned a client-error rejection), `AuthAttemptInfraUnavailable` (one or more validators infra-errored and none accepted — surfaced as HTTP 503). All three carry `AuditOutcome::ExecutionError`. **Successful validations are NOT recorded** — every accepted request immediately produces an `Invocation` row downstream that already carries the principal; emitting an `AuthAttemptAccepted` row per request would 2× the audit-log volume with no security signal. Adapter pattern (`waygate-server::EvidenceAuthAttempts`) translates `AuthAttemptRecorder` outcomes to the bounded `SharedEvidence` submission queue, so rejection floods neither spawn one task per request nor wait on PostgreSQL. `waygate-oidc` stays free of a `waygate-mcp::audit` dependency (which would form a cycle). |
| `ApprovalLifecycle` | ⏳ category reserved; HITL grant lifecycle records `AdminMutation`-category rows today via the `waygate-admin::approval_grants` handler, not a distinct `ApprovalLifecycle` row. Promoting to a dedicated category would let SIEM rules filter approval traffic without joining on `action`; not wired yet. |
| `CatalogDrift` | ✅ on every mode-specific contract mismatch detected during a `tools/list` republish in `crates/waygate-upstream/src/pool/reload.rs`. Compatibility `manifest` mode retains its legacy name/description/input-schema hash; `mcp_annotations` mode hashes both schemas and security metadata. An approved mode cutover seeds the new baseline instead of reporting synthetic drift. `record_observed_schemas` returns the real drift events it detected; while the originating span is still active, the pool captures its trace ID, then a detached task stamps and submits one chained-best-effort row per drifted tool to the bounded queue off the baseline-lock path: `outcome=Denied` when the live contract diverged enough to auto-quarantine, `outcome=Success` for informational drift. This is in addition to the existing `WARN` log and the `mcp_tool_drift_total{server}` metric. First observations and boot-time seeding are not drift and emit nothing. Compliance reviewers can pivot from a metric spike straight to the offending tool's audit row. |
| `DataInspection` | ⏳ category reserved; the inspector chain (Pii / Secrets / Poisoning + per-tenant `inspection_rules`) currently records its findings on the existing `Invocation`-category audit row for the dispatched call (the inspector verdict shows up in `reason` / outcome). A distinct `DataInspection`-category row per finding (rather than per call) would let SIEM enrich a single tool call with multiple inspector hits; the per-finding producer hasn't shipped. |

Reserving the names now means downstream OCSF / syslog / ECS / S3
exporters can stabilise their vocabulary without later
renames.

## OTel spans

Spans export over OTLP/gRPC when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
(unset ⇒ stdout JSON only, picked up by Loki; init lives in
`crates/waygate-telemetry/src/lib.rs`). The MCP operations the gateway
instruments follow the OTel MCP semantic conventions
(<https://opentelemetry.io/docs/specs/semconv/gen-ai/mcp/>):

| Span | Where | `otel.kind` | Attributes |
|------|-------|-------------|------------|
| `tools/call` (inbound) | `waygate-mcp::server::call_tool` | `server` | `mcp.method.name`, `gen_ai.tool.name`, `error.type`, `user.sub` + legacy `mcp.method`, `mcp.tool` |
| `tools/list` (inbound) | `waygate-mcp::server::list_tools` | `server` | `mcp.method.name`, `user.sub` + legacy `mcp.method` |
| `tools/call` (upstream) | `waygate-upstream::pool::call_tool` | `client` | `mcp.server`, `mcp.method.name`, `gen_ai.tool.name`, `error.type`, `upstream.outcome` + legacy `mcp.tool` |

The inbound span is the parent and the upstream span its child (one trace),
joined by `_meta` propagation (below). Attribute notes:

- **`error.type`** — `tool_error` when the tool returns `isError: true`, the
  JSON-RPC error-code string on a protocol error, unset on success. One shared
  helper — `waygate_mcp::protocol::tool_call_error_type` — classifies both
  legs identically.
- **Dual-emit** — the pre-semconv `mcp.method` / `mcp.tool` fields are kept
  alongside the semconv names for a migration window because
  [`docs/compliance.md`](../compliance.md) cites them as SOC2 / NIST control
  evidence. They will be dropped once the doc and any Tempo dashboards cut
  over. `mcp.server` / `upstream.outcome` are gateway-specific (no semconv
  equivalent) and stay permanently.
- **`mcp.session.id`** — not yet emitted; rmcp's `RequestContext` doesn't
  surface the streamable-HTTP session id cheaply. The one remaining semconv
  attribute.
- **No PII** — tool arguments / results are never attached to spans (semconv's
  opt-in `gen_ai.tool.call.{arguments,result}` stay off).

## Trace-context propagation (`_meta`)

MCP is transport-independent (stdio has no headers; one Streamable-HTTP
request multiplexes many JSON-RPC messages), so W3C `traceparent` /
`tracestate` / `baggage` ride in each request's `params._meta`, not
transport headers — MCP 2026-07-28 reserves exactly those three `_meta`
keys for OpenTelemetry propagation, and the same convention applies on the
legacy wire. `crates/waygate-telemetry/src/propagation.rs` is the rmcp-free
carrier:

- **Inbound** — `call_tool` / `list_tools` adopt the agent's context from
  `ctx.meta` as the span parent (`adopt_parent`); rmcp lifts the wire
  `params._meta` onto `ctx.meta`.
- **Outbound** — the upstream `call_tool` injects the current span into a
  fresh `params._meta` (`inject_span`) so the upstream server continues the
  trace.
- **Baggage** — rides with trace context: entries extracted alongside a
  `traceparent` survive on the span's adopted parent context and are
  re-injected outbound. The gateway relays, never originates, baggage; a
  `baggage` key without a `traceparent` is not adopted; the SDK's W3C
  limits (64 entries / 8 KiB) bound what an untrusted caller can relay.

Best-effort: no `traceparent`, or no tracer provider installed ⇒ no-op.

## Prometheus metrics

Pull-based, scraped at `/metrics`; all registered in
`crates/waygate-telemetry/src/metrics.rs` under the `mcp_` prefix (the
canonical list also appears in [`docs/compliance.md`](../compliance.md)
MEASURE 1). Operation-duration highlights:

- `mcp_server_operation_duration_seconds{method,outcome}` — gateway-as-server
  handling time (semconv `mcp.server.operation.duration`); `outcome` is
  `ok`/`error`, where a tool-level `isError` counts as `error`.
- `mcp_upstream_latency_seconds{server}` — the client-leg duration (semconv
  `mcp.client.operation.duration`).
- `mcp_schema_validator_cache_{hits,misses,evictions}_total` and
  `mcp_schema_validator_compile_failures_total` — bounded-cache effectiveness
  and approved schemas refused during Stage 6 validation preparation.
- `mcp_invocation_manifest_fallback_total{approval_authority}` and
  `mcp_invocation_approval_unknown_refusals_total` — calls admitted from
  manifest facts and the subset refused because HITL requirements were not
  authoritative. `approval_authority` is the closed set `known|unknown`.
- `mcp_evidence_chained_best_effort_total{outcome}` — attempted, inserted,
  dropped, and unknown hash-chained best-effort evidence writes. Unknown means
  commit started but the caller did not observe whether PostgreSQL committed. A
  task cancelled during an asynchronous write can leave an attempted count
  without a terminal outcome.
- `mcp_evidence_chained_best_effort_failures_total{stage}` — the exact bounded
  write stage for every terminal failure. `tx_commit` is an unknown outcome;
  stages before commit are confirmed drops.
- `mcp_evidence_chained_best_effort_duration_seconds{outcome}` — end-to-end
  latency by terminal outcome (`inserted`, `dropped`, or `unknown`). Movement
  toward the one-second bucket boundary exposes database or pool pressure.
- `mcp_evidence_submission_total{posture,outcome}` — bounded queue transitions
  for `chained_best_effort|best_effort`: `queued`, `processed`,
  `dropped_full`, `dropped_closed`, `dropped_shutdown`, or
  `dropped_worker_panic`. `processed` means the backing recorder completed its
  attempt; the write-outcome metrics above remain authoritative for durable
  insert/drop/unknown classification.
- `mcp_evidence_submission_pending{posture}` — accepted events not yet
  completed by the backing recorder, including buffered and active events.
- `mcp_evidence_reason_truncations_total` — events whose free-form `reason`
  exceeded 8 KiB and was truncated before queueing or required persistence.
- `gateway_upstream_protocol_generation{server,generation}` — connected
  upstream lanes by negotiated MCP protocol generation (closed label set:
  the served revisions plus `other`), updated at every lane publication
  transition. The fleet-migration input to the legacy-removal decision;
  charted on the dashboard's "Upstream protocol generation" panel.
- `mcp_upstream_reconnect_attempts_total{server}` and
  `mcp_upstream_reconnect_failure_episodes_total{server}` — every launched
  reconnect batch (including one later cancelled/superseded) and the subset
  that begin a new aggregated failure episode.
- `mcp_upstream_reconnect_backoff_seconds{server}` and
  `mcp_upstream_reconnect_next_retry_timestamp_seconds{server}` — the current
  selected full-jitter delay and its wall-clock deadline; both return to zero
  after recovery or removal. Exporting the timestamp rather than “seconds
  since” follows the [Prometheus instrumentation guidance](https://prometheus.io/docs/practices/instrumentation/).
- `gateway_upstream_runtime_state{server,state}` — one-hot authoritative
  runtime availability using the closed `connected|degraded|disconnected`
  state set. `/metrics` refreshes it from the same pool snapshot consumed by
  readiness, REST, dashboard, MCP resources, and triage immediately before
  gathering. Removed server labels are zeroed, and every later scrape
  reconciles the complete active set so a racing stale snapshot cannot leave
  a permanent nonzero series. Charted on the dashboard's "Authoritative
  upstream runtime state" panel.
- `mcp_tools_list_requests_total{protocol_generation,discovery_mode,client_class}` —
  downstream catalog requests split across `legacy` progressive,
  process-wide eager, and per-client eager modes plus the MCP `2026-07-28`
  stable-full projection. All labels come from one closed enum; `client_class`
  distinguishes stateless, allowlisted legacy, other legacy, and the global
  override without recording the self-asserted client name. Client names,
  credentials, tool names, and payloads are never labels. This is the
  rollout/rollback signal for the legacy projection and is charted on the
  dashboard's "Downstream tools/list projection rate" panel.
- `mcp_tools_list_returned_tools{protocol_generation,discovery_mode,client_class}`
  and `mcp_tools_list_serialized_bytes{...}` — response-shape histograms for
  each closed projection class. Serialized bytes cover compact
  `ListToolsResult` JSON before the request-specific JSON-RPC envelope and
  transport framing. The dashboard charts p95 values so a rollout exposes
  catalog expansion without per-client or per-tool cardinality.
- `mcp_discovery_operation_duration_seconds{operation,outcome}` — end-to-end
  authorization-scoped gateway and Code Mode discovery latency. Both labels use
  closed enums; the dashboard charts p95 by operation and outcome.
- `mcp_discovery_cursor_total{surface,outcome}` — accepted and rejected
  continuation attempts for gateway and Code Mode search. Cursor values and
  queries are deliberately absent.
- `mcp_discovery_index_publications_total{mode,outcome}` and
  `mcp_discovery_index_fallback_total{reason}` — legacy compatibility-index
  publication outcomes and bounded reasons that `searchTools` scanned the
  authoritative catalog instead.
- `mcp_discovery_catalog_sources{plane}`,
  `mcp_discovery_catalog_tools{plane}`,
  `mcp_discovery_retrieval_index_state{state}`,
  `mcp_discovery_retrieval_index_generation`, and
  `mcp_discovery_retrieval_index_skew_tools` — the current authoritative
  upstream scope compared with the legacy index. Gateway-local tools use the
  canonical ranker and are intentionally outside this comparison. The state is
  one-hot and all vector labels are closed product vocabularies.
- `mcp_discovery_catalog_reconciliation_duration_seconds{outcome}` — duration
  of the atomic manifest-to-catalog reconciliation keyed only by success or
  error.

These families drive the dashboard panels “Discovery catalog and compatibility
index,” “Discovery compatibility-index state,” “Governed discovery latency
p95,” “Discovery continuation outcomes,” “Discovery index publication and
fallback,” and “Catalog reconciliation latency p95.” Queries, credentials,
tenant identifiers, client identities, tool names, and cursor values stay out
of every discovery metric label.
- `mcp_database_pool_connections{role,state}` — one-second snapshots of the
  isolated `audit|control|reader` pools. `state` is the closed set
  `in_use|idle|max`; `in_use + idle` is the current established size and
  `max` is that role's configured permit ceiling. The reader series is absent
  when its pool failed to connect and dashboard reads use the control fallback.

Queue-full and queue-closed drops emit a warning immediately per posture, then
at most once every ten seconds while drops continue. The warning exposes event
ID, category, audit outcome, action, tenant, trace ID, posture, submission
outcome, shard, channel count, per-channel capacity, total pending events, and
the intervening suppressed-warning count. It never includes `reason`, request
or response bodies, or other free-form payloads. Metrics count every drop even
when its repetitive warning is suppressed.

A panic from the backing recorder is contained at the individual event
attempt, counted immediately as `dropped_worker_panic`, and logged with
metadata-only event ID/category, posture, outcome, and suppression count at
most once every ten seconds per worker. The worker then continues draining its
channel, so one bad attempt cannot strand a shard or leave buffered events
falsely pending.

Chained best-effort failures log immediately, then at most once every ten
seconds while an outage continues. Each emitted failure includes the write
stage, terminal outcome, elapsed time, tenant/action/trace correlation, live
pool size and idle count, and the number of intervening logs suppressed. The
first successful write after ten failure-free seconds emits a recovery summary.
Metrics are incremented for every event even when its repetitive log is
suppressed.

The database-pool monitor reads SQLx's in-process counters once per second; it
does not query Postgres or acquire a connection. On the transition to
`size=max && idle=0`, it emits one WARN with `pool_role`, `pool_size`,
`pool_idle`, and `pool_max`; recovery emits one INFO with the same fields.
This makes an acquire-timeout incident attributable to audit, control-plane,
or reader demand without repeating a warning every second while saturation
persists.

**Cardinality discipline** — label sets are bounded at registration: `server`
(manifest count) and closed enums (`decision`, `risk`, `outcome`, `method`).
We deliberately do **not** label by `tool` or `user.sub`; that per-call detail
lives on the spans (`gen_ai.tool.name`) and the audit log, not in metric
series. A PR adding a metric or label should also grow the dashboard.

## Model usage by provider account

The `gen_ai_client_token_usage_total`, `gen_ai_client_calls_total` and
`gen_ai_client_cost_total` families carry `user_account_id`, obtained from the
trusted credential snapshot used for Codex dispatch. Missing metadata uses
`unknown`; a credential slot and an inbound gateway principal are not Codex
accounts. Account cardinality follows configured provider credentials and their
replacement history. Account metadata is carried through unary/image responses
and stream aggregation into the usage sink, but is not added to the database
ledger.

Token categories retain provider-reported meanings. For OpenAI, cached reads
are a subset of input and reasoning is a subset of output; do not add those
subsets to totals. Missing counts remain absent. Gateway cache replays do not
increment provider usage counters. Catalog-computed cost is an estimate and
does not establish subscription charges or remaining allowance.

`gen_ai_client_duration_seconds` measures terminal calls and failed requests.
`gen_ai_client_request_failures_total` separates dispatch failures, broken
streams and streams abandoned before completion. The latter does not prove a
provider defect. A provider-reported terminal error remains visible under
`gen_ai_client_calls_total{finish_reason="error"}`. No exception text, prompt,
result, caller identity or credential value is a metric label.

Completed usage metrics retain the existing best-effort database usage-sink
path; DB-less deployments do not emit them. Failures are measured independently.
Incomplete streams may have incurred provider usage without terminal token
counts, so token totals are lower bounds when those failures occur. Native
Codex session, compaction, tool decision and approval concepts are not emitted
by the Gateway model API. Upstream MCP reliability metrics remain global and
cannot be joined to Codex accounts without a verified caller mapping.

The Waygate dashboard includes account-oriented token, terminal outcome,
failure and duration panels. These are separate from native Codex exporter
events and must not be treated as duplicate observations of the same call.

## Audit ↔ trace correlation

`AuditEvent` (`crates/waygate-evidence/src/audit.rs`) carries `trace_id`, persisted
on the row by `crates/waygate-storage/src/audit.rs`. The
`TraceStampingRecorder` decorator — wired outside the bounded queue at the
sink's construction site in `waygate-server::main`, so every category captures
the active request trace before asynchronous submission — stamps `trace_id` on
every recorded event. A Grafana/Tempo trace therefore pivots to its audit rows
and back without detached-task context loss. Events recorded outside a request
span (boot-time policy reloads, periodic sweepers) carry `trace_id = NULL` by
design.

## Grafana dashboards

`dashboards/mcp-gateway.json` — one panel set per concern: request volume,
authz decisions (by outcome × risk), bearer validations, upstream calls +
latency, identity-cell wait/queue-depth, authz-latency heatmap,
server-operation duration p50/p95/p99 by `method × outcome`, invocation
schema-validator cache activity, manifest-fallback/refusal rates, bounded
evidence queue depth/drop rates, and chained evidence failure stages plus p95
write latency, plus database-pool connections and utilization by isolated
workload role, upstream protocol generations, and authoritative upstream
runtime state. Datasource uid `prometheus`;
import into Grafana or provision via the LGTM stack.

Upstream lifecycle recovery has two bounded-cardinality counters:
`mcp_upstream_call_failures_total{server,phase}` separates dial,
initialization, pre-dispatch, known refusal, and unknown-outcome failures;
`mcp_upstream_safe_retries_total{server,outcome}` separates attempted,
recovered, and exhausted gateway-owned retries. Neither carries tool names,
URLs, exception text, or caller identity. Use the `trace_id` returned in a
bounded operational error to inspect the protected trace/log for full detail.

## OTel Collector + sampling (runbook)

Production routes spans through an OpenTelemetry Collector rather than
exporting straight to a backend:

- **Buffering** — the Collector decouples the gateway from backend outages.
  The gateway's batch exporter has a 5s timeout and drops on a wedged
  endpoint, so a local/in-cluster Collector absorbs blips.
- **Tail sampling** — for unpredictable agent-driven load, keep every failed
  call and sample the rest. The reliable signal the gateway emits is
  `error.type` (set on failed `tools/call` spans), so key the keep-policy on
  it:

  ```yaml
  processors:
    tail_sampling:
      decision_wait: 10s
      policies:
        - name: keep-errors          # any span carrying error.type
          type: string_attribute
          string_attribute: { key: error.type, values: ['.+'], enabled_regex_matching: true }
        - name: baseline             # sample the rest
          type: probabilistic
          probabilistic: { sampling_percentage: 10 }
  ```

  Risk-tier-based sampling would need a risk attribute on the span (not
  currently emitted — risk lives on metrics/audit).
- **Compression + batch** — enable `gzip` and a `batch` processor; GZIP cuts
  OTLP payloads 60–80%.
- **Env** — `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317` (gRPC
  only — see README), plus `OTEL_SERVICE_NAME` and
  `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=…`.

## Source map

- Init + tracing/OTLP layer: `crates/waygate-telemetry/src/lib.rs`.
- `_meta` propagation carrier: `crates/waygate-telemetry/src/propagation.rs`.
- trace_id correlation helper: `crates/waygate-telemetry/src/correlation.rs`.
- Prometheus metrics: `crates/waygate-telemetry/src/metrics.rs`.
- Dashboards: [`dashboards/`](../../dashboards/).
- Env vars: [`README.md`](../../README.md) (`OTEL_EXPORTER_OTLP_ENDPOINT`, …).
