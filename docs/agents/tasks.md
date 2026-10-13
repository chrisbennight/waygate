# MCP Tasks and durable execution

MCP task augmentation supports upstream-owned work and projects the Code Mode execution journal. Load this
reference when changing task dispatch in `crates/waygate-mcp/src/server.rs` or
execution ownership, polling, cancellation, and continuation in
`crates/waygate-codemode/`.

## Client contract

Task-augmented `codemode.execute` and `codemode.resume` return an execution ID
after admission and an atomic worker claim. `tasks/get` projects lifecycle,
input-required pauses, and bounded completed results throughout retention.
`tasks/cancel` requests owner-scoped cancellation. Task augmentation requires
explicit result storage and a database; see [Code Mode](../codemode.md).

`tasks/update` supplies input to a continuation. The router resolves the
continuation before checking its current Cedar authorization. Updates must
match the execution owner and effective credential profile. Exactly one
recognized input key is accepted, and the atomic claim rechecks execution
state. Polling observes the resumed worker asynchronously.

The journal owns worker fencing, recovery state, immutable tool snapshots,
events, and results. `codemode.result`, `codemode.artifacts`, and
`codemode.artifact` retrieve persisted outputs under the same ownership,
profile, current authorization, and retention checks. `codemode.executions`
lists the caller's executions, allowing recovery of a lost handle.

## What survives restarts, disconnects, and replica changes

Each kind of work has a different owner, so each survives differently. A
restart here is a graceful shutdown within `GATEWAY_DRAIN_TIMEOUT_SECONDS`. A
crash skips the drain: in-flight responses are lost, and Code Mode runs are
reconciled once their claim lease lapses, with `worker_lease_expired` or
`effect_outcome_unknown`.

| Work | Gateway restart | Client disconnect | Next request on another replica |
|---|---|---|---|
| Detached Code Mode run (`codemode.start`, or a task-augmented `execute` or `resume`) | Finishes if it can within the drain window. Otherwise it is recorded at shutdown as `expired` with `worker_interrupted`, or `effect_outcome_unknown` when a side effect may have applied. It is never replayed. | No effect. The run does not depend on the request that started it. | Status, results, and cancellation work from any replica. |
| Paused Code Mode run (`waiting_for_resume`) | Survives. It holds no worker and expires only at retention. | No effect. | Resumes on any replica. |
| Blocking `codemode.execute` | Finishes if it can within the drain window. Otherwise its response is lost, and with a database the run is recorded at shutdown as interrupted, like a detached run. | The program runs to completion. A 2025-11-25 client can resume the response stream with `Last-Event-ID` on the same replica while its session lives. | A repeated call runs the program again. |
| Upstream-owned task | The route survives and the work stays with the upstream. A local-process upstream's tasks end with the gateway unless its task store outlives the process. | Does not cancel the upstream work. A task ID the client never received cannot be recovered. | Works on any replica with the same upstream configuration. |
| Ordinary tool call | Finishes if it can within the drain window. Otherwise it is cancelled upstream and its outcome is unknown. | A 2026-07-28 disconnect cancels it upstream. A 2025-11-25 call keeps running, and its response stream can be resumed on the same replica while the session lives. | A 2026-07-28 request is served by any replica. A 2025-11-25 session lives on one replica and must re-initialize elsewhere. |

No work is repeated automatically after a restart or disconnect. See
[upstream call cancellation](upstreams.md#upstream-call-cancellation) and the
[Code Mode durability model](../codemode.md) for the details behind each row.

## Operator visibility

The metadata-only operator API exposes identity, ownership, lifecycle state,
claim liveness, and age:

```text
GET  /api/v1/admin/codemode/executions
POST /api/v1/admin/codemode/executions/{id}/cancel
```

Both routes require `mcp:admin` and tenant confinement. They do not expose
results, checkpoints, source, or snapshots. Cancellation uses the journal's
cancellation semantics, records the operator in the execution event, and emits
a required admin-mutation audit event. Implementation:
`crates/waygate-admin/src/codemode_executions.rs`.

## Upstream-owned Tasks

The gateway can relay native `io.modelcontextprotocol/tasks` on MCP 2026-07-28
connections. It forwards `tasks/get`, `tasks/update`, and `tasks/cancel` to the
originating upstream. There is no gateway worker, queue, execution journal, or
background polling for this work. Clients poll; task notifications are not
implemented. The same adapter serves any compatible upstream execution engine.

Enable routing with `GATEWAY_DATABASE_URL`. All replicas must use the same
PostgreSQL database. `GATEWAY_UPSTREAM_TASK_RETENTION_SECONDS` defaults to 129600
(36 hours), accepts 1 through 31536000 seconds, and measures retention from
upstream task creation, as the standard's `ttlMs` does. The advertised lifetime
is the shorter of upstream retention and this configured limit. Polling does
not renew it. Changing the configured limit applies to newly issued IDs;
existing records keep their original expiry. Without a database, the gateway
still boots and withholds upstream task capability. Code Mode's independently
configured Tasks support is unchanged. New upstream Tasks do not require
`GATEWAY_MRTR_STATE_KEY`; its continuation and cursor uses are unchanged.

The client keeps a short opaque task ID (`wgt_` plus a random UUID without
hyphens, 36 ASCII characters). Its size is independent of routing metadata.
The immutable `upstream_task_routes` record binds the upstream task ID,
server configuration, admitted tool contract, original operation selection and
typed request facts (including recipient domains and the argument hash),
tenant, issuer, subject, authentication method, and API-key profile. It contains
no other tool arguments, credentials, or execution result. These records contain
sensitive identity and policy metadata and require the same database access and
backup protection as other gateway state. A task ID is not bearer authority:
every request authenticates the caller, rechecks current policy and profile
restrictions, and uses the existing upstream identity and connection gates.
Updates use the original operation's classification; approval-gated updates
require a fresh grant bound to `{taskId, inputResponses}`. Reads and cancellation
do not consume a new execution grant. Lifecycle evidence is named `TaskGet`,
`TaskUpdate`, or `TaskCancel`.

Only an update is charged against the caller's rate limits, because input
advances the work. In fail-closed audit mode, an update or cancellation of a
side-effecting operation writes the required pre-call evidence, as the call
that started it did. A status read and a cancellation start no new execution,
so neither consumes a rate-limit token: an exhausted execution budget must
never stop a caller from following or stopping its own work. A status read
changes nothing upstream, so its `TaskGet` outcome row is its evidence; a
status the gateway refuses to relay, such as metadata that inspection would
have to redact, is recorded the same way. There is no separate limit
for status reads. Each read still authenticates the caller and rechecks
ownership and current policy. Polling faster than the upstream's
`pollIntervalMs` adds load without returning fresher state; the gateway does
not throttle it.

The shared database and unchanged upstream configuration make routing portable
across gateway restarts and replicas. Database errors refuse routing; there is
no process-local or encrypted-handle fallback. If saving a mapping fails after
upstream submission, the error warns that work may already be running. Do not
automatically resubmit the tool call: recover through the upstream's own task
or idempotency interface. A lookup failure never triggers tool execution.
Expired records are inaccessible immediately; each replica removes a bounded
batch of expired metadata every minute. Cleanup never contacts an upstream.

The upstream must itself provide durable, identity-bound task IDs and make the
same task store reachable from every serving instance. This applies to both
remote and local-process transports. Replacing an upstream with unrelated state
at the same address is not a supported recovery method. A removed upstream is
refused; a changed manifest or tool contract cannot inherit outstanding IDs.
Restoring the exact originating configuration can restore access before expiry.
An unavailable upstream returns an operational error; it does not become a
failed or cancelled task. Expiry removes access, not upstream work, and neither
client disconnect nor gateway shutdown implicitly cancels that work.

### Transition from encrypted handles

Previously issued `waygate-task-v1.` handles are explicitly rejected by this
version; they are not imported into the database. Drain outstanding tasks on
the old version before upgrading, or recover them through the originating
upstream. Upgrade serving replicas together: old replicas cannot route new
short IDs, and new replicas cannot route old encrypted handles. Apply the new
migration through normal gateway boot, and retain the shared routing database
through subsequent restarts and deployments. Upgrading never cancels upstream
work. This transition affects native upstream Tasks only.

The upstream atomically resolves outstanding input keys and ignores stale or
already-satisfied keys according to the extension. The gateway forwards the
standard typed input responses and never retries an ambiguous update or initial
submission. Caller retries of original submissions need the upstream operation's
own idempotency contract; Tasks does not invent one. Cancellation acknowledges
intent; only a subsequent observed `cancelled` status confirms termination.

Completed task results pass through the existing retained-response reader,
trust checks, response inspection, schema validation, and governed file plane.
Polling again after a delivery failure retries retrieval, never tool execution.
For an authenticated invocation with configured file output storage, tool and
task dispatch declare Waygate's own file-download capability on every request,
including terminal `tasks/get`. This is independent of downstream native file
support: helper clients can consume the resulting gateway reference too.
Per-call and reused connections use the actual connection's permitted
transports. Disabled storage and anonymous calls do not advertise file output;
Tasks and elicitation negotiation retain their existing rules. See the
[file output interoperability contract](../file-transfer.md#file-output-negotiation-for-tools-and-tasks)
for upstream requirements, native client metadata, and helper behavior.
File retention is governed separately from task retention; a task lifetime is
not a promise that all upstream files will remain available for that duration.
Annotation-native upstreams provide trust labels on task envelopes and final
tool results just as they do on ordinary results and MRTR pauses. Metadata that
an inspector would redact is withheld rather than rewriting task identity or
input instructions. Completed tool results retain normal redaction behavior.

Existing file-plane limits still apply: `structuredContent` FileValue output
is supported; descriptors embedded inside the bytes of another downloaded file
are not recursively imported (issue #31). Gateway file uploads inside
`tasks/update` input are not supported yet and are refused by the file-input
admission gate. Ordinary text and structured elicitation responses are supported.

Code Mode continues to project its own durable executions. Its connector calls
currently do not declare native upstream Tasks or expose lifecycle RPCs inside
JavaScript; an upstream requiring Tasks therefore returns a capability refusal
on that path. Native Tasks clients use the MCP lifecycle directly. There is no
silent synchronous polling fallback.
