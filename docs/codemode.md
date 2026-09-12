# Gateway-native Code Mode

This document defines the product and architecture contract for Code Mode
execution, its SDK and runner boundary, execution persistence, mutation
handling, data-flow enforcement, and nested tool-call context.

## Status

Code Mode is under active development. Direct MCP tools and SEP #1888
progressive discovery remain supported alongside the initial Code Mode surface.
`codemode.search`, `codemode.describe`, and direct-authority
`codemode.execute` are available. Client-authored programs can call every
operation the same principal can call directly, except recursive Code Mode
operations; each nested call re-enters the ordinary invocation path.
Persisted executions write through a
durable journal with fenced ownership and immutable tool snapshots.
`execution.wait(milliseconds)` lets a program pace polling without spinning while
spending the same operator execution budget as computation.
`execution.pause(checkpoint)` and `codemode.resume` provide explicit durable
continuations through normal calls and optional MCP Task augmentation.
The MCP Tasks interface
also projects durable executions for direct status polling, bounded result
retrieval, and owner-scoped cancellation.
Persisted programs can emit bounded intermediate JSON artifacts and receive
stable references before continuing; normal and task-augmented executions share
the same owner-scoped artifact and final-result retrieval tools.
Source-taking tools accept inline JavaScript, an owner-scoped uploaded
`mcp-file`, a private retained SHA-256, or a JavaScript resource available from
the approved Agent Skills catalog. Compatibility metadata is optional and never
blocks execution. Inline, uploaded, and skill source can be retained for bounded
reuse for up to 24 hours.

The [workflow guide](guides/code-mode.md) demonstrates discovery, compact
results, artifacts, and durable pause/resume. Execution hierarchy records the
parent execution, ordered step, nested call, and attempt. Automatic recovery
of uncertain external mutations, general information-flow enforcement, and
compensation remain design work; the contracts below distinguish those
proposals from implemented execution behavior.

## Capability contract

Code Mode is an additional client of the governed data plane:

- Upstream servers remain ordinary typed MCP servers.
- Clients retain direct tool calls and progressive discovery.
- A bounded runner receives generated APIs, never credentials or ambient host
  authority.
- Every nested tool call uses `InvocationService`; the outer Code Mode
  authorization never substitutes for per-call authorization.
- Tool identity, schemas, and governance classification are immutable within
  an execution. Current identity, policy, profile, and revocation state are
  nevertheless checked before each new dispatch.
- Connector identity includes canonical hashes of the exact admitted input and
  output schemas. A catalog `schema_hash` is retained separately as provenance
  because historical and manifest-imported catalog hashes do not necessarily
  cover both live schemas.
- A tool whose arguments select among reviewed operations carries a canonical
  hash of that per-operation definition in its identity, and discovery
  publishes the same hash. Which classification a call is authorized under
  depends on the definition, so the identity has to bind it; a discovery
  surface that could not publish it would describe a contract weaker than the
  one governing the call. The hash is absent, not null, for a tool classified
  by name alone.
- A direct-authority program follows ordinary dispatch-tool behavior: a
  reviewed operation uses its refined classification, while an unreviewed
  value keeps the conservative tool-level classification. Skill scripts use
  this same contract; their source form does not impose another authority ceiling.
- Durable execution state is an internal domain. MCP Tasks may project it to
  clients but does not define its storage or recovery semantics.
- Privileged gateway control-plane changes retain their ordinary direct-call
  controls, including the `waygate-changeset` maker/checker flow where the
  operation requires it. Code Mode neither adds nor removes administrative
  authority held by the principal.
- Nested results undergo the same response inspection and redaction as direct
  results before entering the runner. Code Mode receives no upstream
  credential or ambient credential access.

Security, speed, reliability, and operability are gates on these capabilities.
They do not create separate product surfaces and must not displace the
end-to-end workflow outcome.

## What a client sees

Code Mode does not present one fixed tool set. Three independent conditions
decide what reaches a given caller, and a portable client must not assume any
of them.

### Source submission and reuse

`codemode.execute` and `codemode.start` accept exactly one
source selector:

- `source`: inline JavaScript.
- `source_file`: an owner-scoped `mcp-file://gateway/...` URI returned after
  uploading UTF-8 JavaScript through `gateway-files.prepare_upload`.
- `source_sha256`: the lowercase SHA-256 returned for an earlier retained
  source owned by the same tenant, issuer, and subject.
- `skill_script`: an exact `skill://` resource URI in the active verified
  Agent Skills catalog. It is accepted by execute and start
  with the same caller authority as other source forms.

The published schema carries the selectors as independent optional properties rather
than as a union, because a schema root applying `oneOf`/`anyOf`/`allOf` is
refused by the tool-calling APIs that consume `tools/list` and costs the tool its
place in the client's catalog. The exclusion is therefore enforced when the call
is handled: naming none of the selectors, or more than one, returns
`invalid_source_selector` naming the fields that conflicted.

`skill_script` loads a JavaScript file directly by its `skill://` URI. Clients
can execute a helper without downloading it into model context or uploading it
again:

```json
{
  "skill_script": "skill://tutorial/summarize-items/scripts/summarize.js",
  "input": {"issue": 42}
}
```

When continuing a loaded workflow, also pass `skill_revision` with the exact
catalog revision returned by `gateway-skills.load`. The gateway uses that
revision or fails if it is unavailable or no longer approved; it never substitutes
newer bytes for a pinned revision. Omit the field to select the currently approved
serving revision. `skill_revision` is valid only alongside `skill_script`.

The source uses the caller's ordinary Code Mode permissions and the same
sandbox, tool authorization, quotas, and limits as inline JavaScript. There is
no separate script-execution approval or grant API. Distribution review still
controls which skill contents the tenant can retrieve; pending updates preserve
serving content and quarantine prevents further retrieval. See
[skill distribution review](skill-distribution-review.md).

Direct URI loading also applies the caller's existing skill resource profile,
`FetchSkillResource`, and `ReadSkill` policies and records their decisions, just
like reading the resource. These authorize access to source bytes; they are not
separate permission to execute a script.

The resource must contain UTF-8 JavaScript source. Its MIME type and filename do
not determine admission: Code Mode validates the source bytes and the runtime
parses them just as it does for inline source. Invalid syntax produces an ordinary
execution error.

### Optional compatibility hint

Publishers can report that they tested a helper in the Code Mode runtime with
this optional string-valued Agent Skills metadata:

```yaml
metadata:
  io.cacahuate.mcp-gateway.code-mode: '{"version":2,"scripts":{"helpers/helper.js":true}}'
```

Each key is a relative file path. `true` reports successful compatibility
testing by the publisher; `false` reports no successful test. Missing entries,
malformed values, older declarations, and unknown versions provide no test
information. None of these values grants or blocks execution. The human-readable
`compatibility` field is optional and needs no special phrase.

Publishers should set `true` only after exercising the helper in Code Mode with
representative inputs, checking that it does not depend on unavailable imports,
packages, local files, or ambient APIs. This is a publisher report, not a gateway
certification or a claim that every code path has been tested. The runtime reports
unsupported JavaScript or unavailable APIs normally, regardless of the hint.
`gateway-skills.load` exposes the optional boolean as `files[].code_mode_tested`;
the dashboard displays the same information. `SKILL.md` is instruction text and
shows “Not applicable” in the compatibility column.

The script bytes become the Code Mode function body unchanged. Arguments stay
in `input` and reach the program as `execution.input`. Source origin and digest
are recorded for inspection and retry identity, not as additional execution
permissions.

### Retaining source

Inline, uploaded, and skill source may include `retain_for_seconds`, from 60 seconds
through 24 hours. Omission means the source is admitted for the current
execution without creating a reusable source artifact. A successful response
contains `source_ref.sha256` and an explicit `source_ref.retention_state`:
`not_retained`, `live`, or `unavailable`. A live artifact also carries its exact
`source_ref.expires_at` deadline. `unavailable` means the gateway could not read
retention truth, so the caller should retry instead of treating the artifact as
absent. Hash lookup does not extend the deadline. Resubmitting the inline or
uploaded bytes with another retention request may extend it.

Retained source is content storage and therefore requires both a configured
database and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`. The default `disabled`
posture refuses retention with `source_artifact_unavailable` and preserves its
no-content storage contract; ordinary blocking execution remains available.

Retention defaults to 64 sources and 64 MiB per owner, and 1,024 sources and
1 GiB per tenant. Operators can configure the count and byte quotas; byte
defaults derive from the source limit. Existing-hash extensions do
not consume another source or another copy of its bytes. Operator quota may be
stricter. A new artifact that would exceed a ceiling returns
`source_artifact_capacity`; expiration makes capacity available again.

The hash is a content identifier, not an authorization token. There is no list
or discovery operation, and lookup binds the authenticated tenant, issuer, and
subject. Unknown, expired, and differently-owned hashes all return
`source_artifact_not_found` with guidance to resubmit inline source or upload a
fresh file.

An uploaded file is only an input transport. Code Mode reads and verifies its
exact bytes, then owns a copy under the requested source-artifact lifetime and,
for continuable durable execution paths, the execution journal lifetime. Expiration or
deletion of the original upload therefore cannot interrupt an admitted run,
retry, or resume. Inline, uploaded, and retained-hash submissions containing
the same UTF-8 bytes produce the same digest, including the digest used by
detached-start convergence and `repeat_after`. Durable file starts keep a
fixed-width, owner-scoped binding from the immutable upload URI to that digest
for the execution journal lifetime, so an identical retry can recover the
content identity after the upload disappears. That binding recovers only a
lost response: extending source retention or deliberately starting new work
still requires a live upload (or another live source selector). The binding
stores no source body, has no listing surface, and is intrinsically capped at
256 live rows per owner and 4,096 per tenant; excess new handles return
`source_locator_capacity` until earlier execution-retention windows expire.

**The caller's scope.** `codemode.search` and `codemode.describe` are admitted
by `mcp:read` or `mcp:admin`. Every other Code Mode tool is admitted by
`mcp:invoke` or `mcp:admin`. So a principal holding only `mcp:read` sees
discovery and nothing else, while `mcp:admin` alone satisfies both checks and
sees the whole surface its posture allows.

`codemode.search` draws candidates from the same authorization-first direct
catalog and deterministic lexical ranker as `gateway-discovery.search`. It
then applies the runtime's schema and authority constraints, so discovery and
execution do not implement a second permission boundary.

**The deployment's durable-content posture.** The tools
`codemode.resume`, `codemode.result`, `codemode.artifacts`,
`codemode.artifact`,
`codemode.start`, `codemode.start_resume`, `codemode.status`,
`codemode.executions`, and
`codemode.cancel` — are
withheld unless durable continuation is available, which requires both a
configured execution store and `GATEWAY_CODEMODE_RESULT_STORAGE=allow`. Either
one alone is not enough. The default `disabled` posture therefore serves
`search`, `describe`, and `execute` only. The withholding is
deliberate: a
retrieval tool the gateway cannot honor would be a contract it must break.

`codemode.start`, `codemode.status` and `codemode.cancel` are the submit, poll
and stop halves of that surface, and they are what a client uses when it cannot
rely on the host backgrounding a long call for it. Start admits, quota-checks
and durably claims the execution before it returns, then runs it with nobody
waiting: a returned handle means the work was accepted, not merely queued, so
exhausted capacity is refused at the call rather than discovered by a later
poll. Client-authored starts use the same direct authority as blocking
execution, including reviewed skill scripts.

Starting is safe to retry. Each detached start carries a gateway-derived
retry-equivalence identity — tenant, issuer, subject, source digest, and
execution profile — and while an identical submission is retained, calling
`start` again returns the existing execution's handle instead of running the
work twice, whatever its lifecycle state. The check that creates a new
execution is atomic with claiming it, so two racing first starts cannot both
insert. Deliberate repetition stays possible and distinguishable from retry:
`repeat_after` names the latest retained terminal execution with the same
identity and creates the next run, and retrying a repetition whose response
was lost converges on that newer handle instead of repeating twice. A
`repeat_after` that names anything else is refused with
`execution_repeat_unavailable` or, while the named execution is still
running, `execution_repeat_not_terminal`. No caller-generated idempotency key
exists anywhere in this contract; the same failure that forces a retry is the
one that loses such a key.

A handle that is already lost is recovered rather than retried around.
`codemode.executions` lists the caller's own in-flight executions, newest
submission first, in the same status vocabulary `codemode.status` reports,
with `next_cursor` continuing a bounded page walk. A listed entry never
carries a checkpoint: checkpoints are caller-controlled payloads, so a page
that included them would grow with what the listed programs stored rather
than with its row count — the store selects only the decision-shaped fields,
and a discovered paused execution's checkpoint comes from polling its
identifier. It is the
complement of retry safety: convergence prevents an orphan at the start
boundary, and the listing finds work that is already running when the handle —
not the work — is what went missing, so it can be polled or cancelled instead
of running unreachable until expiry. The listing is scoped exactly as the
by-id tools are — tenant, subject, issuer, and effective profile — and
returns only executions those tools would serve: it reveals nothing about any
other principal's work, and it hands out no protocol-level enumeration
(`tasks/list` stays removed; this is an ordinary governed tool). Terminal
executions are not listed — a known handle's outcome stays retrievable through
`codemode.status` and `codemode.result` until retention expires — and listed
rows are projected as stored: polling a discovered identifier is what
reconciles it.

Operators have their own view of the same journal, deliberately separate from
the caller listing because the authorization models differ: the admin REST
surface at `/api/v1/admin/codemode/executions` is tenant-scoped under
`mcp:admin` and spans principals, answering "what is running here, for whom,
and since when" with identity, lifecycle state, claim liveness, and age —
never source, checkpoints, results, or snapshots, whose retention is an
explicit information-flow decision an observability view must not bypass. The
one intervention is a tenant-scoped cancellation that reuses the journal's
cancellation-request semantics, terminalizes with the distinct
`cancelled_by_operator` reason, names the intervening operator in the journal
event, and records a fail-closed admin evidence row.

Detached admission consumes a process-wide detached permit before creating an
execution journal row or discovering bindings; only the convergence
probe precedes it, because returning an already-durable handle admits nothing
new. A non-converging `start` or `start_resume` is refused with
`detached_execution_capacity` when that pool is full. Detached attempts also
consume the ordinary tenant and process-wide permits, so the detached pool is
a subset of total runner capacity rather than an additional source of runners.
All three limits are process-local and therefore multiply with gateway
replicas.

`codemode.start_resume` is the continuation half. A detached lifecycle has to
survive a pause or it stops being one: without it, a program that checkpoints
would force its caller back into the long blocking `codemode.resume` it started
detached to avoid. Status reports the checkpoint, start_resume answers it, and
both return the same projection, so a caller alternates between them for as
many pauses as the program takes.

`codemode.start` and `codemode.start_resume` govern under their own names
rather than borrowing the authority of the call that started an execution. The
Cedar overlay builds its facts from the descriptor the governance name selects,
and both leave durable work running after the call returns, so a policy keyed
to either one has to be able to see it as what it is.

`codemode.cancel` likewise governs under its own medium-risk, side-effecting
descriptor. A policy authorizing cancellation must name `cancel` explicitly.
Read-only status and retrieval
remain continuations of the execution authority.

Code Mode remains a `DelegatedDataPlane` namespace. Blocking `execute`
and `resume` release runner capacity before their call returns,
and every nested connector dispatch is confined by the exact current profile
and Cedar overlay. Owner-scoped status, listing, result, artifact, and cancellation
operations do not create independent data reach. Any consumption shape that
acknowledges before its runner work ends requires the exact operation in a
tool-confined profile's `allowed_tools`: `start` and `start_resume` on the
ordinary tool surface, task-augmented `execute` and `resume`, and the
`resume` continuation selected by `tasks/update`.
The same operations called in their blocking shape keep the delegated-data
plane rule because they release capacity before returning. Cancellation still
uses its own Cedar identity as described above, including through
`tasks/cancel`, but it controls owner-bound work already created rather than
committing a second durable execution.

Status reports lifecycle only — never the result — so polling it in a loop
stays cheap; retrieve the result with `codemode.result` once status says one is
available. Its one exception is a program that paused: a detached caller never
saw the response carrying the checkpoint and cannot choose resume input without
it, so status carries the checkpoint while the execution waits to be resumed
and omits it in every other state. An approval-bound wait stores a binding
rather than a checkpoint and is never reported here.

Start and status share one response shape, so the first poll and every later
one read identically. All three report lifecycle in the same vocabulary the MCP
Tasks projection uses, and a detached start routes through the same admission,
claim and runner path the Tasks extension uses, so a polling client and a
task-augmented client never see one execution described two ways.

The MCP result has two representations of that response by design:
`structuredContent` is the authoritative machine value, while text `content`
contains its JSON serialization as a compatibility fallback for clients that
cannot consume structured tool results. A programmatic tool runtime should not
serialize the whole `CallToolResult` into model-visible output on every poll,
because that exposes both representations and repeats lifecycle metadata that
the polling program itself can inspect. Keep intermediate envelopes inside the
runtime, inspect `structuredContent`, and expose only the fields needed at an
actionable boundary.

This runtime-neutral example injects the status call and wait primitive because
their JavaScript binding names differ by client. It stops for a terminal state,
a checkpoint that needs caller input, or a local polling bound, and returns one
small projection instead of every raw MCP response:

```js
async function pollDetached({ callStatus, executionId, wait, maxPolls, deadline }) {
  let lastStatus = "working";

  for (let poll = 0; poll < maxPolls; poll += 1) {
    if (Date.now() >= deadline) {
      return {
        execution_id: executionId,
        polling_stopped: "deadline_reached",
        last_status: lastStatus,
      };
    }

    const envelope = await callStatus({ execution_id: executionId });
    const status = envelope.structuredContent;
    if (!status || typeof status !== "object") {
      throw new Error("codemode.status did not return structuredContent");
    }
    lastStatus = status.status;

    if (status.terminal || status.status === "input_required") {
      return {
        execution_id: status.execution_id,
        status: status.status,
        terminal: status.terminal,
        terminal_reason_code: status.terminal_reason_code ?? null,
        result_available: status.result_available,
        checkpoint: status.checkpoint ?? null,
      };
    }

    await wait(250);
  }

  return {
    execution_id: executionId,
    polling_stopped: "attempt_limit_reached",
    last_status: lastStatus,
  };
}
```

Treat a transport error as an explicit retry decision outside this loop; do not
convert it into an unbounded hot retry. If the final projection says
`result_available`, retrieve the payload once with `codemode.result`. If it says
`input_required`, use the checkpoint to decide whether and how to call
`codemode.start_resume`.

**The client's own per-request capability, for tasks only.** MCP task
augmentation applies to `codemode.execute` and `codemode.resume`, is advertised
only when the posture above allows it, and additionally requires the client to
declare the tasks extension in the capabilities it sends with each request. A
client that never declares it receives ordinary synchronous results no matter
how the server is configured.

These compose rather than override. Task augmentation needs the posture *and*
the client declaration; the durable tools need the posture *and* `mcp:invoke`.

### Writing a client that survives both postures

Read the served tool list and branch on what is present. Do not infer the
surface from a previous deployment, from this document, or from the presence of
`codemode.execute`, which is served in every posture.

The failure this prevents is specific and otherwise hard to diagnose: the same
skill works against one gateway and reports a missing tool against another,
with nothing in the client explaining why, because the difference is server
configuration the client cannot see. A caller that needs a durable handle
should check for `codemode.result` before starting work that depends on
retrieving one later, rather than discovering the gap after the execution
exists.

## Execution model

The durable lifecycle must represent pauses and uncertainty without reporting a
guess as fact:

```text
submitted
  -> admitted
  -> running
       -> waiting_for_approval -> running
       -> waiting_for_resume   -> running
       -> compensating         -> compensated
       -> succeeded
       -> failed
       -> cancelled
       -> expired
       -> ambiguous -> reconciled_applied
                    -> reconciled_not_applied
                    -> compensating
```

An admitted execution owns:

- the tenant, principal, client, and acting-agent identity;
- submitted source and its digest;
- one reviewed execution profile with tool, resource, and data bounds;
- immutable tool/schema/governance snapshots;
- ordered steps, nested calls, and call attempts;
- approval bindings and result or artifact references;
- resource use, terminal reason code, and evidence linkage.

Waiting releases runner resources. Resume reclaims the durable execution through
a fenced owner and rechecks the source digest, effective profile, SDK and runner
contracts, original governed tool contracts, and current authorization before
new dispatch. Tools admitted after the original attempt do not invalidate or
widen the resumed program; removed or changed original tools do. Cancellation
prevents future dispatch but does not undo an applied effect.

## Runner authority

The runner is untrusted and has no ambient network, environment, filesystem API,
credentials, subprocesses, dynamic packages, or host APIs. Its only external
capability is a tenant- and execution-bound gateway RPC supporting governed
discovery, invocation, checkpointing, artifacts, and final results.

Completed connector responses use ordinary JavaScript values when they fit the
runtime. Response delivery is independent of authorization and operation type:
reads and mutations use the same retained-response path. The gateway resolves a
recognized retained envelope on the originating upstream session, preserving
server visibility, credential-profile restrictions, URI-specific authorization,
and response inspection. JSON text is decoded to its usual object or array;
other text remains a string.

A direct MCP caller receives an owner-scoped gateway file. Code Mode receives
materialized data when it fits its runtime allowance, or file delivery for a
larger or binary body. Buffering in the gateway is permitted. Files use the
existing storage, integrity, retention, authorization, publication, and cleanup
lifecycle. When inspection changes the data, the file contains only the inspected
replacement; unchanged text retains its original bytes.

The MCP result's `_meta["io.cacahuate.mcp-gateway/retained-delivery"]` carries
`operation_status`, `delivery_status`, and the `file` descriptor for file
delivery. Code Mode exposes that metadata as `_gateway_delivery` alongside the
connector value. If ordinary upstream data already has an `_gateway_delivery`
property, Code Mode places that whole upstream object under `data` so it cannot
be mistaken for gateway-authored status. Direct MCP responses preserve that
ordinary property; only the namespaced MCP metadata carries gateway authority.
Pass its `file.uri` to `gateway-files.prepare_download` and the
file helper to retrieve bytes outside model context. A URI alone is not download
authority. The upstream structured output schema remains separately validated.

If resource recovery or file staging fails after a confirmed mutation, the
result preserves `operation_status: "succeeded"` with
`delivery_status: "unavailable"`, a machine-readable `error`, and
`retry_operation: false`. Inspection refusal withholds the rejected content.
This is an attachment failure, not permission to redispatch the mutation. An
unconfirmed upstream dispatch remains an ordinary uncertain invocation outcome.

Code Mode's serialized materialization allowance is derived from the QuickJS
heap; its heap remains the actual bound on the decoded object graph. File-backed
bodies use the operator's file-size budget. Streamable HTTP bounds the raw
JSON-RPC read before deserialization, allowing for JSON escaping and envelope
overhead, and the decoded body is checked again for declared size and identity.
Legacy SSE and stdio currently lack the bounded retained-read implementation;
unsupported delivery is explicit and does not change the caller's authority.

Values that fit the control frame stay inline. A larger completed value is
serialized once into one execution-private temporary file, using the same
materialization budget. The runner opens that file before confinement and the
parent immediately unlinks it; JavaScript receives no path or file API, and
synchronous connector calls reuse the same file so disk use cannot grow with
call count. This is completed-result buffering, not an end-to-end streaming or
backpressure protocol, and requires no upstream or JavaScript SDK change.

`codemode.execute` and `codemode.resume` support MCP task augmentation when the
durable execution store is configured and the operator explicitly allows
result, checkpoint, and resume-input storage. Task invocation returns the
execution id after bounded admission establishes its fenced worker claim and
immutable tool snapshot, but before runner work begins.
Clients use `tasks/get` to poll the journal projection — a completed task
inlines the bounded original structured result — and `tasks/cancel` to
request cancellation. Task access is scoped to the originating tenant and
principal, requires the same effective credential-profile confinement as
submission, and re-enters the current Cedar forbid overlay. Result content
enters the control database only when the operator sets the explicit coarse
information-flow decision
`GATEWAY_CODEMODE_RESULT_STORAGE=allow`; task augmentation is not advertised in
the default `disabled` posture. The task surface is a projection of the Code
Mode journal, not a separate scheduler or lifecycle store.

CPU, memory, wall time, source size, result size, log size, concurrency, and
cancellation are bounded by the execution profile. No source form has a fixed
connector-call bound.
A runner failure cannot widen authority, leave a live dispatch capability, or
expose an upstream credential.

The generated SDK is the compatibility boundary. Search and describe reuse the
catalog and SEP #1888 substrate. Saved code binds to SDK and tool snapshot
versions rather than a particular runner implementation.

A refused or failed connector call throws an `Error` whose `code` property is
a stable snake_case discriminator; the message is human-readable detail that
may change between releases, so programs branch on `error.code`, never on
message text. Pipeline refusals carry the invocation pipeline's stable kinds
(`forbidden`, `input_schema_violation`, `rate_limited`,
`response_inspection_blocked`, `connector_result_too_large`,
`step_up_required`, `upstream`, …); the broker
adds `binding_unavailable` (the call id is not in this execution's admitted
bindings). A
prefix that is not lowercase snake_case is not a code: the full text becomes
the message and the code is `connector_failure`. A direct-authority call
surfaces the same approval or step-up refusal as the corresponding direct MCP
call. Resume incompatibility surfaces
as the structured `execution_resume_incompatible` refusal on the
`codemode.resume` call itself. `ambiguous` is reserved for the
mutation-recovery epic's uncertain-outcome state.
Structured logging rides the artifact channel — emit an artifact with your
own discriminating shape (for example `{kind: "log", …}`) rather than a
parallel logging API; artifacts are bounded, durable, and retrievable with
the same retention and audience rules either way.

On an initial execution attempt `execution.resume` is
`null`. The program can call `execution.pause(checkpoint)` with any bounded
JSON-compatible checkpoint; the gateway durably records it, releases the worker
claim, and returns
`waiting_for_resume` (or projects MCP Task `inputRequired`). The client calls
`codemode.resume` with the execution id and any JSON-compatible external input.
A fresh runner receives `execution.resume = { checkpoint, input }` and may
complete or establish another checkpoint. Both execute and resume work as
ordinary built-in calls; task augmentation adds disconnect-safe execution
without defining a separate scheduler.

A program can call `execution.wait(milliseconds)` with a finite, non-negative
number. The call blocks only the isolated runner thread, uses the sleep syscalls
already admitted by its confinement profile, and exposes no general timer or
host API. Elapsed waiting spends the ordinary execution budget. A request longer
than what remains is clamped to that remainder and ends with the same
`execution_timeout` reason as computation that exhausts the budget, even if the
program tries to catch the native callback error. On the direct-authority path,
cancellation drops the active attempt and the parent's kill-on-drop child
teardown remains prompt while the runner is sleeping. Approval-bound mutations
retain their existing rule that an attempt is not aborted around a possibly
in-flight effect.

The initial executable profile requires `mcp:invoke`, accepts a JavaScript
function body, and exposes synchronous
`connectors[server][operation]` callable bindings (dot notation is shorthand when
both names are JavaScript identifiers). Search returns the exact connector and
operation pair used by describe and execution, so dots inside either name are
not parsed as separators. Search and describe remain available with `mcp:read`.
For each execution the gateway generates a concrete binding map from the same
versioned contracts returned by `codemode.describe`, restricted to tools the
principal may call directly. Recursive `codemode.*` operations are excluded.
Operations outside that map are absent in JavaScript and are independently
refused at the parent RPC boundary. For each execution attempt the parent
replaces catalog identities with fresh opaque capability handles mapped to the
exact connector, operation, and contract. A handle observed by an earlier
runner is not admitted by a later execution, and flattened display names never
select a dispatch target. The parent also attaches the exact described
authority, schema, and governance identity to every nested invocation. The
invocation pipeline compares that identity with the snapshot it resolves in
Stage 1 and refuses same-name contract drift before dispatch.
Execution permits branching, loops, transformation, and composition. Each
connector call reuses current schema validation, Cedar authorization, approval,
profile restrictions, quota, response inspection, and evidence recording
without silently changing the execution's admitted contract. A successful
execution returns its execution id. Every audit row
created for a nested call carries that same parent id plus its one-based step,
stable call id, and attempt. The hierarchy is persisted in the append-only
audit log, included in its tamper-evident hash chain, and exposed by the audit
read model; direct calls leave it absent. This is also the identity shape
durable retry and resume will reuse.

When the control database is configured, blocking execution acquires its tenant
and global capacity before durable submission. The gateway first applies the
same operator-configured invocation quota used by ordinary tool calls, then
admits capacity and stores a compact submission record containing the exact
source digest, execution profile, and SDK and runner versions. Detached `start` and
`start_resume` have a separate admission boundary: after source resolution and
the retry-equivalence lookup, new detached work acquires the process-wide
detached permit before creating an execution row or discovering catalog
bindings, then follows the same tenant/global admission and worker-claim path.
A detached-capacity refusal therefore stores no execution row and does no
binding discovery; a retry that converges on an existing handle needs no new
permit.

The source itself is attached atomically with the worker claim for ordinary
synchronous execution. When explicit content storage makes an execution
resumable, submission durably stores the bounded source and task
acknowledgment follows bounded admission and the initial worker claim. A
process loss after acknowledgment therefore leaves both source and immutable
tool snapshot available for fenced recovery; an unacknowledged row that never
reached admission expires instead of advertising an unusable resume boundary.
Repeated tenant or global capacity refusals cannot otherwise amplify program
content into the control database. A conditional worker claim fences every
nested-call journal append and terminal transition. Capacity refusal, runner
failure, timeout, nested-call outcome, and success therefore remain
tenant-scoped and attributable after the request returns. Submissions
opportunistically sweep bounded batches of executions past their retention
horizon: completed history, and abandoned in-flight rows no live worker claim
holds — past retention no read or resume path can reach them, so sweeping is
indistinguishable to their owners. In-flight work under a live claim or inside
its retention window is never swept. Successful executions always
persist non-content outcome metadata.
Synchronous calls return the bounded result directly. When the operator
explicitly allows result storage, task-augmented calls additionally persist that
bounded result for repeated retrieval via `tasks/get` during the retention
window. Owner polling returns an abandoned resumable attempt to
`waiting_for_resume`, releases its stale claim, and preserves the bound
checkpoint and input; a stale worker remains fenced. Non-resumable abandoned
submissions and attempts terminalize, so process loss cannot leave a task
projected as working forever. Without that storage decision or durable storage,
the bounded blocking execution path remains available without advertising task
augmentation or claiming restart durability. MCP Tasks projects the internal
journal rather than becoming a competing execution store.

When durable content storage is enabled, the generated SDK exposes
`execution.artifactsAvailable` and
`execution.emitArtifact(value)`. Emission accepts any JSON-compatible value up
to the ordinary bounded-result size, appends it to the execution journal before
returning, and yields an opaque `{execution_id, artifact_id}` reference. Each
fresh runner attempt can emit a bounded set of artifacts; a paused, failed,
cancelled, or completed execution retains already-committed artifacts until its
retention horizon. `codemode.artifacts` pages references in append order
without loading their content, and `codemode.artifact` resolves one value. A
completed persisted response also
contains `result_ref`, which `codemode.result` resolves to the original bounded
JSON-compatible program result. All three retrieval tools require the
originating tenant, principal, effective credential profile, and current
`codemode.execute` governance. With content persistence disabled,
`execution.artifactsAvailable` is false, artifact emission returns a stable
unavailable error, and no result reference is returned. A durable ordinary call
that fails still returns its `execution_id` in structured error data so the
caller can recover artifacts committed before the failure.

The runner is a fresh child process for every attempt, so JavaScript globals
and prototype mutations cannot cross executions. It has a cleared environment,
no module loader or web/system APIs, bounded source and frame sizes, a
kernel-enforced process address-space ceiling, QuickJS memory and stack limits,
an interrupt deadline, a parent wall deadline, a process-wide ceiling, an
independent per-tenant ceiling, and a detached-work
ceiling that remains a subset of both. Before the gateway
submits source, the Linux child must install and report the versioned seccomp
syscall allowlist; the profile admits only stdio, memory management, clocks,
signals, and process exit. Filesystem, network, subprocess, namespace, and
cross-process syscalls fail closed. No source form has a fixed connector-call
count. Hosts that cannot install the profile cannot execute programs.

Execution failures carry a stable machine-readable `data.error` value. Program
evaluation, non-JSON results, oversized results, time limits, unexpected runner
termination, oversized runner frames, malformed protocol frames, and runner
transport failures have distinct codes. The parent owns the only dispatch loop
and the child is killed when that loop is dropped, so a timed-out or cancelled
execution cannot submit a later connector call. Runner protocol version 4 adds
explicit pause frames and resume context on top of typed failure frames;
version 5 adds durable artifact emission, and version 6 adds the private
completed-result spool without changing the JavaScript SDK. SDK version 2
exposes the artifact capability, and SDK version 3 adds the bounded wait
primitive. Paused version 1/4, 2/5, or 3/5 executions are atomically upgraded
to 3/6 when a current worker claims the next attempt; 2/6 and 3/6 remain
compatible as well. Rolling upgrades therefore preserve continuations while
an older worker cannot claim an execution that may depend on a newer SDK
surface.
Success-result contract versioning remains independent.

The initial profile defines these codes: `execution_failed`,
`execution_timeout`, `execution_result_not_json`,
`execution_result_too_large`, `connector_result_too_large`, `execution_capacity`,
`tenant_execution_capacity`, `detached_execution_capacity`,
`execution_unavailable`, `runner_failed`,
`runner_crashed`,
`runner_frame_too_large`, `runner_frame_unterminated`,
`runner_frame_malformed`, `runner_protocol_error`, and `runner_transport_error`.
A runner that never announces readiness within its setup allowance fails with
`execution_setup_timeout`, which is deliberately distinct from
`execution_timeout`: one says the deployment could not start a program, the
other says a program ran out of the budget it was granted, and only the second
is a reason to raise the limit. Setup is bounded independently of program execution.
Pause and continuation add `execution_pause_unavailable`,
`execution_resume_unavailable`, `execution_resume_incompatible`, and
`execution_resume_input_too_large`. Artifact emission adds
`execution_artifact_unavailable`, `execution_artifact_too_large`, and
`execution_artifact_limit_exceeded`; result-reference retrieval uses
`execution_result_unavailable` and `execution_result_not_ready`.

## Mutation contract

Cross-server calls are not a transaction and Code Mode does not promise generic
exactly-once execution.

Client-authored `codemode.execute` and `codemode.start`
use direct authority. Every nested operation visible to the caller, including
side-effecting upstream and non-Code-Mode built-in operations, re-enters the
ordinary direct invocation path under the same principal. Ordinary Cedar
authorization, step-up, approval, validation, quota, quarantine, response
inspection, and audit rules still apply at each call. Code Mode adds no
mutation-admission switch, durable-storage prerequisite, or fixed connector or
effect count. It does not automatically retry direct-authority calls or restart
an execution after a lost worker. Explicit resume starts the same source with
`execution.resume`; programs use its checkpoint to choose their next work rather
than repeating completed work. This is not a transaction or an exactly-once
execution guarantee.

Approved Agent Skills scripts use the same caller authority without an automatic
read-only or connector-call ceiling.

## Data movement

Tool authorization and information-flow authorization are separate decisions.
Permission to read data does not imply permission to return it to the model,
persist it, show it to an operator, or send it through another tool.

## Current execution contract

Every supported source form uses the caller's ordinary operation authority.
Durable execution, explicit checkpoints, cancellation, and
operator evidence apply to this same execution surface.

Execution provenance is available through invocation hierarchy; it does not
select a separate authorization tier.

## Non-goals

- Replacing ordinary MCP calls or SEP #1888 discovery.
- Arbitrary internet access or package installation in the runner.
- Generic exactly-once claims or inferred rollback across upstream systems.
- Self-modifying or automatically promoted model-generated code.
- Bypassing data-plane approval or control-plane maker/checker enforcement.
- Treating provider-side inference `code_interpreter` as this gateway
  capability.
