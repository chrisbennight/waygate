# Combine tool calls with Code Mode

Code Mode runs a bounded JavaScript function body beside the gateway. It can
call authorized tools, filter and combine their results, and return a compact
answer. Intermediate connector data need not enter model context. Every nested
call passes through the same invocation pipeline as a direct MCP call.

## Discover before executing

Use `codemode.search` to find an operation and `codemode.describe` to load its
typed contract. Use the returned connector and operation identifiers exactly;
a dot inside a name is not a separator to infer. Bindings are synchronous:

```javascript
const first = connectors["demo"]["greet"]({ name: "Ada" });
const second = connectors["demo"]["greet"]({ name: "Grace" });
return { first, second };
```

This example requires the tutorial's `demo.greet` tool to be admitted for the
caller. Submit the body in `codemode.execute.source`. For real workflows,
project only the fields needed for the answer instead of returning whole
responses. Pass variable data in the separate `input` object and read it as
`execution.input`; never build source by interpolating untrusted values.

Source can also be an owner-scoped uploaded JavaScript file, a retained source
digest, or a verified skill-script URI. Exactly one source selector is allowed.
Use `skill_revision` with `skill_script` to preserve the loaded workflow's
revision. Optional compatibility metadata never grants execution permission.

## Pause and continue deliberately

With a control database and explicit `GATEWAY_CODEMODE_RESULT_STORAGE=allow`,
the gateway can retain bounded execution content, checkpoints, artifacts, and
results. This is an operator data-retention decision. Without that opt-in,
ordinary bounded execution remains useful but does not promise restart durability.

```javascript
if (execution.resume === null) {
  execution.pause({ next: "summarize", count: execution.input.items.length });
}
return {
  count: execution.resume.checkpoint.count,
  label: execution.resume.input.label
};
```

Submit with `input: {"items":[1,2,3]}`. On `waiting_for_resume`, retain the
execution ID and call `codemode.resume` with that ID and
`input: {"label":"reviewed batch"}`. A fresh runner starts the same source;
the checkpoint chooses its next work. It does not restore a suspended JavaScript
stack or automatically replay prior calls.

Discover `codemode.start` and `start_resume` when work should continue after the
request disconnects. Poll the returned execution with `status`, retrieve its
bounded `result`, or cancel it using the advertised schemas. The official MCP
Tasks extension is another projection of the same durable state, including
continuation input through `tasks/update`. There is no second task database.

Programs can check `execution.artifactsAvailable` and call
`execution.emitArtifact(value)` to persist bounded intermediate JSON. The
`artifacts` tool lists references; `artifact` reads a selected value. Owner,
tenant, current policy, and credential-profile checks still apply at retrieval.
`execution.wait(milliseconds)` paces polling but consumes the execution budget;
use a checkpoint when work should release the worker while awaiting external input.

For a small artifact exercise, submit this source with
`input: {"items":[{"status":"open"},{"status":"closed"}]}`:

```javascript
const items = execution.input.items;
const artifact = execution.emitArtifact({ items });
return { count: items.length, artifact };
```

The final result contains `count: 2` and an artifact reference. Call
`codemode.artifact` using the returned execution and artifact identifiers to
retrieve the two supplied items. This example makes no connector calls and
requires durable storage. In a real workflow, emit the bounded intermediate
data and return only its reference and the summary needed by the caller.

## Reliability and authority

The isolated runner has no ambient filesystem, network, environment, subprocess,
package installation, or upstream credentials. Its tool bindings are generated
from admitted contracts. Current policy, profile, revocation, quarantine, input
validation, quotas, and response controls apply at each nested dispatch.

Durable worker ownership is fenced, so an expired worker cannot append new
journal events or overwrite a successor's outcome. Resume checks original
tool/schema identities and current authority. Changed or removed contracts can
make a continuation incompatible rather than silently redirecting it.

Cancellation prevents future work; it cannot undo an already applied external
effect. Cross-server mutations are not a transaction. Direct-authority programs
do not automatically retry or compensate uncertain outcomes. Reconcile an
unknown mutation through the authoritative system before deciding what to do
next. A failed result download is not evidence that the underlying operation failed.

The [execution contract](../codemode.md),
[runner](../../crates/waygate-server/src/codemode_runner.rs),
[durable journal](../../crates/waygate-codemode/), and
[MCP adapter tests](../../crates/waygate-server/src/mcp_codemode.rs) document and
exercise these boundaries. General information-flow labeling, automatic
compensation, and exactly-once recovery remain design work, not shipped guarantees.
