# MCP Tasks and durable execution

MCP task augmentation projects the Code Mode execution journal. Load this
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

## Supported scope

Ordinary upstream tool calls are not task-augmented. Clients poll for status;
server-push task notifications are not implemented. Result persistence is an
explicit deployment decision rather than a general information-flow policy.
