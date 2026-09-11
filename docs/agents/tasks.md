# MCP Tasks primitive

Reach for this doc when changing
`crates/waygate-dashboard-stores/src/tasks.rs`, the `task_states` migration, or
the admin REST surface at `/api/v1/admin/tasks`.

## Status: durable Code Mode projection shipped

What's shipped:

- `task_states` table (migration `0031_tasks.sql`).
- the `waygate_dashboard_stores::tasks` module with `Task`, `TaskStatus`,
  `NewTask`, `TaskStatusUpdate`, `TaskListFilter`,
  `PgTaskStore`.
- Admin REST surface at `/api/v1/admin/tasks` (list +
  read; mutation is not exposed because there's no
  in-process write-through path yet).
- Protocol-native task augmentation for `codemode.execute` and
  `codemode.resume`. A task call returns the durable Code Mode execution id
  after bounded admission and an atomic worker claim, before runner work;
  `tasks/get` projects its lifecycle, including input-required pauses, and
  inlines the bounded original result for completed tasks throughout the
  retention window (the tasks extension has no separate `tasks/result`
  method), and `tasks/cancel` requests owner-scoped cancellation.
  Persisted Code Mode executions also return a stable final `result_ref` and
  can publish bounded intermediate JSON artifacts before pausing, failing, or
  completing. `codemode.result`, `codemode.artifacts`, and
  `codemode.artifact` resolve those references under the same owner, effective
  profile, current Cedar overlay, and retention rules; these are execution
  journal surfaces rather than additions to `task_states`.
  `codemode.executions` enumerates the caller's own in-flight executions under
  the same owner and effective-profile scoping, so a lost handle is
  recoverable; it is an ordinary governed tool, not a `tasks/list` revival —
  the removed wire method stays removed.
  Resume also works as an ordinary built-in call, so task augmentation is not a
  prerequisite for using the feature. The Code Mode execution journal is the
  source of truth; this path does not duplicate rows into `task_states`.
  Follow-up operations re-enter the current Cedar overlay and require the
  caller's effective profile confinement to match the submitting credential.
- `tasks/update` (SEP-2663 client-to-server input) maps onto the Code Mode
  continuations through `BuiltinTools::update_task`, routed like
  `tasks/get`/`tasks/cancel` with one difference: the router first asks the
  namespace which continuation the update advances
  (`update_task_continuation`) and applies the Cedar overlay for **that**
  continuation's governance tool — a `waiting_for_resume` execution updates
  under `execute` governance (key `resume`, value = the checkpoint input,
  `null` for none). Historical `waiting_for_approval` executions have no
  continuation; the former mutation-resume tool and response key are removed.
  The alias follows the direct `codemode.resume` path's governance.
  Exactly one recognized key is accepted
  per update; the atomic claim re-verifies the waiting state; the
  acknowledgement is eventually consistent (the continuation runs detached,
  observed via `tasks/get`); an `Ambiguous` execution has no update path and
  the refusal says so. `tasks/get` keeps `inputRequests` empty: the
  continuation input is untyped JSON that the elicitation/sampling/roots
  request union cannot honestly describe, so the contract travels in the
  task's status message and the self-documenting continuation tools.

What's NOT shipped:

- **Write-through from the invocation pipeline.** Currently no `waygate-mcp` code writes
  `task_states` rows — the substrate is ready, the
  producer is not.
- **General invocation write-through and task projection** (deferred). Ordinary
  upstream tools do not create `task_states` rows and are not task-augmented.
- **Task status push** (deferred). Code Mode supports direct polling by returned
  id, result retrieval, cancellation, and continuation through the
  self-documenting `codemode.resume` tool. The extension also defines optional
  server-push status updates as `notifications/tasks`, delivered over
  `subscriptions/listen`, with polling as the specified default. That delivery
  channel already exists here, but `accepted_subscription_filter` in
  `crates/waygate-mcp/src/server.rs` accepts exactly one category,
  `tools/list_changed` — so what is missing is publishing task status onto an
  existing channel, not the channel itself.

  `tasks/list` is **not** part of this gap: the extension removed it, so not
  advertising it is conformance rather than deferred work.
- **Fine-grained result-content policy** (deferred to the information-flow
  epic). The current coarse storage decision is explicit and deployment-wide:
  `GATEWAY_CODEMODE_RESULT_STORAGE=allow` authorizes bounded successful
  results, checkpoints and resume input, and intermediate artifacts to enter
  the control database; the default `disabled` posture does not advertise Code
  Mode task augmentation. Source/sink labels, audiences, and declassification
  remain later work.

Gateway-native Code Mode has its own internal execution journal in
`waygate-codemode`. That journal owns worker fencing, recovery state, immutable
tool snapshots, execution event truth, and bounded final results. MCP Tasks
projects those records into the client-facing wire shape. Intermediate
artifacts remain append-only execution events and final result references
resolve the execution row; `task_states` must not become a second Code Mode
scheduler, content store, or recovery authority.

The generic persistence layer remains available for future long-running
upstream tools. Code Mode deliberately projects its richer domain journal
directly because flattening fenced claims, immutable tool snapshots, and
recovery truth into `task_states` would lose required semantics.

## Schema

```sql
task_states (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    principal_sub   TEXT NOT NULL,                  -- starter; read-only (task can't change hands)
    tool_id         UUID REFERENCES mcp_tools(id) ON DELETE RESTRICT,
    arguments_hash  TEXT NOT NULL,                  -- canonical hash (same shape as approval_grants)
    status          TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed','cancelled','resumable')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    result_url      TEXT,                           -- where the client picks up the completed result
    resume_token    TEXT,                           -- opaque resume value, spec TBD
    error_message   TEXT                            -- only populated on `failed`
);
```

### Why `ON DELETE RESTRICT` on `tool_id`

An operator who retires a tool shouldn't silently lose
every task that ran against it. The audit trail value
outweighs the "let me drop this row cleanly" UX. Same
reasoning as `oauth_consent` keeping client_id rather than
FK-cascading to a deleted client.

### Indexes

Two hot-path lookups:

- "show me my tasks" → `(tenant_id, principal_sub, created_at DESC)`
- "what's still in flight" → partial index on
  `(tenant_id, status, created_at DESC) WHERE status IN ('pending','running','resumable')`

The partial index is sized for the future per-task
background worker that doesn't exist yet but needs the
lookup to be cheap when it lands.

## Lifecycle

```
pending ─► running ─┬─► succeeded
                    ├─► failed
                    ├─► cancelled
                    └─► resumable ◄──┐
                                     │
                                     └─► (client re-engages with resume_token)
                                         │
                                         └─► running → terminal
```

`TaskStatus::is_terminal()` returns true for `succeeded`,
`failed`, `cancelled`. `resumable` is a holding state
between the gateway emitting "I paused here, here's how to
resume" and the client coming back.

## Admin REST surface (today)

```
GET  /api/v1/admin/tasks                    # list, tenant-scoped; filters: principal_sub, status; pagination (limit, offset)
GET  /api/v1/admin/tasks/{id}               # single task by id, tenant-scoped
```

No POST / PATCH / DELETE: the gateway is the writer; admin
can only observe. (A future operator-driven cancel surface
might land at `POST /api/v1/admin/tasks/{id}/cancel` once
the consumer side wires write-through.)

## Operator visibility

Code Mode executions have their own operator REST view,
projected from the execution journal rather than
`task_states` (the journal stays the source of truth):

```
GET  /api/v1/admin/codemode/executions              # in-flight executions, tenant-scoped; filter: principal_sub; pagination (limit, offset)
POST /api/v1/admin/codemode/executions/{id}/cancel  # tenant-scoped cancellation, audited, reason cancelled_by_operator
```

Both live in `crates/waygate-admin/src/codemode_executions.rs`
behind `mcp:admin`. The view is metadata only — identity,
ownership, lifecycle state, claim liveness, age — never
results, checkpoints, source, or snapshots, whose retention
is a separate information-flow decision. Cancellation
reuses the journal's cancellation-request semantics, names
the operator in the journal event, and records a
fail-closed `AdminMutation` evidence row.

The dashboard HTML page remains deferred: the dashboard
expansion plan's D-tier proposes a `/admin/tasks` page
(status badges, drilldown, filters), still not on the
immediate roadmap because the `task_states` producer side
hasn't shipped — an empty list isn't worth a page.

## See also

- [Tasks extension](https://modelcontextprotocol.io/extensions/tasks/overview)
  — `io.modelcontextprotocol/tasks`, the shape the gateway serves since the
  rmcp 3.0 upgrade. Authoritative for lifecycle, the three methods, and
  negotiation; note that the client declares support per request rather than
  once at initialize. [SEP-2663](https://modelcontextprotocol.io/seps/2663-tasks-extension)
  is Final and preserved as a historical record — read the extension spec, not
  the SEP, for current requirements.
- `migrations/0031_tasks.sql` — schema with the cascade /
  restrict reasoning inline.
- `crates/waygate-dashboard-stores/src/tasks.rs` — the trait + Pg impl
  the future write-through will consume.
