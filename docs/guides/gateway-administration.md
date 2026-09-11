# Inspect and administer the gateway over MCP

The gateway exposes its own typed MCP tools as well as upstream tools. An
agent can inspect operational state, understand an available change, prepare a
reviewable proposal, and follow its outcome through the same connection.

## Choose the right authority

| Surface | Purpose | Authority |
| --- | --- | --- |
| `gateway-observe.*` | Audit queries, activity summaries, authorization simulation, triage | `mcp:observe` or `mcp:admin`, with tenant-scoped reads. |
| `gateway-admin.*` | Describe, preview, submit, and track privileged changes | A propose-capable non-peer principal; proposal authority does not approve execution. |
| `gateway-control.*` | Quarantine, reconnect, refresh a server catalog, or reload configuration | Direct `mcp:admin` authority; these calls execute immediately. |

Discovery hides tools from callers lacking their scope and invocation checks
again. The scopes are necessary floors, not substitutes for Cedar and other
governance checks. Federation peers cannot become local operators by asserting
these scopes. Some runtime controls act on the gateway-global upstream pool;
consult their descriptions before using them in a multi-tenant installation.

## Prepare a concrete proposal

1. Call `gateway-admin.describe_action` to discover the available actions.
   Select one and read its input schema, required state witnesses, and result.
2. Use `gateway-admin.get_action_context` for the current target document and
   exact revision identifiers. Copy returned witnesses; do not guess hashes.
3. Build the intended change and call `gateway-admin.preview_change`. Resolve
   validation errors and review the rendered result before submission.
4. Call `gateway-admin.propose_change` with the validated action, parameters,
   and reason. Save its change-request ID, binding code, and approval URL.
5. The human opens the authenticated dashboard, compares the binding code and
   captured change, and approves or denies it. Poll `get_change_status` at the
   returned interval; honor back-pressure rather than spinning.

The gateway executes the captured change server-side after eligible approval.
An agent does not receive broad administrator authority as a result. Concurrent
target changes can invalidate a proposal; obtain new context and prepare a new
reviewable change instead of weakening its state checks.

Actions that create a credential have a separate controlled result-retrieval
path. Use an authorized runtime client to consume such a value without putting
it into model context, transcripts, or durable diagnostic output. Secret values
and ordinary identifiers are different data classes; the useful operation is
preserved with its own handling boundary.

## Human approval is implemented; client shortcuts are evolving

Exercise these outcomes with a disposable target before granting an automation
principal proposal access to production configuration:

| Decision or state change | Expected outcome |
| --- | --- |
| Eligible approval reaches the captured quorum | The executor attempts the captured change and status reports its execution outcome; approval alone is not proof of successful execution. |
| Human denies the proposal | The request becomes denied and the proposed change does not execute. |
| Pending request passes its expiry | It can no longer be approved; obtain fresh context before making a new proposal. |
| Target changes after preview or proposal | The applicable state witness refuses a stale write; inspect the current target and propose the intended change again. |
| Propose-only agent tries to approve its own request | Proposal authority does not satisfy the separate human approval gate. |

The [change-request store tests](../../crates/waygate-changeset/src/lib.rs)
cover expiry, denial, and distinct approvers. Action-specific state witnesses
are part of the [executor contract](../agents/hitl-control-plane.md).

The backchannel proposal, dashboard decision, and status-polling workflow ships
today. Its interaction is inspired by
[OpenID CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html),
but this administrative change workflow is not a claim of CIBA login-protocol
conformance. Proposal and approval remain distinct authorities.

The action executor captures the eligible reviewer requirement and quorum at
proposal time. Repeated approval by the same person does not increase the
distinct-admin count. An eligible human administrator who proposed a change may
count once; the default supports a single-operator deployment. Per-action
requirements are implemented in the executor registry, not a general
environment setting for arbitrary quorum changes.

An optional out-of-band webhook notifier can alert the human. Its endpoint and
credentials belong in deployment configuration. MCP form/URL elicitation as a
shortcut into this control-plane approval flow remains proposed work; the
returned approval URL and binding code are the working client path. This is
separate from ordinary tool-call approval and MCP elicitation forwarding.

See the [approval implementation contract](../agents/hitl-control-plane.md),
[proposal tool schemas and tests](../../crates/waygate-server/src/mcp_builtin.rs),
[observation tools](../../crates/waygate-server/src/mcp_observe.rs), and
[direct controls](../../crates/waygate-server/src/mcp_control.rs).
