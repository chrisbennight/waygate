# Discover and call MCP tools

The gateway gives clients one authenticated MCP endpoint while keeping each
upstream's tools discoverable and directly callable. It applies policy when
listing tools and again when calling one. A cached tool definition is never an
access grant.

## Try the portable path

Run [the local tutorial](../../examples/quickstart/README.md). Its checker uses
ordinary `tools/list` and `tools/call`: `demo.greet` succeeds and
`demo.restricted` is hidden and refused. No special client extension is needed
for that workflow.

For a larger catalog, a capable host can retain definitions outside the model's
initial context, search them, and load the selected definitions. This preserves
the upstream's typed inputs, outputs, and descriptions. The host controls
selection quality and prompt size; the gateway controls access and dispatch.
See [deferred tool loading](../host-tool-discovery.md).

When the owning upstream is unknown, `gateway-discovery.search` returns compact
authorized matches across the gateway and its upstreams. Use
`gateway-discovery.inspect` for the exact current tool definition, then invoke
the returned tool directly. See [gateway-wide discovery](../tool-discovery.md).

Code Mode adds server-side search, typed description, and programmatic calls.
It is useful when several results need filtering or joining before returning a
small answer. See [the Code Mode workflow](code-mode.md).

## Standards and enhancements

The implementation explicitly names MCP `2026-07-28` and `2025-11-25` as its
supported specification versions. The newer path uses self-contained requests;
the compatibility path uses negotiated legacy sessions. Downstream and upstream
connections can use different generations. Actual capabilities also depend on
the configured upstream and the caller's authority.

Legacy sessions normally start with the compatibility search projection and
disclose selected tools into that session. Eager-list settings support hosts
that do not refresh callable bindings after a catalog-change notification.
The modern path has a stable authorized direct catalog. See the
[projection configuration](../sep-1888.md) before choosing a client-specific mode.

| Capability | Classification | What this gateway provides |
| --- | --- | --- |
| Discovery, typed tools, resources, prompts | Core MCP | Standard client-facing methods and governed upstream routing. |
| Self-contained requests and `server/discover` | MCP 2026-07-28 | Request-local version/capability handling with a stable, paginated direct-tool catalog. |
| Legacy initialization | Compatibility | Stateful MCP sessions alongside the modern request model. |
| MCP Apps | Official `io.modelcontextprotocol/ui` extension | Passed through: a tool's `_meta.ui` reference, its `ui://` resource and result metadata reach clients unchanged, and the resource is read under ordinary resource authorization. The gateway's shared upstream sessions declare no client extensions, so an upstream that lists app tools only to clients declaring the extension does not list them through the gateway. |
| Durable Tasks | Official `io.modelcontextprotocol/tasks` extension | Configured Code Mode executions project status, results, cancellation, and continuation input through the extension. Durability requires explicit storage configuration. |
| Enterprise-managed authorization | Official MCP authorization extension, built on an IETF draft | Opt-in ID-JAG issuance and redemption using the gateway's policy and directory state. See [identity capabilities](security.md). |
| Progressive `searchTools` | Closed SEP-1888 draft compatibility | An optional search projection; ordinary tools remain the portable interface. |
| Native file authorization | SEP-2631 draft compatibility | HTTPS file transfer and `x-mcp-file` handling, with ordinary `gateway-files.*` tools for clients without the draft. |
| Verified skills and Code Mode | Gateway capabilities with optional extension adapters | Reviewable workflow delivery and bounded execution through the ordinary authorization boundary. |

The [MCP versioning rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
and [release changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
explain the protocol generations and Tasks extension. The source declares its
version list in [waygate-mcp](../../crates/waygate-mcp/src/lib.rs); projection and
extension advertisement live in [the server adapter](../../crates/waygate-mcp/src/server.rs).

Draft compatibility is intentionally explicit. Follow
[SEP-1888](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1888)
and [SEP-2631](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2631)
for their own status. The gateway's file negotiation matrix documents the
current SDK gap for legacy initialization-only file capabilities and the
request-metadata alternative. It does not assume all hosts implement these drafts.

## Protocol support policy

The gateway serves two protocol generations side by side:

- **MCP `2026-07-28`** has no sessions. Any replica can answer any request, so a
  restart or a move to another replica affects only requests already in flight.
- **MCP `2025-11-25`** uses sessions held in the memory of one gateway process.
  An `initialize` request that asks for an earlier version (`2024-11-05`,
  `2025-03-26` or `2025-06-18`) is accepted at that version and served the
  same way; the gateway does not narrow its behavior to the earlier revision.

New capabilities are built for `2026-07-28`. The session path keeps the
features it has and receives security, correctness and compatibility fixes. It
gains a new capability only when that needs no work specific to sessions.

The specification sets no end date for `2025-11-25`, and
[SEP-2567](https://modelcontextprotocol.io/seps/2567-sessionless-mcp) leaves
that choice to each server. The gateway keeps the session path while clients
still use it. `mcp_requests_total` counts every request by protocol generation,
negotiated version and client name; see
[the metrics reference](../agents/telemetry.md#prometheus-metrics). The session
path is retired only after its `legacy` series has stayed flat for an
observation window, and the release notes announce the removal in advance.

Review this policy at each of these points:

- when the first MCP revision released on or after 2027-07-28 is published,
  the earliest point at which the
  [deprecated features registry](https://modelcontextprotocol.io/specification/2026-07-28/deprecated)
  allows Roots, Sampling, Logging and Dynamic Client Registration to be removed;
- when SEP-2596 reaches Final, which starts the registry's three-month notice
  before the HTTP+SSE transport may be removed; and
- whenever the gateway adopts a new specification revision.

### Deprecated features

| Feature | Gateway as a server, toward clients | Gateway as a client, toward upstreams | Plan |
| --- | --- | --- | --- |
| Roots | Never requests roots. When a `2026-07-28` upstream asks for roots before it can finish a call, the gateway does not pass the request on and returns a refusal that says why. | Never declares roots. On a `2025-11-25` upstream session the MCP SDK's default handler answers an unexpected `roots/list` with an empty list. | No change. Nothing depends on the feature, so its removal needs no gateway work. |
| Sampling | Never requests sampling. An upstream sampling request on `2026-07-28` is refused the same way as roots. | Never declares sampling. On a `2025-11-25` upstream session a sampling request is refused as an unknown method. | No change. No sampling relay will be built. |
| Logging | Does not advertise the `logging` capability, refuses `logging/setLevel` as an unknown method and sends no `notifications/message`. | Drops upstream log notifications. | No change. The gateway reports through its own logs, metrics and audit records. |
| Dynamic Client Registration | Not offered. The optional built-in authorization server, off by default, identifies clients by Client ID Metadata Documents. | Not used. Upstream credentials come from each manifest's `auth:` block. | No change. |
| HTTP+SSE transport | Not served. Clients use Streamable HTTP at `/mcp`. | Opt-in per upstream with `transport: sse`, which always uses the `2025-11-25` handshake. | Kept while configured upstreams need it. When SEP-2596 reaches Final, move SSE upstreams to Streamable HTTP before the removal date the registry then sets. |

### Restarts and `2025-11-25` sessions

A restart ends every `2025-11-25` session held by that process, and a request
routed to another replica finds no session there, because each process keeps
its own sessions. In both cases the gateway answers the session ID with HTTP
404 Not Found, which the specification defines as the signal to start a new
session. Claude Code does this automatically since the fix recorded in
[claude-code#55970](https://github.com/anthropics/claude-code/issues/55970)
(May 2026). Older Claude Code releases, and other clients that ignore the
signal, keep failing until the user reconnects the server or restarts the
client; upgrade them, or move them to `2026-07-28`, which needs no reconnection.

A response stream cut off by the restart cannot be resumed. Work that must
survive a restart belongs in a task or a detached Code Mode execution; see
[what survives restarts](../agents/tasks.md#what-survives-restarts-disconnects-and-replica-changes).

## Verify your client

Use the [host-contract probe](../host-tool-discovery.md#executable-proof) with an
explicitly selected harmless tool. Also exercise policy refusal, catalog refresh,
and the actual protocol generation your client uses. The repository's modern
and legacy upstream smoke tests check interoperability; they do not certify
every client release or promise a particular client's native menu behavior.
