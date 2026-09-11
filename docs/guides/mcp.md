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

## Verify your client

Use the [host-contract probe](../host-tool-discovery.md#executable-proof) with an
explicitly selected harmless tool. Also exercise policy refusal, catalog refresh,
and the actual protocol generation your client uses. The repository's modern
and legacy upstream smoke tests check interoperability; they do not certify
every client release or promise a particular client's native menu behavior.
