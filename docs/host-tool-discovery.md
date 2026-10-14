# Deferred-tool host contract

Tool deferral is a host optimization around a standard MCP connection. It is
not a gateway-to-upstream protocol and it does not change what a downstream
server publishes.

## Portable contract

The portable path has four parts:

1. The host registers the gateway as one MCP server, with one concise server
   description.
2. The gateway publishes the caller's authorization-scoped ordinary tools via
   standard `tools/list`. Each tool retains its downstream-authored name,
   description, schemas, title, annotations, and extension metadata.
3. A capable host defers that server or catalog, searches it outside model
   context, and loads a bounded set of matching definitions for the model.
4. The selected tool is invoked directly as `<server>.<tool>` through standard
   `tools/call`. A generic gateway invocation wrapper is not part of this
   contract.

The host owns selection quality, the maximum number of definitions it loads,
and its prompt serialization. The gateway owns authentication, authorization,
runtime admission, direct routing, and faithful MCP projection. Downstream
servers remain unaware of both layers: they publish ordinary MCP tools and do
not add host-specific fields.

This division matches the MCP project's
[client guidance](https://modelcontextprotocol.io/docs/develop/clients/client-best-practices):
the client fetches the ordinary catalog, keeps large definitions outside the
initial model context, searches a lightweight index, and loads only selected
interfaces. Goose's
[Code Mode](https://block.github.io/goose/docs/mcp/code-mode-mcp/) is a useful
host-side exemplar: its three meta-tools let the model search, inspect, and
execute ordinary MCP operations programmatically. It is an optional
acceleration layer, not a reason for the gateway to hide the portable direct
tools from capable clients or for upstream servers to implement a second
discovery protocol.

## Host implementations

Hosts with native deferred loading should keep the optimization in their
server/tool registration layer. For example, OpenAI Responses supports native
tool search and marks deferred function tools or MCP server tools with
`defer_loading`; the model initially receives the server identity rather than
every deferred definition. That setting belongs to the OpenAI request made by
the host, not to MCP `tools/list`, a gateway server manifest, or an upstream
tool's `_meta`. See OpenAI's official
[tool-search guide](https://developers.openai.com/api/docs/guides/tools-tool-search)
and [tools guide](https://developers.openai.com/api/docs/guides/tools).

A host without deferred loading uses the same direct MCP contract and renders
the stable authorization-scoped catalog it receives. It may apply a local
allowlist or another bounded selector before prompt construction, provided
that selection is not mistaken for authorization. The gateway still enforces
access on discovery and again on invocation. Measure that host's rendered
surface with [`report-tool-context.mjs`](../scripts/report-tool-context.mjs)
instead of weakening tool schemas or descriptions to compensate for its
renderer.

Catalog refresh stays standard as well. A stateful host listens for
`notifications/tools/list_changed` and refetches; a stateless MCP 2026 host
receives a stable, current projection on each request. Authorization changes
and quarantine can therefore remove a previously selected tool, and the host
must accept a later direct call refusal rather than cache access as a grant.

The order of that projection is promised, not incidental, so a host can key a
prompt cache or a client-side list cache on the exact tool array. Every client,
including Code Mode-only clients, receives one order sorted by qualified tool
name across built-in and upstream tools. The pages of one MCP 2026 traversal
concatenate to one such order and never mix pages from different views; see
the [pagination contract](tools-list.md#pagination).
The order does not depend on the order in which upstreams,
connection lanes, or reloads publish their tools, so republishing the same
catalog leaves the array unchanged. An authorization filter only removes
tools: two principals with different visibility each see a stable array, and
the tools they share keep the same relative order.

MCP 2026 `tools/list` results also carry a freshness hint (`ttlMs`, set by
`GATEWAY_TOOLS_LIST_CACHE_TTL_SECONDS`) with `cacheScope: private`, because the
catalog is filtered per caller. The hint lets a host reuse the list for that
long instead of refetching it on every request; a `tools/list_changed`
notification invalidates it early. A cached declaration remains discovery
state, never a grant: the gateway authorizes and admits every call again.

Search and code execution do not become authorization boundaries. Following
Block's [agent guardrail guidance](https://block.github.io/goose/blog/2026/01/05/agentic-guardrails-and-controls/),
the gateway treats the agent as a nondeterministic client: it enforces identity,
policy, runtime admission, and human approval deterministically at discovery
and invocation. A host may rank or combine tools, but it cannot grant itself a
tool by discovering or caching its declaration.

## Executable proof

`mcp-test-client host-contract` uses stateless MCP 2026 discovery and checks
the two interoperability properties a deferred host depends on: the named
ordinary tool appears in standard `tools/list`, then succeeds through a direct
`tools/call`. It never sends host-specific metadata.

Against the repository's modern smoke upstream:

```sh
cargo run -p waygate-test-client -- \
  --gateway http://localhost:8080 \
  --auth none \
  host-contract \
  --tool modern-smoke.ping \
  --args '{}'
```

Use an explicitly chosen, non-side-effecting tool in other environments. The
command intentionally requires the caller to name the probe: catalog
membership alone cannot prove that an arbitrary tool is safe to execute. It
prints no tool result content, so the conformance record proves the boundary
without copying a possibly sensitive payload into CI logs.

Failure is non-zero and identifies which contract failed:

- absent from `tools/list` means the host cannot select the tool through the
  portable catalog;
- a JSON-RPC error or `isError=true` means direct invocation did not complete.
