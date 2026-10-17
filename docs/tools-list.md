# The `tools/list` catalog

## One authorized catalog

Every client receives the same kind of `tools/list`: direct `<server>.<tool>`
declarations for every admitted tool the caller may discover, plus the gateway
built-ins the caller holds the scope for, in canonical name order. The gateway
preserves each upstream tool's publishable title, description, input schema,
output schema, and annotations. Ordinary upstreams publish ordinary MCP `Tool`
descriptors and need no gateway-specific contract.

Authorization and runtime admission are re-evaluated on every list and every
call. API-key profiles, Cedar policy, schema admission, and quarantine all
filter the list; a declaration a client still holds never grants access,
because every call is resolved, authorized, and admitted again at invocation.
A call to a name the gateway does not hold, or withholds from the caller,
returns the INVALID_PARAMS `tool_unavailable` error; refresh the list rather
than retrying the call.

For search across a large catalog, use the gateway's own discovery tools,
`gateway-discovery.search` and `gateway-discovery.inspect` (see
[governed tool discovery](tool-discovery.md)), or Code Mode's
`codemode.search` and `codemode.describe`.

## Pagination

MCP 2026 clients receive the catalog through the MCP
[opaque-cursor pagination contract](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination).
Page size is gateway-selected, an explicitly empty cursor starts the traversal,
and only an omitted `nextCursor` ends it. The server-minted continuation is
authenticated and encrypted, binds the complete non-credential principal
projection and exact wire catalog, and never grants access by possession.
Expiry, mutation, cross-operation input, or a different principal context
returns `-32602` with restart guidance. The first page builds the authorized
canonical view and holds it for up to 60 seconds; continuations requesting the
same presentation are served from that view, so a traversal completes with one
consistent list while the live catalog changes, and invocation still resolves
and authorizes every call. Past
that window, or on a process that does not hold the view, a continuation
rebuilds the live view and is accepted only if the exact wire catalog is
unchanged, never mixing pages from different views. The gateway logs the failed
check for every rejected continuation. Deployments share the existing
continuation key across replicas; without it, a process-local key keeps local
development safe but a restart or replica change requires traversal to restart.
Each page carries `cacheScope: "private"` and the configured `tools/list`
freshness hint described under [Private cache boundary](#private-cache-boundary).

Legacy sessions receive the same catalog unpaginated, because deployed legacy
hosts cannot be assumed to follow continuations. They accept an empty
first-page cursor but never issue a non-empty one.

## Compact Code Mode-only clients

Some hosts have a hard initial tool limit, so the full catalog does not fit.
For those hosts, `GATEWAY_CODEMODE_ONLY_CLIENTS` replaces the upstream
declarations with authorized gateway built-ins. Code Mode remains the governed
discovery and invocation path through `codemode.search`, `codemode.describe`,
and `codemode.execute`. This compact projection applies to both protocol
generations. Code Mode execution uses the caller's ordinary direct authority and
does not require durable result storage; durable continuation tools are simply
withheld when that storage is unavailable. After changing this setting,
reconnect a legacy client so its next initialize handshake selects the new
projection. A stateless MCP 2026 client selects the projection independently on
its next request.

`clientInfo.name` is self-asserted and selects only a context-size projection.
It never changes authorization: every list re-runs the same filters, and every
call re-runs governed dispatch. To roll the setting back, remove the exact name
and reconnect legacy clients; stateless clients apply either change on their
next request.

## Observability

The metric
`mcp_tools_list_requests_total{protocol_generation,discovery_mode,client_class}`
exposes only the closed modes `stable_full` and `codemode_only`, with the closed
client classes `legacy_other`, `stateless`, and `compact_allowlisted`. It never
records a client name or payload. Use, for example:

```promql
sum by (protocol_generation, discovery_mode, client_class) (
  rate(mcp_tools_list_requests_total[15m])
)
```

`mcp_tools_list_returned_tools` and `mcp_tools_list_serialized_bytes` are
per-response-page histograms with the same labels. The byte measurement is the
compact serialized `ListToolsResult` before the request-specific JSON-RPC
envelope and transport framing. The gateway counts those bytes with a sink
writer rather than allocating a second catalog-sized buffer.

Retire the legacy generation only after both
`mcp_requests_total{protocol_generation="legacy"}` and every legacy series of
`mcp_tools_list_requests_total` stay flat for the chosen observation window.

## Wire ownership capture

Before changing descriptions or server instructions, capture all three
projections for the same authorization view:

1. the raw `server/discover` result and every page of raw `tools/list`;
2. the connector-adapted tool declarations; and
3. the host-registered declarations presented to the model runtime.

Keep captures outside git: an authorization-scoped catalog is operational
metadata even though it contains no credential values. Normalize each tool
surface to a standard `{ "tools": [...] }` document and run:

```sh
node scripts/report-tool-context.mjs raw-tools-list.json
node scripts/report-tool-context.mjs connector-tools.json
node scripts/report-tool-context.mjs host-tools.json
```

Compare `toolCount`, `toolsJsonBytes`, field groups, and
`repeatedDescriptionLeadingBlocks`. The raw contract is pinned by
`stateless_wire_keeps_server_instructions_out_of_tool_descriptions`: shared
guidance occurs exactly once in `server/discover` and zero times in raw tool
descriptions. Repetition introduced only in a later capture is owned by that
adapter or host. Kagi is a useful small canary, but the comparison is always
catalog-wide so a shared transformation cannot be mistaken for an
upstream-specific defect.

## Private cache boundary

The catalog is always `cacheScope: private`. Its `ttlMs` is the
operator-configured freshness hint `GATEWAY_TOOLS_LIST_CACHE_TTL_SECONDS`
(default 60 seconds; `0` keeps every page immediately stale). A traversal is
built from one stable catalog and policy generation: a first page, or a
continuation whose captured view is no longer held, requested during a catalog
publication or policy swap returns a retryable `catalog_changing` error instead
of a cacheable result. Continuation pages served from a captured view belong
to the generation their first page was built from. A catalog notification
invalidates every page immediately.

Inside the freshness window a client may still hold a page whose visibility
inputs have changed: tenant and principal authorization view, API-key/profile
generation, Cedar policy generation, catalog publication epoch, or
runtime/quarantine generation. That affects only which tools the client
attempts. Every call is resolved, authorized, and admitted again at
invocation, so a cached declaration never grants access. No cache entry may
cross authorization contexts, and a positive TTL is not a substitute for
reauthorization at invocation.

Live catalog changes use the independent process-wide epoch, so failed or
descriptor-identical refreshes stay quiet.
