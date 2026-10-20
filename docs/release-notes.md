# Release notes

## Unreleased

## 2.0.1

- Upload and download authorization over upstream HTTP preserve transfer fields
  when the response includes standard MCP `_meta` metadata. Streamed replies
  answer upstream pings, and method-level refusals retain their error category.
- Retained JSON responses import file descriptors nested in objects and arrays.
  The download helper can read their rewritten gateway file addresses. The
  response and its attachments publish together under the caller's ownership
  and the existing transfer budget.
- An upstream that verifies the gateway's identity token no longer refuses the
  gateway's first connections after a restart. The gateway now serves its
  identity key set before it connects to upstreams; until startup completes,
  every other path answers `503 Service Unavailable`.
- Clients on MCP revision 2026-07-28 can read resources that an upstream on
  an earlier revision provides. Those reads previously reached the client
  without the required `resultType`, and the client rejected them. Clients on
  earlier revisions see no change.
- The warning that an upstream offers resources its manifest declares no
  prefix for appears once, when that becomes true, instead of on every
  connection to the upstream. It appears again after a reload removes the
  last declaration or rebuilds the upstream's connections.

## 2.0.0

This release changes which upstream manifests the gateway accepts. Read
**Upgrading from 1.x** before deploying it.

### Upgrading from 1.x

- **Classify every upstream server.** Each manifest sets `trust: internal` or
  `trust: external`; a server without it is `external`. External servers receive
  no identity token (`X-MCP-Identity`) and no trace context, and an external
  server with a plain `http://` URL fails to load. Mark every server that is part
  of the deployment, and every plain-HTTP server, `trust: internal`. Per-server
  `identity` and `forward_trace_context` settings override the defaults. See
  [trust classification](agents/upstreams.md#trust-classification).
- **Unknown manifest keys are errors.** A key the schema does not define fails
  the load and names the server and key. Remove obsolete or misspelled keys.
- **Resource reads use declared prefixes only.** Native resource reads and
  listings reach an upstream only through `resources` URI prefixes declared in
  its manifest. The gateway no longer finds a resource's owner by asking
  upstreams what they list, because an upstream could list another upstream's
  URIs and receive its reads. Declare a prefix for every upstream whose
  resources should stay readable; the gateway logs a warning for an upstream
  that advertises resources without one. Once a server declares any prefix,
  its retained connector responses must also fall under a declared prefix, or
  large results from that server are refused. See [upstreams](agents/upstreams.md).
- **Stdio upstreams get a minimal environment.** A stdio child receives a fixed
  non-secret baseline plus the variables its manifest names in
  `env_passthrough`, instead of the gateway's whole environment.
- **Upstream requests stay on the configured host.** Redirects are refused,
  and an SSE upstream's message endpoint must share its configured origin.
- **Stage manifest keys by editing the served files.** Versions before 2.0.0
  ignore the new keys, so they can be added ahead of the upgrade. On those
  versions, the dashboard manifest editor and `gateway-admin` manifest actions
  re-serialize the whole set and drop keys they do not know. Make any
  admin-tool manifest changes first, then add the new keys directly to the
  served `servers/*.yaml` files, and avoid admin-tool manifest writes until
  2.0.0 is running.
- **Database migrations `0112` to `0116` run at startup.** A 1.x image refuses
  to start against the migrated database, so take a backup before upgrading if
  you may need to roll back.

### Added

- The `mcp-files` helper can redeem a transfer grant with its own key and the
  gateway file address: `mcp-files download --uri <mcp-file address> --dest <path>`
  and `mcp-files upload --uri <address> --file <path>`. Clients no longer need
  to pass the prepare result to the helper. The previous standard-input form
  still works.
- Per-server upstream credentials: an API key in a named header, a query
  parameter or HTTP Basic, plus fixed non-secret headers.
- Per-server call timeout and tool-call response size limit, and a gateway-wide
  tool-call response size limit (default 64 MiB).
- Long upstream calls run as gateway tasks for clients that support tasks, and
  abandoned upstream calls are cancelled.
- A provider-native Anthropic Messages inference surface.
- Code Mode: programs run as async functions, console output returns to the
  caller, and standard text, URL, crypto and clone helpers are available.
- Dashboard: a page listing every blocked tool, where calls are refused,
  per-tool output-schema rejection details, and a before-and-after view of each
  catalog drift event.
- Response delivery: file thresholds can be configured globally and per
  upstream server.

### Changed and fixed

- A refused tool call says why, without revealing hidden tools.
- Tool search, discovery and built-in tool lists are more compact, and
  `tools/list` continuations are served from the first page's captured view.
- `/readyz` answers without taking a lock or waiting on an upstream.
- In-flight MCP work finishes before the transport closes on shutdown, and
  pooled upstream sessions are closed.
- Resource reads send upstream only metadata the gateway builds.
- File tool responses no longer include a scanner status.

## 1.1.0

- Persist review and quarantine of changed upstream tool contracts, with a
  dashboard workflow for accepting a specific observed contract. The additive
  `0111_tool_contract_reviews.sql` migration stores the review state.
- Support recipient-aware email approval policies and document the workflow.
- Refresh dashboard branding and workflow documentation.

- Preserve upstream-declared response schemas in legacy MCP discovery and Code
  Mode, including nested response types. Catalog schemas retain precedence and
  existing output-validation behavior is unchanged.
- Include declared response schemas in Code Mode discovery identities so clients
  can detect changes. Runtime admission and saved execution bindings are unchanged.

## 1.0.0

Initial public release of Waygate.

- Govern MCP tools and model inference through a shared identity, Cedar policy,
  quota, and audit boundary.
- Discover tool capabilities progressively, transfer files, load verified skills,
  and orchestrate calls with Code Mode.
- Review proposed gateway changes through the administration dashboard.
- Run the gateway as a distroless container and use the `mcp-files` helper on
  Linux, Windows, and macOS.

Start with the [local tutorial](../examples/quickstart/README.md). For production,
follow the [configuration guide](configuration.md) and
[operator runbook](operations.md). Feature prerequisites and current limitations
are described in the [documentation index](README.md).
