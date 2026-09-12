# Tool context budget

The gateway treats model context as a measurable projection cost, not as a
property of an upstream server. Upstreams remain ordinary MCP servers: this
measurement starts from the standard `tools/list` response presented to a
client after authentication and authorization.

## Reproducible report

Capture a `tools/list` JSON-RPC response and run:

```sh
node scripts/report-tool-context.mjs tools-list.json
```

For a paginated MCP 2026 catalog, one response measures one wire page. To
measure the complete authorized view, follow every non-null `nextCursor`, then
combine the returned `tools` arrays into one bare array before running the
reporter. An empty cursor is still a continuation value; only an omitted or
null cursor ends traversal.

The reporter also accepts a bare MCP result (`{"tools": [...]}`), a bare tool
array, or stdin (`-`). It reports:

- the number and serialized JSON bytes of visible tool declarations;
- field-value bytes for names, titles, descriptions, input/output schemas,
  annotations, and `_meta`;
- repeated string values of at least 24 bytes, ranked by avoidable repeated
  bytes;
- repeated leading description blocks, which expose instructions prepended to
  every tool instead of presented once for the server;
- output schemas equivalent across JSON object-key and `required` member order,
  canonicalized so those serialization choices do not hide a repeated result
  envelope; and
- the largest individual declarations.

`estimatedTokensAtFourBytesPerToken` is only a coarse planning estimate.
Tokenizer choice and the host's prompt serialization determine real token
use, so byte counts are the stable comparison unit and future CI budget.

## CI ratchet

PR and release CI use the example executable produced by the workspace test
build to construct a representative full catalog through the real
`GatewayServer` projection path. The size check runs that executable directly,
then streams its standard wire response into the portable reporter and
checked-in budget. This avoids a separate package-scoped build with different
dependency features. For a standalone local measurement, run:

```sh
cargo run --quiet -p waygate-mcp --example tool_context_projection |
  node scripts/report-tool-context.mjs \
    --budget scripts/fixtures/tool-context/standard-budget.json -
```

The budget pins the report format and tool count, then sets maxima for total
bytes, each MCP metadata field group, repeated-description/schema diagnostics,
and the largest declaration. A regression fails CI. An intentional increase
therefore requires an explicit budget-file diff with product rationale; a
decrease should lower the corresponding maximum in the same change so the gain
cannot silently drift back. Because the producer uses `GatewayServer`, changes
to qualification, gateway-owned discovery tools, schemas, annotations, or
projection filtering reach the budget gate instead of being masked by a stale
capture. The representative catalog is deterministic CI evidence, not a
substitute for measuring a deployment's authorization-scoped live catalog.

The output-schema budget includes the gateway's retained-response delivery
alternative. Strict clients need the file descriptor and delivery-error schema
alongside the upstream data schema to validate the result they receive. The limits in the budget file include that schema.


The checked-in fixture at
`scripts/fixtures/tool-context/standard-tools-list.json` is intentionally a
plain MCP `tools/list` response used to test the reporter in isolation. It is
not the CI budget input. Neither the live producer nor the fixture requires a
gateway-only discovery method or invocation envelope.

The targeted repetition sections are diagnostics, not permission to delete MCP
fields. A shared output schema may be intentional and still belongs on every
tool that declares it: clients use `outputSchema` to understand and validate
`structuredContent`. Likewise, a repeated leading description block is a
candidate for inspection; the downstream-authored remainder remains part of
the tool contract.

## Optimization boundary

The downstream contract stays standard MCP. A client or host may defer the
gateway server and search its catalog, but an upstream must not need to know
that it is behind this gateway or emit host-specific metadata. The gateway can
offer compatibility projections separately; it must preserve downstream tool
descriptions, schema validation meaning, titles, annotations, and extension
metadata when it projects directly callable tools.

The gateway places its short discovery guidance in the standard server
`instructions` field. It does not prepend that guidance to projected tool
descriptions. Direct projections clone downstream tools and preserve their
descriptions, schema validation meaning, titles, annotations, and extension
metadata. The callable name gains the `<server>.` namespace, and legal schema
spellings that shipping MCP clients handle unevenly receive the
validation-equivalent portability projection documented in
`docs/agents/mcp-tool-docs.md`.
Synthetic legacy `searchTools` descriptions likewise carry only the upstream
name and purpose; their shared discovery and invocation guidance stays in the
server instructions instead of repeating once per visible upstream.

Some hosts may choose to render server instructions beside every tool in their
own model prompt. That rendering is outside the MCP wire contract. To verify
the boundary without changing tool declarations, capture `server/discover` (or
the legacy initialize result) and `tools/list` for the same authorization view,
run this reporter on the raw `tools/list`, then compare those two wire values
with the host's rendered prompt. Repetition present only in the rendered prompt
is host-owned; report it to the host rather than deleting schemas or rewriting
downstream descriptions in the gateway.
