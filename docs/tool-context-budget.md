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
- the largest individual declarations, and the size of every declaration by
  tool name.

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

### Built-in surface

The gateway's own built-in namespaces (`gateway-*`, `codemode`, and the skills
surface) are the one catalog the project fully controls, so they have a budget
of their own. `scripts/fixtures/tool-context/builtin-tools-list.json` is the
complete built-in `tools/list` a fully authorized caller receives with no
upstream servers, built through the real `GatewayServer` projection from every
namespace's canonical catalog. The `gateway-server` test
`builtin_tool_capture_is_current` fails when any built-in declaration changes
without the capture being regenerated.
`builtin_tool_capture_includes_every_reserved_namespace` fails unless the
capture covers exactly the namespaces in
`waygate_core::RESERVED_BUILTIN_NAMESPACES`, where every built-in namespace
must be reserved, and `builtin_tool_capture_covers_every_namespace` fails when
a namespace's tools are missing. CI then measures the capture against
`scripts/fixtures/tool-context/builtin-budget.json`. After an intentional
change, regenerate the capture and check it against the budget:

```sh
WAYGATE_UPDATE_TOOL_CONTEXT_CAPTURE=1 \
  cargo test -p waygate-server --bin gateway-server builtin_tool_context
node scripts/report-tool-context.mjs \
  --budget scripts/fixtures/tool-context/builtin-budget.json \
  scripts/fixtures/tool-context/builtin-tools-list.json
```

The built-in budget also sets a maximum for each tool in `toolMaximums`, so
one description or schema cannot grow unnoticed while the totals stay within
their limits. Adding, renaming or removing a built-in tool needs a matching
per-tool entry. The same ratchet rule applies: growth needs an explicit budget
diff with a reason, and a reduction lowers the budget in the same change.

The output-schema budget includes the gateway's retained-response delivery
alternative, which strict clients need to validate a result delivered as a
file. Listed tools carry a compact form of it that accepts every delivery
envelope without describing the file descriptor and error fields, because
those fields are the same for every tool. `codemode.describe` returns the full
form for one tool, and the [file transfer guide](file-transfer.md) documents
it. The limits in the budget file include the compact form.

### Realistic catalog

The representative catalog has two upstreams, so a cost the gateway adds once
per upstream or once per tool barely registers in it.
`scripts/fixtures/tool-context/realistic-catalog.json` is a synthetic catalog
closer to a real deployment: fifteen upstreams of common kinds, schemas with
nested objects, enumerations, arrays and alternatives, output schemas on some
tools, and one home automation server deployed twice under two names, as
deployments often do. Its server names use the `demo-*` form that
`scripts/check-synthetic-policy-fixtures.sh` enforces; real deployment details
belong in operators' repositories.

CI measures the full list every client receives against
`realistic-full-budget.json`. The Code Mode-only view lists built-in tools
alone, which the built-in budget already covers. To reproduce the measurement
locally:

```sh
cargo run --quiet -p waygate-mcp --example tool_context_projection -- \
  --catalog scripts/fixtures/tool-context/realistic-catalog.json |
  node scripts/report-tool-context.mjs \
    --budget scripts/fixtures/tool-context/realistic-full-budget.json -
```

A change to what the gateway adds to every tool or every upstream should quote
the report before and after the change. The same ratchet rule applies to this
budget.

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

## Read production size metrics

A deployment's own catalog is measured by two histograms,
`mcp_tools_list_returned_tools` and `mcp_tools_list_serialized_bytes`, labelled
by protocol generation, discovery mode and client class; see
[the metrics reference](agents/telemetry.md#prometheus-metrics). The bundled
dashboard charts their 95th percentiles.

- Serialized bytes cover the compact `ListToolsResult` JSON of one response,
  which is close to the reporter's `toolsJsonBytes` for the same view.
- An MCP 2026 response is one page of up to 50 tools, and pages differ in
  size, so its series describe pages rather than the catalog; a percentile
  cannot be added up across pages. To compare a whole catalog with the
  realistic full view, capture every page as described under
  [reproducible report](#reproducible-report).
- For a breakdown by field or by tool, or to find repeated content, capture
  `tools/list` for one authorization view and run the reporter on it.

## Optimization boundary

The downstream contract stays standard MCP. A client or host may defer the
gateway server and search its catalog, but an upstream must not need to know
that it is behind this gateway or emit host-specific metadata. The gateway can
offer a compact projection separately; it must preserve downstream tool
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

Some hosts may choose to render server instructions beside every tool in their
own model prompt. That rendering is outside the MCP wire contract. To verify
the boundary without changing tool declarations, capture `server/discover` (or
the legacy initialize result) and `tools/list` for the same authorization view,
run this reporter on the raw `tools/list`, then compare those two wire values
with the host's rendered prompt. Repetition present only in the rendered prompt
is host-owned; report it to the host rather than deleting schemas or rewriting
downstream descriptions in the gateway.
