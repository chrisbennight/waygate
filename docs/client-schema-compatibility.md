# Client schema compatibility

Some MCP clients cannot register tools with valid root-level JSON Schema
composition. A server can appear connected while affected tools are missing.
Waygate can present a simplified schema to selected clients and still enforce
the complete admitted schema on every call.

## Enable the profile

Set this on the gateway process and restart it:

```sh
GATEWAY_ROOT_COMPOSITION_CLIENTS=claude-code
```

Use the client's actual MCP `clientInfo.name`. Names are comma-separated,
trimmed, and matched exactly ignoring ASCII case. The default is empty: no
client receives adaptation until the operator opts in. The setting is
independent of eager or compact discovery and never grants tool access.
It works for legacy sessions and stateless MCP requests. Reconnect legacy
clients after restarting the gateway.

Remove the setting and restart to restore the standard declarations. Existing
invocation validation, approvals, authorization, and tool names are unchanged.

## What changes

The profile changes only `tools/list`. For supported object-rooted schemas it
removes root `allOf`, `anyOf`, `oneOf`, `not`, and `if`/`then`/`else` from the
client-facing copy. Root properties still describe the arguments. The removed
constraints are appended as JSON Schema to the tool description, so the model
can use them when constructing calls. Nested applicators remain intact.

This is a broader schema for argument generation, not a replacement validation
contract. For a size cap that depends on mode:

| Arguments | Invocation result |
| --- | --- |
| `{"mode":"large","size":1500000000}` | Accepted |
| `{"mode":"small","size":1000000}` | Accepted |
| `{"mode":"small","size":1500000000}` | Rejected before upstream dispatch |

`gateway-discovery.inspect`, legacy `searchTools` type results, and
`codemode.describe` continue to return the **authoritative** schema as result
data. Their argument shape and tool identity agree with the presented tool;
their constraints can be stricter. Use `tools/list` for the selected client's
registration declaration, not an inspection result as a replacement declaration.

## Supported scope and fallback

The initial adapter supports root branches containing composition/conditionals,
properties and required lists naming root-declared arguments, type constraints,
property counts, and description/title/comment annotations. It does not invent
fields that appear only in branches. Reference-bearing schemas, root pattern
properties, unevaluated properties, and unsupported branch keywords are left
unchanged. Constraints larger than the compatibility description budget
(4096 UTF-8 bytes) are also left unchanged.

An unsupported tool produces a warning naming the tool, profile, and reason.
The original declaration remains available; a restricted client may still
omit it. Server instructions explain the Code Mode route. Debug logging records
successful adaptation. These messages report gateway presentation, not proof
that the client registered a tool.

When Code Mode is available and authorized, use `codemode.search`,
`codemode.describe`, and `codemode.execute` to call the operation without
registering its complex schema as a model tool. To expose only gateway built-ins
to a restricted client, the existing compact option can be used instead:

```sh
GATEWAY_CODEMODE_ONLY_CLIENTS=claude-code
GATEWAY_EAGER_TOOLS_CLIENTS=codex-mcp-client
GATEWAY_EAGER_TOOLS_LIST=false
```

Preserve other configured client names; a name cannot appear in both the compact
and eager allowlists. Code Mode uses existing permissions and validation. It
does not require durable result storage for ordinary execution. See
[discovery compatibility](sep-1888.md) for these settings.

## Reproduce and verify

The synthetic definitions live in
[`client-schema-tools.json`](../crates/waygate-mcp/tests/fixtures/client-schema-tools.json).
They include flat, nested-composition, and conditional size-cap tools. The
dependency-free [stdio fixture](../scripts/client-schema-fixture.py) serves
them without production services or credentials:

```sh
python3 scripts/client-schema-fixture.py
```

To serve the same fixture with the actual adapter output:

```sh
cargo run -p waygate-mcp --example client_schema_projection -- --fixture > /tmp/waygate-presented-tools.json
python3 scripts/client-schema-fixture.py --tools /tmp/waygate-presented-tools.json
```

Register either command with a test client to compare registration behavior.
The fixture reports protocol versions to stderr and answers unknown methods
with a JSON-RPC error; it never claims a modern protocol through a legacy
handshake. For the actual gateway projection and enforcement, run:

```sh
cargo test -p waygate-mcp client_schema
cargo test -p waygate-server conditional_schema_remains_discoverable
```

The HTTP integration tests exercise legacy and stateless presentation, actual
dispatch/rejection, and changed-view pagination. Code Mode tests retain the full
conditional contract through discovery and connector invocation. They run
without paid clients or private infrastructure.

Measure projection plus serialization on a synthetic mixed catalog locally:

```sh
cargo run -p waygate-mcp --example client_schema_projection
```

This prints baseline/adapted list time and response size. It is a manual
measurement, not a timing-sensitive CI gate. The adapter does local schema work
only; it adds no database/network requests or validation stage to invocation.

For a live client check, record the client version, request protocol version,
listed tools, one successful valid call, and rejection of the invalid small-mode
call. Compare profile disabled/enabled against a disposable gateway using the
fixture. Treat client results separately from Rust tests; support for every
client version or every JSON Schema keyword is not implied.
