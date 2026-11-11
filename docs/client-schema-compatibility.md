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
independent of the compact Code Mode-only catalog and never grants tool access.
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

`gateway-discovery.inspect` and `codemode.describe` continue to return the **authoritative** schema as result
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
```

Preserve other configured client names. Code Mode uses existing permissions and
validation. It does not require durable result storage for ordinary execution.
See [the compact catalog](tools-list.md#compact-code-mode-only-clients) for this
setting.

## Reproduce and verify

The synthetic definitions live in
[`client-schema-tools.json`](../crates/waygate-mcp/tests/fixtures/client-schema-tools.json).
They include flat and nested schemas, root unions/intersections, conditionals,
negation, and a reference-bearing schema. The
[fixture launcher](../scripts/client-schema-fixture.py) builds and runs the
workspace's Rust SDK server and full JSON Schema validator. It needs the
repository's Rust toolchain but no production services or credentials:

```sh
python3 scripts/client-schema-fixture.py
```

To serve the same fixture with the actual adapter output:

```sh
python3 scripts/client-schema-fixture.py --adapt
```

Register either command with a test client to compare registration behavior.
The default stdio transport offers only `2025-11-25`. With `--http`, it binds an
ephemeral loopback port, prints its URL, and offers both `2026-07-28` and
`2025-11-25`; add `--legacy` to offer only the latter. The SDK negotiates the
protocol. Bounded client metadata and accepted/rejected fixture call outcomes
go to stderr; arguments and credentials do not. An optional `--tools` file
changes presentation of known fixture tools, while invocation always uses the
original full schemas. For gateway projection and enforcement, run:

```sh
cargo test -p waygate-mcp client_schema
cargo test -p waygate-server conditional_schema_remains_discoverable
```

The HTTP integration tests exercise every fixture in legacy and stateless
presentation, with selection enabled and disabled, valid dispatch and invalid
call rejection, and changed-view pagination. Code Mode tests retain the full
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

## Current client qualification

The [2026-11-11 record](compatibility/client-schema-qualification-2026-11-11.json)
captures Claude Code `2.1.322` and Codex CLI `0.167.1` in eight combinations:
raw/adapted declarations and dual-generation/legacy-only servers. Each client
used fresh isolated configuration, the loopback MCP fixture, and a loopback
model stub. The stub requested a valid and an invalid call for each tool that
the client included in its model request. Every registered tool completed the
valid call and rejected the invalid call against the original schema.

| Client | Raw declarations reaching the model stub | With Waygate adaptation |
| --- | --- | --- |
| Claude Code 2.1.322 | Flat, nested composition, direct conditional, and direct negation; root unions, intersections, and the reference fixture were omitted | All fixtures except the reference-bearing schema |
| Codex CLI 0.167.1 | All nine fixtures; direct conditional and negation keywords were removed in the model request | All nine fixtures; the unsupported reference fixture remained unchanged |

Claude negotiated `2026-07-28` when offered and `2025-11-25` with the
legacy-only server. Codex negotiated `2025-11-25` in both cases. Against the
dual-generation fixture Codex reported `rmcp` / `3.9.0`; against the legacy-only
fixture it reported `codex-mcp-client` / `0.167.1`. These are observed peer
declarations, not a reliable way to identify a product installation from a
generic SDK name.

This qualification establishes client registration, model request shaping, and
actual fixture invocation. It does **not** establish acceptance by the real
Anthropic or OpenAI APIs. Remote feature configuration was not fetched. In
particular, passing a conditional or negation to the stub does not prove that a
provider accepts it, and successful registration does not prove that the model
still sees its full constraints.

Anthropic now documents a Claude Code rewrite for root `allOf`, `anyOf`, and
`oneOf`, controlled by a remote feature flag. If rewriting is unavailable or
unsuccessful, the client can skip the affected tool. See the official
[root combinator guidance](https://code.claude.com/docs/en/mcp#tool-input-schemas-with-a-root-level-combinator).
The isolated run above still demonstrates a need for Waygate's optional
Claude presentation profile. Keep both client-selection settings empty by
default, retain the bounded adapter and authorized Code Mode fallback, and do
not add a generic `rmcp` match based on this observation. Codex did not need a
Waygate schema workaround in this fixture.

Retire a configured workaround only after the target client and provider,
including the operator's normal remote configuration, register the affected
raw schemas and complete valid calls while the gateway rejects invalid calls.
Repeat against both gateway protocol generations that the deployment uses.
Remove the client selection first and compare the same fixtures before
removing a generally useful adapter. An unsupported schema should continue to
use the authorized Code Mode route rather than a broader unverified rewrite.

To repeat an isolated client run, first build the fixture, then supply a
specific locally installed client binary:

```sh
cargo build --locked -p waygate-mcp --example client_schema_fixture
python3 scripts/qualify-client-schemas.py --client claude \
  --client-binary /path/to/claude \
  --fixture-binary target/debug/examples/client_schema_fixture \
  --exercise-calls --report /tmp/claude-schema-raw.json
```

Use `--client codex` for Codex, `--adapt` for Waygate's projection, and
`--legacy` for the legacy-only server. The helper starts only owned loopback
servers, uses synthetic authentication with an isolated client configuration,
and records only known fixture schemas and bounded MCP observations. It does
not change the caller's client configuration or use paid provider credentials.
Keep genuine provider acceptance as a separate, explicitly authorized check.
