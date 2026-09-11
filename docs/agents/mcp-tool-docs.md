# Self-documenting MCP tools (SOP)

Standard for every built-in tool the gateway exposes over MCP. Load when adding
or editing a tool in `crates/waygate-server/src/mcp_builtin.rs`,
`mcp_observe.rs`, `mcp_control.rs`, the `BuiltinTools` impls in
`crates/waygate-mcp/src/builtin.rs`, or any future built-in namespace.

## Why this exists

Clients (LLM agents) calling our control-plane tools — `propose_change` above
all — have had to read this repo's source to learn the request shape, because
the wire schema punted: `params` was a bare `{"type":"object"}` "validated at
execute time, not here." That is a defect, not a design choice. The variants are
compile-time Rust types; their schemas are generable. This SOP codifies the fix
so it stays fixed for every action we add later.

**Migration status — complete.** Every built-in tool in the `gateway-admin`,
`gateway-observe`, and `gateway-control` namespaces now meets this standard: each
advertises a `schemars`-derived `output_schema`, a title, and behavioral
annotations (the PR-F series). The `propose_change.params` polymorphism — the
motivating case above — is resolved by the `describe_action` discovery tool, not
an inline union. A tool shipped *after* this SOP must meet it from day one, and
that is now **mechanically enforced**: `every_builtin_tool_is_self_documenting`
(`crates/waygate-server/src/main_tests/builtin_selfdoc_enforcement.rs`) fails CI if any built-in tool, in any
namespace, ships without a valid object-rooted `input_schema`, a title, an
`output_schema`, or a `read_only_hint`, or ships an `input_schema` that applies a
composition keyword at its root — so a new tool cannot silently regress the
guarantee.

## The litmus (north star)

> Hand a tool's `tools/list` entry — plus its advertised on-demand discovery
> calls — to a fresh agent with no repo access. If it cannot construct a valid
> request, obtain the current state needed to prepare it safely, and predict the
> result shape, the tool fails this standard.

## Scope

All built-in tools in the `gateway-admin`, `gateway-observe`, and
`gateway-control` namespaces, and any future built-in namespace. Upstream-proxied
tools are documented by their own servers; the gateway's obligation there is
**faithful publication of publishable contracts** — preserve whatever a
conforming upstream declares (title, `output_schema`, annotations, and every
schema constraint) in `tools/list`, and resolve both the
`#input` and `#output` type handles that `<server>.searchTools mode=operations`
advertises via `mode=types`, and return the same contract through
`gateway-discovery.inspect`. Before a schema reaches a client through any of
these surfaces, the gateway rewrites legal JSON Schema forms that shipping MCP
clients handle unevenly into validation-equivalent object forms: boolean
schemas, array-valued `type` unions, and unconstrained schema objects. This
projection never guesses a more specific type and never adds or removes an
accepted instance. Fixing the source server remains preferred because its
direct clients need the same portability.

The gateway does not fabricate a schema an upstream omits or invent the target
of a remote reference. An upstream tool whose `inputSchema` lacks the
MCP-required object root or depends on an unresolved remote reference is
withheld from `tools/list`, search/type discovery, and exact inspection, and
direct invocation fails before authorization or dispatch. An optional output
schema with an unresolved remote reference is omitted while the tool remains
callable. The other tools from that upstream remain available. Documentation
gaps that do not invalidate the MCP contract remain visible: the `classify` CLI
reports which tools ship without an `output_schema` or a description, so an
operator can push the upstream to close the gap.

## The standard — seven points

Every built-in tool definition must satisfy all seven:

1. **Action-oriented `description`.** Says *what it does* and *when to use it*.
   For any tool with discoverable/polymorphic input, the description names the
   discovery path (e.g. "call `gateway-admin.describe_action` for the per-action
   params schema").

2. **Per-field `inputSchema` descriptions + constraints.** Every property carries
   a `description`; use `enum`, `minimum`/`maximum`, `default`, and an accurate
   `required` array. The root declares `"type":"object"`, as required by MCP, and
   applies **no composition keyword** — no `oneOf`, `anyOf`, or `allOf` at the
   root. A root union is legal JSON Schema and legal MCP (SEP-2106 permits an
   object root to carry one), but the tool-calling APIs that consume `tools/list`
   refuse such a definition outright, so the tool is dropped from the client's
   catalog or fails the request that carries it. Built-ins are held to what
   clients can actually register, not merely to what the protocol allows.

   Express mutually exclusive arguments as independent optional properties, say
   so in each one's `description`, and enforce the exclusion when the call is
   handled with an error that names the fields that conflicted — the pattern
   `codemode.execute` uses for its source forms. Nested unions below the
   root are unaffected. `every_builtin_tool_is_self_documenting` fails CI on a
   root composition keyword, so this cannot regress silently.

   The in-repo model for per-field documentation is
   `query_audit_schema()` in `crates/waygate-server/src/mcp_observe.rs` — every
   field has a description with examples and bounds inline. `simulate_schema()`
   in the same file is the model for a nested/variant shape: where a leaf can't
   carry a JSON Schema constraint, its parent's `description` spells out the
   accepted variants.

3. **Polymorphic / keyed inputs are never opaque.** A field whose shape depends
   on a sibling discriminator (the `propose_change.params`-keyed-by-`action_type`
   case) must be resolvable through an on-demand discovery affordance
   (`describe_action(action_type?)`) backed by `schemars`-derived schemas, and the
   valid keys must be enumerable. A bare `{"type":"object"}` with "validated at
   execute time" is a defect.

   A mutation schema is not sufficient when callers must preserve or select
   current state. The action's discovery entry must also identify a bounded,
   read-only MCP context call that returns the authoritative current object or
   candidate and a freshness hash/version. State-replacement params must carry
   that witness, proposal capture must reject an already-stale witness, and the
   execution path must bind it to the authoritative mutation check. Requiring
   source access, dashboard HTML, or an admin-only REST route fails the same
   litmus.

4. **`output_schema` on every read tool** (and on the result envelope of
   write/propose tools), derived from the response DTO; return it as
   `structuredContent` so clients don't parse prose.

   A destructive or single-use tool that deliberately keeps its machine
   payload out of text `content` must name the exact
   `CallToolResult.structuredContent.<field>` path in its MCP-visible
   description. It must also state that text `content` is not the serialized
   payload and tell the caller to capture `structuredContent` before
   interpreting another result channel. Repository documentation is supporting
   evidence, not a substitute for this wire-visible warning.

   A pollable tool whose compatibility text mirrors `structuredContent` must
   likewise identify `CallToolResult.structuredContent` as authoritative in its
   MCP-visible description. Teach programmatic callers to keep intermediate
   envelopes inside their runtime, bound the polling loop, stop at terminal or
   input-required states, and expose a task-specific structured projection
   instead of serializing the whole result envelope into model context.

5. **Behavioral `annotations` + `title`.** `readOnlyHint` for observe tools,
   `destructiveHint` for control/propose tools; a human-friendly `title`.
   (Available in rmcp ≥ 1.8.)

6. **Errors teach.** A validation/deser failure returns the *expected schema and
   a worked example* for the specific input that was wrong — not just serde's raw
   message. The existing "unknown action_type … proposable actions: …" listing in
   `crates/waygate-admin/src/change_requests.rs` is the floor; extend it to params
   shape.

7. **Single source of truth.** The advertised schema is *derived from the same
   Rust type* that deserializes/serializes at runtime (`schemars::JsonSchema`),
   via the workspace `schemars` dependency. Hand-written `json!` schemas that can
   drift from the struct are prohibited for new tools and migrated opportunistically
   for existing ones.

## Polymorphic inputs: the `describe_action` pattern

The recurring trap is `propose_change`, whose `params` shape is keyed by
`action_type`. Do **not** inline a 22-branch `oneOf` into the `tools/list` schema
(it loads every variant into every client's context on connect — the exact bloat
SEP #1888 exists to avoid), and do **not** explode into one tool per action (22
entries in `tools/list`, and it dissolves the single HITL propose boundary).

Instead: keep one `propose_change` tool and expose per-action schemas through a
single discovery tool, `gateway-admin.describe_action(action_type?)`, which
returns a **uniform**
`{actions: [{action_type, params_schema, context}, …]}` — the whole catalog when
`action_type` is omitted, or a single-element list when it filters to one action
(one shape regardless of the filter, so the tool can carry a single clean
`output_schema`, the typed `DescribeActionResponse`). The per-action
`params_schema` comes from `ActionExecutor::params_schema()` (derived from each
executor's param struct), so it cannot drift from what the executor actually
deserializes.

For actions whose safe construction depends on live state, `context` names
`gateway-admin.get_action_context` and carries the action-specific selector
schema plus a validating worked selector example. The action entry also carries
a validating `params_example` that shows where the returned witness belongs.
Selector validation errors repeat their schema and example so a client can
recover without source-code access. The context tool
reads the same source of truth as execution: live on-disk manifests and policies
for authoring, or the durable bundle ledger for publish/rollback. A list selector
returns a store-filtered, bounded page of identifiers; an exact selector returns
the complete selected object/source and its hash or version. Actions that need
no preparation state advertise `context: null`. Selected live and ledger
manifests are operator-authored configuration authorized by `mcp:propose`, not
semantically declassified arbitrary strings. Credential values must remain out
of manifests and use governed references, which this tool never resolves. As
defense-in-depth, URL userinfo, unparseable URLs, and high-confidence
credential-shaped literals are refused. Live listings apply the same literal
check to all server names before returning any name. Supported operational
configuration such as benign URL queries and stdio arguments remains available.
`tools/list` stays small; both schemas and state are fetched only when an agent
actually intends to propose.

After preparing params, `gateway-admin.preview_change` is the read-only
proposal check. It validates the same current target and freshness witness as
proposal capture, including the action-specific serialized params cap. Policy
and manifest actions also return the existing human review preview as typed
`effect` structured content: Cedar compile status, attached tests when present,
and bounded authorization-impact replay. Manifest effects additionally expose
the configured tool/server capability delta, projected runtime and catalog
availability, preserved drift-quarantine barriers, and required follow-up.
Their replay report carries an applicability reason so a zero-row comparison is
not mistaken for evidence about newly added tools. Gateway-wide runtime and
catalog availability is withheld outside the default tenant and whenever the
observer fails the maker/admin, peer, profile, or Cedar discovery boundary. That
replay consumes the same operator-configured per-tenant `call` quota as ordinary
MCP calls. A stale context is returned as `valid: false` with recovery guidance
rather than queued; an unavailable replay or execution precondition is explicit
in `effect.note` or `effect.blocked`. Maker-facing availability notes are
canonicalized; detailed store, database, and filesystem diagnostics remain in
operator logs and dashboard surfaces. Preview never replaces the proposal or
execution freshness checks.

## Enforcement (tests, not vibes)

A tool is not done until:

- **the ubiquitous guard covers it.** `every_builtin_tool_is_self_documenting`
  (`crates/waygate-server/src/main_tests/builtin_selfdoc_enforcement.rs`)
  enumerates EVERY built-in tool across all
  namespaces and asserts each carries a title, an `output_schema` (itself a
  compilable JSON Schema), a compilable object-rooted `input_schema`, and a
  `read_only_hint`. A new namespace adds its canonical `surface_catalog()` to
  that one list; a new tool in an existing namespace is covered for free. This
  is the cross-cutting backstop the per-namespace tests below
  refine;
- it is covered by the `surface_descriptor_matches_served_tools` pattern (one per
  namespace, in `mcp_builtin.rs` / `mcp_observe.rs` / `mcp_control.rs`) so the
  served schema and the surface descriptor cannot drift;
- a per-namespace test asserts returned `structuredContent` validates against the
  advertised `output_schema` (`*_output_schemas_validate_sample_content`) — the
  presence guard above does not exercise sample content, so this pins
  serde↔schemars agreement on the wire shape (and read_only polarity per
  namespace);
- for `propose_change`: a test asserts *every* registered `action_type` yields a
  non-empty params schema and that a known-good example deserializes against it
  (the registry IS the propose allowlist — see
  `crates/waygate-admin/src/change_executor/mod.rs`);
- for state-dependent actions: black-box MCP tests start with `tools/list` /
  `describe_action`, invoke the advertised context read, and assert that exact
  live policy statements and complete selected manifests are available without
  repository or dashboard access.

PR checklist item (AERB-verifiable): "new/changed MCP tool meets
`docs/agents/mcp-tool-docs.md`."

## Banned anti-patterns

- A bare `{"type":"object"}` for a structured/keyed param.
- The phrase "validated at execute time, not here" as a substitute for a schema.
- Hand-written `json!` schemas on new tools.
- A property with no `description`.
- A read tool with no `output_schema`.

## Adding a new admin tool — checklist

1. `#[derive(JsonSchema)]` on the input (and output) struct.
2. If the input is keyed/polymorphic, wire it through the discovery affordance.
3. If safe construction depends on current state, add a typed, bounded read
   context and advertise its selector schema from the action entry.
4. Set `output_schema`, `annotations`, and `title`.
5. Enrich the error path to return the expected schema + example.
6. Add it to the namespace's `surface_descriptor_matches_served_tools` test.
7. Tick the AERB checklist item.
