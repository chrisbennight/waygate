# Upstream MCP servers

The manifest schema in
[`crates/waygate-manifest-types/src/lib.rs`](../../crates/waygate-manifest-types/src/lib.rs)
is the code of record. The gateway repo carries representative fixtures under
[`crates/waygate-upstream/tests/fixtures/servers/`](../../crates/waygate-upstream/tests/fixtures/servers/);
a deployment supplies the served set through its servers volume.

## Classification authority: claims are not policy

There are two explicit classification modes. They are compatibility modes, not
two sources that may be blended:

| `classification_mode` | Upstream MCP supplies | Gateway catalog owns |
|---|---|---|
| `manifest` (default) | Tool schema and description | `risk`, `side_effects`, `pii`, admission, roles, approvals |
| `mcp_annotations` | Standard MCP behavior hints, namespaced action metadata, and result trust labels | `risk`, admission, authorization, approval requirements, result release, audit policy |

The default preserves every existing server unchanged. Select
`mcp_annotations` only after the upstream publishes complete metadata and the
catalog has reviewed the resulting behavior hash:

```yaml
name: deployment-controller
classification_mode: mcp_annotations
tools:
  - name: workloads.apply
    risk: high
    approved_behavior_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

In annotation mode, every admitted tool must publish all four standard hints:
`readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`. It
must also publish a bounded object under
`io.modelcontextprotocol/action-metadata` containing input destination and
sensitivity, return source and sensitivity, outcome, and `requiresReview`.
Missing or malformed claims, a missing approved hash, or a live hash mismatch
quarantine the tool; the gateway never invents permissive defaults.
Classifier values remain bounded open strings, as the experimental draft
allows, and unknown action-metadata members are preserved in the behavior hash.
The gateway does not freeze the draft into a private enum or discard future
extension fields. A reviewed vocabulary evolution therefore requires an
ordinary hash approval, not a gateway code change. The display-only annotation
title is deliberately excluded, so presentation edits do not quarantine an
otherwise unchanged capability.

At invocation, annotation mode derives `side_effects` from `!readOnlyHint`.
Input and output sensitivity come from the corresponding action-metadata
classifiers. `none`, `public`, and `operational` are non-sensitive; any other
bounded classifier—including a future value the gateway does not yet
recognize—is treated as protected rather than rejected. This lets the
extension evolve without silently making a new data class public or forcing a
gateway release for every vocabulary addition. `risk` is never derived from
these claims; the reviewed catalog remains authoritative.

Approval authority is a separate, deployment-owned manifest choice:

- `approval_mode: per_call` is the default. The gateway honors
  annotation-native `requiresReview` and the governed catalog's
  `requires_approval` flag; either may require a live grant.
- `approval_mode: policy_only` explicitly suppresses those two ordinary
  sources for that upstream. Use it only when Cedar service policy governs the
  complete side-effecting surface. It does not grant access and it does not
  disable a Cedar approval overlay, which remains independently authoritative.

The mode is keyed only to reviewed manifest configuration. An upstream name
never selects approval behavior, and omitting the field preserves the ordinary
per-call requirement.

The pinned Rust MCP library cannot yet preserve extension keys inside its typed
`ToolAnnotations`. Until it can, the gateway accepts action metadata from
`Tool._meta["io.modelcontextprotocol/action-metadata"]`. The normalizer also
recognizes the extension's intended location inside `annotations`, so moving to
a future library representation does not change the policy contract. This is a
wire-format bridge only. It does not make `_meta` authoritative.

Annotations remain advisory claims. The MCP tools specification requires
clients to treat them as untrusted unless the server is trusted, and recommends
human confirmation and output validation. The action-metadata vocabulary is an
experimental draft, not a stable MCP recommendation. The gateway therefore
canonicalizes and hashes these claims, while the reviewed catalog and Cedar
remain the enforcement authority:

- [`Tool` annotations and security considerations](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [`io.modelcontextprotocol/action-metadata` experimental draft](https://github.com/modelcontextprotocol/experimental-ext-tool-annotations/blob/main/specification/draft/action-metadata.mdx)
- [`io.modelcontextprotocol/trust-annotations` experimental draft](https://github.com/modelcontextprotocol/experimental-ext-tool-annotations/blob/main/specification/draft/trust-annotations.mdx)

Sensitivity is not a capability prohibition. An MCP server may expose a
bounded, typed configuration, log, or secret operation when its upstream API
supports that operation. The server labels the behavior and returned data; the
gateway decides who may discover, approve, invoke, audit, or receive it.
Removing the typed operation merely pushes operators toward direct APIs,
shells, or credential-store access that bypass those controls. Bounds and
schemas constrain the requested operation; they must not redefine a useful
upstream capability into an unusable special case.

The behavior hash covers name, description, input schema, output schema,
standard annotations, and the complete namespaced tool metadata — the
action-metadata namespace plus any sibling namespaced claim, so an unknown
extension changing under `_meta` re-hashes rather than drifting silently. Annotation mode requires that exact
hash in `approved_behavior_hash`; importing the manifest records it as the
approved tool-version identity.

**Obtaining the hashes without direct reach to the upstream.** The gateway
already holds the connected sessions, so the manifest change preview reports
the observed hashes for you — no `classify` run against the upstream network
is needed for a mode flip. Runbook for migrating a connected server to
`classification_mode: mcp_annotations`:

1. Draft the annotation-mode manifest with placeholder (or stale) hashes
   and pass it to `gateway-admin.preview_change` (the dashboard queues
   neither compute nor render this section). For every
   annotation-mode server in the candidate, the effect's `observed` section
   lists each live tool's `observed_behavior_hash` and a `draft_status`:
   `match`, `mismatch`, `missing_from_draft` (live tool the draft omits),
   `ambiguous` (connected lanes disagree — no hash can admit it), or
   `invalid_metadata` (the upstream's annotations/action metadata do not
   normalize; fix the upstream, no hash will help). `would_quarantine`
   is the admission prediction: every non-`match` name.
2. Copy each `observed_behavior_hash` into the draft and re-preview until
   every tool reports `match` and `would_quarantine` is empty.
3. Propose. Keep the capture-to-approval window short: if the upstream
   redeploys in between, admission quarantines the changed tools on
   publish. Re-preview and propose the current hashes; if durable tool-change
   quarantine is enabled, also review the exact replacement through
   [tool change review](../guides/security.md#review-an-upstream-tool-change).

Do not combine the mode flip with a connection-shape change (transport,
protocol, url, command, auth, mTLS, session, or identity settings): publishing a new shape
re-dials, so contracts observed on the current sessions cannot predict the
redialed catalog — the preview refuses with an explanatory note. Publish the
shape change first, then re-preview the flip.

The section is computed read-only from the live sessions and is deliberately
the RAW live catalog — including tools discovery hides (unclassified,
quarantined, policy-restricted) — because a complete annotation manifest
must cover every live tool or admission quarantines the omissions. That
completeness is why the gates control who reads it, never what it contains:
default tenant only (the pool is gateway-wide; other tenants must not probe
liveness); the maker floor (`mcp:propose`, matching the namespace gate — the
propose-only automated maker is exactly who the section exists for — or
`mcp:admin`; never a peer-asserted principal); a server the observer's
API-key profile blocks is omitted; a profile confining the observer to a
subset of a server's live tools withholds that server's whole report with a
note; and Cedar discovery parity — an observer the live policy denies
`SearchTools` on the server, or leaves any live tool undiscoverable,
likewise gets a withheld note (evaluated with the same gate predicates
`tools/list` uses), so this surface can never enumerate what discovery
hides from the same credential. Complete or absent, never filtered. A
disconnected or not-yet-registered server reports `connected: false` with a
note instead of guessing. Any mismatch is hidden and refused until the
catalog entry is reviewed and updated. Admission rules on the callable NAME
across the complete session catalog: every descriptor advertising the name —
on every connected lane — must match the approved hash, because `tools/call`
identifies the operation by name alone and lane publication intersects lanes.
The governed catalog's row participates under the same identity: its
classification mode must match the live manifest's mode, and in annotation
mode its version identity must equal the manifest-approved hash AND its
imported risk must equal the manifest risk before its facts overlay the
live contract — the hash alone would wave through a risk-only manifest
change, and a mode split would overlay an annotation-imported row's
forced-false legacy flags onto a legacy tool. In manifest mode, a stored
catalog input schema remains the validation authority only while the current
upstream descriptor has the MCP-required object root; a malformed live root is
carried to Stage 2 and refused rather than hidden behind the stored schema.
When no catalog row governs (fallback), an annotation-mode snapshot still
binds the manifest-approved hash into its contract identity, so generations
that differ only in description or a sibling namespaced claim stay
distinguishable through
Code Mode and dispatch. An annotation-mode resolution with an EMPTY
published contract fails closed outright: an admitted descriptor always
publishes at least its input schema, so emptiness means the manifest and
the published inventory diverged (e.g. a failed index publication after a
classification reload) and nothing reviewed would be bound to the call.
The published descriptor's own behavior hash must also equal the resolving
generation's approved hash — the published view is read separately from the
manifest snapshot, and this binding refuses any reload interleaving instead
of returning a mixed-generation snapshot to validation, authorization, or
Code Mode discovery. A reload that updates the pool and the catalog non-atomically
therefore yields a fail-closed refusal until both authorities activate the
same generation — never an execution under another generation's facts. A failed doorbell/SIGHUP catalog reconcile
arms a retry on the next tick even without a manifest change, which is what
heals that refusal without operator action; every dashboard-reload reconcile
attempt arms the same latch, so an interleaving with a concurrent
doorbell/SIGHUP run converges the catalog to disk truth on the next tick.
The latch is generation-fenced: a tick observes the owed generation before
reading disk and settles only that observation on success, so a stale
reconcile racing a newer dashboard arm cannot silence the newer obligation.
The dashboard applies the pool BEFORE reconciling — the legacy baseline
order, since manifest-mode resolution overlays catalog risk unconditionally
and a catalog-first commit would govern a still-serving legacy contract with
premature facts. Drift telemetry and the configured quarantine threshold
also apply; a configured database persists tool-change review decisions.
Code Mode contracts carry separate hashes for annotations and action metadata,
so an invocation cannot silently cross a discovery-to-dispatch metadata change.
The binding runs end to end: the invocation pipeline hands its Stage-1
admitted contract identity to the pool, which re-resolves the tool under the
selected connection's read lock and refuses (retryably) when the identity no
longer matches — so a reload that swaps in a different *approved* contract
mid-call cannot execute claims the earlier stages never validated. In
annotation mode the pool additionally reads the executing session's own
`tools/list` immediately before every RPC — the fresh ephemeral session under
the default `per_call` isolation, and the pooled long-lived session under
`reuse` (including forced-reuse stdio, since the pool handles no
`notifications/tools/list_changed`) — and requires the called tool to match
`approved_behavior_hash` on the session that executes it. That costs one
extra upstream round-trip per call in either isolation mode; it is the price
of the exact-hash binding. Manifest mode retains its existing schema and
description hash coverage; durable review adds a refusal check when a database
is configured.
Annotation-mode authorization facts now DERIVE from the reviewed claims:
side-effect behavior from the standard hints, sensitivity from the
input/return classifications, and the approval requirement from
`requiresReview`. The drift-quarantine threshold still keys on the
conservative side-effecting posture, so annotation-native drift always sits
inside the `high` and `medium` bands.
For compatibility with existing Cedar schemas and audit columns, annotation
mode projects `input_sensitive || output_sensitive` into the `pii`
fact. That field means “protected input or output” for annotation-native tools;
it is not a separate upstream-authored PII category, and the cross-cutting PII
overlay (`15-pii-default.cedar`) still governs which auth methods may touch a
`pii`-tagged tool. A deployment that uses a Cedar service grant as the complete
direct-call write control can opt that upstream into
`approval_mode: policy_only`; the service grant should pair a narrow permit
with a confinement forbid so unrelated principals remain denied. The
synthetic `example-deployer` fixture demonstrates that permit-plus-forbid
pattern with its `deploy-operators` role. Every Code Mode source form, including reviewed skill scripts, uses the
same direct channel and approval decision as calls made directly by the
same principal. Code Mode adds no read-only or connector-call-count ceiling.

Every annotation-native result that is returned to the caller must carry
explicit boolean `sensitive` and `untrusted` values under
`io.modelcontextprotocol/trust-annotations`. Missing or malformed labels are
withheld. The requirement covers error results too: an `is_error` result
still hands its content to the caller, so exempting it would let an upstream
leak unanticipated sensitive content through an error. A result labelled
sensitive is released only when the
admitted action metadata anticipated protected OUTPUT (distinct from the
combined `pii` fact, which also covers protected input) and Cedar authorized
the call. On the MCP tool-call path the gateway preserves the complete trust
object on the returned result, including `untrusted` and future members.
Through the Code Mode connector adapter the same enforcement runs at the
call boundary, but the connector contract hands the sandboxed runtime the
structured value only (no MCP `_meta` channel); that runtime executes inside
the gateway trust boundary. Trust labelling governs handling; it does not
remove sensitive reads from discovery or make the result unusable after an
authorized call.


Do not compensate for absent upstream metadata with direct API calls, shell
access, or credential-store reads. Either keep that server in `manifest` mode
or fix the typed MCP server. Inherited secrets that an upstream API cannot
return remain unavailable; classification metadata does not manufacture access
to them.

### Per-operation refinement and its Code Mode consequence

A tool that dispatches on one of its own arguments can name that argument as a
`discriminator` and classify individual values, refining `risk`,
`side_effects`, and `pii` per operation. A tool-level entry must be at least as
severe as every operation it names; the loader and the importer both enforce
that ceiling, and an entry that exceeds it is dropped rather than applied.

On an ordinary tool call, a value no entry names leaves the tool-level
classification in force. That fallback is conservative for risk, precisely
because of the ceiling.

Code Mode uses that same tool-level fallback for unnamed values. Per-operation
classification refines governance for known values; it is not an additional
Code Mode reachability requirement.

## Scope

This document covers:

- The `UpstreamManifest` schema: `name`, `transport` (HTTP / SSE / stdio),
  `protocol` (MCP client lifecycle: `auto` | `legacy` | `2026-07-28`),
  `url` / `command`, `auth` (bearer-env), `exchange` (RFC 8693 token
  exchange config), `tools` (per-tool classification), `resources`
  (URI-prefix ownership and risk classification), `session`
  (per-upstream connection-pool tuning). `protocol` defaults to `auto`:
  probe with `server/discover`, and fall back to the legacy `initialize`
  handshake if that probe fails at all. `protocol: legacy` skips the probe
  and is the operator escape hatch for an upstream known to be older, or
  one that answers the probe in a way that misleads the bridge.
  `2026-07-28` requires discovery and never falls back — an operator who
  pins it wants a migration failure to surface, not to be downgraded past.
  SSE transport is legacy by definition: `auto` resolves to the legacy
  handshake there and an explicit `2026-07-28` is refused at manifest
  load. Every dial runs the configured mode fresh (no lifecycle caching);
  the negotiated generation is per-lane state, visible per server in the
  admin Servers view, `GET /api/v1/servers` (`protocol_versions`), and the
  `gateway_upstream_protocol_generation` gauge.

  **Why `auto` bridges on any discovery failure, not just
  `METHOD_NOT_FOUND`.** The SDK downgrades only when the peer answers the
  probe with `METHOD_NOT_FOUND`, and renegotiates only on a structured
  `UNSUPPORTED_PROTOCOL_VERSION`. Both are behaviors of a server that
  already speaks the stateless generation. A server predating it cannot
  produce either: the probe carries an `MCP-Protocol-Version` header for a
  version it does not know, so it is refused at the transport or session
  layer — as an unsupported version, an unexpected non-`initialize`
  message, or a missing session — before any dispatch could report the
  method unknown. Relying on the SDK condition alone therefore makes
  `auto` mean "new generation only", and every older upstream fails to
  connect. The bridge is deliberately not conditioned on the shape of the
  failure: a legacy refusal and an unreachable upstream are both transport
  errors distinguishable only by SDK message text, and matching on that
  text would stop bridging the day the wording changed.

  The cost is one refused probe per dial against an upstream that cannot
  discover. Because HTTP isolation defaults to `per_call`, that is one
  extra probe **per tool call**, not merely per connect. It is bounded and
  local, but it is the reason a per-upstream generation memo — boot and
  re-probe lanes discovering fresh, per-call lanes reusing the generation
  the upstream last negotiated — is the natural next step; it would keep
  migration observable while taking the probe off the hot path. A `protocol` change is a
  connection-shape change: reloads re-dial it. The `session` block carries
  `concurrency` (overrides the global `GATEWAY_UPSTREAM_POOL_SIZE`) and
  `isolation` (`per_call` | `reuse`). Isolation defaults to the **safe**
  posture: `per_call` for HTTP/SSE (a fresh upstream session per call, so
  no cross-call or cross-principal state can leak through a reused session
  — a property MCP does not guarantee), and `reuse` for stdio (a child
  process is a single long-lived session). Set `isolation: reuse` on an
  HTTP/SSE upstream you trust to drain per-session state between calls, to
  save the per-call `initialize` round-trip. stdio always reuses,
  regardless of the field. The block also carries `scope`
  (`per_principal` | `shared`, default `per_principal`): because the slot
  pool is shared across callers and the gateway may forward per-caller
  identity to a network upstream (Tier-B `X-MCP-Identity` for any
  issuer-wired HTTP/SSE upstream, plus a downscoped bearer under `exchange`
  / `tier_c_peer`), `isolation: reuse` on **any** HTTP/SSE upstream would
  reuse one session across callers. That combination is **refused at
  manifest-load time** unless the operator consciously sets `scope: shared`
  — otherwise use the per-caller-safe `per_call` default. Whether identity
  is actually wired is a runtime property the manifest can't see, so the
  guard is conservative (covers Tier-B, not just `exchange` /
  `tier_c_peer` / `tier_a_required`). It is a validation gate, not a
  dispatch knob: the gateway does not implement per-principal session
  *pooling* because `per_call` already provides per-caller isolation with
  no benchmark-backed reason to widen the trust boundary for low-QPS
  identity-forwarding upstreams. stdio is exempt (a single child-process
  session, not a shared HTTP pool).

  A governed `per_call` HTTP invocation may make one immediate recovery
  attempt when dial, initialization, the executing session's annotation
  contract read, or request handoff fails while tool dispatch is still proven
  absent and the exact admitted contract proves the tool is read-only, has
  known approval requirements, and requires no approval. Both attempts share
  one original deadline and one breaker permit; deadline-bounded session
  cleanup cannot extend that budget. MRTR continuations, side-effecting or
  approval-unknown tools, reused sessions, and every failure after the tool
  request enters the transport worker are never replayed. Operational failures
  return the closed `phase` vocabulary plus `retryable`, `attempts`, and
  `trace_id`; full transport detail stays in protected logs. An upstream MCP
  application error remains the upstream's typed error response. Set
  `session.retry_on_setup_failure: false` to suppress this automatic recovery
  for one upstream; omission/`true` keeps the one-retry default. The setting is
  request-path policy and hot-applies on reload without replacing healthy
  sessions. A dynamic Cedar approval requirement is treated the same as a
  catalog/annotation approval requirement: once a grant is consumed, setup is
  single-attempt.
- `ToolClassification` semantics and the `classification_mode` authority split
  above. Operator review is required before an unclassified tool becomes
  callable.
- MCP resource forwarding: a manifest may declare `resources` entries with a
  literal absolute `uri_prefix` and `risk` tier. Claims provide routing and
  authorization facts together: `resources/read` routes directly to the
  unique declared owner and Cedar receives the declared risk. Prefixes may
  not overlap anywhere in the loaded manifest set, and `mcp-file:` is reserved
  for the independent file-transfer plane. Put the resource kind before an
  opaque handle (for example `browser://screenshot/{handle}/{name}`) so a
  stable prefix can classify it. Existing resource-serving upstreams that
  declare no claims remain compatible: when no claim matches, the gateway
  falls back to bounded catalog enumeration and assigns the legacy low risk.
  `resources/list` preserves upstream order and collapses metadata-free empty
  upstream pages inside the current gateway request, so upstreams with no
  resources do not consume client pagination slots. Resource-bearing pages and
  empty pages with meaningful `_meta` remain individually observable. Its
  opaque cursor carries one 50-upstream-page budget across the full downstream
  pagination sequence, while each request retains a 30-second deadline.
  `resources/templates/list` aggregates complete template catalogs from
  visible upstreams under the same fleet-wide limit; the gateway therefore
  returns no downstream cursor. Undeclared `resources/read` owner resolution
  has its own 50-page / 30-second request-wide budget across the fleet. Reads
  reject a URI advertised by multiple legacy upstreams instead of guessing an
  owner. A declared prefix remains reserved even when its owner is hidden from
  the caller, so that URI space never falls through to a visible legacy server.
  Resolution carries a fleet-wide routing generation into dispatch; a reload
  that changes claims or legacy membership invalidates the admission and the
  read returns `data.error = "resource_routing_changed"` so the caller retries
  from resolution instead of reaching an upstream under stale ownership or
  risk. Original resource URIs are not rewritten. Caller profile restrictions and the server-level
  Cedar discovery decision apply before dedicated `ListResources` or
  `ReadResource` authorization. A profile with a populated `allowed_tools`
  list is tool-confined and exposes no native resources; a resource-capable
  profile uses `allowed_servers` without `allowed_tools`. Cedar evaluates
  reads against a `Resource` entity whose `resource.uri` is the exact upstream
  URI and whose `resource.risk` comes from the matching declaration. For a
  downstream request that advertises HTTPS file downloads, the gateway also
  forwards that capability to the selected upstream and governs any returned
  file-backed resource through the normal file lifecycle. Without that
  request-local signal the upstream must keep returning ordinary inline
  resource contents. Every native read carries the configured raw response
  ceiling (`GATEWAY_RESOURCE_RESPONSE_MAX_BYTES`, 4 MiB by default) into the
  streamable-HTTP client, which refuses an oversized response before rmcp can
  deserialize it. The public error is `resource_response_too_large` and carries
  `limit_bytes`; streamable HTTP enforces the ceiling for both JSON and
  SSE-framed replies. Legacy SSE and stdio transports return
  `bounded_resource_read_unsupported` because they cannot provide that
  pre-buffer guarantee. A governed file read
  can still transfer up to the independent file-service ceiling (1 GiB by
  default): only its bounded descriptor crosses the MCP response path. Textual
  resource contents run through the configured response-inspector chain before
  file staging; blob contents deliberately remain outside text inspection.
  Legacy collision enumeration includes only live lanes whose initialization
  advertised the MCP Resources capability. A tool-only upstream remains
  transport-eligible for its tools without being treated as a resource owner.
  The pool retains its normal circuit breaker, lane limit, timeout,
  tombstone, and session-isolation behavior. A Code Mode tool result that names
  a session-retained resource is the exception to independent resource
  checkout: after URI authorization, its bounded `resources/read` runs on the
  exact checked-out MCP session before that session is released. A fresh
  `per_call` session cannot recover another session's retained state.
- Resource identity delegation is deliberately fail-closed where the current
  resource bridge cannot honor the configured authority. Tier-B identity
  forwarding is supported for issuer-wired HTTP/SSE upstreams. An upstream
  configured with `tier_a_required`, `exchange`, or `tier_c_peer` is omitted
  from the aggregate resource catalog; the pool also refuses direct resource
  operations rather than silently sending them with weaker credentials. Other
  resource-capable upstreams remain available.
- The `classify` CLI for scaffolding starter legacy manifests against a live
  upstream. It omits `classification_mode` (which means `manifest`) and emits
  conservative low/no-side-effects/no-PII placeholders so an operator must
  review the result. Switching to annotation mode is a separate reviewed
  change.
- Transport configuration: HTTP/SSE upstreams behind Docker networks,
  stdio for local development only.
- Reload semantics: SIGHUP (or the Postgres doorbell / dashboard **Reload
  manifests**) triggers a manifest re-read with atomic swap; **adding or
  removing a server applies live** — a newly-listed server is dialed and
  published into the registry + search index, a delisted one is drained and
  dropped — with no restart.
- Reconnect / circuit-breaker behaviour: how failed upstreams come back and
  how `/api/v1/servers/{name}/reconnect` targets recovery. A healthy session is
  intentionally a no-op on that route. Use
  `POST /api/v1/servers/{name}/catalog/refresh` or the admin-scoped
  `gateway-control.refresh_server_catalog` MCP tool to replace a healthy or
  unhealthy session, run a fresh MCP initialization, traverse up to 50
  paginated `tools/list` pages, and atomically republish the classified
  inventory. A longer or non-terminating cursor stream fails the replacement.
  If every replacement dial or the search-index publication fails, the prior
  session and inventory keep serving. The Servers dashboard exposes the same
  admin-only action in each server's Overview panel and renders the structured
  added / removed / behavior-contract-changed result. Its table, the dashboard
  Overview, and the REST server list share the pool's runtime snapshot: breaker state,
  connected/configured lanes, published inventory, and drift-quarantine count.
  That snapshot derives one operator-facing runtime state for every surface:
  `connected` only when every configured lane is present and the breaker is
  closed, `degraded` when some capacity remains but lanes are missing or the
  breaker is half-open, and `disconnected` when no lane is present or the
  breaker is open. This is
  deliberately separate from the durable catalog lifecycle (`live`,
  `quarantined`, and so on). The `gateway-observe` `server` resource publishes
  `catalog_status` and joins runtime fields only onto catalog rows
  already visible to that tenant. The joined projection carries the tri-state
  as `runtime_status`, plus `last_success_at`, bounded `last_error_class`, and
  `next_retry_at` from the same pool snapshot. Raw transport errors remain in
  protected logs/audit and never enter these operator-facing fields.
  Prometheus exposes the same tri-state as the one-hot
  `gateway_upstream_runtime_state{server,state}` gauge. A catalog row
  with no loaded runtime entry reports null runtime fields rather than
  pretending to be healthy or leaking another tenant's runtime-only name.
  Agents holding
  `mcp:propose` can instead queue `upstream.reconnect`,
  `upstream.refresh_catalog`, or `upstream.quarantine.clear` through
  `gateway-admin.propose_change`; an admin approval executes the same shared
  operation on the approving replica. Use the governed `config.reload` action
  when every replica must reconcile policy and/or manifests: it rings the
  fleet-wide Postgres doorbell rather than touching only one in-memory pool.
  These pool controls also leave durable per-tool contract quarantines intact.
  Use [tool change review](../guides/security.md#review-an-upstream-tool-change)
  to inspect and accept an exact replacement. They do not change a durable `mcp_servers.status =
  'quarantined'` row. Restore that layer with the distinct governed action
  `catalog.server.unquarantine`; its proposal captures the exact catalog row
  version and approval atomically transitions only `quarantined -> live`.
  The Catalog dashboard exposes that proposal flow on quarantined rows, while
  its in-page Approve button remains limited to initial proposed/approved rows.

## Reserved upstream names

An upstream `name` cannot contain `.`. Downstream MCP calls use the public
`<server>.<tool>` form and route by the first dot; tool names may contain dots,
so reserving dots out of the server component is what makes every advertised
identity round-trip to exactly one upstream tool.

`validate_manifest_invariants` refuses an upstream whose `name` collides with
a namespace the gateway routes itself, so it can never be silently shadowed at
dispatch:

- The built-in MCP namespaces `gateway-admin`, `gateway-observe`,
  `gateway-control`, `gateway-files`, and `codemode` (exact name OR a
  `<ns>.`-prefixed name — the built-in dispatcher intercepts any `<ns>.*`
  tool call). Optional surfaces remain reserved while disabled so enabling
  them cannot silently shadow an existing upstream. Source of truth:
  `waygate_core::RESERVED_BUILTIN_NAMESPACES`.
- The inference plane's `llm` namespace (`waygate_core::LLM_RESERVED_NAMESPACE`),
  **exact match only** — the LLM model resolver intercepts the exact `llm`
  server, not `llm.*`. Owned unconditionally whenever the binary runs (the
  manifest guard can't see whether the LLM path is configured), so a manifest
  with `name: llm` is refused at load even on an MCP-only deployment. This is a
  reserved name: choose another name for an MCP upstream.

## Network transport deadlines

HTTP and legacy-SSE receive streams use the shared gateway HTTP factory through
`waygate_upstream::http_policy`. Their client intentionally has no total request
timeout because a healthy MCP response stream may remain open indefinitely, but
that lifetime does not leak into setup or writes:

- TCP/TLS connection establishment is capped at 10 seconds;
- the initial request plus first protocol event/initialize response is capped at
  15 seconds (the pool's boot/redial deadline remains the outer authority); and
- each legacy-SSE JSON-RPC POST is capped at 5 seconds.

The runtime dialer and `classify` CLI use the same helper. The legacy-SSE reader
and writer share cancellation: a failed write, a closed stream, or dropping the
transport closes the peer task and response body rather than leaving a detached
receive request in the connection pool. Do not add a generic read timeout to the
receive client; quiet streams are valid unless an upstream protocol declares a
heartbeat contract.

## In the meantime

- **Manifest schema:**
  [`crates/waygate-manifest-types/src/lib.rs`](../../crates/waygate-manifest-types/src/lib.rs)
  — `UpstreamManifest`, `Transport`, `ToolClassification`, `RiskTier`
  (re-exported by `waygate-upstream` at the old paths).
- **Pool:**
  [`crates/waygate-upstream/src/pool/`](../../crates/waygate-upstream/src/pool/)
  — connection lifecycle + dispatch (`mod.rs`), reload/reconnect/drift
  (`reload.rs`), health/quarantine reads (`health.rs`), Tier-A/C identity
  (`session_identity.rs`).
- **Classify CLI:**
  [`crates/waygate-upstream/src/bin/classify.rs`](../../crates/waygate-upstream/src/bin/classify.rs).
- **Manifest fixtures:** [`crates/waygate-upstream/tests/fixtures/servers/`](../../crates/waygate-upstream/tests/fixtures/servers/)
  — representative example manifests (one YAML per upstream). The gateway repo no
  longer ships a real served set; a deployment's authoritative set lives on the
  shared runtime volume and is managed through the dashboard/governed publish
  paths.
- **Identity injection for discovery and per-call dispatch:**
  [`crates/waygate-upstream/src/identity_client.rs`](../../crates/waygate-upstream/src/identity_client.rs).

## Version ledger: the Postgres manifest store

`servers/*.yaml` on disk is the **source of truth** for the upstream set
(see
[`docs/server-config-source-of-truth.md`](../server-config-source-of-truth.md)).
The Postgres `server_manifests` store is a **version ledger**: history,
rollback, and last-resort recovery — NOT the boot source. Each ledger row's
`content` is the entire manifest set serialized as ONE YAML sequence (not one
row per server), so a version and its rollback are atomic. Same
draft → published → rolled_back model as Cedar `policy_bundles`, but inverted
in authority: the file wins, the store records.

- **Boot / SIGHUP / Reload load the file**: boot, the
  SIGHUP reload, and the dashboard **Reload manifests** button all read
  `servers/*.yaml` directly. The ledger is consulted ONLY to *recover* when
  the on-disk set is unreadable (a malformed file, a missing/unmounted dir):
  the newest published version is loaded, logged loud, and the config-health
  signal goes **degraded** (a stale-config banner) so a broken file never
  silently serves a wrong or empty set. A cleanly-loaded empty dir is
  authoritative ("no upstreams"), not a recovery trigger. A
  *configured-but-unreachable* DB aborts boot earlier (shared audit-sink
  connect). The prod manifest-safety gate (`transport: stdio` refusal under
  `GATEWAY_DEPLOYMENT_PROFILE=prod`) is applied at activation time on boot,
  SIGHUP, AND the dashboard reload; a refused reload keeps the previous set
  and marks config-health degraded. Reload also compares a candidate disk hash
  with the recently-advanced turnstile pointer: a mismatch means the reader may
  have caught a coordinated multi-file commit in progress. A running replica
  keeps the previous in-memory set and retries on the next doorbell or poll; a
  booting replica refuses that transient snapshot and lets its supervisor retry.
  The writer also syncs `.manifest-write-in-progress` before moving any live
  YAML. If the process or node dies mid-commit, that marker persists, so boot,
  reload, and proposal-context reads reject the incomplete directory; the
  runtime recovers its last complete ledger snapshot and shows degraded health.
  The marker is removed only after the replacement or rollback is verified. A
  complete rewrite that repairs a marked directory also removes the abandoned
  internal archive from the interrupted commit.
- **Publish / Rollback mirror to disk**: the admin REST and dashboard
  publish/rollback paths claim the cross-replica turnstile, mirror the content
  onto `servers/*.yaml` (the source of truth), and THEN record the ledger
  version — disk write before the ledger transition, so the
  change takes effect on the next reload and survives a restart. If the on-disk
  mirror write fails the operation reports loud and **nothing is recorded** —
  the ledger is unchanged (the turnstile is rolled back); a partial write, if
  any, is reconciled on the next reload. A `transport: stdio` set under `prod`
  is refused at this pre-ledger mirror step, so the publish fails outright
  rather than being recorded. Replicas never activate the mirror's transient
  multi-file view: the pointer is advanced before the mirror, reload retains
  the prior set, and an interrupted mirror's synced marker routes readers to the
  last complete ledger snapshot even after the pointer grace window expires.
- **Seed CLI**: `gateway-server --import-server-bundle [<dir>]`
  loads `servers/*.yaml` strictly, applies the prod-safety gate,
  round-trip self-checks the serialization, refuses an empty set, then
  records it as the first ledger version. Distinct from `--import-manifests`
  (which seeds the catalog). Non-idempotent: re-running records
  a new version from the current YAML.
- **Admin REST**: `/api/v1/server_manifests` — `GET` (list),
  `GET /active`, `POST /validate` (parse-only, no persist),
  `POST` (stage a draft), `POST /{id}/publish`, `POST /{version}/rollback`.
  All `mcp:admin`-gated; `503` without a DB. `validate` and the
  create-draft pre-store guard both run `parse_manifest_set` (per-entry
  invariant checks + duplicate-name rejection).
- **Dashboard editor**: `/admin/server_manifests` — a YAML
  textarea (Validate / Save draft), a versions table with per-row Publish
  / Rollback / Load, and **Export active (YAML)** which downloads the
  active version as `servers.yaml`. Mutations delegate to the same store the
  REST surface uses, so audit + validation are identical across both.
- **HITL propose path**: `manifest.stage_and_publish` — a
  `gateway-admin.propose_change` action (`change_executor/`) that takes a full
  manifest-set YAML, validates it, stages a draft, and publishes it on human
  approval: first read the live set and `base_hash` with
  `gateway-admin.get_action_context`, then propose the set with that hash. The
  proposal and approval paths recheck the hash, and the publish core performs a
  conditional filesystem commit before recording the ledger version. A raw NFS
  edit that lands after the database turnstile is therefore preserved and the
  proposal fails for re-preparation instead of overwriting it. This path is
  default-tenant-only while `servers/*.yaml` remains gateway-wide. **Size**: the
  set rides in the change-request `params`, which for this action use the
  document cap (`DOCUMENT_MAX_PROPOSE_PARAMS_BYTES`) rather than the scalar
  default — a real full set outgrows the default well before a deployment is
  large. The set may also be *uploaded* instead of inlined: put the
  `mcp-file://gateway/<id>` returned by `gateway-files.prepare_upload` in
  `content_file` and the gateway substitutes the file's text into `content`
  before the proposal is validated, stored, or reviewed (see
  `docs/agents/hitl-control-plane.md` § "Uploading a document instead of
  inlining it"). The upload keeps the YAML out of MCP JSON-RPC and model
  context; it does not change what the approver reviews or what executes. The
  path that keeps the *proposal* small for large deployments and single-server
  edits is still
  **`manifest.upsert_servers`**, which carries only the *changed* servers (a
  partial set) and merges them into the inspected live set server-side before
  conditionally publishing the reconstructed full set. It can add or replace a
  server by `name`. Use **`manifest.remove_servers`** to remove selected live
  names without reconstructing the complete set client-side; the gateway
  preserves every unselected manifest and conditionally publishes the result
  against the inspected `base_hash`.

A version's `content` references `auth.bearer_env` *names*, never token
values, so it is safe to display and export. At dial time the gateway first
uses that environment variable's non-empty value; otherwise it reads a token
of at most 16 KiB from the path in the conventional `<NAME>_FILE` companion.
The file path is runtime configuration and never enters the manifest ledger;
missing, empty, unreadable, oversized, or non-UTF-8 files fail the dial closed.
Credential paths must resolve to regular files; devices and FIFOs are refused.
The same `auth:` block may include `catalog_probe_groups` for an HTTP/SSE
upstream that role-filters `tools/list`:

```yaml
auth:
  bearer_env: MCP_GATEWAY_UPSTREAM_BEARER_KOMODO
  catalog_probe_groups:
    - service-operators
```

These groups belong only to the gateway-minted catalog-probe identity used for
`initialize` and `tools/list`; the identity is cleared before caller dispatch.
The default is an empty list. Manifests are rejected if the list has more than
32 entries, contains duplicates, or contains an empty, padded, control-bearing,
or longer-than-128-byte group. Stdio rejects the setting because it cannot
forward identity headers. A gateway without an identity signer also rejects the
dial before contacting the upstream, rather than silently ignoring the groups.
Catalog groups also require the default `session.isolation: per_call`; manifests
that select `reuse` are rejected even with `scope: shared`. An upstream may bind
authorization established during `initialize` to the MCP session, so a caller
must never reuse the privileged discovery session.
Changing the list re-dials the upstream and rebuilds its catalog; a failed
re-dial retains the previously active groups and catalog.
`pool.reload_manifests`
hot-applies tool classifications, `exchange`, and tier on SIGHUP / Reload.
**Adding or removing an upstream is also hot:** the registry map is an
`ArcSwap`, and the structural commit is generation-fenced (the newest reload
wins; a stale reload delayed in a slow dial is superseded and applies nothing).
A reload builds and dials a newly-listed server, splices it into a fresh map
under the reload lock, stores that map, and *then* publishes its tools into the
BM25 index — store-before-index, so a superseded add never pollutes the index
and a map-present entry is dispatchable by name with search catching up a moment
later (reported `added`). A delisted server is tombstoned, drained (each slot's
conn write lock), dropped from the registry map, and pulled from the search
index (reported `removed`); an in-flight caller holds its own `Arc` to the entry
and finishes its current calls, while a dispatch that raced the removal and
observes the tombstone (`entry.removed`) is refused, and new lookups miss
immediately. The dispatch hot path reads the map lock-free and clones out the
entry it needs, so a structural swap never yanks an entry from under a live
call.
Connection-shape changes (`url` / `command` / `auth` / `mtls` / `protocol` /
the `session` block) are **re-dialed live** when the slot count is
unchanged: the
old session is torn down and the new shape dialed in place — a fresh identity
cell, a re-resolved bearer, freshly read mTLS material — no restart (reported
`redialed`). The swap commits under every slot's conn write lock, so a
concurrent `call_tool` never runs on the old bearer/cert after the manifest has
advanced, and each lane's dial is bounded by a per-lane timeout
(default 15s) so an unresponsive new target surfaces as `redial_failed` instead
of wedging the awaited reload. The old session keeps serving until a new-shape
session is in hand; if *every* new-shape dial fails the old shape is kept and
the change is reported `redial_failed` (restart-required) rather than blacking
out the upstream. The two shape edits that **resize the slot pool — a
`stdio`↔network transport flip or a `session.concurrency` change — can't re-dial
the existing slots in place (the slot `Vec` is sized once per entry), so they are
**rebuilt live** instead: a fresh entry with the new slot count is dialed
lock-free, then swapped into the registry under the same structural fence as a
hot add (built entries win the reconcile), and the old entry drains via its
`Arc` — in-flight calls on the old shape complete; new calls land on the rebuilt
entry. A successful rebuild is reported `redialed` (no restart) and advances the
stored manifest to the new shape; if *every* new-shape dial fails the fresh entry
is discarded, the old entry is kept whole, and it is reported `redial_failed`
(restart-required) — the same fail-keep-old semantics as the in-place re-dial.
`requires_restart()` keys off `redial_failed`. Note re-dial / rebuild
keys off the *manifest* `mtls` value for a healthy session. Swapping a cert/key
file **in place at the same path** does not proactively replace a connected
client. For a disconnected entry, however, SIGHUP fingerprints the bounded
dial-time credential inputs: changed material starts one fresh retry episode
and is attempted immediately, while an unchanged reload preserves backoff.
Every cert, key, and CA path must resolve to a regular file of at most 1 MiB.

Code: [`crates/waygate-manifest-store/`](../../crates/waygate-manifest-store/)
(store / ledger), `serialize_manifest_set` / `parse_manifest_set` in
[`waygate-manifest-types/src/lib.rs`](../../crates/waygate-manifest-types/src/lib.rs)
(re-exported by `waygate-upstream`),
`resolve_manifests` in
[`waygate-server/src/reload.rs`](../../crates/waygate-server/src/reload.rs),
[`waygate-admin/src/manifest_bundles.rs`](../../crates/waygate-admin/src/manifest_bundles.rs)
(REST), and
[`waygate-admin/src/dashboard_server_manifests.rs`](../../crates/waygate-admin/src/dashboard_server_manifests.rs)
(UI). Migration: `migrations/0037_server_manifests.sql`.

## See also

- [`docs/agents/identity.md`](identity.md) — Tier-A (RFC 8693 token
  exchange) vs Tier-B (gateway-minted identity JWT) and how each is
  selected per upstream.
- [`docs/agents/authz.md`](authz.md) — how `ToolClassification` reaches
  Cedar at call time.
