# Governed tool discovery

The gateway provides a source-agnostic discovery surface for clients that do
not already know which upstream server or gateway-local namespace owns a
capability:

1. Call `gateway-discovery.search` with keywords or a natural-language query.
   The response contains compact identity, source, description, and governance
   facts, but no schemas. Titles and descriptions are preview text with a
   bounded character budget; inspection remains the exact documentation
   authority.
2. Pass the returned `source_kind`, `source`, and bare `tool` (as `name`) to
   `gateway-discovery.inspect`. The response contains the exact current MCP
   definition, including input and output schemas and annotations.
   When an operator enables [client schema compatibility](client-schema-compatibility.md),
   this remains the authoritative schema; the selected client's `tools/list`
   declaration can have fewer constraints while retaining the argument shape.
3. Invoke the returned fully-qualified identity through ordinary MCP
   `tools/call`. Discovery has no generic execute operation and cannot bypass
   the original tool's typed routing, authorization, quota, inspection, or
   audit path.

Both operations require `mcp:read` or `mcp:admin`. The gateway applies the
caller's credential profile, server-discovery decision, current catalog
admission state, and per-tool Cedar decision before ranking. A denied,
quarantined, retired, or profile-restricted record is therefore absent before
document frequencies, result counts, and cursors are computed. Unknown and
invisible selectors have one `tool_unavailable` response shape.
Discoverable approval and step-up verdicts are represented explicitly in the
governance projection. `requires_approval_known: false` means clients must not
infer that approval is unnecessary, and `required_step_up_scope` names the
current re-authentication requirement when one applies. Invocation always
re-evaluates these decisions at the authoritative call boundary.

The catalog contains both ordinary upstream tools and gateway-local built-ins.
Structured source identity is authoritative; clients do not parse a dotted
fully-qualified display name to distinguish a server from a tool name.
Gateway-local handlers publish weak references into the per-request catalog
registry, so discovery can include its own surface and other built-ins without
creating an ownership cycle.

Search uses a deterministic BM25-style lexical baseline over only the visible
records. Exact fully-qualified queries resolve exactly; other queries search
source names, tool names, titles, and bounded title/description prefixes.
Continuation cursors are authenticated, expire after a bounded interval, and
bind the server-selected position to the caller's safe authorization claims,
normalized query, and exact ranked governed view. They carry no authority:
every page rebuilds and reauthorizes the view before accepting the cursor. A
definition, governance verdict, policy-visible set, ranking, or source change
therefore rejects the cursor with MCP invalid-params (`-32602`); the client
discards collected pages and restarts from the first page. The deployment
continuation key keeps cursors usable across replicas. Without it, process-local
protection intentionally limits cursors to one process lifetime.

Code Mode consumes the same direct authorized catalog and ranker, then applies
its runtime schema constraints and excludes recursive Code Mode operations to
produce connector contracts. Its search continuation is protected by
the same deployment key and binds the caller, query, position, expiry, and
exact ranked authorized view. A catalog, definition, or policy-visibility
change therefore rejects a continuation rather than combining pages from
different generations.

## Catalog lifecycle

The governed catalog is a published snapshot, not a set of independently
mutable index rows:

- A new or refreshed upstream becomes discoverable only after its complete
  admitted tool set and lexical index are ready. Failed first contact publishes
  nothing. Failed later refreshes keep the last-known-good snapshot and report
  degraded or stale source health rather than erasing working tools.
- A successful upstream `notifications/tools/list_changed` event and the
  freshness fallback use the same refresh-and-publication path. Tool additions,
  removals, definition or governance changes publish one new snapshot. A
  reorder-only response remains quiet.
- Multi-lane upstreams publish only the conservative common definition. A
  disagreement never exposes a tool available on only some lanes. Manifest
  governance can retain a shared tool while omitting a disputed optional output
  schema; annotation governance withholds it because the complete reviewed
  definition is the admission authority. Removing an upstream tombstones it,
  wakes subscribed clients, and fences late refreshes so an obsolete task cannot
  resurrect the source.
- Structural additions, rebuilds, and removals prepare their async state while
  the old view remains valid, then rebuild the complete BM25 snapshot in one
  [Tantivy commit](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md)
  before swapping the authoritative map under the catalog epoch. If commit or
  reader reload fails, the old map remains authoritative and BM25 returns no
  opinion so search uses the catalog fallback rather than a split index. The
  index retains its last successfully published slices as a recovery image, not
  a catalog authority. While unhealthy, the next ordinary source refresh rolls
  back uncommitted writer work and upgrades itself to a complete delete-all,
  repopulate, commit, and reader-reload transaction; only that successful full
  handoff restores BM25. This follows Tantivy's documented [rollback and
  delete-all rebuild model](https://docs.rs/tantivy/latest/tantivy/indexer/struct.IndexWriter.html).
- Gateway-local tools enter the same canonical catalog through the built-in
  registry. Their definitions are deployment-owned; policy reloads can change
  their visibility without a restart just as they can for upstream tools.
- Manifest-only governance edits publish the temporary reconcile fence and
  publish again when the durable catalog settles, even when the upstream MCP
  descriptor itself is byte-identical. Successful durable server approval,
  quarantine, and unquarantine transitions advance a database-owned discovery
  generation and ring a transactional PostgreSQL doorbell. The same trigger
  contract covers server and tool additions/removals, approved definitions,
  classifications, and per-operation safety facts. Database triggers own that
  invariant, so later writers cannot commit a discovery-affecting catalog
  change while accidentally omitting fleet invalidation.
- Production attaches the governed catalog only after boot atomically
  reconciles the accepted manifest set. From that point a catalog miss or read
  failure is authoritative unavailability: discovery and invocation refuse the
  tool instead of reviving a removed record through a lagging replica's
  manifest fallback. Catalog-less and explicitly transitional compositions
  retain their separate manifest behavior.
- Each successfully swapped default or tenant Cedar policy advances the shared
  catalog epoch at its serving-state boundary, before best-effort audit or
  scope reconciliation. Byte-identical or rejected policy reloads stay quiet
  and continue serving the last-known-good policy.

Every replica establishes `LISTEN` before reading the durable generation, then
rechecks that generation after notifications, reconnects, and periodic polling.
That order follows PostgreSQL's documented
[listener setup rule](https://www.postgresql.org/docs/current/sql-listen.html),
while the trigger relies on its guarantee that a transactional
[notification is delivered only after commit](https://www.postgresql.org/docs/current/sql-notify.html).
The table is authority and the notification is only a prompt, so a dropped or
coalesced notification delays a client wake-up but cannot make discovery accept
a mixed catalog view.

The shared epoch drives downstream `notifications/tools/list_changed` signals.
As MCP specifies, that notification means clients should refetch; it is not a
delta. Publishers also mark the synchronous state-swap interval as active.
Gateway discovery accepts a catalog read only when the epoch is stable before
and after authorization. For database-governed server changes it additionally
requires the durable generation to match before and after the complete view,
closing the interval between a remote commit and local notification handling.
Standard `tools/list` uses the same fence. Both surfaces also sample a local
catalog-read-error generation: an authoritative per-tool store failure
invalidates the whole projection instead of silently turning one failed lookup
into an omitted tool and a valid cursor.
An overlapping publication causes a bounded retry and sustained churn returns
a retryable, fail-closed error. Invocation distinguishes intentional lifecycle
blocks from store outages; the latter returns a typed retryable
`catalog_unavailable` error rather than a policy denial. This is the ordinary
[sequence-counter consistency pattern](https://docs.kernel.org/locking/seqlock.html):
readers reject an in-progress or changed generation rather than exposing a
mixed snapshot. Standard `tools/list` and gateway discovery cursors also fail
closed when their authorized view no longer matches, preventing a traversal
from splicing pages across catalog or policy generations.

## Discovery cost

Listing and search read governed catalog and review decisions in bounded
groups instead of a serial database round trip for each tool. Definitions and
classifications are indexed by name within the request. The gateway still
authorizes each tool for the current caller and rebuilds the eligible view
before pagination; it does not retain a cross-request authorization cache.
The request's working set therefore follows the current catalog size, while
each storage read is bounded. Invocation continues to check current admission
at the call boundary.

The [discovery diagnostic](testing.md#performance-and-context-measurements)
measures HTTP listing and the legacy `searchTools` adapter against synthetic
catalogs and a disposable database. Its elapsed times are local comparison
evidence, not a production capacity guarantee. The governed search and Code Mode
surfaces use the same batched authorized catalog reader.

## Evaluation

Run the deterministic evaluation from the repository root:

```sh
cargo run -p waygate-mcp --example discovery_evaluation
cargo run -p waygate-mcp --example retrieval_strategy_evaluation
```

The command uses the production authorization-after-filtering ranker against a
representative in-memory corpus. The corpus covers multiple remote HTTP
servers, local upstream processes, and gateway-local tools. Kagi is a web
research exemplar within that corpus, not a source-specific test path.

The JSON report records:

- reciprocal rank and recall at the configured result limit for unknown-server,
  cross-server, exact-selector, local-upstream, gateway-local, and explicit
  vocabulary-gap intents;
- whether every tool required by the modeled task is present in the bounded
  model-visible working set with a serializable definition, reported as
  discovery-stage coverage evidence;
- selected-contract bytes compared with the full visible catalog contract
  bytes, so context efficiency can be compared on the same corpus;
- elapsed ranker time for each scenario.

Retrieval scores, context bytes, and elapsed time are comparison evidence, not
permanent release thresholds. `expected_contracts_available` means that every
tool required by the modeled task fits in the bounded working set and exposes a
serializable definition; it does not claim independent selection, invocation,
or task completion. The command exits unsuccessfully only when a ranker
invariant is violated: an exact selector no longer resolves first. A modeled
task missing one or more required definitions from the working set remains
visible in the report without turning the provisional result limit into a
release threshold. Capture the JSON before and after a retrieval change and
compare the same scenarios.

Authorization isolation, exact inspection, and add, description-change, and
remove behavior are separate deterministic product contracts. The gateway
server test suite drives the real `DiscoveryTools` handler through
`AuthorizedCatalog` and the catalog publication epoch, then asserts the exact
structured search and inspection results. These contracts are not inferred by
editing the ranker's input vector. Expand the corpus when a real incident
reveals a missing intent category; do not special-case the affected server in
production ranking.

The second command compares that lexical baseline with a deterministic local
semantic hybrid over the exact same corpus and intents. It records retrieval,
context-exposure, directional latency/resource, freshness, fallback, and
authorization-isolation evidence. Adjacent hard negatives carry each short
vocabulary-gap query while explicitly lacking the required capability. The
evaluator requires those terms to be present in the candidate vocabulary and
the semantic ordering to be non-empty and distinct from BM25.

The oracle-assisted invocation smoke check requires the expected tool to be
retrieved, its exact current contract to be resolved through the
authorization-filtered catalog, the fixture arguments to validate, the call to
pass through `DefaultInvocationService` or `BuiltinTools`, and a tool-specific
deterministic outcome to match the fixture. Mutating fixtures remain subject to
the real approval gate and do not pass that smoke check without an approval
store. The scenario supplies the expected tool and arguments, so this check
does not measure independent selection or end-to-end task completion. The
comparison supports reopening production semantic/hybrid adoption evaluation
while retaining BM25 in production today; see [Retrieval strategy
decision](retrieval-strategy-decision.md). The local candidate remains
evaluation-only and introduces no model provider, dependency, runtime network
request, second catalog, or alternate authorization path.

## Operations

`/readyz` exposes `checks.discovery_catalog` alongside policy, upstream, and
audit checks. Its `authoritative_upstream` counts come from the live published
upstream snapshots. `legacy_retrieval_index` reports Tantivy health,
publication generation, indexed upstream counts, tool-count skew, and the
serving fallback. `gateway_local.legacy_indexed` is always false by design:
gateway and Code Mode discovery rank gateway-local definitions directly in the
authorization-filtered canonical catalog.

The readiness and metrics paths compare authoritative and index counts only
when both were captured inside one stable catalog publication epoch. If
publication keeps changing across the bounded capture attempts, readiness
reports `catalog_changing` with unavailable comparative counts and metrics keep
the last coherent counts, generation, and skew rather than publishing a false
comparison. The index-state gauge changes to `unhealthy` until a later coherent
scrape restores the observed state.

The legacy index is an accelerator for the closed-draft `searchTools`
compatibility adapter. An unavailable, unhealthy, or skewed index marks the
discovery check `degraded`, but does not make readiness fail because the
authorization-filtered catalog scan remains correct. The index never becomes a
second catalog authority.

The Prometheus surface and Grafana dashboard cover:

- authoritative and indexed source/tool counts, signed tool-count skew, index
  state, and publication generation;
- gateway search, gateway inspection, Code Mode search, and Code Mode describe
  duration by closed outcome;
- accepted and rejected gateway and Code Mode continuation attempts;
- slice, full, and recovery publication outcomes plus bounded fallback reasons;
  and
- atomic manifest-to-catalog reconciliation duration and outcome.

The existing `mcp_authz_latency_seconds` family covers authorization latency,
and `mcp_server_operation_duration_seconds{method="tools/list"}` covers the
standard catalog-list operation; the discovery metrics do not duplicate them.

Queries, cursor values, credentials, tenants, client identities, and tool names
are not metric labels. This follows OpenTelemetry's guidance to use consistent
attributes and meaningful aggregations while controlling cardinality:
[general metric semantic conventions](https://opentelemetry.io/docs/specs/semconv/general/metrics/)
and [metrics concepts](https://opentelemetry.io/docs/concepts/signals/metrics/).

Use this recovery sequence:

1. Compare `authoritative_upstream` with `legacy_retrieval_index`. Do not add
   gateway-local tools to either side to make the counts match.
2. For an unhealthy or unavailable index, inspect publication errors and
   fallback reasons. Refresh the affected source through the dashboard,
   `POST /api/v1/servers/{name}/catalog/refresh`, or
   `gateway-control.refresh_server_catalog`. The next successful ordinary
   source refresh automatically performs a complete recovery rebuild when the
   index is unhealthy.
3. For non-zero skew with a healthy index, first check the affected source's
   runtime drift-quarantine count. Quarantined tools are absent from the
   authoritative served count but can remain in the advisory index, so an
   ordinary source refresh alone does not repair that skew. Diagnose and
   correct the contract drift. With durable tool-change review configured,
   [review and accept the exact replacement](guides/security.md#review-an-upstream-tool-change).
   Otherwise use the audited runtime recovery path
   (`upstream.reconnect` with `clear_quarantine`,
   `upstream.quarantine.clear`, or
   `POST /api/v1/servers/{name}/quarantine/clear`) before refreshing and
   rechecking. This runtime action is distinct from restoring a durable
   quarantined catalog row, which requires the governed
   `catalog.server.unquarantine` change. When no runtime quarantine is present,
   identify the source whose published catalog changed and refresh it. Treat an
   odd publication generation as transient; sustained odd generations or
   `generation_churn` fallbacks indicate a publication that is not converging.
4. Cursor rejection is expected after catalog, policy, governance, or
   definition changes because the client must restart at page one. Investigate
   a sustained rejection rate only after ruling out expected publication
   activity.
5. For reconciliation errors, inspect the manifest validation or catalog-store
   error and correct the source configuration. Do not repair Tantivy directly;
   a successful authoritative reconciliation and source refresh repopulates the
   advisory index.

Rollout and reversal are additive. Deployments can observe the new readiness
projection and metrics before alerting on them. Reverting the binary removes
the added telemetry and panels without migrating data or changing the canonical
catalog. Compare evaluation reports and dashboard signals across the rollout;
do not introduce a parallel serving index as a rollback mechanism.

## Upgrade compatibility

`gateway-discovery` is a gateway-owned namespace and is therefore reserved in
manifest validation. Before upgrading, operators with an upstream already
named `gateway-discovery` must rename that upstream and update its policy and
client references. The gateway refuses the colliding manifest rather than
silently shadowing either the upstream or the built-in discovery tools.

This catalog → inspect → execute shape follows the MCP client guidance on
[progressive tool discovery](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices),
Anthropic's [advanced tool-use guidance](https://www.anthropic.com/engineering/advanced-tool-use),
Block's [discovery/planning/execution layering](https://engineering.block.xyz/blog/build-mcp-tools-like-ogres-with-layers),
and Goose's [on-demand Code Mode tool loading](https://goose-docs.ai/docs/guides/managing-tools/code-mode/).
The lifecycle and restart behavior follow MCP's
[tool-list change notification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
[cache invalidation](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching),
and [opaque pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination)
contracts. Block's guidance additionally motivates treating discovery metadata
and guardrails as one published layer, while Goose's guidance reinforces
loading only the tools needed for the current task. Kagi is one useful canary
for these source-lifecycle cases, not a source-specific exception.
The gateway's closed-draft `searchTools` adapter remains a separate legacy
compatibility projection; it is not this product surface and upstream servers
do not implement either gateway-owned adapter.
