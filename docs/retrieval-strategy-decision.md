# Retrieval strategy decision

## Decision

Keep the production BM25 lexical ranker in service while reopening production
adoption evaluation for a semantic or hybrid ranker. The corrected local hybrid
retrieves the intended capability in all representative vocabulary-gap cases
that BM25 misses. Oracle-assisted smoke checks then verify that those retrieved
capabilities can pass exact inspection, schema validation, and the gateway
invocation seams. The mutating refund path reaches the same governed pipeline
and is correctly stopped because the evaluation fixture has no durable approval
store. These smoke checks do not measure independent tool selection or
end-to-end task success.

This is evidence to design and evaluate a production candidate, not a decision
to ship the small local LSA model used by the harness. That model still adds
derived state, rebuild work, memory, query work, and another failure mode, and
the fixture is not a capacity or model-quality benchmark. Production behavior
does not change here: authorization still filters the canonical catalog before
ranking, inspection still returns the exact current definition, and invocation
still uses the typed, authorized, quota-controlled, approval-controlled, and
audited path.

## Why evaluate a hybrid

The [MCP client best-practices
guide](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices)
describes keyword/BM25, embedding, subagent, and hybrid retrieval as choices.
It recommends progressive catalog, inspect, and execute layers regardless of
retrieval mechanism, and calls out custom retrieval when domain-specific
ranking or access-control filtering is needed. It also requires discovery
caches to refresh after `notifications/tools/list_changed`.

[Anthropic's advanced tool-use
guidance](https://www.anthropic.com/engineering/advanced-tool-use) supports
on-demand tool discovery to reduce initial context and improve selection. Its
[Contextual Retrieval
study](https://www.anthropic.com/news/contextual-retrieval) demonstrates that
BM25 and semantic results can complement one another, but explicitly recommends
running evaluations and accounting for latency and cost. The 2026
[SCOUT paper](https://arxiv.org/abs/2608.23992) is further evidence that BM25
plus dense retrieval and reciprocal-rank fusion can work for large MCP
catalogs. These are reasons to evaluate a hybrid, not evidence that every
catalog benefits from one.

The benchmark must also be capable of exposing the difference. The
[ToolRet paper](https://arxiv.org/abs/2503.01763) identifies lower query-to-tool
term overlap as a defining difficulty of tool retrieval. The 2026
[ToolSense study](https://arxiv.org/abs/2606.12451) likewise reports that
verbose, fully specified queries can mask retrieval weakness and evaluates
short, intent-focused requests at multiple ambiguity levels. The gateway
comparison therefore includes explicit short vocabulary-gap cases; it does not
infer lexical sufficiency from direct queries that repeat tool descriptions.
The 2026 [Agent Retrieval
Bench](https://arxiv.org/html/2607.24882v1) makes the same measurement boundary
explicit: top-k retrieval scores measure an upstream context-acquisition stage
and must not be presented as full agent performance without a downstream
executable evaluation.

The security boundary cannot move with the ranking technique. Block's
[agent guardrails and controls](https://engineering.block.xyz/blog/agent-guardrails-and-controls)
argue that deterministic code, rather than the language model, must enforce
authorization decisions after untrusted tool content enters a session. The
gateway therefore evaluates retrieval only over an already-authorized catalog
projection and leaves invocation authorization at the authoritative call
boundary. Community proposals such as [MCP discussion
#2036](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2036)
are useful design input, but they are not an MCP protocol requirement.

## Evaluation design

Run both deterministic reports from the repository root:

```sh
cargo run -p waygate-mcp --example discovery_evaluation
cargo run -p waygate-mcp --example retrieval_strategy_evaluation
```

The comparison uses the same representative corpus and intents as the
production-ranker evaluation. The corpus includes remote HTTP upstreams, local
upstream processes, and gateway-local tools. Kagi is one web-research exemplar,
not a special retrieval path. Adjacent hard-negative tools contain the short
intent vocabulary but explicitly cannot perform the expected action. This
requires the semantic component to produce a non-empty ordering distinct from
BM25 instead of receiving an all-zero, out-of-vocabulary query.

The candidate is an evaluation-only local latent semantic analysis (LSA)
model:

1. Build TF-IDF document vectors from each authorized tool's structured source
   identity, name, title, and description.
2. Derive a deterministic truncated latent space from that matrix.
3. Rank queries by cosine similarity in the latent space.
4. Fuse the semantic and production BM25 orderings with reciprocal-rank fusion.

This is a credible semantic/hybrid candidate because it can relate terms
through their shared corpus context rather than exact query-token overlap. It
is deliberately local and reproducible: no embedding service, model download,
new package, or network request is involved. It is not a claim that LSA has the
same quality as a production embedding model. A provider-backed candidate
would add provider, model-version, data-handling, availability, and cost
variables that must be evaluated separately before adoption.

The report compares:

- mean reciprocal rank and recall within the bounded discovery set;
- direct-vocabulary, exact-selector, and zero-overlap vocabulary-gap queries;
- whether each modeled task retrieves the expected tool and whether an
  oracle-assisted smoke check can resolve that tool's exact current contract
  through the same `AuthorizedCatalog` seam used by
  `gateway-discovery.inspect`, validate fixture arguments against that schema,
  and invoke it through `DefaultInvocationService` or the `BuiltinTools`
  dispatch seam;
- whether every vocabulary-gap query is represented in the candidate
  vocabulary and produces non-empty semantic evidence distinct from BM25;
- selected exact-contract bytes, which show what could enter model context
  after inspection;
- directional ranking and index-build time plus estimated derived-index bytes;
- exact-selector preservation and lexical fallback when the candidate is
  unavailable;
- behavior after adding, removing, or changing a tool description; and
- isolation when a tool is removed from the authorized projection before both
  rankers run.

Elapsed microseconds and estimated bytes are comparison observations, not
release thresholds or capacity forecasts. The fixture is intentionally small,
so the command records direction and lifecycle obligations rather than
pretending to be a production load benchmark.

## Evidence

On the representative corpus, both strategies complete the direct-vocabulary
and exact-selector retrieval cases. BM25 misses each short vocabulary-gap
target behind an adjacent hard negative. The hybrid emits distinct semantic
rankings and retrieves every intended target within the bounded set. With the
expected tool and fixture arguments supplied by the scenario, the web and
local-file smoke paths pass through governed inspection and invocation. The
refund target is retrieved and its fixture arguments validate, but the real
invocation pipeline refuses execution because no approval store is configured;
the report records that refusal separately.

The candidate therefore improves reciprocal rank and bounded recall on the
discriminating cases. It does not establish that an agent would independently
select the intended tool or complete the task. It also holds a derived
vocabulary, document coordinates, and latent term vectors and requires a model
build. Per-run ranking timings are retained as directional observations rather
than treated as stable evidence on this small fixture.

The lifecycle checks show that rebuilding the candidate incorporates an added
tool, changes after edited descriptive text, and excludes a removed tool. An
authorization-restricted input excludes the denied tool from both result sets.
Exact qualified selectors remain exact, and candidate unavailability returns
the production lexical ordering without approximation.

The fixture invocation is deliberately side-effect-free, but it is not a
universal echo. Upstream scenarios pass through the production
`DefaultInvocationService` stages against a deterministic `UpstreamCatalog`;
gateway-local scenarios use the `BuiltinTools` dispatch contract. Every modeled
tool returns a distinct, scenario-checked outcome, so the smoke check detects a
wrong dispatch. The expected tool and arguments are supplied by the scenario,
so this is not an independent selector or a task-completion benchmark. The
fixture does not call a live upstream or replace handler-level tests for catalog
publication and fleet freshness.

## Data handling and reproducibility

For this evaluation, query text and authorized tool metadata remain inside the
process. No content is sent to a model or retrieval provider. The candidate is
rebuilt from the current authorized corpus and uses fixed tokenization,
weighting, component selection, and rank fusion, so the ranking is reproducible
for the same catalog and query. Timing remains machine-dependent.

A future embedding-backed design must document and govern at least:

- which query, description, schema, governance, and tenant fields may leave the
  gateway boundary;
- provider, region, retention, training-use, credential, and network policy;
- model identity and version, index/model compatibility, and reproducible
  rebuild behavior;
- publication only after a complete candidate index is ready, with
  `list_changed`, reconnect, and periodic freshness reconciliation;
- observable stale, rebuilding, failed, and degraded states;
- a safe lexical path that uses the same authorized catalog and does not make a
  semantic index a second inventory or authorization authority; and
- resource, latency, context-exposure, independent tool-selection, and
  end-to-end task-completion evidence on the governed representative workload.

## Production adoption gate

The discriminating evaluation satisfies the reason to reopen production design
work. It does not select an embedding model or authorize deployment. Any
adoption still requires representative evidence from the governed operational
catalog, an accepted model and data boundary, complete lifecycle and freshness
behavior, safe lexical fallback, observability, latency and resource evidence,
and no regression in authorization isolation or exact selectors. A production
candidate must also demonstrate that its benefit survives realistic hard
negatives rather than learning this fixture's examples.
