# Evaluate tool retrieval strategies

Production discovery uses BM25 over the authorized catalog. The optional local
LSA hybrid is an evaluation candidate, not a production ranker. The evaluation
compares retrieval quality, cost, exact-selector behavior, and authorization
isolation using a synthetic corpus. It does not establish independent agent
selection or end-to-end task success.

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

## Interpreting results

Keep comparisons reproducible and report the corpus, toolchain, retrieval
metrics, timing, and memory observations. Synthetic results are not production
capacity forecasts. Provider-backed evaluation additionally needs an explicit
data boundary for query text and tool metadata.

A production ranking change must preserve authorization filtering, exact
selectors, catalog freshness, and a usable lexical fallback. Evaluate those
contracts alongside retrieval quality on representative workloads.
