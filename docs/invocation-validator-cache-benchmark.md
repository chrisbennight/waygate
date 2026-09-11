# Invocation validator cache benchmark

This benchmark measures the JSON Schema work removed from the steady-state
invocation response path. It compares the previous behavior (compile the
admitted schema, then validate one representative structured response) with
validation through the already-compiled validator carried by the invocation
snapshot.

Run it with:

```sh
cargo bench -p waygate-mcp --bench validator_cache --locked
```

## Recorded results

Both runs were recorded 2026-07-11 on an Apple Silicon macOS host with Rust
1.96.1, using the release profile and 10,000 samples. The initial run isolated
the original compile-versus-cache comparison:

| Path | Median | p95 |
| --- | ---: | ---: |
| Compile and validate on every response | 7.625 µs | 19.459 µs |
| Validate with the admitted cached validator | 0.125 µs | 0.334 µs |

After the cache key gained its canonical validator-schema digest, the benchmark
was rerun against an output schema with a digest-plus-cached-validation
comparison included:

| Path | Median | p95 |
| --- | ---: | ---: |
| Compile and validate on every response | 7.042 µs | 12.041 µs |
| Validate with the admitted cached validator | 0.125 µs | 0.208 µs |
| Hash the output schema and validate with the cached validator | 3.125 µs | 5.042 µs |

The absolute tails vary between short microbench runs. The digest-plus-cached
row isolates output-schema hashing and validation; it does not measure the
complete cache-hit path, which also allocates the catalog-hash key, locks the
cache mutex, looks up the entry, records a metric, and clones the cached cell
and result.

The benchmark intentionally excludes network and database latency so it
isolates validator work. The invocation admission contract tests provide the
other hot-path counts:

| Work per catalog-backed invocation | Before admission-snapshot remediation | After snapshot + cache remediation |
| --- | ---: | ---: |
| Authoritative catalog resolutions | up to 3 | 1 |
| Validator compilations for a stable schema version | 1 per response | 1 initial miss, then 0 |

One process-wide cache is fixed at 256 exact
`(tool_id, catalog_schema_hash, validator_schema_hash)` entries. The canonical
validator-schema digest lets the cache serve admitted input and output schemas
without conflating different values. It remains necessary for output schemas
because the historical catalog hash covers the tool name, description, and
input schema but not the output schema. Its hit, miss, eviction, and
compile-failure counters make production behavior observable; a schema-only
change creates a distinct entry rather than reusing an old positive or negative
validator result. Per-key initialization lets same-key admissions converge
without holding the global lookup and eviction mutex during compilation. At
capacity, a new miss waits for the oldest entry to finish initialization before
evicting it, so FIFO churn cannot split an in-flight exact key across two
validators.
