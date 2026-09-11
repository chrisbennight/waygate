# Generate typed administration clients

Run these commands from the repository root.

Typed clients for the `/api/v1` surface are generated on demand from the
gateway's OpenAPI spec. The schema itself ships with the binary (utoipa
builds it at compile time from `#[utoipa::path]` annotations); the
generator only needs a JSON dump.

```sh
# Dump the spec to ./openapi.json (no DB / port needed)
cargo run -p waygate-admin --bin dump-openapi > openapi.json

# OR — dump + generate TS / Python / Rust clients into ./clients/{ts,python,rust}/
./scripts/gen-clients.sh
```

The `gen-clients.sh` script shells out to `openapi-generator-cli` (install
with `npm install -g @openapitools/openapi-generator-cli`; requires a
JRE 11+). Both the spec dump and the generated `clients/` tree are
gitignored. These are locally generated clients; this repository currently has
no workflow publishing them to npm, PyPI, or crates.io. Follow the
[official generator installation guide](https://openapi-generator.tech/docs/installation/)
and record the generator version when distributing generated output.
