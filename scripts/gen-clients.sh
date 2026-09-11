#!/usr/bin/env bash
# Generates typed admin-API client SDKs
# (TypeScript, Python, Rust) from the gateway's OpenAPI
# spec.
#
# ## What this does
#
# 1. Builds the `dump-openapi` binary (`waygate-admin/src/bin/
#    dump_openapi.rs`) and runs it to emit
#    `openapi.json` — the canonical schema snapshot.
# 2. Invokes `openapi-generator-cli` once per target
#    language, writing to `clients/<lang>/`.
#
# ## Prerequisites
#
# - A working Rust toolchain (for step 1).
# - `openapi-generator-cli` v7.x on PATH. Install via:
#       npm install -g @openapitools/openapi-generator-cli
#   The CLI is a Java wrapper, so a JRE 11+ is also needed.
#
# Run this script directly for local generation. The repository does not
# currently provide a client-package publishing workflow. Record the selected
# generator version when distributing the output; generator names below select
# languages, not a pinned generator release.
#
# ## Why generated clients are NOT committed
#
# `clients/` is gitignored. The spec changes on every admin
# surface PR, and committing megabytes of regenerated TypeScript
# / Python on every change would flood diffs without adding
# review signal. Package publication is a separate consumer/release operation.
#
# ## Exit codes
#
# - 0: all targets generated successfully.
# - 1: dump or generator failed (per-language errors logged to
#      stderr; the first failure aborts so the operator sees
#      it instead of scrolling past).
# - 2: `openapi-generator-cli` not on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/openapi.json"
OUT_DIR="${ROOT}/clients"

log() { printf '\033[36m[gen-clients]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[31m[gen-clients] ERROR:\033[0m %s\n' "$*" >&2; }

# --- 1. Dump the spec --------------------------------------------------

log "building dump-openapi binary"
( cd "$ROOT" && cargo build --quiet -p waygate-admin --bin dump-openapi )

log "writing spec to ${SPEC}"
( cd "$ROOT" && cargo run --quiet -p waygate-admin --bin dump-openapi ) > "$SPEC"

# --- 2. Sanity-check the generator is available -----------------------

if ! command -v openapi-generator-cli >/dev/null 2>&1; then
  err "openapi-generator-cli not on PATH"
  err "install: npm install -g @openapitools/openapi-generator-cli"
  err "(spec is still at ${SPEC} — only the codegen step was skipped)"
  exit 2
fi

# --- 3. Generate per-language clients ---------------------------------
#
# Each generator gets its own subdirectory under clients/.
# The generators are pinned to a STABLE generator name (not
# the cargo / npm wrapper) so a future openapi-generator-cli
# version bump doesn't silently switch templates.

mkdir -p "$OUT_DIR"

gen_one() {
  local lang="$1"   # generator name, e.g. typescript-axios
  local out="$2"    # output subdirectory under clients/
  local extra=("${@:3}")  # extra `-p key=val` pairs
  local target="${OUT_DIR}/${out}"
  log "generating ${lang} → ${target}"
  # Per-generator output is fully owned; rm-then-mkdir keeps
  # stale files (renamed templates, dropped endpoints) from
  # surviving across runs.
  rm -rf "$target"
  mkdir -p "$target"
  openapi-generator-cli generate \
    -i "$SPEC" \
    -g "$lang" \
    -o "$target" \
    "${extra[@]}"
}

# TypeScript: axios flavor — has built-in promise + axios
# interceptor support that the gateway's CLI tools use.
gen_one typescript-axios ts \
  --additional-properties=npmName=@mcp-gateway/admin-client \
  --additional-properties=supportsES6=true \
  --additional-properties=withInterfaces=true

# Python: the maintained `python` generator (NOT
# `python-legacy`); produces typed clients with pydantic v1
# models out of the box.
gen_one python python \
  --additional-properties=packageName=mcp_gateway_admin_client \
  --additional-properties=projectName=mcp-gateway-admin-client

# Rust: synchronous reqwest-backed client. Consumers wanting
# async wrap it in `tokio::task::spawn_blocking` — we don't
# pin a `reqwest`-version because consumers' workspaces
# already do.
gen_one rust rust \
  --additional-properties=packageName=mcp-gateway-admin-client \
  --additional-properties=supportAsync=false

log "done — clients in ${OUT_DIR}/{ts,python,rust}"
