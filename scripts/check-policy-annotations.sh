#!/usr/bin/env bash
# Fail if any policy under policies/ is missing a stable @id or a @layer
# annotation, or if two policies share an @id. Fast, compile-free mirror of the
# waygate-authz `every_on_disk_policy_has_stable_id_and_layer` test, run as an
# early CI step (image.yml) so a missing or duplicate
# annotation fails in seconds with a clear message — not buried in cargo-test
# output and not at prod boot.
#
# Why it exists: a policy @id is a DURABLE CONTRACT. It flows into
# AuthzResult.policy_ids, the simulator, and every audit_log row, so the
# dashboard can deep-link a fired policy back to its definition and answer
# "which decisions matched this policy". A policy with no @id falls back to
# Cedar's positional `policyN` (opaque, and it shifts whenever a policy is
# added or removed); two policies sharing an @id make policy_ids ambiguous and
# silently merge two distinct rules in the UI and the decision log. The loader
# (CedarEngine::from_source) refuses a duplicate @id at boot — this guard
# catches both the missing-@id and duplicate-@id gaps before merge.
#
# Heuristic but aligned with the authoritative Rust test: it assumes one
# top-level permit/forbid per @id and `permit`/`forbid` at column 0, which
# holds for every file under policies/.
#
# Intentionally redundant with the Rust test: this gate still fires if the test
# crate fails to compile for an unrelated reason, and runs without a toolchain.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pol_dir="$repo_root/crates/waygate-authz/tests/fixtures/policies"

[ -d "$pol_dir" ] || {
  echo "check-policy-annotations: policies dir not found at $pol_dir" >&2
  exit 2
}

fail=0

for f in "$pol_dir"/*.cedar; do
  [ -e "$f" ] || continue
  base="$(basename "$f")"
  # Each policy statement starts with `permit` or `forbid` at column 0; each
  # @id / @layer annotation is on its own line. So line counts == element
  # counts. `|| true` keeps `set -e` happy when a file has zero of a thing
  # (grep exits 1 on no match) — e.g. the intentionally-empty deny-by-default.
  stmts="$(grep -cE '^(permit|forbid)' "$f" || true)"
  ids="$(grep -cE '^@id\(' "$f" || true)"
  layers="$(grep -cE '^@layer\(' "$f" || true)"
  if [ "$ids" -ne "$stmts" ]; then
    echo "ERROR: $base has $stmts policy statement(s) but $ids @id annotation(s) — every policy needs exactly one @id." >&2
    fail=1
  fi
  if [ "$layers" -ne "$stmts" ]; then
    echo "ERROR: $base has $stmts policy statement(s) but $layers @layer annotation(s) — every policy needs exactly one @layer." >&2
    fail=1
  fi
done

dupes="$(
  grep -rhoE '@id\("[^"]+"\)' "$pol_dir"/*.cedar 2>/dev/null \
    | sed -E 's/@id\("([^"]+)"\)/\1/' \
    | sort | uniq -d
)"
if [ -n "$dupes" ]; then
  {
    echo "ERROR: duplicate policy @id(s) under policies/ — @id must be unique across all files."
    echo "The loader refuses a duplicate @id at boot; rename so each is unique:"
    echo "$dupes" | sed 's/^/  /'
  } >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

count="$(grep -rcE '^@id\(' "$pol_dir"/*.cedar 2>/dev/null | awk -F: '{s += $2} END {print s}')"
echo "check-policy-annotations: OK ($count policies, all carry a unique @id + @layer)"
