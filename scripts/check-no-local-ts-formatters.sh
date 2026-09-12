#!/usr/bin/env bash
# Fail if any crate defines a local timestamp formatter instead of using
# the shared ones in waygate-core. Fast, compile-free CI tripwire
# (image.yml).
#
# Use waygate_core::fmt for consistent absolute, relative, and RFC 3339 output.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed="crates/waygate-core/src/fmt.rs"

# Match function *definitions* (any visibility) with EXACTLY one of the
# consolidated formatter names — the `[[:space:](<]` terminator right
# after the name means test helpers like `fn format_ts_rel_buckets_...`
# don't match (same shape as check-no-local-escapers.sh).
hits="$(
  grep -rnE '(^|[[:space:]])fn[[:space:]]+(format_ts_rfc3339|format_ts_abs|format_ts_rel|format_ts|rfc3339)[[:space:](<]' \
    "$repo_root/crates" --include='*.rs' \
    | grep -v "$allowed" || true
)"

if [ -n "$hits" ]; then
  {
    echo "ERROR: local timestamp formatter definition(s) found —"
    echo "use waygate_core::fmt::{format_ts_abs, format_ts_rel, format_ts_rfc3339} instead."
    echo "The shared contract lives in $allowed; local copies drift"
    echo "Use the shared implementation:"
    echo "$hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

# Name-agnostic backstop: the name check above can't
# see a local wrapper under a novel name (`fmt_ts`, `ts`) or an inline
# call chain — but every one of those must invoke Rfc3339 FORMATTING, so
# forbid the call itself outside the shared module. Parsing
# (`::parse(x, &Rfc3339)`) is unaffected: this matches only `.format(&…)`.
# `tests/` is exempt: fixtures may hand-format inputs; they don't render
# operator-facing output.
rfc_hits="$(
  grep -rnE '\.format\(&(time::format_description::well_known::)?Rfc3339\)' \
    "$repo_root/crates" --include='*.rs' \
    | grep -v "$allowed" \
    | grep -v '/tests/' || true
)"
if [ -n "$rfc_hits" ]; then
  {
    echo "ERROR: inline RFC 3339 timestamp formatting outside $allowed —"
    echo "use waygate_core::fmt::format_ts_rfc3339 instead:"
    echo "$rfc_hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

echo "check-no-local-ts-formatters: OK (no local format_ts*/rfc3339 definitions or inline Rfc3339 formatting outside waygate-core)"
