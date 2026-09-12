#!/usr/bin/env bash
# Fail if any crate defines a local HTML escaper instead of using the shared
# one in waygate-core. Fast, compile-free CI tripwire (image.yml).
#
# HTML escaping uses waygate_core::html::escape consistently for & < > " and apostrophes.
# What to do instead of adding one: `use waygate_core::html::escape;`
# (waygate-core is dependency-light; any crate can take it).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed="crates/waygate-core/src/html.rs"

# Match a function *definition* (any visibility), not call sites or imports.
hits="$(
  grep -rnE '(^|[[:space:]])fn[[:space:]]+(html_escape|escape_html)[[:space:](<]' \
    "$repo_root/crates" --include='*.rs' \
    | grep -v "$allowed" || true
)"

if [ -n "$hits" ]; then
  {
    echo "ERROR: local HTML escaper definition(s) found — use waygate_core::html::escape instead."
    echo "The one shared escaper lives in $allowed (escapes all of & < > \" ');"
    echo "local copies drift (three different char sets existed before consolidation):"
    echo "$hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

echo "check-no-local-escapers: OK (no local html_escape/escape_html definitions outside waygate-core)"
