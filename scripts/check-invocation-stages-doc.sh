#!/usr/bin/env bash
# Fast structural gate for the normative invocation-stage table. The Rust
# contract test in waygate-mcp owns semantic order/status comparison; this
# script gives an immediate CI error when the marked table is deleted or its
# marker/table shape is duplicated.
set -euo pipefail
cd "$(dirname "$0")/.."

doc=docs/architecture.md
begin='<!-- invocation-stages:begin -->'
end='<!-- invocation-stages:end -->'

begin_count=$(grep -Fxc "$begin" "$doc" || true)
end_count=$(grep -Fxc "$end" "$doc" || true)
if [ "$begin_count" -ne 1 ] || [ "$end_count" -ne 1 ]; then
    echo "check-invocation-stages-doc: FAIL — expected exactly one marked stage table in $doc" >&2
    exit 1
fi

rows=$(sed -n "/$begin/,/$end/p" "$doc" \
    | grep -Ec '^\| [0-9]+ \| `[a-z0-9_]+` \| `(active|placeholder)` \|' || true)
if [ "$rows" -eq 0 ]; then
    echo "check-invocation-stages-doc: FAIL — marked stage table has no data rows" >&2
    exit 1
fi

echo "check-invocation-stages-doc: OK ($rows marked lifecycle rows present)"
