#!/usr/bin/env bash
# CI tripwire: line-count ratchet on the god
# files mapped by the architecture review (F6). Each file has a ceiling;
# a split PR that shrinks a file MUST tighten its ceiling here in the same
# PR (that's the ratchet). Growing a file past its ceiling fails CI — new
# logic goes in a new module, not appended to these files
# (docs/architecture.md §7).
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {
    local file="$1" ceiling="$2"
    if [ ! -f "$file" ]; then
        echo "check-godfile-ratchet: FAIL — $file missing (update the ratchet if it moved)" >&2
        fail=1
        return
    fi
    local n
    n=$(wc -l < "$file" | tr -d ' ')
    if [ "$n" -gt "$ceiling" ]; then
        echo "check-godfile-ratchet: FAIL — $file is $n lines (ceiling $ceiling)." >&2
        echo "  Do not grow the god files: new logic goes in a new module (docs/architecture.md §7)." >&2
        fail=1
    fi
}

# Ceilings = current size + small headroom; tightened by each split PR that shrinks a file.
check crates/waygate-upstream/src/pool/mod.rs      2200   # tightened when the lane helpers moved to pool/lanes.rs
check crates/waygate-server/src/main.rs            2484   # tightened when the reconnect scheduler moved to reconnect_scheduler.rs
check crates/waygate-server/src/config.rs          2344   # tightened when the classification fixtures moved to ToolClassification::new
check crates/waygate-admin/src/dashboard.rs        1300   # ceiling for the module split out of the former 7,147-line dashboard.rs
check crates/waygate-admin/src/change_executor/mod.rs  580   # tightened when the params-schema table moved to change_executor/param_schemas.rs
check crates/waygate-mcp/src/invocation/mod.rs     2154   # tightened when model operation dispatch moved to invocation/llm.rs

[ "$fail" -eq 0 ] || exit 1
echo "check-godfile-ratchet: OK (all tracked files within their ceilings)"
