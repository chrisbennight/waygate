#!/usr/bin/env bash
# CI tripwire: Postgres SQLSTATE class-23 literals are
# confined to waygate_core::store's constants. ~30 hand-written "23505"/
# "23503"/"23514" comparisons across ten crates predated the consolidation;
# stores must match on waygate_core::store::{UNIQUE_VIOLATION,
# FOREIGN_KEY_VIOLATION, CHECK_VIOLATION} instead, so the code→semantics
# mapping cannot drift per crate. Test files are exempt (a test may assert
# the raw wire code deliberately).
set -euo pipefail
cd "$(dirname "$0")/.."

hits=$(grep -rn '"23[0-9][0-9][0-9]"' crates/ --include='*.rs' 2>/dev/null \
    | grep -v '^crates/waygate-core/src/store\.rs:' \
    | grep -v '/tests/' || true)
if [ -n "$hits" ]; then
    echo "check-shared-store-error: FAIL — SQLSTATE literal(s) outside waygate_core::store:" >&2
    echo "$hits" | sed 's/^/  /' >&2
    echo "Match on waygate_core::store::{UNIQUE_VIOLATION, FOREIGN_KEY_VIOLATION, CHECK_VIOLATION}." >&2
    exit 1
fi
echo "check-shared-store-error: OK (SQLSTATE literals confined to waygate_core::store)"
