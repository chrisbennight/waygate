#!/usr/bin/env bash
# CI ratchet: per-file AdminMutation evidence recorders are
# being folded into the single fail-closed
# waygate_admin::admin_mutation::record_admin_mutation. Fifteen near-identical
# private copies existed; a drifted copy is a security bug waiting to happen
# (one that quietly used record_best_effort would turn fail-closed audit into
# fail-open). Two pilot files have already been converted; the rest convert
# incrementally.
#
# The count may only DECREASE. When you fold a file's copy into the shared
# helper, lower MAX_RECORDERS here in the same PR. New resources use the
# shared helper from day one — a new private copy fails this check.
#
# FLOOR: 1. change_requests.rs keeps its recorder by decision —
# its event shape is genuinely different (variable AuditOutcome for
# deny/failure paths, the structured `target` column carrying the change's
# action_type, and plain-Internal error semantics). Rationale in
# admin_mutation.rs's module docs.
#
set -euo pipefail
cd "$(dirname "$0")/.."

MAX_RECORDERS=1

SCAN_DIR=crates/waygate-admin/src
if [ ! -d "$SCAN_DIR" ]; then
    echo "check-admin-boilerplate: FAIL — scan dir missing: $SCAN_DIR" >&2
    exit 2
fi
# Positive control: the shared helper itself must exist.
if ! grep -q 'pub(crate) async fn record_admin_mutation' "$SCAN_DIR/admin_mutation.rs"; then
    echo "check-admin-boilerplate: FAIL — scanner self-check failed (shared recorder not found); refusing to report a vacuous OK" >&2
    exit 2
fi

code=0
hits=$(grep -rnE --include='*.rs' 'async fn record_[a-z_]*mutation[a-z_]*\(' "$SCAN_DIR" \
    | grep -v '^crates/waygate-admin/src/admin_mutation\.rs:') || code=$?
if [ "$code" -gt 1 ]; then
    echo "check-admin-boilerplate: FAIL — scanner error (grep exit $code)" >&2
    exit 2
fi
count=$(printf '%s' "$hits" | grep -c . || true)

if [ "$count" -gt "$MAX_RECORDERS" ]; then
    echo "check-admin-boilerplate: FAIL — $count private mutation recorders (ceiling $MAX_RECORDERS):" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    echo "Use crate::admin_mutation::record_admin_mutation instead of a new per-file copy." >&2
    exit 1
fi
echo "check-admin-boilerplate: OK ($count private mutation recorders <= ceiling $MAX_RECORDERS; floor 1 = change_requests, by decision)"
