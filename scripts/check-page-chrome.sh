#!/usr/bin/env bash
# CI tripwire: dashboard page chrome is the single
# `waygate_admin::chrome::PageChrome` — page structs embed it, they never
# redeclare the seven chrome fields, and tenant-aware URL building has exactly
# one implementation (`tenant_ctx::nav_url`, surfaced via
# `PageChrome::nav_url`). Before the consolidation 38 page structs redeclared
# the fields and 54 `fn nav_url` copies existed.
#
# Two rules:
#   1. No `nav: Vec<NavGroup>` field outside chrome.rs — a page carrying its
#      own nav vector is a chrome copy.
#   2. `fn nav_url` outside chrome.rs / tenant_ctx.rs must be a pure DELEGATE:
#      its body's first line forwards to `self.chrome.nav_url(` (include-
#      context page delegates) or `crate::tenant_ctx::nav_url(` (fragment
#      delegates). Anything else is a second URL-building implementation.
#
# Scanner discipline (same as check-capability-guards.sh): plain grep, scan
# dirs must exist, and a positive-control canary must match before an empty
# result is trusted.
set -euo pipefail
cd "$(dirname "$0")/.."

SCAN_DIR=crates/waygate-admin/src
if [ ! -d "$SCAN_DIR" ]; then
    echo "check-page-chrome: FAIL — scan dir missing: $SCAN_DIR" >&2
    exit 2
fi
# Positive control: chrome.rs itself declares the field and the method.
if ! grep -q 'nav: Vec<NavGroup>' "$SCAN_DIR/chrome.rs" ||
    ! grep -q 'pub fn nav_url' "$SCAN_DIR/chrome.rs"; then
    echo "check-page-chrome: FAIL — scanner self-check failed (canaries in chrome.rs not found); refusing to report a vacuous OK" >&2
    exit 2
fi

# Rule 1: nav field copies.
code=0
hits=$(grep -rnE --include='*.rs' 'nav: Vec<(crate::dashboard::)?NavGroup>' "$SCAN_DIR" \
    | grep -v '^crates/waygate-admin/src/chrome\.rs:') || code=$?
if [ "$code" -gt 1 ]; then
    echo "check-page-chrome: FAIL — scanner error (grep exit $code)" >&2
    exit 2
fi
if [ -n "$hits" ]; then
    echo "check-page-chrome: FAIL — nav field redeclared outside chrome.rs (embed \`chrome: PageChrome\` instead):" >&2
    echo "$hits" | sed 's/^/  /' >&2
    exit 1
fi

# Rule 2: nav_url impls must be delegates.
code=0
impls=$(grep -rn --include='*.rs' -A2 'fn nav_url' "$SCAN_DIR" \
    | grep -v '^crates/waygate-admin/src/chrome\.rs[:-]' \
    | grep -v '^crates/waygate-admin/src/tenant_ctx\.rs[:-]') || code=$?
if [ "$code" -gt 1 ]; then
    echo "check-page-chrome: FAIL — scanner error (grep exit $code)" >&2
    exit 2
fi
bad=$(echo "$impls" | awk '
    /fn nav_url/ { held = $0; ok = 0; next }
    held != "" {
        if ($0 ~ /self\.chrome\.nav_url\(/ || $0 ~ /crate::tenant_ctx::nav_url\(/) { held = ""; next }
        if ($0 ~ /^--$/) { print held; held = ""; next }
        # a second body line that is not the delegate call
        if ($0 !~ /^[^:]*[-][0-9]+[-][[:space:]]*$/) { print held; held = "" }
    }
' | grep -v '^$' || true)
if [ -n "$bad" ]; then
    echo "check-page-chrome: FAIL — non-delegate fn nav_url outside chrome.rs/tenant_ctx.rs:" >&2
    echo "$bad" | sed 's/^/  /' >&2
    echo "Delegate to self.chrome.nav_url(...) (pages) or crate::tenant_ctx::nav_url(...) (fragments)." >&2
    exit 1
fi
echo "check-page-chrome: OK (one PageChrome, one nav_url implementation)"
