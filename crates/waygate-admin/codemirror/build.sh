#!/usr/bin/env bash
# Build the vendored CodeMirror 6 Cedar editor bundle.
#
# Reproducible: versions are pinned in package.json + package-lock.json. Run
# from this directory after `npm ci` (or `npm install`). The OUTPUT
# (../static/js/codemirror.bundle.js) is the committed runtime artifact — the
# repo stays build-step-free at deploy time, exactly like static/js/htmx.min.js.
#
#   cd crates/waygate-admin/codemirror
#   npm ci
#   ./build.sh
#
set -euo pipefail
cd "$(dirname "$0")"

OUT=../static/js/codemirror.bundle.js
LOCK=../../../THIRD_PARTY_LICENSES-CODEMIRROR.lock

npx --no-install esbuild src/cedar-editor.mjs \
  --bundle \
  --minify \
  --format=iife \
  --global-name=CedarEditor \
  --target=es2020 \
  --legal-comments=none \
  --outfile="$OUT"

sha256sum \
  package.json \
  package-lock.json \
  src/cedar-editor.mjs \
  build.sh \
  "$OUT" \
  > "$LOCK"

echo "built $OUT ($(wc -c < "$OUT") bytes)"
