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
case "${1:-}" in
  '') check=0 ;;
  --check) check=1 ;;
  *) echo 'Usage: build.sh [--check]' >&2; exit 2 ;;
esac
test "$#" -le 1 || exit 2
expected="$OUT"
if [ "$check" -eq 1 ]; then
  build_dir="$(mktemp -d)"
  trap 'rm -rf "$build_dir"' EXIT
  OUT="$build_dir/codemirror.bundle.js"
fi

npx --no-install esbuild src/cedar-editor.mjs \
  --bundle \
  --minify \
  --format=iife \
  --global-name=CedarEditor \
  --target=es2020 \
  --legal-comments=none \
  --outfile="$OUT"

if [ "$check" -eq 1 ]; then
  cmp "$OUT" "$expected"
  echo 'CodeMirror bundle is current'
else
  echo "built $OUT ($(wc -c < "$OUT") bytes)"
fi
