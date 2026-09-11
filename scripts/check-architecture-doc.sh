#!/usr/bin/env bash
# CI tripwire: docs/architecture.md's crate map must stay in sync with the
# workspace. Every member in Cargo.toml needs a row between the
# crate-map:begin/end markers, and every row must name a live member — so a
# new crate cannot land undocumented and a deleted crate cannot leave a
# stale row. Toolchain-free on purpose (parses Cargo.toml, not cargo
# metadata) so it runs in the fast check job before Rust is installed.
set -euo pipefail
cd "$(dirname "$0")/.."

doc=docs/architecture.md

if ! grep -q '<!-- crate-map:begin -->' "$doc" || ! grep -q '<!-- crate-map:end -->' "$doc"; then
    echo "check-architecture-doc: FAIL — crate-map markers missing from $doc" >&2
    exit 1
fi

members=$(sed -n '/^members = \[/,/^\]/p' Cargo.toml \
    | grep -oE '"crates/[a-z0-9_-]+"' | sed 's#"crates/##; s#"##' | sort)
rows=$(sed -n '/<!-- crate-map:begin -->/,/<!-- crate-map:end -->/p' "$doc" \
    | grep -oE '^\| `[a-z0-9_-]+`' | sed 's/^| `//; s/`//' | sort)

if [ -z "$members" ]; then
    echo "check-architecture-doc: FAIL — could not parse workspace members from Cargo.toml" >&2
    exit 1
fi

fail=0
missing=$(comm -23 <(echo "$members") <(echo "$rows"))
stale=$(comm -13 <(echo "$members") <(echo "$rows"))
if [ -n "$missing" ]; then
    echo "check-architecture-doc: FAIL — workspace member(s) with no crate-map row in $doc:" >&2
    echo "$missing" | sed 's/^/  - /' >&2
    echo "Add a row (crate, layer, owns, does-not-own) inside the crate-map markers." >&2
    fail=1
fi
if [ -n "$stale" ]; then
    echo "check-architecture-doc: FAIL — crate-map row(s) in $doc for crates that are not workspace members:" >&2
    echo "$stale" | sed 's/^/  - /' >&2
    echo "Remove the stale row(s) (or restore the crate)." >&2
    fail=1
fi
[ "$fail" -eq 0 ] || exit 1

echo "check-architecture-doc: OK ($(echo "$members" | wc -l | tr -d ' ') workspace members all documented, no stale rows)"
