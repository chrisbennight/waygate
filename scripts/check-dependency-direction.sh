#!/usr/bin/env bash
# CI tripwire: enforce docs/architecture.md
# §1's dependency direction. Every intra-workspace [dependencies] edge must
# point sideways or downward in the layer order Leaf < Foundation < Domain <
# Composition, with the layer assignment read from the architecture doc's
# CI-synced crate map (the doc is the source of truth, not a copy here).
# Dev-dependencies are exempt (§1's snapshot excludes them). Zero allow-list:
# all historical upward-dependency violations were retired before this landed.
# Toolchain-free (parses Cargo.toml text, not cargo metadata) so it runs in
# the fast check job before Rust is installed.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, sys, glob

RANK = {'Leaf': 0, 'Foundation': 1, 'Domain': 2, 'Composition': 3}

doc = open('docs/architecture.md').read()
m = re.search(r'<!-- crate-map:begin -->(.*?)<!-- crate-map:end -->', doc, re.S)
if not m:
    sys.exit('check-dependency-direction: FAIL — crate-map markers missing')
layer = {}
for row in re.finditer(r'^\| `([a-z0-9_-]+)` \| (\w+) \|', m.group(1), re.M):
    crate, lyr = row.groups()
    if lyr not in RANK:
        sys.exit(f'check-dependency-direction: FAIL — unknown layer `{lyr}` for `{crate}`')
    layer[crate] = lyr

fails = []
for toml in sorted(glob.glob('crates/*/Cargo.toml')):
    text = open(toml).read()
    name_m = re.search(r'^name = "([^"]+)"', text, re.M)
    if not name_m:
        continue
    crate = name_m.group(1)
    if crate not in layer:
        fails.append(f'{crate}: not in the architecture.md crate map (add its row first)')
        continue
    dep_m = re.search(r'^\[dependencies\]\n(.*?)(?=^\[|\Z)', text, re.M | re.S)
    if not dep_m:
        continue
    for dep in re.finditer(r'^(waygate-[a-z0-9-]+)\b', dep_m.group(1), re.M):
        d = dep.group(1)
        if d not in layer:
            fails.append(f'{crate}: dep `{d}` not in the crate map')
            continue
        if RANK[layer[d]] > RANK[layer[crate]]:
            fails.append(
                f'{crate} ({layer[crate]}) -> {d} ({layer[d]}): upward edge violates '
                f'docs/architecture.md §1'
            )

if fails:
    print('check-dependency-direction: FAIL —', file=sys.stderr)
    for f in fails:
        print(f'  - {f}', file=sys.stderr)
    print('Domain types belong in lower layers (waygate-core first); see', file=sys.stderr)
    print('docs/architecture.md §1 for the rule and §6 for where new code goes.', file=sys.stderr)
    sys.exit(1)

edges = sum(1 for _ in re.finditer(r'^waygate-', open('Cargo.toml').read(), re.M))
print(f'check-dependency-direction: OK ({len(layer)} crates, no upward [dependencies] edges)')
PY
