#!/usr/bin/env bash
# Fail if any crate outside waygate-core's net module classifies IP addresses
# for outbound-destination policy itself. Fast, compile-free CI tripwire
# (image.yml).
#
# Why it exists: waygate-as carried its own `is_public_ip` alongside the
# waygate-core one. The two drifted — the local copy unwrapped only
# `::ffff:0:0/96`, so NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`), and the
# deprecated IPv4-compatible `::a.b.c.d` forms each classified an embedded
# internal IPv4 as public, and it also admitted `0.0.0.0/8`, `192.0.0.0/24`,
# and the `198.18.0.0/15` benchmarking block. A second implementation of an
# SSRF classifier is a second thing to keep correct, and the copy that gets
# forgotten is the one guarding the surface reached by untrusted input.
#
# What to do instead of hand-rolling a classifier:
# `use waygate_core::net::is_public_ip;` and call it on every resolved
# address before dialing. If a surface needs a DIFFERENT policy — the
# upstream transport deliberately allows private addresses, because upstreams
# live on Docker networks — express that as an explicit decision at the call
# site rather than a second range table.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed="crates/waygate-core/src/net.rs"

fail=0

# The std range predicates that make up an address-policy table. Matching on
# these (rather than on the name `is_public_ip`) is what catches a copy that
# renames the function. `is_loopback` alone is legitimate for a URL-shape
# check, so it is deliberately not in this list; two or more of these in one
# file is the signal that a range table has been rebuilt.
predicates='is_private|is_link_local|is_documentation|is_benchmarking|is_shared|to_ipv4_mapped|is_broadcast'

offenders=""
while IFS= read -r file; do
  rel="${file#"$repo_root"/}"
  [ "$rel" = "$allowed" ] && continue
  # Count OCCURRENCES, not matching lines — a range table is usually written
  # as one `!(a() || b() || c())` chain, which `grep -c` would score as 1.
  # Comment-only lines are dropped first so prose describing the policy does
  # not trip the guard; an unanchored `-o` then counts every predicate,
  # including several on one line. The `|| true` sits inside the pipeline
  # because `set -o pipefail` would turn grep's no-match exit into an abort.
  hits="$(
    {
      grep -vE '^[[:space:]]*(//|\*|/\*)' "$file" \
        | grep -oE "\b($predicates)\b" || true
    } | wc -l | tr -d ' '
  )"
  if [ "${hits:-0}" -ge 2 ]; then
    offenders="${offenders}  $rel ($hits address-range predicates)"$'\n'
  fi
done < <(find "$repo_root/crates" -name '*.rs' -not -path '*/target/*')

if [ -n "$offenders" ]; then
  {
    echo "ERROR: address-range classification outside $allowed —"
    echo "use waygate_core::net::is_public_ip instead of a second range table:"
    printf '%s' "$offenders"
  } >&2
  fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "check-single-ip-policy: OK (address-range policy confined to $allowed)"
