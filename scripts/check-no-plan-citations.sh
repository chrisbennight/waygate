#!/usr/bin/env bash
# CI ratchet: comments and user-visible strings must stand alone.
#
# A comment states the constraint or invariant itself, in words that survive
# with zero external context. Citations to internal planning/review state —
# phase/workstream numbering, PR numbers, review-finding IDs — decode to
# nothing a reader can reach: the planning ledgers are retired documents, and
# provenance already lives in git blame and the forge. The same rule covers
# user-visible strings (OTel metric descriptions, error/assertion messages)
# and test identifiers named after plan items.
#
# This script pins the EXACT per-group count of citation-shaped tokens, so
# drift in either direction fails:
#   - an increased count → a new citation landed; write the constraint itself
#     instead. For a genuine false positive (a string that must contain a
#     matching token), append a `citation-ok: <why>` marker on the same line.
#   - a decreased count → good, the sweep advanced; lower the pin for that
#     group to the printed count in the same PR. The end state is every pin
#     at zero, at which point unpinned-and-clean is the invariant.
#
# Scanned scope: crates/, scripts/, .github/ (the pin table below is the
# authoritative list).
#
# Out of scope, permanently:
#   - migrations/ — shipped migrations are immutable (sqlx checksums them at
#     apply time; editing one, even a comment, crash-loops the gateway —
#     docs/agents/migrations.md). Their citations are frozen history.
#   - git history itself.
#
# Domain terms are NOT citations and never match: pipeline "Stage 4"
# (docs/architecture.md section 3), identity "Tier A/B/C"
# (docs/agents/identity.md), RFC/SEP numbers. The pattern only matches
# numbered plan/review tokens.
set -euo pipefail
cd "$(dirname "$0")/.."

# One ERE. This file scans itself like any other: every line below that
# necessarily contains a matching token (the regex, its per-family legend,
# the self-check sample) carries a citation-ok marker, so the script
# contributes zero to the scripts pin and a NEW citation added here still
# trips the ratchet.
# Families:
#   AERB                      review-bot finding citations ("AERB #313")  citation-ok: pattern legend
#   Phase[ -][0-9]            plan phases ("Phase 8", "pre-Phase-1b")  citation-ok: pattern legend
#   WS[0-9]                   workstreams ("WS9-B", test ids like WS13B_*)  citation-ok: pattern legend
#   Tier [0-9]                review tiers (identity tiers are lettered)
#   PR ?#[0-9]                forge PR citations ("PR #92")  citation-ok: pattern legend
#   boundary + (PR|pr)[ ]?[0-9]  plan-PR ids ("PR8-d", "PR 1b", "PR 1.2",  citation-ok: pattern legend
#                             fn pr9_state); the boundary class excludes  citation-ok: pattern legend
#                             base64/hex runs and identifiers merely
#                             containing "pr".
#   boundary + PR-[A-Z0-9]    lettered/numbered plan-PR ids ("PR-C5",  citation-ok: pattern legend
#                             "PR-S3", "EMA PR-5", "PR-2b"); uppercase-or-  citation-ok: pattern legend
#                             digit after the hyphen keeps lowercase infra
#                             names ("pr-review", "PR-only", "PR-time") out.
#   base64-bnd + D[0-9][a-z]  dashboard design-phase codes ("D1a", "D6a",  citation-ok: pattern legend
#                             "D1b"); the base64-aware boundary excludes a  citation-ok: pattern legend
#                             hash fragment like the "/D4t" inside a sha512.
#   boundary + "PR " + [A-Z]  bare lettered plan ids ("policy-edit PR B",  citation-ok: pattern legend
#     + non-letter            "PR C:", "(PR C/E)"); the letter must be  citation-ok: pattern legend
#                             standalone — a trailing letter means a word
#                             ("PR Build") or acronym ("PR CI"), left out.
PAT='AERB|Phase[ -][0-9]|WS[0-9]|Tier [0-9]|PR ?#[0-9]|(^|[^A-Za-z0-9_+/=])(PR|pr) ?[0-9]|(^|[^A-Za-z0-9_])PR-[A-Z0-9]|(^|[^A-Za-z0-9_+/=])D[0-9][a-z]|(^|[^A-Za-z0-9_])PR [A-Z]([^A-Za-z]|$)' # citation-ok: the pattern itself

# Scanner self-checks: a pattern edit that stops matching the known-bad
# sample (or starts matching the known-good one) makes every pin vacuous.
# (The sample string the printf emits carries no citation-ok, so the
# self-check exercises the real match path.)
if ! printf 'fixed per AERB finding in Phase 3\n' | grep -qE "$PAT"; then # citation-ok: known-bad sample
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern no longer matches a known citation" >&2
    exit 2
fi
if printf 'Stage 4 authorizes via Cedar; Tier A token exchange\n' | grep -qE "$PAT"; then
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern matches domain terms it must not" >&2
    exit 2
fi
# The widened forms (PR-<digit>, D<digit><letter> design codes) must match.
if ! printf 'built-in tools since PR-5; the D1a tenant selector\n' | grep -qE "$PAT"; then # citation-ok: known-bad sample
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern no longer matches PR-<digit>/D-code forms" >&2
    exit 2
fi
# Their near-misses must NOT: lowercase after the hyphen ("PR-only"/"PR-time")
# and a D-code preceded by a base64 char (a sha512 fragment) stay out.
if printf 'runs PR-only at PR-time; sha512 tail 9Q/D4tNAmW\n' | grep -qE "$PAT"; then
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern matches lowercase-PR/base64 forms it must not" >&2
    exit 2
fi
# Bare lettered plan ids ("policy-edit PR B", "PR C:") must match; a trailing  citation-ok: self-check doc
# letter (word "PR Build", acronym "PR CI") must keep them out.
if ! printf 'the policy-edit PR B segmenter; PR C: enrichment\n' | grep -qE "$PAT"; then # citation-ok: known-bad sample
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern no longer matches bare PR-letter plan ids" >&2
    exit 2
fi
if printf 'PR CI gates the PR Build step\n' | grep -qE "$PAT"; then
    echo "check-no-plan-citations: FAIL — scanner self-check: pattern matches PR-word/PR-acronym it must not" >&2
    exit 2
fi

count_group() {
    # Token OCCURRENCES under $1, not matching lines: -h strips filename
    # prefixes (a token in a path never counts), the citation-ok filter
    # drops marked lines whole, then -o splits the survivors into one
    # match per line so two tokens on one line count as two. grep exits 1
    # on zero matches; that is a valid count, not an error.
    { grep -rhE "$PAT" "$1" 2>/dev/null || true; } \
        | { grep -v 'citation-ok' || true; } \
        | { grep -oE "$PAT" || true; } \
        | wc -l | tr -d ' '
}

fail=0
PINNED=" "
pin() {
    local path="$1" expected="$2" n
    PINNED="$PINNED$path "
    if [ ! -e "$path" ]; then
        echo "check-no-plan-citations: FAIL — pinned group $path missing (update the pin if it moved)" >&2
        fail=1
        return
    fi
    n=$(count_group "$path")
    if [ "$n" -gt "$expected" ]; then
        echo "check-no-plan-citations: FAIL — $path has $n citation tokens (pin $expected)." >&2
        echo "  Comments state the constraint itself; plan/review citations decode to nothing" >&2
        echo "  a reader can reach. Remove the token (keep the reason), or for a genuine" >&2
        echo "  false positive append 'citation-ok: <why>' on the line. Offending lines:" >&2
        { grep -rEn "$PAT" "$path" 2>/dev/null || true; } \
            | { grep -v 'citation-ok' || true; } | head -15 | sed 's/^/    /' >&2
        fail=1
    elif [ "$n" -lt "$expected" ]; then
        echo "check-no-plan-citations: FAIL — $path is down to $n citation tokens (pin $expected)." >&2
        echo "  Good — lower the pin for $path to $n in this PR so the ratchet holds." >&2
        fail=1
    fi
}

# --- Exact pins (token occurrences; regenerated when the pattern widened ----
# --- to catch dotted and lettered plan-PR ids; each sweep PR lowers its -----
# --- groups) -----------------------------------------------------------------
pin crates/waygate-admin            0
pin crates/waygate-agent            0
pin crates/waygate-agent-runtime    0
pin crates/waygate-apikeys          0
pin crates/waygate-as               0
pin crates/waygate-authz            0
pin crates/waygate-catalog          0
pin crates/waygate-changeset        0
pin crates/waygate-core             0
pin crates/waygate-dashboard-stores 0
pin crates/waygate-evidence         0
pin crates/waygate-federation       0
pin crates/waygate-invocation       0
pin crates/waygate-llm-credentials  0
pin crates/waygate-llm-dispatch     0
pin crates/waygate-llm-translate    0
pin crates/waygate-manifest-store   0
pin crates/waygate-manifest-types   0
pin crates/waygate-mcp              0
pin crates/waygate-oidc             0
pin crates/waygate-policy           0
pin crates/waygate-quota            0
pin crates/waygate-rbac             0
pin crates/waygate-scim             0
pin crates/waygate-server           0
pin crates/waygate-storage          0
pin crates/waygate-telemetry        0
pin crates/waygate-tenants          0
pin crates/waygate-test-support     0
pin crates/waygate-upstream         0
pin crates/waygate-test-client          0
pin scripts                         0
pin .github                         0

# Completeness: every workspace crate is either pinned above or clean. A new
# crate starts at zero — there is no pin to add, only an invariant to keep.
for d in crates/*/; do
    d=${d%/}
    case "$PINNED" in
        *" $d "*) ;;
        *)
            n=$(count_group "$d")
            if [ "$n" -ne 0 ]; then
                echo "check-no-plan-citations: FAIL — unpinned crate $d has $n citation tokens; new crates start clean." >&2
                { grep -rEn "$PAT" "$d" 2>/dev/null || true; } \
                    | { grep -v 'citation-ok' || true; } | head -10 | sed 's/^/    /' >&2
                fail=1
            fi
            ;;
    esac
done

[ "$fail" -eq 0 ] || exit 1
echo "check-no-plan-citations: OK (all groups at their exact pins; sweep PRs lower pins toward zero)"
