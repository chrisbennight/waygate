#!/usr/bin/env bash
# Comments and user-visible strings state constraints without internal review citations.
# Applied SQL migrations are excluded because their bytes are immutable.
set -euo pipefail
cd "$(dirname "$0")/.."

PAT='AERB|Phase[ -][0-9]|WS[0-9]|Tier [0-9]|PR ?#[0-9]|(^|[^A-Za-z0-9_+/=])(PR|pr) ?[0-9]|(^|[^A-Za-z0-9_])PR-[A-Z0-9]|(^|[^A-Za-z0-9_+/=])D[0-9][a-z]|(^|[^A-Za-z0-9_])PR [A-Z]([^A-Za-z]|$)' # citation-ok: the pattern itself

# Scanner self-checks: a pattern edit that stops matching the known-bad
# sample (or starts matching the known-good one) would make the check ineffective.
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

matches="$(mktemp)"
trap 'rm -f "$matches"' EXIT
status=0
grep -rInE --exclude-dir=node_modules --exclude-dir=target "$PAT" crates scripts .github > "$matches" || status=$?
if [ "$status" -gt 1 ]; then
    cat "$matches" >&2
    exit "$status"
fi
if grep -v 'citation-ok' "$matches"; then
    echo 'check-no-plan-citations: FAIL — remove internal review citations' >&2
    exit 1
fi
echo 'check-no-plan-citations: OK'
