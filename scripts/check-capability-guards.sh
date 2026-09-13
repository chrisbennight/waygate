#!/usr/bin/env bash
# CI tripwire: admin availability guards go through
# waygate_admin::capability::Capability (`require()` / `get()` /
# `unavailable_msg()`), never a fresh inline availability-message literal.
# Covers the four literal shapes: ApiError::ServiceUnavailable (REST),
# ReadError::Unavailable (resource_catalog), ExecError::Unavailable
# (change executor), and scim_503 (SCIM protocol bodies) — SCIM sites pass
# unavailable_msg(), never a literal. Feature flags (api-keys runtime,
# policy editing) are waygate_admin::capability::Feature values whose
# canonical messages also live off-literal.
# The canonical unavailable-message per capability lives in AdminState::new;
# 107 hand-typed copies predated the consolidation and had drifted ("audit
# store" vs "audit reader" for the same field).
#
# A small allow-list remains, each for a stated reason:
#   - runtime check-FAILURE 503s (scope/group catalog check failed) — the
#     store is present, the call failed; not an availability guard.
#   - one contextual retention message in audit_sweep.rs that carries extra
#     operator guidance beyond the canonical string.
#   - servers_dir and policies_dir are config values (Option<PathBuf>), not
#     capabilities.
#   - one unit test asserting err_message() passthrough.
# Anything else fails: use `state.<capability>.require()` or reuse
# `unavailable_msg()` instead of minting a new literal.
#
# Scanner discipline: plain grep only (present on
# every runner; no rg dependency), and a scanner ERROR — as distinct from
# "no matches" — fails the script loudly instead of reporting a vacuous OK.
set -euo pipefail
cd "$(dirname "$0")/.."

PAT='(ApiError::ServiceUnavailable|ReadError::Unavailable|ExecError::Unavailable|scim_503)'
SCAN_DIRS=(crates/waygate-admin/src crates/waygate-server/src)

# Scanner self-checks, portable across grep variants (BSD grep exits 1 for a
# missing directory — same as "no matches" — so exit-code routing alone can't
# distinguish "clean" from "didn't scan"):
#   1. every scan directory must exist;
#   2. positive control — the pattern MUST match capability.rs's own unit
#      test literal; a scanner/pattern breakage that would otherwise produce
#      a vacuous empty result fails here instead.
for d in "${SCAN_DIRS[@]}"; do
    if [ ! -d "$d" ]; then
        echo "check-capability-guards: FAIL — scan directory missing: $d; refusing to report a vacuous OK" >&2
        exit 2
    fi
done
if ! grep -qE "${PAT}\\(\"" crates/waygate-admin/src/capability.rs; then
    echo "check-capability-guards: FAIL — scanner self-check failed (canary literal in capability.rs not found); refusing to report a vacuous OK" >&2
    exit 2
fi

# grep exit codes: 0 = hits, 1 = no hits, >1 = scanner error. Under `set -e`
# a bare failing grep aborts the script with no message, and `|| true` would
# mask a real error as "clean" — so capture the code and route on it.
scan_to() {
    local out_file=$1
    shift
    local code=0
    grep -rnE --include='*.rs' "$@" "${SCAN_DIRS[@]}" >>"$out_file" || code=$?
    if [ "$code" -gt 1 ]; then
        echo "check-capability-guards: FAIL — scanner error (grep exit $code); refusing to report a vacuous OK" >&2
        exit 2
    fi
}

hits_file=$(mktemp)
trap 'rm -f "$hits_file"' EXIT

# Same-line literals: Shape("...
scan_to "$hits_file" -e "${PAT}\\(\""
# Multiline literals: Shape( at end of line; -A1 captures the next line, and
# the awk pass keeps the pair ONLY when that continuation opens a string
# literal — `Shape(\n  cap.unavailable_msg(),\n)` is the sanctioned canonical
# form, not a literal, and must not trip. Context lines arrive as
# file-NN-content (dashes, not colons), which the allow-list's `\.rs.*`
# patterns span.
multi_file=$(mktemp)
trap 'rm -f "$hits_file" "$multi_file"' EXIT
scan_to "$multi_file" -A1 -e "${PAT}\\($"
awk '
    /^--$/ { held = ""; next }
    /^[^[:space:]][^:]*:[0-9]+:/ { held = $0; next }
    {
        if (held != "" && $0 ~ /-[0-9]+-[[:space:]]*"/) { print held; print $0 }
        held = ""
    }
' "$multi_file" >>"$hits_file"

hits=$(grep -vE '^(--)?$' "$hits_file" \
    | grep -v '^crates/waygate-admin/src/capability\.rs[:-]' || true)

allowed_patterns=(
    # These failures occur after the tool-review capability is configured:
    # a database operation failed or the upstream could not refresh.
    'crates/waygate-admin/src/tool_reviews\.rs.*Tool review storage is unavailable'
    'crates/waygate-admin/src/tool_reviews\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/tool_reviews\.rs.*Refresh the upstream successfully before accepting its replacement'
    'crates/waygate-admin/src/api_keys\.rs.*scope catalog check failed'
    'crates/waygate-admin/src/api_keys\.rs.*group catalog check failed'
    # Skill services are configured here; the runtime store call, initial tenant
    # observation, or exact Git revision lookup failed. Keep actionable 503s.
    'crates/waygate-admin/src/skill_reviews\.rs.*Skill review storage is unavailable'
    'crates/waygate-admin/src/skill_reviews\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/skill_reviews\.rs.*The skill has not yet been observed for this tenant'
    'crates/waygate-admin/src/skill_reviews\.rs.*The exact candidate revision is unavailable; approval was not recorded'
    'crates/waygate-admin/src/audit_sweep\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/audit_sweep\.rs.*retention store not configured \(cannot resolve cutoff'
    'crates/waygate-admin/src/manifest_bundles\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/manifest_bundles\.rs.*manifest servers_dir is not configured'
    'crates/waygate-admin/src/policy_bundles\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/policy_bundles\.rs.*policy policies_dir is not configured'
    'crates/waygate-admin/src/api_key_profiles_section\.rs.*ApiError::ServiceUnavailable\($'
    'crates/waygate-admin/src/api_key_profiles_section\.rs.*profile store not configured'
    # scim_503 plumbing, not literals: the fn definitions and the
    # unavailable_msg() call form.
    'crates/waygate-admin/src/scim_(users|groups)\.rs.*fn scim_503\(detail: &str\)'
    'crates/waygate-admin/src/scim_(users|groups)\.rs.*scim_503\(state\.'
)

bad=""
while IFS= read -r line; do
    [ -z "$line" ] && continue
    ok=0
    for pat in "${allowed_patterns[@]}"; do
        if echo "$line" | grep -qE "$pat"; then
            ok=1
            break
        fi
    done
    [ "$ok" -eq 0 ] && bad+="$line"$'\n'
done <<<"$hits"

if [ -n "$bad" ]; then
    echo "check-capability-guards: FAIL — inline availability-guard literal(s) outside capability.rs:" >&2
    printf '%s' "$bad" | sed 's/^/  /' >&2
    echo "Use state.<capability>.require() (REST) / .get() + unavailable_msg() (other error shapes)." >&2
    echo "The canonical message lives in AdminState::new. Genuinely-new categories: extend the" >&2
    echo "allow-list here with a stated reason." >&2
    exit 1
fi
echo "check-capability-guards: OK (availability guards confined to waygate_admin::capability)"
