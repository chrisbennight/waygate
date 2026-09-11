#!/usr/bin/env bash
# CI ratchet: boot-time env parsing in waygate-server's
# config.rs migrates to the typed waygate_core::env helpers (reject-at-boot,
# never clamp; uniform operator messages with per-var hints). The raw
# `std::env::var(` count may only DECREASE — the 16-var duration family has
# already been converted; the remaining families (bools, sizes,
# string-enums) migrate incrementally. Lower MAX_RAW here in the same PR as each migration.
# A new raw read fails: use waygate_core::env (extend it if the family
# doesn't exist yet).
#
# RESTING FLOOR: the remaining raw reads are (a) plain
# string/path/URL lookups with no parse/default/range logic, and (b)
# intentional bespoke parsers — string-enum vars (GATEWAY_AUTH_MODE,
# GATEWAY_AUDIT_MODE, GATEWAY_DEPLOYMENT_PROFILE) whose match arms carry
# error text naming the valid values, and the keyring family
# (GATEWAY_UPSTREAM_TOKEN_KEY_* / GATEWAY_IDENTITY_JWT_*) with its
# paired-var validation. A typed reader for either would obscure, not
# dedup. The families with shared logic (durations, bools, ranged
# integers) are fully migrated.
set -euo pipefail
cd "$(dirname "$0")/.."

MAX_RAW=58
FILE=crates/waygate-server/src/config.rs
if [ ! -f "$FILE" ]; then
    echo "check-env-parsing: FAIL — $FILE missing" >&2
    exit 2
fi
# These transitional inputs were retired with the baked-manifest boot path.
# Keep their names out of runtime source regardless of whether a future parser
# would use a raw read or a typed helper.
for retired_var in GATEWAY_IMPORT_ON_BOOT GATEWAY_SERVERS_BAKED_DIR; do
    if grep -R -n --include='*.rs' "$retired_var" crates/waygate-server/src; then
        echo "check-env-parsing: FAIL — retired env var $retired_var reintroduced" >&2
        exit 1
    fi
done
# Positive control: the helpers must be in use (a refactor that dropped them
# would make an empty grep meaningless).
if ! grep -q 'waygate_core::env::duration_secs' "$FILE"; then
    echo "check-env-parsing: FAIL — scanner self-check failed (no waygate_core::env call in $FILE); refusing to report a vacuous OK" >&2
    exit 2
fi
count=$(grep -o 'std::env::var(' "$FILE" | wc -l | tr -d ' ')
if [ "$count" -gt "$MAX_RAW" ]; then
    echo "check-env-parsing: FAIL — $count raw std::env::var( sites in $FILE (ceiling $MAX_RAW)" >&2
    echo "Use waygate_core::env's typed readers instead of a raw read." >&2
    exit 1
fi
echo "check-env-parsing: OK ($count raw env reads <= ceiling $MAX_RAW; remaining reads are plain strings or bespoke enum/keyring parsers, raw by design)"

# --- Section 2: GATEWAY_* env reads outside config.rs ------
#
# New GATEWAY_* boot configuration belongs in waygate-server/src/config.rs,
# parsed through waygate_core::env's typed readers — not scattered across
# handlers and spawn sites. This section pins the EXACT per-file count of
# `env::var("GATEWAY_` occurrences outside config.rs, so drift in either
# direction fails:
#   - a new file or an increased count  → route the read through config.rs;
#   - a decreased count or removed file → good, lower the pin in the same PR
#     (an exact pin, unlike a ceiling, also catches a pinned file being
#     renamed out of the sweep).
#
# Test paths (*/tests/*, */tests.rs) are excluded: save/restore harnesses and
# pg skip-preambles read env as part of the test fixture, a different class
# from production config reads.
#
# Known limitation (shared by every tripwire in scripts/): indirect reads —
# `env::var(some_variable)` where the name is operator-supplied (manifest
# bearer_env, GATEWAY_LLM_CRED_RELOAD key names) — are dynamic by design and
# invisible to a literal grep. This guard stops regeneration-by-pattern, not
# adversarial evasion.
if [ ! -d crates ]; then
    echo "check-env-parsing: FAIL — crates/ missing (section 2 scan dir)" >&2
    exit 2
fi
expected_pins() {
    # "count path", sorted by path. Lower a count in the same PR that
    # migrates its reads into config.rs / waygate_core::env.
    #
    # RESTING FLOOR: the pinned reads are (a) plain string/path
    # lookups (STATIC_DIR, LISTEN_ADDR, REPLICA_ID, LOG_LEVEL, EGRESS_PROXY),
    # (b) domain parsers (CHANGE_SECRET_KEY's fail-loud key decode, the
    # LLM_DISCOVERY / LLM_CRED_RELOAD target lists, the CHANGE_FEED_ACTIONS
    # CSV), and (c) grammars pinned by contract — the `== "on"` redaction
    # family (upgrade-stability comment at the site), the pool strict flag
    # (its test pins `yes` ⇒ false), and the pool size's documented clamp.
    # The silent-default numeric/bool families are fully migrated.
    cat <<'PINS'
1 crates/waygate-admin/src/dashboard.rs
1 crates/waygate-server/src/healthcheck.rs
1 crates/waygate-server/src/llm.rs
8 crates/waygate-server/src/main.rs
1 crates/waygate-server/src/reload.rs
1 crates/waygate-telemetry/src/lib.rs
3 crates/waygate-upstream/src/pool/mod.rs
PINS
}
gw_files=""
gw_status=0
gw_files=$(grep -rl 'env::var("GATEWAY_' crates/ --include='*.rs' 2>&1) || gw_status=$?
if [ "$gw_status" -gt 1 ]; then
    echo "check-env-parsing: FAIL — grep error scanning crates/ (section 2): $gw_files" >&2
    exit 2
fi
actual=""
for f in $gw_files; do
    case "$f" in
        crates/waygate-server/src/config.rs) continue ;;
        */tests/*|*/tests.rs) continue ;;
    esac
    n=$(grep -o 'env::var("GATEWAY_' "$f" | wc -l | tr -d ' ')
    actual="${actual}${n} ${f}
"
done
actual=$(printf '%s' "$actual" | sort -k2)
expected=$(expected_pins)
# Positive control: the pin table is non-empty, so an empty sweep can only
# mean the grep went blind — the mismatch below fails rather than passing.
if [ "$actual" != "$expected" ]; then
    echo "check-env-parsing: FAIL — GATEWAY_* env reads outside config.rs drifted from the pin table" >&2
    echo "--- expected (pin table)" >&2
    printf '%s\n' "$expected" >&2
    echo "--- actual" >&2
    printf '%s\n' "$actual" >&2
    echo "Increase/new file: move the read into crates/waygate-server/src/config.rs via waygate_core::env typed readers." >&2
    echo "Decrease/removed file: lower the pin table in scripts/check-env-parsing.sh in this PR." >&2
    exit 1
fi
gw_total=$(printf '%s\n' "$actual" | awk '{s+=$1} END {print s}')
echo "check-env-parsing: OK (section 2: $gw_total GATEWAY_* reads outside config.rs match the pin table exactly)"
