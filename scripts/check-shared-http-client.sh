#!/usr/bin/env bash
# Fail if any crate constructs a reqwest client builder directly instead of
# going through waygate_core::http_client. Fast, compile-free CI tripwire
# (image.yml).
#
# Why it exists: before consolidation, ~14 call sites each hand-rolled
# `reqwest::Client::builder()` with
# drifting total timeouts (5s/10s/15s/30s) and three copies of the gateway
# user-agent string (one misspelled variant). The factory
# (`waygate_core::http_client::{builder, client, Profile}`) owns the
# user-agent and the named total-timeout tiers; callers layer site-specific
# settings (mTLS identity, redirect policy, proxies) on the returned builder.
#
# `tests/` integration dirs are exempt (harnesses may build bespoke clients).
# In-source tests use the factory unless they define the narrow, individually
# `#[cfg(test)]`-gated `raw_test_http_client` helper; that helper documents why
# the test must remain independent of gateway policy and is the only
# direct-default exemption.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed="crates/waygate-core/src/http_client.rs"
pattern='\bClient::(builder|new|default)\(|\bClientBuilder::new\(|reqwest::(Client|ClientBuilder)[[:space:]]+as[[:space:]]|=[[:space:]]*reqwest::(Client|ClientBuilder)[[:space:]]*;|:[[:space:]]*(reqwest::)?Client[[:space:]]*=[[:space:]]*Default::default\('

# Match builder construction under the spellings that occur in practice —
# fully qualified (`reqwest::Client::builder()`), via a `use
# reqwest::Client;` import (bare `Client::builder()` would otherwise evade
# the fully-qualified pattern above), `ClientBuilder::new()`, or hidden
# behind an alias (`use reqwest::Client as HttpClient;` / `type X =
# reqwest::Client;` — only the alias DECLARATION is caught, not every call
# site that later uses the alias). Deliberately best-effort against
# adversarial evasion — code review owns that tail. Exempt: comment lines
# (docs may cite the pattern), `tests/` harnesses, and the standalone client
# binaries `waygate-test-client` and `waygate-files-helper`. Neither runs inside the
# gateway: the first is a client SIMULATOR whose whole job is building bespoke
# clients, the second is a helper shipped to end users. Their traffic must not
# carry the gateway's user-agent, and routing them through the factory would
# make a distributed CLI depend on server-side policy it does not share.
is_allowed_raw_test_client() {
  local cfg_line="$1"
  local fn_line="$2"
  local construction_line="$3"

  [[ "$cfg_line" =~ ^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$ ]] \
    && [[ "$fn_line" =~ ^[[:space:]]*fn[[:space:]]+raw_test_http_client\(\)[[:space:]]*-\>[[:space:]]*reqwest::Client[[:space:]]*\{[[:space:]]*$ ]] \
    && [[ "$construction_line" =~ ^[[:space:]]*reqwest::Client::new\(\)[[:space:]]*//[[:space:]]*A[[:space:]]+raw[[:space:]]+test[[:space:]]+client[[:space:]]+.+$ ]]
}

candidates="$(
  grep -rnE "$pattern" \
    "$repo_root/crates" --include='*.rs' \
    | grep -v "$allowed" \
    | grep -v '/tests/' \
    | grep -v 'crates/waygate-test-client/' \
    | grep -v 'crates/waygate-files-helper/' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
)"

hits=""
while IFS=: read -r file line source; do
  [ -n "$file" ] || continue
  if [[ "$source" == *'reqwest::Client::new()'* ]] && [ "$line" -ge 3 ]; then
    cfg_line="$(sed -n "$((line - 2))p" "$file")"
    fn_line="$(sed -n "$((line - 1))p" "$file")"
    if is_allowed_raw_test_client "$cfg_line" "$fn_line" "$source"; then
      continue
    fi
  fi
  hits+="${file}:${line}:${source}"$'\n'
done <<< "$candidates"
hits="${hits%$'\n'}"

if [ -n "$hits" ]; then
  {
    echo "ERROR: direct reqwest client construction outside $allowed —"
    echo "use waygate_core::http_client::{builder, client} with a named Profile"
    echo "(Interactive/Standard/Slow) or Profile::Custom/NoTotalTimeout:"
    echo "$hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

# Keep a representative regression embedded in the guard itself: weakening the
# expression so `Client::new()` slips through must make the guard fail in CI.
if ! printf '%s\n' 'fn violation() { let _ = reqwest::Client::new(); }' | grep -Eq "$pattern"; then
  echo "ERROR: check-shared-http-client no longer detects reqwest::Client::new()" >&2
  exit 1
fi
if is_allowed_raw_test_client '' '' \
  'reqwest::Client::new() // A raw test client must not exempt production code.'; then
  echo "ERROR: a comment phrase bypasses the test-only direct-client exemption" >&2
  exit 1
fi
if ! is_allowed_raw_test_client '#[cfg(test)]' \
  'fn raw_test_http_client() -> reqwest::Client {' \
  '    reqwest::Client::new() // A raw test client isolates a wire test from gateway policy.'; then
  echo "ERROR: the narrow cfg(test) raw-client helper is no longer recognized" >&2
  exit 1
fi

echo "check-shared-http-client: OK (reqwest construction confined to waygate-core policy)"
