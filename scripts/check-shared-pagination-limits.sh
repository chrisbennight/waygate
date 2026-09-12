#!/usr/bin/env bash
# Fail if a crate redefines the shared pagination limits instead of using
# waygate_core::page. Fast, compile-free CI tripwire (image.yml).
#
# Pagination defaults and ceilings are defined by waygate_core::page.
# Deliberate overrides are allowed but must be the EXPLICIT, commented
# exceptions listed here — add to this allow-list only with a comment in
# the source explaining why the surface diverges:
#   - waygate-storage/src/agent_conversations.rs (cap 200: rows carry
#     full message bodies)
#   - waygate-dashboard-stores/src/scim_provisioning_log.rs (timestamp-cursor pager,
#     i64 limit)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allowed=(
  "crates/waygate-core/src/page.rs"
  "crates/waygate-storage/src/agent_conversations.rs"
  "crates/waygate-dashboard-stores/src/scim_provisioning_log.rs"
)

hits="$(grep -rnE 'const[[:space:]]+(MAX_LIST_LIMIT|DEFAULT_LIST_LIMIT|DEFAULT_PAGE_LIMIT)' \
  "$repo_root/crates" --include='*.rs' || true)"
for a in "${allowed[@]}"; do
  hits="$(echo "$hits" | grep -v "$a" || true)"
done

if [ -n "$hits" ]; then
  {
    echo "ERROR: pagination limit const redefined outside waygate_core::page —"
    echo "use/re-export waygate_core::page::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT},"
    echo "or (for a genuinely different cap) add a commented override AND extend"
    echo "the allow-list in this script:"
    echo "$hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

# Local `fn default_limit` definitions were the other drift source (ten
# copies before consolidation) — serde defaults now point at
# waygate_core::page::default_list_limit{,_i64}. Deliberate different
# defaults are the commented, allow-listed exceptions:
#   - waygate-admin/src/catalog.rs (100: primary browse surface)
#   - waygate-admin/src/audit_verify.rs (1000: verification batches)
fn_allowed=(
  "crates/waygate-core/src/page.rs"
  "crates/waygate-admin/src/catalog.rs"
  "crates/waygate-admin/src/audit_verify.rs"
)
fn_hits="$(grep -rnE '(^|[[:space:]])fn[[:space:]]+default_limit[[:space:](<]' \
  "$repo_root/crates" --include='*.rs' || true)"
for a in "${fn_allowed[@]}"; do
  fn_hits="$(echo "$fn_hits" | grep -v "$a" || true)"
done

if [ -n "$fn_hits" ]; then
  {
    echo "ERROR: local fn default_limit outside waygate_core::page —"
    echo "point the serde default at waygate_core::page::default_list_limit"
    echo "(or _i64), or add a commented override AND extend fn_allowed here:"
    echo "$fn_hits" | sed 's/^/  /'
  } >&2
  exit 1
fi

echo "check-shared-pagination-limits: OK (limits + default_limit fns defined only in waygate-core + allow-listed overrides)"
