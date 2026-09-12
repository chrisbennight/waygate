#!/usr/bin/env bash
# Fail if the workspace migrations/ directory holds more than one file per sqlx
# version (the leading NNNN_ integer). Fast, compile-free mirror of the
# waygate-storage `migration_versions` test, run as the first image CI step
# so a duplicate fails in seconds with a clear message — not buried in
# cargo-test output and not at prod boot.
#
# Intentionally redundant with the Rust test: this gate still fires if the test
# crate fails to compile for an unrelated reason, and runs without a toolchain.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mig_dir="$repo_root/migrations"

[ -d "$mig_dir" ] || {
  echo "check-migrations: migrations dir not found at $mig_dir" >&2
  exit 2
}

dupes="$(
  for f in "$mig_dir"/*.sql; do
    base="$(basename "$f")"
    printf '%s\t%s\n' "${base%%_*}" "$base"
  done | awk -F'\t' '
    # Key by the prefix coerced to a number ($1 + 0) so this matches the Rust
    # guard, which parses the prefix as i64: 0045 and 45 are the same version.
    { v = $1 + 0; files[v] = (files[v] == "" ? $2 : files[v] ", " $2); n[v]++ }
    END { for (v in n) if (n[v] > 1) printf "  %04d: %s\n", v, files[v] }
  ' | sort
)"

if [ -n "$dupes" ]; then
  {
    echo "ERROR: duplicate migration version(s) under migrations/."
    echo "sqlx collides on the _sqlx_migrations version key at boot."
    echo "Renumber so each version maps to exactly one file:"
    echo "$dupes"
  } >&2
  exit 1
fi

echo "check-migrations: OK ($(find "$mig_dir" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ') migrations, unique versions)"
