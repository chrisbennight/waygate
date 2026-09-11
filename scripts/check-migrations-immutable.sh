#!/usr/bin/env bash
# Fail a PR that MODIFIES or DELETES a migration file that already exists on the
# base branch. Already-applied migrations are immutable: sqlx hashes every file
# under migrations/ (SHA-384) and stores the checksum in `_sqlx_migrations` at
# apply time, so ANY later edit — including a comment-only change — invalidates
# that checksum and the gateway refuses to boot with
#   migration <N> was previously applied but has been modified
# Only ADDING new migration files is allowed.
#
# Why it exists: on 2026-06-20, a stale comment inside
# migrations/0025_rate_limits.sql was flagged during review; the "fix"
# rewrote that comment in place. The bytes changed, the checksum changed,
# and the next deploy crash-looped in prod. (This is a recurring failure
# class: any comment-only edit to a shipped migration invalidates its sqlx
# checksum.) The fix is to never edit a shipped migration — document
# semantic clarifications in the Rust handler that reads the column, or in
# docs/, instead.
#
# Why CI was previously blind to it: the *_pg test suites self-migrate against a
# FRESH, empty Postgres every run, which has no prior _sqlx_migrations rows, so a
# checksum mismatch (a property of already-deployed state) can never surface
# there. check-migrations.sh and the waygate-storage `migration_versions` test
# only catch duplicate version NUMBERS, not content drift. This guard closes that
# gap with a git diff against the base branch.
#
# PR-only by design: it compares HEAD against the merge-base with the base
# branch, so it is meaningful only when base != head. On push-to-main (HEAD is
# the base) the diff is empty. Image CI invokes the guard for both events.
#
# Usage:
#   check-migrations-immutable.sh [BASE_REF]   # real check (CI / local)
#   check-migrations-immutable.sh --self-test  # exercise the classifier logic
#
# BASE_REF defaults to $GITHUB_BASE_REF (set by Gitea/GitHub on pull_request),
# then "main". Requires full history (checkout with fetch-depth: 0).
set -euo pipefail

mig_dir_prefix="migrations/"

# Read `git diff --no-renames --name-status` lines on stdin and print the ones
# that violate immutability: any change to a migrations/*.sql file that is NOT a
# pure addition (status A). M (modified) and D (deleted) are violations; with
# --no-renames a rename is reported as D(old)+A(new), so the D still trips. Files
# outside migrations/ and non-.sql files (e.g. a README) are ignored — sqlx only
# embeds and hashes the .sql files.
classify_violations() {
  awk -F'\t' -v pfx="$mig_dir_prefix" '
    index($2, pfx) != 1 { next }   # path must be under migrations/
    $2 !~ /\.sql$/      { next }   # only embedded .sql files are hashed
    $1 == "A"           { next }   # adding a new migration is allowed
    { printf "  %s\t%s\n", $1, $2 }
  '
}

self_test() {
  local input expected got status=0
  input=$'A\tmigrations/0099_new_feature.sql
M\tmigrations/0025_rate_limits.sql
D\tmigrations/0010_old.sql
M\tmigrations/README.md
A\tmigrations/0100_another.sql
M\tcrates/waygate-storage/src/audit.rs'
  # Expect exactly the M on 0025 and the D on 0010 to be flagged; the addition,
  # the non-.sql README, the non-migrations source file, and the second addition
  # must all pass through clean.
  expected=$'  M\tmigrations/0025_rate_limits.sql
  D\tmigrations/0010_old.sql'
  got="$(printf '%s\n' "$input" | classify_violations)"
  if [ "$got" != "$expected" ]; then
    echo "self-test FAILED" >&2
    echo "--- expected ---" >&2; printf '%s\n' "$expected" >&2
    echo "--- got ---" >&2;      printf '%s\n' "$got" >&2
    status=1
  fi
  # A clean diff (only additions / unrelated files) must yield no violations.
  got="$(printf 'A\tmigrations/0099_new.sql\nM\tCargo.toml\n' | classify_violations)"
  if [ -n "$got" ]; then
    echo "self-test FAILED: clean diff flagged: $got" >&2
    status=1
  fi
  if [ "$status" -eq 0 ]; then
    echo "check-migrations-immutable: self-test OK"
  fi
  return "$status"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

base_ref="${1:-${GITHUB_BASE_REF:-main}}"

# Resolve the base commit. Prefer the existing remote-tracking ref; otherwise
# fetch the base branch (the checkout may not have set up origin/<base>). Fail
# loud rather than vacuously passing if the base can't be found — a guard that
# silently compares against nothing is worse than no guard.
base_commit=""
if base_commit="$(git rev-parse --verify --quiet "origin/${base_ref}^{commit}")"; then
  :
elif git fetch --no-tags --quiet origin "$base_ref" 2>/dev/null; then
  base_commit="$(git rev-parse --verify FETCH_HEAD^{commit})"
elif base_commit="$(git rev-parse --verify --quiet "${base_ref}^{commit}")"; then
  :
else
  echo "check-migrations-immutable: cannot resolve base ref '$base_ref'." >&2
  echo "  In CI, checkout with fetch-depth: 0 so the base branch is available." >&2
  exit 2
fi

merge_base="$(git merge-base "$base_commit" HEAD)"

violations="$(
  git diff --no-renames --name-status "$merge_base" HEAD -- "$mig_dir_prefix" \
    | classify_violations
)"

if [ -n "$violations" ]; then
  {
    echo "ERROR: this PR modifies or deletes already-shipped migration(s):"
    echo "$violations"
    echo
    echo "Migrations under migrations/ are IMMUTABLE once they exist on '${base_ref}'."
    echo "sqlx hashes each file and records the checksum in _sqlx_migrations at"
    echo "apply time; editing a shipped file (even a comment) makes the gateway"
    echo "refuse to boot: 'migration <N> was previously applied but has been"
    echo "modified'. To clarify a migration's semantics after it ships, edit the"
    echo "Rust handler that reads the column, or docs/ — never the migration SQL."
    echo "To change the schema, add a NEW migration with the next version number."
    echo "See docs/agents/migrations.md."
  } >&2
  exit 1
fi

echo "check-migrations-immutable: OK (no shipped migration modified vs ${base_ref})"
