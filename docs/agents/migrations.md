# Schema migrations

Rules for the `sqlx` migrations under [`migrations/`](../../migrations/). The
gateway applies them at boot from a single embedded set
(`sqlx::migrate!("../../migrations")`, see
[`crates/waygate-storage/src/audit.rs`](../../crates/waygate-storage/src/audit.rs)).
Two properties are required for safe upgrades: **migrations are immutable once shipped**, and **one file per
version**.

## The one rule that matters: shipped migrations are immutable

Once a migration file exists on `main`, treat it as frozen. **Never edit it —
not the schema, not even a comment.** To add or change schema, write a *new*
migration with the next version number.

### Why

`sqlx` computes a SHA-384 checksum over the entire file (bytes, comments and
all) and records it in the `_sqlx_migrations` table the first time the migration
is applied. On every subsequent boot it re-hashes the embedded file and compares.
If the bytes changed, the checksums differ and the gateway refuses to start:

```
Error: run audit migrations
Caused by: migrate: migration <N> was previously applied but has been modified
```

This is fatal and a crash-loop: the binary exits non-zero before serving, the
container restarts, and it fails the same way forever until the file is restored
to its applied bytes (or every deployed DB's checksum is surgically rewritten —
don't). Because the comment is part of the hash, a "harmless" doc-only edit is
just as fatal as a schema change.


### When clarification or a change is needed

Keep applied SQL unchanged, including its comments. Explain existing behavior
in the consuming Rust code or documentation. Change schema or stored data with
a new migration. Review findings do not override the checksum constraint.

## The other rule: one file per version

The sqlx version is the leading zero-padded integer (`NNNN_`). Two files sharing
it (`0042_a.sql`, `0042_b.sql`) collide on the `_sqlx_migrations` version key;
`sqlx::migrate!` embeds duplicates *without complaint*, so both PRs go green and
the gateway crash-loops after merge.

- **Pick the next number against the latest `main`, not your branch point** — and
  re-check after a rebase. Parallel branches can otherwise choose the same number.
- Use the four-digit `NNNN_<name>.sql` convention (keeps prefixes lexically
  sortable; the guard enforces the width).

## The guards (and the gap they fill)

Three checks enforce the two rules. They are deliberately layered — a fast
shell fail, a compile-path test, and a base-diff gate — because each catches a
case the others can't.

| Guard | Enforces | When it runs |
| --- | --- | --- |
| [`scripts/check-migrations.sh`](../../scripts/check-migrations.sh) | unique version numbers | source guards in `image.yml` (compile-free, seconds) |
| `migration_versions` test in [`waygate-storage`](../../crates/waygate-storage/src/migration_versions.rs) | unique version numbers + `NNNN_` naming | the workspace test suite — `cargo nextest run --workspace` in PR CI **and** the image build; plain `cargo test --workspace` locally |
| [`scripts/check-migrations-immutable.sh`](../../scripts/check-migrations-immutable.sh) | **no edit/delete of a shipped migration** | `image.yml` (meaningful on PR events) |

### Why the immutability guard is git-diff based, not a test

The `*_pg` test suites self-migrate against a **fresh, empty Postgres** every CI
run. An empty DB has no prior `_sqlx_migrations` rows, so sqlx applies every
migration from scratch and records whatever checksum the *current* files have —
a "previously applied but modified" mismatch is **structurally impossible**
there. Checksum drift is a property of *already-deployed* state, which an
ephemeral DB never has. So no amount of `cargo test` catches it.

`check-migrations-immutable.sh` instead diffs `migrations/` between `HEAD` and
the merge-base with the PR's base branch, and fails on any `M` (modified) or `D`
(deleted) of a `.sql` file — only additions (`A`) are allowed. That is the exact
shape of the violation, caught before merge. It compares against the base
branch; on push-to-`main`, where `HEAD` is the base, its comparison is empty.
The image workflow invokes it for both events and checks out full GitHub
history with `fetch-depth: 0`. Run it
locally with `bash scripts/check-migrations-immutable.sh [base-ref]`; its
classifier has a `--self-test`.

### Detection, not prevention

All three only *detect* — two parallel branches still each pass in isolation,
and a guard can't stop you typing an edit. The companion control is the repo's
**"branch up-to-date with `main` before merge"** rule: the second of two parallel
PRs must pull the other's migrations in first, at which point the relevant guard
trips in their CI and forces a renumber / revert instead of a prod break.

## Adding a migration — checklist

1. Name it `NNNN_<short_name>.sql` where `NNNN` is the next free version against
   the latest `main` (not your branch point).
2. Make it forward-only and idempotent where practical (`IF NOT EXISTS`, etc.).
3. Never touch an existing migration file in the same PR. Clarifying docs go in
   the Rust handler or `docs/`.
4. If you bump the test Postgres image, update `PG_IMAGE` in the image workflow
   so the database suites and image smoke use the same build. Deployment
   operators independently validate their selected database build.
5. Re-check the version number after any rebase.
