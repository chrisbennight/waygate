# AGENTS.md

Rules for agents (and humans) editing this repo. Keep this file short — deep
dives live under [`docs/agents/`](docs/agents/).

Deployment repositories carry their own orchestration, secret-injection, and
image-pinning conventions. They are consumers of this project rather than part
of its source or release boundary.

## Always work in a worktree

Every task in this repo starts by creating a git worktree off `main`. Do not
edit files in the primary checkout. This keeps concurrent tasks isolated and
prevents accidental cross-contamination between branches.

- Use the `EnterWorktree` tool (or `git fetch origin` then
  `git worktree add -b <branch> <path> origin/main`) before making any edits.
- Branch from freshly-fetched `origin/main`, never stale local `main` or
  whatever is checked out in the primary tree — the duplicate-`0042` migration
  incident (see Safe defaults) came from parallel branches numbering against
  stale bases.
- If the task is trivial enough that a worktree feels like overkill, it is
  still required — the overhead is small and the isolation is the point.
- Put worktrees under an ignored `.worktrees/` directory. After verifying a PR
  merged through the forge, remove only your own clean worktree and branch.
  Preserve unmerged work and never remove another contributor's checkout.

## Overview

Rust workspace. Builds into a single `gateway-server` binary plus a `classify`
CLI. Ships as a distroless image; deployment overlays choose a published image
and own their orchestration independently.

- **Non-goals:** no real `servers/` manifest set and no live `policies/` set in
  git (the in-repo sets are synthetic CI/test and local-evaluation examples;
  live sets are deployment state on the runtime volume; see
  `docs/server-config-source-of-truth.md`); no shell or package manager in the
  image (distroless, see Safe defaults); no secret *values* anywhere in the repo.
- **Risk tier: hardened.** This is the auth/authz boundary for every MCP tool
  call (OAuth 2.1 RS/AS, Cedar authorization, append-only audit), and a push to
  `main` publishes a release image that deployments may consume. CI gates
  block; shipped migrations are immutable; confirm before anything
  irreversible.
- Workspace manifest: [`Cargo.toml`](Cargo.toml) (resolver 2). **Dependencies
  are workspace-pinned:** add new deps at the workspace level, and prefer an
  existing workspace dep over introducing a new crate. Renovate manages bumps
  behind the GitHub container-update threat gate.
- Rust channel: [`rust-toolchain.toml`](rust-toolchain.toml). Do not bypass it.
- Entry point: [`crates/waygate-server/src/main.rs`](crates/waygate-server/src/main.rs).
- Wire protocol: `rmcp` (streamable HTTP; version pinned in `Cargo.toml`).
  SEP #1888 shapes are in
  [`crates/waygate-mcp/src/search_tools.rs`](crates/waygate-mcp/src/search_tools.rs).
- Auth modes: the gateway is always an OAuth 2.1 *resource server*. With
  `GATEWAY_AS_ENABLED=true` it *also* runs as its own Authorization Server
  (CIMD client registration, PKCE, no DCR) via
  [`crates/waygate-as/`](crates/waygate-as/). See `docs/agents/identity.md`.

## Commands you will run

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo check --workspace
```

CI runs all four; `-D warnings` means a new clippy lint blocks merge. Fix the
warning, don't `#[allow]` it without a note explaining why.

CI runs the test step through **cargo-nextest** (`cargo nextest run
--workspace --locked --profile ci`; profile in
[`.config/nextest.toml`](.config/nextest.toml), pinned runner version in
[`scripts/ensure-nextest.sh`](scripts/ensure-nextest.sh)) — it executes tests
from all binaries in parallel, where `cargo test` runs one binary at a time.
Plain `cargo test --workspace --locked` runs the identical test set and stays
the zero-setup local command; install the pinned nextest for CI-matching
runs. nextest does not execute doctests, so CI also runs
`cargo test --doc --workspace --locked` — a doctest you add runs there
(the workspace currently has none; `#[cfg(test)]` unit tests remain the
standard placement for runnable examples).

Wall-clock integration checks are opt-in, not required CI gates. Follow
[the timing and synchronization policy](docs/testing.md) when adding tests.

When touching `migrations/`, also run the two CI guards locally before push:
`scripts/check-migrations.sh` and `scripts/check-migrations-immutable.sh`
(see Safe defaults for why).

Local evaluation with no IdP:

```sh
POSTGRES_PASSWORD=dev docker compose up --build --wait
python3 examples/quickstart/check.py
```

The [quickstart](examples/quickstart/README.md) starts a working synthetic MCP
upstream and verifies a successful call and a policy refusal. The host listener
is loopback-only. A disposable test issuer grants anyone the demo identity;
never expose it or use it for production data. Real deployments supply their own
manifests and policies through persistent runtime volumes.

## Testing conventions

Follow [the contributor testing contract](CONTRIBUTING.md#validate-the-contract-you-change).
Test observable behavior, isolate external boundaries, and report skips
separately from passes. Tests provide review evidence for the PR's claims.
Use targeted mutation testing when it adds useful security or correctness
evidence. Repo-specific:

- **Deterministic CI.** Required tests must not depend on winning a scheduling
  race, short wall-clock deadlines, or sleeps that assume background work has
  finished. Use explicit synchronization, controlled clocks, and isolated
  state. Live concurrency stress, timing, and performance diagnostics are
  opt-in with `#[ignore]`, not part of required CI. Report them as skipped;
  never mask flakiness with retries or merely increase timing thresholds.
- **Exemplars to model on:** contract test — `waygate-mcp`
  `waygate_server.rs::list_meta_tools_emits_one_per_upstream` (pins the
  contract, not exact strings); violated-contract regressions — `waygate-admin`
  `upstream_sessions_api.rs::update_if_ciphertext_matches_refuses_to_resurrect_after_revoke`
  and `waygate-as` `oauth_flow_pg.rs::concurrent_refresh_rotates_exactly_once`
  + the refresh-replay tests (a revoked row stays gone; exactly one successor;
  a replayed token revokes the chain). `oauth_flow_pg.rs` is the breadth
  model: PKCE / redirect / expiry / unknown-token / replay / double-spend all
  asserted, not just the happy path.
- **The `*_pg` suites skip silently when their DB env var is unset**
  (`AUDIT_DATABASE_URL` for most; `GATEWAY_AS_DATABASE_URL` for `waygate-as`;
  new suites use `waygate_test_support::pg::pool_or_skip` instead of
  hand-rolling the preamble) — a bare local `cargo test` exercises none of the
  DB layer; treat a clean run with the env unset as "not run", not "passed".
  CI **provisions a live Postgres** in the `test` job of
  [the image workflow](.github/workflows/image.yml), so the suites run there.
- **The `*_pg` suites and image smoke MUST use the same Postgres build.** CI
  pins that build through the `PG_IMAGE` env in the image workflow so collation,
  types, and trigger semantics (the `audit_log` append-only triggers in
  particular) cannot diverge between source validation paths. **When you bump
  `PG_IMAGE`, keep source tests and image smoke on that same build.** Deployment
  operators independently select a supported database build and own validating
  their upgrade against this release.
- **Unit tests live in `#[cfg(test)] mod tests`** next to the code (how
  `waygate-core` is covered despite having no `tests/` crate); reserve the
  per-crate `tests/` integration crates for through-the-public-API /
  router-level checks.

## Commit / push / PR

- Respect the user's authorization for commits, pushes, PRs, and merges.
  Explicit authorization persists through a requested PR-and-monitor workflow;
  do not ask again for an already authorized action.
- Before every PR-branch push, check the forge and confirm the target PR is
  still open. A stale branch push does not update an already merged change.
- Prefer the connected forge's typed tools for issues, PRs, and Actions.
  Keep checkout, worktree, commit, and push operations in Git. Use structured
  arguments or body files for multiline text; never interpolate it into shell.
- Treat PR descriptions as immutable after creation — add a PR comment for
  corrections instead of editing the body.
- Development PRs live on GitHub. Migration issues and imported review evidence
  remain in the private Gitea tracker linked from [SUPPORT.md](SUPPORT.md).
- Request an AERB GitHub review explicitly after every push with the connected
  AERB service, then wait for its job and verify the verdict names the current
  head. GitHub reviews do not start automatically. Record a disposition for
  every finding and require successful CI and the current-head review before
  merging. A missing review or unavailable check is not a pass.
- Before the human recreates GitHub, copy migration PR discussions, reviews,
  patches, and validation evidence to Gitea. Keep Gitea writable until that
  evidence is verified. Repository deletion and recreation are human-owned.

## Image publish

`build-docker.sh` requires an explicit `GATEWAY_IMAGE_REPOSITORY`, then builds
and tags `sha-<source-sha>`. It does **not** publish, and has no
flag that makes it. Repository CI invokes the publication helper only after
the source and smoke gates pass. The GitHub
[image workflow](.github/workflows/image.yml) builds and tests every PR and main
push, runs the hardened boot and both supported upstream handshake smoke tests,
and publishes verified main pushes as `sha-<source-sha>` and `edge`. Release
tags `v<version>` publish versioned images; only newer stable releases advance
`latest`. PRs and manual image runs never publish. See the
[release guide](docs/source-release.md#github-publication) for validation,
publication ownership, and recovery rules.
The [helper workflow](.github/workflows/release-mcp-files.yml) verifies platform
builds on PRs and manual dispatches; only explicit `mcp-files-v<version>` tags
on merged main commits publish GitHub release assets. The helper version file
and workspace version must agree before building. Private repository and package access must be configured
separately; source publication does not grant consumers download access.

The source workflow publishes but never deploys. Deployment repositories select
an immutable published digest and own rollout through their own review and
orchestration controls.

## Safe defaults

- Never log secrets, bearer tokens, or PEM material. `tracing` fields you add
  should expose identifiers (kid, sub, client_id) but not credentials.
- Comments and user-visible strings stand alone: state the constraint or
  invariant itself, never a citation to internal plan/review numbering
  ("Phase 8 PR8-c", "WS9-B", "AERB #313") — provenance lives in git blame
  and the forge. Enforced by `scripts/check-no-plan-citations.sh` (exact
  per-group pins ratcheting to zero; `migrations/` is exempt because
  shipped migrations are immutable). Full rule: `docs/architecture.md` §5/§7.
- Never weaken the distroless image (no `RUN apt-get`, no shell). If you need
  a tool in the container, make the gateway binary itself do the job — see
  `--healthcheck` in
  [`crates/waygate-server/src/healthcheck.rs`](crates/waygate-server/src/healthcheck.rs)
  for the pattern.
- Policies: a broken `.cedar` file must not lock the operator out. SIGHUP
  reload logs the error and keeps the previous policy set. If you touch the
  loader, preserve that invariant.
- Audit sink: when `GATEWAY_DATABASE_URL` is unset the gateway boots with a
  null sink and a `WARN`. Don't flip the default to "panic on missing DB";
  that breaks local dev.
- Already-applied migrations are immutable. `sqlx` hashes every file under
  `migrations/` and stores the checksum in `_sqlx_migrations` at apply time.
  Any later edit — including a comment-only change — invalidates that
  checksum and the gateway will refuse to boot with
  `migration <N> was previously applied but has been modified` (PR #190;
  and the 2026-06-20 / PR #451 repeat, where an AERB-flagged stale *comment*
  was "fixed" in place and crash-looped prod). If a column's semantics need
  clarification after the migration has shipped to prod, document it in
  the Rust gate / handler code that reads the column, or in `docs/`. Never
  edit historical migration SQL. Enforced in PR CI by
  `scripts/check-migrations-immutable.sh` (fails on any modify/delete of a
  migration that already exists on the base branch; only new files are
  allowed) — a plain `cargo test` can't catch this because the `*_pg` suites
  migrate a fresh, empty DB that has no prior checksum to mismatch. Full
  rationale and what-to-do-instead: [`docs/agents/migrations.md`](docs/agents/migrations.md).
- One file per migration version. The sqlx version is the leading `NNNN_`
  integer; two files sharing it collide on the `_sqlx_migrations` version key
  and the gateway crash-loops on boot (the 2026-06-13 duplicate-`0042`
  incident — two parallel worktrees each minted `0042`, neither could see the
  other, and `sqlx::migrate!` embeds duplicates without complaint so both PRs
  were green). **Before adding a migration, pick the next number against the
  latest `main`, not your branch point** — and re-check it when you rebase.
  Two guards enforce this: `scripts/check-migrations.sh` (fast CI fail-fast)
  and the `waygate-storage` `migration_versions` test (runs under
  `cargo test`, so PR CI and the image build both block on it). They only
  *detect* a collision, so `main` requires "branch up-to-date before merge":
  the second of two parallel PRs must pull the other's file in and will trip
  the guard, forcing a renumber instead of a prod break.

## Extended docs — load on demand

Agent-oriented, domain-specific. Load when the task touches the area.

- **[`docs/architecture.md`](docs/architecture.md)** — the convergence
  contract: crate map + layering rule (with the known-debt table), request
  lifecycle, state model, the shared-foundations table ("use these, never
  hand-roll"), and where-new-code-goes conventions. Load for any task that
  adds a crate, a store, an admin resource, an outbound HTTP call, or
  crypto — and before cloning any existing file as a template. A new
  workspace crate must add its crate-map row
  (`scripts/check-architecture-doc.sh` enforces this in CI).
- **[`docs/agents/migrations.md`](docs/agents/migrations.md)** — the schema
  migration rules: append-only / immutable-once-shipped, one file per version,
  the three CI guards (`check-migrations.sh`, the `migration_versions` test, and
  `check-migrations-immutable.sh`), why a fresh-DB test suite can't catch a
  checksum drift, and what to do instead of editing a shipped migration. Load
  when adding or touching anything under `migrations/`.
- **[`docs/agents/authz.md`](docs/agents/authz.md)** — Cedar policy authoring.
  Entity model, policy file layout, step-up semantics, SIGHUP reload. Load
  when changing anything in `crates/waygate-authz/` (the Cedar engine and the policy fixtures under `tests/fixtures/policies/`).
- **[`docs/agents/upstreams.md`](docs/agents/upstreams.md)** — adding or
  editing an upstream MCP server. Manifest schema, transport options, the
  `classify` CLI, Docker network attachment. Load when changing
  `crates/waygate-upstream/` or a deployment's served manifests (the gateway
  repo no longer ships a `servers/` set; see
  docs/server-config-source-of-truth.md).
- **[`docs/agents/identity.md`](docs/agents/identity.md)** — OAuth 2.1
  resource-server behaviour, the optional built-in Authorization Server
  (CIMD flow, dual PKCE, upstream-token encryption), and upstream identity
  chaining (Tier A token-exchange vs Tier B gateway JWT). Load when changing
  `crates/waygate-oidc/`, `crates/waygate-as/`, or anything that mints or
  verifies tokens.
- **[`docs/agents/telemetry.md`](docs/agents/telemetry.md)** — OTel spans,
  metrics, the Grafana dashboard. Load when changing
  `crates/waygate-telemetry/` or adding instrumented code paths.
- **[`docs/agents/dashboard-ui.md`](docs/agents/dashboard-ui.md)** — how to
  edit the admin dashboard. Defines the current UI rules and explains the askama +
  htmx split. Load when changing `crates/waygate-admin/` or any template
  under `crates/waygate-admin/templates/`.
- **[`docs/agents/contextual-assistant.md`](docs/agents/contextual-assistant.md)**
  — the dashboard's docked, page-aware LLM assistant: the two-plane model
  (per-page *context* metadata vs global *capability*/tool reach), the
  `page_context.rs` catalog + always-returns `resolve_page_context`, the
  default-on-everywhere principle (the catalog only enriches), the
  client-facing `PresentationContext` projection that withholds grounding,
  and the focus trust boundary. Load when changing
  `crates/waygate-admin/src/page_context.rs`, the assistant panel
  partial/JS, the `/assist/*` endpoints, or any page that adds curated
  assistant affordances.
- **[`docs/agents/federation.md`](docs/agents/federation.md)** — Tier-C
  gateway-to-gateway federation. Operator model, peer
  registration runbook, JWKS cache + refresh contract, the AERB-enforced
  invariants (scope strip, ambiguity refusal, cache generation fence,
  URL userinfo rejection, streaming body cap, fail-closed dispatch). Load
  when changing `crates/waygate-federation/`, the `federated_peers*`
  migration, `PeerJwtValidator` consumers in `waygate-oidc`, or the
  `tier_c_peer:` manifest field in `waygate-manifest-types`
(re-exported by `waygate-upstream`).
- **[`docs/agents/break-glass.md`](docs/agents/break-glass.md)** —
  single-use override tokens. Mint runbook,
  `scope_pattern` semantics, AMR gate, atomic single-use UPDATE,
  audit attribution. Load when changing
  `crates/waygate-authz/src/break_glass*.rs`, the `break_glass_tokens`
  migration, or the invocation pipeline's authorize stage.
- **[`docs/agents/tasks.md`](docs/agents/tasks.md)** — MCP Tasks
  primitive. Schema, lifecycle
  enum, why the write-through and client-facing endpoints are deferred
  until the spec stabilizes. Load when changing
  `crates/waygate-dashboard-stores/src/tasks.rs`,
  the `task_states` migration, or the admin REST surface at
  `/api/v1/admin/tasks`.
- **[`docs/agents/hitl-control-plane.md`](docs/agents/hitl-control-plane.md)**
  — human-in-the-loop approval of agent-proposed control-plane changes
  (CIBA-shaped backchannel, `mcp:propose` maker credential, configurable
  M-of-N, the dashboard review-queue UX, the built-in `gateway-admin.*`
  MCP tool surface, the out-of-band webhook notifier, safety invariants).
  Load when changing the `waygate-changeset` crate, the `change_requests`
  migration, the `mcp:propose` gate in `crates/waygate-admin/src/scope.rs`,
  the dashboard review queue, the `waygate_mcp::BuiltinTools` seam
  (`crates/waygate-mcp/src/builtin.rs`) or its
  `crates/waygate-server/src/mcp_builtin.rs` impl, the
  `ChangeRequestNotifier` (`crates/waygate-admin/src/change_notify.rs` +
  the `WebhookChangeNotifier` in `crates/waygate-server/src/change_notify.rs`),
  the reserved-namespace guard (`waygate_core::RESERVED_BUILTIN_NAMESPACE` +
  the check in `waygate_upstream::validate_manifest_invariants`), or any
  admin handler that grows a "propose instead of execute" path.
- **[`docs/agents/ema.md`](docs/agents/ema.md)** — Enterprise-Managed
  Authorization (MCP `io.modelcontextprotocol/enterprise-managed-authorization`
  / ID-JAG). The gateway as a SCIM-fed IdP-Authorization-Server: minting
  Cedar-gated ID-JAGs (token-exchange grant) and redeeming them for
  audience-restricted access tokens (jwt-bearer grant), with Authentik kept
  for SSO + outbound SCIM provisioning only. Confirmed id-jag-04 wire
  constants, the additive/opt-in invariants, the SCIM deprovisioning
  tombstones, and deployment configuration. Load when changing
  `crates/waygate-as/src/token.rs`, `crates/waygate-oidc/src/identity_jwt.rs`,
  the `waygate-scim` provisioning surface, the `GrantCrossAppAccess` Cedar
  action / `crates/waygate-authz/tests/fixtures/policies/40-cross-app-access.cedar`, or anything that mints or
  redeems ID-JAGs.
- **[`docs/agents/mcp-tool-docs.md`](docs/agents/mcp-tool-docs.md)** — the SOP
  for self-documenting built-in MCP tools: the litmus (a client must build a
  valid call from the wire surface alone), the seven-point standard (per-field
  descriptions, no opaque polymorphic params, `output_schema`, annotations/title,
  teach-through errors, `schemars` single-source-of-truth), the
  `describe_action` discovery pattern for `propose_change`, and the enforcing
  tests. Load when adding or editing a built-in tool in
  `crates/waygate-server/src/mcp_builtin.rs`, `mcp_observe.rs`, `mcp_control.rs`,
  or the `BuiltinTools` impls in `crates/waygate-mcp/src/builtin.rs`.

## Human docs

For deployment and SEP #1888 background, see [`docs/`](docs/).
[`docs/architecture.md`](docs/architecture.md) is the architecture
contract (indexed above). `README.md` is the top-level overview.
