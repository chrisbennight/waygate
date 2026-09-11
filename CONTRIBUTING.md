# Contribute to the gateway

Start with the [tutorial](examples/quickstart/README.md) and
[architecture](docs/architecture.md). Report a reproducible bug, improve an
example, or propose a focused change through
[the private Gitea issue tracker](https://gitea.cacahuate.org/bennight/mcp-tool-search-gateway/issues).
Discuss a new protocol surface or substantial architecture change before
implementing it. Use [private reporting](SECURITY.md) for security findings.

## Prepare a checkout

Install Git, rustup, a C/C++ build toolchain with CMake and pkg-config, and the
toolchain selected by `rust-toolchain.toml`. Docker with Compose runs the
tutorial and isolated database/image checks. Python 3 and Node.js are needed
for the repository's script checks; individual tooling directories declare
their own locked dependencies. Public package registries are sufficient;
private compiler caches and artifact mirrors are optional deployment settings.

Clone `git@github.com:chrisbennight/waygate.git` with your authorized GitHub
identity. Keep task changes isolated from the primary checkout:

```sh
git fetch origin
git worktree add -b my-change .worktrees/my-change origin/main
cd .worktrees/my-change
```

Add `.worktrees/` to your local Git exclude file if it is not already ignored.
Preserve unrelated changes and remove only your own clean worktree after its
PR merges. Contributors without upstream push access can use a fork and fetch
the target repository's current `main` through a separate upstream remote.

## Validate the contract you change

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo check --workspace
```

Check each command's exit status. CI also uses the pinned nextest runner and
runs doctests separately. Relevant script guards appear in the checked-in
workflows; for documentation and release changes start with:

```sh
bash scripts/check-doc-anchors.sh
bash scripts/check-licenses.sh
bash scripts/check-no-plan-citations.sh
```

For database behavior, run a disposable PostgreSQL 17 instance and set both
`AUDIT_DATABASE_URL` and `GATEWAY_AS_DATABASE_URL` to its connection URL before
testing. CI provisions one isolated database for both, with
`max_connections=200`; use the same image build selected by the workflow when
matching CI. Never point tests at a production or personal database. Tests
without these variables can return early: report the database suites as not
run, not as passing. [Timing diagnostics](docs/testing.md) marked ignored are
also separate from required passes.

Add proportionate regression evidence for the intended behavior. Prefer
observable contracts, real parsers/stores, and mocks at external boundaries.
For concurrency, use explicit synchronization or controlled clocks. Do not
hide a failure by retrying it, weakening an assertion, or increasing a short
timing threshold. Security and persistence changes need refusal, stale-state,
and concurrent-update cases appropriate to the changed boundary.

## Make a reviewable change

Use the workspace's pinned dependencies and existing shared abstractions.
Before adding a package, verify its registry identity, provenance, maintenance,
and fit. Keep secret values out of source, commits, logs, and examples; retain
useful secret-handling capabilities inside their governed runtime boundary.
Use argv arrays and typed parameters for untrusted input, not interpreter
string construction. Use vetted cryptography and platform randomness.

Shipped migrations are immutable, including comments. New migration numbers
must be unique against current `main`; run both migration guards and recheck
after updating your branch. See [migration rules](docs/agents/migrations.md).
Domain-specific guidance is indexed in [AGENTS.md](AGENTS.md).

A PR should explain the user-visible problem, resulting behavior, relevant
design constraints, and validation, including skips or untested environments.
Use current, verifiable claims. Record a disposition for every review finding:
fix, explain a disagreement, or state an appropriate scoped deferral. Update
from main when required, and confirm the PR remains open before pushing again.
Merge only the reviewed head after required checks pass. Hosting-specific
automated reviewers supplement the same code and test evidence.

Document changed behavior beside the feature and update moved references.
Examples should use synthetic identities and public placeholders. Comments
state constraints directly; private ticket numbers belong in PR discussion,
not in source comments or user-facing messages.

## License and participation

Contributions are accepted under this project's `Apache-2.0` license.
Only submit code and assets you have the right to contribute; retain required
third-party notices. No separate contributor license agreement is currently
required. Be respectful, discuss technical disagreements with evidence, and
avoid harassment or disclosure of another person's private information.
Maintainers may moderate abusive content and close unsuitable contributions.
The [code of conduct](CODE_OF_CONDUCT.md) explains participation and reporting.
