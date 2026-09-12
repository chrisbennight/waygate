# Repository instructions

Waygate is a Rust workspace providing an MCP and inference gateway. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and [the architecture](docs/architecture.md).

## Working safely

- Work in an isolated Git worktree under the ignored `.worktrees/` directory,
  based on freshly fetched `main`. Preserve unrelated work. Remove only your
  own clean worktree after its changes are delivered.
- Respect the user's scope and authorization for commits, pushes, and releases.
  A source push can start image publication. Use Git for local operations and
  connected forge tools for repository administration.
- For an authorized PR workflow, confirm the PR is open before pushing. Request
  automated review of the current head, address each finding, and merge only
  after required checks and the current-head review pass.
- Keep credentials out of source, logs, and review material. Use typed inputs,
  parameterized queries, and argument arrays at interpreter boundaries.
- Use existing workspace dependencies and shared security primitives. Follow
  the checked-in Rust toolchain. Do not weaken the distroless image.
- Applied SQL migrations are immutable. New migration numbers must be unique
  against current `main`; see [migration rules](docs/agents/migrations.md).
- Comments explain current constraints. Development chronology belongs in the
  forge, not source comments or product documentation.

## Validation

Run the [contributor validation commands](CONTRIBUTING.md#validate-the-contract-you-change).

Use focused regression tests for changed behavior. The image workflow also runs
source guards, nextest, doctests, and image smoke tests. Database tests need an
isolated Postgres instance with `AUDIT_DATABASE_URL` and
`GATEWAY_AS_DATABASE_URL`; without those settings the database suites are not
exercised. Use the workflow's pinned Postgres image when matching CI. Timing
checks are opt-in; see [testing](docs/testing.md).

When changing migrations, run `scripts/check-migrations.sh` and
`scripts/check-migrations-immutable.sh`. For release or bundled-asset changes,
follow [source publication](docs/source-release.md).

## Domain references

Load the relevant reference before changing its area:

- [architecture](docs/architecture.md)
- [migrations](docs/agents/migrations.md)
- [authz](docs/agents/authz.md)
- [upstreams](docs/agents/upstreams.md)
- [identity](docs/agents/identity.md)
- [telemetry](docs/agents/telemetry.md)
- [dashboard ui](docs/agents/dashboard-ui.md)
- [contextual assistant](docs/agents/contextual-assistant.md)
- [federation](docs/agents/federation.md)
- [break glass](docs/agents/break-glass.md)
- [tasks](docs/agents/tasks.md)
- [hitl control plane](docs/agents/hitl-control-plane.md)
- [ema](docs/agents/ema.md)
- [mcp tool docs](docs/agents/mcp-tool-docs.md)

Deployment-specific manifests, policies, secrets, and orchestration belong to
operators' deployment repositories. Repository fixtures are synthetic examples.
