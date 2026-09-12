# Get help and propose improvements

Start with the [tutorial](examples/quickstart/README.md),
[configuration guide](docs/configuration.md), and [workflow guides](docs/README.md).
For an operational problem, follow the [runbook](docs/operations.md) and
[observability guide](docs/guides/observability.md).

Use
[GitHub issues](https://github.com/chrisbennight/waygate/issues)
for reproducible bugs, documentation gaps,
and feature proposals. Include:

- Gateway version or source commit and image digest, client version, and
  negotiated MCP protocol where relevant.
- Expected behavior, actual behavior, and a minimal synthetic reproduction.
- Enabled feature groups and redacted configuration names, without credential
  values, private URLs, personal file contents, or bearer tokens.
- Relevant bounded error codes and whether the call reached the upstream.
  Describe passes and skipped checks separately.

For a feature request, explain the user outcome and a concrete example. State
whether it concerns core MCP, an extension/proposal, or a gateway-specific
enhancement. Useful capabilities can require configuration or policy; an
expected refusal is not automatically a product defect.

Community support is best effort. There is no service-level agreement or
promise to maintain every historical snapshot. The current release line is
the maintenance target; draft protocol behavior can evolve as standards and
implementations change. Read the capability guide and release changes before
upgrading. Report vulnerabilities through [the security process](SECURITY.md).
