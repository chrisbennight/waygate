# Release notes

## 1.1.0

- Persist review and quarantine of changed upstream tool contracts, with a
  dashboard workflow for accepting a specific observed contract. The additive
  `0111_tool_contract_reviews.sql` migration stores the review state.
- Support recipient-aware email approval policies and document the workflow.
- Refresh dashboard branding and workflow documentation.

- Preserve upstream-declared response schemas in legacy MCP discovery and Code
  Mode, including nested response types. Catalog schemas retain precedence and
  existing output-validation behavior is unchanged.
- Invalidate saved Code Mode bindings when the declared response schema changes.

## 1.0.0

Initial public release of Waygate.

- Govern MCP tools and model inference through a shared identity, Cedar policy,
  quota, and audit boundary.
- Discover tool capabilities progressively, transfer files, load verified skills,
  and orchestrate calls with Code Mode.
- Review proposed gateway changes through the administration dashboard.
- Run the gateway as a distroless container and use the `mcp-files` helper on
  Linux, Windows, and macOS.

Start with the [local tutorial](../examples/quickstart/README.md). For production,
follow the [configuration guide](configuration.md) and
[operator runbook](operations.md). Feature prerequisites and current limitations
are described in the [documentation index](README.md).
