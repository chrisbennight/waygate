# Use and understand Waygate

Start with [your first tool call](../examples/quickstart/README.md). It runs
locally, requires no model-provider account, and proves both a successful call
and a policy refusal. Then choose a workflow below.

| You want to… | Start here | Reference |
| --- | --- | --- |
| Connect MCP clients and discover tools efficiently | [MCP capabilities](guides/mcp.md) | [Host discovery contract](host-tool-discovery.md), [upstream manifests](agents/upstreams.md) |
| Move files without filling model context | [File workflow](guides/files.md) | [Transfer protocol and storage](file-transfer.md) |
| Find and use reviewed workflows | [Skills workflow](guides/skills.md) | [Git integrity](skills-git-source.md), [distribution review](skill-distribution-review.md) |
| Combine tool calls and recover an interrupted workflow | [Code Mode workflow](guides/code-mode.md) | [Execution contract](codemode.md) |
| Control who can do what | [Security capabilities](guides/security.md) | [Cedar model](authorization-model.md), [policy authoring](agents/authz.md) |
| Let an agent inspect and propose gateway changes | [Gateway administration over MCP](guides/gateway-administration.md) | [Approval contract](agents/hitl-control-plane.md) |
| Route model requests through gateway governance | [Inference workflow](guides/inference.md) | [Provider and translation reference](inference-plane.md), [images](images-api.md) |
| Explain an error, refusal, or operational incident | [Audit and observability](guides/observability.md) | [Telemetry reference](agents/telemetry.md) |
| Deploy with real identity and persistent state | [Operator runbook](operations.md) | [Configuration](configuration.md), [deployment example](../examples/deployment/README.md), [configuration ownership](server-config-source-of-truth.md) |
| Change the implementation | [Contribute](../CONTRIBUTING.md) | [Architecture](architecture.md), [testing](testing.md), [repository instructions](../AGENTS.md) |
| Report a problem or vulnerability | [Support](../SUPPORT.md) | [Private security reporting](../SECURITY.md) |
| Publish or adopt a release | [Release notes](release-notes.md) | [Source publication](source-release.md) |

The workflow guides describe implemented behavior and identify prerequisites
beside each capability. Design documents also contain proposed work; their
future-state sections are not a support promise. Protocol proposals and
gateway extensions are distinguished from core MCP in the capability guide.
