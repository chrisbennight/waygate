// Step-up requirement — scoped to a single canary tool (`delete_dataset`).
//
// A `forbid` overrides every `permit` in Cedar. This policy makes the
// `delete_dataset` tool (synthetic data-store deletion — irreversible,
// catastrophic) unavailable to anyone whose access token doesn't carry a
// fresh `mcp:invoke:high` step-up scope, regardless of group membership
// (mcp-admins included). It is the ONLY tool that is step-up-gated.
//
// Step-up is deliberately DECOUPLED from the risk tier. Administrative /
// high-risk tools are governed by the AUTHORIZATION axis (a role/admin
// `permit`), NOT by step-up freshness — `high` no longer implies a step-up
// prompt (the previous `resource.risk == "high"` forbid was retired). Step-up
// is reserved for one exercised canary so the fresh IdP re-auth flow stays
// warm without being sprinkled across every destructive action. See
// docs/authorization-model.md §6.
//
// To step up another tool later, add its name to this forbid. It must also be
// classified `risk: high` so the engine has a `required_scope` to re-authorize
// with (`required_scope_for(High) == mcp:invoke:high`); the re-eval below
// augments the principal with exactly that scope.
//
// How it becomes a step-up prompt (not a flat deny): on a `CallTool` deny, the
// engine re-evaluates with `principal.scopes` augmented by the tool's
// `required_scope`. If that augmented pass would allow (the caller's permit
// grants access and only this forbid was blocking), the engine returns
// `StepUpRequired` carrying the scope to re-authorize with; a caller lacking
// the underlying permit still gets a flat deny.

// `@reason` surfaces in MCP responses. For step-up
// the engine usually re-evaluates with the missing scope
// and converts this forbid into a `StepUpRequired` verdict
// (which carries its own scope-named reason); the @reason
// here covers the residual case where the re-eval still
// denies (e.g. caller lacks the underlying permit too).
@id("step-up-delete-dataset")
@layer("step-up-overlay")
@description("delete_dataset requires a fresh mcp:invoke:high step-up scope — the lone step-up canary.")
@tags("step-up, high, security")
@reason("delete_dataset requires the mcp:invoke:high step-up scope — re-authorize with the elevated scope and retry")
forbid (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.name == "delete_dataset" &&
    !principal.scopes.contains("mcp:invoke:high")
};
