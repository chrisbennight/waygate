// Legacy Code Mode approval overlay retained for compatibility tests of
// approval-bound executions stored by older gateway releases.
//
// `context.channel` is stamped by the gateway from the originating surface
// ("direct" for ordinary client calls, "codemode" for nested Code Mode
// calls) and is never client-supplied. `context.approval_present` is false
// on the real evaluation; the engine re-evaluates with it true and, when
// only this forbid was blocking, reports ApprovalRequired so the
// invocation pipeline gates dispatch on a grant claim instead of flatly
// denying. A caller without the underlying permit still gets a flat deny.
//
// Current client-authored Code Mode executions use the direct channel and do
// not evaluate this overlay. Ordinary direct-channel policy remains the source
// of authority for those nested calls.
@id("codemode-mutation-approval")
@layer("approval-overlay")
@description("Side-effecting Code Mode calls require a per-call administrator approval grant.")
@tags("codemode, approval, security")
@reason("side-effecting Code Mode calls require administrator approval of the exact call")
forbid (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    context.channel == "codemode" &&
    resource.side_effects &&
    !context.approval_present
};
