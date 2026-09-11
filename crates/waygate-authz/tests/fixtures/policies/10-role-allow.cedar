// Role-wide grants that layer on top of the baseline forbid.
//
// mcp-admins are trusted with every action on every resource — including
// high-risk tool calls. Everyone else gets progressive-disclosure (search)
// plus the ability to list tools and call READ-ONLY low-risk TOOLS
// (`risk: low && !side_effects`). A side-effecting tool — even one classified
// `low` — is NOT in this baseline: it must be granted by an explicit per-server
// operator/writer permit (20-*.cedar) or by joining mcp-admins. High-risk calls
// likewise fall through to the baseline forbid.
//
// The `!resource.side_effects` guard is the campaign's pivot: it makes the
// `medium → low` reclassification safe. A demoted write tool lands at
// `low + side_effects: true` and stays OUT of the tool grant rather than
// becoming world-callable. Enforced manifest-wide by
// per_upstream_policies.rs::no_side_effecting_tool_is_reachable_by_a_groupless_principal.
//
// MODELS are governed separately (see the second CallTool permit). The
// `!side_effects` narrowing is a TOOL concept and must NOT touch the inference
// plane: a model invocation is inherently a billable side-effect
// (`synthetic_model_facts` sets `side_effects: true`), but model *access* is
// governed by the risk tier (cost), not side_effects. Unclassified models
// default to `low` and are open to any authenticated principal
// (migrations/0057_llm_models_risk_default_low.sql); the model permit below
// keeps that posture. Scoping the tool narrowing to `resource is Tool` is what
// stops it from silently denying every low-risk model call.

@id("baseline-admin-allow-all")
@layer("baseline")
@description("mcp-admins may take every action on every resource, including high-risk tool calls.")
@tags("admin, baseline")
permit (
    principal in Group::"mcp-admins",
    action,
    resource
);

@id("baseline-discovery")
@layer("baseline")
@description("Any authenticated principal may list and search tools (progressive disclosure).")
@tags("discovery, baseline")
permit (
    principal,
    action in [
        Action::"ListTools",
        Action::"SearchTools"
    ],
    resource
);

// Read-only low-risk TOOLS -> every authenticated principal.
@id("baseline-readonly-tools")
@layer("baseline")
@description("Any authenticated principal may call read-only low-risk tools (risk:low, no side effects).")
@tags("baseline, read-only, tools")
permit (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.risk == "low" && !resource.side_effects
};

// Low-risk MODELS -> every authenticated principal. The tool `!side_effects`
// narrowing deliberately does not apply here (every model carries
// side_effects:true); model access rides the risk tier.
@id("baseline-low-models")
@layer("baseline")
@description("Any authenticated principal may call low-risk models; model access rides the risk tier, not side-effects.")
@tags("baseline, models")
permit (
    principal,
    action == Action::"CallTool",
    resource is Model
) when {
    resource.risk == "low"
};
