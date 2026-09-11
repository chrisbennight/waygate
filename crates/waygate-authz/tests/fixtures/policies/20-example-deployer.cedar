
@id("deploy-operators-actions")
@layer("service-grants")
@description("deploy-operators may call every side-effecting Example deployment service MCP action.")
@tags("example-deployer, administration")
permit (
    principal in Group::"deploy-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-deployer" && resource.side_effects
};

@id("example-deployer-actions-require-service-admin")
@layer("service-grants")
@description("Example deployment service side effects require the service-specific deploy-operators group, including for gateway administrators.")
@tags("example-deployer, administration, confinement")
@reason("Example deployment service actions require membership in the deploy-operators group")
forbid (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-deployer" && resource.side_effects
} unless {
    principal in Group::"deploy-operators"
};
