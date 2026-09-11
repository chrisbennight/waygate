@id("operations-operators-management")
@layer("service-grants")
@description("operations-operators may call the example-operations management (side-effecting) tools.")
@tags("example-operations, management")
permit (
    principal in Group::"operations-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-operations"
        && resource.side_effects
};
