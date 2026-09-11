
@id("compute-operators")
@layer("service-grants")
@description("compute-operators may call mutating Example compute service tools (provision, mutate, delete).")
@tags("example-compute, operator")
permit (
    principal in Group::"compute-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-compute"
};
