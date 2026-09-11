
@id("support-memory-writers")
@layer("service-grants")
@description("support-memory-writers may call the everyday write surface of the support memory bank (below high).")
@tags("example-memory, support, writer")
permit (
    principal in Group::"support-memory-writers",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-memory-support"
        && resource.side_effects
        && resource.risk != "high"
};
