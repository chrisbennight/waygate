
@id("code-memory-writers")
@layer("service-grants")
@description("code-memory-writers may call the everyday write surface of the coding memory bank (below high).")
@tags("example-memory, coding, writer")
permit (
    principal in Group::"code-memory-writers",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-memory-code"
        && resource.side_effects
        && resource.risk != "high"
};
