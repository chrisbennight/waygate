
@id("assistant-memory-writers")
@layer("service-grants")
@description("assistant-memory-writers may call the everyday write surface of the assistant memory bank (below high).")
@tags("example-memory, assistant, writer")
permit (
    principal in Group::"assistant-memory-writers",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-memory-assistant"
        && resource.side_effects
        && resource.risk != "high"
};
