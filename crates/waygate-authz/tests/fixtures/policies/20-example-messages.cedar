
@id("message-operators")
@layer("service-grants")
@description("message-operators may call the Example messaging service messaging surface below high (sends, reactions, group/contact/profile management).")
@tags("example-messages, messaging")
permit (
    principal in Group::"message-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-messages"
        && resource.side_effects
        && resource.risk != "high"
};
