
@id("message-sender-send-only")
@layer("service-grants")
@description("message-sender may only call the outbound message-send tools (messages.send, messages.send_legacy).")
@tags("example-messages, sender, least-privilege")
permit (
    principal in Group::"message-sender",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-messages" &&
    (resource.name == "messages.send" || resource.name == "messages.send_legacy")
};

@id("message-sender-confine")
@layer("service-grants")
@description("message-sender is forbidden every Example messaging service tool that is not a send — send-only is enforced, not merely granted.")
@tags("example-messages, sender, confinement, security")
forbid (
    principal in Group::"message-sender",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-messages" &&
    !(resource.name == "messages.send" || resource.name == "messages.send_legacy")
};

@id("message-reader-read-only")
@layer("service-grants")
@description("message-reader may only call low-risk read/receive Example messaging service tools (no send, no mutate).")
@tags("example-messages, receiver, least-privilege")
permit (
    principal in Group::"message-reader",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-messages" && resource.risk == "low" && !resource.side_effects
};
