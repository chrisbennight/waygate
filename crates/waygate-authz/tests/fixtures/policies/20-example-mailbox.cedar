@id("mail-automation-mailbox")
@layer("service-grants")
@description("mail-automation may call every side-effecting example mailbox tool (send, register/unregister account, mark/move/delete mail) — full mailbox management.")
@tags("mailbox, mail, management, high")
permit (
    principal in Group::"mail-automation",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-mailbox" && resource.side_effects
};
