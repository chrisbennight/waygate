@id("mail-automation-example-mail-admin-accounts")
@layer("service-grants")
@description("mail-automation may create / modify / delete example-mail-admin email accounts only (ephemeral mailbox provisioning); all other example-mail-admin administration stays admin-only.")
@tags("example-mail-admin, mail, provisioning, high")
permit (
    principal in Group::"mail-automation",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-mail-admin"
        && (resource.name == "accounts.create"
            || resource.name == "accounts.update"
            || resource.name == "accounts.delete")
};
