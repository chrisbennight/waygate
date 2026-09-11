
@id("secret-operators-all-tools")
@layer("service-grants")
@description("secret-operators may call every Example secret service MCP tool.")
@tags("example-secrets, administration")
permit (
    principal in Group::"secret-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-secrets"
};

@id("example-secrets-requires-service-admin")
@layer("service-grants")
@description("Every Example secret service tool requires the service-specific secret-operators group, including for gateway administrators.")
@tags("example-secrets, administration, confinement")
@reason("Example secret service access requires membership in the secret-operators group")
forbid (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-secrets"
} unless {
    principal in Group::"secret-operators"
};
