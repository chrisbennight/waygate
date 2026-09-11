
@id("example-forge-gateway-admin")
@layer("service-grants")
@description("Principals holding mcp:admin may call the complete Example forge MCP surface.")
@tags("example-forge, administration, repositories")
permit (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-forge"
        && principal.scopes.contains("mcp:admin")
};
