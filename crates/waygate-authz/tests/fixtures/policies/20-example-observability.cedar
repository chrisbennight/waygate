
@id("example-observability-readonly")
@layer("service-grants")
@description("Read-only Example observability service tools (queries, lists, gets) are open to every authenticated principal.")
@tags("example-observability, read-only")
permit (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-observability" && !resource.side_effects
};

@id("observability-operators-write")
@layer("service-grants")
@description("observability-operators may call mutating Example observability service tools below the high tier.")
@tags("example-observability, operator, write")
permit (
    principal in Group::"observability-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-observability" && resource.side_effects && resource.risk != "high"
};

@id("example-observability-incident-responders-high")
@layer("service-grants")
@description("incident-responders may call high-risk Example observability service tools (alerting, incident, dashboard mutation).")
@tags("example-observability, high")
permit (
    principal in Group::"incident-responders",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-observability" && resource.risk == "high"
};
