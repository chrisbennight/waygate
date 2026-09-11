
@id("incident-triage-example-fetch")
@layer("service-grants")
@description("incident-triage may call example-fetch side-effecting fetch tools below high.")
@tags("incident-triage, example-fetch")
permit (
    principal in Group::"incident-triage",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-fetch" && resource.side_effects && resource.risk != "high"
};

@id("incident-triage-confine")
@layer("service-grants")
@description("incident-triage is confined to the example-search and example-fetch upstreams only.")
@tags("incident-triage, confinement, security")
@reason("incident-triage is confined to the example-search and example-fetch upstreams")
forbid (
    principal in Group::"incident-triage",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server != "example-search" && resource.server != "example-fetch"
};
