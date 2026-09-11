
@id("facility-operators")
@layer("service-grants")
@description("facility-operators may call the device-control surface below high on both example facility instances.")
@tags("example-facility, operator")
permit (
    principal in Group::"facility-operators",
    action == Action::"CallTool",
    resource is Tool
) when {
    (resource.server == "example-facility-east"
        || resource.server == "example-facility-west")
        && resource.side_effects
        && resource.risk != "high"
};
