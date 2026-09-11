
@id("example-security-security-log-readers-raw")
@layer("service-grants")
@description("security-log-readers may read the raw Example security service full_log through events.read_raw.")
@tags("example-security, security, raw-log, least-privilege")
permit (
    principal in Group::"security-log-readers",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-security" && resource.name == "events.read_raw"
};

@id("example-security-security-log-readers-required")
@layer("service-grants")
@description("Raw Example security service full_log access requires security-log-readers membership, including for administrators.")
@tags("example-security, security, raw-log, confinement")
@reason("events.read_raw returns raw security logs and requires security-log-readers membership")
forbid (
    principal,
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-security" && resource.name == "events.read_raw"
} unless {
    principal in Group::"security-log-readers"
};
