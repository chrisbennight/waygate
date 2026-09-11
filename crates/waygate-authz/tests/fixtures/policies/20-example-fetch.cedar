@id("unrestricted-fetchers")
@layer("service-grants")
@description("unrestricted-fetchers may call ALL example-fetch side-effecting tools (pages.fetch_markdown/html/screenshot/pdf/crawl + browser.execute_script / RCE); the example-fetch surface stays confined to this group and triage, never world-callable.")
@tags("example-fetch, fetch, execute-js, high")
permit (
    principal in Group::"unrestricted-fetchers",
    action == Action::"CallTool",
    resource is Tool
) when {
    resource.server == "example-fetch" && resource.side_effects
};
