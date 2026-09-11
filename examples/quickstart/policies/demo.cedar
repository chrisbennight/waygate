// The disposable issuer authenticates a fixed demo identity. This policy is for
// evaluation only; authenticated deployments must author their own grants.
@id("demo-users")
@layer("baseline")
permit (principal in Group::"demo-users", action, resource);

// A forbid overrides a matching permit.
@id("demo-restricted")
@layer("service")
forbid (principal, action == Action::"CallTool", resource == Tool::"demo.restricted");
