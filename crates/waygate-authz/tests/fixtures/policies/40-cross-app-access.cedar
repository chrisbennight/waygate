// Enterprise-Managed Authorization (EMA) — cross-app access grants.
//
// Gates the IdP-Authorization-Server's ID-JAG mint
// (`Action::"GrantCrossAppAccess"`): "may this principal obtain an
// ID-JAG for `resource` (an MCP server), acting through
// `context.client_id`?" The issued ID-JAG is later redeemed (RFC 7523
// jwt-bearer) for an audience-restricted access token — see
// `docs/agents/ema.md`.
//
// Defense in depth — this PERMIT is not the only gate:
//   - The token-exchange endpoint requires a present + ACTIVE SCIM row
//     before it ever calls Cedar (so deprovisioned users never reach
//     here), and
//   - `16-scim-active.cedar` independently `forbid`s deactivated
//     principals across ALL actions (forbid wins), this one included.
//
// This file is the operator-editable permit. Default: a SCIM-provisioned,
// ACTIVE member of the `mcp-users` directory group may obtain an ID-JAG.
// Membership is read from the SCIM-authoritative `scim_groups` (Authentik's
// pushed directory), NOT the token's top-level `principal.groups` — an EMA
// grant must prove directory membership, never a claim a client could carry
// stale. Tighten as needed — e.g. scope to a directory group that maps to one
// server, or add the client dimension:
//
//     when {
//         principal.scim_present && principal.scim_active
//         && principal.scim_groups.contains("eng")
//         && context.client_id == "https://claude.ai/mcp.json"
//     };
//
// `context.client_id` is the requesting OAuth client (the EMA "which
// client" dimension); it is present on this action's requests and absent
// on ordinary tool calls.
@id("cross-app-access-allow")
@layer("service-grants")
@description("EMA: provisioned members may obtain an ID-JAG (cross-app access grant) for a resource.")
@tags("ema, id-jag, cross-app, service-grants")
@reason("Provisioned member is permitted to obtain a cross-app access grant for this resource.")
permit (
    principal,
    action == Action::"GrantCrossAppAccess",
    resource
)
when {
    principal.scim_present
    && principal.scim_active
    && principal.scim_groups.contains("mcp-users")
};
