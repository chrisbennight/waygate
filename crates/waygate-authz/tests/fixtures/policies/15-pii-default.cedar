// Default PII policy.
//
// This propagates the per-tool `pii` flag
// (declared in the YAML manifest's `ToolClassification.pii`) all the
// way to the Cedar `Tool` entity. This file is the operator-editable
// default that consumes it.
//
// Stance: API-key callers are forbidden from invoking tools tagged as
// returning/accepting PII. The reasoning:
//
// * API keys are static long-lived bearers with no MFA, no IdP-tracked
//   step-up, no per-call attestation. A leaked key gives a stranger
//   identity-laundered access to whatever the key authorises.
// * PII tools by definition handle data whose disclosure is
//   meaningful even when the rest of the request looks fine.
// * Interactive OAuth callers go through Authentik (or the gateway's
//   CIMD AS), can be forced through MFA, leave a session-bound audit
//   trail with `auth_method == "oauth"`, and can be revoked at the IdP
//   the moment they're compromised. That's the right access mode for
//   PII.
//
// Operator escape hatch — explicit per-key opt-in via group membership.
// An operator who genuinely needs a service-account API key to read
// PII tools puts that key's subject into a `pii-readers` group (or
// whatever the local mapping calls it). The mcp-admins group also
// continues to win because of the broader permit in
// `10-role-allow.cedar`.

// `@reason` surfaces in the MCP forbidden response's
// `data.reasons` array so the denied client (and operator
// reading the audit) sees *why* the call was blocked.
@id("pii-apikey-forbid")
@layer("pii-overlay")
@description("API-key callers cannot invoke PII-tagged tools unless they are in mcp-admins, pii-readers, or a scoped Example messaging service role.")
@tags("pii, api-key, security")
@reason("PII tool calls require interactive (OAuth) auth, mcp-admins membership, or pii-readers membership — API keys cannot read PII by default")
forbid (
    principal,
    action == Action::"CallTool",
    resource
)
when {
    resource has pii && resource.pii && principal.auth_method == "api_key"
}
unless {
    principal has groups && (
        principal.groups.contains("mcp-admins")
        || principal.groups.contains("pii-readers")
        // Example messaging service message-direction roles (20-example-message-roles.cedar). The exemption
        // is scoped to exactly the tools each role's permit allows — NOT all
        // example-messages tools — because the baseline (10-role-allow) permits any
        // low-risk tool, so a broader exemption would let a *sender* read the
        // low-risk PII-tagged example-messages reads (history/receive/contacts/…), which
        // the send-only contract forbids.
        //   - message-sender: exempt only for the outbound send tools.
        || (principal.groups.contains("message-sender")
            && resource.server == "example-messages"
            && (resource.name == "messages.send" || resource.name == "messages.send_legacy"))
        //   - message-reader: exempt only for the low-risk read-only example-messages
        //     tools — `!side_effects` mirrors the receiver permit in
        //     20-example-message-roles.cedar so the exemption never covers a tool the
        //     receiver cannot call (e.g. a demoted side-effecting low write).
        || (principal.groups.contains("message-reader")
            && resource.server == "example-messages"
            && resource.risk == "low"
            && !resource.side_effects)
    )
};
