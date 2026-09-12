# Govern identity, tools, and models

The gateway combines authenticated identity with the full Cedar policy engine
and a shared invocation pipeline. Policies can use groups, scopes, roles,
tenant identity, authentication method, directory lifecycle, and reviewed
resource facts. This supports more than an API-key allowlist: an operator can
express who may perform an action, which data it concerns, and when additional
assurance or approval is required.

## See a policy decision

The [local tutorial](../../examples/quickstart/README.md) permits `demo.greet`
and explicitly forbids `demo.restricted`. Its checker proves that a forbidden
tool is hidden from discovery and still refused if called by name.

```cedar
forbid (
    principal,
    action == Action::"CallTool",
    resource == Tool::"demo.restricted"
);
```

[Cedar authorization](https://docs.cedarpolicy.com/auth/authorization.html)
is default-deny and forbids override permits. The gateway uses Cedar's parser
and evaluator; its own entity model defines which attributes policies can use.
Start from [policy authoring](../agents/authz.md) and test both a permitted and
a denied identity. Synthetic repository policies are examples, not an
organization's production access model.

## Separate read, write, and approval policy

The [synthetic messaging policies](../../crates/waygate-authz/tests/fixtures/policies/20-example-message-roles.cedar)
provide a worked read/write example. `message-reader` permits low-risk,
non-mutating calls on `example-messages`. `message-sender` permits the named
send operations and explicitly forbids that group's other messaging operations.
The confinement forbid still wins if another policy would permit a read.
Evaluate both groups and an unrelated identity in the policy simulator;
include a read, a send, and a different mutation in the test cases.

To require human approval for an otherwise permitted send, add a narrowing
overlay to an isolated policy set:

```cedar
@id("review-example-send")
@layer("approval-overlay")
forbid (principal, action == Action::"CallTool", resource is Tool)
when {
    resource.server == "example-messages" &&
    resource.name == "messages.send" &&
    !context.approval_present
};
```

For the permitted sender, simulation reports `approval_required`. A principal
without an underlying send permit remains denied. The actual invocation needs
a live approval bound to its principal, reviewed behavior, and arguments;
callers cannot set the gateway's approval context themselves. The overlay also
applies to nested Code Mode calls. See the [approval binding contract](../agents/authz.md#invocation-approval-bindings).

## Choose the identity path

| Path | Useful when | Important setup |
| --- | --- | --- |
| External OAuth resource server | Your identity system issues suitable access tokens | Configure issuer discovery, audience, claim mappings, and compatible client login. |
| Built-in authorization server | Clients need a CIMD/PKCE login flow through the gateway | Configure the upstream identity provider, signing and encryption keys, database, and separate dashboard login. |
| Scoped API keys | Headless automation needs a managed gateway credential | Enable the key store and use narrow scopes, profiles, expiry, and revocation. |
| Upstream token exchange | An upstream needs a user's delegated identity | Configure the upstream exchange/session contract; require it explicitly where fallback is unacceptable. |
| Gateway identity assertions | A legacy upstream trusts the gateway's assertions | Configure signing keys and the upstream's verification/audience policy. |
| Peer federation | Two gateways need to accept peer-asserted identities | Register each peer's issuer and keys and choose local tenant attribution deliberately. |

Set `AUTHENTIK_ISSUER` to your issuer. Generic OIDC
discovery does not establish interoperability with every provider's login or
MFA claims. The gateway's current assurance normalization includes an Authentik
adapter. Validate the intended provider using [identity configuration](../agents/identity.md).

Scopes provide capability floors; Cedar decides access using the complete
request. Tool annotations are upstream claims, not authority to lower risk or
exempt a call from policy. Step-up is selected by policy and is separate from
risk classification. The documented re-login scope flow does not by itself
prove a particular MFA method or authentication freshness for every issuer.

## Enterprise authorization and tenant boundaries

The opt-in [MCP enterprise-managed authorization extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
lets enterprise policy participate in cross-application access. The gateway
implements ID-JAG issuance and redemption, with Cedar authorization and
SCIM-backed lifecycle information. It is a token issuer and policy decision
point; the upstream provider still owns user authentication. ID-JAG is based on
an [IETF draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/),
so use the [implemented wire contract](../agents/ema.md) when integrating.

Tenant-scoped stores and current directory checks prevent a token claim or
cached tool definition from choosing another tenant's authority. Deprovisioned
SCIM users retain inactive tombstones so deletion does not accidentally restore
access. Protected role membership is rechecked against durable state.

Federation does not make remote peers local administrators. The receiving
gateway chooses tenant attribution, refuses ambiguous issuer mappings, and
excludes peer principals from privileged admin surfaces. The `restricted` and
`full` peer labels are advisory today; do not treat them as different isolation
mechanisms. Runtime upstream reconnect/catalog-refresh operations are currently
gateway-global even though their callers are admin-gated. See the
[federation contract](../agents/federation.md).

## Review an upstream tool change

With a configured database, set `GATEWAY_QUARANTINE_ON_DRIFT_RISK=all` to
quarantine changed descriptions and schemas for every classified tool.
`high` and `medium` restrict automatic quarantine by the existing risk and
side-effect thresholds; the default `off` observes changes without enabling
automatic quarantine. This detects a changed contract, not whether its text is
malicious. Response-content inspection is a separate control.

Open **Servers → Review tool changes**. Select the affected tool to compare
its previously accepted contract with the observed replacement. **Keep
quarantined** leaves the block in place. **Approve this replacement** refreshes
the upstream and accepts only the exact reviewed generation; if it changed
again, reopen the comparison. Other tools remain available under their existing
policies. Annotation-mode acceptance also updates the approved behavior hash
through the existing manifest publication path; configuration reload then
applies that reviewed hash across replicas.

Changes are observed during catalog refresh and reconnect, including scheduled
refresh. Annotation mode also verifies the current descriptor before dispatch.
The first observation establishes the comparison baseline. This workflow does
not add upstream change-notification handling or inspect a server's internal
implementation.

Durable review needs `GATEWAY_DATABASE_URL`. The accepted and current contracts
are bounded to 256 KiB each in storage; an observation that cannot be stored is
refused for that tool without preventing review of other tools. Database failures refuse protected
admission. Existing quarantines survive restart, reconnect, and the upstream's
Clear quarantine control. Without a database, the existing process-local
quarantine remains available, but this durable review screen is unavailable.
Upstream configuration and its review belong to the default configuration
tenant; decisions require its administrator session.

For agent proposals, discover `tool_contract.approve` through
`gateway-admin.describe_action`, read its advertised `get_action_context`, and
copy the selected review's generation and hashes into the proposal. Human
approval uses the same exact-replacement checks as the dashboard.

## Operate the boundary

Policy reload preserves the last valid set on a parse failure. Governed policy
publication and the [human-approved control plane](gateway-administration.md)
provide reviewable change paths. Single-use [break-glass tokens](../agents/break-glass.md)
support narrowly scoped emergency overrides with audit attribution.

The distroless non-root image, outbound destination checks, bounded responses,
credential encryption, and append-only audit support this boundary. They do not
replace correct deployment, key handling, backups, or least-privilege policy.
Use the [configuration guide](../configuration.md) and verify actual refusals
as part of deployment acceptance.
