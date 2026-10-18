# Deployment integrations

The gateway's runtime integrations are optional and configured by the operator.
An installation supplies its own issuer, credential sources, storage, upstream
manifests, policies, and skill repository. Those choices belong in a deployment
repository or configuration service. The gateway source provides the reusable
implementation and synthetic examples.

## Skills identity

An enabled Git skills source requires `GATEWAY_SKILLS_SOURCE_ID`. This stable
namespace becomes part of its `skill://` URIs and authorization evidence; choose
it deliberately. The current backend uses a Gitea-compatible Git API. It does
not claim support for every Git hosting API.

Choose a namespace such as `team-skills`. See [skills from Git](skills-git-source.md)
for source integrity, approval, and availability behavior.

## External credential refresh

The optional Infisical adapter re-reads designated provider credentials from a
scoped location. A separate refresher owns rotation of externally managed OAuth
tokens. The gateway must not compete for a single-use refresh token; reading
the newly published credential preserves the single-owner contract.

Use the same credential location as the designated refresher, and scope the
service token to read only that location. Choose a polling interval that fits
the credential lifetime and refresher cadence. The
[configuration reference](configuration-reference.md) defines the Infisical
client settings and credential reload mapping; the
[inference guide](inference-plane.md) explains provider and credential labels.

## OIDC configuration names

Set `AUTHENTIK_ISSUER` to the issuer used for OIDC discovery and JWKS.
The dashboard and built-in authorization server require compatible OAuth
authorization-code/PKCE endpoints, claims, and client registrations. The
existing Authentik assurance normalization remains part of that implementation;
generic discovery support does not establish tested interoperability with every
provider or every provider's MFA claims.

Use the [identity guide](agents/identity.md) and validate the intended provider's
login, audience, group/scope mapping, and step-up behavior before deployment.
Keep provider-specific setup in your deployment configuration.

## Extension metadata identities

The gateway adds these identifiers of its own to MCP messages. Standard
`io.modelcontextprotocol/` keys are described where the gateway uses them.

| Identifier | Where it appears | Direction | Purpose |
| --- | --- | --- | --- |
| `io.cacahuate.mcp-gateway/retained-delivery` | `CallToolResult._meta` | To clients | Describes a result delivered as a gateway file, or an attachment that is unavailable. It matches `structuredContent._gateway_delivery`. An upstream cannot set it: the gateway removes it from upstream results. |
| `io.cacahuate.mcp-gateway/content` | A Code Mode connector value member | Inside Code Mode | Distinct MCP content blocks accompanying structured data, excluding text that only mirrors that data. Colliding upstream objects are preserved under `data`; see [connector result delivery](codemode.md#runner-authority). |
| `io.cacahuate.mcp-gateway/catalog-revision` | `_meta` of skill prompts in `prompts/list` | To clients | The skills catalog revision a prompt was listed from. |
| `io.cacahuate.mcp-gateway.code-mode` | Skill frontmatter `metadata` | Read from skill sources | Optional skill-script compatibility metadata. |
| `io.bennight.gateway/responseMaterializationLimitBytes` | Request `_meta` of the gateway's own `resources/read` calls, inside the gateway only | Internal | The largest response the gateway will materialize for that read. The upstream pool removes it before sending, and the gateway's HTTP transport enforces the limit; upstreams never receive it. |
| `_gateway_delivery` | A `structuredContent` member | To clients | The delivery envelope of a result delivered as a file. Published output schemas accept it as an alternative to the upstream's own result. |
| `_gateway_preview` | A `structuredContent` member, beside `_gateway_delivery` | To clients | The upstream's own text for a result delivered as a file, when it fits the inline threshold and the result is not labeled sensitive. It repeats the text preview for clients that show the model only structured content. |
| `urn:mcp-gateway:upstream-output` | `$id` inside published output schemas | To clients | Keeps the upstream schema's local references scoped inside that delivery alternative. |
| `_gateway_counts` | A `structuredContent` member | To clients | Reports how a result-count argument was adjusted; see [operation envelopes](agents/tool-envelopes.md). |
| `x-mcp-result-count` | A JSON Schema keyword on a count argument in published input schemas | To clients | Declares the count projection that `_gateway_counts` reports. |
| `gateway:approval` | A key in `inputRequests` of an `input_required` result | To clients | The gateway's own approval request. It is removed from retried requests, and an upstream pause that uses it is refused. |
| `X-MCP-Identity` | HTTP request header | To upstreams that receive it | The gateway's identity assertion for the caller. Sent to `internal` servers by default; see [identity](agents/identity.md) and [trust classification](agents/upstreams.md#trust-classification). |

These are gateway protocol identifiers, not network destinations or MCP standard
fields. New gateway-specific keys use the `io.cacahuate.mcp-gateway/` prefix.
See [protocol areas](architecture.md#9-protocol-areas-and-watched-proposals)
for the boundary that owns each of them.

## Storage and deployment ownership

Persistent manifests and policies are deployment state. Writable publication
paths and file-transfer storage must have the visibility required by all
serving replicas; the gateway does not require a particular NAS, filesystem
vendor, or host path. See [runtime configuration ownership](server-config-source-of-truth.md)
and [file transfer](file-transfer.md).

Keep local image selection, reverse-proxy routes, secret-provider coordinates,
and orchestration in the deployment repository. Source CI publishes artifacts;
deployment automation selects and rolls out an immutable published image.
