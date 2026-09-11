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

Configure the reload mapping with `GATEWAY_LLM_CRED_RELOAD`. To enable its client,
supply the API URL, read-only service token, and project identifier through
`GATEWAY_INFISICAL_API_URL`, `GATEWAY_INFISICAL_TOKEN`, and
`GATEWAY_INFISICAL_PROJECT_ID`. The enabled client also requires explicit
`GATEWAY_INFISICAL_ENV` and `GATEWAY_INFISICAL_SECRET_PATH`. The latter two are
location metadata, not credential values. Scope the service token to only that
location. An absent client configuration leaves this optional adapter disabled.

Use the same credential location as the designated refresher. Select `GATEWAY_LLM_CRED_RELOAD_SECS` according to the
credential lifetime and refresher cadence; its default is 300 seconds and zero
disables polling. See [inference configuration](inference-plane.md) for mapping
provider and credential labels.

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

The gateway uses these extension metadata keys:

| Key | Purpose |
| --- | --- |
| `io.cacahuate.mcp-gateway.code-mode` | Optional skill-script compatibility metadata. |
| `io.cacahuate.mcp-gateway/retained-delivery` | Retained file-delivery metadata. |
| `io.bennight.gateway/responseMaterializationLimitBytes` | Catalog materialization budget metadata. |

These are gateway protocol identifiers, not network destinations or MCP standard
fields.

## Storage and deployment ownership

Persistent manifests and policies are deployment state. Writable publication
paths and file-transfer storage must have the visibility required by all
serving replicas; the gateway does not require a particular NAS, filesystem
vendor, or host path. See [runtime configuration ownership](server-config-source-of-truth.md)
and [file transfer](file-transfer.md).

Keep local image selection, reverse-proxy routes, secret-provider coordinates,
and orchestration in the deployment repository. Source CI publishes artifacts;
deployment automation selects and rolls out an immutable published image.
