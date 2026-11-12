# OpenAI API upstreams

OpenAI API routes use documented API endpoints and an explicitly selected API
credential. They do not use a Codex subscription, a CLI version, or a ChatGPT
account identifier. The gateway's client credential is separate from the
upstream API credential; clients continue to use the gateway's authenticated
`/v1` endpoint and authorized model aliases.

## Credentials and routes

Inject `LLM_CRED_OPENAI_API` through the deployment's secret provider using a
JSON object with one `api_key` member. The value belongs to the configured
OpenAI API project. Never put the credential in a model definition or repository.
The explicit envelope distinguishes API access from a legacy subscription
token. Public OpenAI chat, Responses, embeddings, image, audio, and realtime
routes refuse a subscription credential instead of refreshing or forwarding it.

A pinned Responses model in `GATEWAY_LLM_MODELS` uses this shape:

```json
{
  "alias": "reasoning-api",
  "provider": "openai",
  "credential_label": "API",
  "upstream_model": "qualified-responses-model",
  "base_url": "https://api.openai.com/v1",
  "surface": "responses"
}
```

Replace `qualified-responses-model` with a model that the API project can actually use. The alias is a gateway
name, and the upstream model is an operator choice; the gateway does not
translate subscription entitlements into API access. Omit `surface` for Chat
Completions. For images use `kind: images` and omit `surface`; see
[Images API](images-api.md). Existing [audio and realtime](audio-api.md)
configuration remains explicit, including operation capabilities and limits.

Unary and streaming Responses requests use the existing translation, usage,
authorization, approval, quota, budget, audit, and failover paths. A
`previous_response_id` is provider-owned conversation state: send it through
the same stable primary credential and endpoint. Such a continuation makes
one attempt and never moves to another credential or backend. A stateless
request may use configured failover, but a handle created by a fallback belongs
to that backend. Changing the alias's primary does not move stored history.
No gateway conversation store is introduced.

## Model discovery

An OpenAI API target in `GATEWAY_LLM_DISCOVERY` uses:

```json
[
  {
    "provider": "openai",
    "credential_label": "API",
    "base_url": "https://api.openai.com/v1",
    "responses_models": ["qualified-responses-model"]
  }
]
```

The documented `/models` listing supplies model IDs and availability, without
operation, modality, or price metadata. `responses_models` therefore names the
exact IDs that the operator has qualified for Responses. Missing or empty
selection produces an actionable refresh error and preserves the last-good
catalog; it does not guess support from a model name. Other operations remain
explicit model pins. Listing a model does not grant callers access or prove
account entitlement to every feature.

Discovered aliases are `openai:<id>` and use the public `responses` endpoint
with the selected API credential. Only one discovery target per provider is
supported. No CLI release lookup, client-version query, or subscription headers
are used. Existing response-size bounds and refresh intervals apply.
Malformed, failed, or raw-empty listings preserve last-good discovery. A valid
non-empty listing in which every selected model has disappeared soft-disables
those discovered aliases. Operator pins and configured prices are retained.
No price is invented when the provider listing omits it.

## Migrate a subscription route

1. Provision API access, model permissions, and billing with the provider.
   Inject a separate API credential label; do not overwrite the subscription
   label while existing aliases still depend on it.
2. Add explicit API aliases and, optionally, the qualified Responses discovery
   target above. Existing subscription discovery must be replaced because one
   target per provider is supported. Pins can coexist during the transition.
3. Check model authorization and harmless unary/streaming requests through the
   gateway. Qualify image generation/editing and configured audio capabilities
   separately when used. Automated tests require no paid provider call.
4. Move clients to the API aliases. Finish existing provider-owned conversations
   on their original backend or begin a new conversation with explicit history;
   response handles cannot be migrated between accounts or endpoints.
5. Remove unused subscription routes and credentials from deployment
   configuration. Consumer subscription support is removed; follow the
   [API-only upgrade guide](api-only-inference-migration.md) before upgrading.

The API Images adapter preserves bounded PNG/JPEG/WebP uploads, JSON inline
edits, reported usage, and one provider attempt. It does not add automatic
retries, caching, fallback, streaming, remote image fetches, or provider file-ID
resolution. Provider account restrictions and per-model upload limits remain
authoritative. These are reviewed capability differences, not promises that
every subscription feature has an API equivalent.

References: [OpenAI API authentication](https://developers.openai.com/api/reference/overview),
[model listing](https://developers.openai.com/api/reference/resources/models/methods/list),
[Responses](https://developers.openai.com/api/reference/resources/responses/methods/create),
and the image API references in [Images API](images-api.md#references).
