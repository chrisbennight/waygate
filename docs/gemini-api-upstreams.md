# Gemini Developer API upstreams

Waygate supports the documented Gemini Developer API through its existing
inference pipeline. Unary and streaming generation, function calls, structured
output, usage extraction, and ordinary model governance use the Gemini
translation adapter. This integration does not use Code Assist subscriptions,
Gemini CLI sign-in, or a consumer session as an API credential.

## Configure API access

Provision a provider-supported Gemini API key and inject it through the
deployment's secret provider as `LLM_CRED_GOOGLE_API`. Use a JSON object with
one `api_key` string member. Keep the value out of model definitions and source
control. `LLM_CRED_GEMINI_API` is also accepted as a credential-name alias.
The gateway selects and checks API-key material under the credential lock;
reloading a subscription token cannot turn it into a key.

Configure a qualified text/function model in `GATEWAY_LLM_MODELS`:

```json
{
  "alias": "gemini-api",
  "provider": "google",
  "credential_label": "API",
  "upstream_model": "qualified-gemini-model",
  "base_url": "https://generativelanguage.googleapis.com"
}
```

Replace `qualified-gemini-model` with an API model the project can use. The base
URL is the API origin, without `/v1beta`; the adapter supplies the model path
and `generateContent` or `streamGenerateContent` method. Streaming requests use
`alt=sse`. The key travels only in `x-goog-api-key`, never in a URL or consumer
Bearer header. Existing connect, read, response-size, and inference limits apply.

Clients continue to use the gateway's authenticated `/v1/chat/completions` or
`/v1/responses` surface and an authorized alias. Provider access does not grant
gateway model access. Existing profile restrictions, policy, approvals,
budgets, and auditing remain authoritative. Provider project permissions,
availability, and quotas remain provider decisions.

## Function-call continuity

Current Gemini function calls can carry a provider call ID and a
`thoughtSignature` containing opaque context needed for the next step.
Waygate preserves the ID and carries the signature on the returned Chat
Completions tool call as `extra_content.google.thought_signature`. Responses
function-call output items carry the same metadata. Clients must retain that
metadata when replaying calls with their tool results.

The Gemini renderer returns the original function-call signature and matching
call ID, including the ID on `functionResponse`. Parallel calls keep their own
metadata and order; sequential tool steps retain the earlier calls and results.
A later turn reusing a call ID does not rename an earlier function result.
Older responses that omit IDs retain synthetic client correlation. The
contextual assistant also retains this context in its existing transcript.

The signature is not interpreted, generated, or used as gateway authority.
Other provider renderers omit it. Moving to another provider or trimming
history does not transfer the original provider's reasoning state. This is
function-call compatibility, not a native Gemini response/body passthrough.

## Model discovery

An optional `GATEWAY_LLM_DISCOVERY` entry uses:

```json
[
  {
    "provider": "google",
    "credential_label": "API",
    "base_url": "https://generativelanguage.googleapis.com",
    "generate_content_models": ["qualified-gemini-model"]
  }
]
```

The official Models API reports `supportedGenerationMethods`. A selected model
is registered only when it advertises `generateContent`; embedding-only models
are not routed as chat. Selection is explicit because the method name does not
establish every model's output modality. Qualify text/function models rather
than selecting native image or speech generation models by their names.

Discovery follows the API's page tokens with 1000 requested entries per page,
at most ten pages, and the existing body-size bound per page. Keys stay in
headers. Missing selected-model method metadata, malformed data, repeated page
tokens, fetch errors, and incomplete pagination preserve the last-good
catalog. Raw-empty listings also preserve it. A complete non-empty listing
soft-disables disappeared or no-longer-compatible selected models. Pins remain
independent. Discovery supplies no fabricated prices or account entitlement.
Aliases are `google:<id>`, and only one target per provider is supported.

## Migration and boundaries

Add a separate API credential and qualified API aliases, verify the client
conversation flow, then move callers and retire unused subscription
configuration. Subscription material is refused at startup and reload,
before provider contact. Raw token strings are not
API-key envelopes; the provider validates explicitly selected API-key values.
Do not put an OAuth blob inside the `api_key` member; malformed or mixed
envelopes are rejected. Subscription loading and refresh support are removed. See the
[API-only upgrade guide](api-only-inference-migration.md).

Supported here: the Developer API's `v1beta` generateContent methods with API-key
authentication. Vertex AI, ADC/workload OAuth, Code Assist endpoints, the
Interactions API, provider-side built-in tools, and native Google embedding,
image, audio, or Live API operations are outside this adapter. Existing
translation limits, including rejection of `reasoning_effort`, still apply.
The API's broader feature list is not a promise of gateway support. Account
setup and billing are operator responsibilities; tests use synthetic providers
and require no paid calls.

References: [API keys](https://aistudio.google.com/docs/api-key),
[model listing](https://aistudio.google.com/api-reference/models/list-models),
[generation and Part/function fields](https://aistudio.google.com/api-reference/generate-content),
and [Google's function-call signature rules](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/thought-signatures).
