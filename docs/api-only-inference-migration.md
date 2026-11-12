# Migrate inference to supported provider APIs

Waygate inference accepts provider API credentials. Consumer subscription
sign-in, subscription-token loading and refresh, consumer model listing, and
CLI request fingerprints are removed. This is a breaking configuration change.
It does not change MCP client authentication, upstream MCP OAuth, the built-in
authorization server, token exchange, or existing API-key injection and rotation.

## Capability and migration matrix

| Previous configuration | Supported replacement | Constraints to qualify |
| --- | --- | --- |
| OpenAI consumer/Codex subscription upstream | OpenAI API key envelope; Chat Completions or explicit `surface: responses` | API billing, model access and pricing are separate. Select the endpoint and model explicitly; subscription allowances do not transfer. |
| Consumer image route | Explicit OpenAI API `kind: images`, without a surface selector | Qualify generation and editing separately; bounded uploads and supported options remain documented in the Images guide. |
| Google Code Assist or Gemini CLI credential | Gemini Developer API key envelope and explicitly selected generateContent models | Vertex AI, ADC/workload OAuth, Interactions, Live and native image/audio/embedding operations are outside this adapter. |
| Anthropic subscription material | Bare Anthropic API key and Messages endpoint | Native Messages, including supported Claude Code flows, remains available. Claude Code's authentication to Waygate is separate. |
| OpenRouter API key | Existing bare API key | Chat/embedding discovery, pricing and configured failover remain available. |
| External consumer-token refresher | Remove its inference configuration; optionally retain scoped API-key rotation | The Infisical reloader reads selected references and accepts only valid API-key replacements. It never refreshes consumer access tokens. |

The supported [OpenAI](openai-api-upstreams.md),
[Gemini](gemini-api-upstreams.md), [Messages](inference-plane.md#48-native-anthropic-messages-profile),
[Images](images-api.md) and [audio](audio-api.md) guides define each adapter's
actual capabilities. Existing self-hosted embeddings without upstream
authentication remain governed by their explicit configuration. No API feature
parity or account entitlement is inferred from a provider name or model listing.

## Upgrade procedure

1. Inventory configured primary and fallback model routes, discovery targets,
   credential labels and any external credential-reload mappings. Provision
   supported API access and choose billing accounts, qualified models and prices.
2. On a release that supports both configurations, add separate API labels and
   explicit API aliases. Qualify the client operations actually used, including
   streaming, tools, images or audio where applicable. Move callers deliberately.
3. Complete provider-owned conversations on their original backend, or begin a
   new conversation with explicit history. `previous_response_id` belongs to its
   original provider, endpoint and credential; changing a route does not move it.
4. Remove subscription credential blobs and nonempty `LLM_OAUTH_*` settings.
   Replace `surface: codex` in primary and fallback definitions with explicit API
   routes. Remove discovery `client_version`; configure `responses_models` or
   `generate_content_models` where required. Replace consumer endpoint URLs.
5. Migrate or disable historical catalog aliases still marked `openai_chatgpt`.
   An explicit API pin can reclaim a discovered alias; verify its endpoint,
   credential, upstream model and pricing. Retained legacy rows stay readable
   but client model discovery withholds them and invocation refuses them before
   cache lookup or provider contact.
6. Validate the resulting configuration and qualify the candidate deployment
   against its backup and restore procedure before replacing the running release.

Malformed credentials and retired configuration fail with migration guidance;
they are not silently skipped, converted or sent to another provider. Invalid
API-key reloads preserve the prior key. Locally loaded credential health does
not prove provider access. Discovery preserves last-good rows on failed or
incomplete listings. Historical usage, audit and account metadata remain intact;
this upgrade does not revoke credentials or delete provider accounts.
