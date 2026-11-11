# Inference reference

## Supported behavior

- **Realtime surfaces:** standard WebSocket sessions and unified WebRTC calls
  use explicit provider capabilities and model gates. Providers terminate media;
  the gateway observes standard sideband events and applies bounded session
  lifetimes and cleanup. See [Realtime configuration](audio-api.md#realtime-configuration).
- **Speech surface:** `POST /v1/audio/speech` serves explicitly configured
  OpenAI-compatible speech providers through the shared model gates. Audio bytes
  and speech SSE retain their separate delivery contracts; usage stays unknown
  when no authoritative counts are reported. See [Speech API](audio-api.md).
- **Transcription surface:** `POST /v1/audio/transcriptions` serves explicitly
  configured OpenAI-compatible transcription providers through the shared model
  gates. Uploads are bounded, provider requests are rebuilt from validated fields,
  and standard JSON or plain-text formats are returned. Transcription is recorded
  as zero cost. See [Transcription](audio-api.md#transcription).
- Standard recording-based voice and consent resources use one explicitly
  configured audio provider and the same model gates. Resource visibility and
  persistence remain provider-owned; see [voice and consent resources](audio-api.md#voice-and-consent-resources).
- Client surfaces: `POST /v1/chat/completions` and `POST /v1/responses` are both mounted
  today, **unary and streaming**. The Responses route parses to the same canonical
  `LlmRequest` and renders the response through the canonical response hub. For streaming, an
  OpenAI-Responses upstream's frames already speak the Responses event protocol and are
  relayed 1:1 as named SSE events; for the other providers, the gateway's normalized
  chat-chunk stream is lifted into Responses streaming events (`response.created` →
  `output_item.added` → `output_text.delta` … → `response.completed`) — there is no `[DONE]`
  sentinel on the Responses transport. As on the unary path, the translated providers carry
  text + function calls; reasoning is carried in full for the native-protocol
  (OpenAI-Responses) upstream, and as plain reasoning text for an OpenAI-chat upstream that
  returns it (§14).
- **Images surface:** `POST /v1/images/generations` and `POST /v1/images/edits`
  serve explicitly configured OpenAI API image models through the same model
  gates. Consumer subscription image routes are refused; see [API migration](api-only-inference-migration.md).
  See [Images API](images-api.md) for SDK examples, limits, and supported options.
- **Embeddings surface:** `POST /v1/embeddings` is also mounted (**unary only** — embeddings
  have no streaming form), routing an OpenAI-compatible embeddings model through the **same**
  governed pipeline (authorize / quota / budget / audit — I1) as the chat surfaces. It is a
  distinct *operation* (§4.7): its own canonical request, an input-token-only
  usage/cost record, and an `LlmOperation` discriminator on the resolved model that the
  pipeline branches on — rejecting a surface/operation mismatch (an embeddings model on a chat
  route, or a chat model on `/v1/embeddings`) with a clean client error. Only the
  OpenAI-compatible `/embeddings` shape is wired (covering OpenAI, OpenRouter, Together,
  Voyage, Mistral, Jina, Cohere-compat, and self-hosted TEI/vLLM/Ollama); native non-OpenAI
  embed protocols (Gemini `:embedContent`, Cohere `/v1/embed`) are not supported.
  Embeddings *discovery* is wired for **OpenRouter** (its dedicated `/embeddings/models`
  listing); auto-discovery for the other providers is not supported (§7.1).
- **Native Anthropic Messages surface:** `POST /v1/messages` accepts an Anthropic Messages
  request body and forwards it to an Anthropic Messages route without canonical translation,
  unary and streaming. Prompt-cache breakpoints (`cache_control`), extended thinking, native
  content blocks, and provider server-side tools therefore reach the provider intact. The
  surface is provider-pinned: it serves only models whose route speaks Anthropic Messages, and
  every governance stage applies (§4.8).
- Four providers: **OpenAI** (API-key Chat/Responses and configured image/audio operations),
  **Google Gemini** (Developer API key → `generateContent`), **Anthropic** (first-party
  `x-api-key` → Messages API), and **OpenRouter** (API key → compatible Chat Completions).
  Consumer subscription upstreams are removed. See the [OpenAI](openai-api-upstreams.md)
  and [Gemini](gemini-api-upstreams.md) API guides for supported configuration.
- Fully-unified streaming invocation; credentials **injected** by Infisical; **lagging**
  per-user token/cost budgets; routing + credential pooling/failover; exact-match cache
  (off by default); usage/cost analytics; admin UI incl. credential status.

**Out of scope (v1):** semantic caching, server-side multi-turn session state,
experimentation/evals/fine-tuning, guardrail suites beyond the existing inspectors,
inference-specific SAML/SSO or multi-region HA.

---

## 2. Invariants (load-bearing rules)

These are the rules the implementation may not violate. Tests assert them.

- **I1 — One enforcement service.** Every LLM call enters the existing
  `DefaultInvocationService` and reuses its authorization, profile,
  output-validation preparation, quota, approval, and pre-call audit methods in the same
  order as MCP tools. Translation, provider dispatch, and outcome finalization are
  LLM-specific arms inside that service; there is no second authorization or quota
  implementation.
- **I2 — Validate before the irreversible call.** The upstream provider request costs money
  and consumes provider quota; it is the irreversible side effect. Authorization,
  budget-not-exhausted, profile allow-list, and (where configured) approval are all checked
  **before** dispatch. No "validate by failing through the provider call."
- **I3 — Lagging budgets, no reservation.** Token/cost budgets are enforced from *recorded*
  usage. The pre-dispatch gate rejects only when the budget is *already* exhausted; actual
  usage is attempted best-effort after completion or at stream close. The gateway makes no
  pre-dispatch reservation, so concurrency or a dropped usage write can exceed the nominal
  budget by more than one request. A hard overrun bound is not currently provided.
- **I4 — Provider API credentials are injected, never minted or written back.**
  `waygate-llm-credentials` accepts injected API keys and holds them in memory.
  It does not perform consumer sign-in or token refresh. The optional scoped,
  read-only Infisical reloader in `waygate-server` reads only configured secret
  references and applies replacements through the same API-key parser. A failed
  read or invalid replacement retains the prior key. MCP authorization and its
  separate upstream-session refresh remain independent of inference credentials.
- **I5 — Streaming is first-class.** Responses stream and the canonical usage/outcome record
  is finalized at stream close. The generic MCP response-inspector and output-schema stages
  are not wired into the LLM arm today; provider translation normalizes content-filter and
  refusal signals but is not a substitute for gateway DLP inspection.
- **I6 — Provider-agnostic core, provider-specific edges.** A canonical request/response/usage
  model sits between the client surface and the four provider dialects. Provider quirks
  live only in translation adapters.
- **I7 — Models are catalog entities.** Models are registered like tools: catalog entries
  that Cedar gates. One catalog, one authorization model.
- **I8 — Fail closed on policy/identity; fail over on transport/credential.** A denied Cedar
  decision or exhausted budget is a hard stop. A transient upstream/credential failure fails
  over to a healthy pooled credential or provider.
- **I9 — Usage records carry metadata, not content.** The `InferenceRecord` (below) stores
  no prompt or completion text — only counts, ids, timings, costs, classifications — unless
  audit content-logging is explicitly enabled, in which case the existing inspection/redaction
  applies first.

---

## 3. Architecture

```
client (OpenAI SDK / Codex / aider / Open WebUI / LiteLLM)
   │ POST /v1/chat/completions | /v1/responses (unary + streaming)  |  POST /v1/embeddings (unary)
   ▼
waygate-server: inbound authn (waygate-oidc | waygate-apikeys)
   │  LLM ingress adapter: Chat/Responses payload → canonical LlmRequest, OR
   │                       embeddings payload → canonical EmbeddingsRequest → InvocationRequest
   ▼
InvocationService  (waygate-invocation trait / waygate-mcp impl — SHARED with MCP tools)
   resolve → validate_input → extract_facts → authorize(Cedar) → profile →
   prepare_output_validation → check_quota(lagging) → check_approval → record_pre_call →
   dispatch ──► waygate-llm-dispatch → waygate-llm-credentials → waygate-llm-providers
   │                                   (model→pool, failover)   (in-memory API keys)   (HTTP+SSE)
   │                                                            waygate-llm-translate
   │                                                            (canonical ↔ provider, SSE frames)
   inspect_response → validate_output → record_outcome
   │ MCP tools: inspect + validate run in this order
   │ LLM arm: inspect/validate are currently unwired; outcome + usage finalize at stream close
   ▼
InvocationResponse::Stream → axum Sse (text/event-stream) → OpenAI-shaped frames to client
   (stream:false → InvocationResponse::UnaryValue(json) → single JSON body to client)
```

Provider-specific crates: `waygate-llm-translate`, `waygate-llm-providers`, `waygate-llm-credentials`,
`waygate-llm-dispatch`. Shared components are listed in §2.

The unification is at the **pipeline/governance** layer; ingress and egress are OpenAI-shaped
protocol adapters (not MCP JSON-RPC). The one structural pipeline change is a streaming
response type (§5).

---

## 4. Data contracts

The shared data model represents provider differences, usage, and cost.

### 4.1 Canonical request (`LlmRequest`)

The client surface normalizes into one internal shape (both `/v1/chat/completions` and
`/v1/responses` parse into it today); provider adapters render it outward.

```rust
struct LlmRequest {
    inbound_surface: Surface,                // ChatCompletions | Responses (selects the egress shape)
    model_requested: String,                 // alias as the client asked
    messages: Vec<CanonicalMessage>,         // system/user/assistant/tool; content parts incl. ToolUse / ToolResult
                                              //   and replayed reasoning (§14)
    sampling: Sampling,                       // temperature, top_p, max_tokens, stop, seed, reasoning_effort,
                                              //   reasoning_summary, …
    tools: Vec<CanonicalTool>,                // function/tool defs (name, description, parameters, strict)
    tool_choice: Option<ToolChoice>,          // Auto | None | Required | Function(name)
    parallel_tool_calls: Option<bool>,        // forwarded where the provider supports it
    response_format: Option<ResponseFormat>,  // JsonObject | JsonSchema { name, strict, schema }
    previous_response_id: Option<String>,     // Responses continuity; forwarded to a Responses
                                              //   upstream, gated for non-Responses routes (§14)
    store: Option<bool>,                      // forwarded; store:false is honoured (§14)
    stream: bool,
    stream_include_usage: bool,               // chat stream_options.include_usage (§4.4)
    include_encrypted_reasoning: bool,        // Responses include: ["reasoning.encrypted_content"] (§14)
    prompt_cache_key: Option<String>,         // Responses prompt-cache hint (§14)
}
enum Surface { ChatCompletions, Responses }
```

The **completions/responses differentiator**: each provider declares a `upstream_api`.
When the client's surface differs from the target's native surface, the canonical layer
round-trips (e.g. a Chat-surface request routed to Anthropic Messages, Gemini, or the
OpenAI Responses API).

Where a feature is genuinely unrenderable on the resolved provider, a **pre-dispatch
capability gate** (`waygate_llm_translate::check_provider_support`) rejects the request
with a clean client error *before* authorize / quota / provider contact (I2/I6) rather
than silently degrading. In the current implementation that surfaces as
`InvocationError::InvalidArguments` (HTTP 400); the per-provider renderers enforce the
same rules locally as a fail-closed backstop. The standing gates today are (1)
`response_format` combined with the caller's own tools on Anthropic (an ambiguous
emulation — see §4.5), and (2) `previous_response_id` on a non-Responses upstream protocol
(there is no store to resolve it against — see §14); streaming tool calls are translated on
every provider.

### 4.2 `InferenceRecord` — canonical response metadata (the key addition)

Produced once per invocation (at stream close, or at sync collection). It is the single
record that feeds audit, OTel `gen_ai.*`, usage rollups, budget debit, and the response
headers echoed to the client. It captures **far more than tokens** — explicitly including
which model actually served the request.

```rust
struct InferenceRecord {
    // identity / routing
    request_id: Uuid,                 // gateway-assigned
    principal: Option<PrincipalRef>,  // who (sub/tenant), for budgets + audit
    provider: String,                 // "anthropic" | "openai" | "gemini" | "openrouter"
    credential_label: String,         // which pooled cred served it (e.g. "PRIMARY")
    model_requested: String,          // what the client asked for (alias)
    model_served: String,             // what the upstream actually ran  ← per user request
    inbound_surface: Surface,         // ChatCompletions | Responses
    upstream_protocol: UpstreamProto, // OpenAiResponses | AnthropicMessages | Gemini | OpenAiChat

    // tokens (Option = provider did not report this class)
    input_tokens: Option<u64>,       // inclusive of cache reads and creation
    output_tokens: Option<u64>,      // inclusive of reasoning
    cached_read_tokens: Option<u64>,  // prompt-cache hits (Anthropic/OpenAI/Gemini)
    cache_write_tokens: Option<u64>,  // input subset used for cache creation
    reasoning_tokens: Option<u64>,    // thinking/reasoning (o-series, Gemini thoughts)

    // outcome
    finish_reason: FinishReason,      // normalized: Stop|Length|ToolUse|ContentFilter|Error|…
    error_class: Option<ErrorClass>,  // normalized upstream error taxonomy
    refusal: bool,

    // timing
    ttft_ms: Option<u32>,             // time to first token (streaming)
    total_ms: u32,
    upstream_latency_ms: Option<u32>,

    // cost (Option = no costing configured / unknown)
    input_cost: Option<Decimal>,
    output_cost: Option<Decimal>,
    cached_read_cost: Option<Decimal>,
    cache_write_cost: Option<Decimal>,
    total_cost: Option<Decimal>,
    cost_source: CostSource,          // ProviderReported | ComputedFromCatalog | Unknown

    // cache
    gateway_cache_hit: bool,          // our exact-match cache served it
    provider_prompt_cache: Option<bool>,

    // upstream references (for debugging / correlation)
    upstream_request_id: Option<String>,
    system_fingerprint: Option<String>,
}
```

**Cost attribution:** the usage sink looks up catalog rates for **`model_served`**
and the resolved provider. If the served model is unreported, it uses the requested
alias. Provider-reported cost is a reserved source and is not currently extracted.
Ordinary input is the inclusive input total minus reported cache-read and
cache-creation subsets. Each class is priced once at its configured rate.
For example, 1,000 input tokens including 400 cached tokens, with synthetic rates
of 2 per million ordinary tokens and 0.5 per million cached tokens, cost 0.0014
when output is zero. Reasoning is already part of output and is not added again.

A missing primary usage count, an inconsistent cache subset, or a missing rate
for positive usage leaves `total_cost` NULL and `cost_source` `unknown`.
Known line items remain available in `input_cost`, `output_cost`,
`cached_read_cost`, and `cache_write_cost`, but their subtotal is not presented as an
exact call cost. A reported zero needs no rate. Omitted optional cache subsets
remain unreported and add no separate charge. Catalog costs cover the recorded
token classes; they do not include provider storage or other non-token fees.

New ledger rows carry `accounting_version = 2`. Existing rows and writes from
older binaries retain version 1, with the new cache-cost columns left NULL:
their historical counts and costs are preserved,
not retrospectively recomputed. The ledger lacks the original wire protocol and
historical rate snapshots needed to repair every old row reliably. Analyses
requiring normalized counts and complete costs should select version 2.
Rolling budgets continue to include historical rows using their recorded values
until those rows leave the window, so a window spanning the upgrade can retain
the earlier accounting errors. Missing cost remains excluded from cost totals;
missing usage is not evidence that a request was free.

### 4.3 Per-provider extraction mapping (the translator contract)

`waygate-llm-translate` MUST populate `InferenceRecord` from each provider's response and its
**terminal streaming frame**. "—" = not reported by that provider.

| Field | OpenAI Responses | Anthropic Messages | Gemini generateContent | OpenRouter (OpenAI Chat) |
|---|---|---|---|---|
| model_served | `response.model` | `message.model` | `modelVersion` | `model` |
| input_tokens | `usage.input_tokens` | `usage.input_tokens` + reported cache reads + reported cache creation | `usageMetadata.promptTokenCount` | `usage.prompt_tokens` |
| output_tokens | `usage.output_tokens` | `usage.output_tokens` | `usageMetadata.candidatesTokenCount` + reported `thoughtsTokenCount` | `usage.completion_tokens` |
| cached_read_tokens | `usage.input_tokens_details.cached_tokens` | `usage.cache_read_input_tokens` | `usageMetadata.cachedContentTokenCount` | `usage.prompt_tokens_details.cached_tokens` |
| cache_write_tokens | `usage.input_tokens_details.cache_write_tokens`, when reported | `usage.cache_creation_input_tokens` | — | `usage.prompt_tokens_details.cache_write_tokens`, when reported |
| reasoning_tokens | `usage.output_tokens_details.reasoning_tokens` | — | `usageMetadata.thoughtsTokenCount` | `usage.completion_tokens_details.reasoning_tokens` |
| finish_reason | `response.status` + `incomplete_details.reason` | `stop_reason` | `candidates[].finishReason` | `choices[].finish_reason` |
| upstream_request_id | `response.id` | `message.id` | `responseId` (where present) | `id` |
| system_fingerprint | — | — | — | `system_fingerprint` |
| provider-reported cost | — | — | — | usage accounting (when enabled) |

**Streaming usage arrival differs and MUST be handled so budgets always have data:**

- **OpenAI Chat / OpenRouter:** usage only appears in the final chunk **if** the request sets
  `stream_options.include_usage = true`. The gateway MUST inject this on streaming requests.
- **OpenAI Responses:** final `response.completed` event carries `usage`.
- **Anthropic:** `message_start` carries input + cache tokens; `message_delta` carries
  cumulative `output_tokens`; finalize at `message_stop`.
- **Gemini:** `usageMetadata` arrives on the final SSE chunk (cumulative).

The gateway requests streaming usage where supported and uses the same accounting
parsers for unary and streamed responses. A provider can still omit usage or end
early; missing primary counts stay unknown rather than becoming zero.

Provider semantics are grounded in the [OpenAI prompt-cache accounting guide](https://developers.openai.com/api/docs/guides/prompt-caching#monitor-cache-performance),
the [Anthropic cache usage breakdown](https://platform.claude.com/docs/en/build-with-claude/prompt-caching),
and [Gemini usage metadata](https://ai.google.dev/api/generate-content#UsageMetadata).
Anthropic input excludes cache reads and creation; OpenAI and Gemini input already
include cache reads. Gemini reports thoughts separately from response candidates;
OpenAI and Anthropic output already include their reasoning tokens.

### 4.4 Streaming translation (`StreamTranslator`)

The per-provider `StreamTranslator` (`stream.rs`) folds each provider's SSE frame straight
into the OpenAI `chat.completion.chunk` shape the gateway streams back to a
`/v1/chat/completions` client, while folding usage / finish-reason into the terminal
`InferenceRecord`. `push(frame) -> StreamStep { chunks: Vec<Value>, done }`; OpenAI/OpenRouter
frames pass through 1:1, Anthropic / Gemini / Responses events are translated, and each
non-OpenAI stream synthesizes the terminal `[DONE]` for the chat transport.

A chat client that sets `stream_options.include_usage` receives a final usage-only chunk
(`choices: []`) before `[DONE]` on every route. OpenAI/OpenRouter routes already send it,
because the gateway always requests usage upstream for metering and forwards that chunk; the
translated protocols add one carrying the same prompt and completion counts as the unary chat
body, with their sum as the total, and add none when the provider reported no counts. Without the option, or
with `include_usage: false`, each route keeps its existing behavior: OpenAI/OpenRouter
streams still carry the upstream's usage chunk and translated streams carry none. Other
`stream_options` keys are rejected by name, and a cache-hit replay ends with the stored
usage.

For a `/v1/responses` client, this chat-chunk stream is the egress *source*, not the
client output: an OpenAI-Responses upstream's frames are relayed 1:1 as named Responses
events, and for the other providers `ChatStreamToResponses` lifts the normalized chat chunks
into Responses streaming events (`response.created` → `output_item.added` →
`output_text.delta` / `refusal.delta` / `function_call_arguments.delta` … →
`response.completed`). The Responses transport carries **no** `[DONE]` sentinel — its
terminal frame is the named `response.completed` / `response.incomplete` event.

Streamed **tool calls** are translated to OpenAI `delta.tool_calls` chunks on every
provider: Anthropic `content_block_start{tool_use}` + `input_json_delta`, Gemini's whole
`functionCall` parts, and Responses `output_item.added{function_call}` +
`function_call_arguments.delta`. The translator overrides the streamed finish reason to
`tool_calls` when the turn carried a tool call (Gemini reports `STOP`, Responses
`completed`), so the client-visible finish and the durable `InferenceRecord.finish_reason`
agree — the same alignment the unary path enforces.

### 4.5 Tool calling & structured output

- **Tools / `tool_choice`** render to each provider's native shape: OpenAI Chat /
  Responses `function` tools 1:1, Anthropic `input_schema` tools with `tool_use` /
  `tool_result` blocks (results merged into a user turn), Gemini `functionDeclarations` +
  `functionResponse` (keyed by function *name*, resolved from the assistant turn's call
  ids). Unary responses unwind provider tool calls back into `message.tool_calls`.
- **`response_format`** is native on OpenAI Chat (`response_format`), OpenAI Responses
  (`text.format`), and Gemini (`responseMimeType` + `responseJsonSchema`). Anthropic has no
  native equivalent, so it is **emulated**: a single synthetic tool
  (`__gateway_structured_output__`) whose `input_schema` is the requested schema is forced,
  and the response/stream translators unwind that tool call back into message content with
  a normal `stop` finish. Combining `response_format` with the caller's own tools on
  Anthropic is ambiguous and rejected by the capability gate (§4.1).

### 4.6 Canonical response (`CanonicalResponse`) & the egress hub

The response path mirrors the request path: every provider's native reply folds into one
typed `CanonicalResponse` (modelled on the OpenAI Responses *superset* — the most expressive
client surface), and each client surface renders from it. This preserves reasoning,
annotations, and built-in-tool items without routing them through chat-only JSON.

```rust
struct CanonicalResponse {
    id, model, created_at,
    status: ResponseStatus,        // Completed | Incomplete { reason } | InProgress | Failed
    refusal: bool,
    output: Vec<OutputItem>,       // Message { content: [OutputText | Unknown] }
                                   //   | FunctionCall | Reasoning { raw } | Unknown
    usage: Option<Usage>,          // input/output/total/cached_read/reasoning — None when unreported
    #[serde(flatten)] extra: Map,  // unmodeled top-level fields, preserved verbatim
}
```

**Opacity at every level.** Unrecognised output items / content parts (`Unknown`), reasoning
items (which may carry `encrypted_content`), and unmodeled fields at the **response**, **item**,
and **content-part** level are all carried verbatim through a flattened `extra`. This is what
makes a Responses→canonical→Responses round-trip lossless (*near-identity*) for an
OpenAI-Responses upstream, and it is mandatory: without it, annotations / reasoning / item
metadata would be silently dropped (I6).

Two egresses, both rendered from the canonical, selected by `LlmRequest.inbound_surface`:

- **`/v1/chat/completions` — the chat downcast.** `canonical_response_to_openai_chat` projects
  the canonical to the chat shape the gateway has always served. It is gated by a
  **byte-identical golden oracle**: for each provider, `downcast ∘ (provider→canonical)` must
  equal the legacy `*_to_openai_chat` translator's output, so migrating the chat path through
  the hub is provably behaviour-preserving. The downcast deliberately drops what chat cannot
  represent (reasoning, annotations, built-in-tool items) — which is exactly why the oracle
  holds (the legacy translators already omit the same material). The OpenAI-chat *upstream*
  stays a pure passthrough for a chat *client* (a typed hub cannot byte-preserve every chat
  field — `logprobs`, `system_fingerprint`, multiple choices); a Responses client lifts it
  into the hub.
- **`/v1/responses` — the Responses egress.** `canonical_response_to_responses` renders the
  Responses body — modeled fields overlaid on the flattened `extra`, with `status` →
  `incomplete_details` reconstruction. For an OpenAI-Responses upstream this is a lossless
  near-identity round-trip (the native-passthrough behaviour falls out of the faithful hub —
  no separate passthrough path); for a translated provider it is the faithful Responses
  projection of the call (text + function calls + refusal; reasoning where the provider returns
  it — an OpenAI-chat upstream's reasoning text becomes a `reasoning` item, §14).

**Streaming is symmetric** (§4.4): the chat transport keeps its proven per-provider
`StreamTranslator`; the Responses transport relays an OpenAI-Responses upstream's frames 1:1
and, for the other providers, lifts the normalized chat-chunk stream into Responses streaming
events (`ChatStreamToResponses`). Unary and streaming therefore share one fidelity contract —
native-protocol upstreams round-trip in full; translated upstreams carry the text+tools (+
refusal) projection.

`InferenceRecord` (§4.2) stays on its own `extract_*` path: the audit ledger is **unchanged**
by the response hub (content-free, I9) — the hub adds the *content* rendering on top, it does
not feed metering.

### 4.7 Embeddings — a second operation

Embeddings (`POST /v1/embeddings`) are a distinct **operation** alongside chat, not a chat
data-contract variant: the chat canonical model (`LlmRequest` = messages/tools/streaming) does
not fit `input → vectors`, so embeddings get their own small canonical type and adapters in
`waygate-llm-translate`. Everything *below* the translation seam is reused unchanged —
credentials, the `waygate-llm-providers` transport, the `LlmDispatcher` failover/cooldown
machinery (§7), the unified pipeline gates (§5), `InferenceRecord`/usage, and cost.

- **Canonical request** (`EmbeddingsRequest`): `model`, an opaque `input` (string | array of
  strings | token-id array | array of token-id arrays — forwarded losslessly), and optional
  `encoding_format` / `dimensions` / `user` / `input_type`. The last is the retrieval task
  hint (`search_query` / `search_document` / …) — an OpenAI-**compatible** extension (Voyage,
  Cohere, OpenRouter, Jina) that materially improves retrieval quality; not part of OpenAI's
  own spec, so it is forwarded only when the client sends it (the provider is the authority on
  accepted values). Parsed fail-closed (`parse_embeddings`): an empty model/input, a
  `stream: true`, or any untranslated field is rejected **before any cost** (I6/I2). There is
  no streaming form.
- **Outbound** is the OpenAI-compatible `/embeddings` shape — a near-passthrough
  (`render_openai_embeddings` substitutes the resolved upstream model; default `Bearer`). This
  one shape covers OpenAI, OpenRouter, Together, Voyage, Mistral, Jina, Cohere-compat, and
  self-hosted TEI/vLLM/Ollama. Native non-OpenAI shapes (Gemini `:embedContent`, Cohere
  `/v1/embed`) are reserved behind an `EmbeddingsProtocol` enum, the embeddings analog of the
  chat `UpstreamProtocol` — the same way chat grew from one protocol to four.
- **Private embedding backends.** An operator-pinned OpenAI-compatible embedding
  model may set authentication to "none" and omit credential_label. The gateway
  sends no provider authorization header and does not resolve a provider secret.
  This requires provider "openai", kind "embeddings", and one route without
  credential pools or fallbacks. Client authentication and the gateway's existing
  authorization, quota and audit gates still apply. Other routes require their
  configured credential. Restrict the backend network to trusted gateway and
  monitoring containers. This setting lives in the environment pin; discovered
  catalog rows never opt into credential-free authentication.
- **Backend options and failures.** The optional prompt_mode and timeout_seconds
  fields are forwarded when supplied; the backend validates their values.
  Base64 embedding strings remain strings throughout the gateway. Backend
  validation statuses, overload (429/503) and deadlines (504) remain actionable
  HTTP responses, with numeric retry advice capped at five minutes. Backend
  authentication failures become 502. Provider error bodies are omitted from
  embedding client and audit diagnostics.
- **Usage/cost** reuse `InferenceRecord`: embeddings report `{prompt_tokens, total_tokens}`,
  so only the **input** token class is populated (`output = None`, no finish reason).
  When input usage is reported, the usage ledger records zero completion tokens
  because embeddings generate no completion; their input can then be priced alone.
- **Operation discriminator.** The resolved model carries
  `LlmOperation` distinguishes chat, embeddings, images, and configured speech
  and transcription capabilities. Embeddings use env config
  `kind: embeddings` and catalog `upstream_api = embeddings`; images use
  `kind: images` and `upstream_api = images`. The pipeline selects `invoke_llm`,
  `invoke_embeddings`, `invoke_images`, `invoke_speech`, or `invoke_transcription` and rejects a **surface/operation
  mismatch** before parsing or provider contact. Chat models use the chat and
  Responses routes, embeddings use `/v1/embeddings`, and image models use the
  generation and edit routes described in [Images API](images-api.md). Speech
  uses `/v1/audio/speech` and transcription uses `/v1/audio/transcriptions`;
  see [Audio APIs](audio-api.md).
- **Caching.** Embeddings participate in the per-principal exact-match cache (§9) on the same
  two-key arming as chat (`GATEWAY_LLM_CACHE_ENABLED` + the model's `cache_ttl`). Being
  unary-only, it is the simplest cache path: a hit replays the stored body verbatim (free, no
  provider call, a `gateway_cache_hit` record); the canonical key is the serialized
  `EmbeddingsRequest` (prefixed so it never collides with a chat key) and stays per-principal
  scoped (§13).
- **Discovery:** auto-discovered for **OpenRouter** via its dedicated `/embeddings/models`
  listing (§7.1); for providers whose `/v1/models` listing does not flag modality and that
  expose no dedicated embeddings listing, embeddings models stay operator-pinned (env
  `kind: embeddings`). **Deferred:** native non-OpenAI embed protocols, and embeddings
  discovery for the other providers (Gemini, OpenAI-direct — see §7.1, §15).

---

### 4.8 Native Anthropic Messages profile

The canonical surfaces reject request fields the canonical model does not represent (I6), so
provider features such as prompt caching are unreachable through them. `POST /v1/messages` is a
second, provider-pinned surface that keeps the body in the provider's own shape instead of
loosening that rule.

- **Routing.** The `model` field names a catalog alias, exactly as on the canonical surfaces. The
  alias must resolve to a chat model whose primary route uses the Anthropic Messages protocol;
  any other model is rejected with a client error before any gate runs. Fallback targets on
  other protocols are skipped, because a native body has no rendering for them. Anthropic
  Messages fallbacks keep the usual pool failover, cooldown, and time-to-first-byte behavior
  (§7).
- **Body.** The gateway checks only what its own decisions depend on: the body is a JSON object,
  `stream` is absent or a boolean, `messages` is an array, and `max_tokens` is a positive
  integer. It replaces `model` with the route's upstream model and forwards every other field
  unchanged, including unknown fields and the order of system blocks. The provider validates
  the rest. Native ingress forwards the open set of `anthropic-*` headers, including
  `anthropic-beta`, `anthropic-version`, and workspace negotiation, without interpreting beta
  values. An absent API version uses the translation adapter's default. Client authorization
  and API-key headers are excluded; the selected route supplies the provider API key.
- **Governance.** The call enters the same invocation service as the canonical surfaces (I1):
  the model authorizes as a Cedar `Model` resource, and profile restrictions, request quota, the
  lagging budget, approval, response capacity, and the pre-call and outcome audit rows all apply
  before or around the provider call (I2).
- **Responses.** A unary response is the provider's Messages body, unchanged. A streamed
  response relays each provider event as a named SSE event (`message_start`,
  `content_block_delta`, …, `message_delta`, `message_stop`), including JSON `ping` events,
  without accumulating the complete response. The provider's HTTP status and selected
  content-type, request-ID, retry, and `anthropic-ratelimit-*` headers reach the client.
  Provider error bodies are relayed byte-for-byte within a bounded error-body limit; an
  oversized body becomes a gateway transport error rather than a truncated provider error.
  Errors produced by the route and the invocation
  pipeline use the Anthropic error envelope (`{"type":"error","error":{"type","message"}}`)
  with the same HTTP status the canonical surfaces would return. Authentication failures are
  answered earlier by the gateway's shared bearer layer, with its standard `401` challenge and
  body, exactly as on the canonical surfaces.
- **Accounting.** Usage is extracted from the native response with the same Anthropic
  extractors as the canonical path, so cache reads and cache creation are recorded and priced
  as described in §4.2. Usage rows carry `inbound_surface = anthropic_messages`.
- **Cache.** Native requests are never served from or stored in the gateway exact-match cache
  (§9), whose key is the canonical request.
- **Authentication.** Clients authenticate to the gateway with `Authorization: Bearer`, not an
  `x-api-key` header. Anthropic SDKs support this through their auth-token option; point the
  SDK's base URL at the gateway root so it calls `/v1/messages`.
- **Claude Code.** Set `ANTHROPIC_BASE_URL` to the gateway root and
  `ANTHROPIC_AUTH_TOKEN` to the caller's gateway credential. Select an authorized catalog
  alias with `ANTHROPIC_MODEL`; use supported API-key credentials on the upstream route.
  `/v1/messages?beta=true` uses the same native route. The optional
  `/v1/messages/count_tokens` endpoint is not implemented, so Claude Code uses its
  character-based estimate. This surface does not implement a Claude apps gateway sign-in,
  Bedrock, or Vertex dialect. The
  [Claude Code gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
  defines the client contract. Synthetic coverage lives in
  `crates/waygate-server/src/llm/messages.rs` and
  `crates/waygate-mcp/tests/suite/llm_dispatch/native_messages.rs`:
  run `cargo test -p waygate-server llm::messages::` and
  `cargo test -p waygate-mcp --test suite llm_dispatch::native_messages::`.

## 5. Invocation flow (normative, LLM specifics)

The shared service owns a thirteen-stage MCP contract. The LLM arm reuses every
pre-dispatch gate in that order, then uses LLM-specific dispatch and finalization. Its current
behavior per named stage is:

| # | Stage | LLM behaviour |
|---|---|---|
| 1 | resolve | model alias → provider + credential pool (`waygate-llm-dispatch`); load the model's catalog entry (risk, costing, upstream_api). |
| 2 | validate_input | translate the surface payload → `LlmRequest`; reject unsupported params with typed errors (before any cost). |
| 3 | extract_facts | `Facts` gains provider, model, risk, pii=true, cost_class. |
| 4 | authorize | Cedar gates the **model** resource (a `permit` on a group; models are **not** step-up-gated — see `authorization-model.md` §6). **Before first byte.** |
| 5 | profile | API-key profile model allow-list. |
| 6 | prepare_output_validation | Called after authorization; no-op for synthetic model snapshots because they carry no MCP output schema. |
| 7 | check_quota | Run shared request-rate quota, then the LLM-specific lagging token/cost budget gate (I3). Reject iff a configured ledger is already exhausted; make no reservation. |
| 8 | check_approval | Called, but currently inactive for LLM requests: synthetic model facts set `requires_approval=false` and do not propagate `llm_models.requires_approval`. |
| 9 | record_pre_call | in fail-closed audit mode, require a chained intent row before the billable provider call; otherwise no-op. |
| 10 | dispatch | check the per-principal cache, then route to a healthy credential (§7); `waygate-llm-providers` issues the provider-native call with the injected bearer (§6) and `stream_options.include_usage` where applicable. Credential/transport failure → failover (I8). |
| 11 | inspect_response | **Not wired for the LLM arm.** Provider translators normalize native content-filter/refusal signals, but configured MCP inspectors do not scan LLM responses. |
| 12 | validate_output | **Not wired for the LLM arm.** Translation/shape errors fail inside dispatch; the catalog output-schema validator does not run on LLM responses. |
| 13 | record_outcome | Unary calls attempt the LLM outcome and usage rows after dispatch; streaming calls do so at stream close. Both writes are best-effort, so the budget ledger advances only when the usage write succeeds. |

Authorization + budget gate run before the irreversible provider call (I2); the usage-ledger
write deliberately lags completion and is currently best-effort (I3).

The table is the chat path. **Embeddings** (`invoke_embeddings`, §4.7) follow stages 1–10
and 13 — resolve (the model's `LlmOperation` selects this branch), validate_input
(`parse_embeddings`), extract_facts → authorize (a Cedar `Model` resource) → profile →
prepare_output_validation (no-op) → quota → budget → approval → record_pre_call →
(cache check) → dispatch → record_outcome → (cache store)
— but, like chat, currently skip the unwired inspector and output-validator stages 11–12.
The per-principal exact-match cache (§9) applies on the
same two-key arming as chat (a hit is served verbatim, free). The usage row carries the input
token class only.

---

## 6. Credentials

Inject `LLM_CRED_<PROVIDER>_<LABEL>` at startup. Labels identify an operator's
credential pool. OpenAI and Google require a JSON envelope containing only
`api_key`; Anthropic and OpenRouter retain their bare API-key format. Values
must be nonempty and contain no control characters. Consumer token blobs,
malformed envelopes and nonempty `LLM_OAUTH_*` settings fail configuration with
an actionable error that does not reproduce credential values.

The store keeps keys in memory and never refreshes or writes them back.
The optional `GATEWAY_LLM_CRED_RELOAD` scheduler supports scoped, read-only
API-key rotation through Infisical; a rejected replacement leaves the prior
key intact. Restart re-injects the configured key. Local credential health
means a key is loaded, not that provider access has been tested. Historical
usage and account metadata remain readable. Follow the
[API-only migration guide](api-only-inference-migration.md) before upgrading
an installation that used subscription credentials or consumer routes.

---

## 7. Routing & failover

- **Model alias → ordered target groups**, each a list of `(provider, credential_label)`
  targets using supported provider API credentials.
- **Selector (v1):** `in_order` and `least-recently-used`; reserve `cost`/`latency`/
  `performance` (the catalog carries costing already).
- **Cooldown:** per `(provider, credential_label)` exponential backoff on consecutive
  failures, **persisted** (survives restart); cooled targets are skipped.
- **Failover (I8):** for stateless requests, on retryable upstream failure (429/5xx/transport) or unhealthy credential
  (§6), try the next healthy target in the group, then the next group; bounded attempts;
  honor `Retry-After`.
  Requests carrying `previous_response_id` instead make one attempt on the resolved
  primary route, including its configured credential, even when that credential is
  cooling down. A fallback endpoint, provider, or credential cannot establish that
  it owns the referenced history. The first-frame deadline still applies; failure
  never starts a second provider attempt for that continuation.
- **Stall detection:** TTFB stall → fail over before the client sees bytes; throughput stall
  after first byte → abort (client already streaming); per-provider overrides for
  long-pre-token reasoning models.

### 7.1 Dynamic model discovery (implemented)

OpenAI API-key discovery uses an explicit `responses_models` selection because
the provider listing does not identify supported operations. It routes selected
IDs to the public Responses API without subscription headers or CLI tracking.
Other operations remain explicit pins. See [OpenAI API upstreams](openai-api-upstreams.md)
for credential selection, configuration, failure behavior, and migration.

The catalog need not be hand-listed: the gateway can fetch each configured
provider's live model list and register the models itself. Opt-in via
`GATEWAY_LLM_DISCOVERY` (a JSON array of `{provider, credential_label, base_url}`
targets, at most one per provider); off by default. Retired `client_version`
settings fail configuration instead of selecting a consumer backend. The discovered catalog and
the env pins (`GATEWAY_LLM_MODELS`) coexist — discovery only *adds* to what an
operator pins.

An operator pin names its upstream identity either as separate `provider` +
`upstream_model` fields or as a single `model: "provider:upstream"` shorthand
(e.g. `openrouter:qwen/qwen3-embedding-8b`) — the same `provider:id` form a
discovered alias carries. The shorthand lets one environment variable drive the
whole upstream identity (`"model":"${EMBEDDING_MODEL}"`) while the client-facing
`alias` stays fixed and independent (so the model a consumer requests does not
change when the backend does). It is split on the first `:` and resolved to the
two fields at parse time, and is mutually exclusive with them.

- **Listing surfaces use supported provider APIs**
  (crate `waygate-llm-discovery`):
  - **OpenRouter** (api key) — `GET {base}/api/v1/models` for chat models AND the
    dedicated `GET {base}/api/v1/embeddings/models` for embeddings models, each tagged
    by operation (catalog `upstream_api = chat_completions` vs `embeddings`). The only
    listing that carries pricing (USD-per-token → the catalog's per-Mtok rates;
    embeddings bill input tokens only). Both listings feed one provider-scoped reconcile
    with a **unioned** seen-set, so the embeddings cycle never soft-disables the chat
    rows (or vice-versa). The embeddings listing is **best-effort**: a base that does not
    expose `/embeddings/models` (e.g. a self-hosted OpenAI-compat endpoint configured as
    `openrouter`) logs a `WARN`, discovery proceeds with chat models only, and reconcile is
    **skipped that cycle** (incomplete picture) so a transient embeddings outage never
    soft-disables previously-discovered embeddings rows. Reconcile is likewise skipped if the
    primary chat `/models` listing returns empty (the transient/garble case); a *successful
    empty* embeddings listing is not degenerate (the provider has no embeddings models) and
    still reconciles them away.
  - **OpenAI API** — bounded `/models` listing with an explicit
    `responses_models` selection. Selected IDs use the Responses API; operation
    support and account access must be qualified by the operator. No consumer
    backend, CLI version tracking or subscription headers are used.
  - **Anthropic** (`x-api-key`) — discovery unwired: stays operator-pinned
    (`DiscoverySurface::Unsupported`). (`/v1/models` is an `x-api-key` endpoint, so
    listing is now technically reachable, but the refresher arm is not built.)
  - **Google / Gemini** (Developer API key) — bounded `/v1beta/models` pagination.
    Explicitly selected `generate_content_models` must advertise `generateContent`.
    Missing method metadata or incomplete pagination preserves last-good rows;
    native image/audio/embedding models are not inferred as text/function routes.
    Consumer OAuth discovery remains unsupported; see [Gemini API upstreams](gemini-api-upstreams.md).
- **Provenance + soft-disable** (`migrations/0054_llm_models_discovery.sql`).
  `llm_models.source` ∈ `config` | `discovered`, orthogonal to the operator's
  `enabled`; `present_upstream` is discovery's view. A row is **effective-live**
  when `enabled AND (source='config' OR present_upstream)`. When a provider drops
  a model the refresher clears `present_upstream` (soft-disable — the row is
  retained for costing/history and re-enable), never deletes it. Discovery never
  touches a `config` pin (the upsert's provenance gate), never clobbers operator
  costing (cost columns are COALESCE-filled, NULL-only, currency-consistent), and
  never moves `enabled`/`risk` (discovered rows take the schema-default `risk`,
  `low` when omitted).
  A config pin that reclaims a previously-discovered alias drops the now-stale
  discovery pricing only when it re-routes to a different `(provider,
  upstream_model)`.
- **Routing resolver** (`waygate_llm_dispatch::DbModelResolver`). Env pins (full
  failover/TTFB/cache fidelity) overlaid with a discovered layer rebuilt from the
  catalog and hot-swapped (`reload`) after each cycle — the pipeline's
  `Arc<dyn LlmModelResolver>` handle never changes. **A pin always wins** over a
  discovered row of the same alias. The resolver **owns the `llm` namespace
  unconditionally** (it exists only when the LLM path is active), so an unknown /
  not-yet-discovered model under `llm` is rejected as unknown — never fell through
  to the MCP path (which would run a `/v1` completion under MCP facts/audit/budget,
  a governance bypass). `llm` is also reserved at manifest load
  (`waygate_core::LLM_RESERVED_NAMESPACE`, exact match) so an MCP upstream can't
  claim it.
- **Discovery-only mode.** With `GATEWAY_LLM_DISCOVERY` set but no
  `GATEWAY_LLM_MODELS`, the LLM path (dispatcher, resolver, `/v1` routes) still
  activates and the refresher populates everything — the "no hand-listing" goal.
- **The refresher** (`waygate-server::llm_discovery`) runs on boot and every
  `GATEWAY_LLM_DISCOVERY_INTERVAL_SECS` (default 3h; values below the 5-min
  floor, or unparseable, reject at boot; bounded HTTP client). Each cycle, per target: read the selected API key,
  fetch the list(s), upsert the discovered models (provider-namespaced alias
  `openrouter:<id>` / `openai:<id>`, with per-model routing — OpenRouter's
  chat-completions or embeddings, OpenAI Responses, or Gemini generateContent — and pricing
  filled when the listing carries it) and reconcile — **all in one transaction** (all-or-nothing per
  target) — then reload the resolver. **Fail-open:** a failed target keeps the
  last-good catalog (`WARN`); an **empty** result skips reconcile so a transient
  empty/garbled response can never mass-soft-disable a provider. Persisted
  discovered rows are loaded into the resolver at boot, so a restart routes them
  immediately (before the first refresh).
- **Credential HTTP policy.** The optional read-only Infisical reloader uses
  its bounded HTTP client. A transport initialization failure aborts that
  configured path. MCP-only startup does not initialize it.
- **Discovery surface for clients.** `GET /v1/models` (OpenAI-compatible) lists
  the caller's tenant's effective-live models, filtered to those the resolver can
  actually dispatch — a **combined** listing of chat, embeddings, and image models,
  each callable on **its matching surface** (chat/responses models on
  `/v1/chat/completions` and `/v1/responses`, embeddings models (§4.7) on
  `/v1/embeddings`, image models on `/v1/images/generations` and
  `/v1/images/edits`). The filter guarantees every listed alias is dispatchable on
  *some* surface, so the listing never advertises an unroutable model — but it
  does **not** imply a model is callable on *every* surface: sending an embeddings
  model to `/v1/chat/completions` (or a chat model to `/v1/embeddings`) is the
  surface/operation mismatch the pipeline rejects (§4.7). Each entry carries a
  **`modality`** field (`text->embedding`, `text->text`, `text+image->image`,
  `text->audio`, `audio->text`, or `realtime-audio`, derived from the row's
  `upstream_api`; a non-standard OpenAI field SDKs ignore), and the listing accepts
  **`?type=embeddings|chat|images|speech|transcription|realtime`** to filter to one
  kind — so a client discovers non-chat models as *distinct* from chat without
  probing each surface. The same operation distinction is projected into the
  `llm_models_catalog` view as a **`kind`** column (`embeddings` | `chat` |
  `images` | `speech` | `transcription` | `realtime`).
- **Embeddings discovery — OpenRouter wired, others operator-pinned.** OpenRouter
  publishes a dedicated `/embeddings/models` listing, so the refresher discovers its
  embeddings models distinctly and tags each row `upstream_api = embeddings` (path
  `embeddings`) — auto-routed to `/v1/embeddings` exactly like a pinned embeddings
  model. Providers whose `/v1/models` listing does not flag *modality* and that expose
  no dedicated embeddings listing (OpenAI-direct) cannot be auto-classified, so their
  embeddings models stay configured via env pins (`kind: embeddings`). Gemini's
  `models.list` *does* flag embeddings (`supportedGenerationMethods ∋ embedContent`),
  but the native Gemini embedding protocol remains unsupported (§15); its
  discovery adapter admits only qualified `generateContent` models.

---

### Response resource limits

Unary chat and Responses calls accept at most 8 MiB of decoded HTTP body;
embedding responses accept at most 32 MiB. The byte count applies while reading,
including chunked responses without a declared length. An oversized response is
refused with an actionable error and is not retried against another provider.
Reduce the requested output or embedding batch to fit. Existing image response
limits and their single-attempt transport remain in force.

Chat, Responses, and embedding processing share capacity for eight active calls
per gateway process, including cache reads and response finalization. Admission
has no waiting queue: excess calls receive a retryable capacity error before
provider contact (HTTP 503 on the inference routes). A stream holds its place
until it completes or is cancelled. MCP session creation and dispatcher clones
share the same capacity. These limits are fixed defaults, not environment settings.
They bound admitted processing; decoded JSON and HTTP delivery have additional
memory overhead, so they are not an exact process-memory ceiling.

Optional stream caching considers at most 1 MiB of cumulative serialized output
chunks, including text, metadata, usage, and choices. Exceeding that budget, or
seeing content the cache cannot faithfully replay, discards accumulated content
and disables caching for the remainder of that stream. The live response still
reaches the client; no partial completion is stored. Existing SSE frame limits
and timeouts continue to govern delivery independently.

## 8. Quota & budgets

Formalizes I3. Dimensions: requests, `input_tokens`, `output_tokens`, `cached_read_tokens`
(cost-weighted), and `cost`. Scopes: principal, tenant, model (and combinations). Windows:
rolling/daily/weekly/monthly. Cost weighting comes from the `llm_models` costing for
`model_served` (§4.2).

- **Gate (stage 7):** read the principal's recorded usage in-window; if a budget is already
  ≥ its limit, reject with a typed `budget_exhausted` error + the window reset time. No
  estimation, no pre-debit.
- **Ledger update (stage 13):** attempt to record actual usage (including cached tokens)
  after completion or stream close; the next request reads that ledger.
- The PostgreSQL budget gate reads applicable limits and their scoped usage in
  the same statement snapshot. It does not reuse an earlier allow decision;
  each budget keeps its own rolling window, principal, and model scope.
- **Overrun:** no hard bound. Concurrent admitted calls and dropped best-effort usage writes
  can exceed the configured budget because there is no reservation or fail-closed debit.
- Cost-based budgets sum known total costs. Unknown costs are excluded rather
  than treated as a priced free call. Token budgets sum inclusive input and
  output, counting cache reads, creation and reasoning once. Unknown primary
  counts are excluded. These remain lagging gates over recorded usage and do
  not become hard spending limits when reporting is incomplete.

---

## 9. Caching

- **Key:** BLAKE3 over the canonical request **plus tenant, identity-provider issuer,
  and subject** — exact-match cache
  entries are **per-principal scoped**, so one user's completion is never served to another
  (security invariant; strictly stronger than tenant isolation). The key is
  **transport-agnostic** (it normalizes `stream` and `stream_include_usage`), so a unary call
  and a streaming call for the same content share one entry, served in whichever transport the
  request asked for.
  The key format is versioned: entries written before issuer scoping are never
  reused after upgrading. They expire and are swept normally; no database
  migration or manual purge is required. Cache lookups still follow current
  authorization and budget checks.
- **Scope:** the canonical chat, Responses, and embeddings surfaces. The native
  `/v1/messages` surface (§4.8) has no canonical request and is never cached.
- **Default off — two-key arming.** Caching requires BOTH `GATEWAY_LLM_CACHE_ENABLED=true`
  (system-level; default off, since this is the one place the gateway stores response *content*)
  AND a per-model `cache_ttl_ms` (the per-alias opt-in + the entry's TTL). Either unset ⇒ the
  model is never cached. (Per-request no-store flag and a `temperature == 0` default-gate are
  not supported.)
- **Streaming:** on miss, tee the assembled completion into the cache as it streams; on hit,
  replay as a synthetic SSE stream (client behaviour identical). The stored completion carries
  the provider's usage counts even when the client did not ask for usage on its stream, so a
  later unary hit or a streamed hit that asks for usage can report it. A cache hit still produces an
  `InferenceRecord` (`gateway_cache_hit = true`, zero upstream tokens/cost).
- **Backend:** a `CacheStore` trait, Postgres-backed in v1, trait admits
  Valkey/semantic later without touching call sites.
- **Unary completion tail:** chat, Responses, and embeddings cache population
  gets a 50 ms write budget after inline usage accounting. A slow optional
  write is cancelled and logged; the completed response is still returned.
  No background task retains the response. PostgreSQL insertion and configured
  tenant-cap eviction commit together, including when cancellation interrupts
  the write. Capped writes use non-blocking tenant admission; contention skips
  optional population. PostgreSQL statement and lock deadlines bound the work,
  and interrupted connections are retired instead of returned to the shared
  pool. Cache availability can fall under database pressure; accounting
  and budget enforcement retain their existing ordering.
- **Growth bounds:** two layers. A background **TTL sweep**
  (`GATEWAY_LLM_CACHE_SWEEP_SECONDS`, default 300) reclaims expired rows' disk;
  reads filter on expiry, so the sweep only affects storage, never correctness.
  A **per-tenant row cap** (`GATEWAY_LLM_CACHE_MAX_ROWS_PER_TENANT`, default
  10k; `0` = unbounded) evicts the oldest beyond the cap after each store, so a
  within-TTL request-diversity burst can't balloon the table between sweeps.

---

## 10. Observability & dashboard

- **OTel GenAI semantic conventions** emitted from the `InferenceRecord`: `gen_ai.request.model`
  (requested) and the served model, `gen_ai.usage.input_tokens` / `output_tokens`, cached and
  reasoning tokens, cost, TTFT, finish reason, and provider.
- **Audit:** `LlmCompletion` pre-call intent uses the chained/outbox-capable required path only
  when fail-closed mode is active. Final LLM outcomes use chained best effort and can be
  dropped on contention or storage failure without failing the response. Records carry
  metadata only (I9).
- **Grafana panels** (`dashboards/`): tokens and cost per model/principal/tenant,
  cache hit-rate, failover/cooldown counts and TTFT.
- **Admin UI inference dashboard** (`waygate-admin`): model catalog, usage and
  budgets, plus locally loaded API credential status. It does not probe provider
  access, refresh consumer tokens or expose credential values.

---

## 11. Authorization (Cedar)

Models are Cedar resources (via the catalog view, I7). Policies gate per-model by
scope/role/tenant via a `permit` on a group. Models are **not** step-up-gated:
model access is an authorization concern, not a freshness one. See
[authorization](authorization-model.md#6-models-are-not-step-up-gated).
Cost/budget checks are **not** Cedar — they live in quota (atomic, lagging) so policy
evaluation stays fast and stateless. Policies are file-based with SIGHUP hot-reload; LLM
examples live under `crates/waygate-authz/tests/fixtures/policies`.

---

## 12. Persistence

Postgres stores the inference configuration and usage records:

- `llm_models` — provider, model, upstream_api, risk, requires_approval, **optional costing**
  (input / output / cached-read / cache-write price), routing group membership; **+ a
  catalog-compatible view** projecting `ToolDefinition` rows.
- Credential material remains injected and in memory; historical credential
  metadata is retained without reactivating removed consumer refresh behavior.
- `llm_usage` — the persisted `InferenceRecord` (metadata, no content) + rollup tables.
- `llm_budgets` — per-principal/tenant/model token & cost budgets + windows.
- `llm_cache` — key (incl. principal), canonical-request hash, response blob, TTL.

---

## 13. Security invariants

- Credentials never touch disk in plaintext, never appear in logs/audit/usage, and are
  injected-only (I4).
- Exact-match cache is per-principal scoped; no cross-principal (or cross-tenant) completion
  reuse (§9).
- One authorization path; no model is reachable that bypasses Cedar (I1, I7).
- Fail closed on identity/policy. Gateway response inspectors are not currently wired into
  the LLM arm; provider-native refusal/content-filter signals are normalized but do not add
  gateway DLP coverage.
- Usage/audit records store metadata only. Enabling LLM content logging would require wiring
  inspection/redaction before persistence; the current LLM path has no such content-logging
  mode (I9).

### 13.1 Supported API upstreams

Inference uses supported provider API endpoints and credentials. Consumer CLI
fingerprints, subscription token refresh and consumer model listing are removed.
Retired configured selectors fail startup; historical catalog rows keep their
legacy marker so invocation refuses them before cache or provider access.
Migration requires an explicit endpoint, model and credential choice; Waygate
does not infer equivalent entitlements or silently reroute a legacy alias.

`GATEWAY_LLM_EGRESS_PROXY` remains a general operator-controlled proxy for
provider requests, with the existing TLS and timeout policy. Proxy credentials
must not appear in logs. See [migration](api-only-inference-migration.md).

---

## 14. Edge cases & decisions

- **Provider serves a different model than requested.** Record both; cost/budget use
  `model_served` (§4.2). Surface `model_served` back to the client in the response `model`
  field per the surface's convention.
- **Provider doesn't report token usage.** Record what's available; cost-based budgets skip
  (`Unknown`); token budgets debit known classes; flag the gap in telemetry.
- **Surface mismatch** (Responses client → Chat-only provider, or vice-versa). Translate via
  canonical where lossless; otherwise the pre-dispatch capability gate rejects with a client
  error (§4.1). Both inbound surfaces are mounted (unary); the egress renders the canonical
  response to whichever surface the client used.
- **Mid-stream inspection is not implemented.** The LLM arm cannot currently apply the MCP
  response inspectors. A future streaming inspector cannot un-send bytes already forwarded;
  it must define rolling-buffer, terminal-error, audit, and pre-flight semantics before being
  enabled.
- **Multi-turn.** v1 is stateless — clients carry conversation history; `context_id` reserved.
- **Responses statefulness (`previous_response_id` / `store`).** The gateway is stateless and
  its audit ledger is content-free (I9), so it keeps **no** conversation/response store.
  `previous_response_id` is carried in the canonical request and **forwarded** to an
  OpenAI-Responses upstream (whose own store provides continuity); the pre-dispatch capability
  gate (`check_provider_support`, §4.1) **rejects** it when the resolved **primary** route is
  not a Responses upstream (there is no store to resolve it against). Dispatch also
  checks the selected route and refuses retired consumer profiles. A request
  with this handle stays on the primary provider context and never fails over to
  another credential, endpoint, or protocol. Configure a stable primary backend and
  account for a chained conversation. The gateway does not record which route issued
  a previous response: a handle from another context, including an earlier request
  that failed over, must be continued against its originating backend. A provider
  refusal leaves the handle intact and never triggers another attempt.
  `store` is **forwarded to the upstream**, so
  `store:false` stops the *provider* from persisting the response. **Caveat:** this does
  **not** suppress the gateway's own opt-in exact-match cache (§9) — when caching is enabled
  for a model (the system flag *and* a per-model TTL), a `store:false` request's completion
  can still be persisted in that cache (§9, §15). Reasoning input items are
  forwarded opaquely to a Responses upstream. An OpenAI-chat upstream receives
  their plain text (see below); Anthropic and Gemini receive none of it.
- **Replayed model output.** Clients that keep their own history send the model's earlier
  output back with each request, including its reasoning. The canonical surfaces treat that
  differently from client instructions. An instruction the gateway cannot translate is
  rejected (I6). Replayed model output records what the model already produced rather than
  asking for new behavior, so it is carried to upstreams that can use it and left out where
  it has no meaning. On Chat Completions an assistant message may carry `reasoning_content`,
  `reasoning`, or `reasoning_details`, the spellings OpenAI-compatible servers return and
  the chat passthrough delivers to clients unchanged. An OpenAI-chat upstream receives each
  one back unchanged, under the name the client used. The gateway does not rename them:
  servers disagree on the spelling, and a route does not record which server it reaches.
  Anthropic, Gemini, and Responses upstreams receive none of it, because plain or
  provider-structured chat reasoning cannot stand in for their own signed or encrypted
  reasoning. On Responses, an OpenAI-chat upstream's reasoning reaches the client as a
  `reasoning` item of plain `reasoning_text` content, with an empty `summary` and no
  `encrypted_content`, because the upstream produced neither; when streamed, the item closes
  once the answer or a tool call begins. When a client sends a reasoning item back on a turn
  routed to an OpenAI-chat upstream, the item's plain text — its `reasoning_text` content, or
  else its `summary_text` parts, where some clients keep it — reaches the upstream as that
  assistant message's `reasoning_content`, the spelling OpenAI-compatible servers most widely
  accept. An item carrying `encrypted_content` holds reasoning only its originating Responses
  provider can read and is left out. Replayed reasoning is conversation content: it is part of the completion-cache key and stays out of the
  content-free audit ledger.
- **Responses options from stateless clients.** Coding agents send three options with their
  Responses requests. `include: ["reasoning.encrypted_content"]` and `reasoning.summary` ask
  for extra output; both are forwarded to an OpenAI-Responses upstream, which returns it. Other
  upstream protocols produce neither encrypted reasoning nor reasoning summaries, so their
  responses carry none and nothing is invented in their place. Any other `include` value asks
  for output the gateway does not model and is rejected by name. `prompt_cache_key` is a hint
  for the upstream's prompt cache and does not change the output: it is forwarded to an
  OpenAI-Responses upstream, left out for other protocols, and ignored by the gateway's own
  completion-cache key.
- **Retrieval endpoints are unsupported.** `GET` / `DELETE /v1/responses/{id}` and the cancel
  endpoint are **not** served: they require the server-side response store the gateway
  deliberately does not keep (I9). A client that needs retrieval points `store` at an upstream
  it controls. (Full cross-provider *stateful chaining* — a content-bearing store outside the
  I9 ledger — is likewise out of scope; it would be a posture change, not a feature.)

---

## 15. Current limitations

- Inference does not provide general DLP or catalog-schema output validation.
- Usage is recorded after calls without pre-dispatch reservation, so recorded
  budgets do not provide a hard concurrent spending cap.
- Native Gemini and Cohere embedding protocols are not supported. Embedding
  auto-discovery is available for OpenRouter; other models require configuration.
- The discovery dashboard does not expose every model-source or presence field.
- Responses conversation IDs require a stable primary provider context; the gateway
  does not recover the originating route of a handle returned by an earlier fallback.
- The optional native Messages token-counting endpoint is not implemented.
- An upstream `store:false` request does not disable the gateway's separately
  configured exact-match cache. Keep that cache disabled when local persistence
  is unwanted.

**Design constraints:**

- **Cache scoping is per-principal** — cache keys include the principal; no cross-principal
  reuse (stronger than tenant isolation; see §9, §13).
- **Models are catalog entries** — no separate model-search tool; models are ordinary
  Cedar-gated catalog entries (I7).
