# Inference reference

## Supported behavior

- Client surfaces: `POST /v1/chat/completions` and `POST /v1/responses` are both mounted
  today, **unary and streaming**. The Responses route parses to the same canonical
  `LlmRequest` and renders the response through the canonical response hub. For streaming, an
  OpenAI-Responses upstream's frames already speak the Responses event protocol and are
  relayed 1:1 as named SSE events; for the other providers, the gateway's normalized
  chat-chunk stream is lifted into Responses streaming events (`response.created` →
  `output_item.added` → `output_text.delta` … → `response.completed`) — there is no `[DONE]`
  sentinel on the Responses transport. As on the unary path, the translated providers carry
  text + function calls; reasoning is preserved only for the native-protocol
  (OpenAI-Responses) upstream. **Exception — the ChatGPT/Codex subscription backend is
  streaming-only:** a non-streaming call to a Codex-backed model is rejected fail-closed
  (`use stream=true`) because that backend streams-only and the gateway does not aggregate the
  upstream SSE back into a unary body (§13.1). Every other route serves both transports.
- **Images surface:** `POST /v1/images/generations` and `POST /v1/images/edits`
  serve explicitly configured Codex image models through the same model gates.
  See [Images API](images-api.md) for SDK examples, limits, and supported options.
- **Embeddings surface:** `POST /v1/embeddings` is also mounted (**unary only** — embeddings
  have no streaming form), routing an OpenAI-compatible embeddings model through the **same**
  governed pipeline (authorize / quota / budget / audit — I1) as the chat surfaces. It is a
  second *operation* alongside chat (§4.7): its own canonical request, an input-token-only
  usage/cost record, and an `LlmOperation` discriminator on the resolved model that the
  pipeline branches on — rejecting a surface/operation mismatch (an embeddings model on a chat
  route, or a chat model on `/v1/embeddings`) with a clean client error. Only the
  OpenAI-compatible `/embeddings` shape is wired (covering OpenAI, OpenRouter, Together,
  Voyage, Mistral, Jina, Cohere-compat, and self-hosted TEI/vLLM/Ollama); native non-OpenAI
  embed protocols (Gemini `:embedContent`, Cohere `/v1/embed`) are not supported.
  Embeddings *discovery* is wired for **OpenRouter** (its dedicated `/embeddings/models`
  listing); auto-discovery for the other providers is not supported (§7.1).
- Four providers: **OpenAI** (ChatGPT/Codex subscription → Responses API), **Google Gemini**
  (Code Assist subscription → `generateContent`), **Anthropic** (first-party `x-api-key` →
  Messages API), **OpenRouter** (API key → OpenAI-compatible Chat Completions).
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
  and consumes subscription quota; it is the irreversible side effect. Authorization,
  budget-not-exhausted, profile allow-list, and (where configured) approval are all checked
  **before** dispatch. No "validate by failing through the provider call."
- **I3 — Lagging budgets, no reservation.** Token/cost budgets are enforced from *recorded*
  usage. The pre-dispatch gate rejects only when the budget is *already* exhausted; actual
  usage is attempted best-effort after completion or at stream close. The gateway makes no
  pre-dispatch reservation, so concurrency or a dropped usage write can exceed the nominal
  budget by more than one request. A hard overrun bound is not currently provided.
- **I4 — Credentials are injected, never minted or written back.** The gateway reads
  `LLM_CRED_*` values injected by Infisical, refreshes OAuth access tokens **in-process and
  in-memory**, and never mints a credential nor writes back to Infisical or to disk. The
  `waygate-llm-credentials` crate itself holds no Infisical client. **Scoped read exception:**
  for credentials kept fresh by an out-of-band refresher (`ai-credential-refresh`),
  `waygate-server` runs a **read-only** Infisical re-read poller (scoped service token, single
  secret path) that re-fetches the refresher's *current access token* into the in-memory store.
  Those credentials are **not** refreshed in-process (their seed refresh token rotates away),
  and the re-read is read-only — still never minted, never written back. See the rotation edge
  below.
- **I5 — Streaming is first-class.** Responses stream and the canonical usage/outcome record
  is finalized at stream close. The generic MCP response-inspector and output-schema stages
  are not wired into the LLM arm today; provider translation normalizes content-filter and
  refusal signals but is not a substitute for gateway DLP inspection.
- **I6 — Provider-agnostic core, provider-specific edges.** A canonical request/response/usage
  model sits between the client surface and the four provider dialects. Provider quirks
  live only in translation adapters.
- **I7 — Models are catalog entities.** Models are registered like tools: discoverable via
  SEP-1888 `searchTools` and Cedar-gated. One catalog, one authorization model.
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
   │                                   (model→pool, failover)   (in-proc OAuth refresh)   (HTTP+SSE)
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
    sampling: Sampling,                       // temperature, top_p, max_tokens, stop, seed, reasoning_effort, …
    tools: Vec<CanonicalTool>,                // function/tool defs (name, description, parameters, strict)
    tool_choice: Option<ToolChoice>,          // Auto | None | Required | Function(name)
    parallel_tool_calls: Option<bool>,        // forwarded where the provider supports it
    response_format: Option<ResponseFormat>,  // JsonObject | JsonSchema { name, strict, schema }
    previous_response_id: Option<String>,     // Responses continuity; forwarded to a Responses
                                              //   upstream, gated for non-Responses routes (§14)
    store: Option<bool>,                      // forwarded; store:false is honoured (§14)
    stream: bool,
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
    cached_cost: Option<Decimal>,
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
Known line items remain available, but their subtotal is not presented as an
exact call cost. A reported zero needs no rate. Omitted optional cache subsets
remain unreported and add no separate charge. Catalog costs cover the recorded
token classes; they do not include provider storage or other non-token fees.

New ledger rows carry `accounting_version = 2`. Existing rows and writes from
older binaries retain version 1: their historical counts and costs are preserved,
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
  projection of the call (text + function calls + refusal; reasoning only where the provider
  emits it natively).

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
  `LlmOperation { Chat, Embeddings, Images }`. Embeddings use env config
  `kind: embeddings` and catalog `upstream_api = embeddings`; images use
  `kind: images` and `upstream_api = images`. The pipeline selects `invoke_llm`,
  `invoke_embeddings`, or `invoke_images` and rejects a **surface/operation
  mismatch** before parsing or provider contact. Chat models use the chat and
  Responses routes, embeddings use `/v1/embeddings`, and image models use the
  generation and edit routes described in [Images API](images-api.md).
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

**Injection contract.** Infisical injects each credential into the container as an env var (or
mounted file). Naming is semantic — `LLM_CRED_<PROVIDER>_<LABEL>`, where `<LABEL>` names the
account (`PRIMARY`, `FAMILY`, …). The set of labels for a provider is its pool (§7). Blob:

```jsonc
// subscription (OAuth) providers (OpenAI, Google)
{ "tokens": { "access_token": "…", "refresh_token": "…", "id_token": "…" },
  "expires_at": "2026-06-13T18:00:00Z" }
// api-key providers (Anthropic, OpenRouter) — a bare key string
"sk-ant-api03-…"   // Anthropic;  "sk-or-…" for OpenRouter
```

**In-process lifecycle (I4).** `waygate-llm-credentials` loads each `LLM_CRED_*` at startup
into an in-memory cache (optionally encrypted at rest with
`waygate_oidc::upstream_crypto::UpstreamCrypto` if any copy is persisted). A per-credential background
task refreshes the OAuth access token before expiry from the injected `refresh_token`,
updating the in-memory copy under a single-flight lock. **No write-back.**

**Credential health states** (consumed by routing and the dashboard):

```
Healthy ──token near expiry──► Refreshing ──ok──► Healthy
                                   └──fail──► Failing ──threshold──► Stale (skipped by routing)
```

**Restart semantics & rotation edge.** On restart Infisical re-injects the seed blob. While a
provider's `refresh_token` is **stable**, the gateway refreshes in-process from it. Providers
that **rotate** their refresh token single-use (the subscription harness — Codex —
kept fresh by `ai-credential-refresh`) can't be refreshed in-process: the seed refresh token
rotates away within minutes. Those credentials are instead marked **externally-refreshed** —
the gateway serves the current access token and never refreshes it itself — and the scoped
read-only re-read poller (the I4 exception) pulls the refresher's *current* access token
from Infisical on a cadence (`GATEWAY_LLM_CRED_RELOAD*`). An externally-refreshed credential
whose token lapses before the next re-read surfaces an `awaiting re-read` error and a
"failing / stale" dashboard state (§10) rather than attempting a doomed in-process refresh.

---

## 7. Routing & failover

- **Model alias → ordered target groups**, each a list of `(provider, credential_label)`
  targets (e.g. a "subscription" group falling back to an "api-key" group).
- **Selector (v1):** `in_order` and `least-recently-used`; reserve `cost`/`latency`/
  `performance` (the catalog carries costing already).
- **Cooldown:** per `(provider, credential_label)` exponential backoff on consecutive
  failures, **persisted** (survives restart); cooled targets are skipped.
- **Failover (I8):** on retryable upstream failure (429/5xx/transport) or unhealthy credential
  (§6), try the next healthy target in the group, then the next group; bounded attempts;
  honor `Retry-After`.
- **Stall detection:** TTFB stall → fail over before the client sees bytes; throughput stall
  after first byte → abort (client already streaming); per-provider overrides for
  long-pre-token reasoning models.

### 7.1 Dynamic model discovery (implemented)

The catalog need not be hand-listed: the gateway can fetch each configured
provider's live model list and register the models itself. Opt-in via
`GATEWAY_LLM_DISCOVERY` (a JSON array of `{provider, credential_label, base_url}`
targets, at most one per provider, plus an optional `client_version` pin for the
Codex surface — see below); off by default. The discovered catalog and
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

- **The listing surface is keyed on `(provider, auth-kind)`, not provider**
  (crate `waygate-llm-discovery`). The endpoint, its parameters, and even its
  existence differ by auth-kind — this is the inference plane's "OAuth paths are
  different" reality:
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
  - **OpenAI Codex** (subscription OAuth) — the Codex CLI backend
    (`GET {base}/models?client_version=…` at `chatgpt.com/backend-api/codex`, with
    the Codex CLI fingerprint — `Originator` + `User-Agent` — and the OAuth
    `chatgpt-account-id`), NOT `api.openai.com`. **Wired.** No pricing in the
    listing. A discovered Codex model routes chat via the OpenAI *Responses* shape
    against the same ChatGPT backend (`{base}/responses`); the catalog row carries
    an `openai_chatgpt` flag (`migrations/0055_llm_models_codex_auth.sql`) so
    dispatch selects the Codex request fingerprint (`ProviderAuth::OpenAiChatGpt`)
    instead of a bare Bearer. `parse_targets` keeps an `openai` target on the
    provider alone; the refresher resolves the credential's kind (OAuth ⇒ Codex,
    api key ⇒ skipped) since parse time has no credential store.
    The backend **scopes the listing to the `client_version` it is asked as**
    (an old CLI version gets that release's model subset; an ancient one an
    empty list), so the refresher resolves a current version per cycle:
    the target's optional `client_version` pin (operator override, validated
    as `MAJOR.MINOR.PATCH` — a malformed pin is dropped with a `WARN`, not the
    target) → `waygate_llm_discovery::CodexVersionTracker` (latest released
    CLI version from the npm registry, GitHub releases as fallback, cached
    24h, falling back through last-good to the compiled
    `CODEX_DEFAULT_CLIENT_VERSION`). The tracker never fails, so a registry
    outage degrades to a possibly-stale version — never a skipped cycle — and
    the `User-Agent` version always agrees with the `client_version` sent.
    Only **picker-visible** models become catalog rows: the listing tags each
    model with a `visibility`, and anything other than `"list"` (e.g. `"hide"`
    on internal models like `codex-auto-review`, or an unknown future value)
    is skipped — mirroring the reference CLI's picker — so internal models
    never become routable aliases. A model that turns hidden drops out of the
    seen-set and is soft-disabled by the normal reconcile — and a listing whose
    every model is filtered (none picker-visible) is a *complete* answer that
    reconciles with an empty seen-set, soft-disabling all previously discovered
    rows. Only a **raw-empty** listing (the too-old-`client_version` signature —
    the backend returns empty, not an error, below its supported range) skips
    reconcile per the fail-open rule, and its `WARN` names the version sent.
  - **Anthropic** (`x-api-key`) — discovery unwired: stays operator-pinned
    (`DiscoverySurface::Unsupported`). (`/v1/models` is an `x-api-key` endpoint, so
    listing is now technically reachable, but the refresher arm is not built.)
  - **Google / Gemini** (OAuth) — a provider-specific internal endpoint; unwired
    until verifiable against the real credential rather than guessed.
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
  floor, or unparseable, reject at boot; bounded HTTP client). Each cycle, per target: resolve the credential kind + bearer,
  fetch the list(s), upsert the discovered models (provider-namespaced alias
  `openrouter:<id>` / `openai:<id>`, with per-model routing — OpenRouter's
  chat-completions or embeddings, vs Codex's Responses+`openai_chatgpt` — and pricing
  filled when the listing carries it) and reconcile — **all in one transaction** (all-or-nothing per
  target) — then reload the resolver. **Fail-open:** a failed target keeps the
  last-good catalog (`WARN`); an **empty** result skips reconcile so a transient
  empty/garbled response can never mass-soft-disable a provider. Persisted
  discovered rows are loaded into the resolver at boot, so a restart routes them
  immediately (before the first refresh).
- **Credential HTTP policy.** In-process OAuth refresh uses the shared `Slow`
  30-second total-timeout profile. The optional read-only Infisical re-read
  client preserves its explicit 15-second total timeout. Both clients are built
  once during LLM-path startup; a transport/TLS initialization failure aborts
  that configured path instead of silently replacing the bounded client with an
  unconfigured default. MCP-only startup does not initialize either optional
  credential transport.
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
  **`modality`** field (`text->embedding`, `text->text`, or `text+image->image`,
  derived from the row's `upstream_api`; a non-standard OpenAI field SDKs ignore), and the listing accepts
  **`?type=embeddings|chat|images`** to filter to one kind — so a client discovers
  image and embeddings models as *distinct* from chat without probing each surface. The same
  operation distinction is projected into the `llm_models_catalog` view as a
  **`kind`** column (`embeddings` | `chat` | `images`).
- **Embeddings discovery — OpenRouter wired, others operator-pinned.** OpenRouter
  publishes a dedicated `/embeddings/models` listing, so the refresher discovers its
  embeddings models distinctly and tags each row `upstream_api = embeddings` (path
  `embeddings`) — auto-routed to `/v1/embeddings` exactly like a pinned embeddings
  model. Providers whose `/v1/models` listing does not flag *modality* and that expose
  no dedicated embeddings listing (OpenAI-direct) cannot be auto-classified, so their
  embeddings models stay configured via env pins (`kind: embeddings`). Gemini's
  `models.list` *does* flag embeddings (`supportedGenerationMethods ∋ embedContent`),
  but its discovery adapter is not supported (§15).

---

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
  **transport-agnostic** (it normalizes `stream`), so a unary call and a streaming call for the
  same content share one entry, served in whichever transport the request asked for.
  The key format is versioned: entries written before issuer scoping are never
  reused after upgrading. They expire and are swept normally; no database
  migration or manual purge is required. Cache lookups still follow current
  authorization and budget checks.
- **Default off — two-key arming.** Caching requires BOTH `GATEWAY_LLM_CACHE_ENABLED=true`
  (system-level; default off, since this is the one place the gateway stores response *content*)
  AND a per-model `cache_ttl_ms` (the per-alias opt-in + the entry's TTL). Either unset ⇒ the
  model is never cached. (Per-request no-store flag and a `temperature == 0` default-gate are
  not supported.)
- **Streaming:** on miss, tee the assembled completion into the cache as it streams; on hit,
  replay as a synthetic SSE stream (client behaviour identical). A cache hit still produces an
  `InferenceRecord` (`gateway_cache_hit = true`, zero upstream tokens/cost).
- **Backend:** a `CacheStore` trait, Postgres-backed in v1, trait admits
  Valkey/semantic later without touching call sites.
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
- **Grafana panels** (`dashboards/`): tokens & cost per model/principal/tenant; cache hit-rate;
  failover/cooldown counts; TTFT; and a **Provider credential status** panel — per credential:
  provider, label, health state, **access-token expiry countdown**, last-refresh time/outcome,
  pool position. *This panel is where token/credential expiration visibility lives.*
- **Admin UI inference dashboard** (`waygate-admin`): the same credential-status view as an ops
  page (provider/credential health + expiry + "refresh now"), plus the model catalog and
  per-user usage/budget views.

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
- `llm_credentials` — **runtime state only** (per-credential health/cooldown, current
  access-token expiry); credential material is injected, never stored.
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

### 13.1 OAuth-backend fingerprint (Codex)

The OpenAI **Codex** backend (`chatgpt.com/backend-api/codex`) gates a subscription OAuth token
to the *Codex CLI identity* and flags requests whose shape diverges from the real CLI's. (Anthropic
is **not** in this picture: the gateway authenticates Anthropic with a first-party `x-api-key` —
the sanctioned path — having removed the prior subscription-OAuth / Claude-Code impersonation;
api-key requests carry no CLI fingerprint.) The gateway presents the Codex CLI identity across two
layers; they are independent, and detection can key on either:

1. **Headers** — `originator: codex_cli_rs`, the Codex `User-Agent`, a per-credential
   `session_id` (§6: keyed on `sha256(bearer)`, so a pooled credential never shares one session
   across tokens), `x-codex-window-id`, the residency header, and `chatgpt-account-id`.
   The `User-Agent`'s CLI *version* is not a compile-time pin: dispatch reads a shared handle
   (`waygate_llm_providers::SharedCodexUaVersion`) the discovery refresher hot-swaps to the
   `client_version` it fetched the model listing as (§7.1), so `/models` and `/responses`
   present one, current client identity. Without a running Codex discovery target the handle
   keeps the compiled default (`CODEX_FP_DEFAULT_VERSION`, pinned equal to discovery's
   `CODEX_DEFAULT_CLIENT_VERSION` by a `waygate-server` test).
2. **Transport (TLS/JA3·JA4)** — the ClientHello fingerprint. This is the one layer header
   fidelity **cannot** address: the gateway's HTTP client (`reqwest`/`rustls`) presents a TLS
   fingerprint distinct from the real CLI's stack (Codex = a Rust stack), so a sufficiently strict
   backend could flag the gateway on JA3/JA4 alone. (This also applies to any upstream behind a
   TLS-fingerprinting CDN — e.g. `api.anthropic.com` sits behind Cloudflare — independent of the
   header/identity layer.)

   **Why not impersonate TLS in-process:** a BoringSSL-impersonating client (`rquest` and the like)
   could match a target JA3, but swapping the workspace's pinned `reqwest` is high-blast-radius
   (every crate uses it) and — critically — **unverifiable from here without a real CLI capture**,
   so it is deliberately *not* done. A wrong impersonation is no better than none.

   **What is shipped:** `GATEWAY_LLM_EGRESS_PROXY` routes *only* the LLM provider client through an
   operator-provided egress proxy. The intended target is a **uTLS-terminating sidecar** that
   terminates the gateway's TLS and **re-originates** the upstream connection with a CLI-like
   ClientHello. Note a *plain* forwarding/HTTP-CONNECT proxy does **not** help — it tunnels the
   gateway's own TLS end-to-end, leaving JA3 unchanged; the sidecar must terminate and re-originate.
   This keeps the in-process TLS stack untouched (no blast radius) while giving an operator a
   verified path to a CLI-like handshake.

   **Verification method (before investing further):** capture one real `claude`/`codex` CLI
   request through `mitmproxy` and the gateway's outbound equivalent, diff headers + body, and
   compare JA4 (e.g. with a JA4 fingerprinter). Only escalate the TLS work if the JA4 delta is
   what is actually getting tokens flagged — header/body parity may already suffice for a given
   backend, and the sidecar closes the rest without touching the gateway binary.

**Codex Responses request-shape contract.** Beyond identity, the ChatGPT/Codex backend is
strict about the request *body* and rejects a generic Responses body. A Codex route
(`ResolvedRoute::openai_chatgpt`) therefore normalizes the rendered Responses body through
`finalize_codex_responses_body`, mirroring the Codex CLI's own request shape:

- **Streaming-only.** A non-streaming (`stream:false`) call is rejected **before dispatch**
  with a clear, non-retryable error (`use stream=true`) — the backend streams-only and the gateway
  does not aggregate the upstream SSE back into a unary body. The finalizer also forces
  `stream:true` on the body it sends.
- **Stateless.** It forces `store:false` and **removes** `previous_response_id` (the
  subscription backend has no server-side store to honour either against), and requests
  `include: ["reasoning.encrypted_content"]` so a reasoning loop round-trips statelessly.
- **Normalized fields.** `parallel_tool_calls:true`, a non-null `instructions` (defaulted to
  `""` when absent — the backend treats present-but-null as absent), and it strips the
  sampling / control fields the CLI never sends (`max_output_tokens`, `temperature`, `top_p`,
  `truncation`, `user`, `prompt_cache_retention`, `stream_options`, …).

The **standard** api-key OpenAI Responses upstream (`ProviderAuth::Bearer`) has none of these
constraints — it serves unary + streaming and forwards `store` / `previous_response_id` as
written (§14).

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
- **Refresh-token rotation across restarts.** Out of scope for the gateway; re-seeded
  out-of-band; surfaced as a credential-health state (§6, §10).
- **Multi-turn.** v1 is stateless — clients carry conversation history; `context_id` reserved.
- **Responses statefulness (`previous_response_id` / `store`).** The gateway is stateless and
  its audit ledger is content-free (I9), so it keeps **no** conversation/response store.
  `previous_response_id` is carried in the canonical request and **forwarded** to an
  OpenAI-Responses upstream (whose own store provides continuity); the pre-dispatch capability
  gate (`check_provider_support`, §4.1) **rejects** it when the resolved **primary** route is
  not a Responses upstream (there is no store to resolve it against). Note the gate runs
  against the primary route only — a model whose **fallbacks** (§7) cross to a non-Responses
  protocol can still fail over to one, where the id is dropped and continuity is best-effort;
  configure Responses aliases with Responses-only fallbacks (§15). `store` is **forwarded to the upstream**, so
  `store:false` stops the *provider* from persisting the response. **Caveat:** this does
  **not** suppress the gateway's own opt-in exact-match cache (§9) — when caching is enabled
  for a model (the system flag *and* a per-model TTL), a `store:false` request's completion
  can still be persisted in that cache (§9, §15). This forwarding describes the **standard**
  api-key OpenAI Responses upstream; the **ChatGPT/Codex subscription** backend is
  stateless-by-design and overrides it — its finalizer (`finalize_codex_responses_body`)
  forces `store:false` and **strips** `previous_response_id` (§13.1), because the subscription
  backend exposes no server-side store. Reasoning *input* items are carried opaquely and
  forwarded to a Responses upstream (dropped for Anthropic / Gemini / chat, where they are
  meaningless); on the Codex backend the gateway requests `include:
  ["reasoning.encrypted_content"]` so a **stateless** reasoning loop round-trips the
  encrypted reasoning without the gateway (or the backend's store) holding content.
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
- Cross-protocol fallback routes cannot preserve Responses conversation IDs.
- An upstream `store:false` request does not disable the gateway's separately
  configured exact-match cache. Keep that cache disabled when local persistence
  is unwanted.

**Design constraints:**

- **Cache scoping is per-principal** — cache keys include the principal; no cross-principal
  reuse (stronger than tenant isolation; see §9, §13).
- **Models surface via `searchTools`** — no separate `searchModels` meta-tool; models are
  ordinary Cedar-gated catalog entries (I7).
