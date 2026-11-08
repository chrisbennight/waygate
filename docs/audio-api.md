# Audio APIs

`POST /v1/audio/speech` provides OpenAI-compatible speech generation through a
configured provider. The same invocation service applies model authorization,
credential-profile restrictions, request quotas, applicable lagging budgets, and
audit posture before provider contact. Provider credentials remain server-side.
`POST /v1/audio/transcriptions` transcribes completed audio files through the
same gates; see [Transcription](#transcription).

## Configure a speech model

Add a model to `GATEWAY_LLM_MODELS`, with explicit provider capabilities:

```json
{
  "alias": "narration",
  "provider": "openai",
  "credential_label": "SPEECH",
  "base_url": "http://speech-provider:8000/v1",
  "upstream_model": "provider-speech-model",
  "kind": "speech",
  "speech": {
    "formats": ["mp3", "wav", "pcm"],
    "voices": ["narrator"],
    "custom_voices": true,
    "instructions": true,
    "sse_formats": ["pcm"],
    "speed_range": [1, 1]
  }
}
```

The default path is `audio/speech`; an explicit `path` overrides it. The
provider setting identifies the credential namespace and OpenAI-compatible wire
contract. It does not require that the provider be hosted by OpenAI. Speech
supports the `openai` and `openrouter` credential namespaces with standard bearer
authentication. Inject an OpenAI API key as an explicit JSON envelope into
`LLM_CRED_OPENAI_SPEECH`:

```json
{"api_key": "<injected-provider-key>"}
```

The explicit envelope distinguishes API keys from subscription OAuth material.
Malformed or mixed credential envelopes are rejected, rather than sent as a
bearer string. Existing OAuth credential forms remain supported for their
existing operations.
Speech retrieves only API-key material, under the credential lock. Subscription
OAuth credentials are refused without refresh or provider contact.

List only formats and named voices the provider supports. `custom_voices`
permits standard object selectors such as `{"id":"voice_example"}`; the provider
owns their existence and compatibility. Named presets must appear in `voices`.
Absent `speed_range` permits only normal speed. Instructions and SSE are disabled
unless explicitly enabled. `sse_formats` lists the supported SSE codecs, separately
from ordinary audio formats. Unsupported selections fail before generation.

Speech configuration uses one route without automatic fallback, credential
pooling, or completion caching. A transport failure can follow an accepted
generation, so replay could repeat work or charges. Speech capabilities come
from the configured model, not guessed catalog defaults; an old catalog row
cannot revive a removed speech configuration. `GET /v1/models?type=speech` lists
configured, resolvable catalog entries with modality `text->audio`.

## Standard client requests

Use the normal OpenAI client with the gateway's `/v1` base URL and a gateway
credential. The provider key is never sent to the client.

```python
from openai import OpenAI

client = OpenAI(base_url="https://gateway.example/v1")
with client.audio.speech.with_streaming_response.create(
    model="narration",
    input="Welcome home.",
    voice="narrator",
    response_format="pcm",
) as response:
    for chunk in response.iter_bytes():
        play_pcm(chunk)  # Application-owned playback.
```

The SDK reads its gateway credential from `OPENAI_API_KEY`. To save a complete
file instead, use the SDK's ordinary response collection or file-writing
interface and a supported format. WAV providers must produce finalized lengths
on a standard request; callers do not supply an additional `stream` flag.

The supported fields are `model`, `input`, `voice`, `instructions`,
`response_format`, `speed`, and `stream_format`. Input and instructions are
bounded by the documented Speech API limits. Native provider fields are
rejected rather than silently stripped. Audio output streaming does not provide
incremental input text.

`stream_format="audio"` returns audio bytes; `stream_format="sse"` returns the
standard `speech.audio.delta` and `speech.audio.done` payloads. SSE requires an
explicit terminal event. A truncated SSE stream, interrupted audio body, empty
result, or response-limit failure is not successful speech. HTTP failures before
audio begins use an OpenAI-shaped error envelope; a failure after headers ends
the HTTP body with a transport error. The gateway never appends JSON to audio.

## Delivery and evidence

Audio is delivered incrementally with bounded buffering and no proxy buffering
hint. There is a decoded audio limit of 64 MiB and an independent five-minute
generation deadline. Speech shares the inference processing capacity. A client
disconnect closes the upstream body; slow readers cannot hold provider work
indefinitely. Connection closure is not proof that a remote provider acknowledged
cancellation.

Generation and HTTP delivery have separate metadata-only audit outcomes.
Generation records decoded byte count, first-audio timing, and completion or
failure class. Delivery records body consumption or abandonment; it never
claims the client played the audio. Evidence finalization is best effort and
bounded. Request text, instructions, credentials, and audio are not recorded.

The usage ledger identifies the `audio_speech` surface. Provider speech token
placeholders are not measured usage. Speech token counts and costs currently
remain unknown; unknown costs
do not become a known free call or a hard spending guarantee.

## Transcription

`POST /v1/audio/transcriptions` transcribes a completed audio file using the
standard multipart `file` and `model` fields. It applies the same model
authorization, credential-profile restrictions, request quotas, approvals, and
audit posture as other inference calls. Provider credentials and addresses stay
server-side, so the provider can be on a private network with no public listener.

### Configure a transcription model

```json
{
  "alias": "local-asr",
  "provider": "openai",
  "credential_label": "STT",
  "base_url": "http://stt-provider:8080/v1",
  "upstream_model": "provider-asr-model",
  "kind": "transcription",
  "transcription": {
    "file_types": ["wav"],
    "response_formats": ["json", "text"],
    "language": false,
    "prompt": false,
    "temperature": false
  }
}
```

The default path is `audio/transcriptions`; an explicit `path` overrides it.
Transcription supports the `openai` and `openrouter` credential namespaces with
standard bearer authentication. For a private provider, generate a shared key,
configure the provider to require it, and inject the same key into the gateway as
`LLM_CRED_OPENAI_STT`:

```json
{"api_key": "<shared provider key>"}
```

Clients authenticate to the gateway with their own gateway credential and never
receive the provider key.

List only what the provider supports:

- `file_types`: accepted audio files, identified by extension as in the OpenAI
  API: `flac`, `m4a`, `mp3`, `mp4`, `mpeg`, `mpga`, `oga`, `ogg`, `wav`, `webm`.
  The gateway does not convert audio, and the provider still validates the audio
  itself, such as its sample rate or channel count.
- `response_formats`: `json` (required; the API default), `verbose_json`,
  `text`, `srt`, `vtt`.
- `language`, `prompt`, `temperature`: whether the provider accepts these
  optional fields. Each defaults to `false`.

Transcription uses one route without fallback, credential pooling, or caching.
Capabilities come from the configured model; a catalog row cannot revive a
removed transcription configuration. `GET /v1/models?type=transcription` lists
configured, resolvable transcription models with modality `audio->text` and
their capabilities.

### Standard transcription requests

```python
from openai import OpenAI

client = OpenAI(base_url="https://gateway.example/v1")
with open("sample.wav", "rb") as recording:
    result = client.audio.transcriptions.create(model="local-asr", file=recording)
print(result.text)
```

The supported fields are `file`, `model`, `response_format`, `language`,
`prompt`, `temperature`, and `stream`. `stream` may only be `false`; streaming
transcription is not supported. Options the model's configuration does not list,
and other standard fields such as `timestamp_granularities[]`, `include[]`, and
`chunking_strategy`, fail before provider contact rather than being silently
stripped. The gateway sends the provider a rebuilt form containing the validated
fields and the configured upstream model.

`json` and `verbose_json` return `application/json` with a string `text`; other
standard fields from the provider are preserved. `text`, `srt`, and `vtt` return
`text/plain; charset=utf-8`, which the OpenAI SDK returns as a string. A provider
reply that does not match the requested format is a gateway error: JSON formats
need a JSON content type and a string `text`, the others need a text content type,
and VTT and SRT bodies must start like WebVTT and SRT files. Errors always use the
OpenAI JSON error envelope, whatever format was requested.

### Transcription limits, failures, and evidence

Files are limited to 25 MiB (26,214,400 bytes), the OpenAI API limit; larger
uploads return HTTP 413. Uploads have a 60-second deadline. At most four requests
hold uploads or responses at once, from before the upload is read until the
response is delivered or its 60-second delivery deadline passes; further requests
receive HTTP 429 with `Retry-After`. Transcription shares the inference processing
capacity. Provider calls have a five-minute deadline and one attempt, and
responses are capped at 16 MiB. Exceeding the deadline returns HTTP 504; a
connection failure, including the operator's provider connect or read timeout,
returns HTTP 502, as on the other inference surfaces.

A busy provider (429 or 503) keeps its status and `Retry-After`. Other provider
client errors keep their 4xx status, including 413 when the provider's own size
limit is smaller than the gateway's. A provider authentication failure is a
gateway error (502), not a client authentication failure. Provider error bodies
are not passed to clients. A client disconnect abandons the request; the gateway
records the abandonment but cannot confirm that the provider stopped work.

Evidence records the outcome, upload size, response format, attribution, and
timing, including for abandoned requests. Audio, prompts, transcripts, and
credentials are never recorded. The usage ledger identifies the
`audio_transcription` surface. Transcription consumes no metered tokens: each call
records zero input and output tokens, which price as zero cost, and spending
budgets do not block it. Request quotas and other gateway limits still apply.

## Voice and consent resources

One configured Speech or Realtime model may also provide standard recording-based voice and
consent operations. Add only the operations its provider supports to that model's
`speech.resources` or `realtime.resources` array:

```json
{"resources": [
  "voice_create", "voice_delete",
  "consent_create", "consent_list", "consent_retrieve",
  "consent_update", "consent_delete"
]}
```

Resource requests do not carry a model selector. The explicitly configured model
supplies the provider, credential, model authorization, profile, quota, budget,
and audit boundary. Configuring more than one resource provider fails startup;
without one the resource routes report that no provider is configured. Discovered
catalog rows cannot opt into these routes. No provider-specific client selector
or separate gateway voice ownership system is introduced. Authorized callers see
the resources their configured provider makes available.

| Method | Path | Operation |
| --- | --- | --- |
| POST | `/v1/audio/voices` | Create a voice from a recording and consent ID |
| DELETE | `/v1/audio/voices/{voice_id}` | Delete a voice |
| POST / GET | `/v1/audio/voice_consents` | Create / list consent recordings |
| GET / POST / DELETE | `/v1/audio/voice_consents/{consent_id}` | Retrieve / update metadata / delete consent |

Use standard multipart `name`, `consent`, and `audio_sample` fields for voice
creation; optional `type` must be `audio_sample`. Consent creation uses `name`,
`language`, and `recording`. Reference transcription and encoding, when needed,
are internal provider work. Callers do not supply an extra transcript or perform
a preparation request. Returned and pre-existing voice IDs pass unchanged through
standard selectors such as `voice={"id":"voice_example"}`.

Consent listing accepts `after` and `limit` (1–100). Metadata updates accept a
JSON `name`. Unknown fields and unsupported operations fail before provider
contact. Prompt-based voice creation is outside this surface: OpenAI prompt-created
voices are supported only in Live, not Speech or Realtime.

Recordings are limited to 10 MiB, with a 60-second upload deadline and bounded
upload concurrency. Provider operations have a five-minute deadline and one
attempt; metadata responses are capped at 1 MiB. Creation or deletion can have an
uncertain remote outcome after transport failure, so the gateway does not replay
them. A successful deletion requires the provider's explicit confirmation. Voice
deletion does not issue a second request to delete its separate consent resource.
Providers own resource relationships, persistence, and asset cleanup.

Resource evidence contains the operation, outcome, attribution, and timing. Names,
recordings, descriptions, and provider error bodies do not enter routine evidence.
The `audio_resource` usage surface retains unknown token counts and costs rather
than treating resource operations as known free calls. Evidence finalization is
bounded and best effort.

## Realtime configuration

Realtime uses the current OpenAI GA session and event contract. Configure a
separate model with the provider's actual supported features:

```json
{
  "alias": "live-narration",
  "provider": "openai",
  "credential_label": "SPEECH",
  "base_url": "http://speech-provider:8000/v1",
  "upstream_model": "provider-realtime-model",
  "kind": "realtime",
  "realtime": {
    "websocket": true,
    "webrtc": true,
    "voices": ["narrator"],
    "custom_voices": true,
    "instructions": true,
    "audio_input": false,
    "tools": false,
    "max_session_seconds": 600,
    "measured_usage": false
  }
}
```

The base URL is HTTP(S), including for the WebSocket upgrade. Realtime uses the
same strict API-key envelope, proxy/TLS policy, model governance, and single
attempt rule as Speech. There is no credential pool, fallback, or cache. Declared
capabilities state the provider's supported behavior, not per-feature access
policy or extra OpenAI request fields. Model/call authorization remains the
gateway boundary. Only
configured models can supply audio routes; discovery cannot infer capabilities
from model names. `GET /v1/models?type=realtime` and the additional `modality` and
`capabilities` fields are gateway discovery metadata, outside the OpenAI standard.

### WebSocket sessions

Connect to `/v1/realtime?model=live-narration` using a gateway bearer credential
and an ordinary OpenAI Realtime client. Send standard GA `session.update`,
`conversation.item.create`, and `response.create` events. Session updates use
`session.type="realtime"`, `output_modalities`, and `audio.output.voice`.
Provider response and item IDs and `response.output_audio.*`, transcript,
`response.done`, cancellation, and truncation events pass through unchanged.
The provider owns conversation, voice-locking, and cancellation semantics.
On this WebSocket path the gateway prevents model changes and refuses unsupported
configured options before forwarding.
Native incremental text append/flush operations are not standard Realtime
events and are refused. Standard complete text items and response input work
without a gateway-specific extension.

### WebRTC calls

Use the standard unified `POST /v1/realtime/calls` multipart flow: `sdp` contains
the offer and `session` contains JSON with `type: realtime`, the model alias,
and supported session options. The response is HTTP 201 with `application/sdp`
and a gateway `Location`. Native call IDs are preserved. A standard
`POST /v1/realtime/calls/{call_id}/hangup` terminates a call through the same
model gates.

Call controls retain the configured provider credential's account/service scope.
Model authorization grants creation and termination of calls that credential
can control, irrespective of which authorized gateway caller created a call.
Caller and tenant identity remain audit attribution and authorization inputs;
the gateway adds no creator or tenant ownership restriction to native call IDs.
The provider remains authoritative for whether a call belongs to that credential.

The provider terminates WebRTC media and its `oai-events` data channel. Its ICE
or TURN addresses must be reachable from clients even when its HTTP API is
private. The gateway validates the initial session options; later data-channel
commands go directly to the provider, which must enforce its declared feature
support, model immutability, and standard unsupported-option errors. Sideband
monitoring does not intercept those commands. Operators must qualify those
provider guarantees; capability flags cannot disable a feature the provider
continues to accept over its data channel.
The gateway observes the call through the provider's standard sideband
WebSocket. It does not relay RTP or claim client playback. A failed or abandoned
setup triggers bounded hangup cleanup once a provider call ID is known; failures
before an ID is returned leave the remote outcome unknown. Session termination
also attempts bounded provider hangup.

Only one configured Realtime model may enable WebRTC. This is a gateway routing
limit, not an OpenAI requirement: model-less call controls resolve consistently
on every replica without a gateway call ownership database. WebSocket-only models
can coexist. External client-secret minting and external sideband attachment are
not exposed. Browser applications can use the unified offer flow through an
authenticated application server. Provider-global resources retain their
provider authorization model; the gateway adds no per-user voice overlay.

### Session bounds and evidence

Realtime has 32 concurrent session slots, separate from HTTP inference capacity.
The configured lifetime is 1–3600 seconds (default 600), with 1 MiB events,
64 KiB SDP, 256 MiB combined event traffic, 100,000 events, and 128 responses per
session. Uploads, setup, writes, delivery, cleanup, and evidence have deadlines.
Session runners, downstream event delivery, and cleanup participate in the
service's existing cancellation and graceful-drain lifecycle.
Existing request quotas count session/control admission. Live policies and
applicable recorded-usage budgets are checked every five seconds and before
new WebSocket responses or session changes, using the admitted identity facts.
Explicit hangup retains authorization and rate controls but is not refused
because a generation budget is exhausted.
These are lagging budgets; in-flight activity and unknown usage are not a hard
spending guarantee. Identity attributes are the admission snapshot.

Metadata-only generation evidence records response status and observed timing;
the session record separately reports termination.
WebSocket delivery has its own outcome: all observed events written to the
transport, or abandoned delivery. This is independent of generation success and
does not confirm client receipt or playback.
First-audio latency starts when the gateway receives `response.created`; it excludes
earlier client input and provider queue time. The timing origin is recorded.
WebRTC output-buffer stopped/cleared events separately record the provider's
media completion/interruption boundary. Neither confirms client receipt.
First audio means a received WebSocket audio delta or the provider's standard WebRTC
`output_audio_buffer.started` event. The latter is a provider media boundary,
not browser receipt. Missing observations stay unknown. Audio, conversation
text, transcripts, SDP, ICE credentials, and provider keys are never placed in
routine evidence.

Usage is aggregated at session close. Set `measured_usage` only when the provider's
`response.done.usage` counts are authoritative; placeholders remain unknown by
default. Missing or incomplete response usage leaves the session aggregate
unknown. Measured counts do not imply measured cost: the current text-rate
catalog cannot price Realtime's mixed audio/text token classes, so Realtime cost
remains unknown. Provider-confirmed response cancellation and acknowledged call
termination are distinct from a locally closed connection.

See the [OpenAI Realtime guide](https://developers.openai.com/api/docs/guides/realtime)
and [WebRTC flow](https://developers.openai.com/api/docs/guides/realtime-webrtc).

See the [OpenAI Speech contract](https://developers.openai.com/api/reference/resources/audio/subresources/speech/methods/create)
and [inference governance](inference-plane.md#2-invariants-load-bearing-rules).
The [voice](https://developers.openai.com/api/reference/resources/audio/subresources/voices/)
and [consent](https://developers.openai.com/api/reference/resources/audio/subresources/voice_consents/)
contracts define the resource operations.

## Local client qualification

The opt-in SDK test runs an authenticated gateway against a private loopback
provider and a real application WebRTC peer. It checks complete WAV, incremental
PCM, standard SSE, recording voice/consent lifecycle, WebSocket audio/transcript
events, cancellation/truncation, decoded Opus and data-channel events, and
standard call hangup. Direct and proxied first-audio samples are diagnostic,
not a production latency guarantee. Python SDK versions that expose Speech SSE
as a binary response can read its standard frames with `iter_lines()`.

Use an isolated environment with `openai[realtime]`, `aiortc`, and `aiohttp`, then:

```sh
AUDIO_SDK_PYTHON=/path/to/venv/bin/python cargo test -p waygate-server \
  openai_audio_sdk_and_real_webrtc_media -- --ignored --nocapture
```

A separate transcription test needs only the `openai` package. A real OpenAI
client, given only the gateway URL, transcribes a file through an authenticated
local gateway to a private stand-in provider that requires a shared key. It also
checks text output, an unsupported format, and an unauthenticated caller:

```sh
TRANSCRIPTION_SDK_PYTHON=/path/to/venv/bin/python cargo test -p waygate-server \
  openai_transcription_sdk_through_authenticated_gateway -- --ignored --nocapture
```

The default workspace suite skips these optional environment-dependent tests.
Provider deployment qualification must additionally verify its real inference,
voice resources, private HTTP routing, and client-reachable ICE/TURN addresses.
