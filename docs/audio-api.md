# Speech API

`POST /v1/audio/speech` provides OpenAI-compatible speech generation through a
configured provider. The same invocation service applies model authorization,
credential-profile restrictions, request quotas, applicable lagging budgets, and
audit posture before provider contact. Provider credentials remain server-side.

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
request deadline. Speech shares the inference processing capacity. A client
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

This surface does not implement Realtime sessions or voice-resource management.
Providers retain ownership of voices, recordings, and persistence.

See the [OpenAI Speech contract](https://developers.openai.com/api/reference/resources/audio/subresources/speech/methods/create)
and [inference governance](inference-plane.md#2-invariants-load-bearing-rules).
