# Images API with a Codex subscription

The gateway serves `POST /v1/images/generations` and `POST /v1/images/edits`
using the direct Codex image endpoints and the existing subscription credential
store. OpenAI SDK clients use the gateway base URL and a gateway API key.
Image models are a separate operation from chat and embeddings.

## Configuration

Append this entry to the deployment's `GATEWAY_LLM_MODELS` array, using the
credential label already configured for the subscription:

```json
{
  "alias": "gpt-image-2",
  "provider": "openai",
  "credential_label": "PRIMARY",
  "base_url": "https://chatgpt.com/backend-api/codex",
  "surface": "codex",
  "kind": "images"
}
```

The default path prefix is `images`; dispatch appends `generations` or `edits`.
The alias appears in `/v1/models` with `modality: "text+image->image"`, and
`/v1/models?type=images` filters image models. Codex chat discovery does not
advertise this separate capability, so the image alias is an explicit operator
configuration. The gateway does not infer account entitlement from a chat model
listing. Deployment repositories own enabling the alias and selecting the
released image digest.

## SDK examples

```python
import base64
import os
from pathlib import Path
from openai import OpenAI

client = OpenAI(
    base_url=os.environ["GATEWAY_OPENAI_BASE_URL"],  # ends in /v1
    api_key=os.environ["GATEWAY_API_KEY"],
    max_retries=0,
)
result = client.images.generate(
    model="gpt-image-2",
    prompt="A blue square on a white background",
    quality="low",
)
Path("generated.png").write_bytes(base64.b64decode(result.data[0].b64_json))

with open("generated.png", "rb") as image:
    edited = client.images.edit(
        model="gpt-image-2",
        image=image,
        prompt="Make the square green",
    )
Path("edited.png").write_bytes(base64.b64decode(edited.data[0].b64_json))
```

## Supported request contract

Generation accepts JSON. Edits accept standard multipart form uploads named
`image` or repeated `image[]`, plus an optional PNG `mask`. Up to 16 images
fit within the total upload limit. PNG, JPEG and WebP uploads are identified by
their file signatures and converted to inline data URLs for Codex; the gateway
does not fetch remote image URLs or resolve provider file IDs.

The adapter forwards `prompt`, `model`, `n`, `size`, `quality`, `background`,
`output_format`, `output_compression`, `moderation`, and `user`; edits also
accept `input_fidelity`. It validates types, option enums, positive dimensions,
`n` from 1 through 10, and compression from 0 through 100 with JPEG/WebP output.
Provider-specific model and account restrictions remain authoritative.
Unknown fields and unsupported combinations produce a client error before the
provider is contacted. Omitted options retain provider defaults.

Responses preserve `created`, `data[].b64_json`, metadata, and reported usage.
GPT image models return base64; `response_format` is rejected. Streaming and
`partial_images` are explicitly unsupported until the subscription backend's
streaming contract has been verified. This implementation follows the direct
JSON image transport in the Codex source; automated compatibility tests use
local providers, not live subscription accounts.

Generation bodies are limited to 8 MiB; multipart edit bodies, including all
files and form overhead, to 64 MiB; provider response bodies to 128 MiB.
Both image routes share a limit of two active requests per gateway instance.
Admission happens before body parsing; excess calls receive HTTP 429 without
reading their uploads. Uploads must finish within 60 seconds or receive HTTP 408.
Capacity remains reserved through provider execution and bounded response
delivery. Delivery has a 60-second deadline independent of client reads; a stalled
download is terminated and its large buffer and capacity slot are released.
Only small copied chunks are queued for HTTP delivery. Disconnecting also releases
capacity.
The existing inference connect, idle-read, and configured total call timeouts
apply. A limit failure never causes an automatic retry.

## Authorization, usage, and failures

Image calls pass the existing model authorization, API-key profile, quota,
budget, approval, and pre-call audit gates. Usage rows identify generation and
edit calls separately and record only reported token counts. Missing usage and
cost remain unknown. Budgets retain the existing lagging semantics; subscription
allowance is not converted into a fabricated monetary price.

The gateway performs one image request and does not cache or fail over image
results. A disconnect or timeout may occur after the provider generated an
image. Disable SDK retries when duplicate generation is unacceptable, as shown
above. Provider errors use OpenAI-shaped error envelopes, with validation and
rate-limit statuses preserved; upstream credential failures become gateway
errors. Provider error text is withheld because it can echo prompts or uploads.

## References

- [OpenAI image generation API](https://developers.openai.com/api/reference/resources/images/methods/generate)
- [OpenAI image editing API](https://developers.openai.com/api/reference/resources/images/methods/edit)
- [Codex image transport](https://github.com/openai/codex/blob/47ca4619be10c20c1cec6ee9944738c5b961fa1d/codex-rs/codex-api/src/endpoint/images.rs)
- [Codex image request types](https://github.com/openai/codex/blob/47ca4619be10c20c1cec6ee9944738c5b961fa1d/codex-rs/codex-api/src/images.rs)

## SDK compatibility test

The Rust test fixture can exercise generation and multipart edits with the
OpenAI Python SDK, including multiple images and a mask. It binds only to
loopback and uses synthetic credentials and responses. Install the SDK in a
virtual environment, then explicitly run the test:

```sh
python3 -m venv /tmp/images-sdk-venv
/tmp/images-sdk-venv/bin/pip install openai==3.8.0
IMAGES_SDK_PYTHON=/tmp/images-sdk-venv/bin/python \
  cargo test --workspace --locked openai_python_sdk_images_smoke -- --ignored
```

This test is ignored in the default Rust test run because it requires the
separate Python environment. The ordinary Rust suite covers ingress limits,
HTTP error mapping, and provider rate-limit and timeout behavior without it.
