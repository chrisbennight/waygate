# Route model requests through gateway governance

The gateway also accepts model requests. Applications can use OpenAI-shaped
HTTP interfaces while identity, model authorization, credential selection,
routing, usage accounting, and audit remain under gateway control.

## Connect an application

Configure a provider credential and a model or model alias using the
[inference configuration reference](../inference-plane.md). Credentials may be
injected by the deployment's secret provider; API-key and supported OAuth
adapters have distinct refresh ownership. The public tutorial does not contact
a paid provider or include a provider credential.

Point the application's API base URL at your gateway's `/v1` endpoint. Use a
gateway access credential, not the upstream provider credential. Select a model
identifier from your configured catalog. For example, this Python standard-library
request reads its credential from the process environment and prints only the
HTTP status:

```python
import json
import os
import urllib.request

request = urllib.request.Request(
    os.environ["GATEWAY_URL"].rstrip("/") + "/v1/chat/completions",
    data=json.dumps({
        "model": os.environ["GATEWAY_MODEL"],
        "messages": [{"role": "user", "content": "Reply with hello."}],
    }).encode(),
    headers={
        "Authorization": "Bearer " + os.environ["GATEWAY_TOKEN"],
        "Content-Type": "application/json",
    },
    method="POST",
)
with urllib.request.urlopen(request, timeout=60) as response:
    print(response.status)
```

This requires a configured unary chat model and can incur provider charges.
It is an integration example, not part of the free local tutorial. Use
`stream: true` and a client that consumes SSE for streaming-only subscription
backends.

## Available surfaces

| Surface | Gateway behavior | Select deliberately |
| --- | --- | --- |
| `/v1/chat/completions` | Unary and streaming chat, tool calls, structured output translation | Features depend on the selected provider protocol. |
| `/v1/responses` | Responses-shaped ingress and streaming event output | Native Responses preserves protocol-specific features more faithfully; translated providers have a narrower feature set. |
| `/v1/embeddings` | Unary OpenAI-compatible embedding requests | Configure an embeddings model; native non-OpenAI embedding protocols are separate work. |
| `/v1/images/generations` and `/v1/images/edits` | Configured Codex image models through model gates | Follow the [image contract](../images-api.md) for options, uploads, and backend requirements. |

Outbound adapters include OpenAI-compatible, OpenAI Responses/Codex,
Anthropic Messages, and Gemini paths, with OpenRouter using a compatible
interface. A provider name is not a claim that every provider feature is
translated. Model discovery is adapter-specific; unsupported discovery paths
use operator-configured models. Treat upstream model names, availability, and
account entitlements as deployment inputs. For the upstream protocol definitions,
consult [OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create),
[Anthropic Messages](https://platform.claude.com/docs/en/api/messages), and
[Gemini content generation](https://ai.google.dev/api/generate-content).
An upstream API's feature list does not establish gateway translation support.

## Routing, accounting, and data handling

Model aliases can select routes, credential pools, and fallback targets. Verify
capability compatibility across those targets: conversation continuation and
provider-specific fields may not survive a cross-protocol fallback. A
subscription OAuth backend can require streaming even when other providers
support unary requests.

Usage records and configurable budgets make consumption visible. Current
accounting is best effort and budgets use the recorded ledger; there is no
pre-dispatch cost reservation or guaranteed upper bound on concurrent overrun.
Use provider-side limits as appropriate for the account.

The optional exact-match cache is off by default. When enabling it, review
retention and per-request behavior: forwarding `store: false` upstream does
not currently disable the gateway's own cache. LLM response inspection and
catalog-output validation are not wired like the MCP response path, so this
surface does not claim equivalent DLP coverage.

See [provider translation and known caveats](../inference-plane.md),
[model authorization](security.md), and [usage observability](observability.md).
The gateway's Code Mode is a separate governed tool runtime; provider-side
code-interpreter features do not acquire gateway tool authority.
